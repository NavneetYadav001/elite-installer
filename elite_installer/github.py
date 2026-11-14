"""Authenticated download of the latest stable release from a private GitHub repository.

The token is only ever sent to the API host. GitHub redirects asset downloads to another host (object storage); the
redirect handler below drops the Authorization header on any host change, and refuses https -> http downgrades.
"""
from __future__ import annotations

import hashlib
import json
import re
import urllib.error
import urllib.parse
import urllib.request

from . import __version__
from .core import InstallError

API = "https://api.github.com"
REPO_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/(?!\.{1,2}$)[A-Za-z0-9_.-]{1,100}$")
TAG_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
ASSET_RE = re.compile(r"^elite-hosting-(\d+\.\d+\.\d+)\.tar\.gz$")
SUMS_NAME = "SHA256SUMS"
MAX_ARCHIVE = 200 * 1024 * 1024
LOOPBACK = ("127.0.0.1", "localhost", "[::1]")


class _SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        old, new = urllib.parse.urlsplit(req.full_url), urllib.parse.urlsplit(newurl)
        if old.scheme == "https" and new.scheme != "https":
            raise InstallError("Refusing a redirect from https to an insecure URL.")
        nreq = super().redirect_request(req, fp, code, msg, headers, newurl)
        if nreq is None:
            return None
        if old.netloc != new.netloc:
            for h in list(nreq.headers):
                if h.lower() == "authorization":
                    del nreq.headers[h]
            for h in list(nreq.unredirected_hdrs):
                if h.lower() == "authorization":
                    del nreq.unredirected_hdrs[h]
        return nreq


def parse_sums(text: str) -> dict:
    out = {}
    for line in text.splitlines():
        m = re.match(r"^([0-9a-fA-F]{64})\s+\*?(\S+)$", line.strip())
        if m:
            out[m.group(2)] = m.group(1).lower()
    return out


def select_assets(release: dict) -> tuple[dict, dict, str]:
    assets = {a.get("name"): a for a in release.get("assets", []) if isinstance(a, dict)}
    pkgs = [(ASSET_RE.match(n).group(1), a) for n, a in assets.items() if n and ASSET_RE.match(n)]
    if len(pkgs) != 1:
        raise InstallError(f"Release {release.get('tag_name')!r} must contain exactly one elite-hosting-X.Y.Z.tar.gz asset (found {len(pkgs)}).")
    version, pkg = pkgs[0]
    if release.get("tag_name", "").lstrip("v") != version:
        raise InstallError(f"Release tag {release.get('tag_name')!r} does not match the package version {version}.")
    if SUMS_NAME not in assets:
        raise InstallError(f"Release has no {SUMS_NAME} asset - refusing to install an unverifiable package.")
    return pkg, assets[SUMS_NAME], version


class GitHubClient:
    def __init__(self, repo: str, token: str | None, api_base: str | None = None, opener=None):
        if not REPO_RE.match(repo or ""):
            raise InstallError("Repository must look like OWNER/REPO.")
        self.repo, self.token = repo, token
        base = (api_base or API).rstrip("/")
        host = urllib.parse.urlsplit(base).hostname or ""
        if base != API and not (base.startswith("http://") and f"{host}" in ("127.0.0.1", "localhost", "::1")):
            raise InstallError("A custom API base is only allowed for http://127.0.0.1 (testing).")
        self.base = base
        self.opener = opener or urllib.request.build_opener(_SafeRedirect)

    def _req(self, url: str, accept: str) -> urllib.request.Request:
        headers = {"Accept": accept, "User-Agent": f"elite-installer/{__version__}", "X-GitHub-Api-Version": "2022-11-28"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return urllib.request.Request(url, headers=headers)

    def _open(self, url: str, accept: str, timeout: int = 30):
        try:
            return self.opener.open(self._req(url, accept), timeout=timeout)
        except urllib.error.HTTPError as e:
            raise InstallError(*self._explain(e.code, e.headers)) from None
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            raise InstallError("Could not reach GitHub.", "Check the server's internet access and DNS.") from None

    @staticmethod
    def _explain(code: int, headers) -> tuple[str, str]:
        if code == 401:
            return "GitHub rejected the access token (401).", "Create a fine-grained token with read access to 'Contents' (and metadata) for this repository."
        if code == 403:
            if headers and headers.get("X-RateLimit-Remaining") == "0":
                return "GitHub API rate limit reached (403).", "Wait a while, or use an authenticated token."
            return "GitHub denied access (403).", "The token may lack permission, expired, or need SSO authorisation for the organisation."
        if code == 404:
            return "Repository or release not found (404).", "For private repositories GitHub answers 404 when the token cannot see it. Check OWNER/REPO, that a published (non-draft) release exists, and the token's repository access."
        return f"GitHub returned HTTP {code}.", ""

    def release(self, tag: str | None = None) -> dict:
        if tag is not None and not TAG_RE.match(tag):
            raise InstallError("Invalid release tag.")
        path = f"/repos/{self.repo}/releases/" + (f"tags/{tag}" if tag else "latest")   # 'latest' = newest published, non-prerelease
        with self._open(self.base + path, "application/vnd.github+json") as r:
            data = json.loads(r.read(5_000_000).decode("utf-8"))
        if data.get("draft") or (data.get("prerelease") and not tag):
            raise InstallError("The newest release is a draft/pre-release; no stable release is available.")
        return data

    def asset_url(self, asset: dict) -> str:
        aid = asset.get("id")
        if not isinstance(aid, int):
            raise InstallError("Malformed release asset.")
        return f"{self.base}/repos/{self.repo}/releases/assets/{aid}"

    def download(self, asset: dict, dest, progress=None, max_bytes: int = MAX_ARCHIVE) -> str:
        """Stream an asset to dest, enforcing a size cap; returns its sha256."""
        h, got = hashlib.sha256(), 0
        total = int(asset.get("size") or 0)
        if total > max_bytes:
            raise InstallError("Release asset is unexpectedly large; refusing to download.")
        with self._open(self.asset_url(asset), "application/octet-stream", timeout=60) as r, open(dest, "wb") as out:
            while True:
                chunk = r.read(256 * 1024)
                if not chunk:
                    break
                got += len(chunk)
                if got > max_bytes:
                    raise InstallError("Download exceeded the size limit; aborting.")
                h.update(chunk)
                out.write(chunk)
                if progress and total:
                    progress(min(got / total, 1.0), got, total)
        if total and got != total:
            raise InstallError("Download was truncated; try again.")
        return h.hexdigest()

    def download_text(self, asset: dict, limit: int = 200_000) -> str:
        with self._open(self.asset_url(asset), "application/octet-stream") as r:
            return r.read(limit).decode("utf-8", "replace")


def verify_digest(actual: str, *, sums: dict | None, name: str, github_digest: str | None, pinned: str | None) -> None:
    """Every available reference hash must agree with the downloaded file."""
    refs = []
    if sums is not None:
        if name not in sums:
            raise InstallError(f"{SUMS_NAME} does not list {name}.")
        refs.append(("SHA256SUMS", sums[name]))
    if github_digest and github_digest.startswith("sha256:"):
        refs.append(("GitHub asset digest", github_digest[7:].lower()))
    if pinned:
        refs.append(("--sha256 pin", pinned.lower()))
    if not refs:
        raise InstallError("No checksum available to verify the package.")
    for label, want in refs:
        if want != actual:
            raise InstallError(f"Checksum mismatch ({label}) - the package was NOT installed.",
                               f"expected {want[:12]}…, got {actual[:12]}…")
