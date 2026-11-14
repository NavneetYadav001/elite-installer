"""Safe extraction and static validation of a downloaded release. Nothing from the archive is executed here."""
from __future__ import annotations

import os
import re
import tarfile
from pathlib import Path, PurePosixPath

from .core import InstallError

MAX_FILES, MAX_TOTAL, MAX_FILE = 20000, 600 * 1024 * 1024, 100 * 1024 * 1024
REQUIRED = ["wsgi.py", "gunicorn.conf.py", "requirements.txt", "VERSION", "elite_hosting/__init__.py",
            "deploy/elite-hosting-helper", "deploy/elite-hosting-admin", "deploy/elite-hosting.service",
            "deploy/elite-hosting-helper.service", "deploy/logrotate-elite-hosting"]
REQ_LINE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*(\[[A-Za-z0-9,_-]+\])?\s*((==|>=|<=|~=|!=|<|>)\s*[0-9][A-Za-z0-9.*+!-]*\s*,?\s*)*(;\s*[A-Za-z0-9_. '\"<>=!]+)?$")


def _clean(name: str) -> PurePosixPath:
    if not name or "\x00" in name or "\\" in name or name.startswith("/") or re.match(r"^[A-Za-z]:", name):
        raise InstallError(f"Unsafe path in archive: {name!r}")
    p = PurePosixPath(name)
    if any(part in ("..",) for part in p.parts):
        raise InstallError(f"Unsafe path in archive: {name!r}")
    return p


def safe_extract(archive: Path, dest: Path) -> Path:
    """Extract into dest (must be empty/new) and return the project root. Rejects links, devices and path tricks."""
    dest.mkdir(parents=True, exist_ok=True)
    try:
        tf = tarfile.open(archive, "r:gz")
    except (tarfile.TarError, OSError, EOFError) as exc:
        raise InstallError("The release package is not a valid .tar.gz file.") from exc
    with tf:
        members, seen, total, top = [], set(), 0, set()
        for m in tf:
            p = _clean(m.name)
            if m.isdir():
                pass
            elif m.isreg():
                if m.size > MAX_FILE:
                    raise InstallError(f"Archive member too large: {m.name}")
                total += m.size
            else:
                raise InstallError(f"Archive contains a link or special file ({m.name}); refusing.")
            if str(p) in seen:
                raise InstallError(f"Duplicate archive entry: {m.name}")
            seen.add(str(p))
            parts = [x for x in p.parts if x != "."]
            if not parts:
                continue
            top.add(parts[0])
            m.mode = (m.mode & 0o755) | 0o600 if m.isreg() else 0o755
            m.uid = m.gid = 0
            m.uname = m.gname = ""
            members.append(m)
            if len(members) > MAX_FILES or total > MAX_TOTAL:
                raise InstallError("Archive is too large or has too many files.")
        if len(top) != 1:
            raise InstallError("Archive must contain exactly one top-level project folder.")
        try:
            tf.extractall(dest, members=members, filter="data")
        except (tarfile.TarError, OSError) as exc:
            raise InstallError(f"Could not extract the package safely: {exc}") from exc
    root = dest / top.pop()
    if not root.is_dir():
        raise InstallError("Archive must contain a project folder, not a single file.")
    return root


def validate_requirements(text: str) -> list[str]:
    """Only plain 'name>=x,<y' lines: no URLs, VCS, local paths, includes or index options."""
    lines = []
    for raw in text.splitlines():
        line = raw.split(" #")[0].strip()
        if not line or line.startswith("#"):
            continue
        if not REQ_LINE.match(line):
            raise InstallError(f"requirements.txt contains a disallowed line: {line[:60]!r}")
        lines.append(line)
    if not lines:
        raise InstallError("requirements.txt is empty.")
    return lines


def validate_units(app_unit: str, helper_unit: str) -> None:
    def execs(text, key):
        return [l.split("=", 1)[1].strip() for l in text.splitlines() if l.startswith(key + "=")]
    if execs(app_unit, "ExecStart") != ["/opt/elite-hosting/venv/bin/gunicorn --config /opt/elite-hosting/gunicorn.conf.py wsgi:app"]:
        raise InstallError("elite-hosting.service has an unexpected ExecStart; refusing to install it.")
    if execs(helper_unit, "ExecStart") != ["/usr/bin/python3 /usr/local/sbin/elite-hosting-helper serve"]:
        raise InstallError("elite-hosting-helper.service has an unexpected ExecStart; refusing to install it.")
    for text, name in ((app_unit, "app"), (helper_unit, "helper")):
        for key in ("ExecStartPre", "ExecStartPost", "ExecStop", "ExecStopPost", "ExecReload"):
            if execs(text, key):
                raise InstallError(f"The {name} unit defines {key}, which is not allowed.")
        user = execs(text, "User")
        if name == "app" and user != ["elitehost"]:
            raise InstallError("The app unit must run as the unprivileged 'elitehost' user.")


def validate_layout(root: Path) -> str:
    """Static checks only (no execution). Returns the project version."""
    for rel in REQUIRED:
        f = root / rel
        if not f.is_file() or f.is_symlink():
            raise InstallError(f"Release is missing {rel}.")
    version = (root / "VERSION").read_text().strip()
    if not re.match(r"^\d+\.\d+\.\d+$", version):
        raise InstallError(f"Invalid VERSION file: {version!r}")
    validate_requirements((root / "requirements.txt").read_text())
    validate_units((root / "deploy/elite-hosting.service").read_text(), (root / "deploy/elite-hosting-helper.service").read_text())
    helper = (root / "deploy/elite-hosting-helper").read_text()
    if not helper.startswith("#!/usr/bin/env python3") and not helper.startswith("#!/usr/bin/python3"):
        raise InstallError("deploy/elite-hosting-helper is not a Python script.")
    if not (root / "deploy/elite-hosting-admin").read_text().startswith(("#!/bin/bash", "#!/usr/bin/env bash")):
        raise InstallError("deploy/elite-hosting-admin is not a bash script.")
    for path in list(root.rglob("*.py")) + [root / "deploy/elite-hosting-helper"]:
        try:
            compile(path.read_text(encoding="utf-8"), str(path), "exec")     # syntax only; never executed
        except (SyntaxError, ValueError, UnicodeDecodeError) as exc:
            raise InstallError(f"Python syntax error in {path.relative_to(root)}: {exc}") from None
    return version


def version_tuple(v: str) -> tuple:
    return tuple(int(x) for x in v.split("."))
