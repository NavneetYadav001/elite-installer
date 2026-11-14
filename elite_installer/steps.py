"""Install / update / uninstall logic. Every system change is recorded in the journal so a failure can be undone."""
from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import tempfile
import time
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from . import archive, github
from .core import Context, InstallError

APT_PACKAGES = ["python3", "python3-venv", "python3-pip", "python3-dev", "build-essential", "nginx", "certbot", "sqlite3",
                "git", "curl", "ca-certificates", "openssl", "rsync", "unzip", "acl", "iproute2", "gnupg"]
CODE_FILES = ["wsgi.py", "gunicorn.conf.py", "requirements.txt", "VERSION", "README.md"]
DB_BACKUP_SCRIPT = ("import sqlite3,sys\n"
                    "s=sqlite3.connect(sys.argv[1]);d=sqlite3.connect(sys.argv[2]);s.backup(d);d.close();s.close()")
BOOT_CHECK_SCRIPT = ("import sys\nsys.path.insert(0,sys.argv[1])\n"
                     "from elite_hosting import create_app\n"
                     "c=create_app().test_client()\n"
                     "assert c.get('/healthz').status_code==200, 'health endpoint failed'\n"
                     "print('boot-ok')")


@dataclass
class Staged:
    root: Path
    version: str
    source: str
    tmp: Path | None = None


def parse_env_file(path: Path) -> dict:
    out = {}
    for line in path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip()
    return out


# ============================================================================================ obtaining the package
def resolve_token(ctx: Context) -> str | None:
    o = ctx.opts
    token = None
    if o.token_file:
        p = Path(o.token_file)
        if not p.is_file():
            raise InstallError(f"Token file not found: {o.token_file}")
        if p.stat().st_mode & 0o077:
            ctx.ui.warn(f"{o.token_file} is readable by other users; run: chmod 600 {o.token_file}")
        token = p.read_text().strip()
    elif os.environ.get("ELITE_GITHUB_TOKEN"):
        token = os.environ["ELITE_GITHUB_TOKEN"].strip()
    elif ctx.paths.SAVED_TOKEN.is_file():
        token = ctx.paths.SAVED_TOKEN.read_text().strip()
    elif ctx.ui.interactive:
        token = ctx.ui.secret("GitHub access token (input hidden): ").strip()
    if not token:
        raise InstallError("A GitHub access token is required for the private repository.",
                           "Use --token-file FILE, or export ELITE_GITHUB_TOKEN, or run interactively. (The token is never accepted on the command line.)")
    ctx.redactor.add(token)
    ctx.token = token
    return token


def load_state(ctx: Context) -> dict:
    try:
        return json.loads(ctx.paths.STATE.read_text())
    except (OSError, ValueError):
        return {}


def resolve_repo(ctx: Context) -> str:
    repo = ctx.opts.repo or os.environ.get("ELITE_GITHUB_REPO") or load_state(ctx).get("repo")
    if not repo:
        raise InstallError("No source given.", "Use --github OWNER/REPO (your private repository), --archive FILE or --source DIR.")
    return repo


def stage_package(ctx: Context) -> Staged:
    """Download (or open) the package, verify it, extract it safely and validate it statically."""
    ui, o = ctx.ui, ctx.opts
    tmp_base = ctx.paths.p("/var/tmp")
    tmp_base.mkdir(parents=True, exist_ok=True)
    tmp = Path(tempfile.mkdtemp(prefix="elite-installer-", dir=tmp_base))
    os.chmod(tmp, 0o700)
    ctx.journal.add("remove temporary files", lambda: shutil.rmtree(tmp, ignore_errors=True))
    ctx.extra["tmp"] = tmp

    if o.source:
        root = Path(o.source).resolve()
        if not root.is_dir():
            raise InstallError(f"Source directory not found: {o.source}")
        ui.warn("Installing from a local directory: not checksum-verified.")
        return Staged(root, archive.validate_layout(root), f"directory {root}", tmp)

    if o.archive:
        pkg = Path(o.archive)
        if not pkg.is_file():
            raise InstallError(f"Archive not found: {o.archive}")
        import hashlib
        digest = hashlib.sha256(pkg.read_bytes()).hexdigest()
        if o.sha256:
            github.verify_digest(digest, sums=None, name=pkg.name, github_digest=None, pinned=o.sha256)
        else:
            ui.warn(f"Local archive is unverified (sha256 {digest[:16]}…). Use --sha256 to pin it.")
        ui.status("extracting")
        root = archive.safe_extract(pkg, tmp / "src")
        return Staged(root, archive.validate_layout(root), f"archive {pkg.name}", tmp)

    repo = resolve_repo(ctx)
    client = github.GitHubClient(repo, resolve_token(ctx), api_base=o.api_base)
    ui.status("querying latest release")
    rel = client.release(o.tag)
    pkg_asset, sums_asset, version = github.select_assets(rel)
    ctx.log.info(f"release {rel.get('tag_name')} asset {pkg_asset['name']} ({pkg_asset.get('size')} bytes)")
    sums = github.parse_sums(client.download_text(sums_asset))
    dest = tmp / pkg_asset["name"]

    def prog(frac, got, total):
        ui.progress(frac)
        ui.status(f"{pkg_asset['name']}  {got // 1024} / {total // 1024} KB")

    digest = client.download(pkg_asset, dest, progress=prog)
    ui.progress(0)
    ui.status("verifying checksum")
    github.verify_digest(digest, sums=sums, name=pkg_asset["name"], github_digest=pkg_asset.get("digest"), pinned=o.sha256)
    ctx.log.info(f"sha256 verified: {digest}")
    ui.status("extracting")
    root = archive.safe_extract(dest, tmp / "src")
    found = archive.validate_layout(root)
    if found != version:
        raise InstallError(f"Package VERSION ({found}) does not match the release ({version}).")
    ctx.extra["repo"] = repo
    return Staged(root, version, f"GitHub release {rel.get('tag_name')}", tmp)


# ============================================================================================ deployment
class Deployment:
    def __init__(self, ctx: Context, staged: Staged):
        self.ctx, self.st, self.P, self.R = ctx, staged, ctx.paths, ctx.runner
        self.stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
        self.run_dir = self.P.BACKUP / f"installer-{self.stamp}"
        self.health = self._health
        self.wait_socket = self._wait_socket
        self.admin_password: str | None = None
        self.admin_user = ctx.opts.admin_user
        self.updating = (self.P.INSTALL / "venv" / "bin" / "python").exists()
        self.old_version = (self.P.INSTALL / "VERSION").read_text().strip() if (self.P.INSTALL / "VERSION").exists() else None
        self.venv_py = str(self.P.INSTALL / "venv" / "bin" / "python")
        self.had_data_dir = self.P.DATA.exists()

    # ---------------------------------------------------------------- small helpers
    def run(self, cmd, **kw):
        kw.setdefault("on_line", self.ctx.ui.status)
        return self.R.run(cmd, **kw)

    def _stash(self, path: Path) -> Path:
        self.run_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.run_dir, 0o700)
        return self.run_dir / str(path).strip("/").replace("/", "__")

    def put(self, src: Path, dst: Path, mode: int, owner=("root", "root")) -> None:
        """Atomically install a file; remember how to put the old state back."""
        if dst.exists() or dst.is_symlink():
            keep = self._stash(dst)
            shutil.copy2(dst, keep)
            self.ctx.journal.add(f"restore {dst}", lambda d=dst, k=keep: shutil.copy2(k, d))
        else:
            self.ctx.journal.add(f"remove {dst}", lambda d=dst: d.unlink(missing_ok=True))
        dst.parent.mkdir(parents=True, exist_ok=True)
        tmp = dst.with_name(dst.name + ".elite-new")
        shutil.copyfile(src, tmp)
        os.chmod(tmp, mode)
        self.ctx.chown(tmp, *owner)
        os.replace(tmp, dst)

    def ensure_dir(self, path: Path, mode: int, owner="root", group="root") -> None:
        if not path.exists():
            self.ctx.journal.add(f"remove directory {path}", lambda p=path: shutil.rmtree(p, ignore_errors=True))
            path.mkdir(parents=True)
        os.chmod(path, mode)
        self.ctx.chown(path, owner, group)

    def service_active(self, unit: str) -> bool:
        return self.R.run(["systemctl", "is-active", "--quiet", unit], check=False).code == 0

    # ---------------------------------------------------------------- steps
    def step_packages(self):
        env = {"DEBIAN_FRONTEND": "noninteractive", "NEEDRESTART_MODE": "a"}
        apt = ["apt-get", "-o", "DPkg::Lock::Timeout=180", "-y", "-qq"]
        self.run(apt + ["update"], env=env)
        self.run(apt + ["install", "--no-install-recommends"] + APT_PACKAGES, env=env)
        self._apt, self._env = apt, env

    def step_docker(self):
        o, ui = self.ctx.opts, self.ctx.ui
        if self.R.run(["docker", "--version"], check=False).code == 0:
            ui.status("Docker already installed")
        elif o.skip_docker:
            ui.warn("Docker is not installed and --skip-docker-install was given; install Docker yourself.")
            return
        else:
            try:
                self._docker_official()
            except InstallError as exc:
                self.ctx.log.warn(f"official Docker repository failed: {exc}")
                ui.warn("Official Docker repository failed; using Ubuntu's docker.io package.")
                self.P.p("/etc/apt/sources.list.d/docker.list").unlink(missing_ok=True)
                self.run(self._apt + ["update"], env=self._env)
                self.run(self._apt + ["install", "docker.io"], env=self._env)
        self.run(["systemctl", "enable", "--now", "docker"], check=False)

    def _docker_official(self):
        env, apt = self._env, self._apt
        key = self.P.p("/etc/apt/keyrings/docker.asc")
        key.parent.mkdir(parents=True, exist_ok=True)
        self.run(["curl", "-fsSL", "--proto", "=https", "--tlsv1.2", "https://download.docker.com/linux/ubuntu/gpg", "-o", str(key)])
        os.chmod(key, 0o644)
        arch = self.R.run(["dpkg", "--print-architecture"]).out.strip() or "amd64"
        codename = self.ctx.extra.get("codename") or "noble"
        lst = self.P.p("/etc/apt/sources.list.d/docker.list")
        lst.write_text(f"deb [arch={arch} signed-by={key}] https://download.docker.com/linux/ubuntu {codename} stable\n")
        self.run(apt + ["update"], env=env)
        self.run(apt + ["install", "docker-ce", "docker-ce-cli", "containerd.io", "docker-buildx-plugin"], env=env)

    def step_account(self):
        P, svc = self.P, self.P.svc_user
        if self.R.run(["id", "-u", svc], check=False).code != 0:
            self.run(["useradd", "--system", "--user-group", "--home-dir", f"{P.data_dir}/home", "--no-create-home",
                      "--shell", "/usr/sbin/nologin", svc])
            self.ctx.journal.add(f"remove user {svc}", lambda: self.R.run(["userdel", svc], check=False))
        if self.R.run(["getent", "group", "docker"], check=False).code == 0:
            self.run(["usermod", "-aG", "docker", svc])
        D = P.DATA
        self.ensure_dir(D, 0o751, svc, svc)
        self.ensure_dir(D / "storage", 0o751, svc, svc)
        for name in ("db", "tmp"):
            self.ensure_dir(D / name, 0o700, svc, svc)
        for name in ("home", "deploy-logs"):
            self.ensure_dir(D / name, 0o750, svc, svc)
        self.ensure_dir(D / "storage" / "sites", 0o2750, svc, "www-data" if self.ctx.real else svc)
        for name in ("apps", "bots", "files"):
            self.ensure_dir(D / "storage" / name, 0o750, svc, svc)
        self.ensure_dir(P.LOG, 0o750, svc, svc)
        self.ensure_dir(P.ETC, 0o750, "root", svc)
        self.ensure_dir(P.INSTALL, 0o755)
        self.ensure_dir(P.STATE_DIR, 0o755)

    def step_code(self):
        P, root = self.P, self.st.root
        dst = P.INSTALL / "elite_hosting"
        old = None
        if dst.exists():
            old = P.INSTALL / f"elite_hosting.old-{self.stamp}"
            os.replace(dst, old)
        shutil.copytree(root / "elite_hosting", dst, symlinks=False, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        for base, dirs, files in os.walk(dst):
            os.chmod(base, 0o755)
            self.ctx.chown(Path(base), "root", "root")
            for f in files:
                os.chmod(Path(base, f), 0o644)
                self.ctx.chown(Path(base, f), "root", "root")

        def undo():
            shutil.rmtree(dst, ignore_errors=True)
            if old is not None and old.exists():
                os.replace(old, dst)

        self.ctx.journal.add("restore previous application code", undo)
        self.ctx.extra["old_code"] = old
        for name in CODE_FILES:
            if (root / name).is_file():
                self.put(root / name, P.INSTALL / name, 0o644)

    def step_venv(self):
        P = self.P
        venv = P.INSTALL / "venv"
        if not (venv / "bin" / "python").exists():
            self.ctx.journal.add("remove virtual environment", lambda: shutil.rmtree(venv, ignore_errors=True))
            self.run(["python3", "-m", "venv", str(venv)])
        pip = [str(venv / "bin" / "pip"), "install", "--disable-pip-version-check", "--no-input", "--quiet"]
        old_req = self.run_dir / "requirements.previous.txt"
        if self.updating and (self.P.INSTALL / "requirements.txt").exists():
            self.run_dir.mkdir(parents=True, exist_ok=True)
            shutil.copy2(self.P.INSTALL / "requirements.txt", old_req)
            old_copy = old_req
            self.ctx.journal.add("reinstall previous Python dependencies",
                                 lambda: self.R.run(pip + ["--only-binary=:all:", "-r", str(old_copy)], check=False))
        self.run(pip + ["--upgrade", "pip", "wheel"])
        # wheels only: a package's build script (setup.py) is never executed on this server
        self.run(pip + ["--only-binary=:all:", "-r", str(P.INSTALL / "requirements.txt")])
        for p in (venv,):
            if self.ctx.real:
                self.R.run(["chown", "-R", "root:root", str(p)], check=False)

    def step_config(self):
        P = self.P
        if P.ENV_FILE.exists():
            self.ctx.ui.status("keeping existing configuration")
            return
        if (P.DATA / "db").is_dir() and any((P.DATA / "db").glob("*.db")) and not self.ctx.opts.force:
            raise InstallError("A database exists but its environment file (with the encryption key) is missing.",
                               f"Restore {P.ENV_FILE} from your backup. Generating a new key would make stored secrets unreadable. "
                               "If you accept that, re-run with --force.")
        body = ("# ELITE HOSTING configuration. Keep this file private: ELITE_SECRET_KEY signs sessions and encrypts stored secrets.\n"
                "# Losing it means stored API keys / environment variables can no longer be decrypted - back it up.\n"
                f"ELITE_SECRET_KEY={secrets.token_hex(32)}\nELITE_DATA={P.data_dir}\nELITE_LOG_DIR={P.log_dir}\n"
                f"ELITE_BIND={P.panel_bind}\nELITE_HELPER=/run/elite-hosting/helper.sock\n"
                "# auto = session cookie is Secure whenever the page is served over HTTPS\nELITE_COOKIE_SECURE=auto\n")
        self.ctx.journal.add("remove generated configuration", lambda: P.ENV_FILE.unlink(missing_ok=True))
        fd = os.open(P.ENV_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(body)
        os.chmod(P.ENV_FILE, 0o640)
        self.ctx.chown(P.ENV_FILE, "root", P.svc_user)

    def step_services(self):
        P, d = self.P, self.st.root / "deploy"
        self.updating_units = {u: self.service_active(u) for u in ("elite-hosting", "elite-hosting-helper")} if self.ctx.real else {}
        self.put(d / "elite-hosting-helper", P.HELPER, 0o750)
        self.put(d / "elite-hosting-admin", P.ADMIN, 0o755)
        self.put(d / "elite-hosting.service", P.UNIT_APP, 0o644)
        self.put(d / "elite-hosting-helper.service", P.UNIT_HELPER, 0o644)
        self.put(d / "logrotate-elite-hosting", P.LOGROTATE, 0o644)
        self.run(["systemctl", "daemon-reload"])

    def step_validate(self):
        """Everything is checked before any service is (re)started."""
        P, svc = self.P, self.P.svc_user
        self.run([self.venv_py, "-m", "compileall", "-q", str(P.INSTALL / "elite_hosting")])
        res = self.R.run(["systemd-analyze", "verify", str(P.UNIT_APP), str(P.UNIT_HELPER)], check=False)
        if res.code != 0:
            self.ctx.ui.warn("systemd-analyze reported issues with the unit files (see the log).")
        self.R.run(["bash", "-n", str(P.ADMIN)])
        scratch = P.DATA / "tmp" / f"validate-{secrets.token_hex(4)}"
        scratch.mkdir(parents=True)
        self.ctx.chown(scratch, svc, svc)
        try:
            env = {"ELITE_SECRET_KEY": parse_env_file(P.ENV_FILE).get("ELITE_SECRET_KEY", secrets.token_hex(32)),
                   "ELITE_DATA": str(scratch), "ELITE_LOG_DIR": str(scratch), "ELITE_COOKIE_SECURE": "0",
                   "ELITE_HELPER": str(scratch / "none.sock"), "HOME": str(scratch)}
            self.ctx.redactor.add(env["ELITE_SECRET_KEY"])
            cmd = [self.venv_py, "-I", "-c", BOOT_CHECK_SCRIPT, str(P.INSTALL)]
            if self.ctx.real:
                cmd = ["runuser", "-m", "-u", svc, "--"] + cmd
            self.run(cmd, env=env, cwd="/")
        finally:
            shutil.rmtree(scratch, ignore_errors=True)
        if self.R.run(["nginx", "-v"], check=False).code == 0:
            self.run(["nginx", "-t"])

    def backup_database(self):
        P, svc = self.P, self.P.svc_user
        dbs = sorted((P.DATA / "db").glob("*.db")) if (P.DATA / "db").is_dir() else []
        if not dbs:
            return
        self.run_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.run_dir, 0o700)
        for db in dbs:
            scratch = P.DATA / "tmp" / f"{db.stem}.bak-{self.stamp}"
            cmd = [self.venv_py, "-I", "-c", DB_BACKUP_SCRIPT, str(db), str(scratch)]
            if self.ctx.real:
                cmd = ["runuser", "-u", svc, "--"] + cmd
            self.run(cmd)
            kept = self.run_dir / db.name
            shutil.move(str(scratch), kept)
            os.chmod(kept, 0o600)
            self.ctx.log.info(f"database backed up: {kept}")

            def restore(db=db, kept=kept):
                self.R.run(["systemctl", "stop", "elite-hosting"], check=False)
                for ext in ("", "-wal", "-shm"):
                    Path(str(db) + ext).unlink(missing_ok=True)
                shutil.copy2(kept, db)
                os.chmod(db, 0o600)
                self.ctx.chown(db, svc, svc)

            self.ctx.journal.add(f"restore database {db.name}", restore)
        self.ctx.extra["db_backup"] = self.run_dir

    def step_database(self):
        admin = str(self.P.ADMIN)
        self.run([admin, "init-db"])
        if self.R.run([admin, "has-users"], check=False).code == 0:
            self.ctx.ui.status("existing users found; no new admin created")
            return
        if not re.match(r"^[A-Za-z0-9._-]{3,32}$", self.admin_user):
            raise InstallError("--admin-user must be 3-32 characters (letters, digits, . _ -).")
        res = self.R.run([admin, "create-admin", "--username", self.admin_user, "--generate"], log_output=False)
        m = re.search(r"^GENERATED_PASSWORD=(.+)$", res.out, re.M)
        if not m:
            raise InstallError("The administrator account could not be created.")
        self.admin_password = m.group(1).strip()
        self.ctx.redactor.add(self.admin_password)

    def step_nginx(self):
        P, svc = self.P, self.P.svc_user
        default = P.p("/etc/nginx/sites-enabled/default")
        if default.is_symlink():
            target = os.readlink(default)
            default.unlink()
            self.ctx.journal.add("re-enable nginx default site", lambda: default.symlink_to(target))
        self.run(["systemctl", "enable", "nginx"])
        hook = P.p("/etc/letsencrypt/renewal-hooks/deploy/elite-hosting-reload-nginx.sh")
        hook.parent.mkdir(parents=True, exist_ok=True)
        if not hook.exists():
            self.ctx.journal.add("remove certbot reload hook", lambda: hook.unlink(missing_ok=True))
            hook.write_text("#!/bin/sh\nsystemctl reload nginx\n")
            os.chmod(hook, 0o755)
        self.R.run(["systemctl", "enable", "--now", "certbot.timer"], check=False)
        if self.R.run(["setfacl", "-m", f"u:{svc}:rx", "/var/log/nginx"], check=False).code == 0:
            self.R.run(["setfacl", "-d", "-m", f"u:{svc}:r", "/var/log/nginx"], check=False)
            self.R.run(["bash", "-c", f"find /var/log/nginx -maxdepth 1 -type f -exec setfacl -m u:{svc}:r {{}} +"], check=False)
        else:
            self.ctx.ui.warn("Could not set ACLs on /var/log/nginx; nginx logs will not show in the panel.")
        self.run(["nginx", "-t"])        # validate before nginx is started or reloaded
        self.run(["systemctl", "start", "nginx"])

    def _wait_socket(self, seconds=30) -> bool:
        for _ in range(seconds):
            if self.P.HELPER_SOCK.exists():
                return True
            time.sleep(1)
        return False

    def _health(self, seconds=40) -> bool:
        url = f"http://{self.P.panel_bind}/healthz"
        for _ in range(seconds):
            try:
                with urllib.request.urlopen(url, timeout=2) as r:
                    if r.status == 200:
                        return True
            except OSError:
                pass
            time.sleep(1)
        return False

    def step_start(self):
        was = getattr(self, "updating_units", {})
        self.run(["systemctl", "enable", "elite-hosting-helper", "elite-hosting"])
        self.ctx.journal.add("stop and disable services",
                             lambda: [self.R.run(["systemctl", "disable", "--now", u], check=False) for u in ("elite-hosting", "elite-hosting-helper")]
                             if not self.updating else
                             [self.R.run(["systemctl", "restart", u], check=False) for u, a in was.items() if a])
        self.run(["systemctl", "restart", "elite-hosting-helper"])
        if not self.wait_socket():
            tail = self.R.run(["journalctl", "-u", "elite-hosting-helper", "-n", "20", "--no-pager"], check=False).out
            raise InstallError("The privileged helper did not start.", tail.strip()[-800:])
        self.run(["systemctl", "restart", "elite-hosting"])
        if not self.health():
            tail = self.R.run(["journalctl", "-u", "elite-hosting", "-n", "25", "--no-pager"], check=False).out
            raise InstallError("The panel did not become healthy.", tail.strip()[-800:])
        if self.ctx.opts.ufw:
            self._ufw()

    def _ufw(self):
        if self.R.run(["which", "ufw"], check=False).code != 0:
            self.run(self._apt + ["install", "ufw"], env=self._env)
        out = self.R.run(["sshd", "-T"], check=False).out
        ports = sorted(set(re.findall(r"^port (\d+)$", out, re.M))) or ["22"]
        for p in ports:
            self.run(["ufw", "allow", f"{p}/tcp"])
        self.run(["ufw", "allow", "80/tcp"])
        self.run(["ufw", "allow", "443/tcp"])
        self.run(["ufw", "--force", "enable"])

    def finalize(self):
        P = self.P
        for item in (self.ctx.extra.get("old_code"),):
            if item and Path(item).exists():
                shutil.rmtree(item, ignore_errors=True)
        state = load_state(self.ctx)
        state.update({"installed_version": self.st.version, "installed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                      "source": self.st.source})
        repo = self.ctx.extra.get("repo")
        if repo:
            state["repo"] = repo
        P.STATE_DIR.mkdir(parents=True, exist_ok=True)
        P.STATE.write_text(json.dumps(state, indent=2) + "\n")
        if self.ctx.opts.save_token and self.ctx.token:
            fd = os.open(P.SAVED_TOKEN, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as fh:
                fh.write(self.ctx.token + "\n")
        lr = P.p("/etc/logrotate.d/elite-installer")
        lr.write_text("/var/log/elite-installer/*.log {\n    weekly\n    rotate 8\n    compress\n    missingok\n    notifempty\n    create 0600 root root\n}\n")

    def server_ip(self) -> str:
        out = self.R.run(["ip", "-4", "route", "get", "1.1.1.1"], check=False).out
        m = re.search(r"\bsrc (\S+)", out)
        if m:
            return m.group(1)
        out = self.R.run(["hostname", "-I"], check=False).out.split()
        return out[0] if out else "<server-ip>"


# ============================================================================================ orchestration
def run_steps(ctx: Context, steps: list) -> None:
    ui = ctx.ui
    ui.begin(len(steps))
    for title, fn in steps:
        ui.step_start(title)
        ctx.log.info(f"== {title}")
        try:
            fn()
        except BaseException:
            ui.step_end(False)
            raise
        ui.step_end(True)


def install_plan(ctx: Context, dep: Deployment, update: bool) -> list:
    steps = [
        ("Installing system packages", dep.step_packages),
        ("Installing Docker", dep.step_docker),
        ("Preparing service account and directories", dep.step_account),
    ]
    if update or dep.updating:
        steps.append(("Backing up database", dep.backup_database))
    steps += [
        ("Installing application files", dep.step_code),
        ("Building Python environment", dep.step_venv),
        ("Writing configuration", dep.step_config),
        ("Installing helper and systemd services", dep.step_services),
        ("Validating configuration", dep.step_validate),
        ("Preparing database", dep.step_database),
        ("Configuring nginx and certificates", dep.step_nginx),
        ("Starting services", dep.step_start),
    ]
    return steps


def uninstall(ctx: Context) -> None:
    P, R, ui = ctx.paths, ctx.runner, ctx.ui
    purge = ctx.opts.purge
    R.run(["systemctl", "disable", "--now", "elite-hosting", "elite-hosting-helper"], check=False)
    for f in (P.UNIT_APP, P.UNIT_HELPER, P.HELPER, P.ADMIN, P.LOGROTATE):
        f.unlink(missing_ok=True)
    R.run(["systemctl", "daemon-reload"], check=False)
    for sub in ("sites-enabled", "sites-available"):
        for f in P.p(f"/etc/nginx/{sub}").glob("elite-*.conf"):
            f.unlink()
    P.p("/etc/nginx/conf.d/elite-hosting.conf").unlink(missing_ok=True)
    if R.run(["nginx", "-t"], check=False).code == 0:
        R.run(["systemctl", "reload", "nginx"], check=False)
    else:
        ui.warn("nginx -t failed after cleanup; check your nginx configuration manually.")
    shutil.rmtree(P.p("/var/www/elite-acme"), ignore_errors=True)
    P.p("/etc/letsencrypt/renewal-hooks/deploy/elite-hosting-reload-nginx.sh").unlink(missing_ok=True)
    shutil.rmtree(P.INSTALL, ignore_errors=True)
    if purge:
        if R.run(["docker", "--version"], check=False).code == 0:
            R.run(["bash", "-c", "docker ps -aq --filter label=elite.managed=true | xargs -r docker rm -f"], check=False)
            R.run(["bash", "-c", "docker ps -a --format '{{.Names}}' | grep -E '^elite-(app|bot|ai)-' | xargs -r docker rm -f"], check=False)
            R.run(["bash", "-c", "docker images --format '{{.Repository}}:{{.Tag}}' | grep -E '^elite-(app|bot)-' | xargs -r docker rmi -f"], check=False)
            R.run(["bash", "-c", "docker volume ls -q | grep -E '^elite-' | xargs -r docker volume rm -f"], check=False)
        for d in (P.DATA, P.LOG, P.ETC, P.BACKUP, P.STATE_DIR):
            shutil.rmtree(d, ignore_errors=True)
        if R.run(["id", "-u", P.svc_user], check=False).code == 0:
            R.run(["userdel", P.svc_user], check=False)
