"""Shared plumbing: secret redaction, logging, command runner (no shell), rollback journal, paths and options."""
from __future__ import annotations

import collections
import os
import re
import shlex
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

TOKEN_PATTERNS = [
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(r"(?i)(authorization:\s*(?:bearer|token)\s+)\S+"),
    re.compile(r"(?i)((?:password|passwd|secret|token|api[_-]?key)\s*[=:]\s*)\S+"),
    re.compile(r"(GENERATED_PASSWORD=)\S+"),
]
SECRET_ENV = ("ELITE_GITHUB_TOKEN", "GITHUB_TOKEN", "GH_TOKEN")


class InstallError(Exception):
    """A failure with a message that is safe and useful to show to the person installing."""

    def __init__(self, message: str, hint: str = ""):
        super().__init__(message)
        self.hint = hint


class CommandError(InstallError):
    def __init__(self, display: str, code: int, tail: list[str]):
        super().__init__(f"command failed (exit {code}): {display}")
        self.code, self.tail = code, tail


class Redactor:
    """Removes every registered secret (and anything shaped like a token) from text before it is shown or logged."""

    def __init__(self):
        self._secrets: set[str] = set()

    def add(self, secret: str | None) -> None:
        if secret and len(secret) >= 6:
            self._secrets.add(secret)

    def scrub(self, text: str) -> str:
        for s in sorted(self._secrets, key=len, reverse=True):
            text = text.replace(s, "***")
        for pat in TOKEN_PATTERNS:
            text = pat.sub(lambda m: (m.group(1) + "***") if m.groups() else "***", text)
        return text


class Log:
    def __init__(self, path: Path | None, redactor: Redactor):
        self.redactor = redactor
        self._fh = None
        self._lock = threading.Lock()
        if path is not None:
            path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            self._fh = os.fdopen(fd, "a", encoding="utf-8", errors="replace")

    def write(self, level: str, message: str) -> None:
        if self._fh is None:
            return
        stamp = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
        with self._lock:
            for line in self.redactor.scrub(message).splitlines() or [""]:
                self._fh.write(f"{stamp}Z {level:<5} {line}\n")
            self._fh.flush()

    def info(self, m: str) -> None: self.write("INFO", m)
    def warn(self, m: str) -> None: self.write("WARN", m)
    def error(self, m: str) -> None: self.write("ERROR", m)

    def close(self) -> None:
        if self._fh:
            self._fh.close()
            self._fh = None


@dataclass
class Result:
    code: int
    out: str = ""


class Runner:
    """Runs argument lists only (never through a shell). Output is logged after redaction."""

    def __init__(self, log: Log, redactor: Redactor):
        self.log, self.redactor = log, redactor
        self.history: list[list[str]] = []

    def display(self, cmd: list[str]) -> str:
        return self.redactor.scrub(" ".join(shlex.quote(c) for c in cmd))

    def run(self, cmd: list[str], *, check: bool = True, env: dict | None = None, input_text: str | None = None,
            timeout: int | None = 900, log_output: bool = True, on_line=None, cwd: str | None = None) -> Result:
        if not isinstance(cmd, list) or not all(isinstance(c, str) for c in cmd):
            raise TypeError("commands must be lists of strings")
        self.history.append(cmd)
        self.log.info("$ " + self.display(cmd))
        tail: collections.deque[str] = collections.deque(maxlen=40)
        code, out = self._exec(cmd, env, input_text, timeout, log_output, on_line, cwd, tail)
        if code != 0:
            self.log.warn(f"exit status {code}")
            if check:
                raise CommandError(self.display(cmd), code, list(tail))
        return Result(code, out)

    def _exec(self, cmd, env, input_text, timeout, log_output, on_line, cwd, tail):
        full_env = {k: v for k, v in os.environ.items() if k not in SECRET_ENV}
        full_env.update(env or {})
        full_env.setdefault("LC_ALL", "C.UTF-8")
        try:
            proc = subprocess.Popen(cmd, stdin=subprocess.PIPE if input_text is not None else subprocess.DEVNULL,
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1,
                                    env=full_env, cwd=cwd, errors="replace")
        except FileNotFoundError:
            tail.append(f"{cmd[0]}: command not found")
            return 127, ""
        timer = None
        if timeout:
            timer = threading.Timer(timeout, proc.kill)
            timer.start()
        if input_text is not None:
            try:
                proc.stdin.write(input_text)
                proc.stdin.close()
            except BrokenPipeError:
                pass
        chunks = []
        for raw in proc.stdout:
            line = self.redactor.scrub(raw.rstrip("\n"))
            tail.append(line)
            chunks.append(raw)
            if log_output:
                self.log.info("  | " + line)
            if on_line and line.strip():
                on_line(line)
        proc.wait()
        if timer:
            timer.cancel()
        return proc.returncode, "".join(chunks)


class Journal:
    """Undo actions recorded as the installer changes the system; run newest-first when something fails."""

    def __init__(self, log: Log):
        self.log, self.items = log, []

    def add(self, label: str, fn) -> None:
        self.items.append((label, fn))

    def rollback(self, say=None) -> int:
        failures = 0
        for label, fn in reversed(self.items):
            try:
                fn()
                self.log.info(f"rollback ok: {label}")
                if say:
                    say(label, True)
            except Exception as exc:  # keep undoing the rest
                failures += 1
                self.log.error(f"rollback failed: {label}: {exc}")
                if say:
                    say(label, False)
        self.items = []
        return failures

    def clear(self) -> None:
        self.items = []


@dataclass
class Paths:
    """Every absolute location in one place. `root` lets tests run against a scratch directory."""
    root: str = "/"

    def p(self, absolute: str) -> Path:
        return Path(self.root) / absolute.lstrip("/") if self.root != "/" else Path(absolute)

    svc_user = "elitehost"
    install_dir = "/opt/elite-hosting"
    data_dir = "/var/lib/elite-hosting"
    log_dir = "/var/log/elite-hosting"
    etc_dir = "/etc/elite-hosting"
    panel_bind = "127.0.0.1:8080"

    @property
    def INSTALL(self): return self.p(self.install_dir)
    @property
    def DATA(self): return self.p(self.data_dir)
    @property
    def LOG(self): return self.p(self.log_dir)
    @property
    def ETC(self): return self.p(self.etc_dir)
    @property
    def ENV_FILE(self): return self.p(self.etc_dir + "/elite-hosting.env")
    @property
    def HELPER(self): return self.p("/usr/local/sbin/elite-hosting-helper")
    @property
    def ADMIN(self): return self.p("/usr/local/sbin/elite-hosting-admin")
    @property
    def UNIT_APP(self): return self.p("/etc/systemd/system/elite-hosting.service")
    @property
    def UNIT_HELPER(self): return self.p("/etc/systemd/system/elite-hosting-helper.service")
    @property
    def LOGROTATE(self): return self.p("/etc/logrotate.d/elite-hosting")
    @property
    def BACKUP(self): return self.p("/var/backups/elite-hosting")
    @property
    def STATE_DIR(self): return self.p("/etc/elite-installer")
    @property
    def STATE(self): return self.p("/etc/elite-installer/state.json")
    @property
    def SAVED_TOKEN(self): return self.p("/etc/elite-installer/github-token")
    @property
    def INSTALLER_LOG(self): return self.p("/var/log/elite-installer/installer.log")
    @property
    def LOCK(self): return self.p("/run/elite-installer.lock")
    @property
    def HELPER_SOCK(self): return self.p("/run/elite-hosting/helper.sock")


@dataclass
class Options:
    command: str = "install"
    repo: str | None = None
    tag: str | None = None
    archive: str | None = None
    source: str | None = None
    sha256: str | None = None
    token_file: str | None = None
    save_token: bool = False
    admin_user: str = "admin"
    skip_docker: bool = False
    ufw: bool = False
    yes: bool = False
    dry_run: bool = False
    allow_unsupported: bool = False
    force: bool = False
    allow_downgrade: bool = False
    purge: bool = False
    api_base: str | None = None


@dataclass
class Context:
    paths: Paths
    ui: object
    log: Log
    runner: Runner
    journal: Journal
    redactor: Redactor
    opts: Options
    token: str | None = None
    extra: dict = field(default_factory=dict)

    @property
    def real(self) -> bool:
        """True when operating on the real system (not a test root): ownership, services and users apply."""
        return self.paths.root == "/"

    def chown(self, path: Path, user: str, group: str | None = None) -> None:
        if self.real:
            import shutil
            shutil.chown(path, user, group or user)

    def chmod(self, path: Path, mode: int) -> None:
        os.chmod(path, mode)
