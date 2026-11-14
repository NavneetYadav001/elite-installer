"""Prerequisite checks. Everything here is read-only: it never changes the system."""
from __future__ import annotations

import os
import shutil
import socket
from dataclasses import dataclass, field

OK, WARN, FAIL = "ok", "warn", "fail"

MIN_RAM_FAIL_MB, MIN_RAM_WARN_MB = 512, 1024
MIN_DISK_FAIL_MB, MIN_DISK_WARN_MB = 3000, 6000


@dataclass
class Facts:
    os_id: str = ""
    version_id: str = ""
    pretty: str = "unknown"
    codename: str = ""
    arch: str = ""
    ram_mb: int = 0
    cpus: int = 1
    disk_free_mb: dict = field(default_factory=dict)   # path -> free MB
    is_root: bool = False
    has_systemd: bool = False
    listening: set = field(default_factory=set)         # TCP ports in LISTEN state
    nginx_active: bool = False
    github_reachable: bool | None = None                # None = not tested
    python_version: tuple = (0, 0)
    existing_install: bool = False


@dataclass
class Check:
    name: str
    status: str
    detail: str
    hint: str = ""


def parse_os_release(text: str) -> dict:
    out = {}
    for line in text.splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip().strip('"').strip("'")
    return out


def parse_meminfo_mb(text: str) -> int:
    for line in text.splitlines():
        if line.startswith("MemTotal:"):
            return int(line.split()[1]) // 1024
    return 0


def parse_proc_net_tcp(text: str) -> set:
    ports = set()
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) > 3 and parts[3] == "0A":      # 0A = LISTEN
            ports.add(int(parts[1].rsplit(":", 1)[1], 16))
    return ports


def _read(path: str) -> str:
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


def can_reach(host: str, port: int = 443, timeout: float = 6.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def gather_facts(paths, test_github_host: str | None = None, nginx_active=None) -> Facts:
    import platform
    import sys
    osr = parse_os_release(_read("/etc/os-release"))
    f = Facts(os_id=osr.get("ID", ""), version_id=osr.get("VERSION_ID", ""), pretty=osr.get("PRETTY_NAME", "unknown"),
              codename=osr.get("VERSION_CODENAME", ""), arch=platform.machine(), ram_mb=parse_meminfo_mb(_read("/proc/meminfo")),
              cpus=os.cpu_count() or 1, is_root=(os.geteuid() == 0), has_systemd=os.path.isdir("/run/systemd/system"),
              python_version=sys.version_info[:2])
    for path in ("/opt", "/var"):
        probe = path
        while not os.path.exists(probe) and probe != "/":
            probe = os.path.dirname(probe)
        f.disk_free_mb[path] = shutil.disk_usage(probe).free // (1024 * 1024)
    f.listening = parse_proc_net_tcp(_read("/proc/net/tcp")) | parse_proc_net_tcp(_read("/proc/net/tcp6"))
    f.nginx_active = bool(nginx_active) if nginx_active is not None else False
    f.existing_install = (paths.INSTALL / "venv" / "bin" / "python").exists()
    if test_github_host:
        f.github_reachable = can_reach(test_github_host)
    return f


def evaluate(f: Facts, *, need_root: bool, allow_unsupported: bool = False, need_github: bool = False) -> list[Check]:
    out: list[Check] = []
    supported = f.os_id == "ubuntu" and f.version_id == "24.04"
    if supported:
        out.append(Check("Operating system", OK, f.pretty))
    else:
        out.append(Check("Operating system", WARN if allow_unsupported else FAIL, f"{f.pretty} - Ubuntu 24.04 LTS is required",
                         "Use --allow-unsupported to try anyway (not tested)."))
    out.append(Check("CPU architecture", OK if f.arch in ("x86_64", "aarch64") else FAIL, f.arch or "unknown",
                     "" if f.arch in ("x86_64", "aarch64") else "Only x86_64 and aarch64 are supported."))
    out.append(Check("CPU cores", OK if f.cpus >= 2 else WARN, f"{f.cpus} core{'s' if f.cpus != 1 else ''}",
                     "" if f.cpus >= 2 else "One core works, but Docker builds will be slow."))
    if f.ram_mb < MIN_RAM_FAIL_MB:
        out.append(Check("Memory", FAIL, f"{f.ram_mb} MB", f"At least {MIN_RAM_FAIL_MB} MB is required; 1 GB or more recommended."))
    elif f.ram_mb < MIN_RAM_WARN_MB - 100:
        out.append(Check("Memory", WARN, f"{f.ram_mb} MB", "1 GB or more is recommended (Docker builds need memory)."))
    else:
        out.append(Check("Memory", OK, f"{f.ram_mb} MB"))
    for path, free in sorted(f.disk_free_mb.items()):
        if free < MIN_DISK_FAIL_MB:
            out.append(Check(f"Free disk ({path})", FAIL, f"{free} MB", f"At least {MIN_DISK_FAIL_MB} MB is required."))
        elif free < MIN_DISK_WARN_MB:
            out.append(Check(f"Free disk ({path})", WARN, f"{free} MB", "Docker images need several GB; consider more space."))
        else:
            out.append(Check(f"Free disk ({path})", OK, f"{free} MB"))
    if need_root:
        out.append(Check("Permissions", OK if f.is_root else FAIL, "running as root" if f.is_root else "not root",
                         "" if f.is_root else "Run with sudo."))
    else:
        out.append(Check("Permissions", OK if f.is_root else WARN, "running as root" if f.is_root else "not root (fine for checking; install needs sudo)"))
    out.append(Check("systemd", OK if f.has_systemd else FAIL, "available" if f.has_systemd else "not running",
                     "" if f.has_systemd else "A real server or VM with systemd is required (not a plain container or WSL without systemd)."))
    out.append(Check("Python", OK if f.python_version >= (3, 10) else FAIL, "%d.%d" % f.python_version,
                     "" if f.python_version >= (3, 10) else "Python 3.10+ is required."))
    for port in (80, 443):
        if port in f.listening and not f.nginx_active:
            out.append(Check(f"Port {port}", WARN, "already in use by another program",
                             "Stop it (for example apache2) or nginx cannot start."))
        else:
            out.append(Check(f"Port {port}", OK, "available" if port not in f.listening else "used by nginx"))
    if need_github:
        if f.github_reachable is None:
            pass
        else:
            out.append(Check("GitHub reachable", OK if f.github_reachable else FAIL, "api.github.com:443" if f.github_reachable else "cannot connect",
                             "" if f.github_reachable else "Check the server's internet access / DNS / firewall."))
    if f.existing_install:
        out.append(Check("Existing installation", OK, "found - data, keys and env file will be kept"))
    return out


def worst(checks: list[Check]) -> str:
    states = {c.status for c in checks}
    return FAIL if FAIL in states else WARN if WARN in states else OK
