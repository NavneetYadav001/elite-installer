"""ELITE INSTALLER tests. No root, network, systemd, nginx or Docker needed:  python3 -m unittest discover -s tests -v"""
from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from elite_installer import archive, checks, cli, github, steps, ui as uimod  # noqa: E402
from elite_installer.core import (CommandError, Context, InstallError, Journal, Log, Options, Paths, Redactor, Result, Runner)  # noqa: E402

TOKEN = "github_pat_11ABCDEFG0abcdefghijklmnop_SECRETSECRETSECRET"
APP_UNIT = ("[Service]\nUser=elitehost\nExecStart=/opt/elite-hosting/venv/bin/gunicorn --config /opt/elite-hosting/gunicorn.conf.py wsgi:app\n")
HELPER_UNIT = "[Service]\nUser=root\nExecStart=/usr/bin/python3 /usr/local/sbin/elite-hosting-helper serve\n"


def make_project(base: Path, version="1.2.3", marker="v1") -> Path:
    root = base / "elite-hosting"
    (root / "elite_hosting").mkdir(parents=True)
    (root / "deploy").mkdir()
    (root / "elite_hosting" / "__init__.py").write_text(f"MARKER = '{marker}'\n")
    (root / "wsgi.py").write_text("from elite_hosting import *\n")
    (root / "gunicorn.conf.py").write_text("workers = 1\n")
    (root / "requirements.txt").write_text("Flask>=3,<4\ngunicorn>=22,<24\npsutil>=5.9,<8\n")
    (root / "VERSION").write_text(version + "\n")
    (root / "deploy" / "elite-hosting-helper").write_text("#!/usr/bin/env python3\nprint('helper')\n")
    (root / "deploy" / "elite-hosting-admin").write_text("#!/bin/bash\nexit 0\n")
    (root / "deploy" / "elite-hosting.service").write_text(APP_UNIT)
    (root / "deploy" / "elite-hosting-helper.service").write_text(HELPER_UNIT)
    (root / "deploy" / "logrotate-elite-hosting").write_text("/var/log/elite-hosting/*.log {\n weekly\n}\n")
    return root


def make_tar(root: Path, dest: Path) -> Path:
    with tarfile.open(dest, "w:gz") as tf:
        tf.add(root, arcname=root.name)
    return dest


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class TmpCase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="elite-inst-test-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)


# ------------------------------------------------------------------------------------------------ secrets / logging
class RedactionTests(TmpCase):
    def test_registered_and_patterned_secrets_are_scrubbed(self):
        r = Redactor()
        r.add("hunter2-secret-value")
        out = r.scrub(f"x hunter2-secret-value y {TOKEN} Authorization: Bearer abcdef123456 GENERATED_PASSWORD=Zq9 password=foo")
        for leaked in ("hunter2-secret-value", TOKEN, "abcdef123456", "Zq9", "foo"):
            self.assertNotIn(leaked, out)

    def test_log_never_contains_secret(self):
        r = Redactor()
        r.add(TOKEN)
        log = Log(self.tmp / "l" / "installer.log", r)
        log.info(f"token is {TOKEN}")
        log.close()
        self.assertNotIn(TOKEN, (self.tmp / "l" / "installer.log").read_text())
        self.assertEqual(((self.tmp / "l" / "installer.log").stat().st_mode & 0o777), 0o600)

    def test_runner_scrubs_output_and_hides_token_env(self):
        r = Redactor(); r.add(TOKEN)
        log = Log(self.tmp / "log.txt", r)
        run = Runner(log, r)
        with mock.patch.dict(os.environ, {"ELITE_GITHUB_TOKEN": TOKEN}):
            res = run.run([sys.executable, "-c", "import os;print(os.environ.get('ELITE_GITHUB_TOKEN'));print('"+TOKEN+"')"], on_line=lambda l: None)
        log.close()
        self.assertTrue(res.out.startswith("None"))                       # child never sees the token variable
        self.assertNotIn(TOKEN, (self.tmp / "log.txt").read_text())
        with self.assertRaises(CommandError) as cm:
            run.run([sys.executable, "-c", f"print('{TOKEN}'); raise SystemExit(3)"])
        self.assertNotIn(TOKEN, "\n".join(cm.exception.tail) + str(cm.exception))

    def test_runner_rejects_string_commands(self):
        run = Runner(Log(None, Redactor()), Redactor())
        with self.assertRaises(TypeError):
            run.run("ls; rm -rf /")


class JournalTests(TmpCase):
    def test_rollback_runs_newest_first_and_continues_after_failure(self):
        order = []
        j = Journal(Log(None, Redactor()))
        j.add("a", lambda: order.append("a"))
        j.add("b", lambda: (_ for _ in ()).throw(RuntimeError("boom")))
        j.add("c", lambda: order.append("c"))
        self.assertEqual(j.rollback(), 1)
        self.assertEqual(order, ["c", "a"])


# ------------------------------------------------------------------------------------------------ prerequisites
class CheckTests(unittest.TestCase):
    def good(self, **kw):
        base = dict(os_id="ubuntu", version_id="24.04", pretty="Ubuntu 24.04 LTS", arch="x86_64", ram_mb=2048, cpus=2,
                    disk_free_mb={"/opt": 20000, "/var": 20000}, is_root=True, has_systemd=True, python_version=(3, 12))
        base.update(kw)
        return checks.Facts(**base)

    def test_parsers(self):
        self.assertEqual(checks.parse_os_release('ID=ubuntu\nVERSION_ID="24.04"\n# c\n')["VERSION_ID"], "24.04")
        self.assertEqual(checks.parse_meminfo_mb("MemTotal:  2097152 kB\n"), 2048)
        tcp = "sl local rem st\n0: 00000000:0050 00000000:0000 0A x\n1: 0100007F:1F90 0100007F:9999 01 x\n"
        self.assertEqual(checks.parse_proc_net_tcp(tcp), {80})

    def test_happy_path(self):
        self.assertEqual(checks.worst(checks.evaluate(self.good(), need_root=True)), checks.OK)

    def test_failures_and_warnings(self):
        names = lambda f, **k: {c.name: c.status for c in checks.evaluate(f, need_root=True, **k)}
        self.assertEqual(names(self.good(version_id="22.04"))["Operating system"], checks.FAIL)
        self.assertEqual(names(self.good(version_id="22.04"), allow_unsupported=True)["Operating system"], checks.WARN)
        self.assertEqual(names(self.good(ram_mb=300))["Memory"], checks.FAIL)
        self.assertEqual(names(self.good(ram_mb=700))["Memory"], checks.WARN)
        self.assertEqual(names(self.good(disk_free_mb={"/opt": 1000, "/var": 20000}))["Free disk (/opt)"], checks.FAIL)
        self.assertEqual(names(self.good(is_root=False))["Permissions"], checks.FAIL)
        self.assertEqual(names(self.good(has_systemd=False))["systemd"], checks.FAIL)
        self.assertEqual(names(self.good(arch="armv7l"))["CPU architecture"], checks.FAIL)
        self.assertEqual(names(self.good(listening={80}))["Port 80"], checks.WARN)
        self.assertEqual(names(self.good(listening={80}, nginx_active=True))["Port 80"], checks.OK)

    def test_non_root_is_only_a_warning_for_check_command(self):
        res = {c.name: c.status for c in checks.evaluate(self.good(is_root=False), need_root=False)}
        self.assertEqual(res["Permissions"], checks.WARN)


# ------------------------------------------------------------------------------------------------ archive safety
class ArchiveTests(TmpCase):
    def evil(self, name, build):
        p = self.tmp / f"{name}.tar.gz"
        with tarfile.open(p, "w:gz") as tf:
            build(tf)
        return p

    def add(self, tf, name, data=b"x", **kw):
        ti = tarfile.TarInfo(name)
        ti.size = len(data)
        for k, v in kw.items():
            setattr(ti, k, v)
        tf.addfile(ti, io.BytesIO(data) if ti.isreg() else None)

    def test_valid_archive_extracts_and_validates(self):
        root = make_project(self.tmp / "src")
        got = archive.safe_extract(make_tar(root, self.tmp / "ok.tar.gz"), self.tmp / "out")
        self.assertEqual(archive.validate_layout(got), "1.2.3")

    def test_rejects_traversal_absolute_links_devices_duplicates(self):
        cases = {
            "traversal": lambda tf: self.add(tf, "top/../../evil"),
            "absolute": lambda tf: self.add(tf, "/etc/cron.d/evil"),
            "symlink": lambda tf: self.add(tf, "top/l", b"", type=tarfile.SYMTYPE, linkname="/etc/passwd"),
            "hardlink": lambda tf: self.add(tf, "top/h", b"", type=tarfile.LNKTYPE, linkname="/etc/passwd"),
            "device": lambda tf: self.add(tf, "top/dev", b"", type=tarfile.CHRTYPE),
            "backslash": lambda tf: self.add(tf, "top\\..\\evil"),
            "two-tops": lambda tf: (self.add(tf, "a/x"), self.add(tf, "b/y")),
            "dup": lambda tf: (self.add(tf, "top/x"), self.add(tf, "top/x")),
        }
        for name, build in cases.items():
            with self.subTest(name), self.assertRaises(InstallError):
                archive.safe_extract(self.evil(name, build), self.tmp / f"o-{name}")
        self.assertFalse((self.tmp / "evil").exists())

    def test_not_a_tarball(self):
        bad = self.tmp / "bad.tar.gz"
        bad.write_bytes(b"not an archive")
        with self.assertRaises(InstallError):
            archive.safe_extract(bad, self.tmp / "o")

    def test_setuid_bits_are_dropped(self):
        p = self.evil("suid", lambda tf: self.add(tf, "top/x", b"x", mode=0o4755))
        out = archive.safe_extract(p, self.tmp / "o")
        self.assertEqual((out / "x").stat().st_mode & 0o7000, 0)

    def test_requirements_validation(self):
        self.assertEqual(len(archive.validate_requirements("Flask>=3,<4\n# c\nrequests>=2.31,<3  # why\n")), 2)
        for bad in ("-r other.txt", "--index-url http://evil", "git+https://x/y.git", "https://x/y.whl", "./local", "flask @ http://x",
                    "-e .", "flask;rm -rf /", "x>=1 --hash=sha256:aa"):
            with self.subTest(bad), self.assertRaises(InstallError):
                archive.validate_requirements(bad)

    def test_unit_validation(self):
        archive.validate_units(APP_UNIT, HELPER_UNIT)
        with self.assertRaises(InstallError):
            archive.validate_units(APP_UNIT.replace("gunicorn --config", "gunicorn --bind 0.0.0.0:80 --config"), HELPER_UNIT)
        with self.assertRaises(InstallError):
            archive.validate_units(APP_UNIT + "ExecStartPre=/bin/sh -c 'curl x|sh'\n", HELPER_UNIT)
        with self.assertRaises(InstallError):
            archive.validate_units(APP_UNIT.replace("elitehost", "root"), HELPER_UNIT)
        with self.assertRaises(InstallError):
            archive.validate_units(APP_UNIT, HELPER_UNIT.replace("serve", "serve; rm"))

    def test_layout_rejects_missing_files_syntax_errors_bad_version(self):
        root = make_project(self.tmp / "a")
        (root / "VERSION").write_text("1.2\n")
        with self.assertRaises(InstallError):
            archive.validate_layout(root)
        root = make_project(self.tmp / "b")
        (root / "elite_hosting" / "bad.py").write_text("def (:\n")
        with self.assertRaises(InstallError):
            archive.validate_layout(root)
        root = make_project(self.tmp / "c")
        (root / "wsgi.py").unlink()
        with self.assertRaises(InstallError):
            archive.validate_layout(root)

    def test_real_project_passes_if_present(self):
        real = ROOT.parent / "elite-hosting"
        if not (real / "wsgi.py").exists():
            self.skipTest("project not next to installer")
        archive.validate_layout(real)


# ------------------------------------------------------------------------------------------------ GitHub (local mock server)
class Mock:
    """Two local servers: 'api' (needs the token) and 'cdn' (where asset downloads redirect to, like GitHub's object storage)."""

    def __init__(self, pkg: Path, name="elite-hosting-1.2.3.tar.gz", tag="v1.2.3", sums=True, tamper_sums=False, digest=None, prerelease=False):
        self.seen_api, self.seen_cdn = [], []
        data = pkg.read_bytes()
        good = hashlib.sha256(data).hexdigest()
        sums_text = f"{'0' * 64 if tamper_sums else good}  {name}\n"
        mock = self

        class Cdn(BaseHTTPRequestHandler):
            def log_message(self, *a): pass
            def do_GET(self):
                mock.seen_cdn.append(dict(self.headers))
                self.send_response(200); self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)

        self.cdn = ThreadingHTTPServer(("127.0.0.1", 0), Cdn)
        cdn_port = self.cdn.server_address[1]

        class Api(BaseHTTPRequestHandler):
            def log_message(self, *a): pass
            def reply(self, code, body=b"", ctype="application/json", extra=None):
                self.send_response(code); self.send_header("Content-Type", ctype); self.send_header("Content-Length", str(len(body)))
                for k, v in (extra or {}).items():
                    self.send_header(k, v)
                self.end_headers(); self.wfile.write(body)
            def do_GET(self):
                mock.seen_api.append((self.path, dict(self.headers)))
                if self.headers.get("Authorization") != f"Bearer {TOKEN}":
                    return self.reply(404, b'{"message":"Not Found"}')
                if self.path.endswith("/releases/latest") or "/releases/tags/" in self.path:
                    assets = [{"id": 1, "name": name, "size": len(data)}]
                    if digest is not None:
                        assets[0]["digest"] = digest
                    if sums:
                        assets.append({"id": 2, "name": "SHA256SUMS", "size": len(sums_text)})
                    return self.reply(200, json.dumps({"tag_name": tag, "draft": False, "prerelease": prerelease, "assets": assets}).encode())
                if self.path.endswith("/assets/1"):
                    return self.reply(302, extra={"Location": f"http://127.0.0.1:{cdn_port}/blob"})
                if self.path.endswith("/assets/2"):
                    return self.reply(200, sums_text.encode(), "text/plain")
                self.reply(404, b"{}")

        self.api = ThreadingHTTPServer(("127.0.0.1", 0), Api)
        for s in (self.api, self.cdn):
            threading.Thread(target=s.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.api.server_address[1]}"
        self.sha = good

    def close(self):
        for s in (self.api, self.cdn):
            s.shutdown(); s.server_close()


class GitHubTests(TmpCase):
    def setUp(self):
        super().setUp()
        self.pkg = make_tar(make_project(self.tmp / "src"), self.tmp / "elite-hosting-1.2.3.tar.gz")

    def serve(self, **kw):
        m = Mock(self.pkg, **kw)
        self.addCleanup(m.close)
        return m

    def client(self, m, token=TOKEN):
        return github.GitHubClient("owner/repo", token, api_base=m.url)

    def test_download_flow_authenticates_api_but_not_the_redirect_target(self):
        m = self.serve()
        c = self.client(m)
        rel = c.release()
        pkg, sums_asset, version = github.select_assets(rel)
        sums = github.parse_sums(c.download_text(sums_asset))
        digest = c.download(pkg, self.tmp / "dl.tar.gz")
        github.verify_digest(digest, sums=sums, name=pkg["name"], github_digest=None, pinned=m.sha)
        self.assertEqual(version, "1.2.3")
        self.assertTrue(all(h.get("Authorization") == f"Bearer {TOKEN}" for _, h in m.seen_api))
        self.assertTrue(m.seen_cdn)
        for headers in m.seen_cdn:
            self.assertNotIn("Authorization", {k.title() for k in headers})
            self.assertNotIn(TOKEN, json.dumps(headers))

    def test_errors_never_mention_the_token(self):
        m = self.serve()
        with self.assertRaises(InstallError) as cm:
            self.client(m, token="wrong-token-value-123456").release()
        self.assertNotIn("wrong-token-value", str(cm.exception) + cm.exception.hint)
        self.assertIn("404", str(cm.exception))

    def test_refuses_unverifiable_or_inconsistent_releases(self):
        for kw, why in ((dict(sums=False), "no sums"), (dict(tag="v9.9.9"), "tag mismatch"), (dict(prerelease=True), "prerelease")):
            m = self.serve(**kw)
            with self.subTest(why), self.assertRaises(InstallError):
                c = self.client(m)
                github.select_assets(c.release())

    def test_checksum_mismatch_is_fatal(self):
        m = self.serve(tamper_sums=True)
        c = self.client(m)
        pkg, sums_asset, _ = github.select_assets(c.release())
        sums = github.parse_sums(c.download_text(sums_asset))
        digest = c.download(pkg, self.tmp / "dl")
        with self.assertRaises(InstallError) as cm:
            github.verify_digest(digest, sums=sums, name=pkg["name"], github_digest=None, pinned=None)
        self.assertIn("mismatch", str(cm.exception))
        with self.assertRaises(InstallError):     # a pin that disagrees also fails, even when SHA256SUMS is fine
            github.verify_digest(digest, sums={pkg["name"]: digest}, name=pkg["name"], github_digest=None, pinned="0" * 64)
        with self.assertRaises(InstallError):     # GitHub's own digest must agree too
            github.verify_digest(digest, sums={pkg["name"]: digest}, name=pkg["name"], github_digest="sha256:" + "1" * 64, pinned=None)
        with self.assertRaises(InstallError):
            github.verify_digest(digest, sums=None, name="x", github_digest=None, pinned=None)

    def test_custom_api_base_only_allowed_for_loopback_http(self):
        for bad in ("http://evil.example", "https://evil.example", "http://127.0.0.1.evil.example"):
            with self.subTest(bad), self.assertRaises(InstallError):
                github.GitHubClient("o/r", TOKEN, api_base=bad)
        github.GitHubClient("o/r", TOKEN)                      # default api.github.com
        for repo in ("nope", "a/b/c", "a/b;rm", "../x"):
            with self.assertRaises(InstallError):
                github.GitHubClient(repo, TOKEN)

    def test_redirect_downgrade_to_http_is_refused(self):
        h = github._SafeRedirect()
        req = github.urllib.request.Request("https://api.github.com/x", headers={"Authorization": "Bearer t"})
        with self.assertRaises(InstallError):
            h.redirect_request(req, None, 302, "Found", {}, "http://evil.example/x")

    def test_parse_sums(self):
        self.assertEqual(github.parse_sums(f"{'a' * 64}  f.tar.gz\n{'B' * 64} *g\ngarbage\n"), {"f.tar.gz": "a" * 64, "g": "b" * 64})

    def test_size_cap(self):
        m = self.serve()
        c = self.client(m)
        with self.assertRaises(InstallError):
            c.download({"id": 1, "name": "x", "size": 10}, self.tmp / "x", max_bytes=5)


# ------------------------------------------------------------------------------------------------ UI
class UiTests(unittest.TestCase):
    def test_plain_output_has_no_escape_codes(self):
        out = io.StringIO()
        ui = uimod.Ui(out=out)
        ui.logo("1.0.0")
        ui.begin(2); ui.step_start("Step one"); ui.step_end(True); ui.warn("careful")
        text = out.getvalue()
        self.assertNotIn("\x1b", text)
        self.assertIn("[1/2] Step one", text)
        self.assertIn("v1.0.0", text)
        self.assertIn("█", text)

    def test_narrow_terminal_uses_compact_logo(self):
        out = io.StringIO()
        uimod.Ui(out=out, width=40).logo("1.0.0")
        self.assertNotIn("╚═╝", out.getvalue())
        self.assertIn("H O S T I N G", out.getvalue())

    def test_colour_uses_blue_purple_gradient(self):
        out = io.StringIO()
        with mock.patch.dict(os.environ, {"COLORTERM": "truecolor"}):
            ui = uimod.Ui(out=out, color=True, animate=False, width=100)
        ui.logo("1.0.0")
        self.assertIn("38;2;59;130;246", out.getvalue() + ui.fg("x", uimod.BLUE))
        self.assertEqual(uimod.gradient_at(0), uimod.BLUE)
        self.assertEqual(uimod.gradient_at(1), uimod.PURPLE)
        ui256 = uimod.Ui(out=io.StringIO(), color=True, animate=False)
        ui256.truecolor = False
        self.assertIn("38;5;", ui256.fg("x", uimod.PURPLE))

    def test_progress_bar(self):
        ui = uimod.Ui(out=io.StringIO(), color=False, animate=False)
        ui.begin(4); ui.done_steps = 2
        self.assertEqual(ui.percent(), 0.5)
        self.assertEqual(ui.bar(0.5, 10), "[#####-----]")
        ui.progress(0.5)
        self.assertEqual(ui.percent(), 0.625)

    def test_animated_step_draws_and_finishes(self):
        out = io.StringIO()
        ui = uimod.Ui(out=out, color=False, animate=True, width=80)
        ui.begin(1); ui.step_start("Working"); ui.status("apt: Setting up nginx")
        import time; time.sleep(0.25)
        ui.step_end(True)
        self.assertIn("Working", out.getvalue())
        self.assertIn("✔", out.getvalue())

    def test_confirm_assume_yes_and_noninteractive(self):
        ui = uimod.Ui(out=io.StringIO(), color=False)
        self.assertTrue(ui.confirm("go?", assume_yes=True))
        with mock.patch.object(uimod.Ui, "_tty_input", staticmethod(lambda: None)), self.assertRaises(RuntimeError):
            ui.confirm("go?")


# ------------------------------------------------------------------------------------------------ orchestration with a fake system
class FakeRunner(Runner):
    def __init__(self, log, red, handler=None):
        super().__init__(log, red)
        self.handler = handler or (lambda cmd: None)

    def _exec(self, cmd, env, input_text, timeout, log_output, on_line, cwd, tail):
        hooked = self.handler(cmd)
        if hooked is not None:
            code, out = hooked
        elif cmd[:2] == ["id", "-u"] or cmd[:2] == ["systemctl", "is-active"]:
            code, out = 1, ""
        elif cmd[-1:] == ["has-users"]:
            code, out = 1, ""
        elif "create-admin" in cmd:
            code, out = 0, "created\nGENERATED_PASSWORD=Pa55-w0rd-ONE-TIME\n"
        elif cmd[:2] == ["ip", "-4"]:
            code, out = 0, "1.1.1.1 via 10.0.0.1 dev eth0 src 203.0.113.7 uid 0\n"
        else:
            code, out = 0, ""
        if code and tail is not None:
            tail.append("simulated failure")
        return code, out


class OrchestrationTests(TmpCase):
    def ctx(self, handler=None, **opts):
        red = Redactor()
        paths = Paths(str(self.tmp / "sys"))
        log = Log(paths.INSTALLER_LOG, red)
        self.addCleanup(log.close)
        c = Context(paths, uimod.Ui(out=io.StringIO(), color=False, animate=False), log, FakeRunner(log, red, handler), Journal(log), red,
                    Options(**opts))
        return c

    def deploy(self, ctx, marker="v1", version="1.2.3", healthy=True):
        proj = make_project(self.tmp / f"proj-{marker}-{version}", version=version, marker=marker)
        st = steps.Staged(proj, archive.validate_layout(proj), "test")
        dep = steps.Deployment(ctx, st)
        dep.health = lambda *a, **k: healthy
        dep.wait_socket = lambda *a, **k: True
        return dep

    def run_install(self, ctx, dep, update=False):
        steps.run_steps(ctx, steps.install_plan(ctx, dep, update))
        dep.finalize()
        ctx.journal.clear()

    def test_fresh_install_creates_files_secret_once_and_hides_password(self):
        ctx = self.ctx(admin_user="admin")
        dep = self.deploy(ctx)
        self.run_install(ctx, dep)
        P = ctx.paths
        env = P.ENV_FILE.read_text()
        self.assertRegex(env, r"ELITE_SECRET_KEY=[0-9a-f]{64}")
        self.assertEqual(P.ENV_FILE.stat().st_mode & 0o777, 0o640)
        self.assertIn("MARKER = 'v1'", (P.INSTALL / "elite_hosting" / "__init__.py").read_text())
        for f in (P.UNIT_APP, P.UNIT_HELPER, P.HELPER, P.ADMIN, P.LOGROTATE, P.STATE):
            self.assertTrue(f.exists(), f)
        self.assertEqual(json.loads(P.STATE.read_text())["installed_version"], "1.2.3")
        self.assertEqual(dep.admin_password, "Pa55-w0rd-ONE-TIME")
        self.assertNotIn("Pa55-w0rd-ONE-TIME", P.INSTALLER_LOG.read_text())
        flat = [" ".join(c) for c in ctx.runner.history]
        self.assertTrue(any("--only-binary=:all:" in c and "-r" in c for c in flat), "pip must refuse source builds")
        self.assertTrue(any(c.startswith("nginx -t") for c in flat))
        # ordering guarantee: configuration is validated before any service is restarted
        idx = lambda s: next(i for i, c in enumerate(flat) if s in c)
        self.assertLess(idx("compileall"), idx("systemctl restart elite-hosting-helper"))
        self.assertLess(idx("nginx -t"), idx("systemctl restart elite-hosting-helper"))
        self.assertTrue(all(isinstance(c, list) for c in ctx.runner.history))
        self.assertFalse(any(c[0] == "bash" and c[1] == "-c" and "token" in c[2].lower() for c in ctx.runner.history))

    def test_reinstall_keeps_secret_and_existing_users(self):
        ctx = self.ctx()
        self.run_install(ctx, self.deploy(ctx))
        before = ctx.paths.ENV_FILE.read_text()
        (ctx.paths.INSTALL / "venv" / "bin").mkdir(parents=True)
        (ctx.paths.INSTALL / "venv" / "bin" / "python").write_text("")       # what a real venv would have left
        ctx2 = self.ctx(lambda cmd: (0, "") if cmd[-1:] == ["has-users"] else None)
        dep2 = self.deploy(ctx2, marker="v2", version="1.3.0")
        self.assertTrue(dep2.updating)
        self.run_install(ctx2, dep2, update=True)
        self.assertEqual(ctx2.paths.ENV_FILE.read_text(), before)
        self.assertIsNone(dep2.admin_password)
        self.assertFalse(any("create-admin" in c for c in ctx2.runner.history))
        self.assertIn("MARKER = 'v2'", (ctx2.paths.INSTALL / "elite_hosting" / "__init__.py").read_text())

    def test_failed_fresh_install_rolls_back_everything_it_created(self):
        ctx = self.ctx(lambda cmd: (1, "") if "compileall" in cmd else None)
        dep = self.deploy(ctx)
        with self.assertRaises(CommandError):
            self.run_install(ctx, dep)
        failures = ctx.journal.rollback()
        self.assertEqual(failures, 0)
        P = ctx.paths
        for gone in (P.INSTALL, P.ENV_FILE, P.UNIT_APP, P.UNIT_HELPER, P.HELPER, P.ADMIN, P.DATA, P.LOGROTATE):
            self.assertFalse(gone.exists(), f"{gone} should have been removed")

    def test_failed_update_restores_code_database_and_keeps_secret(self):
        ctx = self.ctx()
        self.run_install(ctx, self.deploy(ctx))
        P = ctx.paths
        (P.DATA / "db").mkdir(parents=True, exist_ok=True)
        db = P.DATA / "db" / "elite.db"
        db.write_bytes(b"ORIGINAL-DATABASE")
        env_before, unit_before = P.ENV_FILE.read_text(), P.UNIT_APP.read_text()
        site = P.DATA / "storage" / "sites" / "mine"
        site.mkdir(parents=True)
        (site / "index.html").write_text("my site")

        def handler(cmd):
            if "-c" in cmd and steps.DB_BACKUP_SCRIPT in cmd:        # emulate the sqlite online backup
                shutil.copy(cmd[-2], cmd[-1]); return 0, ""
            if cmd[-1:] == ["init-db"]:                                # emulate a migration that touched the database
                db.write_bytes(b"MIGRATED"); return 0, ""
            if cmd[-1:] == ["has-users"]:
                return 0, ""
            return None

        ctx2 = self.ctx(handler)
        dep = self.deploy(ctx2, marker="v2", version="1.3.0", healthy=False)       # panel never becomes healthy
        with self.assertRaises(InstallError) as cm:
            self.run_install(ctx2, dep, update=True)
        self.assertIn("healthy", str(cm.exception))
        self.assertEqual(db.read_bytes(), b"MIGRATED")
        self.assertEqual(ctx2.journal.rollback(), 0)
        self.assertEqual(db.read_bytes(), b"ORIGINAL-DATABASE")
        self.assertIn("MARKER = 'v1'", (P.INSTALL / "elite_hosting" / "__init__.py").read_text())
        self.assertEqual(P.ENV_FILE.read_text(), env_before)
        self.assertEqual(P.UNIT_APP.read_text(), unit_before)
        self.assertEqual((site / "index.html").read_text(), "my site")
        self.assertEqual([p.name for p in P.INSTALL.glob("elite_hosting.old-*")], [])

    def test_existing_database_without_env_file_is_refused(self):
        ctx = self.ctx()
        (ctx.paths.DATA / "db").mkdir(parents=True)
        (ctx.paths.DATA / "db" / "elite.db").write_bytes(b"precious")
        dep = self.deploy(ctx)
        with self.assertRaises(InstallError) as cm:
            self.run_install(ctx, dep)
        self.assertIn("encryption key", str(cm.exception))
        ctx.journal.rollback()
        self.assertEqual((ctx.paths.DATA / "db" / "elite.db").read_bytes(), b"precious")
        self.assertFalse(ctx.paths.ENV_FILE.exists())

    def test_admin_user_validation(self):
        ctx = self.ctx(admin_user="bad name; rm")
        with self.assertRaises(InstallError):
            self.run_install(ctx, self.deploy(ctx))

    def test_uninstall_keeps_data_unless_purged(self):
        ctx = self.ctx()
        self.run_install(ctx, self.deploy(ctx))
        steps.uninstall(ctx)
        P = ctx.paths
        self.assertFalse(P.INSTALL.exists())
        self.assertFalse(P.UNIT_APP.exists())
        self.assertTrue(P.DATA.exists() and P.ENV_FILE.exists())
        ctx.opts.purge = True
        steps.uninstall(ctx)
        self.assertFalse(P.DATA.exists() or P.ETC.exists())


# ------------------------------------------------------------------------------------------------ token handling + CLI
class TokenTests(TmpCase):
    def ctx(self):
        red = Redactor()
        paths = Paths(str(self.tmp / "sys"))
        return Context(paths, uimod.Ui(out=io.StringIO(), color=False), Log(None, red), Runner(Log(None, red), red), Journal(Log(None, red)), red, Options())

    def test_sources_and_precedence(self):
        ctx = self.ctx()
        f = self.tmp / "tok"
        f.write_text(TOKEN + "\n"); f.chmod(0o600)
        ctx.opts.token_file = str(f)
        with mock.patch.dict(os.environ, {"ELITE_GITHUB_TOKEN": "env-token-should-lose"}):
            self.assertEqual(steps.resolve_token(ctx), TOKEN)
        self.assertIn(TOKEN, ctx.redactor._secrets)

    def test_env_and_missing(self):
        ctx = self.ctx()
        with mock.patch.dict(os.environ, {"ELITE_GITHUB_TOKEN": TOKEN}):
            self.assertEqual(steps.resolve_token(ctx), TOKEN)
        ctx = self.ctx()
        with mock.patch.dict(os.environ, {}, clear=False), mock.patch.object(uimod.Ui, "_tty_input", staticmethod(lambda: None)):
            os.environ.pop("ELITE_GITHUB_TOKEN", None)
            with self.assertRaises(InstallError) as cm:
                steps.resolve_token(ctx)
        self.assertIn("never accepted on the command line", cm.exception.hint)

    def test_world_readable_token_file_warns(self):
        ctx = self.ctx()
        f = self.tmp / "tok"
        f.write_text(TOKEN); f.chmod(0o644)
        ctx.opts.token_file = str(f)
        steps.resolve_token(ctx)
        self.assertTrue(any("readable by other users" in w for w in ctx.ui.warnings))

    def test_cli_has_no_token_argument(self):
        for argv in (["install", "--github", "o/r", "--token", TOKEN], ["install", "--github", "o/r", "--password", "x"],
                     ["install", "--github", "o/r", f"--token={TOKEN}"], ["install", "--github", "o/r", "--tok", TOKEN],
                     ["install", "--github", "o/r", "--token-file", TOKEN]):
            err = io.StringIO()
            with self.assertRaises(SystemExit) as cm, mock.patch("sys.stderr", err):
                cli.main(argv)
            self.assertEqual(cm.exception.code, 2, argv)
            self.assertNotIn(TOKEN, err.getvalue())
        err = io.StringIO()
        with self.assertRaises(SystemExit), mock.patch("sys.stderr", err):          # abbreviations are not accepted
            cli.build_parser().parse_args(["install", "--github", "o/r", "--token-f", "x"])
        self.assertNotIn("--token-file", cli.build_parser().parse_args(["install", "--token-file", "f"]).__dict__.get("x", ""))

    def test_repo_default_comes_from_saved_state(self):
        ctx = self.ctx()
        ctx.paths.STATE_DIR.mkdir(parents=True)
        ctx.paths.STATE.write_text(json.dumps({"repo": "me/private"}))
        self.assertEqual(steps.resolve_repo(ctx), "me/private")


class CliEndToEndTests(TmpCase):
    def good_facts(self, *a, **k):
        return checks.Facts(os_id="ubuntu", version_id="24.04", pretty="Ubuntu 24.04 LTS", arch="x86_64", ram_mb=4096, cpus=2,
                            disk_free_mb={"/opt": 50000, "/var": 50000}, is_root=True, has_systemd=True, python_version=(3, 12))

    def test_dry_run_from_mock_github_verifies_without_changing_anything_or_leaking_token(self):
        pkg = make_tar(make_project(self.tmp / "src"), self.tmp / "elite-hosting-1.2.3.tar.gz")
        m = Mock(pkg)
        self.addCleanup(m.close)
        tokfile = self.tmp / "token"; tokfile.write_text(TOKEN); tokfile.chmod(0o600)
        root = self.tmp / "sys"
        buf = io.StringIO()
        with mock.patch("elite_installer.checks.gather_facts", self.good_facts), mock.patch("sys.stdout", buf):
            code = cli.main(["--no-color", "--root", str(root), "install", "--github", "owner/repo", "--api-base", m.url,
                             "--token-file", str(tokfile), "--dry-run", "--yes"])
        self.assertEqual(code, 0, buf.getvalue())
        self.assertIn("Dry run complete", buf.getvalue())
        self.assertIn("v1.2.3", buf.getvalue())
        self.assertNotIn(TOKEN, buf.getvalue())
        logtext = (root / "var/log/elite-installer/installer.log").read_text()
        self.assertNotIn(TOKEN, logtext)
        self.assertIn("sha256 verified", logtext)
        self.assertFalse((root / "opt").exists(), "dry run must not install anything")
        self.assertEqual(list((root / "var/tmp").glob("elite-installer-*")), [], "temporary files cleaned up")

    def test_tampered_release_is_rejected(self):
        pkg = make_tar(make_project(self.tmp / "src"), self.tmp / "elite-hosting-1.2.3.tar.gz")
        m = Mock(pkg, tamper_sums=True)
        self.addCleanup(m.close)
        tokfile = self.tmp / "token"; tokfile.write_text(TOKEN); tokfile.chmod(0o600)
        buf = io.StringIO()
        with mock.patch("elite_installer.checks.gather_facts", self.good_facts), mock.patch("sys.stdout", buf):
            code = cli.main(["--no-color", "--root", str(self.tmp / "sys"), "install", "--github", "owner/repo", "--api-base", m.url,
                             "--token-file", str(tokfile), "--dry-run"])
        self.assertEqual(code, 1)
        self.assertIn("Checksum mismatch", buf.getvalue())
        self.assertNotIn(TOKEN, buf.getvalue())

    def test_unsupported_os_stops_before_anything_happens(self):
        bad = lambda *a, **k: checks.Facts(os_id="debian", version_id="12", arch="x86_64", ram_mb=4096, disk_free_mb={"/opt": 50000},
                                           is_root=True, has_systemd=True, python_version=(3, 12))
        buf = io.StringIO()
        with mock.patch("elite_installer.checks.gather_facts", bad), mock.patch("sys.stdout", buf):
            code = cli.main(["--no-color", "--root", str(self.tmp / "sys"), "install", "--archive", "x", "--yes"])
        self.assertEqual(code, 1)
        self.assertIn("Prerequisites not met", buf.getvalue())

    def test_archive_pin_mismatch(self):
        pkg = make_tar(make_project(self.tmp / "src"), self.tmp / "a.tar.gz")
        buf = io.StringIO()
        with mock.patch("elite_installer.checks.gather_facts", self.good_facts), mock.patch("sys.stdout", buf):
            code = cli.main(["--no-color", "--root", str(self.tmp / "sys"), "install", "--archive", str(pkg), "--sha256", "0" * 64, "--dry-run"])
        self.assertEqual(code, 1)
        self.assertIn("mismatch", buf.getvalue())

    def test_check_command_changes_nothing_and_reports(self):
        buf = io.StringIO()
        with mock.patch("elite_installer.checks.gather_facts", self.good_facts), mock.patch("sys.stdout", buf):
            code = cli.main(["--no-color", "--root", str(self.tmp / "sys"), "check"])
        self.assertEqual(code, 0)
        self.assertIn("Ready to install", buf.getvalue())
        self.assertFalse((self.tmp / "sys").exists())


# ------------------------------------------------------------------------------------------------ distribution scripts
class DistTests(TmpCase):
    def test_launcher_scripts_have_valid_syntax_and_run(self):
        for s in ("elite-installer", "install.sh", "update.sh", "uninstall.sh", "check.sh", "tools/build-dist.sh", "bootstrap.sh.in"):
            self.assertEqual(subprocess.run(["bash", "-n", str(ROOT / s)]).returncode, 0, s)
        out = subprocess.run([str(ROOT / "elite-installer"), "version"], capture_output=True, text=True, cwd="/")
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("elite-installer", out.stdout)

    def test_unconfigured_bootstrap_refuses_to_run(self):
        out = subprocess.run(["bash", str(ROOT / "bootstrap.sh.in")], capture_output=True, text=True)
        self.assertNotEqual(out.returncode, 0)
        self.assertIn("not been configured", out.stderr)

    def test_build_dist_requires_https_endpoint_and_embeds_checksum(self):
        work = self.tmp / "copy"
        shutil.copytree(ROOT, work, ignore=shutil.ignore_patterns("dist", "__pycache__", ".git"))
        (work / "README.md").touch()
        script = work / "tools" / "build-dist.sh"
        for bad in ("http://insecure.example", "", "https://x y", "ftp://x"):
            r = subprocess.run(["bash", str(script), "--endpoint", bad], capture_output=True, text=True)
            self.assertEqual(r.returncode, 2, bad)
        r = subprocess.run(["bash", str(script), "--endpoint", "https://dist.test.invalid/elite/"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        d = work / "dist"
        pkg = next(d.glob("elite-installer-*.tar.gz"))
        boot = (d / "get-elite.sh").read_text()
        self.assertNotRegex(boot, r"@@[A-Z0-9]+@@")
        self.assertIn("https://dist.test.invalid/elite", boot)
        self.assertIn(sha(pkg), boot)
        self.assertIn("does not work until you have uploaded", r.stdout)
        with tarfile.open(pkg) as tf:
            names = tf.getnames()
        self.assertIn("elite-installer/elite_installer/cli.py", names)
        self.assertFalse(any("tests" in n or "__pycache__" in n for n in names))


if __name__ == "__main__":
    unittest.main()
