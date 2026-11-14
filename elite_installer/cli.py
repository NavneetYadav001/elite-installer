"""ELITE INSTALLER command line: check | install | update | uninstall | version."""
from __future__ import annotations

import argparse
import fcntl
import os
import sys
from pathlib import Path

from . import __version__, checks, github
from .core import CommandError, Context, InstallError, Journal, Log, Options, Paths, Redactor, Runner
from .steps import Deployment, install_plan, load_state, resolve_repo, resolve_token, run_steps, stage_package, uninstall
from .ui import Ui, WHITE, GREEN, AMBER

EXIT_FAIL, EXIT_USAGE, EXIT_INTR = 1, 2, 130


class _Parser(argparse.ArgumentParser):
    """argparse that never echoes secrets and never accepts abbreviated options (so --token cannot alias --token-file)."""

    def __init__(self, *a, **k):
        k.setdefault("allow_abbrev", False)
        super().__init__(*a, **k)

    def error(self, message):
        self.print_usage(sys.stderr)
        sys.stderr.write(f"{self.prog}: error: {Redactor().scrub(message)}\n")
        raise SystemExit(2)


SECRET_FLAGS = ("--token", "--github-token", "--password", "--pat", "--secret")


def reject_secrets_in_argv(argv: list[str]) -> None:
    """Secrets on the command line leak via shell history and `ps`; refuse them without echoing them back."""
    probe = Redactor()
    for arg in argv:
        if arg.split("=", 1)[0] in SECRET_FLAGS or probe.scrub(arg) != arg:
            sys.stderr.write("ERROR: do not pass tokens or passwords as command-line arguments (they leak through shell history and process lists).\n"
                             "       Use --token-file FILE (chmod 600) or the ELITE_GITHUB_TOKEN environment variable.\n")
            raise SystemExit(2)


def build_parser() -> argparse.ArgumentParser:
    p = _Parser(prog="elite-installer", allow_abbrev=False,
                description="ELITE INSTALLER - installs and maintains ELITE HOSTING on Ubuntu 24.04 LTS.")
    p.add_argument("--no-color", action="store_true", help="disable colours and animation")
    p.add_argument("--root", default="/", help=argparse.SUPPRESS)
    sub = p.add_subparsers(dest="command", required=True, parser_class=_Parser)

    def source_opts(sp):
        g = sp.add_argument_group("package source (choose one)")
        g.add_argument("--github", metavar="OWNER/REPO", help="private GitHub repository holding your releases (default: remembered from the last install)")
        g.add_argument("--archive", metavar="FILE", help="local elite-hosting-X.Y.Z.tar.gz")
        g.add_argument("--source", metavar="DIR", help="extracted project directory (not checksum-verified)")
        sp.add_argument("--tag", help="install this release tag instead of the latest stable release")
        sp.add_argument("--sha256", metavar="HEX", help="require the package to have exactly this SHA-256")
        sp.add_argument("--token-file", metavar="FILE", help="file containing the GitHub token (or set ELITE_GITHUB_TOKEN; tokens are never accepted as arguments)")
        sp.add_argument("--save-token", action="store_true", help="remember the token in /etc/elite-installer (root-only, 0600) for updates")
        sp.add_argument("--api-base", help=argparse.SUPPRESS)
        sp.add_argument("--allow-unsupported", action="store_true", help="continue on an OS other than Ubuntu 24.04 (untested)")
        sp.add_argument("-y", "--yes", action="store_true", help="do not ask for confirmation")
        sp.add_argument("--dry-run", action="store_true", help="check, download, verify and validate the package, then stop before changing the system")

    c = sub.add_parser("check", help="check prerequisites; changes nothing")
    c.add_argument("--github", metavar="OWNER/REPO")
    c.add_argument("--token-file", metavar="FILE")
    c.add_argument("--api-base", help=argparse.SUPPRESS)
    c.add_argument("--allow-unsupported", action="store_true")
    i = sub.add_parser("install", help="install ELITE HOSTING (safe to re-run; existing data and keys are kept)")
    source_opts(i)
    i.add_argument("--admin-user", default="admin")
    i.add_argument("--skip-docker-install", action="store_true")
    i.add_argument("--ufw", action="store_true", help="also configure the ufw firewall (SSH, 80, 443)")
    i.add_argument("--force", action="store_true", help="proceed even if the encryption key file is missing (stored secrets become unreadable)")
    u = sub.add_parser("update", help="update an existing installation (backs up first, rolls back on failure)")
    source_opts(u)
    u.add_argument("--skip-docker-install", action="store_true")
    u.add_argument("--force", action="store_true", help="reinstall even if the version is unchanged")
    u.add_argument("--allow-downgrade", action="store_true")
    r = sub.add_parser("uninstall", help="remove ELITE HOSTING (keeps your data unless --purge)")
    r.add_argument("--purge", action="store_true", help="ALSO delete all data, secrets, logs and the service account")
    r.add_argument("-y", "--yes", action="store_true")
    sub.add_parser("version", help="print the installer version")
    return p


def make_options(a: argparse.Namespace) -> Options:
    g = lambda k, d=None: getattr(a, k, d)
    return Options(command=a.command, repo=g("github"), tag=g("tag"), archive=g("archive"), source=g("source"), sha256=g("sha256"),
                   token_file=g("token_file"), save_token=g("save_token", False), admin_user=g("admin_user", "admin"),
                   skip_docker=g("skip_docker_install", False), ufw=g("ufw", False), yes=g("yes", False), dry_run=g("dry_run", False),
                   allow_unsupported=g("allow_unsupported", False), force=g("force", False), allow_downgrade=g("allow_downgrade", False),
                   purge=g("purge", False), api_base=g("api_base"))


def show_checks(ui: Ui, results: list) -> None:
    ui.heading("System check")
    for c in results:
        line = f"{c.name.ljust(26)} {c.detail}"
        {"ok": ui.ok, "warn": ui.warn, "fail": ui.fail}[c.status](line)
        if c.hint and c.status != "ok":
            ui.line("      " + ui.dim(c.hint))


def make_context(a, opts: Options, need_log: bool) -> Context:
    red = Redactor()
    ui = Ui(color=False if a.no_color else None, animate=False if a.no_color else None)
    paths = Paths(a.root)
    log = Log(paths.INSTALLER_LOG if need_log else None, red)
    return Context(paths, ui, log, Runner(log, red), Journal(log), red, opts)


def facts_for(ctx: Context, need_github: bool):
    host = None
    if need_github and not ctx.opts.api_base:
        host = "api.github.com"
    probe = ctx.runner.run(["systemctl", "is-active", "--quiet", "nginx"], check=False).code == 0 if ctx.real else False
    facts = checks.gather_facts(ctx.paths, host, nginx_active=probe)
    ctx.extra["codename"] = facts.codename or "noble"
    return facts


def cmd_check(a, opts) -> int:
    ctx = make_context(a, opts, need_log=False)
    ui = ctx.ui
    ui.logo(__version__, "PREREQUISITE CHECK")
    repo = opts.repo or os.environ.get("ELITE_GITHUB_REPO") or load_state(ctx).get("repo")
    facts = facts_for(ctx, bool(repo))
    results = checks.evaluate(facts, need_root=False, allow_unsupported=opts.allow_unsupported, need_github=bool(repo))
    if repo:
        try:
            token = None
            try:
                token = resolve_token(ctx)
            except InstallError:
                results.append(checks.Check("GitHub token", checks.WARN, "none provided", "Set ELITE_GITHUB_TOKEN or use --token-file."))
            if token:
                rel = github.GitHubClient(repo, token, opts.api_base).release(None)
                pkg, _, version = github.select_assets(rel)
                results.append(checks.Check("Latest stable release", checks.OK, f"{rel.get('tag_name')} ({pkg['name']})"))
        except InstallError as exc:
            results.append(checks.Check("GitHub release", checks.FAIL, str(exc), exc.hint))
    show_checks(ui, results)
    verdict = checks.worst(results)
    ui.line()
    if verdict == checks.FAIL:
        ui.fail("Not ready: fix the items marked ✘ and run the check again.")
        return EXIT_FAIL
    ui.ok("Ready to install." if verdict == checks.OK else "Ready, with warnings (see !).")
    return 0


def summary(ctx: Context, dep: Deployment, updated: bool) -> None:
    ui, ip = ctx.ui, dep.server_ip()
    ui.line()
    ui.line("  " + ui.grad(("ELITE HOSTING updated" if updated else "ELITE HOSTING is installed") + f"  ·  v{dep.st.version}", bold=True))
    lines = [f"Panel URL   http://{ip}/"]
    if dep.admin_password:
        lines += [f"Username    {dep.admin_user}", f"Password    {dep.admin_password}", "",
                  "One-time password: shown only now, never written to a log.",
                  "Sign in, then change it under Account."]
    elif updated:
        lines += ["Your existing accounts and data are unchanged."]
    else:
        lines += ["Sign in with your existing account.", "Forgot it?  sudo elite-hosting-admin reset-password --username NAME"]
    ui.box(lines, "Panel access")
    ui.heading("Next steps")
    ui.info("Add a domain under Domains & SSL (target: ELITE HOSTING panel) and issue a certificate, so the panel uses HTTPS.")
    ui.info(f"Back up {ctx.paths.ENV_FILE} (it holds the encryption key) and {ctx.paths.DATA}.")
    ui.info(f"Logs: {ctx.paths.INSTALLER_LOG}   Status: systemctl status elite-hosting elite-hosting-helper")
    ui.line()


def rollback_report(ctx: Context) -> None:
    ui = ctx.ui
    ui.line()
    ui.warn("Rolling back the changes made by this run…")
    failures = ctx.journal.rollback(lambda label, ok: (ui.ok if ok else ui.fail)(f"rollback: {label}"))
    if failures:
        ui.fail(f"{failures} rollback step(s) failed; see the log.")
    else:
        ui.ok("Previous state restored. Your data, keys and env file were not touched.")
    ui.info("Packages installed from apt (nginx, docker, ...) are left in place.")


def cmd_install_or_update(a, opts) -> int:
    update = opts.command == "update"
    ctx = make_context(a, opts, need_log=True)
    ui, P = ctx.ui, ctx.paths
    ui.logo(__version__, "ELITE INSTALLER" if not update else "ELITE UPDATER")
    if not update:
        ui.line("  Welcome. This will install ELITE HOSTING, your personal VPS panel,")
        ui.line("  with nginx, Docker, Gunicorn and systemd, on this server.")
    else:
        ui.line("  This will update ELITE HOSTING. The database and code are backed up first.")
    facts = facts_for(ctx, not (opts.archive or opts.source))
    results = checks.evaluate(facts, need_root=not opts.dry_run, allow_unsupported=opts.allow_unsupported,
                              need_github=not (opts.archive or opts.source))
    show_checks(ui, results)
    if checks.worst(results) == checks.FAIL:
        ui.line()
        ui.fail("Prerequisites not met. Nothing was changed.")
        return EXIT_FAIL
    if update and not facts.existing_install:
        ui.fail("ELITE HOSTING is not installed here. Use: elite-installer install")
        return EXIT_FAIL
    if not update and facts.existing_install:
        ui.info("An existing installation was found: it will be updated in place; data, keys and env file stay untouched.")

    if not opts.dry_run:
        ui.line()
        if not ui.confirm("Continue with the " + ("update" if update else "installation") + "?", default=False, assume_yes=opts.yes):
            ui.line("  Cancelled. Nothing was changed.")
            return 0

    lock = None
    try:
        if ctx.real:
            lock = open(P.LOCK, "w")
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                raise InstallError("Another ELITE installer is already running.")
        ctx.log.info(f"ELITE INSTALLER {__version__} {opts.command}; source={'github' if not (opts.archive or opts.source) else 'local'}")
        ui.line()
        staged_box = {}
        ui.begin(1 + (0 if opts.dry_run else 12))

        def fetch():
            staged_box["s"] = stage_package(ctx)

        ui.step_start("Downloading and verifying package")
        try:
            fetch()
        except BaseException:
            ui.step_end(False)
            raise
        ui.step_end(True)
        st = staged_box["s"]
        ui.ok(f"Package v{st.version} validated ({st.source})")
        dep = Deployment(ctx, st)
        if opts.dry_run:
            ui.ok("Dry run complete: the package passed all checks. Nothing was installed.")
            return 0
        if update and dep.old_version:
            from .archive import version_tuple
            old, new = version_tuple(dep.old_version), version_tuple(st.version)
            if new == old and not opts.force:
                ui.ok(f"Already up to date (v{st.version}). Use --force to reinstall.")
                return 0
            if new < old and not opts.allow_downgrade:
                raise InstallError(f"Refusing to downgrade v{dep.old_version} -> v{st.version}.", "Use --allow-downgrade if you really want this.")
        steps = install_plan(ctx, dep, update)
        ui.begin(len(steps))
        run_steps(ctx, steps)
        dep.finalize()
        ctx.journal.clear()
        summary(ctx, dep, updated=update or dep.updating)
        ctx.log.info("finished successfully")
        return 0
    except KeyboardInterrupt:
        ui.finish()
        ui.line()
        ui.fail("Interrupted.")
        rollback_report(ctx)
        return EXIT_INTR
    except (InstallError, CommandError) as exc:
        ui.finish()
        ui.line()
        ui.fail(str(exc))
        if getattr(exc, "hint", ""):
            ui.line("      " + ui.dim(exc.hint))
        if isinstance(exc, CommandError):
            for l in exc.tail[-12:]:
                ui.line("      " + ui.dim(l[:ui.width - 10]))
        ctx.log.error(str(exc))
        rollback_report(ctx)
        ui.line()
        ui.info(f"Log: {P.INSTALLER_LOG}")
        return EXIT_FAIL
    finally:
        tmp = ctx.extra.get("tmp")
        if tmp:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)
        if lock:
            lock.close()
        ctx.log.close()


def cmd_uninstall(a, opts) -> int:
    ctx = make_context(a, opts, need_log=False)
    ui = ctx.ui
    ui.logo(__version__, "ELITE UNINSTALLER")
    if ctx.real and os.geteuid() != 0:
        ui.fail("Run as root: sudo elite-installer uninstall")
        return EXIT_FAIL
    ui.line("  This stops and removes the ELITE HOSTING services and its nginx configuration.")
    if opts.purge:
        ui.warn("PURGE: all sites, apps, bots, the database, secrets and the elitehost account will be DELETED.")
        ui.line("  Back up first:  sudo tar czf ~/elite-hosting-backup.tgz /var/lib/elite-hosting /etc/elite-hosting")
        if not opts.yes:
            if not ui.interactive:
                raise SystemExit("Non-interactive purge needs --yes.")
            ui._write("  Type DELETE to continue: ")
            if (ui._tty_input().readline().strip()) != "DELETE":
                ui.line("  Aborted. Nothing was changed.")
                return 1
    elif not ui.confirm("Continue? (your data is kept)", default=False, assume_yes=opts.yes):
        ui.line("  Aborted. Nothing was changed.")
        return 1
    ui.begin(1)
    ui.step_start("Removing ELITE HOSTING")
    uninstall(ctx)
    ui.step_end(True)
    ui.line()
    if opts.purge:
        ui.ok("Purged. Let's Encrypt certificates and apt packages (nginx, docker, certbot) were left in place.")
    else:
        ui.ok("Removed. Kept: /var/lib/elite-hosting (data), /etc/elite-hosting (secrets), Docker containers, certificates.")
        ui.info("Reinstalling later picks everything up again.")
    return 0


def main(argv: list[str] | None = None) -> int:
    reject_secrets_in_argv(list(sys.argv[1:] if argv is None else argv))
    parser = build_parser()
    a = parser.parse_args(argv)
    if a.command == "version":
        print(f"elite-installer {__version__}")
        return 0
    opts = make_options(a)
    try:
        if a.command == "check":
            return cmd_check(a, opts)
        if a.root == "/" and os.geteuid() != 0 and not (a.command in ("install", "update") and opts.dry_run):
            sys.stderr.write(f"ERROR: run as root:  sudo elite-installer {a.command}\n")
            return EXIT_FAIL
        if a.command == "uninstall":
            return cmd_uninstall(a, opts)
        return cmd_install_or_update(a, opts)
    except InstallError as exc:
        sys.stderr.write(f"ERROR: {exc}\n" + (f"       {exc.hint}\n" if exc.hint else ""))
        return EXIT_FAIL
    except KeyboardInterrupt:
        return EXIT_INTR


if __name__ == "__main__":
    sys.exit(main())
