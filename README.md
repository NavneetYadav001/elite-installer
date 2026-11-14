# ELITE INSTALLER

A separate, terminal-first installer for **ELITE HOSTING** on **Ubuntu 24.04 LTS**. It checks the server, downloads the latest
stable release from your **private GitHub repository**, verifies and safely unpacks it, installs and configures everything
(venv, Gunicorn, systemd, nginx, Docker, certbot), validates the configuration **before** restarting any service, and rolls back
if something fails. The panel itself is unchanged; the old `install.sh` inside the panel project keeps working for tarball installs.

```
elite-installer check                        prerequisites only - changes nothing
elite-installer install --github OWNER/REPO  first install (re-runnable; keeps data, keys and env file)
elite-installer update                       update to the newest stable release (backup + automatic rollback)
elite-installer uninstall [--purge]          remove (data kept unless --purge, which needs typing DELETE)
```
`install.sh`, `update.sh`, `uninstall.sh` and `check.sh` in this folder are thin wrappers around the same commands.

## What a run looks like
Gradient blue/purple ASCII logo (compact on phone-width terminals), welcome + confirmation, system check
(Ubuntu version, CPU, RAM, disk on `/opt` and `/var`, root, systemd, Python, ports 80/443, GitHub reachability),
then an animated progress bar with live status for each step, and finally the panel URL and a **one-time admin password**
(shown once on screen, never logged). `--no-color` or a non-terminal gives plain text.

## Requirements
Ubuntu 24.04 LTS (x86_64 or aarch64) with systemd, root access, ≥512 MB RAM (1 GB+ recommended), ≥3 GB free disk (6 GB+ recommended),
and internet access. `python3` ships with Ubuntu.

## 1. Publish a release of the panel (on your computer)
The installer only installs **published, non-draft, non-prerelease** GitHub releases, so "latest" means latest stable.
```bash
cd elite-hosting
tools/make-release.sh            # runs the panel tests, builds dist/elite-hosting-X.Y.Z.tar.gz + SHA256SUMS
gh release create vX.Y.Z dist/elite-hosting-X.Y.Z.tar.gz dist/SHA256SUMS --title "ELITE HOSTING X.Y.Z"
```
The tag must equal the `VERSION` file (`v1.0.0` ↔ `1.0.0`). A release without `SHA256SUMS` is refused.

## 2. Create a read-only GitHub token
GitHub → Settings → Developer settings → **Fine-grained personal access tokens** → repository access: *only* your panel repo →
permission **Contents: Read-only**. Put it in a file on the server (never on the command line):
```bash
install -m 600 /dev/null ~/gh-token && nano ~/gh-token     # paste the token, save
```
Tokens are accepted only from `--token-file FILE`, the `ELITE_GITHUB_TOKEN` variable, or a hidden prompt. Anything token-shaped
on the command line is rejected. `--save-token` stores it root-only (0600) in `/etc/elite-installer/` so `update` needs no input.

## 3. Install
```bash
# copy this folder to the server (from Termux: scp -r elite-installer you@SERVER:~), then:
cd elite-installer
./check.sh --github OWNER/REPO                         # optional prerequisites check (also validates your token + latest release)
sudo ./install.sh --github OWNER/REPO --token-file ~/gh-token
```
Useful options: `--tag vX.Y.Z`, `--sha256 HEX` (pin the exact package), `--admin-user NAME`, `--skip-docker-install`, `--ufw`,
`--dry-run` (download + verify + validate, then stop), `--yes` (no confirmation), `--save-token`.
Offline/local sources: `--archive elite-hosting-X.Y.Z.tar.gz [--sha256 HEX]` or `--source DIR` (both flagged as unverified unless pinned).

Update later with `sudo ./update.sh` (the repository is remembered). Same version → "already up to date"; downgrades need `--allow-downgrade`.

## One-line installation (not live until YOU configure an endpoint)
This project does not ship or assume a domain. You host three small files on a web location you control, then the one-liner works.
```bash
tools/build-dist.sh --endpoint https://YOUR-ENDPOINT/path     # writes dist/: installer tarball, .sha256, get-elite.sh
# upload the three files from dist/ so that  https://YOUR-ENDPOINT/path/get-elite.sh  is reachable
```
It then prints the command; its shape is:
```bash
curl -fsSL https://YOUR-ENDPOINT/path/get-elite.sh | sudo bash -s -- install --github OWNER/REPO
```
`get-elite.sh` downloads the installer tarball over HTTPS (TLS ≥1.2), compares it to the SHA-256 baked into the script at build time,
refuses to run on mismatch, unpacks into a private temp folder and starts the installer (prompts use your terminal, not the pipe).
An unconfigured template (`bootstrap.sh.in`) refuses to run. **Prefer to read before you run:** `curl -fsSLO …/get-elite.sh`,
inspect it, then `sudo bash get-elite.sh install …`. The command only works after you have uploaded the files; until then it does not.

## Safety design
| Concern | What the installer does |
|---|---|
| Token | Never in argv, output, logs or child-process environment; sent only to `api.github.com`; dropped on redirects to other hosts (asset storage); https→http redirects refused; token-shaped text is scrubbed from every log line |
| Authenticity | SHA-256 from `SHA256SUMS`, GitHub's own asset digest and an optional `--sha256` pin must **all** agree; tag must match package version; size caps |
| Untrusted download | Extracted by a strict extractor (no links, devices, `..`, absolute paths, duplicates, setuid; one top folder; size/count limits) and only **read**; static validation of layout, Python syntax, `requirements.txt` (plain `name>=x,<y` only), and systemd units (fixed `ExecStart`, no `ExecStartPre`/`Post`, panel must run as `elitehost`) |
| No arbitrary execution | Nothing from the download is run through a shell or as an install script; the installer's own logic installs the files. `pip` uses `--only-binary=:all:` so no `setup.py` runs. The panel code is imported only as the unprivileged `elitehost` user against a scratch data dir |
| Existing data | Existing DB, `ELITE_SECRET_KEY`/env file, sites, apps and bots are never overwritten. If a database exists but the env file is missing, install stops (a new key would make stored secrets unreadable) unless `--force` |
| Validation first | compileall, unit syntax, `bash -n`, app boot test (`/healthz`), and `nginx -t` all pass before helper/panel/nginx are (re)started |
| Rollback | Every change is journaled and undone newest-first: files restored, new files/dirs/user removed (only things created by that run), DB restored from an online backup, services restarted. apt packages stay installed |
| Concurrency | One run at a time (`flock`); Ctrl-C triggers rollback |

Honest limits: the release is **code that runs on your server as root-adjacent components** (the helper). Trust anchors are your private repo,
your token's scope, and — if you use `--sha256` — your own pin. Checksums published in the same release detect corruption/tampering of
the asset but cannot prove authorship; protect your GitHub account (2FA, branch protection). The installer cannot undo packages it installed
with apt, and Docker group membership for the panel account remains root-equivalent (see the panel README).

## Logs
`/var/log/elite-installer/installer.log` (root only, 0600, redacted, rotated weekly). Failures show the last lines of the failing command.

## Tests
```bash
python3 -m unittest discover -s tests -v      # 51 tests; no root, network, systemd or Docker needed
```
They cover redaction, token handling, GitHub download against a local mock (including the redirect/auth behaviour and tampered
checksums), archive attacks, requirement/unit validation, prerequisites, the UI, full install/re-install/update flows and rollback on a fake
system, uninstall, CLI secret rejection, and the build-dist/bootstrap scripts. What they cannot prove: behaviour of apt/systemd/nginx/Docker
on a real Ubuntu 24.04 host — do a first install on a fresh VM before relying on it.
