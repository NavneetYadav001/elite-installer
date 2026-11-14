#!/usr/bin/env bash
# ELITE INSTALLER - uninstall.   Usage: sudo ./uninstall.sh [options]   (see: ./elite-installer uninstall --help)
set -Eeuo pipefail
exec "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/elite-installer" uninstall "$@"
