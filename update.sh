#!/usr/bin/env bash
# ELITE INSTALLER - update.   Usage: sudo ./update.sh [options]   (see: ./elite-installer update --help)
set -Eeuo pipefail
exec "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/elite-installer" update "$@"
