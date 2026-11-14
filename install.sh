#!/usr/bin/env bash
# ELITE INSTALLER - install.   Usage: sudo ./install.sh [options]   (see: ./elite-installer install --help)
set -Eeuo pipefail
exec "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/elite-installer" install "$@"
