#!/usr/bin/env bash
# ELITE INSTALLER - check prerequisites without changing anything.   Usage: ./check.sh [--github OWNER/REPO]
set -Eeuo pipefail
exec "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/elite-installer" check "$@"
