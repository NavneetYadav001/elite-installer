#!/usr/bin/env bash
#
# Build the files you upload to YOUR distribution endpoint:
#     tools/build-dist.sh --endpoint https://your-endpoint.example/path
# Output in ./dist:  elite-installer-X.Y.Z.tar.gz   elite-installer-X.Y.Z.tar.gz.sha256   get-elite.sh
# Upload all three so that  <endpoint>/get-elite.sh  and  <endpoint>/elite-installer-X.Y.Z.tar.gz  resolve.
#
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENDPOINT=""
while [ $# -gt 0 ]; do
  case "$1" in
    --endpoint) ENDPOINT="${2:-}"; shift 2 ;;
    -h|--help) sed -n '2,8p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done
[[ "$ENDPOINT" =~ ^https://[A-Za-z0-9._~:/-]+$ ]] || { echo "ERROR: --endpoint must be an https:// URL you control (no spaces or special characters)." >&2; exit 2; }
ENDPOINT="${ENDPOINT%/}"
VERSION="$(python3 -I -c "import re,sys; print(re.search(r'__version__ = \"([^\"]+)\"', open(sys.argv[1]).read()).group(1))" "${ROOT}/elite_installer/__init__.py")"
OUT="${ROOT}/dist"; rm -rf "$OUT"; mkdir -p "$OUT"
STAGE="$(mktemp -d)"; trap 'rm -rf "$STAGE"' EXIT
mkdir "${STAGE}/elite-installer"
cp -r "${ROOT}/elite_installer" "${STAGE}/elite-installer/"
cp "${ROOT}/elite-installer" "${ROOT}"/{install,update,uninstall,check}.sh "${ROOT}/README.md" "${STAGE}/elite-installer/"
find "${STAGE}" -name '__pycache__' -prune -exec rm -rf {} +
PKG="elite-installer-${VERSION}.tar.gz"
tar --sort=name --owner=0 --group=0 --numeric-owner --mtime='2000-01-01 00:00:00' -C "$STAGE" -cf - elite-installer | gzip -9n > "${OUT}/${PKG}"
SHA="$(sha256sum "${OUT}/${PKG}" | awk '{print $1}')"
echo "${SHA}  ${PKG}" > "${OUT}/${PKG}.sha256"
sed -e "s|@@ENDPOINT@@|${ENDPOINT}|" -e "s|@@VERSION@@|${VERSION}|" -e "s|@@SHA256@@|${SHA}|" "${ROOT}/bootstrap.sh.in" > "${OUT}/get-elite.sh"
chmod 0755 "${OUT}/get-elite.sh"; bash -n "${OUT}/get-elite.sh"
echo "Built ${OUT}:"; ls -l "$OUT"
echo
echo "After uploading these files to ${ENDPOINT}/ , the one-line installer is:"
echo "  curl -fsSL ${ENDPOINT}/get-elite.sh | sudo bash -s -- install --github OWNER/REPO"
echo "(It does not work until you have uploaded the files. Pin: sha256 ${SHA})"
