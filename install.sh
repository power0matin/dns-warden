#!/usr/bin/env bash
# dns-warden installer: downloads a release, verifies its checksum and installs the `dns-warden` command.
#
#   bash <(curl -fsSL https://raw.githubusercontent.com/power0matin/dns-warden/main/install.sh)
#
# Options:  --version <vX.Y.Z>  install a specific release (default: latest)
#           --no-run            install only, do not start the menu
#           --uninstall         remove dns-warden (backups and reports are kept)
set -euo pipefail

REPO="power0matin/dns-warden"
INSTALL_DIR="/usr/local/share/dns-warden"
BIN_PATH="/usr/local/bin/dns-warden"

VERSION="${DNS_WARDEN_VERSION:-latest}"
RUN_AFTER=1
UNINSTALL=0

log()  { printf '[dns-warden] %s\n' "$*"; }
fail() { printf '[dns-warden] ERROR: %s\n' "$*" >&2; exit 1; }

while (( $# > 0 )); do
  case "$1" in
    --version)   [[ $# -ge 2 ]] || fail "--version requires a tag such as v1.6.0"; VERSION="$2"; shift 2 ;;
    --no-run)    RUN_AFTER=0; shift ;;
    --uninstall) UNINSTALL=1; shift ;;
    -h|--help)   sed -n '2,9p' "${BASH_SOURCE[0]}" 2>/dev/null | sed 's/^# \{0,1\}//' || true; exit 0 ;;
    *)           fail "Unknown option: $1" ;;
  esac
done

SUDO=""
if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  command -v sudo >/dev/null 2>&1 || fail "Run as root or install sudo."
  SUDO="sudo"
fi

if (( UNINSTALL == 1 )); then
  ${SUDO} rm -f "${BIN_PATH}"
  ${SUDO} rm -rf "${INSTALL_DIR}"
  log "Removed. Backups (/var/backups/dns-warden) and reports (/var/log/dns-warden) were kept."
  exit 0
fi

command -v curl >/dev/null 2>&1 || fail "curl is required."
command -v sha256sum >/dev/null 2>&1 || fail "sha256sum is required."

if [[ "${VERSION}" == "latest" ]]; then
  BASE_URL="https://github.com/${REPO}/releases/latest/download"
else
  [[ "${VERSION}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "Invalid version '${VERSION}' (expected vX.Y.Z)."
  BASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"
fi

if ! command -v dig >/dev/null 2>&1; then
  command -v apt-get >/dev/null 2>&1 || fail "dig is missing and apt-get is unavailable. Install dnsutils manually."
  log "Installing dependency: dnsutils"
  ${SUDO} apt-get update -qq
  ${SUDO} apt-get install -y -qq dnsutils
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

log "Downloading ${VERSION} release"
for f in dns-warden.sh dns-list.txt SHA256SUMS; do
  curl -fsSL --retry 3 -o "${TMP_DIR}/${f}" "${BASE_URL}/${f}" || fail "Download failed: ${BASE_URL}/${f}"
done

log "Verifying checksums"
( cd "${TMP_DIR}" && sha256sum --check --ignore-missing --status SHA256SUMS ) || fail "Checksum verification failed."
bash -n "${TMP_DIR}/dns-warden.sh" || fail "Downloaded script failed the syntax check."

${SUDO} install -d -m 0755 "${INSTALL_DIR}"
if [[ -f "${INSTALL_DIR}/dns-list.txt" ]] && ! cmp -s "${INSTALL_DIR}/dns-list.txt" "${TMP_DIR}/dns-list.txt"; then
  ${SUDO} cp -p "${INSTALL_DIR}/dns-list.txt" "${INSTALL_DIR}/dns-list.txt.bak"
  log "Previous resolver list saved to ${INSTALL_DIR}/dns-list.txt.bak"
fi
${SUDO} install -m 0755 "${TMP_DIR}/dns-warden.sh" "${INSTALL_DIR}/dns-warden.sh"
${SUDO} install -m 0644 "${TMP_DIR}/dns-list.txt" "${INSTALL_DIR}/dns-list.txt"

printf '#!/usr/bin/env bash\nexec bash %s/dns-warden.sh "$@"\n' "${INSTALL_DIR}" > "${TMP_DIR}/dns-warden"
${SUDO} install -m 0755 "${TMP_DIR}/dns-warden" "${BIN_PATH}"

log "Installed $(bash "${INSTALL_DIR}/dns-warden.sh" --version) -> ${BIN_PATH}"

if (( RUN_AFTER == 1 )) && [[ -t 0 && -t 1 ]]; then
  exec ${SUDO} "${BIN_PATH}"
fi
log "Run it with: sudo dns-warden"
