#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
export DNS_WARDEN_LAUNCHED=1
export DNS_WARDEN_SOURCE_ONLY=1
# shellcheck source=../dns-warden.sh disable=SC1091
source "${ROOT_DIR}/dns-warden.sh"

assert_eq() {
  local expected="$1" actual="$2" label="$3"
  if [[ "${actual}" != "${expected}" ]]; then
    printf "FAIL: %s (expected=%s actual=%s)\n" "${label}" "${expected}" "${actual}" >&2
    exit 1
  fi
  printf "PASS: %s\n" "${label}"
}

assert_rejected() {
  local value="$1" label="$2"
  if normalize_dns_target "${value}" >/dev/null 2>&1; then
    printf "FAIL: %s (value was accepted)\n" "${label}" >&2
    exit 1
  fi
  printf "PASS: %s\n" "${label}"
}

getent() {
  case "$1:$2" in
    ahostsv4:dns.example) printf "192.0.2.10 STREAM dns.example\n" ;;
    ahostsv6:v6only.example) printf "2001:db8::10 STREAM v6only.example\n" ;;
    *) return 2 ;;
  esac
}

assert_eq "1.1.1.1" "$(normalize_dns_target " 1.1.1.1 ")" "IPv4 address is accepted and trimmed"
assert_eq "2606:4700:4700::1111" "$(normalize_dns_target 2606:4700:4700::1111)" "IPv6 address is accepted"
assert_eq "192.0.2.10" "$(normalize_dns_target dns.example)" "hostname resolves to IPv4"
assert_eq "2001:db8::10" "$(normalize_dns_target v6only.example)" "hostname falls back to IPv6"

assert_rejected "" "empty target is rejected"
assert_rejected "999.1.1.1" "out-of-range IPv4 is rejected"
assert_rejected "1.1.1.1;reboot" "shell metacharacters are rejected"
assert_rejected $'1.1.1.1\nnameserver 8.8.8.8' "newline injection is rejected"
assert_rejected "unresolvable.example" "unresolvable hostname is rejected"

TMP_BACKUPS="$(mktemp -d)"
trap 'rm -rf "${TMP_BACKUPS}"' EXIT
BACKUP_DIR="${TMP_BACKUPS}"
: > "${BACKUP_DIR}/resolv.conf.20260101-000000"
: > "${BACKUP_DIR}/resolv.conf.20260101-000000.meta"
: > "${BACKUP_DIR}/resolv.conf.20260102-000000"
assert_eq "2" "$(list_backups | wc -l | tr -d ' ')" "backup listing skips .meta files"

assert_eq "$(grep -m1 '^VERSION=' "${ROOT_DIR}/dns-warden.sh" | cut -d'"' -f2)" "${APP_VERSION}" "APP_VERSION matches VERSION"

printf "All apply-target and backup-listing tests passed.\n"
