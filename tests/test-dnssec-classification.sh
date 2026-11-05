#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
export DNS_WARDEN_LAUNCHED=1
export DNS_WARDEN_SOURCE_ONLY=1
# shellcheck source=../dns-warden.sh
source "${ROOT_DIR}/dns-warden.sh"

assert_eq() {
  local expected="$1" actual="$2" label="$3"
  if [[ "${actual}" != "${expected}" ]]; then
    printf "FAIL: %s (expected=%s actual=%s)\n" "${label}" "${expected}" "${actual}" >&2
    exit 1
  fi
  printf "PASS: %s\n" "${label}"
}

assert_eq "VALIDATES" \
  "$(classify_dnssec_validation NOERROR 3 SERVFAIL 0 NOERROR 2)" \
  "normal SERVFAIL + CD answers indicates validation"

assert_eq "DOES_NOT_VALIDATE" \
  "$(classify_dnssec_validation NOERROR 3 NOERROR 2 NOERROR 2)" \
  "broken-domain answers in both modes indicate no validation signal"

assert_eq "INCONCLUSIVE" \
  "$(classify_dnssec_validation NOERROR 3 SERVFAIL 0 SERVFAIL 0)" \
  "SERVFAIL in both modes is inconclusive"

assert_eq "INCONCLUSIVE" \
  "$(classify_dnssec_validation SERVFAIL 0 SERVFAIL 0 NOERROR 2)" \
  "failed positive control is inconclusive"

assert_eq "INCONCLUSIVE" \
  "$(classify_dnssec_validation NOERROR 3 SERVFAIL 0 NOERROR 0)" \
  "CD NOERROR without answers is inconclusive"

assert_eq "AD_PRESENT" \
  "$(classify_dnssec_ad_signal NOERROR 3 YES)" \
  "positive control reports AD present"

assert_eq "AD_ABSENT" \
  "$(classify_dnssec_ad_signal NOERROR 3 NO)" \
  "positive control reports AD absent independently"

assert_eq "INCONCLUSIVE" \
  "$(classify_dnssec_ad_signal SERVFAIL 0 NO)" \
  "failed positive control makes AD signal inconclusive"

# Verify that query_dns actually sends the requested flags to dig.
MOCK_DIR="$(mktemp -d)"
trap 'rm -rf "${MOCK_DIR}"' EXIT
export DNS_WARDEN_TEST_DIG_LOG="${MOCK_DIR}/dig-args.log"
mkdir -p "${MOCK_DIR}/bin"
cat > "${MOCK_DIR}/bin/dig" <<'MOCK_DIG'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "${DNS_WARDEN_TEST_DIG_LOG}"
cat <<'DNS_RESPONSE'
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1234
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1
;; ANSWER SECTION:
example.test. 60 IN A 192.0.2.1
;; Query time: 1 msec
DNS_RESPONSE
MOCK_DIG
chmod +x "${MOCK_DIR}/bin/dig"
export PATH="${MOCK_DIR}/bin:${PATH}"

: > "${DNS_WARDEN_TEST_DIG_LOG}"
query_dns 192.0.2.53 example.test udp ad >/dev/null
grep -q -- '+adflag' "${DNS_WARDEN_TEST_DIG_LOG}"
if grep -q -- '+cdflag' "${DNS_WARDEN_TEST_DIG_LOG}"; then
  printf "FAIL: AD-only query unexpectedly sent CD\n" >&2
  exit 1
fi
printf "PASS: AD probe sends +adflag without +cdflag\n"

: > "${DNS_WARDEN_TEST_DIG_LOG}"
query_dns 192.0.2.53 example.test udp cd >/dev/null
grep -q -- '+adflag' "${DNS_WARDEN_TEST_DIG_LOG}"
grep -q -- '+cdflag' "${DNS_WARDEN_TEST_DIG_LOG}"
printf "PASS: CD probe sends both +adflag and +cdflag\n"

printf "All DNSSEC classification tests passed.\n"
