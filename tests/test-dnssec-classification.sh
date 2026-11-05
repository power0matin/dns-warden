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
args="$*"
printf '%s\n' "${args}" >> "${DNS_WARDEN_TEST_DIG_LOG}"

if [[ "${args}" == *"version.bind"* ]]; then
  cat <<'DNS_RESPONSE'
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1234
;; flags: qr aa rd; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1
;; ANSWER SECTION:
version.bind. 0 CH TXT "9.18.0"
;; Query time: 1 msec
DNS_RESPONSE
elif [[ "${args}" == *"dnssec-failed.org"* && "${args}" == *"+cdflag"* ]]; then
  cat <<'DNS_RESPONSE'
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1234
;; flags: qr rd ra cd; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 1
;; ANSWER SECTION:
dnssec-failed.org. 60 IN A 192.0.2.9
dnssec-failed.org. 60 IN RRSIG A 8 2 60 20300101000000 20290101000000 12345 dnssec-failed.org. FAKE
;; Query time: 1 msec
DNS_RESPONSE
elif [[ "${args}" == *"dnssec-failed.org"* ]]; then
  cat <<'DNS_RESPONSE'
;; ->>HEADER<<- opcode: QUERY, status: SERVFAIL, id: 1234
;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1
;; Query time: 2 msec
DNS_RESPONSE
elif [[ "${args}" == *"cloudflare.com"* ]]; then
  cat <<'DNS_RESPONSE'
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1234
;; flags: qr rd ra ad; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 1
;; ANSWER SECTION:
cloudflare.com. 60 IN A 192.0.2.10
cloudflare.com. 60 IN RRSIG A 8 2 60 20300101000000 20290101000000 12345 cloudflare.com. FAKE
;; Query time: 1 msec
DNS_RESPONSE
else
  cat <<'DNS_RESPONSE'
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1234
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1
;; ANSWER SECTION:
github.com. 60 IN A 192.0.2.1
;; Query time: 1 msec
DNS_RESPONSE
fi
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

# Exercise the endpoint integration and its 11-field summary with deterministic dig output.
DNS_COUNT=1
DNS_TIMEOUT=1
DNS_TEST_DOMAINS=("github.com")
LAST_DETAILS_FILE="${MOCK_DIR}/endpoint.details.txt"
: > "${LAST_DETAILS_FILE}"

summary="$(test_dns_endpoint 192.0.2.53)"
IFS='|' read -r endpoint successful total avg tcp bind score ad_count bind_value dnssec ad_signal <<< "${summary}"
assert_eq "192.0.2.53" "${endpoint}" "endpoint summary address"
assert_eq "1/1" "${successful}/${total}" "single UDP matrix probe succeeds"
assert_eq "OK" "${tcp}" "TCP status is included in endpoint summary"
assert_eq "BIND_VERSION_LIKE" "${bind}" "BIND-like fingerprint is preserved"
assert_eq "VALIDATES" "${dnssec}" "normal-vs-CD result reaches endpoint summary"
assert_eq "AD_PRESENT" "${ad_signal}" "AD signal reaches endpoint summary"

grep -q '^192\.0\.2\.53|cloudflare\.com|DNSSEC_POSITIVE|NOERROR|2|' "${LAST_DETAILS_FILE}"
grep -q '^192\.0\.2\.53|dnssec-failed\.org|DNSSEC_NORMAL|SERVFAIL|0|' "${LAST_DETAILS_FILE}"
grep -q '^192\.0\.2\.53|dnssec-failed\.org|DNSSEC_CD|NOERROR|2|' "${LAST_DETAILS_FILE}"
printf "PASS: per-query report contains all three DNSSEC probe rows\n"

printf "All DNSSEC classification and integration tests passed.\n"
