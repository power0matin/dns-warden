#!/usr/bin/env bash
# DNS Warden - Ubuntu-only DNS tester & switcher (Rathole_v2-style TUI)
# Safe for: Ubuntu 20.04+
# No external deps beyond core utils; uses less/nano if present.

# ---------------------------
# Loader: sudo re-exec support
# ---------------------------
if [[ -z "${DNS_WARDEN_LAUNCHED:-}" ]]; then
  export DNS_WARDEN_LAUNCHED=1

  _euid="${EUID:-$(id -u)}"
  _script_path="${BASH_SOURCE[0]:-}"

  if [[ -z "${_script_path}" || ! -r "${_script_path}" ]]; then
    _tmp="$(mktemp -t dns-warden.XXXXXX)"
    cat > "${_tmp}"
    chmod 0700 "${_tmp}"

    if [[ "${_euid}" -ne 0 ]]; then
      if command -v sudo >/dev/null 2>&1; then
        exec sudo -E bash "${_tmp}" "$@"
      else
        echo "ERROR: This script must run as root, and 'sudo' is not available." >&2
        exit 1
      fi
    else
      exec bash "${_tmp}" "$@"
    fi
  else
    if [[ "${_euid}" -ne 0 ]]; then
      if command -v sudo >/dev/null 2>&1; then
        exec sudo -E bash "${_script_path}" "$@"
      else
        echo "ERROR: This script must run as root, and 'sudo' is not available." >&2
        exit 1
      fi
    fi
  fi
fi

set -euo pipefail
IFS=$'\n\t'
export LC_ALL=C

VERSION="1.2.0"
SCRIPT_NAME="dns-warden.sh"
APP_VERSION="${VERSION}"

PING_COUNT_DEFAULT=3
PING_TIMEOUT_DEFAULT=2
PING_COUNT="${PING_COUNT_DEFAULT}"
PING_TIMEOUT="${PING_TIMEOUT_DEFAULT}"

SCRIPT_DIR=""
CONFIG_DIR="/etc/dns-warden"
BACKUP_DIR="/var/backups/dns-warden"
LIST_FILE=""

TMP_DIR=""
LAST_RESULTS_FILE=""
LAST_TABLE_FILE=""

FLAG_TEST_ONLY=0
FLAG_APPLY_DNS=""
FLAG_METHOD=""     # auto|resolved|force
FLAG_YES=0
FLAG_LIST_OVERRIDE=""

# ---------------------------
# Colors (Rathole_v2-like)
# ---------------------------
is_tty() { [[ -t 1 ]]; }

c_reset() { is_tty && printf "\033[0m" || true; }
c_dim()   { is_tty && printf "\033[2m" || true; }
c_bold()  { is_tty && printf "\033[1m" || true; }
c_red()   { is_tty && printf "\033[31m" || true; }
c_green() { is_tty && printf "\033[32m" || true; }
c_yellow(){ is_tty && printf "\033[33m" || true; }
c_blue()  { is_tty && printf "\033[34m" || true; }
c_cyan()  { is_tty && printf "\033[36m" || true; }
c_mag()   { is_tty && printf "\033[35m" || true; }

# ---------------------------
# Logging
# ---------------------------
log_info()  { printf "%s[INFO]%s %s\n"  "$(c_cyan)" "$(c_reset)" "$*"; }
log_warn()  { printf "%s[WARN]%s %s\n"  "$(c_yellow)" "$(c_reset)" "$*"; }
log_error() { printf "%s[ERR ]%s %s\n"  "$(c_red)" "$(c_reset)" "$*"; }
die()       { log_error "$*"; exit 1; }

# ---------------------------
# Cleanup
# ---------------------------
cleanup() {
  if [[ -n "${TMP_DIR}" && -d "${TMP_DIR}" ]]; then
    rm -rf "${TMP_DIR}"
  fi
}
trap cleanup EXIT

# ---------------------------
# Helpers
# ---------------------------
have_command() { command -v "$1" >/dev/null 2>&1; }

ensure_dirs() {
  mkdir -p "${CONFIG_DIR}" "${BACKUP_DIR}"
  chmod 0755 "${CONFIG_DIR}" "${BACKUP_DIR}"
}

detect_script_dir() {
  if [[ -n "${BASH_SOURCE[0]:-}" && -r "${BASH_SOURCE[0]}" ]]; then
    SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
  else
    SCRIPT_DIR="$(pwd -P)"
  fi
}

detect_ubuntu_or_exit() {
  [[ -r /etc/os-release ]] || die "Cannot read /etc/os-release. This script requires Ubuntu 20.04+."
  local os_id os_ver
  mapfile -t _os < <(. /etc/os-release && printf '%s\n%s\n' "${ID:-}" "${VERSION_ID:-}")
  os_id="${_os[0]:-}"
  os_ver="${_os[1]:-0}"

  if [[ "${os_id}" != "ubuntu" ]]; then
    die "Unsupported OS: ID='${os_id:-unknown}'. This script supports Ubuntu 20.04+ only."
  fi

  local ver="${os_ver}"
  local major="${ver%%.*}"
  if [[ "${major}" =~ ^[0-9]+$ ]]; then
    (( major >= 20 )) || die "Unsupported Ubuntu version: ${ver}. Require Ubuntu 20.04+."
  else
    die "Could not parse Ubuntu version (VERSION_ID='${ver}')."
  fi
}

ensure_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    die "Root is required (this should have been handled by the loader)."
  fi
}

init_tmp() {
  TMP_DIR="$(mktemp -d -t dns-warden-tmp.XXXXXX)"
  chmod 0700 "${TMP_DIR}"
  LAST_RESULTS_FILE="${TMP_DIR}/results.raw"
  LAST_TABLE_FILE="${TMP_DIR}/results.table.txt"
}

trim() {
  local s="$1"
  s="$(echo "${s}" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
  printf "%s" "${s}"
}

is_ipv4() {
  local ip="$1"
  [[ "${ip}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  local o1 o2 o3 o4
  IFS='.' read -r o1 o2 o3 o4 <<< "${ip}"
  for o in "${o1}" "${o2}" "${o3}" "${o4}"; do
    [[ "${o}" =~ ^[0-9]+$ ]] || return 1
    (( o >= 0 && o <= 255 )) || return 1
  done
  return 0
}

is_ipv6() {
  local ip="$1"
  [[ "${ip}" =~ ^[0-9A-Fa-f:]+$ ]] || return 1
  [[ "${ip}" == *:* ]] || return 1
  return 0
}

resolve_prefer_v4_then_v6() {
  local host="$1"
  local ip=""
  if getent ahostsv4 "${host}" >/dev/null 2>&1; then
    ip="$(getent ahostsv4 "${host}" | awk '{print $1; exit}')"
    [[ -n "${ip}" ]] && { printf "4 %s" "${ip}"; return 0; }
  fi
  if getent ahostsv6 "${host}" >/dev/null 2>&1; then
    ip="$(getent ahostsv6 "${host}" | awk '{print $1; exit}')"
    [[ -n "${ip}" ]] && { printf "6 %s" "${ip}"; return 0; }
  fi
  return 1
}

init_list_file() {
  if [[ -n "${FLAG_LIST_OVERRIDE}" ]]; then
    LIST_FILE="${FLAG_LIST_OVERRIDE}"
    return 0
  fi

  if [[ -n "${SCRIPT_DIR}" && -r "${SCRIPT_DIR}/dns-list.txt" ]]; then
    LIST_FILE="${SCRIPT_DIR}/dns-list.txt"
    return 0
  fi

  LIST_FILE="${CONFIG_DIR}/dns-list.txt"
  if [[ ! -f "${LIST_FILE}" ]]; then
    cat > "${LIST_FILE}" <<'EOF'
# dns-warden default list
# One entry per line: IPv4, IPv6, or hostname
# Comments start with '#'

# Cloudflare
1.1.1.1
1.0.0.1
2606:4700:4700::1111
2606:4700:4700::1001

# Google
8.8.8.8
8.8.4.4
2001:4860:4860::8888
2001:4860:4860::8844

# Quad9
9.9.9.9
149.112.112.112
2620:fe::fe
2620:fe::9

# OpenDNS (Cisco)
208.67.222.222
208.67.220.220
2620:119:35::35
2620:119:53::53

# Hostname examples
# one.one.one.one
# dns.google
EOF
    chmod 0644 "${LIST_FILE}"
  fi
}

# ---------------------------
# DNS list parsing
# ---------------------------
read_dns_list() {
  local file="$1"
  [[ -r "${file}" ]] || die "DNS list file not readable: ${file}"

  local line raw
  local -a entries=()
  while IFS= read -r raw || [[ -n "${raw}" ]]; do
    line="$(trim "${raw}")"
    [[ -z "${line}" ]] && continue
    [[ "${line}" == \#* ]] && continue
    entries+=("${line}")
  done < "${file}"

  (( ${#entries[@]} > 0 )) || die "DNS list is empty after filtering comments/blank lines: ${file}"
  printf "%s\n" "${entries[@]}"
}

# ---------------------------
# Ping testing
# ---------------------------
ping_one() {
  local endpoint="$1"

  local family="" ip_for_ping="" display="${endpoint}"
  local resolved="" ip=""

  if is_ipv4 "${endpoint}"; then
    family="4"; ip_for_ping="${endpoint}"
  elif is_ipv6 "${endpoint}"; then
    family="6"; ip_for_ping="${endpoint}"
  else
    if resolved="$(resolve_prefer_v4_then_v6 "${endpoint}" 2>/dev/null)"; then
      family="$(awk '{print $1}' <<< "${resolved}")"
      ip="$(awk '{print $2}' <<< "${resolved}")"
      ip_for_ping="${ip}"
    else
      family="?"; ip_for_ping="${endpoint}"
    fi
  fi

  local ping_cmd="" ping_args=()
  if [[ "${family}" == "6" ]]; then
    if have_command ping6; then
      ping_cmd="ping6"; ping_args=(-c "${PING_COUNT}" -W "${PING_TIMEOUT}")
    else
      ping_cmd="ping"; ping_args=(-6 -c "${PING_COUNT}" -W "${PING_TIMEOUT}")
    fi
  else
    ping_cmd="ping"; ping_args=(-4 -c "${PING_COUNT}" -W "${PING_TIMEOUT}")
  fi

  local out rc=0
  set +e
  out="$("${ping_cmd}" "${ping_args[@]}" "${ip_for_ping}" 2>&1)"
  rc=$?
  set -e

  local loss avg score
  loss="$(awk '/packet loss/ {for (i=1;i<=NF;i++) if ($i ~ /%/) {gsub(/%/,"",$i); print $i; exit}}' <<< "${out}" || true)"
  [[ -n "${loss}" ]] || loss="100"

  avg="$(awk '
    /rtt min\/avg\/max\/mdev/ || /round-trip min\/avg\/max\/stddev/ {
      split($0, a, "=")
      gsub(/^[[:space:]]+/, "", a[2])
      split(a[2], b, "/")
      print b[2]
      exit
    }' <<< "${out}" || true)"
  [[ -n "${avg}" ]] || avg="9999"

  score="$(awk -v a="${avg}" -v l="${loss}" 'BEGIN{printf "%.3f", a + (l*1000)}')"
  printf "%s|%s|%s|%s|%s\n" "${display}" "${family}" "${loss}" "${avg}" "${score}"
  return "${rc}"
}

build_results_table() {
  [[ -s "${LAST_RESULTS_FILE}" ]] || die "No results to display."
  local sorted="${TMP_DIR}/results.sorted"
  sort -t'|' -k5,5n "${LAST_RESULTS_FILE}" > "${sorted}"

  {
    printf "DNS Warden v%s\n" "${APP_VERSION}"
    printf "List file: %s\n" "${LIST_FILE}"
    printf "Backups:   %s\n" "${BACKUP_DIR}"
    printf "Ping:      count=%s timeout=%ss\n" "${PING_COUNT}" "${PING_TIMEOUT}"
    printf "\n"
    printf "Results (sorted by score; lower is better)\n"
    printf -- "------------------------------------------------------------\n"
    printf "%-4s  %-42s  %-6s  %-7s  %-10s\n" "Rank" "DNS" "Loss%" "Avg(ms)" "Score"
    printf "%-4s  %-42s  %-6s  %-7s  %-10s\n" "----" "------------------------------------------" "------" "-------" "----------"

    local rank=0 endpoint family loss avg score
    while IFS='|' read -r endpoint family loss avg score; do
      rank=$((rank + 1))
      printf "%-4s  %-42s  %-6s  %-7s  %-10s\n" "${rank}" "${endpoint}" "${loss}" "${avg}" "${score}"
    done < "${sorted}"

    printf "\nNotes:\n"
    printf -- "- Hostnames are resolved (prefer IPv4; fallback IPv6).\n"
    printf -- "- Loss is heavily penalized in score (loss*1000).\n"
  } > "${LAST_TABLE_FILE}"
}

test_dns_list() {
  local -a entries=()
  mapfile -t entries < <(read_dns_list "${LIST_FILE}")

  : > "${LAST_RESULTS_FILE}"

  # UX: minimal progress indicator
  local total="${#entries[@]}"
  local i=0 e
  for e in "${entries[@]}"; do
    i=$((i+1))
    if is_tty; then
      printf "\r%sTesting DNS...%s %s/%s  " "$(c_cyan)" "$(c_reset)" "${i}" "${total}"
    fi
    ping_one "${e}" >> "${LAST_RESULTS_FILE}" || true
  done
  if is_tty; then printf "\r%sTesting DNS...%s done.           \n" "$(c_green)" "$(c_reset)"; fi

  build_results_table
}

# ---------------------------
# DNS apply logic
# ---------------------------
resolv_conf_is_symlink() { [[ -L /etc/resolv.conf ]]; }

resolv_conf_symlink_managed_by_systemd() {
  resolv_conf_is_symlink || return 1
  local target
  target="$(readlink -f /etc/resolv.conf || true)"
  [[ "${target}" == /run/systemd/resolve/* ]]
}

systemd_resolved_active() {
  have_command systemctl || return 1
  systemctl is-active --quiet systemd-resolved
}

backup_resolv_conf() {
  ensure_dirs
  local ts backup meta
  ts="$(date +%Y%m%d-%H%M%S)"
  backup="${BACKUP_DIR}/resolv.conf.${ts}"
  meta="${backup}.meta"

  local is_link=0 target_rel="" target_abs=""
  if [[ -L /etc/resolv.conf ]]; then
    is_link=1
    target_rel="$(readlink /etc/resolv.conf || true)"
    target_abs="$(readlink -f /etc/resolv.conf || true)"
    cp -L --preserve=mode,ownership,timestamps /etc/resolv.conf "${backup}"
  else
    cp --preserve=mode,ownership,timestamps /etc/resolv.conf "${backup}"
  fi

  {
    printf "TIMESTAMP=%s\n" "${ts}"
    printf "IS_SYMLINK=%s\n" "${is_link}"
    printf "SYMLINK_TARGET_REL=%s\n" "${target_rel}"
    printf "SYMLINK_TARGET_ABS=%s\n" "${target_abs}"
  } > "${meta}"
  chmod 0600 "${meta}"
  printf "%s" "${backup}"
}

confirm() {
  # confirm "question"
  local q="$1"
  if (( FLAG_YES == 1 )); then
    return 0
  fi
  printf "%s%s%s [y/N]: " "$(c_yellow)" "${q}" "$(c_reset)"
  local ans=""
  read -r ans
  [[ "${ans}" =~ ^[Yy]$ ]]
}

apply_force_resolv_conf() {
  local dns="$1"
  local backup
  backup="$(backup_resolv_conf)"

  if resolv_conf_is_symlink; then
    if ! confirm "Detected /etc/resolv.conf is a symlink. Force-write will BREAK the symlink. Proceed?"; then
      log_warn "Cancelled. No changes were made."
      return 1
    fi
    rm -f /etc/resolv.conf
  fi

  {
    printf "# Managed by dns-warden.sh\n"
    printf "nameserver %s\n" "${dns}"
    printf "options edns0 trust-ad\n"
  } > /etc/resolv.conf
  chmod 0644 /etc/resolv.conf

  log_info "Applied: wrote /etc/resolv.conf (nameserver ${dns})"
  log_info "Backup: ${backup}"
}

write_resolved_dropin() {
  local dns="$1"
  local dropin_dir="/etc/systemd/resolved.conf.d"
  local dropin_file="${dropin_dir}/99-dns-warden.conf"

  mkdir -p "${dropin_dir}"
  chmod 0755 "${dropin_dir}"

  if [[ -f "${dropin_file}" ]]; then
    local ts
    ts="$(date +%Y%m%d-%H%M%S)"
    cp --preserve=mode,ownership,timestamps "${dropin_file}" "${BACKUP_DIR}/resolved.dropin.${ts}"
  fi

  cat > "${dropin_file}" <<EOF
# Managed by dns-warden.sh
[Resolve]
DNS=${dns}
FallbackDNS=
EOF
  chmod 0644 "${dropin_file}"
}

apply_via_systemd_resolved() {
  local dns="$1"
  ensure_dirs

  if ! systemd_resolved_active; then
    log_warn "systemd-resolved is not active. Falling back to force-write method."
    apply_force_resolv_conf "${dns}"
    return 0
  fi

  local backup
  backup="$(backup_resolv_conf)"

  write_resolved_dropin "${dns}"
  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl restart systemd-resolved

  log_info "Applied via systemd-resolved: DNS=${dns}"
  log_info "Backup of previous /etc/resolv.conf content: ${backup}"
}

verify_dns() {
  local out_file="${TMP_DIR}/verify.txt"
  {
    echo "=== Verification (DNS Warden) ==="
    echo
    echo "--- /etc/resolv.conf ---"
    if [[ -L /etc/resolv.conf ]]; then
      echo "SYMLINK: /etc/resolv.conf -> $(readlink /etc/resolv.conf)"
      echo "REALPATH: $(readlink -f /etc/resolv.conf || true)"
    fi
    cat /etc/resolv.conf || true
    echo
    if have_command resolvectl; then
      echo "--- resolvectl status (summary) ---"
      resolvectl status 2>/dev/null | head -n 120 || true
      echo
      echo "--- resolvectl query google.com ---"
      resolvectl query google.com 2>/dev/null || true
      echo
    fi
    echo "--- getent hosts google.com ---"
    if getent hosts google.com >/dev/null 2>&1; then
      echo "OK"
      getent hosts google.com | head -n 5 || true
    else
      echo "FAILED"
    fi
  } > "${out_file}"

  pager_file "${out_file}"
}

apply_dns_auto() {
  local dns="$1"
  local method="${FLAG_METHOD:-auto}"

  if [[ "${method}" == "auto" ]]; then
    if resolv_conf_symlink_managed_by_systemd; then
      method="resolved"
    else
      method="force"
    fi
  fi

  case "${method}" in
    resolved) apply_via_systemd_resolved "${dns}" ;;
    force)   apply_force_resolv_conf "${dns}" ;;
    *)       die "Unknown method: ${method} (use resolved|force|auto)" ;;
  esac
}

# ---------------------------
# Backups restore
# ---------------------------
list_backups() { ls -1 "${BACKUP_DIR}"/resolv.conf.* 2>/dev/null | grep -v '\.meta$' || true; }

meta_get() {
  local file="$1" key="$2"
  [[ -r "${file}" ]] || return 1
  awk -F'=' -v k="${key}" '$1==k {sub(/^[^=]*=/,""); print $0; exit}' "${file}" 2>/dev/null
}

restore_backup_cli() {
  local -a backups=()
  mapfile -t backups < <(list_backups)
  (( ${#backups[@]} > 0 )) || { log_warn "No backups found in ${BACKUP_DIR}"; return 0; }

  echo
  printf "%sAvailable backups:%s\n" "$(c_cyan)" "$(c_reset)"
  local i=0 b
  for b in "${backups[@]}"; do
    i=$((i+1))
    printf "  %s) %s\n" "${i}" "${b}"
  done
  echo

  local pick=""
  read -r -p "Select backup number (or Enter to cancel): " pick
  pick="$(trim "${pick}")"
  [[ -z "${pick}" ]] && return 0
  [[ "${pick}" =~ ^[0-9]+$ ]] || { log_warn "Invalid input."; return 0; }
  (( pick >= 1 && pick <= ${#backups[@]} )) || { log_warn "Out of range."; return 0; }

  local chosen="${backups[$((pick-1))]}"
  local meta="${chosen}.meta"
  local is_link="0" target_rel=""
  if [[ -r "${meta}" ]]; then
    is_link="$(meta_get "${meta}" "IS_SYMLINK" || echo "0")"
    target_rel="$(meta_get "${meta}" "SYMLINK_TARGET_REL" || echo "")"
  fi

  if [[ "${is_link}" == "1" && -n "${target_rel}" ]]; then
    echo
    printf "%sRestore mode:%s\n" "$(c_cyan)" "$(c_reset)"
    echo "  1) Recreate symlink (/etc/resolv.conf -> ${target_rel})"
    echo "  2) Restore file content (write file; breaks symlink)"
    echo
    local mode=""
    read -r -p "Choose [1-2] (Enter=cancel): " mode
    mode="$(trim "${mode}")"
    [[ -z "${mode}" ]] && return 0
    if [[ "${mode}" == "1" ]]; then
      confirm "Recreate symlink /etc/resolv.conf -> ${target_rel}. This removes current resolv.conf. Proceed?" || return 0
      rm -f /etc/resolv.conf
      ln -s "${target_rel}" /etc/resolv.conf
      log_info "Restored symlink: /etc/resolv.conf -> ${target_rel}"
    elif [[ "${mode}" == "2" ]]; then
      confirm "Restore backup content into /etc/resolv.conf (may break symlink). Proceed?" || return 0
      rm -f /etc/resolv.conf
      cp --preserve=mode,ownership,timestamps "${chosen}" /etc/resolv.conf
      log_info "Restored content from: ${chosen}"
    else
      log_warn "Cancelled."
      return 0
    fi
  else
    confirm "Restore backup content into /etc/resolv.conf? Proceed?" || return 0
    rm -f /etc/resolv.conf
    cp --preserve=mode,ownership,timestamps "${chosen}" /etc/resolv.conf
    log_info "Restored content from: ${chosen}"
  fi

  verify_dns
}

# ---------------------------
# Pager / UI
# ---------------------------
pager_file() {
  local f="$1"
  if have_command less; then
    less -R "${f}"
  else
    cat "${f}"
  fi
}

clear_screen() {
  if is_tty; then
    clear || true
  fi
}

ubuntu_pretty() {
  if [[ -r /etc/os-release ]]; then
    . /etc/os-release
    printf "%s %s" "${NAME:-Ubuntu}" "${VERSION_ID:-}"
  else
    printf "Ubuntu"
  fi
}

dns_management_status() {
  if resolv_conf_symlink_managed_by_systemd; then
    printf "systemd-resolved (symlink)"
  elif resolv_conf_is_symlink; then
    printf "symlink (unknown target)"
  else
    printf "file"
  fi
}

current_nameserver_summary() {
  # show first nameserver line
  awk '/^nameserver[[:space:]]+/ {print $2; exit}' /etc/resolv.conf 2>/dev/null || true
}

print_banner() {
  clear_screen
  printf "%s" "$(c_blue)"
  cat <<'EOF'
 ____  _   _ ____   __        __              _
|  _ \| \ | / ___|  \ \      / /_ _ _ __   __| | ___ _ __
| | | |  \| \___ \   \ \ /\ / / _` | '_ \ / _` |/ _ \ '_ \
| |_| | |\  |___) |   \ V  V / (_| | | | | (_| |  __/ | | |
|____/|_| \_|____/     \_/\_/ \__,_|_| |_|\__,_|\___|_| |_|

EOF
  printf "%s" "$(c_reset)"

  local host ver mgmt ns
  host="$(hostname 2>/dev/null || echo "unknown")"
  ver="$(ubuntu_pretty)"
  mgmt="$(dns_management_status)"
  ns="$(current_nameserver_summary)"
  [[ -z "${ns}" ]] && ns="(unknown)"

  printf "%sVersion:%s v%s\n" "$(c_dim)" "$(c_reset)" "${APP_VERSION}"
  printf "%sOS:%s %s   %sHost:%s %s\n" "$(c_dim)" "$(c_reset)" "${ver}" "$(c_dim)" "$(c_reset)" "${host}"
  printf "%sDNS Mgmt:%s %s   %sCurrent NS:%s %s\n" "$(c_dim)" "$(c_reset)" "${mgmt}" "$(c_dim)" "$(c_reset)" "${ns}"
  printf "%sList:%s %s\n" "$(c_dim)" "$(c_reset)" "${LIST_FILE}"
  printf "%sBackups:%s %s\n" "$(c_dim)" "$(c_reset)" "${BACKUP_DIR}"
  printf "%sPing:%s count=%s timeout=%ss\n" "$(c_dim)" "$(c_reset)" "${PING_COUNT}" "${PING_TIMEOUT}"
  echo
}

pause_any() {
  if is_tty; then
    printf "%sPress Enter to continue...%s" "$(c_dim)" "$(c_reset)"
    read -r _ || true
  fi
}

# ---------------------------
# UX: Select DNS from ranked results (no whiptail)
# ---------------------------
select_dns_from_results() {
  [[ -s "${LAST_RESULTS_FILE}" ]] || test_dns_list

  local sorted="${TMP_DIR}/results.sorted"
  sort -t'|' -k5,5n "${LAST_RESULTS_FILE}" > "${sorted}"

  print_banner
  printf "%sRanked DNS endpoints:%s\n" "$(c_cyan)" "$(c_reset)"
  echo

  local i=0 endpoint family loss avg score
  while IFS='|' read -r endpoint family loss avg score; do
    i=$((i+1))
    # Color hint: low loss/low avg => greener
    local col=""
    if [[ "${loss}" =~ ^[0-9]+$ ]] && (( loss == 0 )); then col="$(c_green)"; else col="$(c_yellow)"; fi
    printf "  %s%2d)%s %-42s  loss=%-3s%% avg=%-6sms score=%s\n" "${col}" "${i}" "$(c_reset)" "${endpoint}" "${loss}" "${avg}" "${score}"
    (( i >= 25 )) && break
  done < "${sorted}"

  echo
  local pick=""
  read -r -p "Select DNS number (Enter=cancel): " pick
  pick="$(trim "${pick}")"
  [[ -z "${pick}" ]] && { printf ""; return 0; }
  [[ "${pick}" =~ ^[0-9]+$ ]] || { log_warn "Invalid number."; printf ""; return 0; }
  (( pick >= 1 && pick <= 25 )) || { log_warn "Out of range."; printf ""; return 0; }

  local selected
  selected="$(awk -F'|' -v n="${pick}" 'NR==n{print $1; exit}' "${sorted}")"
  printf "%s" "${selected}"
}

# ---------------------------
# Flows
# ---------------------------
view_current_dns_config() {
  local out="${TMP_DIR}/current.txt"
  {
    echo "=== Current DNS configuration ==="
    echo
    if [[ -L /etc/resolv.conf ]]; then
      echo "SYMLINK: /etc/resolv.conf -> $(readlink /etc/resolv.conf)"
      echo "REALPATH: $(readlink -f /etc/resolv.conf || true)"
      if resolv_conf_symlink_managed_by_systemd; then
        echo "Managed by systemd-resolved: YES"
      else
        echo "Managed by systemd-resolved: NO/UNKNOWN"
      fi
    else
      echo "/etc/resolv.conf is a regular file."
    fi
    echo
    echo "--- /etc/resolv.conf content ---"
    cat /etc/resolv.conf || true
    echo
    if have_command resolvectl; then
      echo "--- resolvectl status (summary) ---"
      resolvectl status 2>/dev/null | head -n 120 || true
    elif have_command systemd-resolve; then
      echo "--- systemd-resolve --status (summary) ---"
      systemd-resolve --status 2>/dev/null | head -n 120 || true
    else
      echo "No resolvectl/systemd-resolve available."
    fi
  } > "${out}"
  pager_file "${out}"
}

edit_dns_list() {
  local editor="${EDITOR:-}"
  if [[ -z "${editor}" ]]; then
    if have_command nano; then editor="nano"
    elif have_command vi; then editor="vi"
    elif have_command vim; then editor="vim"
    fi
  fi
  [[ -n "${editor}" ]] || { log_error "No editor found (nano/vi/vim). Install nano: apt-get install -y nano"; return 1; }
  clear_screen
  "${editor}" "${LIST_FILE}"
}

show_help_screen() {
  local out="${TMP_DIR}/help.txt"
  : > "${out}"
  cat >> "${out}" <<EOF
DNS Warden v${APP_VERSION}

Usage (Interactive):
  sudo ./${SCRIPT_NAME}

Curl:
  curl -fsSL https://raw.githubusercontent.com/power0matin/dns-warden/main/dns-warden.sh | sudo bash

Non-interactive:
  --test
    sudo ./${SCRIPT_NAME} --test

  --apply <dns> [--method auto|resolved|force] --yes
    sudo ./${SCRIPT_NAME} --apply 1.1.1.1 --method auto --yes

Files:
  DNS list: ${LIST_FILE}
  Backups:  ${BACKUP_DIR}

Notes:
  - If /etc/resolv.conf is managed by systemd-resolved, 'resolved' method is safest.
  - Force method can break the /etc/resolv.conf symlink.
EOF
  pager_file "${out}"
}

# ---------------------------
# CLI apply/test flows
# ---------------------------
apply_dns_cli() {
  local dns="$1"
  local method="${FLAG_METHOD:-auto}"
  dns="$(trim "${dns}")"
  [[ -n "${dns}" ]] || die "--apply value is empty"

  if (( FLAG_YES != 1 )); then
    die "Refusing to apply without explicit confirmation. Re-run with --yes."
  fi

  apply_dns_auto "${dns}"

  [[ -L /etc/resolv.conf ]] && log_info "SYMLINK: /etc/resolv.conf -> $(readlink /etc/resolv.conf)"
  log_info "Final /etc/resolv.conf:"
  cat /etc/resolv.conf
  if getent hosts google.com >/dev/null 2>&1; then
    log_info "DNS test: OK (getent hosts google.com)"
  else
    log_warn "DNS test: FAILED (getent hosts google.com)"
  fi
}

test_dns_cli() {
  test_dns_list
  cat "${LAST_TABLE_FILE}"
}

# ---------------------------
# Args / help
# ---------------------------
usage() {
  cat <<EOF
${SCRIPT_NAME} v${APP_VERSION} - Ubuntu-only DNS tester & switcher (Rathole_v2-style TUI)

Usage:
  sudo bash ${SCRIPT_NAME}

Options:
  -h, --help              Show this help
  --list <path>           Use an alternate DNS list file
  --count <n>             Ping count per endpoint (default: ${PING_COUNT_DEFAULT})
  --timeout <sec>         Ping timeout per packet (default: ${PING_TIMEOUT_DEFAULT})
  --test                  Run tests and print results (no TUI)
  --apply <dns|hostname>  Apply a specific DNS (requires --yes)
  --method <auto|resolved|force>
  --yes                   Non-interactive confirmation for --apply
EOF
}

parse_args() {
  while (( $# > 0 )); do
    case "$1" in
      -h|--help) usage; exit 0 ;;
      --list)    [[ $# -ge 2 ]] || die "--list requires a path"; FLAG_LIST_OVERRIDE="$2"; shift 2 ;;
      --count)   [[ $# -ge 2 ]] || die "--count requires a number"; PING_COUNT="$2"; shift 2 ;;
      --timeout) [[ $# -ge 2 ]] || die "--timeout requires seconds"; PING_TIMEOUT="$2"; shift 2 ;;
      --test)    FLAG_TEST_ONLY=1; shift ;;
      --apply)   [[ $# -ge 2 ]] || die "--apply requires a DNS endpoint/hostname"; FLAG_APPLY_DNS="$2"; shift 2 ;;
      --method)  [[ $# -ge 2 ]] || die "--method requires auto|resolved|force"; FLAG_METHOD="$2"; shift 2 ;;
      --yes)     FLAG_YES=1; shift ;;
      --)        shift; break ;;
      *)         die "Unknown argument: $1 (use --help)" ;;
    esac
  done

  [[ "${PING_COUNT}" =~ ^[0-9]+$ ]] || die "--count must be an integer"
  [[ "${PING_TIMEOUT}" =~ ^[0-9]+$ ]] || die "--timeout must be an integer"
  (( PING_COUNT >= 1 && PING_COUNT <= 20 )) || die "--count must be in range 1..20"
  (( PING_TIMEOUT >= 1 && PING_TIMEOUT <= 10 )) || die "--timeout must be in range 1..10"

  if [[ -n "${FLAG_METHOD}" ]]; then
    case "${FLAG_METHOD}" in
      auto|resolved|force) ;;
      *) die "--method must be auto|resolved|force" ;;
    esac
  fi
}

# ---------------------------
# Main Menu (Rathole_v2-style)
# ---------------------------
menu_loop() {
  while true; do
    print_banner
    printf "%s1.%s Test DNS list (ping + rank)\n" "$(c_green)" "$(c_reset)"
    printf "%s2.%s Select & Apply DNS\n"         "$(c_red)"   "$(c_reset)"
    printf "%s3.%s View current DNS config\n"    "$(c_blue)"  "$(c_reset)"
    printf "%s4.%s Edit DNS list\n"             "$(c_green)" "$(c_reset)"
    printf "%s5.%s Restore backup\n"            "$(c_green)" "$(c_reset)"
    printf "%s6.%s Help\n"                      "$(c_green)" "$(c_reset)"
    printf "%s0.%s Exit\n"                      "$(c_dim)"   "$(c_reset)"
    echo
    printf "%sEnter your choice [0-6]: %s" "$(c_cyan)" "$(c_reset)"

    local choice=""
    read -r choice || true
    choice="$(trim "${choice}")"

    case "${choice}" in
      1)
        test_dns_list
        pager_file "${LAST_TABLE_FILE}"
        pause_any
        ;;
      2)
        test_dns_list
        local selected=""
        selected="$(select_dns_from_results || true)"
        selected="$(trim "${selected}")"
        if [[ -z "${selected}" ]]; then
          log_warn "No DNS selected."
          pause_any
          continue
        fi

        # UX: auto-detect method + show confirmation
        local method="auto"
        [[ -n "${FLAG_METHOD}" ]] && method="${FLAG_METHOD}"
        if [[ "${method}" == "auto" ]]; then
          if resolv_conf_symlink_managed_by_systemd; then method="resolved"; else method="force"; fi
        fi

        echo
        printf "%sApply DNS:%s %s\n" "$(c_cyan)" "$(c_reset)" "${selected}"
        printf "%sMethod:%s %s\n"    "$(c_cyan)" "$(c_reset)" "${method}"
        echo
        confirm "Proceed to apply?" || { log_warn "Cancelled."; pause_any; continue; }

        FLAG_METHOD="${method}"
        apply_dns_auto "${selected}"
        verify_dns
        pause_any
        ;;
      3)
        view_current_dns_config
        pause_any
        ;;
      4)
        edit_dns_list
        ;;
      5)
        restore_backup_cli
        pause_any
        ;;
      6)
        show_help_screen
        pause_any
        ;;
      0|"")
        break
        ;;
      *)
        log_warn "Invalid choice."
        pause_any
        ;;
    esac
  done
}

main() {
  detect_script_dir
  detect_ubuntu_or_exit
  ensure_root

  parse_args "$@"

  init_tmp
  ensure_dirs
  init_list_file

  have_command ping   || die "Missing dependency: ping (iputils-ping)"
  have_command getent || die "Missing dependency: getent (libc-bin)"

  if [[ -n "${FLAG_APPLY_DNS}" ]]; then
    apply_dns_cli "${FLAG_APPLY_DNS}"
    return 0
  fi

  if (( FLAG_TEST_ONLY == 1 )); then
    test_dns_cli
    return 0
  fi

  # Interactive menu (terminal)
  if [[ -t 0 && -t 1 ]]; then
    menu_loop
  else
    usage
    die "Non-interactive mode: use --test or --apply <dns> --yes"
  fi
}

main "$@"
