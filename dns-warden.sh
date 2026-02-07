#!/usr/bin/env bash
# DNS Warden - Ubuntu-only DNS tester & switcher (TUI via whiptail)
#
# Supports:
# - Test DNS endpoints from a list file (IPv4/IPv6/hostnames)
# - Show sorted results (loss/avg/score)
# - Select & apply DNS safely (systemd-resolved aware)
# - Backup/restore /etc/resolv.conf with timestamp + metadata
#
# Safe for: Ubuntu 20.04+
# Shellcheck-friendly.

# ---------------------------
# Loader: sudo re-exec support
# ---------------------------
# Enables "curl ... | bash" to auto-rerun with sudo by capturing the script into a temp file.
if [[ -z "${DNS_WARDEN_LAUNCHED:-}" ]]; then
  export DNS_WARDEN_LAUNCHED=1

  _euid="${EUID:-$(id -u)}"
  _script_path="${BASH_SOURCE[0]:-}"

  if [[ -z "${_script_path}" || ! -r "${_script_path}" ]]; then
    # Likely running via stdin (curl|bash). Capture the rest of the script.
    _tmp="$(mktemp -t dns-warden.XXXXXX)"
    cat > "${_tmp}"
    chmod 0700 "${_tmp}"

    if [[ "${_euid}" -ne 0 ]]; then
      if command -v sudo >/dev/null 2>&1; then
        exec sudo -E bash "${_tmp}" "$@"
      else
        echo "ERROR: This script must run as root, and 'sudo' is not available." >&2
        echo "Re-run as root, e.g.: curl -fsSL <raw_url> | sudo bash" >&2
        exit 1
      fi
    else
      exec bash "${_tmp}" "$@"
    fi
  else
    # Running from a real file path.
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

# ---------------------------
# Main script starts here
# ---------------------------
set -euo pipefail
IFS=$'\n\t'
export LC_ALL=C

VERSION="1.0.0"
SCRIPT_NAME="dns-warden.sh"

# Defaults (overridable by flags)
PING_COUNT_DEFAULT=3
PING_TIMEOUT_DEFAULT=2

PING_COUNT="${PING_COUNT_DEFAULT}"
PING_TIMEOUT="${PING_TIMEOUT_DEFAULT}"

# Paths
SCRIPT_DIR=""
CONFIG_DIR="/etc/dns-warden"
BACKUP_DIR="/var/backups/dns-warden"
LIST_FILE="" # resolved at runtime

# UI / mode
INTERACTIVE=0
HAVE_WHIPTAIL=0

# State
TMP_DIR=""
LAST_RESULTS_FILE=""
LAST_TABLE_FILE=""

# CLI flags
FLAG_TEST_ONLY=0
FLAG_APPLY_DNS=""
FLAG_METHOD=""     # resolved|force|auto
FLAG_YES=0
FLAG_LIST_OVERRIDE=""

# ---------------------------
# Logging (non-TUI)
# ---------------------------
_color() {
  local code="$1"
  if [[ -t 1 ]]; then
    printf "\033[%sm" "${code}"
  fi
}

log_info()  { printf "%s[INFO]%s %s\n"  "$(_color 36)" "$(_color 0)" "$*"; }
log_warn()  { printf "%s[WARN]%s %s\n"  "$(_color 33)" "$(_color 0)" "$*"; }
log_error() { printf "%s[ERR ]%s %s\n"  "$(_color 31)" "$(_color 0)" "$*"; }
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
is_interactive() {
  [[ -t 0 && -t 1 ]]
}

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
  # shellcheck disable=SC1091
  . /etc/os-release

  if [[ "${ID:-}" != "ubuntu" ]]; then
    die "Unsupported OS: ID='${ID:-unknown}'. This script supports Ubuntu 20.04+ only."
  fi

  local ver="${VERSION_ID:-0}"
  local major="${ver%%.*}"
  if [[ "${major}" =~ ^[0-9]+$ ]]; then
    if (( major < 20 )); then
      die "Unsupported Ubuntu version: ${ver}. Require Ubuntu 20.04+."
    fi
  else
    die "Could not parse Ubuntu version (VERSION_ID='${ver}')."
  fi
}

ensure_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    die "Root is required (this should have been handled by the loader)."
  fi
}

ensure_whiptail() {
  if command -v whiptail >/dev/null 2>&1; then
    HAVE_WHIPTAIL=1
    return 0
  fi

  HAVE_WHIPTAIL=0

  if (( INTERACTIVE == 1 )); then
    log_warn "whiptail not found. Attempting to install..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y >/dev/null 2>&1 || true
    apt-get install -y whiptail >/dev/null 2>&1 || apt-get install -y newt >/dev/null 2>&1 || true
  fi

  if command -v whiptail >/dev/null 2>&1; then
    HAVE_WHIPTAIL=1
  else
    HAVE_WHIPTAIL=0
  fi
}

have_command() { command -v "$1" >/dev/null 2>&1; }

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
  [[ "${ip}" == *:* ]]
}

resolve_prefer_v4_then_v6() {
  local host="$1"
  local ip=""
  if getent ahostsv4 "${host}" >/dev/null 2>&1; then
    ip="$(getent ahostsv4 "${host}" | awk '{print $1; exit}')"
    if [[ -n "${ip}" ]]; then
      printf "4 %s" "${ip}"
      return 0
    fi
  fi
  if getent ahostsv6 "${host}" >/dev/null 2>&1; then
    ip="$(getent ahostsv6 "${host}" | awk '{print $1; exit}')"
    if [[ -n "${ip}" ]]; then
      printf "6 %s" "${ip}"
      return 0
    fi
  fi
  return 1
}

init_tmp() {
  TMP_DIR="$(mktemp -d -t dns-warden-tmp.XXXXXX)"
  chmod 0700 "${TMP_DIR}"
  LAST_RESULTS_FILE="${TMP_DIR}/results.raw"
  LAST_TABLE_FILE="${TMP_DIR}/results.table.txt"
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

# Optional hostname examples
# one.one.one.one
# dns.google
EOF
    chmod 0644 "${LIST_FILE}"
  fi
}

# ---------------------------
# whiptail helpers
# ---------------------------
wt_msg() {
  local title="$1"; shift
  local text="$1"; shift || true
  if (( HAVE_WHIPTAIL == 1 && INTERACTIVE == 1 )); then
    whiptail --title "${title}" --msgbox "${text}" 10 72
  else
    log_info "${title}: ${text}"
  fi
}

wt_textbox() {
  local title="$1"
  local file="$2"
  if (( HAVE_WHIPTAIL == 1 && INTERACTIVE == 1 )); then
    whiptail --title "${title}" --scrolltext --textbox "${file}" 25 92
  else
    cat "${file}"
  fi
}

wt_yesno() {
  local title="$1"
  local text="$2"
  if (( HAVE_WHIPTAIL == 1 && INTERACTIVE == 1 )); then
    if whiptail --title "${title}" --yesno "${text}" 10 72; then
      return 0
    else
      return 1
    fi
  fi

  if (( FLAG_YES == 1 )); then
    return 0
  fi

  if [[ -t 0 ]]; then
    printf "%s [y/N]: " "${text}"
    local ans=""
    read -r ans
    [[ "${ans}" =~ ^[Yy]$ ]]
  else
    return 1
  fi
}

wt_menu_main() {
  local choice=""
  choice="$(whiptail --title "DNS Warden (Ubuntu) v${VERSION}" \
    --menu "Select an action:" 18 72 10 \
    "1" "Test DNS list" \
    "2" "Select & Apply DNS" \
    "3" "View current DNS config" \
    "4" "Edit DNS list" \
    "5" "Restore backup" \
    "6" "Exit" \
    3>&1 1>&2 2>&3)" || true

  printf "%s" "${choice}"
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

  if (( ${#entries[@]} == 0 )); then
    die "DNS list is empty after filtering comments/blank lines: ${file}"
  fi

  printf "%s\n" "${entries[@]}"
}

# ---------------------------
# Ping testing
# ---------------------------
ping_one() {
  local endpoint="$1"

  local family="" ip_for_ping="" ping_cmd="" ping_args=()
  local resolved=""

  if is_ipv4 "${endpoint}"; then
    family="4"
    ip_for_ping="${endpoint}"
  elif is_ipv6 "${endpoint}"; then
    family="6"
    ip_for_ping="${endpoint}"
  else
    if resolved="$(resolve_prefer_v4_then_v6 "${endpoint}" 2>/dev/null)"; then
      family="$(awk '{print $1}' <<< "${resolved}")"
      ip_for_ping="${endpoint}"
    else
      family="?"
      ip_for_ping="${endpoint}"
    fi
  fi

  if [[ "${family}" == "6" ]]; then
    if have_command ping6; then
      ping_cmd="ping6"
      ping_args=(-c "${PING_COUNT}" -W "${PING_TIMEOUT}")
    else
      ping_cmd="ping"
      ping_args=(-6 -c "${PING_COUNT}" -W "${PING_TIMEOUT}")
    fi
  else
    ping_cmd="ping"
    ping_args=(-4 -c "${PING_COUNT}" -W "${PING_TIMEOUT}")
  fi

  local out rc
  out="$("${ping_cmd}" "${ping_args[@]}" "${ip_for_ping}" 2>&1 || true)"
  rc=$?

  local loss avg score
  loss="$(grep -oE '[0-9]+(?=% packet loss)' <<< "${out}" | head -n1 || true)"
  if [[ -z "${loss}" ]]; then
    loss="100"
  fi

  avg="$(awk '
    /rtt min\/avg\/max\/mdev/ || /round-trip min\/avg\/max\/stddev/ {
      split($0, a, "=")
      gsub(/^[[:space:]]+/, "", a[2])
      split(a[2], b, "/")
      print b[2]
      exit
    }' <<< "${out}" || true)"

  if [[ -z "${avg}" ]]; then
    avg="9999"
  fi

  score="$(awk -v a="${avg}" -v l="${loss}" 'BEGIN{printf "%.3f", a + (l*1000)}')"

  printf "%s|%s|%s|%s|%s\n" "${endpoint}" "${family}" "${loss}" "${avg}" "${score}"
  return "${rc}"
}

test_dns_list() {
  local -a entries=()
  mapfile -t entries < <(read_dns_list "${LIST_FILE}")

  : > "${LAST_RESULTS_FILE}"

  local e
  for e in "${entries[@]}"; do
    ping_one "${e}" >> "${LAST_RESULTS_FILE}" || true
  done

  build_results_table
}

build_results_table() {
  [[ -s "${LAST_RESULTS_FILE}" ]] || die "No results to display."

  local sorted="${TMP_DIR}/results.sorted"
  sort -t'|' -k5,5n "${LAST_RESULTS_FILE}" > "${sorted}"

  {
    printf "DNS Warden Results (sorted by score; lower is better)\n"
    printf "Ping: count=%s timeout=%ss\n\n" "${PING_COUNT}" "${PING_TIMEOUT}"
    printf "%-4s  %-42s  %-6s  %-7s  %-10s\n" "Rank" "DNS" "Loss%" "Avg(ms)" "Score"
    printf "%-4s  %-42s  %-6s  %-7s  %-10s\n" "----" "------------------------------------------" "------" "-------" "----------"

    local rank=0
    local endpoint family loss avg score
    while IFS='|' read -r endpoint family loss avg score; do
      rank=$((rank + 1))
      printf "%-4s  %-42s  %-6s  %-7s  %-10s\n" "${rank}" "${endpoint}" "${loss}" "${avg}" "${score}"
    done < "${sorted}"

    printf "\nNotes:\n"
    printf "- Hostnames are resolved (prefer IPv4; fallback IPv6).\n"
    printf "- Loss is heavily penalized in score (loss*1000).\n"
  } > "${LAST_TABLE_FILE}"
}

select_best_dns_tui() {
  [[ -s "${LAST_RESULTS_FILE}" ]] || test_dns_list

  local sorted="${TMP_DIR}/results.sorted"
  sort -t'|' -k5,5n "${LAST_RESULTS_FILE}" > "${sorted}"

  local -a opts=()
  local first=1
  local endpoint family loss avg score desc status

  while IFS='|' read -r endpoint family loss avg score; do
    desc="loss=${loss}%, avg=${avg}ms, score=${score}"
    status="OFF"
    if (( first == 1 )); then
      status="ON"
      first=0
    fi
    opts+=("${endpoint}" "${desc}" "${status}")
  done < "${sorted}"

  local chosen=""
  chosen="$(whiptail --title "Select DNS to apply" \
    --radiolist "Choose one DNS endpoint:" 20 92 10 \
    "${opts[@]}" \
    3>&1 1>&2 2>&3)" || true

  printf "%s" "${chosen}"
}

# ---------------------------
# DNS apply logic
# ---------------------------
resolv_conf_is_symlink() { [[ -L /etc/resolv.conf ]]; }

resolv_conf_symlink_target() {
  if resolv_conf_is_symlink; then
    readlink /etc/resolv.conf
  else
    printf ""
  fi
}

resolv_conf_symlink_managed_by_systemd() {
  if ! resolv_conf_is_symlink; then
    return 1
  fi
  local target
  target="$(readlink -f /etc/resolv.conf || true)"
  [[ "${target}" == /run/systemd/resolve/* ]]
}

systemd_resolved_active() {
  if have_command systemctl; then
    systemctl is-active --quiet systemd-resolved
  else
    return 1
  fi
}

backup_resolv_conf() {
  ensure_dirs
  local ts
  ts="$(date +%Y%m%d-%H%M%S)"
  local backup="${BACKUP_DIR}/resolv.conf.${ts}"
  local meta="${backup}.meta"

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

apply_force_resolv_conf() {
  local dns="$1"

  local backup
  backup="$(backup_resolv_conf)"

  if resolv_conf_is_symlink; then
    if ! wt_yesno "Confirm" "Detected /etc/resolv.conf is a symlink.\n\nForce-writing will BREAK the symlink.\n\nProceed?"; then
      wt_msg "Cancelled" "No changes were made."
      return 1
    fi
    rm -f /etc/resolv.conf
  fi

  printf "nameserver %s\n" "${dns}" > /etc/resolv.conf
  chmod 0644 /etc/resolv.conf

  wt_msg "Applied" "Wrote /etc/resolv.conf with only:\n\nnameserver ${dns}\n\nBackup:\n${backup}"
  return 0
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
    wt_msg "systemd-resolved" "systemd-resolved is not active. Falling back to force-write method."
    apply_force_resolv_conf "${dns}"
    return 0
  fi

  local backup
  backup="$(backup_resolv_conf)"

  write_resolved_dropin "${dns}"
  systemctl restart systemd-resolved

  wt_msg "Applied (systemd-resolved)" \
    "Configured systemd-resolved to use DNS=${dns}.\n\nNOTE: /etc/resolv.conf may remain a stub (e.g., 127.0.0.53) when managed by systemd-resolved.\n\nBackup of previous /etc/resolv.conf content:\n${backup}"
}

verify_dns() {
  local out_file="${TMP_DIR}/verify.txt"
  {
    echo "=== /etc/resolv.conf (final) ==="
    if [[ -L /etc/resolv.conf ]]; then
      echo "SYMLINK: /etc/resolv.conf -> $(readlink /etc/resolv.conf)"
      echo "REALPATH: $(readlink -f /etc/resolv.conf || true)"
    fi
    cat /etc/resolv.conf || true
    echo
    echo "=== DNS resolution test ==="
    if getent hosts google.com >/dev/null 2>&1; then
      echo "OK: getent hosts google.com"
      getent hosts google.com | head -n 3 || true
    else
      echo "FAILED: getent hosts google.com"
    fi
  } > "${out_file}"

  wt_textbox "Verification" "${out_file}"
}

apply_dns_flow_tui() {
  local selected="$1"

  local method="auto"
  if [[ -n "${FLAG_METHOD}" ]]; then
    method="${FLAG_METHOD}"
  fi

  if resolv_conf_symlink_managed_by_systemd; then
    if [[ "${method}" == "auto" ]]; then
      local choice=""
      choice="$(whiptail --title "systemd-resolved detected" \
        --menu "/etc/resolv.conf is managed by systemd-resolved.\n\nChoose how to apply DNS:" 16 80 3 \
        "resolved" "Recommended: configure systemd-resolved (safe; resolv.conf may stay stub)" \
        "force" "Force-write /etc/resolv.conf (break symlink; requires confirmation)" \
        "cancel" "Cancel" \
        3>&1 1>&2 2>&3)" || true

      case "${choice}" in
        resolved) method="resolved" ;;
        force)   method="force" ;;
        *)       wt_msg "Cancelled" "No changes were made."; return 1 ;;
      esac
    fi
  else
    if [[ "${method}" == "auto" ]]; then
      method="force"
    fi
  fi

  if ! wt_yesno "Confirm Apply" "Apply DNS '${selected}' using method '${method}'?\n\nNo changes will be made if you choose No."; then
    wt_msg "Cancelled" "No changes were made."
    return 1
  fi

  case "${method}" in
    resolved) apply_via_systemd_resolved "${selected}" ;;
    force)   apply_force_resolv_conf "${selected}" ;;
    *)       die "Unknown method: ${method}" ;;
  esac

  verify_dns
}

view_current_dns_config() {
  local out="${TMP_DIR}/current.txt"
  {
    echo "=== Current DNS configuration ==="
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
      resolvectl status 2>/dev/null | head -n 80 || true
    elif have_command systemd-resolve; then
      echo "--- systemd-resolve --status (summary) ---"
      systemd-resolve --status 2>/dev/null | head -n 80 || true
    else
      echo "No resolvectl/systemd-resolve available to show resolver status."
    fi
  } > "${out}"

  wt_textbox "Current DNS config" "${out}"
}

edit_dns_list() {
  if (( INTERACTIVE == 1 )); then
    if have_command nano; then
      nano "${LIST_FILE}"
      return 0
    fi
    wt_msg "Editor missing" "nano is not installed. Install it with:\n\napt-get update && apt-get install -y nano"
    return 1
  fi

  cat <<EOF
Non-interactive mode detected; cannot open an editor.

Edit the DNS list file at:
  ${LIST_FILE}

Example:
  sudo nano ${LIST_FILE}
EOF
}

list_backups() {
  ls -1 "${BACKUP_DIR}"/resolv.conf.* 2>/dev/null | grep -v '\.meta$' || true
}

restore_backup_tui() {
  local -a backups=()
  mapfile -t backups < <(list_backups)

  if (( ${#backups[@]} == 0 )); then
    wt_msg "Restore" "No backups found in:\n${BACKUP_DIR}"
    return 0
  fi

  local -a opts=()
  local f base
  for f in "${backups[@]}"; do
    base="$(basename "${f}")"
    opts+=("${f}" "${base}")
  done

  local chosen=""
  chosen="$(whiptail --title "Restore backup" \
    --menu "Select a backup to restore:" 20 92 10 \
    "${opts[@]}" \
    3>&1 1>&2 2>&3)" || true

  [[ -n "${chosen}" ]] || return 0

  local meta="${chosen}.meta"
  local is_link="0" target_rel=""
  if [[ -r "${meta}" ]]; then
    # shellcheck disable=SC1090
    . "${meta}"
    is_link="${IS_SYMLINK:-0}"
    target_rel="${SYMLINK_TARGET_REL:-}"
  fi

  local restore_mode="content"
  if [[ "${is_link}" == "1" && -n "${target_rel}" ]]; then
    restore_mode="$(whiptail --title "Restore mode" \
      --menu "This backup was taken when /etc/resolv.conf was a symlink.\nChoose restore behavior:" 16 80 3 \
      "symlink" "Recreate symlink (/etc/resolv.conf -> ${target_rel}) if possible" \
      "content" "Restore file content (break symlink; write file)" \
      "cancel" "Cancel" \
      3>&1 1>&2 2>&3)" || true
  fi

  case "${restore_mode}" in
    cancel|"") return 0 ;;
    symlink)
      if ! wt_yesno "Confirm" "Recreate symlink /etc/resolv.conf -> ${target_rel}?\n\nThis will remove the current /etc/resolv.conf."; then
        return 0
      fi
      rm -f /etc/resolv.conf
      ln -s "${target_rel}" /etc/resolv.conf
      wt_msg "Restored" "Symlink restored:\n/etc/resolv.conf -> ${target_rel}"
      ;;
    content)
      if ! wt_yesno "Confirm" "Restore backup content into /etc/resolv.conf?\n\nThis may break any existing symlink."; then
        return 0
      fi
      rm -f /etc/resolv.conf
      cp --preserve=mode,ownership,timestamps "${chosen}" /etc/resolv.conf
      wt_msg "Restored" "Restored content from:\n${chosen}"
      ;;
    *)
      return 0
      ;;
  esac

  verify_dns
}

# ---------------------------
# CLI apply/test flows
# ---------------------------
apply_dns_cli() {
  local dns="$1"
  local method="${FLAG_METHOD:-auto}"

  if (( FLAG_YES != 1 )); then
    if (( INTERACTIVE == 1 )); then
      if ! wt_yesno "Confirm Apply" "Apply DNS '${dns}' using method '${method}'?"; then
        die "Cancelled."
      fi
    else
      die "Refusing to apply without explicit confirmation. Re-run with --yes."
    fi
  fi

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

  if [[ -L /etc/resolv.conf ]]; then
    log_info "SYMLINK: /etc/resolv.conf -> $(readlink /etc/resolv.conf)"
  fi
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
${SCRIPT_NAME} v${VERSION} - Ubuntu-only DNS tester & switcher (whiptail TUI)

Usage:
  sudo bash ${SCRIPT_NAME}
  bash ${SCRIPT_NAME}               # will auto re-run with sudo if possible

Curl (raw GitHub link):
  curl -fsSL <raw_url> | sudo bash

Options:
  -h, --help              Show this help
  --list <path>           Use an alternate DNS list file
  --count <n>             Ping count per endpoint (default: ${PING_COUNT_DEFAULT})
  --timeout <sec>         Ping timeout per packet (default: ${PING_TIMEOUT_DEFAULT})
  --test                  Run tests and print results (no TUI)
  --apply <dns>           Apply a specific DNS (requires --yes if non-interactive)
  --method <auto|resolved|force>
                          auto: resolved if systemd-managed; else force
                          resolved: configure systemd-resolved (safe)
                          force: write /etc/resolv.conf with only "nameserver <dns>"
  --yes                   Non-interactive confirmation for --apply

Notes:
- If dns-list.txt is not found next to the script, the list is created at:
    ${CONFIG_DIR}/dns-list.txt
- Backups are stored in:
    ${BACKUP_DIR}/
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
      --apply)   [[ $# -ge 2 ]] || die "--apply requires a DNS endpoint"; FLAG_APPLY_DNS="$2"; shift 2 ;;
      --method)  [[ $# -ge 2 ]] || die "--method requires auto|resolved|force"; FLAG_METHOD="$2"; shift 2 ;;
      --yes)     FLAG_YES=1; shift ;;
      --)        shift; break ;;
      *)         die "Unknown argument: $1 (use --help)" ;;
    esac
  done

  [[ "${PING_COUNT}" =~ ^[0-9]+$ ]] || die "--count must be an integer"
  [[ "${PING_TIMEOUT}" =~ ^[0-9]+$ ]] || die "--timeout must be an integer"
  if [[ -n "${FLAG_METHOD}" ]]; then
    case "${FLAG_METHOD}" in
      auto|resolved|force) ;;
      *) die "--method must be auto|resolved|force" ;;
    esac
  fi
}

# ---------------------------
# Main menu loop (TUI)
# ---------------------------
menu_loop() {
  while true; do
    local choice
    choice="$(wt_menu_main)"
    case "${choice}" in
      1)
        test_dns_list
        wt_textbox "DNS Test Results" "${LAST_TABLE_FILE}"
        ;;
      2)
        test_dns_list
        wt_textbox "DNS Test Results" "${LAST_TABLE_FILE}"
        local selected
        selected="$(select_best_dns_tui)"
        if [[ -n "${selected}" ]]; then
          apply_dns_flow_tui "${selected}"
        fi
        ;;
      3) view_current_dns_config ;;
      4) edit_dns_list ;;
      5) restore_backup_tui ;;
      6|"") break ;;
      *) break ;;
    esac
  done
}

main() {
  INTERACTIVE=0
  if is_interactive; then
    INTERACTIVE=1
  fi

  detect_script_dir
  detect_ubuntu_or_exit
  ensure_root

  init_tmp
  ensure_dirs
  init_list_file

  parse_args "$@"

  have_command ping || die "Missing dependency: ping (iputils-ping)"
  have_command getent || die "Missing dependency: getent (libc-bin)"

  if [[ -n "${FLAG_APPLY_DNS}" ]]; then
    apply_dns_cli "${FLAG_APPLY_DNS}"
    return 0
  fi

  if (( FLAG_TEST_ONLY == 1 )); then
    test_dns_cli
    return 0
  fi

  if (( INTERACTIVE == 1 )); then
    ensure_whiptail
    if (( HAVE_WHIPTAIL != 1 )); then
      die "whiptail is not available. Install it: apt-get update && apt-get install -y whiptail"
    fi
    menu_loop
  else
    usage
    die "Non-interactive mode: use --test or --apply <dns> --yes"
  fi
}

main "$@"
