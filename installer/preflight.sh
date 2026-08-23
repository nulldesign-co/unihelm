#!/usr/bin/env bash
# Ferrum preflight (spec §7.1).
#
# Refuses clearly and early rather than failing halfway through provisioning.
# Sourced by install.sh, and runnable on its own to check a candidate server:
#
#     bash preflight.sh
#
set -euo pipefail

# Minimum viable server (spec §3).
readonly MIN_RAM_MB=900          # 1 GB of RAM reports as ~960 MB after firmware
readonly MIN_DISK_MB=10240

preflight_problems=()
preflight_warnings=()

_fail() { preflight_problems+=("$1"); }
_warn() { preflight_warnings+=("$1"); }

preflight_check_root() {
  if [ "$(id -u)" -ne 0 ]; then
    _fail "must be run as root"
  fi
}

preflight_check_os() {
  if [ ! -r /etc/os-release ]; then
    _fail "/etc/os-release is missing — this does not look like a supported Linux distribution"
    return
  fi

  # shellcheck disable=SC1091
  . /etc/os-release
  FERRUM_OS_ID="${ID:-unknown}"
  FERRUM_OS_VERSION="${VERSION_ID:-}"
  FERRUM_OS_NAME="${PRETTY_NAME:-$FERRUM_OS_ID}"
  local like="${ID_LIKE:-}"
  local major="${FERRUM_OS_VERSION%%.*}"

  case "$FERRUM_OS_ID" in
    debian)
      FERRUM_FAMILY=debian
      [ "$major" -ge 12 ] 2>/dev/null || _warn "Debian $FERRUM_OS_VERSION is older than the tested 12/13"
      ;;
    ubuntu)
      FERRUM_FAMILY=debian
      case "$FERRUM_OS_VERSION" in
        22.04 | 24.04 | 26.04) ;;
        *) _warn "Ubuntu $FERRUM_OS_VERSION is not one of the tested LTS releases" ;;
      esac
      ;;
    almalinux | rocky | rhel | centos)
      FERRUM_FAMILY=rhel
      [ "$major" -ge 9 ] 2>/dev/null || _warn "$FERRUM_OS_NAME is older than the tested 9/10"
      ;;
    *)
      case " $like " in
        *" debian "* | *" ubuntu "*) FERRUM_FAMILY=debian; _warn "$FERRUM_OS_NAME is an untested Debian derivative" ;;
        *" rhel "* | *" fedora "* | *" centos "*) FERRUM_FAMILY=rhel; _warn "$FERRUM_OS_NAME is an untested RHEL derivative" ;;
        *) _fail "$FERRUM_OS_NAME is not supported (Debian/Ubuntu or RHEL family only)" ;;
      esac
      ;;
  esac
}

preflight_check_arch() {
  FERRUM_ARCH="$(uname -m)"
  case "$FERRUM_ARCH" in
    x86_64 | aarch64 | arm64) ;;
    *) _fail "architecture $FERRUM_ARCH is not supported (x86_64 and aarch64 only)" ;;
  esac
}

preflight_check_systemd() {
  if [ ! -d /run/systemd/system ]; then
    _fail "systemd is required (spec §1.3); this system is not running it"
  fi
}

preflight_check_cgroups() {
  # cgroups v2 unified hierarchy is what per-tenant memory and CPU limits are
  # built on, so a v1 system cannot enforce a plan (spec §6.3).
  if [ ! -f /sys/fs/cgroup/cgroup.controllers ]; then
    _fail "cgroups v2 unified hierarchy is required; boot with systemd.unified_cgroup_hierarchy=1"
  fi
}

preflight_check_memory() {
  local kb
  kb="$(awk '/^MemTotal:/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)"
  local mb=$((kb / 1024))
  if [ "$mb" -lt "$MIN_RAM_MB" ]; then
    _fail "${mb} MB of RAM; Ferrum needs at least 1 GB"
  elif [ "$mb" -lt 1800 ]; then
    _warn "${mb} MB of RAM — enough for the panel, tight for a full stack"
  fi
}

preflight_check_disk() {
  local mb
  mb="$(df -Pm /var 2>/dev/null | awk 'NR==2 {print $4}')"
  if [ -z "$mb" ]; then
    _warn "could not determine free space on /var"
  elif [ "$mb" -lt "$MIN_DISK_MB" ]; then
    _fail "${mb} MB free on /var; Ferrum needs at least 10 GB"
  fi
}

preflight_check_conflicts() {
  # Another panel owning nginx or the same ports turns into a fight the user
  # loses at 3am. Say so now.
  for unit in httpd apache2 cpanel psa; do
    if systemctl is-active --quiet "$unit" 2>/dev/null; then
      _warn "$unit is running and will compete with the stack Ferrum manages"
    fi
  done
  for panel in /usr/local/cpanel /opt/psa /www/server/panel; do
    [ -d "$panel" ] && _warn "another control panel is installed at $panel"
  done
}

preflight_run() {
  preflight_check_root
  preflight_check_os
  preflight_check_arch
  preflight_check_systemd
  preflight_check_cgroups
  preflight_check_memory
  preflight_check_disk
  preflight_check_conflicts
}

preflight_report() {
  local w p
  for w in ${preflight_warnings+"${preflight_warnings[@]}"}; do
    printf '  \033[33mwarn\033[0m  %s\n' "$w" >&2
  done
  for p in ${preflight_problems+"${preflight_problems[@]}"}; do
    printf '  \033[31mFAIL\033[0m  %s\n' "$p" >&2
  done
  [ ${#preflight_problems[@]} -eq 0 ]
}

# Run standalone when executed rather than sourced.
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
  preflight_run
  echo "Ferrum preflight"
  if preflight_report; then
    echo "  ok    ${FERRUM_OS_NAME:-this system} (${FERRUM_FAMILY:-?}, ${FERRUM_ARCH:-?}) can run Ferrum"
    exit 0
  fi
  exit 1
fi
