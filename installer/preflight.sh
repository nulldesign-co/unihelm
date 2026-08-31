#!/usr/bin/env bash
# Unihelm preflight (spec §7.1).
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
preflight_notes=()

_fail() { preflight_problems+=("$1"); }
_warn() { preflight_warnings+=("$1"); }
# What was measured, whether or not it was a problem. The report used to print
# only failures, so a healthy server produced silence — and the documented use
# of "run this to size up a machine before you commit to it" told you nothing
# on the machines where the answer was good news.
_note() { preflight_notes+=("$1"); }

preflight_check_root() {
  if [ "$(id -u)" -ne 0 ]; then
    _fail "must be run as root"
  fi
  return 0
}

preflight_check_os() {
  if [ ! -r /etc/os-release ]; then
    _fail "/etc/os-release is missing — this does not look like a supported Linux distribution"
    return
  fi

  # shellcheck disable=SC1091
  . /etc/os-release
  UNIHELM_OS_ID="${ID:-unknown}"
  UNIHELM_OS_VERSION="${VERSION_ID:-}"
  UNIHELM_OS_NAME="${PRETTY_NAME:-$UNIHELM_OS_ID}"
  local like="${ID_LIKE:-}"
  local major="${UNIHELM_OS_VERSION%%.*}"

  case "$UNIHELM_OS_ID" in
    debian)
      UNIHELM_FAMILY=debian
      [ "$major" -ge 12 ] 2>/dev/null || _warn "Debian $UNIHELM_OS_VERSION is older than the tested 12/13"
      ;;
    ubuntu)
      UNIHELM_FAMILY=debian
      case "$UNIHELM_OS_VERSION" in
        22.04 | 24.04 | 26.04) ;;
        *) _warn "Ubuntu $UNIHELM_OS_VERSION is not one of the tested LTS releases" ;;
      esac
      ;;
    almalinux | rocky | rhel | centos)
      UNIHELM_FAMILY=rhel
      [ "$major" -ge 9 ] 2>/dev/null || _warn "$UNIHELM_OS_NAME is older than the tested 9/10"
      ;;
    *)
      case " $like " in
        *" debian "* | *" ubuntu "*) UNIHELM_FAMILY=debian; _warn "$UNIHELM_OS_NAME is an untested Debian derivative" ;;
        *" rhel "* | *" fedora "* | *" centos "*) UNIHELM_FAMILY=rhel; _warn "$UNIHELM_OS_NAME is an untested RHEL derivative" ;;
        *) _fail "$UNIHELM_OS_NAME is not supported (Debian/Ubuntu or RHEL family only)" ;;
      esac
      ;;
  esac
  return 0
}

preflight_check_arch() {
  UNIHELM_ARCH="$(uname -m)"
  case "$UNIHELM_ARCH" in
    x86_64 | aarch64 | arm64) ;;
    *) _fail "architecture $UNIHELM_ARCH is not supported (x86_64 and aarch64 only)" ;;
  esac
  return 0
}

preflight_check_systemd() {
  if [ ! -d /run/systemd/system ]; then
    _fail "systemd is required (spec §1.3); this system is not running it"
  fi
  return 0
}

preflight_check_cgroups() {
  # cgroups v2 unified hierarchy is what per-tenant memory and CPU limits are
  # built on, so a v1 system cannot enforce a plan (spec §6.3).
  if [ ! -f /sys/fs/cgroup/cgroup.controllers ]; then
    _fail "cgroups v2 unified hierarchy is required; boot with systemd.unified_cgroup_hierarchy=1"
  fi
  return 0
}

preflight_check_memory() {
  local kb
  kb="$(awk '/^MemTotal:/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)"
  local mb=$((kb / 1024))
  _note "RAM: ${mb} MB"
  if [ "$mb" -lt "$MIN_RAM_MB" ]; then
    _fail "${mb} MB of RAM; Unihelm needs at least 1 GB"
  elif [ "$mb" -lt 1800 ]; then
    _warn "${mb} MB of RAM — enough for the panel, tight for a full stack"
  fi
  return 0
}

preflight_check_disk() {
  local mb
  mb="$(df -Pm /var 2>/dev/null | awk 'NR==2 {print $4}')"
  [ -n "$mb" ] && _note "free on /var: ${mb} MB"
  if [ -z "$mb" ]; then
    _warn "could not determine free space on /var"
  elif [ "$mb" -lt "$MIN_DISK_MB" ]; then
    _fail "${mb} MB free on /var; Unihelm needs at least 10 GB"
  fi
  return 0
}

preflight_check_conflicts() {
  # Another panel owning nginx or the same ports turns into a fight the user
  # loses at 3am. Say so now.
  # nginx is in this list even though Unihelm manages nginx itself: an nginx that
  # is already running was configured by somebody else, holds 80 and 443, and its
  # vhosts are not ones the panel wrote. Finding it after the install, when the
  # first site fails to bind, is the expensive way to learn this.
  for unit in nginx httpd apache2 cpanel psa; do
    if systemctl is-active --quiet "$unit" 2>/dev/null; then
      _warn "$unit is running and will compete with the stack Unihelm manages"
    fi
  done
  for panel in /usr/local/cpanel /opt/psa /www/server/panel; do
    if [ -d "$panel" ]; then
      _warn "another control panel is installed at $panel"
    fi
  done

  # Every check function must succeed. A bare `[ -d x ] && warn` as the last
  # statement returns 1 on a *clean* server, which under `set -e` killed the
  # installer silently — the failure mode nobody sees until it is on somebody
  # else's machine.
  return 0
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
  local n w p
  for n in ${preflight_notes+"${preflight_notes[@]}"}; do
    printf '  \033[2m....\033[0m  %s\n' "$n" >&2
  done
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
  echo "Unihelm preflight"
  if preflight_report; then
    echo "  ok    ${UNIHELM_OS_NAME:-this system} (${UNIHELM_FAMILY:-?}, ${UNIHELM_ARCH:-?}) can run Unihelm"
    exit 0
  fi
  exit 1
fi
