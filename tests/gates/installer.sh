#!/usr/bin/env bash
# CI gate: the installer must not die silently.
#
# The bug this exists for: `preflight_check_conflicts` ended with
# `[ -d "$panel" ] && _warn ...`, which returns 1 when the directory is absent.
# As the last statement in a function that is the last thing a `set -e` script
# calls, that killed the installer on every *clean* server — with no output at
# all. It passed `bash -n`, passed shellcheck, and only showed up on a real box.
#
# So this gate asserts two things: every preflight check returns success on its
# own, and the script always produces output before exiting.
set -uo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/../.."

failures=0
ok()   { printf '\033[32mok\033[0m   %s\n' "$1"; }
fail() { printf '\033[31mFAIL\033[0m %s\n' "$1"; failures=$((failures + 1)); }

# --- 1. every check function succeeds in isolation --------------------------
# shellcheck source=../../installer/preflight.sh
. installer/preflight.sh

for check in \
  preflight_check_os \
  preflight_check_arch \
  preflight_check_systemd \
  preflight_check_cgroups \
  preflight_check_memory \
  preflight_check_disk \
  preflight_check_conflicts
do
  if (set -e; "$check"); then
    ok "$check returns success"
  else
    fail "$check returns non-zero — under \`set -e\` this kills the installer silently"
  fi
done

# --- 2. the script always says something ------------------------------------
output=$(bash installer/preflight.sh 2>&1 || true)
if [ -n "$output" ]; then
  ok "preflight produces output"
else
  fail "preflight exited without printing anything"
fi

if printf '%s' "$output" | grep -q "Ferrum preflight"; then
  ok "preflight reaches its report"
else
  fail "preflight died before reporting: ${output:-<empty>}"
fi

# --- 3. unit hardening must not contradict what each daemon does -------------
# `ProtectHome=read-only` on the agent made `useradd --create-home` fail with a
# bare "cannot create directory" — a hardening setting quietly breaking the
# feature it was meant to protect. The split is the point: the root daemon needs
# /home, the web process must never see it.
agent_unit=installer/systemd/ferrum-agentd.service
web_unit=installer/systemd/ferrum-web.service

if grep -qE '^ProtectHome=(yes|read-only)' "$agent_unit"; then
  fail "$agent_unit restricts /home, but creating tenant homes is its job"
else
  ok "agent can write to /home"
fi

if grep -qE '^ProtectHome=yes' "$web_unit"; then
  ok "web process cannot see tenant homes"
else
  fail "$web_unit should set ProtectHome=yes — it has no business in /home"
fi

if grep -qE '^CapabilityBoundingSet=$' "$web_unit"; then
  ok "web process drops every capability"
else
  fail "$web_unit should drop all capabilities"
fi

# --- 4. both scripts parse --------------------------------------------------
for script in installer/preflight.sh installer/install.sh tests/gates/*.sh; do
  if bash -n "$script"; then ok "$script parses"; else fail "$script has a syntax error"; fi
done

echo
if [ "$failures" -gt 0 ]; then
  echo "installer gate failed with $failures problem(s)" >&2
  exit 1
fi
echo "installer gate passed"
