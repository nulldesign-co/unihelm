#!/usr/bin/env bash
# CI gate: the performance budgets from spec §3.
#
# These are the numbers the whole project is justified by. A change that blows
# one of them is a change that has to be fixed before it merges (spec §16.3) —
# so they are checked, not aspired to.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/../.."

# Spec §3.
readonly BINARY_BUDGET_BYTES=$((25 * 1024 * 1024))
readonly BUNDLE_BUDGET_BYTES=$((350 * 1024))
readonly RSS_BUDGET_BYTES=$((80 * 1024 * 1024))
readonly RSS_TARGET_BYTES=$((50 * 1024 * 1024))

failures=0
mode="${1:-all}"

human() { numfmt --to=iec-i --suffix=B "$1" 2>/dev/null || echo "$1 bytes"; }

ok()   { printf '\033[32mok\033[0m   %-34s %s\n' "$1" "$2"; }
fail() { printf '\033[31mFAIL\033[0m %-34s %s\n' "$1" "$2"; failures=$((failures + 1)); }
note() { printf '     %-34s %s\n' "$1" "$2"; }

# --- binary size -----------------------------------------------------------
check_binaries() {
  local target="${CARGO_TARGET_DIR:-target}/release"
  if [ ! -d "$target" ]; then
    fail "binary size" "no release build at $target (run: cargo build --release)"
    return
  fi
  for binary in ferrum-agentd ferrum-web ferrum; do
    local path="$target/$binary"
    if [ ! -f "$path" ]; then
      fail "binary size: $binary" "not built"
      continue
    fi
    local size
    size=$(wc -c <"$path" | tr -d ' ')
    if [ "$size" -le "$BINARY_BUDGET_BYTES" ]; then
      ok "binary size: $binary" "$(human "$size") / $(human "$BINARY_BUDGET_BYTES")"
    else
      fail "binary size: $binary" "$(human "$size") exceeds $(human "$BINARY_BUDGET_BYTES")"
    fi
  done
}

# --- ui bundle -------------------------------------------------------------
check_bundle() {
  local dist="crates/ferrum-web/ui-dist/assets"
  if [ ! -d "$dist" ]; then
    fail "ui bundle" "not built (run: cd ui && npm run build)"
    return
  fi

  # The budget is the initial route: the entry chunk plus its stylesheet,
  # gzipped. Lazy chunks (Monaco, xterm) are explicitly outside it (spec §4.2).
  local total=0 file size
  for file in "$dist"/index-*.js "$dist"/index-*.css; do
    [ -f "$file" ] || continue
    size=$(gzip -9 -c "$file" | wc -c | tr -d ' ')
    total=$((total + size))
    note "  $(basename "$file")" "$(human "$size") gzipped"
  done

  if [ "$total" -eq 0 ]; then
    fail "ui bundle" "no entry chunk found in $dist"
  elif [ "$total" -le "$BUNDLE_BUDGET_BYTES" ]; then
    ok "ui bundle (initial route)" "$(human "$total") / $(human "$BUNDLE_BUDGET_BYTES")"
  else
    fail "ui bundle (initial route)" "$(human "$total") exceeds $(human "$BUNDLE_BUDGET_BYTES")"
  fi
}

# --- idle memory -----------------------------------------------------------
# Starts both daemons against a throwaway directory, lets them settle, and reads
# their real resident memory. Linux-only: `smaps_rollup` is where the honest
# number lives, and Linux is the only platform Ferrum runs on in production.
check_rss() {
  if [ "$(uname -s)" != "Linux" ]; then
    note "idle RSS" "skipped (measured on Linux in CI)"
    return
  fi

  local target="${CARGO_TARGET_DIR:-target}/release"
  local dir
  dir=$(mktemp -d /tmp/ferrum-rss.XXXXXX)
  trap 'rm -rf "$dir"' RETURN

  "$target/ferrum-agentd" --dev "$dir" >"$dir/agentd.log" 2>&1 &
  local agent_pid=$!
  "$target/ferrum-web" --dev "$dir" --listen 127.0.0.1:18099 >"$dir/web.log" 2>&1 &
  local web_pid=$!
  # shellcheck disable=SC2064
  trap "kill $agent_pid $web_pid 2>/dev/null; rm -rf '$dir'" RETURN

  # The budget is idle RSS after settling, not peak during startup.
  local settle="${FERRUM_RSS_SETTLE_SECONDS:-60}"
  note "idle RSS" "settling for ${settle}s"
  sleep "$settle"

  local total=0 pid rss
  for pid in $agent_pid $web_pid; do
    if [ ! -r "/proc/$pid/smaps_rollup" ]; then
      fail "idle RSS" "process $pid is not running — check $dir/*.log"
      return
    fi
    rss=$(awk '/^Rss:/ {print $2}' "/proc/$pid/smaps_rollup")
    total=$((total + rss * 1024))
    note "  pid $pid" "$(human $((rss * 1024)))"
  done

  if [ "$total" -le "$RSS_TARGET_BYTES" ]; then
    ok "idle RSS (web + agent)" "$(human "$total") / target $(human "$RSS_TARGET_BYTES")"
  elif [ "$total" -le "$RSS_BUDGET_BYTES" ]; then
    ok "idle RSS (web + agent)" "$(human "$total") / budget $(human "$RSS_BUDGET_BYTES") (over the ${RSS_TARGET_BYTES} target)"
  else
    fail "idle RSS (web + agent)" "$(human "$total") exceeds $(human "$RSS_BUDGET_BYTES")"
  fi
}

case "$mode" in
  binaries) check_binaries ;;
  bundle) check_bundle ;;
  rss) check_rss ;;
  all) check_binaries; check_bundle; check_rss ;;
  *) echo "usage: budgets.sh [all|binaries|bundle|rss]" >&2; exit 2 ;;
esac

echo
if [ "$failures" -gt 0 ]; then
  echo "budget gate failed with $failures violation(s)" >&2
  echo "Beating the incumbents on weight is the point of this project (spec §2.2)." >&2
  exit 1
fi
echo "budget gate passed"
