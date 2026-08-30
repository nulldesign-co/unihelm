#!/usr/bin/env bash
# CI gate: the performance budgets from spec §3.
#
# These are the numbers the whole project is justified by. A change that blows
# one of them is a change that has to be fixed before it merges (spec §16.3) —
# so they are checked, not aspired to.
#
# Run `bash tests/gates/budgets.sh --self-test` to check the UI budget's own
# logic against fixture builds: which chunks count as initial, that the limit
# actually bites, and that renaming a chunk does not slip past it.
set -euo pipefail

SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

# Spec §3.
readonly BINARY_BUDGET_BYTES=$((25 * 1024 * 1024))
readonly BUNDLE_BUDGET_BYTES=$((350 * 1024))
readonly RSS_BUDGET_BYTES=$((80 * 1024 * 1024))
readonly RSS_TARGET_BYTES=$((50 * 1024 * 1024))

# Overridable for the self-test only, which points it at a fixture build. The
# budget itself is not overridable: a threshold with an escape hatch is not a
# threshold, so the self-test uses real incompressible bytes to cross the real
# 350 KB line.
readonly UI_DIST="${UNIHELM_UI_DIST:-crates/unihelm-web/ui-dist}"

failures=0
mode="${1:-all}"

if [ -n "${NO_COLOR:-}" ]; then
  C_RED='' C_GREEN='' C_OFF=''
else
  C_RED=$'\033[31m' C_GREEN=$'\033[32m' C_OFF=$'\033[0m'
fi

human() { numfmt --to=iec-i --suffix=B "$1" 2>/dev/null || echo "$1 bytes"; }

ok()   { printf '%sok%s   %-34s %s\n' "$C_GREEN" "$C_OFF" "$1" "$2"; }
fail() { printf '%sFAIL%s %-34s %s\n' "$C_RED" "$C_OFF" "$1" "$2"; failures=$((failures + 1)); }
note() { printf '     %-34s %s\n' "$1" "$2"; }

gzipped() { gzip -9 -c "$1" | wc -c | tr -d ' '; }

# --- binary size -----------------------------------------------------------
check_binaries() {
  local target="${CARGO_TARGET_DIR:-target}/release"
  if [ ! -d "$target" ]; then
    fail "binary size" "no release build at $target (run: cargo build --release)"
    return
  fi
  for binary in unihelm-agentd unihelm-web unihelm; do
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
# Build the UI if there is nothing to measure. In CI the `ui` job has already
# run `npm ci && npm run build`, so this is normally a no-op; run the gate on a
# clean checkout and it does the build itself rather than reporting a miss.
ensure_ui_build() {
  if [ -f "$UI_DIST/index.html" ]; then
    note "ui build" "measuring existing $UI_DIST"
    return 0
  fi
  if [ "${UNIHELM_BUDGET_SKIP_UI_BUILD:-0}" = "1" ]; then
    fail "ui bundle" "no build at $UI_DIST and UNIHELM_BUDGET_SKIP_UI_BUILD=1"
    return 1
  fi
  if ! command -v npm >/dev/null 2>&1; then
    fail "ui bundle" "no build at $UI_DIST and npm is not installed"
    return 1
  fi
  note "ui build" "building ui/ (npm ci && npm run build)"
  if ! (cd ui && npm ci >/dev/null 2>&1 && npm run build >/dev/null 2>&1); then
    fail "ui bundle" "the ui build failed — run \`cd ui && npm run build\` to see why"
    return 1
  fi
  return 0
}

# The assets index.html pulls in itself: the entry module plus everything the
# browser is told to fetch before first paint (`modulepreload` is a static
# import of the entry, so it is on the critical path just as much). Anything
# else in the output is reached through a dynamic import — a lazy chunk — and
# is outside the budget by design (spec §4.2), which is exactly why heavy
# things like the code editor must be imported lazily.
#
# Parsing index.html rather than globbing `index-*.js` matters: the glob is a
# guess about Vite's naming that a `build.rollupOptions.output` tweak would
# quietly invalidate, and a budget you can slip past by renaming a chunk is not
# a budget.
initial_assets() {
  tr '>' '>\n' <"$UI_DIST/index.html" |
    grep -Eo '<(script[^>]*src|link[^>]*(rel="(modulepreload|stylesheet)"[^>]*href|href[^>]*rel="(modulepreload|stylesheet)"))="[^"]+"' |
    grep -Eo '(src|href)="[^"]+"' |
    sed -e 's/^[a-z]*="//' -e 's/"$//' |
    sed 's|^/||' |
    sort -u
}

check_bundle() {
  ensure_ui_build || return

  local initial=() asset path
  while IFS= read -r asset; do
    [ -n "$asset" ] || continue
    path="$UI_DIST/$asset"
    if [ ! -f "$path" ]; then
      # A reference index.html makes to something that is not in the output is
      # a broken build, not a passing budget.
      fail "ui bundle" "index.html references $asset, which is missing"
      continue
    fi
    initial+=("$path")
  done < <(initial_assets)

  if [ "${#initial[@]}" -eq 0 ]; then
    fail "ui bundle" "index.html references no built assets — is the build stale?"
    return
  fi

  # The budget is per chunk, not per sum: the browser fetches initial chunks in
  # parallel, and one 400 KB chunk is the stall a user feels.
  local largest=0 largest_name="" css_total=0 size name
  for path in "${initial[@]}"; do
    name=$(basename "$path")
    size=$(gzipped "$path")
    case "$path" in
      *.js)
        note "  initial js: $name" "$(human "$size") gzipped"
        if [ "$size" -gt "$largest" ]; then
          largest=$size
          largest_name=$name
        fi
        ;;
      *.css)
        note "  initial css: $name" "$(human "$size") gzipped"
        css_total=$((css_total + size))
        ;;
      *)
        note "  initial: $name" "$(human "$size") gzipped"
        ;;
    esac
  done

  if [ "$largest" -eq 0 ]; then
    fail "ui bundle" "index.html loads no JavaScript — is the build stale?"
  elif [ "$largest" -le "$BUNDLE_BUDGET_BYTES" ]; then
    ok "ui bundle: largest initial chunk" \
      "$largest_name $(human "$largest") / $(human "$BUNDLE_BUDGET_BYTES")"
  else
    fail "ui bundle: largest initial chunk" \
      "$largest_name $(human "$largest") exceeds $(human "$BUNDLE_BUDGET_BYTES")"
    note "" "import the heavy dependency lazily so it lands in its own chunk"
  fi
  [ "$css_total" -gt 0 ] && note "  initial css total" "$(human "$css_total") gzipped"

  # Lazy chunks are exempt, not invisible: a 3 MB lazy chunk is still three
  # megabytes somebody waits for the first time they open that page.
  local lazy=0 is_initial known
  while IFS= read -r path; do
    is_initial=0
    for known in "${initial[@]}"; do
      [ "$known" = "$path" ] && is_initial=1 && break
    done
    [ "$is_initial" -eq 1 ] && continue
    size=$(gzipped "$path")
    note "  lazy chunk: $(basename "$path")" "$(human "$size") gzipped (exempt)"
    lazy=$((lazy + 1))
  done < <(find "$UI_DIST" -name '*.js' -type f | sort)
  note "  lazy chunks" "$lazy outside the initial budget"
}

# --- idle memory -----------------------------------------------------------
# Starts both daemons against a throwaway directory, lets them settle, and reads
# their real resident memory. Linux-only: `smaps_rollup` is where the honest
# number lives, and Linux is the only platform Unihelm runs on in production.
check_rss() {
  if [ "$(uname -s)" != "Linux" ]; then
    note "idle RSS" "skipped (measured on Linux in CI)"
    return
  fi

  local target="${CARGO_TARGET_DIR:-target}/release"
  local dir
  dir=$(mktemp -d /tmp/unihelm-rss.XXXXXX)
  trap 'rm -rf "$dir"' RETURN

  "$target/unihelm-agentd" --dev "$dir" >"$dir/agentd.log" 2>&1 &
  local agent_pid=$!
  "$target/unihelm-web" --dev "$dir" --listen 127.0.0.1:18099 >"$dir/web.log" 2>&1 &
  local web_pid=$!
  # shellcheck disable=SC2064
  trap "kill $agent_pid $web_pid 2>/dev/null; rm -rf '$dir'" RETURN

  # The budget is idle RSS after settling, not peak during startup.
  local settle="${UNIHELM_RSS_SETTLE_SECONDS:-60}"
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

# --- self-test --------------------------------------------------------------
# Fixture builds, not mocks: a directory shaped like Vite's output, measured by
# the real `check_bundle`. The oversized chunks are `/dev/urandom`, because
# gzip cannot shrink random bytes and the assertion has to cross the real
# 350 KB line rather than a lowered one.

selftest_failures=0

# _dist <dir> <index.html body> — writes a fixture build.
_dist() {
  local dir="$1" head="$2"
  mkdir -p "$dir/assets"
  cat >"$dir/index.html" <<HTML
<!doctype html>
<html><head>$head</head><body><div id="root"></div></body></html>
HTML
}

_small() { head -c 4096 /dev/zero | tr '\0' 'a' >"$1"; }
# 400 KB of incompressible bytes: over 350 KB even after gzip -9.
_huge() { head -c 400000 /dev/urandom >"$1"; }

# _case <name> <dist-dir> <expected-status> <expected-substring>
_case() {
  local name="$1" dist="$2" want_status="$3" want_text="$4"
  local out status=0
  out=$(NO_COLOR=1 UNIHELM_UI_DIST="$dist" bash "$SELF" bundle 2>&1) || status=$?

  if [ "$status" -ne "$want_status" ]; then
    printf 'FAIL %s: exit %d, expected %d\n' "$name" "$status" "$want_status"
    printf '%s\n' "$out" | sed 's/^/       /'
    selftest_failures=$((selftest_failures + 1))
    return
  fi
  if [ -n "$want_text" ] && ! printf '%s' "$out" | grep -qF -- "$want_text"; then
    printf 'FAIL %s: output does not mention "%s"\n' "$name" "$want_text"
    printf '%s\n' "$out" | sed 's/^/       /'
    selftest_failures=$((selftest_failures + 1))
    return
  fi
  printf 'ok   %s\n' "$name"
}

self_test() {
  local root
  root=$(mktemp -d)
  # shellcheck disable=SC2064  # expand $root now, not at trap time
  trap "rm -rf '$root'" RETURN

  # A normal build: small entry, small stylesheet, one heavy lazy chunk.
  _dist "$root/normal" \
    '<script type="module" crossorigin src="/assets/index-aaaa.js"></script>
     <link rel="stylesheet" crossorigin href="/assets/index-aaaa.css">'
  _small "$root/normal/assets/index-aaaa.js"
  _small "$root/normal/assets/index-aaaa.css"
  _huge "$root/normal/assets/code-editor-bbbb.js"
  _case an_initial_chunk_under_budget_passes "$root/normal" 0 'largest initial chunk'
  _case a_lazy_chunk_over_budget_is_exempt_but_still_reported \
    "$root/normal" 0 'lazy chunk: code-editor-bbbb.js'

  # The same heavy chunk, now loaded from index.html.
  _dist "$root/fat" '<script type="module" src="/assets/index-cccc.js"></script>'
  _huge "$root/fat/assets/index-cccc.js"
  _case an_initial_chunk_over_budget_fails "$root/fat" 1 'exceeds'

  # A modulepreload is a static import of the entry: on the critical path, and
  # therefore inside the budget, however the browser spells the fetch.
  _dist "$root/preload" \
    '<script type="module" src="/assets/index-dddd.js"></script>
     <link rel="modulepreload" crossorigin href="/assets/vendor-eeee.js">'
  _small "$root/preload/assets/index-dddd.js"
  _huge "$root/preload/assets/vendor-eeee.js"
  _case a_modulepreloaded_chunk_counts_against_the_budget "$root/preload" 1 'vendor-eeee.js'

  # The reason the gate parses index.html instead of globbing `index-*.js`: a
  # rollupOptions rename must not be a way to leave the budget.
  _dist "$root/renamed" '<script type="module" src="/assets/app.bundle.js"></script>'
  _huge "$root/renamed/assets/app.bundle.js"
  _case renaming_the_entry_chunk_does_not_escape_the_budget "$root/renamed" 1 'app.bundle.js'

  # A reference to something the build did not emit is a broken build, not a
  # passing budget.
  _dist "$root/missing" '<script type="module" src="/assets/gone-ffff.js"></script>'
  _case an_index_referencing_a_missing_asset_fails "$root/missing" 1 'which is missing'

  # No JavaScript at all means a stale or half-written dist, and "no chunks" is
  # not the same as "no chunk is too big".
  _dist "$root/empty" '<link rel="stylesheet" href="/assets/only-gggg.css">'
  _small "$root/empty/assets/only-gggg.css"
  _case an_index_that_loads_no_javascript_fails "$root/empty" 1 'loads no JavaScript'

  echo
  if [ "$selftest_failures" -eq 0 ]; then
    echo "budget gate self-test passed"
    return 0
  fi
  echo "budget gate self-test failed with $selftest_failures problem(s)" >&2
  return 1
}

case "$mode" in
  binaries) check_binaries ;;
  bundle) check_bundle ;;
  rss) check_rss ;;
  all) check_binaries; check_bundle; check_rss ;;
  --self-test) self_test; exit $? ;;
  *) echo "usage: budgets.sh [all|binaries|bundle|rss|--self-test]" >&2; exit 2 ;;
esac

echo
if [ "$failures" -gt 0 ]; then
  echo "budget gate failed with $failures violation(s)" >&2
  echo "Beating the incumbents on weight is the point of this project (spec §2.2)." >&2
  exit 1
fi
echo "budget gate passed"
