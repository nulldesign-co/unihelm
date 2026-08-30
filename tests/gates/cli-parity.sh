#!/usr/bin/env bash
# CI gate: the CLI reaches every operation the API does (spec §11.20).
#
# "New capability = new typed op + REST endpoint + CLI verb + audit + task +
# tests + docs" (spec §16.5). The CLI verb is the half nobody notices missing,
# because the UI is what gets demonstrated and the CLI is what gets used at
# three in the morning when the UI will not load. This gate is what notices.
#
# It compares two lists:
#
#   1. Every operation registered in `crates/unihelm-ops/src/registry.rs` —
#      the whitelist, and therefore the definition of what exists.
#   2. Every operation named in `COVERAGE` in
#      `crates/unihelm-cli/src/parity.rs`, which pairs an operation with a real
#      `unihelm …` command line.
#
# The second list is only worth reading because a unit test
# (`parity::tests::every_listed_command_really_plans_that_operation`) parses
# each of those command lines through the real command tree and the real
# planner and asserts it emits exactly that operation. This gate checks the set;
# that test checks the mapping. Neither is sufficient alone.
#
# Anything registered and not covered must appear in
# `tests/gates/cli-parity-allowlist.txt` with a reason.
#
# **The failing list is the checklist.** When this gate fails it prints the
# operations the CLI cannot reach. The fix is a subcommand, or an allowlist
# entry whose reason survives being read aloud — never a wider grep.
#
# Run `bash tests/gates/cli-parity.sh --self-test` to check the gate's own
# extraction against fixtures: that it fails on a gap, passes when the gap is
# covered, passes when it is allowlisted with a reason, and reports an
# allowlist entry that suppresses nothing.
set -euo pipefail

SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

# Overridable for the self-test only.
REGISTRY="${UNIHELM_PARITY_REGISTRY:-crates/unihelm-ops/src/registry.rs}"
OPS_SRC="${UNIHELM_PARITY_OPS_SRC:-crates/unihelm-ops/src}"
COVERAGE_SRC="${UNIHELM_PARITY_COVERAGE:-crates/unihelm-cli/src/parity.rs}"
ALLOWLIST="${UNIHELM_PARITY_ALLOWLIST:-tests/gates/cli-parity-allowlist.txt}"

if [ -n "${NO_COLOR:-}" ]; then
  C_RED='' C_GREEN='' C_YELLOW='' C_OFF=''
else
  C_RED=$'\033[31m' C_GREEN=$'\033[32m' C_YELLOW=$'\033[33m' C_OFF=$'\033[0m'
fi

# --- which types are registered --------------------------------------------
# Same technique as tests/gates/ops-docs.sh, deliberately copied rather than
# shared: each gate stays a single file somebody can read end to end, and a
# shared helper is one more thing a merge can break.
registered_types() {
  grep -oE 'registry\.register\(crate::[a-z0-9_:]+::[A-Za-z][A-Za-z0-9]*' "$REGISTRY" |
    sed 's/^registry\.register(crate:://'
}

module_file() {
  local module_path="$1" as_dir as_file
  as_file="$OPS_SRC/${module_path//:://}.rs"
  as_dir="$OPS_SRC/${module_path//:://}/mod.rs"
  if [ -f "$as_file" ]; then
    printf '%s' "$as_file"
  elif [ -f "$as_dir" ]; then
    printf '%s' "$as_dir"
  fi
}

op_name_of() {
  local file="$1" type_name="$2"
  awk -v want="$type_name" '
    $0 ~ "^impl TypedOperation for " want "([ {]|$)" { inside = 1; next }
    inside && /const NAME/ {
      line = $0
      sub(/.*= *"/, "", line)
      sub(/".*/, "", line)
      print line
      exit
    }
    inside && /^}/ { inside = 0 }
  ' "$file"
}

# --- which operations the CLI reaches ---------------------------------------
# The first string literal of each COVERAGE entry. Both shapes are handled: the
# one-per-line form the `#[rustfmt::skip]` in parity.rs preserves, and the form
# rustfmt would produce if that attribute were ever removed.
covered_operations() {
  awk '
    /pub const COVERAGE/ { inside = 1; next }
    inside && /^\];/     { inside = 0 }
    !inside              { next }
    {
      if (match($0, /^[[:space:]]*\("[a-z0-9_.]+"[[:space:]]*,/)) {
        name = substr($0, RSTART, RLENGTH)
        sub(/^[[:space:]]*\("/, "", name)
        sub(/"[[:space:]]*,$/, "", name)
        print name
        open = 0
        next
      }
      if ($0 ~ /^[[:space:]]*\([[:space:]]*$/) { open = 1; next }
      if (open && match($0, /^[[:space:]]*"[a-z0-9_.]+"[[:space:]]*,/)) {
        name = $0
        sub(/^[[:space:]]*"/, "", name)
        sub(/"[[:space:]]*,$/, "", name)
        print name
      }
      open = 0
    }
  ' "$COVERAGE_SRC"
}

# --- the allowlist ----------------------------------------------------------
allowlisted_operations() {
  [ -f "$ALLOWLIST" ] || return 0
  awk '
    /^[[:space:]]*#/ { next }
    NF >= 2 { print $1 }
  ' "$ALLOWLIST"
}

# An entry with a name and nothing else is not an exemption, it is a shrug.
allowlist_entries_without_a_reason() {
  [ -f "$ALLOWLIST" ] || return 0
  awk '
    /^[[:space:]]*#/ { next }
    NF == 1 { print $1 }
  ' "$ALLOWLIST"
}

# `contains needle "${haystack[@]+"${haystack[@]}"}"` — the expansion is written
# that way at every call site because bash 3.2 (still the system shell on
# macOS) treats `"${empty[@]}"` as an unbound variable under `set -u`.
contains() {
  local needle="$1"
  shift
  local item
  for item in "$@"; do
    if [ "$item" = "$needle" ]; then
      return 0
    fi
  done
  return 1
}

run_gate() {
  local required
  for required in "$REGISTRY" "$COVERAGE_SRC"; do
    if [ ! -e "$required" ]; then
      echo "no $required — run this from the repository root" >&2
      return 2
    fi
  done

  local registered=() unresolved=()
  local qualified type_name module_path file name
  while IFS= read -r qualified; do
    [ -n "$qualified" ] || continue
    type_name=${qualified##*::}
    module_path=${qualified%::*}
    file=$(module_file "$module_path")
    if [ -z "$file" ]; then
      unresolved+=("$qualified (no source file for module $module_path)")
      continue
    fi
    name=$(op_name_of "$file" "$type_name")
    if [ -z "$name" ]; then
      unresolved+=("$qualified (no \`const NAME\` on its TypedOperation impl in $file)")
      continue
    fi
    registered+=("$name")
  done < <(registered_types)

  if [ "${#registered[@]}" -eq 0 ]; then
    echo "could not extract a single operation name from $REGISTRY" >&2
    echo "the gate cannot report honestly on a registry it cannot parse" >&2
    return 2
  fi

  # A registered type the gate cannot resolve is a parsing failure, and a gate
  # that quietly skips what it cannot parse is worse than no gate.
  if [ "${#unresolved[@]}" -gt 0 ]; then
    printf '%sFAIL%s could not resolve %d registered type(s):\n' \
      "$C_RED" "$C_OFF" "${#unresolved[@]}"
    printf '       %s\n' "${unresolved[@]}"
    return 1
  fi

  local covered=()
  local allowed=()
  local reasonless=()
  local entry
  while IFS= read -r entry; do
    if [ -n "$entry" ]; then covered+=("$entry"); fi
  done < <(covered_operations)
  while IFS= read -r entry; do
    if [ -n "$entry" ]; then allowed+=("$entry"); fi
  done < <(allowlisted_operations)
  while IFS= read -r entry; do
    if [ -n "$entry" ]; then reasonless+=("$entry"); fi
  done < <(allowlist_entries_without_a_reason)

  if [ "${#covered[@]}" -eq 0 ]; then
    echo "could not extract a single operation from $COVERAGE_SRC" >&2
    echo "a gate that reads an empty list would pass on an empty CLI" >&2
    return 2
  fi

  local failures=0

  if [ "${#reasonless[@]}" -gt 0 ]; then
    printf '%sFAIL%s allowlist entries with no reason:\n' "$C_RED" "$C_OFF"
    printf '       %s\n' "${reasonless[@]}"
    failures=$((failures + 1))
  fi

  # 1. Registered but unreachable and unexcused.
  local missing=()
  local op
  for op in "${registered[@]}"; do
    if contains "$op" "${covered[@]}"; then continue; fi
    if contains "$op" ${allowed[@]+"${allowed[@]}"}; then continue; fi
    missing+=("$op")
  done

  # 2. Claimed by the CLI but not registered: a typo in COVERAGE, or an
  #    operation that was removed and left a dead subcommand behind.
  local phantom=()
  for op in "${covered[@]}"; do
    if ! contains "$op" "${registered[@]}"; then
      phantom+=("$op")
    fi
  done

  # 3. Exemptions that are not exempting anything.
  local stale=()
  for op in ${allowed[@]+"${allowed[@]}"}; do
    if contains "$op" "${covered[@]}"; then
      stale+=("$op (the CLI reaches it — delete the allowlist line)")
    elif ! contains "$op" "${registered[@]}"; then
      stale+=("$op (no longer a registered operation — delete the allowlist line)")
    fi
  done

  printf '%d registered operation(s), %d reachable from the CLI, %d allowlisted, %d missing\n' \
    "${#registered[@]}" "$((${#registered[@]} - ${#missing[@]} - ${#allowed[@]}))" \
    "${#allowed[@]}" "${#missing[@]}"
  echo

  if [ "${#phantom[@]}" -gt 0 ]; then
    printf '%sFAIL%s the CLI claims operations that are not registered:\n' "$C_RED" "$C_OFF"
    printf '       %s\n' "${phantom[@]}"
    failures=$((failures + 1))
  fi

  if [ "${#stale[@]}" -gt 0 ]; then
    printf '%sstale%s allowlist:\n' "$C_YELLOW" "$C_OFF"
    printf '       %s\n' "${stale[@]}"
    failures=$((failures + 1))
  fi

  if [ "${#missing[@]}" -gt 0 ]; then
    printf '%sFAIL%s the following operations cannot be reached from the CLI:\n' \
      "$C_RED" "$C_OFF"
    printf '       %s\n' "${missing[@]}"
    cat >&2 <<'EOF'

This list is the checklist. Each one needs a `unihelm …` subcommand and an entry
in COVERAGE in crates/unihelm-cli/src/parity.rs — or, if it genuinely does not
belong on a command line, a line in tests/gates/cli-parity-allowlist.txt saying
why. Spec §11.20: the CLI reaches everything the UI can.
EOF
    failures=$((failures + 1))
  fi

  if [ "$failures" -gt 0 ]; then
    return 1
  fi
  printf '%sok%s   every registered operation is reachable from the CLI or excused\n' \
    "$C_GREEN" "$C_OFF"
  return 0
}

# --- self-test --------------------------------------------------------------
# A gate nobody ever saw fail might be matching nothing at all.
self_test() {
  local dir status out failed=0
  dir=$(mktemp -d)
  trap 'rm -rf "$dir"' RETURN

  mkdir -p "$dir/ops"
  cat >"$dir/ops/thing.rs" <<'RUST'
impl TypedOperation for Alpha {
    const NAME: &'static str = "thing.alpha";
}
impl TypedOperation for Beta {
    const NAME: &'static str = "thing.beta";
}
RUST
  cat >"$dir/registry.rs" <<'RUST'
        registry.register(crate::thing::Alpha);
        registry.register(crate::thing::Beta);
RUST

  # Covers alpha only.
  cat >"$dir/parity.rs" <<'RUST'
pub const COVERAGE: &[(&str, &[&str])] = &[
    ("thing.alpha", &["unihelm", "thing", "alpha"]),
];
RUST

  run_fixture() {
    NO_COLOR=1 \
      UNIHELM_PARITY_REGISTRY="$dir/registry.rs" \
      UNIHELM_PARITY_OPS_SRC="$dir/ops" \
      UNIHELM_PARITY_COVERAGE="$dir/parity.rs" \
      UNIHELM_PARITY_ALLOWLIST="$1" \
      bash "$SELF" 2>&1
  }

  check() {
    if [ "$1" = "ok" ]; then
      echo "ok   $2"
    else
      echo "FAIL $2"
      failed=1
    fi
  }

  : >"$dir/empty-allow.txt"
  out=$(run_fixture "$dir/empty-allow.txt") && status=0 || status=$?
  if [ "$status" -ne 0 ] && printf '%s' "$out" | grep -q 'thing.beta'; then
    check ok "an_uncovered_operation_fails_the_gate_and_is_named"
  else
    check no "an_uncovered_operation_fails_the_gate_and_is_named"
    printf '%s\n' "$out" | sed 's/^/       /'
  fi

  printf 'thing.beta it is deliberately not on the command line\n' >"$dir/allow.txt"
  out=$(run_fixture "$dir/allow.txt") && status=0 || status=$?
  if [ "$status" -eq 0 ]; then
    check ok "an_allowlisted_operation_with_a_reason_passes"
  else
    check no "an_allowlisted_operation_with_a_reason_passes"
    printf '%s\n' "$out" | sed 's/^/       /'
  fi

  printf 'thing.beta\n' >"$dir/no-reason.txt"
  out=$(run_fixture "$dir/no-reason.txt") && status=0 || status=$?
  if [ "$status" -ne 0 ] && printf '%s' "$out" | grep -q 'no reason'; then
    check ok "an_allowlist_entry_without_a_reason_is_refused"
  else
    check no "an_allowlist_entry_without_a_reason_is_refused"
    printf '%s\n' "$out" | sed 's/^/       /'
  fi

  printf 'thing.alpha covered anyway\nthing.beta fine\n' >"$dir/stale.txt"
  out=$(run_fixture "$dir/stale.txt") && status=0 || status=$?
  if [ "$status" -ne 0 ] && printf '%s' "$out" | grep -q 'stale'; then
    check ok "an_allowlist_entry_that_excuses_nothing_is_reported_stale"
  else
    check no "an_allowlist_entry_that_excuses_nothing_is_reported_stale"
    printf '%s\n' "$out" | sed 's/^/       /'
  fi

  # A COVERAGE entry naming an operation that does not exist: a typo that would
  # otherwise read as coverage.
  cat >"$dir/parity.rs" <<'RUST'
pub const COVERAGE: &[(&str, &[&str])] = &[
    ("thing.alpha", &["unihelm", "thing", "alpha"]),
    ("thing.beta", &["unihelm", "thing", "beta"]),
    ("thing.gamma", &["unihelm", "thing", "gamma"]),
];
RUST
  out=$(run_fixture "$dir/empty-allow.txt") && status=0 || status=$?
  if [ "$status" -ne 0 ] && printf '%s' "$out" | grep -q 'thing.gamma'; then
    check ok "a_covered_operation_that_is_not_registered_is_reported"
  else
    check no "a_covered_operation_that_is_not_registered_is_reported"
    printf '%s\n' "$out" | sed 's/^/       /'
  fi

  # The rustfmt-exploded shape must parse too, or a future `cargo fmt` would
  # silently empty the covered list and turn the gate into a rubber stamp.
  cat >"$dir/parity.rs" <<'RUST'
pub const COVERAGE: &[(&str, &[&str])] = &[
    (
        "thing.alpha",
        &["unihelm", "thing", "alpha"],
    ),
    (
        "thing.beta",
        &["unihelm", "thing", "beta"],
    ),
];
RUST
  out=$(run_fixture "$dir/empty-allow.txt") && status=0 || status=$?
  if [ "$status" -eq 0 ]; then
    check ok "the_multiline_coverage_shape_is_understood"
  else
    check no "the_multiline_coverage_shape_is_understood"
    printf '%s\n' "$out" | sed 's/^/       /'
  fi

  echo
  if [ "$failed" -eq 0 ]; then
    echo "cli-parity self-test passed"
  else
    echo "cli-parity self-test failed" >&2
  fi
  return "$failed"
}

if [ "${1:-}" = "--self-test" ]; then
  self_test
  exit $?
fi

run_gate
