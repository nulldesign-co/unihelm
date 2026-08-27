#!/usr/bin/env bash
# CI gate: migrations are numbered once and never rewritten (spec §4.1, §10.4).
#
# Two invariants, and one deliberate softness between them.
#
#   1. **Numbering.** Every file in `crates/ferrum-db/migrations/` is
#      `NNNN_name.sql` with a 4-digit prefix. Two files may never share a
#      number: sqlx applies migrations in filename order and records them by
#      version, so a duplicate number means one of the two silently never runs
#      on a database that already saw the other.
#
#   2. **Forward-only.** A migration's content is frozen the moment it is
#      committed. Editing an applied migration is the classic "works on my
#      machine, corrupts in production" bug: the developer's fresh database
#      gets the new text, every existing server keeps the old schema, and the
#      checksum test only notices if it happens to be run against a database
#      old enough to care. So this gate compares each file's current blob hash
#      against the blob recorded in the commit that first introduced it
#      (`git log --follow` back to the beginning, then the blob at that
#      commit). Different hash, or a rename, means history was rewritten:
#      hard failure. The fix is always the same — revert the edit and add
#      `NNNN+1_fix_whatever.sql`.
#
# ## Why a gap is a warning and not a failure
#
# Migration numbers are *allocated up front* in `docs/wave1-contracts.md` so
# that agents working in parallel branches never collide on a number. While
# those branches are in flight, `main` legitimately holds e.g. 0001-0006 and
# 0013 with 0007-0012 reserved but unwritten. Failing on that would mean the
# gate is red for as long as any module is under development, which trains
# people to ignore it — the one thing a gate must never do.
#
# So: a *single contiguous* block of missing numbers is reported as a WARNING
# naming the range, because that is exactly what a reserved-and-not-yet-landed
# allocation looks like. Two or more separate gaps are a hard failure: that is
# no longer one reserved block, it is numbering that has actually diverged.
# Duplicates and rewritten migrations are always hard failures — neither has a
# benign explanation.
#
# Set FERRUM_MIGRATIONS_STRICT=1 to turn the gap warning into a failure; the
# integrator should do that once every allocated number has landed.
#
# Run `bash tests/gates/migrations.sh --self-test` to prove the three hard
# failures still fail and the warning still only warns. A gate this permissive
# about gaps has to demonstrate that it is not permissive about the rest.
set -euo pipefail

SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

# Not configurable: the forward-only half asks git about this exact path, so a
# redirected directory would silently check only half of what it claims to.
# The self-test builds whole throwaway repositories instead.
readonly MIGRATIONS_DIR="crates/ferrum-db/migrations"

failures=0
warnings=0

# Colour is decoration. The self-test greps this output and so do people piping
# it into a log; NO_COLOR is the convention for turning it off.
if [ -n "${NO_COLOR:-}" ]; then
  C_RED='' C_GREEN='' C_YELLOW='' C_OFF=''
else
  C_RED=$'\033[31m' C_GREEN=$'\033[32m' C_YELLOW=$'\033[33m' C_OFF=$'\033[0m'
fi

ok()   { printf '%sok%s   %-38s %s\n' "$C_GREEN" "$C_OFF" "$1" "${2:-}"; }
fail() { printf '%sFAIL%s %-38s %s\n' "$C_RED" "$C_OFF" "$1" "${2:-}"; failures=$((failures + 1)); }
warn() { printf '%swarn%s %-38s %s\n' "$C_YELLOW" "$C_OFF" "$1" "${2:-}"; warnings=$((warnings + 1)); }
note() { printf '     %-38s %s\n' "$1" "${2:-}"; }

# --- self-test --------------------------------------------------------------
# Every case is a whole throwaway git repository with this script copied into
# it, because the forward-only half is a question about history and cannot be
# faked with a directory of loose files.

# _fixture <dir> <migration>... — a repo where each migration is its own commit.
_fixture() {
  local dir="$1" file
  shift
  mkdir -p "$dir/crates/ferrum-db/migrations" "$dir/tests/gates"
  cp "$SELF" "$dir/tests/gates/migrations.sh"
  git -c init.defaultBranch=main init -q "$dir"
  git -C "$dir" config user.email gate@example.invalid
  git -C "$dir" config user.name 'migration gate self-test'
  for file in "$@"; do
    printf -- '-- %s\nSELECT 1;\n' "$file" >"$dir/crates/ferrum-db/migrations/$file"
    git -C "$dir" add -A
    git -C "$dir" commit -qm "add $file"
  done
}

selftest_failures=0

# _case <name> <dir> <expected-status> <expected-substring> [ENV=VALUE...]
_case() {
  local name="$1" dir="$2" want_status="$3" want_text="$4"
  shift 4
  local out status=0
  out=$(NO_COLOR=1 env "$@" bash "$dir/tests/gates/migrations.sh" 2>&1) || status=$?

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
  # shellcheck disable=SC2064  # expand $root now: it is gone by trap time otherwise
  trap "rm -rf '$root'" RETURN

  _fixture "$root/gapless" 0001_init.sql 0002_sites.sql 0003_scheduler.sql
  _case a_gapless_sequence_passes \
    "$root/gapless" 0 'numbering is gapless'

  # The wave-2 shape: 0001-0002 landed, 0003-0004 reserved by the contracts
  # file, 0005 landed from a branch that finished first.
  _fixture "$root/reserved" 0001_init.sql 0002_sites.sql 0005_databases.sql
  _case a_single_contiguous_reserved_gap_is_a_warning_not_a_failure \
    "$root/reserved" 0 'reserved range 0003-0004'
  _case strict_mode_turns_the_reserved_gap_into_a_failure \
    "$root/reserved" 1 'FERRUM_MIGRATIONS_STRICT=1' FERRUM_MIGRATIONS_STRICT=1

  # Two holes is not one reserved block; it is numbering that has diverged.
  _fixture "$root/two-gaps" 0001_init.sql 0003_scheduler.sql 0005_databases.sql
  _case two_separate_gaps_are_a_failure \
    "$root/two-gaps" 1 'separate gaps'

  # sqlx records a migration by its version, so the second 0002 would never run
  # on a database that already saw the first.
  _fixture "$root/duplicate" 0002_sites.sql
  printf -- '-- collision\n' >"$root/duplicate/crates/ferrum-db/migrations/0002_other.sql"
  git -C "$root/duplicate" add -A
  git -C "$root/duplicate" commit -qm 'add a colliding number'
  _case a_duplicate_number_is_a_failure \
    "$root/duplicate" 1 'duplicate number: 0002'

  _fixture "$root/edited" 0001_init.sql 0002_sites.sql
  printf -- 'ALTER TABLE sites ADD COLUMN oops TEXT;\n' \
    >>"$root/edited/crates/ferrum-db/migrations/0002_sites.sql"
  _case an_uncommitted_edit_to_an_applied_migration_is_a_failure \
    "$root/edited" 1 'migrations are forward-only'
  # And committing the edit does not launder it: the comparison is against the
  # blob at the migration's *first* commit, not against HEAD.
  git -C "$root/edited" add -A
  git -C "$root/edited" commit -qm 'sneak an edit in'
  _case a_committed_edit_to_an_applied_migration_is_still_a_failure \
    "$root/edited" 1 'migrations are forward-only'

  # A shallow clone cannot answer "what did this look like at first commit" and
  # would answer "unchanged" for everything — a false pass, the worst outcome.
  local shallow="$root/shallow"
  if git clone -q --depth 1 "file://$root/gapless" "$shallow" 2>/dev/null; then
    _case a_shallow_clone_fails_rather_than_passing_blindly \
      "$shallow" 1 'shallow clone'
    _case a_shallow_clone_can_be_waived_explicitly \
      "$shallow" 0 'FERRUM_ALLOW_SHALLOW=1' FERRUM_ALLOW_SHALLOW=1
  else
    printf 'skip a_shallow_clone_fails_rather_than_passing_blindly: clone failed\n'
  fi

  echo
  if [ "$selftest_failures" -eq 0 ]; then
    echo "migration gate self-test passed"
    return 0
  fi
  echo "migration gate self-test failed with $selftest_failures problem(s)" >&2
  return 1
}

if [ "${1:-}" = "--self-test" ]; then
  self_test
  exit $?
fi

if [ ! -d "$MIGRATIONS_DIR" ]; then
  echo "no $MIGRATIONS_DIR — run this from the repository root" >&2
  exit 2
fi

# --- collect ---------------------------------------------------------------
files=()
while IFS= read -r path; do
  files+=("$path")
done < <(find "$MIGRATIONS_DIR" -maxdepth 1 -name '*.sql' | sort)

if [ "${#files[@]}" -eq 0 ]; then
  fail "migrations present" "no .sql files in $MIGRATIONS_DIR"
  exit 1
fi

# --- 1. names and numbering -------------------------------------------------
numbers=()
seen_prefixes=""
for path in "${files[@]}"; do
  base=$(basename "$path")
  if ! printf '%s' "$base" | grep -qE '^[0-9]{4}_[a-z0-9_]+\.sql$'; then
    fail "name: $base" "expected NNNN_lower_snake_case.sql"
    continue
  fi
  prefix=${base:0:4}
  case " $seen_prefixes " in
    *" $prefix "*)
      other=$(basename "$(find "$MIGRATIONS_DIR" -maxdepth 1 -name "${prefix}_*.sql" | sort | head -n 1)")
      fail "duplicate number: $prefix" "$base collides with $other"
      ;;
    *)
      seen_prefixes="$seen_prefixes $prefix"
      # 10# so that 0008 is eight, not an invalid octal literal.
      numbers+=("$((10#$prefix))")
      ;;
  esac
done

if [ "${#numbers[@]}" -eq 0 ]; then
  fail "numbering" "no well-formed migration names to check"
else
  ok "numbering: no duplicate prefixes" "${#numbers[@]} migration(s)"

  highest=0
  lowest=99999
  for n in "${numbers[@]}"; do
    [ "$n" -gt "$highest" ] && highest=$n
    [ "$n" -lt "$lowest" ] && lowest=$n
  done

  if [ "$lowest" -ne 1 ]; then
    fail "numbering starts at 0001" "lowest present is $(printf '%04d' "$lowest")"
  fi

  # Walk 1..highest and group the absentees into contiguous runs.
  runs=()
  run_start=0
  prev_missing=0
  for ((n = 1; n <= highest; n++)); do
    present=0
    for have in "${numbers[@]}"; do
      if [ "$have" -eq "$n" ]; then
        present=1
        break
      fi
    done
    if [ "$present" -eq 0 ]; then
      if [ "$prev_missing" -eq 0 ]; then
        run_start=$n
      fi
      prev_missing=$n
    elif [ "$prev_missing" -ne 0 ]; then
      runs+=("$(printf '%04d-%04d' "$run_start" "$prev_missing")")
      prev_missing=0
    fi
  done
  if [ "$prev_missing" -ne 0 ]; then
    runs+=("$(printf '%04d-%04d' "$run_start" "$prev_missing")")
  fi

  case "${#runs[@]}" in
    0)
      ok "numbering is gapless" "0001-$(printf '%04d' "$highest")"
      ;;
    1)
      if [ "${FERRUM_MIGRATIONS_STRICT:-0}" = "1" ]; then
        fail "reserved range ${runs[0]} unfilled" "FERRUM_MIGRATIONS_STRICT=1"
      else
        warn "reserved range ${runs[0]} unfilled" "allocated in docs/wave1-contracts.md, not yet landed"
      fi
      ;;
    *)
      fail "numbering has ${#runs[@]} separate gaps" "${runs[*]}"
      note "" "one reserved block is expected; several means numbering diverged"
      ;;
  esac
fi

# --- 2. forward-only --------------------------------------------------------
# A shallow clone cannot answer "what did this file look like when it was first
# committed", and would answer "unchanged" for everything — a false pass, which
# is worse than no check. CI checks out with fetch-depth: 0 for this reason.
if [ "$(git rev-parse --is-shallow-repository 2>/dev/null || echo true)" = "true" ]; then
  if [ "${FERRUM_ALLOW_SHALLOW:-0}" = "1" ]; then
    warn "forward-only" "skipped: shallow clone (FERRUM_ALLOW_SHALLOW=1)"
  else
    fail "forward-only" "shallow clone — fetch full history (fetch-depth: 0) to check this"
  fi
else
  for path in "${files[@]}"; do
    base=$(basename "$path")

    if ! git ls-files --error-unmatch -- "$path" >/dev/null 2>&1; then
      note "$base" "not committed yet — nothing to compare against"
      continue
    fi

    first_commit=$(git log --follow --format=%H -- "$path" | tail -n 1)
    if [ -z "$first_commit" ]; then
      note "$base" "no commit history found"
      continue
    fi

    # --follow means the earliest commit may know the file under an older name;
    # take the path as it was spelled there.
    original_path=$(git log --follow --name-only --format='' -- "$path" |
      grep -v '^[[:space:]]*$' | tail -n 1)
    original_path=${original_path:-$path}

    original_blob=$(git rev-parse --verify --quiet "$first_commit:$original_path" || true)
    if [ -z "$original_blob" ]; then
      fail "$base" "cannot read its blob at ${first_commit:0:8} — history was rewritten"
      continue
    fi

    if [ "$original_path" != "$path" ]; then
      # A rename changes the version sqlx recorded, so it is a rewrite of an
      # applied migration by another name.
      fail "$base" "renamed since ${first_commit:0:8} (was $original_path)"
      continue
    fi

    current_blob=$(git hash-object -- "$path")
    if [ "$current_blob" = "$original_blob" ]; then
      ok "$base" "unchanged since ${first_commit:0:8}"
    else
      fail "$base" "modified since ${first_commit:0:8} — migrations are forward-only"
      note "" "git diff $first_commit -- $path"
      note "" "revert it and add a new migration instead"
    fi
  done
fi

echo
if [ "$failures" -gt 0 ]; then
  echo "migration gate failed with $failures violation(s)" >&2
  echo "Numbers are allocated once and content is frozen once committed (spec §4.1)." >&2
  exit 1
fi
if [ "$warnings" -gt 0 ]; then
  echo "migration gate passed with $warnings warning(s)"
else
  echo "migration gate passed"
fi
