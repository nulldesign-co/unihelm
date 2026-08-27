#!/usr/bin/env bash
# CI gate: no shell string execution, anywhere (spec §12 rule 2).
#
# This is the gate that kills shell injection as a category. It enforces two
# invariants:
#
#   1. No process is ever started through a shell. `sh -c "$user_input"` is the
#      bug class this whole design exists to avoid.
#   2. `std::process::Command` (and tokio's) may only be constructed inside
#      `ferrum-distro`'s exec module. Everything else goes through `Cmd`, which
#      takes argv arrays and resolves programs against a fixed list of trusted
#      directories.
#
# The rules below come in two flavours. `shell-program`, `shell-string`,
# `shell-argv` and `shell-owned` are *facts*: a match is a shell invocation,
# full stop. `dash-c`, `command-new` and `metachars` are *heuristics*: they
# catch the shapes those facts usually arrive in, and they can be wrong.
# Heuristics need somewhere for a verified false positive to live, or the first
# one turns the whole gate off — hence tests/gates/no-shell-allowlist.txt,
# whose format is documented in its own header. Exemptions are per (rule,
# file), and an exemption that suppresses nothing is reported as stale.
#
# Comment lines are ignored: this file, the module docs, and the spec all talk
# about `sh -c` on purpose.
#
# Run `bash tests/gates/no-shell.sh --self-test` to check the rules still fire
# and the allowlist still suppresses — a gate nobody ever saw fail is a gate
# that might be matching nothing at all.
set -euo pipefail

SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

SCAN_ROOT="${FERRUM_NO_SHELL_ROOT:-crates/}"
ALLOWLIST="${FERRUM_NO_SHELL_ALLOWLIST:-tests/gates/no-shell-allowlist.txt}"

failures=0
suppressed_log=$(mktemp)
selftest_dir=""
trap 'rm -f "$suppressed_log"; [ -n "$selftest_dir" ] && rm -rf "$selftest_dir"' EXIT

# Colour is decoration; the self-test greps this output, and so do people
# piping it into a log. NO_COLOR is the convention for turning it off.
if [ -n "${NO_COLOR:-}" ]; then
  C_RED='' C_GREEN='' C_YELLOW='' C_OFF=''
else
  C_RED=$'\033[31m' C_GREEN=$'\033[32m' C_YELLOW=$'\033[33m' C_OFF=$'\033[0m'
fi

# Every path allowlisted for one rule.
allowed_for() {
  local rule="$1"
  [ -f "$ALLOWLIST" ] || return 0
  awk -v rule="$rule" '
    /^[[:space:]]*#/ { next }
    NF >= 2 && $1 == rule { print $2 }
  ' "$ALLOWLIST"
}

# Strip `//` and `*` comment lines so prose about the rule does not trip it.
scan() {
  local rule="$1"
  local pattern="$2"
  local description="$3"

  local hits before after path
  hits=$(
    grep -rnE --include='*.rs' "$pattern" "$SCAN_ROOT" 2>/dev/null |
      grep -vE ':[[:space:]]*(//|/\*|\*)' || true
  )

  while IFS= read -r path; do
    [ -n "$path" ] || continue
    before=$(printf '%s' "$hits" | grep -c . || true)
    # Exact prefix, not a substring: `src/a.rs` must not exempt `src/aa.rs`.
    hits=$(printf '%s\n' "$hits" | awk -v p="$path:" 'index($0, p) != 1' || true)
    after=$(printf '%s' "$hits" | grep -c . || true)
    if [ "$before" -gt "$after" ]; then
      printf '%s\t%s\n' "$rule" "$path" >>"$suppressed_log"
    fi
  done < <(allowed_for "$rule")

  if [ -n "$hits" ]; then
    printf '%sFAIL%s %-12s %s\n' "$C_RED" "$C_OFF" "$rule" "$description"
    printf '%s\n' "$hits" | sed 's/^/       /'
    failures=$((failures + 1))
  else
    printf '%sok%s   %-12s %s\n' "$C_GREEN" "$C_OFF" "$rule" "$description"
  fi
}

run_rules() {
  # 1. Never spawn a shell by name. `/usr/bin/sh` and `/bin/bash` are the same
  #    program with a longer spelling, so the path prefix is optional.
  scan shell-program \
    '(Command|Cmd)::new\(\s*"(/(usr/)?bin/)?(sh|bash|zsh|dash|ksh|fish|csh|tcsh)"' \
    'no Command::new("sh") / Cmd::new("bash")'

  # 2. Never a shell invocation inside a string literal — a config file, a
  #    systemd ExecStart, a cron line the panel writes.
  scan shell-string \
    '"[^"]*\b(sh|bash|zsh|dash|ksh)[[:space:]]+-c\b' \
    'no "sh -c" / "bash -c" strings'

  # 3. A shell binary and its `-c` in the same argv array. This is the shape
  #    that slips past rule 1: the program is not `Command::new("bash")` but a
  #    plain `"bash"` element in a vec that some runner later executes.
  scan shell-argv \
    '"(/(usr/)?bin/)?(sh|bash|zsh|dash|ksh)"[^)]*"-c"' \
    'no shell binary + "-c" in one argv'

  # 4. A shell binary turned into an *owned* string. Rule 3 is line-based and
  #    stops at the first `)`, so `vec!["bash".into(), "-c".into(), payload]`
  #    walks straight through it — and that is precisely how argv vectors are
  #    written in this codebase (see `quota.rs`). The only reason to allocate
  #    the name of a shell is to put it in an argv, so this is close to a fact
  #    rather than a heuristic. A shell *path* used as a value — the login
  #    shell `"/bin/bash"` that `provision.rs` hands to `useradd --shell` — is
  #    a `&str` and does not match.
  scan shell-owned \
    '"(/(usr/)?bin/)?(sh|bash|zsh|dash|ksh|fish|csh|tcsh)"[[:space:]]*\.[[:space:]]*(into|to_string|to_owned|to_os_string)\(\)' \
    'no "bash".into() — argv elements naming a shell'

  # 5. `-c` in builder position at all, in either the borrowed or the owned
  #    spelling. Heuristic, and deliberately broad: the flag means "execute
  #    this string" for every shell, and the handful of non-shell programs that
  #    spell something else `-c` (xfs_quota takes a sub-command string it
  #    splits itself, no shell involved) are cheap to allowlist and worth a
  #    human reading once.
  scan dash-c \
    '(\.args?\(\s*(&?\[|vec!\[)?\s*"-c"|"-c"[[:space:]]*\.[[:space:]]*(into|to_string|to_owned|to_os_string)\(\))' \
    'no .arg("-c") / .args(["-c", …]) / "-c".into()'

  # 6. Command construction is confined to the exec module.
  scan command-new \
    '(std::process::Command|tokio::process::Command|[^:_[:alnum:]]Command)::new\(' \
    'Command::new only in the exec module'

  # 7. No shell metacharacter piping built into an argument. Nothing executes
  #    it today, but an argument shaped like a pipeline is written by somebody
  #    who expects a shell to be there.
  scan metachars \
    '\.arg\(\s*format!\("[^"]*[|;&`]' \
    'no shell metacharacters built into arguments'
}

report_stale_allowlist() {
  [ -f "$ALLOWLIST" ] || return 0
  local rule path
  while read -r rule path _; do
    case "$rule" in '' | '#'*) continue ;; esac
    [ -n "$path" ] || continue
    if ! grep -qF "$(printf '%s\t%s' "$rule" "$path")" "$suppressed_log" 2>/dev/null; then
      printf '%sstale%s %-12s %s no longer matches — delete the allowlist line\n' \
        "$C_YELLOW" "$C_OFF" "$rule" "$path"
    fi
  done <"$ALLOWLIST"
}

# --- self-test --------------------------------------------------------------
# Builds a throwaway tree containing one violation per rule, runs the gate over
# it, and asserts the rules fire; then allowlists them and asserts they stop.
self_test() {
  local dir status out
  selftest_dir=$(mktemp -d)
  dir="$selftest_dir"

  mkdir -p "$dir/crates/evil/src"
  cat >"$dir/crates/evil/src/lib.rs" <<'RUST'
pub fn shell_program() { let _ = Command::new("/bin/bash"); }
pub fn shell_string() { let _ = "sh -c echo hi"; }
pub fn shell_argv() { let _ = run(vec!["bash", "-c", payload]); }
pub fn shell_owned() { let _ = run(vec!["bash".into(), payload]); }
pub fn dash_c() { cmd.args(["-c", payload]); }
pub fn metachars() { cmd.arg(format!("{a} | tee {b}")); }
RUST
  # The shape that walks through `shell-argv`: `.into()` puts a `)` between the
  # program and its `-c`, and rustfmt then splits the vec across lines, so the
  # single-line, no-parenthesis pattern never sees them together. `shell-owned`
  # and the owned half of `dash-c` are what actually catch this.
  cat >"$dir/crates/evil/src/owned.rs" <<'RUST'
pub fn owned_argv() -> Vec<String> {
    vec![
        "bash".into(),
        "-c".into(),
        payload.to_string(),
    ]
}
RUST
  # A comment that talks about the rules must not trip them.
  cat >"$dir/crates/evil/src/prose.rs" <<'RUST'
// We never call Command::new("sh") or pass .arg("-c") anywhere.
/* `bash -c` is forbidden repo-wide. */
RUST
  # A shell *path* used as a value, not as a program: the login shell handed to
  # `useradd --shell`. It must not be reported.
  cat >"$dir/crates/evil/src/login_shell.rs" <<'RUST'
pub fn login_shell(can_ssh: bool) -> &'static str {
    if can_ssh { "/bin/bash" } else { "/usr/sbin/nologin" }
}
RUST

  local rules=(shell-program shell-string shell-argv shell-owned dash-c command-new metachars)
  local rule ok_all=0

  out=$(NO_COLOR=1 FERRUM_NO_SHELL_ROOT="$dir/crates/" FERRUM_NO_SHELL_ALLOWLIST=/dev/null \
    bash "$SELF" 2>&1) && status=0 || status=$?

  if [ "$status" -eq 0 ]; then
    echo "FAIL a_tree_full_of_violations_is_rejected: the gate passed"
    ok_all=1
  else
    echo "ok   a_tree_full_of_violations_is_rejected"
  fi

  for rule in "${rules[@]}"; do
    case "$rule" in
      command-new) continue ;; # covered by shell-program's Command::new hit
    esac
    if printf '%s' "$out" | grep -q "FAIL $rule"; then
      echo "ok   ${rule//-/_}_fires_on_its_own_pattern"
    else
      echo "FAIL ${rule//-/_}_fires_on_its_own_pattern: rule did not match"
      ok_all=1
    fi
  done

  if printf '%s' "$out" | grep -q 'prose.rs'; then
    echo "FAIL prose_about_the_rules_is_not_a_violation: comment lines matched"
    ok_all=1
  else
    echo "ok   prose_about_the_rules_is_not_a_violation"
  fi

  if printf '%s' "$out" | grep -q 'login_shell.rs'; then
    echo "FAIL a_login_shell_path_is_not_a_shell_invocation: login_shell.rs was reported"
    ok_all=1
  else
    echo "ok   a_login_shell_path_is_not_a_shell_invocation"
  fi

  # The regression this rule set exists for: a multi-line argv vec of owned
  # strings. Scanned on its own so the assertion is about *these* rules and not
  # about a hit that some other file happened to contribute.
  local owned_dir="$dir/owned-only"
  mkdir -p "$owned_dir/crates/evil/src"
  cp "$dir/crates/evil/src/owned.rs" "$owned_dir/crates/evil/src/owned.rs"
  local owned_out owned_status=0
  owned_out=$(NO_COLOR=1 FERRUM_NO_SHELL_ROOT="$owned_dir/crates/" \
    FERRUM_NO_SHELL_ALLOWLIST=/dev/null bash "$SELF" 2>&1) || owned_status=$?
  if [ "$owned_status" -ne 0 ] &&
    printf '%s' "$owned_out" | grep -q 'FAIL shell-owned' &&
    printf '%s' "$owned_out" | grep -q 'FAIL dash-c'; then
    echo "ok   a_multiline_argv_vec_of_owned_strings_is_caught"
  else
    echo "FAIL a_multiline_argv_vec_of_owned_strings_is_caught"
    printf '%s\n' "$owned_out" | sed 's/^/       /'
    ok_all=1
  fi

  # Now allowlist the offending files for every rule and expect a clean run.
  local allow="$dir/allow.txt" fixture
  : >"$allow"
  for rule in "${rules[@]}"; do
    for fixture in lib.rs owned.rs; do
      printf '%s %s a fixture\n' "$rule" "$dir/crates/evil/src/$fixture" >>"$allow"
    done
  done

  out=$(NO_COLOR=1 FERRUM_NO_SHELL_ROOT="$dir/crates/" FERRUM_NO_SHELL_ALLOWLIST="$allow" \
    bash "$SELF" 2>&1) && status=0 || status=$?
  if [ "$status" -eq 0 ]; then
    echo "ok   an_allowlisted_file_is_not_reported"
  else
    echo "FAIL an_allowlisted_file_is_not_reported: still failing"
    printf '%s\n' "$out" | sed 's/^/       /'
    ok_all=1
  fi

  # An entry for a file with nothing to suppress must be called out.
  printf 'dash-c %s stale on purpose\n' "$dir/crates/evil/src/nonexistent.rs" >>"$allow"
  out=$(NO_COLOR=1 FERRUM_NO_SHELL_ROOT="$dir/crates/" FERRUM_NO_SHELL_ALLOWLIST="$allow" \
    bash "$SELF" 2>&1) || true
  if printf '%s' "$out" | grep -q 'stale .*nonexistent.rs'; then
    echo "ok   an_allowlist_entry_that_suppresses_nothing_is_reported_stale"
  else
    echo "FAIL an_allowlist_entry_that_suppresses_nothing_is_reported_stale"
    ok_all=1
  fi

  echo
  if [ "$ok_all" -eq 0 ]; then
    echo "no-shell self-test passed"
  else
    echo "no-shell self-test failed" >&2
  fi
  return "$ok_all"
}

if [ "${1:-}" = "--self-test" ]; then
  self_test
  exit $?
fi

run_rules
report_stale_allowlist

echo
if [ "$failures" -gt 0 ]; then
  echo "no-shell gate failed with $failures violation(s)" >&2
  echo "Every privileged command goes through ferrum_distro::Cmd with an argv array." >&2
  echo "A verified false positive goes in $ALLOWLIST, with a reason." >&2
  exit 1
fi
echo "no-shell gate passed"
