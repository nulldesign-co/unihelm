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
# Comment lines are ignored: this file, the module docs, and the spec all talk
# about `sh -c` on purpose.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/../.."

readonly EXEC_MODULE="crates/ferrum-distro/src/exec.rs"
failures=0

# Strip `//` and `*` comment lines so prose about the rule does not trip it.
scan() {
  local pattern="$1"
  local description="$2"
  local exclude="${3:-}"

  local hits
  hits=$(
    grep -rnE --include='*.rs' "$pattern" crates/ 2>/dev/null |
      grep -vE ':[[:space:]]*(//|/\*|\*)' |
      { [ -n "$exclude" ] && grep -vE "$exclude" || cat; } || true
  )

  if [ -n "$hits" ]; then
    printf '\033[31mFAIL\033[0m %s\n' "$description"
    printf '%s\n' "$hits" | sed 's/^/       /'
    failures=$((failures + 1))
  else
    printf '\033[32mok\033[0m   %s\n' "$description"
  fi
}

# 1. Never spawn a shell.
scan '(Command|Cmd)::new\(\s*"(/bin/)?(sh|bash|zsh|dash|ksh)"' \
  'no Command::new("sh"/"bash")'

# 2. Never a shell invocation inside a string literal.
scan '"[^"]*\b(sh|bash)[[:space:]]+-c\b' \
  'no "sh -c" / "bash -c" strings'

# 3. Command construction is confined to the exec module.
scan '(std::process::Command|tokio::process::Command|[^:_[:alnum:]]Command)::new\(' \
  "Command::new only in $EXEC_MODULE" \
  "^$EXEC_MODULE:"

# 4. No shell metacharacter piping built into an argument.
scan '\.arg\(\s*format!\("[^"]*[|;&`]' \
  'no shell metacharacters built into arguments'

echo
if [ "$failures" -gt 0 ]; then
  echo "no-shell gate failed with $failures violation(s)" >&2
  echo "Every privileged command goes through ferrum_distro::Cmd with an argv array." >&2
  exit 1
fi
echo "no-shell gate passed"
