#!/usr/bin/env bash
# CI gate: every registered operation is documented (spec §16.10).
#
# The working agreement says "new capability = new typed op + REST endpoint +
# CLI verb + audit + task + tests + docs, in that spirit" (spec §16.5) and
# "document as you go" (§16.10). Those are the two rules that rot first,
# because nothing breaks when they are ignored. This gate is what breaks.
#
# It reads `crates/unihelm-ops/src/registry.rs`, resolves each registered type
# to the `const NAME` on its `impl TypedOperation`, and requires that name to
# appear somewhere under `docs/`. Registration is the source of truth on
# purpose: an operation that is not registered does not exist (the registry is
# the whitelist), and one that is registered is reachable over the API whether
# or not anyone wrote it down.
#
# **The failing list is the point.** When this gate fails it prints every
# undocumented operation — that list is the documentation checklist, not an
# error to be silenced. The fix is always to write the documentation, never to
# widen the search or delete the check.
#
# Two files under `docs/` do not count as documentation and are excluded:
#
#   - `docs/wave1-contracts.md` is an *allocation table*. It lists op names to
#     stop parallel branches from colliding on one; a name appearing there says
#     somebody claimed it, not that anybody explained it.
#   - `docs/api/errors.md` is generated from the error enum.
#
# Matching is on whole tokens, so `db.list` in the docs does not satisfy
# `db.listener`, and a name inside a longer dotted name does not count.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/../.."

readonly REGISTRY="crates/unihelm-ops/src/registry.rs"
readonly OPS_SRC="crates/unihelm-ops/src"
readonly DOCS_DIR="docs"

# Not documentation; see the header.
EXCLUDED_DOCS=(
  "docs/wave1-contracts.md"
  "docs/api/errors.md"
)

if [ -n "${NO_COLOR:-}" ]; then
  C_RED='' C_GREEN='' C_OFF=''
else
  C_RED=$'\033[31m' C_GREEN=$'\033[32m' C_OFF=$'\033[0m'
fi

for required in "$REGISTRY" "$DOCS_DIR"; do
  if [ ! -e "$required" ]; then
    echo "no $required — run this from the repository root" >&2
    exit 2
  fi
done

# --- which types are registered --------------------------------------------
# `registry.register(crate::fsops::ops::List);` and
# `registry.register(crate::adminer::Enable::default());` both mean "the type
# at that module path is live".
registered_types() {
  grep -oE 'registry\.register\(crate::[a-z0-9_:]+::[A-Za-z][A-Za-z0-9]*' "$REGISTRY" |
    sed 's/^registry\.register(crate:://'
}

# --- module path -> file ----------------------------------------------------
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

# --- the NAME on one type's TypedOperation impl -----------------------------
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

# --- is a name written down anywhere in docs/ -------------------------------
documented() {
  local name="$1" escaped exclusions=()
  local doc
  for doc in "${EXCLUDED_DOCS[@]}"; do
    exclusions+=(--exclude="$(basename "$doc")")
  done
  # Dots are literal, and the name must not be a fragment of a longer one.
  escaped=${name//./\\.}
  grep -rqE "(^|[^A-Za-z0-9_.])${escaped}([^A-Za-z0-9_.]|$)" \
    "${exclusions[@]}" "$DOCS_DIR" 2>/dev/null
}

names=()
unresolved=()
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
  names+=("$name")
done < <(registered_types)

if [ "${#names[@]}" -eq 0 ]; then
  echo "could not extract a single operation name from $REGISTRY" >&2
  echo "the gate cannot report honestly on a registry it cannot parse" >&2
  exit 2
fi

# A registered type whose name could not be resolved is a parsing failure, and
# a gate that quietly skips what it cannot parse is worse than no gate.
if [ "${#unresolved[@]}" -gt 0 ]; then
  printf '%sFAIL%s could not resolve %d registered type(s):\n' \
    "$C_RED" "$C_OFF" "${#unresolved[@]}"
  printf '       %s\n' "${unresolved[@]}"
  exit 1
fi

missing=()
for name in "${names[@]}"; do
  documented "$name" || missing+=("$name")
done

printf '%d registered operation(s), %d documented, %d missing\n' \
  "${#names[@]}" "$(( ${#names[@]} - ${#missing[@]} ))" "${#missing[@]}"
echo

if [ "${#missing[@]}" -eq 0 ]; then
  printf '%sok%s   every registered operation appears in %s/\n' "$C_GREEN" "$C_OFF" "$DOCS_DIR"
  exit 0
fi

printf '%sFAIL%s the following operations are registered but undocumented:\n' "$C_RED" "$C_OFF"
printf '       %s\n' "${missing[@]}"
cat >&2 <<EOF

This list is the documentation checklist. Each name needs an entry in
docs/operations.md giving its permission, its input fields and what it does —
written from the operation's own source, not guessed from its name.
Spec §16.5 and §16.10: docs ship in the same change as the code.
EOF
exit 1
