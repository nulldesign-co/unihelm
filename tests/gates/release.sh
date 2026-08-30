#!/usr/bin/env bash
# CI gate: the release workflow still does the things a release depends on.
#
# A release pipeline is the one workflow that cannot be tested by running it —
# it needs a tag, a signing key and a repository to publish into, so the first
# time anybody exercises it is the day it matters. What is cheap is asserting
# that the steps a release *cannot be correct without* are still in the file:
# the UI is built and handed to the compiler that embeds it, both architectures
# are built, the 25 MB budget (spec §3) is checked before anything is signed,
# minisign signs the checksums, and the result is a draft rather than a live
# release that self-update would immediately pull (spec §5.5).
#
# This is a grep gate, not a simulation. It catches deletion and drift — a step
# renamed away, an architecture dropped, the budget check quietly removed — which
# is the failure mode that actually happens to release workflows.

# Nearly every string below is a regex matched against a YAML file, so a `$` in
# one is a literal dollar in that file and single quotes are the right quoting.
# shellcheck disable=SC2016

# No `-e`: this gate reports every problem it finds in one run rather than
# stopping at the first, so failures are counted, not fatal. That makes the `cd`
# below the one place a silent wrong answer could come from — checking a
# different directory's workflow would pass or fail for reasons nobody could
# see — so it is the one command that does exit on failure.
set -uo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/../.." || exit 1

readonly WORKFLOW=.github/workflows/release.yml
readonly PUBKEY=minisign.pub

failures=0
ok()   { printf '\033[32mok\033[0m   %s\n' "$1"; }
fail() { printf '\033[31mFAIL\033[0m %s\n' "$1"; failures=$((failures + 1)); }

# The workflow is heavily commented, and a check that a comment can satisfy is
# not a check — deleting `minisign -S -s ...` while leaving the paragraph above
# it explaining what minisign does would sail straight through. So every pattern
# is matched against the workflow with comment lines stripped first.
workflow_code() { grep -Ev '^[[:space:]]*#' "$WORKFLOW"; }

# has <description> <regex>            — the workflow's code must match
has() {
  if workflow_code | grep -Eq -- "$2"; then ok "$1"; else fail "$1 (no match for /$2/ in $WORKFLOW)"; fi
}
# hasnt <description> <regex>          — the workflow's code must not match
hasnt() {
  if workflow_code | grep -Eq -- "$2"; then fail "$1 (matched /$2/ in $WORKFLOW)"; else ok "$1"; fi
}
# prose <description> <regex>          — comments count for this one, on purpose
prose() {
  if grep -Eq -- "$2" "$WORKFLOW"; then ok "$1"; else fail "$1 (no match for /$2/ in $WORKFLOW)"; fi
}

if [ ! -f "$WORKFLOW" ]; then
  echo "no $WORKFLOW — there is no release pipeline to check" >&2
  exit 1
fi

# --- 1. trigger -------------------------------------------------------------
has "triggered on v* tags" '^ *- "v\*"'
# A workflow holding a signing key must never run on somebody else's pull
# request. This is the whole reason releases are a separate workflow from CI.
hasnt "not triggered by pull_request" '^ *pull_request'

# --- 2. the UI, built once and handed to the compiler -----------------------
# unihelm-web embeds crates/unihelm-web/ui-dist with rust-embed at compile time
# (crates/unihelm-web/src/ui.rs). If the bundle is not on disk before cargo runs,
# the binary still builds and still serves — an empty shell.
has "UI job uses node 20"          '^ *node-version: 20$'
has "UI installed with npm ci"     '^ *run: npm ci$'
has "UI built with npm run build"  '^ *run: npm run build$'
has "UI built in ui/"              '^ *working-directory: ui$'
has "UI bundle uploaded once"      '^ *name: ui-dist$'
has "UI downloaded into the embed folder" '^ *path: crates/unihelm-web/ui-dist$'
has "empty ui-dist fails the build" 'test -d crates/unihelm-web/ui-dist/assets'

# --- 3. both architectures --------------------------------------------------
# Matched as matrix keys, not as bare triples: the cross-compilation fallback
# comment mentions both triples, and must not be able to stand in for an entry
# that was actually deleted.
has "x86_64 built"   '^ *target: x86_64-unknown-linux-gnu$'
has "aarch64 built"  '^ *target: aarch64-unknown-linux-gnu$'
has "x86_64 runner"  '^ *runner: ubuntu-24\.04$'
has "aarch64 runner" '^ *runner: ubuntu-24\.04-arm$'
# If the arm runner ever has to go, the fallback must stay written down where
# the person making that change will read it. This one is deliberately allowed
# to live in a comment — it is instructions for a human, not a step.
prose "cross-compilation fallback documented" 'gcc-aarch64-linux-gnu'

# --- 4. the size budget, before anything is signed --------------------------
# Reused from tests/gates/budgets.sh so the 25 MB number lives in one place.
has "binary size budget checked" 'run: bash tests/gates/budgets\.sh binaries$'
has "bundle size budget checked" 'run: bash tests/gates/budgets\.sh bundle$'
if grep -Eq '25 \* 1024 \* 1024|26214400' "$WORKFLOW"; then
  fail "the 25 MB budget is re-derived in the workflow — call tests/gates/budgets.sh instead"
else
  ok "the budget is not duplicated in the workflow"
fi

# --- 5. packaging -----------------------------------------------------------
has "per-arch tarball named unihelm-<version>-<arch>.tar.gz" 'unihelm-\$\{VERSION\}-\$\{ARCH\}\.tar\.gz"$'
# `tar -czf` invokes gzip without -n, and gzip stamps the current time into its
# own header even when it is reading a pipe. Everything else about the tarball
# is pinned (--sort, --owner, --mtime), so dropping -n is the one change that
# silently turns a reproducible checksum back into a per-run one — and nothing
# fails, the checksums are simply never the same twice.
has "tarball gzip is timestamp-free"  'gzip -n'
has "tarball file order is pinned"    'tar --sort=name'
has "tarball mtimes are pinned"       '\-\-mtime='
has "all three binaries packaged: agentd" '^ *install -m 0755 "target/.*/release/unihelm-agentd"'
has "all three binaries packaged: web"    '^ *install -m 0755 "target/.*/release/unihelm-web"'
has "all three binaries packaged: cli"    '^ *install -m 0755 "target/.*/release/unihelm"'
has "installer packaged"       '^ *install -m 0755 installer/install\.sh'
has "preflight packaged"       '^ *install -m 0755 installer/preflight\.sh'
has "systemd units packaged"   '^ *install -m 0644 installer/systemd/unihelm-web\.service'
has "config example packaged"  '^ *install -m 0644 installer/config\.toml\.example'

# --- 6. signing -------------------------------------------------------------
has "signs with minisign -S"          '^ *minisign -S -s '
has "key comes from the repo secret"  'secrets\.MINISIGN_SECRET_KEY'
has "SHA256SUMS produced"             '^ *sha256sum unihelm-\*\.tar\.gz'
has "SHA256SUMS signed"               '\-m SHA256SUMS$'
has "each tarball signed on its own"  '\-m "\$tarball"'
# Against the *committed* public key: a rotation done halfway — new secret in
# CI, old public key in the repository — has to fail here, not in the field.
has "signatures verified before publishing" 'minisign -Vm .* -p \.\./minisign\.pub'
has "signing key removed from the runner"   'rm -f "\$RUNNER_TEMP/minisign\.key"'

# The secret is materialised as a file under $RUNNER_TEMP for exactly one step.
# Writing it anywhere in the checked-out tree would put it one `upload-artifact`
# away from being published with the release it signed.
if workflow_code | grep -Eq 'minisign\.key' &&
  ! workflow_code | grep -Eq '\$RUNNER_TEMP/minisign\.key'; then
  fail "the signing key file is not under \$RUNNER_TEMP — keep it out of the workspace"
else
  ok "the signing key never touches the checked-out tree"
fi

# Printing the secret is the other way it escapes: job logs are readable by
# everyone who can read the repository. A redirect into the key file is the one
# legitimate expansion, so lines with a `>` are not the failure being looked for.
if workflow_code | awk '
    /(echo|printf)[^>]*\$\{?MINISIGN_SECRET_KEY/ && !/>/ { bad = 1 }
    /cat[^|]*minisign\.key/                              { bad = 1 }
    END { exit !bad }
  '; then
  fail "the signing key is echoed or cat'd — that puts it in the job log"
else
  ok "the signing key is never printed"
fi

# Belt and braces for the human half of the procedure: `minisign -G` in a clone
# writes minisign.key next to minisign.pub, and `git add -A` would take it.
if grep -qxF 'minisign.key' .gitignore; then
  ok "minisign.key cannot be committed by accident"
else
  fail ".gitignore does not cover minisign.key — a generated signing key is one \`git add -A\` from the public repo"
fi

# --- 7. the public key ------------------------------------------------------
if [ ! -f "$PUBKEY" ]; then
  fail "$PUBKEY is missing — operators have nothing to verify against"
elif grep -q PLACEHOLDER "$PUBKEY"; then
  # Expected state until the maintainer generates the real key. The point of the
  # gate is that the workflow refuses to ship this file.
  ok "$PUBKEY is the documented placeholder"
  has "the workflow refuses to release with the placeholder key" '^ *if grep -q PLACEHOLDER minisign\.pub; then'
  # And refuses *before* half an hour of two-architecture building is spent on a
  # release that cannot be signed. The obvious place to write this check is next
  # to the signing it protects, which is why it is worth pinning it to the job
  # that `build` waits on: the `version` job, whose whole purpose is failing fast.
  job() { awk -v want="  $1:" '$0 == want {f=1;next} /^  [a-z_-]+:$/{f=0} f' "$WORKFLOW"; }
  if job version | grep -q 'grep -q PLACEHOLDER minisign\.pub' &&
    job build | grep -Eq '^ *needs: .*version'; then
    ok "the placeholder check runs before anything is compiled"
  else
    fail "the placeholder check is not in the fast \`version\` job that \`build\` waits on — a release that cannot be signed would burn a full two-arch build first"
  fi
else
  ok "$PUBKEY holds a real key"
  if [ "$(wc -l <"$PUBKEY")" -eq 2 ]; then
    ok "$PUBKEY has minisign's two-line shape"
  else
    fail "$PUBKEY is not two lines — minisign will not parse it"
  fi
fi

# --- 8. the release itself --------------------------------------------------
has "creates the release with gh, not a third-party action" '^ *gh release create '
# Draft, not published: self-update follows published releases (spec §5.5), so
# publishing has to stay a human action. An accidental tag must not be able to
# push a binary to every server running Unihelm.
has "the release is a draft"                    '^ *--draft'
has "the tag is verified before assets attach"  '^ *--verify-tag'
# A re-run deletes and recreates the release so assets do not pile up in two
# generations. That is safe for a draft and destructive for a published release:
# the URLs are already in people's scripts and self-update is already following
# it (spec §5.5). The guard is what keeps "re-run the release" from meaning
# "unpublish the release".
has "a published release is never clobbered by a re-run" '\-\-json isDraft'
# Default-read at the top of the file, write granted inside one job.
has "the workflow is read-only by default"      '^permissions:'
has "write permission scoped to a job"          '^ *contents: write'

# --- 9. the file is valid YAML ---------------------------------------------
# Every check above is a grep, and a grep is perfectly happy with a file GitHub
# will reject at parse time. Two parsers are tried because neither is everywhere:
# pyyaml is not installed on stock macOS, ruby is not installed in a slim
# container, and both are present on a GitHub runner. Skipped rather than faked
# if neither is around — a check that quietly passes is worse than an absent one.
yaml_parses() {
  if command -v python3 >/dev/null && python3 -c 'import yaml' 2>/dev/null; then
    python3 -c 'import sys,yaml; yaml.safe_load(open(sys.argv[1]))' "$1" 2>/dev/null
  elif command -v ruby >/dev/null; then
    ruby -ryaml -e 'YAML.safe_load(File.read(ARGV[0]), aliases: true)' "$1" 2>/dev/null
  else
    return 2
  fi
}

yaml_parses "$WORKFLOW"
case $? in
  0) ok "$WORKFLOW parses as YAML" ;;
  2) printf '     %s\n' "YAML parse check skipped (no pyyaml and no ruby here; CI has both)" ;;
  *) fail "$WORKFLOW is not valid YAML" ;;
esac

echo
if [ "$failures" -gt 0 ]; then
  echo "release gate failed with $failures problem(s)" >&2
  echo "A release nobody can verify is worse than no release (spec §5.5)." >&2
  exit 1
fi
echo "release gate passed"
