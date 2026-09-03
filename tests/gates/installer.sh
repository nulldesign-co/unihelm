#!/usr/bin/env bash
# CI gate: the installer must not die silently, and must not install anything
# it has not verified.
#
# The bug the first half exists for: `preflight_check_conflicts` ended with
# `[ -d "$panel" ] && _warn ...`, which returns 1 when the directory is absent.
# As the last statement in a function that is the last thing a `set -e` script
# calls, that killed the installer on every *clean* server — with no output at
# all. It passed `bash -n`, passed shellcheck, and only showed up on a real box.
#
# The second half exists because install.sh now downloads a binary by default
# (spec §5.5). The only thing between a user and somebody else's code is a
# minisign signature and a SHA-256 checksum, so this gate drives those
# decisions against local fixtures: a placeholder key must refuse, a bad
# signature must refuse, a bad checksum must refuse, and a good release must
# get through. `fetch_to` — the one function in install.sh that touches the
# network — is the only thing replaced; everything the fixtures exercise below
# it is the code that runs on a real server.
#
# shellcheck disable=SC1091
# (installer/install.sh is sourced in a dozen subshells below, each with the
# environment that one assertion needs; there is nothing for shellcheck to
# learn by following it a dozen times.)
set -uo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/../.."

failures=0
ok()   { printf '\033[32mok\033[0m   %s\n' "$1"; }
fail() { printf '\033[31mFAIL\033[0m %s\n' "$1"; failures=$((failures + 1)); }

# --- 1. every check function succeeds in isolation --------------------------
# Each check runs in its own subshell that sources preflight.sh for itself.
# "In isolation" is the point of the test, and it keeps preflight's `set -e` and
# its `readonly` constants out of this script, which counts failures and keeps
# going rather than stopping at the first one.
for check in \
  preflight_check_os \
  preflight_check_arch \
  preflight_check_systemd \
  preflight_check_cgroups \
  preflight_check_memory \
  preflight_check_disk \
  preflight_check_conflicts
do
  # shellcheck source=../../installer/preflight.sh
  if ( . installer/preflight.sh; "$check" ); then
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

if printf '%s' "$output" | grep -q "Unihelm preflight"; then
  ok "preflight reaches its report"
else
  fail "preflight died before reporting: ${output:-<empty>}"
fi

# --- 3. unit hardening must not contradict what each daemon does -------------
# `ProtectHome=read-only` on the agent made `useradd --create-home` fail with a
# bare "cannot create directory" — a hardening setting quietly breaking the
# feature it was meant to protect. The split is the point: the root daemon needs
# /home, the web process must never see it.
agent_unit=installer/systemd/unihelm-agentd.service
web_unit=installer/systemd/unihelm-web.service

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

# Same lesson as RuntimeDirectory=, learned the other way round. systemd
# recursively chowns an exec directory it finds owned by somebody other than the
# unit's user, and /var/log/unihelm is created for `unihelm` by create_layout.
# With both units declaring it, the root agent rewrote the whole tree on every
# start and the web process rewrote it back: the per-site log directories lost
# the tenant group that lets a customer read their own access log, and the WAF
# audit log ended up owned by the internet-facing account. Nothing fails to
# start, which is why only an assertion catches it.
if grep -qE '^LogsDirectory=' "$agent_unit"; then
  fail "$agent_unit claims /var/log/unihelm as root; every start then chowns
  the site log directories and the WAF audit log away from their owners"
else
  ok "the agent leaves /var/log/unihelm to the account that owns it"
fi

if grep -qE '^LogsDirectory=unihelm$' "$web_unit"; then
  ok "the web unit still guarantees /var/log/unihelm exists for its ReadWritePaths"
else
  fail "$web_unit lists /var/log/unihelm in ReadWritePaths= without a \`-\`, so
  something has to create it: keep LogsDirectory=unihelm here"
fi

# --- 4. both scripts parse --------------------------------------------------
for script in installer/preflight.sh installer/install.sh tests/gates/*.sh; do
  if bash -n "$script"; then ok "$script parses"; else fail "$script has a syntax error"; fi
done

# --- 5. install.sh functions also return success in isolation ---------------
# Same lesson as section 1, applied to the file it was learned in. These are the
# ones with no side effects worth guarding; the rest are covered by section 6.
for check in cleanup parse_args; do
  if ( . installer/install.sh; "$check" ) >/dev/null 2>&1; then
    ok "install.sh: $check returns success"
  else
    fail "install.sh: $check returns non-zero — under \`set -e\` this kills the installer silently"
  fi
done

# --- 5b. the release path installs the files that came with the binaries -----
# `write_configuration` and `install_units` read config.toml.example, the two
# units and the tmpfiles fragment from `$here` — the directory the script was
# run from. On the documented `sudo installer/install.sh` that is a clone, and
# re-running the installer is the only upgrade path there is, so the clone can
# be many releases behind while the binaries it just downloaded are current.
# Every one of those files is inside the verified tarball too, so `here` has to
# move there once the release is on disk.
#
# Everything main() does to the machine is replaced; `install_units` reports the
# directory the units would have come from and installs nothing. The answer is
# picked out by its marker rather than by position, because what main prints
# after it is not this assertion's business.
# shellcheck disable=SC2030,SC2031,SC2329
release_here="$(
  . installer/install.sh
  run_preflight() { :; }
  create_service_account() { :; }
  install_binaries() { :; }
  create_layout() { :; }
  write_configuration() { :; }
  install_units() { printf 'units-from %s\n' "$here"; }
  open_panel_port() { :; }
  create_first_admin() { :; }
  print_summary() { :; }
  download_and_verify_release() {
    local root="$1/unpacked/unihelm-0.0.0-gate"
    mkdir -p "$root/systemd" "$root/bin"
    touch "$root/install.sh" "$root/preflight.sh" "$root/config.toml.example" \
      "$root/systemd/unihelm-agentd.service" "$root/systemd/unihelm-web.service"
    STAGED_BIN_DIR="$root/bin"
  }
  main 2>/dev/null || true
)"
release_here="$(printf '%s\n' "$release_here" | sed -n 's/^units-from //p')"
case "$release_here" in
  */unpacked/unihelm-0.0.0-gate)
    ok "the release path takes its units and config template from the verified tarball" ;;
  "")
    fail "the release path never reached install_units" ;;
  *)
    fail "the release path would install units from '$release_here' — files that
  came with whatever checkout ran the installer, not with the binaries it verified" ;;
esac

# --- 6. release identity: architecture and version --------------------------
# `uname -m` says amd64 on some images and arm64 on others. Getting this wrong
# means a 404 on a download URL instead of a sentence a human can act on.
for pair in "x86_64:x86_64" "amd64:x86_64" "aarch64:aarch64" "arm64:aarch64"; do
  machine="${pair%%:*}"
  expected="${pair##*:}"
  got="$( . installer/install.sh; normalize_arch "$machine" 2>/dev/null )"
  if [ "$got" = "$expected" ]; then
    ok "uname -m $machine maps to the $expected release"
  else
    fail "uname -m $machine mapped to '${got:-<nothing>}', expected $expected"
  fi
done

for machine in i686 armv7l riscv64 ppc64le s390x; do
  if ( . installer/install.sh; normalize_arch "$machine" ) >/dev/null 2>&1; then
    fail "$machine was accepted; no release is built for it"
  else
    ok "$machine is refused rather than 404ing on a download"
  fi
done

# The version tag becomes part of a download URL and of a filename on disk, and
# when it is not pinned it arrives from the GitHub API — somebody else's data.
#
# The loop variable is `want_tag`, not `tag`: install.sh's `resolve_version`
# declares a `local tag`, and sourcing it inside the test subshell makes a loop
# variable of that name look — to a reader, and to static analysis — like it
# might be reading the installer's value rather than this loop's.
for want_tag in v0.4.1 0.4.1 v1.2.3-rc.1 0.0.0-gate v10.20.30.40; do
  if ( . installer/install.sh; valid_version "$want_tag" ); then
    ok "$want_tag is accepted as a version tag"
  else
    fail "$want_tag is a legitimate version tag and was rejected"
  fi
done

# `$(id)` and the rest are single-quoted on purpose: the point of the fixture is
# the literal text reaching valid_version, not what it would expand to here.
# shellcheck disable=SC2016
for want_tag in '../../etc/passwd' 'v1.0; rm -rf /' '$(id)' 'v1.0 v2.0' 'latest' '' '-rf'; do
  if ( . installer/install.sh; valid_version "$want_tag" ); then
    fail "'$want_tag' was accepted as a version tag and would end up in a URL and a path"
  else
    ok "'$want_tag' is rejected as a version tag"
  fi
done

# The same rule, applied where it matters: the tag the release API hands back.
if ( . installer/install.sh
     fetch_stdout() { printf '{"tag_name":"../../../etc/passwd"}\n'; }
     resolve_version ) >/dev/null 2>&1
then
  fail "a tag_name of ../../../etc/passwd from the release API was accepted"
else
  ok "a tag_name that is not a version is refused rather than built into a URL"
fi

resolved="$( . installer/install.sh
             fetch_stdout() { printf '{"name":"x","tag_name":"v9.9.9","draft":false}\n'; }
             resolve_version
             printf '%s\n' "${RELEASE_VERSION:-}" )"
if [ "$resolved" = "v9.9.9" ]; then
  ok "the latest release tag is read out of the API response"
else
  fail "resolve_version produced '${resolved:-<nothing>}', expected v9.9.9"
fi

# --- 7. the release path refuses everything it cannot verify -----------------
fixtures="$(mktemp -d "${TMPDIR:-/tmp}/unihelm-installer-gate.XXXXXX")"
cleanup_fixtures() {
  rm -rf "$fixtures"
  return 0
}
trap cleanup_fixtures EXIT

gate_sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$@"
  else
    shasum -a 256 "$@"
  fi
}

# Take the architecture and the artefact name from the installer itself, so the
# fixture and the code under test cannot drift apart.
#
# `gate_tarball` is derived rather than spelled out, and that is not tidiness.
# It used to be written here as unihelm-<v>-<arch>-linux.tar.gz, matching what
# release_tarball_name built and *not* matching what release.yml publishes, so
# the fixture and the installer agreed with each other while both disagreed with
# the actual release. Every download would have 404ed and this gate would have
# stayed green. Asking the installer for the name is what makes that impossible.
gate_arch="$( . installer/install.sh; release_arch )"
gate_version="0.0.0-gate"
gate_tarball="$( . installer/install.sh; RELEASE_VERSION="$gate_version"; release_tarball_name )"
gate_dir="${gate_tarball%.tar.gz}"

if [ -z "$gate_arch" ]; then
  fail "install.sh does not recognise this machine's architecture; skipping the release fixtures"
else

mkdir -p "$fixtures/bin" "$fixtures/payload/$gate_dir"
for binary in unihelm-agentd unihelm-web unihelm; do
  printf '#!/bin/sh\nexit 0\n' >"$fixtures/payload/$gate_dir/$binary"
  chmod 0755 "$fixtures/payload/$gate_dir/$binary"
done

# Two keypairs: the one the installer is told to trust, and one an attacker
# might sign with. If the real minisign is not installed, stand in a double
# that implements the same exit-status contract — the installer's dependency on
# minisign is "did it exit 0 for this public key", and that is what gets tested
# either way. CI installs the real one (.github/workflows/ci.yml).
signer=shim
trusted_key="RW$(printf '%054d' 0 | tr '0' 'A')"
attacker_key="RW$(printf '%054d' 0 | tr '0' 'B')"

if command -v minisign >/dev/null 2>&1 &&
   minisign -G -f -W -p "$fixtures/trusted.pub" -s "$fixtures/trusted.key" </dev/null >/dev/null 2>&1 &&
   minisign -G -f -W -p "$fixtures/attacker.pub" -s "$fixtures/attacker.key" </dev/null >/dev/null 2>&1
then
  signer=minisign
  trusted_key="$(grep -v '^untrusted comment' "$fixtures/trusted.pub" | head -n 1)"
  attacker_key="$(grep -v '^untrusted comment' "$fixtures/attacker.pub" | head -n 1)"
else
  cat >"$fixtures/bin/minisign" <<'SHIM'
#!/usr/bin/env bash
# Test double for minisign (tests/gates/installer.sh). This is deliberately not
# a signature checker: it exists to prove install.sh honours minisign's exit
# status and passes the public key it was configured with through to it, which
# are the two things the installer depends on. A signature file naming the key
# verifies; anything else does not.
set -uo pipefail
key=""; message=""; signature=""
while [ $# -gt 0 ]; do
  case "$1" in
    -P) key="${2:-}"; shift 2 ;;
    -m) message="${2:-}"; shift 2 ;;
    -x) signature="${2:-}"; shift 2 ;;
    *) shift ;;
  esac
done
[ -n "$key" ] || exit 1
[ -f "$message" ] || exit 1
[ -f "$signature" ] || exit 1
head -n 1 "$signature" | grep -qxF "signed-by $key" || exit 1
exit 0
SHIM
  chmod 0755 "$fixtures/bin/minisign"
fi

sign_sums() { # directory  secret-key-file  public-key
  if [ "$signer" = minisign ]; then
    minisign -S -s "$2" -m "$1/SHA256SUMS" -x "$1/SHA256SUMS.minisig" \
      </dev/null >/dev/null 2>&1
  else
    printf 'signed-by %s\n' "$3" >"$1/SHA256SUMS.minisig"
  fi
}

good="$fixtures/release-good"
bad_checksum="$fixtures/release-bad-checksum"
bad_signature="$fixtures/release-bad-signature"
not_listed="$fixtures/release-not-listed"
mkdir -p "$good" "$bad_checksum" "$bad_signature" "$not_listed"

tar -czf "$good/$gate_tarball" -C "$fixtures/payload" "$gate_dir"
( cd "$good" && gate_sha256 "$gate_tarball" >SHA256SUMS )
# A real SHA256SUMS lists every architecture, so it names tarballs this machine
# never downloads. Feeding the whole file to `sha256sum -c` would fail on those;
# the installer has to pick out its own line, and this fixture proves it does.
printf '%s  unihelm-%s-otherarch.tar.gz\n' \
  "0000000000000000000000000000000000000000000000000000000000000000" \
  "$gate_version" >>"$good/SHA256SUMS"
sign_sums "$good" "$fixtures/trusted.key" "$trusted_key"

# A tarball that is not the one the signed checksum file names.
cp "$good/SHA256SUMS" "$good/SHA256SUMS.minisig" "$bad_checksum/"
cp "$good/$gate_tarball" "$bad_checksum/$gate_tarball"
printf 'tampered\n' >>"$bad_checksum/$gate_tarball"

# A perfectly consistent release, signed by somebody else.
cp "$good/SHA256SUMS" "$good/$gate_tarball" "$bad_signature/"
sign_sums "$bad_signature" "$fixtures/attacker.key" "$attacker_key"

# A correctly signed checksum file that says nothing about our tarball.
cp "$good/$gate_tarball" "$not_listed/"
printf '%s  unihelm-%s-otherarch.tar.gz\n' \
  "0000000000000000000000000000000000000000000000000000000000000000" \
  "$gate_version" >"$not_listed/SHA256SUMS"
sign_sums "$not_listed" "$fixtures/trusted.key" "$trusted_key"

# The download stub. `fetch_to` is the single point in install.sh where bytes
# come off the network, so replacing it — and nothing else — runs the real
# verification, unpacking and staging code against a local directory.
run_release_path() { # serve-dir  public-key (empty = force the placeholder)  workdir
  local serve="$1" pubkey="$2" work="$3"
  # Every assertion below needs its own environment and its own copy of the
  # installer's globals, so each run happens in a subshell and nothing it sets
  # is meant to outlive it. That is what SC2030/SC2031 warn about, and here it
  # is the entire design: the next case must not inherit this one's key.
  # SC2329 sees `fetch_to` defined and never called by name — it is called by
  # `download_and_verify_release`, which is the point of overriding it.
  # shellcheck disable=SC2030,SC2031,SC2329
  (
    export PATH="$fixtures/bin:$PATH"
    export UNIHELM_VERSION="$gate_version"
    export UNIHELM_SERVE="$serve"
    if [ -n "$pubkey" ]; then
      export UNIHELM_PUBKEY="$pubkey"
    else
      # Injected, not inherited. install.sh used to default to the placeholder
      # and this branch unset the variable to reach it; the real key is committed
      # now, because the advertised `curl … | sudo bash` fetches install.sh from
      # main and a placeholder there could verify nothing. The refusal still has
      # to work, so the case is forced rather than relying on the default.
      export UNIHELM_PUBKEY="PLACEHOLDER-REPLACE-AT-RELEASE"
    fi

    # shellcheck source=../../installer/install.sh
    . installer/install.sh

    fetch_to() {
      local name="${1##*/}"
      [ -f "$UNIHELM_SERVE/$name" ] || return 22
      cp "$UNIHELM_SERVE/$name" "$2"
    }

    download_and_verify_release "$work"
  ) >"$fixtures/last-run.log" 2>&1
}

staged() { # workdir — did all three binaries get unpacked?
  local work="$1" binary
  for binary in unihelm-agentd unihelm-web unihelm; do
    find "$work" -type f -name "$binary" 2>/dev/null | grep -q . || return 1
  done
  return 0
}

if [ "$signer" = minisign ]; then
  ok "release fixtures signed with the real minisign"
else
  ok "release fixtures signed with the minisign test double (minisign is not installed here)"
fi

# 7a. The placeholder key. A fork that cloned the repo and pointed it at its own
# releases must not download, "verify" and install a tarball against no key at
# all.
work="$fixtures/work-placeholder"
if run_release_path "$good" "" "$work"; then
  fail "the placeholder signing key installed a release anyway"
else
  ok "placeholder signing key refuses to install"
fi
if [ -d "$work" ]; then
  fail "the placeholder check ran after downloading; it must refuse before any request"
else
  ok "the placeholder check refuses before anything is downloaded"
fi
if grep -q "signing key" "$fixtures/last-run.log"; then
  ok "the placeholder refusal says what is wrong"
else
  fail "the placeholder refusal did not explain itself: $(cat "$fixtures/last-run.log")"
fi

# 7b. A release signed by the wrong key. Everything else about it is consistent,
# which is exactly what makes it dangerous.
work="$fixtures/work-bad-signature"
if run_release_path "$bad_signature" "$trusted_key" "$work"; then
  fail "a release signed by an untrusted key was accepted"
else
  ok "a release signed by an untrusted key is refused"
fi
if staged "$work"; then
  fail "the bad-signature release was unpacked before the signature was checked"
else
  ok "nothing is unpacked when the signature does not verify"
fi

# 7c. A tarball that does not match its signed checksum: the signature is real,
# the bytes are not the ones it vouches for.
work="$fixtures/work-bad-checksum"
if run_release_path "$bad_checksum" "$trusted_key" "$work"; then
  fail "a tarball that does not match its signed checksum was accepted"
else
  ok "a tarball that does not match its signed checksum is refused"
fi
if staged "$work"; then
  fail "the mismatched tarball was unpacked anyway"
else
  ok "nothing is unpacked when the checksum does not match"
fi

# 7d. A signed checksum file that does not mention our artefact at all. Silently
# treating "nothing to check" as "checked" is the classic way this goes wrong.
work="$fixtures/work-not-listed"
if run_release_path "$not_listed" "$trusted_key" "$work"; then
  fail "a tarball absent from the signed checksum file was accepted"
else
  ok "an unlisted tarball is refused rather than treated as checked"
fi

# 7e. The good release. If this stops passing, the gate above proves nothing.
work="$fixtures/work-good"
if run_release_path "$good" "$trusted_key" "$work"; then
  ok "a correctly signed release with a matching checksum proceeds"
else
  fail "the good release was refused: $(tail -n 10 "$fixtures/last-run.log")"
fi
if staged "$work"; then
  ok "the good release stages all three binaries"
else
  fail "the good release verified but staged no binaries"
fi

fi  # gate_arch is known

# --- 8. verification cannot be configured away ------------------------------
# `ensure_minisign` is the one function allowed to give up on installing a
# package. It must never give up on *having* minisign, because everything after
# it assumes a signature was really checked.
#
# Emptying PATH inside the subshell is how minisign is made unfindable, and
# blanking UNIHELM_FAMILY is how the package manager is taken away — both are
# deliberate, both are scoped to the subshell, and both are what SC2123/SC2030
# would otherwise flag as an accident.
# shellcheck disable=SC2123,SC2030
if ( . installer/install.sh; PATH=/nonexistent; UNIHELM_FAMILY=""; ensure_minisign ) >/dev/null 2>&1; then
  fail "ensure_minisign returned success without minisign — the release path would install an unverified binary"
else
  ok "ensure_minisign refuses when minisign cannot be obtained"
fi

# The committed key must be a real one. This used to assert the opposite — that
# the placeholder appeared exactly once "so release tooling can rewrite it" — but
# no such tooling was ever written: nothing in .github/workflows/release.yml
# touches UNIHELM_PUBKEY. The placeholder would have shipped, and the advertised
# install command, which fetches install.sh from main, would have refused every
# release for want of a key it could never obtain.
# The pattern must contain a literal `$` — it is matched against the
# installer's source, where that character is the shell syntax being
# asserted about. Expanding it here would defeat the assertion.
# shellcheck disable=SC2016
installer_key="$(sed -n 's/^UNIHELM_PUBKEY="${UNIHELM_PUBKEY:-\(.*\)}"$/\1/p' installer/install.sh)"
case "$installer_key" in
  PLACEHOLDER-* | "")
    fail "installer/install.sh still carries the placeholder signing key, so a
  piped install can verify nothing; commit the public half of the release key" ;;
  RW*)
    if [ "$installer_key" = "$(sed -n 2p minisign.pub)" ]; then
      ok "the installer's signing key is the one in minisign.pub"
    else
      fail "installer/install.sh and minisign.pub disagree about the signing key:
  install.sh has $installer_key, minisign.pub has $(sed -n 2p minisign.pub)" ;
    fi ;;
  *)
    fail "the installer's signing key is not a minisign public key: $installer_key" ;;
esac

# ... and the refusal it replaced must still exist, for a fork that points this
# at its own releases without setting a key.
if grep -qE 'PLACEHOLDER-\* \| ""' installer/install.sh; then
  ok "a placeholder or empty key is still refused outright"
else
  fail "nothing refuses a placeholder or empty signing key any more"
fi

if grep -qE -- '--(skip|no|without)-(verify|verification|signature|checksum|minisign)' installer/install.sh; then
  fail "install.sh offers an option that skips verification"
else
  ok "install.sh offers no option that skips verification"
fi

if grep -nE '(verify_signature|verify_checksum|minisign -V|sha256sum -c|shasum -a 256 -c)[^|]*\|\|[[:space:]]*true' installer/install.sh; then
  fail "a verification step is swallowed by \`|| true\`"
else
  ok "no verification step is swallowed by \`|| true\`"
fi

# The source build has to stay reachable: it is the answer for architectures we
# do not publish, and for anyone who would rather compile than trust a binary.
if grep -q -- '--from-source)' installer/install.sh && grep -q -- '--from)' installer/install.sh; then
  ok "--from-source and --from are still accepted"
else
  fail "the source-build path lost an option"
fi

if ( . installer/install.sh; parse_args; [ -z "${SOURCE_DIR:-}" ] && [ "${FROM_SOURCE:-1}" -eq 0 ] ); then
  ok "with no arguments the installer takes the release path"
else
  fail "the default is no longer the release path"
fi

# --- 9. the install line the README advertises ------------------------------
# `curl … | sudo bash` hands bash a stream, not a file, so BASH_SOURCE is empty
# and there is no directory beside the script holding preflight.sh, the units or
# config.toml.example. The script used to die under `set -u` computing `$here`,
# with the operator seeing "BASH_SOURCE[0]: unbound variable" from the flagship
# install command.
#
# The obvious repair is worse than the bug: writing `${BASH_SOURCE[0]:-}` and
# leaving the dispatch alone makes a piped run compare "" against "bash",
# conclude it was sourced, and exit 0 having installed nothing at all. So both
# halves are asserted here — it must run, and it must run the right thing. None
# of these reach the network.
# shellcheck disable=SC2002
piped_help="$(cat installer/install.sh | bash -s -- --help 2>&1 || true)"
if printf '%s' "$piped_help" | grep -q 'Usage: install.sh'; then
  ok "piped into bash, the installer reaches its own argument parsing"
else
  fail "piped into bash the installer never got started: ${piped_help:-<nothing at all>}"
fi
if printf '%s' "$piped_help" | grep -qE 'unbound variable|null directory'; then
  fail "the piped installer still dies on BASH_SOURCE: $piped_help"
else
  ok "piped into bash, nothing dies on BASH_SOURCE"
fi

# The piped path must reach the network only through the verified download. A
# mutation that replaced `download_and_verify_release` in the bootstrap with
# plain fetches of the same files from raw.githubusercontent.com passed every
# other check in this file: the install still worked, and nothing it ran had a
# signature. So the shape of the bootstrap is asserted directly.
bootstrap_body="$(awk '/^bootstrap_from_release\(\)/,/^}/' installer/install.sh)"
# The pattern must contain a literal `$` — it is matched against the
# installer's source, where that character is the shell syntax being
# asserted about. Expanding it here would defeat the assertion.
# shellcheck disable=SC2016
if printf '%s' "$bootstrap_body" | grep -q 'download_and_verify_release'; then
  ok "the piped bootstrap goes through the verified download"
else
  fail "bootstrap_from_release never calls download_and_verify_release — a piped
  install would run code whose signature was never checked"
fi

# ... and it must fetch nothing else. Every other retrieval in that function is
# a way to obtain an unsigned file.
# Command position only, and outside quotes. The function's own error messages
# quote the advertised `curl ... | sudo bash` line back at the operator inside a
# multi-line `die "..."`, so matching a line at a time reads documentation as
# behaviour. Blank out anything inside a double-quoted string first.
bootstrap_fetches="$(printf '%s' "$bootstrap_body" | awk '
  {
    line = $0; out = ""; i = 1
    while (i <= length(line)) {
      c = substr(line, i, 1)
      if (c == "\\") { i += 2; continue }
      if (c == "\"") { inq = !inq; i++; continue }
      if (!inq) out = out c
      i++
    }
    print out
  }' | grep -nE "^[[:space:]]*(curl|wget|fetch_to|fetch_stdout)([[:space:]]|$)" || true)"
if [ -n "$bootstrap_fetches" ]; then
  fail "bootstrap_from_release fetches something outside the verified tarball:
  $bootstrap_fetches"
else
  ok "the piped bootstrap fetches nothing but the release it verifies"
fi

# The hand-over must run the installer out of the extraction directory, not a
# path that could name anything else on the machine.
# The pattern must contain a literal `$` — it is matched against the
# installer's source, where that character is the shell syntax being
# asserted about. Expanding it here would defeat the assertion.
# shellcheck disable=SC2016
if printf '%s' "$bootstrap_body" | grep -q '"\$root/install.sh"'; then
  ok "the hand-over runs the installer found inside the verified tarball"
else
  fail "the hand-over does not run \$root/install.sh; what does it run?"
fi

# A candidate root must be a real directory. `-d` follows symlinks, so an
# archive member that is a link would point the hand-over at bytes that were
# never in the signed tarball.
# The pattern must contain a literal `$` — it is matched against the
# installer's source, where that character is the shell syntax being
# asserted about. Expanding it here would defeat the assertion.
# shellcheck disable=SC2016
if grep -q 'real_dir "\$candidate"' installer/install.sh &&
   grep -qE '^real_dir\(\).*\{|\[ ! -L' installer/install.sh; then
  ok "extraction roots are rejected when they are symlinks"
else
  fail "locate_binaries/locate_installer_root accept a symlinked candidate:
  a signed tarball carrying a link could redirect what gets run and installed"
fi

# `cat file | bash` rather than `bash < file` in the three checks below. The
# "useless cat" warning is wrong about them: the point is that the script's stdin
# is a PIPE rather than a file, which is exactly what a curl-to-bash install
# looks like and precisely what these assertions measure. Each carries its own
# directive because shellcheck's disable applies to the next command, not to a
# section.

# Silence is the failure mode worth naming: a piped run that neither installs
# nor explains itself looks like success to every caller.
# shellcheck disable=SC2002
piped_bare="$(cat installer/install.sh | bash 2>&1 || true)"
if [ -n "$piped_bare" ]; then
  ok "a piped run with no arguments says something"
else
  fail "a piped run with no arguments printed nothing — it decided it was sourced and gave up"
fi

# --from-source needs a source tree and --from needs a directory; a pipe has
# neither. Both must refuse in words, and must do it before any request.
# shellcheck disable=SC2002
piped_src="$(cat installer/install.sh | bash -s -- --from-source 2>&1 || true)"
if printf '%s' "$piped_src" | grep -q 'git clone'; then
  ok "piped --from-source refuses with the clone command that would work"
else
  fail "piped --from-source did not explain itself: ${piped_src:-<nothing>}"
fi

# The bootstrap hands over to the installer inside the verified tarball. If that
# child ever came back round to the bootstrap it would fork-bomb the machine,
# so the guard that makes that one error line is worth an assertion of its own.
# shellcheck disable=SC2002
piped_loop="$(cat installer/install.sh | UNIHELM_BOOTSTRAPPED=1 bash 2>&1 || true)"
if printf '%s' "$piped_loop" | grep -q 'refusing to loop'; then
  ok "the bootstrap refuses to re-enter itself"
else
  fail "a re-entered bootstrap was not refused: ${piped_loop:-<nothing>}"
fi

# --- 10. the documented uninstall -------------------------------------------
# The uninstall in docs/operator/install.md offered to delete /var/lib/unihelm
# and /var/log/unihelm while leaving the nginx includes, the PHP-FPM pools and
# the logrotate files that name those trees on disk. nginx opens certificates,
# ModSecurity rules and log files at configuration load, so the server kept
# serving and only fell over at the next reload or reboot — by which time the
# panel that could have explained it was gone. The rendered configuration has to
# come out first, which is an ordering claim, so it is asserted as one.
uninstall_doc=docs/operator/install.md
uninstall="$(awk '/^## Uninstalling/,0' "$uninstall_doc")"

if [ -z "$uninstall" ]; then
  fail "$uninstall_doc no longer has an Uninstalling section"
else
  for leftover in \
    '/etc/nginx/conf.d/unihelm.conf' \
    '/etc/nginx/unihelm.d/' \
    '/etc/logrotate.d/unihelm-' \
    'pool.d/unihelm-'
  do
    if printf '%s\n' "$uninstall" | grep -qF "$leftover"; then
      ok "the documented uninstall removes $leftover"
    else
      fail "the documented uninstall leaves $leftover on the server, still naming
  the certificates and log directories it tells the operator to delete"
    fi
  done

  if printf '%s\n' "$uninstall" | grep -qF 'nginx -t'; then
    ok "the documented uninstall checks nginx before walking away"
  else
    fail "the documented uninstall never runs \`nginx -t\`, so a server left
  unable to reload is not discovered until it reboots"
  fi

  footprint="$(printf '%s\n' "$uninstall" | grep -nF '/etc/nginx/unihelm.d/' | head -n 1 | cut -d: -f1)"
  state="$(printf '%s\n' "$uninstall" | grep -nF 'rm -rf /etc/unihelm' | head -n 1 | cut -d: -f1)"
  if [ -n "$footprint" ] && [ -n "$state" ] && [ "$footprint" -lt "$state" ]; then
    ok "the rendered configuration comes out before the state it points at"
  else
    fail "the documented uninstall deletes /var/lib/unihelm and /var/log/unihelm
  before removing the nginx configuration that references them"
  fi
fi

echo
if [ "$failures" -gt 0 ]; then
  echo "installer gate failed with $failures problem(s)" >&2
  exit 1
fi
echo "installer gate passed"
