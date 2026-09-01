#!/usr/bin/env bash
# Unihelm installer (spec §14 Phase 0; release verification per spec §5.5).
#
# Two ways in. The default is a signed release binary — the thing almost
# everybody wants, and the thing that does not need a Rust toolchain, 2 GB of
# build artefacts and twenty minutes on a 1 GB VPS:
#
#     sudo ./install.sh                          # the latest release
#     sudo UNIHELM_VERSION=v0.4.1 ./install.sh    # a pinned one
#
# and a source build stays available for developers, for architectures we do
# not publish binaries for, and for anyone who would rather compile than trust
# a binary:
#
#     sudo ./install.sh --from-source            # cargo build --release, then install
#     sudo ./install.sh --from ./target/release  # install an already-built tree
#
# ---------------------------------------------------------------------------
# The default (release) path, in order:
#
#   1. preflight (spec §7.1) — refuse early rather than break a working server.
#   2. Normalise `uname -m` into a release architecture. x86_64 and aarch64 are
#      the only two we build; anything else stops here with a sentence that
#      says so and points at --from-source, rather than 404ing on a download.
#   3. Refuse outright while UNIHELM_PUBKEY is still the release-time
#      placeholder. This is the fork trap: a repository someone cloned and
#      pointed at their own releases would otherwise download a tarball,
#      "verify" it against nothing in particular and install it. Refusing costs
#      a fork one line of configuration. Not refusing costs whoever runs it
#      everything on the box.
#   4. Install minisign from the distribution's own repositories — EPEL on the
#      RHEL family, using the same epel-release + `crb` sequence the repo layer
#      in crates/unihelm-distro/src/pkg.rs applies before any third-party repo.
#      No minisign, no install: there is no code path below that continues
#      without a verified signature, and no flag that creates one.
#   5. Resolve the version — $UNIHELM_VERSION if set, otherwise the GitHub
#      release API — and validate it *before* it becomes part of a URL or a
#      filename. The API response is somebody else's data (spec §12).
#   6. Download <tarball>, SHA256SUMS and SHA256SUMS.minisig.
#   7. Verify the minisign signature on SHA256SUMS against the embedded public
#      key, and only then `sha256sum -c` the tarball against the file we have
#      just proved is ours. That order is the whole point: a checksum file
#      nobody signed is a checksum file an attacker wrote.
#   8. Unpack into a scratch directory and take exactly the three binaries we
#      expect out of it — never whatever layout the archive happens to have.
#
# From there both paths run the same functions: create the unprivileged
# `unihelm` account, install the binaries and the directory layout from spec
# §4.3, write /etc/unihelm/config.toml and generate the master key, install and
# start the two systemd units, and create the first administrator whose
# password is printed exactly once.
#
# It installs no stack components. Nginx, PHP, MariaDB and the rest arrive on
# demand from the Stack Manager, which is what keeps a base install small
# enough for a 1 GB VPS (spec §1.1).
#
# ---------------------------------------------------------------------------
# Everything below the constants is a function, and `main` runs only when this
# file is executed rather than sourced. tests/gates/installer.sh sources it,
# replaces `fetch_to` with a local fixture and drives the verification
# decisions directly — the seam is one function wide, so the code the gate
# exercises is the code that runs on a real server.
set -euo pipefail

# --- release identity ------------------------------------------------------
# The repository releases come from. A fork changes this and UNIHELM_PUBKEY and
# needs to change nothing else.
UNIHELM_REPO="${UNIHELM_REPO:-farzam-seyedhashem/unihelm}"

# The minisign public key every release is signed with (spec §5.5 — the same
# ed25519/minisign format self-update verifies). The literal below is rewritten
# when a release is cut; packaging/README.md is the other half of that
# contract. Until it is rewritten, `require_signing_key` refuses to install
# anything at all. Setting UNIHELM_PUBKEY in the environment points this
# installer at a fork's own key; note what that cannot do — there is no value
# of it, including the empty string, that skips verification.
UNIHELM_PUBKEY="${UNIHELM_PUBKEY:-RWSj0olr2XQ6OU9F7XmaNUTsVQMelXpx6b4mK/NZ22cxRB75xdu/RGQs}"

readonly BIN_DIR=/usr/local/unihelm/bin
readonly CONFIG_DIR=/etc/unihelm
readonly DATA_DIR=/var/lib/unihelm
readonly LOG_DIR=/var/log/unihelm
readonly UNIT_DIR=/etc/systemd/system
readonly SERVICE_USER=unihelm
readonly BINARIES=(unihelm-agentd unihelm-web unihelm)

SOURCE_DIR=""
FROM_SOURCE=0
ADMIN_USER="admin"
ADMIN_EMAIL=""
LISTEN=""
SKIP_PREFLIGHT=0
RELEASE_VERSION="${UNIHELM_VERSION:-}"
STAGED_BIN_DIR=""
WORKDIR=""

# Where this script is, and whether it is anywhere at all.
#
# preflight.sh, config.toml.example and the two systemd units are read relative
# to this file, so `here` has to exist before any of them can be. Run from a
# clone or from an unpacked release tarball it is this script's own directory.
# Piped into bash — `curl … | sudo bash`, the line the README advertises — there
# is no file on disk at all: BASH_SOURCE is empty, none of those companion files
# came with us, and no ordering trick conjures them. That is a mode, not an
# error; `bootstrap_from_release` at the bottom of this file is what it means.
#
# The `:-` is load-bearing: without it `set -u` kills the script on this line,
# which is exactly the bug this handles.
if [ -n "${BASH_SOURCE[0]:-}" ]; then
  here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  piped=0
else
  here=""
  piped=1
fi

# --- output helpers --------------------------------------------------------
step() { printf '\033[1m==>\033[0m %s\n' "$*"; }
info() { printf '    %s\n' "$*"; }
warn() { printf '\033[33m    warning:\033[0m %s\n' "$*" >&2; }
die() {
  printf '\033[31merror:\033[0m %s\n' "$*" >&2
  exit 1
}

usage() {
  cat <<'USAGE'
Usage: install.sh [options]

By default this downloads the latest signed release for this architecture,
verifies its minisign signature and SHA-256 checksum, and installs it.

  --from-source       Build from this source tree instead of downloading
  --from DIR          Install binaries already built in DIR (implies source mode)
  --version TAG       Install this release instead of the latest (e.g. v0.4.1)
  --admin-user NAME   Username for the first administrator (default: admin)
  --admin-email MAIL  Email for the first administrator (default: admin@<hostname>)
  --listen ADDR:PORT  Panel listen address (default: 127.0.0.1:8088)
  --skip-preflight    Install anyway on an unsupported system. Not recommended.
  -h, --help          This text

Environment:
  UNIHELM_VERSION      Same as --version
  UNIHELM_REPO         owner/name of the GitHub repository to fetch from
  UNIHELM_PUBKEY       minisign public key releases must be signed with

There is deliberately no option to skip signature verification.
USAGE
}

parse_args() {
  while [ $# -gt 0 ]; do
    case "$1" in
      --from) SOURCE_DIR="${2:?--from needs a directory}"; shift 2 ;;
      --from-source) FROM_SOURCE=1; shift ;;
      --version) RELEASE_VERSION="${2:?--version needs a tag}"; shift 2 ;;
      --admin-user) ADMIN_USER="${2:?--admin-user needs a name}"; shift 2 ;;
      --admin-email) ADMIN_EMAIL="${2:?--admin-email needs an address}"; shift 2 ;;
      --listen) LISTEN="${2:?--listen needs an address}"; shift 2 ;;
      --skip-preflight) SKIP_PREFLIGHT=1; shift ;;
      -h | --help) usage; exit 0 ;;
      *) die "unknown option $1" ;;
    esac
  done

  if [ -n "$SOURCE_DIR" ] && [ "$FROM_SOURCE" -eq 1 ]; then
    die "--from and --from-source do the same job two different ways; pick one"
  fi
  return 0
}

# --- the network seam ------------------------------------------------------
# Every byte this script pulls off the network goes through these two functions
# and nothing else, which is what lets the CI gate swap in a local fixture and
# still exercise the real verification code.
require_curl() {
  command -v curl >/dev/null 2>&1 ||
    die "curl is required to download a release; install it, or build from source with --from-source"
  return 0
}

# `--proto`/`--proto-redir` pin us to https on the first request *and* on every
# redirect: GitHub bounces release downloads to a storage host, and a redirect
# to http would otherwise be followed silently.
fetch_to() { # url dest
  require_curl
  curl --fail --silent --show-error --location \
    --proto '=https' --proto-redir '=https' --tlsv1.2 \
    --retry 3 --retry-delay 2 --max-time 600 \
    --output "$2" --url "$1"
}

fetch_stdout() { # url
  require_curl
  curl --fail --silent --show-error --location \
    --proto '=https' --proto-redir '=https' --tlsv1.2 \
    --retry 3 --retry-delay 2 --max-time 60 \
    --header 'Accept: application/vnd.github+json' --url "$1"
}

# --- release identity ------------------------------------------------------
normalize_arch() {
  case "$1" in
    x86_64 | amd64) printf 'x86_64\n' ;;
    aarch64 | arm64) printf 'aarch64\n' ;;
    *)
      die "no Unihelm release is published for $1 — x86_64 and aarch64 only. Build one with: sudo ./install.sh --from-source"
      ;;
  esac
  return 0
}

release_arch() { normalize_arch "$(uname -m)"; }

# A tag is about to be interpolated into a URL and a filename. Anything that is
# not shaped like a version stops here rather than reaching the filesystem.
valid_version() {
  local candidate="${1:-}" pattern='^v?[0-9]+(\.[0-9]+){0,3}([.+-][0-9A-Za-z.]+)?$'
  [[ $candidate =~ $pattern ]]
}

resolve_version() {
  if [ -n "$RELEASE_VERSION" ]; then
    valid_version "$RELEASE_VERSION" ||
      die "\"$RELEASE_VERSION\" is not a version tag (expected something like v0.4.1)"
    return 0
  fi

  local body tag
  body="$(fetch_stdout "https://api.github.com/repos/$UNIHELM_REPO/releases/latest")" ||
    die "could not reach the GitHub release API for $UNIHELM_REPO; pin a version with UNIHELM_VERSION=vX.Y.Z"
  tag="$(printf '%s\n' "$body" |
    sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)"
  [ -n "$tag" ] ||
    die "$UNIHELM_REPO has no published releases yet; build from source with --from-source"
  valid_version "$tag" ||
    die "the release API answered with \"$tag\", which is not a version tag; refusing to build a download URL out of it"

  RELEASE_VERSION="$tag"
  return 0
}

# Release artefacts are named unihelm-<version>-<arch>.tar.gz, with the leading
# `v` of the tag dropped, and each one unpacks to a directory of the same name.
# .github/workflows/release.yml is the other half of this contract — it is what
# actually publishes the assets — and packaging/README.md documents it; changing
# one without the others breaks every install. This said `-linux` until the
# piped install was fixed, which nothing had noticed because no release had been
# cut yet: every download would have 404ed.
release_tarball_name() {
  printf 'unihelm-%s-%s.tar.gz\n' "${RELEASE_VERSION#v}" "$(release_arch)"
}

release_base_url() {
  printf 'https://github.com/%s/releases/download/%s\n' "$UNIHELM_REPO" "$RELEASE_VERSION"
}

# --- verification ----------------------------------------------------------
# The gate that stops a half-configured fork. It runs before anything is
# downloaded, so a clone that nobody signed for never even makes a request.
require_signing_key() {
  case "$UNIHELM_PUBKEY" in
    PLACEHOLDER-* | "")
      die "this installer has no release signing key: the placeholder is still in place.
    That means nothing it downloaded could be verified, so it will not download anything.
    If you are running a fork, set UNIHELM_PUBKEY to your minisign public key.
    If you are building Unihelm yourself, use --from-source."
      ;;
  esac

  # A minisign public key is base64 of 42 bytes — 2-byte algorithm id, 8-byte
  # key id, 32-byte key — so it is always 56 characters and always starts `RW`.
  # Checking the shape turns a truncated copy-paste into a sentence rather than
  # an opaque minisign error three steps later.
  local pattern='^RW[A-Za-z0-9+/]{54}$'
  [[ $UNIHELM_PUBKEY =~ $pattern ]] ||
    die "UNIHELM_PUBKEY does not look like a minisign public key (56 characters starting RW)"
  return 0
}

enable_rhel_repo() {
  local repo="$1"
  command -v dnf >/dev/null 2>&1 || return 0

  if dnf -y config-manager --set-enabled "$repo" >/dev/null 2>&1; then
    info "enabled the \`$repo\` repository"
    return 0
  fi
  # `dnf config-manager` lives in dnf-plugins-core, which a minimal image may
  # not have. Best-effort after that: `crb` is named differently on RHEL proper
  # than on the rebuilds, and an install that does not need it should not fail
  # over a name (mirrors Prerequisite::EnableRepo in unihelm-distro).
  dnf install -y dnf-plugins-core >/dev/null 2>&1 || true
  if dnf -y config-manager --set-enabled "$repo" >/dev/null 2>&1; then
    info "enabled the \`$repo\` repository"
  else
    info "could not enable \`$repo\`; continuing, since not every package needs it"
  fi
  return 0
}

ensure_minisign() {
  if command -v minisign >/dev/null 2>&1; then
    return 0
  fi

  step "Installing minisign to verify the download"

  # Normally preflight has already named the family. In the piped bootstrap it
  # has not, and cannot: preflight.sh travels inside the tarball minisign is
  # here to verify. The only question this function actually asks is which
  # package manager exists, and that one is answerable without preflight.
  #
  # Note what the fallback cannot do. It cannot create a path that continues
  # without minisign — the check at the end of this function is the same check
  # it always was, and on a box with neither apt-get nor dnf `family` stays
  # empty and we still refuse.
  local family="${UNIHELM_FAMILY:-}"
  if [ -z "$family" ]; then
    if command -v apt-get >/dev/null 2>&1; then
      family=debian
    elif command -v dnf >/dev/null 2>&1; then
      family=rhel
    fi
  fi

  case "$family" in
    debian)
      DEBIAN_FRONTEND=noninteractive apt-get update -qq ||
        warn "apt-get update failed; trying the install anyway"
      DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends minisign || true
      ;;
    rhel)
      # minisign is an EPEL package on the RHEL family, and epel-release itself
      # is signed by the distribution — no pin of ours needed, which is exactly
      # why unihelm-distro models it as Prerequisite::DistroPackage.
      dnf install -y epel-release || warn "could not install epel-release; minisign may not resolve"
      enable_rhel_repo crb
      dnf install -y minisign || true
      ;;
    *)
      warn "unrecognised OS family; not attempting to install minisign automatically"
      ;;
  esac

  # The one thing this function must never do is return successfully without
  # minisign. Everything below it assumes a signature was actually checked.
  command -v minisign >/dev/null 2>&1 || die \
    "minisign is required to verify the release signature and could not be installed.
    Debian/Ubuntu:  apt-get install minisign
    AlmaLinux/Rocky: dnf install epel-release && dnf install minisign
    Then run this again — or build from source with --from-source."
  info "minisign is available"
  return 0
}

verify_signature() { # sums-file sig-file
  local sums="$1" sig="$2" output
  info "checking the signature against $UNIHELM_PUBKEY"
  if output="$(minisign -V -P "$UNIHELM_PUBKEY" -m "$sums" -x "$sig" 2>&1)"; then
    return 0
  fi
  printf '%s\n' "$output" >&2
  return 1
}

sha256_check() { # a sha256sum-format file, relative to $PWD
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum -c "$1"
  elif command -v shasum >/dev/null 2>&1; then
    # Every supported distribution ships coreutils; this branch exists so the
    # CI gate can run the real verification code on a developer's macOS.
    shasum -a 256 -c "$1"
  else
    die "neither sha256sum nor shasum is available to check the download"
  fi
}

verify_checksum() { # dir sums-file filename
  local dir="$1" sums="$2" name="$3" hashes count

  # Pull out the hash for exactly the file we downloaded, by basename, and
  # rebuild a one-line checksum file from it. SHA256SUMS lists every
  # architecture, so feeding it to `sha256sum -c` whole would fail on the
  # tarballs we did not fetch; and a signed file that names the same artefact
  # twice is not something to pick a winner from, so two matches is a refusal.
  hashes="$(awk -v want="$name" '
    { f = $2; sub(/^\*/, "", f); n = f; sub(/^.*\//, "", n)
      if (n == want) print $1 }
  ' "$sums")"
  count="$(printf '%s' "$hashes" | grep -c . || true)"
  if [ "$count" -eq 0 ]; then
    warn "SHA256SUMS does not list $name"
    return 1
  elif [ "$count" -ne 1 ]; then
    warn "SHA256SUMS lists $name $count times; expected exactly once"
    return 1
  fi

  printf '%s  %s\n' "$hashes" "$name" >"$dir/SHA256SUM.checked"
  ( cd "$dir" && sha256_check SHA256SUM.checked )
}

unpack_release() { # tarball dest
  install -d -m 0700 "$2"
  # We run as root, so without --no-same-owner tar would restore whatever uid
  # and gid the archive recorded. Nothing downstream reads that ownership —
  # `install_binaries` copies with an explicit mode — so the only thing honouring
  # it could do is surprise somebody. Defence in depth behind a verified
  # signature, which is where the cheap kind belongs.
  tar -xzf "$1" -C "$2" --no-same-owner
  return 0
}

# We never install "whatever was in the archive": we look for the three names
# we expect, at the top level or one directory down, and copy only those.
# A candidate must be a real directory inside the extraction root, not a symlink
# to one. `-d` follows links: an archive member that is a symlink would let a
# tarball point the installer at bytes that were never in the archive and never
# signed, while the run says everything came from a verified tarball.
real_dir() { # path -> true when it is a directory and not a symlink
  [ -d "$1" ] && [ ! -L "$1" ]
}

locate_binaries() { # unpacked-dir -> prints the directory holding all three
  local root="$1" candidate binary complete
  for candidate in "$root" "$root"/*/ "$root"/*/bin; do
    real_dir "$candidate" || continue
    complete=1
    for binary in "${BINARIES[@]}"; do
      [ -f "$candidate/$binary" ] || complete=0
    done
    if [ "$complete" -eq 1 ]; then
      ( cd "$candidate" && pwd )
      return 0
    fi
  done
  return 1
}

download_and_verify_release() { # workdir; sets STAGED_BIN_DIR
  local work="$1" arch tarball base

  require_signing_key
  arch="$(release_arch)"
  resolve_version

  tarball="$(release_tarball_name)"
  base="$(release_base_url)"

  ensure_minisign

  install -d -m 0700 "$work"
  step "Downloading Unihelm $RELEASE_VERSION ($arch)"
  fetch_to "$base/$tarball" "$work/$tarball" ||
    die "could not download $base/$tarball"
  fetch_to "$base/SHA256SUMS" "$work/SHA256SUMS" ||
    die "could not download $base/SHA256SUMS"
  fetch_to "$base/SHA256SUMS.minisig" "$work/SHA256SUMS.minisig" ||
    die "could not download $base/SHA256SUMS.minisig — this release is unsigned and will not be installed"

  step "Verifying the download"
  verify_signature "$work/SHA256SUMS" "$work/SHA256SUMS.minisig" || die \
    "SHA256SUMS is not signed by the key this installer trusts.
    Either this is not our release, or it was modified in transit. Nothing has been installed."
  info "signature ok"

  verify_checksum "$work" "$work/SHA256SUMS" "$tarball" || die \
    "$tarball does not match its signed checksum. Nothing has been installed."
  info "$tarball matches its signed checksum"

  unpack_release "$work/$tarball" "$work/unpacked"
  STAGED_BIN_DIR="$(locate_binaries "$work/unpacked")" ||
    die "$tarball does not contain ${BINARIES[*]}"
  return 0
}

# --- the piped install -----------------------------------------------------
# `curl -fsSL …/install.sh | sudo bash` delivers one file and nothing else: no
# preflight.sh, no config.toml.example, no systemd units — the four files this
# installer reads from its own directory. Fetching those loose from the raw
# content host would put four unsigned files on somebody's server, which is the
# one thing the release path exists to prevent.
#
# The release tarball already holds every one of them, beside the binaries and
# beside a copy of this same script (see .github/workflows/release.yml). So a
# piped run has exactly one job: verify that tarball with the code above —
# minisign signature first, then the checksum that signature vouches for — and
# hand the install over to the install.sh that came out of it. From that point
# on every byte executed or installed is covered by the release signature, which
# is strictly more than the file-executed path can say about its own companions.
#
# The companion half of locate_binaries, and for the same reason: take the files
# we expect from where we expect them, never "whatever was in the archive". A
# directory only counts as an installer if it has all four things install.sh
# reads by relative path, so a tarball missing one says so here rather than
# three functions later as `install: cannot stat`.
locate_installer_root() { # unpacked-dir -> prints the directory holding install.sh
  local root="$1" candidate file complete
  for candidate in "$root" "$root"/*/; do
    real_dir "$candidate" || continue
    complete=1
    for file in install.sh preflight.sh config.toml.example \
      systemd/unihelm-agentd.service systemd/unihelm-web.service; do
      [ -f "$candidate/$file" ] || complete=0
    done
    if [ "$complete" -eq 1 ]; then
      ( cd "$candidate" && pwd )
      return 0
    fi
  done
  return 1
}

bootstrap_from_release() {
  local root

  # Belt and braces. The real guarantee is structural — the installer we hand
  # over to is run from a file, so it has a BASH_SOURCE and takes the executed
  # branch, and it is given --from so it never downloads anything. This turns
  # any future mistake into one error line instead of a fork bomb.
  [ -z "${UNIHELM_BOOTSTRAPPED:-}" ] ||
    die "the installer re-entered its own bootstrap; refusing to loop"

  # Before a byte is fetched: --help must print, an unknown option must stop,
  # and --version must be honoured, since it decides which tarball we download.
  parse_args "$@"

  # An argument error is an argument error whoever you are, so this comes before
  # the root check.
  if [ "$FROM_SOURCE" -eq 1 ] || [ -n "$SOURCE_DIR" ]; then
    die "--from and --from-source install from files on this machine, and a piped
    install has none: this script arrived on stdin with no directory of its own.
    Clone the repository and run the installer out of it:
      git clone https://github.com/$UNIHELM_REPO
      sudo unihelm/installer/install.sh --from-source"
  fi

  # preflight's own root check is inside the tarball we have not got yet, and
  # what follows writes to /tmp as root and may install a package.
  [ "$(id -u)" -eq 0 ] ||
    die "this installs system services and must run as root:
    curl -fsSL https://raw.githubusercontent.com/$UNIHELM_REPO/main/installer/install.sh | sudo bash"

  trap cleanup EXIT
  WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/unihelm-install.XXXXXX")"

  # Dies unless the signature and the checksum both verify. Nothing below this
  # line runs otherwise, which is the whole point of putting it above the
  # hand-over.
  download_and_verify_release "$WORKDIR"

  root="$(locate_installer_root "$WORKDIR/unpacked")" ||
    die "the verified $RELEASE_VERSION tarball carries no installer — no install.sh,
    preflight.sh, config.toml.example and systemd units together in one place.
    Download it from $(release_base_url), unpack it, and run ./install.sh --from ./bin,
    or pin a release that has one with UNIHELM_VERSION."

  step "Handing over to the installer from the verified release"
  info "everything from here comes out of a tarball whose signature verified"

  # A child rather than `exec`: the EXIT trap above is what removes $WORKDIR,
  # and exec would drop it and leave a 0700 directory holding a tarball in /tmp.
  # `set -e` still propagates a failing install.
  #
  # </dev/null because bash reads a piped script as it runs it — without the
  # redirect the child would inherit the unread tail of this very script as its
  # standard input. Nothing on the install path reads stdin (`user create-admin`
  # only does under --password-stdin, which the installer never passes), so
  # /dev/null costs nothing.
  #
  # `bash "$root/install.sh"`, not `"$root/install.sh"`: /tmp is mounted noexec
  # on plenty of hardened servers, and this way that fails nothing and tempts
  # nobody into a chmod workaround.
  UNIHELM_BOOTSTRAPPED=1 "${BASH:-bash}" "$root/install.sh" \
    --from "$STAGED_BIN_DIR" "$@" </dev/null
  return 0
}

# --- source build ----------------------------------------------------------
build_from_source() {
  local root
  # Unreachable from a pipe — the bootstrap refuses --from-source before it gets
  # here — but an empty `here` would make this `cd /..`, and silently building
  # the root directory is not a failure mode worth leaving open.
  [ -n "$here" ] ||
    die "--from-source needs the Unihelm source tree, and this script has no directory of its own"
  root="$(cd "$here/.." && pwd)"
  [ -f "$root/Cargo.toml" ] ||
    die "--from-source needs the Unihelm source tree, and $root has no Cargo.toml"
  command -v cargo >/dev/null 2>&1 ||
    die "--from-source needs cargo on PATH (see https://rustup.rs)"

  # unihelm-web embeds the built interface, so the UI has to exist before the
  # Rust build rather than after it.
  # A missing package manager is fatal here, not a warning. `unihelm-web` embeds
  # whatever is in ui-dist at compile time, so building without one produces a
  # binary that starts, serves, and answers every request with a blank page —
  # an install that looks like it worked and is discovered broken in a browser.
  # Better to stop now, while the operator is still watching the terminal.
  if [ -f "$root/ui/package-lock.json" ] || [ -f "$root/ui/pnpm-lock.yaml" ]; then
    step "Building the interface"
    if [ -f "$root/ui/pnpm-lock.yaml" ] && command -v pnpm >/dev/null 2>&1; then
      ( cd "$root/ui" && pnpm install --frozen-lockfile && pnpm run build )
    elif [ -f "$root/ui/package-lock.json" ] && command -v npm >/dev/null 2>&1; then
      ( cd "$root/ui" && npm ci && npm run build )
    else
      die "the interface cannot be built: no package manager for the lockfile in
  $root/ui. Install Node 20+ with npm (or pnpm, for a pnpm-lock.yaml) and run
  this again. Building without it would produce a panel that serves a blank
  page, so this stops rather than going on."
    fi
    # A lockfile and a package manager are not proof the build produced anything.
    [ -s "$root/crates/unihelm-web/ui-dist/index.html" ] ||
      die "the interface build left no index.html in crates/unihelm-web/ui-dist"
  fi

  step "Building Unihelm (this takes a while)"
  ( cd "$root" && cargo build --release )
  SOURCE_DIR="${CARGO_TARGET_DIR:-$root/target}/release"
  return 0
}

# --- steps shared by both paths --------------------------------------------
run_preflight() {
  step "Checking this server"
  preflight_run
  if ! preflight_report; then
    [ "$SKIP_PREFLIGHT" -eq 1 ] ||
      die "preflight failed; fix the items above or pass --skip-preflight"
    warn "continuing despite preflight failures because --skip-preflight was given"
  fi
  # Guarded: with --skip-preflight on a system without /etc/os-release these
  # are never assigned, and `set -u` would kill the installer here rather than
  # let the operator through the door they explicitly asked for.
  info "${UNIHELM_OS_NAME:-unknown system} (${UNIHELM_FAMILY:-?}, ${UNIHELM_ARCH:-?})"
  return 0
}

create_service_account() {
  step "Creating the $SERVICE_USER account"
  if id -u "$SERVICE_USER" >/dev/null 2>&1; then
    info "already exists"
    return 0
  fi
  # A system account with no shell and no login: it exists to own a socket and
  # a database file, not to be signed into.
  useradd --system --user-group --no-create-home \
    --home-dir "$DATA_DIR" --shell /usr/sbin/nologin \
    --comment "Unihelm panel" "$SERVICE_USER" 2>/dev/null ||
    useradd --system --user-group --no-create-home \
      --home-dir "$DATA_DIR" --shell /sbin/nologin \
      --comment "Unihelm panel" "$SERVICE_USER"
  info "created"
  return 0
}

install_binaries() { # source directory
  local src="$1" binary
  for binary in "${BINARIES[@]}"; do
    [ -f "$src/$binary" ] || die "$src/$binary is missing"
  done

  step "Installing to $BIN_DIR"
  install -d -m 0755 "$BIN_DIR"
  for binary in "${BINARIES[@]}"; do
    install -m 0755 "$src/$binary" "$BIN_DIR/$binary"
    info "$binary"
  done
  return 0
}

create_layout() {
  # The panel database is root-owned and readable only by the panel account.
  install -d -m 0755 "$CONFIG_DIR"
  install -d -m 0750 -o "$SERVICE_USER" -g "$SERVICE_USER" "$DATA_DIR"
  install -d -m 0750 -o "$SERVICE_USER" -g "$SERVICE_USER" "$DATA_DIR/state"
  install -d -m 0750 -o "$SERVICE_USER" -g "$SERVICE_USER" "$LOG_DIR"

  # `unihelm` on PATH, without putting our whole bin directory there.
  ln -sf "$BIN_DIR/unihelm" /usr/local/bin/unihelm
  return 0
}

write_configuration() {
  step "Writing configuration"
  if [ -f "$CONFIG_DIR/config.toml" ]; then
    info "$CONFIG_DIR/config.toml exists; leaving it alone"
  else
    install -m 0644 "$here/config.toml.example" "$CONFIG_DIR/config.toml"
    if [ -n "$LISTEN" ]; then
      sed -i "s|^listen = .*|listen = \"$LISTEN\"|" "$CONFIG_DIR/config.toml"
    fi
    info "$CONFIG_DIR/config.toml"
  fi

  # Master key for secrets at rest: ACME account keys, DNS credentials, SMTP
  # passwords (spec §12 rule 6). Generated once and never regenerated — losing
  # it means losing the ability to read anything sealed with it.
  if [ -f "$CONFIG_DIR/secret.key" ]; then
    info "secret key exists; leaving it alone"
  else
    umask 077
    head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' >"$CONFIG_DIR/secret.key"
    chmod 0600 "$CONFIG_DIR/secret.key"
    info "$CONFIG_DIR/secret.key (0600)"
  fi
  return 0
}

install_units() {
  step "Installing systemd units"
  install -m 0644 "$here/systemd/unihelm-agentd.service" "$UNIT_DIR/unihelm-agentd.service"
  install -m 0644 "$here/systemd/unihelm-web.service" "$UNIT_DIR/unihelm-web.service"
  systemctl daemon-reload
  systemctl enable --now unihelm-agentd.service
  info "unihelm-agentd started"

  # The agent creates the database on first start; wait for it before the web
  # process and the CLI need it.
  for _ in $(seq 1 30); do
    [ -S /run/unihelm/agent.sock ] && break
    sleep 0.5
  done
  [ -S /run/unihelm/agent.sock ] ||
    die "unihelm-agentd did not come up; check: journalctl -u unihelm-agentd"

  systemctl enable --now unihelm-web.service
  info "unihelm-web started"
  return 0
}

# An address the panel will actually accept.
#
# `Email::parse` requires a domain with at least one dot, and a fresh cloud VM
# usually answers `hostname -f` with a bare name like `ubuntu-server`. Deriving
# `admin@$(hostname -f)` and hoping therefore failed at the very last step of an
# otherwise perfect install, with `UNI-1200 email domain is not a valid domain
# name` — after the account, the binaries, the config and both services were
# already in place. The address is the one thing here only the operator can
# supply, so ask for it rather than guessing and failing.
valid_admin_email() { # candidate -> 0 when the panel would accept it
  case "$1" in
    *@*.*) [ "${#1}" -le 254 ] ;;
    *) return 1 ;;
  esac
}

resolve_admin_email() {
  local candidate answer
  candidate="admin@$(hostname -f 2>/dev/null || hostname 2>/dev/null || echo localhost)"
  valid_admin_email "$candidate" || candidate="admin@$(hostname 2>/dev/null || echo unihelm).local"

  # /dev/tty, never stdin: under `curl … | sudo bash` stdin is the script itself,
  # and after the bootstrap hands over it is /dev/null. Reading from it would
  # either swallow the rest of the installer or return nothing at all.
  # Opened, not stat'ed. `/dev/tty` passes -r and -w in contexts where opening it
  # still fails with ENXIO — a process with no controlling terminal, which is
  # what a systemd unit, a CI runner and `ssh host 'curl … | bash'` all are.
  if { : >/dev/tty; } 2>/dev/null && { : </dev/tty; } 2>/dev/null; then
    printf '    Administrator email [%s]: ' "$candidate" >/dev/tty
    IFS= read -r answer </dev/tty || answer=""
    if [ -n "$answer" ]; then
      if valid_admin_email "$answer"; then
        ADMIN_EMAIL="$answer"
        return 0
      fi
      # One correction, then fall back — a prompt loop in an installer somebody
      # is watching a progress log scroll past is its own kind of trap.
      printf '    that needs a domain with a dot, e.g. you@example.com [%s]: ' \
        "$candidate" >/dev/tty
      IFS= read -r answer </dev/tty || answer=""
      if [ -n "$answer" ] && valid_admin_email "$answer"; then
        ADMIN_EMAIL="$answer"
        return 0
      fi
    fi
  fi

  ADMIN_EMAIL="$candidate"
  info "using $ADMIN_EMAIL — change it from the panel's account page"
  return 0
}

create_first_admin() {
  step "Creating the first administrator"
  if [ -z "$ADMIN_EMAIL" ]; then
    resolve_admin_email
  elif ! valid_admin_email "$ADMIN_EMAIL"; then
    die "--admin-email $ADMIN_EMAIL is not an address the panel will accept:
  the domain needs at least one dot, as in you@example.com"
  fi

  # `create-admin` already refuses when any account exists, and says so — it is
  # the only thing that can decide this correctly, because it asks the database.
  # This used to guard it with `user list | grep -q admin`, which matched any
  # substring: an account named `sysadmin`, or an address like
  # `notadmin@example.com`, read as "an administrator exists" and the real one
  # was never created, leaving an install nobody could log in to. Let the binary
  # answer, and treat its refusal as the "already done" case it is.
  if "$BIN_DIR/unihelm" user create-admin \
       --username "$ADMIN_USER" --email "$ADMIN_EMAIL" 2>"$WORKDIR/create-admin.err"; then
    :
  elif grep -q "an account already exists" "$WORKDIR/create-admin.err"; then
    info "an account already exists; skipping"
  else
    cat "$WORKDIR/create-admin.err" >&2
    die "could not create the first administrator"
  fi
  return 0
}

# This server's address as somebody else would reach it.
#
# `hostname -f` is not it: a fresh cloud VM answers with a bare name that
# resolves nowhere but on itself, and printing that in an ssh command gives the
# operator a line that cannot work. Ask the routing table which source address
# this machine would use to reach the internet.
server_address() {
  local ip=""
  if command -v ip >/dev/null 2>&1; then
    ip="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}')"
  fi
  [ -n "$ip" ] || ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
  [ -n "$ip" ] || ip="$(hostname -f 2>/dev/null || hostname 2>/dev/null)"
  printf '%s' "${ip:-this-server}"
}

print_summary() {
  local listen_addr host port
  listen_addr="$(awk -F'"' '/^listen = /{print $2}' "$CONFIG_DIR/config.toml")"
  port="${listen_addr##*:}"
  host="${listen_addr%:*}"
  local server; server="$(server_address)"

  # Loopback and exposed are genuinely different instructions, and the old
  # summary printed one line for both: `Panel http://127.0.0.1:8088`, which an
  # operator reads as a link, pastes into the browser on their own laptop, and
  # reaches nothing — because that address is this server's loopback, not
  # theirs. Say where the panel is, then say what to actually type.
  case "$host" in
    127.0.0.1 | ::1 | localhost)
      cat <<DONE

$(printf '\033[1m')Unihelm is installed.$(printf '\033[0m')

  The panel is listening on ${listen_addr} $(printf '\033[1m')on this server$(printf '\033[0m') — not on the machine
  you are reading this from. Nothing is exposed to the network, which is
  deliberate: a fresh install has a generated password and no certificate yet.

  To open it, forward the port from your own computer:

      ssh -L ${port}:${listen_addr} root@${server}

  and then visit http://127.0.0.1:${port} in your browser.

  To serve it on this server's own address instead, set

      listen = "0.0.0.0:${port}"

  in ${CONFIG_DIR}/config.toml and run \`systemctl restart unihelm-web\`. Issue a
  certificate first if it will face the internet.

  Health    unihelm doctor
  Logs      journalctl -u unihelm-agentd -u unihelm-web -f

No stack components are installed yet — add nginx, PHP and a database from the
panel when you are ready.
DONE
      ;;
    *)
      cat <<DONE

$(printf '\033[1m')Unihelm is installed.$(printf '\033[0m')

  Panel     http://${server}:${port}
  Health    unihelm doctor
  Logs      journalctl -u unihelm-agentd -u unihelm-web -f

The panel is reachable on the network (it listens on ${listen_addr}). Point a
domain at this server and issue a certificate before you rely on it — until
then the login form is served over plain HTTP.

No stack components are installed yet — add nginx, PHP and a database from the
panel when you are ready.
DONE
      ;;
  esac
  return 0
}

# The scratch directory holds a downloaded tarball and nothing secret, but it
# is 0700 and it goes away on the way out either way. `return 0` is not
# decoration: an EXIT trap that ends on a false test changes the exit status of
# a *successful* install, which is the same class of bug as the one
# tests/gates/installer.sh exists for.
cleanup() {
  if [ -n "$WORKDIR" ] && [ -d "$WORKDIR" ]; then
    rm -rf "$WORKDIR"
  fi
  return 0
}

main() {
  parse_args "$@"
  run_preflight

  if [ -n "$SOURCE_DIR" ]; then
    info "installing binaries from $SOURCE_DIR"
  elif [ "$FROM_SOURCE" -eq 1 ]; then
    build_from_source
  else
    trap cleanup EXIT
    WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/unihelm-install.XXXXXX")"
    download_and_verify_release "$WORKDIR"
    SOURCE_DIR="$STAGED_BIN_DIR"
  fi

  create_service_account
  install_binaries "$SOURCE_DIR"
  create_layout
  write_configuration
  install_units
  create_first_admin
  print_summary
}

if [ "$piped" -eq 0 ]; then
  # shellcheck source-path=SCRIPTDIR
  # shellcheck source=installer/preflight.sh
  . "$here/preflight.sh"
fi

# --- how this file was started ---------------------------------------------
# Three ways, and they have to be told apart, because two facts distinguish them
# and the old test here only looked at one:
#
#   executed  ./install.sh, bash install.sh   BASH_SOURCE[0] is set and is $0
#   piped     curl … | sudo bash              BASH_SOURCE is empty, $0 is "bash"
#   sourced   . installer/install.sh          BASH_SOURCE[0] is set, $0 is not it
#
# "Empty" is the piped signal, and it is captured at the top of the file where
# it has to be captured anyway to keep `set -u` from killing us. Testing it
# *first* is what matters: the obvious repair — writing `${BASH_SOURCE[0]:-}`
# and leaving the comparison alone — collapses piped into sourced, so the
# advertised install line would exit 0 having done absolutely nothing. Silence
# is a worse failure than the crash it replaces.
#
# The piped branch never falls through to main: it verifies a release and runs
# the installer out of it, in a child process that is executed from a file and
# therefore takes the first branch.
if [ "$piped" -eq 1 ]; then
  bootstrap_from_release "$@"
elif [ "${BASH_SOURCE[0]}" = "${0}" ]; then
  # Executed. Sourcing gives you the functions and no side effects, which is how
  # the CI gate drives the verification path without installing anything.
  main "$@"
fi
