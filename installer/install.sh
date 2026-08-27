#!/usr/bin/env bash
# Ferrum installer (spec §14 Phase 0; release verification per spec §5.5).
#
# Two ways in. The default is a signed release binary — the thing almost
# everybody wants, and the thing that does not need a Rust toolchain, 2 GB of
# build artefacts and twenty minutes on a 1 GB VPS:
#
#     sudo ./install.sh                          # the latest release
#     sudo FERRUM_VERSION=v0.4.1 ./install.sh    # a pinned one
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
#   3. Refuse outright while FERRUM_PUBKEY is still the release-time
#      placeholder. This is the fork trap: a repository someone cloned and
#      pointed at their own releases would otherwise download a tarball,
#      "verify" it against nothing in particular and install it. Refusing costs
#      a fork one line of configuration. Not refusing costs whoever runs it
#      everything on the box.
#   4. Install minisign from the distribution's own repositories — EPEL on the
#      RHEL family, using the same epel-release + `crb` sequence the repo layer
#      in crates/ferrum-distro/src/pkg.rs applies before any third-party repo.
#      No minisign, no install: there is no code path below that continues
#      without a verified signature, and no flag that creates one.
#   5. Resolve the version — $FERRUM_VERSION if set, otherwise the GitHub
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
# `ferrum` account, install the binaries and the directory layout from spec
# §4.3, write /etc/ferrum/config.toml and generate the master key, install and
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
# The repository releases come from. A fork changes this and FERRUM_PUBKEY and
# needs to change nothing else.
FERRUM_REPO="${FERRUM_REPO:-farzam/ferrum}"

# The minisign public key every release is signed with (spec §5.5 — the same
# ed25519/minisign format self-update verifies). The literal below is rewritten
# when a release is cut; packaging/README.md is the other half of that
# contract. Until it is rewritten, `require_signing_key` refuses to install
# anything at all. Setting FERRUM_PUBKEY in the environment points this
# installer at a fork's own key; note what that cannot do — there is no value
# of it, including the empty string, that skips verification.
FERRUM_PUBKEY="${FERRUM_PUBKEY:-PLACEHOLDER-REPLACE-AT-RELEASE}"

readonly BIN_DIR=/usr/local/ferrum/bin
readonly CONFIG_DIR=/etc/ferrum
readonly DATA_DIR=/var/lib/ferrum
readonly LOG_DIR=/var/log/ferrum
readonly UNIT_DIR=/etc/systemd/system
readonly SERVICE_USER=ferrum
readonly BINARIES=(ferrum-agentd ferrum-web ferrum)

SOURCE_DIR=""
FROM_SOURCE=0
ADMIN_USER="admin"
ADMIN_EMAIL=""
LISTEN=""
SKIP_PREFLIGHT=0
RELEASE_VERSION="${FERRUM_VERSION:-}"
STAGED_BIN_DIR=""
WORKDIR=""

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

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
  FERRUM_VERSION      Same as --version
  FERRUM_REPO         owner/name of the GitHub repository to fetch from
  FERRUM_PUBKEY       minisign public key releases must be signed with

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
      die "no Ferrum release is published for $1 — x86_64 and aarch64 only. Build one with: sudo ./install.sh --from-source"
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
  body="$(fetch_stdout "https://api.github.com/repos/$FERRUM_REPO/releases/latest")" ||
    die "could not reach the GitHub release API for $FERRUM_REPO; pin a version with FERRUM_VERSION=vX.Y.Z"
  tag="$(printf '%s\n' "$body" |
    sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)"
  [ -n "$tag" ] ||
    die "$FERRUM_REPO has no published releases yet; build from source with --from-source"
  valid_version "$tag" ||
    die "the release API answered with \"$tag\", which is not a version tag; refusing to build a download URL out of it"

  RELEASE_VERSION="$tag"
  return 0
}

# Release artefacts are named ferrum-<version>-<arch>-linux.tar.gz, with the
# leading `v` of the tag dropped. packaging/README.md is the other half of this
# contract; changing one without the other breaks every install.
release_tarball_name() {
  printf 'ferrum-%s-%s-linux.tar.gz\n' "${RELEASE_VERSION#v}" "$(release_arch)"
}

release_base_url() {
  printf 'https://github.com/%s/releases/download/%s\n' "$FERRUM_REPO" "$RELEASE_VERSION"
}

# --- verification ----------------------------------------------------------
# The gate that stops a half-configured fork. It runs before anything is
# downloaded, so a clone that nobody signed for never even makes a request.
require_signing_key() {
  case "$FERRUM_PUBKEY" in
    PLACEHOLDER-* | "")
      die "this installer has no release signing key: the placeholder is still in place.
    That means nothing it downloaded could be verified, so it will not download anything.
    If you are running a fork, set FERRUM_PUBKEY to your minisign public key.
    If you are building Ferrum yourself, use --from-source."
      ;;
  esac

  # A minisign public key is base64 of 42 bytes — 2-byte algorithm id, 8-byte
  # key id, 32-byte key — so it is always 56 characters and always starts `RW`.
  # Checking the shape turns a truncated copy-paste into a sentence rather than
  # an opaque minisign error three steps later.
  local pattern='^RW[A-Za-z0-9+/]{54}$'
  [[ $FERRUM_PUBKEY =~ $pattern ]] ||
    die "FERRUM_PUBKEY does not look like a minisign public key (56 characters starting RW)"
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
  # over a name (mirrors Prerequisite::EnableRepo in ferrum-distro).
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
  case "${FERRUM_FAMILY:-}" in
    debian)
      DEBIAN_FRONTEND=noninteractive apt-get update -qq ||
        warn "apt-get update failed; trying the install anyway"
      DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends minisign || true
      ;;
    rhel)
      # minisign is an EPEL package on the RHEL family, and epel-release itself
      # is signed by the distribution — no pin of ours needed, which is exactly
      # why ferrum-distro models it as Prerequisite::DistroPackage.
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
  info "checking the signature against $FERRUM_PUBKEY"
  if output="$(minisign -V -P "$FERRUM_PUBKEY" -m "$sums" -x "$sig" 2>&1)"; then
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
locate_binaries() { # unpacked-dir -> prints the directory holding all three
  local root="$1" candidate binary complete
  for candidate in "$root" "$root"/*/ "$root"/*/bin; do
    [ -d "$candidate" ] || continue
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
  step "Downloading Ferrum $RELEASE_VERSION ($arch)"
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

# --- source build ----------------------------------------------------------
build_from_source() {
  local root
  root="$(cd "$here/.." && pwd)"
  [ -f "$root/Cargo.toml" ] ||
    die "--from-source needs the Ferrum source tree, and $root has no Cargo.toml"
  command -v cargo >/dev/null 2>&1 ||
    die "--from-source needs cargo on PATH (see https://rustup.rs)"

  # ferrum-web embeds the built interface, so the UI has to exist before the
  # Rust build rather than after it.
  if [ -f "$root/ui/package-lock.json" ]; then
    if command -v npm >/dev/null 2>&1; then
      step "Building the interface"
      ( cd "$root/ui" && npm ci && npm run build )
    else
      warn "npm is not installed; ferrum-web will be built without its interface"
    fi
  fi

  step "Building Ferrum (this takes a while)"
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
  info "${FERRUM_OS_NAME:-unknown system} (${FERRUM_FAMILY:-?}, ${FERRUM_ARCH:-?})"
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
    --comment "Ferrum panel" "$SERVICE_USER" 2>/dev/null ||
    useradd --system --user-group --no-create-home \
      --home-dir "$DATA_DIR" --shell /sbin/nologin \
      --comment "Ferrum panel" "$SERVICE_USER"
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

  # `ferrum` on PATH, without putting our whole bin directory there.
  ln -sf "$BIN_DIR/ferrum" /usr/local/bin/ferrum
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
  install -m 0644 "$here/systemd/ferrum-agentd.service" "$UNIT_DIR/ferrum-agentd.service"
  install -m 0644 "$here/systemd/ferrum-web.service" "$UNIT_DIR/ferrum-web.service"
  systemctl daemon-reload
  systemctl enable --now ferrum-agentd.service
  info "ferrum-agentd started"

  # The agent creates the database on first start; wait for it before the web
  # process and the CLI need it.
  for _ in $(seq 1 30); do
    [ -S /run/ferrum/agent.sock ] && break
    sleep 0.5
  done
  [ -S /run/ferrum/agent.sock ] ||
    die "ferrum-agentd did not come up; check: journalctl -u ferrum-agentd"

  systemctl enable --now ferrum-web.service
  info "ferrum-web started"
  return 0
}

create_first_admin() {
  step "Creating the first administrator"
  if [ -z "$ADMIN_EMAIL" ]; then
    ADMIN_EMAIL="admin@$(hostname -f 2>/dev/null || hostname)"
  fi

  if "$BIN_DIR/ferrum" user list 2>/dev/null | grep -q admin; then
    info "an account already exists; skipping"
  else
    "$BIN_DIR/ferrum" user create-admin --username "$ADMIN_USER" --email "$ADMIN_EMAIL"
  fi
  return 0
}

print_summary() {
  local listen_addr
  listen_addr="$(awk -F'"' '/^listen = /{print $2}' "$CONFIG_DIR/config.toml")"
  cat <<DONE

$(printf '\033[1m')Ferrum is installed.$(printf '\033[0m')

  Panel     http://${listen_addr}
  Health    ferrum doctor
  Logs      journalctl -u ferrum-agentd -u ferrum-web -f

The panel listens on ${listen_addr}. If that is loopback, reach it over an SSH
tunnel until you have pointed a domain at this server and issued a certificate:

  ssh -L 8088:${listen_addr} root@$(hostname -f 2>/dev/null || hostname)

No stack components are installed yet — add nginx, PHP and a database from the
panel when you are ready.
DONE
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
    WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/ferrum-install.XXXXXX")"
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

# shellcheck source-path=SCRIPTDIR
# shellcheck source=installer/preflight.sh
. "$here/preflight.sh"

# Run only when executed. Sourcing gives you the functions and no side effects,
# which is how the CI gate drives the verification path without installing
# anything.
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
  main "$@"
fi
