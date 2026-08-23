#!/usr/bin/env bash
# Ferrum installer (spec §14, Phase 0).
#
#   sudo ./install.sh --from ./target/release
#
# What it does, in order, and nothing more:
#   1. preflight — refuse early rather than break a working server
#   2. create the unprivileged `ferrum` account
#   3. install the three binaries and the directory layout from spec §4.3
#   4. write /etc/ferrum/config.toml and generate the secret key
#   5. install and start the two systemd units
#   6. create the first administrator and print its password once
#
# It installs no stack components. Nginx, PHP, MariaDB and the rest arrive on
# demand from the Stack Manager, which is what keeps a base install small enough
# for a 1 GB VPS (spec §1.1).
set -euo pipefail

readonly BIN_DIR=/usr/local/ferrum/bin
readonly CONFIG_DIR=/etc/ferrum
readonly DATA_DIR=/var/lib/ferrum
readonly LOG_DIR=/var/log/ferrum
readonly UNIT_DIR=/etc/systemd/system
readonly SERVICE_USER=ferrum
readonly BINARIES=(ferrum-agentd ferrum-web ferrum)

SOURCE_DIR=""
ADMIN_USER="admin"
ADMIN_EMAIL=""
LISTEN=""
SKIP_PREFLIGHT=0

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

  --from DIR          Directory holding the built binaries (required for now)
  --admin-user NAME   Username for the first administrator (default: admin)
  --admin-email MAIL  Email for the first administrator (default: admin@<hostname>)
  --listen ADDR:PORT  Panel listen address (default: 127.0.0.1:8088)
  --skip-preflight    Install anyway on an unsupported system. Not recommended.
  -h, --help          This text
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --from) SOURCE_DIR="${2:?--from needs a directory}"; shift 2 ;;
    --admin-user) ADMIN_USER="${2:?--admin-user needs a name}"; shift 2 ;;
    --admin-email) ADMIN_EMAIL="${2:?--admin-email needs an address}"; shift 2 ;;
    --listen) LISTEN="${2:?--listen needs an address}"; shift 2 ;;
    --skip-preflight) SKIP_PREFLIGHT=1; shift ;;
    -h | --help) usage; exit 0 ;;
    *) die "unknown option $1" ;;
  esac
done

# --- 1. preflight ----------------------------------------------------------
step "Checking this server"
# shellcheck source=preflight.sh
. "$here/preflight.sh"
preflight_run
if ! preflight_report; then
  [ "$SKIP_PREFLIGHT" -eq 1 ] || die "preflight failed; fix the items above or pass --skip-preflight"
  warn "continuing despite preflight failures because --skip-preflight was given"
fi
info "${FERRUM_OS_NAME} (${FERRUM_FAMILY}, ${FERRUM_ARCH})"

# TODO(scope): download and verify a signed release tarball when the packaging
# work lands (spec §5.5 self-update uses the same minisign verification). Until
# then, install from a locally built --from directory.
[ -n "$SOURCE_DIR" ] || die "pass --from <dir> with the built binaries (release downloads are not wired up yet)"
for binary in "${BINARIES[@]}"; do
  [ -x "$SOURCE_DIR/$binary" ] || die "$SOURCE_DIR/$binary is missing or not executable"
done

# --- 2. service account ----------------------------------------------------
step "Creating the $SERVICE_USER account"
if id -u "$SERVICE_USER" >/dev/null 2>&1; then
  info "already exists"
else
  # A system account with no shell and no login: it exists to own a socket and
  # a database file, not to be signed into.
  useradd --system --user-group --no-create-home \
    --home-dir "$DATA_DIR" --shell /usr/sbin/nologin \
    --comment "Ferrum panel" "$SERVICE_USER" 2>/dev/null ||
    useradd --system --user-group --no-create-home \
      --home-dir "$DATA_DIR" --shell /sbin/nologin \
      --comment "Ferrum panel" "$SERVICE_USER"
  info "created"
fi

# --- 3. layout and binaries ------------------------------------------------
step "Installing to $BIN_DIR"
install -d -m 0755 "$BIN_DIR"
for binary in "${BINARIES[@]}"; do
  install -m 0755 "$SOURCE_DIR/$binary" "$BIN_DIR/$binary"
  info "$binary"
done

# The panel database is root-owned and readable only by the panel account.
install -d -m 0755 "$CONFIG_DIR"
install -d -m 0750 -o "$SERVICE_USER" -g "$SERVICE_USER" "$DATA_DIR"
install -d -m 0750 -o "$SERVICE_USER" -g "$SERVICE_USER" "$DATA_DIR/state"
install -d -m 0750 -o "$SERVICE_USER" -g "$SERVICE_USER" "$LOG_DIR"

# `ferrum` on PATH, without putting our whole bin directory there.
ln -sf "$BIN_DIR/ferrum" /usr/local/bin/ferrum

# --- 4. configuration and secret key ---------------------------------------
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
# passwords (spec §12 rule 6). Generated once and never regenerated — losing it
# means losing the ability to read anything sealed with it.
if [ -f "$CONFIG_DIR/secret.key" ]; then
  info "secret key exists; leaving it alone"
else
  umask 077
  head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' >"$CONFIG_DIR/secret.key"
  chmod 0600 "$CONFIG_DIR/secret.key"
  info "$CONFIG_DIR/secret.key (0600)"
fi

# --- 5. systemd ------------------------------------------------------------
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
[ -S /run/ferrum/agent.sock ] || die "ferrum-agentd did not come up; check: journalctl -u ferrum-agentd"

systemctl enable --now ferrum-web.service
info "ferrum-web started"

# --- 6. first administrator ------------------------------------------------
step "Creating the first administrator"
if [ -z "$ADMIN_EMAIL" ]; then
  ADMIN_EMAIL="admin@$(hostname -f 2>/dev/null || hostname)"
fi

if "$BIN_DIR/ferrum" user list 2>/dev/null | grep -q admin; then
  info "an account already exists; skipping"
else
  "$BIN_DIR/ferrum" user create-admin --username "$ADMIN_USER" --email "$ADMIN_EMAIL"
fi

# --- done ------------------------------------------------------------------
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
