# Installing Ferrum

## What you need

| | |
|---|---|
| OS | Debian 12/13, Ubuntu 22.04/24.04/26.04, AlmaLinux or Rocky 9/10 |
| Arch | x86_64 or aarch64 |
| RAM | 1 GB minimum |
| Disk | 10 GB free on `/var` |
| Other | systemd, cgroups v2 |

Check a candidate server before committing to it:

```bash
sudo bash installer/preflight.sh
```

It reports every problem it finds rather than stopping at the first, and warns
about things that will work but are worth knowing — a 1 GB box, another control
panel already installed, Apache running on port 80.

## Installing

```bash
sudo installer/install.sh                        # the latest release
sudo FERRUM_VERSION=v0.4.1 installer/install.sh  # a pinned one
```

That downloads the release built for this machine's architecture, verifies it,
and installs it. No Rust toolchain, no twenty-minute build, no 2 GB of build
artefacts on a 1 GB VPS.

The installer:

1. runs preflight and refuses an unsupported system,
2. downloads the tarball, `SHA256SUMS` and `SHA256SUMS.minisig`,
3. verifies the minisign signature on `SHA256SUMS` against the key built into
   the installer, then checks the tarball against that signed file,
4. creates the unprivileged `ferrum` account,
5. installs three binaries into `/usr/local/ferrum/bin`,
6. writes `/etc/ferrum/config.toml` and generates `/etc/ferrum/secret.key`,
7. installs and starts both systemd units,
8. creates the first administrator and prints its password **once**.

Step 3 has no override. There is no `--skip-verify`, and installing minisign is
not optional — if the signature cannot be checked, nothing is installed. If you
would rather not trust a binary at all, build one; that path is below and it
downloads nothing.

It installs no stack components. Nginx, PHP and databases arrive on demand from
the panel, which is what keeps a base install small enough for a 1 GB VPS.

### Building from source instead

For an architecture we do not publish, for development, or because you would
rather compile:

```bash
sudo installer/install.sh --from-source
```

That builds the UI and the binaries here and then runs exactly the same
installation steps. If you have already built:

```bash
cargo build --release
cd ui && npm ci && npm run build && cd ..
cargo build --release -p ferrum-web    # embeds the built UI

sudo installer/install.sh --from ./target/release
```

### Installing from a fork

`FERRUM_REPO` chooses the repository releases come from and `FERRUM_PUBKEY` the
minisign public key they must be signed with. Both are needed: an installer
whose key is still the release-time placeholder refuses to download anything,
precisely so that a fork cannot end up skipping verification by omission. See
[packaging/README.md](../../packaging/README.md) for how a release is signed.

## First login

The panel listens on `127.0.0.1:8088` by default. That is deliberate: a brand
new panel should not be reachable from the internet before you have decided it
should be. Reach it over an SSH tunnel:

```bash
ssh -L 8088:127.0.0.1:8088 root@your-server
```

Then open <http://127.0.0.1:8088>.

To expose it directly, set `listen` in `/etc/ferrum/config.toml` and restart
`ferrum-web`. Leave `secure_cookies = true` and put TLS in front of it — with
`secure_cookies` off, a session cookie can cross an unencrypted hop.

## Checking on it

```bash
ferrum doctor          # config, database, agent, disk — exits non-zero on failure
ferrum status          # cpu, memory, disk, uptime
journalctl -u ferrum-agentd -u ferrum-web -f
```

`ferrum doctor` is safe to run from cron: warnings (Docker not installed, a
small disk) exit 0, and only real failures exit 1.

## If the panel is down

Your sites are not. Nginx, PHP-FPM and the databases are ordinary systemd units
with ordinary configuration files, and neither Ferrum process is in the serving
path. A panel outage is an inconvenience for you, not for the people visiting
the sites you host.

```bash
systemctl status ferrum-agentd ferrum-web
journalctl -u ferrum-agentd -n 100 --no-pager
ferrum doctor
```

The agent is the one to check first: `ferrum-web` will serve the interface and
report the agent as unreachable, so a working panel that cannot do anything
privileged means the agent, not the web process.

## Files

```
/usr/local/ferrum/bin/       ferrum-agentd, ferrum-web, ferrum
/etc/ferrum/config.toml      bootstrap configuration
/etc/ferrum/secret.key       master key for secrets at rest (0600, back this up)
/var/lib/ferrum/panel.db     all panel state
/var/lib/ferrum/state/       rendered configs, ACME account keys, task artefacts
/run/ferrum/agent.sock       the privilege boundary (0700, owned by `ferrum`)
/var/log/ferrum/             file logs (also in journald)
```

`secret.key` is generated once and never regenerated. Losing it means losing the
ability to read anything sealed with it — ACME account keys, DNS credentials,
backup repository passwords. Back it up somewhere other than this server.

## Uninstalling

```bash
sudo systemctl disable --now ferrum-web ferrum-agentd
sudo rm -f /etc/systemd/system/ferrum-{web,agentd}.service
sudo systemctl daemon-reload
sudo rm -rf /usr/local/ferrum /usr/local/bin/ferrum
# Keep these until you are certain: they hold every account and setting.
# sudo rm -rf /etc/ferrum /var/lib/ferrum /var/log/ferrum
# sudo userdel ferrum
```
