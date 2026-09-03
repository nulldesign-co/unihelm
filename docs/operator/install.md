# Installing Unihelm

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
sudo UNIHELM_VERSION=v0.1.4 installer/install.sh  # a pinned one
```

That downloads the release built for this machine's architecture, verifies it,
and installs it. No Rust toolchain, no twenty-minute build, no 2 GB of build
artefacts on a 1 GB VPS.

The installer:

1. runs preflight and refuses an unsupported system,
2. downloads the tarball, `SHA256SUMS` and `SHA256SUMS.minisig`,
3. verifies the minisign signature on `SHA256SUMS` against the key built into
   the installer, then checks the tarball against that signed file,
4. creates the unprivileged `unihelm` account,
5. installs three binaries into `/usr/local/unihelm/bin`,
6. writes `/etc/unihelm/config.toml` and generates `/etc/unihelm/secret.key`,
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
cargo build --release -p unihelm-web    # embeds the built UI

sudo installer/install.sh --from ./target/release
```

### Installing from a fork

`UNIHELM_REPO` chooses the repository releases come from and `UNIHELM_PUBKEY` the
minisign public key they must be signed with. Both are needed: an installer
whose key is still the release-time placeholder refuses to download anything,
precisely so that a fork cannot end up skipping verification by omission. See
[packaging/README.md](../../packaging/README.md) for how a release is signed.

## First login

The installer prints the address when it finishes. It is the server's own:

```
Panel     https://203.0.113.7:8088
```

Your browser will warn that the certificate is not trusted, and it is right —
the panel generated its own on first start, because a server with no domain has
nothing a certificate authority can vouch for. The connection is encrypted
regardless, which is the part that keeps your password off the wire. Click
through the warning.

Log in with the username the installer created and the password it printed once.

### Giving it a real certificate

Point a domain at the server and issue one:

```bash
sudo unihelm cert panel panel.example.com
```

nginx then fronts the panel on 443 with a Let's Encrypt certificate, renews it
on schedule, and the browser warning goes away.

### If you would rather it were not reachable

Set `listen = "127.0.0.1:8088"` in `/etc/unihelm/config.toml`, restart
`unihelm-web`, and reach it over an SSH tunnel:

```bash
ssh -L 8088:127.0.0.1:8088 <your-login>@your-server
```

### What not to do

Do not set `tls = "off"` while the panel is on a public address. That serves the
login form over plain HTTP, where anyone on the network path can read the
password you type. It is there for the case where something else terminates TLS
in front of the panel and sets `X-Forwarded-Proto` — which is what
`unihelm cert panel` sets up, and it turns `tls` off for you.

Do not turn off `secure_cookies` either. Off loopback the session cookie is
marked `Secure` so a browser will not return it over plain HTTP, and the tempting
fix — switching the flag off — puts the session cookie on an unencrypted hop,
which is the thing it exists to prevent. Serving TLS is the fix.

## Checking on it

```bash
sudo unihelm doctor     # config, database, agent, panel, disk — exits non-zero on failure
unihelm status          # cpu, memory, disk, uptime
journalctl -u unihelm-agentd -u unihelm-web -f
```

`unihelm doctor` is safe to run from cron: warnings (Docker not installed, a
small disk) exit 0, and only real failures exit 1.

## If the panel is down

Your sites are not. Nginx, PHP-FPM and the databases are ordinary systemd units
with ordinary configuration files, and neither Unihelm process is in the serving
path. A panel outage is an inconvenience for you, not for the people visiting
the sites you host.

```bash
systemctl status unihelm-agentd unihelm-web
journalctl -u unihelm-agentd -n 100 --no-pager
sudo unihelm doctor
```

The agent is the one to check first: `unihelm-web` will serve the interface and
report the agent as unreachable, so a working panel that cannot do anything
privileged means the agent, not the web process.

## Files

```
/usr/local/unihelm/bin/       unihelm-agentd, unihelm-web, unihelm
/etc/unihelm/config.toml      bootstrap configuration
/etc/unihelm/secret.key       master key for secrets at rest (0600, back this up)
/var/lib/unihelm/panel.db     all panel state
/var/lib/unihelm/state/       rendered configs, ACME account keys, task artefacts
/run/unihelm/agent.sock       the privilege boundary (0700, owned by `unihelm`)
/var/log/unihelm/             file logs (also in journald)
```

`secret.key` is generated once and never regenerated. Losing it means losing the
ability to read anything sealed with it — ACME account keys, DNS credentials,
backup repository passwords. Back it up somewhere other than this server.

## Uninstalling

Removing the panel is not the same as removing what it rendered. The nginx
includes, the PHP-FPM pool files and the logrotate files stay behind, and they
name the certificates, the WAF rules and the log directories that live under
`/var/lib/unihelm` and `/var/log/unihelm`. nginx opens all of those at
configuration load, so deleting them under a running nginx changes nothing until
the next reload, reboot or package upgrade — and then every site on the server
fails to come back, with the panel that could have explained it already gone.
So the rendered configuration comes out first, and only then the state.

```bash
sudo systemctl disable --now unihelm-web unihelm-agentd
sudo rm -f /etc/systemd/system/unihelm-{web,agentd}.service
sudo systemctl daemon-reload
sudo rm -rf /usr/local/unihelm /usr/local/bin/unihelm
```

Now the serving path. After this nginx and PHP-FPM know nothing about Unihelm,
and the sites it was serving are gone with it:

```bash
sudo rm -f /etc/nginx/conf.d/unihelm.conf
sudo rm -f /etc/nginx/unihelm.d/*.conf
sudo rm -f /etc/logrotate.d/unihelm-*
sudo rm -f /etc/php/*/fpm/pool.d/unihelm-*.conf         # Debian, Ubuntu
sudo rm -f /etc/opt/remi/php*/php-fpm.d/unihelm-*.conf  # AlmaLinux, Rocky
sudo nginx -t && sudo systemctl reload nginx
```

Reload the PHP-FPM unit for each PHP version you had installed as well —
`php8.3-fpm` on Debian and Ubuntu, `php83-php-fpm` on AlmaLinux and Rocky.

Once `nginx -t` passes with those files gone, nothing on the server references
what is left:

```bash
# Only when you are certain. This is every account and setting, every
# certificate the panel ever issued together with the ACME account keys that
# would have renewed them, and the log directories the configuration above was
# writing into.
# sudo rm -rf /etc/unihelm /var/lib/unihelm /var/log/unihelm
# sudo userdel unihelm
```
