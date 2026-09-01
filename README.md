# Unihelm

A multi-tenant hosting control panel that is small, hard to knock over, and does
not compile PHP on your server.

Two Rust daemons under systemd, one SQLite file, and a React interface embedded
in the binary. No external database, no Node.js on the server, no shell strings
anywhere in the codebase. The full specification is
[`UNIHELM_SPEC_1.md`](UNIHELM_SPEC_1.md).

## Status

**Phase 1 is complete and verified on a real server.** A live AlmaLinux 9.8
box, provisioned entirely through the panel's own API, serves PHP 8.3 over
HTTP/2 with a real Let's Encrypt certificate. The renewal scheduler was
verified the only way that means anything: a certificate forced to twenty days
remaining was renewed unattended — production ACME order, new certificate on
disk, nginx reloaded onto it, the new expiry served to the public internet.

Measured on that box: **18.9 MB combined idle RSS** for both daemons
(via `/proc/*/smaps_rollup`), against an 80 MB budget. Tenant isolation was
proven from inside a tenant's PHP, not asserted: `open_basedir` confined to the
site, `/etc/passwd` unreadable, `/home` unlistable, `shell_exec` absent, and
files written by the pool owned by the tenant.

Live verification also found six bugs that 424 passing tests and clean clippy
could not see — among them nginx serving an expired certificate from memory
after a renewal (the config text is unchanged, so no reload was triggered), and
the distribution's stock PHP-FPM `www` pool quietly providing a second,
unisolated path into PHP. Both are fixed, with regression tests. The details
are in the git log, which is written to be read.

**Phases 2 and 3 are merged and exercised on that same server.** MariaDB 11.8
was installed through the panel's own API, a database created through the API
exists in the engine, a tenant cron job landed in a real crontab, and a restic
backup of the panel ran to a real repository. The [roadmap table](#roadmap)
below is the honest ledger.

Live verification kept earning its place. It found that the panel could not
install MariaDB at all — the repository host it used answers package managers
with 403, and the unit test that should have caught it asserted that broken
host by name and passed the whole time. It found that a successful install left
MariaDB listening on `0.0.0.0:3306` with two anonymous accounts and a shared
`test` database, which on a multi-tenant host is not a wart but an isolation
failure: every tenant's PHP is a local client. It found that the file manager's
recycle bin could never be created, so nothing could be deleted, because
chrooted SFTP deliberately makes the tenant home root-owned. None of those were
reachable from a test suite that runs in a temporary directory without root or
a network.

**Early.** Signed releases exist and the installer downloads them. Every release
is installed and smoke-tested on nine distributions across both families in CI,
and both families have now been exercised on a real server — AlmaLinux 9 and
Ubuntu 24.04. What that does not buy you is age: the panel is young, upgrades
are a re-run of the installer rather than a considered migration path, and the
first four releases each shipped a first-install bug found by somebody
installing it. Read the release notes before you upgrade.

## Why

| Problem with incumbent panels | Unihelm's answer |
|---|---|
| The panel crashes and takes the day with it | Two small crash-only daemons, `Restart=always`, all state in SQLite. Neither daemon is in the serving path: stop both and every site keeps serving. |
| 300–600 MB resident for a control panel | ≤ 80 MB budget for both processes combined, enforced in CI. Measured live: 18.9 MB. |
| Compiling PHP from source on a customer's box | Install from upstream vendor repositories only, GPG-fingerprint-pinned and verified in-process. |
| A root-owned web application | `unihelm-web` runs unprivileged. Everything privileged crosses a Unix socket into a whitelist of typed operations. |
| One admin, no resellers | Admin / reseller / customer, plans and quotas, designed in from day one. |

## Architecture

```
  Browser ── HTTPS ──▶  unihelm-web        user: unihelm, no capabilities
  CLI ────── UDS ────▶   • REST API + SSE
                         • sessions, RBAC, rate limiting
                         • embedded React UI
                                │
                                │  length-prefixed JSON over /run/unihelm/agent.sock
                                │  (0700, SO_PEERCRED-checked on accept)
                                ▼
                        unihelm-agentd     user: root
                         • operation registry — a whitelist, not a dispatcher
                         • task queue and persistent scheduler
                         • package / service / firewall backends
                                │
                                ▼
                        nginx · php-fpm · mariadb · postgresql
```

`unihelm-web` faces the internet and holds nothing. It cannot restart a service,
write a config file, or read a tenant's home directory. When it needs something
done, it names an operation and sends a frame. The agent looks the name up in a
registry, re-derives the caller's rights from the database (ignoring whatever
the frame claimed), deserializes the input into a struct of validated newtypes,
and only then runs it — through argv arrays, never a shell.

The longer story, with references into the code:
[docs/architecture.md](docs/architecture.md).

## Security model

- **A whitelist of operations.** Every privileged action is a named entry in
  one registry (`crates/unihelm-ops/src/registry.rs`). An unknown name is an
  error, not a fallback.
- **No shell, ever.** All process execution is argv arrays through
  `unihelm_distro::Cmd`; `Command::new` exists in exactly one file. A CI gate
  (`tests/gates/no-shell.sh`) proves both.
- **Validated newtypes at every boundary.** A domain, a path, a database name
  or a PHP version is rejected at deserialization or it does not exist —
  `Domain`, `TenantPath`, `DbName`, `LinuxUser`, `PhpVersion`. Free-form
  strings never reach a command line or a SQL identifier.
- **Authorization checked twice.** Once by the web process from the session,
  again by the agent against the same tables. A forged IPC frame can only lose
  privileges.
- **Secrets sealed at rest.** ACME account keys and future credentials are
  encrypted with XChaCha20-Poly1305 under a master key that refuses to load
  from a world-readable file and prints `<redacted>` from its Debug impl.
- **Repository keys pinned by full fingerprint.** OpenPGP packets are parsed
  in-process — no shelling out to gpg — and the fingerprint of the key actually
  downloaded must match the pin before a line is written to `sources.list.d`.
  Short key IDs are rejected as pins; a pin you can collide is decorative.
- **Never clobber a human's edit.** Every generated file carries a content
  hash; a file somebody changed is reported with a diff, never overwritten.
  See [docs/config-safety.md](docs/config-safety.md).

Reporting a vulnerability: [SECURITY.md](SECURITY.md).

## Budgets

The budgets are CI gates (`tests/gates/budgets.sh`), not aspirations. Numbers
below are real measurements, with where they were taken.

| Metric | Budget (spec §3) | Measured |
|---|---|---|
| Idle RSS, both daemons combined | ≤ 80 MB (target 50) | **18.9 MB** on the live AlmaLinux 9.8 server, `/proc/*/smaps_rollup` |
| Binary size, stripped | ≤ 25 MB each | 3.8 / 9.2 / 15.8 MB (`unihelm`, `unihelm-web`, `unihelm-agentd`) with every Phase 1–3 module merged |
| UI initial route, gzipped | ≤ 350 KB | 160 KB (its code editor is a 278 KB lazy chunk, loaded only when a file is opened) |
| Cold start to ready | ≤ 3 s | budget defined; gate not built yet |
| API p95, non-task endpoints | ≤ 150 ms | budget defined; gate not built yet |

## Installing

```bash
curl -fsSL https://raw.githubusercontent.com/farzam-seyedhashem/unihelm/main/installer/install.sh | sudo bash
```

That script is a bootstrap and nothing else: it downloads the latest release's
tarball for your architecture, checks its minisign signature against the key
committed here, and refuses to go on if it cannot. Everything that then runs and
gets installed comes out of that verified tarball — including the installer
itself, which is why reading
[`installer/install.sh`](installer/install.sh) shows you what fetches the release
rather than what the release does. The installer inside the tarball is the same
file at the tag you install.

Pin a version with `UNIHELM_VERSION=v0.1.4`, or point the installer at a fork
with `UNIHELM_REPO=owner/name`.

### From source (works today)

You need stable Rust (`rust-toolchain.toml` pins the channel) and Node 20+ for
the UI build. Build the UI first — `unihelm-web` embeds it at compile time:

```bash
cd ui && npm ci && npm run build && cd ..    # builds into crates/unihelm-web/ui-dist
cargo build --release
```

On a development machine, run the whole panel unprivileged out of a directory:

```bash
mkdir -p /tmp/fd
./target/release/unihelm-agentd --dev /tmp/fd &
./target/release/unihelm user --dev /tmp/fd create-admin \
    --username admin --email admin@example.com     # prints the password once
./target/release/unihelm-web --dev /tmp/fd --listen 127.0.0.1:8088
```

Then open <http://127.0.0.1:8088>.

On a real server (Debian 12/13, Ubuntu 22.04/24.04/26.04, AlmaLinux/Rocky
9/10 — with the caveat from [Status](#status) that only AlmaLinux has been
verified live):

```bash
sudo installer/install.sh --from ./target/release
```

The installer runs a preflight, creates the unprivileged `unihelm` account,
installs the binaries and systemd units, and prints the first administrator's
password once. It installs no stack components — nginx, PHP and databases
arrive on demand from the panel. The full walkthrough is
[docs/operator/install.md](docs/operator/install.md).

## Roadmap

The phases are from spec §14. "Done" means the exit criterion was met, and
says where.

| Phase | Scope | Status |
|---|---|---|
| 0 — Walking skeleton | Two daemons under systemd, privilege boundary, auth, task engine, distro abstraction, CI gates | **Done.** 231 tests at the gate; budgets enforced since. |
| 1 — Web serving core | nginx + vhost engine, PHP versions from Sury/Remi, site CRUD, HTTP-01 certificates, renewal scheduler, panel's own vhost + certificate | **Done.** Site serving, issuance and unattended renewal verified live on AlmaLinux 9.8; the Debian family is implemented and unit-tested but has not run on a real server. Merged since the live run, so not yet live-verified: the panel's own vhost + certificate, and the file manager's UI and API (its privileged `fs.*` backend is still landing). |
| 2 — Multi-tenancy & databases | Tenant isolation, plans, quotas, MariaDB/PostgreSQL, Adminer, cron, DNS + wildcards, SFTP | **Done.** MariaDB installed through the panel on AlmaLinux 9.8 and a database created through the API verified present in the engine; a cron job verified in a real crontab. Also merged: PostgreSQL, Adminer (loopback-only by design), per-tenant cgroup slices, XFS/ext4/du quotas, chrooted SFTP, plans and suspension, Cloudflare DNS with DNS-01 wildcards. The engine is hardened at install — loopback-only, no anonymous accounts, no `test` database — because the first live install proved it needed to be. |
| 3 — Node.js, monitoring, backups | Node apps, reverse proxies, metrics dashboards and alerts, restic-format backups | **Done.** Node apps with a systemd unit per app; alert rules with span-based debounce so a metric flapping at its threshold sends one message, not twenty; restic backups verified by running one — a real snapshot of the panel, taking a consistent database copy through `VACUUM INTO` rather than copying a live WAL file. |
| 4 — App store, WordPress, migration | App store, WP toolkit, cPanel importer, Sentinel brute-force defense, WAF | **Partly done.** Sentinel and the firewall UI surface are merged: firewalld/ufw/nftables backends, managed rules with drift detection, and brute-force banning that ships disabled so a fresh install cannot lock its operator out. WordPress toolkit, app store, cPanel importer and the WAF are in progress. |
| 5 — Email & polish | Mail stack, webmail, white-label, docs site | Not started. |
| 6 — Extensibility | Plugin system (sidecar model), stable public API, multi-server seams | Not started. |

## Layout

```
crates/
  unihelm-core/     domain types, validated newtypes, RBAC, error taxonomy
  unihelm-db/       SQLite schema, migrations, tenant-scoped repositories, sealed secrets
  unihelm-ipc/      the framed protocol between the two daemons
  unihelm-distro/   the only place OS differences live; pinned upstream repositories
  unihelm-config/   templates, and the render/validate/activate/rollback engine
  unihelm-ops/      the operation registry — every privileged action
  unihelm-metrics/  the metrics collector
  unihelm-web/      unprivileged HTTP server + embedded UI   (binary)
  unihelm-agentd/   root daemon: operations, tasks, scheduler (binary)
  unihelm-cli/      `unihelm`                                  (binary)
ui/                React + TypeScript, built into unihelm-web
installer/         preflight, install script, systemd units
tests/gates/       the CI gates that enforce §3 budgets and §12 invariants
docs/              operator, developer and API documentation
```

## Documentation

- [Architecture](docs/architecture.md) — the two-process design, the operation
  registry, and the config contract, with references into the code
- [Configuration safety](docs/config-safety.md) — what happens when you edit a
  generated file
- [Installing](docs/operator/install.md) — a real server, start to finish
- [Error codes](docs/api/errors.md) — generated from the source, drift-checked
  by a test
- [Contributing](CONTRIBUTING.md) — the working agreement
- [Security policy](SECURITY.md) — reporting, and the threat model in brief

## License

[GNU Affero General Public License v3.0](LICENSE) (AGPL-3.0-or-later). If you
run a modified Unihelm for others over a network, they are entitled to your
modifications' source.

Built with [Claude Code](https://claude.com/claude-code). The commit history is
the honest record of what was built, what broke, and what a live server taught
us that the test suite could not.
