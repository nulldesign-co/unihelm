# Ferrum

A multi-tenant hosting control panel that is small, hard to knock over, and does
not compile PHP on your server.

Two Rust daemons under systemd, one SQLite file, and a React interface embedded
in the binary. The full specification is [`FERRUM_SPEC_1.md`](FERRUM_SPEC_1.md).

**Status: Phase 0 (walking skeleton).** Both daemons run, the privilege boundary
works, and the panel serves a live dashboard. No stack components — nginx, PHP,
databases — are managed yet; that is Phase 1.

## Why

| Problem | Answer |
|---|---|
| The panel service itself crashes and takes the day with it | Two small daemons, `Restart=always`, watchdog, all state in SQLite. Panel downtime never touches nginx. |
| 300–600 MB resident for a control panel | ≤ 80 MB for both processes combined, enforced in CI. |
| Compiling PHP from source on a customer's box | Install from upstream vendor repositories only, GPG-fingerprint-pinned. |
| A root-owned web application | `ferrum-web` runs unprivileged. Everything privileged crosses a Unix socket into a whitelist of typed operations. |
| One admin, no resellers | Admin / reseller / customer, plans and quotas, from day one. |

## Quick start

Development, on any machine with Rust and Node:

```bash
cargo build
cd ui && npm install && npm run build && cd ..
cargo build -p ferrum-web            # embeds the built UI

mkdir -p /tmp/fd
./target/debug/ferrum-agentd --dev /tmp/fd &
./target/debug/ferrum user --dev /tmp/fd create-admin \
    --username admin --email admin@example.com     # prints the password once
./target/debug/ferrum-web --dev /tmp/fd --listen 127.0.0.1:8088
```

Then open <http://127.0.0.1:8088>.

On a real server (Debian 12/13, Ubuntu 22.04/24.04/26.04, AlmaLinux/Rocky 9/10):

```bash
cargo build --release
sudo installer/install.sh --from ./target/release
```

## Layout

```
crates/
  ferrum-core/     domain types, validated newtypes, RBAC, error taxonomy
  ferrum-db/       SQLite schema, migrations, tenant-scoped repositories
  ferrum-ipc/      the framed protocol between the two daemons
  ferrum-distro/   the only place OS differences live
  ferrum-ops/      the operation registry — every privileged action
  ferrum-metrics/  the metrics collector
  ferrum-web/      unprivileged HTTP server + embedded UI   (binary)
  ferrum-agentd/   root daemon: operations, tasks, scheduler (binary)
  ferrum-cli/      `ferrum`                                  (binary)
ui/                React + TypeScript, built into ferrum-web
installer/         preflight, install script, systemd units
tests/gates/       the CI gates that enforce §3 budgets and §12 invariants
docs/              operator, developer and API documentation
```

## The rules this codebase is held to

1. **No shell, ever.** Commands are argv arrays. A CI gate proves it.
2. **`Command::new` lives in exactly one file.** Everything else uses
   `ferrum_distro::Cmd`.
3. **Inputs are validated newtypes**, not strings — a domain, a database name or
   a path is rejected at deserialization or it does not exist.
4. **Authorization is checked twice**: once by the web process, once by the agent
   against the same tables.
5. **Budgets are gates.** Binary size, bundle size and idle memory fail the build.

See [`docs/developer/contributing.md`](docs/developer/contributing.md).

## Documentation

- [Architecture](docs/architecture.md) — the two-process design and why
- [Installing](docs/operator/install.md) — a real server, start to finish
- [Error codes](docs/api/errors.md) — generated from the source
- [Contributing](docs/developer/contributing.md) — the working agreement

## Licence

AGPL-3.0-or-later. (Provisional — see spec §17.)
