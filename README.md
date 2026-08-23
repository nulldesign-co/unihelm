# Ferrum

A multi-tenant hosting control panel that is small, hard to knock over, and does
not compile PHP on your server.

Two Rust daemons under systemd, one SQLite file, and a React interface embedded
in the binary. The full specification is [`FERRUM_SPEC_1.md`](FERRUM_SPEC_1.md).

**Status: Phase 1 in progress.** Both daemons run, the privilege boundary works,
and the panel installs nginx and PHP from pinned upstream repositories, creates
PHP sites with their own Linux account and FPM pool, and issues Let's Encrypt
certificates over HTTP-01 — all from the UI.

Not yet: the file manager, the renewal scheduler, and the panel's own vhost.
Databases and multi-tenancy are Phase 2. Nothing has been run on a real Debian
or AlmaLinux server yet — the CI matrix that would prove it is written but has
never executed.

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
  ferrum-db/       SQLite schema, migrations, tenant-scoped repositories, sealed secrets
  ferrum-ipc/      the framed protocol between the two daemons
  ferrum-distro/   the only place OS differences live; pinned upstream repositories
  ferrum-config/   templates, and the render/validate/activate/rollback engine
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
6. **Never clobber a human's edit.** Generated files carry a hash header; a file
   somebody changed is reported with a diff, not overwritten.
7. **Repository keys are pinned by full fingerprint**, verified against the key
   actually downloaded, before anything is written to `sources.list.d`.

See [`docs/developer/contributing.md`](docs/developer/contributing.md).

## Documentation

- [Architecture](docs/architecture.md) — the two-process design and why
- [Configuration safety](docs/config-safety.md) — what happens when you edit a generated file
- [Installing](docs/operator/install.md) — a real server, start to finish
- [Error codes](docs/api/errors.md) — generated from the source
- [Contributing](docs/developer/contributing.md) — the working agreement

## Licence

AGPL-3.0-or-later. (Provisional — see spec §17.)
