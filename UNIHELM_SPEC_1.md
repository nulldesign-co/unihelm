# UNIHELM — Modern Multi-Tenant Hosting Control Panel

> **Master specification for Claude Code.** Read this file fully before writing any code.
> Work phase-by-phase (see §14 Roadmap) and follow the working agreement in §16.
> Codename `unihelm` (Latin for iron — the thing Rust grows on) is a placeholder; renaming it is a find-and-replace, do not block on it.

**Status:** v1.0 spec · August 2026
**Owner:** farzam
**Language of implementation:** Rust (backend) + TypeScript/React (frontend)

---

## 1. Vision

A hosting control panel in the cPanel / aaPanel category that is **light, reliable, modern, and complete**: one small self-contained panel that manages the full hosting stack — Nginx, multiple PHP versions with extensions, MariaDB/MySQL, PostgreSQL, Redis, Node.js apps, SSL, DNS, cron, firewall, backups, monitoring — for **multiple isolated customers on one server**, with a UI that feels like a 2026 product, not 2008.

### 1.1 Why existing panels lose (pain → design answer)

Every architectural decision in this spec traces back to a concrete failure of an existing panel. Keep this table in mind; it is the product's reason to exist.

| Pain (observed) | Where | Unihelm's design answer |
|---|---|---|
| Panel service itself crashes / hangs ("قطعی") | aaPanel | Two small Rust daemons under systemd with `Restart=always` + `WatchdogSec`; panel downtime NEVER affects served sites (Nginx keeps running); crash-only design, all state in SQLite (WAL) |
| High memory usage (Python stack, 300–600 MB) | aaPanel | Rust; hard CI-enforced budget: **web + agent combined ≤ 80 MB RSS idle** (§3) |
| Compiles PHP/Nginx from source → slow installs, breaks on updates | aaPanel | Install ONLY from official upstream repos (Sury/Ondřej, Remi, nginx.org, MariaDB, PGDG, NodeSource) — never compile from source |
| Heavy monolith, everything preinstalled, needs 1 GB+ for the panel alone | cPanel | Base install = the panel binary and nothing else; every stack component is installed on demand from the Stack Manager |
| Ancient UI, jQuery-era UX | cPanel | React 18 + TypeScript + Tailwind + shadcn/ui, dark mode, realtime (SSE), English-only UI (strings centralised behind i18next) |
| Panel edits break user's manual config edits | all | Managed-block config strategy + drift detection + validate-before-reload + auto-rollback (§10.4) |
| Panel is a root-owned web app = giant attack surface | most | Privilege separation: unprivileged web process, root agent behind a typed Unix-socket RPC with a fixed operation whitelist — no shell-string execution anywhere (§5) |
| Locked to one OS family | cPanel (RHEL-ish), CloudPanel (Debian family) | First-class Debian family AND RHEL family via a distro abstraction layer (§7) |
| Single-admin only, no resellers | aaPanel | Full multi-tenant from day one: Admin / Reseller / Customer roles, plans, quotas (§6) |

### 1.2 Competitive positioning (one line each)

- **cPanel/WHM** — feature ceiling to aspire to; avoid its weight, cost, and legacy UI.
- **Plesk** — good multi-OS story; avoid its licensing and bloat.
- **aaPanel/BT-Panel** — good breadth and one-click UX; avoid its instability, memory use, and source-compiling.
- **CloudPanel** — good lightweight feel; it is single-admin-ish and Debian-family-only — we go beyond.
- **HestiaCP/CyberPanel** — free but rough edges and dated internals.
- **Coolify/CapRover** — great for docker apps; useless for classic shared PHP hosting. We do both (hybrid, §8).

### 1.3 Non-goals for v1 (explicit)

- **No built-in mail server** before Phase 5 (§11.18 explains the interim path via Stalwart).
- **No FTP daemon** — chrooted SFTP only (an FTP module may come later if demanded).
- **No Windows support. No OpenVZ-era kernels.** Linux with systemd + cgroups v2 only.
- **No multi-server clustering** in v1 — but the IPC design must not preclude it (§5.4).
- **No billing/invoicing** — expose a clean API + webhooks so WHMCS/FOSSBilling can integrate later.

---

## 2. Product principles

1. **The panel must never be the reason a site is down.** Serving path (nginx→fpm→db) has zero runtime dependency on panel processes.
2. **Small is a feature.** Every dependency, daemon, and resident megabyte must justify itself. Budgets are CI-enforced, not aspirational.
3. **Install from upstream, never compile.** Official vendor repositories give us security updates for free.
4. **Root is earned per-operation, not held by default.** All privileged work goes through a whitelisted, typed operation registry.
5. **Idempotent, journaled, reversible.** Every mutation is a Task with logs; config changes are revisioned and can roll back.
6. **API-first.** The UI and CLI are both clients of the same documented REST API. If it can't be done via API, it doesn't exist.
7. **Respect the sysadmin.** Never destroy manual edits; surface raw configs and logs one click away; provide escape hatches (custom nginx snippets, raw ini overrides).
8. **Multi-tenant honesty.** Isolation is enforced by the OS (users, cgroups, quotas, chroot), not by UI hiding.

---

## 3. Hard constraints & performance budgets (CI-enforced)

| Metric | Budget | How measured |
|---|---|---|
| Panel idle RSS (unihelm-web + unihelm-agentd combined) | ≤ 80 MB (target 50 MB) | integration harness reads `/proc/*/smaps_rollup` after 5 min idle; CI fails over budget |
| Panel cold start to ready | ≤ 3 s | systemd `notify` timestamp |
| Base install time (panel only, no stack) | ≤ 2 min on 1 vCPU / 1 GB VPS | installer e2e test |
| Minimum viable server | 1 GB RAM / 1 vCPU / 10 GB disk | documented + installer preflight check |
| API p95 latency (non-task endpoints) | ≤ 150 ms | k6 smoke in CI |
| UI bundle (gzipped, initial route) | ≤ 350 KB | vite build check |
| Binary size (each daemon, stripped) | ≤ 25 MB | CI check |
| SQLite panel DB after 1y simulated metrics | ≤ 500 MB | rollup/retention test |

Rules that guard the budgets:

- No embedded Chromium, no Electron-ish helpers, no Python/PHP runtime required by the panel itself.
- Metrics collector budget: ≤ 1% of one core average, sampling per §11.11.
- Frontend is static files embedded in the binary (`rust-embed`) — no Node.js at runtime on the server.

---

## 4. Technology stack (decided — do not relitigate)

### 4.1 Backend (Rust, edition 2024, MSRV = latest stable − 2)

| Concern | Choice | Notes |
|---|---|---|
| Async runtime | `tokio` | multi-thread runtime in web, current-thread pools in agent where sensible |
| HTTP framework | `axum` + `tower` middlewares | routing, extractors, SSE |
| Serialization | `serde` / `serde_json` | everywhere, including IPC |
| Panel state DB | SQLite via `sqlx` (WAL mode, `foreign_keys=ON`) | compile-time checked queries; NO external DB dependency for the panel |
| Migrations | `sqlx::migrate!` | forward-only, checked in CI |
| Password hashing | `argon2` (argon2id) | OWASP params |
| TOTP 2FA | `totp-rs` | + recovery codes |
| ACME / Let's Encrypt | `instant-acme` | HTTP-01 + DNS-01; account key in DB, encrypted |
| System metrics | `sysinfo` + direct `/proc`, `/sys/fs/cgroup` reads | keep collector allocation-light |
| Templates (nginx/fpm/systemd configs) | `minijinja` | templates embedded in binary, versioned |
| Docker control | `bollard` (API) + `docker compose` CLI for app stacks | hybrid model §8 |
| Process exec | `tokio::process::Command` with argv arrays | **`sh -c` with interpolated strings is FORBIDDEN repo-wide (clippy lint + CI grep gate)** |
| Logging/tracing | `tracing` + `tracing-subscriber` (json to journald) | request-id propagation across IPC |
| OpenAPI | `utoipa` + `utoipa-swagger-ui` (behind admin flag) | spec generated from code, committed, diffed in CI |
| CLI | `clap` v4 (`unihelm` binary) | talks to the same REST API over UDS |
| Errors | `thiserror` (libs) / `anyhow` (bins) | every API error has a stable machine code (§10.5) |
| Embedded UI | `rust-embed` | single-binary deploy |
| Backups engine | `rustic_core` (restic-format, pure Rust) | fall back to shelling out to `rustic` CLI if the lib API blocks us |
| Archive/compress | `zip`/`tar`/`flate2`/`zstd` crates | file manager + backups |

### 4.2 Frontend

React 18 + TypeScript (strict) + Vite + TailwindCSS + **shadcn/ui** components; TanStack Router + TanStack Query; `react-hook-form` + `zod`; `i18next` with **English only** (strings centralised, a second language stays an import away); dark/light/system theme; xterm.js for web terminal; Monaco editor (lazy-loaded chunk, allowed to exceed initial bundle budget as an async route) for file/config editing; charts with `recharts` (or lightweight `uPlot` for dense metric charts).

Design direction: clean admin aesthetic in the family of Vercel/Linear dashboards — generous whitespace, 8px grid, one accent color, semantic status colors, keyboard palette (⌘K) for navigation, empty states that teach. No skeuomorphic server icons, no 2010 gradients.

### 4.3 Runtime layout on the server

```
/usr/local/unihelm/bin/{unihelm-web, unihelm-agentd, unihelm}   # binaries
/etc/unihelm/config.toml                                     # minimal bootstrap config
/var/lib/unihelm/panel.db                                    # SQLite (0600 root)
/var/lib/unihelm/state/                                      # acme accounts, rendered configs, task logs
/run/unihelm/agent.sock                                      # UDS, 0700, owner unihelm-web user
/var/log/unihelm/                                            # file logs (also journald)
/home/<tenant>/sites/<domain>/{public, logs, tmp, private}  # tenant site layout
```

---

## 5. System architecture

### 5.1 Component diagram

```
                      ┌────────────────────────────── Server ──────────────────────────────┐
  Browser ── HTTPS ──▶│  unihelm-web  (user: unihelm, NO root)                               │
  CLI ────── UDS  ───▶│   • axum REST API + SSE      • sessions, RBAC, rate-limit          │
                      │   • embedded React UI        • reads panel.db (ro + own tables)    │
                      │             │  typed RPC over /run/unihelm/agent.sock               │
                      │             ▼                                                      │
                      │  unihelm-agentd  (root)                                             │
                      │   • operation registry (whitelist)   • task queue + workers        │
                      │   • config renderer + validator      • metrics collector           │
                      │   • pkg backends (apt/dnf)           • scheduler (cron-like)       │
                      │             │ systemd / D-Bus, argv-only exec                      │
                      │             ▼                                                      │
                      │  nginx ─ php-fpm(8.x pools) ─ mariadb ─ postgres ─ redis ─ node    │
                      │  docker (optional, for app-store apps)          ── all systemd ──  │
                      └────────────────────────────────────────────────────────────────────┘
```

**Two processes, hard privilege boundary.** `unihelm-web` runs as an unprivileged system user and can be exposed to the internet. `unihelm-agentd` runs as root, listens ONLY on a Unix socket with strict peer-credential checks (SO_PEERCRED must match the unihelm user), and executes only operations registered in its whitelist.

### 5.2 The operation registry (heart of the security model)

Every privileged action is a named operation with a strict serde-validated input struct, e.g.:

```
site.create        { tenant_id, domain, php_version?, www_alias: bool }
php.install        { version: PhpVersion }            # enum, not free string
php.ext.install    { version, extension: PhpExt }     # enum of vetted extensions
db.mysql.create    { tenant_id, name: DbName }        # DbName = validated newtype
svc.action         { unit: ManagedUnit, action: Start|Stop|Restart|Reload }
fs.op              { tenant_id, op: Read|Write|Chmod|Extract|..., path: TenantPath }
```

Rules:

1. Inputs are **typed newtypes with validation at deserialization** (domain names, db names, paths, versions). Free-form strings never reach a command line.
2. Execution is `Command::new(bin).args([...])` — argv arrays only. A CI grep gate + custom clippy lint forbids `sh -c`, `bash -c`, and format!-into-command patterns.
3. **Tenant-scoped filesystem ops run as the tenant's uid** (agent forks a helper with setuid/setgid to the tenant user), so path escapes hit OS permissions, not just our checks. `TenantPath` additionally canonicalizes and asserts the prefix.
4. Every op call carries an auth context `{actor_user_id, acting_role, tenant_scope}` propagated from the web layer; agentd re-checks authorization (defense in depth) against the same RBAC tables.
5. Every op emits: audit row, task record (if long-running), structured tracing span.

### 5.3 IPC protocol (`unihelm-ipc` crate)

Length-prefixed JSON frames over UDS (debuggable with `unihelm dev ipc-tap`); envelope:

```json
{ "v": 1, "id": "uuid", "op": "site.create", "auth": {…}, "input": {…} }
{ "v": 1, "id": "uuid", "result": "ok|err|task", "data": {…}, "task_id": "…" }
```

Long-running ops return a `task_id` immediately; progress/log lines stream over a separate subscription frame type and are also persisted (§11.17). Version field from day one; unknown fields ignored (forward compat).

### 5.4 Future multi-server note (do not build now)

Keep `unihelm-ipc` transport-abstract (`trait FrameTransport`), so a later `mTLS TcpTransport` turns remote agents into a feature, not a rewrite. No other clustering work in v1.

### 5.5 Reliability mechanics (the anti-aaPanel section)

- Both daemons: systemd units with `Restart=always`, `RestartSec=2`, `WatchdogSec=30` (daemons call `sd_notify` heartbeats), `OOMScoreAdjust=-500` for agentd.
- `unihelm-web` unit hardening: `NoNewPrivileges`, `ProtectSystem=strict`, `PrivateTmp`, `CapabilityBoundingSet=`, RW only its state dirs.
- Crash-only design: no in-memory state that matters; task queue, sessions, scheduler state all in SQLite; on restart, interrupted tasks are re-queued or marked failed-with-reason.
- SQLite in WAL + `synchronous=NORMAL`, single-writer discipline (agentd owns writes to task/metric tables; web owns sessions) to avoid lock contention.
- **agentd owns the schema.** It is the only process that applies migrations, under an exclusive `flock` on `<database>-migrate.lock` held across check-and-apply. `unihelm-web` and the CLI open the database read-only with respect to the schema: they verify it and refuse to start against one they do not recognise, rather than rewriting a root-owned schema from an unprivileged process. The lock is what makes this true where systemd's ordering does not reach — `--dev`, containers, and a CLI command run while the agent is restarting.
- Self-monitoring: agentd watches web (and vice versa via socket ping); a `unihelm doctor` CLI command prints a full health report (units, sockets, db integrity, disk space, cert expiries).
- **Update safety:** self-update downloads the new binary, verifies ed25519 signature (`minisign` format), swaps atomically, restarts one daemon at a time, auto-rolls back if the new version fails its health check within 60 s.

---

## 6. Multi-tenancy model (day one)

### 6.1 Roles & hierarchy

```
Admin (server owner)
 └── Reseller (optional layer; owns Plans it may sell within its own allocation)
      └── Customer (owns Subscriptions; a Subscription = one plan instance holding sites/dbs/apps)
```

- RBAC: `roles` are fixed (admin/reseller/customer) + a granular `permissions` matrix for feature toggles (e.g. customer may/may-not use SSH, cron, Node apps). Admin can impersonate ("login as") any account — always audited.
- Every API object carries `tenant_id`; every query is tenant-scoped by construction (repository layer takes `TenantScope`, not raw ids — make it impossible to forget a WHERE clause).

### 6.2 Plans & quotas

Plan = named bundle of limits + feature flags, owned by admin or reseller:

- disk_mb, inode_count, monthly_bandwidth_mb, site_count, db_count, mailbox_count (future), cron_count, nodejs_app_count, php_workers_max, memory_mb (cgroup), cpu_pct (cgroup), backup_quota_mb, can_ssh, can_docker_apps, allowed_php_versions[].
- Reseller allocation = same fields, aggregate ceiling across everything the reseller provisions. Enforcement math: reseller's customers' plan sums may not exceed the allocation (checked at assign time + nightly reconciliation report).

### 6.3 OS-level isolation (enforcement, not decoration)

| Layer | Mechanism |
|---|---|
| Identity | one Linux user per customer subscription (`uh_<short-id>`), no shell by default (`/usr/sbin/nologin`; `can_ssh` flips to bash with chroot-less but quota'd home) |
| Filesystem | `/home/<user>` mode 0710, group-based FPM access; per-tenant disk quota — **XFS project quotas preferred; ext4 user quotas fallback; `du`-scan nightly as last resort** (installer detects & reports which level you got) |
| PHP | one FPM pool per site, running as the tenant user, `open_basedir` to the site root + tmp, per-plan `pm.max_children`, sane `disable_functions` default (overridable by admin per site) |
| CPU/RAM | one systemd slice per tenant (`unihelm-<user>.slice`) with `MemoryMax`, `CPUQuota`, `TasksMax` from plan; FPM pools and Node app units are placed in the tenant slice |
| Network | per-site nginx rate-limit/conn-limit toggles; bandwidth accounting from access logs (§11.11) |
| SFTP | openssh `Match Group unihelm-sftp` → `ChrootDirectory %h`, `ForceCommand internal-sftp` (panel manages an include file in sshd_config.d) |
| Cron | per-tenant crontab written via `crontab -u`, count-capped by plan; long jobs run inside the tenant slice |
| Node.js | apps run as tenant user, systemd unit in tenant slice, port allocation from a managed range, nginx reverse-proxy vhost |

### 6.4 Suspension & lifecycle

Suspend customer = stop tenant slice, switch vhosts to a branded 403 "suspended" page, disable SFTP/cron/db remote access — one transaction, reversible. Delete = suspend + grace period (configurable, default 7 days) + archived final backup before wipe.

---

## 7. OS support & distro abstraction layer

### 7.1 Support matrix v1 (as of Aug 2026)

| Family | Releases | Arch |
|---|---|---|
| Debian | 12 (bookworm), 13 (trixie) | x86_64, arm64 |
| Ubuntu LTS | 22.04, 24.04, 26.04 | x86_64, arm64 |
| RHEL family | AlmaLinux 9/10, Rocky 9/10 | x86_64, arm64 |

Installer preflight refuses anything else (clear message), including non-systemd or cgroups-v1 systems.

### 7.2 `unihelm-distro` crate — the only place OS differences live

```rust
trait PkgBackend   { install/remove/query/add_repo(GPG-pinned)/update; }   // AptBackend, DnfBackend
trait SvcBackend   { unit lifecycle, enable, status, journald tail; }      // Systemd (both)
trait FwBackend    { open/close port, list, per-ip bans; }                 // FirewalldBackend (RHEL), UfwNftBackend (Debian family)
trait SecModule    { fix contexts / profiles for paths & ports; }          // SelinuxBackend (semanage/restorecon), AppArmorBackend
```

Rules: modules NEVER call apt/dnf/systemctl directly — always through these traits. Adding a distro = implementing traits + CI images, zero module changes.

### 7.3 Upstream repo sources per component

| Component | Debian family | RHEL family |
|---|---|---|
| PHP 7.4 → 8.5 (coexisting; the oldest EOL versions may be unavailable on the newest distro releases — surface what each repo actually offers, per §11.3) | Sury (deb.sury.org) / Ondřej PPA | Remi (php74–php85 SCL-style streams) |
| Nginx (stable) | nginx.org repo | nginx.org repo |
| MariaDB LTS | mariadb.org repo | mariadb.org repo |
| PostgreSQL | PGDG apt | PGDG yum |
| Redis (or Valkey if licensing shifts again — keep the module name generic `kvstore`) | redis.io / distro | Remi/redis.io |
| Node.js LTS lines | NodeSource + per-tenant `fnm` for version pinning | same |
| Docker CE | docker.com repo | docker.com repo |

All repo definitions are GPG-fingerprint-pinned in code; adding a repo is itself an audited operation.

### 7.4 SELinux / AppArmor policy (RHEL is not "best effort")

- Never disable SELinux. The `SecModule` sets booleans/contexts we need (`httpd_unified` off; proper `httpd_sys_content_t` on site roots, custom port contexts for panel + node ports via `semanage port`).
- CI runs the full integration suite on Alma with SELinux **enforcing** — this is the gate that keeps RHEL first-class.

---

## 8. Hybrid service model (native core + docker apps)

**Native (systemd) — the hosting core:** nginx, PHP-FPM (all versions), MariaDB, PostgreSQL, Redis, and tenant Node.js apps. Reason: performance, low overhead, classic shared-hosting semantics, no Docker dependency for the main product.

**Docker (optional) — the app layer:** the App Store (§11.14) installs self-hosted apps (n8n, Uptime Kuma, Ghost, Gitea, Metabase, …) as compose stacks, each bound to 127.0.0.1 ports and published through managed nginx vhosts with SSL. Docker engine itself is installed on demand the first time a docker feature is used. Per-app resources capped via compose `deploy.resources` + a per-tenant docker cgroup parent.

A tenant Node/Python app may ALSO be toggled to "containerized" mode (Dockerfile or nixpacks-style autodetect is **out of scope v1** — v1 containerized mode = user-supplied image or compose file, gated by `can_docker_apps`).

---

## 9. Data model (SQLite — core tables sketch)

Keep names/casing exactly; extend with migrations only.

```
users(id, role, email, username, pass_hash, totp_secret?, status, reseller_id?, created_at, …)
sessions(id, user_id, ip, ua, csrf, expires_at)            api_tokens(id, user_id, name, hash, scopes, last_used)
plans(id, owner_user_id, name, limits_json, features_json)
subscriptions(id, customer_id, plan_id, linux_user, status, suspended_reason?)
sites(id, subscription_id, domain, type: php|node|static|proxy|docker, php_version?, root_dir, status, …)
site_aliases(id, site_id, domain, redirect: bool)
certificates(id, site_id?, kind: le|custom, domains_json, not_after, auto_renew, status)
databases(id, subscription_id, engine: mysql|pg, name, …)  db_users(id, database_id, username, remote_cidrs)
node_apps(id, site_id, runtime_version, start_cmd, env_json, port, instances, status)
cron_jobs(id, subscription_id, schedule, command, enabled)
backups_jobs / backups_targets / backups_snapshots(…restic repo ids, sizes, stats…)
tasks(id, op, input_json, actor_id, tenant_id?, status: queued|running|ok|failed|cancelled, progress, started_at, finished_at)
task_logs(task_id, seq, line)                              audit_log(id, actor, ip, action, target, detail_json, at)
config_revisions(id, path, sha256, rendered_by_task, content_blob, active: bool)
metrics_1m / metrics_1h / metrics_1d (ring tables, per scope: server|service|tenant|site)
alerts_rules / alerts_events / notifier_channels(kind: email|telegram|webhook|slack, config_json)
settings(key, value_json)                                  firewall_rules(id, port, proto, source?, comment, managed_by)
dns_provider_creds(id, user_id, provider, creds_encrypted) app_store_installs(id, subscription_id, app_slug, version, compose_path, status)
webhooks(id, owner_user_id, url, secret, events_json, active, last_delivery_at, failure_count)
```

Encryption at rest for secrets columns (dns creds, smtp passwords, acme keys): libsodium sealed boxes with a master key in `/etc/unihelm/secret.key` (0600, generated at install).

---

## 10. Cross-cutting behaviors

### 10.1 Task engine
Everything slower than ~300 ms is a Task: queued in SQLite, executed by agentd worker pool (default 2 workers + 1 dedicated "fast lane" for service reload/status ops so a stuck install never blocks a restart button). Tasks stream logs live (SSE), are cancellable where safe, retried only when idempotent-marked, and every task ends in a terminal state with a human-readable failure reason. UI shows a global task drawer (like a CI run view).

### 10.2 Scheduler
Internal cron-like scheduler (agentd, persisted): cert renewals, metric rollups, quota scans, backup jobs, bandwidth aggregation, update checks, reconciliation reports. Jitter every schedule to avoid thundering herds.

### 10.3 Audit
Every state-changing API call → `audit_log` (actor, ip, before/after summary). Admin UI: filterable audit browser. Retention configurable (default 180 days).

### 10.4 Config management contract (the "never break my server" rules)
1. Files Unihelm fully owns (rendered vhosts, fpm pools, unit files) live in dedicated include dirs (`/etc/nginx/unihelm.d/…`) and carry a `# UNIHELM-MANAGED sha256:<hash>` header.
2. Before every re-render: hash-check. If a human edited the file, DON'T overwrite — mark site "drifted" in UI and offer diff / adopt / force choices.
3. User escape hatches are first-class fields (per-site custom nginx snippet, per-site php ini overrides) injected into safe include points — so people rarely need manual edits at all.
4. Apply sequence: render to temp → validate (`nginx -t`, `php-fpmX -t`, `named-checkconf` style per service) → atomic move → reload → post-check (service active + test request where possible) → on ANY failure: restore previous revision, reload, mark task failed with the validator output.
5. Every activation stores a `config_revisions` row; UI offers one-click rollback to any revision.

### 10.5 Error taxonomy
Stable machine codes (`FER-1201 domain_already_exists`, …) in every API error + docs page listing all codes. Task failures link to the exact log line span that failed.

---

## 11. Feature modules — detailed spec

Each module below lists: scope, key behaviors, and **acceptance criteria (AC)** that define "done". Build order comes from the roadmap (§14), not from this section's order.

### 11.1 Stack Manager
Install/upgrade/remove stack components from upstream repos with pinned GPG keys. Shows installed vs available versions, disk cost, and per-component status/logs. Component removal refuses while dependents exist (can't remove PHP 8.3 while sites use it).
**AC:** on a fresh minimal VPS of every supported distro, installing nginx + PHP 8.3 + MariaDB via UI completes < 5 min, all services healthy, task logs complete; removing and reinstalling a component is idempotent.

### 11.2 Sites & web server (nginx)
- Site types: **php**, **static**, **node/proxy** (reverse proxy to app port), **docker** (proxy to compose app), **redirect**.
- Per site: primary domain + aliases, www policy, HTTP→HTTPS, HTTP/2 + HTTP/3, per-site `client_max_body_size`, gzip static compression (brotli/zstd only via a **prebuilt dynamic module shipped from our own package repo** — nginx.org packages don't include them and we never compile on the user's server), security headers preset, custom nginx snippet (validated), rate/conn-limit toggles, per-site access/error logs with rotation (logrotate config managed), maintenance-mode toggle, default catch-all server with self-signed cert.
- vhost templates versioned; template upgrades re-render all sites via a migration task with rollback.
**AC:** create/edit/suspend/delete site lifecycle correct on all distros; invalid custom snippet is rejected with `nginx -t` output shown and NO reload happens; concurrent site creations don't corrupt configs (rendering is serialized per service).

### 11.3 PHP manager
- Coexisting versions 7.4–8.5 (as available per family), each with FPM service; per-site version switch = pool re-render + reload, zero-downtime.
- Extension manager per version from vetted list (repo packages only), pecl explicitly out of scope v1.
- Per-site ini overrides (upload size, memory_limit, execution time as first-class fields + free-form validated extra), opcache tuning panel, per-pool status page wiring for metrics.
- Composer binary managed per server; `wp-cli` installed with the WordPress toolkit.
**AC:** two sites on the same server run 8.1 and 8.5 simultaneously; switching a site's PHP version keeps it serving (old pool drained after new one passes health request); `php -v`/pool users/open_basedir verified per tenant in integration tests.

### 11.4 Databases
- Engines: **MariaDB** (default), **PostgreSQL**, **Redis/kvstore** (shared instance, per-tenant ACL users + prefixed keyspace policy; dedicated instances per tenant only via docker app path v1).
- Per engine: create DB + users with host scoping (localhost default; remote access = explicit CIDR + firewall opening in one flow), password reset, size stats, per-DB export (sql.gz) / import, slow-query log surface (admin).
- Root/admin credentials generated at install, stored encrypted, rotatable from UI.
- Web DB browser: **Phase 2 ships Adminer** (single PHP file served on a panel-auth-protected internal path — no Docker dependency, fits the Phase 2 timeline); **phpMyAdmin/pgAdmin become one-click App Store (docker) options in Phase 4**. Don't write our own browser.
**AC:** tenant A can never see/connect to tenant B's DBs (verified by integration test connecting with A's creds); remote-access flow opens exactly the firewall hole requested and closes it on revoke; import of a 1 GB dump streams without OOM.

### 11.5 SSL / certificates
- Let's Encrypt via `instant-acme`: HTTP-01 (webroot) default; **DNS-01 with provider plugins (Cloudflare first, then generic RFC2136, others)** enabling wildcards; multi-domain SAN per site (primary + aliases).
- Auto-renew scheduler at 30 days remaining with backoff + failure alerts (email/telegram) escalating at 14/7/3 days; renew → validate → reload nginx atomically.
- Custom cert upload (chain validation, key match check), self-signed for internal, panel's own cert management (panel port serves LE cert once a domain is pointed, else self-signed).
**AC:** issuance works behind both HTTP-01 and Cloudflare DNS-01 in e2e (staging ACME directory in CI); renewal failure path produces alert + does NOT break the currently served cert; cert store survives restore-from-backup.

### 11.6 Node.js / app runtimes
- Per app: Node LTS line pinned via `fnm` under tenant home, start command, env vars (secret-masked), working dir, instances (N systemd template units), port auto-allocated, websocket-ready proxy vhost, health check URL, log tail, restart policy, deploy hook URL (POST → `git pull`+ build cmd + rolling restart) for simple CI.
- Same framework generalizes later to Python/Ruby ("runtime = trait"), but **v1 ships Node only** — do not build speculative abstraction beyond one trait seam.
**AC:** a sample Next.js app deploys from a git URL, survives reboot (systemd), respects tenant memory cap (OOM kills app, not server, event surfaced in UI), websockets pass through, `fnm` version pin honored.

### 11.7 File manager
- Scoped to tenant home, ALL operations executed as tenant uid (§5.2 rule 3): browse, upload (chunked, resumable, drag-drop), download, copy/move/rename, permissions (safe subset), compress/extract (zip/tar.gz/zst, zip-bomb + path-traversal guarded), Monaco edit with syntax highlight + save-revision, image preview, search by name, recycle bin (per-tenant `.trash`, quota-counted, auto-purge 7d), "open terminal here" (admin or can_ssh only).
**AC:** path traversal attempts (symlinks, `..`, crafted archive entries) land in tests and fail safely; 2 GB upload works via chunking on a 1 GB RAM server; edits create restorable revisions for files < 5 MB.

### 11.8 Cron
Per-subscription cron with schedule builder (+ raw cron string), command run as tenant user inside tenant slice, per-job run history (exit code, duration, tail of output), email/telegram on failure opt-in, plan-capped count.
**AC:** job output captured and truncated safely (10 KB tail); removing subscription removes crontab entries; system crontab untouched.

### 11.9 Firewall & security center
- Firewall page: managed rules (port/proto/source/comment) through `FwBackend`; presets for panel/web/ssh/db ports; "who opened what" from audit.
- Brute-force defense ("Sentinel"): built-in log watcher (journald/auth.log/nginx) with ban policies via nftables/firewalld ipsets — **replaces fail2ban** to avoid the python dependency; ships default jails for sshd, panel login, wp-login/xmlrpc; ban list UI with unban + allowlist.
- Panel access hardening: optional secret URL path, per-account IP allowlist, forced 2FA policy for admins, session device list with revoke.
- Optional per-site WAF (Phase 4): ModSecurity + OWASP CRS via a **prebuilt dynamic nginx module from our own repo** (same no-compile rule as brotli, §11.2); per-site on/off + paranoia level, with a log-only mode first.
- Security advisor: one-page checklist scan (ssh root login?, weak mysql users?, world-writable dirs?, pending security updates?, cert expiries, exposed db ports) with fix-it buttons.
**AC:** 20 failed panel logins from one IP → banned at firewall layer (verified in e2e); firewall changes on RHEL survive `firewalld` reload; advisor findings each link to a fixing action.

### 11.10 Backups & restore
- Engine: restic-format repositories via `rustic_core`; encrypted, deduplicated, compressed.
- Targets: local path, SFTP, **S3-compatible** (AWS/MinIO/Backblaze/ArvanCloud-style endpoints), WebDAV (best effort).
- Scopes & schedules: full-server config+state, per-subscription (home + DBs + panel metadata), per-site, per-DB; retention policies (keep-last/daily/weekly/monthly); bandwidth/IO throttle (ionice/cpu nice + restic limits); pre/post hooks.
- Restore: browse snapshots → restore whole subscription, single site, single DB, or single files (to original or alternate path + "download as archive"); **disaster recovery**: fresh server + `unihelm restore --from <repo>` rebuilds panel state, then re-provisions stack + tenants (this is the ultimate integration test).
- DB dumps: consistent (`--single-transaction` / `pg_dump`), streamed into the repo, never require 2× disk.
**AC:** backup→wipe→restore of a server with 2 tenants, 3 sites, 2 DBs yields working sites (e2e, both distro families); a corrupted target produces alert not silent success; retention prunes verified.

### 11.11 Monitoring, metrics & alerting
- Collector (agentd): 10 s samples → 1 m rollups (RAM ring) → SQLite 1m/1h/1d tables with retention (7d/90d/2y). Scopes: server (cpu/mem/swap/disk io+space/net/load), per managed service (up, mem, restarts), per tenant slice (cpu/mem), per FPM pool (active/idle/slow), per site (req/s, 4xx/5xx, bandwidth from log agg), certs (days left), backups (last success age).
- Dashboard: realtime SSE charts, service tiles with restart buttons, top-tenants by resource, disk pressure forecast (simple linear).
- Alert rules: threshold+duration on any series, plus event alerts (service crashed, cert renew failed, backup failed, disk > x%, ban wave). Channels: email (SMTP), **Telegram bot**, generic webhook, Slack-compatible. Per-channel quiet hours + dedup/cooldown.
- Log viewer: journald units + nginx/php/site logs, follow mode, filter, download.
**AC:** collector overhead ≤ 1% core avg on idle 1 vCPU server; killing mariadb produces alert < 30 s via telegram in e2e; dashboard initial load < 1 s on cold panel with 1y of rolled-up data.

### 11.12 WordPress toolkit (adoption magnet — treat as first-class)
One-click install (latest core, locale incl. fa_IR, db+user auto), clone-to-staging (files+db, URL search-replace, robots off) and push-to-production, auto-update policy per site (core/plugins/themes with safe-hour window + pre-update snapshot), integrity check (`wp core verify-checksums`), maintenance mode, magic admin login (wp-cli created one-time login link), basic hardening toggles (xmlrpc off, editor off), site health card (WP version, PHP version match, cron working).
**AC:** install→stage→edit→push flow e2e; auto-update rolls back automatically when the post-update health request fails.

### 11.13 DNS
- v1: **provider-integration model** — manage records at Cloudflare (+ deSEC/Hetzner/generic RFC2136 later) via stored API creds; template records on site create (A/AAAA/CNAME/CAA) with per-zone review screen; drives DNS-01.
- Own authoritative DNS (PowerDNS pair) = Phase 5, out of v1.
**AC:** creating a site with a Cloudflare-managed zone offers correct record plan and applies it only on confirm; token scopes validated and stored encrypted.

### 11.14 App Store (docker apps)
Curated JSON manifest catalog (in-repo, remotely updatable index): app slug, versions, compose template, required resources, exposed port, health path, env schema (typed prompts), backup paths. Install flow: pick subdomain → panel renders compose to `/var/lib/unihelm/apps/<tenant>/<app>` → up → nginx vhost + SSL → health gate. Lifecycle: upgrade (image pin bump with pre-snapshot), stop/start, logs, uninstall (with volume keep/delete choice). v1 catalog: phpMyAdmin, pgAdmin, Uptime Kuma, n8n, Ghost, Gitea, Metabase, code-server.
**AC:** each catalog app installs to healthy state on a 2 GB test server; uninstall leaves no orphan containers/volumes/vhosts; apps survive reboot.

### 11.15 Migration importers (Phase 4, spec now for data-model compat)
- **From cPanel:** parse `cpmove`/full backup tarballs → homedir files, MySQL dumps, domains/subdomains/aliases → map to subscription+sites+dbs; report unmappables (mail, dns zones) explicitly.
- **From aaPanel:** read its SQLite metadata + `/www/wwwroot` layout + vhost configs → same mapping.
- Dry-run first: show the full plan (what maps, what doesn't) before touching anything.
**AC:** a real cPanel backup of a WP site restores to a serving site with working DB in one flow.

### 11.16 Web terminal & SSH
Admin: full root web terminal (xterm.js ↔ agentd PTY, audited, recordable). Customers: only if `can_ssh`, opens as tenant user. SSH key manager per account (authorized_keys managed block).
**AC:** terminal session survives panel web restart (PTY owned by agentd); every root terminal session start/end is audited.

### 11.17 Tasks & jobs UI
Global task drawer + full task-history page: live streaming logs (SSE), cancel/retry, filter by tenant/op/status/date. Every long op shows staged progress. This is how users *see* the panel working — transparency is the antidote to aaPanel's opaque hangs.
**AC:** a running install's logs stream live and survive a page reload; cancelling a safe-to-cancel task leaves the system consistent; a failed task always shows a human-readable reason linked to the failing log span.

### 11.18 Email (staged — NOT a full MTA in v1)
- **v1 = relay-only:** configure an external SMTP relay (SES/Postmark/Mailgun/self-hosted) so sites can send mail; per-site `sendmail`/PHP `mail()` shim points at the relay; SPF/DKIM/DMARC records surfaced as guidance in the DNS module.
- **Phase 5 (optional module):** integrate **Stalwart** (modern Rust mail server) as the managed full stack (IMAP/JMAP/SMTP, per-tenant mailboxes, webmail via Roundcube/SnappyMail app), chosen over Postfix+Dovecot+SpamAssassin sprawl to keep the memory/ops story consistent with the panel's ethos. Mailbox quotas tie into plans.
**AC:** a WordPress site sends password-reset mail via the configured relay in e2e; DKIM/SPF/DMARC guidance records match the relay in use.

### 11.19 Notifications & branding (reseller-friendly)
- Notifier channels (§11.11) also carry lifecycle events: account created, near quota, cert renewed, backup done/failed, tenant suspended.
- **White-label:** panel name, logo, favicon, login background, support URL, custom login domain + its own cert, per-reseller branding, themable email templates. (cPanel/Plesk charge for this — make it built-in.)
**AC:** a reseller's customers see the reseller's branding end-to-end (login, emails, panel chrome); switching branding requires no restart.

### 11.20 CLI (`unihelm`)
Full automation parity: `unihelm site create`, `unihelm php install 8.4`, `unihelm backup run <sub>`, `unihelm doctor`, `unihelm tenant suspend <id>`, `unihelm db mysql create …`, `unihelm task logs <id> -f`. Talks to the same REST API over the UDS with an admin token; ships shell completions. This is also how power users and the migration tooling script bulk operations.
**AC:** every action available in the UI is reachable from the CLI (dogfood check in CI: CLI drives a full site-create→ssl→backup cycle headless).

---

## 12. Security requirements (repo-wide invariants)

These are gates, not guidelines — CI and code review enforce them.

1. **Privilege separation (§5).** `unihelm-web` never runs as root and never spawns privileged processes; all privileged work crosses the UDS into `unihelm-agentd`. Peer credentials (`SO_PEERCRED`) on the socket must match the `unihelm` user or the frame is rejected.
2. **No shell string execution, anywhere.** `Command` is invoked with argv arrays only. `sh -c`/`bash -c`/`format!`-into-command patterns are blocked by a custom clippy lint **and** a CI grep gate. This kills the entire shell-injection class.
3. **Typed, validated inputs at the boundary.** Every operation input is a newtype validated at deserialization (`Domain`, `DbName`, `TenantPath`, `PhpVersion`, `PhpExt` enums …). Free-form strings never reach a command line or a SQL string.
4. **Authorization checked twice.** `unihelm-web` authorizes via RBAC; `unihelm-agentd` re-checks the same tables against the propagated auth context (defense in depth). The repository layer takes a `TenantScope`, making an un-scoped tenant query impossible to write by accident.
5. **Tenant fs ops run as the tenant uid.** The agent drops to the tenant's uid/gid for filesystem work, so a path-escape bug hits OS permissions, not just our `TenantPath` canonicalization. Archive extraction is zip-bomb + path-traversal guarded.
6. **Secrets at rest are encrypted.** ACME account keys, DNS API creds, SMTP passwords, backup repo keys → libsodium sealed boxes under a master key in `/etc/unihelm/secret.key` (0600, generated at install). Nothing sensitive is logged; secret fields are masked in API responses and audit rows.
7. **Panel auth hardening.** argon2id password hashing (OWASP params), TOTP 2FA + recovery codes, per-IP + per-account rate limiting, CSRF tokens, secure/HttpOnly/SameSite cookies, session pinning + device list with revoke, optional admin IP allowlist and forced-2FA policy.
8. **Network exposure is opt-in.** DB remote access, panel port changes, and any port opening go through the `FwBackend` explicitly and are audited; nothing listens publicly unless a user asked for it. SELinux/AppArmor stay **enforcing** — the `SecModule` sets the minimal contexts/booleans/ports we need, never `setenforce 0`.
9. **Supply chain.** All upstream repos are GPG-fingerprint-pinned in code (adding one is an audited op). `cargo deny` in CI (advisories, licenses, bans, duplicate versions). Self-update binaries are ed25519/minisign-verified before swap, with auto-rollback on failed health check (§5.5).
10. **Everything is audited.** Every state-changing call writes an `audit_log` row (actor, ip, action, before/after summary); admin impersonation ("login as") and any root terminal session are always audited. Retention configurable (default 180 days).

**Verification duties:** each new operation gets a threat note in its PR; the integration suite includes negative tests (path traversal, cross-tenant access, injection payloads, privilege boundary) that must fail-safe; a periodic dependency + CVE scan runs in CI.

## 13. API & extensibility

- **REST API** (OpenAPI 3.1 generated from code via utoipa) is the ONLY way the UI and CLI talk to the backend — dogfood it. Token auth (scoped), full CRUD for every resource, task polling + SSE streams, pagination/filtering conventions, idempotency keys on create ops.
- **Webhooks** for events (site.created, cert.renewed, backup.failed, quota.exceeded, tenant.suspended…) so billing systems (WHMCS/FOSSBilling/Blesta) and automation can react. HMAC-signed payloads.
- **Plugin system (Phase 6, design the seams now):** app-store manifests are the first extension point. A future plugin can register: new app definitions, new DnsProvider/BackupTarget/notifier implementations (via a stable ABI or a sidecar-process + IPC contract — sidecar preferred for isolation and to keep the core small), and UI panels (micro-frontend mount points). Do NOT let plugins run in-process as root. Keep the core lean; plugins are how breadth grows without bloating the base (the anti-cPanel principle).

---

## 14. Roadmap (phased — each phase ships something usable & is a natural Claude Code milestone)

> Guiding rule: **reach a real, deployable single-server PHP host as early as possible (end of Phase 2)**, then widen. Never let the tree get so big it can't run.

### Phase 0 — Foundations & skeleton (the walking skeleton)
Repo/workspace layout (§15), the two daemons booting under systemd, `unihelm-ipc` with 2–3 trivial ops (ping, `svc.status`, `metrics.snapshot`), SQLite + first migrations, auth (login, argon2, sessions, one admin user via installer), RBAC scaffolding, the operation-registry pattern + the CI gates (no-`sh -c`, RSS budget, binary size), `unihelm-distro` traits with Apt+Dnf+Systemd implemented, base installer script + preflight, embedded React shell with login + empty dashboard + task drawer + i18n(en)/theming wired. **Exit:** you can log in on Debian 13 and AlmaLinux 10 and see live server metrics; CI enforces budgets.

### Phase 1 — Web serving core
Nginx backend + vhost renderer + config-management contract (§10.4), PHP module (install versions from Sury/Remi, FPM pools per site), site CRUD (php/static types), file manager, SSL via instant-acme (HTTP-01), basic per-site settings & logs. **Exit:** create a PHP site with SSL and serve real traffic, entirely from the UI, on both distro families.

### Phase 2 — Multi-tenancy & databases (→ first real product)
Linux-user-per-tenant, tenant slices (cgroup limits), quotas (XFS project/ext4/du detection), SFTP chroot, plans & subscriptions, MariaDB + PostgreSQL modules, db/user management, Adminer, suspension lifecycle, cron module, DNS advisory + Cloudflare provider (+ DNS-01 wildcards). **Exit:** a reseller can create a customer on a plan, who creates a PHP+MySQL site with wildcard SSL, isolated and quota'd. **This is the first version worth deploying for real.**

### Phase 3 — Node.js, monitoring, backups
Node.js apps (systemd unit per app, port mgmt, reverse-proxy vhosts, version pinning), reverse-proxy site type, monitoring/metrics + dashboards + alerts + notifier channels, backups (restic engine, local + S3 + B2, schedules, restore, panel DR). **Exit:** run a Node app behind SSL next to PHP sites; scheduled encrypted offsite backups with tested restore; get alerted before disks fill or certs expire.

### Phase 4 — App Store, WordPress toolkit, migration, hardening
App Store (native + docker apps), WordPress toolkit (staging/clone/WP-CLI/updates), cPanel importer (+ aaPanel/Plesk best-effort), firewall UI + Sentinel brute-force defense (§11.9), security dashboard, optional ModSecurity WAF (prebuilt module). **Exit:** a shared-hosting company can migrate cPanel accounts in and run WordPress hosting at parity.

### Phase 5 — Email & polish
Email relay module → optional full Stalwart mail stack + webmail + mailbox plans, self-hosted authoritative DNS (PowerDNS) option (§11.13), white-label/branding, email templating, quality-of-life passes across every module, docs site, performance hardening against the budgets under load. **Exit:** feature-comparable to mainstream panels for a typical hosting business, still within the memory budget.

### Phase 6 — Extensibility & scale seams
Plugin system (sidecar model), webhooks maturity, public API stability guarantee + versioning, `mTLS TcpTransport` groundwork for future multi-server, marketplace for app manifests. **Exit:** third parties can extend Unihelm without patching the core.

### Ongoing (every phase, not a final step)
Security review of each new operation, docs for each feature as it lands, e2e tests on all supported distros in CI, budget regression checks, accessibility pass on new UI.

## 15. Repository & workspace layout (Cargo workspace)

```
unihelm/
├─ Cargo.toml                 # workspace
├─ crates/
│  ├─ unihelm-core/            # domain types, newtypes, RBAC, plan math, error taxonomy
│  ├─ unihelm-db/              # sqlx models, migrations, repositories (TenantScope-based)
│  ├─ unihelm-ipc/             # frame protocol, transport trait, client + server halves
│  ├─ unihelm-distro/          # PkgBackend/SvcBackend/FwBackend/SecModule + impls
│  ├─ unihelm-ops/             # the operation registry: each privileged op + typed input
│  ├─ unihelm-config/          # minijinja templates + render/validate/activate/rollback engine
│  ├─ unihelm-metrics/         # collector + rollups
│  ├─ unihelm-backup/          # rustic wrapper
│  ├─ unihelm-web/             # axum app, REST API, SSE, auth, embedded UI  (BINARY, unprivileged)
│  ├─ unihelm-agentd/          # root daemon: registry executor, task queue, scheduler (BINARY, root)
│  └─ unihelm-cli/             # `unihelm` (BINARY)
├─ ui/                        # React/TS/Vite app → built into unihelm-web via rust-embed
├─ installer/                 # bootstrap script + preflight + systemd units + repo definitions
├─ packaging/                 # .deb + .rpm build (cargo-deb / cargo-generate-rpm), signing
├─ tests/                     # e2e harness (spins distro containers/VMs), budget checks, k6
├─ docs/                      # mdBook: user, admin, api, operator, contributing
└─ .github/workflows/         # CI: build, clippy(+custom lints), test-matrix(distros×SELinux), budgets
```

Testing expectations: unit tests in every crate; `unihelm-ops` gets a mock distro backend so ops are testable without root; integration harness runs the real thing in throwaway containers/VMs per distro; every bug fixed gets a regression test.

## 16. Working agreement for Claude Code (read every session)

1. **Follow the phases.** Do not start Phase N+1 modules before Phase N's exit criteria pass. Keep `main` deployable.
2. **Security invariants are non-negotiable:** no `sh -c`/string-interpolated commands anywhere; all privileged work goes through `unihelm-ops` with typed, validated inputs; web process never runs as root; agentd re-checks authorization; tenant fs ops run as the tenant uid.
3. **Respect the budgets (§3).** If a change blows the RSS/binary/bundle budget, fix it before merging — the whole point of this project is to beat the incumbents on weight.
4. **Config safety contract (§10.4) applies to every file the panel writes.** Validate before reload; keep revisions; roll back on failure; never clobber human edits silently.
5. **API-first & idempotent.** New capability = new typed op + REST endpoint + CLI verb + audit + task (if slow) + tests + docs, in that spirit. UI consumes only the public API.
6. **Distro differences live ONLY in `unihelm-distro`.** Modules must be OS-agnostic. Test on both families (SELinux enforcing on RHEL) before calling a feature done.
7. **Every mutation:** typed input → validate → task/log → audit → reversible where possible. Every API error: stable code.
8. **Ask before inventing scope.** If a requirement here is ambiguous, prefer the smallest thing that satisfies the phase exit criteria and leave a `// TODO(scope):` note rather than gold-plating. The enemy is bloat.
9. **i18n hygiene and accessibility are not afterthoughts** — new UI keeps every string behind `t()` in `en.ts` and ships with keyboard access.
10. **Document as you go** in `docs/` and keep the OpenAPI spec + error-code list current in the same PR as the code.

## 17. Open questions to resolve with farzam (before/near the relevant phase)

- Final product name & license (AGPL/open-core/source-available?) — affects branding module and community strategy.
- Panel access model default: subdomain+own-cert vs. IP:port vs. path — pick a secure sane default for the installer.
- Which DNS provider after Cloudflare is priority #2? (affects Phase 2/4)
- App Store curation policy & who signs manifests.
- Telemetry: opt-in anonymous usage stats? (helps prioritize; must be clearly optional.)
- Target "first design partner" (a small host willing to migrate) to validate Phase 2/4 against reality.

---

*End of specification. Build small, build safe, ship each phase. The product wins by being the panel that doesn't fall over, doesn't eat the RAM, installs from real repos, and looks like it belongs in 2026.*
