# Wave 1 — parallel implementation contracts

You are one of ~23 agents working on Ferrum in parallel, each in your own git
worktree branched from the same commit. This file is the coordination contract.
Deviating from it creates merge conflicts for everyone else, so read it before
writing anything.

## Ground rules (non-negotiable)

1. **No shell strings.** All process execution is argv arrays via
   `ferrum_distro::Cmd`. `sh -c`, `bash -c`, `Command::new("sh")` are forbidden
   repo-wide and CI greps for them (`tests/gates/no-shell.sh` — run it).
2. **Never touch a remote server.** No ssh, no scp. The integrator owns the
   live test box.
3. **Never `git push`, never merge, never touch `main`.** Commit your work to
   the branch you are on (named `agent/<your-slug>`); the integrator merges.
4. **Stay in your lane.** Only create/modify the files your task names, plus the
   shared insertion points below. Do not "fix" another module in passing — note
   it in your report instead.
5. **Builds:** use `export PATH="/opt/homebrew/opt/rustup/bin:$PATH"` and
   `export CARGO_TARGET_DIR=/Users/farzamseyedhashem/Documents/Projects/panel-server/target`
   (shared cache — disk is tight; a private target dir per worktree would fill
   the disk). Concurrent cargo invocations queue on a lock; that is expected.
   Test only your own crate: `cargo test -p <crate>`; finish with
   `cargo clippy -p <crate> --all-targets -- -D warnings`.
6. **Comment style:** comments explain *why*, cite spec sections (`spec §11.7`),
   and read like the surrounding code. Look at `crates/ferrum-ops/src/cert.rs`
   or `crates/ferrum-db/src/scheduler.rs` for the register.
7. **Tests are part of the deliverable.** Behavior tests with meaningful names
   (`a_failed_site_can_be_tried_again_on_the_same_domain` style). Security
   claims get hostile-input tests.
8. **Secrets:** never log or store one in the clear. Sealed secrets go through
   `ferrum_db::MasterKey` (XChaCha20-Poly1305) like the ACME account does.

## Shared insertion points (additive edits allowed)

| File | What you may do |
|---|---|
| `crates/ferrum-ops/src/lib.rs` | add your `pub mod <name>;` line (alphabetical) |
| `crates/ferrum-ops/src/registry.rs` | add `registry.register(...)` lines at the end of the existing block |
| `crates/ferrum-web/src/routes/mod.rs` | add your `pub mod`, and routes at the end of `protected()` |
| `crates/ferrum-db/src/lib.rs` | add your `pub mod` / `pub use` lines |
| `Cargo.toml` (workspace) | add new deps to `[workspace.dependencies]`, alphabetical; pin a version |
| `crates/*/Cargo.toml` | add `x = { workspace = true }` lines |
| `crates/ferrum-core/src/error.rs` | new `ErrorCode` variants **at the end of the enum only**; prefer existing codes; regenerate docs if the sync test tells you to |
| `crates/ferrum-core/src/rbac.rs` | Permission variants already exist for every wave-1 feature — use them, do not add |
| `ui/src/router.tsx`, `ui/src/i18n/{en,fa}.ts` | additive entries only |

## Allocations (do not take another task's number/name)

Migrations (`crates/ferrum-db/migrations/`):
`0005_databases.sql` db-mgmt · `0006_plans.sql` plans-suspension ·
`0007_cron.sql` cron · `0008_dns.sql` dns-cloudflare · `0009_backups.sql`
backups · `0010_node_apps.sql` node-apps · `0011_monitoring.sql` monitoring ·
`0012_sentinel.sql` sentinel-fw · `0013_quotas.sql` quotas

Operation names (spec §5.2 style, registered in the op registry):
- fsops-backend: `fs.list fs.stat fs.read fs.write fs.mkdir fs.rename fs.copy
  fs.delete fs.chmod fs.search fs.compress fs.extract fs.trash.list
  fs.trash.restore fs.trash.purge fs.usage`
- db-mgmt: `db.list db.create db.drop db.user.create db.user.drop
  db.user.password db.grant`
- cron: `cron.list cron.set cron.delete`
- dns-cloudflare: `dns.check dns.provider.set cert.issue_wildcard`
- backups: `backup.repo.init backup.run backup.list backup.restore`
- node-apps: `app.create app.delete app.restart app.logs`
- quotas: `quota.set quota.usage`
- sftp-chroot: `sftp.enable sftp.disable`
- plans-suspension: `plan.create plan.update plan.delete plan.assign
  subscription.suspend subscription.unsuspend`
- sentinel-fw: `fw.port.open fw.port.close fw.rules fw.ban fw.unban fw.bans`
- panel-tls: `panel.tls.issue`

HTTP routes: prefix by area — `/api/files/*`, `/api/databases/*`,
`/api/cron/*`, `/api/dns/*`, `/api/backups/*`, `/api/apps/*`, `/api/plans/*`,
`/api/firewall/*`. Follow the existing handler pattern in
`crates/ferrum-web/src/routes/sites.rs` (auth extractor, CSRF on mutations,
202+task_id for long ops).

## Key facts about the codebase

- Two daemons: `ferrum-agentd` (root) + `ferrum-web` (unprivileged), IPC over a
  UDS. Web calls ops through the agent client; ops run in the agent.
- Ops implement `TypedOperation` (`crates/ferrum-ops/src/registry.rs`), get an
  `OpContext` (`ctx.db()`, `ctx.distro()`, `ctx.config()`, `ctx.log(...)`,
  `ctx.scope()`), and declare `Execution::{Immediate, Task{..}}`.
- DB access: repositories on `ferrum_db::Db`, tenant-scoped via
  `TenantScope` (`db.sites(scope)`), runtime `sqlx::query_as` (no macros),
  `WITHOUT ROWID` where a natural key exists, times via `to_sql_time(now())`.
- Config files are written through `ferrum_config::apply::ApplyRequest`
  (render→validate→activate→rollback, FERRUM-MANAGED header, drift detection).
  Templates are minijinja, `UndefinedBehavior::Strict`, in
  `crates/ferrum-config/templates/`.
- Paths come from `ferrum_config::paths` (rootable for dev instances). Add new
  path fns there, `under("/...")` style.
- Package repos are pinned by full 40-hex GPG fingerprint in
  `crates/ferrum-distro/src/repos.rs`; keys verified in-process by
  `pgp.rs`. Short key ids are never pins.
- Firewall backends: `crates/ferrum-distro/src/fw.rs` (firewalld/ufw/nft +
  Unmanaged), already implemented — use `ctx.distro().fw`.
- UI: React 18 + TS + Vite + Tailwind v4 + TanStack Router/Query, pages in
  `ui/src/routes/`, API client in `ui/src/lib/api.ts`, i18n en+fa (RTL). The
  gzipped initial JS budget is 350 KB — anything heavy (an editor, a chart lib)
  must be a lazily imported chunk. For node_modules run `npm ci` in `ui/`.
- Phase 2 external facts (repo pins, argv sequences, distro paths for MariaDB,
  PostgreSQL, quotas, cgroups, SFTP, Cloudflare, Adminer) were researched and
  verified; the brief lives at
  `/private/tmp/claude-501/-Users-farzamseyedhashem-Documents-Projects-panel-server/8e770d3f-ee21-461b-a685-d34d1ef59ee9/tasks/wudnts94f.output`
  — grep it for your section and follow it. Where it marks something
  UNVERIFIED, keep the code but gate it behind a pin-verification the way
  `repos.rs::UNVERIFIED_PINS` does.

## Report

Your final structured report must include: branch name, what works, what is
stubbed, exact registration/route lines you added to shared files, new
workspace deps, new error codes, test count and result, and anything the
integrator must do by hand.

## Integrator log (running)
- openapi completeness test greps `.route("...")` only — merged sub-routers
  (files::router()) are invisible to it. /api/files/* is undocumented; extend
  the doc + test in the wave-2 cleanup.
- Migration numbers 0007-0012 are still unallocated after wave 1 (cron, dns,
  backups, node-apps, monitoring, sentinel did not finish). Wave 2 keeps the
  original allocation so nothing renumbers.
- Union-merging two branches that both appended to the same Rust file lost a
  closing brace twice (paths.rs, templates.rs tuple). Always `cargo build`
  immediately after a union resolve, never trust the merge.
- Wave 2 landed: sentinel-fw, monitoring, release-pipeline, installer-release,
  gates-ci, node-apps (ops only — no web routes, no docs). Still missing
  entirely: cron (0007), dns-cloudflare (0008), backups (0009). Their migration
  numbers stay reserved.
- The ops-docs gate is the real forcing function: merging a module without its
  docs fails CI with the exact list. Twice now that list was the checklist.
- Wave 4: cron (0007) and dns-cloudflare (0008) merged. Union-merge ate a
  closing paren in routes/mod.rs again — third time. Build immediately after
  every union resolve; the merge is never trustworthy on its own.
- Live-server findings this round, none of which any unit test could reach:
  MariaDB's repo host answered package managers with 403 (the test asserted the
  broken host by name and passed the whole time); the panel left MariaDB on
  0.0.0.0:3306 with two anonymous accounts and a shared `test` database; the
  recycle bin could never be created in a chroot-shaped home. Fixed and
  verified on the box.
- Wave 5: the union-merge hazard is now the single most reliable source of
  breakage — it has swallowed a terminator on EVERY multi-branch merge (Rust
  braces, a JSX element, i18n groups, TS interface bodies). Two rules that
  actually work: (a) never blind-union an import line — merge the named imports;
  (b) after any union resolve, run the real build immediately. Note `npx tsc
  --noEmit` at the ui/ root checks NOTHING (the root tsconfig is a solution file
  of references); `npm run build` (tsc -b) is the only honest gate.
