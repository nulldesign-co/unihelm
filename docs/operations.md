# Operations reference

Every privileged thing Ferrum can do is an *operation*: a named entry in the
registry at `crates/ferrum-ops/src/registry.rs`, with a typed input, a declared
permission and a declared execution mode. The registry is a whitelist — a name
that is not in it does not exist, and the agent answers `FER-1504
unknown_operation` rather than falling back to anything (spec §5.2).

This page documents every operation this build registers. It is checked:
`tests/gates/ops-docs.sh` reads the registry, resolves each registered type to
the `const NAME` on its `impl TypedOperation`, and fails if a name does not
appear somewhere under `docs/`. New operation, same change, new entry here.

## How to read an entry

**Permission** is the single `Permission` the caller must hold, re-derived from
the database by the agent — the web process's claim can only ever *lose*
privileges at that boundary, never gain them (`OpRegistry::verify_auth`). The
permission is not the whole authorization story: almost every operation also
resolves its subject through the caller's `TenantScope`, so a reseller reaching
for another reseller's subscription gets `not_found` and learns nothing else.

**Execution** is either:

- *immediate* — answered in the same IPC round trip, under roughly 300 ms; or
- *task* — returns a task id at once and streams its log (spec §10.1). Each
  task also declares whether it is **cancellable** and whether it is
  **idempotent** (safe to re-run after a crash or a half-finished attempt).

**Input** lists the JSON fields of the operation's `Input` type. Fields marked
*(optional)* have a `#[serde(default)]`; everything else is required. Inputs
are validated by *parsing*: `Domain`, `DbName`, `PhpVersion`, `TenantPath` and
friends are newtypes that reject their bad values before the operation body
runs at all (spec §12 rule 3), so "invalid domain" is `FER-1201` from the
parser, not a check somebody remembered to write.

Where an operation takes `subscription_id` as *(optional)*, omitting it means
"the caller's own subscription".

---

## System

### `sys.ping`

| | |
|---|---|
| Permission | `task_read` |
| Execution | immediate |
| Input | `nonce` *(optional string)* — echoed back so a caller can correlate |

Is the agent alive, and what is it running on? Answers with the agent version,
the detected distribution and family, the architecture, and which package,
firewall and security-module backends were selected. The simplest operation and
the one `ferrum doctor` leans on: if it answers, the socket, the peer check,
the registry and the database handle all work.

### `metrics.snapshot`

| | |
|---|---|
| Permission | `server_read` |
| Execution | immediate |
| Input | `include_panel_footprint` *(optional bool)*, `web_pid` *(optional u32)* |

One reading of CPU, memory, disks, network and — when asked — the panel's own
resident memory. This is the dashboard's operation, so it is on the hot path:
the collector throttles refreshes, and a room full of open dashboards costs one
sweep per second rather than one per viewer. The agent knows its own pid; the
web process passes `web_pid` because the agent has no reliable way to identify
it.

## Services

### `svc.status`

| | |
|---|---|
| Permission | `server_read` |
| Execution | immediate |
| Input | `unit` — a `ManagedUnit`, not a free-form unit name |

Reads one managed service's state (active, enabled, since when) plus its
display name. The unit is an enum: a caller cannot ask the panel about — or
later act on — an arbitrary systemd unit.

### `svc.action`

| | |
|---|---|
| Permission | `server_manage` |
| Execution | immediate |
| Input | `unit` — a `ManagedUnit`; `action` — start, stop, restart or reload |

Starts, stops, restarts or reloads a managed service and returns the state
afterwards, so the UI does not have to poll to find out what happened. Service
actions are deliberately in the fast lane: a stuck package install must never
be the reason a restart button does nothing (spec §10.1). Stopping the agent
through the agent, or sshd through the panel, is refused.

## Stack

### `stack.status`

| | |
|---|---|
| Permission | `server_read` |
| Execution | immediate |
| Input | none |

What is installed and what the panel could install: per component, the stored
status and version alongside the service's own view, which can disagree if
somebody removed a package by hand. Also reports repository pins that could not
be verified, which the UI surfaces rather than hides.

### `stack.install`

| | |
|---|---|
| Permission | `stack_manage` |
| Execution | task — not cancellable, idempotent |
| Input | `component` *(flattened)* — `nginx`, `php` (with `version`), `mariadb` or `postgres`; `extensions` *(optional list of `PhpExt`)* |

Adds the component's repository, verifies its signing key against a full 40-hex
fingerprint pin (`crates/ferrum-distro/src/repos.rs`), installs the packages
and starts the service. `component` is a typed enum precisely so an API caller
cannot ask the panel to `apt install` something of their choosing. For PHP, an
empty `extensions` list means the default set mainstream applications assume.

### `stack.remove`

| | |
|---|---|
| Permission | `stack_manage` |
| Execution | task — not cancellable, idempotent |
| Input | `component` *(flattened)*, as for `stack.install` |

Removes a component, refusing while anything still depends on it — a PHP
version with sites on it, or a database engine with managed databases, comes
back as `FER-1404 dependents_exist` instead of breaking those sites.

## Sites

### `site.list`

| | |
|---|---|
| Permission | `site_read` |
| Execution | immediate |
| Input | `limit` *(optional i64, default 100)*, `offset` *(optional i64, default 0)* |

Lists the sites visible in the caller's tenant scope, with their domain, type,
PHP version, document root and current status.

### `site.create`

| | |
|---|---|
| Permission | `site_manage` |
| Execution | task — not cancellable, **not** idempotent |
| Input | `domain`; `site_type` *(optional, default `php`)* — `php`, `static`, `proxy` or `redirect`; `php_version` *(optional, required for `php`)*; `subscription_id` *(optional)*; `with_www` *(optional bool)*; `proxy_port` *(optional u16)*; `redirect_target` *(optional domain)* |

Creates the Linux account if the subscription does not have one yet, builds the
document root, renders the nginx vhost and (for a PHP site) the php-fpm pool,
validates both, activates them and reloads the two services. A PHP site must
name a version, and that version must already be installed — `site.create` will
not silently install one. Returns the site id, document root, Linux user and a
short list of next steps for the UI. Not idempotent: it makes an account and a
directory tree, so a re-run is a second attempt at a partly-built site, not a
converging one.

### `site.update`

| | |
|---|---|
| Permission | `site_manage` |
| Execution | task — not cancellable, idempotent |
| Input | `site_id`; then any of `php_version`, `force_https`, `http3`, `maintenance_mode`, `client_max_body_size`, `custom_nginx_snippet`, `php_ini_overrides`, `rate_limit_enabled`, `www_policy` (`none`, `add` or `strip`) — all *(optional)* |

Changes a site's settings and re-renders whatever those settings feed. Absent
fields are left alone; the two `Option<Option<String>>` fields
(`custom_nginx_snippet`, `php_ini_overrides`) distinguish "not mentioned" from
"explicitly cleared". The render goes through the config engine, so a snippet
that nginx rejects fails validation and rolls back rather than taking the web
server down (spec §10.4).

### `site.delete`

| | |
|---|---|
| Permission | `site_manage` |
| Execution | task — not cancellable, idempotent |
| Input | `site_id`; `purge_files` *(optional bool, default false)* |

Removes the vhost first — stop serving before removing what was served — then
the php-fpm pool, then the database row. Files are kept unless `purge_files` is
set: a deleted vhost is re-renderable, a deleted home directory is not.

### `site.drift`

| | |
|---|---|
| Permission | `site_read` |
| Execution | immediate |
| Input | `site_id` |

Has somebody edited this site's generated files? Compares each managed file
against the hash recorded when the panel last wrote it and reports what
diverged (spec §10.4, and `docs/config-safety.md` for what happens next).

## Certificates

### `cert.list`

| | |
|---|---|
| Permission | `site_read` |
| Execution | immediate |
| Input | none |

Every certificate in scope, with days remaining and whether it is due for
renewal.

### `cert.issue`

| | |
|---|---|
| Permission | `site_manage` |
| Execution | task — not cancellable, **not** idempotent |
| Input | `site_id`; `staging` *(optional bool)*; `contact_email` *(optional string)* |

Obtains a Let's Encrypt certificate for a site over HTTP-01 and installs it.
`staging` uses the CA's staging directory — its root is not publicly trusted,
so a staging certificate must never be installed on a live site, but it is the
right way to prove the flow works without spending rate-limit budget. Not
idempotent because each run spends real ACME rate-limit budget.

### `panel.tls.issue`

| | |
|---|---|
| Permission | `server_manage` |
| Execution | task — not cancellable, **not** idempotent |
| Input | `domain`; `contact_email` *(optional email)*; `staging` *(optional bool)* |

Gives the panel itself a domain and a Let's Encrypt certificate, and puts its
vhost live. The domain must already resolve to this server or the CA cannot
fetch the HTTP-01 challenge. Same staging caveat as `cert.issue`, more sharply:
a staging certificate on the panel is for proving the flow, not for a panel
anyone logs in to.

## Databases

All `db.*` operations run the engine's own client through
`ferrum_distro::Cmd` — argv array, binary resolved against a fixed list of
trusted directories, scrubbed environment, SQL delivered on stdin. No SQL is
ever interpolated into a shell string (spec §12 rule 2, and
`tests/gates/no-shell.sh`).

### `db.list`

| | |
|---|---|
| Permission | `db_manage` |
| Execution | immediate |
| Input | `limit` *(optional i64, default 100)*, `offset` *(optional i64, default 0)* |

The databases and database users in the caller's scope.

### `db.create`

| | |
|---|---|
| Permission | `db_manage` |
| Execution | immediate |
| Input | `name` (`DbName`); `engine` — `mariadb` or `postgres`; `subscription_id` *(optional)*; `owner` *(optional `DbName`)* |

Creates a database. An `owner`, if given, must already exist in the same engine
*and* the same subscription — binding someone else's user would be a
cross-tenant grant. The name is checked twice: against panel metadata for a
precise answer, then against the engine itself, so a database created outside
the panel is refused rather than adopted. The metadata row is claimed *before*
`CREATE` runs, so two racing creates resolve on the UNIQUE index and only the
winner touches the engine; if `CREATE` then fails, the claim is released rather
than burning the name forever.

### `db.drop`

| | |
|---|---|
| Permission | `db_manage` |
| Execution | immediate |
| Input | `database_id`; `confirm_name` — the database's name, retyped |

Drops a database. `confirm_name` must equal the stored name: dropped data has
no re-render, so this uses the type-the-name pattern rather than a boolean flag
a UI could default to `true`. The engine is told first and the metadata row
deleted second — if the `DROP` fails the row survives to describe what still
exists, and if the row delete fails the next attempt hits `IF EXISTS` and
completes.

### `db.user.create`

| | |
|---|---|
| Permission | `db_manage` |
| Execution | immediate |
| Input | `username` (`DbName`); `engine`; `subscription_id` *(optional)* |

Creates a database user with a generated password. **The password is returned
once and stored nowhere** — losing it means resetting it with
`db.user.password`, never recovering it. The task log records that a user was
created, never the credential.

### `db.user.drop`

| | |
|---|---|
| Permission | `db_manage` |
| Execution | immediate |
| Input | `username` (`DbName`) |

Drops a database user, engine first and metadata second. PostgreSQL refuses to
drop a role that still owns a database; that error surfaces verbatim so the
operator knows to drop or reassign the database, rather than the panel
cascading through owned objects on their behalf.

### `db.user.password`

| | |
|---|---|
| Permission | `db_manage` |
| Execution | immediate |
| Input | `username` (`DbName`) |

Resets a database user's password to a freshly generated one and returns it —
once, like at creation.

### `db.grant`

| | |
|---|---|
| Permission | `db_manage` |
| Execution | immediate |
| Input | `database` (`DbName`); `username` (`DbName`) |

Grants a user full access to a database. Both ends are resolved inside the
caller's scope, so a grant is only ever wired between objects the caller could
already see, and the two must share an engine *and* a subscription —
cross-subscription grants would quietly couple two tenants' lifecycles.

### `db.adminer.status`

| | |
|---|---|
| Permission | `server_manage` |
| Execution | immediate |
| Input | none |

Is Adminer installed, on which PHP version, and at what URL. Also reports the
provenance of the checksum pin: the Adminer release is pinned by SHA-256 with
one source and no upstream signature, and the UI shows that the same way it
shows unverified repository pins from `stack.status`.

### `db.adminer.enable`

| | |
|---|---|
| Permission | `server_manage` |
| Execution | task — not cancellable, idempotent |
| Input | none |

Downloads the pinned Adminer release over HTTPS (bounded, short timeout),
verifies its SHA-256, installs it, creates a dedicated php-fpm pool and renders
a loopback-only vhost. Loopback means reachable from the server, not from a
browser, until the authenticated proxy ships.

### `db.adminer.disable`

| | |
|---|---|
| Permission | `server_manage` |
| Execution | task — not cancellable, idempotent |
| Input | none |

Removes the vhost, then the pool(s), then the script. Cleanup that fails after
the vhost is already gone is reported as a warning rather than an error —
nothing serves Adminer once the vhost is removed.

## Files

The `fs.*` operations are the tenant file manager's backend (spec §11.7). Each
request is executed by a helper process that re-execs the agent binary and
drops to the tenant's uid **before reading a byte** (spec §5.2 rule 3); on top
of that, every path is component-walked and symlinks are refused, so an escape
has to beat the path checks *and* the OS permission model at once. All of them
require `file_manage` and, unless noted, are immediate.

`path`, `from`, `to`, `root`, `archive` and `dest` are `TenantPath` values:
relative to the subscription's home, and rejected at parse time if they contain
a traversal component or an absolute prefix.

### `fs.list`

| | |
|---|---|
| Permission | `file_manage` |
| Execution | immediate |
| Input | `subscription_id` *(optional)*; `path` *(optional, home root when absent)*; `show_hidden` *(optional bool)* |

Lists a directory. The recycle bin (`.trash`) is hidden from the normal browse
view; `fs.trash.list` is how you look inside it.

### `fs.stat`

| | |
|---|---|
| Permission | `file_manage` |
| Execution | immediate |
| Input | `subscription_id` *(optional)*; `path` *(optional)* |

One entry's metadata: type, size, mode, owner, modification time.

### `fs.read`

| | |
|---|---|
| Permission | `file_manage` |
| Execution | immediate |
| Input | `subscription_id` *(optional)*; `path`; `offset` *(optional u64, default 0)*; `max_bytes` *(optional u64)* |

Reads a chunk of a file for the editor or a download. `max_bytes` is capped at
8 MB per call regardless of what is asked for, and the helper refuses to open
anything over 16 MB as an editable file at all.

### `fs.write`

| | |
|---|---|
| Permission | `file_manage` |
| Execution | immediate |
| Input | `subscription_id` *(optional)*; `path`; `content_b64` — base64, at most 8 MB decoded; `append` *(optional bool)*; `create_parents` *(optional bool)* |

Writes (or, with `append`, extends) a file as the tenant. Chunked uploads send
the first chunk with `append: false` and the rest with `append: true`.

### `fs.mkdir`

| | |
|---|---|
| Permission | `file_manage` |
| Execution | immediate |
| Input | `subscription_id` *(optional)*; `path` |

Creates a directory owned by the tenant.

### `fs.rename`

| | |
|---|---|
| Permission | `file_manage` |
| Execution | immediate |
| Input | `subscription_id` *(optional)*; `from`; `to` |

Renames or moves an entry. Both ends are resolved inside the same home, so a
rename cannot be used to walk out of it.

### `fs.copy`

| | |
|---|---|
| Permission | `file_manage` |
| Execution | immediate |
| Input | `subscription_id` *(optional)*; `from`; `to` |

Copies a file or directory tree and returns the bytes written.

### `fs.delete`

| | |
|---|---|
| Permission | `file_manage` |
| Execution | immediate |
| Input | `subscription_id` *(optional)*; `path` |

Moves an entry into the tenant's recycle bin at `~/.trash` rather than
unlinking it (spec §11.7). Deletion in the file manager is always recoverable;
`fs.trash.purge` is the only operation that actually destroys data.

### `fs.chmod`

| | |
|---|---|
| Permission | `file_manage` |
| Execution | immediate |
| Input | `subscription_id` *(optional)*; `path`; `mode` (u32); `recursive` *(optional bool)* |

Changes permission bits. The helper refuses anything outside `0o777` — setuid,
setgid and sticky are rejected rather than masked off, because a tenant who can
set the setuid bit on a file they own has a way out of their own account.

### `fs.search`

| | |
|---|---|
| Permission | `file_manage` |
| Execution | immediate |
| Input | `subscription_id` *(optional)*; `query` — case-insensitive substring of the file name; `root` *(optional)*; `limit` *(optional, default 100, capped at 500)* |

Finds files by name under a subtree. Names only: this is the file manager's
find box, not a content grep.

### `fs.compress`

| | |
|---|---|
| Permission | `file_manage` |
| Execution | task — not cancellable, **not** idempotent |
| Input | `subscription_id` *(optional)*; `root` *(optional)*; `entries` — names one level under `root`, no separators; `archive` — where the archive lands; `format` |

Builds an archive from a selection. `entries` are plain names rather than paths
so a selection cannot reach sideways out of `root`. Not idempotent: a re-run
fails on the existing archive rather than silently rebuilding it.

### `fs.extract`

| | |
|---|---|
| Permission | `file_manage` |
| Execution | task — not cancellable, idempotent |
| Input | `subscription_id` *(optional)*; `archive`; `dest` *(optional, home root when absent; must exist)* |

Extracts an archive with path-traversal and zip-bomb guards: entries with
absolute or `..` paths — and symlink entries, which would plant a
tenant-chosen redirection for every later operation — are refused, and an entry
count cap, a total-uncompressed cap and a compression-ratio cap are enforced
*while streaming*, so a small hostile archive aborts partway instead of filling
the disk. Idempotent — it overwrites what it already extracted, so a re-run
converges.

### `fs.trash.list`

| | |
|---|---|
| Permission | `file_manage` |
| Execution | immediate |
| Input | `subscription_id` *(optional)* |

What is in the recycle bin, newest first — the thing just deleted is the thing
being looked for.

### `fs.trash.restore`

| | |
|---|---|
| Permission | `file_manage` |
| Execution | immediate |
| Input | `subscription_id` *(optional)*; `name` — the entry's name inside `.trash`, from `fs.trash.list`; `to` *(optional, defaults to the original name in the home root)* |

Restores one entry out of the recycle bin.

### `fs.trash.purge`

| | |
|---|---|
| Permission | `file_manage` |
| Execution | immediate |
| Input | `subscription_id` *(optional)*; `older_than_days` *(optional u32, default 0)* |

Permanently destroys recycle-bin entries. Zero — the default — empties the bin;
the scheduled auto-purge passes 7 (spec §11.7). This is the one `fs.*`
operation with no undo.

### `fs.usage`

| | |
|---|---|
| Permission | `file_manage` |
| Execution | immediate |
| Input | `subscription_id` *(optional)*; `path` *(optional, the whole home when absent)* |

Measures a subtree by walking it. For the enforced number, use `quota.usage` —
this is "how big is this folder", not "how much of the quota is left".

## Quotas

### `quota.set`

| | |
|---|---|
| Permission | `plan_manage` |
| Execution | immediate |
| Input | `subscription_id`; `soft_mb` (u64); `hard_mb` (u64) |

Applies disk limits to a subscription (spec §6.2). `plan_manage`, not
`file_manage`: limits are plan machinery, and a tenant must not be able to
raise their own ceiling. `hard_mb` must be at least 1 — use suspension, not a
zero quota, to stop a tenant — `soft_mb` may not exceed it, and a `hard_mb`
above 16 TB is rejected on the assumption the caller passed bytes. The reply
says which backend took the limit and whether it is `enforced`.

### `quota.usage`

| | |
|---|---|
| Permission | `site_read` |
| Execution | immediate |
| Input | `subscription_id` |

How much of its quota a subscription is using. Owner-readable — every role
holds `site_read`, and the scoped subscription lookup confines a customer to
their own numbers. The reply keeps two things apart on purpose: `limit_mb` is
what the kernel reports it is enforcing right now (absent under the `du`
fallback), while `soft_mb` / `hard_mb` are what the plan promised. That is what
lets the UI say "limit 500 MB (not enforced on this server)" truthfully.

### `quota.backend`

| | |
|---|---|
| Permission | `server_read` |
| Execution | immediate |
| Input | none |

Which rung of the enforcement ladder this server is on: XFS project quotas
(per-directory, kernel-enforced, immune to a tenant `chown`ing files around),
ext4 user quotas (keyed by uid, still kernel-enforced, weaker), or the `du`
fallback, which measures by walking the tree and enforces nothing. The spec's
installer "detects & reports which level you got" (§6.3); this is that report at
runtime.

## SFTP

### `sftp.enable`

| | |
|---|---|
| Permission | `ssh_access` |
| Execution | task — not cancellable, idempotent |
| Input | `subscription_id`; `password` *(optional string)* |

Chroots a tenant's home and opens SFTP access to it. One managed sshd drop-in
carries a single `Match Group ferrum-sftp` block (`ChrootDirectory %h`,
`ForceCommand internal-sftp`, forwarding off), so enabling SFTP for the second
tenant is a group membership change and not a config change. sshd requires
every component of a chroot path to be root-owned and not group- or
world-writable, so the operation also fixes ownership down to the home,
computing the whole plan before running anything. `password`, if supplied, is
held only for the duration of the operation: hashed in-process, installed into
`/etc/shadow`, never stored and never logged.

### `sftp.disable`

| | |
|---|---|
| Permission | `ssh_access` |
| Execution | immediate |
| Input | `subscription_id` |

Closes SFTP access by removing the tenant from the group, and touches nothing
else — the drop-in, the home ownership and the account all stay as they are.

## Plans and subscriptions

### `plan.list`

| | |
|---|---|
| Permission | `plan_manage` |
| Execution | immediate |
| Input | `limit` *(optional i64, default 100)*, `offset` *(optional i64, default 0)* |

The plans in the caller's scope, each with the number of subscriptions on it —
the number that gates deletion, so the UI can grey the button out instead of
surprising the operator.

### `plan.create`

| | |
|---|---|
| Permission | `plan_manage` |
| Execution | immediate |
| Input | `name`; `max_sites` (u32); `max_dbs` (u32); `storage_mb` (u32); `can_ssh` *(optional bool, default false)*; `can_cron` *(optional bool, default true)*; `can_node_apps` *(optional bool, default false)* |

Creates a plan. The limits are `u32`, not `i64`, so a negative limit is
rejected by the parser before the operation body ever runs (spec §12 rule 3).

### `plan.update`

| | |
|---|---|
| Permission | `plan_manage` |
| Execution | immediate |
| Input | `plan_id`; then any of `name`, `max_sites`, `max_dbs`, `storage_mb`, `can_ssh`, `can_cron`, `can_node_apps` — all *(optional)* |

Changes a plan in place. Absent fields are left alone. Lowering a limit below
what a subscription already uses is allowed — downgrades happen — and shows up
at the next create attempt rather than retroactively.

### `plan.delete`

| | |
|---|---|
| Permission | `plan_manage` |
| Execution | immediate |
| Input | `plan_id` |

Deletes a plan. Refused while subscriptions are on it (`FER-1404
dependents_exist`), with the guard inside the `DELETE` statement itself so a
concurrent assignment cannot slip past it.

### `plan.assign`

| | |
|---|---|
| Permission | `plan_manage` |
| Execution | immediate |
| Input | `subscription_id`; `plan_id` |

Moves a subscription onto a plan. Both halves resolve through the caller's
scope, so a reseller can neither hand out another reseller's plan nor touch a
subscription that is not theirs — either way the answer is `not_found`,
revealing nothing. The reply carries `over_limit` when the subscription already
holds more sites than the new plan allows, so the UI can say so instead of the
tenant discovering it at the next create.

### `subscription.suspend`

| | |
|---|---|
| Permission | `user_manage` |
| Execution | task — not cancellable, idempotent |
| Input | `subscription_id`; `reason` — 1–500 characters of plain text, required |

Suspends a subscription: marks the row suspended, then switches every one of
its sites to the maintenance vhost. `user_manage`, not `plan_manage`:
suspension governs an account's service, not the plan catalogue — and a
customer holds neither permission, so nobody can unsuspend themselves. The
order is the safety property (spec §6.4): once the row says suspended nothing
new can be created under it even if every render below fails, whereas rendering
first could show maintenance pages for a tenant the database still calls
active. `reason` is required because a tenant looking at a maintenance page
deserves to find out why in the panel.

### `subscription.unsuspend`

| | |
|---|---|
| Permission | `user_manage` |
| Execution | task — not cancellable, idempotent |
| Input | `subscription_id` |

The mirror image: mark the subscription active first, then re-render each site
from its own stored flags. That last detail matters — a site the tenant had put
into maintenance mode themselves comes back in maintenance, because suspension
never rewrote their settings.
