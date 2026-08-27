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

### `cert.issue_wildcard`

| | |
|---|---|
| Permission | `site_manage` |
| Execution | task — not cancellable, **not** idempotent |
| Input | `site_id`; `staging` *(optional bool)*; `contact_email` *(optional string)* |

Obtains a wildcard certificate for a site over **DNS-01**, through the stored
Cloudflare credential (spec §11.5, §11.13), and installs it.

The certificate covers **both** `example.com` and `*.example.com`. A
`*.example.com` certificate does not match `example.com` — a wildcard covers
exactly one label — so a wildcard-only certificate leaves the apex broken, which
is the single most common wildcard mistake.

The flow: find the stored token whose zone list covers the site's domain by
**longest suffix** (so `example.co.uk` wins over a `co.uk` the token also
administers, and `evil-example.com` never matches a zone named `example.com` —
matching is on label boundaries); publish one `_acme-challenge.<domain>` TXT
record per authorization; wait for those values to appear at the zone's
**authoritative** nameservers, with a capped and jittered backoff bounded to
roughly three minutes; tell the CA to validate; finalize; write the files;
supersede the older row through the same `db.certificate_issued` path
`cert.issue` uses; then **reload nginx explicitly**.

That reload is not optional and is not a duplicate of the vhost render. nginx
holds certificates in memory from the moment it loads them, and on a renewal the
vhost text does not change — same paths, same options — so the config engine
correctly reports "nothing to do" and skips the reload. Without the explicit
reload a renewal appears to succeed while the expiring certificate stays live.

The challenge TXT records are removed on **every** exit path: when the order
succeeds, when it fails, and when publishing the second record fails after the
first one was created. A cleanup failure is logged as a warning and never
replaces the reason the order failed. Fails with `not_found` when no stored
credential administers the site's zone, naming the zone to add a token for.

`staging` uses the CA's staging directory; same caveat as `cert.issue`. Not
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

## DNS

Ferrum does not run authoritative DNS in v1. It holds an API credential for
somebody who does, and drives DNS-01 through it (spec §11.13; own authoritative
DNS is Phase 5). Cloudflare is the only provider this build speaks, and the
`dns_providers.kind` CHECK constraint says so rather than accepting a name the
code cannot honour.

**Cloudflare API Tokens only — never the Global API Key.** A Global Key
authenticates *the account*: every permission the human has, on every zone, plus
billing, and it cannot be scoped. A token carries an explicit permission list
against an explicit resource list, and the one this panel wants is `Zone:Read` +
`Zone:DNS:Edit` on the single zone whose wildcard is being issued. A panel
holding a Global Key has taken custody of the customer's whole Cloudflare
account on the strength of its own disk encryption; a panel holding a scoped
token can at worst edit DNS in one zone, which is the authority it was given the
credential to exercise. There is no code path that sends
`X-Auth-Key`/`X-Auth-Email`.

Because a scoped token cannot see zones it was not scoped to, an operator
hosting several customers' domains needs several tokens. That is why the table
is unique on `(kind, label)` rather than on `kind`, and why wildcard issuance
walks every stored credential looking for one whose zone list covers the name.

### `dns.check`

| | |
|---|---|
| Permission | `site_read` |
| Execution | immediate |
| Input | `domain` |

An advisory: does this domain point at this server? Resolves A and AAAA for the
domain and its `www.` form and compares them against this server's public
addresses, returning the records, `matches_server`, a `proxied_hint`, and one
`advice` sentence the UI renders as-is rather than keeping its own copy of the
decision table.

`site_read`, not a DNS permission: this reads public DNS and touches no stored
credential, so it reveals nothing a `dig` from any shell would not, and the
customer about to point a domain at their site is exactly who needs it.

This server's addresses come from three sources, in order: the
`dns.server_addresses` setting (a JSON array of IPs — explicit beats inferred,
and it is the documented fix when the advisory is wrong, because a server behind
a NAT, a floating IP or a load balancer answers on an address that appears on no
local interface); then the addresses actually bound to local interfaces, via the
same `getifaddrs(3)` call Sentinel's self-ban guard uses, filtered to the
globally routable ones; then a best-effort default-route probe, which asks the
kernel which source address it *would* use to reach the internet without sending
a packet. The probe is last because it is right behind a one-to-one NAT's inside
address and wrong behind many-to-one NAT.

`matches_server: false` with `proxied_hint: true` is a **correct** setup, not a
fault: the domain resolves into Cloudflare's anycast space and reaches the origin
through the proxy. Without that branch every Cloudflare-proxied customer would be
told their DNS is broken. The lookups are bounded at six seconds; a timeout comes
back as an advisory saying so rather than as an error.

### `dns.provider.set`

| | |
|---|---|
| Permission | `server_manage` |
| Execution | immediate |
| Input | `kind` (`cloudflare`); `label`; `token` |

Verifies a Cloudflare API token and stores it sealed. Returns the label,
Cloudflare's verdict on the token, and every zone the token administers — the
credential's blast radius, shown back so the operator can check it is as small as
they meant.

**The token is never returned and never logged.** `ProviderSetOutput` has no
field that could carry one, the audit row records the label and the kind, the log
line records the label and the zone count, and the `Authorization` header is
marked sensitive so reqwest redacts it in its own `Debug` output. The token
newtype's `Debug` prints a placeholder, so an input struct rendered into a
`tracing` field cannot leak it either. It is sealed with the panel master key
(XChaCha20-Poly1305) exactly the way the ACME account key is (spec §12 rule 6).

`server_manage` — admin only, deliberately not the reseller-held DNS permission.
This credential is server-wide: every tenant's wildcard issuance runs through
whatever token is stored here, so a reseller who could replace it could redirect
the panel's DNS writes into a Cloudflare account they control. Storing the
credential is an admin act; *using* it (`cert.issue_wildcard`) is not.

Verification happens before storage, always, and it is two calls because they
answer different questions: `/user/tokens/verify` asks "is this a live token",
and the zone list asks "what can it actually reach". A token that verifies but
sees no zones is rejected with the scopes it needs, because a stored token that
cannot do the job turns every future issuance into a failure discovered minutes
into a task. Re-sending the same label rotates that credential in place rather
than accumulating a dead row whose revoked token would be tried first.

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

## Firewall and Sentinel

The backend is the truth and the database is the intent. Every read merges the
two and flags the difference, because a rule the panel believes in and the
firewall has never heard of is exactly the state an operator needs told about.
On a host with no firewall at all the backend is `none`, and these operations
say so rather than reporting a success they did not achieve.

### `fw.port.open`

| | |
|---|---|
| Permission | `firewall_manage` |
| Execution | immediate |
| Input | `port`; `proto` — `tcp` or `udp`; `source` — optional CIDR, absent means anywhere; `comment` — optional |

Opens a port in whichever backend owns the ruleset, then records the intent.
That order matters: a rule recorded but never applied would make the panel
claim a hole exists that does not. `source` is a literal address or CIDR, never
a hostname — a rule whose meaning depends on DNS at apply time is a rule nobody
can audit.

### `fw.port.close`

| | |
|---|---|
| Permission | `firewall_manage` |
| Execution | immediate |
| Input | the same fields as `fw.port.open` |

Removes a rule **the panel created**. Rules the operator wrote by hand are
never touched: every rule Ferrum adds carries a `ferrum:` comment, and that
mark is what tells them apart.

### `fw.rules`

| | |
|---|---|
| Permission | `firewall_manage` |
| Execution | immediate |
| Input | none |

The merged view: the backend's live rules, the panel's recorded intent, and a
drift flag on each. Also reports which backend was detected and whether it is
actually running — a stopped firewall with rules in it protects nothing.

### `fw.ban`

| | |
|---|---|
| Permission | `firewall_manage` |
| Execution | immediate |
| Input | `ip`; `minutes` — absent means the configured default, `0` means permanent; `reason`; `client_ip` — filled in by the web layer from the live connection |

Drops an address at the firewall and records the ban with its expiry. Bans go
into an ipset or an nft set rather than one rule each, because Sentinel can
accumulate thousands and a thousand rules is a linear scan per packet.

`client_ip` exists for one reason: **the operator cannot ban themselves.** That
address, loopback, and the server's own addresses are all refused. A panel that
lets an admin lock themselves out of the machine over the network has turned a
security feature into an outage.

### `fw.unban`

| | |
|---|---|
| Permission | `firewall_manage` |
| Execution | immediate |
| Input | `ip` |

Lifts a ban in the backend and closes the record. An address the backend has
already expired is not an error — that is the state we wanted.

### `fw.bans`

| | |
|---|---|
| Permission | `firewall_manage` |
| Execution | immediate |
| Input | `limit` — optional |

Recorded bans, plus an `unrecorded` list of addresses the backend is blocking
that the panel has no row for. Those are somebody else's rules or a leftover
from a previous install, and listing them separately is how an operator finds
out why an address they never banned cannot reach the box.

### `sentinel.settings`

| | |
|---|---|
| Permission | `firewall_manage` |
| Execution | immediate |
| Input | none |

Sentinel's configuration: `enabled`, `ssh_threshold`, `window_minutes`,
`ban_minutes`.

### `sentinel.settings.set`

| | |
|---|---|
| Permission | `firewall_manage` |
| Execution | immediate |
| Input | `enabled`, `ssh_threshold`, `window_minutes`, `ban_minutes` |

The switch that turns the brute-force defence on. **Off on a fresh install**,
deliberately: the scan runs every minute either way, but returns before reading
anything while `enabled` is false. A panel that starts banning addresses before
anybody asked it to is a panel that eventually bans its own operator during
setup.

## Alerts and notifications

An alert is a *span*, not an event: it opens when a reading crosses the
threshold and closes when it comes back past it by a hysteresis band. Only the
edges of that span send a message, which is why a disk sitting at 90% produces
one notification and not one a minute. The "one open event per rule and
subject" rule is a partial unique index in the database rather than application
logic, so two overlapping evaluation passes cannot both open one.

### `alert.rules.list`

| | |
|---|---|
| Permission | `server_manage` |
| Execution | immediate |
| Input | none |

Every rule, the currently open events, and the list of rule kinds this build
understands.

### `alert.rules.set`

| | |
|---|---|
| Permission | `server_manage` |
| Execution | immediate |
| Input | `kind` — `disk_pct`, `mem_pct`, `load`, `service_down`, `cert_expiry_days`; `target` — the mount point or unit the rule is about, where the kind takes one; `threshold`; `enabled` |

Creates or updates a rule. Thresholds that could never stop firing are refused
(a disk rule at 0%, a certificate rule at 90 days on a 90-day certificate), and
so is a `target` on a kind that has nothing to target.

### `alert.events.list`

| | |
|---|---|
| Permission | `server_read` |
| Execution | immediate |
| Input | `limit` — optional; `open_only` |

Alert history. `server_read` rather than `server_manage` because this is
dashboard content — the secrets live behind the channel operations below.

### `alert.channels.list`

| | |
|---|---|
| Permission | `server_manage` |
| Execution | immediate |
| Input | none |

Configured notifiers. The sealed configuration is `#[serde(skip)]`, so a
webhook URL or a bot token cannot leave through this operation even by mistake.

### `alert.channels.set`

| | |
|---|---|
| Permission | `server_manage` |
| Execution | immediate |
| Input | `id` — absent creates; `kind` — `webhook` or `telegram`; `label`; the channel's configuration |

Creates or updates a notifier. The configuration is sealed with the master key
before it is stored. A Telegram bot token is validated on the way in **and** on
the way out: it is interpolated into the request path, so a token containing a
slash or a question mark would aim the request somewhere else entirely, and a
hand-edited database row must not be able to do that.

### `alert.channels.delete`

| | |
|---|---|
| Permission | `server_manage` |
| Execution | immediate |
| Input | `id` |

### `alert.channels.test`

| | |
|---|---|
| Permission | `server_manage` |
| Execution | immediate |
| Input | `id` |

Sends one message through the channel and reports whether it was delivered. The
point is to find out that a webhook is wrong now, rather than at three in the
morning when the disk fills.

## Node applications

A Node app is four things that have to agree: a **row** (which owns the port), a
**directory** in the tenant's home, a **systemd unit** running as the tenant
inside the tenant's slice, and — optionally — a **reverse-proxy vhost** in front
of it. `app.create` builds them in that order and unwinds in the reverse one,
because the state that hurts is the half-created app: a port marked taken with
nothing listening, or a unit nobody has a row for.

The port is allocated *inside* the `INSERT`, not read-then-written. The vhost has
to name the port before anything has ever bound it, so "bind and see what you
get" is not available; two concurrent creates must therefore not be able to
compute the same answer, and `port INTEGER NOT NULL UNIQUE` means that even if
they do, exactly one insert survives. Freed ports are reused — smallest free
number in 20000–25000 — because leaking one per deleted app would exhaust the
range after 5001 create/delete cycles on a box hosting three apps.

Everything a tenant supplies is validated twice: once by the newtypes
(`AppName`, `TenantPath`, `Domain`) at deserialization, and again against
*systemd's* own syntax on the way into the unit file. A unit file is a place
where one unescaped newline turns a value into a directive and where `%` is a
specifier expanded before anything else reads the line, so the template only
interpolates — it makes no decisions.

### `app.list`

| | |
|---|---|
| Permission | `node_apps` |
| Execution | immediate |
| Input | `limit` *(optional i64, default 100)*, `offset` *(optional i64, default 0)* |

Every app visible in the caller's tenant scope, each with its stored row (name,
entry, port, `NODE_ENV`, proxy site id), the systemd unit it maps to, that
unit's current state and its resident memory. The state comes from systemd
rather than from the row on purpose: the row says what the panel intended, and
an app that crash-looped overnight is exactly the case where those two differ.
A unit systemd has never heard of reports `not_found` instead of failing the
listing, so one broken app cannot blank the page.

### `app.create`

| | |
|---|---|
| Permission | `node_apps` |
| Execution | task — not cancellable, **not** idempotent |
| Input | `name`; `entry` — tenant-home-relative path to the JS entry point; `subscription_id` *(optional)*; `env` *(optional list of `{key, value}`)*; `node_env` *(optional, `production` \| `development` \| `test`, default `production`)*; `memory_mb` *(optional u32)*; `proxy_domain` *(optional)* |

Allocates a port, creates `<home>/apps/<name>` owned by the tenant at `0750`,
writes the slice drop-in, writes and verifies the unit, enables it (so a reboot
brings the app back — spec §11.6) and starts it. With `proxy_domain` it then
calls `site.create` with `SiteType::Proxy` pointing at the allocated port.

The order is the design. The slice drop-in is written **before the first
start**, so an app is never outside its tenant's memory and CPU ceiling, not
even for a second — `MemoryMax` on the unit is the app's own ceiling, the slice
is the tenant's. The vhost is written **last**, because pointing a proxy at a
port nothing is listening on 502s for as long as the start takes. On any
failure the operation unwinds in reverse — disable, remove the unit files,
delete the row — but deliberately leaves the app *directory* alone: it may
already hold the tenant's code, and deleting somebody's source because their
app failed to start is not a trade this panel makes.

Publishing calls the existing site machinery rather than rendering a
node-flavoured vhost, so domain-conflict detection, the plan's site limit, the
nginx validate/rollback cycle and logrotate all keep working from one
implementation. It also requires `site_manage` **in addition to** `node_apps`:
creating a site is creating a site, whichever operation asks for it.

Three refusals are worth knowing about, because each is a systemd rule rather
than a Ferrum preference:

- `PORT` and `NODE_ENV` cannot appear in `env`. The panel sets both, systemd
  keeps the *last* assignment of a name, and a tenant override would either
  break the proxy wiring or contradict the stored row. The panel's two are also
  emitted first, so even a value that slipped past validation could not shadow
  them.
- A value containing `"`, `\`, a newline or any control character is refused
  outright rather than escaped. The escape rules differ between systemd's quoted
  and unquoted forms, and a value that needs them is a configuration mistake
  worth naming. Whitespace is fine — the assignment is quoted whole — and `%` is
  escaped to `%%`, so a threshold of `100%h` reaches the app as `100%h` and not
  as `100/root`.
- An `entry` containing a space, `%`, a quote or `$` is refused: `TenantPath`
  already blocks traversal and control characters, but `ExecStart` would split
  on the space and expand the specifier. Rename the file.

`app.create` also refuses, naming what to install, when there is no `node`
binary in the system directories — it will not add a package repository as a
side effect of creating an app. The plan's `can_node_apps` flag is checked
against the **target** subscription, which is a different question from the
caller's permission whenever an admin or reseller creates an app for a
customer. Not idempotent: it makes an account, a directory and a port
allocation, so a re-run is a second attempt rather than a converging one.

### `app.delete`

| | |
|---|---|
| Permission | `node_apps` |
| Execution | task — not cancellable, idempotent |
| Input | `app_id` |

`systemctl disable --now`, then the unit file and its slice drop-in, then the
row — stop serving before removing what was served, and free the port *last* so
the next app cannot be handed a number a stale service still binds. A unit that
is already gone is logged and stepped over rather than failing the delete:
deletes get retried, and the row must still go.

The app's proxy site is deliberately left standing, and its id is returned as
`orphaned_site_id` so the UI can offer to remove it. Deleting a tenant's domain
as a side effect of removing an application is the kind of surprise a panel does
not get to spring; `site.delete` is one click away.

### `app.restart`

| | |
|---|---|
| Permission | `node_apps` |
| Execution | task — not cancellable, idempotent |
| Input | `app_id` |

`systemctl restart` on the app's unit. A task rather than an immediate
operation because restart waits for the unit to stop and come back, which for an
app with open connections is seconds. A missing unit gets a sentence saying the
unit file is gone and the app should be recreated, rather than systemd's "Unit
not found" — the two failures look identical from the outside and have entirely
different fixes.

### `app.logs`

| | |
|---|---|
| Permission | `node_apps` |
| Execution | immediate |
| Input | `app_id`; `lines` *(optional u32, default 200, clamped to 1–2000)* |

The tail of the app's journal, as lines. The security property is in what the
input *cannot* say: there is no field here that names a unit. The unit is
derived from a row the caller's scope could already see, so no caller can read
`sshd.service`'s journal through an app they own. The line cap bounds one IPC
frame rather than the operator's access to their logs — the journal itself keeps
far more, and a narrower window is one more request away.

## Cron

A tenant's crontab is a **rendering of the panel database**, never a file the
panel edits in place. Every `cron.set` and `cron.delete` re-renders the whole
crontab from `cron_jobs` and installs it with `crontab -u <user> -`, the content
arriving on stdin. Two properties follow, and both are the reason for the
design: the same set of jobs always renders byte-identical output (sorted by
schedule, then command, then id), and no operation ever has to find "the line
that used to be this job" — which is exactly what fails when a job's command is
what changed.

**The schedule grammar is small and strict.** Five whitespace-separated fields
(minute, hour, day-of-month, month, day-of-week), each a comma-separated list of
`*`, a number, an `a-b` range, or `*`/`a-b` with a `/n` step. Values are checked
against their own field's range (day-of-week accepts `7` as Sunday's second
spelling, which both Vixie cron and cronie do). Refused: month and day *names*,
a step on a bare number (`5/5` — Vixie reads it as `5-59/5`, which is rarely
what anyone meant), a step of zero or one wider than the range it walks, empty
list entries, and anything with more or fewer than five fields. The schedule is
stored canonicalised — five fields, single spaces — so two spellings of one
schedule cannot render two different crontabs.

**`@reboot` and every other `@` alias are refused for tenants**, and not for
tidiness. A `@reboot` job runs when cron starts at boot, which is *before*
`ferrum-agentd` has re-applied the tenant's systemd slice and disk quota: the
job would run with no memory ceiling, no CPU quota and no quota accounting —
precisely the window in which a runaway job is unbounded. Every alias has a
five-field spelling (`@daily` is `0 0 * * *`), so the refusal costs a tenant
nothing, and the error says so.

**A command may contain no control characters at all.** The one that makes this
a security boundary rather than a style rule is the newline: a crontab line ends
at the newline, so a command carrying one appends a *second job*, with its own
schedule and its own command, that nobody approved. A NUL is refused for the
same class of reason. Commands are capped at 1024 characters — comfortably
inside every cron implementation's line budget once the schedule is prepended,
and a command truncated by the cron daemon is the worst outcome available: one
that runs, but not the one that was saved. On the way into the file every `%`
becomes `\%`, because cron rewrites an unescaped `%` to a newline and feeds
everything after the first one to the command as *stdin* — `date +%F` would
otherwise silently run as `date +`.

What is deliberately *not* restricted is the shell. The command field is a shell
command line — that is what a crontab command field is — and cron hands it to
the tenant's own shell under the tenant's own uid. Refusing pipes and redirects
would break the feature and protect nothing: a tenant can already run any
command they like as themselves.

**A crontab the panel did not write is never overwritten** (spec §10.4 rule 2).
Before anything is stored, the account's existing crontab is read with
`crontab -u <user> -l` (exit 1 tolerated as "no crontab", which is how both
implementations say it). It counts as the panel's only if the
`# FERRUM-MANAGED cron` header appears **before any line that is not a
comment**; otherwise the operation refuses with `FER-1403 conflict` and tells
the operator how to save and remove the file. The rule is that shape rather than
"the header is line one" because some `crontab` implementations prepend a banner
of their own (`# DO NOT EDIT THIS FILE`) and hand it back on `-l`, and rather
than "the header appears somewhere" because a file whose first real line is
somebody's `MAILTO=` is one the panel half-owns — which is the state that ends
with a re-render throwing away their work. A crontab that is empty or nothing
but comments counts as the panel's: there is no schedule in it to destroy.

The check runs on every apply, not just the first: ownership is a fact about the
file, and somebody who runs `crontab -e` afterwards has taken it back. Files the
panel *does* own carry a header saying in as many words that edits are replaced.

**Cron jobs do not run inside the tenant's systemd slice.** A crontab line is
executed by cron as the tenant, and an unprivileged process cannot place itself
into a system slice — so a tenant's cron job is bounded by the server, not by
the plan. This is written up in full in `ferrum_ops::slices`, along with the fix
(render each job as a systemd timer written by the root agent, where `Slice=`
and `User=` are ordinary directives). Rendering from the database is what makes
that a change of renderer and nothing else.

Two further limits are named here because they are visible to callers: a
subscription may hold at most **100 jobs** (spec §11.8 asks for a plan-capped
count and the `plans` table has no cron column yet, so this is the interim
ceiling; `cron.list` returns it as `max_jobs_per_subscription`), and per-job run
history — exit code, duration, output tail, failure notifications (spec §11.8) —
is **not implemented**: it needs a runner that captures output, which crontab
alone does not give us. `last_error` on a job is the *apply* error, not the
job's exit status.

### `cron.list`

| | |
|---|---|
| Permission | `cron_manage` |
| Execution | immediate |
| Input | `subscription_id` *(optional)*, `limit` *(optional i64, default 200)*, `offset` *(optional i64, default 0)* |

Every cron job visible in the caller's tenant scope: schedule, command,
`enabled`, and `last_error` — why this subscription's crontab could not be
installed the last time it was rendered, or `null`. Also returns
`max_jobs_per_subscription`, so the UI can say "12 of 100" without hard-coding a
number that lives in the database layer.

With `subscription_id`, the subscription is resolved through the caller's scope
*first*, so an id outside it answers `not_found` rather than an empty list —
"there are no jobs" and "that is not yours" are different answers and only one
of them is true.

### `cron.set`

| | |
|---|---|
| Permission | `cron_manage` |
| Execution | immediate |
| Input | `schedule`; `command`; `id` *(optional)* — update this job instead of creating one; `subscription_id` *(optional)*; `enabled` *(optional bool, default `true`)* |

Creates a job, or updates the one named by `id`, then re-renders and installs
the whole crontab. Immediate rather than a task: one `crontab` invocation over a
payload bounded by the job limit is well inside the round-trip budget, and a
task id for something this fast would only make the UI wait twice.

The order of the checks is the design, and each step is chosen so that a refusal
leaves nothing behind. The subscription is resolved through the caller's scope;
a suspended one is refused (`FER-1105 account_suspended`); the **target** plan's
`can_cron` flag is checked, which is a different question from the caller's
permission whenever an admin or reseller edits a customer's jobs (a
subscription with no plan is unlimited — the same Phase 1 behaviour `site.create`
keeps); the schedule and the command are validated; and only then is the
existing crontab read and the row written. A refusal at any of those points
leaves the database exactly as it found it.

`id` names the job, and the job names the subscription: a `subscription_id` that
disagrees with the job's own is refused rather than ignored, because there is no
request shape in which moving a command from one Linux account to another is
what somebody meant. A disabled job keeps its row and renders into the crontab
as a comment — it is part of what the tenant configured, and an operator reading
the file should see the same list the panel shows.

If the install itself fails, the reason is recorded on **every** job of the
subscription and the operation fails loudly. That is what the failure is: the
crontab installs as one file, so when it does not install, no job in it took
effect. The row survives, because the row is the panel's intent and `cron.set`
is convergent — re-running it once the machine is fixed installs it. The next
successful install clears the record.

### `cron.delete`

| | |
|---|---|
| Permission | `cron_manage` |
| Execution | immediate |
| Input | `id` |

Removes a job and re-installs the crontab without it. Neither the plan flag nor
the suspension check applies here: removing a job is de-escalation, and a tenant
whose plan lost `can_cron`, or whose subscription was just suspended, must still
be able to take their jobs out — refusing would strand exactly the schedules an
operator most wants gone. The foreign-crontab refusal still applies, because
that one is about not destroying somebody's file.

Deleting the last job leaves a header-only crontab rather than removing the
crontab entirely, so the panel's ownership marker — and with it the right to
re-render without asking again — stays where it is.
