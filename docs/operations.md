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

### `subscription.list`

`SiteRead`. Immediate. The tenants themselves, scoped: an admin sees every
subscription, a reseller sees their customers', a customer sees their own.

Each row carries the owner's username, the number of sites it holds, and how
many of those are actually serving. The site counts exist for the suspension
confirmation, which has to be able to name the domains that will go dark before
it asks.

This exists because deriving the list from `site.list` — which the plans page
did first — cannot work: a subscription with no sites is invisible, and the
suspension state is unreadable, since suspending deliberately leaves the site
rows alone and only changes the subscription's own status.

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

## Web application firewall (ModSecurity)

**On a stock Ferrum server this feature refuses to enable, and it says exactly
why.** Ferrum installs nginx from nginx.org, and nginx.org publishes no
ModSecurity module. Checked on 2026-08-28 against every package tree Ferrum
installs from — `packages/debian`, `packages/ubuntu`, `packages/mainline/debian`
and `packages/centos/10` — the published modules are acme, geoip, image-filter,
njs, otel, perl and xslt. There is no `nginx-module-modsecurity` in any of them.

A connector *is* packaged elsewhere: `libnginx-mod-http-modsecurity` on
Debian/Ubuntu, `nginx-mod-modsecurity` in EPEL 9. Both are built against their
own distribution's nginx, and an nginx dynamic module records the nginx build it
was compiled against and is rejected by any other (`module ... is not binary
compatible`). Installing one beside nginx.org's nginx produces a module that
cannot load.

There is a second, independent blocker on the same servers. `load_module` is a
main-context directive, and nginx.org's `nginx.conf` — verified by unpacking
`nginx-1.30.4-1.el10.ngx.x86_64.rpm` and `nginx_1.30.4-1~trixie_amd64.deb` —
contains no main-context `include` at all; its only include is
`/etc/nginx/conf.d/*.conf`, inside `http`. So even with a compatible module on
disk there is nowhere to put the line that loads it except `nginx.conf` itself,
which the panel does not edit (spec §10.4 rule 1).

Spec §11.9's answer is a prebuilt dynamic module from Ferrum's own package
repository, the same rule as brotli in §11.2. That repository does not exist in
this build. `waf.enable` therefore refuses with `FER-1403 conflict` and a
message naming both conditions and what would fix them. Everything below the
preflight is implemented and tested: given a loadable module and a place to load
it from, the configuration, validation and reload path works like any other
nginx change.

### How per-site policy works

ModSecurity's nginx directives are valid at http, server and location level, so
the obvious design is `modsecurity on;` inside each vhost. Ferrum does not do
that. It would mean re-rendering every vhost to change one site's WAF, and a
site whose owner had hand-edited their vhost (which the config engine detects
and refuses to overwrite) could not be governed at all.

Instead the engine is switched on once at http level in
`/etc/nginx/ferrum.d/03-waf.conf`, starting in `DetectionOnly`, and each site's
policy is a phase-1 `SecRule` matching that site's own hostnames which uses
`ctl:ruleEngine` and `setvar:tx.*_paranoia_level` to set the mode and paranoia
level for that transaction. One generated file (`/etc/ferrum/waf/main.conf`)
holds every site's policy; turning a site on is one render and one reload.

Rule ids come from the 20,000 block — inside the 1–99,999 range the Core Rule
Set reserves for local rules — and are `20000 + site_id`, so a rule id in an
audit log names exactly one site.

A request whose `Host` matches no site matches no rule and gets the server-wide
default. That is the safe direction: unknown traffic inherits the strictest
configured position, never a site's relaxations.

### The Core Rule Set pin

OWASP CRS **4.29.0**, the `minimal` tarball, pinned by SHA-256
`1aa1c5c8fc29e532d35293bcea36bf72de61db8f6ed4716a0f91ab14552b7fed`. The value
was computed on 2026-08-28 by downloading the asset and hashing the 278,138
bytes served; GitHub's release API reports the same asset. Both observations
come from github.com, so this is a **single-source pin**: it detects a later
tampered or truncated download, not a source that was already wrong. CRS
publishes a detached OpenPGP signature beside every asset, and this build does
not verify it — Ferrum's in-tree OpenPGP code parses keys and computes
fingerprints but does not check signatures. `waf.status` reports that state in
`crs.pin_provenance` so an operator does not have to read the source to learn
it.

The archive is unpacked with explicit guards: absolute paths, `..` components,
symlink and hard-link entries, an entry-count cap and an unpacked-size cap are
all refused. The checksum already proves the bytes, so the guards never fire in
production; they exist so a future caller unpacking something less trusted
inherits a function that cannot be talked into writing outside its destination.

### `waf.status`

| | |
|---|---|
| Permission | `server_manage` |
| Execution | immediate |
| Input | none |

Whether the WAF is switched on, whether it *could* be, and why not. Reports the
module search result, where a `load_module` line could go, the packages that
would provide a connector on this family and why installing them does not help,
the running nginx version, the CRS pin and its provenance, every site's policy
with its allocated rule id, and the server-wide exclusion list.

`available: false` with a populated `blockers` array is the expected answer on a
stock server. Each blocker carries a stable `code` (`module_missing`,
`no_main_context_include`), what was observed, and the remedy.

### `waf.enable`

| | |
|---|---|
| Permission | `server_manage` |
| Execution | task (not cancellable, idempotent) |
| Input | `site_id` *(optional)*; `mode` *(optional)* — `detect` or `block`; `paranoia_level` *(optional)* — 1–4 |

Without `site_id`, switches the WAF on for the server: runs the preflight,
downloads and verifies the Core Rule Set if it is not already unpacked, stores
the default mode and paranoia level, and renders both files through the config
engine. With `site_id`, sets that one site's policy.

The preflight runs first in both cases. Enabling a site's policy on a server
whose WAF cannot load would write a rules file nothing reads and report success.
A per-site enable also requires the server-wide WAF to be on already, and says
so rather than silently enabling it.

`mode: off` is refused as a contradiction — `waf.disable` is how you switch
something off. A paranoia level outside 1–4 is refused because it would fail
*quietly*: CRS tests no such level, so the rule set would behave as if it were
at level 1 while the panel displayed whatever was typed.

Both rendered files go through the config engine with `nginx -t` as the
validator, so a rules file ModSecurity cannot read fails validation and the
whole change rolls back before any reload.

### `waf.disable`

| | |
|---|---|
| Permission | `server_manage` |
| Execution | task (not cancellable, idempotent) |
| Input | `site_id` *(optional)* |

Without `site_id`, switches the WAF off server-wide by **removing** the nginx
include. Removal rather than rendering `modsecurity off;`: if the module is not
loaded, *any* `modsecurity` directive is an unknown directive and nginx will not
start, so removal is the only spelling of "off" that is safe in both worlds.
`/etc/ferrum/waf/main.conf` is left in place — nothing reads it once the include
is gone, and keeping it means re-enabling restores the policy that was there.

With `site_id`, writes an explicit `off` policy for that site rather than
deleting its row. A deleted row means "inherit the server default", and if that
default is `block` then deleting would *enable* the WAF on a site somebody had
just asked to switch it off for.

### `waf.rules.set`

| | |
|---|---|
| Permission | `server_manage` |
| Execution | task (not cancellable, idempotent) |
| Input | `exclusions` — a list of `{ rule_id, site_id (optional), reason }` |

Replaces the whole exclusion list in one transaction. Wholesale replacement
rather than add/remove verbs: the list is short, an operator edits it as a list,
and a partial apply would leave the rendered rules file agreeing with neither
the old list nor the new one.

A server-wide exclusion (`site_id` absent) renders as `SecRuleRemoveById` after
the CRS includes — after, because the directive can only remove a rule that has
already been defined. A site-scoped exclusion renders as a `ctl:ruleRemoveById`
action on that site's own phase-1 rule, which is what keeps one tenant's
exclusion off another tenant's traffic.

`reason` is required and may not contain line breaks. Required because an
unexplained hole in a WAF is indistinguishable from an attacker's and will
outlive whoever opened it; single-line because it is rendered as a `#` comment
in the rules file and a newline would end the comment.

When the WAF is off the list is stored but nothing is rendered, and the result
says `applied: false` so "stored" is not read as "in effect".

## Security posture

### `security.posture`

| | |
|---|---|
| Permission | `server_read` |
| Execution | immediate |
| Input | none |

The one-page checklist scan (spec §11.9's security advisor). Returns findings
ordered most severe first, each with a stable `id`, a `severity`, a one-line
plain-language `risk`, a `remedy`, and where relevant the `subject` it is
about — plus the `facts` every verdict was derived from, so a sceptical operator
can see the evidence rather than take the verdict on faith.

`server_read`, not `server_manage`: telling somebody their server accepts
password logins is how they come to fix it, and gating that behind the
permission to change the server would keep the report from the person most
likely to act on it.

**A check whose evidence could not be gathered produces an `unknown` finding
naming what failed. It never produces silence and never produces a clean
result.** "We could not read sshd's configuration" and "sshd is configured
safely" are different answers, and rendering them identically converts an
unknown into a reassurance.

The checks:

| id | severity | what it asserts |
|---|---|---|
| `ssh.password_auth` | high | `PasswordAuthentication` or `KbdInteractiveAuthentication` is on |
| `ssh.root_login` | critical with passwords, medium without | `PermitRootLogin yes` |
| `firewall.absent` | high | no firewall backend was detected |
| `firewall.inactive` | high | a backend is installed but not running |
| `mariadb.off_loopback` | critical | something is listening on 3306 on a non-loopback address |
| `panel.tls_missing` / `panel.tls_expired` | high | the panel has no certificate, or an expired one |
| `panel.tls_expiring` | medium | fewer than 14 days left |
| `sites.no_certificate` | medium | sites served over plain HTTP, named |
| `sentinel.disabled` | low | brute-force defence is switched off |
| `updates.security_pending` | high | the package manager has pending security updates |

Each check also has an `*.unknown` sibling (`ssh.unknown`, `firewall.unknown`,
`mariadb.exposure_unknown`, `updates.unknown`) for the case where the evidence
could not be gathered.

Four details worth knowing:

**SSH is read twice.** `sshd -T` is asked first — it is sshd's own settled
answer with `Include` resolved. When it cannot run, `/etc/ssh/sshd_config` and
`/etc/ssh/sshd_config.d/*.conf` are parsed directly and the finding's remedy
says so, because file parsing is an approximation of sshd's resolution. sshd's
rule is **first value wins**, the opposite of nearly every other configuration
format, and settings inside a `Match` block are skipped — Ferrum's own
chrooted-SFTP drop-in is such a block, and reading its contents as global
settings would report the SFTP group's policy as the server's.
`KbdInteractiveAuthentication` is checked alongside `PasswordAuthentication`
because turning the latter off is widely believed to be enough and on most
distributions is not: PAM keyboard-interactive still asks for the same password.
An absent setting reads as OpenSSH's *default*, not as the safe value — a check
that assumes safety when it sees nothing reports safety on a file it failed to
parse.

**Listening sockets come from `/proc/net/tcp` and `/proc/net/tcp6`, not from
`ss`.** This is a security check, and a check that depends on a tool being
installed and its output format holding still is a check that fails open on the
day it matters. Only sockets in state `0A` (LISTEN) count, so an outbound
connection to somebody else's database is not reported, and an IPv4-mapped
loopback address is normalised so `::ffff:127.0.0.1` is not read as public.
`mariadb.off_loopback` is the exact state a live AlmaLinux box was found in
after a panel install; `ferrum_ops::harden` now prevents it at install time and
this check is what catches it coming back.

**The update count uses cached package metadata only** (`apt-get --no-download`,
`dnf --cacheonly`), because this runs on a dashboard page load and a check that
goes to the network turns that into a wait on a slow mirror. Only updates from a
security suite are counted: "17 packages have newer versions" is always true and
always ignored, while "3 security updates are pending" is worth interrupting
somebody for.

**A certificate inside the normal renewal window is not a finding.** Renewal
starts at 30 days, so a panel certificate at 29 days is normal; the warning
threshold is 14, which means renewal has been failing for two weeks.

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
## Backups

Backups are restic repositories driven over argv by `ferrum_ops::backup`
(spec §11.10). Three properties of that module decide how these operations
behave, and each of them is a decision rather than an accident:

**Secrets travel in the environment, never in argv.** `RESTIC_REPOSITORY`,
`RESTIC_PASSWORD` and the S3 credentials reach restic as environment variables.
`/proc/<pid>/cmdline` is mode 0444 — every hosted tenant on the box can read
root's command lines with `ps auxww` — while `/proc/<pid>/environ` is 0400 and
owned by the process's uid. A password on the command line would therefore be a
password published to every tenant. `Cmd` also clears the child's environment,
so restic sees exactly those variables and nothing the agent was started with,
and the task log renders argv only.

**The repository password is shown once and cannot be recovered.** See
`backup.repo.init` below; this is the disaster-recovery decision of the whole
area, and it has an operator obligation attached to it.

**Snapshots are tagged by scope.** A panel backup is tagged `ferrum-panel` and
a tenant's is `ferrum-sub-<subscription id>` — the id, never the Linux user
name, which can be recycled when a tenant is deleted and recreated. Retention
runs `restic forget --prune --tag <tag> --group-by tags`, so one repository can
hold the panel's history and every tenant's without one policy deleting
another's snapshots.

Every operation below needs `backup_manage`, and every one except `backup.run`
and `backup.list` additionally requires **administrator scope**: repositories
carry credentials that cover the whole server, and a restored tree can contain
`/etc/ferrum/secret.key` and any tenant's private files. A scoped caller
reaching one of those gets `FER-1002 permission_denied`.

restic itself is installed on first use through the package backend. If it
cannot be installed, the failure names the package and — on EL, where restic
lives in EPEL rather than the base repositories — the repository to enable,
because `No match for argument: restic` on a fresh AlmaLinux otherwise sends an
operator hunting for a typo.

### `backup.repo.init`

| | |
|---|---|
| Permission | `backup_manage` (administrator scope) |
| Execution | immediate |
| Input | `kind` — `local` or `s3`; `label`; `path_or_url`; `s3` *(optional object: `access_key_id`, `secret_access_key`, `region` (optional))* |

Creates a repository: generates a 32-character alphanumeric password, seals it
under the master key, writes the row, then runs `restic init
--repository-version 2`. If restic fails, the row is rolled back so the operator
can fix the endpoint and re-use the same label. `path_or_url` is an absolute
path for `local` (no `..`), and `endpoint/bucket[/prefix]` for `s3` — the `s3:`
scheme prefix is added by the panel, so pasting one in does not produce
`s3:s3:`. Control characters are refused: a NUL in the middle of
`RESTIC_REPOSITORY` would silently truncate it and send the backup somewhere
other than where the row says.

**The response contains the repository password, once.** There is no operation
that reveals it again, and that is deliberate: one that could would turn a
stolen admin session into every backup this panel has ever taken.

The consequence has to be stated plainly, because it is the difference between
a backup and a false sense of one. A restic repository is encrypted and its
password is the only key. The panel keeps a sealed copy so the scheduler can run
an unattended backup at three in the morning — but that copy lives in
`panel.db`, and `panel.db` is *inside* the panel-scope backup. **If the panel
database is the only holder of the password, a panel-scope backup cannot be
restored after losing the panel.** The key to the safe would be inside the safe.

Recovering a lost panel therefore needs two things kept **off this server**:

1. the password returned here, at creation; and
2. `/etc/ferrum/secret.key`, the master key — because every other secret in the
   restored database (ACME account keys, database passwords, notifier tokens) is
   sealed under it and is ciphertext without it.

With both, `restic restore` against the repository yields `panel.db`,
`/etc/ferrum` and the state directory, which is the whole of the panel's state.

Immediate rather than a task, for two reasons that are both about secrets: a
task persists its *input* verbatim in `tasks.input` — which here would write the
S3 secret access key into the database in the clear, beside the sealed copy —
and a task discards its output, which here is the password.

### `backup.repo.delete`

| | |
|---|---|
| Permission | `backup_manage` (administrator scope) |
| Execution | immediate |
| Input | `repo_id` |

Makes the panel forget a repository. **Nothing inside it is deleted** — not the
snapshots, not the data; wiping a bucket is not an action that belongs behind a
row in a list, and an operator who wants the data gone has `restic forget` and
their storage provider's console. Refused with `FER-1403 already_exists` while
any run is recorded against the repository: that history is the panel's only
record of which snapshots exist, and dropping it would leave data in a bucket
nobody can account for. The check is made before the delete so the refusal says
why, instead of surfacing the schema's `ON DELETE RESTRICT` as an opaque
database error.

### `backup.schedule.set`

| | |
|---|---|
| Permission | `backup_manage` (administrator scope) |
| Execution | immediate |
| Input | `repo_id`; `scope` — `panel` or `subscription`; `subscription_id` *(optional; required for `subscription` scope, refused for `panel`)*; `cron`; `keep_daily` *(optional, default 7)*; `keep_weekly` *(optional, default 4)*; `keep_monthly` *(optional, default 6)*; `enabled` *(optional, default true)* |

Records when a scope is backed up and how much history is kept. `cron` is a
five-field expression (`minute hour day-of-month month day-of-week`) and is
*parsed* here, not merely stored — an expression the scheduler cannot read is a
schedule that silently never fires, and the moment to discover that is while
somebody is looking at the form. The retention counts are bounded to 0–3650:
they reach restic's argv as `--keep-daily <n>`, and a five-digit one is a typo,
not a policy.

Administrator-only, and this is the operation that grants a tenant access to a
repository at all. `backup.run` lets a scoped caller write only into a
repository an administrator has already pointed a schedule for *their*
subscription at, so a tenant who could write their own schedule could grant
themselves that access — and repository ids are small integers that are trivial
to walk.

### `backup.schedule.delete`

| | |
|---|---|
| Permission | `backup_manage` (administrator scope) |
| Execution | immediate |
| Input | `schedule_id` |

Stops a schedule firing. The runs it already made keep their rows, with
`schedule_id` set to NULL rather than cascaded away: turning off a schedule must
not erase the evidence of what it did.

### `backup.run`

| | |
|---|---|
| Permission | `backup_manage` (administrator scope for `panel`) |
| Execution | task — not cancellable, idempotent |
| Input | `repo_id`; `scope` — `panel` or `subscription`; `subscription_id` *(optional; required for `subscription` scope, refused for `panel`)* |

Takes one snapshot, streaming restic's output into the task log line by line.
The per-second `status` progress messages are filtered out — a two-hour backup
would otherwise be hundreds of thousands of log rows — and the final `summary`
message is where the snapshot id and byte count come from. A restic old enough
not to emit a summary still took a perfectly good backup, so its absence is
recorded as a nameless snapshot rather than a failed run.

**Panel scope** writes a consistent copy of the panel database with `VACUUM
INTO`, then backs that copy up together with `/etc/ferrum` and the state
directory (certificates and ACME accounts). It never copies `panel.db` itself:
the panel runs SQLite in WAL mode, where the `.db` file alone is an arbitrarily
stale prefix of the truth — committed transactions live in `panel.db-wal` until
a checkpoint folds them in. Copying it produces a file that restores to some
earlier state, or to no valid state at all if a checkpoint lands mid-copy. It is
the classic backup that only fails when you finally need it. The working copy is
0600, lives in `<state>/backup-work`, and is deleted on every path out of the
run including the failing ones — it is a complete second copy of every sealed
secret the panel holds.

**Subscription scope** writes the tenant's home directory. Database dumps are
not yet part of it; see *Not implemented* below.

A run row is created *before* restic starts, and finished with restic's own
words on failure, so a crash mid-backup leaves evidence rather than silence and
the history can answer "when did this stop working" (spec §11.10 AC: a corrupted
target produces an alert, not a silent success).

Retention runs afterwards, and only after the run is recorded successful —
pruning before the new snapshot is safely in would be deleting old backups on
the strength of one that might yet fail. The policy comes from the first enabled
schedule covering this repository and scope, so a manual run prunes exactly as a
scheduled one would; a scope with no schedule prunes **nothing**, because
inventing a policy would be the panel deleting snapshots nobody asked it to
delete. A failed prune never fails the run: it leaves more history than asked
for, which is a disk problem, where a run reported as failed after the snapshot
is safely written is a correctness problem — the next thing an operator does is
re-run it, and what they conclude is that backups are broken.

Not cancellable, because killing restic mid-write leaves a lock for the next run
to clear rather than stopping cleanly. Idempotent: a repeat costs time and
produces a second snapshot, which retention then prunes.

A scoped (non-administrator) caller may run a backup only for a subscription
their own scope resolves, and only into a repository an administrator's schedule
already points at for it. Anything else answers `not_found`, not
`permission_denied`, so a customer walking repository ids cannot learn which
repositories exist.

### `backup.list`

| | |
|---|---|
| Permission | `backup_manage` |
| Execution | immediate |
| Input | `repo_id`; `subscription_id` *(optional)* |

`restic snapshots --json`, parsed. Unknown fields are ignored and missing
optional ones default, so the panel does not stop listing snapshots the day
restic adds a field; only `id` is required, since a snapshot without one is not
something a restore could ever name.

A snapshot list names paths and hostnames across the whole server, so a scoped
caller sees only snapshots tagged for a subscription they own — and the tag is
derived from a subscription resolved through their own scope, never taken from
the request. An administrator may pass `subscription_id` to narrow the list, or
omit it for everything in the repository.

### `backup.restore`

| | |
|---|---|
| Permission | `backup_manage` (administrator scope) |
| Execution | task — not cancellable, idempotent |
| Input | `repo_id`; `snapshot_id` — 8–64 hex characters, or `latest` |

Restores a snapshot into a fresh **staging directory** under
`<state>/restore/<timestamp>-<snapshot>` and reports where it landed. Nothing
live is touched. The directory is 0700 before restic writes a byte, because a
restored tree can contain `/etc/ferrum/secret.key` and every tenant's private
files — and the response says so, along with a reminder to delete the staging
directory once it has been picked over. One directory per restore, so two
restores of the same snapshot cannot merge into one tree and an operator can
still tell them apart afterwards.

`snapshot_id` is validated strictly because it is the one value in this area
that *does* reach argv: hex cannot begin with a dash, so a validated id can
never be read by restic as a flag.

### The `backup.scheduler` job

Not an operation — a job in the agent's internal scheduler
(`crates/ferrum-agentd/src/scheduler.rs`), running every 60 s with 10 s of
jitter. Every minute, because the schedules are cron expressions whose finest
granularity is one minute; a slower job would silently skip the minute a nightly
backup asked for.

Deliberately not a Task, for the same reason as `sentinel.scan` and
`alerts.evaluate`: it wakes 1,440 times a day and decides nothing on almost all
of them, and a task row per tick would bury the tasks a human started. The
backups it does start each get a `backup_runs` row, which is what the history
reads.

The due check walks back minute by minute from now to the schedule's last run
(capped at 24 hours) rather than asking only whether the current minute matches:
the loop wakes on a jittered interval and can miss a wall-clock minute entirely,
and an agent that was restarted has missed every minute it was down. Missing the
nightly backup because the agent was updated at 03:00 is exactly the failure
this avoids. A schedule that has never run looks back only five minutes, so
creating one at two in the afternoon does not immediately fire last night's
backup. One schedule failing — a dead S3 endpoint, an unreadable cron
expression — is logged and stepped over; it must not stop every other tenant's
backup that night.

### Not implemented, on purpose

- **In-place restore.** `backup.restore` stages; it never writes recovered files
  over live ones. That is a different operation with a very different blast
  radius, and it belongs with a UI that can show what is about to be
  overwritten.
- **Adopting an existing repository.** `backup.repo.init` creates. It cannot
  take over a repository somebody else initialised, because the panel would have
  to be told that repository's password — and a panel that can be told a
  password is a panel that can be made to show one.
- **Database dumps in the subscription scope.** Spec §11.10 wants
  `--single-transaction` dumps streamed into the repository. Subscription scope
  currently covers the tenant home only.

## WordPress toolkit

The `wp.*` operations are `ferrum_ops::wordpress` (spec §11.12). Four
properties of that module decide how all six behave, and each is a decision
rather than an accident.

**WP-CLI runs as the tenant, never as root.** WP-CLI is a PHP program that
loads the site's own `wp-config.php`, plugins and themes — that is, code the
tenant controls, and on a shared box a plugin is not trusted input. Every run
therefore goes through `ferrum-agentd --wp-helper`, which re-execs the agent
binary (`ferrum_distro::exec::reexec_current`), calls
`setgroups`/`setgid`/`setuid`, and **proves** the drop by checking that
`setuid(0)` now fails, before a single byte of PHP is loaded. It is the same
`drop_privileges` the file manager's helper uses (spec §5.2 rule 3).

It is a second *entry point*, not a second mechanism. The file manager's
protocol (`FsRequest`) is a closed set of filesystem verbs with no arm that
carries a command, and widening it so that helper could also execute programs
would turn the panel's most tightly bounded interface into a general exec
channel. What the two share is the part that matters: the re-exec, the drop and
its proof. On an agent that is *already* unprivileged (`--dev`, tests) there is
no privilege to shed and PHP runs in-process — the same `Local`/`Tenant` split
`fsops::FsRunner` makes, for the same reason.

**`wp.cli` is not a shell.** The command group is a closed enum (`core`,
`plugin`, `theme`, `option`, `user`, `db`, `cache`, `rewrite`), so `eval`,
`eval-file`, `shell`, `server`, `package` and `cli` are not spellable at all.
Each argument must be ASCII, free of control characters and free of shell
metacharacters, and must not name a reserved flag: `--path` (the panel decides
which installation), `--require` (loads an arbitrary PHP file), `--exec` (runs
arbitrary PHP), `--ssh`, `--http`, `--prompt` (would block until the timeout)
and `--context`. The `--no-` negation spelling is refused too. `--path=<dir>`
is prepended by the panel and is always the first argument, and the
privilege-dropping helper **re-checks the reserved list and that `--path`
matches the directory it was told about** — after the drop, because that is
where the privilege boundary is, and a bug on the agent side must not become
arbitrary code execution inside a tenant account.

The metacharacter refusal is worth a sentence of its own. Through
`ferrum_distro::Cmd` an argv reaches `execve` untouched, so `;` and backticks
are already inert *for us* — but WP-CLI builds its own `mysql` and `mysqldump`
command lines for parts of `wp db`, and our argv discipline does not extend
into another program's process spawning.

**The WP-CLI phar is pinned, and its pin has one source.** The panel installs
WP-CLI 2.12.0 from the upstream GitHub release, refuses to install it unless
the SHA-256 matches `WP_CLI_SHA256`, and stores it root-owned 0755 under
`/var/lib/ferrum/wp-cli/` — a tenant runs it but must never be able to replace
it. The checksum was computed from the asset and agrees with the publisher's
own `.sha512` file in the same release; the release also carries a detached
OpenPGP signature (issuer `63AF7AA1 5067C056 16FDDD88 A3A2E8F2 26F0BC06`,
`releases@wp-cli.org`) which **this build does not verify**. Every observation
therefore comes from one host, so the pin protects against a later tampered or
truncated download, not against the source having been wrong on the day it was
pinned. `wp.detect` reports that provenance the way `db.adminer.status` reports
Adminer's.

**No password is ever returned or logged.** The database password reaches
exactly two places — the string the panel renders and the `wp-config.php` it
writes — and never an argv, a task log or an operation output. The WordPress
administrator password is generated for `wp core install` and discarded. Both
have to work this way: a task's `input_json` is stored verbatim with no
redaction (unlike audit details, which redact by key), and a task's *output* is
never delivered to the caller at all — only its log survives, and a log is
exactly where a credential must not be. Rotate the database password with
`db.user.password`; reset the WordPress administrator with
`wp.cli user update <user> --user_pass=…` or WordPress's own password-reset
mail.

Every operation below needs `site_manage`, and every one resolves its subject —
a site id, or an install id — through the caller's `TenantScope`. Another
tenant's install id answers `not_found`, which is exactly what a nonexistent id
answers.

### `wp.install`

| | |
|---|---|
| Permission | `site_manage` |
| Execution | task (not cancellable, not idempotent) |
| Input | `site_id`; `subdirectory` *(optional tenant-relative path under the document root)*; `locale` *(optional, `en_US` by default; `fa_IR` is first-class)*; `title`; `admin_user`; `admin_email`; `auto_update` *(optional bool)* |

One-click WordPress. In order: refuse if the site already has an install row or
the directory already holds a `wp-config.php`; download and verify the pinned
WP-CLI phar if it is not already on disk; create a MySQL user and database
**through `db.user.create` and `db.create`** rather than any SQL written here;
`wp core download --locale=…`; render `wp-config.php` and write it as the
tenant; `wp core install`; record the row.

`wp-config.php` is rendered by the panel rather than by `wp config create`,
because that command takes the database password as `--dbpass=…` — a
long-lived credential in a process's argv, and `/proc/<pid>/cmdline` is
world-readable on a box whose whole point is that other people's code runs on
it. The eight WordPress salts come from a CSPRNG on this server (the same
`rand::thread_rng` the panel's database passwords use); they are the site's
cookie-signing keys, so a predictable one lets anyone forge an admin session.
The file is written **through the file-manager helper, as the tenant**, at mode
0640: the install directory is tenant-controlled, so a root process writing
there could be aimed at `/etc/shadow` with a pre-placed symlink, and the helper
resolves paths as the tenant and refuses symlinks. `DISALLOW_FILE_EDIT` and
`FS_METHOD = direct` are set (spec §11.12's "basic hardening toggles"); the
theme/plugin editor is a code-execution surface reachable from a stolen admin
session.

Not idempotent, because it creates a database and a database user and a retry
would try to create a second pair. Not cancellable, because the dangerous
moment is between "database created" and "install row written" — on any failure
after that point the operation drops the database and the user itself, in
reverse creation order. The **files are deliberately left in place**: they are
the tenant's, the failure text names the directory, and deleting a tree the
panel only partly wrote is how a panel eats somebody's data.

The response carries the install id, path, URL, version, locale, the database
and user names, and a note explaining where the credentials went. It carries no
password.

### `wp.detect`

| | |
|---|---|
| Permission | `site_manage` |
| Execution | immediate |
| Input | `site_id`; `subdirectory` *(optional)* |

Is there a WordPress on this site? Presence is decided from the filesystem —
`wp-config.php` and `wp-load.php` both present — and not from the install row,
because a panel that reports "installed" on the strength of a row is wrong
exactly when it matters. Also returns the install row if the panel has one
(absent for a WordPress somebody imported or uploaded), the core version
WP-CLI reports, and the pinned WP-CLI version with its pin provenance.

A WP-CLI failure here is *information*, not an error: `version` comes back
`null` rather than failing the call, because a broken installation is precisely
what an operator opens this screen to find out about. The version, when
observed, is cached on the row so a list page need not spawn one PHP process
per site — and caching it never touches the `auto_update` policy the operator
set.

### `wp.update`

| | |
|---|---|
| Permission | `site_manage` |
| Execution | task (not cancellable, idempotent) |
| Input | `install_id`; `version` *(optional, e.g. `6.8.2`)*; `update_db` *(optional bool, default true)* |

`wp core update`, then `wp core update-db` unless asked not to — the second is
what WordPress itself prompts for after a core update. Idempotent because
updating an already-current install is a no-op that exits 0, so a retry after
an agent restart is safe. `version` goes through the same argument validator
the passthrough uses and must additionally look like a version (digits, dots
and dashes). The observed version afterwards is cached on the row.

### `wp.plugin.list`

| | |
|---|---|
| Permission | `site_manage` |
| Execution | immediate |
| Input | `install_id` |

`wp plugin list --format=json --skip-plugins --skip-themes`, passed through as
parsed JSON rather than re-modelled: the fields are WordPress's to define, and
a struct here would silently drop whatever it did not know about. The two
`--skip-*` flags matter — a plugin that fatals on load must not take the
listing down with it, because this is the screen an operator opens *to find*
the broken plugin.

### `wp.plugin.update`

| | |
|---|---|
| Permission | `site_manage` |
| Execution | task (not cancellable, idempotent) |
| Input | `install_id`; `plugins` *(optional list of slugs; empty means every plugin with an update available)* |

Each slug is validated as a slug — WordPress's own alphabet for a plugin
directory, so `--all` cannot be smuggled in as one. WP-CLI's own report comes
back verbatim: plugin updates partially succeed all the time (one download
fails, four update fine), and a boolean would throw away the only description
of which was which.

### `wp.cli`

| | |
|---|---|
| Permission | `site_manage` |
| Execution | immediate |
| Input | `install_id`; `subcommand` — one of `core`, `plugin`, `theme`, `option`, `user`, `db`, `cache`, `rewrite`; `args` *(optional list, at most 32, each at most 512 bytes)* |

The restricted passthrough described above. Returns the exact argv WP-CLI
received (`--path` included, so there is no hidden rewriting), its exit status,
stdout and stderr.

**A non-zero exit is data, not a failure.** `wp option get missing_key` exits
1, and an operation that turned that into `FER-1601` would make half of WP-CLI
unusable.

Immediate rather than a task, because a passthrough whose output is discarded
would not be a passthrough — a task delivers only its log. The cost is a
25-second ceiling, chosen to sit inside the 30-second IPC call timeout so a
slow command produces a clear error instead of `agent_unavailable` from a dead
round trip. Work that legitimately takes longer has its own operations.

`wp db cli` is refused: it opens an interactive `mysql` session and, with no
terminal, would block until the timeout — a denial of service dressed as a
feature request.

The REST layer records the command *group* and the argument count in the audit
log, never the argument values: `wp user update admin --user_pass=…` and
`wp option update stripe_key sk_live_…` are both ordinary uses of this
endpoint, and an audit row is browsable by anyone holding `audit_read`
(spec §12 rule 6).

### Not implemented, on purpose

- **Clone-to-staging and push-to-production** (spec §11.12). They need a
  second site, a database copy and a URL search-replace across a serialised
  blob; each is its own operation with its own failure modes.
- **The magic one-time admin login link** (spec §11.12). It is the intended way
  back into a fresh install, and it is why `wp.install` can decline to hand
  back a password at all.
- **A UI page.** The backend and the REST surface are complete; no
  `ui/src/routes/wordpress.tsx` exists yet.
- **Verifying the WP-CLI release signature.** The fingerprint is recorded in
  `WP_CLI_SIGNING_KEY_FPR`; verifying it through `ferrum_distro::pgp` (the way
  repository keys already are) is what would make the pin multi-source.
- **The auto-update runner.** `wp_installs.auto_update` is stored and
  `Db::wp_installs_with_auto_update()` exposes it, but no scheduler job walks
  it yet; the safe-hour window and pre-update snapshot the spec asks for belong
  with that job.

---

## Webhooks

Outbound event delivery (spec §2.4, §9 `webhooks`, §14 Phase 6). Ferrum will
never grow a billing module, so it has to be a panel somebody else's billing
module can watch. Four operations register endpoints; a scheduler job
(`webhook.deliver`, every 30 s) does the sending.

Three properties shape every operation below, and each is explained in full in
**`docs/webhooks.md`**, which is the contract an integrator implements against:

- **Deliveries are signed.** `X-Ferrum-Signature: v1=<hex>` is an HMAC-SHA256
  over `v1:<X-Ferrum-Timestamp>:<raw body>`, so a receiver can prove the panel
  sent it *and* refuse a replay — the timestamp is inside the MAC precisely so
  it cannot be edited by anyone who did not have the secret.
- **Delivery is at-least-once and bounded at both ends.** Each delivery gets
  six attempts on a 30/60/120/240/480-second curve; a hook whose *consecutive*
  failures reach 20 is switched off with a reason and its queue abandoned. A
  dead endpoint must not become an unbounded retry queue.
- **The event catalogue is closed.** A name that is not one the panel emits is
  refused, because a typo is otherwise a hook that looks configured and never
  fires. The catalogue: `account.created`, `quota.near_limit`,
  `certificate.renewed`, `backup.completed`, `backup.failed`,
  `subscription.suspended`, `site.created`, `site.deleted`, plus `*` for all of
  them.

The permissions are `server_read` to look and `server_manage` to change.
Registering a hook means this panel will POST its internal events to an address
of the caller's choosing, which is a server-configuration change rather than a
tenant one. (Spec §6.1's permission set is fixed for this wave; a dedicated
`webhook_manage` permission is the natural follow-up, and the rows are already
owner-scoped for it.)

### `webhook.list`

| | |
|---|---|
| Permission | `server_read` |
| Execution | immediate |
| Input | `id` *(optional)* — also return this hook's recent delivery history |

Every hook the caller's tenant scope can see: URL, subscribed events, `active`,
the consecutive-failure count, `last_status` (the HTTP status of the most recent
attempt) and `disabled_reason` — why the panel switched it off, or `null` if a
human did. Also returns the whole event catalogue and `max_per_owner`, so a UI
never hard-codes either.

The scope resolves through `users.reseller_id` exactly as the user repository
does: an admin sees everything, a reseller its own hooks and its customers',
a customer only its own.

**The signing secret is never in the answer.** It is not merely omitted from
this output — `ferrum_db::Webhook` marks the field `#[serde(skip)]`, so no
future caller can serialise it by accident.

With `id`, the hook is resolved through the caller's scope *first*, so an id
outside it answers `not_found` rather than an empty history — "there are no
deliveries" and "that is not yours" are different answers and only one of them
is true. The history is the last 50 attempts with their status, attempt count,
response code and last error.

### `webhook.set`

| | |
|---|---|
| Permission | `server_manage` |
| Execution | immediate |
| Input | `url`; `events`; `id` *(optional)* — update this hook instead of creating one; `active` *(optional bool, default `true`)*; `owner_user_id` *(optional)* — defaults to the caller's own account; `rotate_secret` *(optional bool, default false)* |

Creates a hook, or updates the one named by `id`.

**On create the signing secret is minted and returned once**: 32 bytes of
CSPRNG, hex-encoded, sealed with the panel master key (spec §12 rule 6) on the
way into the database and never readable again. On update it is absent unless
`rotate_secret` is set, which is how a leaked secret is replaced — and which
invalidates every signature made with the old one immediately.

`owner_user_id` is resolved **through the caller's scope**, so an id outside it
is `not_found` and cannot be used to plant a hook on somebody else's account. A
hook cannot be moved between accounts afterwards; the REST layer drops the field
on the update path rather than letting a client that round-trips a hook object
trip over the refusal.

The URL must be `http://` or `https://`, under 2048 characters, with no
whitespace or control characters — an embedded newline is header injection into
the request the panel is about to build. Private and loopback addresses are
**not** blocked: only an account holding `server_manage` can register a hook,
that account already has root on the machine, and relaying through
`http://127.0.0.1:9000/hook` is a legitimate and common setup.

Re-enabling a hook clears its failure bookkeeping. That is the point of the
verb: an operator who fixed their endpoint has said the previous failures are
history, and leaving the counter at its threshold would disable the hook again
on the first hiccup.

An account may hold at most 20 hooks. The cap is enforced inside the `INSERT`
rather than as a read-then-write, so two concurrent creates cannot both see
"19 hooks" and both insert; past it the answer is `FER-1403 conflict`.

### `webhook.delete`

| | |
|---|---|
| Permission | `server_manage` |
| Execution | immediate |
| Input | `id` |

Removes a hook and, by cascade, everything still queued for it. Resolved
through the caller's scope, so guessing an id is not a way in.

### `webhook.test`

| | |
|---|---|
| Permission | `server_manage` |
| Execution | immediate |
| Input | `id` |

Sends one synthetic delivery and reports what the endpoint answered:
`delivered`, the HTTP `status` if one was seen, the `error` if not, and the
`timestamp` and `signature` that were sent — the last two so somebody writing
the receiving side can diff their own computation against the panel's.

Synchronous rather than queued, and that is the whole value: an operator
pressing "test" wants the answer, not a task id and a promise.

The payload carries the reserved event name `webhook.test`, which is
deliberately **not** in the catalogue and cannot be subscribed to, so a receiver
switching on `event` can tell a drill from the real thing. Its `id` is `0`: a
probe has no delivery row, and saying so beats colliding with a real delivery a
receiver has stored.

**A test counts toward the failure streak.** It is a real POST to a real
endpoint, and an operator who tests a hook twenty times against a dead host has
taught the panel exactly what twenty failed deliveries would.

---

## Plugins

The extension system (spec §6 plugin note, §14 Phase 6), **sidecar model only**.
Spec §6 is explicit — *"Do NOT let plugins run in-process as root"* — so a
plugin is a separate process, started under a dedicated unprivileged system
account, inside a systemd unit carrying the same hardening as the panel's own
`ferrum-web` unit, speaking the panel's existing length-prefixed JSON framing
(`ferrum-ipc`) over its own Unix socket.

The full contract — the manifest format, the trust model, the socket protocol
and a working sidecar in twenty lines — is **`docs/plugins.md`**. Two properties
matter enough to restate here:

- **The manifest is the routing authority.** A plugin declares its extension
  points at install time; the stored list is what the agent routes against, and
  a running sidecar is never asked what it thinks it provides. A plugin that
  declared `notifier` and is asked for `dns.present` is refused before a socket
  is opened.
- **A plugin can never register an operation.** The registry is built from a
  fixed list in Rust and nothing here inserts into it. That is load-bearing:
  the registry is where the permission check lives, so an extension point that
  could add an operation would be one that could add an unchecked one. Plugins
  are reached *through* operations, never as them.

### `plugin.list`

| | |
|---|---|
| Permission | `server_read` |
| Execution | immediate |
| Input | *(none)* |

Every installed plugin: slug, name, version, the validated manifest, the
declared extension points, the install directory, the account its sidecar runs
as, how it was signed (`minisign` or `unsigned`), whether it is enabled, and the
last error its sidecar reported. Also returns this build's extension-point
catalogue, the plugin `api_version`, whether `plugins.allow_unsigned` is on, and
how many trusted signing keys are configured — which is what an operator needs
to see next to "unsigned plugins: refused".

### `plugin.install`

| | |
|---|---|
| Permission | `server_manage` |
| Execution | task (not cancellable, **not** idempotent) |
| Input | `source` — an absolute path to a staged plugin tree containing `plugin.toml` |

Verifies a payload and installs it **disabled**.

**The panel does not fetch anything.** Staging is the operator's step; a
marketplace client (spec §14 Phase 6) belongs above this layer and would stage a
tree exactly like this one. `source` must be absolute and canonical, and may not
be under `/home` — a tree a tenant can rewrite between the moment it is verified
and the moment it is copied would make the signature check theatre.

The order of the checks is the design, and each refusal leaves nothing behind:

1. **The manifest** is parsed and validated: the slug's alphabet (the
   intersection of a systemd unit-name component, a Unix account name and a path
   component), the entry point (relative, traversal-free, and free of anything
   systemd would read as syntax in `ExecStart=`), the protocol version, a
   non-empty duplicate-free extension list, and a `[files]` digest table that
   includes the entry point — an unlisted file is an unverified file.
2. **Authenticity**: `plugin.toml.minisig` is verified in-process against the
   keys in `plugins.trusted_keys`, the same ed25519/minisign format the
   installer verifies releases with (spec §5.5). Both the payload signature and
   the global signature over the trusted comment are checked. A signature from a
   key nobody has said they trust is `FER-1300`, and so is a signed plugin
   installed while no trusted keys are configured — a signature nobody trusts is
   not better than no signature, it is just longer.
3. **Unsigned payloads are refused** unless `plugins.allow_unsigned` is
   explicitly on (it defaults to **false**). The refusal names the setting. The
   reasoning is in `docs/plugins.md`: a plugin is code the agent starts as a
   service on a machine full of other people's websites, and "I downloaded it
   from somewhere" is not a trust decision a panel makes on an operator's
   behalf. When it *is* on, the decision is recorded on the row
   (`signature = "unsigned"`) rather than forgotten.
4. **Integrity**: every listed file must match its SHA-256, **and every file in
   the tree must be listed**. The second direction is the one that matters — a
   checker that only verifies what the manifest mentions is defeated by shipping
   a second binary the manifest does not mention. Symlinks are refused anywhere
   in the tree.
5. **The row is written before anything on disk changes**, so two concurrent
   installs of one slug cannot both create an account and a unit; the second is
   `FER-1403 conflict`.
6. **The account, the tree, the unit**, in that order. The tree is copied
   file by file with modes set explicitly (0755 for the entry point, 0644 for
   everything else, nothing group- or world-writable) rather than by `cp -a`,
   which would preserve whatever the staging directory happened to have. The
   unit goes through the config engine like every other file the panel owns:
   render, `systemd-analyze verify`, `daemon-reload`, rollback on failure.

A failure after step 5 unwinds the row, the tree and the unit. The **account is
deliberately not unwound**: a system account with no files is inert, and
deleting one is how a uid gets recycled onto files somebody still owns.

**Installing is not starting.** A freshly installed plugin is disabled, so an
operator can read the manifest the panel accepted before any of that code runs.
There is no in-place upgrade: installing over an existing slug is a conflict.

### `plugin.enable`

| | |
|---|---|
| Permission | `server_manage` |
| Execution | immediate |
| Input | `slug` |

Starts the sidecar (`systemctl enable --now`) and marks the row enabled, which
is what makes the agent willing to route its declared extension points. Clears
any previously recorded sidecar error. Returns the row and the unit's state.

### `plugin.disable`

| | |
|---|---|
| Permission | `server_manage` |
| Execution | immediate |
| Input | `slug` |

The reverse, and the order is the safety property: **the row is flipped first**.
If systemd refuses to stop the unit, the panel must still stop routing to it — a
plugin the registry thinks is enabled is a plugin the agent will happily dial.
A stop failure is reported, with the row already disabled and the reason
recorded.

### `plugin.remove`

| | |
|---|---|
| Permission | `server_manage` |
| Execution | task (not cancellable, idempotent) |
| Input | `slug` |

Stops the sidecar, removes the unit and reloads systemd, removes the installed
tree, and deletes the row. Every step is "make sure this is gone", which is why
it is safe to re-run: a unit that is already absent reports an error that means
"already done", and the tree is only ever removed from inside
`/var/lib/ferrum/plugins`, so a hand-edited `install_dir` cannot turn this into
a recursive delete of somewhere else.

The dedicated account is left behind and the result names it, for the same
reason `plugin.install` does not unwind it.

### Not implemented, on purpose

- **A marketplace client.** `plugin.install` takes a staged path; fetching,
  browsing and updating from a remote index (spec §14 Phase 6) is a layer above
  this one.
- **In-place upgrade.** Remove and install. Reconciling a running sidecar, a
  changed manifest and a changed extension set is its own operation with its own
  failure modes, and getting it half-right is worse than not offering it.
- **Calling plugins from the core modules.** `ferrum_ops::plugin::call` is the
  routed, permission-respecting entry point and is tested end to end against a
  real socket, but no core module consults a plugin yet: `dns.rs` still knows
  only Cloudflare, `backup.rs` only its built-in targets, `alerts.rs` only its
  own channels. Wiring each one is a change to that module, not to this one.
- **A UI page and the micro-frontend mount.** A manifest may declare a
  `ui_panel` with its `[ui]` mount point and the panel validates and stores it,
  but nothing in `ui/` renders it yet.
