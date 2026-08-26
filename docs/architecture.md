# Architecture

Three stories explain most of Ferrum: the two-daemon privilege boundary, the
operation registry that is the only door through it, and the configuration
contract that governs every file the panel writes. This page tells all three
and points into the code that enforces them — the claims here are checkable.

## Two processes, one hard boundary

```
  Browser ── HTTPS ──▶  ferrum-web        user: ferrum, no capabilities
  CLI ────── UDS ────▶   • REST API + SSE
                         • sessions, RBAC, rate limiting
                         • embedded React UI
                                │
                                │  length-prefixed JSON over /run/ferrum/agent.sock
                                ▼
                        ferrum-agentd     user: root
                         • operation registry (a whitelist)
                         • task queue and scheduler
                         • package / service / firewall backends
                                │
                                ▼
                        nginx · php-fpm · mariadb · postgres
```

`ferrum-web` faces the internet and holds nothing. It cannot restart a service,
write a config file, or read a tenant's home directory. When it needs something
done, it names an operation and sends a frame.

The design's central assumption is that the internet-facing half will one day
be compromised, and the interesting question is what happens next. The answer
is bounded by construction: a compromised web process can ask for privileged
work, but only work that is already on a list, only within the rights the
database says that account has, and only with inputs that survive validation.

## Anatomy of a privileged request

Every privileged action — from the UI, the CLI, or the scheduler — takes the
same path. Each step names the code that enforces it.

1. **The web process authorizes** the session against RBAC and sends a frame
   naming an operation (`crates/ferrum-web/src/`, routes under `routes/`).
2. **The transport authenticates the peer**, not the payload: the socket is
   0700, and `SO_PEERCRED` is checked on accept
   (`crates/ferrum-ipc/src/peercred.rs`, `server.rs`). A process that is not
   the `ferrum` user does not get to speak the protocol at all.
3. **The agent looks the name up in the registry**
   (`crates/ferrum-ops/src/registry.rs`). The registry is a whitelist, not a
   dispatcher: an unknown name is `FER-1504`, never a fallback.
4. **The agent re-derives the caller's rights from the database**
   (auth validation in `crates/ferrum-ops/src/registry.rs`) and intersects
   them with what the frame claimed. The frame's asserted permissions are advisory downward only —
   a forged context can lose privileges, never gain them.
5. **The input deserializes into the operation's typed struct**, where every
   field is a validated newtype or an enum
   (`crates/ferrum-core/src/newtypes.rs`: `Domain`, `TenantPath`, `DbName`,
   `LinuxUser`, `PhpVersion`, …). Validation runs inside `serde`, so a hostile
   frame dies at the protocol edge, before any operation code runs.
6. **The operation runs** — through `ferrum_distro::Cmd`
   (`crates/ferrum-distro/src/exec.rs`), which takes argv arrays and resolves
   programs against a fixed list of trusted directories. `Command::new` exists
   in that one file, and `tests/gates/no-shell.sh` fails CI if it appears
   anywhere else, or if a shell is ever the program. There is no path from an
   API request to a shell.
7. **The action is audited** (`crates/ferrum-db/src/audit.rs`), with secret
   fields recursively redacted before the row is written. Anything slower than
   ~300 ms runs as a Task (`crates/ferrum-agentd/src/tasks.rs`) with a
   persistent log.

An operation declares its name, its required permission and its execution mode
in one place, as constants on the type — see `TypedOperation` in
`registry.rs`. Reviewing an operation's security posture means reading one impl
block, which is the point.

## The operation registry is the security model made concrete

The registry pattern earns its structure three times over:

- **Enumerable surface.** The complete set of privileged actions is one list
  in `registry.rs`. There is no reflection, no dynamic dispatch by string into
  arbitrary code — adding power to the agent requires a code change that a
  review can see.
- **Uniform enforcement.** Permission checks, input validation and error
  mapping happen in the registry's dispatch path, not per-operation. An
  operation cannot forget to check permission, because it never sees a request
  the check has not passed.
- **Testability without root.** Operations receive an `OpContext` carrying the
  database, the distro backends and the config engine; the distro layer has
  mock backends, so every operation's logic — including its failure paths — is
  unit-tested without touching a real system.

## Why the panel going down is not an outage

Nothing in the serving path — nginx, php-fpm, the databases — depends on either
daemon at runtime. They are ordinary systemd units with ordinary configuration
files. Stop both Ferrum processes and every hosted site keeps serving.

That is a design constraint, not a happy accident, and it is why the panel can
afford to be crash-only: both daemons restart unconditionally, keep no state
that matters in memory, and reconcile whatever was in flight on the way back
up. The scheduler is built the same way: its jobs live in SQLite
(`crates/ferrum-db/src/scheduler.rs`), so a job that fell due while the agent
was down runs on the way back up instead of being skipped — verified on a live
server, where a certificate forced to twenty days remaining was renewed
unattended, production ACME order to reloaded nginx, in seconds.

## The configuration contract

Every file the panel writes — vhosts, FPM pools, systemd slices — goes through
one engine (`crates/ferrum-config/src/apply.rs`), which exists to keep two
promises: *never reload a broken configuration* and *never clobber a human's
edit*.

- **Render** from a minijinja template with strict undefined behavior
  (`templates.rs`, templates in `crates/ferrum-config/templates/`). A renamed
  variable is a render failure, not an empty string — because `server_name ;`
  is a vhost that silently swallows every request on the server.
- **Write atomically** in the target directory, fsynced before and after the
  rename, so a power cut leaves the old file rather than half the new one.
- **Validate with the service's own checker** (`nginx -t`, `php-fpm -t`)
  *after* writing, *before* reloading — writing a file changes nothing about
  the running server; only the reload does. (The spec's literal
  render→validate→move order is impossible for nginx, which can only test the
  installed tree; `apply.rs` documents why the property still holds.)
- **Roll back byte-for-byte** on any failure, including a post-check that
  fails after a reload — in which case the engine reloads back onto the old
  file.
- **Record a revision** (`crates/ferrum-db/src/revisions.rs`); any revision
  can be reactivated.
- **Detect drift** (`managed.rs`): managed files carry a
  `# FERRUM-MANAGED sha256:` header over their body. A human edit is reported
  with a diff and stops management of that file; a file the panel did not
  write is Foreign and refused outright; a forged header does not make
  somebody else's file ours.

Applies are serialized per service, so two concurrent site creations cannot
interleave a validation against a half-written tree. The operator-facing
consequences of all this are in [config-safety.md](config-safety.md).

One lesson from live verification is now part of the contract's lore: a
renewed certificate does not change the vhost text, so the engine correctly
skips the reload — while nginx keeps serving the old certificate from memory.
The thing that changed was not the thing being watched. Certificate issuance
reloads explicitly (`crates/ferrum-ops/src/cert.rs`), and the same shape has
been found and fixed twice since; when a change's effect lives outside the
file, the operation owns the reload.

## State

One SQLite file in WAL mode. No external database, because a panel that needs
MariaDB running in order to tell you why MariaDB is down has its dependency
arrow pointing the wrong way.

Writers are kept apart on purpose: the agent owns tasks and metrics, the web
process owns sessions and audit. That is what avoids lock contention under
load rather than hoping WAL absorbs it.

Repositories are tenant-scoped by construction: they take a `TenantScope`
(`crates/ferrum-db/src/scope.rs`), not a raw id, so an unscoped query is
something you must write on purpose. Secrets — the ACME account key, every
credential to come — are sealed with XChaCha20-Poly1305 under
`ferrum_db::MasterKey` (`secrets.rs`) before touching a row; the master key
refuses to load from a file anybody else can read, and its `Debug` impl prints
`<redacted>`, because the way key material reaches a log is somebody adding
`?key` to a tracing call.

## Tasks

Anything slower than about 300 ms becomes a Task: a row, a live log, and a
terminal state with a human-readable reason. The UI shows them in a drawer
that reads like a CI run — because "the button did something, probably" is the
worst part of using other panels.

Task output goes to two places at once: `task_logs`, which survives a
disconnect, and an event stream, which is what makes the drawer live. The
persisted copy is authoritative; a viewer that falls behind loses lines from
the stream, never from the record.

## Where OS differences live

`crates/ferrum-distro`, and nowhere else. Four traits — packages, services,
firewall, security module — with an implementation per family. A feature
module that knows whether it is on Debian or RHEL is a bug: unit names,
package names and firewall syntax all resolve behind those traits.

Two details worth knowing:

- **Upstream repositories are pinned in code** (`repos.rs`): full 40-hex GPG
  fingerprints, verified against the key actually downloaded by parsing the
  OpenPGP packets in-process (`pgp.rs`) — no shelling out to gpg, whose
  absence on a minimal server and instability as an interface are each reason
  enough, before the point that executing a program on attacker-influenced
  input at the moment of establishing trust is backwards.
- **The firewall backend is chosen by what actually owns the ruleset**
  (`fw.rs`) — firewalld, ufw, or nft, probed rather than assumed from the
  distro family, with an explicit `none` for a host that has no firewall,
  which says so rather than impersonating one.

Adding a distribution is implementing the traits and adding a CI image.
