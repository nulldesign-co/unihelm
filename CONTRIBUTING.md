# Contributing to Unihelm

This is the working agreement (spec §16), with the parts that are actually
enforced marked as such. The short version: the invariants below are CI gates,
the budgets are CI gates, and a change that breaks either does not merge —
however good it is otherwise.

## The workspace

```
crates/
  unihelm-core/     domain types, validated newtypes, RBAC, error taxonomy
  unihelm-db/       SQLite schema, migrations, tenant-scoped repositories, sealed secrets
  unihelm-ipc/      the framed protocol between the two daemons
  unihelm-distro/   the ONLY place OS differences live; pinned repos; Cmd (argv exec)
  unihelm-config/   minijinja templates + the render/validate/activate/rollback engine
  unihelm-ops/      the operation registry — every privileged action is a module here
  unihelm-metrics/  the metrics collector
  unihelm-web/      unprivileged HTTP server + embedded UI   (binary)
  unihelm-agentd/   root daemon: operations, tasks, scheduler (binary)
  unihelm-cli/      the `unihelm` CLI                          (binary)
ui/                React 18 + TypeScript + Vite + Tailwind, English-only i18n
installer/         preflight, install script, systemd units
packaging/         .deb / .rpm build (not yet implemented)
tests/gates/       the CI gates described below
docs/              operator, developer and API documentation
```

Dependency direction flows downward: `unihelm-core` depends on nothing of ours;
the binaries depend on everything. A feature module that knows whether it is on
Debian or RHEL is a bug — that knowledge lives in `unihelm-distro` behind four
traits (packages, services, firewall, security module), and nowhere else.

## Non-negotiable invariants

These are enforced by `tests/gates/` and code review. They are the product's
security model; there is no "just this once".

**No shell string execution.** Every command is
`Cmd::new(program).args([...])`, which becomes an `execve` with an argv array.
No `sh -c`, no `bash -c`, no building a command line out of user input — that
is the entire injection class this design deletes. `tests/gates/no-shell.sh`
proves it, and also proves that `Command::new` appears in exactly one file
(`crates/unihelm-distro/src/exec.rs`); everything else goes through `Cmd`.

**Typed, validated newtypes at every boundary.** Anything that reaches a
command line, a config template, a filesystem path or a SQL identifier is a
newtype whose only constructor validates: `Domain`, `DbName`, `TenantPath`,
`LinuxUser`, `PhpVersion`, `ManagedUnit` (`crates/unihelm-core/src/newtypes.rs`).
They validate through `serde` too, so a hostile IPC frame or API body is
rejected at the protocol edge, not deep inside an operation. If you find
yourself passing a `String` toward a privileged action, stop and mint the
newtype.

**Authorization twice.** `unihelm-web` authorizes from the session;
`unihelm-agentd` re-derives the same rights from the database and intersects
them with what the frame claimed. A forged permission set can only ever lose
privileges. Repositories take a `TenantScope`, not an id — you cannot write an
unscoped tenant query by accident, you have to ask for `TenantScope::Global`
on purpose.

**The config safety contract** (spec §10.4, [docs/config-safety.md](docs/config-safety.md))
applies to every file the panel writes, without exception:

1. rendered from a strict-undefined template — a missing value is a render
   failure, never an empty string;
2. written atomically in the target directory, fsynced;
3. validated by the service's own checker (`nginx -t`, `php-fpm -t`) before
   any reload;
4. rolled back byte-for-byte on any failure, including a failed post-check;
5. recorded as a revision;
6. and **never overwrites a human's edit** — managed files carry a
   `UNIHELM-MANAGED sha256:` header; a body that no longer matches is drift,
   reported with a diff, and only an explicit "discard my edit" re-renders it.

New file-writing code goes through `unihelm_config::apply::ApplyRequest`. If
that seems like overhead, read the six-bugs commit in the git log for what
happens between "the file is right" and "the server is serving it".

**Secrets are sealed or they do not exist.** Anything credential-shaped is
encrypted through `unihelm_db::MasterKey` (XChaCha20-Poly1305) before it
touches SQLite, is never logged, and is masked in API responses and audit
rows.

**Budgets.** ≤ 25 MB per stripped binary, ≤ 350 KB gzipped for the initial UI
route, ≤ 80 MB combined idle RSS. `tests/gates/budgets.sh` checks all three.
Anything heavy in the UI (an editor, a chart library) must be a lazily
imported chunk — the budget is the initial route, and lazy chunks are outside
it by design.

## Tests are named after behavior

A test name is a sentence about what must stay true:

```
a_failed_site_can_be_tried_again_on_the_same_domain
challenge_token_that_is_a_path_traversal_is_rejected
validation_failure_restores_the_previous_bytes_exactly
```

When one fails, the name is the bug report. Security claims get hostile-input
tests — the path traversal, the oversized chunk, the forged header, the caller
without the permission — not just the happy path.

## Adding an operation

An operation is a `TypedOperation` impl and one registry line
(`crates/unihelm-ops/src/registry.rs`):

```rust
#[async_trait]
impl TypedOperation for Restart {
    type Input = RestartInput;      // every field a newtype or an enum
    type Output = RestartOutput;

    const NAME: &'static str = "svc.action";
    const PERMISSION: Permission = Permission::ServerManage;
    const EXECUTION: Execution = Execution::Immediate;   // or Task { .. }

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> { … }
}
```

The registry handles naming, the permission check, input parsing and error
mapping. What you owe on top of that:

- **negative tests** — cross-tenant access, path traversal, injection
  payloads, a caller without the permission;
- **a threat note in the PR** — what the worst input to this operation is,
  and what stops it;
- **a REST endpoint and a CLI verb** — if it can't be done via the API, it
  doesn't exist;
- **an audit row**, and a `Task` if it can take longer than ~300 ms.

## Adding an error code

Add the variant to `ErrorCode` (`crates/unihelm-core/src/error.rs`), give it a
number inside its area's range, a slug and an HTTP status, then regenerate the
reference:

```bash
cargo run -p unihelm-core --bin gen-error-docs > docs/api/errors.md
```

A test compares the committed file against the generated one, so the published
list cannot drift from the code.

## Running everything locally

```bash
export PATH="$HOME/.cargo/bin:$PATH"     # stable toolchain, per rust-toolchain.toml

cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace

bash tests/gates/no-shell.sh
bash tests/gates/budgets.sh              # needs a release build and a built UI
bash tests/gates/installer.sh
bash tests/gates/migrations.sh           # needs full history, not a shallow clone
bash tests/gates/ops-docs.sh             # every registered op appears in docs/

# Each gate that relies on a heuristic can prove it still fires:
bash tests/gates/no-shell.sh --self-test
bash tests/gates/migrations.sh --self-test
bash tests/gates/budgets.sh --self-test  # fixture builds; no npm needed

cd ui && npm ci && npm run typecheck && npm run test && npm run build
```

`cargo clippy -- -D warnings` clean is the merge bar, not a nice-to-have.

## Style

Match the code around you. Comments explain *why* a decision was made — the
constraint, the failure mode, the trade-off — and cite the spec section they
implement (`spec §11.7`); `crates/unihelm-ops/src/cert.rs` is the register to
imitate. Comments that restate the next line are deleted on sight.

UI strings live behind `t()` in `ui/src/i18n/en.ts`, never inline in JSX —
the panel ships English-only, but copy stays in one reviewable file. Keyboard
access ships in the same change; it is not a follow-up.

## Scope discipline

Prefer the smallest thing that satisfies the current phase's exit criteria
(spec §14) and leave a `// TODO(scope):` note over gold-plating. The enemy is
bloat: the product wins by being the panel that does not fall over and does
not eat the RAM, and every speculative feature is weight the budgets have to
carry.
