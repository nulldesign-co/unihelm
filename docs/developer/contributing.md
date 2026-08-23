# Contributing

The working agreement from spec §16, with the parts that are actually enforced
marked as such.

## Non-negotiable invariants

These are CI gates. A pull request that breaks one does not merge.

**No shell string execution.** Every command is `Cmd::new(program).args([...])`,
which becomes an `execve` with an argv array. No `sh -c`, no `bash -c`, no
building a command line out of user input. `tests/gates/no-shell.sh` proves it,
and also proves that `Command::new` appears in exactly one file
(`crates/ferrum-distro/src/exec.rs`) — everything else goes through `Cmd`.

**Typed, validated inputs.** Anything that reaches a command line, a config
template or a SQL identifier is a newtype whose only constructor validates:
`Domain`, `DbName`, `TenantPath`, `LinuxUser`, `PhpVersion`, `ManagedUnit`. They
validate through `serde` too, so a hostile IPC frame is rejected at the protocol
edge rather than deep inside an operation.

**Authorization twice.** `ferrum-web` authorizes from the session;
`ferrum-agentd` re-derives the same rights from the database and intersects them
with what the frame claimed. A forged permission set can only ever lose
privileges.

**Repositories take a `TenantScope`.** Not an id. You cannot write an unscoped
tenant query by accident — you have to ask for `TenantScope::Global` on purpose.

**Budgets.** ≤ 25 MB per binary, ≤ 350 KB gzipped for the initial UI route,
≤ 80 MB combined idle RSS. `tests/gates/budgets.sh` checks all three.

## Adding an operation

An operation is a `TypedOperation` impl and a registry line:

```rust
#[async_trait]
impl TypedOperation for Restart {
    type Input = RestartInput;      // every field a newtype or an enum
    type Output = RestartOutput;

    const NAME: &'static str = "svc.action";
    const PERMISSION: Permission = Permission::ServerManage;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> { … }
}
```

The registry handles naming, the permission check, input parsing and error
mapping. What you owe on top of that:

- **negative tests** — cross-tenant access, path traversal, injection payloads,
  a caller without the permission;
- **a threat note in the PR** — what the worst input to this operation is, and
  what stops it;
- **a REST endpoint and a CLI verb**, because "if it can't be done via the API,
  it doesn't exist";
- **an audit row**, and a Task if it can take longer than ~300 ms.

## Adding an error code

Add the variant to `ErrorCode`, give it a number inside its range, a slug and an
HTTP status, then regenerate the docs page:

```bash
cargo run -p ferrum-core --bin gen-error-docs > docs/api/errors.md
```

A test compares the committed file against the generated one, so the published
list cannot drift from the code.

## Adding a distribution

Implement the four `ferrum-distro` traits and add an image to the CI matrix.
If a feature module needs changing to support a new distribution, the difference
is in the wrong place.

## Running everything locally

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace

bash tests/gates/no-shell.sh
bash tests/gates/budgets.sh          # needs a release build and a built UI

cd ui && npm run typecheck && npm run build
```

## Style

Match the code around you. Comments explain *why* a decision was made — the
constraint, the failure mode, the trade-off — not what the next line does. Tests
are named after the behaviour they protect, so a failure reads as a sentence
about what broke.
