//! What Docker is running on this machine, and the lifecycle of what is
//! already on it.
//!
//! The line this module draws is between **acting on a container that exists**
//! and **bringing a new one into being**, and it is drawn there for a reason
//! rather than out of caution.
//!
//! **Creating is not here, and is not coming.** No `docker run`, no
//! `docker create`, nothing that takes an image plus flags. The panel's whole
//! security model is that a tenant reaches their own files and nothing else,
//! enforced by Linux users, directory modes and per-tenant FPM pools; Docker
//! sits outside all of it. A container started with `-v /:/host`, or with the
//! daemon socket mounted, is root on the machine — so an operation that accepts
//! arbitrary run arguments is a root shell with extra steps, whatever the
//! button above it says. There is no flag allow-list short enough to be safe
//! and long enough to be useful, which is why this is a boundary and not a
//! to-do.
//!
//! **Start, stop, restart, remove and a log tail are here**, because the flags
//! were chosen by whoever created the container and nothing below changes them.
//! These are the things an operator needs at 3am, and the alternative to having
//! them in the panel is an SSH session — which is strictly more privilege than
//! the four verbs below.
//!
//! Three properties hold the acting half up:
//!
//! 1. Every operation names its target with a [`ContainerRef`], which is
//!    validated on the way in, so no free-form string reaches an argv.
//! 2. Removing a running container **refuses**. It is never forced; see
//!    [`Remove`].
//! 3. Most of what is here was not put here by the panel. A container serving
//!    somebody's production site looks exactly like one an operator is
//!    finished with, so these need `ServerManage` and the UI confirms before
//!    anything stops.
//!
//! Nothing here assumes Docker is installed. A machine without it reports
//! `installed: false` and an empty list from `docker.list`, because "Docker is
//! not here" is a useful answer and an error is not; the acting operations do
//! error, because there is nothing else they could truthfully return.

use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use unihelm_core::{ErrorCode, Permission, Result, UnihelmError};

use crate::registry::{Execution, OpContext, TypedOperation};

/// Docker's own client, not the daemon socket.
///
/// Shelling out to `docker` rather than speaking to /var/run/docker.sock keeps
/// the panel out of the business of holding a handle that is equivalent to root
/// — and `docker` is what an operator would run themselves, so what the panel
/// reports and what they see agree.
const DOCKER: &str = "docker";

/// Docker is either quick or wedged; a long wait means the daemon is stuck, and
/// a page that hangs is worse than one that says so.
const BUDGET: Duration = Duration::from_secs(10);

/// How long a container is given to exit on SIGTERM before Docker SIGKILLs it.
///
/// Docker's own default is the same ten seconds; it is passed explicitly so
/// that [`ACTION_BUDGET`] can be derived from a number this module controls
/// rather than from one a future Docker release is free to change.
const GRACE_SECONDS: u32 = 10;

/// The wait for a lifecycle command, which is a different budget from a read.
///
/// A stop legitimately takes the full [`GRACE_SECONDS`] and a restart takes
/// that plus a start, so the ten-second read budget would kill our own wait at
/// precisely the moment a well-behaved container was shutting down cleanly, and
/// report a failure for an action that then succeeded. The ceiling is
/// `unihelm_ipc::client::DEFAULT_CALL_TIMEOUT` (30s), which an immediate
/// operation's answer has to cross; 25s leaves the caller an error from Docker
/// rather than a timeout from the IPC layer.
const ACTION_BUDGET: Duration = Duration::from_secs(25);

/// A container that already exists, named by id or by name.
///
/// The type is the proof, not a promise repeated at each call site: this is the
/// only thing any operation below will put on a `docker` argv, and the only way
/// to build one is through [`ContainerRef::parse`].
///
/// Docker's own name grammar is `[a-zA-Z0-9][a-zA-Z0-9_.-]*`, and an id is hex,
/// so accepting exactly that costs an operator nothing. Two details of it are
/// load bearing:
///
/// - The first character must be alphanumeric. Everything else follows from
///   argv being an array — no quoting, no word splitting — but a leading `-`
///   would still be read by Docker as an option rather than as a container.
/// - Case is **preserved**. Unlike [`unihelm_core::AppName`], which lowercases,
///   Docker names are case-sensitive: folding `Redis` to `redis` would either
///   miss or, worse, act on a different container than the operator named.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ContainerRef(String);

impl ContainerRef {
    pub fn parse(input: &str) -> Result<Self> {
        let s = input.trim();
        // 64 hex characters is a full id and compose names are long; 128 is
        // past both and short of anything that looks like an attempt.
        if s.is_empty() || s.len() > 128 {
            return Err(UnihelmError::new(
                ErrorCode::InvalidInput,
                "container must be 1-128 characters",
            )
            .with_field("container"));
        }
        let first = s.bytes().next().unwrap();
        if !first.is_ascii_alphanumeric() {
            return Err(UnihelmError::new(
                ErrorCode::InvalidInput,
                "container must start with a letter or digit",
            )
            .with_field("container"));
        }
        if !s
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.' || b == b'-')
        {
            return Err(UnihelmError::new(
                ErrorCode::InvalidInput,
                "container may only contain letters, digits, underscore, dot and hyphen",
            )
            .with_field("container"));
        }
        Ok(Self(s.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ContainerRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for ContainerRef {
    type Error = UnihelmError;
    fn try_from(v: String) -> Result<Self> {
        Self::parse(&v)
    }
}

impl From<ContainerRef> for String {
    fn from(v: ContainerRef) -> String {
        v.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Container {
    pub id: String,
    pub name: String,
    pub image: String,
    /// As Docker words it: `Up 3 hours`, `Exited (0) 2 days ago`.
    pub status: String,
    /// Whether it is running right now, derived rather than parsed from prose.
    pub running: bool,
    /// Published ports, as Docker prints them.
    pub ports: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Image {
    pub id: String,
    pub repository: String,
    pub tag: String,
    pub size: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Volume {
    pub name: String,
    pub driver: String,
}

#[derive(Debug, Default, Deserialize)]
pub struct ListInput {}

#[derive(Debug, Serialize)]
pub struct ListOutput {
    /// False when there is no `docker` on the machine at all.
    pub installed: bool,
    /// False when Docker is installed but its daemon is not answering.
    pub daemon_running: bool,
    /// Every container, running or not — a stopped one is still something the
    /// operator has, and hiding it makes the list lie about disk in use.
    pub containers: Vec<Container>,
    pub images: Vec<Image>,
    pub volumes: Vec<Volume>,
    /// What went wrong, when something did, in Docker's own words.
    pub note: Option<String>,
}

/// `docker.list` — containers, images and volumes on this server.
pub struct List;

#[async_trait::async_trait]
impl TypedOperation for List {
    type Input = ListInput;
    type Output = ListOutput;

    const NAME: &'static str = "docker.list";
    // Reading the machine's inventory. The same permission the rest of the
    // server-wide read surface uses.
    const PERMISSION: Permission = Permission::ServerRead;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, _ctx: &OpContext, _input: Self::Input) -> Result<Self::Output> {
        let Ok(docker) = unihelm_distro::exec::resolve_program(DOCKER) else {
            return Ok(ListOutput {
                installed: false,
                daemon_running: false,
                containers: Vec::new(),
                images: Vec::new(),
                volumes: Vec::new(),
                note: Some(
                    "Docker is not installed on this server. `stack.install` can add it.".into(),
                ),
            });
        };
        let docker = docker.to_string_lossy().into_owned();

        // Installed but not answering is a different situation from not
        // installed, and an operator debugging one does not want to be told the
        // other.
        let ping = run_docker(&docker, &["info", "--format", "{{.ServerVersion}}"]).await;
        if ping.is_none() {
            return Ok(ListOutput {
                installed: true,
                daemon_running: false,
                containers: Vec::new(),
                images: Vec::new(),
                volumes: Vec::new(),
                note: Some(
                    "Docker is installed but its daemon is not responding. \
                     `systemctl status docker` will say why."
                        .into(),
                ),
            });
        }

        Ok(ListOutput {
            installed: true,
            daemon_running: true,
            containers: containers(&docker).await,
            images: images(&docker).await,
            volumes: volumes(&docker).await,
            note: None,
        })
    }
}

// ---------------------------------------------------------------------------
// The lifecycle of a container that already exists
// ---------------------------------------------------------------------------

/// What every acting operation takes, and all it takes.
#[derive(Debug, Deserialize)]
pub struct ContainerInput {
    pub container: ContainerRef,
}

/// Where the container stands once the action has been taken.
///
/// Read back from Docker rather than assumed from the exit status, for the same
/// reason `svc.action` re-reads a unit: a page that has to poll to find out
/// whether the button worked will show the operator the old state at least once.
#[derive(Debug, Serialize)]
pub struct ActionOutput {
    pub id: String,
    pub name: String,
    /// Docker's machine word — `running`, `exited`, `created`, `paused` — not
    /// the prose beside it in `docker ps`.
    pub state: String,
    pub running: bool,
}

/// What was removed, in the identity Docker resolved it to.
#[derive(Debug, Serialize)]
pub struct RemoveOutput {
    pub id: String,
    pub name: String,
}

/// The four verbs, kept in one place so a test can assert on what is *absent*
/// from an argv as easily as on what is in it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Lifecycle {
    Start,
    Stop,
    Restart,
    Remove,
}

impl Lifecycle {
    /// Docker's own subcommand, which is also what an operator would type.
    const fn verb(self) -> &'static str {
        match self {
            Lifecycle::Start => "start",
            Lifecycle::Stop => "stop",
            Lifecycle::Restart => "restart",
            Lifecycle::Remove => "rm",
        }
    }

    fn argv(self, target: &ContainerRef) -> Vec<String> {
        let target = target.as_str().to_string();
        let grace = GRACE_SECONDS.to_string();
        match self {
            Lifecycle::Start => vec!["start".into(), target],
            Lifecycle::Stop => vec!["stop".into(), "-t".into(), grace, target],
            Lifecycle::Restart => vec!["restart".into(), "-t".into(), grace, target],
            // Bare `rm`, and both omissions are the point. No `--force`: that
            // is `docker rm -f`, which SIGKILLs a running container, and the
            // panel refuses to remove one rather than killing it (see
            // [`Remove`]). No `--volumes`: an anonymous volume outlives its
            // container on purpose and is where a containerised database keeps
            // its data, so removing a container must never be how somebody
            // discovers that.
            Lifecycle::Remove => vec!["rm".into(), target],
        }
    }
}

/// `docker.start` — start a container that is already on this server.
pub struct Start;

#[async_trait::async_trait]
impl TypedOperation for Start {
    type Input = ContainerInput;
    type Output = ActionOutput;

    const NAME: &'static str = "docker.start";
    // `ServerManage`, not `DockerApps`. These containers belong to whoever put
    // them here, which is usually not the panel, and one of them may be an
    // nginx serving somebody's production site. `DockerApps` is the plan flag
    // for a tenant's own applications; using it here would hand a customer the
    // stop button for every container on the machine.
    const PERMISSION: Permission = Permission::ServerManage;
    // The fast lane, like `svc.action`: a stuck package install must never be
    // the reason a start button does nothing (spec §10.1).
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        act(ctx, Lifecycle::Start, &input.container).await
    }
}

/// `docker.stop` — stop a running container, gracefully.
pub struct Stop;

#[async_trait::async_trait]
impl TypedOperation for Stop {
    type Input = ContainerInput;
    type Output = ActionOutput;

    const NAME: &'static str = "docker.stop";
    const PERMISSION: Permission = Permission::ServerManage;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        act(ctx, Lifecycle::Stop, &input.container).await
    }
}

/// `docker.restart` — stop and start again, in Docker's own single step.
pub struct Restart;

#[async_trait::async_trait]
impl TypedOperation for Restart {
    type Input = ContainerInput;
    type Output = ActionOutput;

    const NAME: &'static str = "docker.restart";
    const PERMISSION: Permission = Permission::ServerManage;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        act(ctx, Lifecycle::Restart, &input.container).await
    }
}

/// `docker.remove` — delete a container that is already stopped.
///
/// Removing a **running** container is refused rather than forced. `docker rm
/// -f` is a SIGKILL: no graceful shutdown, no flush, and a database mid-write
/// finds out about it on next boot. An operator who means it can stop the
/// container and remove it, which is two deliberate presses instead of one that
/// silently escalated.
pub struct Remove;

#[async_trait::async_trait]
impl TypedOperation for Remove {
    type Input = ContainerInput;
    type Output = RemoveOutput;

    const NAME: &'static str = "docker.remove";
    const PERMISSION: Permission = Permission::ServerManage;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let docker = docker_program()?;
        let found = inspect(&docker, &input.container).await?;
        ensure_removable(&found)?;

        // The resolved id, not the name the caller sent. Between the check
        // above and the removal below a name can be moved onto a different
        // container by a `docker rename` or a compose recreate, and this is the
        // one operation where landing on the wrong container is unrecoverable.
        // Docker's ids are hex, so this parse is a formality that keeps the
        // "only a validated ref reaches an argv" rule without an exception.
        let target = ContainerRef::parse(&found.id)?;

        ctx.log(format!("docker rm {}", found.name));
        run_checked(&docker, &Lifecycle::Remove.argv(&target), ACTION_BUDGET).await?;

        Ok(RemoveOutput {
            id: found.id,
            name: found.name,
        })
    }
}

/// `docker.logs` — the last N lines one container has written.
pub struct Logs;

#[derive(Debug, Deserialize)]
pub struct LogsInput {
    pub container: ContainerRef,
    #[serde(default)]
    pub lines: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct LogsOutput {
    pub id: String,
    pub name: String,
    pub lines: Vec<String>,
}

/// How many lines an unasked-for tail returns.
const DEFAULT_LOG_LINES: u32 = 200;
/// The most one request may ask for. This bounds a single IPC frame, not the
/// operator's access to their logs.
const MAX_LOG_LINES: u32 = 2_000;

/// How many lines to ask Docker for, given what the caller asked for.
///
/// The floor is 1, not 0: `--tail 0` is a valid Docker argument that returns an
/// empty log, so an unclamped `?lines=0` from the query string would render as
/// "this container has written nothing" for a container writing steadily.
fn tail_lines(requested: Option<u32>) -> u32 {
    requested
        .unwrap_or(DEFAULT_LOG_LINES)
        .clamp(1, MAX_LOG_LINES)
}

fn logs_argv(target: &ContainerRef, tail: u32) -> Vec<String> {
    vec![
        "logs".to_string(),
        // Timestamps are not decoration: they are the only thing that can put
        // the two streams below back into one order, and the only way to line a
        // container's log up against anything else the operator is reading.
        // Drop this flag and `interleave` silently degrades to concatenation —
        // every line keys on the empty string — which is why a test holds it.
        "--timestamps".to_string(),
        "--tail".to_string(),
        tail.to_string(),
        target.as_str().to_string(),
    ]
}

#[async_trait::async_trait]
impl TypedOperation for Logs {
    type Input = LogsInput;
    type Output = LogsOutput;

    const NAME: &'static str = "docker.logs";
    // Reading, so `ServerRead` — the same permission that lists the containers
    // these lines came from.
    const PERMISSION: Permission = Permission::ServerRead;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, _ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let docker = docker_program()?;
        // Inspected first so that a container which is not there is a clean
        // "not found" rather than whatever `docker logs` prints, and so the
        // answer carries the identity the lines belong to.
        let found = inspect(&docker, &input.container).await?;

        let tail = tail_lines(input.lines);
        // The resolved id, parsed like every other target, so the "only a
        // validated ref reaches an argv" rule holds here too rather than
        // holding everywhere except the one operation that builds its argv
        // from a string Docker handed back.
        let target = ContainerRef::parse(&found.id)?;

        let out = run_raw(&docker, &logs_argv(&target, tail), BUDGET).await?;
        if !out.success() {
            return Err(UnihelmError::new(
                ErrorCode::CommandFailed,
                out.failure_text(),
            ));
        }

        Ok(LogsOutput {
            lines: interleave(&out.stdout, &out.stderr, tail as usize),
            id: found.id,
            name: found.name,
        })
    }
}

/// Start, stop or restart, then report where the container ended up.
async fn act(ctx: &OpContext, action: Lifecycle, target: &ContainerRef) -> Result<ActionOutput> {
    let docker = docker_program()?;

    // No daemon ping first. The command itself fails with Docker's own
    // "Cannot connect to the Docker daemon" when the daemon is down, which is
    // both more accurate and more actionable than anything this module could
    // synthesise, and a second round trip in front of every button press is a
    // cost paid on every success to improve one failure.
    ctx.log(format!("docker {} {target}", action.verb()));
    run_checked(&docker, &action.argv(target), ACTION_BUDGET).await?;

    let found = inspect(&docker, target).await?;
    Ok(ActionOutput {
        id: found.id,
        name: found.name,
        state: found.state,
        running: found.running,
    })
}

/// A container's identity and state, as Docker reports them.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Inspected {
    id: String,
    name: String,
    state: String,
    running: bool,
}

/// `{{.State.Running}}` first: the bool is the thing decisions are made from,
/// and `{{.State.Status}}` is carried beside it because "exited" and "created"
/// are different answers to "why is this not running".
const INSPECT_FORMAT: &str = "{{.State.Running}}\t{{.State.Status}}\t{{.Name}}\t{{.Id}}";

/// Built here rather than inline so a test can hold it, the way
/// [`Lifecycle::argv`] is. The flags below are each load bearing and each
/// invisible in their absence, which is the kind that comes back.
fn inspect_argv(target: &ContainerRef) -> Vec<String> {
    vec![
        "inspect".to_string(),
        // `--type container` is not optional. Without it `docker inspect`
        // happily answers about an *image* of the same name, and a page would
        // then show an image's fields where a container's state belongs.
        "--type".to_string(),
        "container".to_string(),
        "--format".to_string(),
        INSPECT_FORMAT.to_string(),
        target.as_str().to_string(),
    ]
}

async fn inspect(docker: &str, target: &ContainerRef) -> Result<Inspected> {
    let out = run_raw(docker, &inspect_argv(target), BUDGET).await?;
    if !out.success() {
        return Err(inspect_error(&out.failure_text(), target));
    }
    parse_inspect(out.trimmed_stdout())
}

fn parse_inspect(text: &str) -> Result<Inspected> {
    let Some(row) = rows(text, 4).into_iter().next() else {
        return Err(UnihelmError::internal(
            "`docker inspect` answered in a shape this build does not recognise",
        ));
    };
    Ok(Inspected {
        running: row[0] == "true",
        state: row[1].clone(),
        // Docker returns the name with a leading slash; the operator's name for
        // the container does not have one.
        name: row[2].trim_start_matches('/').to_string(),
        id: row[3].clone(),
    })
}

/// Why `docker inspect` failed, which is not always "there is no such thing".
///
/// A daemon that is down also fails this command, and reporting that as a
/// missing container would send an operator looking for something they deleted
/// while the real fault is a stopped `docker.service`.
fn inspect_error(text: &str, target: &ContainerRef) -> UnihelmError {
    let lower = text.to_ascii_lowercase();
    if lower.contains("no such object") || lower.contains("no such container") {
        UnihelmError::not_found(format!("container `{target}`")).with_field("container")
    } else {
        UnihelmError::new(ErrorCode::CommandFailed, text.trim().to_string())
    }
}

/// Refuse to remove a container that is still running.
fn ensure_removable(found: &Inspected) -> Result<()> {
    if found.running {
        return Err(UnihelmError::new(
            ErrorCode::Conflict,
            format!(
                "`{}` is still running — stop it first. The panel will not force-remove a \
                 running container.",
                found.name
            ),
        )
        .with_field("container"));
    }
    Ok(())
}

/// The two halves of a container's log, put back into one order.
///
/// `docker logs` writes the container's stdout to our stdout and its stderr to
/// our stderr, and there is no shell here to redirect one into the other. Most
/// server software — nginx's error log, anything using a stock logging library
/// — writes to stderr, so reading only stdout shows an empty log for a
/// container that is logging perfectly well.
///
/// Concatenating the two would misorder them, which is worse than useless in a
/// log. `--timestamps` makes them sortable instead: Docker emits a fixed-width
/// RFC 3339 UTC prefix, so lexicographic order is chronological order. A line
/// with no timestamp of its own is a continuation — the second line of a stack
/// trace — and inherits the key of the line above it in its own stream, so a
/// traceback stays in one piece rather than being dealt out across the merge.
fn interleave(stdout: &str, stderr: &str, limit: usize) -> Vec<String> {
    let mut keyed: Vec<(String, String)> = Vec::new();
    for stream in [stdout, stderr] {
        let mut last = String::new();
        for line in stream.lines() {
            let key = match line.split_once(' ') {
                Some((first, _)) if is_timestamp(first) => {
                    last = first.to_string();
                    last.clone()
                }
                _ => last.clone(),
            };
            keyed.push((key, line.to_string()));
        }
    }

    // A stable sort, so two lines written in the same nanosecond keep the order
    // they were read in rather than swapping between refreshes.
    keyed.sort_by(|a, b| a.0.cmp(&b.0));

    // Docker applies `--tail` to the combined log before it splits into two
    // streams, so the merge should already be within the limit. Clamping again
    // costs nothing and keeps the frame bounded whatever a future daemon counts.
    let start = keyed.len().saturating_sub(limit);
    keyed.drain(..start);
    keyed.into_iter().map(|(_, line)| line).collect()
}

fn is_timestamp(token: &str) -> bool {
    let b = token.as_bytes();
    b.len() >= 20 && b[..4].iter().all(u8::is_ascii_digit) && b[4] == b'-' && token.contains('T')
}

/// The `docker` binary, or the reason there is nothing to act on.
///
/// `docker.list` answers "not installed" as data because an inventory of
/// nothing is a true inventory. An action has no such answer: there is no
/// container to start, so this is an error, and it names the page that can fix
/// it.
fn docker_program() -> Result<String> {
    unihelm_distro::exec::resolve_program(DOCKER)
        .map(|p| p.to_string_lossy().into_owned())
        .map_err(|_| {
            UnihelmError::new(
                ErrorCode::NotFound,
                "Docker is not installed on this server. `stack.install` can add it.",
            )
        })
}

async fn run_raw(
    docker: &str,
    args: &[String],
    budget: Duration,
) -> Result<unihelm_distro::exec::CmdOutput> {
    unihelm_distro::Cmd::new(docker)
        .args(args)
        .timeout(budget)
        .run()
        .await
        .map_err(UnihelmError::from)
}

/// Run, and turn a non-zero exit into an error carrying Docker's own words.
///
/// Docker's failures are already written for the person reading them —
/// "Cannot connect to the Docker daemon", "container is marked for removal" —
/// and paraphrasing them here would put a second, worse source of truth in
/// front of the operator.
async fn run_checked(docker: &str, args: &[String], budget: Duration) -> Result<String> {
    let out = run_raw(docker, args, budget).await?;
    if !out.success() {
        return Err(UnihelmError::new(
            ErrorCode::CommandFailed,
            out.failure_text(),
        ));
    }
    Ok(out.trimmed_stdout().to_string())
}

async fn run_docker(docker: &str, args: &[&str]) -> Option<String> {
    let out = unihelm_distro::Cmd::new(docker)
        .args(args)
        .timeout(BUDGET)
        .run()
        .await
        .ok()?;
    out.success().then(|| out.trimmed_stdout().to_string())
}

/// Docker's Go template output, one record per line, tab-separated.
///
/// `--format` with explicit fields rather than `--format json`: the JSON shape
/// has changed between Docker releases, and a tab-separated template of named
/// fields is the one thing that has been stable across all of them.
fn rows(text: &str, fields: usize) -> Vec<Vec<String>> {
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| {
            let parts: Vec<String> = l.split('\t').map(|p| p.trim().to_string()).collect();
            (parts.len() == fields).then_some(parts)
        })
        .collect()
}

async fn containers(docker: &str) -> Vec<Container> {
    let Some(text) = run_docker(
        docker,
        &[
            "ps",
            "--all",
            "--format",
            "{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}",
        ],
    )
    .await
    else {
        return Vec::new();
    };

    rows(&text, 5)
        .into_iter()
        .map(|r| Container {
            // Docker's status prose is localised in some builds, but "Up" as a
            // prefix is emitted by the daemon rather than translated, and it is
            // what `docker ps` filters on internally.
            running: r[3].starts_with("Up"),
            id: r[0].clone(),
            name: r[1].clone(),
            image: r[2].clone(),
            status: r[3].clone(),
            ports: r[4].clone(),
        })
        .collect()
}

async fn images(docker: &str) -> Vec<Image> {
    let Some(text) = run_docker(
        docker,
        &[
            "images",
            "--format",
            "{{.ID}}\t{{.Repository}}\t{{.Tag}}\t{{.Size}}",
        ],
    )
    .await
    else {
        return Vec::new();
    };

    rows(&text, 4)
        .into_iter()
        .map(|r| Image {
            id: r[0].clone(),
            repository: r[1].clone(),
            tag: r[2].clone(),
            size: r[3].clone(),
        })
        .collect()
}

async fn volumes(docker: &str) -> Vec<Volume> {
    let Some(text) = run_docker(
        docker,
        &["volume", "ls", "--format", "{{.Name}}\t{{.Driver}}"],
    )
    .await
    else {
        return Vec::new();
    };

    rows(&text, 2)
        .into_iter()
        .map(|r| Volume {
            name: r[0].clone(),
            driver: r[1].clone(),
        })
        .collect()
}

// ---------------------------------------------------------------------------
// creating one
// ---------------------------------------------------------------------------

/// An image reference: `nginx`, `redis:7`, `registry.example.com:5000/team/app`.
///
/// Validated rather than passed through, because this is the one field that
/// names something the server will fetch and execute. The grammar is Docker's
/// own, minus anything that could be read as an option.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct ImageRef(String);

impl ImageRef {
    pub fn parse(input: &str) -> Result<Self> {
        let s = input.trim();
        if s.is_empty() || s.len() > 255 {
            return Err(UnihelmError::new(
                ErrorCode::InvalidInput,
                "image must be 1-255 characters",
            )
            .with_field("image"));
        }
        // A leading `-` would be read as an option by `docker run`, whatever the
        // argument order; the rest of the set is what a registry, a repository,
        // a tag and a digest are made of.
        if !s.bytes().next().is_some_and(|b| b.is_ascii_alphanumeric()) {
            return Err(UnihelmError::new(
                ErrorCode::InvalidInput,
                "image must start with a letter or a digit",
            )
            .with_field("image"));
        }
        if !s.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b'/' | b':' | b'@')
        }) {
            return Err(UnihelmError::new(
                ErrorCode::InvalidInput,
                "image may contain letters, digits and . - _ / : @ only",
            )
            .with_field("image"));
        }
        Ok(Self(s.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for ImageRef {
    type Error = UnihelmError;
    fn try_from(value: String) -> Result<Self> {
        Self::parse(&value)
    }
}

/// One published port: a host port, a container port, and TCP or UDP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortMap {
    pub host: u16,
    pub container: u16,
    #[serde(default)]
    pub udp: bool,
}

/// What `docker.create` accepts, and by omission what it refuses.
///
/// **There is no field for arbitrary flags, and that is the design.** The
/// argument this module opened with still holds: `-v /:/host`, the daemon
/// socket, `--privileged`, `--pid=host`, `--network=host`, `--cap-add` — each
/// one turns a container into root on the machine, and a form that accepted a
/// free-text argument list would be a root shell with a nicer font. What is here
/// is the shape of a container somebody actually wants from a control panel:
/// an image, a name, some ports, some environment, a named volume or two, and a
/// restart policy.
///
/// Anything beyond that is still `docker run` over SSH, deliberately.
#[derive(Debug, Deserialize)]
pub struct CreateInput {
    pub image: ImageRef,
    /// What to call it. Docker generates one if this is omitted, but a panel
    /// that lists containers by name should not be making up names.
    pub name: ContainerRef,
    #[serde(default)]
    pub ports: Vec<PortMap>,
    #[serde(default)]
    pub env: Vec<EnvVar>,
    /// Named volumes only, mounted at a path inside the container.
    ///
    /// A named volume is Docker's own storage; a bind mount is a path on the
    /// host, and the difference is the whole security boundary. `/:/host` is a
    /// bind mount. There is no field for one.
    #[serde(default)]
    pub volumes: Vec<VolumeMount>,
    /// `no`, `on-failure`, `always`, `unless-stopped`. Docker's own set.
    #[serde(default)]
    pub restart: RestartPolicy,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EnvVar {
    pub key: String,
    pub value: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct VolumeMount {
    /// The name of a Docker volume. Not a path.
    pub volume: String,
    /// Where it appears inside the container. Absolute.
    pub path: String,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RestartPolicy {
    #[default]
    No,
    OnFailure,
    Always,
    UnlessStopped,
}

impl RestartPolicy {
    const fn as_str(self) -> &'static str {
        match self {
            RestartPolicy::No => "no",
            RestartPolicy::OnFailure => "on-failure",
            RestartPolicy::Always => "always",
            RestartPolicy::UnlessStopped => "unless-stopped",
        }
    }
}

#[derive(Debug, Serialize)]
pub struct CreateOutput {
    pub id: String,
    pub name: String,
    pub image: String,
    pub running: bool,
}

/// `docker.create` — start a container from an image already chosen.
pub struct Create;

#[async_trait::async_trait]
impl TypedOperation for Create {
    type Input = CreateInput;
    type Output = CreateOutput;

    const NAME: &'static str = "docker.create";
    const PERMISSION: Permission = Permission::ServerManage;
    // Pulling an image is minutes on a slow link, and the operator should see
    // the pull rather than a spinner.
    const EXECUTION: Execution = Execution::Task {
        cancellable: false,
        idempotent: false,
    };

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let docker = docker_program()?;

        // A name already in use fails at `docker run` with a message about a
        // conflict; saying it here means the operator learns before the image is
        // pulled rather than after.
        if inspect(&docker, &input.name).await.is_ok() {
            return Err(UnihelmError::new(
                ErrorCode::Conflict,
                format!(
                    "a container called `{}` already exists. Remove it first, or \
                     choose another name.",
                    input.name.as_str()
                ),
            )
            .with_field("name"));
        }

        let mut args: Vec<String> = vec![
            "run".into(),
            "--detach".into(),
            "--name".into(),
            input.name.as_str().to_string(),
            "--restart".into(),
            input.restart.as_str().to_string(),
        ];

        for p in &input.ports {
            // Bound to every interface, as `docker run -p` does by default. The
            // firewall is where an operator decides who reaches it, and the
            // panel has a page for that; quietly binding to loopback here would
            // make a published port that nothing can reach.
            args.push("--publish".into());
            args.push(format!(
                "{}:{}{}",
                p.host,
                p.container,
                if p.udp { "/udp" } else { "" }
            ));
        }

        for e in &input.env {
            validate_env_key(&e.key)?;
            args.push("--env".into());
            args.push(format!("{}={}", e.key, e.value));
        }

        for v in &input.volumes {
            validate_volume(v)?;
            args.push("--volume".into());
            args.push(format!("{}:{}", v.volume, v.path));
        }

        args.push(input.image.as_str().to_string());

        ctx.log(format!(
            "docker run --detach --name {} {}",
            input.name.as_str(),
            input.image.as_str()
        ));

        let out = unihelm_distro::Cmd::new(&docker)
            .args(args.iter().map(String::as_str))
            // A pull over a slow link, and Docker gives no progress this can
            // stream, so the ceiling is generous rather than tight.
            .timeout(std::time::Duration::from_secs(600))
            .run()
            .await
            .map_err(|e| UnihelmError::internal(e.to_string()))?;

        if !out.success() {
            return Err(UnihelmError::new(
                ErrorCode::CommandFailed,
                format!("docker run failed: {}", out.failure_text()),
            ));
        }

        let id = out.trimmed_stdout().to_string();
        // Read the state back rather than assuming: a container can exit the
        // instant it starts — a bad command, a missing environment variable —
        // and reporting `running: true` from a successful `docker run` would be
        // the same lie the stack installer used to tell about systemd.
        let running = inspect(&docker, &input.name)
            .await
            .map(|found| found.running)
            .unwrap_or(false);

        Ok(CreateOutput {
            id: if id.is_empty() {
                input.name.as_str().to_string()
            } else {
                id
            },
            name: input.name.as_str().to_string(),
            image: input.image.as_str().to_string(),
            running,
        })
    }
}

/// An environment key that cannot smuggle a second variable in.
fn validate_env_key(key: &str) -> Result<()> {
    if key.is_empty() || key.len() > 128 {
        return Err(UnihelmError::new(
            ErrorCode::InvalidInput,
            "an environment key must be 1-128 bytes",
        )
        .with_field("env"));
    }
    if !key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
        return Err(UnihelmError::new(
            ErrorCode::InvalidInput,
            format!("`{key}` is not an environment variable name"),
        )
        .with_field("env"));
    }
    Ok(())
}

/// A named volume at an absolute path, and nothing that is a bind mount.
///
/// This is the check that keeps `docker.create` from being a way to hand a
/// container the host filesystem. A Docker volume name has the same grammar as
/// a container name; anything containing a `/` in the source position is a path,
/// which is to say a bind mount, which is the thing this operation does not do.
fn validate_volume(v: &VolumeMount) -> Result<()> {
    if v.volume.is_empty() || v.volume.len() > 128 {
        return Err(UnihelmError::new(
            ErrorCode::InvalidInput,
            "a volume name must be 1-128 bytes",
        )
        .with_field("volumes"));
    }
    if !v
        .volume
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
        || !v
            .volume
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_alphanumeric())
    {
        return Err(UnihelmError::new(
            ErrorCode::InvalidInput,
            format!(
                "`{}` is not a volume name. This creates containers with named \
                 volumes; a path here would be a bind mount, which would give the \
                 container part of this server's filesystem.",
                v.volume
            ),
        )
        .with_field("volumes"));
    }
    if !v.path.starts_with('/') || v.path.contains("..") || v.path.len() > 255 {
        return Err(UnihelmError::new(
            ErrorCode::InvalidInput,
            "the mount path must be absolute and free of `..`",
        )
        .with_field("volumes"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A container that is up must be reported as running, and one that is not
    /// must not — the panel's list is the thing an operator decides from.
    #[test]
    fn running_is_derived_from_dockers_own_status_prefix() {
        let text = "abc123\tweb\tnginx:latest\tUp 3 hours\t0.0.0.0:80->80/tcp\n\
                    def456\told\tredis:7\tExited (0) 2 days ago\t\n";
        let found = rows(text, 5);
        assert_eq!(found.len(), 2);
        assert!(found[0][3].starts_with("Up"));
        assert!(!found[1][3].starts_with("Up"));
    }

    /// A stopped container with no published ports still produces its column,
    /// so the record must not be dropped for having an empty field.
    #[test]
    fn a_record_with_empty_trailing_fields_is_kept() {
        let text = "def456\told\tredis:7\tExited (0) 2 days ago\t\n";
        assert_eq!(rows(text, 5).len(), 1, "a stopped container vanished");
    }

    /// Docker prints nothing at all when there is nothing to print, and a blank
    /// line is not a record.
    #[test]
    fn empty_and_ragged_output_produce_no_records() {
        assert!(rows("", 5).is_empty());
        assert!(rows("\n\n  \n", 5).is_empty());
        // A line with the wrong field count is a template that did not render,
        // not a container — inventing one from it would put a phantom in the
        // operator's list.
        assert!(rows("only\ttwo\n", 5).is_empty());
    }

    /// An image name can contain a colon and a slash; splitting on tabs rather
    /// than guessing at the shape is what keeps that intact.
    #[test]
    fn registry_qualified_image_names_survive() {
        let text = "sha256:aa\tregistry.example.com:5000/team/app\tv1.2.3\t120MB\n";
        let found = rows(text, 4);
        assert_eq!(found[0][1], "registry.example.com:5000/team/app");
        assert_eq!(found[0][2], "v1.2.3");
    }

    // -----------------------------------------------------------------------
    // ContainerRef
    // -----------------------------------------------------------------------

    /// What an operator actually types: a full id, a short id, a compose name.
    #[test]
    fn real_container_names_and_ids_are_accepted() {
        for input in [
            "web",
            "a1b2c3d4e5f6",
            "9f2c8e0b4a6d7f13c5e8a0b2d4f6a8c0e2b4d6f81a3c5e7092b4d6f8a0c2e4b6",
            "shop_web_1",
            "shop-web-1",
            "unihelm.panel-2",
        ] {
            assert!(
                ContainerRef::parse(input).is_ok(),
                "`{input}` is a container Docker would answer about"
            );
        }
    }

    /// The whole reason this type exists: nothing that could be read as an
    /// option, a second word, a path or a shell construction gets through.
    #[test]
    fn nothing_that_could_become_an_argument_gets_through() {
        for input in [
            // Docker would read this as a flag, not as a container.
            "--volumes",
            "-f",
            "",
            "   ",
            "web app",
            "web;rm -rf /",
            "$(id)",
            "`id`",
            "web\nstop",
            "../../etc/passwd",
            "web/other",
            "café",
        ] {
            let Err(err) = ContainerRef::parse(input) else {
                panic!("`{input}` reached an argv");
            };
            assert_eq!(err.code, ErrorCode::InvalidInput, "for `{input}`");
            assert_eq!(err.field.as_deref(), Some("container"), "for `{input}`");
        }
    }

    /// Docker names are case-sensitive. Folding case here would send the action
    /// to a different container, or to none — which is the failure mode that
    /// looks like the panel doing nothing.
    #[test]
    fn case_is_preserved() {
        assert_eq!(
            ContainerRef::parse("MyApp_DB").unwrap().as_str(),
            "MyApp_DB"
        );
    }

    // -----------------------------------------------------------------------
    // The argv
    // -----------------------------------------------------------------------

    fn cref(s: &str) -> ContainerRef {
        ContainerRef::parse(s).unwrap()
    }

    /// A stop is graceful and says so out loud, so the command's own wait and
    /// this module's budget cannot drift apart.
    #[test]
    fn stop_and_restart_pass_the_grace_period() {
        assert_eq!(
            Lifecycle::Stop.argv(&cref("web")),
            vec!["stop", "-t", "10", "web"]
        );
        assert_eq!(
            Lifecycle::Restart.argv(&cref("web")),
            vec!["restart", "-t", "10", "web"]
        );
        assert!(
            ACTION_BUDGET.as_secs() > GRACE_SECONDS as u64,
            "the budget must outlast the grace period, or a clean shutdown is \
             reported as a failed one"
        );
    }

    /// Removal is never a kill and never takes the data with it.
    #[test]
    fn remove_forces_nothing_and_deletes_no_volumes() {
        let argv = Lifecycle::Remove.argv(&cref("web"));
        assert_eq!(argv, vec!["rm", "web"]);
        for forbidden in ["-f", "--force", "-v", "--volumes", "--link"] {
            assert!(
                !argv.iter().any(|a| a == forbidden),
                "`{forbidden}` turns a removal into something the operator did not ask for"
            );
        }
    }

    /// The container is named last, after every flag, so it is never parsed as
    /// the value of one.
    #[test]
    fn the_container_is_always_the_final_argument() {
        for action in [
            Lifecycle::Start,
            Lifecycle::Stop,
            Lifecycle::Restart,
            Lifecycle::Remove,
        ] {
            let argv = action.argv(&cref("web"));
            assert_eq!(argv.last().map(String::as_str), Some("web"));
            assert_eq!(argv.first().map(String::as_str), Some(action.verb()));
        }
    }

    // -----------------------------------------------------------------------
    // Removing
    // -----------------------------------------------------------------------

    fn inspected(state: &str, running: bool) -> Inspected {
        Inspected {
            id: "a1b2c3".into(),
            name: "web".into(),
            state: state.into(),
            running,
        }
    }

    /// A running container is refused, not forced. The alternative — `rm -f` —
    /// is a SIGKILL to something that may be mid-write.
    #[test]
    fn removing_a_running_container_is_refused() {
        let err = ensure_removable(&inspected("running", true)).unwrap_err();
        assert_eq!(err.code, ErrorCode::Conflict);
        assert!(
            err.detail.contains("stop it first"),
            "the refusal has to say what to do instead: {}",
            err.detail
        );
        assert!(ensure_removable(&inspected("exited", false)).is_ok());
    }

    // -----------------------------------------------------------------------
    // inspect
    // -----------------------------------------------------------------------

    /// Without `--type container`, `docker inspect redis` will happily answer
    /// about the *image* `redis` when no container by that name exists — and
    /// an image has no `.State`, so the page would show a container that is
    /// neither running nor stopped instead of the "no such container" the
    /// operator needs. Nothing else in this file notices the flag's absence.
    #[test]
    fn inspect_asks_about_a_container_and_not_an_image_of_the_same_name() {
        let argv = inspect_argv(&cref("redis"));
        let pair = argv
            .windows(2)
            .any(|w| w[0] == "--type" && w[1] == "container");
        assert!(pair, "inspect must be pinned to containers: {argv:?}");
        assert_eq!(argv.first().map(String::as_str), Some("inspect"));
        assert_eq!(argv.last().map(String::as_str), Some("redis"));
    }

    #[test]
    fn inspect_output_becomes_an_identity_and_a_state() {
        let found = parse_inspect("true\trunning\t/shop_web_1\tabc123\n").unwrap();
        assert_eq!(
            found,
            Inspected {
                id: "abc123".into(),
                // Docker's leading slash is not part of the name anybody types.
                name: "shop_web_1".into(),
                state: "running".into(),
                running: true,
            }
        );
        assert!(
            !parse_inspect("false\texited\t/old\tdef456\n")
                .unwrap()
                .running
        );
    }

    /// A daemon that is not answering must not be reported as a container that
    /// is not there — that sends an operator hunting for something they
    /// deleted while `docker.service` is what is actually down.
    #[test]
    fn a_wedged_daemon_is_not_a_missing_container() {
        let target = cref("web");

        let missing = inspect_error("Error: No such object: web", &target);
        assert_eq!(missing.code, ErrorCode::NotFound);

        let down = inspect_error(
            "Cannot connect to the Docker daemon at unix:///var/run/docker.sock. \
             Is the docker daemon running?",
            &target,
        );
        assert_eq!(down.code, ErrorCode::CommandFailed);
        assert!(
            down.detail.contains("Cannot connect"),
            "Docker's own words are the useful ones: {}",
            down.detail
        );
    }

    // -----------------------------------------------------------------------
    // Logs
    // -----------------------------------------------------------------------

    /// The defect this function exists for: nginx, and most other server
    /// software, logs to stderr. Reading only stdout showed an empty log for a
    /// container that was logging fine.
    #[test]
    fn a_container_that_logs_only_to_stderr_still_has_logs() {
        let lines = interleave(
            "",
            "2026-01-01T10:00:00.000000000Z 2026/01/01 [error] connect() failed\n",
            200,
        );
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("[error]"));
    }

    /// Two streams, one log. Concatenating them would put every stderr line
    /// after every stdout line, which reads as a different incident.
    #[test]
    fn the_two_streams_come_back_in_the_order_they_happened() {
        let out = "2026-01-01T10:00:00.000000000Z started\n\
                   2026-01-01T10:00:02.000000000Z ready\n";
        let err = "2026-01-01T10:00:01.000000000Z warning: no config\n\
                   2026-01-01T10:00:03.000000000Z fatal\n";
        let lines = interleave(out, err, 200);
        let text: Vec<&str> = lines
            .iter()
            .map(|l| l.rsplit(' ').next().unwrap())
            .collect();
        assert_eq!(text, vec!["started", "config", "ready", "fatal"]);
    }

    /// A stack trace is one event written as several lines, and only its first
    /// carries a timestamp. Sorting the rest to the top of the log would take
    /// the traceback away from its exception.
    #[test]
    fn a_continuation_line_stays_under_the_line_it_belongs_to() {
        let err = "2026-01-01T10:00:01.000000000Z Traceback (most recent call last):\n\
                   \x20 File \"app.py\", line 3\n\
                   \x20   raise RuntimeError\n";
        let out = "2026-01-01T10:00:00.000000000Z serving\n";
        let lines = interleave(out, err, 200);
        assert_eq!(lines.len(), 4);
        assert!(lines[0].ends_with("serving"));
        assert!(lines[1].contains("Traceback"));
        assert!(lines[2].contains("app.py"));
        assert!(lines[3].contains("RuntimeError"));
    }

    /// The tail the caller asked for is the tail they get, counted after the
    /// merge — and it is the *newest* lines that survive.
    #[test]
    fn the_limit_keeps_the_end_of_the_log() {
        let out = "2026-01-01T10:00:00.000000000Z one\n\
                   2026-01-01T10:00:02.000000000Z three\n";
        let err = "2026-01-01T10:00:01.000000000Z two\n\
                   2026-01-01T10:00:03.000000000Z four\n";
        let lines = interleave(out, err, 2);
        assert_eq!(lines.len(), 2);
        assert!(lines[0].ends_with("three"));
        assert!(lines[1].ends_with("four"));
    }

    /// Nothing written yet is an empty log, not a malformed one.
    #[test]
    fn an_empty_log_is_no_lines() {
        assert!(interleave("", "", 200).is_empty());
    }

    /// `--timestamps` is the only reason `interleave` can merge anything, and
    /// dropping it fails nothing else here: every line would key on the empty
    /// string, the stable sort would leave stdout's block ahead of stderr's,
    /// and the merge would quietly become the concatenation it exists to
    /// avoid. This is that flag's only guard.
    #[test]
    fn the_log_tail_asks_for_the_timestamps_the_merge_depends_on() {
        let argv = logs_argv(&cref("web"), 200);
        assert!(
            argv.iter().any(|a| a == "--timestamps"),
            "without this the two streams cannot be ordered: {argv:?}"
        );
        assert_eq!(argv, vec!["logs", "--timestamps", "--tail", "200", "web"]);
    }

    /// `--tail 0` is a valid Docker argument that returns nothing, so a
    /// `?lines=0` reaching the daemon unclamped would show a busy container as
    /// one that has never written a line. The ceiling bounds one IPC frame.
    #[test]
    fn a_tail_of_zero_never_reaches_docker() {
        assert_eq!(tail_lines(Some(0)), 1);
        assert_eq!(tail_lines(None), DEFAULT_LOG_LINES);
        assert_eq!(tail_lines(Some(50)), 50);
        assert_eq!(tail_lines(Some(u32::MAX)), MAX_LOG_LINES);
        assert_eq!(logs_argv(&cref("web"), tail_lines(Some(0)))[3], "1");
    }
}
#[cfg(test)]
mod create_tests {
    use super::*;

    fn mount(volume: &str, path: &str) -> VolumeMount {
        VolumeMount {
            volume: volume.into(),
            path: path.into(),
        }
    }

    /// The line this operation exists behind.
    ///
    /// A bind mount is a path on the host handed to a container; a named volume
    /// is Docker's own storage. `-v /:/host` is the first and it is root on the
    /// machine. The input has no field for a bind mount, and the volume name is
    /// checked so a path cannot be smuggled through the field that does exist.
    #[test]
    fn a_path_is_never_accepted_where_a_volume_name_belongs() {
        for attempt in [
            "/",
            "/etc",
            "/var/run/docker.sock",
            "../../etc",
            "./data",
            "/home/uh_abc123",
        ] {
            let err = validate_volume(&mount(attempt, "/data"))
                .expect_err("a path was accepted as a volume name");
            assert!(
                err.to_string().contains("bind mount"),
                "the refusal should say why: {err}"
            );
        }
        // A real volume name still works.
        assert!(validate_volume(&mount("app_data", "/var/lib/app")).is_ok());
        assert!(validate_volume(&mount("pg-16.data", "/var/lib/postgresql")).is_ok());
    }

    /// The mount point is inside the container, but `..` in it is still somebody
    /// probing, and an absolute path is what Docker requires anyway.
    #[test]
    fn the_mount_path_must_be_absolute_and_plain() {
        for bad in ["data", "", "../etc", "/var/../.."] {
            assert!(
                validate_volume(&mount("app_data", bad)).is_err(),
                "accepted `{bad}` as a mount path"
            );
        }
    }

    /// An image reference reaches a command line and names something the server
    /// will fetch and execute, so a leading `-` must never survive: whatever the
    /// argument order, `docker run` would read it as an option.
    #[test]
    fn an_image_cannot_begin_with_a_dash_or_carry_shell_syntax() {
        for bad in [
            "-v",
            "--privileged",
            "",
            "nginx; rm -rf /",
            "nginx && curl evil",
            "nginx$(whoami)",
            "nginx`id`",
            "nginx|sh",
        ] {
            assert!(ImageRef::parse(bad).is_err(), "accepted image `{bad}`");
        }

        for good in [
            "nginx",
            "redis:7",
            "mongo:8.3.1",
            "registry.example.com:5000/team/app:v1.2.3",
            "ghcr.io/owner/image@sha256:aaaa",
        ] {
            assert!(ImageRef::parse(good).is_ok(), "refused image `{good}`");
        }
    }

    /// `FOO=bar BAZ=qux` in one key would put a second variable into the
    /// container through a field that promised one.
    #[test]
    fn an_environment_key_cannot_carry_a_second_variable() {
        for bad in ["FOO=bar", "FOO BAR", "", "FOO;BAR", "FOO\nBAR"] {
            assert!(validate_env_key(bad).is_err(), "accepted key `{bad}`");
        }
        for good in ["NODE_ENV", "DATABASE_URL", "PORT", "_PRIVATE", "X1"] {
            assert!(validate_env_key(good).is_ok(), "refused key `{good}`");
        }
    }

    /// Docker's own set, spelled Docker's way — `unless-stopped`, not
    /// `unlessStopped`, because it goes straight to `--restart`.
    #[test]
    fn restart_policies_are_dockers_own_spelling() {
        assert_eq!(RestartPolicy::No.as_str(), "no");
        assert_eq!(RestartPolicy::OnFailure.as_str(), "on-failure");
        assert_eq!(RestartPolicy::Always.as_str(), "always");
        assert_eq!(RestartPolicy::UnlessStopped.as_str(), "unless-stopped");
        assert_eq!(RestartPolicy::default(), RestartPolicy::No);
    }

    /// There is no field for a raw flag, and there must not be one. This test is
    /// a tripwire: it fails if somebody adds one, which is the moment the
    /// operation stops being a form and becomes a root shell.
    #[test]
    fn the_input_has_no_field_for_arbitrary_flags() {
        let json = serde_json::json!({
            "image": "nginx",
            "name": "web",
            "args": ["--privileged"],
            "flags": ["-v", "/:/host"],
            "privileged": true,
            "network": "host",
        });
        let parsed: CreateInput =
            serde_json::from_value(json).expect("unknown fields are ignored, not accepted");
        // Nothing of the above survives into anything the operation uses.
        assert_eq!(parsed.image.as_str(), "nginx");
        assert!(parsed.ports.is_empty());
        assert!(parsed.volumes.is_empty());
        assert_eq!(parsed.restart, RestartPolicy::No);
    }
}
