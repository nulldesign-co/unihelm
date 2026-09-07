//! What Docker is running on this machine, and the lifecycle of what is
//! already on it.
//!
//! The line this module draws is not between reading and writing — it manages
//! containers, images and volumes — but around the **shape** of what may be
//! asked for, and it is drawn there for a reason rather than out of caution.
//!
//! **Creating is a form, not `docker run`.** [`Create`] takes an image, a name,
//! ports, environment, named volumes and a restart policy, and there is no
//! field for a raw flag. The panel's whole security model is that a tenant
//! reaches their own files and nothing else, enforced by Linux users, directory
//! modes and per-tenant FPM pools; Docker sits outside all of it. A container
//! started with `-v /:/host`, or with the daemon socket mounted, is root on the
//! machine — so an operation that accepted arbitrary run arguments would be a
//! root shell with extra steps, whatever the button above it said. There is no
//! flag allow-list short enough to be safe and long enough to be useful, which
//! is why the shape of the input is the boundary rather than a check inside it.
//!
//! **Start, stop, restart, remove and a log tail** act on what is already
//! there, and the flags it runs under were chosen by whoever created it —
//! nothing below changes them. These are the things an operator needs at 3am,
//! and the alternative to having them in the panel is an SSH session, which is
//! strictly more privilege.
//!
//! **Images and volumes are managed here too**, because a panel that can only
//! ever add to a disk is not managing it: `docker.image.pull`,
//! `docker.image.remove`, `docker.image.prune` and `docker.volume.remove`. On a
//! small VPS the dangling layers left behind by a few image upgrades are the
//! difference between a working server and a full one, and until these existed
//! the only way to reclaim that space was an SSH session.
//!
//! Four properties hold all of it up:
//!
//! 1. Every operation names its target with a [`ContainerRef`], an [`ImageRef`]
//!    or a [`VolumeRef`], each validated on the way in, so no free-form string
//!    reaches an argv.
//! 2. Anything still in use **refuses**, and names what is using it. A running
//!    container is not force-removed (see [`Remove`]), an image a container
//!    still needs is not `rmi -f`'d (see [`ImageRemove`]) and a volume a
//!    container still references is not deleted (see [`VolumeRemove`]) —
//!    Docker's own `-f` in those places takes a running service, or somebody's
//!    database, with it.
//! 3. Deleting says what it deleted. [`ImagePrune`] names the images before it
//!    removes them and reports the space Docker actually reclaimed, because
//!    "reclaimed 3.2 GB" is the whole value of the operation and a bare "done"
//!    is indistinguishable from having deleted nothing.
//! 4. Most of what is here was not put here by the panel. A container serving
//!    somebody's production site looks exactly like one an operator is
//!    finished with, so these need `ServerManage` and the UI confirms before
//!    anything stops.
//!
//! Nothing here assumes Docker is installed. A machine without it reports
//! `installed: false` and an empty list from `docker.list`, because "Docker is
//! not here" is a useful answer and an error is not; the acting operations do
//! error, because there is nothing else they could truthfully return.

use std::collections::BTreeMap;
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

/// One volume, and the three things that make an orphan tellable from a
/// keepsake.
///
/// A volume outliving its container is this panel's own design — `docker rm`
/// here never passes `--volumes`, precisely so a containerised database is not
/// destroyed by somebody tidying up containers. The cost of that decision is
/// that a name and a driver cannot say whether a volume is a deliberate
/// keepsake or the residue of a container deleted a year ago, and an operator
/// looking at a full disk has to guess. These three fields are what stops the
/// guessing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Volume {
    pub name: String,
    pub driver: String,
    /// What it occupies, in Docker's own words — `1.093GB` — from
    /// `docker system df`.
    ///
    /// `None` when that accounting could not be had: it is a separate, slower
    /// command than `volume ls`, and reporting `0B` for a volume nobody
    /// measured would invite somebody to delete a database on the strength of
    /// a number the panel made up.
    #[serde(default)]
    pub size: Option<String>,
    /// The containers that mount it, running or stopped.
    ///
    /// `None` — not an empty list — when the question could not be asked.
    /// "Nothing uses this" reads as permission to delete it and "the panel
    /// could not tell" does not, and collapsing the two into `[]` is the
    /// difference between an orphan and somebody's data.
    #[serde(default)]
    pub used_by: Option<Vec<String>>,
    /// The engine container this panel installed that keeps its data here.
    ///
    /// Deleting this volume is deleting every database in that engine, so the
    /// page says whose it is before offering the button. Read from the panel's
    /// own engine registry, which is the only thing that knows.
    #[serde(default)]
    pub engine: Option<String>,
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

    async fn run(&self, ctx: &OpContext, _input: Self::Input) -> Result<Self::Output> {
        let found = inventory().await;
        let Some(docker) = found.docker else {
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

        // Installed but not answering is a different situation from not
        // installed, and an operator debugging one does not want to be told the
        // other.
        if !found.daemon_running {
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

        // The panel's own engine registry, so a volume holding somebody's
        // databases can say whose before anybody is offered a delete button. A
        // registry that will not parse is not a reason to fail the inventory —
        // the containers and images below are still true — but it is a reason
        // to stop claiming that none of these volumes belongs to an engine,
        // which is why it becomes the note rather than a silence.
        let (engines, note) = match crate::engine::registry(ctx.db()).await {
            Ok(found) => (found, None),
            Err(e) => (
                crate::engine::EngineRegistry::new(),
                Some(format!(
                    "The volumes below cannot say which of them hold a database: the panel's \
                     engine registry could not be read ({e}). Until that is fixed, treat every \
                     volume here as something's data."
                )),
            ),
        };

        Ok(ListOutput {
            installed: true,
            daemon_running: true,
            containers: found.containers,
            images: images(&docker).await,
            volumes: volumes(&docker, &engines).await,
            note,
        })
    }
}

/// Whether Docker is here, whether it is answering, and what containers it has.
///
/// **The cheap half of `docker.list`, and it is separate on purpose.** The full
/// list pays `docker system df`, which walks every volume's directory to size
/// it — seconds on a machine with a large one, which is a price worth paying to
/// let an operator tell an orphan volume from somebody's database. It is not a
/// price worth paying on [`crate::engine`]'s status read, which renders none of
/// those columns and is an immediate operation behind the Databases page's
/// first paint. Before this split, adding the volume accounting to `docker.list`
/// would have put those seconds on every engine status call.
pub(crate) struct Inventory {
    /// `None` when there is no `docker` on the machine at all.
    pub(crate) docker: Option<String>,
    /// False when Docker is installed but its daemon is not answering.
    pub(crate) daemon_running: bool,
    pub(crate) containers: Vec<Container>,
}

pub(crate) async fn inventory() -> Inventory {
    let Ok(path) = unihelm_distro::exec::resolve_program(DOCKER) else {
        return Inventory {
            docker: None,
            daemon_running: false,
            containers: Vec::new(),
        };
    };
    let docker = path.to_string_lossy().into_owned();

    if run_docker(&docker, &["info", "--format", "{{.ServerVersion}}"])
        .await
        .is_none()
    {
        return Inventory {
            docker: Some(docker),
            daemon_running: false,
            containers: Vec::new(),
        };
    }

    let containers = containers(&docker).await;
    Inventory {
        docker: Some(docker),
        daemon_running: true,
        containers,
    }
}

/// Just the names, for a caller that only has to know whether a volume is still
/// there — no size, no mount list, and none of the cost of either.
pub(crate) async fn volume_names(docker: &str) -> Vec<String> {
    let Some(text) = run_docker(docker, &["volume", "ls", "--quiet"]).await else {
        return Vec::new();
    };
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect()
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

/// Whether a container of this name is on the machine, running or not.
///
/// One `docker inspect` rather than the whole inventory. [`crate::engine`]'s
/// install used to answer this by listing every container, image and volume on
/// the server and scanning the names — which since the volume record grew a
/// size means `docker system df`, a command that walks each volume's directory.
/// Paying that to find out whether one name is taken is a minute of an
/// operator's install spent on an answer nobody reads.
pub(crate) async fn container_exists(docker: &str, name: &ContainerRef) -> bool {
    inspect(docker, name).await.is_ok()
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

/// Every volume, with the two things Docker knows about it and the one thing
/// only the panel does.
///
/// Three sources, deliberately, rather than one:
///
/// - `volume ls` is the list. It is the cheap command and the authority on what
///   exists.
/// - `system df -v` is the size. It is a *separate* command because it is the
///   expensive one — Docker walks each volume's directory to answer — and its
///   failure or timeout must cost a size, not the whole page.
/// - `ps --all` is who mounts it, which `volume ls` cannot say at all. One
///   shell-out for the whole table rather than one `--filter volume=` per
///   volume, because a machine with forty volumes would otherwise pay forty
///   round trips to draw one page.
async fn volumes(docker: &str, engines: &crate::engine::EngineRegistry) -> Vec<Volume> {
    let Some(text) = run_docker(
        docker,
        &["volume", "ls", "--format", "{{.Name}}\t{{.Driver}}"],
    )
    .await
    else {
        return Vec::new();
    };

    let sizes = volume_sizes(docker).await;
    let users = volume_users(docker).await;

    rows(&text, 2)
        .into_iter()
        .map(|r| Volume {
            size: sizes.as_ref().and_then(|m| m.get(&r[0]).cloned()),
            // `used_by` is only ever a list when `docker ps` answered. Mapping a
            // missing answer onto "no containers" would put an orphan badge on
            // a volume a running database is writing to.
            used_by: users
                .as_ref()
                .map(|m| m.get(&r[0]).cloned().unwrap_or_default()),
            engine: engines
                .values()
                .find(|record| record.volume.as_deref() == Some(r[0].as_str()))
                .map(|record| record.container.clone()),
            name: r[0].clone(),
            driver: r[1].clone(),
        })
        .collect()
}

/// What each volume occupies, from `docker system df`.
///
/// `None` when the command did not answer — it is the slow one on this page and
/// the ten-second budget can genuinely expire against a large volume, so its
/// absence has to be tellable from a volume of zero bytes.
async fn volume_sizes(docker: &str) -> Option<BTreeMap<String, String>> {
    let text = run_docker(
        docker,
        &[
            "system",
            "df",
            // Without `-v` the answer is one summary row per object type, which
            // is a total and not a per-volume size.
            "-v",
            "--format",
            "{{range .Volumes}}{{.Name}}\t{{.Size}}\n{{end}}",
        ],
    )
    .await?;

    Some(
        rows(&text, 2)
            .into_iter()
            .map(|r| (r[0].clone(), r[1].clone()))
            .collect(),
    )
}

/// Read `docker ps`'s mount column into "which containers hold this volume".
///
/// Its own function so a test can hold it: the two rules below are each one
/// line and each invisible in their absence.
fn mounts_to_users(text: &str) -> BTreeMap<String, Vec<String>> {
    let mut map: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for row in rows(text, 2) {
        for mount in row[1].split(',').map(str::trim).filter(|m| !m.is_empty()) {
            // A bind mount is a path and is nobody's volume. Skipping it keeps
            // `/var/www` out of a map keyed by volume name — and, more to the
            // point, keeps a volume that happens to share a container with a
            // bind mount from being credited with the bind mount's user.
            if mount.starts_with('/') {
                continue;
            }
            map.entry(mount.to_string())
                .or_default()
                .push(row[0].clone());
        }
    }
    map
}

/// Which containers mount each volume, running or stopped.
///
/// A stopped container counts. It is exactly the case that makes a volume look
/// like an orphan — the container is not in `docker ps` and the volume is still
/// its data — and it is also the case Docker itself refuses a `volume rm` for.
async fn volume_users(docker: &str) -> Option<BTreeMap<String, Vec<String>>> {
    let text = run_docker(
        docker,
        &[
            "ps",
            "--all",
            "--format",
            // `.Mounts` is Docker's own list of what this container has
            // attached: named volumes by name, bind mounts by host path.
            "{{.Names}}\t{{.Mounts}}",
        ],
    )
    .await?;

    Some(mounts_to_users(&text))
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

impl fmt::Display for ImageRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A Docker volume, named the one way this module will accept.
///
/// Docker's volume-name grammar is the container one, and the same leading
/// character rule applies for the same reason: `-f` in the volume position of
/// `docker volume rm` is an option, not a volume.
///
/// The distinction this type carries is the one [`validate_volume`] was written
/// for and now delegates here so there is a single grammar rather than two that
/// can drift: **a name is not a path**. `/`, `.` at the front, `..` anywhere —
/// each of those is a bind mount, which is a piece of this server's filesystem
/// handed to a container, which is the thing this module does not do.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct VolumeRef(String);

impl VolumeRef {
    pub fn parse(input: &str) -> Result<Self> {
        let s = input.trim();
        if s.is_empty() || s.len() > 128 {
            return Err(UnihelmError::new(
                ErrorCode::InvalidInput,
                "a volume name must be 1-128 bytes",
            )
            .with_field("volume"));
        }
        if !s.bytes().next().is_some_and(|b| b.is_ascii_alphanumeric()) {
            return Err(UnihelmError::new(
                ErrorCode::InvalidInput,
                "a volume name must start with a letter or a digit",
            )
            .with_field("volume"));
        }
        if !s
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
        {
            return Err(UnihelmError::new(
                ErrorCode::InvalidInput,
                "a volume name may only contain letters, digits, underscore, dot and hyphen",
            )
            .with_field("volume"));
        }
        Ok(Self(s.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for VolumeRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for VolumeRef {
    type Error = UnihelmError;
    fn try_from(value: String) -> Result<Self> {
        Self::parse(&value)
    }
}

impl From<VolumeRef> for String {
    fn from(v: VolumeRef) -> String {
        v.0
    }
}

/// The interface a published port is bound to unless somebody asks for more.
///
/// Docker installs its published-port DNAT rule in `PREROUTING`, which nftables
/// evaluates before `INPUT` — where ufw and firewalld keep their rules. A port
/// published as `-p 8080:80` therefore answers the internet whatever the panel's
/// own Firewall page has been told, and that page has no way to see it: the
/// operator reads "closed" off a chain the packet never reaches. Binding the
/// host side to loopback puts the port back under the firewall's jurisdiction,
/// which is what [`crate::engine`] and [`crate::appcontainer`] have always done.
const LOOPBACK: &str = "127.0.0.1";

/// One published port: a host port, a container port, TCP or UDP, and who may
/// reach it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortMap {
    pub host: u16,
    pub container: u16,
    #[serde(default)]
    pub udp: bool,
    /// Bind the host side to every interface instead of to [`LOOPBACK`].
    ///
    /// Defaults to false, and the default is the security property. Until 0.7.2
    /// there was no field here at all and every container the panel created was
    /// published on `0.0.0.0`: a database created from this form was open to the
    /// internet from the moment it started, and the Firewall page went on
    /// showing the port as closed because Docker's DNAT rule is evaluated before
    /// the chain that page describes. That is the panel reporting something is
    /// true when it is not, which is the one thing it must never do.
    ///
    /// Set, this is a deliberate choice by somebody who wants a port reachable
    /// from outside — and [`Create`] writes that choice into the task output, so
    /// the audit trail says who opened it and when rather than leaving the next
    /// operator to find it with a port scan.
    #[serde(default)]
    pub public: bool,
}

/// What goes after `--publish`, which is the whole of this defect's surface.
///
/// Built as a function rather than inline so a test can hold it: the difference
/// between the two branches is invisible in a diff of the argv, and nothing else
/// in this file notices if the loopback prefix goes missing again.
fn publish_spec(p: &PortMap) -> String {
    let proto = if p.udp { "/udp" } else { "" };
    if p.public {
        format!("{}:{}{proto}", p.host, p.container)
    } else {
        format!("{LOOPBACK}:{}:{}{proto}", p.host, p.container)
    }
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

        // Every host port this form asks for, checked against what is already
        // published, **before** the image is pulled.
        //
        // Without this the first thing that noticed a clash was Docker, minutes
        // into a pull, and its answer named an endpoint id and a driver rather
        // than the port — so an operator whose Valkey already had 6379 learned
        // that "driver failed programming external connectivity" and nothing
        // about which of their two forms to change. The check is a pre-flight
        // and not a lock: something can still take a port between here and the
        // run, which is why `run_failure` below still translates Docker's own
        // refusal rather than assuming this pass makes one impossible.
        let published = published_ports(&docker).await;
        for p in &input.ports {
            if let Some(taken) = published
                .iter()
                .find(|held| held.host == p.host && held.udp == p.udp)
            {
                return Err(UnihelmError::new(
                    ErrorCode::Conflict,
                    format!(
                        "host port {}{} is already published by the container `{}`. \
                         Publish this one on a different host port, or stop `{}` first. \
                         Nothing has been created.",
                        p.host,
                        proto(p.udp),
                        taken.container,
                        taken.container
                    ),
                )
                .with_field("ports"));
            }
        }

        let args = create_argv(&input)?;

        ctx.log(format!(
            "docker run --detach --name {} {}",
            input.name.as_str(),
            input.image.as_str()
        ));

        // A public port is the one thing this form can do that the Firewall page
        // will not show afterwards, so it is named in the task output at the
        // moment it happens. Without this line the only record of the decision
        // is the DNAT rule itself, and the operator who finds that six months
        // later has no way to tell a deliberate choice from this module's old
        // default.
        for p in input.ports.iter().filter(|p| p.public) {
            ctx.log(format!(
                "publishing {}{} on every interface, as asked: this port is \
                 reachable from the internet and the Firewall page cannot close \
                 it, because Docker's rule is evaluated before ufw's",
                p.host,
                if p.udp { "/udp" } else { "" }
            ));
        }

        let out = unihelm_distro::Cmd::new(&docker)
            .args(args.iter().map(String::as_str))
            // A pull over a slow link, and Docker gives no progress this can
            // stream, so the ceiling is generous rather than tight.
            .timeout(std::time::Duration::from_secs(600))
            .run()
            .await
            .map_err(|e| UnihelmError::internal(e.to_string()))?;

        if !out.success() {
            let text = out.failure_text();

            // `docker run` creates the container and *then* starts it, so a
            // failure at the start — a port already allocated is the usual one
            // — leaves it on the machine in `created`. Until this swept, the
            // operator's second attempt failed on the *name* as well as the
            // port, and the message they got was about the name: it sent them
            // hunting for a container they never successfully made. The name
            // was free a moment ago (checked above), so anything wearing it now
            // is this run's own wreckage and nobody else's container.
            let swept = sweep_failed_run(ctx, &docker, &input.name).await;

            // Whichever container is holding the port, so the refusal names it
            // rather than leaving the operator to run `docker ps` themselves.
            let holder = allocated_port(&text).and_then(|port| {
                published
                    .iter()
                    .find(|held| held.host == port)
                    .map(|held| held.container.clone())
            });

            let err = run_failure(&text, input.name.as_str(), holder.as_deref(), swept);
            // The ports box is the field an operator has to change, and only
            // when the failure really was a port; a `field` on any other
            // failure would point the form at the wrong input.
            return Err(if err.code == ErrorCode::Conflict {
                err.with_field("ports")
            } else {
                err
            });
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

/// The whole `docker run` argv, and every check that has to pass before one
/// exists.
///
/// Lifted out of [`Create::run`] for the same reason [`inspect_argv`] and
/// [`logs_argv`] are functions: a test can hold it. The bindings below are each
/// load bearing and each invisible in their absence — a missing `127.0.0.1:` on
/// a `--publish` reads exactly like the argv that has one until somebody scans
/// the port from outside.
fn create_argv(input: &CreateInput) -> Result<Vec<String>> {
    let mut args: Vec<String> = vec![
        "run".into(),
        "--detach".into(),
        "--name".into(),
        input.name.as_str().to_string(),
        "--restart".into(),
        input.restart.as_str().to_string(),
    ];

    for p in &input.ports {
        args.push("--publish".into());
        args.push(publish_spec(p));
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

    // The image last, after every flag, so it is never read as the value of one
    // — the same rule the lifecycle argvs follow for the container.
    args.push(input.image.as_str().to_string());
    Ok(args)
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
    // One grammar, in [`VolumeRef`], rather than a second copy here. The
    // wording is still this call site's, because "not a volume name" is a thin
    // answer where the operator has just typed a path and the reason they must
    // not is the whole point of the field.
    VolumeRef::parse(&v.volume).map_err(|_| {
        UnihelmError::new(
            ErrorCode::InvalidInput,
            format!(
                "`{}` is not a volume name. This creates containers with named \
                 volumes; a path here would be a bind mount, which would give the \
                 container part of this server's filesystem.",
                v.volume
            ),
        )
        .with_field("volumes")
    })?;
    if !v.path.starts_with('/') || v.path.contains("..") || v.path.len() > 255 {
        return Err(UnihelmError::new(
            ErrorCode::InvalidInput,
            "the mount path must be absolute and free of `..`",
        )
        .with_field("volumes"));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Images
// ---------------------------------------------------------------------------

/// What the two single-image operations take, and all they take.
#[derive(Debug, Deserialize)]
pub struct ImageInput {
    pub image: ImageRef,
}

#[derive(Debug, Serialize)]
pub struct ImagePullOutput {
    pub image: String,
    /// The digest Docker resolved the reference to, which is the only thing
    /// that says *which* `nginx:latest` this now is.
    pub id: String,
    /// What it occupies, in bytes.
    ///
    /// `None` rather than 0 when Docker answered in a shape this build cannot
    /// read: an image reported as occupying nothing is a lie about a disk, and
    /// a disk is the thing this operation exists to manage.
    pub size_bytes: Option<u64>,
    /// True when the tag was already at this digest and nothing was fetched.
    ///
    /// Reported rather than glossed over: "pulled" and "already had it" are
    /// different answers to "did my update arrive", and a panel that says
    /// `pulled` for both is telling somebody their image is new when it is the
    /// one they have been running for a year.
    pub already_current: bool,
}

/// `docker.image.pull` — fetch an image, or confirm it is already current.
pub struct ImagePull;

#[async_trait::async_trait]
impl TypedOperation for ImagePull {
    type Input = ImageInput;
    type Output = ImagePullOutput;

    const NAME: &'static str = "docker.image.pull";
    const PERMISSION: Permission = Permission::ServerManage;
    // Minutes on a slow link, and the operator should see the pull rather than
    // a spinner — the same reason `docker.create` is a task.
    const EXECUTION: Execution = Execution::Task {
        cancellable: false,
        // Re-running a pull that half-finished is what an operator would do by
        // hand, and Docker resumes from the layers it already has.
        idempotent: true,
    };

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let docker = docker_program()?;

        // The same [`ImageRef`] the create form validates against, not a second
        // parser: this is the one field that names something the server will
        // fetch, and two grammars for it would be two things to keep in step.
        ctx.log(format!("docker pull {}", input.image));

        let out = run_raw(&docker, &pull_argv(&input.image), PULL_BUDGET).await?;
        if !out.success() {
            return Err(UnihelmError::new(
                ErrorCode::CommandFailed,
                out.failure_text(),
            ));
        }

        // Docker's own closing line — "Status: Image is up to date for
        // nginx:latest" or "Status: Downloaded newer image for nginx:latest" —
        // quoted into the task log, because it is the sentence that says which
        // of the two happened.
        let status = status_line(out.trimmed_stdout());
        if let Some(line) = &status {
            ctx.log(line.clone());
        }

        let (id, size_bytes) = image_identity(&docker, &input.image).await?;
        Ok(ImagePullOutput {
            image: input.image.as_str().to_string(),
            id,
            size_bytes,
            already_current: status.is_some_and(|l| l.contains("up to date")),
        })
    }
}

#[derive(Debug, Serialize)]
pub struct ImageRemoveOutput {
    pub image: String,
    pub id: String,
    /// Docker's own `Untagged:` and `Deleted:` lines.
    ///
    /// An image with two tags is *untagged* rather than deleted, and no space
    /// comes back until the last tag goes. Reporting the lines verbatim is how
    /// an operator who expected a gigabyte back finds out why they did not get
    /// it.
    pub removed: Vec<String>,
}

/// `docker.image.remove` — delete an image nothing is running.
///
/// **An image a container still needs is refused, and the container is named.**
/// Docker's own answer to this is `rmi -f`, which untags the image out from
/// under a running service: the container keeps running on an image that no
/// longer has a name, and the next restart — a reboot, a `restart: always`
/// after an OOM kill — finds nothing to start from. That is a service that dies
/// hours later for a reason nobody will connect to a button pressed this
/// morning, so this refuses instead and says which container to deal with
/// first.
pub struct ImageRemove;

#[async_trait::async_trait]
impl TypedOperation for ImageRemove {
    type Input = ImageInput;
    type Output = ImageRemoveOutput;

    const NAME: &'static str = "docker.image.remove";
    const PERMISSION: Permission = Permission::ServerManage;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let docker = docker_program()?;
        let (id, _) = image_identity(&docker, &input.image).await?;

        let users = containers_using_image(&docker, &input.image).await;
        if !users.is_empty() {
            return Err(UnihelmError::new(
                ErrorCode::DependentsExist,
                format!(
                    "`{}` is the image {} {} — remove {} first, or leave the image where \
                     it is. The panel will not force-remove an image a container is \
                     built on: the container would keep running with no image to \
                     restart from.",
                    input.image,
                    if users.len() == 1 {
                        "behind the container"
                    } else {
                        "behind the containers"
                    },
                    quoted_list(&users),
                    if users.len() == 1 { "it" } else { "them" },
                ),
            )
            .with_field("image"));
        }

        ctx.log(format!("docker image rm {}", input.image));
        let out = run_raw(&docker, &image_remove_argv(&input.image), ACTION_BUDGET).await?;
        if !out.success() {
            return Err(UnihelmError::new(
                ErrorCode::CommandFailed,
                out.failure_text(),
            ));
        }

        Ok(ImageRemoveOutput {
            image: input.image.as_str().to_string(),
            id,
            removed: out
                .trimmed_stdout()
                .lines()
                .map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty())
                .collect(),
        })
    }
}

#[derive(Debug, Default, Deserialize)]
pub struct ImagePruneInput {
    /// List what would go and delete nothing.
    ///
    /// Defaults to false, because an operator who pressed Prune and got a list
    /// would reasonably believe the disk had been reclaimed. The dry run is for
    /// somebody who asked for it by name.
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Debug, Serialize)]
pub struct ImagePruneOutput {
    pub dry_run: bool,
    /// The dangling images, named **before** anything is removed.
    pub candidates: Vec<Image>,
    /// Docker's own `deleted:` and `untagged:` lines. Empty on a dry run.
    pub deleted: Vec<String>,
    /// Docker's own "Total reclaimed space" figure — `0B` when nothing went.
    ///
    /// This number is the entire value of the operation. A prune that answers
    /// "done" is indistinguishable from one that deleted nothing, and an
    /// operator watching a disk fill needs to know which of those happened.
    pub reclaimed: String,
}

/// `docker.image.prune` — reclaim the disk that dangling layers eat.
///
/// **Dangling only. Never `--all`.** `docker image prune -a` removes every image
/// no container currently uses, which includes the one an operator pulled this
/// morning for a container they have not created yet, and every image behind a
/// container they have stopped for the weekend. Dangling images — the untagged
/// leftovers of a rebuild or a re-pull — are the ones nothing can ever refer to
/// again, and they are what actually fills a small VPS.
pub struct ImagePrune;

#[async_trait::async_trait]
impl TypedOperation for ImagePrune {
    type Input = ImagePruneInput;
    type Output = ImagePruneOutput;

    const NAME: &'static str = "docker.image.prune";
    const PERMISSION: Permission = Permission::ServerManage;
    // Deleting several gigabytes of layers is not a 300 ms answer, and the list
    // of what went belongs in a log the operator can read afterwards.
    const EXECUTION: Execution = Execution::Task {
        cancellable: false,
        // Nothing is left half-pruned that a second run would make worse: the
        // second run finds whatever the first did not get to.
        idempotent: true,
    };

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let docker = docker_program()?;

        // Named before anything is deleted, in the task log, so the record of
        // what a prune took is written even if the prune itself then fails
        // half-way.
        let candidates = dangling_images(&docker).await;
        if candidates.is_empty() {
            ctx.log("no dangling images on this server; nothing to reclaim");
        }
        for image in &candidates {
            ctx.log(format!(
                "dangling: {} {} ({})",
                image.id, image.repository, image.size
            ));
        }

        if input.dry_run {
            ctx.log("dry run: nothing was deleted");
            return Ok(ImagePruneOutput {
                dry_run: true,
                candidates,
                deleted: Vec::new(),
                reclaimed: "0B".to_string(),
            });
        }

        ctx.log("docker image prune");
        let out = run_raw(&docker, &prune_argv(), PRUNE_BUDGET).await?;
        if !out.success() {
            return Err(UnihelmError::new(
                ErrorCode::CommandFailed,
                out.failure_text(),
            ));
        }

        let text = out.trimmed_stdout();
        let reclaimed = reclaimed_space(text);
        ctx.log(format!("reclaimed {reclaimed}"));

        Ok(ImagePruneOutput {
            dry_run: false,
            candidates,
            deleted: deleted_lines(text),
            reclaimed,
        })
    }
}

/// How long a pull is given: fifteen minutes, sized on the operator's link.
///
/// The same number and the same reasoning as [`crate::engine`]'s budget: a
/// few hundred megabytes over the 5 Mbit uplink a cheap VPS actually has is
/// minutes and is not a failure, and a pull killed for being slow throws away
/// the layers it had already fetched.
const PULL_BUDGET: Duration = Duration::from_secs(15 * 60);

/// How long a prune is given. Deleting tens of gigabytes of layers off a slow
/// disk is minutes, and a prune killed part-way leaves the operator unable to
/// say how much actually came back.
const PRUNE_BUDGET: Duration = Duration::from_secs(10 * 60);

fn pull_argv(image: &ImageRef) -> Vec<String> {
    vec!["pull".to_string(), image.as_str().to_string()]
}

/// Bare `image rm`, and the omission is the point: no `--force`.
///
/// `docker rmi -f` untags an image a container is still built on, which leaves
/// that container running on something it can never be restarted from. The
/// refusal in [`ImageRemove`] is what replaces it.
fn image_remove_argv(image: &ImageRef) -> Vec<String> {
    vec![
        "image".to_string(),
        "rm".to_string(),
        image.as_str().to_string(),
    ]
}

/// `--force` here is **not** `rm -f`: it is Docker's "do not ask me y/N", and
/// there is no terminal on the other end of this to answer the prompt. What is
/// deliberately absent is `--all`; see [`ImagePrune`].
fn prune_argv() -> Vec<String> {
    vec![
        "image".to_string(),
        "prune".to_string(),
        "--force".to_string(),
    ]
}

/// The digest and the byte size of an image that is already here.
async fn image_identity(docker: &str, image: &ImageRef) -> Result<(String, Option<u64>)> {
    let out = run_raw(
        docker,
        &[
            "image".to_string(),
            "inspect".to_string(),
            "--format".to_string(),
            "{{.Id}}\t{{.Size}}".to_string(),
            image.as_str().to_string(),
        ],
        BUDGET,
    )
    .await?;
    if !out.success() {
        let text = out.failure_text();
        let lower = text.to_ascii_lowercase();
        // A daemon that is down fails this command too, and reporting that as a
        // missing image would send an operator looking for something they never
        // pulled while `docker.service` is what is actually wrong.
        return Err(
            if lower.contains("no such image") || lower.contains("no such object") {
                UnihelmError::not_found(format!("image `{image}`")).with_field("image")
            } else {
                UnihelmError::new(ErrorCode::CommandFailed, text.trim().to_string())
            },
        );
    }

    let Some(row) = rows(out.trimmed_stdout(), 2).into_iter().next() else {
        return Err(UnihelmError::internal(
            "`docker image inspect` answered in a shape this build does not recognise",
        ));
    };
    Ok((row[0].clone(), row[1].parse().ok()))
}

/// Which containers are built on this image, running or stopped.
///
/// A stopped container counts, and that is the case this exists for: it is
/// invisible in `docker ps`, it is what an operator forgets, and it is exactly
/// what a removed image would strand.
///
/// Docker's `ancestor` filter answers with containers built on the image *or on
/// anything derived from it*. Erring wide is the safe direction here — the
/// worst it costs is a refusal an operator can resolve by removing a container
/// — and it is Docker's own accounting rather than a second one kept here.
async fn containers_using_image(docker: &str, image: &ImageRef) -> Vec<String> {
    let filter = format!("ancestor={}", image.as_str());
    let Some(text) = run_docker(
        docker,
        &["ps", "--all", "--filter", &filter, "--format", "{{.Names}}"],
    )
    .await
    else {
        return Vec::new();
    };
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect()
}

/// The untagged leftovers of a rebuild or a re-pull.
async fn dangling_images(docker: &str) -> Vec<Image> {
    let Some(text) = run_docker(
        docker,
        &[
            "images",
            "--filter",
            "dangling=true",
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

/// Docker's `Total reclaimed space:` figure, in Docker's own units.
///
/// `0B` when the line is absent rather than an empty string, because the field
/// is what an operator reads to find out whether the operation was worth
/// pressing, and a blank there reads as a bug rather than as "nothing went".
fn reclaimed_space(text: &str) -> String {
    text.lines()
        .find_map(|l| l.trim().strip_prefix("Total reclaimed space:"))
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "0B".to_string())
}

/// The `untagged:` and `deleted:` lines a prune prints, and nothing else.
///
/// The rest of the output is a `Deleted Images:` heading, a blank line and the
/// reclaimed total, none of which is a thing that was deleted.
fn deleted_lines(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| {
            let lower = l.to_ascii_lowercase();
            lower.starts_with("deleted:") || lower.starts_with("untagged:")
        })
        .map(str::to_string)
        .collect()
}

/// Docker's closing `Status:` line from a pull, which says whether anything was
/// actually fetched.
fn status_line(text: &str) -> Option<String> {
    text.lines()
        .map(str::trim)
        .find(|l| l.starts_with("Status:"))
        .map(str::to_string)
}

/// `` `a` ``, `` `a` and `b` ``, `` `a`, `b` and `c` `` — a list a person reads.
fn quoted_list(names: &[String]) -> String {
    let quoted: Vec<String> = names.iter().map(|n| format!("`{n}`")).collect();
    match quoted.split_last() {
        None => String::new(),
        Some((last, [])) => last.clone(),
        Some((last, rest)) => format!("{} and {last}", rest.join(", ")),
    }
}

// ---------------------------------------------------------------------------
// Volumes
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct VolumeInput {
    pub volume: VolumeRef,
}

#[derive(Debug, Serialize)]
pub struct VolumeRemoveOutput {
    pub volume: String,
}

/// `docker.volume.remove` — delete a volume nothing is using.
///
/// Two refusals stand in front of this, and both exist because a volume is the
/// only thing on this page whose deletion cannot be undone by pulling something
/// again:
///
/// 1. **A container still references it.** Named, not forced. Docker refuses
///    this too, but its message names the volume and not the container, which
///    leaves the operator to find the container themselves.
/// 2. **It holds an engine this panel installed.** Deleting it is deleting
///    every database in that engine while the panel's own registry goes on
///    saying the engine is there — the panel reporting something that is not
///    true, which is the one thing it must never do. `engine.remove` with
///    `delete_data` is the operation that does this properly: it forgets the
///    record at the same time.
pub struct VolumeRemove;

#[async_trait::async_trait]
impl TypedOperation for VolumeRemove {
    type Input = VolumeInput;
    type Output = VolumeRemoveOutput;

    const NAME: &'static str = "docker.volume.remove";
    const PERMISSION: Permission = Permission::ServerManage;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let docker = docker_program()?;
        volume_exists(&docker, &input.volume).await?;

        let engines = crate::engine::registry(ctx.db()).await?;
        if let Some(record) = engines
            .values()
            .find(|r| r.volume.as_deref() == Some(input.volume.as_str()))
        {
            return Err(UnihelmError::new(
                ErrorCode::Conflict,
                format!(
                    "`{}` is where the {} engine `{}` keeps its data — deleting it deletes \
                     every database in that engine. `engine.remove` with `delete_data` is \
                     the way to do this: it removes the engine's record at the same time, \
                     so the panel does not go on reporting an engine whose data is gone.",
                    input.volume, record.slug, record.container
                ),
            )
            .with_field("volume"));
        }

        let users = containers_using_volume(&docker, &input.volume).await;
        if !users.is_empty() {
            return Err(UnihelmError::new(
                ErrorCode::DependentsExist,
                format!(
                    "`{}` is mounted by {} {} — remove {} first. A volume outlives its \
                     container here on purpose, so the panel will not delete one out from \
                     under something that still refers to it.",
                    input.volume,
                    if users.len() == 1 {
                        "the container"
                    } else {
                        "the containers"
                    },
                    quoted_list(&users),
                    if users.len() == 1 {
                        "that container"
                    } else {
                        "those containers"
                    },
                ),
            )
            .with_field("volume"));
        }

        ctx.log(format!("docker volume rm {}", input.volume));
        run_checked(&docker, &volume_remove_argv(&input.volume), ACTION_BUDGET).await?;

        Ok(VolumeRemoveOutput {
            volume: input.volume.as_str().to_string(),
        })
    }
}

fn volume_remove_argv(volume: &VolumeRef) -> Vec<String> {
    vec![
        "volume".to_string(),
        "rm".to_string(),
        volume.as_str().to_string(),
    ]
}

/// Fail with "no such volume" before anything else is decided, so a typo does
/// not come back as one of the refusals above.
async fn volume_exists(docker: &str, volume: &VolumeRef) -> Result<()> {
    let out = run_raw(
        docker,
        &[
            "volume".to_string(),
            "inspect".to_string(),
            "--format".to_string(),
            "{{.Name}}".to_string(),
            volume.as_str().to_string(),
        ],
        BUDGET,
    )
    .await?;
    if out.success() {
        return Ok(());
    }
    let text = out.failure_text();
    let lower = text.to_ascii_lowercase();
    Err(
        if lower.contains("no such volume") || lower.contains("no such object") {
            UnihelmError::not_found(format!("volume `{volume}`")).with_field("volume")
        } else {
            UnihelmError::new(ErrorCode::CommandFailed, text.trim().to_string())
        },
    )
}

/// Which containers mount this volume, running or stopped, from Docker's own
/// `volume=` filter rather than from a mount list this module re-derived.
async fn containers_using_volume(docker: &str, volume: &VolumeRef) -> Vec<String> {
    let filter = format!("volume={}", volume.as_str());
    let Some(text) = run_docker(
        docker,
        &["ps", "--all", "--filter", &filter, "--format", "{{.Names}}"],
    )
    .await
    else {
        return Vec::new();
    };
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect()
}

// ---------------------------------------------------------------------------
// When a run does not start: which port, and what was left behind
// ---------------------------------------------------------------------------

/// How a port is spelled in a sentence to an operator.
fn proto(udp: bool) -> &'static str {
    if udp { "/udp" } else { "" }
}

/// One host port a container is currently publishing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Published {
    pub(crate) host: u16,
    pub(crate) udp: bool,
    pub(crate) container: String,
}

/// Which container publishes which host port, from Docker's own `ps`.
///
/// Running containers only, and that is not an oversight: a stopped container
/// releases its published ports, so listing `--all` here would refuse a port
/// nothing is actually holding.
pub(crate) async fn published_ports(docker: &str) -> Vec<Published> {
    let Some(text) = run_docker(docker, &["ps", "--format", "{{.Names}}\t{{.Ports}}"]).await else {
        // No answer is no knowledge, not "nothing is published". The caller
        // treats an empty list as "we could not tell" and lets Docker be the
        // backstop, which is the only honest reading.
        return Vec::new();
    };

    rows(&text, 2)
        .into_iter()
        .flat_map(|r| {
            let container = r[0].clone();
            host_ports_in(&r[1])
                .into_iter()
                .map(move |(host, udp)| Published {
                    host,
                    udp,
                    container: container.clone(),
                })
        })
        .collect()
}

/// The host side of every mapping in a `docker ps` ports column.
///
/// The column is a comma-separated list of `127.0.0.1:8080->80/tcp`, plus bare
/// `9000/tcp` entries for ports a container *exposes* but does not publish.
/// Only the published half matters here — an exposed port holds nothing on the
/// host — so an entry with no `->` is skipped rather than read as a host port,
/// which would refuse 9000 to everybody because one container documented it.
///
/// The host address is split off at the **last** colon before the arrow, so an
/// IPv6 bind (`[::]:8080->80/tcp`) yields 8080 rather than a parse failure.
fn host_ports_in(column: &str) -> Vec<(u16, bool)> {
    column
        .split(',')
        .map(str::trim)
        .filter_map(|entry| {
            let (host_side, target) = entry.split_once("->")?;
            let udp = target.ends_with("/udp");
            let port = host_side.rsplit(':').next()?;
            port.trim().parse::<u16>().ok().map(|p| (p, udp))
        })
        .collect()
}

/// The host port Docker refused to bind, read out of its own failure text.
///
/// Docker says it like this, on one line with an endpoint id and a driver in
/// front of it:
///
/// ```text
/// driver failed programming external connectivity on endpoint web (a1b2…):
/// Bind for 127.0.0.1:6379 failed: port is already allocated
/// ```
///
/// The number is in there and an operator should not have to find it. Anchored
/// on `port is already allocated` rather than on `Bind for`, so a different
/// bind failure — a permission denied on a privileged port, say — is not
/// rewritten into a conflict it is not.
pub(crate) fn allocated_port(text: &str) -> Option<u16> {
    if !text.contains("port is already allocated") {
        return None;
    }
    let after = text.split("Bind for ").nth(1)?;
    let addr = after.split_whitespace().next()?;
    addr.rsplit(':').next()?.trim().parse::<u16>().ok()
}

/// What became of the container a failed `docker run` left behind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Swept {
    /// There was nothing on the machine to remove.
    Nothing,
    /// The half-made container was removed; its name is free again.
    Removed,
    /// It is still there, and the operator has to deal with it. Carries why.
    Left(String),
}

/// Remove the container a failed `docker run` created.
///
/// Bare `rm`, never `-f`: the run failed at the start, so there is nothing
/// running to kill, and a force here would be a habit that eventually meets a
/// container that did start.
pub(crate) async fn sweep_failed_run(ctx: &OpContext, docker: &str, name: &ContainerRef) -> Swept {
    let Ok(found) = inspect(docker, name).await else {
        return Swept::Nothing;
    };
    if found.running {
        // It started after all, so the run failed for some other reason and
        // this container is not wreckage. Removing it would be this function
        // deleting something that works.
        return Swept::Left(format!("`{}` is running", found.name));
    }
    let Ok(target) = ContainerRef::parse(&found.id) else {
        return Swept::Left("Docker returned an id this build cannot parse".to_string());
    };

    ctx.log(format!(
        "the run failed after creating {}; removing it so the name is free",
        found.name
    ));
    match run_raw(docker, &Lifecycle::Remove.argv(&target), ACTION_BUDGET).await {
        Ok(out) if out.success() => Swept::Removed,
        Ok(out) => Swept::Left(out.failure_text()),
        Err(e) => Swept::Left(e.to_string()),
    }
}

/// Turn a failed `docker run` into a sentence an operator can act on.
///
/// Two things are added to Docker's own text, and both are what the raw message
/// left the operator to work out for themselves: **which host port** is taken,
/// which Docker buries inside a sentence about endpoint ids, and **what
/// happened to the container** the failed run created, which Docker does not
/// mention at all. Docker's words are kept verbatim for every other failure —
/// they are already written for the person reading them, and paraphrasing would
/// put a second, worse source of truth in front of the operator.
pub(crate) fn run_failure(
    text: &str,
    container: &str,
    holder: Option<&str>,
    swept: Swept,
) -> UnihelmError {
    let (code, mut detail) = match allocated_port(text) {
        Some(port) => {
            let held = match holder {
                Some(name) => format!("the container `{name}` is already publishing it"),
                // Docker knows the port is taken; the panel could not find a
                // container holding it, which usually means something outside
                // Docker is listening. Saying that is more use than naming a
                // container that is not the one.
                None => "something on this server is already listening on it".to_string(),
            };
            (
                ErrorCode::Conflict,
                format!(
                    "`{container}` could not start: host port {port} is already in use — \
                     {held}. Publish it on a different host port, or free {port} first."
                ),
            )
        }
        None => (
            ErrorCode::CommandFailed,
            format!("`{container}` could not start: {}", text.trim()),
        ),
    };

    match swept {
        // Nothing to say. A sentence about a cleanup that had nothing to clean
        // reads as though something went wrong twice.
        Swept::Nothing => {}
        Swept::Removed => detail.push_str(&format!(
            " The container Docker had already created was removed, so the name \
             `{container}` is free to try again."
        )),
        Swept::Left(why) => detail.push_str(&format!(
            " The container `{container}` was created before the failure and could not be \
             removed ({why}), so this name cannot be reused until `docker rm {container}` \
             clears it."
        )),
    }

    UnihelmError::new(code, detail)
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

    // -----------------------------------------------------------------------
    // Where a published port is bound
    // -----------------------------------------------------------------------

    fn port(host: u16, container: u16) -> PortMap {
        PortMap {
            host,
            container,
            udp: false,
            public: false,
        }
    }

    fn create_input(ports: Vec<PortMap>) -> CreateInput {
        CreateInput {
            image: ImageRef::parse("nginx").unwrap(),
            name: ContainerRef::parse("web").unwrap(),
            ports,
            env: Vec::new(),
            volumes: Vec::new(),
            restart: RestartPolicy::No,
        }
    }

    fn value_of(argv: &[String], flag: &str) -> String {
        argv.windows(2)
            .find(|w| w[0] == flag)
            .map(|w| w[1].clone())
            .unwrap_or_else(|| panic!("no `{flag}` in {argv:?}"))
    }

    /// The defect this binding exists for, and the reason a test rather than a
    /// comment holds it.
    ///
    /// Docker's published-port DNAT rule lands in `PREROUTING`, ahead of the
    /// `INPUT` chain ufw and firewalld write to. A container created here with a
    /// bare `-p 8080:80` was reachable from the internet the moment it started,
    /// and the panel's own Firewall page kept showing the port as closed —
    /// because the packet never reaches the chain that page describes. Nothing
    /// else in this file notices if the prefix is dropped again.
    #[test]
    fn a_published_port_is_bound_to_loopback_unless_it_was_asked_for() {
        let argv = create_argv(&create_input(vec![port(8080, 80)])).unwrap();
        let publish = value_of(&argv, "--publish");
        assert!(
            publish.starts_with("127.0.0.1:"),
            "this container would answer the internet: {publish}"
        );
        assert_eq!(publish, "127.0.0.1:8080:80");
        assert_eq!(argv.last().map(String::as_str), Some("nginx"));
    }

    /// UDP is published the same way. The protocol suffix goes on the end, where
    /// Docker expects it, and does not displace the bind address.
    #[test]
    fn a_udp_port_is_bound_to_loopback_too() {
        let mut p = port(5353, 53);
        p.udp = true;
        assert_eq!(publish_spec(&p), "127.0.0.1:5353:53/udp");
        p.public = true;
        assert_eq!(publish_spec(&p), "5353:53/udp");
    }

    /// Asking for it is the only way to get it, and asking for it drops the bind
    /// address rather than adding a second one — `0.0.0.0:8080:80` and
    /// `8080:80` mean the same thing to Docker, and the shorter is what an
    /// operator would have typed.
    #[test]
    fn the_public_flag_is_the_only_thing_that_opens_a_port_to_the_internet() {
        let mut p = port(8080, 80);
        p.public = true;
        let argv = create_argv(&create_input(vec![p])).unwrap();
        let publish = value_of(&argv, "--publish");
        assert_eq!(publish, "8080:80");
        assert!(!publish.contains("127.0.0.1"));
    }

    /// One public port must not carry its neighbours out with it: each mapping
    /// is bound on its own, in the order the operator listed them.
    #[test]
    fn one_public_port_does_not_open_the_others() {
        let mut open = port(8080, 80);
        open.public = true;
        let argv = create_argv(&create_input(vec![
            port(5432, 5432),
            open,
            port(6379, 6379),
        ]))
        .unwrap();
        let published: Vec<&String> = argv
            .windows(2)
            .filter(|w| w[0] == "--publish")
            .map(|w| &w[1])
            .collect();
        assert_eq!(
            published,
            vec!["127.0.0.1:5432:5432", "8080:80", "127.0.0.1:6379:6379"]
        );
    }

    /// The wire default is the safe one. A caller that has never heard of this
    /// field — an older UI build, a script written against 0.7.1, `curl` — gets
    /// a private port, because the alternative is a silent world-reachable one.
    #[test]
    fn a_port_with_no_public_field_is_private() {
        let parsed: CreateInput = serde_json::from_value(serde_json::json!({
            "image": "postgres:16",
            "name": "db",
            "ports": [{ "host": 5432, "container": 5432 }],
        }))
        .expect("a port map without `public` must still parse");
        assert!(!parsed.ports[0].public);
        assert_eq!(
            value_of(&create_argv(&parsed).unwrap(), "--publish"),
            "127.0.0.1:5432:5432"
        );

        let asked: CreateInput = serde_json::from_value(serde_json::json!({
            "image": "nginx",
            "name": "web",
            "ports": [{ "host": 80, "container": 80, "public": true }],
        }))
        .expect("`public` is a field a caller can set");
        assert!(asked.ports[0].public);
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

/// Images, volumes, and the port clash that used to leave wreckage behind.
///
/// Everything here was missing rather than wrong. Images and volumes were a
/// read-only list — an operator could watch a disk fill and had no way to empty
/// it from the panel — and a `docker run` that failed on a port answered with
/// Docker's sentence about endpoint ids while leaving the half-made container
/// on the machine for the next attempt to trip over.
#[cfg(test)]
mod image_volume_and_conflict_tests {
    use super::*;

    // -----------------------------------------------------------------------
    // VolumeRef
    // -----------------------------------------------------------------------

    /// The grammar `validate_volume` used to carry its own copy of. A path in
    /// the volume position is a bind mount, which is a piece of this server's
    /// filesystem handed to a container.
    #[test]
    fn a_volume_name_is_never_a_path_or_an_option() {
        for bad in [
            "/",
            "/var/lib/docker",
            "../etc",
            "./data",
            "-f",
            "--force",
            "",
            "   ",
            "app data",
            "app;rm -rf /",
            "$(id)",
            "café",
        ] {
            let Err(err) = VolumeRef::parse(bad) else {
                panic!("`{bad}` reached an argv as a volume");
            };
            assert_eq!(err.code, ErrorCode::InvalidInput, "for `{bad}`");
            assert_eq!(err.field.as_deref(), Some("volume"), "for `{bad}`");
        }

        for good in ["app_data", "pg-16.data", "unihelm-mariadb-11.8", "v1"] {
            assert!(VolumeRef::parse(good).is_ok(), "refused volume `{good}`");
        }
    }

    /// `validate_volume` still speaks about bind mounts, because that is the
    /// mistake somebody typing into the create form has just made — it only
    /// stopped carrying a second copy of the grammar.
    #[test]
    fn the_mount_field_still_explains_bind_mounts_while_sharing_one_grammar() {
        let err = validate_volume(&VolumeMount {
            volume: "/var/run/docker.sock".into(),
            path: "/sock".into(),
        })
        .expect_err("a path was accepted as a volume name");
        assert!(
            err.to_string().contains("bind mount"),
            "the refusal should say why: {err}"
        );
        assert_eq!(err.field.as_deref(), Some("volumes"));
    }

    // -----------------------------------------------------------------------
    // The argvs
    // -----------------------------------------------------------------------

    fn iref(s: &str) -> ImageRef {
        ImageRef::parse(s).expect("a real image reference")
    }

    /// Removing an image is never forced. `docker rmi -f` untags an image a
    /// running container is built on: the container keeps going and its next
    /// restart finds nothing to start from, hours later, for a reason nobody
    /// will connect to this button.
    #[test]
    fn removing_an_image_forces_nothing() {
        let argv = image_remove_argv(&iref("nginx:alpine"));
        assert_eq!(argv, vec!["image", "rm", "nginx:alpine"]);
        for forbidden in ["-f", "--force", "--no-prune"] {
            assert!(
                !argv.iter().any(|a| a == forbidden),
                "`{forbidden}` turns a removal into something the operator did not ask for"
            );
        }
    }

    /// The one flag that must never appear on a prune, and the one that must.
    ///
    /// `--all` removes every image no container currently uses — the one pulled
    /// this morning for a container not yet created, and every image behind a
    /// container stopped for the weekend. `--force` here is not `rm -f`: it is
    /// "do not ask me y/N", and there is no terminal to answer the prompt.
    #[test]
    fn a_prune_takes_dangling_images_only() {
        let argv = prune_argv();
        assert_eq!(argv, vec!["image", "prune", "--force"]);
        for forbidden in ["-a", "--all", "--filter"] {
            assert!(
                !argv.iter().any(|a| a == forbidden),
                "`{forbidden}` would delete images the operator still wants"
            );
        }
    }

    #[test]
    fn a_volume_is_removed_by_name_and_nothing_else() {
        let argv = volume_remove_argv(&VolumeRef::parse("app_data").unwrap());
        assert_eq!(argv, vec!["volume", "rm", "app_data"]);
        assert!(!argv.iter().any(|a| a == "--force"));
    }

    #[test]
    fn a_pull_names_the_image_last() {
        let argv = pull_argv(&iref("ghcr.io/owner/app:v1"));
        assert_eq!(argv, vec!["pull", "ghcr.io/owner/app:v1"]);
    }

    // -----------------------------------------------------------------------
    // What a prune reports
    // -----------------------------------------------------------------------

    /// The number that is the whole point of the operation. A prune that
    /// answers "done" is indistinguishable from one that deleted nothing.
    #[test]
    fn the_reclaimed_figure_is_dockers_own_and_never_blank() {
        let output = "Deleted Images:\n\
                      untagged: nginx@sha256:aaaa\n\
                      deleted: sha256:bbbb\n\
                      deleted: sha256:cccc\n\
                      \n\
                      Total reclaimed space: 1.093GB\n";
        assert_eq!(reclaimed_space(output), "1.093GB");
        assert_eq!(
            deleted_lines(output),
            vec![
                "untagged: nginx@sha256:aaaa",
                "deleted: sha256:bbbb",
                "deleted: sha256:cccc"
            ]
        );

        // Docker prints only the total when there was nothing to take.
        assert_eq!(reclaimed_space("Total reclaimed space: 0B\n"), "0B");
        assert!(deleted_lines("Total reclaimed space: 0B\n").is_empty());

        // And a shape this build does not recognise must still be a number an
        // operator can read, not an empty field that looks like a bug.
        assert_eq!(reclaimed_space(""), "0B");
        assert_eq!(reclaimed_space("Deleted Images:\n"), "0B");
    }

    /// The heading and the total are not things that were deleted, and counting
    /// them would overstate what a prune did.
    #[test]
    fn the_deleted_list_holds_only_deletions() {
        let lines =
            deleted_lines("Deleted Images:\ndeleted: sha256:aa\n\nTotal reclaimed space: 12MB\n");
        assert_eq!(lines, vec!["deleted: sha256:aa"]);
    }

    /// "Pulled" and "already had it" are different answers to "did my update
    /// arrive", and reporting the first for both tells somebody their image is
    /// new when it is the one they have been running for a year.
    #[test]
    fn a_pull_can_tell_a_fetch_from_an_image_already_current() {
        let fresh = status_line(
            "latest: Pulling from library/nginx\n\
             Digest: sha256:aaaa\n\
             Status: Downloaded newer image for nginx:latest\n",
        )
        .expect("Docker's closing line");
        assert!(!fresh.contains("up to date"));

        let same = status_line(
            "latest: Pulling from library/nginx\n\
             Status: Image is up to date for nginx:latest\n",
        )
        .expect("Docker's closing line");
        assert!(same.contains("up to date"));

        assert_eq!(status_line("no status here\n"), None);
    }

    // -----------------------------------------------------------------------
    // What a volume is attached to
    // -----------------------------------------------------------------------

    /// A stopped container still holds its volume, and it is the case that
    /// makes a volume look like an orphan: invisible in `docker ps`, still
    /// somebody's data, and the one Docker itself refuses a `volume rm` for.
    #[test]
    fn a_volume_names_every_container_that_mounts_it() {
        let ps = "shop_web_1\tapp_data,/etc/nginx/conf.d\n\
                  shop_db_1\tpg_data\n\
                  old_worker\tapp_data\n";
        let users = mounts_to_users(ps);
        assert_eq!(
            users.get("app_data").map(Vec::as_slice),
            Some(["shop_web_1".to_string(), "old_worker".to_string()].as_slice())
        );
        assert_eq!(
            users.get("pg_data").map(Vec::as_slice),
            Some(["shop_db_1".to_string()].as_slice())
        );
        // A bind mount is a path on the host and is nobody's volume.
        assert!(!users.contains_key("/etc/nginx/conf.d"));
    }

    /// A container with nothing mounted contributes nothing, rather than an
    /// entry under the empty name.
    #[test]
    fn a_container_with_no_mounts_claims_no_volume() {
        assert!(mounts_to_users("web\t\n").is_empty());
        assert!(mounts_to_users("").is_empty());
    }

    // -----------------------------------------------------------------------
    // Ports
    // -----------------------------------------------------------------------

    /// The pre-flight's whole input: which host ports are actually spoken for.
    ///
    /// A bare `9000/tcp` is a port a container *exposes* and does not publish —
    /// it holds nothing on the host, and reading it as taken would refuse 9000
    /// to everybody because one container documented it.
    #[test]
    fn only_published_mappings_hold_a_host_port() {
        let column = "127.0.0.1:6379->6379/tcp, 9000/tcp, 0.0.0.0:80->80/tcp, 53->53/udp";
        assert_eq!(
            host_ports_in(column),
            vec![(6379, false), (80, false), (53, true)]
        );
        assert!(host_ports_in("").is_empty());
        assert!(host_ports_in("9000/tcp").is_empty());
    }

    /// An IPv6 bind address is full of colons, and splitting on the first one
    /// would take `[` for a port number and lose the mapping entirely — which
    /// would let the pre-flight wave through a port that is very much taken.
    #[test]
    fn an_ipv6_binding_still_yields_its_host_port() {
        assert_eq!(host_ports_in("[::]:8080->80/tcp"), vec![(8080, false)]);
        assert_eq!(
            host_ports_in("[::1]:5432->5432/tcp, 0.0.0.0:5432->5432/tcp"),
            vec![(5432, false), (5432, false)]
        );
    }

    /// Docker buries the port inside a sentence about endpoint ids and driver
    /// programming. This is the line an operator was left to read.
    #[test]
    fn the_port_is_pulled_out_of_dockers_own_sentence() {
        let text = "docker: Error response from daemon: failed to set up container \
                    networking: driver failed programming external connectivity on \
                    endpoint unihelm-redis-7 (9f2c8e0b4a6d): Bind for 127.0.0.1:6379 \
                    failed: port is already allocated";
        assert_eq!(allocated_port(text), Some(6379));

        // 0.0.0.0 and IPv6 spellings of the same failure.
        assert_eq!(
            allocated_port("Bind for 0.0.0.0:8080 failed: port is already allocated"),
            Some(8080)
        );
        assert_eq!(
            allocated_port("Bind for [::]:8080 failed: port is already allocated"),
            Some(8080)
        );
    }

    /// A different bind failure is not a conflict, and rewriting it as one
    /// would send an operator looking for a container holding a port that
    /// nothing is holding.
    #[test]
    fn another_bind_failure_is_not_read_as_a_port_conflict() {
        assert_eq!(
            allocated_port("Bind for 0.0.0.0:80 failed: permission denied"),
            None
        );
        assert_eq!(allocated_port("no such image: nginx:nope"), None);
        assert_eq!(allocated_port(""), None);
    }

    // -----------------------------------------------------------------------
    // What the operator is told when a run does not start
    // -----------------------------------------------------------------------

    /// The defect, in one assertion: the port, the holder, and the fact that
    /// the name is free to try again.
    #[test]
    fn a_port_clash_names_the_port_the_holder_and_the_swept_container() {
        let err = run_failure(
            "driver failed programming external connectivity on endpoint unihelm-redis-7 \
             (9f2c): Bind for 127.0.0.1:6379 failed: port is already allocated",
            "unihelm-redis-7",
            Some("unihelm-valkey-8"),
            Swept::Removed,
        );
        assert_eq!(err.code, ErrorCode::Conflict);
        assert!(err.detail.contains("6379"), "{}", err.detail);
        assert!(err.detail.contains("unihelm-valkey-8"), "{}", err.detail);
        assert!(
            err.detail.contains("free to try again"),
            "the operator has to be told the name is reusable: {}",
            err.detail
        );
        // None of Docker's endpoint-id noise survives into the sentence.
        assert!(!err.detail.contains("9f2c"), "{}", err.detail);
    }

    /// Nothing in Docker holding the port means something outside Docker is,
    /// and saying that beats naming a container that is not the one.
    #[test]
    fn an_unknown_holder_is_said_to_be_unknown_rather_than_guessed_at() {
        let err = run_failure(
            "Bind for 127.0.0.1:6379 failed: port is already allocated",
            "web",
            None,
            Swept::Nothing,
        );
        assert_eq!(err.code, ErrorCode::Conflict);
        assert!(
            err.detail
                .contains("something on this server is already listening"),
            "{}",
            err.detail
        );
        // Nothing was left behind, so nothing is said about a cleanup — a
        // sentence about tidying up something that was never made reads as a
        // second failure.
        assert!(!err.detail.contains("removed"), "{}", err.detail);
    }

    /// A container that could not be swept is the one case where the operator
    /// has to do something by hand, so the command is in the message.
    #[test]
    fn a_container_that_could_not_be_swept_is_reported_with_the_command_to_clear_it() {
        let err = run_failure(
            "Bind for 127.0.0.1:6379 failed: port is already allocated",
            "web",
            None,
            Swept::Left("permission denied".into()),
        );
        assert!(err.detail.contains("docker rm web"), "{}", err.detail);
        assert!(err.detail.contains("permission denied"), "{}", err.detail);
    }

    /// Every other failure keeps Docker's own words. They are already written
    /// for the person reading them, and a paraphrase would be a second, worse
    /// source of truth about a machine the panel cannot see.
    #[test]
    fn a_failure_that_is_not_a_port_keeps_dockers_own_sentence() {
        let err = run_failure(
            "Unable to find image 'nginx:nope' locally: manifest unknown",
            "web",
            None,
            Swept::Removed,
        );
        assert_eq!(err.code, ErrorCode::CommandFailed);
        assert!(err.detail.contains("manifest unknown"), "{}", err.detail);
    }

    // -----------------------------------------------------------------------
    // Lists a person reads
    // -----------------------------------------------------------------------

    #[test]
    fn a_list_of_containers_reads_as_a_sentence() {
        let names = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(quoted_list(&names(&["web"])), "`web`");
        assert_eq!(quoted_list(&names(&["web", "db"])), "`web` and `db`");
        assert_eq!(
            quoted_list(&names(&["web", "db", "cache"])),
            "`web`, `db` and `cache`"
        );
        assert_eq!(quoted_list(&[]), "");
    }

    // -----------------------------------------------------------------------
    // The volume record
    // -----------------------------------------------------------------------

    /// The distinction the widened record exists for: "no container uses this"
    /// is a licence to delete and "the panel could not tell" is not. Collapsing
    /// the second into an empty list is how somebody deletes a database.
    #[test]
    fn a_volume_whose_users_could_not_be_read_is_not_reported_as_unused() {
        let unknown = Volume {
            name: "app_data".into(),
            driver: "local".into(),
            size: None,
            used_by: None,
            engine: None,
        };
        let orphan = Volume {
            used_by: Some(Vec::new()),
            ..unknown.clone()
        };
        assert_ne!(
            unknown.used_by, orphan.used_by,
            "an unread answer and an empty one must not serialise the same"
        );

        let json = serde_json::to_value(&unknown).expect("a volume serialises");
        assert!(json["used_by"].is_null());
        assert!(json["size"].is_null());
        assert!(serde_json::to_value(&orphan).expect("a volume serialises")["used_by"].is_array());
    }
}
