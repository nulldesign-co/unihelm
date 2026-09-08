//! Running a catalogue entry as a container instead of as host packages.
//!
//! The agreed shape is in `docs/design/containerised-runtimes.md`: installing a
//! tool gives you a container; installing a second version gives you a second
//! container; everything that names a version points at that one container.
//! Not a container per site. This module is the first step of that — databases
//! and caches, which are self-contained: no uid mapping and no shared socket
//! directory, both of which are what makes the PHP-FPM step able to break a
//! running server and why it comes last.
//!
//! What it buys, immediately: installing MariaDB 11.4 beside 11.8 stops being
//! the transaction apt resolves by *removing* one of them, and installing an
//! engine stops being able to disturb the one already serving. A version is an
//! image; there is no shared `/var/lib/mysql` and no shared `/etc/my.cnf` for
//! two of them to disagree over.
//!
//! ## Why this builds its own `docker run` and does not call `docker.create`
//!
//! [`crate::docker`] refuses to grow a general "create a container" surface for
//! a good reason: a form that accepts arbitrary run arguments is a root shell
//! with a nicer font. Nothing here weakens that. **Every byte of every argv
//! below is derived from a catalogue lookup** — the image from [`RECIPES`], the
//! tag from the version the operator picked off a fixed list, the ports and the
//! mount from this file. A caller supplies a slug and a version and nothing
//! else, so there is no flag to smuggle. `docker.create` takes an image and a
//! name from whoever is asking; an engine's identity, port and data directory
//! are the panel's own and are not an operator's to type.
//!
//! ## The four things that had to be right
//!
//! 1. **A port can only be published once.** 11.8 and 11.4 both want 3306, so
//!    the second is *allocated* the next free port rather than refused, and the
//!    number is recorded — see [`choose_host_port`].
//! 2. **The data volume outlives the container.** One named volume per (tool,
//!    version); `docker rm` never carries `-v`, and the volume is deleted only
//!    when a caller passes `delete_data`.
//! 3. **"Started" is not "accepting connections."** [`wait_until_ready`] does
//!    against a container what `stack::wait_until_ready` does against a unit,
//!    with a longer budget because a first boot also initialises an empty data
//!    directory.
//! 4. **The root credential** is generated per container from a CSPRNG, sealed
//!    with the panel's master key exactly like the SMTP relay password, reaches
//!    the image through the child process's *environment* rather than an argv,
//!    and is never written to a log line.
//! 5. **A cache is a database too.** Redis, Valkey and Memcached shipped with
//!    no authentication at all on the strength of being published on loopback
//!    — but "localhost only" is not a boundary on a shared host, where every
//!    tenant's PHP process and every tenant shell is on that same host. Any
//!    customer could run `KEYS *` over every other customer's sessions and
//!    `FLUSHALL` the lot. Redis and Valkey now get a generated password like
//!    the SQL engines, handed over the one way that does not cross the boundary
//!    being drawn — see [`Credential`]. Memcached still has none, honestly and
//!    on the record: see its recipe.
//!
//! **None of that reaches a container that is already running.** A cache
//! installed before this was written has no password and no configuration file,
//! and nothing here can retrofit one: the server reads its configuration at
//! start. It keeps answering every local account until it is installed again,
//! which replaces the container. `engine.status` says so per container rather
//! than leaving the operator to assume the fix was retroactive.

use std::collections::BTreeMap;
use std::time::Duration;

use async_trait::async_trait;
use rand::Rng;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use unihelm_core::{ErrorCode, Permission, Result, UnihelmError};
use unihelm_db::{ComponentStatus, Db, MasterKey};

use crate::catalogue;
use crate::docker::{ContainerRef, ImageRef, List as DockerList, ListInput};
use crate::registry::{Execution, OpContext, TypedOperation};
use crate::stack::StackComponent;

/// Docker's own client, not the daemon socket — the same choice, for the same
/// reason, as [`crate::docker`].
const DOCKER: &str = "docker";

/// Every port is published **here and nowhere else**.
///
/// This is not caution, it is the only correct answer on a machine with a
/// firewall. `docker run -p 3306:3306` inserts its DNAT rule ahead of the
/// `INPUT` chain, so a published port answers the internet whatever ufw or
/// firewalld has been told — an operator who firewalled 3306 would have a
/// world-reachable database and a panel page telling them the port is closed.
/// Nothing needs the wider binding yet: `db.create` connects from this host,
/// and step 2's application containers will reach an engine over a Docker
/// network rather than through a published port.
const LOOPBACK: &str = "127.0.0.1";

/// How many ports past its default one protocol family may use.
///
/// Ten is two more than the catalogue offers versions of anything, so a run of
/// alternates can never be the reason an install fails, and it is small enough
/// that the panel cannot wander into a range somebody else's service lives in.
const PORT_SPARE: u16 = 9;

/// Where the engine registry lives.
///
/// One JSON document in `settings`, rather than a table, because this step owns
/// no migration. It is read-modify-written, so two installs of *different*
/// engines starting in the same instant could lose one record; installs of the
/// same engine cannot, because `claim_component` serialises them. A
/// `runtime_engines` table keyed on (slug, version) is the right home and is
/// noted for the migration that follows.
pub const ENGINES_SETTING: &str = "engines.containers";

// ---------------------------------------------------------------------------
// What each engine is, as a container
// ---------------------------------------------------------------------------

/// How a live server is asked whether it is actually answering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Probe {
    /// A client that ships inside the image, run with `docker exec`.
    ///
    /// No credential is passed to any of these. `mysqladmin ping` exits 0 even
    /// when the account is refused, because a refusal *is* the server
    /// answering — which is exactly the signal wanted here, and it keeps the
    /// root password out of one more argv.
    Exec {
        argv: &'static [&'static str],
        /// Text a healthy answer contains, where the exit status alone is not
        /// enough. `redis-cli` exits 0 having printed an error.
        expect: Option<&'static str>,
    },
    /// A client that has to log in first, told to do so on its **stdin**.
    ///
    /// A probe that cannot authenticate against a server that now requires a
    /// password is worse than no probe: `redis-cli ping` answers `NOAUTH` and
    /// exits 0, so the install would either hang for the full budget or — if
    /// the refusal were accepted as an answer — report a healthy cache the
    /// panel cannot actually talk to. Authenticating also proves the sealed
    /// password is the one the server was started with, which is the only thing
    /// that makes the record worth keeping.
    ///
    /// Stdin rather than `-a <password>` or `REDISCLI_AUTH`, for the same
    /// reason the credential does not reach the server that way either: the
    /// `docker exec` runs on the host, so its argv and its environment are in
    /// `/proc` for every local account to read — the very boundary the password
    /// exists to draw. `redis-cli` runs whatever lines it reads from a pipe,
    /// which is exactly how `db.rs` gets SQL to `mariadb`.
    ExecAuthenticated {
        argv: &'static [&'static str],
        expect: &'static str,
    },
    /// A line spoken to the published port, for an image that ships no client.
    Wire {
        send: &'static str,
        expect: &'static str,
    },
}

/// How the administrative credential reaches a server when its container starts.
///
/// An enum rather than the optional variable name this used to be, because that
/// `None` meant two different things at once — "this image has no notion of a
/// password" and "nobody has wired one up here yet" — and Redis, Valkey and
/// Memcached were all running with no authentication at all on the strength of
/// the ambiguity. Every engine now has to say which of the three it is, and a
/// new one cannot be added without answering the question.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Credential {
    /// The image reads it **once**, from this variable, while it initialises an
    /// empty data directory, and never looks at it again. `--env NAME` with no
    /// value keeps it off the argv; see [`run_argv`].
    Env { variable: &'static str },
    /// The server reads it out of a configuration file at every start. The
    /// panel renders that file, keeps it in a directory no unprivileged account
    /// can traverse ([`unihelm_config::paths::engine_config_dir`]), and
    /// bind-mounts it read-only at `mount`.
    ///
    /// Not an environment variable and not an argv, both of which are readable
    /// from `/proc` by any local account — which is the boundary in question,
    /// since on a shared host every tenant *is* a local account.
    ConfigFile { mount: &'static str },
    /// This image has no authentication the panel can configure, and saying so
    /// out loud is the only honest option. Only Memcached: see its recipe.
    Unauthenticated,
}

/// Where a cache container reads its configuration.
///
/// Its own name under `/etc`, so it cannot collide with a file the base image
/// ships now or grows later — and one level deep, so Docker creates no
/// directory in the container to place it.
const CACHE_CONFIG_MOUNT: &str = "/etc/unihelm-cache.conf";

/// The template rendered into [`CACHE_CONFIG_MOUNT`]'s host-side file. One for
/// Redis and Valkey both: Valkey is a fork of Redis down to its configuration
/// grammar.
const CACHE_CONFIG_TEMPLATE: &str = "engine/redis.conf";

/// Everything this panel knows about running one catalogue entry as a container.
#[derive(Debug, Clone, Copy)]
struct Recipe {
    /// Docker Hub's name for the official image, which is not always the
    /// catalogue's slug: the entry is `mongodb`, the image is `mongo`.
    repository: &'static str,
    /// The tag for a catalogue version that is not a number.
    ///
    /// `redis` and three others are catalogued as `distro`, because on the host
    /// they are whatever the release maintains. A container has no distribution
    /// to inherit from, so the pin lives here — and it is a pin, not a
    /// `latest`: an image tag that moves under a running server is how a
    /// restart becomes a major-version upgrade nobody asked for.
    unversioned_tag: &'static str,
    /// The port the server listens on inside the container.
    container_port: u16,
    /// The host port the first container of this protocol family publishes on.
    ///
    /// Shared by design: MariaDB and MySQL both speak 3306, Redis and Valkey
    /// both speak 6379, so they allocate out of one range and can never be
    /// handed the same number.
    default_host_port: u16,
    /// Where the image keeps its data, or `None` for a server that has none.
    /// Memcached is `None`, and that is not an omission: it is a cache with no
    /// disk, so promising it a volume would be promising durability it does not
    /// have.
    data_dir: Option<&'static str>,
    /// How this server is told its password, and whether it has one at all.
    credential: Credential,
    /// The account that password belongs to, as `db.create` must connect as.
    root_user: Option<&'static str>,
    /// The SQL client that ships **inside this image**, which is the one
    /// `db.rs` runs with `docker exec`.
    ///
    /// Named per recipe rather than derived from the slug, because the images
    /// disagree: MariaDB renamed every binary in 10.5 and keeps `mysql` only as
    /// a deprecated symlink, MySQL's image has never carried `mariadb`, and
    /// PostgreSQL's is `psql` either way. Guessing gets a missing binary on a
    /// server that is perfectly healthy.
    ///
    /// `None` where there is no client for `db.rs` to drive: a cache
    /// authenticates a connection rather than a login, and MongoDB is not an
    /// engine `db.create` manages.
    sql_client: Option<&'static str>,
    /// Environment every container of this kind needs, none of it secret.
    env: &'static [(&'static str, &'static str)],
    /// The command, where the image's own default would not persist anything.
    command: &'static [&'static str],
    probe: Probe,
}

/// The engines this step runs as containers, by catalogue slug.
///
/// Databases and caches only. Applications and PHP-FPM are deliberately absent:
/// they need uid mapping and a shared socket directory, and those are built on
/// a path this step has already exercised.
const RECIPES: &[(&str, Recipe)] = &[
    (
        "mariadb",
        Recipe {
            repository: "mariadb",
            unversioned_tag: "11.8",
            container_port: 3306,
            default_host_port: 3306,
            data_dir: Some("/var/lib/mysql"),
            credential: Credential::Env {
                variable: "MARIADB_ROOT_PASSWORD",
            },
            root_user: Some("root"),
            sql_client: Some("mariadb"),
            env: &[],
            command: &[],
            probe: Probe::Exec {
                // `--protocol=tcp` against the container's own loopback, not the
                // socket: on a first boot the entrypoint runs a temporary server
                // with networking disabled to initialise the data directory, and
                // a socket probe would call that ready.
                argv: &[
                    "mariadb-admin",
                    "--no-defaults",
                    "--protocol=tcp",
                    "--host=127.0.0.1",
                    "--connect-timeout=3",
                    "ping",
                ],
                expect: None,
            },
        },
    ),
    (
        "mysql",
        Recipe {
            repository: "mysql",
            // The catalogue offers MySQL as `distro`, which on Ubuntu is 8.0.
            // Keeping the container on the same series means an operator who
            // moves from the host model to this one is not also moving major
            // version.
            unversioned_tag: "8.0",
            container_port: 3306,
            default_host_port: 3306,
            data_dir: Some("/var/lib/mysql"),
            credential: Credential::Env {
                variable: "MYSQL_ROOT_PASSWORD",
            },
            root_user: Some("root"),
            sql_client: Some("mysql"),
            env: &[],
            command: &[],
            probe: Probe::Exec {
                argv: &[
                    "mysqladmin",
                    "--no-defaults",
                    "--protocol=tcp",
                    "--host=127.0.0.1",
                    "--connect-timeout=3",
                    "ping",
                ],
                expect: None,
            },
        },
    ),
    (
        "postgres",
        Recipe {
            repository: "postgres",
            unversioned_tag: "17",
            container_port: 5432,
            default_host_port: 5432,
            data_dir: Some("/var/lib/postgresql/data"),
            credential: Credential::Env {
                variable: "POSTGRES_PASSWORD",
            },
            root_user: Some("postgres"),
            sql_client: Some("psql"),
            env: &[],
            command: &[],
            probe: Probe::Exec {
                argv: &["pg_isready", "--quiet", "--host=127.0.0.1"],
                expect: None,
            },
        },
    ),
    (
        "mongodb",
        Recipe {
            repository: "mongo",
            unversioned_tag: "8.0",
            container_port: 27017,
            default_host_port: 27017,
            data_dir: Some("/data/db"),
            credential: Credential::Env {
                variable: "MONGO_INITDB_ROOT_PASSWORD",
            },
            root_user: Some("root"),
            sql_client: None,
            // The image creates the administrative user only when *both* halves
            // are present; a password with no username is silently ignored and
            // the server comes up with no authentication at all.
            env: &[("MONGO_INITDB_ROOT_USERNAME", "root")],
            command: &[],
            probe: Probe::Exec {
                argv: &["mongosh", "--quiet", "--eval", "db.adminCommand({ping:1})"],
                expect: Some("ok"),
            },
        },
    ),
    (
        "redis",
        Recipe {
            repository: "redis",
            unversioned_tag: "7",
            container_port: 6379,
            default_host_port: 6379,
            data_dir: Some("/data"),
            // This used to be `None`, on the reasoning that Redis has no root
            // account and is published on loopback only. Loopback is not a
            // boundary on a shared host: every tenant's PHP process and every
            // tenant shell runs on it, so "no password" meant any customer
            // could read every other customer's sessions with `KEYS *` and
            // delete the lot with `FLUSHALL`. Redis has no user, but it does
            // have `requirepass`, and that is what this generates.
            credential: Credential::ConfigFile {
                mount: CACHE_CONFIG_MOUNT,
            },
            // Still none: `requirepass` authenticates a connection, it does not
            // create an account. Nothing here is a login `db.create` could use,
            // which is why this stays `None` while the password is real.
            root_user: None,
            sql_client: None,
            env: &[],
            // The image's own command persists nothing, so a volume at /data
            // would stay empty and "your data survives a restart" would be a
            // lie. Passing a command replaces the image's CMD entirely, which is
            // why the server is named again here. `--appendonly yes` used to
            // ride along; it moved into the configuration file the password
            // needs, whose path [`run_argv`] appends after this.
            command: &["redis-server"],
            probe: Probe::ExecAuthenticated {
                argv: &["redis-cli"],
                expect: "PONG",
            },
        },
    ),
    (
        "valkey",
        Recipe {
            repository: "valkey/valkey",
            unversioned_tag: "8",
            container_port: 6379,
            default_host_port: 6379,
            data_dir: Some("/data"),
            // A fork of Redis down to `requirepass` and the configuration file
            // grammar, so it is protected the same way and out of the same
            // template.
            credential: Credential::ConfigFile {
                mount: CACHE_CONFIG_MOUNT,
            },
            root_user: None,
            sql_client: None,
            env: &[],
            command: &["valkey-server"],
            probe: Probe::ExecAuthenticated {
                argv: &["valkey-cli"],
                expect: "PONG",
            },
        },
    ),
    (
        "memcached",
        Recipe {
            repository: "memcached",
            unversioned_tag: "1.6",
            container_port: 11211,
            default_host_port: 11211,
            data_dir: None,
            // **This one really has no authentication, and the panel will not
            // pretend otherwise.** Memcached has no password: its only
            // authentication is SASL, which needs a binary built with
            // `--enable-sasl` and a `sasldb` of accounts to go with it, and the
            // official image is not built that way. There is nothing to
            // generate and nothing to seal, so nothing is — rather than
            // inventing a credential the server would ignore, which would leave
            // the panel holding a secret that protects nothing and an operator
            // believing their cache is closed.
            //
            // What that costs, said plainly: anything that can reach
            // 127.0.0.1:11211 — every tenant shell and every tenant's PHP — can
            // read and delete every key in this cache. It is only safe on a
            // machine whose local accounts are all trusted, which a shared host
            // is not.
            credential: Credential::Unauthenticated,
            root_user: None,
            sql_client: None,
            env: &[],
            command: &[],
            // The image ships no client at all, so readiness is asked over the
            // published port in memcached's own text protocol. `version` is the
            // one command that needs no key and no storage.
            probe: Probe::Wire {
                send: "version\r\n",
                expect: "VERSION",
            },
        },
    ),
];

fn recipe(slug: &str) -> Option<&'static Recipe> {
    RECIPES.iter().find(|(s, _)| *s == slug).map(|(_, r)| r)
}

/// Whether the panel can run this catalogue entry as a container yet.
pub fn is_containerisable(slug: &str) -> bool {
    recipe(slug).is_some()
}

// ---------------------------------------------------------------------------
// Identity: the image, the container, the volume
// ---------------------------------------------------------------------------

/// The tag for a catalogue version.
///
/// A version with a digit in it is one the operator chose off the page and is
/// the tag verbatim, so asking for 11.4 gets 11.4 and not "whatever 11 means
/// today". The same test [`catalogue`] already applies to decide whether a
/// version belongs in a sentence decides it here, and for the same reason:
/// `distro` and `stable` are not versions anybody picked.
fn tag_for(version: &catalogue::Version, recipe: &Recipe) -> &'static str {
    if version.version.bytes().any(|b| b.is_ascii_digit()) {
        version.version
    } else {
        recipe.unversioned_tag
    }
}

/// One (tool, version) resolved into everything needed to run it.
///
/// Built only from a [`StackComponent`], which can only be built from a
/// catalogue lookup — so a plan is the proof that both the slug and the version
/// were in the table.
#[derive(Debug, Clone)]
pub struct EnginePlan {
    component: StackComponent,
    recipe: &'static Recipe,
    image: ImageRef,
    container: ContainerRef,
    /// `None` for a server with nothing to keep.
    volume: Option<String>,
}

impl EnginePlan {
    pub fn for_component(component: StackComponent) -> Result<Self> {
        let slug = component.entry().slug;
        let recipe = recipe(slug).ok_or_else(|| {
            UnihelmError::new(
                ErrorCode::InvalidInput,
                format!(
                    "the panel does not run {} in a container. It runs: {}.",
                    component.entry().display_name,
                    RECIPES
                        .iter()
                        .map(|(s, _)| *s)
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            )
            .with_field("component")
        })?;

        let tag = tag_for(component.version(), recipe);
        // The name **is** the identity: two sites naming 11.8 resolve to this
        // one string, and it is derived rather than stored so that resolving it
        // twice can never produce two containers. The tag, not the catalogue's
        // version, so `unihelm-redis-7` names what is actually running instead
        // of `unihelm-redis-distro`, which names nothing.
        let container = ContainerRef::parse(&format!("unihelm-{slug}-{tag}"))?;
        let image = ImageRef::parse(&format!("{}:{tag}", recipe.repository))?;
        let volume = recipe
            .data_dir
            .map(|_| format!("{}-data", container.as_str()));

        Ok(Self {
            component,
            recipe,
            image,
            container,
            volume,
        })
    }

    pub fn resolve(slug: &str, version: Option<&str>) -> Result<Self> {
        Self::for_component(StackComponent::resolve(slug, version)?)
    }

    pub fn container(&self) -> &ContainerRef {
        &self.container
    }

    pub fn image(&self) -> &ImageRef {
        &self.image
    }

    pub fn volume(&self) -> Option<&str> {
        self.volume.as_deref()
    }

    /// The host-side file this engine's configuration is written to, named for
    /// the container so two versions of one cache cannot share a password.
    ///
    /// Derived rather than stored, exactly like the container name: install and
    /// remove have to agree on it without consulting anything.
    fn config_file(&self) -> std::path::PathBuf {
        unihelm_config::paths::engine_config_file(self.container.as_str())
    }

    pub fn display_name(&self) -> String {
        self.component.display_name()
    }

    /// The `stack_components` row this engine claims and reports itself in.
    ///
    /// The **container name**, and deliberately not [`StackComponent::slug`].
    /// That key belongs to the host install: `mariadb` is one row because on
    /// the host there is one MariaDB — one port, one `/var/lib/mysql`, one
    /// `/etc`. Containers are the opposite, which is the entire point of this
    /// module, so sharing that key would mean installing 11.4 claims the row
    /// 11.8 is reported in: `claim_component` would refuse to run the two
    /// installs at once, a failed install of 11.4 would put a `failed` mark on
    /// a machine whose 11.8 is serving perfectly, and a container install would
    /// mark the *host* MariaDB installed.
    ///
    /// Nothing is lost by not being a catalogue key: `stack::status` builds a
    /// row per container out of the engine registry and reports it beside the
    /// host rows, so a row named for a container is simply not one of them. It
    /// is derived, so any caller holding the same (slug, version) computes the
    /// same key — which is what makes [`crate::stack::row_key`] able to hand
    /// install, status and removal one string instead of three.
    pub fn row_key(&self) -> &str {
        self.container.as_str()
    }

    /// The row the **host** install of this same engine holds, which is what
    /// [`refuse_when_the_host_already_runs_this_engine`] has to ask about.
    fn host_row_key(&self) -> String {
        self.component.slug()
    }
}

// ---------------------------------------------------------------------------
// The registry: what is installed, on which port, under which credential
// ---------------------------------------------------------------------------

/// One installed engine, as the panel remembers it.
///
/// This is the record `db.create` reads to find out where the engine it must
/// connect to actually is. It is never an operation's output: it carries the
/// sealed credential, and the API surface has no business shipping that around.
#[derive(Clone, Serialize, Deserialize)]
pub struct EngineRecord {
    /// The catalogue slug: `mariadb`.
    pub slug: String,
    /// The catalogue version the operator asked for: `11.8`, or `distro`.
    pub version: String,
    /// `mariadb:11.8`.
    pub image: String,
    /// `unihelm-mariadb-11.8`, which is the identity.
    pub container: String,
    /// The named volume, absent for a server with no data.
    #[serde(default)]
    pub volume: Option<String>,
    /// **The port `db.create` must connect to**, on [`LOOPBACK`]. Not always the
    /// engine's default one — see [`choose_host_port`].
    pub host_port: u16,
    pub container_port: u16,
    /// The administrative account, absent for the caches — `requirepass`
    /// authenticates a connection without naming anybody, so there is no login
    /// for `db.create` to use even where the password is real.
    #[serde(default)]
    pub root_user: Option<String>,
    /// Sealed with the panel's master key, exactly as the SMTP relay password
    /// is. Opened with [`EngineRecord::open_root_password`] and never logged.
    ///
    /// `None` on two kinds of record, and telling them apart matters to an
    /// operator: an engine the panel cannot authenticate at all (Memcached),
    /// and a cache installed before it gave caches passwords, which keeps
    /// running unauthenticated until the container is replaced. See
    /// [`authentication_note`], which is what `engine.status` says about each.
    ///
    /// **Nothing shows this to an operator yet**, and for a SQL engine nothing
    /// needs to: `db.create` uses it on their behalf and hands out per-tenant
    /// credentials. A cache has no such flow — the password *is* what an
    /// application connects with — so until the panel grows a place to reveal
    /// it, the install logs the root-only file it can be read out of.
    #[serde(default)]
    pub root_password_sealed: Option<String>,
}

impl EngineRecord {
    /// The root password, in clear, for the one caller that needs it.
    pub fn open_root_password(&self, key: &MasterKey) -> Result<Option<String>> {
        match &self.root_password_sealed {
            None => Ok(None),
            Some(sealed) => key.open_str(sealed).map(Some).map_err(UnihelmError::from),
        }
    }
}

/// Redacted by hand, for the reason [`unihelm_db::MasterKey`] is: the way a
/// credential reaches a log is somebody adding `?record` to a tracing call.
impl std::fmt::Debug for EngineRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EngineRecord")
            .field("container", &self.container)
            .field("image", &self.image)
            .field("host_port", &self.host_port)
            .field("root_user", &self.root_user)
            .field("root_password_sealed", &"<redacted>")
            .finish()
    }
}

/// Every containerised engine on this server, keyed by container name.
pub type EngineRegistry = BTreeMap<String, EngineRecord>;

/// Read the registry.
///
/// A document that will not parse is an **error**, never an empty registry:
/// defaulting here and then writing a fresh map over it would destroy every
/// root credential on the machine, and with it access to every database.
pub async fn registry(db: &Db) -> Result<EngineRegistry> {
    match db.get_setting::<EngineRegistry>(ENGINES_SETTING).await {
        Ok(Some(found)) => Ok(found),
        Ok(None) => Ok(EngineRegistry::new()),
        Err(e) => Err(UnihelmError::internal(format!(
            "the containerised-engine registry could not be read ({e}). The root \
             credentials for every engine container are in it, so the panel will not \
             overwrite it — restore `{ENGINES_SETTING}` from a panel backup."
        ))),
    }
}

async fn save_registry(db: &Db, registry: &EngineRegistry) -> Result<()> {
    db.set_setting(ENGINES_SETTING, registry)
        .await
        .map_err(UnihelmError::from)
}

/// Add or replace one record, against whatever the registry holds **now**.
///
/// The registry is read again here rather than the caller's copy being written
/// back, and the gap is why: an install reads it, then pulls an image, which is
/// minutes on a slow link. Writing that stale map back would erase any record
/// another install wrote in the meantime — and a record is the only key to the
/// data in that engine's volume, so the loss is somebody's database rather than
/// a line of bookkeeping. It narrows the window to this function; closing it
/// entirely wants a `runtime_engines` table, which is noted on
/// [`ENGINES_SETTING`] for the migration that follows.
async fn record_engine(db: &Db, record: EngineRecord) -> Result<()> {
    let mut registry = registry(db).await?;
    registry.insert(record.container.clone(), record);
    save_registry(db, &registry).await
}

/// Drop one record, against whatever the registry holds now, for
/// [`record_engine`]'s reason read the other way round: a removal must not put
/// back a record another install wrote while this one was stopping a container.
async fn forget_engine(db: &Db, container: &str) -> Result<()> {
    let mut registry = registry(db).await?;
    registry.remove(container);
    save_registry(db, &registry).await
}

/// What `db.create` needs in order to reach an engine: which container it is
/// in, where it listens inside that container, and who to be when it gets
/// there.
#[derive(Clone, PartialEq, Eq)]
pub struct RootConnection {
    /// The container the client is run inside, with `docker exec`.
    ///
    /// Inside, and not over the published port, because on a default install
    /// there is no client on the host to run: the whole point of the container
    /// is that this server has no MariaDB packages, and `mariadb` is one of
    /// them. The client that ships in the image is the one that exists.
    pub container: String,
    /// The client binary in that image: `mariadb`, `mysql`, `psql`.
    pub client: &'static str,
    /// Loopback **inside** the container, where the server binds.
    pub host: &'static str,
    /// The port the server binds inside the container — not
    /// [`EngineRecord::host_port`]. A client running inside never crosses the
    /// publish boundary, and the two numbers differ the moment a second
    /// version of one engine is installed.
    pub port: u16,
    /// Where this same server answers on this machine. Carried so a refusal or
    /// a log line can name the address an operator would connect to by hand.
    pub host_port: u16,
    pub user: String,
    pub password: String,
}

impl std::fmt::Debug for RootConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RootConnection")
            .field("container", &self.container)
            .field("client", &self.client)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("host_port", &self.host_port)
            .field("user", &self.user)
            .field("password", &"<redacted>")
            .finish()
    }
}

impl RootConnection {
    /// Wrap a client invocation in the `docker exec` that runs it inside this
    /// engine's container.
    ///
    /// `-i` is load bearing: `db.rs` puts every statement on the client's
    /// stdin, and without it Docker hands the child `/dev/null` — the client
    /// reads EOF, executes nothing, exits zero, and the panel reports a
    /// database it never created. [`exec_argv`] carries the same note for the
    /// readiness probes.
    ///
    /// `env_names` go on as `--env NAME` with no `=value`, which is Docker's
    /// own form for "take this one from my environment". The value is set on
    /// the `docker` child by [`unihelm_distro::Cmd::env`] and appears nowhere
    /// else: written `--env NAME=secret` the root password would sit in
    /// `/proc/<pid>/cmdline` for the length of the run, readable by every local
    /// account on the machine — which is the boundary the sealed credential
    /// exists to hold. This function is not given the password at all, so there
    /// is no way to get that wrong from here.
    ///
    /// `docker` is named bare and left for [`unihelm_distro::Cmd`] to resolve
    /// against the trusted directories, as every other program in this codebase
    /// is. Resolving it here would only move the same failure earlier: a
    /// registry record exists because [`install_container`] built the container,
    /// which needs Docker — so a machine holding one and no `docker` is one
    /// somebody removed it from, and `stack::status` reports those engines as
    /// unknown rather than as running.
    pub fn exec_argv(&self, env_names: &[&str], client: Vec<String>) -> Vec<String> {
        let mut argv = vec![DOCKER.to_string(), "exec".to_string(), "-i".to_string()];
        for name in env_names {
            argv.push("--env".to_string());
            argv.push((*name).to_string());
        }
        argv.push(self.container.clone());
        argv.extend(client);
        argv
    }
}

/// How to reach the containerised engine behind a set of catalogue slugs, or
/// `None` when there is none and the caller should use the host's socket.
///
/// The entry point `db.rs` calls, and until this release it had no callers at
/// all — the containers were built, health-checked and sealed, and every
/// database operation went on talking to a host socket that a default install
/// does not have.
///
/// Several slugs rather than one, because `db.create` names a **protocol** and
/// not a product: MariaDB and MySQL are one `DbEngine` and one wire format, and
/// an operator who installed either expects `db.create` to find it. Where more
/// than one container answers — two versions of MariaDB, or a MariaDB beside a
/// MySQL — the lowest host port wins: that is the container holding the
/// family's own default port, which is the one an operator who typed `mysql` on
/// this server, or an application whose connection string predates the second
/// install, would have reached. The alternative — newest wins — would move
/// every unversioned caller onto a fresh, empty engine the moment a second one
/// was installed.
pub async fn root_connection(
    db: &Db,
    key: &MasterKey,
    slugs: &[&str],
) -> Result<Option<RootConnection>> {
    let registry = registry(db).await?;
    let Some(record) = primary_record(&registry, slugs) else {
        return Ok(None);
    };

    let client = recipe(&record.slug).and_then(|r| r.sql_client);
    // A refusal, never a fall through to the host socket. There is no host
    // install behind a container record, so "use the socket instead" would send
    // the caller at a socket that has never existed and hand them the client's
    // own "can't connect" — an error about a file, for a server that is up.
    let (Some(user), Some(password), Some(client)) = (
        record.root_user.clone(),
        record.open_root_password(key)?,
        client,
    ) else {
        return Err(UnihelmError::new(
            ErrorCode::ServiceUnavailable,
            format!(
                "{} runs in the container `{}`, and the panel cannot administer it: it holds \
                 no root login for that container. Install {} again from the Stack Manager to \
                 replace it with one the panel has the credential for.",
                record.slug, record.container, record.slug
            ),
        ));
    };

    Ok(Some(RootConnection {
        container: record.container.clone(),
        client,
        host: LOOPBACK,
        port: record.container_port,
        host_port: record.host_port,
        user,
        password,
    }))
}

/// Which of several installed engines a caller that named only a protocol
/// means: the one on the lowest host port. See [`root_connection`].
fn primary_record<'a>(registry: &'a EngineRegistry, slugs: &[&str]) -> Option<&'a EngineRecord> {
    registry
        .values()
        .filter(|r| slugs.contains(&r.slug.as_str()))
        .min_by_key(|r| r.host_port)
}

// ---------------------------------------------------------------------------
// The port
// ---------------------------------------------------------------------------

/// Pick the host port this container publishes on.
///
/// **Allocate, do not refuse.** Refusing the second version would put back the
/// thing this whole change exists to remove: an operator migrating an old
/// application installs 11.4 beside 11.8, and being told "3306 is taken" leaves
/// them doing it by hand on a production box. So the first container of a
/// protocol family gets the port everybody expects, and the next gets the next
/// free number — recorded in [`EngineRecord::host_port`], which is where
/// `db.create` reads it, so nothing has to guess.
///
/// Three things can hold a candidate:
///
/// - another engine container this panel installed, running or stopped, which is
///   why the registry is consulted and not just the kernel;
/// - anything else on this machine, which `free` answers for;
/// - nothing, and it is taken.
///
/// Running out is refused with the holder named, because at that point the
/// machine has ten servers on one protocol and the operator needs to know which.
///
/// `ours` is the container being installed. Its own record does not hold a port
/// against it, and where it has one already that port is the answer.
fn choose_host_port(
    recipe: &Recipe,
    registry: &EngineRegistry,
    ours: &str,
    free: &dyn Fn(u16) -> bool,
) -> Result<u16> {
    // An engine removed with its data kept keeps its record, and the port in it
    // is not the panel's private business: it is in an application's connection
    // string, in somebody's notes, in a firewall rule. Reinstalling it must land
    // back on that number. Reading its own record as "taken" would move it one
    // along every time it was removed and put back, and every client configured
    // for the old number would fail to connect against a panel reporting the
    // engine healthy.
    if let Some(mine) = registry.get(ours).filter(|r| free(r.host_port)) {
        return Ok(mine.host_port);
    }

    let first = recipe.default_host_port;
    let last = first.saturating_add(PORT_SPARE);
    for port in first..=last {
        if let Some(holder) = registry
            .values()
            .find(|r| r.host_port == port && r.container != ours)
        {
            if port == last {
                return Err(port_exhausted(first, &holder.container));
            }
            continue;
        }
        if free(port) {
            return Ok(port);
        }
    }

    Err(port_exhausted(first, "another service on this server"))
}

fn port_exhausted(first: u16, holder: &str) -> UnihelmError {
    UnihelmError::new(
        ErrorCode::Conflict,
        format!(
            "ports {first} to {} are all in use — {holder} holds one of them, and there \
             is no free port left for this engine to publish on. Remove an engine you no \
             longer run, or free a port in that range.",
            first.saturating_add(PORT_SPARE)
        ),
    )
    .with_field("component")
}

/// Whether this host port can be published on.
///
/// A bind on [`LOOPBACK`] is the same question Docker will ask a moment later,
/// and it catches the case the registry cannot: an engine installed on the host
/// before this panel existed, still serving, still holding 3306.
fn host_port_is_free(port: u16) -> bool {
    std::net::TcpListener::bind((LOOPBACK, port)).is_ok()
}

// ---------------------------------------------------------------------------
// The argv
// ---------------------------------------------------------------------------

fn pull_argv(image: &ImageRef) -> Vec<String> {
    vec!["pull".to_string(), image.as_str().to_string()]
}

/// The full `docker run`, and the credential is **not in it**.
///
/// `--env NAME` with no `=value` is Docker's own form for "take this from my
/// environment", and the environment is set on the child process by
/// [`unihelm_distro::Cmd::env`]. Written the other way — `--env NAME=secret` —
/// the password would sit in `/proc/<pid>/cmdline` for the length of the run,
/// readable by every local user, which is precisely the leak `db.rs` puts its
/// SQL on stdin to avoid. The function does not take the password at all, so
/// there is no way to get this wrong later.
///
/// A [`Credential::ConfigFile`] engine keeps that property differently: what
/// goes on the argv is the *path* of a file only root can reach, mounted
/// read-only. Read-only because the panel writes that file and the server only
/// reads it — a cache that could rewrite its own configuration could rewrite
/// away its own password.
fn run_argv(plan: &EnginePlan, host_port: u16) -> Vec<String> {
    let mut argv = vec![
        "run".to_string(),
        "--detach".to_string(),
        "--name".to_string(),
        plan.container.as_str().to_string(),
        // The containerised form of `systemctl enable`: a database must be back
        // after a reboot. `unless-stopped` rather than `always` so that an
        // operator who deliberately stopped it still has it stopped after a
        // daemon restart.
        "--restart".to_string(),
        "unless-stopped".to_string(),
        "--publish".to_string(),
        format!("{LOOPBACK}:{host_port}:{}", plan.recipe.container_port),
    ];

    if let (Some(volume), Some(data_dir)) = (plan.volume.as_deref(), plan.recipe.data_dir) {
        argv.push("--volume".to_string());
        argv.push(format!("{volume}:{data_dir}"));
    }

    for (key, value) in plan.recipe.env {
        argv.push("--env".to_string());
        argv.push(format!("{key}={value}"));
    }

    if let Credential::ConfigFile { mount } = plan.recipe.credential {
        argv.push("--volume".to_string());
        argv.push(format!("{}:{mount}:ro", plan.config_file().display()));
    }
    if let Credential::Env { variable } = plan.recipe.credential {
        argv.push("--env".to_string());
        argv.push(variable.to_string());
    }

    argv.push(plan.image.as_str().to_string());
    argv.extend(plan.recipe.command.iter().map(|c| c.to_string()));
    // After the command, because that is where the server expects it:
    // `redis-server /path/to/redis.conf`. A configuration file named anywhere
    // else on that line is one the server ignores, and an ignored
    // configuration file here is a cache with no password.
    if let Credential::ConfigFile { mount } = plan.recipe.credential {
        argv.push(mount.to_string());
    }
    argv
}

/// Stop, with the same ten-second grace [`crate::docker`] uses. A database
/// mid-write is the reason it is a stop and not a kill.
fn stop_argv(container: &ContainerRef) -> Vec<String> {
    vec![
        "stop".to_string(),
        "-t".to_string(),
        "10".to_string(),
        container.as_str().to_string(),
    ]
}

/// Bare `rm`, and both omissions are load bearing. No `--force`, which is a
/// SIGKILL to something that may be flushing; no `--volumes`, which is how
/// removing a container becomes how somebody discovers their database is gone.
fn remove_argv(container: &ContainerRef) -> Vec<String> {
    vec!["rm".to_string(), container.as_str().to_string()]
}

/// The only thing in this file that destroys data, reachable only from an
/// explicit `delete_data`.
fn volume_remove_argv(volume: &str) -> Vec<String> {
    vec!["volume".to_string(), "rm".to_string(), volume.to_string()]
}

/// `docker exec` for a probe. `interactive` adds `-i`, which is what keeps the
/// child's stdin attached to the pipe: without it Docker hands the process
/// `/dev/null`, `redis-cli` reads EOF before it has authenticated, and the
/// probe would fail against a perfectly healthy server.
fn exec_argv(
    container: &ContainerRef,
    probe: &'static [&'static str],
    interactive: bool,
) -> Vec<String> {
    let mut argv = vec!["exec".to_string()];
    if interactive {
        argv.push("-i".to_string());
    }
    argv.push(container.as_str().to_string());
    argv.extend(probe.iter().map(|a| a.to_string()));
    argv
}

// ---------------------------------------------------------------------------
// Readiness
// ---------------------------------------------------------------------------

/// How long an engine is given to start answering: three minutes, probed on a
/// 500 ms schedule that doubles to a 5 s ceiling.
///
/// A budget rather than a count of attempts, because a count is easy to write
/// and hard to read: fifteen tries on that schedule is 57 seconds, which is
/// barely more than the 45 `stack::wait_until_ready` allows and would have made
/// the paragraph below false.
///
/// Longer than that 45 seconds on purpose. `stack` waits on a package whose
/// postinst has already initialised the data directory; a container's first boot
/// does the initialisation *itself* — InnoDB's redo logs, or `initdb` for
/// Postgres — on a volume that starts empty, and on a small VPS that is
/// comfortably past a minute. Timing out too early is not a harmless retry: the
/// install is marked failed on a machine where the engine came up fine a moment
/// later. Short enough that a genuinely broken container still fails while
/// somebody is watching.
const READY_BUDGET: Duration = Duration::from_secs(180);

/// Poll until the engine actually accepts connections.
///
/// Two gates, in this order, because they fail for different reasons and the
/// operator needs to know which:
///
/// 1. **The published port answers on the host.** This is the exact path
///    `db.create` will take, so a container that is up but whose publish did not
///    work is caught here rather than by the first tenant.
/// 2. **The server speaks its own protocol.** A TCP accept is not a handshake:
///    both database images bind the port before they finish coming up.
/// 3. **The server accepts the credential the panel holds.** For an engine
///    whose password is in a mounted file, a probe that did not log in would
///    pass against a server the panel cannot use — and against one started
///    under a different password entirely.
async fn wait_until_ready(
    ctx: &OpContext,
    plan: &EnginePlan,
    host_port: u16,
    password: Option<&str>,
) -> Result<()> {
    let deadline = tokio::time::Instant::now() + READY_BUDGET;
    let mut delay = Duration::from_millis(500);
    let mut last = String::from("nothing answered on the published port");

    for attempt in 1.. {
        match probe_once(plan, host_port, password).await {
            Ok(()) => {
                ctx.log(format!(
                    "{} is accepting connections on {LOOPBACK}:{host_port} (attempt {attempt})",
                    plan.display_name()
                ));
                return Ok(());
            }
            Err(why) => last = why,
        }
        // The sleep has to fit inside the budget, or the last attempt is
        // followed by a wait nobody is waiting for.
        if tokio::time::Instant::now() + delay >= deadline {
            break;
        }
        tokio::time::sleep(delay).await;
        delay = (delay * 2).min(Duration::from_secs(5));
    }

    Err(UnihelmError::new(
        ErrorCode::ServiceActionFailed,
        format!(
            "{} started but never became ready to accept connections: {last}. \
             `docker logs {}` says why.",
            plan.display_name(),
            plan.container.as_str()
        ),
    ))
}

/// One readiness attempt. `Err` carries why, in words worth showing.
async fn probe_once(
    plan: &EnginePlan,
    host_port: u16,
    password: Option<&str>,
) -> std::result::Result<(), String> {
    match plan.recipe.probe {
        Probe::Wire { send, expect } => wire_probe(host_port, send, expect).await,
        Probe::Exec { argv, expect } => {
            let out = exec_probe(plan, host_port, argv, false, None).await?;
            match expect {
                Some(text) if !out.contains(text) => Err(format!(
                    "the readiness check answered `{}` rather than `{text}`",
                    out.trim()
                )),
                _ => Ok(()),
            }
        }
        Probe::ExecAuthenticated { argv, expect } => {
            // No password, no probe — and no pretending. This is reachable only
            // if a `ConfigFile` engine ever reached the wait without one, which
            // would mean the server was started with a configuration file the
            // panel cannot log in with; calling that ready is exactly the lie
            // this probe exists to prevent.
            let Some(password) = password else {
                return Err(format!(
                    "the panel holds no password for {}, so it cannot check whether the \
                     server is answering; the container was started from a configuration \
                     file it cannot log in with",
                    plan.container.as_str()
                ));
            };
            // Two lines on stdin, which `redis-cli` and `valkey-cli` run in
            // order. The password is alphanumeric by construction
            // ([`generate_password`]), so nothing in it can be read as a
            // separator or a quote and change what this line means.
            let script = format!("AUTH {password}\nPING\n");
            let out = exec_probe(plan, host_port, argv, true, Some(script)).await?;
            read_authenticated_probe(&out, expect)
        }
    }
}

/// What two lines from `redis-cli` mean: the reply to `AUTH`, then the reply to
/// `PING`.
///
/// **Both, and in that order, because the ping alone is not the question.** A
/// server that came up with no password at all answers `AUTH` with "ERR Client
/// sent AUTH, but no password is set" and then answers `PING` with `PONG` quite
/// happily — so a probe that only looked for `PONG` would pass the very
/// condition this whole change exists to remove, and the install would report a
/// protected cache that any account on the machine can read. The first line has
/// to be the server accepting the credential.
fn read_authenticated_probe(out: &str, expect: &str) -> std::result::Result<(), String> {
    let mut lines = out.lines().map(str::trim).filter(|l| !l.is_empty());
    // The client's own words are worth passing on rather than paraphrasing:
    // `WRONGPASS` means the panel's sealed copy is not what the server was
    // started under, which is a different problem with a different fix. `AUTH`
    // is never echoed back, so nothing secret is in them.
    match lines.next() {
        Some("OK") => {}
        Some(refused) => {
            return Err(format!(
                "the server refused the password the panel holds for it: {refused}"
            ));
        }
        None => return Err("the client said nothing at all".to_string()),
    }
    if lines.any(|l| l.contains(expect)) {
        Ok(())
    } else {
        Err(format!(
            "the server accepted the password but did not answer `{expect}`: {}",
            out.trim()
        ))
    }
}

/// Run a client that ships inside the image and hand back what it printed.
///
/// The published port is checked first in every case: a client inside the
/// container can be perfectly happy while nothing outside can reach it, and
/// outside is where `db.create` and every tenant application connect from.
async fn exec_probe(
    plan: &EnginePlan,
    host_port: u16,
    argv: &'static [&'static str],
    interactive: bool,
    stdin: Option<String>,
) -> std::result::Result<String, String> {
    let _ = tokio::net::TcpStream::connect((LOOPBACK, host_port))
        .await
        .map_err(|e| format!("{LOOPBACK}:{host_port} is not answering ({e})"))?;

    let docker = docker_program().map_err(|e| e.detail)?;
    let mut cmd = unihelm_distro::Cmd::new(&docker)
        .args(exec_argv(&plan.container, argv, interactive))
        .timeout(Duration::from_secs(10));
    if let Some(script) = stdin {
        cmd = cmd.stdin_data(script.into_bytes());
    }
    let out = cmd.run().await.map_err(|e| e.to_string())?;

    if !out.success() {
        return Err(out.failure_text());
    }
    Ok(out.stdout)
}

/// Speak to the published port and check the reply, for an image with no client.
async fn wire_probe(port: u16, send: &str, expect: &str) -> std::result::Result<(), String> {
    let mut stream = tokio::net::TcpStream::connect((LOOPBACK, port))
        .await
        .map_err(|e| format!("{LOOPBACK}:{port} is not answering ({e})"))?;
    stream
        .write_all(send.as_bytes())
        .await
        .map_err(|e| e.to_string())?;

    let mut buf = [0u8; 128];
    let read = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut buf))
        .await
        .map_err(|_| format!("{LOOPBACK}:{port} accepted a connection but never replied"))?
        .map_err(|e| e.to_string())?;

    let reply = String::from_utf8_lossy(&buf[..read]);
    if reply.contains(expect) {
        Ok(())
    } else {
        Err(format!("the server replied `{}`", reply.trim()))
    }
}

// ---------------------------------------------------------------------------
// engine.install
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct InstallOutput {
    pub slug: String,
    pub version: String,
    pub container: String,
    pub image: String,
    pub volume: Option<String>,
    /// The port `db.create` will connect to. Shown, because it is not always the
    /// number an operator expects and every client they configure by hand needs
    /// it.
    pub host_port: u16,
    pub running: bool,
}

/// How long an image is given to arrive: fifteen minutes.
///
/// Sized on the operator's link rather than on Docker Hub. A database image is
/// a few hundred megabytes, which on the 5 Mbit uplink a cheap VPS actually has
/// is minutes and is not a failure — and a pull killed for being slow does not
/// merely retry: it fails the install having thrown away the layers it had
/// already fetched, so the next attempt starts from the beginning of the same
/// slow link.
const PULL_BUDGET: Duration = Duration::from_secs(15 * 60);

/// Pull the image, start the container, and wait until the engine answers.
///
/// **Public because the `stack_components` row is the caller's business.**
/// Nothing here claims it, marks it installed or marks it failed —
/// `stack.install` calls this from inside the claim it is already holding, and
/// a second claim on the same row from in here would find that row busy and
/// refuse the very install it is performing.
pub async fn install_container(ctx: &OpContext, plan: &EnginePlan) -> Result<InstallOutput> {
    let db = ctx.db().clone();
    let docker = docker_program()?;
    let name = plan.container.as_str().to_string();

    let known = registry(&db).await?;
    let host_port = choose_host_port(plan.recipe, &known, &name, &host_port_is_free)?;
    let root_password =
        root_password_to_start_under(plan.recipe, known.get(&name), ctx.master_key())?;

    // Before the pull, and before anything is taken down. The file has to exist
    // when `docker run` resolves the mount — Docker creates an empty *directory*
    // where a bind source is missing, and a server handed a directory for its
    // configuration does not start. Doing it first also means a render or a
    // permission failure costs nothing: no image fetched, no serving container
    // stopped.
    if let Credential::ConfigFile { .. } = plan.recipe.credential {
        let Some(password) = root_password.as_deref() else {
            return Err(UnihelmError::internal(format!(
                "{name} needs a password in a configuration file and none was generated"
            )));
        };
        write_engine_config(ctx, plan, password)?;
    }

    ctx.log(format!("docker pull {}", plan.image.as_str()));
    run_checked(&docker, &pull_argv(&plan.image), PULL_BUDGET).await?;

    // The name is the identity, so a container already holding it is this same
    // engine — an install that was interrupted, or one being put back — rather
    // than somebody else's container to work around. `docker run` would refuse
    // the name, so it is replaced, and without `delete_data`: the volume is the
    // database and the new container is about to pick it straight back up.
    //
    // After the pull, never before. Taking a serving engine down and then
    // spending a quarter of an hour on a download is an outage bought for
    // nothing, and bought again if the download fails.
    if crate::docker::container_exists(&docker, &plan.container).await {
        ctx.log(format!(
            "{name} is already on this server; replacing it, and keeping its data"
        ));
        // What replacing a cache the panel holds no password for actually
        // means, said while the operator is watching the task rather than
        // discovered afterwards. Nothing could give a *running* server a
        // password — it reads its configuration once, at start — so a cache
        // installed before this existed has been accepting every connection on
        // the machine, and recreating the container is the only thing that
        // changes that. It is also what breaks the clients using it.
        if let (Credential::ConfigFile { .. }, None) = (
            plan.recipe.credential,
            known
                .get(&name)
                .and_then(|r| r.root_password_sealed.as_ref()),
        ) {
            ctx.log(format!(
                "the panel holds no password for the {name} it is replacing, so that \
                 container has been accepting any connection from this server — every tenant \
                 shell and every site's PHP. The replacement requires one: anything already \
                 using this cache will be refused with NOAUTH until it is given that password."
            ));
        }
        remove_container(ctx, &docker, plan, false).await?;
    }

    ctx.log(format!(
        "docker run {} as {name}, published on {LOOPBACK}:{host_port}",
        plan.image.as_str()
    ));
    let mut start = unihelm_distro::Cmd::new(&docker)
        .args(run_argv(plan, host_port))
        .timeout(Duration::from_secs(60));
    if let (Credential::Env { variable }, Some(password)) =
        (plan.recipe.credential, root_password.as_deref())
    {
        start = start.env(variable, password);
    }
    let started = start.run().await.map_err(UnihelmError::from)?;
    if !started.success() {
        let text = started.failure_text();

        // Two things this used to leave the operator holding, and both of them
        // are what a port clash between Redis and Valkey actually looked like:
        //
        // 1. **A broken container.** `docker run` creates it and *then* starts
        //    it, so a bind failure leaves `unihelm-redis-7` sitting in `created`
        //    on the machine. The next attempt then failed on the name as well as
        //    the port, and the message was about the name.
        // 2. **Docker's own sentence**, which names an endpoint id and a driver
        //    and mentions the port in the middle of it. `run_failure` pulls the
        //    port out and names the holder — and the panel already knows the
        //    holder, because every engine it published a port for is in the
        //    registry above.
        let swept = crate::docker::sweep_failed_run(ctx, &docker, &plan.container).await;
        let holder = crate::docker::allocated_port(&text).and_then(|port| {
            known
                .values()
                .find(|r| r.host_port == port)
                .map(|r| r.container.clone())
        });
        return Err(crate::docker::run_failure(
            &text,
            plan.container.as_str(),
            holder.as_deref(),
            swept,
        ));
    }

    let record = EngineRecord {
        slug: plan.component.entry().slug.to_string(),
        version: plan.component.version().version.to_string(),
        image: plan.image.as_str().to_string(),
        container: name,
        volume: plan.volume.clone(),
        host_port,
        container_port: plan.recipe.container_port,
        root_user: plan.recipe.root_user.map(str::to_string),
        root_password_sealed: root_password
            .as_deref()
            .map(|clear| ctx.master_key().seal_str(clear))
            .transpose()
            .map_err(UnihelmError::from)?,
    };

    // Written **before** the wait rather than after it. The container is
    // already initialising its volume under this password, and the sealed copy
    // here is the only one that will ever exist: returning from a readiness
    // timeout without having written it would leave an engine on the machine,
    // holding somebody's data directory, that nothing can ever log in to again.
    record_engine(&db, record.clone()).await?;

    wait_until_ready(ctx, plan, host_port, root_password.as_deref()).await?;

    // Reported out of the record, so what the operator is told is what the panel
    // will still say tomorrow — `db.create` reads that port from the same row.
    Ok(InstallOutput {
        slug: record.slug,
        version: record.version,
        container: record.container,
        image: record.image,
        volume: record.volume,
        host_port: record.host_port,
        running: true,
    })
}

/// The root password this container has to be started under.
///
/// A [`Credential::Env`] image reads that variable **once**, while it
/// initialises an empty data directory, and never looks at it again. So an
/// engine going back beside a volume it left behind has to be started under the
/// credential already baked into that data: generating a fresh one would leave
/// the panel holding a password the server has never heard of, and `db.create`
/// locked out of a database that is in perfect health.
///
/// A [`Credential::ConfigFile`] server rereads its file at every start, so it
/// *could* be given a fresh password here — and must not be. That password is
/// in the connection string of every application using the cache, and rotating
/// it silently on a reinstall would take those applications down while the
/// panel reported the engine healthy. Rotation is a thing an operator asks for,
/// not a side effect of putting a container back.
fn root_password_to_start_under(
    recipe: &Recipe,
    kept: Option<&EngineRecord>,
    key: &MasterKey,
) -> Result<Option<String>> {
    if let Some(kept) = kept
        && let Some(already) = kept.open_root_password(key)?
    {
        return Ok(Some(already));
    }
    match recipe.credential {
        Credential::Env { .. } | Credential::ConfigFile { .. } => Ok(Some(generate_password())),
        // Nothing to generate: Memcached would ignore it, and a secret that
        // protects nothing is worse than no secret — it reads, in the record
        // and on the page, exactly like one that does.
        Credential::Unauthenticated => Ok(None),
    }
}

/// Render this engine's configuration file and put it where only root can read
/// it and only the container can use it.
///
/// The mode on the *file* is deliberately not the protection here, and
/// [`unihelm_config::paths::engine_config_dir`] explains why at length: the
/// cache images drop to their own unprivileged account before reading their
/// configuration, so a 0600 file is one the server cannot open. The directory
/// is the boundary — 0700, so no local account can traverse to the file however
/// its own mode reads — and it is created before the file exists, so there is
/// never a moment when the password is sitting in a directory somebody could
/// walk into.
///
/// Rendered through the panel's own template environment rather than assembled
/// here, because that environment treats an undefined variable as an error: a
/// context that lost its `password` fails the install instead of writing a
/// cache with authentication switched off.
fn write_engine_config(ctx: &OpContext, plan: &EnginePlan, password: &str) -> Result<()> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

    let dir = unihelm_config::paths::engine_config_dir();
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(unihelm_config::paths::ENGINE_CONFIG_DIR_MODE)
        .create(&dir)
        .map_err(|e| {
            UnihelmError::internal(format!(
                "could not create {} to hold the engine's password: {e}",
                dir.display()
            ))
        })?;
    // `DirBuilder`'s mode applies only to directories it creates, so a
    // directory an older panel left behind at 0755 would keep it — and that
    // mode is the entire access control on the file inside.
    std::fs::set_permissions(
        &dir,
        std::fs::Permissions::from_mode(unihelm_config::paths::ENGINE_CONFIG_DIR_MODE),
    )
    .map_err(|e| {
        UnihelmError::internal(format!(
            "could not restrict {} to root; refusing to write an engine password into a \
             directory other accounts can read: {e}",
            dir.display()
        ))
    })?;

    let body = ctx.config().preview(
        CACHE_CONFIG_TEMPLATE,
        &serde_json::json!({ "engine": {
            "container": plan.container.as_str(),
            "password": password,
            // The mount point of the data volume, which is where the
            // append-only file has to land for the volume to hold anything.
            "data_dir": plan.recipe.data_dir.unwrap_or("/data"),
        }}),
    )?;

    let path = plan.config_file();
    unihelm_config::managed::write_atomic(
        &path,
        &body,
        unihelm_config::paths::ENGINE_CONFIG_FILE_MODE,
    )?;
    // The path, never the contents — but the path *is* the answer to the
    // question this install leaves an operator with. A cache that now demands a
    // password is no use to anybody who cannot find out what it is, and the
    // panel has nowhere yet to show them (see the note on
    // [`EngineRecord::root_password_sealed`]); root can read the file, and
    // nobody else on the machine can.
    ctx.log(format!(
        "wrote {} — {} will require the password in it. Applications need that password: \
         read it as root with `grep requirepass {}`. No unprivileged account on this server \
         can open that file.",
        path.display(),
        plan.container.as_str(),
        path.display()
    ));
    Ok(())
}

/// Take an engine's configuration file off the machine.
///
/// Called exactly where the record is forgotten, because the two are one thing:
/// the record holds the sealed password and the file holds the copy the server
/// reads, and a file left behind for an engine the panel no longer remembers is
/// a password nothing can ever use again sitting on disk.
fn remove_engine_config(plan: &EnginePlan) -> Result<()> {
    let path = plan.config_file();
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(UnihelmError::internal(format!(
            "could not remove {}: {e}",
            path.display()
        ))),
    }
}

/// Refuse to run an engine in a container when this server already has it as
/// host packages.
///
/// The two want one port and nothing arbitrates between them: whichever starts
/// second is the one that cannot bind, and after a reboot that is whichever of
/// systemd and Docker got there first. What the operator is shown is not a
/// conflict — it is the engine that was working, reporting itself broken.
///
/// [`choose_host_port`] cannot stand in for this. It asks who holds the port
/// *now*, and a host engine that is installed but not currently listening —
/// stopped for maintenance, or simply not yet started on a machine that is still
/// booting — holds nothing, so the container is handed the port and the
/// collision is scheduled rather than avoided.
///
/// The question is the host install's own row, so [`EnginePlan::host_row_key`]
/// and not [`EnginePlan::row_key`]: the container's row is the one this very
/// install is about to claim, and reading that one would refuse every install
/// the moment it was retried.
///
/// That row is the panel's own memory, so what this catches is a host install
/// the panel made. An engine somebody apt-got before Unihelm existed has no row
/// at all — `stack.status` derives `unmanaged` for those from the machine rather
/// than from the table — and while it is serving it is caught a step later, by
/// the bind in [`host_port_is_free`].
pub async fn refuse_when_the_host_already_runs_this_engine(
    ctx: &OpContext,
    plan: &EnginePlan,
) -> Result<()> {
    let Some(host) = ctx
        .db()
        .component(&plan.host_row_key())
        .await
        .map_err(UnihelmError::from)?
    else {
        return Ok(());
    };
    // The one stored status that means the packages are on this machine: a host
    // install claims its row before a single package has landed, and `failed`
    // and `absent` are rows about packages that are not there.
    if host.status != ComponentStatus::Installed {
        return Ok(());
    }

    let here = match &host.installed_version {
        Some(version) => format!("{} {version}", plan.component.entry().display_name),
        None => plan.component.entry().display_name.to_string(),
    };
    Err(UnihelmError::new(
        ErrorCode::Conflict,
        format!(
            "{here} is already installed on this server as host packages, and it listens \
             on port {port} — the port a container of {there} publishes on. Nothing \
             decides between the two: whichever starts second is the one that cannot \
             bind, and after a reboot that is whichever of systemd and Docker got there \
             first, so what you would be left looking at is the engine that was working \
             reporting itself broken. Remove the host install from the Stack Manager \
             first if this server is meant to run {there} in a container.",
            port = plan.recipe.default_host_port,
            there = plan.display_name(),
        ),
    )
    .with_field("component"))
}

// ---------------------------------------------------------------------------
// engine.remove
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct RemoveInput {
    #[serde(flatten)]
    pub component: StackComponent,
    /// Delete the data volume as well. Off by default, because the volume is
    /// the databases: removing a container is reversible and this is not.
    #[serde(default)]
    pub delete_data: bool,
}

#[derive(Debug, Serialize)]
pub struct RemoveOutput {
    pub slug: String,
    pub container: String,
    /// The volume that is still there, holding the data.
    pub volume_kept: Option<String>,
    pub volume_deleted: Option<String>,
}

/// `engine.remove` — stop and remove the container. The data survives.
pub struct Remove;

#[async_trait]
impl TypedOperation for Remove {
    type Input = RemoveInput;
    type Output = RemoveOutput;

    const NAME: &'static str = "engine.remove";
    const PERMISSION: Permission = Permission::StackManage;
    const EXECUTION: Execution = Execution::Task {
        cancellable: false,
        idempotent: true,
    };

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let plan = EnginePlan::for_component(input.component)?;
        let db = ctx.db().clone();
        let docker = docker_program()?;
        let stack_slug = plan.row_key().to_string();

        let task_id = ctx.task_id().map(|t| t.to_string()).unwrap_or_default();
        if !db
            .claim_component(&stack_slug, ComponentStatus::Removing, &task_id)
            .await
            .map_err(UnihelmError::from)?
        {
            return Err(UnihelmError::new(
                ErrorCode::Conflict,
                format!(
                    "{} is already being installed or removed",
                    plan.display_name()
                ),
            ));
        }

        let outcome = remove_container(ctx, &docker, &plan, input.delete_data).await;

        // This row is this container's alone (see [`EnginePlan::row_key`]), so
        // removing 11.4 says nothing at all about 11.8 — its row is a different
        // row and is left exactly as it was, still installed, still serving.
        match &outcome {
            Ok(_) => db
                .component_removed(&stack_slug)
                .await
                .map_err(UnihelmError::from)?,
            Err(e) => {
                let _ = db.component_failed(&stack_slug, &e.detail).await;
            }
        }
        outcome
    }
}

/// Take the container off the machine. Public for [`install_container`]'s
/// reason, and the caller owns the row here too.
pub async fn remove_container(
    ctx: &OpContext,
    docker: &str,
    plan: &EnginePlan,
    delete_data: bool,
) -> Result<RemoveOutput> {
    let db = ctx.db().clone();
    let name = plan.container.as_str().to_string();
    let inventory = DockerList.run(ctx, ListInput::default()).await?;
    let present = inventory.containers.iter().find(|c| c.name == name);

    if let Some(found) = present {
        if found.running {
            ctx.log(format!("docker stop {name}"));
            run_checked(docker, &stop_argv(&plan.container), Duration::from_secs(25)).await?;
        }
        ctx.log(format!("docker rm {name}"));
        run_checked(
            docker,
            &remove_argv(&plan.container),
            Duration::from_secs(25),
        )
        .await?;
    } else {
        // Removing what is not there is not a failure — the operation is
        // idempotent, and an interrupted removal has to be able to finish.
        ctx.log(format!("{name} is not on this server; nothing to remove"));
    }

    let mut deleted = None;
    let mut kept = plan.volume.clone();

    if delete_data {
        if let Some(volume) = plan.volume() {
            if inventory.volumes.iter().any(|v| v.name == volume) {
                ctx.log(format!("docker volume rm {volume} — this deletes the data"));
                run_checked(docker, &volume_remove_argv(volume), Duration::from_secs(25)).await?;
            }
            deleted = Some(volume.to_string());
            kept = None;
        }
        // The record goes with the data. Keeping the credential for a volume
        // that no longer exists would only mean a later install of the same
        // version silently reusing a password for data that is not there.
        forget_engine(&db, &name).await?;
        remove_engine_config(plan)?;
    } else {
        // The record **stays**, and that is deliberate: the volume it names is
        // still on the machine, and the sealed credential is the only thing that
        // can log in to the data inside it. Dropping it here would turn
        // "remove and reinstall" into "lose the database".
        if let Some(volume) = plan.volume() {
            ctx.log(format!(
                "the data volume `{volume}` was kept; installing {} again reuses it",
                plan.display_name()
            ));
        } else {
            forget_engine(&db, &name).await?;
            remove_engine_config(plan)?;
        }
    }

    Ok(RemoveOutput {
        slug: plan.component.entry().slug.to_string(),
        container: name,
        volume_kept: kept,
        volume_deleted: deleted,
    })
}

// ---------------------------------------------------------------------------
// engine.status
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Deserialize)]
pub struct StatusInput {
    /// One catalogue slug, or every engine when absent.
    #[serde(default)]
    pub component: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct EngineStatus {
    pub slug: String,
    pub version: String,
    pub display_name: String,
    pub container: String,
    pub image: String,
    pub host_port: u16,
    pub volume: Option<String>,
    /// Whether the container exists at all — a record with no container is an
    /// engine somebody removed with `docker rm` behind the panel's back.
    pub present: bool,
    pub running: bool,
    /// Docker's own prose: `Up 3 hours`, `Exited (0) 2 days ago`.
    pub status: String,
    /// Whether the data is still on the machine.
    pub data_volume_present: bool,
    /// **Whether anything at all has to log in to this server.**
    ///
    /// Read off the record rather than off the recipe, because those are
    /// different questions: the recipe says what the panel installs *today*, the
    /// record says what this container was actually started with. A Redis
    /// installed before caches had passwords has no sealed credential, and it
    /// keeps answering every account on this machine until it is installed
    /// again — the panel says so instead of showing a page that implies the fix
    /// was retroactive.
    pub authenticated: bool,
    /// Said in words when it is not, because `false` on a status page is a fact
    /// and not an instruction. `None` when the container does require a
    /// password.
    pub authentication_note: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct StatusOutput {
    /// False when there is no Docker on this machine, which is a true answer
    /// rather than an error — the same choice `docker.list` makes.
    pub docker_available: bool,
    pub engines: Vec<EngineStatus>,
}

/// `engine.status` — what the panel runs in containers, and whether it is up.
pub struct Status;

#[async_trait]
impl TypedOperation for Status {
    type Input = StatusInput;
    type Output = StatusOutput;

    const NAME: &'static str = "engine.status";
    const PERMISSION: Permission = Permission::ServerRead;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let registry = registry(ctx.db()).await?;
        // The cheap inventory, not `docker.list`. This operation renders no
        // volume size and no mount list, and `docker.list` now pays
        // `docker system df` — which walks every volume's directory — to draw
        // those on the Docker page. Reading the full list here would put those
        // seconds behind the Databases page's first paint for two fields
        // (a container's state, and whether a volume name still exists) that
        // cost one command each.
        let inventory = crate::docker::inventory().await;
        let volumes = match inventory.docker.as_deref() {
            Some(docker) => crate::docker::volume_names(docker).await,
            None => Vec::new(),
        };

        let mut engines: Vec<EngineStatus> = registry
            .values()
            .filter(|r| input.component.as_deref().is_none_or(|s| s == r.slug))
            .map(|record| {
                let found = inventory
                    .containers
                    .iter()
                    .find(|c| c.name == record.container);
                EngineStatus {
                    display_name: StackComponent::resolve(&record.slug, Some(&record.version))
                        .map(|c| c.display_name())
                        .unwrap_or_else(|_| record.slug.clone()),
                    slug: record.slug.clone(),
                    version: record.version.clone(),
                    container: record.container.clone(),
                    image: record.image.clone(),
                    host_port: record.host_port,
                    data_volume_present: record
                        .volume
                        .as_deref()
                        .is_some_and(|v| volumes.iter().any(|have| have == v)),
                    volume: record.volume.clone(),
                    present: found.is_some(),
                    running: found.is_some_and(|c| c.running),
                    status: found.map(|c| c.status.clone()).unwrap_or_else(|| {
                        "not on this server — the container was removed outside the panel"
                            .to_string()
                    }),
                    authenticated: record.root_password_sealed.is_some(),
                    authentication_note: authentication_note(record),
                }
            })
            .collect();
        engines.sort_by(|a, b| a.container.cmp(&b.container));

        Ok(StatusOutput {
            docker_available: inventory.docker.is_some() && inventory.daemon_running,
            engines,
        })
    }
}

/// What to tell an operator about a container nothing has to log in to.
///
/// Two different situations, and they need different sentences because they
/// have different fixes. One is a container the panel could protect and has
/// not yet — installing it again does it. The other is Memcached, which the
/// panel cannot protect at all, and the only fix is not putting untrusted
/// accounts on the machine. Collapsing them into one "unauthenticated" badge
/// would leave an operator either doing nothing about the first or waiting
/// forever for a fix to the second.
fn authentication_note(record: &EngineRecord) -> Option<String> {
    if record.root_password_sealed.is_some() {
        return None;
    }
    let unfixable = matches!(
        recipe(&record.slug).map(|r| r.credential),
        Some(Credential::Unauthenticated)
    );
    Some(if unfixable {
        format!(
            "{} has no password: its only authentication is SASL, which needs a build the \
             official image does not ship. Anything that can reach {LOOPBACK}:{} — every \
             shell and every site's PHP on this server — can read and delete every key in \
             it. Run it only on a machine whose local accounts you all trust.",
            record.container, record.host_port
        )
    } else {
        format!(
            "{} was installed before the panel gave this engine a password, so it accepts \
             any connection from this machine — including every tenant shell and every \
             site's PHP. A running server cannot be given one; install {} again from the \
             Stack Manager to replace the container with an authenticated one, and expect \
             to hand the new password to whatever already connects to it.",
            record.container, record.slug
        )
    })
}

// ---------------------------------------------------------------------------
// Plumbing
// ---------------------------------------------------------------------------

/// The `docker` binary, or the reason there is nothing to install into.
fn docker_program() -> Result<String> {
    unihelm_distro::exec::resolve_program(DOCKER)
        .map(|p| p.to_string_lossy().into_owned())
        .map_err(|_| {
            UnihelmError::new(
                ErrorCode::NotFound,
                "Docker is not installed on this server, and this engine runs in a \
                 container. Install Docker from the Stack Manager first.",
            )
        })
}

async fn run_checked(docker: &str, args: &[String], budget: Duration) -> Result<String> {
    let out = unihelm_distro::Cmd::new(docker)
        .args(args)
        .timeout(budget)
        .run()
        .await
        .map_err(UnihelmError::from)?;
    if !out.success() {
        return Err(UnihelmError::new(
            ErrorCode::CommandFailed,
            out.failure_text(),
        ));
    }
    Ok(out.trimmed_stdout().to_string())
}

/// A root password for an engine container.
///
/// The alphabet is `db::generate_password`'s, and for the same reason: it
/// contains nothing that needs quoting in a SQL literal, a shell word or a
/// URL, so the value cannot change meaning wherever it ends up. Longer than a
/// tenant's, because this one is never typed by a person and unlocks the whole
/// engine.
fn generate_password() -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    const LEN: usize = 32;
    let mut rng = rand::thread_rng();
    (0..LEN)
        .map(|_| ALPHABET[rng.gen_range(0..ALPHABET.len())] as char)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // The panel's real template environment, so what these tests assert about a
    // cache's configuration is what an install actually writes — a fixture
    // string here could agree with itself while the shipped template had lost
    // its `requirepass` line.
    use unihelm_config::TemplateSet;

    fn plan(slug: &str, version: Option<&str>) -> EnginePlan {
        EnginePlan::resolve(slug, version).expect("a catalogued engine")
    }

    fn record(container: &str, slug: &str, port: u16) -> EngineRecord {
        EngineRecord {
            slug: slug.into(),
            version: "11.8".into(),
            image: "mariadb:11.8".into(),
            container: container.into(),
            volume: Some(format!("{container}-data")),
            host_port: port,
            container_port: 3306,
            root_user: Some("root".into()),
            root_password_sealed: None,
        }
    }

    // -----------------------------------------------------------------------
    // Identity
    // -----------------------------------------------------------------------

    /// "Install 11.4" has to mean 11.4. A tag that resolved to anything else
    /// would be the panel installing a version nobody chose, which is the
    /// failure the whole containerised model exists to remove.
    #[test]
    fn the_tag_is_the_version_the_operator_picked() {
        for (slug, version, image) in [
            ("mariadb", "11.8", "mariadb:11.8"),
            ("mariadb", "11.4", "mariadb:11.4"),
            ("mariadb", "10.11", "mariadb:10.11"),
            ("postgres", "17", "postgres:17"),
            ("postgres", "15", "postgres:15"),
            ("mongodb", "7.0", "mongo:7.0"),
        ] {
            assert_eq!(plan(slug, Some(version)).image().as_str(), image);
        }
    }

    /// `distro` is not a Docker tag. Every entry catalogued that way must still
    /// pin an exact one — a `latest` here would turn a restart into a major
    /// version upgrade of somebody's cache.
    #[test]
    fn an_unversioned_entry_still_pins_an_exact_tag() {
        for (slug, image) in [
            ("mysql", "mysql:8.0"),
            ("redis", "redis:7"),
            ("valkey", "valkey/valkey:8"),
            ("memcached", "memcached:1.6"),
        ] {
            let resolved = plan(slug, None);
            assert_eq!(resolved.image().as_str(), image);
            assert!(
                !image.ends_with(":latest"),
                "{slug} must not float on a moving tag"
            );
        }
    }

    /// The name is the identity: two callers naming 11.8 must land on one
    /// container, and 11.4 must land on a different one.
    #[test]
    fn the_container_name_is_deterministic_and_per_version() {
        assert_eq!(
            plan("mariadb", Some("11.8")).container().as_str(),
            "unihelm-mariadb-11.8"
        );
        assert_eq!(
            plan("mariadb", Some("11.8")).container().as_str(),
            plan("mariadb", Some("11.8")).container().as_str()
        );
        assert_ne!(
            plan("mariadb", Some("11.8")).container().as_str(),
            plan("mariadb", Some("11.4")).container().as_str()
        );
        // A version nobody typed still produces a name that says what is running.
        assert_eq!(plan("redis", None).container().as_str(), "unihelm-redis-7");
    }

    /// One volume per (tool, version), named after the container so an operator
    /// reading `docker volume ls` can tell whose data it is.
    #[test]
    fn each_version_keeps_its_data_in_its_own_volume() {
        assert_eq!(
            plan("mariadb", Some("11.8")).volume(),
            Some("unihelm-mariadb-11.8-data")
        );
        assert_ne!(
            plan("mariadb", Some("11.8")).volume(),
            plan("mariadb", Some("11.4")).volume()
        );
        // Memcached keeps nothing, so promising it a volume would promise
        // durability it does not have.
        assert_eq!(plan("memcached", None).volume(), None);
    }

    /// This step is databases and caches. Applications and PHP-FPM need uid
    /// mapping and a shared socket directory and are deliberately not here; the
    /// refusal has to say so rather than producing a container.
    #[test]
    fn only_databases_and_caches_run_as_containers_in_this_step() {
        for slug in ["php", "nginx", "node", "apache", "go", "docker"] {
            let err = match EnginePlan::resolve(slug, None) {
                Err(e) => e,
                Ok(resolved) => {
                    panic!("{slug} is not part of this step, yet it planned {resolved:?}")
                }
            };
            assert_eq!(err.code, ErrorCode::InvalidInput);
        }
        for (slug, _) in RECIPES {
            assert!(EnginePlan::resolve(slug, None).is_ok(), "{slug}");
        }
    }

    /// Every containerisable entry has to be a real catalogue entry, or the
    /// operator can never ask for it.
    #[test]
    fn every_recipe_names_a_catalogue_entry_of_the_right_kind() {
        for (slug, _) in RECIPES {
            let entry =
                catalogue::entry(slug).unwrap_or_else(|| panic!("{slug} is not in the catalogue"));
            assert!(
                matches!(
                    entry.category,
                    catalogue::Category::Database | catalogue::Category::Cache
                ),
                "{slug} is not a database or a cache"
            );
            // And every version the catalogue offers has to resolve to an image.
            for version in entry.versions {
                assert!(
                    EnginePlan::resolve(slug, Some(version.version)).is_ok(),
                    "{slug} {} has no image",
                    version.version
                );
            }
        }
    }

    // -----------------------------------------------------------------------
    // The port
    // -----------------------------------------------------------------------

    /// The first engine of a family gets the port everybody expects.
    #[test]
    fn the_first_engine_publishes_on_the_port_everybody_expects() {
        let empty = EngineRegistry::new();
        assert_eq!(
            choose_host_port(
                recipe("mariadb").unwrap(),
                &empty,
                "unihelm-mariadb-11.8",
                &|_| true
            )
            .unwrap(),
            3306
        );
        assert_eq!(
            choose_host_port(
                recipe("postgres").unwrap(),
                &empty,
                "unihelm-postgres-17",
                &|_| true
            )
            .unwrap(),
            5432
        );
    }

    /// The defect this exists for: 11.8 and 11.4 both want 3306. The second is
    /// given a port rather than refused, because refusing leaves an operator
    /// migrating an old application to do it by hand on a live machine.
    #[test]
    fn a_second_version_is_allocated_a_port_rather_than_refused() {
        let mut registry = EngineRegistry::new();
        registry.insert(
            "unihelm-mariadb-11.8".into(),
            record("unihelm-mariadb-11.8", "mariadb", 3306),
        );

        let port = choose_host_port(
            recipe("mariadb").unwrap(),
            &registry,
            "unihelm-mariadb-11.4",
            &|_| true,
        )
        .unwrap();
        assert_eq!(port, 3307, "the second version needs a port of its own");
    }

    /// MariaDB and MySQL are one protocol family. Allocating them out of
    /// separate ranges would hand both of them 3306 and the second would never
    /// start.
    #[test]
    fn engines_that_share_a_protocol_share_a_range() {
        let mut registry = EngineRegistry::new();
        registry.insert(
            "unihelm-mariadb-11.8".into(),
            record("unihelm-mariadb-11.8", "mariadb", 3306),
        );
        assert_eq!(
            choose_host_port(
                recipe("mysql").unwrap(),
                &registry,
                "unihelm-mysql-8.0",
                &|_| true
            )
            .unwrap(),
            3307
        );
        assert_eq!(
            recipe("redis").unwrap().default_host_port,
            recipe("valkey").unwrap().default_host_port,
            "Valkey is a fork of Redis down to the default port"
        );
    }

    /// A port held by something that is not ours — a MySQL the panel never
    /// installed, still serving — is just as taken.
    #[test]
    fn a_port_held_by_something_else_on_the_machine_is_skipped() {
        let empty = EngineRegistry::new();
        let busy = |port: u16| port != 3306;
        assert_eq!(
            choose_host_port(
                recipe("mariadb").unwrap(),
                &empty,
                "unihelm-mariadb-11.8",
                &busy
            )
            .unwrap(),
            3307
        );
    }

    /// When there is genuinely nowhere to go, the refusal names a holder — a
    /// bare "no free port" tells an operator nothing they can act on.
    #[test]
    fn running_out_of_ports_names_what_holds_them() {
        let mut registry = EngineRegistry::new();
        for (i, port) in (3306..=3306 + PORT_SPARE).enumerate() {
            let name = format!("unihelm-mariadb-{i}");
            registry.insert(name.clone(), record(&name, "mariadb", port));
        }
        let err = choose_host_port(
            recipe("mariadb").unwrap(),
            &registry,
            "unihelm-mariadb-11.8",
            &|_| true,
        )
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::Conflict);
        assert!(
            err.detail.contains("unihelm-mariadb-"),
            "the refusal must name a holder: {}",
            err.detail
        );
    }

    // -----------------------------------------------------------------------
    // The argv
    // -----------------------------------------------------------------------

    /// A database published on every interface answers the internet whatever
    /// the firewall says, because Docker's DNAT rule sits in front of `INPUT`.
    /// Nothing else in this file notices if this binding is dropped.
    #[test]
    fn every_port_is_published_on_loopback_only() {
        for (slug, _) in RECIPES {
            let argv = run_argv(&plan(slug, None), 3306);
            let publish = argv
                .windows(2)
                .find(|w| w[0] == "--publish")
                .map(|w| w[1].clone())
                .unwrap_or_else(|| panic!("{slug} publishes nothing"));
            assert!(
                publish.starts_with("127.0.0.1:"),
                "{slug} would be reachable from the internet: {publish}"
            );
        }
    }

    /// The credential must not reach an argv: `/proc/<pid>/cmdline` is readable
    /// by every local user, which is the same leak `db.rs` puts its SQL on
    /// stdin to avoid. `--env KEY` with no value is Docker's own form for
    /// "take it from my environment", and the environment is set on the child.
    #[test]
    fn the_root_password_is_never_an_argument() {
        let argv = run_argv(&plan("mariadb", Some("11.8")), 3306);
        assert!(
            argv.iter().any(|a| a == "MARIADB_ROOT_PASSWORD"),
            "the image has to be told where to read it: {argv:?}"
        );
        assert!(
            !argv.iter().any(|a| a.contains("MARIADB_ROOT_PASSWORD=")),
            "a value on the argv is a password in /proc: {argv:?}"
        );
        // Nor can it: the builder is not given one.
        let twice = run_argv(&plan("mariadb", Some("11.8")), 3306);
        assert_eq!(argv, twice, "the run argv is a function of the plan alone");
    }

    /// The data volume is mounted where the image actually keeps its data —
    /// a volume mounted anywhere else is a database that quietly persists
    /// nothing.
    #[test]
    fn the_volume_is_mounted_where_the_image_keeps_its_data() {
        let argv = run_argv(&plan("postgres", Some("17")), 5432);
        assert!(
            argv.windows(2).any(|w| w[0] == "--volume"
                && w[1] == "unihelm-postgres-17-data:/var/lib/postgresql/data"),
            "{argv:?}"
        );
        // And an image with no data has no mount at all.
        assert!(
            !run_argv(&plan("memcached", None), 11211)
                .iter()
                .any(|a| a == "--volume")
        );
    }

    /// The Redis image's own command keeps nothing on disk, so a volume at
    /// /data would stay empty while the panel reported the data was safe.
    ///
    /// `--appendonly yes` used to be an argument; it moved into the
    /// configuration file the password needs, so this now asks the file. The
    /// property is the same one and losing it would be just as quiet.
    #[test]
    fn a_cache_given_a_volume_is_told_to_persist_to_it() {
        let templates = TemplateSet::load().expect("the panel's own templates");
        for slug in ["redis", "valkey"] {
            let resolved = plan(slug, None);
            let rendered = templates
                .render(
                    CACHE_CONFIG_TEMPLATE,
                    &serde_json::json!({ "engine": {
                        "container": resolved.container().as_str(),
                        "password": "irrelevant-here",
                        "data_dir": resolved.recipe.data_dir.unwrap(),
                    }}),
                )
                .unwrap();
            assert!(
                rendered.contains("appendonly yes"),
                "{slug} would persist nothing:\n{rendered}"
            );
            assert!(rendered.contains("dir /data"), "{slug}:\n{rendered}");

            // The command comes after the image, or Docker reads it as a flag.
            // The image by its exact name: `--name unihelm-redis-7` also
            // contains the slug and comes first, so a substring match here
            // would pass whatever the order was.
            let argv = run_argv(&resolved, 6379);
            let image = argv
                .iter()
                .position(|a| a == resolved.image().as_str())
                .unwrap_or_else(|| panic!("{slug} names no image: {argv:?}"));
            let command = argv
                .iter()
                .position(|a| a.ends_with("-server"))
                .unwrap_or_else(|| panic!("{slug} names no server: {argv:?}"));
            assert!(image < command, "{argv:?}");
        }
    }

    /// **The defect this wave exists for.** Every containerised cache ran with
    /// no authentication at all, published on loopback — which is not a
    /// boundary on a shared host, where every tenant's PHP and every tenant
    /// shell is a local account. Any customer could `KEYS *` over everybody
    /// else's sessions and `FLUSHALL` the lot.
    #[test]
    fn a_cache_requires_a_password_and_reads_it_from_a_file_only_root_can_reach() {
        for slug in ["redis", "valkey"] {
            let resolved = plan(slug, None);
            let Credential::ConfigFile { mount } = resolved.recipe.credential else {
                panic!("{slug} would answer anybody on this server");
            };
            let argv = run_argv(&resolved, 6379);

            // The file is bind-mounted read-only: the panel writes it, the
            // server only reads it, and a cache that could rewrite its own
            // configuration could rewrite away its own password.
            let expected = format!(
                "{}:{mount}:ro",
                unihelm_config::paths::engine_config_file(resolved.container().as_str()).display()
            );
            assert!(
                argv.windows(2)
                    .any(|w| w[0] == "--volume" && w[1] == expected),
                "{slug} does not mount its configuration: {argv:?}"
            );

            // And the server is actually told to read it. A configuration file
            // mounted but not named is a cache with no password, which is
            // exactly the state this replaces.
            let named = argv
                .iter()
                .position(|a| a == mount)
                .unwrap_or_else(|| panic!("{slug} never reads its config: {argv:?}"));
            let server = argv
                .iter()
                .position(|a| a.ends_with("-server"))
                .unwrap_or_else(|| panic!("{slug} names no server: {argv:?}"));
            assert!(
                server < named,
                "the path is the server's argument: {argv:?}"
            );
        }
    }

    /// Every engine's password reaches it **by reference and never by value**,
    /// and each one has exactly one channel — the variable Docker is told to
    /// copy from this process's environment, or the file only root can reach.
    ///
    /// Held over every recipe rather than over the two caches, because the way
    /// this broke was an engine being added with no channel at all: `None` read
    /// as "this image has no password" and nobody noticed it also meant "and so
    /// it has none".
    #[test]
    fn every_engine_carries_its_password_by_reference_and_by_exactly_one_route() {
        for (slug, recipe) in RECIPES {
            let resolved = plan(slug, None);
            let argv = run_argv(&resolved, recipe.default_host_port);
            let mounts: Vec<&String> = argv
                .windows(2)
                .filter(|w| w[0] == "--volume")
                .map(|w| &w[1])
                .collect();
            let config_mounts = mounts.iter().filter(|m| m.contains("/engines/")).count();

            match recipe.credential {
                Credential::Env { variable } => {
                    // The name alone. `--env NAME=secret` would put it in
                    // `/proc/<pid>/cmdline` for the length of the run.
                    assert!(
                        argv.windows(2).any(|w| w[0] == "--env" && w[1] == variable),
                        "{slug} does not tell Docker where to read {variable}: {argv:?}"
                    );
                    assert_eq!(config_mounts, 0, "{slug} has two routes: {argv:?}");
                }
                Credential::ConfigFile { mount } => {
                    assert_eq!(
                        config_mounts, 1,
                        "{slug} does not mount the file its password is in: {argv:?}"
                    );
                    assert!(
                        argv.contains(&mount.to_string()),
                        "{slug} never reads the file it mounts: {argv:?}"
                    );
                    // No environment variable beside it. Two routes would mean
                    // the leaky one still leaks.
                    assert!(
                        !argv.iter().any(|a| a == "--env"),
                        "{slug} also passes the password by environment: {argv:?}"
                    );
                }
                Credential::Unauthenticated => {
                    assert_eq!(config_mounts, 0, "{slug}: {argv:?}");
                    assert!(!argv.iter().any(|a| a == "--env"), "{slug}: {argv:?}");
                }
            }
        }
    }

    /// MongoDB's image creates its administrative user only when both halves are
    /// present; a password with no username is ignored and the server comes up
    /// with no authentication at all.
    #[test]
    fn mongodb_gets_the_username_its_password_is_useless_without() {
        let argv = run_argv(&plan("mongodb", Some("8.0")), 27017);
        assert!(
            argv.windows(2)
                .any(|w| w[0] == "--env" && w[1] == "MONGO_INITDB_ROOT_USERNAME=root"),
            "{argv:?}"
        );
    }

    /// A database must come back after a reboot, and must stay stopped when an
    /// operator stopped it.
    #[test]
    fn an_engine_comes_back_after_a_reboot() {
        let argv = run_argv(&plan("mariadb", Some("11.8")), 3306);
        assert!(
            argv.windows(2)
                .any(|w| w[0] == "--restart" && w[1] == "unless-stopped"),
            "{argv:?}"
        );
    }

    /// Removing a container must never be how somebody finds out their database
    /// is gone. `-v` deletes the volume, `-f` SIGKILLs something mid-write, and
    /// neither is ever what "remove this engine" meant.
    #[test]
    fn removing_a_container_takes_neither_the_data_nor_a_kill_with_it() {
        let target = plan("mariadb", Some("11.8"));
        let argv = remove_argv(target.container());
        assert_eq!(argv, vec!["rm", "unihelm-mariadb-11.8"]);
        for forbidden in ["-v", "--volumes", "-f", "--force"] {
            assert!(
                !argv.iter().any(|a| a == forbidden),
                "{forbidden} in {argv:?}"
            );
        }
        // The stop before it is graceful, for a server that may be flushing.
        assert_eq!(
            stop_argv(target.container()),
            vec!["stop", "-t", "10", "unihelm-mariadb-11.8"]
        );
        // Deleting the data is a separate command, reachable only from an
        // explicit `delete_data`.
        assert_eq!(
            volume_remove_argv("unihelm-mariadb-11.8-data"),
            vec!["volume", "rm", "unihelm-mariadb-11.8-data"]
        );
    }

    /// Absent means keep the data. A flag whose default destroyed a database
    /// would be a button whose worst outcome is unrecoverable.
    #[test]
    fn a_removal_that_does_not_ask_keeps_the_data() {
        let parsed: RemoveInput =
            serde_json::from_value(serde_json::json!({ "component": "mariadb" })).unwrap();
        assert!(!parsed.delete_data);
    }

    // -----------------------------------------------------------------------
    // Readiness
    // -----------------------------------------------------------------------

    /// Every engine has to be asked whether it is *answering*, not whether
    /// Docker started it. An engine with no probe would report ready the
    /// instant the container existed, and every follow-up — create database,
    /// create user — would fail confusingly.
    #[test]
    fn every_engine_knows_how_to_be_asked_whether_it_is_ready() {
        for (slug, recipe) in RECIPES {
            match recipe.probe {
                Probe::Exec { argv, .. } | Probe::ExecAuthenticated { argv, .. } => {
                    assert!(!argv.is_empty(), "{slug} has an empty probe");
                    // No credential in a probe: `docker exec` argv are as
                    // readable as any other — this one runs on the *host*, so
                    // its command line is in `/proc` for every local account —
                    // and ping either answers without one or authenticates over
                    // stdin.
                    assert!(
                        !argv.iter().any(|a| a.contains("password")
                            || a.contains("PASSWORD")
                            || a.starts_with("-a")
                            || a.starts_with("-p")),
                        "{slug}'s probe carries a credential: {argv:?}"
                    );
                }
                Probe::Wire { send, expect } => {
                    assert!(!send.is_empty() && !expect.is_empty(), "{slug}");
                }
            }
        }
    }

    /// A probe that cannot log in is worse than no probe once the server
    /// requires a password: `redis-cli ping` answers `NOAUTH` and exits 0, so
    /// the install would either burn the whole readiness budget or — if that
    /// refusal were taken for an answer — report a healthy cache the panel
    /// cannot actually talk to. Authenticating is also the only thing that
    /// proves the sealed password is the one the server was started with.
    #[test]
    fn a_cache_that_requires_a_password_is_probed_with_it() {
        for slug in ["redis", "valkey"] {
            let recipe = recipe(slug).unwrap();
            assert!(
                matches!(recipe.credential, Credential::ConfigFile { .. }),
                "{slug} has no password, so this test is asserting nothing"
            );
            let Probe::ExecAuthenticated { argv, expect } = recipe.probe else {
                panic!("{slug} would report a server it cannot log in to as ready");
            };
            assert_eq!(expect, "PONG");
            // `-i`, or Docker hands the client `/dev/null` and it reads EOF
            // before it has authenticated — a failing probe against a perfectly
            // healthy server.
            let exec = exec_argv(plan(slug, None).container(), argv, true);
            assert_eq!(exec[0..2], ["exec".to_string(), "-i".to_string()]);
        }
    }

    /// The trap inside the fix: a Redis that came up with **no** password
    /// answers `AUTH` with an error and then answers `PING` with `PONG`. A
    /// probe that only looked for the pong would pass the exact condition this
    /// change exists to remove and report a protected cache that every account
    /// on the machine can read.
    #[test]
    fn a_ping_alone_does_not_prove_a_cache_is_protected() {
        assert_eq!(read_authenticated_probe("OK\nPONG\n", "PONG"), Ok(()));

        let unprotected = read_authenticated_probe(
            "(error) ERR Client sent AUTH, but no password is set\nPONG\n",
            "PONG",
        )
        .expect_err("a server with no password must not read as ready");
        assert!(unprotected.contains("no password is set"), "{unprotected}");

        // A password the server does not know is a different fault with a
        // different fix, and the server's own word for it is the useful one.
        let wrong = read_authenticated_probe("(error) WRONGPASS invalid password\n", "PONG")
            .expect_err("a refused credential is not readiness");
        assert!(wrong.contains("WRONGPASS"), "{wrong}");

        // Authenticated but not answering, and nothing at all, are both refusals
        // rather than a shrug.
        assert!(read_authenticated_probe("OK\n", "PONG").is_err());
        assert!(read_authenticated_probe("", "PONG").is_err());
    }

    /// A socket probe would pass against the temporary server both MySQL-family
    /// images run to initialise the data directory, and call a container ready
    /// while nothing outside it can connect.
    #[test]
    fn the_mysql_family_is_probed_over_tcp_and_not_over_its_socket() {
        for slug in ["mariadb", "mysql"] {
            let Probe::Exec { argv, .. } = recipe(slug).unwrap().probe else {
                panic!("{slug} should exec a client");
            };
            assert!(argv.contains(&"--protocol=tcp"), "{slug}: {argv:?}");
        }
    }

    /// The probe reaches the client through `docker exec`, and the container is
    /// named before the command so nothing in the probe can be read as an
    /// argument to Docker itself.
    #[test]
    fn the_probe_runs_inside_the_container_it_names() {
        let argv = exec_argv(
            plan("redis", None).container(),
            &["redis-cli", "ping"],
            false,
        );
        assert_eq!(argv, vec!["exec", "unihelm-redis-7", "redis-cli", "ping"]);

        // `-i` is a flag to Docker, so it belongs before the container name;
        // after it, Docker would hand it to the client as an argument.
        let interactive = exec_argv(plan("redis", None).container(), &["redis-cli"], true);
        assert_eq!(
            interactive,
            vec!["exec", "-i", "unihelm-redis-7", "redis-cli"]
        );
    }

    // -----------------------------------------------------------------------
    // The credential
    // -----------------------------------------------------------------------

    /// Not a constant, and not the same twice — a shared root password across
    /// two servers is one compromise away from both.
    #[test]
    fn the_root_credential_is_generated_and_never_repeats() {
        let a = generate_password();
        let b = generate_password();
        assert_ne!(a, b);
        assert_eq!(a.len(), 32);
        // Nothing that changes meaning in a SQL literal, a shell word or a URL.
        assert!(a.bytes().all(|c| c.is_ascii_alphanumeric()), "{a}");
    }

    /// Sealed at rest and redacted in print: the way a credential reaches a log
    /// is somebody adding `?record` to a tracing call.
    #[test]
    fn a_stored_credential_is_sealed_and_does_not_print() {
        let key = MasterKey::generate();
        let secret = generate_password();
        let mut stored = record("unihelm-mariadb-11.8", "mariadb", 3306);
        stored.root_password_sealed = Some(key.seal_str(&secret).unwrap());

        let json = serde_json::to_string(&stored).unwrap();
        assert!(
            !json.contains(&secret),
            "the settings row holds the plaintext"
        );
        assert!(!format!("{stored:?}").contains(&secret));
        assert!(format!("{stored:?}").contains("redacted"));

        // And the one caller that needs it can still get it back.
        assert_eq!(
            stored.open_root_password(&key).unwrap().as_deref(),
            Some(secret.as_str())
        );
    }

    /// The image reads that variable once, initialising an empty data
    /// directory, and never again. An engine put back beside the volume it left
    /// behind therefore has to start under the credential already in that data —
    /// a fresh one would leave the panel holding a password the server never
    /// heard of, and `db.create` locked out of a database in perfect health.
    #[test]
    fn a_reinstall_starts_under_the_credential_its_data_was_initialised_with() {
        let key = MasterKey::generate();
        let secret = generate_password();
        let mut kept = record("unihelm-mariadb-11.8", "mariadb", 3306);
        kept.root_password_sealed = Some(key.seal_str(&secret).unwrap());

        assert_eq!(
            root_password_to_start_under(recipe("mariadb").unwrap(), Some(&kept), &key).unwrap(),
            Some(secret.clone())
        );

        // A first install has nothing to keep and gets one of its own.
        let fresh = root_password_to_start_under(recipe("mariadb").unwrap(), None, &key)
            .unwrap()
            .expect("a database needs a root password");
        assert_ne!(fresh, secret);
        assert_eq!(fresh.len(), 32);

        // And a cache that has no notion of one is not handed a password to
        // ignore, which would only be a secret to keep for nothing.
        assert_eq!(
            root_password_to_start_under(recipe("memcached").unwrap(), None, &key).unwrap(),
            None
        );

        // A cache whose password lives in a file gets one generated on a first
        // install, and keeps the one it has on a reinstall. It *could* be
        // rotated — the file is reread at every start — and must not be:
        // rotating it silently would break every application holding the old
        // one while the panel reported the engine healthy.
        let redis = recipe("redis").unwrap();
        let first = root_password_to_start_under(redis, None, &key)
            .unwrap()
            .expect("a cache on a shared host needs a password");
        assert_eq!(first.len(), 32);

        let mut cached = record("unihelm-redis-7", "redis", 6379);
        cached.root_password_sealed = Some(key.seal_str(&secret).unwrap());
        assert_eq!(
            root_password_to_start_under(redis, Some(&cached), &key).unwrap(),
            Some(secret)
        );
    }

    /// Memcached is the one engine here with no authentication, and the panel
    /// says so rather than implying otherwise: its only mechanism is SASL,
    /// which needs a build the official image does not ship. This test is what
    /// stops a *second* engine quietly joining it — every other recipe has to
    /// give its password a way in.
    #[test]
    fn only_memcached_runs_without_authentication_and_it_says_so() {
        for (slug, recipe) in RECIPES {
            match recipe.credential {
                Credential::Unauthenticated => assert_eq!(
                    *slug, "memcached",
                    "{slug} would run with no authentication on a shared host"
                ),
                Credential::Env { variable } => assert!(!variable.is_empty(), "{slug}"),
                Credential::ConfigFile { mount } => assert!(
                    mount.starts_with('/'),
                    "{slug} names no configuration file: {mount}"
                ),
            }
        }
    }

    /// A container the panel cannot log in to is a fact the operator has to be
    /// told, with the fix that applies to *their* case. A cache installed
    /// before this existed keeps running unauthenticated until it is installed
    /// again — nothing here is retroactive — and Memcached cannot be fixed at
    /// all. One badge for both would leave an operator either doing nothing
    /// about the first or waiting for a fix to the second.
    #[test]
    fn a_container_with_no_password_says_so_and_says_what_to_do() {
        // What an upgrade finds on disk: a Redis recorded before caches had
        // passwords.
        let mut legacy = record("unihelm-redis-7", "redis", 6379);
        legacy.root_password_sealed = None;
        let note = authentication_note(&legacy).expect("an unauthenticated cache must say so");
        assert!(note.contains("install"), "{note}");
        assert!(note.contains("redis"), "{note}");

        // Memcached's note may not tell anybody to reinstall: that fixes
        // nothing, and sending an operator round that loop is its own lie.
        let mut memcached = record("unihelm-memcached-1.6", "memcached", 11211);
        memcached.root_password_sealed = None;
        let note = authentication_note(&memcached).expect("memcached has no password");
        assert!(note.contains("SASL"), "{note}");
        assert!(
            !note.contains("install"),
            "reinstalling memcached changes nothing: {note}"
        );

        // And an engine that does require one is not warned about.
        let mut protected = record("unihelm-mariadb-11.8", "mariadb", 3306);
        protected.root_password_sealed = Some("sealed".into());
        assert_eq!(authentication_note(&protected), None);
    }

    /// `db.create` connects to a port, and the record is where that port lives.
    /// Where two versions run, the one holding the engine's own default port is
    /// the one an operator typing `mysql` on this server would have reached —
    /// and it is the one with the data, since it was there first.
    #[test]
    fn a_caller_that_names_no_version_gets_the_engine_on_the_default_port() {
        let mut registry = EngineRegistry::new();
        // Inserted newest-first, and the map is ordered by name, so neither
        // insertion order nor alphabetical order can be what picks the answer.
        registry.insert(
            "unihelm-mariadb-11.4".into(),
            record("unihelm-mariadb-11.4", "mariadb", 3307),
        );
        registry.insert(
            "unihelm-mariadb-11.8".into(),
            record("unihelm-mariadb-11.8", "mariadb", 3306),
        );
        registry.insert(
            "unihelm-postgres-17".into(),
            record("unihelm-postgres-17", "postgres", 5432),
        );

        let chosen = primary_record(&registry, &["mariadb"]).expect("mariadb is installed");
        assert_eq!(chosen.host_port, 3306);
        assert_eq!(chosen.container, "unihelm-mariadb-11.8");
        // And an engine nobody installed is not somebody else's engine.
        assert!(primary_record(&registry, &["redis"]).is_none());

        // `db.create` names a protocol, not a product: MariaDB and MySQL are
        // one `DbEngine`, so both slugs are asked at once and the same
        // lowest-port rule decides between them.
        registry.insert(
            "unihelm-mysql-8.0".into(),
            record("unihelm-mysql-8.0", "mysql", 3308),
        );
        let family = primary_record(&registry, &["mariadb", "mysql"]).expect("one of the two");
        assert_eq!(family.container, "unihelm-mariadb-11.8");
        // And a machine carrying only the other one still resolves.
        let mut only_mysql = EngineRegistry::new();
        only_mysql.insert(
            "unihelm-mysql-8.0".into(),
            record("unihelm-mysql-8.0", "mysql", 3306),
        );
        assert_eq!(
            primary_record(&only_mysql, &["mariadb", "mysql"])
                .expect("MySQL is what is installed")
                .slug,
            "mysql"
        );
    }

    /// The one that had to be caught: an engine removed with its data kept
    /// keeps its record, and its port is in applications' connection strings.
    /// Reinstalling it read its own record as "3306 is taken" and moved it to
    /// 3307, so every client configured for the engine stopped being able to
    /// reach it while the panel reported it healthy.
    #[test]
    fn reinstalling_an_engine_lands_back_on_the_port_it_was_on() {
        let mut registry = EngineRegistry::new();
        registry.insert(
            "unihelm-mariadb-11.8".into(),
            record("unihelm-mariadb-11.8", "mariadb", 3306),
        );

        assert_eq!(
            choose_host_port(
                recipe("mariadb").unwrap(),
                &registry,
                "unihelm-mariadb-11.8",
                &|_| true
            )
            .unwrap(),
            3306
        );

        // A second version is still a second port: only the container's *own*
        // record stops holding a port against it.
        assert_eq!(
            choose_host_port(
                recipe("mariadb").unwrap(),
                &registry,
                "unihelm-mariadb-11.4",
                &|_| true
            )
            .unwrap(),
            3307
        );
    }

    /// Unless something else has taken it in the meantime, in which case the
    /// engine moves rather than failing to bind — and the record is rewritten,
    /// so the panel still knows where it is.
    #[test]
    fn an_engine_whose_old_port_was_taken_while_it_was_away_moves() {
        let mut registry = EngineRegistry::new();
        registry.insert(
            "unihelm-mariadb-11.8".into(),
            record("unihelm-mariadb-11.8", "mariadb", 3306),
        );
        let taken = |port: u16| port != 3306;
        assert_eq!(
            choose_host_port(
                recipe("mariadb").unwrap(),
                &registry,
                "unihelm-mariadb-11.8",
                &taken
            )
            .unwrap(),
            3307
        );
    }

    /// The row an engine claims is the container's, never the host install's.
    ///
    /// Sharing `mariadb` with the host meant three things at once: installing
    /// 11.4 claimed the row 11.8 reports itself in, so the two could not
    /// install at once and a failed 11.4 put a `failed` mark on a machine whose
    /// 11.8 was serving; and a container install marked the host MariaDB
    /// installed, which is a sentence about apt packages that are not there.
    #[test]
    fn a_container_claims_its_own_row_and_not_the_host_installs() {
        let a = plan("mariadb", Some("11.8"));
        let b = plan("mariadb", Some("11.4"));

        assert_ne!(a.row_key(), b.row_key());
        assert_eq!(a.row_key(), "unihelm-mariadb-11.8");
        // The host's row for the same engine, which `stack.install` writes and
        // `stack.status` reads. Neither version may collide with it.
        assert_eq!(a.host_row_key(), "mariadb");
        assert_ne!(a.row_key(), a.host_row_key());
        assert_ne!(b.row_key(), b.host_row_key());

        // And it holds for every engine, including the ones catalogued without
        // a version, where the host key is the bare slug.
        for (slug, _) in RECIPES {
            let resolved = plan(slug, None);
            assert_ne!(
                resolved.row_key(),
                resolved.host_row_key(),
                "{slug} would claim the host install's row"
            );
        }
    }

    /// And the host install of the same engine is a collision the port
    /// allocator cannot see. It asks who holds 3306 *now*; a host MariaDB that
    /// is installed but not currently listening holds nothing, the container
    /// takes the port, and the failure arrives at the next boot as the engine
    /// that was working reporting itself broken.
    #[tokio::test]
    async fn an_engine_the_host_already_has_is_refused_rather_than_started_twice() {
        let (reg, admin, _) = crate::registry::testing::registry().await;
        let ctx = OpContext::new(
            reg.services().clone(),
            crate::registry::testing::auth_for(admin, unihelm_core::Role::Admin),
        );
        let target = plan("mariadb", Some("11.8"));

        // A machine with no MariaDB on it: nothing to collide with.
        refuse_when_the_host_already_runs_this_engine(&ctx, &target)
            .await
            .expect("there is no host install");

        let db = ctx.db();
        db.claim_component("mariadb", ComponentStatus::Installing, "task")
            .await
            .unwrap();
        db.component_installed("mariadb", Some("10.11"))
            .await
            .unwrap();

        let err = refuse_when_the_host_already_runs_this_engine(&ctx, &target)
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::Conflict);
        // What is already there, and what to do about it.
        assert!(err.detail.contains("10.11"), "{}", err.detail);
        assert!(err.detail.contains("3306"), "{}", err.detail);
        assert!(
            err.detail.contains("Remove the host install"),
            "{}",
            err.detail
        );

        // Removing the host install clears the way.
        db.component_removed("mariadb").await.unwrap();
        refuse_when_the_host_already_runs_this_engine(&ctx, &target)
            .await
            .expect("the host install is gone");

        // And the container's own row is not the host's, so an engine already
        // installed this way is not a collision with itself — which is what
        // reading `row_key` here instead would have made every reinstall.
        db.claim_component(target.row_key(), ComponentStatus::Installing, "task")
            .await
            .unwrap();
        db.component_installed(target.row_key(), Some("11.8"))
            .await
            .unwrap();
        refuse_when_the_host_already_runs_this_engine(&ctx, &target)
            .await
            .expect("its own row says nothing about the host");
    }

    /// A connection carries a password, so its `Debug` must not.
    #[test]
    fn a_connection_does_not_print_its_password() {
        let conn = RootConnection {
            container: "unihelm-mariadb-11.8".into(),
            client: "mariadb",
            host: LOOPBACK,
            port: 3306,
            host_port: 3307,
            user: "root".into(),
            password: "hunter2-super-secret".into(),
        };
        let rendered = format!("{conn:?}");
        assert!(!rendered.contains("hunter2"), "{rendered}");
        assert!(rendered.contains("3306"));
    }

    /// The credential must not reach an argv, and this is where that is
    /// decided: `/proc/<pid>/cmdline` is readable by every local account on the
    /// machine, so a password on the `docker exec` line is readable by every
    /// tenant shell on a shared host — which is the boundary sealing it exists
    /// to hold.
    #[test]
    fn the_root_password_is_named_on_the_exec_line_and_never_carried_on_it() {
        let conn = RootConnection {
            container: "unihelm-mariadb-11.8".into(),
            client: "mariadb",
            host: LOOPBACK,
            port: 3306,
            host_port: 3306,
            user: "root".into(),
            password: "hunter2-super-secret".into(),
        };
        let argv = conn.exec_argv(&["MYSQL_PWD"], vec!["mariadb".into(), "--batch".into()]);
        assert!(
            !argv.iter().any(|a| a.contains("hunter2")),
            "the password reached the command line: {argv:?}"
        );
        // `--env NAME` with no `=value` is Docker's own form for "take it from
        // my environment"; `--env NAME=value` is the leak.
        let named = argv
            .windows(2)
            .any(|w| w[0] == "--env" && w[1] == "MYSQL_PWD");
        assert!(named, "{argv:?}");
        // Without `-i` Docker hands the client `/dev/null` and every batch on
        // stdin is silently empty.
        assert!(argv.contains(&"-i".to_string()), "{argv:?}");
        assert!(
            argv.contains(&"unihelm-mariadb-11.8".to_string()),
            "{argv:?}"
        );
    }

    /// An install reads the registry, then pulls an image, which is minutes on
    /// a slow link. Writing that stale copy back at the end would erase every
    /// record another install wrote in the meantime — and a record is the only
    /// key to the data in that engine's volume, so what is lost is a database
    /// rather than a line of bookkeeping.
    #[tokio::test]
    async fn recording_an_engine_keeps_what_another_install_wrote_meanwhile() {
        let db = Db::open_memory().await.unwrap();

        // What this install saw before it started pulling: nothing at all.
        assert!(registry(&db).await.unwrap().is_empty());

        // Another install finishes while that pull is still running.
        record_engine(&db, record("unihelm-redis-7", "redis", 6379))
            .await
            .unwrap();

        // And then this one lands.
        record_engine(&db, record("unihelm-mariadb-11.8", "mariadb", 3306))
            .await
            .unwrap();

        let after = registry(&db).await.unwrap();
        assert!(
            after.contains_key("unihelm-redis-7"),
            "the other install's credential was erased: {:?}",
            after.keys().collect::<Vec<_>>()
        );
        assert!(after.contains_key("unihelm-mariadb-11.8"));

        // And a removal takes its own record and nobody else's.
        forget_engine(&db, "unihelm-mariadb-11.8").await.unwrap();
        let after = registry(&db).await.unwrap();
        assert_eq!(after.len(), 1);
        assert!(after.contains_key("unihelm-redis-7"));
    }

    /// A document that will not parse must not read as "no engines installed".
    /// The next install would write a fresh map over it, and every root
    /// credential on the machine would go with it — which is access to every
    /// database on the server, gone, with the data still sitting there.
    #[tokio::test]
    async fn an_unreadable_registry_is_an_error_and_never_an_empty_one() {
        let db = Db::open_memory().await.unwrap();
        db.set_setting(ENGINES_SETTING, &"not a registry at all")
            .await
            .unwrap();

        let err = registry(&db).await.unwrap_err();
        assert!(
            err.detail.contains("backup"),
            "the refusal has to say what to do: {}",
            err.detail
        );

        // And nothing in the read path wrote over it on the way out.
        assert_eq!(
            db.get_setting::<String>(ENGINES_SETTING).await.unwrap(),
            Some("not a registry at all".to_string())
        );
    }

    /// A budget that only just beat the host installer's would not be worth
    /// having. The reason it is longer is a first boot that initialises an
    /// empty data directory, and timing out early does not merely retry: it
    /// marks the install failed on a machine where the engine came up fine a
    /// moment later.
    #[test]
    fn an_engine_is_given_meaningfully_longer_to_start_than_a_host_package() {
        assert!(
            READY_BUDGET >= Duration::from_secs(150),
            "{READY_BUDGET:?} is not long enough for a first boot to initialise"
        );
    }

    /// And the image has to arrive before any of that can start. A pull killed
    /// for being slow fails the install having thrown away the layers it had
    /// already fetched, so the retry begins again at the top of the same link.
    #[test]
    fn an_image_is_given_time_to_arrive_over_the_link_a_cheap_vps_has() {
        assert!(
            PULL_BUDGET >= Duration::from_secs(600),
            "{PULL_BUDGET:?} is not long enough for a database image on a slow uplink"
        );
    }

    /// The registry round-trips through the settings document it lives in.
    #[test]
    fn the_registry_survives_being_stored_as_json() {
        let mut registry = EngineRegistry::new();
        registry.insert(
            "unihelm-mariadb-11.8".into(),
            record("unihelm-mariadb-11.8", "mariadb", 3306),
        );
        let json = serde_json::to_string(&registry).unwrap();
        let back: EngineRegistry = serde_json::from_str(&json).unwrap();
        assert_eq!(back["unihelm-mariadb-11.8"].host_port, 3306);
        assert_eq!(
            back["unihelm-mariadb-11.8"].volume.as_deref(),
            Some("unihelm-mariadb-11.8-data")
        );
    }
}
