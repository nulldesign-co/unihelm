//! A short, curated list of containers people actually run on a hosting box.
//!
//! [`crate::docker`]'s create form is deliberately a form and not `docker run`,
//! and that is right — but it left starting anything at all as an exam. The
//! operator had to already know the image, the tag, the port the server listens
//! on, the path its data lives at and the environment it needs, and type all of
//! it into empty boxes. This is the answer sheet: pick a template, name it,
//! press the button.
//!
//! ## Why it is compiled in
//!
//! **Exactly the reason [`crate::catalogue`] is, and it is the same boundary.**
//! A template names an image, and an image is what runs as root on this machine
//! a moment later. Compiled in, the list ships inside a signed release and
//! changes by pull request. As `/etc/unihelm/templates.toml` it would be a
//! file, and every account, every stray `chmod` and every bug that could ever
//! write it would inherit "start this image with these mounts" on a box full of
//! other people's websites. The price is the same too, and it is real: a
//! template goes stale, and the only way to move a pin is a release. Keeping
//! these tags current is part of cutting one.
//!
//! This is *not* a second gate in front of `docker.create`. That operation
//! still takes any image reference an operator types, because a panel that
//! could only run five containers would not be a panel. The list is a shortcut
//! with the sharp edges already filed off, not a permission.
//!
//! ## The four things that had to be right
//!
//! 1. **Every tag exists.** A catalogue entry pointing at a tag that 404s is
//!    worse than no catalogue: the pull fails minutes in, and the operator has
//!    no way to tell a typo in the panel from a network they cannot reach. Each
//!    [`Template::tag`] below is a real published tag with a digest, pinned to
//!    an exact release rather than to `latest` — a tag that moves under a
//!    running server is how a restart becomes a major-version upgrade nobody
//!    asked for, which is the same rule [`crate::engine`] pins its images by.
//! 2. **A template that needs a password generates one, and never ships a
//!    default.** `admin`/`admin` in a catalogue is a published credential for
//!    every install of this panel. Where the image takes an administrative
//!    secret in its environment, [`Prepare`] mints one per call from a CSPRNG —
//!    the same alphabet and length [`crate::engine`] uses. Unlike an engine, the
//!    panel keeps **no copy**: the container is the operator's own, so the
//!    secret is handed to them once, in the draft, and saying that out loud is
//!    part of the draft.
//! 3. **A template says what it will expose.** 0.7.2 stopped `docker.create`
//!    publishing on every interface by default, because Docker's DNAT rule is
//!    evaluated ahead of the chain the Firewall page describes and the panel was
//!    reporting a world-reachable port as closed. Nothing here opts out of that:
//!    every [`DraftPort`] leaves `public` false, and each one carries the
//!    [`TemplatePort::purpose`] that lets the page say what is behind it.
//! 4. **The panel does not pretend a first run is secure when it is not.** Most
//!    of these images have no account at all until somebody opens them: the
//!    first browser to arrive sets the administrator password. On loopback that
//!    is contained; published, it is a giveaway. [`FirstRun`] makes every
//!    template answer which of the two it is, so a new entry cannot be added
//!    without saying.
//!
//! ## What is deliberately not here
//!
//! Anything needing a flag [`crate::docker::CreateInput`] has no field for. A
//! container that wants the daemon socket, a bind mount or its own `--command`
//! is not a template this panel can honestly offer, because the operation
//! underneath would refuse it — so Portainer, Watchtower and MinIO are absent
//! rather than present and broken. Databases and caches are absent too: those
//! are [`crate::engine`]'s, which knows how to seal their credentials and how
//! `db.create` reaches them, and a second way to start a MariaDB would be two
//! panels disagreeing about one machine.

use rand::Rng;
use serde::{Deserialize, Serialize};
use unihelm_core::{ErrorCode, Permission, Result, UnihelmError};

use crate::registry::{Execution, OpContext, TypedOperation};

/// The interface a template's ports are published on.
///
/// Named here as well as in [`crate::docker`] because it is what the draft
/// *says*, and the sentence an operator reads has to carry the address they
/// will actually type into a browser.
const LOOPBACK: &str = "127.0.0.1";

/// How far past its preferred host port a template may be moved.
///
/// Ten, matching [`crate::engine`]'s spare range, and for the same reason: far
/// enough that a busy box does not run out, short enough that the panel cannot
/// wander into a range somebody else's service lives in.
const PORT_SPARE: u16 = 9;

// ---------------------------------------------------------------------------
// What a template is
// ---------------------------------------------------------------------------

/// How a value reaches the container's environment.
///
/// An enum rather than an optional string, for the reason [`crate::engine`]'s
/// [`Credential`](crate::engine) is one: "no value here" would mean both "the
/// image wants nothing" and "nobody has wired a secret up yet", and the second
/// of those is how a catalogue ends up shipping `admin`/`admin`. A new entry
/// has to say which it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EnvValue {
    /// Part of the recipe and not a secret: a database driver, a uid, a switch.
    Fixed(&'static str),
    /// Minted per [`Prepare`] call from a CSPRNG and shown to the operator once.
    Generated,
}

/// One port a template publishes, and what answers on it.
#[derive(Debug, Clone, Copy)]
struct TemplatePort {
    /// The host side the draft asks for first. Moved when something holds it.
    host: u16,
    /// What the server inside the image listens on.
    container: u16,
    /// What is behind it, in words a page can print beside the number.
    purpose: &'static str,
}

/// One named volume a template mounts.
#[derive(Debug, Clone, Copy)]
struct TemplateVolume {
    /// Appended to the container's name to make the volume's, so two copies of
    /// a template never share a disk — the same derivation
    /// [`crate::engine`] uses for its data volumes.
    suffix: &'static str,
    /// Where it appears inside the container. Absolute, and never a host path:
    /// `docker.create` takes named volumes only.
    path: &'static str,
    /// What is in it, which is what an operator needs before deleting it.
    holds: &'static str,
}

/// Who can sign in the moment a container from this template starts.
///
/// The question every one of these images answers differently and none of them
/// answers on its tin. A template cannot be added without picking a variant.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FirstRun {
    /// There is no account yet: the first browser to reach it makes one.
    ///
    /// Safe behind loopback, where the only things that can reach it are on
    /// this server. A giveaway the moment the port is opened, which is why the
    /// draft says so beside the box that opens it.
    Wizard,
    /// The administrator already exists, under this account and the password
    /// generated into this variable.
    Credential {
        user: &'static str,
        /// The [`EnvValue::Generated`] entry the password is in, so the page can
        /// point at the line the operator has to copy.
        variable: &'static str,
    },
}

/// Everything the panel knows about running one curated container.
#[derive(Debug, Clone, Copy)]
struct Template {
    /// Stable, lowercase, hyphenated. It is the API name and the CLI argument.
    id: &'static str,
    display_name: &'static str,
    /// One sentence: what it is for, not why it is good.
    summary: &'static str,
    /// The image's repository, exactly as Docker resolves it.
    repository: &'static str,
    /// An exact published release. Never `latest`, never a moving series.
    tag: &'static str,
    /// The container name the draft offers. The operator may change it.
    suggested_name: &'static str,
    ports: &'static [TemplatePort],
    volumes: &'static [TemplateVolume],
    env: &'static [(&'static str, EnvValue)],
    first_run: FirstRun,
    /// What the operator does next, in the order they do it.
    after_start: &'static str,
}

impl Template {
    fn image(&self) -> String {
        format!("{}:{}", self.repository, self.tag)
    }
}

/// Every container this panel offers as a template.
///
/// Five, and five is the point: a hundred entries nobody verified would be a
/// list of tags that will 404 by next year. Each tag below was checked against
/// the registry and resolves to a published multi-architecture digest, and each
/// image starts correctly under [`crate::docker::CreateInput`] — no command, no
/// bind mount, no daemon socket, no second container to talk to.
const TEMPLATES: &[Template] = &[
    Template {
        id: "uptime-kuma",
        display_name: "Uptime Kuma",
        summary: "Watches sites and services and tells you when one stops answering.",
        repository: "louislam/uptime-kuma",
        tag: "2.5.3",
        suggested_name: "uptime-kuma",
        ports: &[TemplatePort {
            host: 3001,
            container: 3001,
            purpose: "the dashboard",
        }],
        volumes: &[TemplateVolume {
            suffix: "data",
            path: "/app/data",
            holds: "every monitor, its history and the login accounts",
        }],
        // Nothing to set: the image needs no configuration to start, and an
        // environment variable here would be one the operator could not undo
        // without recreating the container.
        env: &[],
        first_run: FirstRun::Wizard,
        after_start: "Open it and create the administrator account. Until you do, anyone who can reach \
             the port can create it instead.",
    },
    Template {
        id: "gitea",
        display_name: "Gitea",
        summary: "A self-hosted Git service: repositories, issues and pull requests.",
        repository: "gitea/gitea",
        tag: "1.27.3",
        suggested_name: "gitea",
        ports: &[TemplatePort {
            host: 3000,
            container: 3000,
            purpose: "the web interface",
        }],
        volumes: &[TemplateVolume {
            suffix: "data",
            path: "/data",
            holds: "every repository, the database and the configuration",
        }],
        // SQLite by name rather than by default. Gitea's installer offers
        // MySQL and PostgreSQL too, and a template that left the choice to the
        // installer page would be a template that sometimes needs a database
        // server this draft never mentioned.
        env: &[
            ("GITEA__database__DB_TYPE", EnvValue::Fixed("sqlite3")),
            ("USER_UID", EnvValue::Fixed("1000")),
            ("USER_GID", EnvValue::Fixed("1000")),
        ],
        first_run: FirstRun::Wizard,
        after_start: "Open it, accept the settings on the install page and create the administrator \
             account. Git over SSH needs a second published port, which this draft does not \
             ask for.",
    },
    Template {
        id: "vaultwarden",
        display_name: "Vaultwarden",
        summary: "A password manager that Bitwarden's own apps and browser extensions talk to.",
        repository: "vaultwarden/server",
        tag: "1.37.2",
        suggested_name: "vaultwarden",
        ports: &[TemplatePort {
            host: 8081,
            container: 80,
            purpose: "the web vault and the API the apps use",
        }],
        volumes: &[TemplateVolume {
            suffix: "data",
            path: "/data",
            holds: "every vault, its attachments and the encryption keys",
        }],
        // Sign-ups closed and an administration token generated, which is the
        // pair that makes this safe to start. Open sign-ups behind a port
        // somebody later publishes is a stranger's account in the operator's
        // password manager; a closed instance with no token is one nobody can
        // ever get into. The token is a generated 32-character secret in plain
        // text: the image also accepts an Argon2 hash of one, and the plain
        // form costs a line in its log saying so, but hashing here would mean
        // the operator never sees the value the panel does not keep.
        env: &[
            ("SIGNUPS_ALLOWED", EnvValue::Fixed("false")),
            ("ADMIN_TOKEN", EnvValue::Generated),
        ],
        first_run: FirstRun::Credential {
            user: "the admin page at /admin",
            variable: "ADMIN_TOKEN",
        },
        after_start: "Open /admin, sign in with the generated token and invite your own account — \
             sign-ups are closed, so nobody else can register.",
    },
    Template {
        id: "grafana",
        display_name: "Grafana",
        summary: "Dashboards and alerts over a metrics or log store you already run.",
        repository: "grafana/grafana",
        tag: "13.2.1",
        suggested_name: "grafana",
        ports: &[TemplatePort {
            host: 3002,
            container: 3000,
            purpose: "the web interface",
        }],
        volumes: &[TemplateVolume {
            suffix: "data",
            path: "/var/lib/grafana",
            holds: "every dashboard, data source and user",
        }],
        // The one entry here that would otherwise ship a published credential:
        // Grafana's own default is `admin`/`admin`, and an operator who never
        // changes it has a dashboard anybody can edit.
        env: &[
            ("GF_SECURITY_ADMIN_USER", EnvValue::Fixed("admin")),
            ("GF_SECURITY_ADMIN_PASSWORD", EnvValue::Generated),
        ],
        first_run: FirstRun::Credential {
            user: "admin",
            variable: "GF_SECURITY_ADMIN_PASSWORD",
        },
        after_start: "Sign in as admin with the generated password, then add a data source. Changing \
             the password inside Grafana leaves this variable behind: the stored password \
             wins from then on.",
    },
    Template {
        id: "nextcloud",
        display_name: "Nextcloud",
        summary: "File sync and sharing, with calendars and contacts on top.",
        repository: "nextcloud",
        tag: "34.0.3-apache",
        suggested_name: "nextcloud",
        ports: &[TemplatePort {
            host: 8082,
            container: 80,
            purpose: "the web interface and the sync clients",
        }],
        volumes: &[TemplateVolume {
            suffix: "data",
            path: "/var/www/html",
            holds: "every file, the database and the installed apps",
        }],
        // SQLite, which the image sets up on its own when no database is
        // named. Fine for a handful of people; a busy instance wants MariaDB or
        // PostgreSQL from the Stack page, and moving it later is Nextcloud's
        // own `occ db:convert-type` rather than anything this panel does.
        env: &[("SQLITE_DATABASE", EnvValue::Fixed("nextcloud"))],
        first_run: FirstRun::Wizard,
        after_start: "Open it and create the administrator account on the setup page. It stores its \
             files in SQLite, which suits a few users; point it at a database engine before \
             it grows past that.",
    },
];

fn template(id: &str) -> Option<&'static Template> {
    TEMPLATES.iter().find(|t| t.id == id)
}

// ---------------------------------------------------------------------------
// `docker.template.list`
// ---------------------------------------------------------------------------

/// What one template looks like on the wire, before anything is generated.
///
/// No secret in it and no host port decided: this is the page an operator
/// browses, and both of those are questions [`Prepare`] answers about the
/// machine at the moment they choose.
#[derive(Debug, Serialize)]
pub struct TemplateView {
    pub id: String,
    pub display_name: String,
    pub summary: String,
    /// `grafana/grafana:13.2.1` — repository and pinned tag, as Docker takes it.
    pub image: String,
    pub suggested_name: String,
    pub ports: Vec<PortView>,
    pub volumes: Vec<VolumeView>,
    pub env: Vec<EnvView>,
    pub first_run: FirstRun,
    pub after_start: String,
    /// True where at least one variable is generated, so the page can say the
    /// panel keeps no copy before the operator commits to anything.
    pub generates_secret: bool,
}

#[derive(Debug, Serialize)]
pub struct PortView {
    /// What the draft will ask for, before the machine is consulted.
    pub host: u16,
    pub container: u16,
    pub purpose: String,
}

#[derive(Debug, Serialize)]
pub struct VolumeView {
    pub path: String,
    pub holds: String,
}

/// One environment entry as the catalogue describes it.
///
/// `value` is `None` for a generated one — not an empty string, which reads as
/// "set to nothing" beside a variable whose whole job is to be a password.
#[derive(Debug, Serialize)]
pub struct EnvView {
    pub key: String,
    pub value: Option<String>,
    pub generated: bool,
}

#[derive(Debug, Default, Deserialize)]
pub struct ListInput {}

#[derive(Debug, Serialize)]
pub struct ListOutput {
    pub templates: Vec<TemplateView>,
}

/// `docker.template.list` — the curated catalogue, exactly as compiled in.
pub struct List;

#[async_trait::async_trait]
impl TypedOperation for List {
    type Input = ListInput;
    type Output = ListOutput;

    const NAME: &'static str = "docker.template.list";
    // A constant, and one that says nothing about this machine. Reading it is
    // the same privilege as reading the Docker page it appears on.
    const PERMISSION: Permission = Permission::ServerRead;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, _ctx: &OpContext, _input: Self::Input) -> Result<Self::Output> {
        Ok(ListOutput {
            templates: TEMPLATES.iter().map(view).collect(),
        })
    }
}

fn view(t: &'static Template) -> TemplateView {
    TemplateView {
        id: t.id.to_string(),
        display_name: t.display_name.to_string(),
        summary: t.summary.to_string(),
        image: t.image(),
        suggested_name: t.suggested_name.to_string(),
        ports: t
            .ports
            .iter()
            .map(|p| PortView {
                host: p.host,
                container: p.container,
                purpose: p.purpose.to_string(),
            })
            .collect(),
        volumes: t
            .volumes
            .iter()
            .map(|v| VolumeView {
                path: v.path.to_string(),
                holds: v.holds.to_string(),
            })
            .collect(),
        env: t
            .env
            .iter()
            .map(|(key, value)| EnvView {
                key: (*key).to_string(),
                value: match value {
                    EnvValue::Fixed(v) => Some((*v).to_string()),
                    EnvValue::Generated => None,
                },
                generated: matches!(value, EnvValue::Generated),
            })
            .collect(),
        first_run: t.first_run,
        after_start: t.after_start.to_string(),
        generates_secret: t.env.iter().any(|(_, v)| matches!(v, EnvValue::Generated)),
    }
}

// ---------------------------------------------------------------------------
// `docker.template.prepare`
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct PrepareInput {
    /// The template id, as `docker.template.list` prints it.
    pub template: String,
    /// What to call the container. The template's own suggestion otherwise.
    #[serde(default)]
    pub name: Option<String>,
}

/// One published port in a draft, in the shape `docker.create` takes.
///
/// `public` is here and is always false. It could have been left out and
/// defaulted, and that is exactly what makes it worth carrying: the field's
/// absence used to be the bug — every container the panel created answered the
/// internet — so a template states the answer rather than inheriting it.
#[derive(Debug, Clone, Serialize)]
pub struct DraftPort {
    pub host: u16,
    pub container: u16,
    pub udp: bool,
    pub public: bool,
    /// What is behind the port, so the page can say it beside the number.
    pub purpose: String,
    /// The address this port answers on while `public` is false.
    pub address: String,
}

/// One environment variable in a draft, with generated values filled in.
#[derive(Clone, Serialize)]
pub struct DraftEnv {
    pub key: String,
    pub value: String,
    /// True where the panel minted this value and kept no copy of it.
    pub generated: bool,
}

/// Redacted by hand, the way [`crate::engine::EngineRecord`] is: the route a
/// generated password takes into a log is somebody adding `?draft` to a tracing
/// call, and this one exists only in flight.
impl std::fmt::Debug for DraftEnv {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DraftEnv")
            .field("key", &self.key)
            .field(
                "value",
                if self.generated {
                    &"<generated>"
                } else {
                    &self.value
                },
            )
            .finish()
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct DraftVolume {
    /// A Docker volume name, derived from the container's. Never a path.
    pub volume: String,
    pub path: String,
    pub holds: String,
}

/// A filled-in template: everything `docker.create` needs, and the sentences
/// that make it safe to press the button.
#[derive(Debug, Serialize)]
pub struct PrepareOutput {
    pub template: String,
    pub display_name: String,
    pub image: String,
    pub name: String,
    pub ports: Vec<DraftPort>,
    pub env: Vec<DraftEnv>,
    pub volumes: Vec<DraftVolume>,
    /// `unless-stopped` for every template: these are things an operator wants
    /// back after a reboot, and a container that quietly does not come back is
    /// a monitoring system that stops monitoring.
    pub restart: String,
    pub first_run: FirstRun,
    pub after_start: String,
    /// Where a preferred host port was already taken, one line per move naming
    /// the container that holds it. Empty when every port was free.
    pub port_notes: Vec<String>,
}

/// `docker.template.prepare` — one template, filled in for this machine.
pub struct Prepare;

#[async_trait::async_trait]
impl TypedOperation for Prepare {
    type Input = PrepareInput;
    type Output = PrepareOutput;

    const NAME: &'static str = "docker.template.prepare";
    // `server_manage`, not `server_read`, though nothing on this server changes.
    // The draft carries a credential the panel does not keep a copy of, and the
    // only thing it is for is `docker.create` — which needs this permission. A
    // reader who could mint one could not use it, so handing them one would be
    // giving away a secret for nothing.
    const PERMISSION: Permission = Permission::ServerManage;
    // No pull and no start: this reads one `docker ps` and answers. Creating
    // the container is `docker.create`, which is the task.
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, _ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let found = template(&input.template).ok_or_else(|| unknown_template(&input.template))?;

        let name = match input.name.as_deref().map(str::trim) {
            Some(n) if !n.is_empty() => n.to_string(),
            _ => found.suggested_name.to_string(),
        };
        // Parsed rather than trusted, so a draft can never carry a name that
        // `docker.create` will refuse — the refusal would arrive after the
        // operator had already copied a generated password out of the form.
        let name = crate::docker::ContainerRef::parse(&name)?
            .as_str()
            .to_string();

        // What is already published, from Docker itself. An empty answer is "we
        // could not tell", not "nothing is published" — the same reading
        // `docker.create` gives it — so the preferred ports stand and the
        // create refuses by name if one of them is really held.
        let published = match unihelm_distro::exec::resolve_program("docker") {
            Ok(path) => crate::docker::published_ports(&path.to_string_lossy()).await,
            Err(_) => Vec::new(),
        };

        let mut ports = Vec::with_capacity(found.ports.len());
        let mut port_notes = Vec::new();
        for p in found.ports {
            let (host, holder) = free_host_port(p.host, &published, &ports);
            if let Some(holder) = holder {
                port_notes.push(format!(
                    "{} is already published by `{holder}`, so this draft uses {host} instead. \
                     {} still listens on {} inside the container.",
                    p.host, found.display_name, p.container
                ));
            }
            ports.push(DraftPort {
                host,
                container: p.container,
                udp: false,
                // Never true, and never derived from anything a caller sent.
                // See the type's own note.
                public: false,
                purpose: p.purpose.to_string(),
                address: format!("{LOOPBACK}:{host}"),
            });
        }

        Ok(PrepareOutput {
            template: found.id.to_string(),
            display_name: found.display_name.to_string(),
            image: found.image(),
            ports,
            volumes: found
                .volumes
                .iter()
                .map(|v| DraftVolume {
                    volume: format!("{name}-{}", v.suffix),
                    path: v.path.to_string(),
                    holds: v.holds.to_string(),
                })
                .collect(),
            name,
            env: found
                .env
                .iter()
                .map(|(key, value)| DraftEnv {
                    key: (*key).to_string(),
                    value: match value {
                        EnvValue::Fixed(v) => (*v).to_string(),
                        EnvValue::Generated => generate_secret(),
                    },
                    generated: matches!(value, EnvValue::Generated),
                })
                .collect(),
            restart: "unless-stopped".to_string(),
            first_run: found.first_run,
            after_start: found.after_start.to_string(),
            port_notes,
        })
    }
}

fn unknown_template(asked: &str) -> UnihelmError {
    UnihelmError::new(
        ErrorCode::NotFound,
        format!(
            "there is no container template called `{asked}`. The panel ships: {}. Anything \
             else is `docker.create` with the image typed in.",
            TEMPLATES
                .iter()
                .map(|t| t.id)
                .collect::<Vec<_>>()
                .join(", ")
        ),
    )
    .with_field("template")
}

/// The host port a draft asks for, and whoever pushed it off its first choice.
///
/// **Move, do not refuse.** A box already running something on 3000 is the
/// common case, not the exceptional one, and "3000 is taken" would leave the
/// operator doing arithmetic the panel could have done. Where the whole window
/// is held the preferred port comes back anyway: `docker.create`'s own
/// pre-flight refuses it by name a moment later, and that refusal is a better
/// answer than one invented here from a list that may be empty because Docker
/// did not reply.
fn free_host_port(
    preferred: u16,
    published: &[crate::docker::Published],
    already_drafted: &[DraftPort],
) -> (u16, Option<String>) {
    let taken = |port: u16| -> Option<String> {
        if let Some(held) = published.iter().find(|p| p.host == port && !p.udp) {
            return Some(held.container.clone());
        }
        // A template with two ports must not be handed the same number twice.
        already_drafted
            .iter()
            .find(|p| p.host == port)
            .map(|_| "this same draft".to_string())
    };

    let Some(holder) = taken(preferred) else {
        return (preferred, None);
    };
    for port in preferred.saturating_add(1)..=preferred.saturating_add(PORT_SPARE) {
        if taken(port).is_none() {
            return (port, Some(holder));
        }
    }
    (preferred, None)
}

/// A password nobody chose.
///
/// The alphabet and the length are [`crate::engine`]'s, deliberately: two
/// generators in one tree with different strengths is how the weaker one ends
/// up on the thing that mattered. 32 characters out of 62 is ~190 bits, which
/// is past anything an offline attack on a container's environment is worth.
fn generate_secret() -> String {
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
    use crate::docker::{CreateInput, Published};

    fn published(container: &str, host: u16) -> Published {
        Published {
            host,
            udp: false,
            container: container.to_string(),
        }
    }

    fn draft(template: &Template) -> PrepareOutput {
        // The operation's own body needs an `OpContext`; everything it decides
        // that a test cares about is in these two helpers, so they are called
        // directly and the assertions below stay free of a database.
        let mut ports = Vec::new();
        for p in template.ports {
            let (host, _) = free_host_port(p.host, &[], &ports);
            ports.push(DraftPort {
                host,
                container: p.container,
                udp: false,
                public: false,
                purpose: p.purpose.to_string(),
                address: format!("{LOOPBACK}:{host}"),
            });
        }
        PrepareOutput {
            template: template.id.to_string(),
            display_name: template.display_name.to_string(),
            image: template.image(),
            name: template.suggested_name.to_string(),
            ports,
            env: template
                .env
                .iter()
                .map(|(key, value)| DraftEnv {
                    key: (*key).to_string(),
                    value: match value {
                        EnvValue::Fixed(v) => (*v).to_string(),
                        EnvValue::Generated => generate_secret(),
                    },
                    generated: matches!(value, EnvValue::Generated),
                })
                .collect(),
            volumes: template
                .volumes
                .iter()
                .map(|v| DraftVolume {
                    volume: format!("{}-{}", template.suggested_name, v.suffix),
                    path: v.path.to_string(),
                    holds: v.holds.to_string(),
                })
                .collect(),
            restart: "unless-stopped".to_string(),
            first_run: template.first_run,
            after_start: template.after_start.to_string(),
            port_notes: Vec::new(),
        }
    }

    #[test]
    fn every_template_pins_an_exact_tag_and_never_a_moving_one() {
        for t in TEMPLATES {
            let tag = t.tag;
            assert!(
                !matches!(tag, "latest" | "stable" | "main" | "edge" | "nightly"),
                "{} points at `{tag}`, which moves under a running container",
                t.id
            );
            assert!(
                tag.contains('.'),
                "{} pins `{tag}`, which is a series and not a release: a patch \
                 published tomorrow changes what a restart runs",
                t.id
            );
        }
    }

    /// The catalogue is a boundary, so the shape of an entry has to be one
    /// `docker.create` will actually accept — a template that refuses at the
    /// operation is a catalogue entry that does not exist.
    #[test]
    fn every_template_is_a_container_docker_create_would_accept() {
        for t in TEMPLATES {
            let d = draft(t);
            let payload = serde_json::json!({
                "image": d.image,
                "name": d.name,
                "ports": d.ports.iter().map(|p| serde_json::json!({
                    "host": p.host, "container": p.container, "udp": p.udp, "public": p.public,
                })).collect::<Vec<_>>(),
                "env": d.env.iter().map(|e| serde_json::json!({
                    "key": e.key, "value": e.value,
                })).collect::<Vec<_>>(),
                "volumes": d.volumes.iter().map(|v| serde_json::json!({
                    "volume": v.volume, "path": v.path,
                })).collect::<Vec<_>>(),
                "restart": d.restart,
            });
            serde_json::from_value::<CreateInput>(payload)
                .unwrap_or_else(|e| panic!("{} is not a container docker.create takes: {e}", t.id));
        }
    }

    #[test]
    fn no_template_publishes_a_port_on_every_interface() {
        for t in TEMPLATES {
            for p in draft(t).ports {
                assert!(
                    !p.public,
                    "{} would publish {} on every interface, where Docker's own rule \
                     is evaluated before the firewall's",
                    t.id, p.host
                );
                assert_eq!(p.address, format!("127.0.0.1:{}", p.host));
            }
        }
    }

    /// The defect this catalogue would otherwise ship: Grafana's own default is
    /// `admin`/`admin`, and a template carrying it would publish one credential
    /// for every install of this panel.
    #[test]
    fn a_template_that_needs_a_password_generates_one_and_ships_no_default() {
        for t in TEMPLATES {
            if let FirstRun::Credential { variable, .. } = t.first_run {
                let entry = t
                    .env
                    .iter()
                    .find(|(key, _)| *key == variable)
                    .unwrap_or_else(|| panic!("{} names {variable} and never sets it", t.id));
                assert_eq!(
                    entry.1,
                    EnvValue::Generated,
                    "{}'s {variable} is a compiled-in value, which is a published password",
                    t.id
                );
            }
            // Any variable whose *name* says it holds a secret has to be
            // generated, whatever the entry meant. `GF_SECURITY_ADMIN_USER` is
            // a username and is rightly a constant; `GF_SECURITY_ADMIN_PASSWORD`
            // as a constant would be one password shared by every install of
            // this panel, and the difference between the two is one word in a
            // long line nobody reads twice.
            for (key, value) in t.env {
                let secret = ["PASSWORD", "TOKEN", "SECRET", "_KEY", "PASSWD"]
                    .iter()
                    .any(|needle| key.to_ascii_uppercase().contains(needle));
                if secret {
                    assert_eq!(
                        *value,
                        EnvValue::Generated,
                        "{} ships a compiled-in value in `{key}`, which is a published \
                         credential for every install of this panel",
                        t.id
                    );
                }
            }
        }
    }

    #[test]
    fn a_generated_value_is_different_every_time_and_never_empty() {
        let first = draft(&TEMPLATES[3]);
        let second = draft(&TEMPLATES[3]);
        let secret = |d: &PrepareOutput| {
            d.env
                .iter()
                .find(|e| e.generated)
                .map(|e| e.value.clone())
                .unwrap_or_default()
        };
        assert_eq!(secret(&first).len(), 32);
        assert_ne!(
            secret(&first),
            secret(&second),
            "two operators would share one password"
        );
    }

    /// `?draft` on a tracing call is how a credential reaches a log, which is
    /// the same reason `EngineRecord` redacts itself.
    #[test]
    fn a_generated_value_is_redacted_from_the_debug_rendering() {
        let d = draft(&TEMPLATES[3]);
        let rendered = format!("{d:?}");
        for e in &d.env {
            if e.generated {
                assert!(
                    !rendered.contains(&e.value),
                    "the generated {} is in a Debug rendering",
                    e.key
                );
            } else {
                assert!(rendered.contains(&e.value), "{} was redacted too", e.key);
            }
        }
    }

    #[test]
    fn a_preferred_port_already_published_moves_and_names_who_holds_it() {
        let held = vec![published("gitea", 3000), published("other", 3001)];
        let (port, holder) = free_host_port(3000, &held, &[]);
        assert_eq!(port, 3002);
        assert_eq!(holder.as_deref(), Some("gitea"));
    }

    #[test]
    fn a_free_preferred_port_is_left_exactly_where_the_template_put_it() {
        let (port, holder) = free_host_port(3001, &[published("gitea", 3000)], &[]);
        assert_eq!(port, 3001);
        assert_eq!(holder, None);
    }

    /// No answer from Docker is no knowledge. Inventing a different port here
    /// would put the operator on 3001 while 3000 was free, and would do it
    /// silently — `docker.create`'s own pre-flight is the honest refusal.
    #[test]
    fn a_window_with_nothing_free_falls_back_to_the_preferred_port() {
        let held: Vec<_> = (3000..=3009).map(|p| published("busy", p)).collect();
        let (port, holder) = free_host_port(3000, &held, &[]);
        assert_eq!(port, 3000);
        assert_eq!(holder, None);
    }

    #[test]
    fn every_template_names_a_volume_derived_from_the_container_name() {
        for t in TEMPLATES {
            for v in draft(t).volumes {
                assert!(
                    v.volume.starts_with(t.suggested_name),
                    "{} keeps its data in `{}`, which two copies would share",
                    t.id,
                    v.volume
                );
                assert!(v.path.starts_with('/') && !v.path.contains(".."));
            }
        }
    }

    #[test]
    fn an_unknown_template_is_refused_by_name_and_lists_the_ones_that_exist() {
        let err = unknown_template("portainer");
        assert_eq!(err.code, ErrorCode::NotFound);
        assert!(err.detail.contains("portainer"));
        for t in TEMPLATES {
            assert!(err.detail.contains(t.id), "{} is not offered", t.id);
        }
    }

    #[test]
    fn every_template_has_a_unique_id_and_a_sentence_saying_what_to_do_next() {
        let mut seen = std::collections::BTreeSet::new();
        for t in TEMPLATES {
            assert!(seen.insert(t.id), "two templates called {}", t.id);
            assert!(!t.summary.is_empty() && !t.after_start.is_empty());
            assert!(!t.ports.is_empty(), "{} publishes nothing", t.id);
        }
    }
}
