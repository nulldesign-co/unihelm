//! The Stack Manager (spec §11.1): installing what the catalogue offers.
//!
//! A base install ships the panel binary and nothing else. Everything the server
//! actually serves with arrives through here, on demand — which is what keeps a
//! fresh install small enough for a 1 GB VPS and makes security updates the
//! vendor's job rather than ours.
//!
//! What a caller may ask for lives in [`crate::catalogue`], not in an enum here.
//! This file used to offer exactly what it had variants for — four things, of
//! which only PHP could carry a version — so "which MariaDB?" and "where is
//! Redis?" were questions about the shape of a type rather than about packaging.
//! A request now names a slug and a version string, both are looked up in that
//! table, and a [`StackComponent`] cannot be built any other way. That keeps the
//! property the enum had: nothing a caller sends reaches a package manager
//! without appearing in the catalogue first.
//!
//! Resolution from there is per-family and lives in three functions:
//! [`StackComponent::repo`] (only when the version's source is `Vendor`),
//! [`StackComponent::packages`], and [`StackComponent::unit`] — which returns
//! `None` for a toolchain that installs binaries and nothing systemd could
//! start.

use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use unihelm_config::apply::ApplyRequest;
use unihelm_config::managed::ManagedFile;
use unihelm_config::paths;
use unihelm_core::{ErrorCode, Permission, PhpVersion, Result, UnihelmError};
use unihelm_db::ComponentStatus;
use unihelm_distro::fw::{PortRule, Proto};
use unihelm_distro::svc::{ManagedUnit, SvcAction, UnitName};
use unihelm_distro::{Cmd, Distro, Family, PackageName, ResolvedRepo};

use crate::catalogue;
use crate::php::{PhpExt, packages_for};
use crate::registry::{Execution, OpContext, TypedOperation};
use crate::services::{NoReload, SkipValidation};

/// A component the Stack Manager can install: one catalogue entry at one of its
/// versions.
///
/// The fields are `&'static` references into [`catalogue::CATALOGUE`] and are
/// private, so the only way to hold one is to have gone through
/// [`catalogue::version`]. The type is the proof that the lookup happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "ComponentWire", into = "ComponentWire")]
pub struct StackComponent {
    entry: &'static catalogue::Entry,
    version: &'static catalogue::Version,
}

/// The wire shape, unchanged from when this was an internally tagged enum:
/// `{"component": "php", "version": "8.3"}`, with the version optional for
/// anything an operator has no opinion about.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ComponentWire {
    component: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    version: Option<String>,
}

impl TryFrom<ComponentWire> for StackComponent {
    type Error = String;

    fn try_from(wire: ComponentWire) -> std::result::Result<Self, String> {
        // Deserialisation, not just the operation, is a place the refusal can
        // happen — an unknown slug should not survive parsing an IPC frame.
        Self::resolve(&wire.component, wire.version.as_deref()).map_err(|e| e.detail)
    }
}

impl From<StackComponent> for ComponentWire {
    fn from(c: StackComponent) -> Self {
        ComponentWire {
            component: c.entry.slug.to_string(),
            version: Some(c.version.version.to_string()),
        }
    }
}

impl StackComponent {
    /// The only constructor. An unknown slug or an unknown version is refused
    /// here, which is why no other function in this file has to wonder.
    pub fn resolve(slug: &str, version: Option<&str>) -> Result<Self> {
        let entry = catalogue::entry(slug).ok_or_else(|| {
            UnihelmError::new(
                ErrorCode::InvalidInput,
                format!(
                    "`{slug}` is not something this panel installs. It offers: {}",
                    catalogue::CATALOGUE
                        .iter()
                        .map(|e| e.slug)
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            )
        })?;

        let version = match version {
            Some(asked) => catalogue::version(slug, asked)
                .map(|(_, v)| v)
                .ok_or_else(|| {
                    UnihelmError::new(
                        ErrorCode::InvalidInput,
                        format!(
                            "{} has no version `{asked}`. It offers: {}",
                            entry.display_name,
                            entry
                                .versions
                                .iter()
                                .map(|v| v.version)
                                .collect::<Vec<_>>()
                                .join(", ")
                        ),
                    )
                })?,
            // Omitting the version is how the old wire shape asked for nginx or
            // MariaDB, and it still means "whatever you recommend".
            None => catalogue::default_version(slug)
                .ok_or_else(|| UnihelmError::internal(format!("{slug} offers no version")))?,
        };

        Ok(Self { entry, version })
    }

    pub fn entry(self) -> &'static catalogue::Entry {
        self.entry
    }

    pub fn version(self) -> &'static catalogue::Version {
        self.version
    }

    /// Stable key for the `stack_components` table.
    ///
    /// Versioned only where several versions can be installed at once, because
    /// there the version is part of the identity: `php8.3` and `php8.4` are two
    /// rows. Anything else replaces what is there, so the row is the engine and
    /// the version it happens to be at is a column.
    /// The catalogue entry's own slug, without the version.
    ///
    /// `slug()` carries the version for the entries that run several at once —
    /// `php8.3` is a row in `stack_components`, `php` is the thing it is a
    /// version of. Anything asking the catalogue a question wants the second.
    pub fn catalogue_slug(self) -> &'static str {
        self.entry.slug
    }

    pub fn slug(self) -> String {
        if self.entry.side_by_side {
            format!("{}{}", self.entry.slug, self.version.version)
        } else {
            self.entry.slug.to_string()
        }
    }

    /// What an operator reads in a task log or a confirmation dialogue.
    pub fn display_name(self) -> String {
        // `distro` and `stable` are not versions an operator picked; appending
        // them would produce "Redis distro". A version with a digit in it is one
        // somebody chose off the page, and belongs in the sentence.
        if self.version.version.bytes().any(|b| b.is_ascii_digit()) {
            format!("{} {}", self.entry.display_name, self.version.version)
        } else {
            self.entry.display_name.to_string()
        }
    }

    /// The leading integer of the version, for the repositories and package
    /// names that select a major that way (`postgresql-17`, NodeSource).
    fn major(self) -> Result<u32> {
        self.version
            .version
            .split('.')
            .next()
            .unwrap_or_default()
            .parse()
            .map_err(|_| {
                UnihelmError::internal(format!(
                    "{}'s version `{}` has no major to select a repository with",
                    self.entry.slug, self.version.version
                ))
            })
    }

    /// PHP's version as the rest of the panel spells it.
    ///
    /// The catalogue and [`PhpVersion`] have to agree; a catalogue entry for a
    /// PHP the panel cannot name a pool or a unit for is a bug in the pair, and
    /// this is where it surfaces.
    fn php_version(self) -> Result<PhpVersion> {
        PhpVersion::parse(self.version.version)
    }

    /// The repository to add, or `None` when the packages come from the
    /// distribution and there is no key to pin.
    fn repo(self, distro: &Distro) -> Result<Option<ResolvedRepo>> {
        if self.version.source == catalogue::Source::Distro {
            return Ok(None);
        }

        let info = &distro.info;
        let resolved = match self.entry.slug {
            "nginx" => unihelm_distro::repos::nginx(info),
            "php" => unihelm_distro::repos::php(info),
            "node" => unihelm_distro::repos::nodesource(info, self.major()?),
            // The series names the repository tree, not the package, which is
            // why this is the one resolver that takes the version through.
            "mariadb" => unihelm_distro::repos::mariadb(info, self.version.version),
            // One PGDG tree carries every major; the major picks packages.
            "postgres" => unihelm_distro::repos::pgdg(info),
            "mongodb" => unihelm_distro::repos::mongodb(info, self.version.version),
            "docker" => unihelm_distro::repos::docker(info),
            "litespeed" => unihelm_distro::repos::litespeed(info),
            // A catalogue entry can arrive before its pinned repository does.
            // Refusing with a sentence is the only honest answer: installing it
            // would mean an unpinned archive, and pretending it worked would
            // mean an empty package set.
            _ => {
                return Err(UnihelmError::new(
                    ErrorCode::NotImplemented,
                    format!(
                        "{} is in the catalogue but Unihelm has no pinned repository for it \
                         yet, so the panel cannot install it",
                        self.display_name()
                    ),
                ));
            }
        };

        resolved
            .map(Some)
            .map_err(|e| UnihelmError::new(ErrorCode::UnsupportedDistro, e))
    }

    /// The packages to install, for this family.
    ///
    /// `extensions` is PHP's alone; every other entry ignores it.
    fn packages(self, distro: &Distro, extensions: &[PhpExt]) -> Result<Vec<PackageName>> {
        let family = distro.info.family;
        match self.entry.slug {
            "nginx" => parse_packages(&["nginx"]),
            "apache" => match family {
                Family::Debian => parse_packages(&["apache2"]),
                Family::Rhel => parse_packages(&["httpd"]),
            },
            // One package on both families; LiteSpeed builds its own deb and rpm
            // from the same source tree and names them identically.
            "litespeed" => parse_packages(&["openlitespeed"]),

            "php" => packages_for(family, self.php_version()?, extensions),
            "node" => parse_packages(&["nodejs"]),
            "python" => match family {
                Family::Debian => parse_packages(&["python3", "python3-venv", "python3-pip"]),
                // EL has no `python3-venv`: the module ships inside `python3-libs`,
                // and asking for a package that does not exist fails the whole
                // transaction rather than the one name.
                Family::Rhel => parse_packages(&["python3", "python3-pip"]),
            },
            "go" => match family {
                Family::Debian => parse_packages(&["golang-go"]),
                Family::Rhel => parse_packages(&["golang"]),
            },
            "ruby" => match family {
                // `ruby-full` pulls the standard library, the dev headers and
                // rubygems, which is what "install Ruby" means to anybody who
                // then runs `gem install`.
                Family::Debian => parse_packages(&["ruby-full"]),
                Family::Rhel => parse_packages(&["ruby", "ruby-devel", "rubygems"]),
            },

            "mariadb" => match family {
                // Package names verified against the live 11.8 repository
                // indexes on both families.
                //
                // The `*-compat` pair is listed explicitly because nothing
                // depends on it: since 11.x the binaries are `mariadb` /
                // `mariadbd`, and the compat packages are what still provides
                // the `mysql`/`mysqld` entry points that most applications,
                // scripts and health checks actually invoke.
                Family::Debian => parse_packages(&[
                    "mariadb-server",
                    "mariadb-client",
                    "mariadb-backup",
                    "mariadb-server-compat",
                    "mariadb-client-compat",
                ]),
                // Capital M, deliberately: MariaDB plc names its own RPMs
                // `MariaDB-*` precisely so they stay distinct from Red Hat's
                // lowercase `mariadb-*` AppStream packages. Asking dnf for the
                // lowercase names here would install the distribution's older
                // build instead of the repository we just pinned.
                Family::Rhel => parse_packages(&[
                    "MariaDB-server",
                    "MariaDB-client",
                    "MariaDB-backup",
                    "MariaDB-server-compat",
                    "MariaDB-client-compat",
                ]),
            },
            // `mysql-server` on both: Ubuntu's is 8.0, EL's AppStream module
            // ships the same name. The client comes with it as a dependency.
            "mysql" => parse_packages(&["mysql-server"]),
            "postgres" => {
                let major = self.major()?;
                match family {
                    // PGDG apt selects the major by package name; `postgresql-17`
                    // pulls the server, `postgresql-client-17` the tools.
                    Family::Debian => parse_packages(&[
                        &format!("postgresql-{major}"),
                        &format!("postgresql-client-{major}"),
                    ]),
                    // PGDG rpm naming: `postgresql17-server` is the daemon,
                    // `postgresql17` the client, `-contrib` the standard extension
                    // set (pg_stat_statements et al.) a hosting box wants anyway.
                    Family::Rhel => parse_packages(&[
                        &format!("postgresql{major}-server"),
                        &format!("postgresql{major}"),
                        &format!("postgresql{major}-contrib"),
                    ]),
                }
            }

            "redis" => match family {
                Family::Debian => parse_packages(&["redis-server"]),
                Family::Rhel => parse_packages(&["redis"]),
            },
            "valkey" => match family {
                Family::Debian => parse_packages(&["valkey-server"]),
                // EL carries Valkey only in EPEL, which this panel does not add
                // for a cache. Say so instead of guessing a name: a wrong guess
                // fails as dnf's "no match for argument", which tells an
                // operator nothing about why the panel offered it.
                Family::Rhel => Err(no_package_here(
                    self,
                    family,
                    "Install Redis instead — it is in the distribution's own \
                     repositories and speaks the same protocol.",
                )),
            },
            "memcached" => parse_packages(&["memcached"]),

            // `mongodb-org` is the metapackage the vendor repository is built
            // around: server, mongos, the tools and mongosh. Naming the parts
            // individually is how installs end up with a server and no shell.
            "mongodb" => parse_packages(&["mongodb-org"]),

            "docker" => parse_packages(&["docker-ce", "docker-ce-cli", "containerd.io"]),

            other => Err(UnihelmError::internal(format!(
                "{other} is in the catalogue but no package set resolves for it"
            ))),
        }
    }

    /// Whether another version of this same entry resolves to the same packages.
    ///
    /// True for Node, whose three majors are all one `nodejs`; false for PHP,
    /// whose names carry the version. What it is for is the removal path: where
    /// the packages are shared, removing one row uninstalls the other.
    fn shares_packages_with_its_other_versions(self, distro: &Distro) -> bool {
        let Ok(mine) = self.packages(distro, PhpExt::DEFAULT) else {
            return false;
        };
        self.entry
            .versions
            .iter()
            .filter(|v| v.version != self.version.version)
            .any(|version| {
                Self {
                    entry: self.entry,
                    version,
                }
                .packages(distro, PhpExt::DEFAULT)
                .is_ok_and(|theirs| theirs == mine)
            })
    }

    /// The systemd unit the packages ship, or `None` for a toolchain.
    ///
    /// `None` is not "we could not work it out": Go, Ruby, Python and Node
    /// install binaries and there is nothing for systemd to start. The install
    /// path must skip the started-and-active check for those rather than fail
    /// it, which is why this is an `Option` and not an empty string.
    fn unit(self, family: Family) -> Result<Option<UnitName>> {
        // Where a `ManagedUnit` exists it is used rather than a literal, so
        // `svc.action` and the Stack Manager can never disagree about a name.
        let unit = match self.entry.slug {
            "nginx" => ManagedUnit::Nginx.unit_name(family),
            "apache" => unit_named(match family {
                Family::Debian => "apache2.service",
                Family::Rhel => "httpd.service",
            })?,
            // `lsws`, not `openlitespeed`: the package installs to
            // /usr/local/lsws and names its unit after the directory.
            "litespeed" => unit_named("lsws.service")?,
            "php" => ManagedUnit::PhpFpm {
                version: self.php_version()?,
            }
            .unit_name(family),

            "mariadb" => ManagedUnit::MariaDb.unit_name(family),
            "mysql" => unit_named(match family {
                Family::Debian => "mysql.service",
                Family::Rhel => "mysqld.service",
            })?,
            // Not `ManagedUnit::PostgreSql`: that resolves the major from a
            // compile-time constant, and on EL the unit is versioned. The
            // operator picked a major here and it has to be the one we start.
            "postgres" => unit_named(&match family {
                Family::Debian => "postgresql.service".to_string(),
                Family::Rhel => format!("postgresql-{}.service", self.major()?),
            })?,

            "redis" => ManagedUnit::KvStore.unit_name(family),
            "valkey" => unit_named(match family {
                Family::Debian => "valkey-server.service",
                Family::Rhel => "valkey.service",
            })?,
            "memcached" => unit_named("memcached.service")?,
            "mongodb" => unit_named("mongod.service")?,

            "docker" => ManagedUnit::Docker.unit_name(family),

            "python" | "go" | "ruby" | "node" => return Ok(None),

            other => {
                return Err(UnihelmError::internal(format!(
                    "{other} is in the catalogue but no unit resolves for it"
                )));
            }
        };
        Ok(Some(unit))
    }

    /// The entry as one of the units the panel is allowed to name.
    ///
    /// Deliberately narrower than [`Self::unit`], which builds a `UnitName` from
    /// a string literal wherever no `ManagedUnit` covers the entry. That is safe
    /// there because the literal is written in this file; it would not be safe
    /// for `stack.start` and `stack.stop`, whose input is a slug an operator
    /// typed. Routing that through the same enum `svc.action` uses is what keeps
    /// the pair from ever becoming a way to name an arbitrary systemd unit
    /// (spec §5.2) — the property the enum exists to buy.
    ///
    /// PostgreSQL is absent even though a `ManagedUnit` exists for it: that
    /// variant resolves the major from a compile-time constant, so on EL it can
    /// name `postgresql-17.service` on a machine running 16 — and a stop that
    /// reports success against a unit that is not the one installed is exactly
    /// the lie this file is written against. Everything else missing here has
    /// only a literal unit name, which is the same problem one step earlier.
    fn managed_unit(self) -> Result<ManagedUnit> {
        match self.entry.slug {
            "nginx" => Ok(ManagedUnit::Nginx),
            "apache" => Ok(ManagedUnit::Apache),
            "php" => Ok(ManagedUnit::PhpFpm {
                version: self.php_version()?,
            }),
            "mariadb" => Ok(ManagedUnit::MariaDb),
            "redis" => Ok(ManagedUnit::KvStore),
            "docker" => Ok(ManagedUnit::Docker),
            _ => Err(UnihelmError::new(
                ErrorCode::NotImplemented,
                format!(
                    "the panel cannot start or stop {}: its service is not one of the units \
                     the panel is allowed to name. It can start and stop: {}.",
                    self.display_name(),
                    CONTROLLABLE_SLUGS.join(", ")
                ),
            )
            .with_field("component")),
        }
    }
}

/// The catalogue slugs [`StackComponent::managed_unit`] answers for.
///
/// Beside the match rather than derived from it, for two readers: the refusal
/// above lists them, and the Stack page mirrors them to decide whether a chip
/// draws a start/stop control at all. A slug in one and not the other is a
/// button that always comes back refused, which is the shape of defect this
/// list exists to prevent — so a test below pins the two together.
pub const CONTROLLABLE_SLUGS: &[&str] = &["nginx", "apache", "php", "mariadb", "redis", "docker"];

/// A runtime as a sentence, for a refusal an operator has to act on.
///
/// `host`/`container` are the wire's words; "on the host, as packages" is what
/// the Stack page's own menu says, and an error that answers a menu should use
/// the menu's language.
fn as_words(runtime: catalogue::Runtime) -> &'static str {
    match runtime {
        catalogue::Runtime::Host => "on the host, as packages",
        catalogue::Runtime::Container => "in a container",
    }
}

/// Where this install or removal happens: what the caller asked for, or the
/// catalogue's default when they expressed no preference.
///
/// The Stack page has offered "Run it: on the server / in a container" since
/// containers landed, and the answer never left the browser — the web layer's
/// `ComponentRequest` had no field to carry it. An operator who picked the host
/// got whatever the catalogue preferred, which for every database and cache is
/// a container, and the panel said nothing. It showed a choice it did not have.
///
/// A runtime the entry does not offer is refused by name rather than quietly
/// corrected to the default, because a silent correction is the same defect in
/// a different hat: the operator asked for one thing and got another without
/// being told.
fn runtime_for(
    component: StackComponent,
    asked: Option<catalogue::Runtime>,
) -> Result<catalogue::Runtime> {
    let install = component.entry.install;
    let Some(runtime) = asked else {
        return Ok(install.default_runtime());
    };
    if !install.allows(runtime) {
        return Err(UnihelmError::new(
            ErrorCode::InvalidInput,
            format!(
                "{} does not run {}. It runs: {}.",
                component.display_name(),
                as_words(runtime),
                install
                    .runtimes()
                    .iter()
                    .map(|r| as_words(*r))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        )
        .with_field("runtime"));
    }
    Ok(runtime)
}

/// The `stack_components` row an install claims and settles, and a removal
/// clears.
///
/// **One derivation for both runtimes**, and that is the whole of it: claim,
/// settle and remove are three writes that have to name one string, and they
/// did not. `stack.install` claimed [`StackComponent::slug`] — the *host* key —
/// whichever way it then installed, so a container install marked the host
/// MariaDB row installed; `stack.status` asked the package manager whether
/// `mariadb-server` was present, got no, and rewrote that row to `absent`
/// through the arm that exists to catch somebody removing a package by hand.
/// The Stack page said "Not installed" over a container that was serving, and
/// `engine.remove` wrote a *third* key — the container name — so removing the
/// container could not correct the host row either.
///
/// The container's key is the container name and
/// [`crate::engine::EnginePlan::row_key`] owns that derivation, for the reason
/// documented there: two versions of one engine are two containers, with two
/// ports and two data directories, so they are two rows and must not collide
/// with each other or with the host's one.
pub fn row_key(component: StackComponent, runtime: catalogue::Runtime) -> Result<String> {
    match runtime {
        catalogue::Runtime::Host => Ok(component.slug()),
        catalogue::Runtime::Container => Ok(crate::engine::EnginePlan::for_component(component)?
            .row_key()
            .to_string()),
    }
}

fn parse_packages(names: &[&str]) -> Result<Vec<PackageName>> {
    names
        .iter()
        .map(|n| {
            PackageName::parse(n)
                .map_err(|e| UnihelmError::new(ErrorCode::InvalidInput, e.to_string()))
        })
        .collect()
}

fn unit_named(name: &str) -> Result<UnitName> {
    UnitName::parse(name)
        .map_err(|e| UnihelmError::internal(format!("`{name}` is not a unit name: {e}")))
}

/// This family has no package for this entry, said plainly.
///
/// The alternative is guessing a name, which surfaces as the package manager's
/// own "no match for argument" — an error that names a package the operator
/// never typed and never explains why the panel offered the thing at all.
fn no_package_here(component: StackComponent, family: Family, instead: &str) -> UnihelmError {
    UnihelmError::new(
        ErrorCode::UnsupportedDistro,
        format!(
            "{} has no package in the {} family's own repositories. {instead}",
            component.display_name(),
            match family {
                Family::Debian => "Debian",
                Family::Rhel => "RHEL",
            },
        ),
    )
}

// ---------------------------------------------------------------------------
// stack.status
// ---------------------------------------------------------------------------

/// `stack.status` — what is installed, and what the panel could install.
pub struct Status;

#[derive(Debug, Deserialize)]
pub struct StatusInput {}

#[derive(Debug, Serialize)]
pub struct ComponentView {
    pub slug: String,
    pub display_name: String,
    /// The catalogue entry this row belongs to, so the UI can group without
    /// having to parse `php8.3` back apart.
    pub component: String,
    /// Which catalogue version this row is about.
    pub version: String,
    pub category: String,
    /// Host packages, or a container.
    ///
    /// The field this view did not have, which is why the Stack page could not
    /// tell an apt package from an image even once the rows were right: two
    /// chips reading `11.8` and `11.4` are a contradiction on the host and two
    /// containers everywhere else, and the Remove beside them goes to a
    /// different operation in each case.
    pub runtime: catalogue::Runtime,
    pub status: String,
    pub installed_version: Option<String>,
    pub last_error: Option<String>,
    /// What is actually running this component, which can disagree with our
    /// record if somebody removed it by hand.
    ///
    /// systemd's word for a host row, and Docker's for a container one —
    /// `running`, `stopped`, or `unknown` when the daemon could not be asked.
    /// `none` where there is nothing to run at all: a toolchain installs a
    /// compiler and has no service either way.
    pub unit_state: String,
    pub unit_active: bool,
    /// Why pressing install on this row could not work on *this* machine, or
    /// `None` when it can.
    ///
    /// The catalogue is the same everywhere; what a family packages is not.
    /// Valkey is in EPEL rather than EL's own repositories, and OpenLiteSpeed
    /// publishes a Debian tree this panel pins but an EL layout it does not
    /// handle — without this the page offers both on a machine that can install
    /// neither, and an operator finds out by pressing a button and reading a
    /// failure.
    pub unavailable: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct StatusOutput {
    pub components: Vec<ComponentView>,
    /// Everything installable, with its versions — so one page can offer the
    /// whole catalogue instead of the UI carrying a second copy of this list.
    pub catalogue: &'static [catalogue::Entry],
    /// Repository pins that have not been independently corroborated yet.
    pub unverified_pins: &'static [&'static str],
    /// Which web server actually serves this machine's sites.
    ///
    /// Not derivable from the rows above: two web servers can be installed at
    /// once, and "installed" has never meant "serving". A page that guessed
    /// from the install rows would put the Serving badge on whichever was
    /// installed first.
    pub web_server: String,
}

#[async_trait]
impl TypedOperation for Status {
    type Input = StatusInput;
    type Output = StatusOutput;

    const NAME: &'static str = "stack.status";
    const PERMISSION: Permission = Permission::ServerRead;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, _input: Self::Input) -> Result<Self::Output> {
        let distro = ctx.distro();
        let recorded = ctx.db().components().await.map_err(UnihelmError::from)?;

        let mut components = Vec::new();
        for (candidate, presence) in status_candidates(distro).await {
            let slug = candidate.slug();
            let row = recorded.iter().find(|c| c.slug == slug);

            let unit = candidate.unit(distro.info.family).ok().flatten();
            let unit_status = match &unit {
                Some(unit) => distro.svc.status(unit).await.ok(),
                None => None,
            };
            // The package manager, never the unit. A unit answering to this
            // name is not proof this component is here: MariaDB's own package
            // installs `mysql.service` as an alias on Debian, so asking systemd
            // reports MySQL installed on a machine that has never had it — and
            // then offers to remove it.
            //
            // `None` is a third answer and not a quiet `false`: it means the
            // package manager could not be asked, and treating that as absent
            // would tell an operator their database is gone because a
            // `dpkg-query` failed to run.
            let here = presence.holds(candidate);

            components.push(ComponentView {
                slug,
                display_name: candidate.display_name(),
                component: candidate.entry.slug.to_string(),
                version: candidate.version.version.to_string(),
                category: candidate.entry.category.as_str().to_string(),
                // These are the package-manager rows and nothing else. What
                // runs in a container is a separate row from the registry, per
                // [`container_rows`] — the two cannot be one row, because one
                // machine can hold both.
                runtime: catalogue::Runtime::Host,
                status: match (row, here) {
                    // The panel installed it and its packages are gone: somebody
                    // removed them by hand, and reading the database back would
                    // offer Remove for something that is not there. Only from
                    // `installed`, because an install in flight has claimed its
                    // row before a single package has landed.
                    (Some(c), Some(false)) if c.status == ComponentStatus::Installed => {
                        ComponentStatus::Absent.as_str().to_string()
                    }
                    (Some(c), _) => c.status.as_str().to_string(),
                    // The database only knows what this panel installed. A
                    // component put there by hand — nginx serving a dozen sites
                    // before Unihelm existed — has no row, and reporting that as
                    // `absent` is the same kind of lie the comment above warns
                    // about, only in the other direction: it invites an operator
                    // to press install on something that is already running.
                    (None, Some(true)) => ComponentStatus::Unmanaged.as_str().to_string(),
                    (None, _) => ComponentStatus::Absent.as_str().to_string(),
                },
                installed_version: match here {
                    // The machine's own answer, which is the only one that is
                    // not a memory of an install that may since have been undone.
                    Some(true) => presence.version(),
                    Some(false) => None,
                    None => row.and_then(|c| c.installed_version.clone()),
                },
                last_error: row.and_then(|c| c.last_error.clone()),
                unit_state: match (&unit, &unit_status) {
                    (None, _) => "none".into(),
                    (Some(_), Some(s)) => format!("{:?}", s.state).to_lowercase(),
                    (Some(_), None) => "unknown".into(),
                },
                unit_active: unit_status.map(|s| s.is_active()).unwrap_or(false),
                unavailable: why_this_machine_cannot_install(candidate, distro),
            });
        }

        components.extend(container_rows(ctx, &recorded).await?);

        Ok(StatusOutput {
            web_server: crate::webserver::active(ctx).await?.as_str().to_string(),
            components,
            catalogue: catalogue::CATALOGUE,
            unverified_pins: unihelm_distro::repos::UNVERIFIED_PINS,
        })
    }
}

/// One row per containerised engine the panel installed, cross-checked against
/// Docker.
///
/// **The package manager cannot answer here and must not be asked.** A
/// container installs no packages, so the question `status_candidates` puts to
/// `dpkg-query` comes back "not here" for a MariaDB that is up and serving —
/// which is exactly how a running container came to be reported as
/// `Not installed`.
///
/// So two sources, and neither stands in for the other. The registry is the
/// panel's own record that it built this container and holds its credential;
/// Docker is the machine's answer about whether the container is still there
/// and whether it is up. Three outcomes an operator needs told apart:
///
/// - **running** — installed, and answering;
/// - **stopped** — installed *and down*, which is a different sentence from
///   absent and is most of the reason somebody opens this page;
/// - **gone** — somebody ran `docker rm` behind the panel's back, and the row
///   says so instead of reporting the registry's memory of an install.
///
/// A daemon that cannot be reached is a fourth answer and not a quiet "gone",
/// for the reason [`Presence::Unknown`] exists: telling an operator their
/// database has disappeared because `docker info` timed out is the same lie in
/// a different hat.
/// What Docker was able to say about one engine's container.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ContainerState {
    Running,
    /// On the machine and not up. **Installed and down**, which is the sentence
    /// this whole enum exists to keep separate from the next one.
    Stopped,
    /// No container of that name: `docker rm` behind the panel's back.
    Gone,
    /// No Docker, or a daemon that did not answer. Not a "no".
    Unasked,
}

impl ContainerState {
    /// The row's `unit_state`/`unit_active` pair. A container is what runs this
    /// component, so it answers the question systemd answers for a host row.
    fn as_unit(self) -> (String, bool) {
        match self {
            ContainerState::Running => ("running".to_string(), true),
            ContainerState::Stopped => ("stopped".to_string(), false),
            // Nothing to be running or stopped: the status beside this already
            // says `absent`, and a state as well would be a second answer to a
            // question that has one.
            ContainerState::Gone => ("none".to_string(), false),
            // Said as its own word rather than as `stopped`. A daemon that did
            // not answer is not a container that is down, and a page that
            // spelt the two the same would tell an operator to go and restart
            // something that is running.
            ContainerState::Unasked => ("unknown".to_string(), false),
        }
    }
}

/// What one engine's row says, given the panel's stored status and what Docker
/// could see.
///
/// Pure, because this is the decision the defect was in and it is worth pinning
/// without a Docker daemon in the room.
fn container_status(stored: Option<ComponentStatus>, state: ContainerState) -> ComponentStatus {
    match stored {
        // An operation in flight, or the reason the last one failed, is the
        // truest thing about this row and Docker cannot contradict it: an
        // install claims its row before the image has finished pulling, so "no
        // container yet" is what an install underway looks like.
        Some(s) if s.is_busy() || s == ComponentStatus::Failed => s,
        // Nothing was able to disagree with the panel's own record. `absent`
        // here would be a claim built out of not having looked.
        stored if state == ContainerState::Unasked => stored.unwrap_or(ComponentStatus::Installed),
        // The registry record **is** the panel's record of the install, so a
        // container that is there is installed whether or not
        // `stack_components` has caught up — and on every machine installed
        // before the row key was fixed, it has not: the install settled the
        // host row instead.
        _ if state != ContainerState::Gone => ComponentStatus::Installed,
        _ => ComponentStatus::Absent,
    }
}

async fn container_rows(
    ctx: &OpContext,
    recorded: &[unihelm_db::StackComponent],
) -> Result<Vec<ComponentView>> {
    let registry = crate::engine::registry(ctx.db()).await?;
    // Nothing to ask about. Worth the early return rather than letting the loop
    // do nothing: `inventory` shells out to `docker info` and `docker ps`, and
    // this page's first paint should not pay for them on a machine that runs no
    // containers.
    if registry.is_empty() {
        return Ok(Vec::new());
    }

    let inventory = crate::docker::inventory().await;
    // Whether the machine could be asked at all, kept apart from what it said.
    let answered = inventory.docker.is_some() && inventory.daemon_running;

    let mut rows = Vec::new();
    for record in registry.values() {
        let row = recorded.iter().find(|c| c.slug == record.container);
        let found = inventory
            .containers
            .iter()
            .find(|c| c.name == record.container);

        let state = match (answered, found) {
            (false, _) => ContainerState::Unasked,
            (true, Some(c)) if c.running => ContainerState::Running,
            (true, Some(_)) => ContainerState::Stopped,
            (true, None) => ContainerState::Gone,
        };
        let status = container_status(row.map(|c| c.status), state);
        let (unit_state, unit_active) = state.as_unit();

        let known = StackComponent::resolve(&record.slug, Some(&record.version));
        rows.push(ComponentView {
            // The container name, which is this row's key everywhere: what
            // `stack.install` claimed, what `engine.remove` clears.
            slug: record.container.clone(),
            display_name: known
                .map(|c| c.display_name())
                // A record whose catalogue version this build no longer carries
                // is a downgrade, not an invitation to hide the row: a
                // container nobody can see is a container nobody can remove.
                .unwrap_or_else(|_| record.container.clone()),
            component: record.slug.clone(),
            version: record.version.clone(),
            category: catalogue::entry(&record.slug)
                .map(|e| e.category.as_str().to_string())
                // Every recipe names a database or a cache — `engine` pins that
                // in a test — so this is only reachable on that same downgrade.
                .unwrap_or_else(|| catalogue::Category::Database.as_str().to_string()),
            runtime: catalogue::Runtime::Container,
            status: status.as_str().to_string(),
            // The version the container was built at, which is the image tag
            // and not a package version. It is the machine's own answer here:
            // the tag is part of the container's name.
            installed_version: match status {
                ComponentStatus::Installed => Some(record.version.clone()),
                _ => None,
            },
            last_error: row.and_then(|c| c.last_error.clone()),
            unit_state,
            unit_active,
            // Nothing about this machine's packaging can stop a container being
            // installed; what can — no Docker, a host install already holding
            // the port — is refused by name at install time.
            unavailable: None,
        });
    }

    rows.sort_by(|a, b| a.slug.cmp(&b.slug));
    Ok(rows)
}

/// One row per thing an operator can act on.
///
/// Side-by-side entries get a row per version, because each one is separately
/// installable and separately removable. Everything else gets a single row —
/// two MariaDBs cannot coexist, so offering three would be offering a choice the
/// machine cannot hold. Which version that row is about is decided by asking the
/// machine, since on EL `postgresql-16.service` and `postgresql-17.service` are
/// different units and only one of them exists.
///
/// The machine is asked through the package manager rather than through systemd,
/// for the same reason the view is: a unit name can belong to another
/// package (`mysql.service` is MariaDB's alias on Debian), and Debian's single
/// `postgresql.service` exists for whichever major is installed, so the unit
/// cannot tell 16 from 17 there either.
async fn status_candidates(distro: &Distro) -> Vec<(StackComponent, Presence)> {
    let mut out = Vec::new();
    for entry in catalogue::CATALOGUE {
        if entry.side_by_side {
            for version in entry.versions {
                let candidate = StackComponent { entry, version };
                let presence = presence(distro, candidate).await;
                out.push((candidate, presence));
            }
            continue;
        }

        // Where none of them is installed the row is about what pressing
        // install would get you, which is the recommended version. Its answer
        // from the package manager is carried along rather than assumed,
        // because "could not ask" must not arrive at the view as "no".
        let default = catalogue::default_version(entry.slug).expect("catalogue has a default");
        let mut fallback = None;
        let mut chosen: Option<(StackComponent, Presence)> = None;
        for version in entry.versions {
            let candidate = StackComponent { entry, version };
            let found = presence(distro, candidate).await;
            if found.holds(candidate) != Some(true) {
                if version.version == default.version {
                    fallback = Some((candidate, found));
                }
                continue;
            }
            // Several versions of one engine usually resolve to one package set
            // (every MariaDB is `mariadb-server`), so "installed" alone cannot
            // say *which*. The version the machine reports can, and answering
            // "which MariaDB is on here" is half of what this page is for.
            let names_the_one_here = found
                .version()
                .is_some_and(|v| upstream_version(&v).starts_with(version.version));
            if names_the_one_here {
                chosen = Some((candidate, found));
                break;
            }
            chosen.get_or_insert((candidate, found));
        }

        out.push(chosen.or(fallback).unwrap_or((
            StackComponent {
                entry,
                version: default,
            },
            Presence::Absent,
        )));
    }
    out
}

/// What the package manager says about a component's own package.
enum Presence {
    /// Installed, at the version the package manager reports.
    Installed(Option<String>),
    /// The package manager answered, and it is not here.
    Absent,
    /// The package manager could not be asked at all. Not the same as absent:
    /// acting on it would mean telling an operator a component is gone because
    /// `dpkg-query` failed to spawn.
    Unknown,
}

impl Presence {
    /// Whether this is *this* component at *this* version, or `None` when the
    /// machine gave no answer.
    ///
    /// Side by side means the package can be there at the wrong version:
    /// NodeSource installs one `nodejs`, so "is Node 20 installed" is a
    /// question about the version string, not about the package name.
    fn holds(&self, component: StackComponent) -> Option<bool> {
        match self {
            Presence::Unknown => None,
            Presence::Absent => Some(false),
            Presence::Installed(_) if !component.entry.side_by_side => Some(true),
            Presence::Installed(version) => Some(
                version
                    .as_deref()
                    .is_some_and(|v| upstream_version(v).starts_with(component.version.version)),
            ),
        }
    }

    fn version(&self) -> Option<String> {
        match self {
            Presence::Installed(version) => version.clone(),
            _ => None,
        }
    }
}

/// Ask the package manager about a component's main package.
///
/// The only honest way to ask whether a component is here: unit names can
/// belong to another package, package names cannot.
async fn presence(distro: &Distro, component: StackComponent) -> Presence {
    // No package under any name on this family — a definite "not here", not a
    // failure to look.
    let Ok(packages) = component.packages(distro, PhpExt::DEFAULT) else {
        return Presence::Absent;
    };
    let Some(main) = packages.first() else {
        return Presence::Absent;
    };
    match distro.pkg.query(main).await {
        Ok(status) if status.installed => Presence::Installed(status.installed_version),
        Ok(_) => Presence::Absent,
        Err(_) => Presence::Unknown,
    }
}

/// The upstream part of a package version, without dpkg's epoch.
///
/// MariaDB 11.8 is `1:11.8.2-1` to dpkg, and the leading `1:` is what makes a
/// plain `starts_with` conclude that the version on the machine is not the one
/// that was asked for. Only a run of digits before the colon is an epoch;
/// anything else is left alone. rpm's `%{VERSION}-%{RELEASE}` carries no epoch,
/// so this is a no-op there.
fn upstream_version(version: &str) -> &str {
    match version.split_once(':') {
        Some((epoch, rest)) if !epoch.is_empty() && epoch.bytes().all(|b| b.is_ascii_digit()) => {
            rest
        }
        _ => version,
    }
}

/// The version the package manager reports for this entry's main package, or
/// `None` when the package is not installed at all.
async fn installed_package_version(
    distro: &Distro,
    component: StackComponent,
) -> Option<Option<String>> {
    match presence(distro, component).await {
        Presence::Installed(version) => Some(version),
        _ => None,
    }
}

/// Whether this entry is present on the machine, at this version.
async fn package_is_installed(distro: &Distro, component: StackComponent) -> bool {
    presence(distro, component)
        .await
        .holds(component)
        .unwrap_or(false)
}

/// Why this machine could not install this row, or `None` when it can.
///
/// Both questions are answered from the distribution's own description of
/// itself and cost nothing: what a family packages, and whether a pinned
/// repository exists for this entry and this release. Asking them here is what
/// stops the page offering an install that was never going to work.
fn why_this_machine_cannot_install(component: StackComponent, distro: &Distro) -> Option<String> {
    if let Err(e) = component.packages(distro, PhpExt::DEFAULT) {
        return Some(e.detail);
    }
    if let Err(e) = component.repo(distro) {
        return Some(e.detail);
    }
    None
}

// ---------------------------------------------------------------------------
// stack.install
// ---------------------------------------------------------------------------

/// `stack.install` — add the repository, install the packages, start the service.
pub struct Install;

#[derive(Debug, Deserialize)]
pub struct InstallInput {
    #[serde(flatten)]
    pub component: StackComponent,
    /// Extensions to install alongside a PHP version. Empty means the default
    /// set that mainstream applications assume.
    #[serde(default)]
    pub extensions: Vec<PhpExt>,
    /// Where to run it: `host` or `container`.
    ///
    /// A third state rather than a defaulted value, and that is the point:
    /// "the operator chose the host" and "the operator said nothing" are
    /// different requests, and only the second one may be answered with the
    /// catalogue's container. See [`runtime_for`].
    #[serde(default)]
    pub runtime: Option<catalogue::Runtime>,
}

#[derive(Debug, Serialize)]
pub struct InstallOutput {
    pub slug: String,
    pub installed_version: Option<String>,
    pub packages: Vec<String>,
    /// How it actually runs: `host` or `container`.
    ///
    /// One install surface answers for both, so the answer has to say which it
    /// took — an operator reading "installed" wants to know whether that means
    /// packages on their server or an image.
    pub runtime: String,
    /// The container it runs in, when it runs in one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container: Option<String>,
    /// Where its data lives, which outlives the container.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub volume: Option<String>,
    /// The port clients connect to. Not always the number they expect: a second
    /// version of the same engine cannot publish on the first one's port.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_port: Option<u16>,
}

#[async_trait]
impl TypedOperation for Install {
    type Input = InstallInput;
    type Output = InstallOutput;

    const NAME: &'static str = "stack.install";
    const PERMISSION: Permission = Permission::StackManage;
    // Minutes, not milliseconds. Streams the package manager's output so the
    // user can see it working rather than watching a spinner.
    const EXECUTION: Execution = Execution::Task {
        cancellable: false,
        idempotent: true,
    };

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let component = input.component;
        let db = ctx.db().clone();

        // Before the claim for the same reason the two collision checks are:
        // an unsupported runtime is a refusal, and a refusal must not leave a
        // `failed` row behind for an install that never began.
        let runtime = runtime_for(component, input.runtime)?;

        // The row this install claims, settles and is later removed from,
        // derived from the runtime it actually lands on rather than assumed to
        // be the host's. See [`row_key`] for what assuming it cost.
        let slug = row_key(component, runtime)?;

        // Before the claim, not after: a refusal here means nothing was
        // touched, and marking the component `failed` for an install that never
        // started would put a red row on the page for a machine that is fine.
        refuse_a_second_engine_on_3306(ctx, component).await?;
        decide_about_the_contested_port(ctx, component).await?;

        let task_id = ctx.task_id().map(|t| t.to_string()).unwrap_or_default();
        if !db
            .claim_component(&slug, ComponentStatus::Installing, &task_id)
            .await
            .map_err(UnihelmError::from)?
        {
            return Err(UnihelmError::new(
                ErrorCode::Conflict,
                format!(
                    "{} is already being installed or removed",
                    component.display_name()
                ),
            ));
        }

        let outcome = install_component(ctx, component, runtime, &input.extensions).await;

        match &outcome {
            Ok(out) => {
                db.component_installed(&slug, out.installed_version.as_deref())
                    .await
                    .map_err(UnihelmError::from)?;

                // A service the operator has just installed is one this machine
                // really runs, which is the only honest moment to start watching
                // it. Migration 0011 armed `service_down`/`nginx` on every
                // install instead, including machines that would never run it —
                // so a fresh server showed an armed alert for an nginx it did
                // not have, and the rule stayed quiet until nginx was installed
                // and stopped once. Container installs are skipped: there is no
                // host unit to watch. Never fatal, and never over a rule the
                // operator already has.
                if out.container.is_none()
                    && let Ok(unit) = component.managed_unit()
                {
                    crate::alerts::arm_service_rule(ctx, unit).await;
                }
            }
            Err(e) => {
                // Record before returning, so the UI can explain a failure that
                // happened while nobody was watching.
                let _ = db.component_failed(&slug, &e.detail).await;
            }
        }

        outcome
    }
}

/// The other engine that wants port 3306, if this one wants it too.
fn mysql_protocol_rival(slug: &str) -> Option<&'static str> {
    match slug {
        "mariadb" => Some("mysql"),
        "mysql" => Some("mariadb"),
        _ => None,
    }
}

/// The server packages that mean this engine is already on the machine.
///
/// Deliberately not [`StackComponent::packages`]: that names what *this panel*
/// would install, and the engine already holding 3306 usually came from
/// somewhere else. On EL the panel installs MariaDB plc's `MariaDB-server`
/// while Red Hat's own AppStream build is `mariadb-server` — probing only the
/// first would let MySQL be installed on top of a live distribution MariaDB,
/// which is exactly the transaction dnf and apt resolve by removing one of the
/// two.
///
/// Every name a family might carry has to be listed, because `dpkg-query -W`
/// and `rpm -q` match a package's own name and not what it provides.
fn server_packages_holding_3306(slug: &str, family: Family) -> &'static [&'static str] {
    match (slug, family) {
        ("mariadb", Family::Debian) => &["mariadb-server"],
        ("mariadb", Family::Rhel) => &["MariaDB-server", "mariadb-server"],
        // Oracle's own repository names its server package differently from the
        // distribution's, on both families, and a machine can carry either.
        ("mysql", _) => &["mysql-server", "mysql-community-server"],
        _ => &[],
    }
}

/// Refuse to put a second MySQL-protocol engine on a machine that has one.
///
/// MariaDB and MySQL both bind 3306 and both want `/var/lib/mysql`. Left to the
/// package manager, apt on Debian resolves the conflict by *removing* the
/// installed one mid-transaction — which is a database engine disappearing from
/// under whatever was using it. Refuse first, and name what is already there so
/// the operator knows what they would be replacing.
///
/// Only the rival is probed, never the engine being installed: reinstalling a
/// component has to stay idempotent (spec §11.1).
async fn refuse_a_second_engine_on_3306(ctx: &OpContext, component: StackComponent) -> Result<()> {
    let Some(rival_slug) = mysql_protocol_rival(component.entry.slug) else {
        return Ok(());
    };
    let rival = StackComponent::resolve(rival_slug, None)?;
    let distro = ctx.distro();

    // Server packages alone. `mariadb-client` is routinely installed on a
    // machine with no server on it — an application box talking to a database
    // elsewhere — and refusing there would be refusing for no reason.
    for name in server_packages_holding_3306(rival_slug, distro.info.family) {
        let Ok(package) = PackageName::parse(name) else {
            continue;
        };
        let installed = distro
            .pkg
            .query(&package)
            .await
            .map(|s| s.installed)
            .unwrap_or(false);
        if !installed {
            continue;
        }

        return Err(UnihelmError::new(
            ErrorCode::Conflict,
            format!(
                "{} is already installed (`{name}` is present) and it holds port 3306 and \
                 /var/lib/mysql. Installing {} beside it would leave one of them unable \
                 to start, so the panel will not do it — remove {} first if you mean to \
                 replace it.",
                rival.entry.display_name,
                component.display_name(),
                rival.entry.display_name,
            ),
        ));
    }
    Ok(())
}

/// The port this entry binds, where the catalogue offers something else that
/// binds the same one.
///
/// `None` means nothing in the table contends for it — PostgreSQL has 5432 to
/// itself, and so does MongoDB.
///
/// Web servers are keyed on the category rather than slug by slug, so a fourth
/// one added to the table tomorrow is covered without anyone remembering to
/// come back here. The caches are not, because they do not share a port with
/// each other: Memcached is on 11211, while Valkey is a fork of Redis down to
/// the default `bind` line.
fn contested_port(entry: &catalogue::Entry) -> Option<u16> {
    match entry.category {
        catalogue::Category::WebServer => Some(80),
        catalogue::Category::Cache => matches!(entry.slug, "redis" | "valkey").then_some(6379),
        _ => None,
    }
}

/// Decide what installing this does to whatever already holds the port it wants,
/// and say so.
///
/// Apache, OpenLiteSpeed and nginx all bind port 80 and none of them yields;
/// Redis and Valkey do the same on 6379. Installing one while another is
/// serving means one of the two stops answering, and on Debian the package's
/// own postinst starts it before the panel gets a word in — so the decision has
/// to be made *before* the transaction, not repaired after it.
///
/// The panel refuses rather than reconfiguring, because reconfiguring means
/// rewriting a dpkg conffile (`ports.conf`, `httpd_config.conf`, `redis.conf`)
/// on a machine whose configuration an operator wrote by hand. Where nothing is
/// serving, the install proceeds and the log says plainly what that costs.
///
/// Symmetric on purpose. nginx is the web server this panel renders vhosts for,
/// but installing it onto a machine Apache is serving is the same collision seen
/// from the other end — and letting that one through only means the package
/// installs, fails to bind, and leaves a half-configured nginx and a `failed`
/// row behind. Refusing before the transaction says which server is in the way.
///
/// The incumbent is judged by its unit being *active*, not by its packages
/// being present: an installed-but-stopped Redis is not holding 6379, and
/// refusing there would be refusing an install that would have worked.
async fn decide_about_the_contested_port(ctx: &OpContext, component: StackComponent) -> Result<()> {
    let Some(port) = contested_port(component.entry) else {
        return Ok(());
    };

    let distro = ctx.distro();
    for entry in catalogue::CATALOGUE {
        // Reinstalling the server that is already serving is idempotent
        // (spec §11.1), not a collision with itself.
        if contested_port(entry) != Some(port) || entry.slug == component.entry.slug {
            continue;
        }
        let incumbent = StackComponent::resolve(entry.slug, None)?;
        let Some(unit) = incumbent.unit(distro.info.family)? else {
            continue;
        };
        if !distro.svc.status(&unit).await.is_ok_and(|s| s.is_active()) {
            continue;
        }

        // Only sites this panel configured can be counted, and only nginx's are
        // ones it rendered — but the count is the part of the sentence that
        // tells an operator what they are about to take offline.
        let sites = if entry.slug == "nginx" {
            ctx.db().all_sites().await.map(|s| s.len()).unwrap_or(0)
        } else {
            0
        };
        let here = entry.display_name;
        let other = component.entry.display_name;
        return Err(UnihelmError::new(
            ErrorCode::Conflict,
            format!(
                "{here} is running and holds port {port}{}. {other} wants the same port, \
                 and installing it now would leave one of the two unable to bind — the \
                 panel will not pick which. Stop {here} first if {other} is meant to \
                 replace it.",
                if sites > 0 {
                    format!(", serving {sites} sites configured here")
                } else {
                    String::new()
                }
            ),
        ));
    }

    // The other branch is not "nothing happened": it is a decision, and an
    // operator who later cannot start the other one deserves to find the reason
    // in this log rather than in a bind() error. It says "nothing else",
    // because reinstalling the thing that is already serving arrives here too.
    ctx.log(format!(
        "nothing else in the catalogue is holding port {port}, so {} will have it. \
         Nothing that wants the same port can be started alongside it without moving \
         one of them elsewhere.",
        component.entry.display_name
    ));
    Ok(())
}

async fn install_component(
    ctx: &OpContext,
    component: StackComponent,
    runtime: catalogue::Runtime,
    extensions: &[PhpExt],
) -> Result<InstallOutput> {
    // One install surface, two ways of running the thing.
    //
    // Which way is [`runtime_for`]'s answer, not the catalogue's: this used to
    // read `default_runtime` directly, so the "Run it" menu on the Stack page
    // decided nothing at all and an operator asking for host packages got a
    // container. The catalogue is still what answers when nobody chose — that
    // decision has just moved to where the caller's own preference is visible.
    //
    // Both branches live here rather than in a second `engine.install` beside
    // this one. The owner's complaint about the old stack was that the panel had
    // several places to install software and they disagreed; adding another
    // would be repeating it in a new shape.
    ctx.log(format!(
        "installing {} {}",
        component.display_name(),
        as_words(runtime)
    ));
    if runtime == catalogue::Runtime::Container {
        let plan = crate::engine::EnginePlan::for_component(component)?;
        crate::engine::refuse_when_the_host_already_runs_this_engine(ctx, &plan).await?;
        let out = crate::engine::install_container(ctx, &plan).await?;
        return Ok(InstallOutput {
            slug: out.slug,
            installed_version: Some(out.version),
            // No packages were installed on this server, and saying so with an
            // empty list is more honest than inventing the image's contents.
            packages: Vec::new(),
            // The resolved runtime rather than a literal, so the field cannot
            // disagree with the branch that produced it.
            runtime: runtime.as_str().into(),
            container: Some(out.container),
            volume: out.volume,
            host_port: Some(out.host_port),
        });
    }

    let distro = ctx.distro().clone();
    let log = ctx.log_sink();

    // 1. The repository, with its key verified against the pin — for the
    //    versions that come from one. Most do not, and adding nothing is the
    //    better answer there: a vendor repository is a key to keep pinned.
    match component.repo(&distro)? {
        None => ctx.log(format!(
            "{} comes from the distribution's own repositories; no repository to add",
            component.display_name()
        )),
        Some(repo) => {
            ctx.log(format!(
                "adding {} ({})",
                repo.definition.display_name, repo.definition.base_url
            ));
            if repo.provenance == unihelm_distro::Provenance::SingleSource {
                ctx.log(format!(
                    "note: this repository's key pin comes from a single source ({}); \
                     verify it against the vendor before relying on it in production",
                    repo.source
                ));
            }

            // Whatever this repository's packages depend on, first. Doing it
            // after would mean the install fails on a missing library with an
            // error that never names the archive it lives in.
            for prerequisite in &repo.prerequisites {
                distro.pkg.ensure_prerequisite(prerequisite, log).await?;
            }

            let key = fetch_key(&repo.definition.gpg_key_url).await?;
            ctx.log(format!("fetched {} bytes of key material", key.len()));
            distro
                .pkg
                .add_repo(&repo.definition, &key, &repo.options, log)
                .await?;
        }
    }

    // 2. The packages.
    let extensions = if extensions.is_empty() {
        PhpExt::DEFAULT
    } else {
        extensions
    };
    let packages = component.packages(&distro, extensions)?;
    ctx.log(format!(
        "installing {}",
        packages
            .iter()
            .map(|p| p.as_str())
            .collect::<Vec<_>>()
            .join(" ")
    ));
    distro.pkg.install(&packages, log).await?;

    // 3. Anything the component needs before it can usefully start.
    match component.entry.slug {
        "nginx" => bootstrap_nginx(ctx).await?,
        // Apache had no arm here at all, and the packages alone are not a web
        // server this panel can serve with: the include that makes Apache read
        // `/etc/apache2/unihelm.d` was written by `webserver.switch` and by
        // nothing else. So `stack install apache` on a machine with no nginx —
        // the state a fresh install with no panel domain is in — enabled and
        // started Apache, wrote no include and no default vhost, and every
        // site created afterwards passed `apachectl configtest` (which never
        // saw the file), reloaded cleanly and was reported live while Apache
        // answered with the distribution's default page.
        "apache" => bootstrap_apache(ctx).await?,
        // A database the panel installed is a database the panel is answerable
        // for.
        "mariadb" => {
            crate::harden::mariadb(ctx).await?;
            if distro.info.family == Family::Rhel {
                // `MariaDB-server` only *recommends* the SELinux policy package,
                // and weak-dependency installation can be disabled host-wide. On
                // an enforcing host a missing policy surfaces later as mysterious
                // `mysqld_safe` denials — say so now, in the task log, where the
                // operator will actually look. Warn, never fail: a lab VM with
                // SELinux permissive is not a broken install.
                warn_if_mysql_selinux_missing(ctx).await;
            }
        }
        // The hardening drop-in and its validator are written against MariaDB's
        // binary. Applying it here would be writing an untested config into
        // somebody's database server, so it is not applied — and the operator is
        // told, rather than left assuming the panel hardened this too.
        "mysql" => ctx.log(
            "Unihelm's database hardening drop-in is written for MariaDB and was not \
             applied to MySQL; review /etc/mysql/mysql.conf.d before exposing this server",
        ),
        "php" => {
            // Before it starts, so the stock `www` pool never gets to spawn a
            // single worker as the web server user.
            crate::fpm::retire_and_log(ctx, component.php_version()?).await;
        }
        "postgres" => {
            // On EL the versioned unit refuses to start until initdb has run;
            // Debian's postgresql-common already created the cluster in postinst.
            bootstrap_postgres(ctx, component.major()?).await?;
        }
        _ => {}
    }

    // 4. Start it, and make it come back after a reboot — where there is
    //    something to start at all.
    match component.unit(distro.info.family)? {
        None => ctx.log(format!(
            "{} installs a toolchain, not a service; there is no unit to enable",
            component.display_name()
        )),
        Some(unit) => {
            distro.svc.enable(&unit, true).await?;

            // `enable --now` succeeding means systemd accepted the request, not
            // that the service is running. A PHP-FPM with no pool exits
            // immediately afterwards, and the install used to report `ok` with
            // the unit dead — an operator told the component installed, and
            // every PHP site on the machine answering 502.
            let state = distro.svc.status(&unit).await.ok();
            if !state.as_ref().is_some_and(|s| s.is_active()) {
                return Err(UnihelmError::new(
                    ErrorCode::ServiceUnavailable,
                    format!(
                        "{unit} was installed and enabled but is not running \
                         ({}). `systemctl status {unit}` and `journalctl -xeu {unit}` \
                         say why.",
                        state
                            .map(|s| format!("{:?}", s.state).to_lowercase())
                            .unwrap_or_else(|| "state unknown".into())
                    ),
                ));
            }
            ctx.log(format!("{unit} enabled and started"));
        }
    }

    // 4b. For a database, "started" is not "ready": every engine here accepts
    // the systemd start-up notification before it accepts connections on a slow
    // first boot (InnoDB initialisation, crash recovery). Handing the operator
    // a component marked installed that refuses connections would make every
    // follow-up step (create database, create user) fail confusingly.
    wait_until_ready(ctx, component).await?;

    // 5. Report the version actually installed, not the one we asked for.
    let installed_version = distro
        .pkg
        .query(&packages[0])
        .await
        .ok()
        .and_then(|s| s.installed_version);

    Ok(InstallOutput {
        slug: component.slug(),
        installed_version,
        packages: packages.iter().map(|p| p.as_str().to_string()).collect(),
        // The host path: packages on this server, nothing containerised.
        runtime: runtime.as_str().into(),
        container: None,
        volume: None,
        host_port: None,
    })
}

/// The default vhost, for a web server that is not (yet) the active one.
///
/// The switch's path. Split out of [`bootstrap_nginx`] rather than duplicated,
/// because the default vhost is the file that decides which site answers for a
/// hostname nobody configured — and two copies of that decision is how the two
/// web servers end up disagreeing about it.
pub async fn write_catchall_for(
    ctx: &OpContext,
    server: crate::webserver::WebServer,
) -> Result<()> {
    let default_certs = paths::default_cert_dir();
    if !crate::tls::certificate_present(&default_certs) {
        crate::tls::write_self_signed(&default_certs, &[])?;
        ctx.log("generated a self-signed certificate for the default server");
    }

    let catchall = server.catchall()?;
    let reloader = server.reloader(ctx.distro())?;

    // Only nginx has a `default_server` keyword to collide over. Apache decides
    // by parse order, so there is nothing to yield and nothing to survey — see
    // `apache/catchall.conf.j2`.
    //
    // Yielding it: `default_server` may appear once per listening address, so on
    // a machine that was already serving sites a second one fails `nginx -t`,
    // the engine rolls the whole apply back, and the panel refuses to set up a
    // stack on a working server — which is the opposite of what a control panel
    // is for.
    let owns_default = if server == crate::webserver::WebServer::Nginx {
        let existing = crate::nginx_survey::survey();
        if existing.has_foreign_default_server() {
            ctx.log(format!(
                "nginx already has a default server ({}); leaving it in place",
                existing
                    .default_server_files
                    .iter()
                    .map(|p| p.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
            false
        } else {
            true
        }
    } else {
        true
    };

    ctx.config()
        .apply(ApplyRequest {
            file: catchall.file,
            template: catchall.template,
            context: serde_json::json!({
                "acme_webroot": paths::acme_webroot(),
                "default_cert": default_certs.join("fullchain.pem"),
                "default_key": default_certs.join("privkey.pem"),
                "owns_default": owns_default,
                "catchall_names": CATCHALL_NAME,
                "catchall_primary": CATCHALL_NAME,
                "http3": false,
            }),
            service: catchall.service,
            validator: server.validator()?,
            reloader: &reloader,
            post_check: None,
            force: false,
            task_id: ctx.task_id().map(|t| t.to_string()),
        })
        .await?;
    Ok(())
}

/// Something has to answer for a hostname nobody configured, and it must not be
/// a name anyone else serves. `.invalid` is reserved for exactly this.
const CATCHALL_NAME: &str = "unihelm-catchall.invalid";

/// The parts of a web server's bootstrap that have nothing to do with which one
/// it is.
///
/// Split out when Apache grew a bootstrap of its own, rather than copied into
/// it: every line here is a *worker* reaching a file — the ACME challenge, the
/// maintenance page, the log directory — and a second copy is how one of the
/// two web servers ends up with a 404 on every challenge that nobody notices
/// until a certificate fails to renew.
fn prepare_the_tree_a_web_server_reads(ctx: &OpContext) -> Result<()> {
    // A self-signed certificate for the catch-all. It is not meant to be
    // trusted; it exists so TLS on the default server is *something*.
    let default_certs = paths::default_cert_dir();
    if !crate::tls::certificate_present(&default_certs) {
        crate::tls::write_self_signed(&default_certs, &[])?;
        ctx.log("generated a self-signed certificate for the default server");
    }

    // The ACME webroot has to exist before the first challenge, and the web
    // server's *workers* have to be able to reach it at request time.
    //
    // This is not the same as reading a certificate: nginx opens those as root
    // during a reload, before dropping privileges. A challenge file is fetched
    // by a worker running as `nginx` (or `www-data` under Apache), and
    // `/var/lib/unihelm` is 0750 unihelm:unihelm — so without this the CA gets a
    // 404 and nginx logs `stat() failed (13: Permission denied)` where nobody
    // looks.
    //
    // `o+x` grants traversal, not listing. `panel.db` (0640) and private keys
    // (0600) stay unreadable to everyone else either way.
    let challenge_dir = paths::acme_webroot().join(".well-known/acme-challenge");
    std::fs::create_dir_all(&challenge_dir)
        .map_err(|e| UnihelmError::internal(format!("could not create the ACME webroot: {e}")))?;
    make_traversable(&[paths::data_dir(), paths::state_dir()])?;
    set_mode(&paths::acme_webroot(), 0o755)?;
    set_mode(&challenge_dir, 0o755)?;

    // The maintenance page, for the same reason and read by the same workers:
    // a suspended tenant's vhost and a site in maintenance mode both answer 503
    // through an internal redirect to `maintenance.html`, so a missing file
    // turns the branded page the panel promises into a bare 404.
    write_maintenance_page_in(&paths::maintenance_root())?;

    std::fs::create_dir_all(paths::site_log_root())
        .map_err(|e| UnihelmError::internal(format!("could not create the log directory: {e}")))?;
    Ok(())
}

/// Everything Apache needs before it is worth starting.
///
/// **This arm did not exist**, and its absence is the release blocker. The
/// panel's Apache footprint is one include — `/etc/apache2/conf-enabled/unihelm.conf`,
/// the single `IncludeOptional` that makes `/etc/apache2/unihelm.d` a directory
/// Apache parses — and it was written only at the end of a successful
/// `webserver.switch`. An operator who installed Apache from the Stack page on
/// a machine with no nginx had nothing to switch *from*, so the include was
/// never written: Apache started, the panel rendered vhosts into a directory
/// nothing includes, `apachectl configtest` passed over a configuration that
/// did not contain them, and every site came back Active while Apache served
/// the distribution's default page.
///
/// The modules and the group membership are here for the same reason they are
/// in the switch and not as a refinement: without `proxy_fcgi` a PHP site is a
/// 500, and without `www-data` in the web group every site directory (0710) and
/// every FPM socket (0660) is unreachable — 403 for static files, 503 for PHP,
/// over a configuration that is otherwise perfect.
async fn bootstrap_apache(ctx: &OpContext) -> Result<()> {
    prepare_the_tree_a_web_server_reads(ctx)?;

    // Before anything is written, as in the switch: a machine that cannot serve
    // with Apache should find that out from a refusal, not from a tree of files
    // it half wrote.
    crate::webserver::ensure_apache_modules(ctx).await?;
    crate::webserver::admit_to_the_web_group(ctx, crate::webserver::WebServer::Apache).await?;

    // The include, then the default vhost — the same two files and the same
    // order the switch writes them in, through the same functions, so the two
    // roads to a serving Apache cannot disagree about what one looks like.
    crate::webserver::write_hook(ctx, crate::webserver::WebServer::Apache).await?;
    write_catchall_for(ctx, crate::webserver::WebServer::Apache).await?;
    ctx.log("default server configured");

    open_web_ports(ctx).await;
    Ok(())
}

/// Everything nginx needs before it is worth starting.
///
/// The include hook, a default server, and a certificate for it — an nginx with
/// no `default_server` serves whichever vhost it parsed first to a request for
/// an unknown host, which is how one customer's site answers for another's
/// domain.
pub async fn bootstrap_nginx(ctx: &OpContext) -> Result<()> {
    let engine = ctx.config();

    prepare_the_tree_a_web_server_reads(ctx)?;

    // The include hook. Written with no validator: nginx may not be running yet,
    // and `nginx -t` on a tree that does not include this file cannot test it.
    engine
        .apply(ApplyRequest {
            file: ManagedFile::nginx(paths::nginx_hook()),
            template: "nginx/unihelm.conf",
            context: serde_json::json!({ "nginx_dir": paths::nginx_dir() }),
            service: "nginx",
            validator: &SkipValidation,
            reloader: &NoReload,
            post_check: None,
            force: false,
            task_id: ctx.task_id().map(|t| t.to_string()),
        })
        .await?;

    // The default server. Now nginx -t can see the whole tree.
    //
    // Through the same function the switch uses, so there is one place that
    // decides what answers for a hostname nobody configured. Two copies of that
    // decision is how the two web servers end up disagreeing about it.
    write_catchall_for(ctx, crate::webserver::WebServer::Nginx).await?;

    ctx.log("default server configured");

    // The web ports. An nginx that is running but unreachable is the single
    // most confusing state a new panel can be in, and it is what the operator
    // gets on a distro image that ships firewalld enabled with only SSH open.
    open_web_ports(ctx).await;

    Ok(())
}

/// Open 80 and 443, if there is a firewall to open them in.
///
/// Deliberately never fatal. A firewall that refuses the change must not undo an
/// otherwise-successful nginx install, and a host with no firewall at all is not
/// an error — the ports are already reachable there. Either way the task log
/// says exactly what happened, because "why can I not reach my site" is
/// answered by that line.
async fn open_web_ports(ctx: &OpContext) {
    let fw = &ctx.distro().fw;

    match fw.is_active().await {
        Ok(true) => {}
        Ok(false) => {
            ctx.log(format!(
                "no active firewall ({}); ports 80 and 443 need no change",
                fw.name()
            ));
            return;
        }
        Err(e) => {
            ctx.log(format!(
                "could not query the firewall ({e}); leaving it alone"
            ));
            return;
        }
    }

    for (port, what) in [(80u16, "http"), (443, "https")] {
        let rule = PortRule::anywhere(port, Proto::Tcp, what);
        match fw.open_port(&rule).await {
            Ok(()) => ctx.log(format!("opened {port}/tcp in {}", fw.name())),
            Err(e) => ctx.log(format!(
                "could not open {port}/tcp in {}: {e} — the site will not be \
                 reachable from outside until this port is open",
                fw.name()
            )),
        }
    }
}

/// What PostgreSQL needs before its unit can start.
///
/// On the RHEL family the PGDG packages install binaries and a unit but **no
/// data directory** — `postgresql-17.service` exits immediately with
/// "Directory /var/lib/pgsql/17/data is missing or empty" until initdb has run.
/// PGDG ships a setup script for exactly this, and its argv is the documented
/// install step: `/usr/pgsql-17/bin/postgresql-17-setup initdb`.
///
/// On the Debian family there is nothing to do: postgresql-common's postinst
/// creates and starts the default `main` cluster during package installation.
async fn bootstrap_postgres(ctx: &OpContext, major: u32) -> Result<()> {
    if ctx.distro().info.family != Family::Rhel {
        ctx.log("postgresql-common created the default cluster during package install");
        return Ok(());
    }

    // The marker initdb itself writes. Present means a previous install (or the
    // operator) already initialised this directory — running initdb again would
    // fail on the non-empty directory, and must not, because reinstalling a
    // component is idempotent (spec §11.1).
    let marker = format!("/var/lib/pgsql/{major}/data/PG_VERSION");
    if std::path::Path::new(&marker).exists() {
        ctx.log("data directory already initialised; skipping initdb");
        return Ok(());
    }

    ctx.log("initialising the PostgreSQL data directory");
    Cmd::new(format!("/usr/pgsql-{major}/bin/postgresql-{major}-setup"))
        .arg("initdb")
        .run_checked()
        .await
        .map_err(UnihelmError::from)?;
    ctx.log("initdb complete");
    Ok(())
}

/// Warn when the SELinux policy for MariaDB did not come along. Never fatal.
async fn warn_if_mysql_selinux_missing(ctx: &OpContext) {
    // `rpm -q` exits non-zero for "not installed"; that is data here, not an
    // error, so `run` rather than `run_checked`.
    match Cmd::new("rpm").args(["-q", "mysql-selinux"]).run().await {
        Ok(out) if out.success() => {
            ctx.log(format!("SELinux policy present: {}", out.trimmed_stdout()));
        }
        _ => ctx.log(
            "warning: mysql-selinux is not installed — on an SELinux-enforcing host, \
             MariaDB may be denied access to its own files. Install it from the \
             distribution's repositories.",
        ),
    }
}

/// One readiness attempt for a component. `None` for everything whose systemd
/// "active" already means "serving" — nginx, php-fpm, the caches, a toolchain.
///
/// Every probe runs as root over the local socket and needs no credentials: the
/// MySQL-family root account authenticates via `unix_socket` on a fresh install,
/// and `pg_isready` only sends an empty startup packet.
fn readiness_probe(component: StackComponent, family: Family) -> Option<Cmd> {
    // `--no-defaults` must be the first argument to any MySQL-family tool or it
    // is ignored: the probe must not be steered by an /etc/my.cnf or ~/.my.cnf
    // an operator left behind.
    let mysql_family_probe = |binary: &str| {
        Some(Cmd::new(binary).args([
            "--no-defaults",
            "--protocol=socket",
            "--user=root",
            "--connect-timeout=3",
            "--execute",
            "SELECT 1",
        ]))
    };

    match component.entry.slug {
        "mariadb" => mysql_family_probe("mariadb"),
        "mysql" => mysql_family_probe("mysql"),
        // `mongosh` ships in the `mongodb-org` metapackage. `--quiet` keeps the
        // banner out of the task log; the ping is the cheapest command that
        // proves the server is past start-up.
        "mongodb" => {
            Some(Cmd::new("mongosh").args(["--quiet", "--eval", "db.adminCommand({ ping: 1 })"]))
        }
        "postgres" => Some(match family {
            // Debian's postgresql-client-common puts a version-routing
            // `pg_isready` on PATH; PGDG on EL installs only versioned paths.
            Family::Debian => Cmd::new("pg_isready").arg("--quiet"),
            Family::Rhel => Cmd::new(format!(
                "/usr/pgsql-{}/bin/pg_isready",
                component.major().ok()?
            ))
            .arg("--quiet"),
        }),
        _ => None,
    }
}

/// Poll a component's readiness probe until it answers, with bounded backoff.
///
/// The schedule (500 ms doubling, capped at 5 s, 12 attempts) allows roughly
/// 45 seconds — generous enough for InnoDB's first-boot initialisation on a
/// 1 GB VPS, small enough that a genuinely broken service fails the task while
/// somebody is still watching it.
async fn wait_until_ready(ctx: &OpContext, component: StackComponent) -> Result<()> {
    const ATTEMPTS: u32 = 12;
    let Some(probe) = readiness_probe(component, ctx.distro().info.family) else {
        return Ok(());
    };

    let mut delay = Duration::from_millis(500);
    let mut last_failure = String::new();
    for attempt in 1..=ATTEMPTS {
        match probe.run().await {
            Ok(out) if out.success() => {
                ctx.log(format!(
                    "{} is accepting connections (attempt {attempt})",
                    component.display_name()
                ));
                return Ok(());
            }
            Ok(out) => last_failure = out.failure_text(),
            // A missing binary or spawn failure is as retryable as a refused
            // connection here — and if it persists, the final error says why.
            Err(e) => last_failure = e.to_string(),
        }
        if attempt < ATTEMPTS {
            tokio::time::sleep(delay).await;
            delay = (delay * 2).min(Duration::from_secs(5));
        }
    }

    Err(UnihelmError::new(
        ErrorCode::ServiceActionFailed,
        format!(
            "{} started but never became ready to accept connections: {last_failure}",
            component.display_name()
        ),
    ))
}

// ---------------------------------------------------------------------------
// stack.remove
// ---------------------------------------------------------------------------

/// `stack.remove` — remove a component, refusing while anything depends on it.
pub struct Remove;

#[derive(Debug, Deserialize)]
pub struct RemoveInput {
    #[serde(flatten)]
    pub component: StackComponent,
    /// Which of the two installs to take off, when the entry offers both.
    ///
    /// Carried for the same reason [`InstallInput::runtime`] is: the page sends
    /// it, and a field the panel accepts and ignores is how "remove the
    /// container" became "run the package manager over packages that were never
    /// installed, and report success". See [`Remove::run`], which refuses that
    /// rather than performing it.
    ///
    /// Absent means the **host**, and not the catalogue's default the way it
    /// does on the install side. The catalogue's preference is an answer about
    /// a fresh install, and this operation removes packages — reading it here
    /// would make a bare `stack.remove mariadb` refuse to touch the host
    /// MariaDB that is actually on the machine.
    #[serde(default)]
    pub runtime: Option<catalogue::Runtime>,
}

#[derive(Debug, Serialize)]
pub struct RemoveOutput {
    pub slug: String,
}

#[async_trait]
impl TypedOperation for Remove {
    type Input = RemoveInput;
    type Output = RemoveOutput;

    const NAME: &'static str = "stack.remove";
    const PERMISSION: Permission = Permission::StackManage;
    const EXECUTION: Execution = Execution::Task {
        cancellable: false,
        idempotent: true,
    };

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let component = input.component;
        let db = ctx.db().clone();

        // What is being removed, before anything is removed. Only when the
        // caller said something: silence here is the host, per
        // [`RemoveInput::runtime`], and putting it through `runtime_for` would
        // read the catalogue's *install* preference as a removal target.
        //
        // A container is refused rather than attempted. Everything below this
        // point is the package manager; a container has no packages, so the
        // removal would run to completion, touch nothing, mark the row removed
        // and report success while the container carried on serving.
        // `engine.remove` is the operation that takes a container off, and the
        // refusal says so rather than leaving the operator to find out.
        if let Some(asked) = input.runtime
            && runtime_for(component, Some(asked))? == catalogue::Runtime::Container
        {
            return Err(UnihelmError::new(
                ErrorCode::InvalidInput,
                format!(
                    "`stack.remove` removes {}'s packages from this server, and a container \
                     has none — running it here would report a removal that did not happen. \
                     Remove the container with `engine.remove` (`unihelm engine remove {}`).",
                    component.display_name(),
                    component.entry.slug,
                ),
            )
            .with_field("runtime"));
        }

        // Everything past the refusal above is the package manager, so the row
        // this clears is the host one — derived through the same function the
        // install used, so the two can never spell it differently.
        let slug = row_key(component, catalogue::Runtime::Host)?;

        // Removing PHP 8.3 while sites are running on it takes those sites down
        // (spec §11.1). Refuse and say which ones.
        if component.entry.slug == "php" {
            let version = component.php_version()?;
            let dependents: Vec<String> = db
                .all_sites()
                .await
                .map_err(UnihelmError::from)?
                .into_iter()
                .filter(|s| s.php_version == Some(version))
                .map(|s| s.domain)
                .collect();

            if !dependents.is_empty() {
                return Err(UnihelmError::new(
                    ErrorCode::DependentsExist,
                    format!(
                        "{} sites still use PHP {}: {}. Move them to another version first.",
                        dependents.len(),
                        version.as_str(),
                        dependents.join(", ")
                    ),
                ));
            }
        }

        // The web server that is actually serving, not nginx by name.
        //
        // Keyed on the literal slug, this guarded the wrong thing twice over on
        // a machine switched to Apache: removing Apache — the one holding every
        // site up — was allowed, and removing nginx, which by then serves
        // nothing, was refused.
        let serving = crate::webserver::active(ctx).await?;
        if component.entry.slug == serving.as_str() {
            let site_count = db.all_sites().await.map_err(UnihelmError::from)?.len();
            // The panel counts as a dependent here for the same reason it does
            // in the stop guard, and it is worse on this path: a removal takes
            // the packages as well, so an operator locked out of a stopped
            // nginx can at least start it from the console, while one who
            // removed it has to install a web server over ssh before the panel
            // answers again.
            let panel = the_panel_behind_this_web_server(ctx).await?;
            if site_count > 0 || panel.is_some() {
                return Err(UnihelmError::new(
                    ErrorCode::DependentsExist,
                    format!(
                        "{} is what serves this machine{}{}. Switch to another web server \
                         first — that moves everything behind it across — and this becomes \
                         a safe removal.",
                        serving.display_name(),
                        match &panel {
                            // A removal takes the packages too, so even the
                            // half-reachable case is worse here than it is for
                            // a stop: nothing is left to start again.
                            Some(route) => format!(", and {}", route.what_removal_costs()),
                            None => String::new(),
                        },
                        match site_count {
                            0 => String::new(),
                            n => format!(
                                "; {n} sites are still configured and removing it takes \
                                 them all offline"
                            ),
                        },
                    ),
                ));
            }
        }

        let distro = ctx.distro().clone();
        refuse_to_remove_a_version_that_is_not_the_one_here(ctx, component).await?;

        let task_id = ctx.task_id().map(|t| t.to_string()).unwrap_or_default();
        if !db
            .claim_component(&slug, ComponentStatus::Removing, &task_id)
            .await
            .map_err(UnihelmError::from)?
        {
            return Err(UnihelmError::new(
                ErrorCode::Conflict,
                format!(
                    "{} is already being installed or removed",
                    component.display_name()
                ),
            ));
        }

        let packages = component.packages(&distro, PhpExt::DEFAULT)?;

        // Only stop the service when this component's own packages are on the
        // machine. A unit answering to this name may belong to another package:
        // on Debian MariaDB installs `mysql.service` as an alias of its own
        // unit, so `stack.remove mysql` on a MariaDB server used to run
        // `systemctl disable --now mysql.service` and stop the live database —
        // over packages that were never installed and are about to be a no-op.
        if installed_package_version(&distro, component)
            .await
            .is_some()
        {
            if let Some(unit) = component.unit(distro.info.family)? {
                let _ = distro.svc.disable(&unit, true).await;
            }
        } else {
            ctx.log(format!(
                "none of {}'s packages are installed; leaving every service on this \
                 machine alone and letting the package removal be the no-op it is",
                component.display_name()
            ));
        }

        let outcome = distro.pkg.remove(&packages, ctx.log_sink()).await;

        match outcome {
            Ok(_) => {
                db.component_removed(&slug)
                    .await
                    .map_err(UnihelmError::from)?;
                Ok(RemoveOutput { slug })
            }
            Err(e) => {
                let _ = db.component_failed(&slug, &e.to_string()).await;
                Err(e.into())
            }
        }
    }
}

/// Refuse to remove a version whose packages are shared with another version
/// that *is* installed.
///
/// The catalogue marks Node side by side, but NodeSource ships a single `nodejs`
/// package — one major at a time. So `stack.remove node --version 20` on a
/// machine running Node 22 would resolve to `nodejs`, uninstall the major that
/// is actually there, and take every Node service on the box down with it. PHP
/// has the same `side_by_side` flag and no such problem, because its package
/// names carry the version; the test is therefore whether the packages are
/// shared, not which entry this is.
///
/// Removing something genuinely absent stays a no-op, as removal has to
/// (spec §11.1) — only removing *the wrong one* is refused.
async fn refuse_to_remove_a_version_that_is_not_the_one_here(
    ctx: &OpContext,
    component: StackComponent,
) -> Result<()> {
    let distro = ctx.distro();
    if !component.shares_packages_with_its_other_versions(distro) {
        return Ok(());
    }
    // Not installed at all: nothing to take down, and refusing would make a
    // repeated removal fail.
    let Some(installed) = installed_package_version(distro, component).await else {
        return Ok(());
    };
    if package_is_installed(distro, component).await {
        return Ok(());
    }

    Err(UnihelmError::new(
        ErrorCode::Conflict,
        format!(
            "{} installs one package for every version, and the one on this machine is {}. \
             Removing {} would uninstall it and stop whatever is running on it, so the \
             panel will not do it — remove the version that is actually here instead.",
            component.entry.display_name,
            installed.as_deref().unwrap_or("another version"),
            component.display_name(),
        ),
    ))
}

// ---------------------------------------------------------------------------
// stack.start / stack.stop
// ---------------------------------------------------------------------------

/// What `stack.start` and `stack.stop` take: one catalogue entry, and for the
/// side-by-side ones the version, because `php8.3-fpm` and `php8.4-fpm` are two
/// services.
///
/// No `runtime`: these act on a systemd unit, and a container has none. Stopping
/// a containerised engine is `docker.stop`.
#[derive(Debug, Deserialize)]
pub struct ServiceInput {
    #[serde(flatten)]
    pub component: StackComponent,
    /// The component's own catalogue slug, said back by whoever is asking, for
    /// a stop that takes something else down with it.
    ///
    /// Ignored by `stack.start`, which takes nothing down, and unnecessary for
    /// a stop with nothing behind it — the refusal that asks for it names the
    /// string, so it is never a guess. `user.delete` and `db.drop` take the
    /// same kind of confirmation for the same reason: a click is not a decision
    /// when what it costs is not on the button.
    ///
    /// The slug rather than the unit name, so that every client already holds
    /// it: a page that had to derive `docker.service` in order to confirm
    /// stopping Docker would be keeping a second copy of the slug-to-unit table
    /// this file owns, and that table drifting is how a control acts on the
    /// wrong unit.
    #[serde(default)]
    pub confirm: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ServiceOutput {
    pub slug: String,
    /// The unit systemd was actually told about, so a task log names it rather
    /// than the slug the operator typed.
    pub unit: String,
    pub action: &'static str,
    pub unit_state: String,
    pub unit_active: bool,
}

/// `stack.start` — start the service a catalogue entry installed.
pub struct Start;

/// `stack.stop` — stop it, unless stopping it takes something else down.
///
/// Two guards and they answer differently on purpose. The web server that is
/// serving is a flat refusal: there is a way through that leaves the machine
/// serving, so the panel takes it rather than asking. Everything else is a
/// refusal that names what goes with it and can be confirmed, because there is
/// no other way to stop Docker and a control panel with something it cannot
/// stop is what this pair was added to fix.
pub struct Stop;

#[async_trait]
impl TypedOperation for Start {
    type Input = ServiceInput;
    type Output = ServiceOutput;

    const NAME: &'static str = "stack.start";
    // `server_manage` and not `stack_manage`: this changes service state, which
    // is the permission's own description, and it is what `svc.action` already
    // requires for the identical act. Filing it under the stack namespace it is
    // reached from must not quietly widen who may do it.
    const PERMISSION: Permission = Permission::ServerManage;
    // The fast lane, for `svc.action`'s reason: a package install that has been
    // running for four minutes must never be why a start button does nothing.
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        act_on_the_service(ctx, input.component, SvcAction::Start).await
    }
}

#[async_trait]
impl TypedOperation for Stop {
    type Input = ServiceInput;
    type Output = ServiceOutput;

    const NAME: &'static str = "stack.stop";
    const PERMISSION: Permission = Permission::ServerManage;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        refuse_to_stop_what_is_serving(ctx, input.component).await?;
        // The web server was the only stop this operation knew the cost of, and
        // four of the six controllable slugs went straight through. Docker is
        // the widest: on a default install every database and cache is a
        // container, so one unconfirmed click on the Stop beside Docker takes
        // the lot down while nginx and PHP-FPM keep serving database-connection
        // errors.
        refuse_to_stop_what_others_are_riding_on(ctx, input.component, input.confirm.as_deref())
            .await?;
        act_on_the_service(ctx, input.component, SvcAction::Stop).await
    }
}

/// Tell systemd, then check it happened.
///
/// The second half is the part worth writing down. `systemctl start` exiting
/// zero means systemd accepted the request, not that the service is running —
/// the install path learned that when a PHP-FPM with no pool exited immediately
/// after `enable --now` and the install reported `ok` over a machine answering
/// 502 on every PHP site. A start that reports success over a unit that died on
/// start-up is the same lie, so the state afterwards is read and disagreed with.
async fn act_on_the_service(
    ctx: &OpContext,
    component: StackComponent,
    action: SvcAction,
) -> Result<ServiceOutput> {
    let unit = component.managed_unit()?;
    let name = unit.unit_name(ctx.distro().info.family);

    ctx.log(format!("{} {name}", action.as_str()));
    ctx.distro().svc.action(&name, action).await?;

    let status = ctx.distro().svc.status(&name).await?;
    let wanted_active = matches!(action, SvcAction::Start);
    if status.is_active() != wanted_active {
        return Err(UnihelmError::new(
            ErrorCode::ServiceActionFailed,
            format!(
                "{name} was told to {} and systemd accepted it, but the unit is {}. \
                 `systemctl status {name}` and `journalctl -xeu {name}` say why.",
                action.as_str(),
                format!("{:?}", status.state).to_lowercase(),
            ),
        ));
    }

    Ok(ServiceOutput {
        slug: component.slug(),
        unit: name.as_str().to_string(),
        action: action.as_str(),
        unit_state: format!("{:?}", status.state).to_lowercase(),
        unit_active: status.is_active(),
    })
}

/// Refuse to stop the web server this machine serves with while anything is
/// riding on it — its sites, or the panel itself.
///
/// There was no way to stop a web server from the panel at all until this pair
/// existed, which is how a machine that came up serving with Apache had nothing
/// anywhere in the UI that could take it off port 80. The control is the fix;
/// this is the sentence that has to come with it. One click here is every site
/// on the server going dark, and "taking a machine offline" is not a thing a
/// panel should do without saying so first.
///
/// Judged on which server actually serves (never nginx by name; a machine
/// switched to Apache had that guard pointing at the wrong one for a release)
/// and on what is behind it. A site that is suspended or failed is already not
/// being served, so it is not a reason to refuse: "every site is already down"
/// is the state in which stopping costs nothing, and it has to stay reachable or
/// the incumbent could never be stopped at all.
///
/// **The panel is behind it too**, and it was not counted. That is new in this
/// release rather than an oversight from an old one — `panel.tls.issue` narrows
/// `panel.listen` to loopback once its own vhost is serving — but the guard was
/// written to prevent exactly this class of damage and did not see the one
/// dependent whose loss cannot be undone from the panel.
async fn refuse_to_stop_what_is_serving(ctx: &OpContext, component: StackComponent) -> Result<()> {
    let Some(server) = crate::webserver::WebServer::from_slug(component.entry.slug) else {
        return Ok(());
    };
    if crate::webserver::active(ctx).await? != server {
        return Ok(());
    }

    let live: Vec<String> = ctx
        .db()
        .all_sites()
        .await
        .map_err(UnihelmError::from)?
        .into_iter()
        .filter(|s| s.status == unihelm_db::SiteStatus::Active)
        .map(|s| s.domain)
        .collect();
    let panel = the_panel_behind_this_web_server(ctx).await?;

    if live.is_empty() && panel.is_none() {
        return Ok(());
    }

    // The panel's own vhost, which this guard did not look at and which this
    // release is the one that made load-bearing. `panel.tls.issue` now narrows
    // `panel.listen` to loopback once the vhost is live and closes the direct
    // port behind it, so from then on `01-panel.conf` in *this* web server's
    // tree is the only way in. On the recommended first move — point a domain
    // at the box and issue the panel certificate before creating any sites —
    // `live` is empty, and this used to return `Ok(())`: one click stopped
    // nginx and left the operator with no panel and no route back but the
    // console. The old sentence made it worse by telling them to suspend their
    // sites first, which is the state that reaches the lockout fastest.
    let mut because = Vec::new();
    if let Some(route) = &panel {
        because.push(route.what_stopping_costs());
    }
    if !live.is_empty() {
        because.push(format!(
            "{} sites are still up on it: {}",
            live.len(),
            live.join(", ")
        ));
    }

    // The way through, and only the ones that are actually open. The old
    // sentence offered "suspend those sites" unconditionally, which on a
    // machine whose panel is behind this vhost is an instruction that walks the
    // operator into the lockout: every site can be suspended and the panel is
    // still gone.
    let way_through = match (&panel, live.is_empty()) {
        (Some(_), _) => "Switch to another web server first — that moves the panel's vhost \
                         across with the sites, and this becomes a stop with nothing \
                         behind it."
            .to_string(),
        (None, false) => "Switch to another web server first, or suspend those sites, and \
                          this becomes a stop with nothing behind it."
            .to_string(),
        // Unreachable: with no panel and no live site the guard returned above.
        (None, true) => String::new(),
    };

    Err(UnihelmError::new(
        ErrorCode::DependentsExist,
        format!(
            "{} is what serves this machine, and {}. {way_through}{}",
            server.display_name(),
            because.join("; and "),
            match &panel {
                // Named only where it is not a lockout. `svc.action` stops the
                // same unit without this guard, and pointing an operator at it
                // while the vhost is their only way in would be handing them
                // the rope — which is what the old sentence did by suggesting
                // they suspend their sites.
                Some(PanelRoute::AndADirectPort { port, .. }) => format!(
                    " If losing the panel's own name is acceptable, `svc.action` stops the \
                     same unit without this guard and the panel keeps answering on port \
                     {port}."
                ),
                _ => String::new(),
            },
        ),
    ))
}

/// How the panel is reached, when it is reached through this web server at all.
///
/// Two facts and not one, because the cost of the stop is different. Once
/// `panel.rs`'s `narrow_listener_to_loopback` has run — which is what
/// `panel.tls.issue` does on success — the vhost is the whole route in and
/// stopping the web server is a lockout. Before that, `panel.listen` is still a
/// network address and the panel keeps answering there: the operator loses the
/// name they use and nothing else, which is worth refusing over and not worth
/// refusing *silently*, so that case names the way through instead.
///
/// The reachability question is asked through the same function the firewall
/// rules use, so a stop and a `fw.port.close` cannot disagree about whether
/// there is another way in.
enum PanelRoute {
    /// The vhost, and nothing else.
    OnlyTheVhost { domain: String },
    /// The vhost, plus a `panel.listen` the network can still dial.
    AndADirectPort { domain: String, port: u16 },
}

impl PanelRoute {
    fn what_stopping_costs(&self) -> String {
        match self {
            PanelRoute::OnlyTheVhost { domain } => format!(
                "this panel is served through it at {domain} and `panel.listen` is on \
                 loopback, so stopping it leaves no way back in except the console"
            ),
            PanelRoute::AndADirectPort { domain, port } => format!(
                "this panel is served through it at {domain}, so stopping it takes the \
                 panel off its own address (it would still answer on port {port})"
            ),
        }
    }

    fn what_removal_costs(&self) -> String {
        match self {
            PanelRoute::OnlyTheVhost { domain } => format!(
                "this panel is served through it at {domain} with `panel.listen` on \
                 loopback, so removing it leaves no way back in except the console — and \
                 nothing left to start again once you are there"
            ),
            PanelRoute::AndADirectPort { domain, port } => format!(
                "this panel is served through it at {domain}, so removing it takes the \
                 panel off its own address for good (it would still answer on port {port})"
            ),
        }
    }
}

async fn the_panel_behind_this_web_server(ctx: &OpContext) -> Result<Option<PanelRoute>> {
    let domain: Option<unihelm_core::Domain> = ctx
        .db()
        .get_setting(unihelm_db::panel::DOMAIN_KEY)
        .await
        .map_err(UnihelmError::from)?;
    let Some(domain) = domain else {
        return Ok(None);
    };
    let domain = domain.as_str().to_string();
    Ok(Some(
        match crate::panel::panel_port_reachable_from_network() {
            Some(port) => PanelRoute::AndADirectPort { domain, port },
            None => PanelRoute::OnlyTheVhost { domain },
        },
    ))
}

/// Refuse a stop that takes something else down, and say what.
///
/// The gap this closes: `stack.stop` ran one check, and it looked only at the
/// web server. Four of the six controllable slugs — php, mariadb, redis,
/// docker — went straight through to `svc.action` with no guard, no
/// confirmation and no count, while `stack.remove` on the *same* components
/// refuses and names the dependents. Docker is the widest of them: on a default
/// install `mariadb`, `postgres` and `redis` are `Install::Either { default:
/// Container }`, so the engines are containers and one click on the Stop beside
/// the Docker row takes every database on the machine down at once — with nginx
/// and PHP-FPM still up, so every site serves connection errors rather than
/// going cleanly offline.
///
/// Confirmable rather than flatly refused, and that is the difference from
/// [`refuse_to_stop_what_is_serving`]. Stopping the web server has a way
/// through that leaves the machine serving (switch, or suspend); stopping
/// Docker to work on it does not, and a refusal with no way through would put
/// back the thing this control was added to fix — a machine with something the
/// panel cannot stop. So the operator is told exactly what goes with it and
/// asked to say the component's name back.
///
/// The catalogue slug rather than the unit, because that is the string the
/// caller already sent and can check by eye: an operator reading
/// `docker.service` in a refusal cannot tell whether it is the row they pressed,
/// and a client that had to derive a unit name to confirm a stop would be
/// keeping a second copy of the slug-to-unit table this file owns. The unit is
/// still named in the sentence — it is what systemd is told about — but it is
/// not what has to be typed.
async fn refuse_to_stop_what_others_are_riding_on(
    ctx: &OpContext,
    component: StackComponent,
    confirm: Option<&str>,
) -> Result<()> {
    let unit = component
        .managed_unit()?
        .unit_name(ctx.distro().info.family);
    let riders = what_is_riding_on(ctx, component).await?;
    if riders.is_empty() {
        return Ok(());
    }

    if confirm.map(str::trim) == Some(component.entry.slug) {
        return Ok(());
    }

    Err(UnihelmError::new(
        ErrorCode::DependentsExist,
        format!(
            "stopping {} ({unit}) stops {}:\n\n{}\n\nNothing is deleted and the Start \
             beside it brings them back, but they go down now and stay down until it \
             does. Confirm with `{slug}` to go ahead.",
            component.display_name(),
            a_list_of(&riders.iter().map(|r| r.what.clone()).collect::<Vec<_>>()),
            riders
                .iter()
                .map(|r| format!("  - {}", r.detail))
                .collect::<Vec<_>>()
                .join("\n"),
            unit = unit.as_str(),
            slug = component.entry.slug,
        ),
    )
    .with_field("confirm"))
}

/// One kind of thing that goes down with a unit.
struct Rider {
    /// Counted and named for the summary line: "3 databases".
    what: String,
    /// The sentence under it, which names them.
    detail: String,
}

/// What the panel's own records say depends on this unit.
///
/// **Records, never a probe.** `docker ps` would answer more completely and
/// would also make this refusal disagree with itself on a machine whose daemon
/// is slow: a stop that is refused or allowed depending on whether a shell-out
/// timed out is worse than one that is consistently narrow. So every count here
/// is a row this panel wrote, and the refusal says as much.
async fn what_is_riding_on(ctx: &OpContext, component: StackComponent) -> Result<Vec<Rider>> {
    let db = ctx.db();
    let mut found = Vec::new();

    match component.entry.slug {
        "docker" => {
            // Every containerised engine on the machine. `engine::registry` is
            // the panel's own record that it built these containers and holds
            // their credentials, so this is exact — and on a default install it
            // is every database and cache the machine has.
            let registry = crate::engine::registry(db).await?;
            let mut engines: Vec<String> = registry.values().map(|r| r.container.clone()).collect();
            engines.sort();
            if !engines.is_empty() {
                found.push(Rider {
                    what: format!(
                        "{} containerised {}",
                        engines.len(),
                        plural(engines.len(), "engine", "engines")
                    ),
                    detail: format!(
                        "{}: every database and cache in them stops accepting connections, \
                         so sites that use them serve connection errors rather than going \
                         offline",
                        engines.join(", ")
                    ),
                });
            }

            let mut apps: Vec<String> = db
                .node_apps(&unihelm_core::TenantScope::Global)
                .list(APP_SCAN_LIMIT, 0)
                .await
                .map_err(UnihelmError::from)?
                .into_iter()
                .filter(|a| a.mode == unihelm_db::node_apps::AppMode::Container)
                .map(|a| a.name)
                .collect();
            apps.sort();
            if !apps.is_empty() {
                found.push(Rider {
                    what: format!(
                        "{} containerised {}",
                        apps.len(),
                        plural(apps.len(), "application", "applications")
                    ),
                    detail: format!(
                        "{}: each one is a container, so the site in front of it starts \
                         answering 502",
                        apps.join(", ")
                    ),
                });
            }
        }
        // The same list `stack.remove` refuses on, for the same reason: a stop
        // and a removal cost these sites the same thing. `remove` will not do
        // it at all; `stop` is reversible by the button beside it, so it asks.
        "php" => {
            let version = component.php_version()?;
            let mut sites: Vec<String> = db
                .all_sites()
                .await
                .map_err(UnihelmError::from)?
                .into_iter()
                .filter(|s| {
                    s.php_version == Some(version) && s.status == unihelm_db::SiteStatus::Active
                })
                .map(|s| s.domain)
                .collect();
            sites.sort();
            if !sites.is_empty() {
                found.push(Rider {
                    what: format!("{} {}", sites.len(), plural(sites.len(), "site", "sites")),
                    detail: format!(
                        "{}: every PHP request on them answers 502 until the pool is \
                         running again",
                        sites.join(", ")
                    ),
                });
            }
        }
        // Only where the answer is not a guess. `dbs` rows record the engine
        // family (`mysql`) and not *which* server holds them, so on a machine
        // running both a host MariaDB and a containerised one the panel cannot
        // say which of the two a database lives in — and a refusal that names
        // databases the stop would not touch is the panel stating something it
        // has not checked. Where there is no containerised MySQL-family engine,
        // the host install is the only place they can be.
        "mariadb" => {
            let containerised = crate::engine::registry(db)
                .await?
                .values()
                .any(|r| matches!(r.slug.as_str(), "mariadb" | "mysql"));
            if !containerised {
                let count = db
                    .databases(&unihelm_core::TenantScope::Global)
                    .list(APP_SCAN_LIMIT, 0)
                    .await
                    .map_err(UnihelmError::from)?
                    .into_iter()
                    .filter(|d| d.engine == unihelm_db::DbEngine::Mysql)
                    .count();
                if count > 0 {
                    found.push(Rider {
                        what: format!(
                            "{count} {}",
                            plural(count, "MySQL database", "MySQL databases")
                        ),
                        detail: format!(
                            "{count} {} on this server, and every site and application \
                             that connects to one starts failing at the connection",
                            plural(count, "database is recorded", "databases are recorded")
                        ),
                    });
                }
            }
        }
        // Redis and the web servers are deliberately absent. Nothing in the
        // panel's records says which sites use a cache, so a count here would
        // be invented; the web servers have their own guard above, which is a
        // refusal rather than a question.
        _ => {}
    }

    Ok(found)
}

/// How many rows a dependent scan reads before it stops counting.
///
/// The repositories cap a page at 500 of their own accord. A machine with more
/// applications than this has a refusal that under-counts rather than one that
/// pages through the whole table to build a sentence — and under-counting still
/// refuses, which is the part that matters.
const APP_SCAN_LIMIT: i64 = 500;

fn plural(n: usize, one: &'static str, many: &'static str) -> &'static str {
    if n == 1 { one } else { many }
}

/// "3 databases, 2 applications and 1 cache" — the summary an operator reads
/// before they read the list.
fn a_list_of(parts: &[String]) -> String {
    match parts {
        [] => String::new(),
        [only] => only.clone(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    }
}

/// Add the execute bit for "other" so a service running as another account can
/// traverse into a subdirectory, without being able to list what is there.
fn make_traversable(dirs: &[std::path::PathBuf]) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    for dir in dirs {
        let Ok(metadata) = std::fs::metadata(dir) else {
            continue;
        };
        let mode = metadata.permissions().mode() & 0o7777;
        if mode & 0o001 == 0 {
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(mode | 0o001)).map_err(
                |e| UnihelmError::internal(format!("could not chmod {}: {e}", dir.display())),
            )?;
        }
    }
    Ok(())
}

fn set_mode(path: &std::path::Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .map_err(|e| UnihelmError::internal(format!("could not chmod {}: {e}", path.display())))
}

/// The page every 503 lands on until an operator replaces it.
///
/// Self-contained on purpose: it is served while the site behind it is down, so
/// a stylesheet, a font or an image would be one more request to a vhost that
/// is answering 503 to everything.
const DEFAULT_MAINTENANCE_PAGE: &str = r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Temporarily unavailable</title>
<style>
  body { margin: 0; min-height: 100vh; display: flex; align-items: center;
         justify-content: center; background: #f6f7f9; color: #1f2430;
         font: 16px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif; }
  main { max-width: 32rem; padding: 2rem; text-align: center; }
  h1 { font-size: 1.5rem; margin: 0 0 0.5rem; }
  p { margin: 0; color: #5b6472; }
</style>
</head>
<body>
<main>
  <h1>Temporarily unavailable</h1>
  <p>This site is down for maintenance. Please try again shortly.</p>
</main>
</body>
</html>
"#;

/// Create the maintenance root and seed the page nginx redirects 503s to.
///
/// Split out so the tests can work in a temporary directory: `paths::set_root`
/// is a process-wide `OnceLock`, which a parallel test binary cannot use to give
/// each test its own tree.
///
/// An existing page is never overwritten — replacing `maintenance.html` is how
/// an operator brands it, and bootstrap runs again on every nginx install.
fn write_maintenance_page_in(root: &std::path::Path) -> Result<()> {
    std::fs::create_dir_all(root).map_err(|e| {
        UnihelmError::internal(format!("could not create the maintenance directory: {e}"))
    })?;

    let page = root.join("maintenance.html");
    if !page.exists() {
        std::fs::write(&page, DEFAULT_MAINTENANCE_PAGE).map_err(|e| {
            UnihelmError::internal(format!("could not write the maintenance page: {e}"))
        })?;
        set_mode(&page, 0o644)?;
    }
    set_mode(root, 0o755)?;
    Ok(())
}

/// Download a repository's signing key.
///
/// Bounded and short-timeout: this runs inside a task the user is watching, and
/// a vendor whose key server is down should produce a clear failure rather than
/// a hung install.
pub(crate) async fn fetch_key(url: &str) -> Result<Vec<u8>> {
    /// No vendor's keyring is anywhere near this large.
    const MAX_KEY_BYTES: usize = 1024 * 1024;

    if !url.starts_with("https://") {
        return Err(UnihelmError::internal(format!(
            "refusing to fetch a key over `{url}`"
        )));
    }

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent(concat!("unihelm/", env!("CARGO_PKG_VERSION")))
        // A redirect to http:// would silently drop the transport security we
        // are relying on to bootstrap trust.
        .https_only(true)
        .build()
        .map_err(|e| UnihelmError::internal(format!("could not build an HTTP client: {e}")))?;

    let response = client.get(url).send().await.map_err(|e| {
        UnihelmError::new(
            ErrorCode::PackageBackendFailed,
            format!("could not fetch the signing key from {url}: {e}"),
        )
    })?;

    if !response.status().is_success() {
        return Err(UnihelmError::new(
            ErrorCode::PackageBackendFailed,
            format!("{url} returned {}", response.status()),
        ));
    }

    let bytes = response.bytes().await.map_err(|e| {
        UnihelmError::new(
            ErrorCode::PackageBackendFailed,
            format!("could not read {url}: {e}"),
        )
    })?;

    if bytes.len() > MAX_KEY_BYTES {
        return Err(UnihelmError::new(
            ErrorCode::PackageBackendFailed,
            format!("{url} served {} bytes, which is not a keyring", bytes.len()),
        ));
    }
    Ok(bytes.to_vec())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use unihelm_core::{AuthContext, Role, TenantScope, UserId};
    use unihelm_db::Db;
    use unihelm_distro::mock::{SharedRecorder, mock_distro_with_recorder};

    use super::*;
    use crate::registry::testing::{auth_for, registry};

    fn c(slug: &str) -> StackComponent {
        StackComponent::resolve(slug, None).unwrap()
    }

    fn cv(slug: &str, version: &str) -> StackComponent {
        StackComponent::resolve(slug, Some(version)).unwrap()
    }

    fn names(component: StackComponent, distro: &Distro) -> Vec<String> {
        component
            .packages(distro, PhpExt::DEFAULT)
            .unwrap()
            .iter()
            .map(|p| p.as_str().to_string())
            .collect()
    }

    /// An OpContext over a recorded mock distro and an in-memory database,
    /// built directly (as in `nodeapp.rs`) because these tests need the
    /// recorder and no dispatch happens on the way in.
    async fn op_ctx(family: Family) -> (OpContext, Distro, SharedRecorder) {
        let (distro, rec) = mock_distro_with_recorder(family);
        let db = Db::open_memory().await.unwrap();
        let services = Arc::new(
            crate::registry::Services::new(distro.clone(), db, unihelm_db::MasterKey::generate())
                .expect("templates compile"),
        );
        let auth = AuthContext::from_role(UserId(1), Role::Admin, TenantScope::Global, "req-test");
        (OpContext::new(services, auth), distro, rec)
    }

    // -- the catalogue is the boundary --------------------------------------

    #[test]
    fn a_component_cannot_be_an_arbitrary_package() {
        // The property the old enum had, now held by the catalogue lookup: no
        // API caller can ask the panel to `apt install` something of their
        // choosing, and the refusal happens at deserialisation.
        assert!(serde_json::from_str::<StackComponent>(r#"{"component":"nginx"}"#).is_ok());
        assert!(
            serde_json::from_str::<StackComponent>(r#"{"component":"php","version":"8.3"}"#)
                .is_ok()
        );
        assert!(serde_json::from_str::<StackComponent>(r#"{"component":"mariadb"}"#).is_ok());
        assert!(serde_json::from_str::<StackComponent>(r#"{"component":"postgres"}"#).is_ok());
        for bad in [
            r#"{"component":"backdoor"}"#,
            r#"{"component":"php","version":"9.9"}"#,
            r#"{"component":"mariadb","version":"../../etc/passwd"}"#,
            r#"{"component":"nginx; rm -rf /"}"#,
            r#""nginx""#,
        ] {
            assert!(
                serde_json::from_str::<StackComponent>(bad).is_err(),
                "{bad} should not parse"
            );
        }
    }

    #[test]
    fn the_whole_catalogue_is_installable_now_and_not_only_four_things() {
        // The complaint this rework answers: the panel offered what the enum had
        // variants for. Every slug the catalogue lists must resolve.
        for entry in catalogue::CATALOGUE {
            for version in entry.versions {
                let component = StackComponent::resolve(entry.slug, Some(version.version))
                    .unwrap_or_else(|e| panic!("{}/{}: {}", entry.slug, version.version, e.detail));
                assert_eq!(component.entry.slug, entry.slug);
                assert_eq!(component.version.version, version.version);
            }
        }
        assert!(
            catalogue::CATALOGUE.len() > 4,
            "the catalogue is the offer now"
        );
    }

    #[test]
    fn an_unknown_slug_says_what_is_on_offer() {
        let err = StackComponent::resolve("cassandra", None).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidInput);
        assert!(err.detail.contains("mariadb"), "{}", err.detail);

        let err = StackComponent::resolve("mariadb", Some("5.5")).unwrap_err();
        assert!(err.detail.contains("11.8"), "{}", err.detail);

        // And it survives the route an API caller actually takes. `flatten`
        // buffers the object before the conversion runs, and serde is entitled
        // to replace a `TryFrom` error with a message of its own — a refusal
        // that arrives as "invalid type" tells an operator nothing about what
        // the panel does install.
        let err = serde_json::from_str::<InstallInput>(r#"{"component":"cassandra"}"#).unwrap_err();
        assert!(err.to_string().contains("mariadb"), "{err}");
    }

    #[test]
    fn the_wire_shape_from_before_the_catalogue_still_parses() {
        // `{"component":"php","version":"8.3"}` is what the CLI, the web layer
        // and every stored task input already send.
        let php: StackComponent =
            serde_json::from_str(r#"{"component":"php","version":"8.3"}"#).unwrap();
        assert_eq!(php.slug(), "php8.3");
        // And a bare component still means "whatever you recommend".
        let mariadb: StackComponent = serde_json::from_str(r#"{"component":"mariadb"}"#).unwrap();
        assert_eq!(mariadb.version.version, "11.8");

        let input: InstallInput =
            serde_json::from_str(r#"{"component":"php","version":"8.4","extensions":["redis"]}"#)
                .unwrap();
        assert_eq!(input.component.slug(), "php8.4");
        assert_eq!(input.extensions.len(), 1);
    }

    #[test]
    fn component_slugs_are_stable_and_distinct() {
        assert_eq!(c("nginx").slug(), "nginx");
        assert_eq!(cv("php", "8.3").slug(), "php8.3");
        assert_eq!(c("mariadb").slug(), "mariadb");
        assert_eq!(c("postgres").slug(), "postgres");
        // A version only joins the slug where two of them can coexist; MariaDB
        // 11.4 replaces MariaDB 11.8 in the same row.
        assert_eq!(cv("mariadb", "11.4").slug(), "mariadb");
        assert_eq!(cv("node", "22").slug(), "node22");

        let mut slugs: Vec<String> = Vec::new();
        for entry in catalogue::CATALOGUE {
            for version in entry.versions {
                slugs.push(cv(entry.slug, version.version).slug());
            }
        }
        slugs.sort();
        let before = slugs.len();
        slugs.dedup();
        // Non-side-by-side entries collapse to one slug each, by design; what
        // must not happen is two *entries* sharing one.
        let distinct_entries: std::collections::HashSet<&str> =
            slugs.iter().map(|s| s.as_str()).collect();
        assert_eq!(distinct_entries.len(), slugs.len());
        assert!(before >= slugs.len());
    }

    #[test]
    fn display_names_carry_a_version_only_when_one_was_chosen() {
        assert_eq!(c("nginx").display_name(), "Nginx");
        assert_eq!(c("redis").display_name(), "Redis");
        assert_eq!(c("docker").display_name(), "Docker");
        assert_eq!(cv("php", "8.3").display_name(), "PHP 8.3");
        assert_eq!(cv("mariadb", "11.8").display_name(), "MariaDB 11.8");
        assert_eq!(cv("postgres", "16").display_name(), "PostgreSQL 16");
    }

    // -- resolution ---------------------------------------------------------

    #[test]
    fn every_catalogue_entry_resolves_packages_and_a_unit_on_both_families() {
        for family in [Family::Debian, Family::Rhel] {
            let (distro, _) = mock_distro_with_recorder(family);
            for entry in catalogue::CATALOGUE {
                for version in entry.versions {
                    let component = cv(entry.slug, version.version);

                    // A refusal is a legitimate answer, but it has to be the
                    // deliberate one and not an internal "nothing resolves".
                    if let Err(e) = component.packages(&distro, PhpExt::DEFAULT) {
                        assert_eq!(
                            e.code,
                            ErrorCode::UnsupportedDistro,
                            "{}/{} on {family:?}: {}",
                            entry.slug,
                            version.version,
                            e.detail
                        );
                        assert!(
                            e.detail.contains("no package"),
                            "a refusal must say so plainly: {}",
                            e.detail
                        );
                        continue;
                    }

                    component.unit(family).unwrap_or_else(|e| {
                        panic!(
                            "{}/{} on {family:?}: {}",
                            entry.slug, version.version, e.detail
                        )
                    });
                }
            }
        }
    }

    #[test]
    fn a_vendor_version_resolves_a_pinned_repository_and_a_distro_one_adds_nothing() {
        for family in [Family::Debian, Family::Rhel] {
            let (distro, _) = mock_distro_with_recorder(family);
            for entry in catalogue::CATALOGUE {
                for version in entry.versions {
                    let component = cv(entry.slug, version.version);
                    let repo = match component.repo(&distro) {
                        Ok(repo) => repo,
                        // Two legitimate refusals: no pinned repository exists
                        // for this entry yet (`NotImplemented`), or the vendor
                        // does not publish for this release (`UnsupportedDistro`,
                        // which is what the mock distro gets from NodeSource).
                        // What must never happen is a silent empty install.
                        Err(e) => {
                            assert!(
                                matches!(
                                    e.code,
                                    ErrorCode::NotImplemented | ErrorCode::UnsupportedDistro
                                ),
                                "{}/{}: {:?} {}",
                                entry.slug,
                                version.version,
                                e.code,
                                e.detail
                            );
                            continue;
                        }
                    };
                    match version.source {
                        catalogue::Source::Vendor => {
                            let repo = repo.unwrap_or_else(|| {
                                panic!("{} says Vendor but resolved no repository", entry.slug)
                            });
                            assert!(!repo.definition.accepted_fingerprints.is_empty());
                            // A definition that fails `validate` can never be
                            // added, so offering it is offering an install that
                            // cannot work. `add_repo` validates before it writes
                            // anything, so this is the whole of the check.
                            //
                            // MongoDB is the one this catches: its apt suite is
                            // legitimately path-shaped (`trixie/mongodb-org/8.0`)
                            // and `RepoDefinition::validate` used to allow only
                            // `[a-z0-9-]`, so every MongoDB install failed on
                            // "implausible suite" before a package was fetched.
                            repo.definition.validate().unwrap_or_else(|e| {
                                panic!(
                                    "{} resolves a repository that cannot be added: {e}",
                                    entry.slug
                                )
                            });
                        }
                        // Nothing to pin is the point of a distro source.
                        catalogue::Source::Distro => assert!(
                            repo.is_none(),
                            "{} says Distro but wanted a repository",
                            entry.slug
                        ),
                    }
                }
            }
        }
    }

    #[test]
    fn the_version_an_operator_picked_selects_the_packages_and_the_unit() {
        // The whole complaint: "why can't I pick which MariaDB". Picking has to
        // reach further than the label.
        let (debian, _) = mock_distro_with_recorder(Family::Debian);
        assert!(
            cv("mariadb", "10.11")
                .repo(&debian)
                .unwrap()
                .unwrap()
                .definition
                .base_url
                .contains("10.11"),
        );

        let (rhel, _) = mock_distro_with_recorder(Family::Rhel);
        assert_eq!(
            names(cv("postgres", "15"), &rhel),
            vec![
                "postgresql15-server".to_string(),
                "postgresql15".into(),
                "postgresql15-contrib".into()
            ]
        );
        // PGDG on EL ships only versioned units, so the choice has to reach the
        // unit too — a constant here would start the wrong PostgreSQL.
        assert_eq!(
            cv("postgres", "15")
                .unit(Family::Rhel)
                .unwrap()
                .unwrap()
                .as_str(),
            "postgresql-15.service"
        );
        assert_eq!(
            cv("postgres", "17")
                .unit(Family::Rhel)
                .unwrap()
                .unwrap()
                .as_str(),
            "postgresql-17.service"
        );
    }

    #[test]
    fn the_new_entries_use_the_names_each_family_actually_ships() {
        let (debian, _) = mock_distro_with_recorder(Family::Debian);
        let (rhel, _) = mock_distro_with_recorder(Family::Rhel);

        assert_eq!(names(c("apache"), &debian), vec!["apache2"]);
        assert_eq!(names(c("apache"), &rhel), vec!["httpd"]);
        assert_eq!(names(c("mysql"), &debian), vec!["mysql-server"]);
        assert_eq!(names(c("redis"), &debian), vec!["redis-server"]);
        assert_eq!(names(c("redis"), &rhel), vec!["redis"]);
        assert_eq!(names(c("memcached"), &debian), vec!["memcached"]);
        assert_eq!(
            names(c("docker"), &debian),
            vec!["docker-ce", "docker-ce-cli", "containerd.io"]
        );
        assert_eq!(names(c("go"), &debian), vec!["golang-go"]);
        assert_eq!(names(c("go"), &rhel), vec!["golang"]);
        assert_eq!(names(c("ruby"), &debian), vec!["ruby-full"]);
        // EL has no python3-venv; the module lives in python3-libs.
        assert!(names(c("python"), &debian).contains(&"python3-venv".to_string()));
        assert!(!names(c("python"), &rhel).contains(&"python3-venv".to_string()));

        assert_eq!(
            c("apache").unit(Family::Debian).unwrap().unwrap().as_str(),
            "apache2.service"
        );
        assert_eq!(
            c("apache").unit(Family::Rhel).unwrap().unwrap().as_str(),
            "httpd.service"
        );
        assert_eq!(
            c("mysql").unit(Family::Debian).unwrap().unwrap().as_str(),
            "mysql.service"
        );
        assert_eq!(
            c("mysql").unit(Family::Rhel).unwrap().unwrap().as_str(),
            "mysqld.service"
        );
        assert_eq!(
            c("redis").unit(Family::Debian).unwrap().unwrap().as_str(),
            "redis-server.service"
        );
        assert_eq!(
            c("valkey").unit(Family::Debian).unwrap().unwrap().as_str(),
            "valkey-server.service"
        );
        assert_eq!(
            c("memcached")
                .unit(Family::Debian)
                .unwrap()
                .unwrap()
                .as_str(),
            "memcached.service"
        );
        assert_eq!(
            c("docker").unit(Family::Debian).unwrap().unwrap().as_str(),
            "docker.service"
        );

        assert_eq!(names(c("mongodb"), &debian), vec!["mongodb-org"]);
        assert_eq!(
            c("mongodb").unit(Family::Debian).unwrap().unwrap().as_str(),
            "mongod.service"
        );
        // The package is `openlitespeed`; the unit is named after the install
        // directory, not after the package.
        assert_eq!(names(c("litespeed"), &debian), vec!["openlitespeed"]);
        assert_eq!(
            c("litespeed").unit(Family::Rhel).unwrap().unwrap().as_str(),
            "lsws.service"
        );
    }

    #[test]
    fn every_catalogued_vendor_entry_resolves_a_repository() {
        // The bug this catches shipped once: `repos::litespeed` was written,
        // reviewed and merged, and nothing connected it to the match below — so
        // OpenLiteSpeed sat on the Stack page permanently greyed out with
        // "Unihelm has no pinned repository for it yet", which was true and
        // entirely self-inflicted. Asserting the *fallback arm's wording* could
        // not have caught that; asserting that no catalogued entry reaches the
        // fallback at all is what catches it. The wrong outcome the fallback
        // guards against — an install that adds no repository and then asks apt
        // for a package the machine has never heard of — is still guarded,
        // because an entry added without an arm here fails this test instead of
        // reaching a user.
        let (debian, _) = mock_distro_with_recorder(Family::Debian);
        for e in catalogue::CATALOGUE {
            for v in e.versions {
                if v.source != catalogue::Source::Distro {
                    let component = cv(e.slug, v.version);
                    assert!(
                        component.repo(&debian).is_ok(),
                        "{} {} is catalogued as a vendor package but `repo` has no arm for it, \
                         so the panel offers something it cannot install",
                        e.slug,
                        v.version,
                    );
                }
            }
        }
    }

    /// Hazard 1: `enable --now` succeeding is not the same as running, and a
    /// toolchain has no unit to check at all.
    #[test]
    fn a_toolchain_has_no_unit_to_enable_or_to_check() {
        for slug in ["python", "go", "ruby", "node"] {
            for family in [Family::Debian, Family::Rhel] {
                assert!(
                    c(slug).unit(family).unwrap().is_none(),
                    "{slug} on {family:?} claims a unit; the install would enable-and-check \
                     something that does not exist and fail a working install"
                );
            }
        }
        // And everything that is a service still has one.
        for slug in ["nginx", "apache", "mariadb", "mysql", "postgres", "redis"] {
            assert!(c(slug).unit(Family::Debian).unwrap().is_some(), "{slug}");
        }
    }

    #[test]
    fn a_family_with_no_package_says_so_instead_of_guessing_a_name() {
        let (rhel, _) = mock_distro_with_recorder(Family::Rhel);
        let err = c("valkey").packages(&rhel, PhpExt::DEFAULT).unwrap_err();
        assert_eq!(err.code, ErrorCode::UnsupportedDistro);
        assert!(err.detail.contains("Valkey"), "{}", err.detail);
        assert!(err.detail.contains("Redis"), "{}", err.detail);
    }

    #[test]
    fn every_catalogued_php_is_a_php_the_rest_of_the_panel_can_name() {
        // A catalogue entry the panel cannot name an FPM unit or a pool for is
        // a bug in the pair, not at install time on somebody's server.
        for version in catalogue::entry("php").unwrap().versions {
            cv("php", version.version).php_version().unwrap();
        }
    }

    #[test]
    fn mariadb_packages_are_capital_m_on_el_and_include_the_compat_pair() {
        // Lowercase names on EL would resolve to the distribution's own
        // AppStream build, not the pinned vendor repository.
        let (rhel, _) = mock_distro_with_recorder(Family::Rhel);
        let pkgs = names(c("mariadb"), &rhel);
        assert!(pkgs.contains(&"MariaDB-server".to_string()), "{pkgs:?}");
        assert!(pkgs.contains(&"MariaDB-backup".to_string()));
        // The `mysql`/`mysqld` entry points live only here; nothing pulls them
        // in as a dependency.
        assert!(pkgs.contains(&"MariaDB-server-compat".to_string()));
        assert!(pkgs.contains(&"MariaDB-client-compat".to_string()));
        assert!(
            !pkgs.iter().any(|n| n.starts_with("mariadb-")),
            "no lowercase names on EL: {pkgs:?}"
        );

        let (debian, _) = mock_distro_with_recorder(Family::Debian);
        let pkgs = names(c("mariadb"), &debian);
        assert!(pkgs.contains(&"mariadb-server".to_string()));
        assert!(pkgs.contains(&"mariadb-server-compat".to_string()));
        assert!(
            !pkgs.iter().any(|n| n.starts_with("MariaDB-")),
            "no capital names on Debian: {pkgs:?}"
        );
    }

    #[test]
    fn php_pulls_its_family_specific_package_set() {
        let (debian, _) = mock_distro_with_recorder(Family::Debian);
        let packages = names(cv("php", "8.3"), &debian);
        assert!(packages.contains(&"php8.3-fpm".to_string()));
        assert!(packages.contains(&"php8.3-curl".to_string()));

        let (rhel, _) = mock_distro_with_recorder(Family::Rhel);
        let packages = names(cv("php", "8.3"), &rhel);
        assert!(packages.contains(&"php83-php-fpm".to_string()));
        assert!(
            !packages.iter().any(|p| p.contains("curl")),
            "Remi has no curl package; asking for one fails the transaction"
        );
    }

    #[test]
    fn readiness_probes_exist_only_for_the_engines_that_start_before_they_serve() {
        // For nginx, php-fpm and the caches, systemd "active" already means
        // "serving".
        assert!(readiness_probe(c("nginx"), Family::Debian).is_none());
        assert!(readiness_probe(cv("php", "8.3"), Family::Rhel).is_none());
        assert!(readiness_probe(c("redis"), Family::Debian).is_none());
        assert!(readiness_probe(c("go"), Family::Debian).is_none());

        for (slug, binary) in [("mariadb", "mariadb"), ("mysql", "mysql")] {
            let probe = readiness_probe(c(slug), Family::Debian).unwrap().display();
            // `--no-defaults` must be the first argument or the client ignores
            // it — and then an operator's stray ~/.my.cnf can steer the probe.
            assert!(
                probe.starts_with(&format!("{binary} --no-defaults")),
                "{probe}"
            );
            assert!(probe.contains("SELECT 1"));
            assert!(probe.contains("--protocol=socket"));
        }

        assert_eq!(
            readiness_probe(c("postgres"), Family::Debian)
                .unwrap()
                .display(),
            "pg_isready --quiet"
        );
        // PGDG on EL installs no `pg_isready` on PATH, and the path carries the
        // major the operator picked.
        assert_eq!(
            readiness_probe(cv("postgres", "16"), Family::Rhel)
                .unwrap()
                .display(),
            "/usr/pgsql-16/bin/pg_isready --quiet"
        );
    }

    // -- hazard 2: two engines, one port 3306 -------------------------------

    #[tokio::test]
    async fn mysql_is_refused_on_a_machine_that_already_runs_mariadb() {
        let (ctx, distro, _) = op_ctx(Family::Debian).await;
        distro
            .pkg
            .install(
                &parse_packages(&["mariadb-server"]).unwrap(),
                ctx.log_sink(),
            )
            .await
            .unwrap();

        let err = refuse_a_second_engine_on_3306(&ctx, c("mysql"))
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::Conflict);
        assert!(err.detail.contains("MariaDB"), "{}", err.detail);
        assert!(err.detail.contains("3306"), "{}", err.detail);
        assert!(err.detail.contains("mariadb-server"), "{}", err.detail);

        // And the other way round.
        let (ctx, distro, _) = op_ctx(Family::Debian).await;
        distro
            .pkg
            .install(&parse_packages(&["mysql-server"]).unwrap(), ctx.log_sink())
            .await
            .unwrap();
        let err = refuse_a_second_engine_on_3306(&ctx, c("mariadb"))
            .await
            .unwrap_err();
        assert!(err.detail.contains("MySQL"), "{}", err.detail);
    }

    #[tokio::test]
    async fn reinstalling_the_engine_that_is_already_there_is_not_a_collision() {
        // Reinstalling a component is idempotent (spec §11.1); only the *rival*
        // engine is a reason to refuse.
        let (ctx, distro, _) = op_ctx(Family::Debian).await;
        distro
            .pkg
            .install(
                &parse_packages(&["mariadb-server"]).unwrap(),
                ctx.log_sink(),
            )
            .await
            .unwrap();
        refuse_a_second_engine_on_3306(&ctx, c("mariadb"))
            .await
            .unwrap();

        // A client package without a server is not an engine holding the port.
        let (ctx, distro, _) = op_ctx(Family::Debian).await;
        distro
            .pkg
            .install(
                &parse_packages(&["mariadb-client"]).unwrap(),
                ctx.log_sink(),
            )
            .await
            .unwrap();
        refuse_a_second_engine_on_3306(&ctx, c("mysql"))
            .await
            .unwrap();

        // And nothing that does not want 3306 is ever checked.
        let (ctx, _, _) = op_ctx(Family::Debian).await;
        refuse_a_second_engine_on_3306(&ctx, c("postgres"))
            .await
            .unwrap();
        refuse_a_second_engine_on_3306(&ctx, c("redis"))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn the_distributions_own_database_package_holds_3306_just_as_hard() {
        // On EL the panel installs MariaDB plc's `MariaDB-server`, but Red Hat's
        // own AppStream build of the same engine is `mariadb-server` — and a
        // live database under the lowercase name is just as live. Probing only
        // the name this panel would have used let MySQL be installed on top of
        // it, which is the transaction dnf resolves by removing one of the two.
        let (ctx, distro, _) = op_ctx(Family::Rhel).await;
        distro
            .pkg
            .install(
                &parse_packages(&["mariadb-server"]).unwrap(),
                ctx.log_sink(),
            )
            .await
            .unwrap();

        let err = refuse_a_second_engine_on_3306(&ctx, c("mysql"))
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::Conflict);
        assert!(err.detail.contains("mariadb-server"), "{}", err.detail);

        // And the name Oracle's own repository uses, which is neither the
        // distribution's nor the one this panel installs.
        let (ctx, distro, _) = op_ctx(Family::Debian).await;
        distro
            .pkg
            .install(
                &parse_packages(&["mysql-community-server"]).unwrap(),
                ctx.log_sink(),
            )
            .await
            .unwrap();
        let err = refuse_a_second_engine_on_3306(&ctx, c("mariadb"))
            .await
            .unwrap_err();
        assert!(err.detail.contains("MySQL"), "{}", err.detail);
    }

    // -- hazard 3: apache and nginx both want :80 ---------------------------

    #[tokio::test]
    async fn a_second_web_server_is_refused_while_nginx_is_serving() {
        // Every web server the catalogue offers but nginx, not just Apache —
        // the guard is keyed on the category so a new one is covered too.
        for slug in ["apache", "litespeed"] {
            let (ctx, distro, _) = op_ctx(Family::Debian).await;
            distro
                .svc
                .enable(&unit_named("nginx.service").unwrap(), true)
                .await
                .unwrap();

            let err = decide_about_the_contested_port(&ctx, c(slug))
                .await
                .unwrap_err();
            assert_eq!(err.code, ErrorCode::Conflict, "{slug}");
            assert!(err.detail.contains("Nginx"), "{}", err.detail);
            assert!(err.detail.contains("port 80"), "{}", err.detail);
            assert!(
                err.detail.contains(c(slug).entry.display_name),
                "the refusal has to name what was asked for: {}",
                err.detail
            );
        }
    }

    #[tokio::test]
    async fn nginx_is_refused_while_apache_is_serving_too() {
        // The same collision from the other end. Letting it through means the
        // package installs, fails to bind, and leaves a half-configured nginx
        // and a `failed` row on a machine that was serving fine.
        let (ctx, distro, _) = op_ctx(Family::Debian).await;
        distro
            .svc
            .enable(&unit_named("apache2.service").unwrap(), true)
            .await
            .unwrap();

        let err = decide_about_the_contested_port(&ctx, c("nginx"))
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::Conflict);
        assert!(err.detail.contains("Apache"), "{}", err.detail);
        assert!(err.detail.contains("Nginx"), "{}", err.detail);
    }

    #[tokio::test]
    async fn reinstalling_the_web_server_that_is_already_serving_is_not_a_collision() {
        let (ctx, distro, _) = op_ctx(Family::Debian).await;
        distro
            .svc
            .enable(&unit_named("nginx.service").unwrap(), true)
            .await
            .unwrap();
        decide_about_the_contested_port(&ctx, c("nginx"))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn apache_installs_where_nothing_is_serving_and_nothing_else_is_checked() {
        let (ctx, _, _) = op_ctx(Family::Debian).await;
        decide_about_the_contested_port(&ctx, c("apache"))
            .await
            .unwrap();
        decide_about_the_contested_port(&ctx, c("nginx"))
            .await
            .unwrap();
        // Nothing outside the web-server category is looked at at all.
        decide_about_the_contested_port(&ctx, c("redis"))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn a_second_cache_is_refused_while_the_first_is_serving_on_6379() {
        // Valkey is a fork of Redis down to the default port. Installing it
        // beside a running Redis means one of the two cannot bind — and on
        // Debian the package's postinst tries to start it before the panel gets
        // a word in.
        let (ctx, distro, _) = op_ctx(Family::Debian).await;
        distro
            .svc
            .enable(&unit_named("redis-server.service").unwrap(), true)
            .await
            .unwrap();

        let err = decide_about_the_contested_port(&ctx, c("valkey"))
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::Conflict);
        assert!(err.detail.contains("Redis"), "{}", err.detail);
        assert!(err.detail.contains("6379"), "{}", err.detail);

        // Memcached is in the same category and contends with nothing: it is on
        // 11211, and refusing it here would be refusing an install that works.
        decide_about_the_contested_port(&ctx, c("memcached"))
            .await
            .unwrap();
        // Nor is a cache a reason to refuse a web server.
        decide_about_the_contested_port(&ctx, c("apache"))
            .await
            .unwrap();
    }

    // -- hazard 4: a unit name is not proof of ownership --------------------

    #[tokio::test]
    async fn removing_mysql_never_stops_the_mariadb_that_answers_to_its_unit_name() {
        // On Debian MariaDB's own package installs `mysql.service` as an alias
        // of `mariadb.service`. `systemctl disable --now mysql.service` there
        // stops the live database — over `mysql-server`, which was never
        // installed and whose removal is a no-op.
        let (ctx, distro, rec) = op_ctx(Family::Debian).await;
        distro
            .pkg
            .install(
                &parse_packages(&["mariadb-server"]).unwrap(),
                ctx.log_sink(),
            )
            .await
            .unwrap();
        // The mock keeps units under their own names, so it cannot model the
        // alias itself. The invariant that makes the alias harmless is what is
        // asserted: nothing is stopped when none of the component's own
        // packages are here.
        Remove
            .run(
                &ctx,
                RemoveInput {
                    component: c("mysql"),
                    runtime: None,
                },
            )
            .await
            .unwrap();

        let actions = rec.lock().unwrap().service_actions.clone();
        assert!(
            actions.is_empty(),
            "removing a MySQL that was never installed touched a service: {actions:?}"
        );
    }

    #[tokio::test]
    async fn removing_a_component_that_is_here_still_stops_its_service() {
        let (ctx, distro, rec) = op_ctx(Family::Debian).await;
        distro
            .pkg
            .install(
                &parse_packages(&["mariadb-server"]).unwrap(),
                ctx.log_sink(),
            )
            .await
            .unwrap();

        Remove
            .run(
                &ctx,
                RemoveInput {
                    component: c("mariadb"),
                    runtime: None,
                },
            )
            .await
            .unwrap();

        assert!(
            rec.lock()
                .unwrap()
                .service_actions
                .iter()
                .any(|(unit, action)| unit.contains("mariadb") && *action == SvcAction::Stop),
            "the engine that was here should have been stopped first"
        );
    }

    #[tokio::test]
    async fn a_status_row_is_installed_only_when_its_own_packages_are() {
        // Same alias, read rather than written: systemd answers for
        // `mysql.service` on a MariaDB box, and reporting MySQL as installed
        // there invites an operator to press Remove on a database they do not
        // have.
        let (ctx, distro, _) = op_ctx(Family::Debian).await;
        distro
            .pkg
            .install(
                &parse_packages(&["mariadb-server"]).unwrap(),
                ctx.log_sink(),
            )
            .await
            .unwrap();
        distro
            .svc
            .enable(&unit_named("mysql.service").unwrap(), true)
            .await
            .unwrap();

        let out = Status.run(&ctx, StatusInput {}).await.unwrap();
        let row = |slug: &str| {
            out.components
                .iter()
                .find(|c| c.slug == slug)
                .unwrap_or_else(|| panic!("no {slug} row"))
        };
        assert_eq!(row("mysql").status, "absent");
        assert_eq!(row("mariadb").status, "unmanaged");
    }

    #[tokio::test]
    async fn a_component_whose_packages_were_removed_by_hand_stops_reading_as_installed() {
        // The database only remembers that this panel installed it. An operator
        // who then ran `apt remove redis-server` is looking at a page offering
        // Remove for something that is already gone, and at no way to put it
        // back.
        let (ctx, _, _) = op_ctx(Family::Debian).await;
        ctx.db()
            .claim_component("redis", ComponentStatus::Installing, "task-1")
            .await
            .unwrap();
        ctx.db()
            .component_installed("redis", Some("5:7.0.15-1"))
            .await
            .unwrap();

        let out = Status.run(&ctx, StatusInput {}).await.unwrap();
        let redis = out
            .components
            .iter()
            .find(|c| c.slug == "redis")
            .expect("no redis row");
        assert_eq!(redis.status, "absent");
        assert_eq!(
            redis.installed_version, None,
            "a version is a claim about the machine, not a memory of one"
        );

        // An install still in flight has claimed its row before a single
        // package has landed, and must not be reported as absent for it.
        let (ctx, _, _) = op_ctx(Family::Debian).await;
        ctx.db()
            .claim_component("redis", ComponentStatus::Installing, "task-2")
            .await
            .unwrap();
        let out = Status.run(&ctx, StatusInput {}).await.unwrap();
        assert_eq!(
            out.components
                .iter()
                .find(|c| c.slug == "redis")
                .unwrap()
                .status,
            "installing"
        );
    }

    // -- one row key, whichever runtime it landed on -------------------------

    /// The registry record `engine::install_container` writes beside the row.
    async fn record_a_container(db: &Db, slug: &str, version: &str, host_port: u16) -> String {
        let plan = crate::engine::EnginePlan::resolve(slug, Some(version)).unwrap();
        let container = plan.container().as_str().to_string();
        let mut engines = crate::engine::EngineRegistry::new();
        engines.insert(
            container.clone(),
            crate::engine::EngineRecord {
                slug: slug.to_string(),
                version: version.to_string(),
                image: plan.image().as_str().to_string(),
                container: container.clone(),
                volume: plan.volume().map(str::to_string),
                host_port,
                container_port: 3306,
                root_user: Some("root".into()),
                root_password_sealed: None,
            },
        );
        db.set_setting(crate::engine::ENGINES_SETTING, &engines)
            .await
            .unwrap();
        container
    }

    #[test]
    fn one_row_key_is_derived_for_whichever_runtime_the_install_landed_on() {
        // The defect this exists for: `stack.install` claimed and settled the
        // *host* key whatever it had installed, `stack.status` then asked the
        // package manager about that key, got no, and rewrote it to `absent` —
        // and `engine.remove` cleared a third key again, so removing the
        // container could not correct the host row either.
        assert_eq!(
            row_key(c("mariadb"), catalogue::Runtime::Host).unwrap(),
            "mariadb"
        );
        assert_eq!(
            row_key(cv("mariadb", "11.8"), catalogue::Runtime::Container).unwrap(),
            "unihelm-mariadb-11.8"
        );
        // The key `engine.remove` clears is that same string, because both come
        // out of the plan rather than each spelling it out.
        let plan = crate::engine::EnginePlan::for_component(cv("mariadb", "11.8")).unwrap();
        assert_eq!(
            row_key(cv("mariadb", "11.8"), catalogue::Runtime::Container).unwrap(),
            plan.row_key()
        );
        // Two containers of one engine are two rows: two ports, two data
        // directories, and a failed install of one must not put a red mark on
        // the other.
        assert_ne!(
            row_key(cv("mariadb", "11.4"), catalogue::Runtime::Container).unwrap(),
            row_key(cv("mariadb", "11.8"), catalogue::Runtime::Container).unwrap()
        );
        // And neither is the host's row, which is a different install of a
        // different thing on the same machine.
        assert_ne!(
            row_key(cv("mariadb", "11.8"), catalogue::Runtime::Container).unwrap(),
            row_key(c("mariadb"), catalogue::Runtime::Host).unwrap()
        );
    }

    #[test]
    fn a_stopped_container_is_installed_and_down_rather_than_absent() {
        use ContainerState::*;
        let installed = Some(ComponentStatus::Installed);

        // What the page reported "Not installed" over: a container that is up.
        assert_eq!(
            container_status(installed, Running),
            ComponentStatus::Installed
        );
        // Stopped is a different sentence from gone, and telling the two apart
        // is most of the reason an operator opens this page.
        assert_eq!(
            container_status(installed, Stopped),
            ComponentStatus::Installed
        );
        // `docker rm` behind the panel's back: the row says so rather than
        // reporting the registry's memory of an install.
        assert_eq!(container_status(installed, Gone), ComponentStatus::Absent);
        // A daemon that could not be asked is not a database that has gone.
        assert_eq!(
            container_status(installed, Unasked),
            ComponentStatus::Installed
        );
        assert_eq!(container_status(None, Unasked), ComponentStatus::Installed);

        // An operation in flight, or the reason the last one failed, outranks
        // Docker: an install claims its row before the image has been pulled.
        for (stored, state) in [
            (ComponentStatus::Installing, Gone),
            (ComponentStatus::Removing, Running),
            (ComponentStatus::Failed, Gone),
        ] {
            assert_eq!(container_status(Some(stored), state), stored);
        }

        // A machine whose row was never written — every one installed before
        // the key was fixed — still reads off the container that is there.
        assert_eq!(container_status(None, Running), ComponentStatus::Installed);
        assert_eq!(container_status(None, Gone), ComponentStatus::Absent);

        // And the words the page reads for each.
        assert_eq!(Running.as_unit(), ("running".to_string(), true));
        assert_eq!(Stopped.as_unit(), ("stopped".to_string(), false));
        assert_eq!(Unasked.as_unit(), ("unknown".to_string(), false));
    }

    #[tokio::test]
    async fn a_containerised_engine_gets_a_row_of_its_own_instead_of_none_at_all() {
        let (ctx, _, _) = op_ctx(Family::Debian).await;
        let component = cv("mariadb", "11.8");
        let slug = row_key(component, catalogue::Runtime::Container).unwrap();

        // Exactly what a container install now leaves behind: its own row, and
        // the registry record beside it.
        ctx.db()
            .claim_component(&slug, ComponentStatus::Installing, "task-1")
            .await
            .unwrap();
        ctx.db()
            .component_installed(&slug, Some("11.8"))
            .await
            .unwrap();
        record_a_container(ctx.db(), "mariadb", "11.8", 3306).await;

        let out = Status.run(&ctx, StatusInput {}).await.unwrap();
        let row = out
            .components
            .iter()
            .find(|c| c.slug == slug)
            .expect("no row at all for a container this panel installed");
        assert_eq!(row.component, "mariadb");
        assert_eq!(row.version, "11.8");
        assert_eq!(row.runtime, catalogue::Runtime::Container);
        assert_eq!(row.display_name, "MariaDB 11.8");
        assert_eq!(row.category, "database");
        // Nothing about this machine's packaging can stop a container: what can
        // is refused by name at install time.
        assert_eq!(row.unavailable, None);
        // Whether it is up is Docker's answer, and the machine running this
        // test may have none — [`container_status`] pins that decision on its
        // own. What must hold here is that the row exists and is not one about
        // packages.

        // The host row stays a row about packages, and there are none: this
        // engine is not on the host, and the install saying it was is the other
        // half of the same lie.
        let host = out
            .components
            .iter()
            .find(|c| c.slug == "mariadb")
            .expect("no host row");
        assert_eq!(host.runtime, catalogue::Runtime::Host);
        assert_eq!(host.status, "absent");
    }

    #[tokio::test]
    async fn a_machine_with_no_engine_containers_reports_only_package_rows() {
        // The early return matters twice: nothing to say, and nothing to pay —
        // `docker info` and `docker ps` are not run on a machine whose registry
        // is empty, which is every machine before the first engine.
        let (ctx, _, _) = op_ctx(Family::Debian).await;
        let out = Status.run(&ctx, StatusInput {}).await.unwrap();
        assert!(
            out.components
                .iter()
                .all(|c| c.runtime == catalogue::Runtime::Host),
            "a container row appeared with no engine installed"
        );
    }

    #[tokio::test]
    async fn a_row_this_machine_cannot_install_says_so_instead_of_offering_a_button() {
        let (ctx, _, _) = op_ctx(Family::Rhel).await;
        let out = Status.run(&ctx, StatusInput {}).await.unwrap();
        let row = |slug: &str| {
            out.components
                .iter()
                .find(|c| c.component == slug)
                .unwrap_or_else(|| panic!("no {slug} row"))
        };

        // EL carries Valkey only in EPEL, which the panel does not add.
        let valkey = row("valkey").unavailable.as_deref().unwrap_or_default();
        assert!(valkey.contains("Redis"), "{valkey}");
        // LiteSpeed publishes a Debian tree the panel pins, and a per-release
        // RPM layout it does not handle. This context is EL, so the row says so
        // rather than offering a button that would fail at the repository step.
        let litespeed = row("litespeed").unavailable.as_deref().unwrap_or_default();
        assert!(litespeed.contains("OpenLiteSpeed"), "{litespeed}");
        // And everything the machine can actually install says nothing.
        assert_eq!(row("redis").unavailable, None);
        assert_eq!(row("memcached").unavailable, None);
    }

    #[test]
    fn a_packaging_epoch_does_not_make_the_installed_version_look_like_another_one() {
        // dpkg spells MariaDB 11.8 `1:11.8.2-1` and Debian's own nodejs carries
        // an epoch too; a bare `starts_with` reads both as "not the version you
        // asked for" and reports an installed runtime as absent.
        assert_eq!(
            Presence::Installed(Some("1:22.11.0-1nodesource1".into())).holds(cv("node", "22")),
            Some(true)
        );
        assert_eq!(
            Presence::Installed(Some("20.11.0-1nodesource1".into())).holds(cv("node", "22")),
            Some(false)
        );
        // Only digits before the colon are an epoch.
        assert_eq!(upstream_version("8.3.11-1"), "8.3.11-1");
        assert_eq!(upstream_version("1:11.8.2-1"), "11.8.2-1");
        assert_eq!(upstream_version("abc:1.0"), "abc:1.0");

        // And a package manager that could not be asked is not a "no": reading
        // it as one turns a failed `dpkg-query` into a component reported gone.
        assert_eq!(Presence::Unknown.holds(c("redis")), None);
        assert_eq!(Presence::Absent.holds(c("redis")), Some(false));
    }

    // -- hazard 5: one package, several catalogue versions ------------------

    #[tokio::test]
    async fn removing_the_node_major_that_is_not_here_would_uninstall_the_one_that_is() {
        let (ctx, distro, _) = op_ctx(Family::Debian).await;
        distro
            .pkg
            .install(&parse_packages(&["nodejs"]).unwrap(), ctx.log_sink())
            .await
            .unwrap();

        // The mock reports `1.0.0-mock`, which is no catalogue major, so every
        // row is "not the one here" — which is the case being guarded.
        let err = Remove
            .run(
                &ctx,
                RemoveInput {
                    component: cv("node", "20"),
                    runtime: None,
                },
            )
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::Conflict);
        assert!(err.detail.contains("Node.js"), "{}", err.detail);

        // PHP carries the version in its package names, so its rows are
        // genuinely independent and nothing is refused.
        let (debian, _) = mock_distro_with_recorder(Family::Debian);
        assert!(!cv("php", "8.3").shares_packages_with_its_other_versions(&debian));
        assert!(cv("node", "20").shares_packages_with_its_other_versions(&debian));
    }

    #[tokio::test]
    async fn removing_a_runtime_that_is_not_installed_at_all_stays_a_no_op() {
        // Removal is idempotent (spec §11.1); only removing the *wrong* version
        // is refused.
        let (ctx, _, _) = op_ctx(Family::Debian).await;
        Remove
            .run(
                &ctx,
                RemoveInput {
                    component: cv("node", "20"),
                    runtime: None,
                },
            )
            .await
            .unwrap();
    }

    // -- a refusal must leave no trace on a machine nothing touched ---------

    #[tokio::test]
    async fn a_refused_install_leaves_no_failed_row_behind() {
        let (ctx, distro, _) = op_ctx(Family::Debian).await;
        distro
            .pkg
            .install(
                &parse_packages(&["mariadb-server"]).unwrap(),
                ctx.log_sink(),
            )
            .await
            .unwrap();

        let err = Install
            .run(
                &ctx,
                InstallInput {
                    component: c("mysql"),
                    extensions: Vec::new(),
                    runtime: None,
                },
            )
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::Conflict);
        assert!(
            ctx.db().component("mysql").await.unwrap().is_none(),
            "a refusal before anything was touched must not mark the component failed"
        );
    }

    // -- the pieces that did not change -------------------------------------

    #[test]
    fn traversal_is_granted_without_granting_a_listing() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("state");
        std::fs::create_dir(&target).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o750)).unwrap();

        make_traversable(std::slice::from_ref(&target)).unwrap();

        let mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o751,
            "expected traverse-only for other, got {mode:o}"
        );
        assert_eq!(
            mode & 0o004,
            0,
            "`other` must not be able to list the directory"
        );
    }

    #[test]
    fn making_a_directory_traversable_twice_changes_nothing() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("state");
        std::fs::create_dir(&target).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755)).unwrap();
        make_traversable(std::slice::from_ref(&target)).unwrap();
        assert_eq!(
            std::fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o755
        );
    }

    #[test]
    fn a_maintenance_mode_site_has_a_page_to_serve() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("maintenance");

        write_maintenance_page_in(&root).unwrap();

        // The name and the location are the vhost template's contract:
        // `root <maintenance_root>; rewrite ^ /maintenance.html break;`.
        let page = root.join("maintenance.html");
        assert!(page.is_file(), "nginx would answer 404 instead of the page");
        assert!(std::fs::read_to_string(&page).unwrap().contains("<html"));
        // Read by a worker running as `nginx`, not by the panel.
        assert_eq!(
            std::fs::metadata(&root).unwrap().permissions().mode() & 0o777,
            0o755
        );
        assert_eq!(
            std::fs::metadata(&page).unwrap().permissions().mode() & 0o777,
            0o644
        );
    }

    #[test]
    fn a_branded_maintenance_page_survives_the_next_bootstrap() {
        // Replacing the file is how an operator brands it, and bootstrap_nginx
        // runs again on every nginx install.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("maintenance");
        write_maintenance_page_in(&root).unwrap();
        std::fs::write(root.join("maintenance.html"), "<h1>back soon</h1>").unwrap();

        write_maintenance_page_in(&root).unwrap();

        assert_eq!(
            std::fs::read_to_string(root.join("maintenance.html")).unwrap(),
            "<h1>back soon</h1>"
        );
    }

    #[tokio::test]
    async fn a_key_is_never_fetched_over_plain_http() {
        // Bootstrapping trust over an unauthenticated transport is not
        // bootstrapping trust.
        let err = fetch_key("http://example.com/key.gpg").await.unwrap_err();
        assert!(err.detail.contains("refusing to fetch"));
    }

    // -- where the operator asked it to run ---------------------------------

    #[test]
    fn the_runtime_the_operator_chose_is_the_one_that_is_used() {
        // The defect: the Stack page's "Run it" menu posted `runtime` and every
        // layer between it and here dropped the field, so picking "on the
        // server" for MariaDB installed a container and the panel said nothing.
        assert_eq!(
            runtime_for(c("mariadb"), Some(catalogue::Runtime::Host)).unwrap(),
            catalogue::Runtime::Host
        );
        assert_eq!(
            runtime_for(c("mariadb"), Some(catalogue::Runtime::Container)).unwrap(),
            catalogue::Runtime::Container
        );
        // And saying nothing still means the catalogue's own answer, which for
        // an engine is the container the design settled on.
        assert_eq!(
            runtime_for(c("mariadb"), None).unwrap(),
            catalogue::Runtime::Container
        );
        assert_eq!(
            runtime_for(c("nginx"), None).unwrap(),
            catalogue::Runtime::Host
        );
    }

    #[test]
    fn a_runtime_the_entry_does_not_offer_is_refused_by_name() {
        // Not corrected to the default: a silent correction is the same defect
        // as a silently dropped field — the operator asked for one thing and
        // got another without being told.
        let err = runtime_for(c("nginx"), Some(catalogue::Runtime::Container)).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidInput);
        assert!(err.detail.contains("Nginx"), "{}", err.detail);
        assert!(err.detail.contains("container"), "{}", err.detail);
        assert!(
            err.detail.contains("host"),
            "the refusal has to say what it does run: {}",
            err.detail
        );
    }

    #[test]
    fn the_wire_carries_the_runtime_the_page_sends() {
        let chosen: InstallInput =
            serde_json::from_str(r#"{"component":"mariadb","runtime":"host"}"#).unwrap();
        assert_eq!(chosen.runtime, Some(catalogue::Runtime::Host));

        // Absent stays absent rather than becoming a value: "the operator chose
        // the host" and "the operator said nothing" are different requests.
        let silent: InstallInput = serde_json::from_str(r#"{"component":"mariadb"}"#).unwrap();
        assert_eq!(silent.runtime, None);

        let removal: RemoveInput =
            serde_json::from_str(r#"{"component":"redis","runtime":"container"}"#).unwrap();
        assert_eq!(removal.runtime, Some(catalogue::Runtime::Container));
    }

    #[tokio::test]
    async fn an_install_onto_a_runtime_the_entry_refuses_leaves_no_row_behind() {
        // The refusal has to happen before the row is claimed, like the two
        // port collisions: a `failed` row for an install that never began puts
        // a red row on the page for a machine that is perfectly fine.
        let (ctx, _, _) = op_ctx(Family::Debian).await;
        let err = Install
            .run(
                &ctx,
                InstallInput {
                    component: c("nginx"),
                    extensions: Vec::new(),
                    runtime: Some(catalogue::Runtime::Container),
                },
            )
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidInput);
        assert!(ctx.db().components().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn removing_a_container_through_the_package_path_is_refused_not_reported_done() {
        // Everything below that refusal is the package manager. A container has
        // no packages, so the removal would run to completion, touch nothing,
        // and mark the row removed while the container carried on serving.
        let (ctx, _, _) = op_ctx(Family::Debian).await;
        let err = Remove
            .run(
                &ctx,
                RemoveInput {
                    component: c("mariadb"),
                    runtime: Some(catalogue::Runtime::Container),
                },
            )
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidInput);
        assert!(err.detail.contains("engine.remove"), "{}", err.detail);
        assert!(ctx.db().components().await.unwrap().is_empty());

        // And saying nothing still means the packages, even though MariaDB's
        // catalogue *install* default is a container: reading that preference
        // here would make a bare removal refuse to touch the host install that
        // is the only thing on the machine.
        Remove
            .run(
                &ctx,
                RemoveInput {
                    component: c("mariadb"),
                    runtime: None,
                },
            )
            .await
            .unwrap();
    }

    // -- stack.start / stack.stop -------------------------------------------

    #[test]
    fn only_the_entries_the_panel_whitelists_can_be_started_or_stopped() {
        // The property `svc.action` buys with an enum, kept here: a slug an
        // operator typed can only ever reach a unit this file already manages.
        for entry in catalogue::CATALOGUE {
            assert_eq!(
                CONTROLLABLE_SLUGS.contains(&entry.slug),
                c(entry.slug).managed_unit().is_ok(),
                "`{}` disagrees with CONTROLLABLE_SLUGS, which the Stack page mirrors",
                entry.slug
            );
        }

        // And what it will not name, it refuses about — listing what it can, so
        // the answer is actionable rather than a flat no.
        let err = c("postgres").managed_unit().unwrap_err();
        assert_eq!(err.code, ErrorCode::NotImplemented);
        assert!(err.detail.contains("PostgreSQL"), "{}", err.detail);
        assert!(err.detail.contains("nginx"), "{}", err.detail);
    }

    #[tokio::test]
    async fn a_start_names_the_unit_it_told_systemd_about_and_checks_it_came_up() {
        let (reg, admin, _) = registry().await;
        let out = reg
            .dispatch(
                "stack.start",
                &auth_for(admin, Role::Admin),
                serde_json::json!({ "component": "php", "version": "8.3" }),
                None,
            )
            .await
            .unwrap();
        // The mock distro is Debian-family.
        assert_eq!(out["unit"], "php8.3-fpm.service");
        assert_eq!(out["slug"], "php8.3");
        assert_eq!(out["unit_active"], true);
    }

    #[tokio::test]
    async fn stopping_the_web_server_that_is_serving_is_refused_while_sites_are_up() {
        // Issue 23's other half. The control exists so a machine serving with
        // Apache is not stuck on port 80 with nothing in the panel to stop it —
        // and it comes with this sentence, because one click here is every site
        // on the server going dark.
        let (reg, admin, customer) = registry().await;
        seed_active_site(reg.services().db.clone(), customer, "shop.example.com").await;

        let err = reg
            .dispatch(
                "stack.stop",
                &auth_for(admin, Role::Admin),
                serde_json::json!({ "component": "nginx" }),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::DependentsExist);
        assert!(err.detail.contains("shop.example.com"), "{}", err.detail);
        assert!(err.detail.contains("Nginx"), "{}", err.detail);
    }

    #[tokio::test]
    async fn stopping_a_web_server_nothing_is_riding_on_goes_ahead() {
        // The escape hatch has to stay open, or the incumbent could never be
        // stopped at all: a suspended site is already not being served, so it is
        // not a reason to refuse.
        let (reg, admin, customer) = registry().await;
        let db = reg.services().db.clone();
        let site = seed_active_site(db.clone(), customer, "gone.example.com").await;
        db.set_site_status(site, unihelm_db::SiteStatus::Suspended)
            .await
            .unwrap();

        let out = reg
            .dispatch(
                "stack.stop",
                &auth_for(admin, Role::Admin),
                serde_json::json!({ "component": "nginx" }),
                None,
            )
            .await
            .unwrap();
        assert_eq!(out["unit"], "nginx.service");
        assert_eq!(out["unit_active"], false);
    }

    #[tokio::test]
    async fn a_web_server_that_is_not_the_one_serving_can_be_stopped_with_sites_up() {
        // Which server is serving, never a slug: on a machine switched to
        // Apache this guard keyed on `nginx` would refuse to stop the one that
        // serves nothing and allow the stop of the one holding every site up.
        let (reg, admin, customer) = registry().await;
        seed_active_site(reg.services().db.clone(), customer, "live.example.com").await;

        // Nothing has switched this machine, so nginx serves and Apache does not.
        reg.dispatch(
            "stack.stop",
            &auth_for(admin, Role::Admin),
            serde_json::json!({ "component": "apache" }),
            None,
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn installing_apache_never_reports_a_web_server_that_reads_none_of_the_panels_tree() {
        // There was no `"apache"` arm in the bootstrap match at all, so the
        // install put the packages on, started the unit and stopped — leaving
        // Apache with no `IncludeOptional` for /etc/apache2/unihelm.d and no
        // default vhost. Every site created afterwards rendered into a directory
        // nothing parses, passed `apachectl configtest` because it was never
        // parsed, reloaded cleanly and was reported live while Apache answered
        // with the distribution's default page.
        //
        // The invariant, not the mechanism: this install either leaves the
        // include in place or fails saying why. A machine with no writable
        // /etc/apache2 — which is every machine these tests run on — gets the
        // second, and that is the honest half of the same rule.
        let (ctx, _, _) = op_ctx(Family::Debian).await;
        let hook = crate::webserver::WebServer::Apache.hook().unwrap();
        let before = hook.path().exists();

        match Install
            .run(
                &ctx,
                InstallInput {
                    component: c("apache"),
                    extensions: Vec::new(),
                    runtime: None,
                },
            )
            .await
        {
            Ok(out) => assert!(
                hook.path().exists(),
                "reported {out:?} over an Apache with no include for the panel's tree"
            ),
            Err(e) => assert!(
                !before || hook.path().exists(),
                "the install failed and took the include with it: {}",
                e.detail
            ),
        }
    }

    #[tokio::test]
    async fn stopping_the_web_server_the_panel_is_served_through_is_refused() {
        // The lockout this release created and this guard did not see. On the
        // recommended first move — point a domain at the box, issue the panel
        // certificate, create sites afterwards — `panel.tls.issue` writes
        // `panel.domain`, renders `01-panel.conf` into the web server's tree and
        // narrows `panel.listen` to loopback. With no sites yet, the guard's
        // only question ("are any sites up?") answered no and one click on Stop
        // took the panel off the air with no route back but the console.
        let (reg, admin, _) = registry().await;
        reg.services()
            .db
            .set_setting(
                unihelm_db::panel::DOMAIN_KEY,
                &unihelm_core::Domain::parse("panel.example.com").unwrap(),
            )
            .await
            .unwrap();

        let err = reg
            .dispatch(
                "stack.stop",
                &auth_for(admin, Role::Admin),
                serde_json::json!({ "component": "nginx" }),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::DependentsExist);
        assert!(
            err.detail.contains("panel.example.com"),
            "the refusal has to name what is behind it: {}",
            err.detail
        );
        // And it must not repeat the old instruction, which walked the operator
        // into the lockout: suspending every site does not move the panel.
        assert!(
            !err.detail.contains("suspend those sites"),
            "{}",
            err.detail
        );
    }

    #[tokio::test]
    async fn removing_the_web_server_the_panel_is_served_through_is_refused() {
        // The same hole with the packages taken as well, so there is nothing
        // left to start again from the console.
        let (reg, admin, _) = registry().await;
        reg.services()
            .db
            .set_setting(
                unihelm_db::panel::DOMAIN_KEY,
                &unihelm_core::Domain::parse("panel.example.com").unwrap(),
            )
            .await
            .unwrap();

        let err = Remove
            .run(
                &crate::registry::OpContext::new(
                    reg.services().clone(),
                    auth_for(admin, Role::Admin),
                ),
                RemoveInput {
                    component: c("nginx"),
                    runtime: None,
                },
            )
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::DependentsExist);
        assert!(err.detail.contains("panel.example.com"), "{}", err.detail);
    }

    #[tokio::test]
    async fn stopping_docker_names_every_database_it_takes_with_it() {
        // The widest unguarded stop on the page. `refuse_to_stop_what_is_serving`
        // returns `Ok(())` for anything that is not a web-server slug, so Stop
        // beside Docker went straight to `docker.service` — and on a default
        // install every engine is `Install::Either { default: Container }`, so
        // that is every database and cache on the machine, with nginx and
        // PHP-FPM still up serving connection errors.
        let (reg, admin, _) = registry().await;
        let db = reg.services().db.clone();
        seed_containerised_engines(&db, &["unihelm-mariadb-11.8", "unihelm-redis-7"]).await;

        let err = reg
            .dispatch(
                "stack.stop",
                &auth_for(admin, Role::Admin),
                serde_json::json!({ "component": "docker" }),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::DependentsExist);
        // Counted and named. "Are you sure?" is a question an operator cannot
        // answer; "2 containerised engines: unihelm-mariadb-11.8, unihelm-redis-7"
        // is one they can.
        assert!(err.detail.contains('2'), "{}", err.detail);
        assert!(
            err.detail.contains("unihelm-mariadb-11.8"),
            "{}",
            err.detail
        );
        assert!(err.detail.contains("unihelm-redis-7"), "{}", err.detail);
        assert_eq!(err.field.as_deref(), Some("confirm"));

        // And it is a question, not a wall: there is no other way to stop
        // Docker, so a refusal with no way through would put back the thing
        // this control was added to fix.
        let out = reg
            .dispatch(
                "stack.stop",
                &auth_for(admin, Role::Admin),
                serde_json::json!({ "component": "docker", "confirm": "docker" }),
                None,
            )
            .await
            .unwrap();
        assert_eq!(out["unit"], "docker.service");
        assert_eq!(out["unit_active"], false);
    }

    #[tokio::test]
    async fn a_confirmation_for_another_component_does_not_stop_this_one() {
        // The confirmation names the component, so it cannot be satisfied by a
        // click that was meant for a different row.
        let (reg, admin, _) = registry().await;
        seed_containerised_engines(&reg.services().db.clone(), &["unihelm-mariadb-11.8"]).await;

        let err = reg
            .dispatch(
                "stack.stop",
                &auth_for(admin, Role::Admin),
                serde_json::json!({ "component": "docker", "confirm": "nginx" }),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::DependentsExist);
    }

    #[tokio::test]
    async fn stopping_docker_on_a_machine_running_nothing_asks_nothing() {
        // The refusal is made of the panel's own records, so a machine with no
        // containers has nothing to be asked about. A confirmation demanded
        // where there is no cost is one an operator learns to click through.
        let (reg, admin, _) = registry().await;
        reg.dispatch(
            "stack.stop",
            &auth_for(admin, Role::Admin),
            serde_json::json!({ "component": "docker" }),
            None,
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn stopping_a_php_pool_names_the_sites_that_go_to_502() {
        // `stack.remove php 8.3` refuses and names these sites; `stack.stop` on
        // the identical component refused nothing, with the identical
        // user-visible impact.
        let (reg, admin, customer) = registry().await;
        let db = reg.services().db.clone();
        seed_active_php_site(db, customer, "shop.example.com").await;

        let err = reg
            .dispatch(
                "stack.stop",
                &auth_for(admin, Role::Admin),
                serde_json::json!({ "component": "php", "version": "8.3" }),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::DependentsExist);
        assert!(err.detail.contains("shop.example.com"), "{}", err.detail);
        assert!(err.detail.contains("php8.3-fpm.service"), "{}", err.detail);
    }

    /// One active site on PHP 8.3, which is what a pool stop costs.
    async fn seed_active_php_site(db: Db, owner: UserId, domain: &str) {
        let sub = db.create_subscription(owner).await.unwrap();
        let site = db
            .create_site(unihelm_db::NewSite {
                subscription_id: sub.id,
                domain: unihelm_core::Domain::parse(domain).unwrap(),
                site_type: unihelm_db::SiteType::Php,
                php_version: Some(unihelm_core::PhpVersion::V83),
                root_dir: format!("/home/{}/sites/{domain}/public", sub.linux_user),
                proxy_port: None,
                redirect_target: None,
            })
            .await
            .unwrap();
        db.set_site_status(site.id, unihelm_db::SiteStatus::Active)
            .await
            .unwrap();
    }

    /// Engine records as `engine.install` writes them, so the stop guard reads
    /// the same registry the Stack page builds its container rows from.
    async fn seed_containerised_engines(db: &Db, containers: &[&str]) {
        let mut registry = crate::engine::EngineRegistry::new();
        for container in containers {
            registry.insert(
                (*container).to_string(),
                crate::engine::EngineRecord {
                    slug: "mariadb".into(),
                    version: "11.8".into(),
                    image: "mariadb:11.8".into(),
                    container: (*container).to_string(),
                    volume: None,
                    host_port: 3306,
                    container_port: 3306,
                    root_user: Some("root".into()),
                    root_password_sealed: None,
                },
            );
        }
        db.set_setting(crate::engine::ENGINES_SETTING, &registry)
            .await
            .unwrap();
    }

    /// One active site under a fresh subscription, for the stop guard.
    async fn seed_active_site(db: Db, owner: UserId, domain: &str) -> unihelm_core::SiteId {
        let sub = db.create_subscription(owner).await.unwrap();
        let site = db
            .create_site(unihelm_db::NewSite {
                subscription_id: sub.id,
                domain: unihelm_core::Domain::parse(domain).unwrap(),
                site_type: unihelm_db::SiteType::Static,
                php_version: None,
                root_dir: format!("/home/{}/sites/{domain}/public", sub.linux_user),
                proxy_port: None,
                redirect_target: None,
            })
            .await
            .unwrap();
        db.set_site_status(site.id, unihelm_db::SiteStatus::Active)
            .await
            .unwrap();
        site.id
    }
}
