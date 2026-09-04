//! Everything this panel knows how to install, and which versions of it.
//!
//! Replaces a closed enum in which only PHP could carry a version, so a caller
//! could ask for "MariaDB" but never "MariaDB 10.11", and the panel offered two
//! database engines because two was how many the enum had variants for. The
//! shape was the limit, not the packaging.
//!
//! **This is still a fixed list.** The safety property the enum had — an API
//! caller cannot talk the panel into `apt install`-ing something of their
//! choosing — is kept by looking every request up in this table and refusing
//! anything that is not in it. What changed is that the table is data, so adding
//! an engine is an entry rather than a variant threaded through six matches.
//!
//! Most entries install from the distribution's own repositories. That is
//! deliberate and not laziness: a vendor repository means a signing key this
//! panel has to pin by fingerprint and keep pinned, and every one of those is a
//! thing that can go stale and lock an operator out of security updates. Where
//! Ubuntu and Debian already ship a maintained package — Apache, MySQL, Redis,
//! Valkey, Memcached, Go, Python — that is the better answer, and the version
//! offered is whatever the distribution maintains.
//!
//! An entry also says how it is run, in [`Install`]: on the host, in a
//! container, or either with one of them the default. That is a separate
//! question from where packages come from, and every entry answers it out loud
//! — a thing that stays on the host says so, rather than saying nothing and
//! being read as whichever default a later change picks.

use serde::{Deserialize, Serialize};

/// Where an entry belongs on the page, and roughly what it is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    WebServer,
    Language,
    Database,
    Cache,
    Container,
}

impl Category {
    pub const ALL: &'static [Category] = &[
        Category::WebServer,
        Category::Language,
        Category::Database,
        Category::Cache,
        Category::Container,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Category::WebServer => "web_server",
            Category::Language => "language",
            Category::Database => "database",
            Category::Cache => "cache",
            Category::Container => "container",
        }
    }
}

/// Where a version's packages come from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    /// The distribution's own repositories. No key to pin, no repository to add,
    /// and security updates arrive with the rest of the system.
    Distro,
    /// A vendor repository the panel adds, with its key pinned by fingerprint.
    Vendor,
}

/// How a thing runs once it is installed.
///
/// A different question from [`Source`], and kept apart from it on purpose.
/// `Source` answers "where do the packages come from"; this answers "is there a
/// package at all". Conflating the two produces an entry that claims both a
/// vendor repository to pin and an image to pull, and then a caller that adds
/// an archive nobody will ever install from.
///
/// See `docs/design/containerised-runtimes.md` for the shape this serves: one
/// container per tool and version, shared by every site that names that
/// version — not a container per site.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Runtime {
    /// Packages on the host, started by systemd. What everything did before
    /// containers, and what the web servers keep doing.
    Host,
    /// An image, pulled and run as one container named for the tool and the
    /// version. There is no repository to pin and no package list to resolve on
    /// this path.
    Container,
}

impl Runtime {
    pub const fn as_str(self) -> &'static str {
        match self {
            Runtime::Host => "host",
            Runtime::Container => "container",
        }
    }
}

/// Which runtimes an entry can be installed onto, and which one it gets when
/// nobody says.
///
/// Every entry states one of these. There is no "unset" and no `Option`: the
/// field decides what the Stack page offers, so an entry that stays on the host
/// has to say so out loud rather than say nothing and be read as a default
/// somebody later changes underneath it.
///
/// The default is inside the value rather than beside it, so there is no way to
/// write an entry that offers only the host and defaults to a container.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(into = "InstallWire")]
pub enum Install {
    /// Host packages, and nothing else. Either the thing has no business in a
    /// container or its turn has not come yet; the entry says which.
    HostOnly,
    /// An image, and nothing else. Nothing on this path has a repository or a
    /// package list, and asking for one is a bug rather than a fallback —
    /// see [`Entry::host_package_source`].
    ContainerOnly,
    /// Both, with the one an operator gets by default named here.
    ///
    /// What the containerised entries use: a container is the answer the design
    /// argues for, and the host path stays reachable because a machine without
    /// Docker, or an operator who already runs the engine on the host, is not a
    /// machine this panel gets to break.
    Either { default: Runtime },
}

/// The wire shape the Stack page reads: what may be chosen, and what is chosen
/// for you. Flattening it here means the UI never has to know the variants.
#[derive(Serialize)]
struct InstallWire {
    runtimes: &'static [Runtime],
    default_runtime: Runtime,
}

impl From<Install> for InstallWire {
    fn from(install: Install) -> Self {
        InstallWire {
            runtimes: install.runtimes(),
            default_runtime: install.default_runtime(),
        }
    }
}

impl Install {
    /// Everything this entry can be installed onto, in the order a page shows
    /// them. Host first where both are offered: it is the older path, and a
    /// list that reorders itself per entry is a list nobody can scan.
    pub const fn runtimes(self) -> &'static [Runtime] {
        match self {
            Install::HostOnly => &[Runtime::Host],
            Install::ContainerOnly => &[Runtime::Container],
            Install::Either { .. } => &[Runtime::Host, Runtime::Container],
        }
    }

    /// What an operator gets by not choosing.
    pub const fn default_runtime(self) -> Runtime {
        match self {
            Install::HostOnly => Runtime::Host,
            Install::ContainerOnly => Runtime::Container,
            Install::Either { default } => default,
        }
    }

    /// Whether a runtime somebody asked for is one this entry offers. The
    /// refusal an API caller gets is built on this, the same way an unknown
    /// version's is built on [`version`].
    pub const fn allows(self, runtime: Runtime) -> bool {
        matches!(
            (self, runtime),
            (Install::HostOnly, Runtime::Host)
                | (Install::ContainerOnly, Runtime::Container)
                | (Install::Either { .. }, _)
        )
    }
}

/// One installable version of one piece of software.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Version {
    /// What the operator picks: `11.8`, `8.3`, `24`.
    pub version: &'static str,
    /// Shown beside it. Empty when the version speaks for itself.
    pub note: &'static str,
    /// Where the packages come from — a question the host path asks and the
    /// container path does not. An entry that is only ever pulled as an image
    /// has no answer here, and this field still holds one because the struct is
    /// a single shape for every version; read it through
    /// [`Entry::host_package_source`], which returns nothing where there are no
    /// packages, rather than off the field, where `Distro` reads like an
    /// instruction to `apt install` something that has no package.
    pub source: Source,
    /// Past its upstream support date. Offered, because somebody migrating an
    /// old application needs it, and marked, because nobody should choose it
    /// by accident.
    pub eol: bool,
    /// The one to pick when you have no opinion.
    pub recommended: bool,
}

/// One thing the panel can install.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Entry {
    pub slug: &'static str,
    pub display_name: &'static str,
    pub category: Category,
    /// What it is for, in one sentence, for somebody who has not met it.
    pub summary: &'static str,
    pub versions: &'static [Version],
    /// Whether more than one version can be installed at once **on the host**.
    ///
    /// PHP can: every site names its own and gets its own pool. A database
    /// engine cannot — two MariaDBs want the same port and the same data
    /// directory — so choosing a version there means replacing what is
    /// installed, and the UI has to say so rather than offering a second row.
    ///
    /// This field is the host's answer only. The container path has a different
    /// one, and asking this field for it is how a page ends up warning that an
    /// install will replace a database it will not touch — read
    /// [`Entry::side_by_side_in`] instead, which takes the runtime.
    pub side_by_side: bool,
    /// How this can be installed, and what it is by default.
    pub install: Install,
}

impl Entry {
    /// Where this version's packages come from when it is installed on the
    /// host, or `None` when this entry is never installed as packages at all.
    ///
    /// The point of the `Option` is the `None`. A caller resolving a repository
    /// reads "not `Vendor`" as "the distribution has it", which is true of
    /// every entry that installs packages and false of one that is only ever an
    /// image — there is no repository to pin because there is nothing to
    /// install. Making that a third answer rather than a `Distro` is what keeps
    /// an image-only entry from quietly acquiring an `apt` line.
    pub const fn host_package_source(&self, version: &Version) -> Option<Source> {
        match self.install {
            Install::ContainerOnly => None,
            Install::HostOnly | Install::Either { .. } => Some(version.source),
        }
    }

    /// Whether two versions of this can be installed at once *on this runtime*.
    ///
    /// The two runtimes genuinely disagree, and it is the whole reason the
    /// choice is on the page. On the host, [`Entry::side_by_side`]: one port,
    /// one data directory, one `/etc`, so a second version replaces the first.
    /// In a container a version **is** a container — the model
    /// `docs/design/containerised-runtimes.md` settles on — with its own data
    /// volume and its own published port, so nothing is replaced by anything.
    ///
    /// Two things read this and both are load-bearing:
    ///
    /// - the page's "installing this replaces what is there" warning, which is
    ///   a sentence about somebody's database and has to be true in both
    ///   directions;
    /// - the key of a row in `stack_components`, which has to carry the version
    ///   wherever two of them can coexist, or the second install overwrites the
    ///   first row and the first container keeps serving on a port the panel no
    ///   longer knows it holds.
    ///
    /// Container rows are keyed this way from their first release, which is the
    /// only moment it is free: no server has one yet, so there is nothing to
    /// migrate. Host rows are untouched — `mariadb` stays `mariadb`.
    pub const fn side_by_side_in(&self, runtime: Runtime) -> bool {
        match runtime {
            Runtime::Host => self.side_by_side,
            Runtime::Container => true,
        }
    }
}

const fn v(version: &'static str) -> Version {
    Version {
        version,
        note: "",
        source: Source::Distro,
        eol: false,
        recommended: false,
    }
}

const fn vendor(version: &'static str) -> Version {
    Version {
        source: Source::Vendor,
        ..v(version)
    }
}

const fn rec(mut version: Version) -> Version {
    version.recommended = true;
    version
}

const fn eol(mut version: Version) -> Version {
    version.eol = true;
    version
}

const fn note(mut version: Version, text: &'static str) -> Version {
    version.note = text;
    version
}

// ---------------------------------------------------------------------------
// web servers
// ---------------------------------------------------------------------------

const NGINX: &[Version] = &[rec(note(
    vendor("stable"),
    "from nginx.org, the version nginx themselves call stable",
))];

/// OpenLiteSpeed, from LiteSpeed's own repository.
///
/// Not in Debian or Ubuntu at all, so a vendor repository is the only way. The
/// key that signs its `Release` was verified against the live repository rather
/// than copied from documentation — see `repos::litespeed`.
///
/// OpenLiteSpeed, not the commercial LiteSpeed Enterprise: the latter needs a
/// licence key the panel has no business holding.
const LITESPEED: &[Version] = &[note(
    vendor("openlitespeed"),
    "the open-source edition; LiteSpeed Enterprise needs a licence",
)];

/// Apache from the distribution.
///
/// No vendor repository: neither the ASF nor Ubuntu publishes one worth pinning,
/// and `apache2` is maintained for the life of the release. The version is
/// whatever that is, which is why there is one entry rather than a list.
const APACHE: &[Version] = &[note(v("distro"), "whatever this release maintains")];

// ---------------------------------------------------------------------------
// languages
// ---------------------------------------------------------------------------

/// PHP from Sury, which is where every version but the distribution's own lives.
///
/// Side by side: each site names its version and gets its own FPM pool.
const PHP: &[Version] = &[
    vendor("8.5"),
    vendor("8.4"),
    rec(vendor("8.3")),
    eol(vendor("8.2")),
    eol(vendor("8.1")),
    eol(vendor("8.0")),
    eol(vendor("7.4")),
];

/// Node from NodeSource, one repository per major line.
const NODE: &[Version] = &[
    note(vendor("24"), "current"),
    rec(note(vendor("22"), "LTS")),
    note(vendor("20"), "LTS, maintenance"),
];

const PYTHON: &[Version] = &[rec(note(v("distro"), "whatever this release maintains"))];
const GO: &[Version] = &[rec(note(v("distro"), "whatever this release maintains"))];
const RUBY: &[Version] = &[rec(note(v("distro"), "whatever this release maintains"))];

// ---------------------------------------------------------------------------
// databases
// ---------------------------------------------------------------------------

/// MariaDB from its own repository, which carries every maintained series.
const MARIADB: &[Version] = &[
    rec(note(vendor("11.8"), "long-term support")),
    note(vendor("11.4"), "long-term support"),
    note(vendor("10.11"), "long-term support, older applications"),
];

/// MongoDB from its own repository, one per major series.
///
/// The only entry here with no distribution package anywhere: Debian and Ubuntu
/// dropped MongoDB when it left the OSI-approved licences, so the vendor
/// repository is not a preference, it is the only route.
const MONGODB: &[Version] = &[
    rec(note(vendor("8.0"), "current")),
    note(vendor("7.0"), "previous series, still supported"),
];

/// MySQL from the distribution.
///
/// Oracle's own repository exists, and its signing key has been rotated in a way
/// that broke installs across the internet more than once. Ubuntu's `mysql-server`
/// is 8.0 and maintained for the life of the release, which is the version
/// almost everybody asking for MySQL wants.
const MYSQL: &[Version] = &[rec(note(
    v("distro"),
    "8.0, maintained by the distribution",
))];

const POSTGRES: &[Version] = &[
    rec(note(vendor("17"), "current")),
    vendor("16"),
    vendor("15"),
];

// ---------------------------------------------------------------------------
// caches and key-value stores
// ---------------------------------------------------------------------------

const REDIS: &[Version] = &[rec(note(v("distro"), "whatever this release maintains"))];

/// Valkey, the fork the Linux Foundation took up when Redis changed licence.
const VALKEY: &[Version] = &[note(v("distro"), "Redis-compatible, BSD licensed")];

const MEMCACHED: &[Version] = &[v("distro")];

// ---------------------------------------------------------------------------
// containers
// ---------------------------------------------------------------------------

const DOCKER: &[Version] = &[rec(note(vendor("stable"), "Docker CE, stable channel"))];

/// A container by default, the host still offered.
///
/// What every database and cache says, and the only thing this change moves.
/// The default is the container because that is the shape the design settled
/// on: installing a version cannot disturb another one, removing it is removing
/// a container, and there is no shared `/etc` for two engines to disagree over
/// — which is the failure that took a production site down. The host stays
/// offered because a machine with no Docker, or one already running the engine
/// on the host, is not a machine this panel gets to break.
const CONTAINER_FIRST: Install = Install::Either {
    default: Runtime::Container,
};

/// Everything, in the order a page should show it.
pub const CATALOGUE: &[Entry] = &[
    Entry {
        slug: "nginx",
        display_name: "Nginx",
        category: Category::WebServer,
        summary: "The web server Unihelm renders vhosts for. Required before a site can be served.",
        versions: NGINX,
        side_by_side: false,
        // Unchanged, and not pending: the web server terminates TLS, reads
        // certificates the panel renews and serves files out of tenant homes.
        // It is the thing everything else is behind, so a container isolates it
        // from nothing and costs a bind mount of every path it already needs.
        install: Install::HostOnly,
    },
    Entry {
        slug: "apache",
        display_name: "Apache",
        category: Category::WebServer,
        summary: "For applications that need .htaccess or a module nginx has no equivalent for.",
        versions: APACHE,
        side_by_side: false,
        // Host, for nginx's reasons, plus its own: the panel writes its vhosts
        // and its modules read from the same tenant homes.
        install: Install::HostOnly,
    },
    Entry {
        slug: "litespeed",
        display_name: "OpenLiteSpeed",
        category: Category::WebServer,
        summary: "Reads Apache .htaccess files and has its own PHP handler; a common answer for PHP hosting.",
        versions: LITESPEED,
        side_by_side: false,
        // Host, with the other two. Its external-app handler points at the same
        // per-site socket the others do, which is what makes switching web
        // servers tractable at all.
        install: Install::HostOnly,
    },
    Entry {
        slug: "php",
        display_name: "PHP",
        category: Category::Language,
        summary: "Versions run side by side; each site picks its own.",
        versions: PHP,
        side_by_side: true,
        // Host, for now, and this is a statement rather than a silence: PHP is
        // step three of the containerised plan. It needs the host's uids inside
        // the container and a shared socket directory, and those are the parts
        // that can take a running server offline, so they are built last on a
        // path the databases have already exercised.
        install: Install::HostOnly,
    },
    Entry {
        slug: "node",
        display_name: "Node.js",
        category: Category::Language,
        summary: "For applications the panel runs as a service behind a proxy.",
        versions: NODE,
        side_by_side: true,
        // Host, for now. Applications are step two, and they are not this
        // shape: Node has no multiplexer, so a Node container is one per
        // application built from the version's image, not one per version.
        install: Install::HostOnly,
    },
    Entry {
        slug: "python",
        display_name: "Python",
        category: Category::Language,
        summary: "For applications the panel runs as a service behind a proxy.",
        versions: PYTHON,
        side_by_side: false,
        // Host, for now; an application's container is step two, as for Node.
        install: Install::HostOnly,
    },
    Entry {
        slug: "go",
        display_name: "Go",
        category: Category::Language,
        summary: "The toolchain. A Go application is a compiled binary and needs no runtime.",
        versions: GO,
        side_by_side: false,
        // Host, and likely to stay there: this installs a compiler, and what it
        // produces is a binary with nothing to run it in.
        install: Install::HostOnly,
    },
    Entry {
        slug: "ruby",
        display_name: "Ruby",
        category: Category::Language,
        summary: "For applications the panel runs as a service behind a proxy.",
        versions: RUBY,
        side_by_side: false,
        // Host, for now; an application's container is step two, as for Node.
        install: Install::HostOnly,
    },
    Entry {
        slug: "mariadb",
        display_name: "MariaDB",
        category: Category::Database,
        summary: "The default engine. Speaks the MySQL protocol; most applications cannot tell them apart.",
        versions: MARIADB,
        side_by_side: false,
        // Changed. A container also ends the collision with MySQL, which on the
        // host is two packages fighting over one port and one data directory.
        install: CONTAINER_FIRST,
    },
    Entry {
        slug: "mysql",
        display_name: "MySQL",
        category: Category::Database,
        summary: "Oracle's MySQL, for applications that need it specifically.",
        versions: MYSQL,
        side_by_side: false,
        // Changed. The other half of that collision.
        install: CONTAINER_FIRST,
    },
    Entry {
        slug: "mongodb",
        display_name: "MongoDB",
        category: Category::Database,
        summary: "Document store. Not packaged by Debian or Ubuntu, so it comes from MongoDB's own repository.",
        versions: MONGODB,
        side_by_side: false,
        // Changed, and the one this helps most: the vendor repository exists
        // for a handful of releases and the image exists everywhere, so a
        // container is the difference between offering MongoDB and refusing it.
        install: CONTAINER_FIRST,
    },
    Entry {
        slug: "postgres",
        display_name: "PostgreSQL",
        category: Category::Database,
        summary: "For applications that want its types, its extensions, or its strictness.",
        versions: POSTGRES,
        side_by_side: false,
        // Changed. Two majors in one place is a packaging problem on the host
        // and two containers otherwise.
        install: CONTAINER_FIRST,
    },
    Entry {
        slug: "redis",
        display_name: "Redis",
        category: Category::Cache,
        summary: "In-memory store, for sessions, queues and caches.",
        versions: REDIS,
        side_by_side: false,
        // Changed. A cache holds nothing that cannot be rebuilt, which makes it
        // the safest thing on the list to move first.
        install: CONTAINER_FIRST,
    },
    Entry {
        slug: "valkey",
        display_name: "Valkey",
        category: Category::Cache,
        summary: "The BSD-licensed fork of Redis. Drop-in for most applications.",
        versions: VALKEY,
        side_by_side: false,
        // Changed, and it gains the most of the three: on EL there is no
        // package outside EPEL, so the host path there is a refusal and the
        // image is the only way to offer it at all.
        install: CONTAINER_FIRST,
    },
    Entry {
        slug: "memcached",
        display_name: "Memcached",
        category: Category::Cache,
        summary: "A simpler cache than Redis, for when that is all you need.",
        versions: MEMCACHED,
        side_by_side: false,
        // Changed, with the other caches.
        install: CONTAINER_FIRST,
    },
    Entry {
        slug: "docker",
        display_name: "Docker",
        category: Category::Container,
        summary: "The container runtime. Unihelm drives containers it did not create.",
        versions: DOCKER,
        side_by_side: false,
        // Host, necessarily: it is what runs the containers. An entry that
        // installed itself into one would have nothing to be installed into.
        install: Install::HostOnly,
    },
];

/// One entry by slug.
pub fn entry(slug: &str) -> Option<&'static Entry> {
    CATALOGUE.iter().find(|e| e.slug == slug)
}

/// One version of one entry.
///
/// The lookup that keeps the old enum's safety property: a request names a slug
/// and a version, both are found here or the request is refused, and nothing a
/// caller sends reaches a package manager without appearing in this file first.
pub fn version(slug: &str, version: &str) -> Option<(&'static Entry, &'static Version)> {
    let e = entry(slug)?;
    e.versions
        .iter()
        .find(|v| v.version == version)
        .map(|v| (e, v))
}

/// The version to install when the caller expressed no preference.
pub fn default_version(slug: &str) -> Option<&'static Version> {
    let e = entry(slug)?;
    e.versions
        .iter()
        .find(|v| v.recommended)
        .or_else(|| e.versions.first())
}

/// The runtime to install onto when the caller expressed no preference.
///
/// The companion to [`default_version`], and the reason it exists is the same:
/// most callers — the CLI with no flag, an API request with no field, the first
/// install on a new machine — say nothing, and what they get then has to be
/// decided in this file rather than at each of those call sites.
pub fn default_runtime(slug: &str) -> Option<Runtime> {
    Some(entry(slug)?.install.default_runtime())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Slugs reach the database, the API and the UI's routing. A duplicate would
    /// mean two entries fighting over one row in `stack_components`.
    #[test]
    fn every_slug_is_unique() {
        let mut seen = std::collections::HashSet::new();
        for e in CATALOGUE {
            assert!(seen.insert(e.slug), "duplicate slug `{}`", e.slug);
        }
    }

    /// A version string is part of a package name and a repository path on some
    /// of these, so it has to be boring.
    #[test]
    fn version_strings_are_safe_to_interpolate() {
        for e in CATALOGUE {
            for v in e.versions {
                assert!(
                    v.version
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'.'),
                    "{}/{} is not a plain version",
                    e.slug,
                    v.version
                );
                assert!(!v.version.is_empty(), "{} has an empty version", e.slug);
            }
        }
    }

    /// Every entry offers something, and at most one recommendation — two would
    /// make "the one to pick" meaningless.
    #[test]
    fn each_entry_offers_exactly_one_default() {
        for e in CATALOGUE {
            assert!(!e.versions.is_empty(), "{} offers nothing", e.slug);
            let recommended = e.versions.iter().filter(|v| v.recommended).count();
            assert!(
                recommended <= 1,
                "{} recommends {recommended} versions",
                e.slug
            );
            assert!(
                default_version(e.slug).is_some(),
                "{} has no default",
                e.slug
            );
        }
    }

    /// Nothing end-of-life should be what somebody gets by not choosing.
    #[test]
    fn no_default_is_end_of_life() {
        for e in CATALOGUE {
            let d = default_version(e.slug).unwrap();
            assert!(!d.eol, "{} defaults to an end-of-life version", e.slug);
        }
    }

    /// The lookup is the safety boundary: anything not in the table must be
    /// refused rather than passed to a package manager.
    #[test]
    fn unknown_slugs_and_versions_do_not_resolve() {
        assert!(entry("definitely-not-a-thing").is_none());
        assert!(version("nginx", "; rm -rf /").is_none());
        assert!(version("php", "9.9").is_none());
        assert!(version("mariadb", "../../etc/passwd").is_none());
        // And a real one does.
        assert!(version("mariadb", "11.8").is_some());
    }

    /// The web servers and Docker itself are on the host and are not waiting
    /// for a later step. Offering a container for any of them would be offering
    /// something the design argues against — or, for Docker, something with
    /// nothing to run it.
    #[test]
    fn the_web_servers_and_the_container_runtime_are_host_only() {
        for slug in ["nginx", "apache", "litespeed", "docker"] {
            let e = entry(slug).unwrap();
            assert_eq!(e.install, Install::HostOnly, "{slug} offers a container");
        }
    }

    /// Step one of the containerised plan: every database and every cache
    /// defaults to a container, and none of them loses the host path.
    ///
    /// The default is what somebody gets by not choosing, so it is the whole
    /// behaviour of this change; the host path staying reachable is what keeps
    /// a machine without Docker installable.
    #[test]
    fn databases_and_caches_default_to_a_container_and_keep_the_host() {
        for e in CATALOGUE {
            if !matches!(e.category, Category::Database | Category::Cache) {
                continue;
            }
            assert_eq!(
                e.install.default_runtime(),
                Runtime::Container,
                "{} does not default to a container",
                e.slug
            );
            assert!(
                e.install.allows(Runtime::Host),
                "{} cannot be installed on a machine without Docker",
                e.slug
            );
        }
    }

    /// Languages say "host" rather than saying nothing. PHP is step three and
    /// the rest are step two; when those land, this test is what has to be
    /// changed deliberately, which is the point of it.
    #[test]
    fn the_languages_are_still_host_only() {
        for e in CATALOGUE {
            if e.category != Category::Language {
                continue;
            }
            assert_eq!(
                e.install,
                Install::HostOnly,
                "{} moved to a container ahead of the step that maps uids",
                e.slug
            );
        }
    }

    /// Nothing that is only ever an image can be asked where its packages come
    /// from. `Distro` is not a safe answer there — a caller reading "not
    /// `Vendor`" as "the distribution has it" would `apt install` a name that
    /// does not exist — so the answer is that there is no answer.
    #[test]
    fn an_image_only_entry_has_no_package_source() {
        let image_only = Entry {
            install: Install::ContainerOnly,
            ..*entry("mariadb").unwrap()
        };
        for v in image_only.versions {
            assert_eq!(v.source, Source::Vendor, "the sample lost its vendor repo");
            assert!(
                image_only.host_package_source(v).is_none(),
                "an image-only entry offered a repository to pin"
            );
        }
    }

    /// And everything that does install packages still answers, so the host
    /// path is not quietly turned into a refusal by the same rule.
    #[test]
    fn everything_installable_on_the_host_says_where_its_packages_come_from() {
        for e in CATALOGUE {
            for v in e.versions {
                assert_eq!(
                    e.host_package_source(v).is_some(),
                    e.install.allows(Runtime::Host),
                    "{}/{} disagrees with itself about having packages",
                    e.slug,
                    v.version
                );
            }
        }
    }

    /// The default is inside the value, so it cannot name a runtime the value
    /// does not offer. Checked over every shape, not just the ones in use.
    #[test]
    fn a_default_runtime_is_always_one_of_the_offered_ones() {
        for install in [
            Install::HostOnly,
            Install::ContainerOnly,
            Install::Either {
                default: Runtime::Host,
            },
            Install::Either {
                default: Runtime::Container,
            },
        ] {
            assert!(
                install.runtimes().contains(&install.default_runtime()),
                "{install:?} defaults to a runtime it does not offer"
            );
            for runtime in [Runtime::Host, Runtime::Container] {
                assert_eq!(
                    install.allows(runtime),
                    install.runtimes().contains(&runtime),
                    "{install:?} disagrees with itself about {}",
                    runtime.as_str()
                );
            }
            assert!(!install.runtimes().is_empty());
        }
    }

    /// Every entry resolves a runtime for a caller that named none, the way
    /// every entry resolves a version.
    #[test]
    fn every_entry_has_a_default_runtime() {
        for e in CATALOGUE {
            assert_eq!(
                default_runtime(e.slug),
                Some(e.install.default_runtime()),
                "{} has no default runtime",
                e.slug
            );
        }
        assert!(default_runtime("definitely-not-a-thing").is_none());
    }

    /// The two runtimes disagree about this, and for the entries this change
    /// moves they disagree in the dangerous direction: `side_by_side` is false
    /// for every database, so anything reading that field for a container
    /// install says "this replaces what is there" over an install that replaces
    /// nothing — and keys both versions to one `stack_components` row, which
    /// leaves the first container serving on a port no row mentions.
    #[test]
    fn a_second_version_replaces_the_first_on_the_host_and_joins_it_in_a_container() {
        for e in CATALOGUE {
            if !e.install.allows(Runtime::Container) {
                continue;
            }
            assert!(
                e.side_by_side_in(Runtime::Container),
                "{} cannot hold two containers, which is the whole model",
                e.slug
            );
            assert_eq!(
                e.side_by_side_in(Runtime::Host),
                e.side_by_side,
                "{} answers the host question with something other than the host field",
                e.slug
            );
        }

        // The pair the accessor exists for: the same entry, two answers.
        let mariadb = entry("mariadb").unwrap();
        assert!(!mariadb.side_by_side_in(Runtime::Host));
        assert!(mariadb.side_by_side_in(Runtime::Container));
    }

    /// Exactly which entries a caller that says nothing now gets a container
    /// for. Spelled out rather than derived, because every slug here has to
    /// have somewhere to run — an entry that defaults to a container the panel
    /// has no image and no port for is an entry whose default install refuses.
    /// Adding one is adding both, and this list is where that is noticed.
    #[test]
    fn the_container_default_is_exactly_these_seven() {
        let container: Vec<&str> = CATALOGUE
            .iter()
            .filter(|e| e.install.default_runtime() == Runtime::Container)
            .map(|e| e.slug)
            .collect();
        assert_eq!(
            container,
            [
                "mariadb",
                "mysql",
                "mongodb",
                "postgres",
                "redis",
                "valkey",
                "memcached"
            ]
        );
    }

    /// The Stack page reads the choice off this, so the shape is part of the
    /// API and not an implementation detail of the enum.
    #[test]
    fn the_wire_shape_says_what_may_be_chosen_and_what_is_chosen_for_you() {
        let mariadb = serde_json::to_value(entry("mariadb").unwrap()).unwrap();
        assert_eq!(
            mariadb["install"],
            serde_json::json!({
                "runtimes": ["host", "container"],
                "default_runtime": "container",
            })
        );

        let nginx = serde_json::to_value(entry("nginx").unwrap()).unwrap();
        assert_eq!(
            nginx["install"],
            serde_json::json!({ "runtimes": ["host"], "default_runtime": "host" })
        );
    }

    /// Only PHP and Node can have several versions at once. Anything else
    /// wanting the same port and data directory has to replace what is there,
    /// and the page has to say so rather than offering a second row.
    #[test]
    fn only_the_runtimes_that_can_coexist_say_they_can() {
        for e in CATALOGUE {
            if e.side_by_side {
                assert!(
                    matches!(e.slug, "php" | "node"),
                    "{} claims it can run side by side",
                    e.slug
                );
            }
        }
    }
}
