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

/// One installable version of one piece of software.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Version {
    /// What the operator picks: `11.8`, `8.3`, `24`.
    pub version: &'static str,
    /// Shown beside it. Empty when the version speaks for itself.
    pub note: &'static str,
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
    /// Whether more than one version can be installed at once.
    ///
    /// PHP can: every site names its own and gets its own pool. A database
    /// engine cannot — two MariaDBs want the same port and the same data
    /// directory — so choosing a version there means replacing what is
    /// installed, and the UI has to say so rather than offering a second row.
    pub side_by_side: bool,
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

/// Everything, in the order a page should show it.
pub const CATALOGUE: &[Entry] = &[
    Entry {
        slug: "nginx",
        display_name: "Nginx",
        category: Category::WebServer,
        summary: "The web server Unihelm renders vhosts for. Required before a site can be served.",
        versions: NGINX,
        side_by_side: false,
    },
    Entry {
        slug: "apache",
        display_name: "Apache",
        category: Category::WebServer,
        summary: "For applications that need .htaccess or a module nginx has no equivalent for.",
        versions: APACHE,
        side_by_side: false,
    },
    Entry {
        slug: "litespeed",
        display_name: "OpenLiteSpeed",
        category: Category::WebServer,
        summary: "Reads Apache .htaccess files and has its own PHP handler; a common answer for PHP hosting.",
        versions: LITESPEED,
        side_by_side: false,
    },
    Entry {
        slug: "php",
        display_name: "PHP",
        category: Category::Language,
        summary: "Versions run side by side; each site picks its own.",
        versions: PHP,
        side_by_side: true,
    },
    Entry {
        slug: "node",
        display_name: "Node.js",
        category: Category::Language,
        summary: "For applications the panel runs as a service behind a proxy.",
        versions: NODE,
        side_by_side: true,
    },
    Entry {
        slug: "python",
        display_name: "Python",
        category: Category::Language,
        summary: "For applications the panel runs as a service behind a proxy.",
        versions: PYTHON,
        side_by_side: false,
    },
    Entry {
        slug: "go",
        display_name: "Go",
        category: Category::Language,
        summary: "The toolchain. A Go application is a compiled binary and needs no runtime.",
        versions: GO,
        side_by_side: false,
    },
    Entry {
        slug: "ruby",
        display_name: "Ruby",
        category: Category::Language,
        summary: "For applications the panel runs as a service behind a proxy.",
        versions: RUBY,
        side_by_side: false,
    },
    Entry {
        slug: "mariadb",
        display_name: "MariaDB",
        category: Category::Database,
        summary: "The default engine. Speaks the MySQL protocol; most applications cannot tell them apart.",
        versions: MARIADB,
        side_by_side: false,
    },
    Entry {
        slug: "mysql",
        display_name: "MySQL",
        category: Category::Database,
        summary: "Oracle's MySQL, for applications that need it specifically.",
        versions: MYSQL,
        side_by_side: false,
    },
    Entry {
        slug: "mongodb",
        display_name: "MongoDB",
        category: Category::Database,
        summary: "Document store. Not packaged by Debian or Ubuntu, so it comes from MongoDB's own repository.",
        versions: MONGODB,
        side_by_side: false,
    },
    Entry {
        slug: "postgres",
        display_name: "PostgreSQL",
        category: Category::Database,
        summary: "For applications that want its types, its extensions, or its strictness.",
        versions: POSTGRES,
        side_by_side: false,
    },
    Entry {
        slug: "redis",
        display_name: "Redis",
        category: Category::Cache,
        summary: "In-memory store, for sessions, queues and caches.",
        versions: REDIS,
        side_by_side: false,
    },
    Entry {
        slug: "valkey",
        display_name: "Valkey",
        category: Category::Cache,
        summary: "The BSD-licensed fork of Redis. Drop-in for most applications.",
        versions: VALKEY,
        side_by_side: false,
    },
    Entry {
        slug: "memcached",
        display_name: "Memcached",
        category: Category::Cache,
        summary: "A simpler cache than Redis, for when that is all you need.",
        versions: MEMCACHED,
        side_by_side: false,
    },
    Entry {
        slug: "docker",
        display_name: "Docker",
        category: Category::Container,
        summary: "The container runtime. Unihelm drives containers it did not create.",
        versions: DOCKER,
        side_by_side: false,
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
