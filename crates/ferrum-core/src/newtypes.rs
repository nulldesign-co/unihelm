//! Validated-at-deserialization input types (spec §5.2 rule 1, §12 rule 3).
//!
//! The rule the whole security model leans on: **a free-form `String` never
//! reaches a command line or a SQL identifier**. Anything that will be handed to
//! `Command::args`, interpolated into a config template, or used as a database
//! identifier is one of the types below, and the only way to build one is through
//! validation — including via `serde`, so an IPC frame carrying garbage is
//! rejected at the protocol edge rather than deep inside an operation.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::error::{ErrorCode, FerrumError, Result};

/// Linux users the panel must never create, take over, or run tenant work as.
const RESERVED_SYSTEM_USERS: &[&str] = &[
    "root",
    "daemon",
    "bin",
    "sys",
    "sync",
    "games",
    "man",
    "lp",
    "mail",
    "news",
    "uucp",
    "proxy",
    "www-data",
    "backup",
    "list",
    "irc",
    "nobody",
    "systemd-network",
    "systemd-resolve",
    "messagebus",
    "sshd",
    "nginx",
    "apache",
    "httpd",
    "mysql",
    "mariadb",
    "postgres",
    "redis",
    "valkey",
    "docker",
    "ferrum",
    "ferrum-web",
    "ferrum-agent",
    "adm",
    "operator",
    "ftp",
    "dbus",
    "polkitd",
    "chrony",
];

/// Database names that belong to the engine, not to a tenant.
const RESERVED_DB_NAMES: &[&str] = &[
    "information_schema",
    "mysql",
    "performance_schema",
    "sys",
    "postgres",
    "template0",
    "template1",
];

fn err(code: ErrorCode, detail: impl Into<String>) -> FerrumError {
    FerrumError::new(code, detail)
}

// ---------------------------------------------------------------------------
// Domain
// ---------------------------------------------------------------------------

/// A fully-qualified DNS name, normalised to lowercase with any trailing dot
/// removed. ASCII only — callers must punycode IDNs before constructing one, so
/// what we render into an nginx `server_name` is exactly what DNS resolves.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Domain(String);

impl Domain {
    pub fn parse(input: &str) -> Result<Self> {
        let s = input.trim().trim_end_matches('.').to_ascii_lowercase();

        if s.is_empty() {
            return Err(err(ErrorCode::InvalidDomain, "domain is empty"));
        }
        if s.len() > 253 {
            return Err(err(
                ErrorCode::InvalidDomain,
                "domain exceeds 253 characters",
            ));
        }

        let labels: Vec<&str> = s.split('.').collect();
        if labels.len() < 2 {
            return Err(err(
                ErrorCode::InvalidDomain,
                "domain must contain at least one dot (e.g. example.com)",
            ));
        }

        for label in &labels {
            if label.is_empty() {
                return Err(err(ErrorCode::InvalidDomain, "domain has an empty label"));
            }
            if label.len() > 63 {
                return Err(err(
                    ErrorCode::InvalidDomain,
                    "domain label exceeds 63 characters",
                ));
            }
            if label.starts_with('-') || label.ends_with('-') {
                return Err(err(
                    ErrorCode::InvalidDomain,
                    "domain label may not start or end with a hyphen",
                ));
            }
            if !label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            {
                return Err(err(
                    ErrorCode::InvalidDomain,
                    "domain may only contain a-z, 0-9 and hyphen (punycode IDNs first)",
                ));
            }
        }

        // An all-numeric last label means someone handed us an IP address.
        let tld = labels[labels.len() - 1];
        if tld.bytes().all(|b| b.is_ascii_digit()) {
            return Err(err(
                ErrorCode::InvalidDomain,
                "expected a domain name, not an IP address",
            ));
        }

        Ok(Self(s))
    }

    /// `*.example.com` — accepted only where wildcards are meaningful (DNS-01
    /// certificates). Returns the wildcard form as a plain string plus the base.
    pub fn parse_wildcard(input: &str) -> Result<(String, Self)> {
        match input.trim().strip_prefix("*.") {
            Some(base) => {
                let base = Self::parse(base)?;
                Ok((format!("*.{}", base.as_str()), base))
            }
            None => Err(err(
                ErrorCode::InvalidDomain,
                "expected a wildcard of the form *.example.com",
            )),
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// `www.` prefixed form, used for the www-alias policy.
    pub fn with_www(&self) -> Result<Domain> {
        Domain::parse(&format!("www.{}", self.0))
    }
}

// ---------------------------------------------------------------------------
// LinuxUser / Username / Email
// ---------------------------------------------------------------------------

/// A Linux account name the panel may create or act as (`ft_<short-id>`).
///
/// Rejects every account that already exists on a normal server, so a tenant can
/// never be provisioned onto `root`, `nginx`, or the panel's own user.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct LinuxUser(String);

impl LinuxUser {
    pub fn parse(input: &str) -> Result<Self> {
        let s = input.trim();
        if s.is_empty() || s.len() > 32 {
            return Err(err(
                ErrorCode::InvalidUsername,
                "linux user must be 1-32 characters",
            ));
        }
        let mut bytes = s.bytes();
        let first = bytes.next().unwrap();
        if !(first.is_ascii_lowercase() || first == b'_') {
            return Err(err(
                ErrorCode::InvalidUsername,
                "linux user must start with a lowercase letter or underscore",
            ));
        }
        if !bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-') {
            return Err(err(
                ErrorCode::InvalidUsername,
                "linux user may only contain a-z, 0-9, underscore and hyphen",
            ));
        }
        if RESERVED_SYSTEM_USERS.contains(&s) {
            return Err(err(
                ErrorCode::InvalidUsername,
                format!("`{s}` is a reserved system user"),
            ));
        }
        Ok(Self(s.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A panel login name (distinct from the tenant's Linux account).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Username(String);

impl Username {
    pub fn parse(input: &str) -> Result<Self> {
        let s = input.trim().to_ascii_lowercase();
        if s.len() < 3 || s.len() > 32 {
            return Err(err(
                ErrorCode::InvalidUsername,
                "username must be 3-32 characters",
            ));
        }
        if !s.bytes().next().unwrap().is_ascii_alphanumeric() {
            return Err(err(
                ErrorCode::InvalidUsername,
                "username must start with a letter or digit",
            ));
        }
        if !s.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'_' || b == b'-'
        }) {
            return Err(err(
                ErrorCode::InvalidUsername,
                "username may only contain a-z, 0-9, dot, underscore and hyphen",
            ));
        }
        Ok(Self(s))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A deliberately permissive email check: enough to catch typos and to keep
/// header-injection characters out, not an RFC 5322 parser.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Email(String);

impl Email {
    pub fn parse(input: &str) -> Result<Self> {
        let s = input.trim().to_ascii_lowercase();
        if s.len() < 3 || s.len() > 254 {
            return Err(
                err(ErrorCode::InvalidInput, "email must be 3-254 characters").with_field("email"),
            );
        }
        if s.bytes()
            .any(|b| b.is_ascii_control() || b == b' ' || b == b',' || b == b';')
        {
            return Err(
                err(ErrorCode::InvalidInput, "email contains illegal characters")
                    .with_field("email"),
            );
        }
        let Some((local, domain)) = s.split_once('@') else {
            return Err(err(ErrorCode::InvalidInput, "email must contain @").with_field("email"));
        };
        if local.is_empty() || local.len() > 64 {
            return Err(err(
                ErrorCode::InvalidInput,
                "email local part must be 1-64 characters",
            )
            .with_field("email"));
        }
        Domain::parse(domain).map_err(|_| {
            err(
                ErrorCode::InvalidInput,
                "email domain is not a valid domain name",
            )
            .with_field("email")
        })?;
        Ok(Self(s))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// ---------------------------------------------------------------------------
// DbName
// ---------------------------------------------------------------------------

/// A database (or database-user) identifier.
///
/// Restricted to `[A-Za-z0-9_]` so it needs no quoting in either MySQL or
/// PostgreSQL, which removes identifier-injection as a category.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct DbName(String);

impl DbName {
    pub fn parse(input: &str) -> Result<Self> {
        let s = input.trim();
        if s.is_empty() || s.len() > 63 {
            return Err(err(
                ErrorCode::InvalidDbName,
                "database name must be 1-63 characters",
            ));
        }
        let first = s.bytes().next().unwrap();
        if !(first.is_ascii_alphabetic() || first == b'_') {
            return Err(err(
                ErrorCode::InvalidDbName,
                "database name must start with a letter or underscore",
            ));
        }
        if !s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
            return Err(err(
                ErrorCode::InvalidDbName,
                "database name may only contain letters, digits and underscore",
            ));
        }
        let lower = s.to_ascii_lowercase();
        if RESERVED_DB_NAMES.contains(&lower.as_str()) || lower.starts_with("pg_") {
            return Err(err(
                ErrorCode::InvalidDbName,
                format!("`{s}` is reserved by the database engine"),
            ));
        }
        Ok(Self(s.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// ---------------------------------------------------------------------------
// TenantPath
// ---------------------------------------------------------------------------

/// A path *relative to a tenant's home directory*.
///
/// This type rejects the obvious escapes (absolute paths, `..`, NUL, control
/// characters). It is deliberately **not** the whole defence: the agent also
/// canonicalises the joined path, asserts the tenant-home prefix, and performs
/// the operation as the tenant's uid, so a bug here still lands on an OS
/// permission check (spec §5.2 rule 3).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct TenantPath(String);

impl TenantPath {
    pub fn parse(input: &str) -> Result<Self> {
        let s = input.trim();
        // The empty string is the home directory itself, not a missing value.
        //
        // [`Self::root`] produces exactly this, and `Serialize` writes it as
        // `""` — so rejecting it here made the type non-round-trippable, and the
        // one path that could never cross the IPC boundary was the file
        // manager's own starting directory. Found by opening the file manager on
        // a live server: `fs.list` with no path answered "path is empty".
        //
        // A caller that means "no path given" uses `Option<TenantPath>`; that is
        // the distinction serde is for.
        if s.is_empty() {
            return Ok(Self::root());
        }
        if s.len() > 4096 {
            return Err(err(ErrorCode::InvalidPath, "path exceeds 4096 characters"));
        }
        if s.starts_with('/') {
            return Err(err(
                ErrorCode::InvalidPath,
                "path must be relative to the tenant home",
            ));
        }
        if s.contains('\0') {
            return Err(err(ErrorCode::InvalidPath, "path contains a NUL byte"));
        }
        if s.chars().any(|c| c.is_control()) {
            return Err(err(
                ErrorCode::InvalidPath,
                "path contains control characters",
            ));
        }
        if s.contains('\\') {
            return Err(err(
                ErrorCode::InvalidPath,
                "path may not contain backslashes",
            ));
        }

        let mut parts = Vec::new();
        for part in s.split('/') {
            match part {
                "" => {
                    return Err(err(
                        ErrorCode::InvalidPath,
                        "path contains an empty component",
                    ));
                }
                "." => return Err(err(ErrorCode::InvalidPath, "path contains a `.` component")),
                ".." => {
                    return Err(err(
                        ErrorCode::InvalidPath,
                        "path traversal (`..`) is not allowed",
                    ));
                }
                p if p.len() > 255 => {
                    return Err(err(
                        ErrorCode::InvalidPath,
                        "path component exceeds 255 characters",
                    ));
                }
                p => parts.push(p),
            }
        }

        Ok(Self(parts.join("/")))
    }

    /// The tenant-relative form. Joining happens in the agent, never here.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The root of a tenant home, used when an operation targets the home itself.
    pub fn root() -> Self {
        Self(String::new())
    }
}

// ---------------------------------------------------------------------------
// PhpVersion
// ---------------------------------------------------------------------------

/// The PHP versions Ferrum knows how to install (spec §11.3).
///
/// An enum, not a string: this value ends up in package names, unit names and
/// FPM socket paths, and none of those may ever be attacker-influenced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub enum PhpVersion {
    V74,
    V80,
    V81,
    V82,
    V83,
    V84,
    V85,
}

impl PhpVersion {
    pub const ALL: &'static [PhpVersion] = &[
        PhpVersion::V74,
        PhpVersion::V80,
        PhpVersion::V81,
        PhpVersion::V82,
        PhpVersion::V83,
        PhpVersion::V84,
        PhpVersion::V85,
    ];

    pub fn parse(input: &str) -> Result<Self> {
        Ok(match input.trim() {
            "7.4" | "74" => Self::V74,
            "8.0" | "80" => Self::V80,
            "8.1" | "81" => Self::V81,
            "8.2" | "82" => Self::V82,
            "8.3" | "83" => Self::V83,
            "8.4" | "84" => Self::V84,
            "8.5" | "85" => Self::V85,
            other => {
                return Err(err(
                    ErrorCode::InvalidPhpVersion,
                    format!("`{other}` is not a supported PHP version (7.4-8.5)"),
                ));
            }
        })
    }

    /// Dotted form used in UI and config: `8.3`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::V74 => "7.4",
            Self::V80 => "8.0",
            Self::V81 => "8.1",
            Self::V82 => "8.2",
            Self::V83 => "8.3",
            Self::V84 => "8.4",
            Self::V85 => "8.5",
        }
    }

    /// Undotted form used by RHEL/Remi package and module names: `83`.
    pub const fn compact(self) -> &'static str {
        match self {
            Self::V74 => "74",
            Self::V80 => "80",
            Self::V81 => "81",
            Self::V82 => "82",
            Self::V83 => "83",
            Self::V84 => "84",
            Self::V85 => "85",
        }
    }

    /// Upstream security support ended — surfaced as a warning in the UI.
    pub const fn is_eol(self) -> bool {
        matches!(self, Self::V74 | Self::V80 | Self::V81 | Self::V82)
    }
}

// ---------------------------------------------------------------------------
// Port
// ---------------------------------------------------------------------------

/// A TCP/UDP port the panel is willing to manage.
///
/// Port 0 is meaningless here and the privileged range is refused for tenant-
/// facing allocations, so an app can never be asked to bind :22 or :80.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "u16", into = "u16")]
pub struct Port(u16);

impl Port {
    pub fn parse(v: u16) -> Result<Self> {
        if v == 0 {
            return Err(err(ErrorCode::InvalidPort, "port 0 is not valid"));
        }
        Ok(Self(v))
    }

    /// Ports handed out to tenant apps: unprivileged and outside the ephemeral range.
    pub fn parse_app_port(v: u16) -> Result<Self> {
        if !(1024..=61000).contains(&v) {
            return Err(err(
                ErrorCode::InvalidPort,
                "app ports must be between 1024 and 61000",
            ));
        }
        Ok(Self(v))
    }

    pub const fn get(self) -> u16 {
        self.0
    }
}

// ---------------------------------------------------------------------------
// AppName
// ---------------------------------------------------------------------------

/// The name of a tenant's Node application (spec §11.6).
///
/// This one string ends up in three places that each have their own idea of
/// what a dangerous character is, so the alphabet is the intersection of all
/// three:
///
/// - a **systemd unit name** (`ferrum-app-<user>-<name>.service`), where a
///   newline would end the `Description=` line and start a directive of the
///   attacker's choosing, and where `%` is a specifier systemd expands;
/// - a **filesystem path** (`<home>/apps/<name>`), where `/` and `..` would
///   leave the tenant's home;
/// - the **argv of `systemctl`**, where argv arrays already make quoting moot
///   but a leading `-` would still be read as an option.
///
/// `[a-z0-9][a-z0-9_-]*`, 1–32 characters, lowercased on the way in. Nothing
/// in that alphabet needs quoting anywhere, which is the point: the type is the
/// proof, not a promise made at each of the three call sites.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct AppName(String);

impl AppName {
    pub fn parse(input: &str) -> Result<Self> {
        let s = input.trim().to_ascii_lowercase();
        if s.is_empty() || s.len() > 32 {
            return Err(
                err(ErrorCode::InvalidInput, "app name must be 1-32 characters").with_field("name"),
            );
        }
        let first = s.bytes().next().unwrap();
        if !first.is_ascii_alphanumeric() {
            return Err(err(
                ErrorCode::InvalidInput,
                "app name must start with a letter or digit",
            )
            .with_field("name"));
        }
        if !s
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
        {
            return Err(err(
                ErrorCode::InvalidInput,
                "app name may only contain a-z, 0-9, underscore and hyphen",
            )
            .with_field("name"));
        }
        Ok(Self(s))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// ---------------------------------------------------------------------------
// Boilerplate: Display / AsRef / TryFrom / Into for every string newtype
// ---------------------------------------------------------------------------

macro_rules! string_newtype_impls {
    ($($name:ident),* $(,)?) => {$(
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.as_str())
            }
        }
        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str { self.as_str() }
        }
        impl TryFrom<String> for $name {
            type Error = FerrumError;
            fn try_from(v: String) -> Result<Self> { Self::parse(&v) }
        }
        impl TryFrom<&str> for $name {
            type Error = FerrumError;
            fn try_from(v: &str) -> Result<Self> { Self::parse(v) }
        }
        impl std::str::FromStr for $name {
            type Err = FerrumError;
            fn from_str(v: &str) -> Result<Self> { Self::parse(v) }
        }
        impl From<$name> for String {
            fn from(v: $name) -> String { v.0 }
        }
    )*};
}

string_newtype_impls!(
    AppName, Domain, LinuxUser, Username, Email, DbName, TenantPath
);

impl fmt::Display for PhpVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
impl TryFrom<String> for PhpVersion {
    type Error = FerrumError;
    fn try_from(v: String) -> Result<Self> {
        Self::parse(&v)
    }
}
impl std::str::FromStr for PhpVersion {
    type Err = FerrumError;
    fn from_str(v: &str) -> Result<Self> {
        Self::parse(v)
    }
}
impl From<PhpVersion> for String {
    fn from(v: PhpVersion) -> String {
        v.as_str().to_string()
    }
}

impl fmt::Display for Port {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}
impl TryFrom<u16> for Port {
    type Error = FerrumError;
    fn try_from(v: u16) -> Result<Self> {
        Self::parse(v)
    }
}
impl From<Port> for u16 {
    fn from(v: Port) -> u16 {
        v.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_accepts_normal_names_and_normalises() {
        assert_eq!(
            Domain::parse("Example.COM.").unwrap().as_str(),
            "example.com"
        );
        assert_eq!(
            Domain::parse(" sub.example.co.uk ").unwrap().as_str(),
            "sub.example.co.uk"
        );
        assert_eq!(
            Domain::parse("xn--fsq.example.com").unwrap().as_str(),
            "xn--fsq.example.com"
        );
    }

    #[test]
    fn domain_rejects_injection_and_nonsense() {
        for bad in [
            "",
            "localhost",
            "example .com",
            "exa mple.com",
            "-bad.example.com",
            "bad-.example.com",
            "example.com/../../etc/passwd",
            "example.com;rm -rf /",
            "example.com\nserver_name evil.com;",
            "$(whoami).example.com",
            "1.2.3.4",
            "exam_ple.com",
            "پارسی.com",
        ] {
            assert!(
                Domain::parse(bad).is_err(),
                "expected `{bad}` to be rejected"
            );
        }
    }

    #[test]
    fn domain_length_limits() {
        let long_label = "a".repeat(64);
        assert!(Domain::parse(&format!("{long_label}.com")).is_err());
        let ok_label = "a".repeat(63);
        assert!(Domain::parse(&format!("{ok_label}.com")).is_ok());
        // 4x60 + 3 dots + ".com" = 247 chars, just inside the 253 limit.
        let near_limit = format!("{}.com", vec!["a".repeat(60); 4].join("."));
        assert_eq!(near_limit.len(), 247);
        assert!(Domain::parse(&near_limit).is_ok());
        let over_limit = format!("{}.com", vec!["a".repeat(60); 5].join("."));
        assert!(Domain::parse(&over_limit).is_err());
    }

    #[test]
    fn wildcard_parsing() {
        let (w, base) = Domain::parse_wildcard("*.Example.com").unwrap();
        assert_eq!(w, "*.example.com");
        assert_eq!(base.as_str(), "example.com");
        assert!(Domain::parse_wildcard("example.com").is_err());
        assert!(
            Domain::parse("*.example.com").is_err(),
            "plain Domain must not accept wildcards"
        );
    }

    #[test]
    fn tenant_path_rejects_traversal() {
        for bad in [
            "../etc/passwd",
            "sites/../../../etc/shadow",
            "/etc/passwd",
            "a//b",
            "./x",
            "a/./b",
            "a/../b",
            "bad\0name",
            "bad\nname",
            "back\\slash",
        ] {
            assert!(
                TenantPath::parse(bad).is_err(),
                "expected `{bad}` to be rejected"
            );
        }
    }

    #[test]
    fn the_tenant_home_itself_survives_a_round_trip() {
        // The root is a real, addressable location — the file manager's opening
        // screen. It serialises to `""`, so `""` has to parse back to it; when
        // it did not, `fs.list` on a live server answered "path is empty" for
        // the one directory every session starts in.
        let root = TenantPath::root();
        assert_eq!(root.as_str(), "");
        assert_eq!(TenantPath::parse("").unwrap(), root);

        let json = serde_json::to_string(&root).unwrap();
        assert_eq!(json, r#""""#);
        assert_eq!(serde_json::from_str::<TenantPath>(&json).unwrap(), root);
    }

    #[test]
    fn accepting_the_root_did_not_reopen_the_traversal_hole() {
        // Whitespace trims to empty, so this is the one shape where "empty means
        // root" could have let something odd through.
        assert_eq!(TenantPath::parse("   ").unwrap(), TenantPath::root());
        for still_bad in ["/", "//", "..", "./", "/etc"] {
            assert!(
                TenantPath::parse(still_bad).is_err(),
                "expected `{still_bad}` to stay rejected"
            );
        }
    }

    #[test]
    fn tenant_path_accepts_ordinary_files() {
        assert_eq!(
            TenantPath::parse("sites/example.com/public/index.php")
                .unwrap()
                .as_str(),
            "sites/example.com/public/index.php"
        );
        // Dots inside a name are fine; only a bare `.`/`..` component is not.
        assert!(TenantPath::parse("sites/..hidden/file.txt").is_ok());
        assert!(TenantPath::parse("my file with spaces.txt").is_ok());
    }

    #[test]
    fn db_name_rules() {
        assert!(DbName::parse("wp_main").is_ok());
        assert!(DbName::parse("_tmp1").is_ok());
        for bad in [
            "", "1abc", "wp-main", "wp main", "wp;drop", "mysql", "PG_toast", "sys", "a'b",
        ] {
            assert!(
                DbName::parse(bad).is_err(),
                "expected `{bad}` to be rejected"
            );
        }
    }

    #[test]
    fn linux_user_rules() {
        assert!(LinuxUser::parse("ft_a1b2c3").is_ok());
        for bad in [
            "root",
            "nginx",
            "ferrum",
            "Ft_Upper",
            "1user",
            "user name",
            "a".repeat(33).as_str(),
        ] {
            assert!(
                LinuxUser::parse(bad).is_err(),
                "expected `{bad}` to be rejected"
            );
        }
    }

    #[test]
    fn email_rules() {
        assert_eq!(
            Email::parse(" Farzam@Example.COM ").unwrap().as_str(),
            "farzam@example.com"
        );
        for bad in [
            "nope",
            "a@b",
            "a@@b.com",
            "a b@example.com",
            "a@example.com\nBcc: x@y.com",
            "@example.com",
        ] {
            assert!(
                Email::parse(bad).is_err(),
                "expected `{bad}` to be rejected"
            );
        }
    }

    #[test]
    fn php_version_roundtrip() {
        for &v in PhpVersion::ALL {
            assert_eq!(PhpVersion::parse(v.as_str()).unwrap(), v);
            assert_eq!(PhpVersion::parse(v.compact()).unwrap(), v);
        }
        assert!(PhpVersion::parse("8.6").is_err());
        assert!(PhpVersion::parse("8.3; rm -rf /").is_err());
    }

    #[test]
    fn serde_validates_on_deserialize() {
        // The whole point: invalid data cannot enter the process as a typed value.
        assert!(serde_json::from_str::<Domain>("\"exa mple.com\"").is_err());
        assert!(serde_json::from_str::<TenantPath>("\"../../etc/passwd\"").is_err());
        assert!(serde_json::from_str::<PhpVersion>("\"9.0\"").is_err());
        assert_eq!(
            serde_json::from_str::<Domain>("\"Example.com\"")
                .unwrap()
                .as_str(),
            "example.com"
        );
    }

    #[test]
    fn app_name_accepts_ordinary_names_and_lowercases() {
        assert_eq!(AppName::parse("Blog").unwrap().as_str(), "blog");
        assert_eq!(AppName::parse(" api-v2 ").unwrap().as_str(), "api-v2");
        assert_eq!(AppName::parse("next_app3").unwrap().as_str(), "next_app3");
    }

    #[test]
    fn app_name_rejects_everything_that_would_escape_a_unit_file_or_a_path() {
        // Each of these is a live hazard somewhere the name is used: the first
        // group would write directives into the generated unit, the second
        // would leave `<home>/apps/`, `%h` is a systemd specifier that expands,
        // and a leading `-` reads as an option in argv.
        for bad in [
            "",
            "a b",
            "app\nExecStart=/bin/sh",
            "app\rReboot",
            "app\0",
            "app;reboot",
            "app$(id)",
            "app\"quoted\"",
            "../../etc/systemd/system/evil",
            "apps/blog",
            "a%hb",
            "-flag",
            "_leading",
            "app.service",
            "app@1",
            &"a".repeat(33),
        ] {
            assert!(
                AppName::parse(bad).is_err(),
                "expected `{bad}` to be rejected"
            );
        }
    }

    #[test]
    fn app_names_compose_into_valid_unit_names_and_paths() {
        // The reason the alphabet is what it is: every accepted name has to
        // survive being pasted into a unit file name and a path without
        // quoting or escaping.
        for name in ["a", "blog", "api-v2", "next_app3", &"z".repeat(32)] {
            let app = AppName::parse(name).unwrap();
            let unit = format!("ferrum-app-ft_abc12345-{app}.service");
            assert!(
                unit.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.')),
                "`{unit}` contains something systemd would have to quote"
            );
            assert!(!app.as_str().contains('/'));
        }
    }

    #[test]
    fn port_rules() {
        assert!(Port::parse(0).is_err());
        assert!(Port::parse(80).is_ok());
        assert!(Port::parse_app_port(80).is_err());
        assert!(Port::parse_app_port(3000).is_ok());
        assert!(Port::parse_app_port(65000).is_err());
    }
}
