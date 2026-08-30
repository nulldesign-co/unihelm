//! The plan document: what an import *would* do (spec §11.15).
//!
//! Everything here is `Serialize + Deserialize` because the plan is stored as
//! JSON (`import_plans.plan_json`) and read back by `import.apply`. That round
//! trip is the module's whole contract: the operator approves this document,
//! and the applier executes this document — not the source it came from.
//!
//! The design rule that shaped these types: **a plan says what does not map as
//! loudly as what does.** A migration tool that silently drops mail accounts is
//! how somebody loses their email. So [`Unmapped`] is a first-class list with a
//! typed kind and a written reason, every importer is expected to fill it, and
//! the tests assert that the obvious unmappables actually appear in it.

use serde::{Deserialize, Serialize};

pub use unihelm_db::imports::ImportSource;

/// The complete dry run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportPlan {
    pub source: ImportSource,
    /// The tarball or aaPanel root that was read, as an absolute server path.
    pub source_path: String,
    /// SHA-256 identifying the source's contents; `import.apply` recomputes it
    /// and refuses a source that has changed since the plan was made.
    pub fingerprint: String,
    /// The account the source belonged to (`cpuser`, or the aaPanel site
    /// owner). Informational — the import always lands in `subscription_id`.
    pub account: Option<String>,
    /// The Unihelm subscription every mapped object will be created under.
    pub subscription_id: i64,
    pub sites: Vec<PlannedSite>,
    pub databases: Vec<PlannedDatabase>,
    /// Everything the importer recognised and will **not** create. The list is
    /// the point of the dry run.
    pub unmapped: Vec<Unmapped>,
    /// Things the operator should know that are not per-object: version
    /// mismatches, things that will need a manual follow-up.
    pub notes: Vec<String>,
    pub totals: PlanTotals,
}

impl ImportPlan {
    /// A plan with nothing in it but its source identity — importers fill the
    /// rest in.
    pub fn empty(source: ImportSource, source_path: String, subscription_id: i64) -> Self {
        Self {
            source,
            source_path,
            fingerprint: String::new(),
            account: None,
            subscription_id,
            sites: Vec::new(),
            databases: Vec::new(),
            unmapped: Vec::new(),
            notes: Vec::new(),
            totals: PlanTotals::default(),
        }
    }

    pub fn note(&mut self, note: impl Into<String>) {
        self.notes.push(note.into());
    }

    pub fn unmapped(
        &mut self,
        kind: UnmappedKind,
        item: impl Into<String>,
        reason: impl Into<String>,
    ) {
        self.unmapped.push(Unmapped {
            kind,
            item: item.into(),
            reason: reason.into(),
        });
    }

    /// Recompute the summary counters from the lists. Called once, after an
    /// importer has finished filling the plan, so the totals cannot disagree
    /// with the detail the operator is reading.
    pub fn finish(&mut self) {
        self.totals = PlanTotals {
            sites: self.sites.len() as u64,
            databases: self.databases.len() as u64,
            unmapped: self.unmapped.len() as u64,
            files: self.sites.iter().map(|s| s.file_count).sum(),
            file_bytes: self.sites.iter().map(|s| s.bytes).sum(),
            dump_bytes: self.databases.iter().map(|d| d.bytes).sum(),
        };
    }
}

/// The summary line a UI shows above the detail.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct PlanTotals {
    pub sites: u64,
    pub databases: u64,
    pub unmapped: u64,
    pub files: u64,
    pub file_bytes: u64,
    pub dump_bytes: u64,
}

/// What a domain was to the source panel. Kept because it explains the mapping:
/// a cPanel "addon domain" is a directory under the main account's home, and an
/// operator who sees `addon` next to a document root understands why.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DomainRole {
    Main,
    Addon,
    Subdomain,
    /// A parked/aliased domain: it becomes an alias on another site, never a
    /// site of its own.
    Alias,
}

/// One site the import would create.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlannedSite {
    pub domain: String,
    pub role: DomainRole,
    /// Domains that will be added as aliases of this site (cPanel parked
    /// domains, aaPanel extra domains on one site).
    #[serde(default)]
    pub aliases: Vec<String>,
    /// The document root as the *source* names it — a path inside the tarball,
    /// or an absolute directory on this server.
    pub source_docroot: String,
    /// Where the payload comes from and how the applier fetches it.
    pub files: FileSource,
    /// The PHP version the source ran, when it could be read (`ea-php82`,
    /// `enable-php-74.conf`). Informational: it is what `target_php` defaults
    /// to, and the reason a plan can warn that the version is not installed
    /// here.
    pub detected_php: Option<String>,
    /// The PHP version the site will be created with. `None` creates a static
    /// site.
    pub target_php: Option<String>,
    /// How many regular files the payload holds, and how many bytes they
    /// occupy uncompressed. Counted by actually walking the source, so the
    /// operator sees the real size before the copy starts.
    pub file_count: u64,
    pub bytes: u64,
}

/// Where a site's files live in the source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FileSource {
    /// A subtree of the cpmove tarball, named by its entry prefix
    /// (`bob/homedir/public_html`). Never a path on this server.
    TarSubtree { prefix: String },
    /// A directory on this server (`/www/wwwroot/example.com`).
    Directory { path: String },
}

/// One database the import would create, and the data that would go into it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlannedDatabase {
    /// What the source called it (`bob_wp`).
    pub source_name: String,
    /// What Unihelm will call it. Different from `source_name` whenever the
    /// original is not a valid [`unihelm_core::DbName`] or is already taken on
    /// this server — the rename is in the plan precisely so nobody discovers it
    /// afterwards by reading a connection error.
    pub target_name: String,
    /// The database user Unihelm creates and grants on it. A **new** user with a
    /// **new** password: source passwords are never read, never copied, and in
    /// aaPanel's case never even looked at (it stores them in the clear).
    pub target_user: String,
    /// Only `mysql` today; see [`crate::importer`] on why PostgreSQL dumps are
    /// reported as unmapped instead.
    pub engine: String,
    pub payload: DumpSource,
    /// Uncompressed size of the dump, or of the live database.
    pub bytes: u64,
}

/// Where a database's data comes from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DumpSource {
    /// A `.sql` member inside the cpmove tarball.
    TarMember { path: String },
    /// A database that is live in this server's own MariaDB — the aaPanel case,
    /// where the panel being replaced is on the same box. The applier dumps it
    /// and loads the dump into the new database; the original is left alone.
    LocalMysql { name: String },
}

/// Something the importer found and will not create.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Unmapped {
    pub kind: UnmappedKind,
    /// The thing itself: an address, a zone name, a path.
    pub item: String,
    /// Why it does not map, in words an operator can act on.
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnmappedKind {
    /// A mailbox, forwarder, autoresponder or filter.
    Mail,
    /// A DNS zone file.
    DnsZone,
    /// An FTP account.
    Ftp,
    /// A cron entry.
    Cron,
    /// A TLS certificate or key.
    Certificate,
    /// A database (or database user) the import will not create.
    Database,
    /// A domain that will not become a site.
    Site,
    /// Source-panel state with no Unihelm equivalent: bandwidth counters,
    /// per-account panel settings, API tokens, Apache includes.
    PanelState,
    /// A credential of any kind. Always unmapped, always for the same reason.
    Credential,
}

impl UnmappedKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            UnmappedKind::Mail => "mail",
            UnmappedKind::DnsZone => "dns_zone",
            UnmappedKind::Ftp => "ftp",
            UnmappedKind::Cron => "cron",
            UnmappedKind::Certificate => "certificate",
            UnmappedKind::Database => "database",
            UnmappedKind::Site => "site",
            UnmappedKind::PanelState => "panel_state",
            UnmappedKind::Credential => "credential",
        }
    }
}

// ---------------------------------------------------------------------------
// What an apply actually did
// ---------------------------------------------------------------------------

/// The result of executing a plan, stored back on the plan row.
///
/// An import that half-worked is the case an operator most needs to read, so
/// this records every step's verdict rather than only the failure that stopped
/// it. `import.apply` keeps going after a failed *site* (the next site may be
/// fine) and stops only when the failure is about the plan itself.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ApplyOutcome {
    pub steps: Vec<ApplyStep>,
}

impl ApplyOutcome {
    pub fn record(&mut self, step: ApplyStep) {
        self.steps.push(step);
    }

    pub fn failures(&self) -> usize {
        self.steps.iter().filter(|s| !s.ok).count()
    }

    pub fn ok(&self) -> bool {
        self.failures() == 0
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplyStep {
    /// `site`, `files`, `database`, `dump`.
    pub stage: String,
    /// The object: a domain, a database name.
    pub subject: String,
    pub ok: bool,
    /// What happened, or why it did not. Never carries a credential.
    pub detail: String,
    /// The row the step created, when it created one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<i64>,
}

impl ApplyStep {
    pub fn ok(stage: &str, subject: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            stage: stage.into(),
            subject: subject.into(),
            ok: true,
            detail: detail.into(),
            id: None,
        }
    }

    pub fn failed(stage: &str, subject: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            stage: stage.into(),
            subject: subject.into(),
            ok: false,
            detail: detail.into(),
            id: None,
        }
    }

    pub fn with_id(mut self, id: i64) -> Self {
        self.id = Some(id);
        self
    }
}

// ---------------------------------------------------------------------------
// Name mapping
// ---------------------------------------------------------------------------

/// Turn a source database (or user) name into one Unihelm will accept.
///
/// cPanel and aaPanel both allow names Unihelm's [`unihelm_core::DbName`] does
/// not: a leading digit, a hyphen, 64+ characters, `mysql`. Rather than refuse
/// the import, the name is *mapped* — and the mapping goes in the plan, so the
/// operator sees `bob-wp → bob_wp` before anything is created rather than
/// discovering it in a connection error later.
///
/// Deterministic on purpose: planning twice produces the same names, so a plan
/// made yesterday still describes what apply will do today.
pub fn map_db_name(source: &str) -> String {
    let mut out = String::with_capacity(source.len().min(MAX_DB_NAME));
    for ch in source.chars() {
        // Everything outside the allowed alphabet becomes `_`; that collapses
        // `a-b` and `a.b` onto the same name, which is why the caller
        // de-duplicates the result set (see `unique_db_name`).
        if ch.is_ascii_alphanumeric() || ch == '_' {
            out.push(ch);
        } else {
            out.push('_');
        }
        if out.len() >= MAX_DB_NAME {
            break;
        }
    }
    // A name has to start with a letter or `_`; a leading digit gets a prefix
    // rather than losing its first character.
    if out.is_empty() || out.starts_with(|c: char| c.is_ascii_digit()) {
        out.insert_str(0, "imp_");
        out.truncate(MAX_DB_NAME);
    }
    out
}

/// `DbName` allows 63; leave room for the `_2` de-duplication suffix.
const MAX_DB_NAME: usize = 60;

/// Make `candidate` unique against names already chosen, by appending `_2`,
/// `_3`, … — the same shape a person would pick, and short enough to stay
/// inside the length limit.
pub fn unique_db_name(candidate: &str, taken: &[String]) -> String {
    if !taken.iter().any(|t| t.eq_ignore_ascii_case(candidate)) {
        return candidate.to_string();
    }
    for n in 2..=99 {
        let next = format!("{candidate}_{n}");
        if !taken.iter().any(|t| t.eq_ignore_ascii_case(&next)) {
            return next;
        }
    }
    // 98 collisions on one name is not a real import; fail loudly upstream by
    // returning something `DbName::parse` will reject rather than silently
    // reusing a name.
    format!("{candidate}_!")
}

#[cfg(test)]
mod tests {
    use super::*;
    use unihelm_core::DbName;

    #[test]
    fn source_database_names_map_onto_names_unihelm_accepts() {
        for source in [
            "bob_wp",
            "bob-wp",
            "9lives",
            "a.very.dotted.name",
            "UPPER_case",
        ] {
            let mapped = map_db_name(source);
            DbName::parse(&mapped)
                .unwrap_or_else(|e| panic!("{source} mapped to {mapped}, which is invalid: {e}"));
        }
    }

    #[test]
    fn an_over_long_source_name_is_truncated_to_something_valid() {
        let long = "x".repeat(200);
        let mapped = map_db_name(&long);
        assert!(mapped.len() <= 60);
        assert!(DbName::parse(&mapped).is_ok());
    }

    #[test]
    fn two_source_names_that_map_together_do_not_collide() {
        // `a-b` and `a.b` both sanitise to `a_b`; the second must not silently
        // become an alias for the first, or one database's data lands in the
        // other.
        let first = map_db_name("a-b");
        let second = unique_db_name(&map_db_name("a.b"), std::slice::from_ref(&first));
        assert_eq!(first, "a_b");
        assert_eq!(second, "a_b_2");
        assert!(DbName::parse(&second).is_ok());
    }

    #[test]
    fn totals_are_derived_from_the_lists_they_summarise() {
        let mut plan = ImportPlan::empty(ImportSource::Cpanel, "/tmp/x.tar.gz".into(), 1);
        plan.sites.push(PlannedSite {
            domain: "example.com".into(),
            role: DomainRole::Main,
            aliases: vec![],
            source_docroot: "bob/homedir/public_html".into(),
            files: FileSource::TarSubtree {
                prefix: "bob/homedir/public_html".into(),
            },
            detected_php: Some("8.2".into()),
            target_php: Some("8.2".into()),
            file_count: 12,
            bytes: 4096,
        });
        plan.unmapped(UnmappedKind::Mail, "info@example.com", "no MTA in v1");
        plan.finish();

        assert_eq!(plan.totals.sites, 1);
        assert_eq!(plan.totals.files, 12);
        assert_eq!(plan.totals.file_bytes, 4096);
        assert_eq!(plan.totals.unmapped, 1);
    }
}
