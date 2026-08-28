//! Reading an aaPanel installation (spec §11.15).
//!
//! aaPanel keeps its inventory in a SQLite database at
//! `<root>/server/panel/data/default.db` and its files under `<root>/wwwroot`,
//! with one nginx vhost per site in `<root>/server/panel/vhost/nginx`. `<root>`
//! is `/www` on every stock install; it is an input so the same importer works
//! against a copy of another server's `/www` rsynced onto this one.
//!
//! Three decisions worth stating:
//!
//! 1. **The database is opened read-only and immutable.** It belongs to a panel
//!    that may still be running. `immutable=1` also stops SQLite from trying to
//!    recover a hot journal, which is a *write* — and writing into the
//!    inventory of the panel we are migrating away from would be a spectacular
//!    way to lose somebody's data.
//! 2. **The `databases.password` column is never selected.** aaPanel stores
//!    database passwords in the clear. Reading them would be easy, would make
//!    the import smoother, and is exactly the thing this panel must not do
//!    (spec §12 rule 6): every imported database gets a *new* user with a new
//!    password, and the plan says so.
//! 3. **This is a same-server takeover, and the plan says that out loud.**
//!    aaPanel is still installed, still owns nginx, and still serves these
//!    domains. Ferrum's vhosts cannot take over a hostname while another
//!    nginx configuration claims it, and the imported databases must be named
//!    differently from the originals because the originals are right there in
//!    the same MariaDB. Both facts are notes on every aaPanel plan.

use std::path::{Path, PathBuf};

use ferrum_core::{Domain, ErrorCode, FerrumError, PhpVersion, Result};
use sqlx::sqlite::SqliteConnectOptions;
use sqlx::{Connection, Row, SqliteConnection};

use super::model::{
    DomainRole, DumpSource, FileSource, ImportPlan, ImportSource, PlannedDatabase, PlannedSite,
    UnmappedKind, map_db_name, unique_db_name,
};

/// The most of a vhost file we will read looking for a PHP version. A vhost is
/// a couple of kilobytes; anything past this is not one.
const MAX_VHOST_BYTES: u64 = 256 * 1024;

/// How deep the file walk goes when sizing a site's document root. aaPanel
/// sites are ordinary web trees; this exists so a pathological symlink-free
/// but absurdly deep tree cannot make the plan take forever.
const MAX_DEPTH: usize = 32;

/// Where things live under the aaPanel root.
pub struct Layout {
    pub root: PathBuf,
}

impl Layout {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn database(&self) -> PathBuf {
        self.root.join("server/panel/data/default.db")
    }

    pub fn wwwroot(&self) -> PathBuf {
        self.root.join("wwwroot")
    }

    pub fn nginx_vhost(&self, site: &str) -> PathBuf {
        self.root
            .join("server/panel/vhost/nginx")
            .join(format!("{site}.conf"))
    }
}

/// Produce the dry run for an aaPanel installation.
pub async fn plan(
    root: &Path,
    subscription_id: i64,
    default_php: Option<PhpVersion>,
    fingerprint: String,
) -> Result<ImportPlan> {
    let layout = Layout::new(root);
    let mut plan = ImportPlan::empty(
        ImportSource::Aapanel,
        root.display().to_string(),
        subscription_id,
    );
    plan.fingerprint = fingerprint;

    let mut conn = open_read_only(&layout.database()).await?;

    let sites = read_sites(&mut conn).await?;
    let domains = read_domains(&mut conn, &mut plan).await;

    for site in &sites {
        map_site(&mut plan, &layout, site, &domains, default_php);
    }

    map_databases(&mut plan, &mut conn).await;
    report_unmappables(&mut plan, &mut conn).await;

    plan.note(
        "aaPanel is still installed on this server and still owns its own nginx configuration. \
         Ferrum's vhosts cannot serve these domains until aaPanel's are removed or its nginx is \
         stopped — plan the cutover, then apply.",
    );
    plan.note(
        "imported databases are copies with new names and new users, because the originals are \
         in this same MariaDB. Each application's configuration (wp-config.php, .env) must be \
         repointed at the new name, user and password, or it will keep using the aaPanel copy.",
    );

    plan.finish();
    Ok(plan)
}

/// Open somebody else's panel database without touching it.
async fn open_read_only(path: &Path) -> Result<SqliteConnection> {
    if !path.is_file() {
        return Err(FerrumError::new(
            ErrorCode::NotFound,
            format!(
                "{} is not there; point `root` at an aaPanel installation (usually /www)",
                path.display()
            ),
        ));
    }
    // `read_only` is the permission and `immutable` is the promise: no locking,
    // no hot-journal recovery, no write of any kind — not even the ones SQLite
    // would consider maintenance.
    let options = SqliteConnectOptions::new()
        .filename(path)
        .read_only(true)
        .immutable(true)
        .create_if_missing(false);

    SqliteConnection::connect_with(&options).await.map_err(|e| {
        FerrumError::new(
            ErrorCode::InvalidInput,
            format!(
                "cannot read the aaPanel database at {}: {e}",
                path.display()
            ),
        )
    })
}

/// A stable identity for the part of aaPanel's inventory an import depends on.
///
/// Deliberately **not** a hash of `default.db`: aaPanel is still running and
/// rewrites that file constantly, so a byte hash would make every plan stale
/// within minutes for reasons unrelated to the import. What must not change
/// between plan and apply is the set of sites (name and document root) and
/// databases the mapping was derived from, so that is what is hashed — in a
/// canonical, ordered form, with separators that cannot appear in the values
/// being joined.
pub async fn inventory_fingerprint(root: &Path) -> Result<String> {
    use sha2::{Digest, Sha256};

    let layout = Layout::new(root);
    let mut conn = open_read_only(&layout.database()).await?;
    let sites = read_sites(&mut conn).await?;

    let mut hasher = Sha256::new();
    hasher.update(b"ferrum-aapanel-inventory-v1");
    for site in &sites {
        hasher.update(b"\nsite\x00");
        hasher.update(site.name.as_bytes());
        hasher.update(b"\x00");
        hasher.update(site.path.as_bytes());
    }
    // A missing `databases` table is a state the plan already reports; it
    // hashes as "no databases", which is exactly what the plan said.
    if let Ok(rows) = sqlx::query("SELECT name FROM databases ORDER BY id")
        .fetch_all(&mut conn)
        .await
    {
        for row in rows {
            if let Ok(name) = row.try_get::<String, _>("name") {
                hasher.update(b"\ndb\x00");
                hasher.update(name.as_bytes());
            }
        }
    }
    let _ = conn.close().await;
    Ok(hex::encode(hasher.finalize()))
}

struct SourceSite {
    id: i64,
    name: String,
    path: String,
}

/// aaPanel's `sites` table. Only three columns are selected: the ones whose
/// types have been stable across aaPanel's schema changes. Everything else the
/// importer needs comes from the vhost file or the filesystem, both of which
/// are self-describing.
async fn read_sites(conn: &mut SqliteConnection) -> Result<Vec<SourceSite>> {
    let rows = sqlx::query("SELECT id, name, path FROM sites ORDER BY id")
        .fetch_all(&mut *conn)
        .await
        .map_err(|e| {
            FerrumError::new(
                ErrorCode::InvalidInput,
                format!("the aaPanel database has no readable `sites` table: {e}"),
            )
        })?;

    Ok(rows
        .into_iter()
        .filter_map(|row| {
            Some(SourceSite {
                id: row.try_get::<i64, _>("id").ok()?,
                name: row.try_get::<String, _>("name").ok()?,
                path: row.try_get::<String, _>("path").ok()?,
            })
        })
        .collect())
}

/// `domain` rows, as `(site id, hostname)`. A missing table is a note, not a
/// failure: a site's own name is a domain, so the import still works without
/// the alias list.
async fn read_domains(conn: &mut SqliteConnection, plan: &mut ImportPlan) -> Vec<(i64, String)> {
    match sqlx::query("SELECT pid, name FROM domain ORDER BY id")
        .fetch_all(&mut *conn)
        .await
    {
        Ok(rows) => rows
            .into_iter()
            .filter_map(|row| {
                Some((
                    row.try_get::<i64, _>("pid").ok()?,
                    row.try_get::<String, _>("name").ok()?,
                ))
            })
            .collect(),
        Err(e) => {
            plan.note(format!(
                "the aaPanel database has no readable `domain` table ({e}); each site is \
                 imported with its own name only, and any additional hostnames must be added by \
                 hand"
            ));
            Vec::new()
        }
    }
}

fn map_site(
    plan: &mut ImportPlan,
    layout: &Layout,
    site: &SourceSite,
    domains: &[(i64, String)],
    default_php: Option<PhpVersion>,
) {
    let Ok(primary) = Domain::parse(&site.name) else {
        plan.unmapped(
            UnmappedKind::Site,
            site.name.clone(),
            "aaPanel's site name is not a domain Ferrum will serve (an IP-only or wildcard site)",
        );
        return;
    };

    let docroot = PathBuf::from(&site.path);
    // The document root has to be inside the tree we were pointed at. A site
    // whose files live somewhere else entirely is a deliberate operator
    // decision that this importer will not silently follow out of the sandbox.
    if !docroot.starts_with(layout.wwwroot()) {
        plan.unmapped(
            UnmappedKind::Site,
            site.name.clone(),
            format!(
                "its document root ({}) is outside {}",
                docroot.display(),
                layout.wwwroot().display()
            ),
        );
        return;
    }
    if !docroot.is_dir() {
        plan.unmapped(
            UnmappedKind::Site,
            site.name.clone(),
            format!("its document root ({}) does not exist", docroot.display()),
        );
        return;
    }

    let (file_count, bytes, links) = measure(&docroot);
    if links > 0 {
        plan.note(format!(
            "{}: {links} symlink(s) under the document root will not be copied",
            site.name
        ));
    }

    let detected = detect_php(&layout.nginx_vhost(&site.name));
    let target_php = detected.or(default_php);

    let aliases: Vec<String> = domains
        .iter()
        .filter(|(pid, name)| *pid == site.id && name != &site.name)
        .filter_map(|(_, name)| Domain::parse(name).ok())
        .map(|d| d.as_str().to_string())
        .collect();

    plan.sites.push(PlannedSite {
        domain: primary.as_str().to_string(),
        role: DomainRole::Main,
        aliases,
        source_docroot: site.path.clone(),
        files: FileSource::Directory {
            path: docroot.display().to_string(),
        },
        detected_php: detected.map(|p| p.as_str().to_string()),
        target_php: target_php.map(|p| p.as_str().to_string()),
        file_count,
        bytes,
    });
}

/// Count regular files and bytes under a document root, skipping symlinks.
///
/// Symlinks are counted separately and never followed: an aaPanel site with
/// `uploads -> /etc` would otherwise have `/etc` measured into the plan and, at
/// apply time, copied. The archive builder that does the copy skips them for
/// the same reason, so the plan and the copy agree.
fn measure(dir: &Path) -> (u64, u64, u64) {
    fn walk(dir: &Path, depth: usize, out: &mut (u64, u64, u64)) {
        if depth > MAX_DEPTH {
            return;
        }
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let Ok(meta) = entry.path().symlink_metadata() else {
                continue;
            };
            if meta.file_type().is_symlink() {
                out.2 += 1;
            } else if meta.is_dir() {
                walk(&entry.path(), depth + 1, out);
            } else if meta.is_file() {
                out.0 += 1;
                out.1 += meta.len();
            }
        }
    }
    let mut out = (0, 0, 0);
    walk(dir, 0, &mut out);
    out
}

/// Read the PHP version out of an aaPanel nginx vhost.
///
/// aaPanel writes one of two markers: `include enable-php-74.conf;` or a
/// `fastcgi_pass unix:/tmp/php-cgi-74.sock;`. Both carry the compact version
/// right after the last `-`, which is all this needs to find. A vhost we cannot
/// read leaves the version unknown, and the operation's `php_version` input
/// decides instead.
fn detect_php(vhost: &Path) -> Option<PhpVersion> {
    let meta = std::fs::metadata(vhost).ok()?;
    if !meta.is_file() || meta.len() > MAX_VHOST_BYTES {
        return None;
    }
    let text = std::fs::read_to_string(vhost).ok()?;
    for marker in ["enable-php-", "php-cgi-", "php-fpm-"] {
        for (index, _) in text.match_indices(marker) {
            let rest = &text[index + marker.len()..];
            let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
            if let Ok(version) = PhpVersion::parse(&digits) {
                return Some(version);
            }
        }
    }
    None
}

/// aaPanel's `databases` table.
///
/// The `password` column is deliberately absent from the SELECT — see the
/// module docs. `pid` links to the site when aaPanel knows which one owns it;
/// it is not used for the mapping, because a database can legitimately be
/// shared between sites and Ferrum's ownership is the subscription anyway.
async fn map_databases(plan: &mut ImportPlan, conn: &mut SqliteConnection) {
    let rows = match sqlx::query("SELECT name, username FROM databases ORDER BY id")
        .fetch_all(&mut *conn)
        .await
    {
        Ok(rows) => rows,
        Err(e) => {
            plan.note(format!(
                "the aaPanel database has no readable `databases` table ({e}); no databases will \
                 be imported"
            ));
            return;
        }
    };

    let mut taken: Vec<String> = Vec::new();
    for row in rows {
        let Ok(name) = row.try_get::<String, _>("name") else {
            continue;
        };
        let source_user = row.try_get::<String, _>("username").ok();

        // The copy lands in the same MariaDB as the original, so the mapped
        // name is *seeded* with a suffix rather than colliding on the first
        // try. `unique_db_name` then handles a second import of the same
        // account.
        let candidate = format!("{}_imp", map_db_name(&name));
        let target_name = unique_db_name(&candidate, &taken);
        taken.push(target_name.clone());
        let mut user = target_name.clone();
        user.truncate(32);
        let target_user = unique_db_name(&user, &taken);
        taken.push(target_user.clone());

        if let Some(source_user) = source_user {
            plan.unmapped(
                UnmappedKind::Credential,
                format!("aaPanel database user `{source_user}`"),
                "aaPanel stores database passwords in the clear; this importer does not read \
                 them. A new user with a new password is created for the imported copy",
            );
        }

        plan.databases.push(PlannedDatabase {
            source_name: name.clone(),
            target_name,
            target_user,
            engine: "mysql".into(),
            payload: DumpSource::LocalMysql { name },
            // Unknown until the dump runs: the size on disk is MariaDB's
            // business, and guessing it from `information_schema` would be a
            // number that does not match what actually gets copied.
            bytes: 0,
        });
    }
}

async fn report_unmappables(plan: &mut ImportPlan, conn: &mut SqliteConnection) {
    // FTP accounts: aaPanel manages its own; Ferrum's SFTP is per-subscription
    // and chrooted (spec §11.6), so there is nothing to map an aaPanel FTP user
    // onto.
    if let Ok(rows) = sqlx::query("SELECT name FROM ftps")
        .fetch_all(&mut *conn)
        .await
    {
        for row in rows {
            if let Ok(name) = row.try_get::<String, _>("name") {
                plan.unmapped(
                    UnmappedKind::Ftp,
                    name,
                    "Ferrum has no per-site FTP accounts; the tenant gets one chrooted SFTP \
                     login for the whole subscription (`sftp.enable`)",
                );
            }
        }
    }

    if let Ok(rows) = sqlx::query("SELECT name FROM crontab")
        .fetch_all(&mut *conn)
        .await
    {
        for row in rows {
            if let Ok(name) = row.try_get::<String, _>("name") {
                plan.unmapped(
                    UnmappedKind::Cron,
                    name,
                    "aaPanel cron entries are shell scripts it generates and stores itself; \
                     recreate the job with `cron.set` after reading what it does",
                );
            }
        }
    }

    // aaPanel issues and stores its own certificates under
    // `/www/server/panel/vhost/cert`. Ferrum issues its own.
    plan.unmapped(
        UnmappedKind::Certificate,
        "aaPanel-issued certificates",
        "certificates are not imported; Ferrum issues its own from Let's Encrypt once each \
         domain resolves here",
    );
    plan.unmapped(
        UnmappedKind::PanelState,
        "aaPanel users, settings, plugins and logs",
        "the panel's own state has no equivalent here and is not imported",
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::Executor;

    /// Build a miniature aaPanel installation: the SQLite inventory, the
    /// wwwroot tree and one nginx vhost.
    async fn fixture(root: &Path) {
        std::fs::create_dir_all(root.join("server/panel/data")).unwrap();
        std::fs::create_dir_all(root.join("server/panel/vhost/nginx")).unwrap();
        std::fs::create_dir_all(root.join("wwwroot/example.com/wp-content")).unwrap();
        std::fs::write(root.join("wwwroot/example.com/index.php"), b"<?php echo 1;").unwrap();
        std::fs::write(root.join("wwwroot/example.com/wp-content/a.css"), b"body{}").unwrap();
        std::fs::write(
            root.join("server/panel/vhost/nginx/example.com.conf"),
            b"server {\n  listen 80;\n  server_name example.com www.example.com;\n  \
              root /www/wwwroot/example.com;\n  include enable-php-74.conf;\n}\n",
        )
        .unwrap();

        let db = root.join("server/panel/data/default.db");
        let options = SqliteConnectOptions::new()
            .filename(&db)
            .create_if_missing(true);
        let mut conn = SqliteConnection::connect_with(&options).await.unwrap();
        conn.execute(
            "CREATE TABLE sites (id INTEGER PRIMARY KEY, name TEXT, path TEXT, status TEXT);
             CREATE TABLE domain (id INTEGER PRIMARY KEY, pid INTEGER, name TEXT, port INTEGER);
             CREATE TABLE databases (id INTEGER PRIMARY KEY, pid INTEGER, name TEXT,
                                     username TEXT, password TEXT, ps TEXT);
             CREATE TABLE ftps (id INTEGER PRIMARY KEY, pid INTEGER, name TEXT, password TEXT);
             CREATE TABLE crontab (id INTEGER PRIMARY KEY, name TEXT, type TEXT);
             INSERT INTO sites VALUES (1, 'example.com', '/www/wwwroot/example.com', '1');
             INSERT INTO sites VALUES (2, 'gone.example.net', '/www/wwwroot/gone', '1');
             INSERT INTO sites VALUES (3, 'outside.example.org', '/opt/elsewhere', '1');
             INSERT INTO domain VALUES (1, 1, 'example.com', 80);
             INSERT INTO domain VALUES (2, 1, 'www.example.com', 80);
             INSERT INTO databases VALUES (1, 1, 'wp_main', 'wp_main', 'PlainTextSecret1', '');
             INSERT INTO ftps VALUES (1, 1, 'example_ftp', 'PlainTextSecret2');
             INSERT INTO crontab VALUES (1, 'nightly backup', 'toFile');",
        )
        .await
        .unwrap();
        conn.close().await.unwrap();
    }

    /// The fixture's paths are `/www/...`; rewrite them to the temp root so the
    /// "inside wwwroot" check sees the same tree the test built.
    async fn planned(root: &Path) -> ImportPlan {
        fixture(root).await;
        // Rewrite the two absolute paths the fixture stored.
        let db = root.join("server/panel/data/default.db");
        let mut conn = SqliteConnection::connect(&format!("sqlite://{}", db.display()))
            .await
            .unwrap();
        sqlx::query("UPDATE sites SET path = ?1 WHERE id = 1")
            .bind(root.join("wwwroot/example.com").display().to_string())
            .execute(&mut conn)
            .await
            .unwrap();
        sqlx::query("UPDATE sites SET path = ?1 WHERE id = 2")
            .bind(root.join("wwwroot/gone").display().to_string())
            .execute(&mut conn)
            .await
            .unwrap();
        conn.close().await.unwrap();

        plan(root, 3, Some(PhpVersion::V83), "fp".into())
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn a_site_maps_with_its_aliases_its_php_version_and_its_real_size() {
        let dir = tempfile::tempdir().unwrap();
        let plan = planned(dir.path()).await;

        assert_eq!(plan.sites.len(), 1, "{:#?}", plan.unmapped);
        let site = &plan.sites[0];
        assert_eq!(site.domain, "example.com");
        assert_eq!(site.aliases, vec!["www.example.com".to_string()]);
        assert_eq!(site.detected_php.as_deref(), Some("7.4"));
        assert_eq!(site.file_count, 2);
        assert_eq!(site.bytes, 13 + 6);
        assert!(matches!(site.files, FileSource::Directory { .. }));
    }

    #[tokio::test]
    async fn a_missing_or_out_of_tree_document_root_is_unmapped_not_invented() {
        let dir = tempfile::tempdir().unwrap();
        let plan = planned(dir.path()).await;
        let unmapped_sites: Vec<&str> = plan
            .unmapped
            .iter()
            .filter(|u| u.kind == UnmappedKind::Site)
            .map(|u| u.item.as_str())
            .collect();
        assert!(
            unmapped_sites.contains(&"gone.example.net"),
            "{unmapped_sites:?}"
        );
        assert!(
            unmapped_sites.contains(&"outside.example.org"),
            "{unmapped_sites:?}"
        );
    }

    #[tokio::test]
    async fn the_plan_never_contains_an_aapanel_password() {
        // aaPanel keeps database and FTP passwords in plain text in this very
        // table. The importer must not read them, and the stored plan is the
        // proof.
        let dir = tempfile::tempdir().unwrap();
        let plan = planned(dir.path()).await;
        let json = serde_json::to_string(&plan).unwrap();
        assert!(!json.contains("PlainTextSecret1"), "{json}");
        assert!(!json.contains("PlainTextSecret2"), "{json}");
    }

    #[tokio::test]
    async fn the_imported_database_is_renamed_because_the_original_is_on_this_server() {
        let dir = tempfile::tempdir().unwrap();
        let plan = planned(dir.path()).await;
        assert_eq!(plan.databases.len(), 1);
        let db = &plan.databases[0];
        assert_eq!(db.source_name, "wp_main");
        assert_ne!(
            db.target_name, db.source_name,
            "a same-server copy cannot reuse the name"
        );
        assert_eq!(
            db.payload,
            DumpSource::LocalMysql {
                name: "wp_main".into()
            }
        );
    }

    #[tokio::test]
    async fn ftp_accounts_cron_and_certificates_are_reported_as_unmapped() {
        let dir = tempfile::tempdir().unwrap();
        let plan = planned(dir.path()).await;
        let kinds: Vec<UnmappedKind> = plan.unmapped.iter().map(|u| u.kind).collect();
        for expected in [
            UnmappedKind::Ftp,
            UnmappedKind::Cron,
            UnmappedKind::Certificate,
            UnmappedKind::Credential,
            UnmappedKind::PanelState,
        ] {
            assert!(
                kinds.contains(&expected),
                "{expected:?} missing: {:#?}",
                plan.unmapped
            );
        }
    }

    #[tokio::test]
    async fn the_source_database_is_opened_without_being_modified() {
        // The mtime and the byte length must both survive a plan: this database
        // belongs to a panel that may still be running.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let _ = planned(root).await;
        let db = root.join("server/panel/data/default.db");
        let before = std::fs::metadata(&db).unwrap();

        let _ = plan(root, 3, None, "fp".into()).await.unwrap();

        let after = std::fs::metadata(&db).unwrap();
        assert_eq!(before.len(), after.len(), "the file's size changed");
        assert_eq!(
            before.modified().unwrap(),
            after.modified().unwrap(),
            "the aaPanel database was written to"
        );
        // A journal or WAL sidecar appearing is the same failure by another
        // name: it means SQLite opened the database for writing.
        for sidecar in ["default.db-wal", "default.db-journal", "default.db-shm"] {
            assert!(
                !root.join("server/panel/data").join(sidecar).exists(),
                "{sidecar} was created next to the source database"
            );
        }
    }

    #[tokio::test]
    async fn the_inventory_fingerprint_ignores_unrelated_writes_and_notices_a_moved_site() {
        // aaPanel is still running while the operator reviews the plan, and it
        // writes to its own database constantly. A fingerprint that changed on
        // every heartbeat would make every plan un-appliable; one that ignored
        // a moved document root would let apply copy from somewhere the
        // operator never saw.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let _ = planned(root).await;

        let before = inventory_fingerprint(root).await.unwrap();

        let db = root.join("server/panel/data/default.db");
        let mut conn = SqliteConnection::connect(&format!("sqlite://{}", db.display()))
            .await
            .unwrap();
        conn.execute("CREATE TABLE logs (id INTEGER PRIMARY KEY, line TEXT);")
            .await
            .unwrap();
        conn.execute("INSERT INTO logs (line) VALUES ('a heartbeat');")
            .await
            .unwrap();
        conn.close().await.unwrap();

        assert_eq!(
            inventory_fingerprint(root).await.unwrap(),
            before,
            "an unrelated write must not invalidate a plan"
        );

        let mut conn = SqliteConnection::connect(&format!("sqlite://{}", db.display()))
            .await
            .unwrap();
        sqlx::query("UPDATE sites SET path = '/www/wwwroot/moved' WHERE id = 1")
            .execute(&mut conn)
            .await
            .unwrap();
        conn.close().await.unwrap();

        assert_ne!(
            inventory_fingerprint(root).await.unwrap(),
            before,
            "a moved document root must invalidate the plan that described the old one"
        );
    }

    #[test]
    fn php_versions_are_read_from_both_vhost_markers() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a.conf");
        std::fs::write(&a, "include enable-php-82.conf;").unwrap();
        assert_eq!(detect_php(&a), Some(PhpVersion::V82));

        let b = dir.path().join("b.conf");
        std::fs::write(&b, "fastcgi_pass unix:/tmp/php-cgi-74.sock;").unwrap();
        assert_eq!(detect_php(&b), Some(PhpVersion::V74));

        let c = dir.path().join("c.conf");
        std::fs::write(&c, "# a static site\n").unwrap();
        assert_eq!(detect_php(&c), None);
    }
}
