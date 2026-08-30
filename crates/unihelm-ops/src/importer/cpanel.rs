//! Reading a cPanel `cpmove` / full-backup tarball (spec §11.15).
//!
//! A cpmove archive is a whole hosting account: the home directory, the
//! account's domains, its MySQL dumps, its mail, its DNS zones, its cron, its
//! certificates and a pile of cPanel bookkeeping. Unihelm can host the first
//! three of those. **The other five are the interesting part of this file**,
//! because a migration tool that quietly drops somebody's mailboxes is how
//! people lose their email — so everything recognised and not imported goes on
//! the plan's `unmapped` list with a reason, and the tests below assert it.
//!
//! What the layout looks like, with `<top>` being the single top-level
//! directory in the archive (the cPanel username, or `cpmove-<user>`):
//!
//! ```text
//! <top>/cp/<user>              account summary, `KEY=value`
//! <top>/userdata/main          main/addon/parked/sub domain lists (YAML)
//! <top>/userdata/<domain>      per-domain: documentroot, phpversion (YAML)
//! <top>/homedir/…              the account's files; public_html is the main root
//! <top>/mysql/<db>.sql         one dump per database
//! <top>/mysql/<db>.create      its CREATE DATABASE (unused: we create our own)
//! <top>/mysql.sql              GRANTs and CREATE USER with password hashes
//! <top>/homedir/etc/<domain>/passwd   mail accounts
//! <top>/dnszones/<domain>.db   zone files
//! <top>/cron/<user>            the account's crontab
//! <top>/sslcerts, sslkeys      certificates and their private keys
//! ```
//!
//! The YAML parser here is deliberately a *subset* — see [`yaml::parse`]. It
//! reads the handful of shapes cPanel actually writes and refuses to guess at
//! anything else, and a domain whose `userdata` file cannot be understood is
//! reported as unmapped rather than imported with a guessed document root.

use std::path::Path;

use unihelm_core::{Domain, ErrorCode, PhpVersion, Result, UnihelmError};

use super::model::{
    DomainRole, DumpSource, FileSource, ImportPlan, ImportSource, PlannedDatabase, PlannedSite,
    UnmappedKind, map_db_name, unique_db_name,
};
use super::scan::{self, TarIndex, Want};
use crate::fsops::archive::Limits;

/// How many individual mail accounts are listed before the plan switches to a
/// count. The list exists to be read.
const MAX_LISTED: usize = 200;

/// Produce the dry run for one cpmove tarball.
///
/// `default_php` is the version imported PHP sites are created with when the
/// archive does not say (or says one this server does not have); it comes from
/// the operation's input, so the operator chooses it *before* seeing the plan
/// and then sees the consequence in the plan.
pub fn plan(
    tarball: &Path,
    subscription_id: i64,
    default_php: Option<PhpVersion>,
    fingerprint: String,
    limits: Limits,
) -> Result<ImportPlan> {
    let index = scan::index(tarball, &want, limits)?;
    let top = single_top_level(&index)?;
    let mut plan = ImportPlan::empty(
        ImportSource::Cpanel,
        tarball.display().to_string(),
        subscription_id,
    );
    plan.fingerprint = fingerprint;

    let account = account_name(&index, &top);
    plan.account = account.clone();

    map_sites(&mut plan, &index, &top, default_php);
    map_databases(&mut plan, &index, &top);
    report_unmappables(&mut plan, &index, &top, account.as_deref());

    if index.truncated {
        plan.note(
            "this archive has more directories than the scanner indexes; the per-site file \
             counts and sizes below are lower bounds",
        );
    }
    if !index.skipped.is_empty() {
        let symlinks = index
            .skipped
            .iter()
            .filter(|(_, why)| why.starts_with("symlink"))
            .count();
        if symlinks > 0 {
            plan.note(format!(
                "{symlinks} symlink(s) in the archive will not be recreated — an imported link \
                 would be a tenant-chosen redirection inside their own home"
            ));
        }
        let others = index.skipped.len() - symlinks;
        if others > 0 {
            plan.note(format!(
                "{others} archive entr(ies) are hardlinks, device nodes or have names that are \
                 not valid UTF-8; none of them will be created"
            ));
        }
    }

    plan.finish();
    Ok(plan)
}

/// Which members the scan should remember or read.
///
/// Everything here is metadata or an unmappable object; the payload
/// (`homedir/…`) is only ever counted.
fn want(name: &str) -> Want {
    let Some((_, rest)) = name.split_once('/') else {
        // A file at the very top of the archive: `mysql.sql` lives one level
        // deeper, so anything here is cPanel bookkeeping.
        return Want::Nothing;
    };

    // Account and domain metadata: parsed.
    if rest == "userdata/main"
        || rest.starts_with("cp/")
        || (rest.starts_with("userdata/")
            && !rest.ends_with("_SSL")
            && !rest.ends_with(".cache")
            && rest.matches('/').count() == 1)
    {
        return Want::Content;
    }
    // The account's crontab and its mail account lists: parsed, but only for
    // the *names* in them — see `report_unmappables`.
    if rest.starts_with("cron/") || (rest.starts_with("homedir/etc/") && rest.ends_with("/passwd"))
    {
        return Want::Content;
    }
    // Objects that will be reported as unmapped, by name only.
    if rest.starts_with("dnszones/")
        || rest.starts_with("sslcerts/")
        || rest.starts_with("sslkeys/")
        || rest.starts_with("apache_tls/")
        || rest.starts_with("psql/")
        || rest.starts_with("mm/")
        || rest.starts_with("va/")
    {
        return Want::Name;
    }
    Want::Nothing
}

/// The archive must have exactly one top-level directory.
///
/// Not fussiness: every path in the plan is derived by joining onto this
/// prefix, and an archive with two roots is either two accounts (which this
/// operation does not claim to handle) or something that is not a cpmove at
/// all. Guessing would put one account's files into another's site.
fn single_top_level(index: &TarIndex) -> Result<String> {
    match index.top_level.as_slice() {
        [only] => Ok(only.clone()),
        [] => Err(UnihelmError::new(
            ErrorCode::InvalidInput,
            "the archive is empty, or holds no regular files",
        )),
        many => Err(UnihelmError::new(
            ErrorCode::InvalidInput,
            format!(
                "a cpmove archive has one top-level directory; this one has {}: {}",
                many.len(),
                many.join(", ")
            ),
        )),
    }
}

/// The cPanel account name, from `cp/<user>`'s own `USER=` line if it is there,
/// otherwise from the archive's top-level directory.
fn account_name(index: &TarIndex, top: &str) -> Option<String> {
    for (path, bytes) in &index.metadata {
        if !path.starts_with(&format!("{top}/cp/")) {
            continue;
        }
        let text = String::from_utf8_lossy(bytes);
        for line in text.lines() {
            if let Some(value) = line.strip_prefix("USER=") {
                let value = value.trim();
                if !value.is_empty() {
                    return Some(value.to_string());
                }
            }
        }
        // `cp/<user>` — the file is named for the account.
        if let Some(name) = path.rsplit('/').next()
            && !name.is_empty()
        {
            return Some(name.to_string());
        }
    }
    Some(top.trim_start_matches("cpmove-").to_string()).filter(|s| !s.is_empty())
}

// ---------------------------------------------------------------------------
// sites
// ---------------------------------------------------------------------------

fn map_sites(plan: &mut ImportPlan, index: &TarIndex, top: &str, default_php: Option<PhpVersion>) {
    let main_key = format!("{top}/userdata/main");
    let Some(main_raw) = index.metadata.get(&main_key) else {
        plan.unmapped(
            UnmappedKind::Site,
            "(every domain)",
            "the archive has no userdata/main, so which domains this account served cannot be \
             read; nothing will be created",
        );
        return;
    };
    let main = yaml::parse(&String::from_utf8_lossy(main_raw));

    let main_domain = main.scalar("main_domain");
    // `addon_domains` maps the real domain to the internal subdomain cPanel
    // parks it on; the internal name must not become a site of its own.
    let addon: Vec<(String, String)> = main.map("addon_domains");
    let internal: Vec<String> = addon.iter().map(|(_, v)| v.clone()).collect();
    let parked = main.seq("parked_domains");
    let subs: Vec<String> = main
        .seq("sub_domains")
        .into_iter()
        .filter(|s| !internal.contains(s))
        .collect();

    let mut planned: Vec<(String, DomainRole)> = Vec::new();
    if let Some(domain) = main_domain.clone() {
        planned.push((domain, DomainRole::Main));
    }
    for (domain, _) in &addon {
        planned.push((domain.clone(), DomainRole::Addon));
    }
    for domain in subs {
        planned.push((domain, DomainRole::Subdomain));
    }

    for (domain, role) in planned {
        let Ok(parsed) = Domain::parse(&domain) else {
            plan.unmapped(
                UnmappedKind::Site,
                domain,
                "not a domain name Unihelm will serve",
            );
            continue;
        };
        let domain = parsed.as_str().to_string();

        let userdata_key = format!("{top}/userdata/{domain}");
        let Some(raw) = index.metadata.get(&userdata_key) else {
            plan.unmapped(
                UnmappedKind::Site,
                domain.clone(),
                format!(
                    "no `userdata/{domain}` in the archive, so its document root is unknown; \
                     create the site by hand and copy its files with the file manager"
                ),
            );
            continue;
        };
        let doc = yaml::parse(&String::from_utf8_lossy(raw));

        let Some(docroot) = doc.scalar("documentroot") else {
            plan.unmapped(
                UnmappedKind::Site,
                domain.clone(),
                "its userdata file has no `documentroot`",
            );
            continue;
        };
        let home = doc.scalar("homedir");
        let Some(relative) = docroot_inside_home(&docroot, home.as_deref()) else {
            plan.unmapped(
                UnmappedKind::Site,
                domain.clone(),
                format!(
                    "its document root ({docroot}) is not inside the account's home directory, \
                     so it is not in this archive"
                ),
            );
            continue;
        };

        let prefix = if relative.is_empty() {
            format!("{top}/homedir")
        } else {
            format!("{top}/homedir/{relative}")
        };
        let (file_count, bytes) = index.subtree(&prefix);
        if file_count == 0 {
            plan.unmapped(
                UnmappedKind::Site,
                domain.clone(),
                format!("its document root ({prefix}) holds no files in this archive"),
            );
            continue;
        }

        let detected = doc.scalar("phpversion");
        let detected_php = detected.as_deref().and_then(parse_ea_php);
        let target_php = detected_php.or(default_php);
        if detected.is_some() && detected_php.is_none() {
            plan.note(format!(
                "{domain}: the archive says PHP `{}`, which Unihelm does not offer; it will be \
                 created with {}",
                detected.unwrap_or_default(),
                target_php.map(|p| p.as_str()).unwrap_or("no PHP")
            ));
        }

        let aliases = if role == DomainRole::Main {
            parked
                .iter()
                .filter_map(|p| Domain::parse(p).ok())
                .map(|d| d.as_str().to_string())
                .collect()
        } else {
            Vec::new()
        };

        plan.sites.push(PlannedSite {
            domain,
            role,
            aliases,
            source_docroot: docroot,
            files: FileSource::TarSubtree {
                prefix: prefix.clone(),
            },
            detected_php: detected_php.map(|p| p.as_str().to_string()),
            target_php: target_php.map(|p| p.as_str().to_string()),
            file_count,
            bytes,
        });
    }

    // cPanel serves through Apache, so `.htaccess` is load-bearing there and
    // inert here. Saying so on the plan is cheaper than the support ticket
    // about a site that "imported fine" and 404s on every deep link.
    if !plan.sites.is_empty() {
        plan.note(
            "`.htaccess` files are copied but nginx does not read them — Apache rewrite rules, \
             auth and redirects have to be re-expressed in the site's nginx snippet",
        );
    }

    // A parked domain with no main site to hang off is not silently dropped.
    if plan.sites.is_empty() {
        for domain in &parked {
            plan.unmapped(
                UnmappedKind::Site,
                domain.clone(),
                "a parked domain becomes an alias of the main site, and no main site mapped",
            );
        }
    }
}

/// Turn `/home/bob/public_html` into `public_html`, given the account's home.
///
/// Refuses anything that is not *inside* the home: a document root pointing at
/// `/var/www` is not in the archive at all, and pretending otherwise would plan
/// a copy of a directory that does not exist.
fn docroot_inside_home(docroot: &str, home: Option<&str>) -> Option<String> {
    let docroot = docroot.trim().trim_end_matches('/');
    let home = home.map(|h| h.trim().trim_end_matches('/').to_string());

    let relative = match home.as_deref() {
        Some(home) if !home.is_empty() => docroot.strip_prefix(home)?,
        // No `homedir` in the userdata file: fall back to the conventional
        // layout, which is the only other thing cPanel writes.
        _ => docroot
            .strip_prefix("/home/")
            .and_then(|rest| rest.split_once('/').map(|(_, tail)| tail))
            .or_else(|| docroot.strip_prefix("/home"))?,
    };
    let relative = relative.trim_start_matches('/');
    if relative.contains("..") {
        return None;
    }
    Some(relative.to_string())
}

/// `ea-php82` / `ea-php74` / `alt-php72` / `8.2` → a [`PhpVersion`], when it is
/// one Unihelm offers.
fn parse_ea_php(raw: &str) -> Option<PhpVersion> {
    let raw = raw.trim();
    let digits: String = raw
        .rsplit(|c: char| !c.is_ascii_digit())
        .next()
        .unwrap_or_default()
        .to_string();
    // `ea-php82` ends in the compact form; a bare `8.2` parses directly.
    PhpVersion::parse(raw)
        .ok()
        .or_else(|| PhpVersion::parse(&digits).ok())
}

// ---------------------------------------------------------------------------
// databases
// ---------------------------------------------------------------------------

fn map_databases(plan: &mut ImportPlan, index: &TarIndex, top: &str) {
    let mysql_prefix = format!("{top}/mysql/");
    let mut taken: Vec<String> = Vec::new();

    for (member, size) in &index.sql_members {
        let Some(file) = member.strip_prefix(&mysql_prefix) else {
            continue;
        };
        // `mysql/<db>.sql` only — a nested path is not something cpmove writes.
        if file.contains('/') {
            continue;
        }
        let Some(source_name) = file.strip_suffix(".sql") else {
            continue;
        };

        let target_name = unique_db_name(&map_db_name(source_name), &taken);
        taken.push(target_name.clone());
        // MariaDB's `user` column is 80 characters in current releases and 32
        // in older ones; staying inside 32 means the same plan applies on both.
        let mut user = target_name.clone();
        user.truncate(32);
        let target_user = unique_db_name(&user, &taken);
        taken.push(target_user.clone());

        if *size > super::MAX_DUMP_BYTES {
            plan.unmapped(
                UnmappedKind::Database,
                source_name,
                format!(
                    "its dump is {size} bytes, past the {} byte limit this importer loads in one \
                     piece; create the database in Unihelm and restore the dump with the MariaDB \
                     client instead",
                    super::MAX_DUMP_BYTES
                ),
            );
            continue;
        }

        plan.databases.push(PlannedDatabase {
            source_name: source_name.to_string(),
            target_name,
            target_user,
            engine: "mysql".into(),
            payload: DumpSource::TarMember {
                path: member.clone(),
            },
            bytes: *size,
        });
    }

    if plan
        .databases
        .iter()
        .any(|d| d.target_name != d.source_name)
    {
        plan.note(
            "some databases are renamed (cPanel names are not always valid here, and a name may \
             already be taken on this server). Application configuration — wp-config.php, .env — \
             must be updated to the new name and the new user.",
        );
    }
}

// ---------------------------------------------------------------------------
// what does not map
// ---------------------------------------------------------------------------

fn report_unmappables(plan: &mut ImportPlan, index: &TarIndex, top: &str, account: Option<&str>) {
    // --- mail ---------------------------------------------------------------
    let mut accounts = Vec::new();
    for (path, bytes) in &index.metadata {
        let Some(rest) = path.strip_prefix(&format!("{top}/homedir/etc/")) else {
            continue;
        };
        let Some(domain) = rest.strip_suffix("/passwd") else {
            continue;
        };
        // Only the login name, which is the field before the first colon. The
        // rest of the line — and `shadow` next to it — carries password
        // material, and this importer never reads a credential (spec §12
        // rule 6).
        for line in String::from_utf8_lossy(bytes).lines() {
            let Some((user, _)) = line.split_once(':') else {
                continue;
            };
            if !user.trim().is_empty() {
                accounts.push(format!("{}@{domain}", user.trim()));
            }
        }
    }
    let mail_files = index.subtree(&format!("{top}/homedir/mail")).0;
    for address in accounts.iter().take(MAX_LISTED) {
        plan.unmapped(
            UnmappedKind::Mail,
            address.clone(),
            "Unihelm v1 has no mail server (spec §11.18 ships relay-only); the mailbox and its \
             password are not imported",
        );
    }
    if accounts.len() > MAX_LISTED {
        plan.unmapped(
            UnmappedKind::Mail,
            format!("and {} more mail accounts", accounts.len() - MAX_LISTED),
            "listed in full in the archive's homedir/etc/<domain>/passwd files",
        );
    }
    if mail_files > 0 {
        plan.unmapped(
            UnmappedKind::Mail,
            format!("{mail_files} files under homedir/mail"),
            "stored mail is not imported. Keep this archive: it is the only copy of those \
             messages Unihelm will ever have",
        );
    }

    // --- DNS, certificates, credentials, cron, panel state -------------------
    for name in &index.names {
        let Some(rest) = name.strip_prefix(&format!("{top}/")) else {
            continue;
        };
        if let Some(zone) = rest.strip_prefix("dnszones/") {
            plan.unmapped(
                UnmappedKind::DnsZone,
                zone.trim_end_matches(".db"),
                "Unihelm is not an authoritative nameserver (spec §11.13 manages Cloudflare \
                 zones); recreate the records at your DNS provider",
            );
        } else if let Some(cert) = rest.strip_prefix("sslcerts/") {
            plan.unmapped(
                UnmappedKind::Certificate,
                cert,
                "certificates are not imported; Unihelm issues its own from Let's Encrypt once \
                 the domain resolves here",
            );
        } else if rest.starts_with("sslkeys/") || rest.starts_with("apache_tls/") {
            plan.unmapped(
                UnmappedKind::Credential,
                rest,
                "private key material is never read or copied by an import",
            );
        } else if let Some(db) = rest.strip_prefix("psql/") {
            plan.unmapped(
                UnmappedKind::Database,
                db,
                "PostgreSQL dumps are not loaded by this build; create the database with \
                 `db.create` and restore the dump with psql",
            );
        } else if rest.starts_with("mm/") {
            plan.unmapped(
                UnmappedKind::Mail,
                rest,
                "Mailman lists have no equivalent in Unihelm",
            );
        } else if rest.starts_with("va/") {
            plan.unmapped(
                UnmappedKind::Mail,
                rest,
                "vacation/autoresponder settings have no equivalent in Unihelm",
            );
        }
    }
    if index.names_truncated {
        plan.note(
            "the archive holds more unmappable objects than this plan lists; the list above is a \
             sample",
        );
    }

    // --- cron ---------------------------------------------------------------
    for (path, bytes) in &index.metadata {
        let Some(_) = path.strip_prefix(&format!("{top}/cron/")) else {
            continue;
        };
        let entries = String::from_utf8_lossy(bytes)
            .lines()
            .filter(|l| {
                let l = l.trim();
                !l.is_empty() && !l.starts_with('#')
            })
            .count();
        if entries > 0 {
            plan.unmapped(
                UnmappedKind::Cron,
                format!("{entries} cron entr(ies)"),
                "cron commands are shell command lines written for another server's paths; \
                 recreate them with `cron.set` after checking each one",
            );
        }
    }

    // --- credentials, always ------------------------------------------------
    if let Some(account) = account {
        plan.unmapped(
            UnmappedKind::Credential,
            format!("{account} (cPanel login, FTP and database passwords)"),
            "no password or password hash is imported. Unihelm creates a new database user with a \
             new password for each imported database, and the tenant's own login is created by \
             the operator",
        );
    }
    if index.has_subtree(&format!("{top}/bandwidth"))
        || index.has_subtree(&format!("{top}/counters"))
        || index.has_subtree(&format!("{top}/logs"))
    {
        plan.unmapped(
            UnmappedKind::PanelState,
            "bandwidth counters, statistics and access logs",
            "historical panel state has no equivalent here and is not imported",
        );
    }
}

// ---------------------------------------------------------------------------
// The YAML subset cPanel actually writes
// ---------------------------------------------------------------------------

pub mod yaml {
    //! A deliberately small YAML reader.
    //!
    //! cPanel's `userdata` files are machine-written and use four shapes:
    //! `key: value`, `key:` followed by indented `- item` lines, `key:`
    //! followed by indented `key: value` lines, and the inline empties `{}` and
    //! `[]`. This parser reads exactly those.
    //!
    //! It is a subset on purpose rather than a dependency on purpose. A general
    //! YAML parser is a large attack surface (anchors, aliases, merge keys,
    //! billion-laughs) pointed at a file that came from somebody else's server,
    //! and the panel would gain nothing from the other 90% of the grammar. What
    //! this parser does not understand it *drops*, and a domain whose document
    //! root is therefore missing is reported as unmapped — never guessed.

    use std::collections::BTreeMap;

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum Node {
        Scalar(String),
        Seq(Vec<String>),
        Map(Vec<(String, String)>),
    }

    #[derive(Debug, Default, Clone)]
    pub struct Doc(pub BTreeMap<String, Node>);

    impl Doc {
        pub fn scalar(&self, key: &str) -> Option<String> {
            match self.0.get(key) {
                Some(Node::Scalar(s)) if !s.is_empty() => Some(s.clone()),
                _ => None,
            }
        }

        pub fn seq(&self, key: &str) -> Vec<String> {
            match self.0.get(key) {
                Some(Node::Seq(items)) => items.clone(),
                // A single-item sequence written inline is common enough in
                // hand-edited files to be worth accepting.
                Some(Node::Scalar(s)) if !s.is_empty() => vec![s.clone()],
                _ => Vec::new(),
            }
        }

        pub fn map(&self, key: &str) -> Vec<(String, String)> {
            match self.0.get(key) {
                Some(Node::Map(pairs)) => pairs.clone(),
                _ => Vec::new(),
            }
        }
    }

    /// Strip surrounding quotes and trailing comments from a scalar.
    fn scalar(raw: &str) -> String {
        let raw = raw.trim();
        let unquoted = if (raw.starts_with('\'') && raw.ends_with('\'') && raw.len() >= 2)
            || (raw.starts_with('"') && raw.ends_with('"') && raw.len() >= 2)
        {
            &raw[1..raw.len() - 1]
        } else {
            raw
        };
        unquoted.trim().to_string()
    }

    pub fn parse(text: &str) -> Doc {
        let mut out: BTreeMap<String, Node> = BTreeMap::new();
        let mut current: Option<String> = None;

        for line in text.lines() {
            let trimmed = line.trim_end();
            if trimmed.trim().is_empty()
                || trimmed.trim_start().starts_with('#')
                || trimmed.trim() == "---"
            {
                continue;
            }
            let indent = trimmed.len() - trimmed.trim_start().len();
            let body = trimmed.trim_start();

            if indent == 0 {
                current = None;
                let Some((key, value)) = body.split_once(':') else {
                    continue;
                };
                let key = key.trim().to_string();
                let value = scalar(value);
                match value.as_str() {
                    "" => {
                        // A block follows; its first indented line decides
                        // whether it is a sequence or a map.
                        current = Some(key.clone());
                        out.insert(key, Node::Scalar(String::new()));
                    }
                    "[]" => {
                        out.insert(key, Node::Seq(Vec::new()));
                    }
                    "{}" => {
                        out.insert(key, Node::Map(Vec::new()));
                    }
                    _ => {
                        out.insert(key, Node::Scalar(value));
                    }
                }
                continue;
            }

            let Some(key) = current.clone() else { continue };
            if let Some(item) = body.strip_prefix("- ") {
                let item = scalar(item);
                match out.get_mut(&key) {
                    Some(Node::Seq(items)) => items.push(item),
                    _ => {
                        out.insert(key, Node::Seq(vec![item]));
                    }
                }
            } else if let Some((k, v)) = body.split_once(':') {
                let pair = (k.trim().to_string(), scalar(v));
                match out.get_mut(&key) {
                    Some(Node::Map(pairs)) => pairs.push(pair),
                    _ => {
                        out.insert(key, Node::Map(vec![pair]));
                    }
                }
            }
        }

        Doc(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::importer::scan::tests::tar_gz;

    fn fixture(dir: &Path) -> std::path::PathBuf {
        let path = dir.join("cpmove-bob.tar.gz");
        tar_gz(
            &path,
            &[
                (
                    "bob/cp/bob",
                    0o600,
                    b"USER=bob\nDNS=example.com\nPLAN=default\nMAXPOP=unlimited\n",
                ),
                (
                    "bob/userdata/main",
                    0o644,
                    b"main_domain: example.com\naddon_domains:\n  addon.com: addon.example.com\n\
                      parked_domains:\n  - parked.com\nsub_domains:\n  - shop.example.com\n  \
                      - addon.example.com\n",
                ),
                (
                    "bob/userdata/example.com",
                    0o644,
                    b"documentroot: /home/bob/public_html\nhomedir: /home/bob\n\
                      phpversion: ea-php82\nservername: example.com\n",
                ),
                (
                    "bob/userdata/addon.com",
                    0o644,
                    b"documentroot: /home/bob/addon\nhomedir: /home/bob\nphpversion: ea-php74\n",
                ),
                (
                    "bob/userdata/shop.example.com",
                    0o644,
                    b"documentroot: /home/bob/shop\nhomedir: /home/bob\nphpversion: ea-php82\n",
                ),
                ("bob/homedir/public_html/index.php", 0o644, b"<?php echo 1;"),
                ("bob/homedir/public_html/.htaccess", 0o644, b"RewriteEngine On"),
                ("bob/homedir/addon/index.html", 0o644, b"<h1>addon</h1>"),
                ("bob/homedir/shop/index.php", 0o644, b"<?php"),
                ("bob/homedir/mail/example.com/info/cur/1.eml", 0o600, b"mail"),
                (
                    "bob/homedir/etc/example.com/passwd",
                    0o640,
                    b"info:x:1001:1001::/home/bob/mail/example.com/info:/usr/sbin/nologin\n\
                      sales:x:1002:1002::/home/bob/mail/example.com/sales:/usr/sbin/nologin\n",
                ),
                (
                    "bob/homedir/etc/example.com/shadow",
                    0o600,
                    b"info:$6$averyrealhash:19000::::::\n",
                ),
                ("bob/mysql/bob_wp.sql", 0o644, b"CREATE TABLE wp_posts (id INT);"),
                ("bob/mysql/bob_wp.create", 0o644, b"CREATE DATABASE `bob_wp`;"),
                (
                    "bob/mysql.sql",
                    0o644,
                    b"GRANT ALL ON `bob_wp`.* TO 'bob_wp'@'localhost' IDENTIFIED BY PASSWORD '*ABC';",
                ),
                ("bob/dnszones/example.com.db", 0o644, b"$TTL 14400"),
                ("bob/cron/bob", 0o600, b"# cron\n0 3 * * * /home/bob/backup.sh\n"),
                ("bob/sslcerts/example.com.crt", 0o644, b"-----BEGIN CERTIFICATE-----"),
                ("bob/sslkeys/example.com.key", 0o600, b"-----BEGIN PRIVATE KEY-----"),
                ("bob/bandwidth/example.com.rrd", 0o644, b"rrd"),
            ],
        );
        path
    }

    fn planned() -> ImportPlan {
        let dir = tempfile::tempdir().unwrap();
        let path = fixture(dir.path());
        plan(
            &path,
            7,
            Some(PhpVersion::V83),
            "fp".into(),
            Limits::default(),
        )
        .unwrap()
    }

    #[test]
    fn the_main_addon_and_subdomain_all_become_sites_with_their_own_roots() {
        let plan = planned();
        let domains: Vec<&str> = plan.sites.iter().map(|s| s.domain.as_str()).collect();
        assert_eq!(
            domains,
            vec!["example.com", "addon.com", "shop.example.com"]
        );

        let main = &plan.sites[0];
        assert_eq!(main.role, DomainRole::Main);
        assert_eq!(
            main.files,
            FileSource::TarSubtree {
                prefix: "bob/homedir/public_html".into()
            }
        );
        assert_eq!(main.file_count, 2, "index.php and .htaccess");
        assert_eq!(main.detected_php.as_deref(), Some("8.2"));
        assert_eq!(main.aliases, vec!["parked.com".to_string()]);
    }

    #[test]
    fn an_addons_internal_subdomain_does_not_become_a_second_site() {
        // cPanel parks `addon.com` on `addon.example.com`. Importing both would
        // create two sites serving one directory, and the second would fight
        // the first for the vhost.
        let plan = planned();
        assert!(
            !plan.sites.iter().any(|s| s.domain == "addon.example.com"),
            "the internal addon subdomain must not become a site of its own"
        );
    }

    #[test]
    fn mail_dns_certificates_cron_and_credentials_are_all_reported_as_unmapped() {
        let plan = planned();
        let kinds: Vec<UnmappedKind> = plan.unmapped.iter().map(|u| u.kind).collect();
        for expected in [
            UnmappedKind::Mail,
            UnmappedKind::DnsZone,
            UnmappedKind::Certificate,
            UnmappedKind::Cron,
            UnmappedKind::Credential,
            UnmappedKind::PanelState,
        ] {
            assert!(
                kinds.contains(&expected),
                "{expected:?} must appear in the unmapped list: {:#?}",
                plan.unmapped
            );
        }
        assert!(
            plan.unmapped
                .iter()
                .any(|u| u.item == "info@example.com" && u.kind == UnmappedKind::Mail),
            "each mail account is named, not just counted: {:#?}",
            plan.unmapped
        );
    }

    #[test]
    fn no_password_or_hash_from_the_archive_appears_anywhere_in_the_plan() {
        // The fixture's shadow file, the MySQL grant's hash and the private key
        // are all in the archive. None of them may reach the stored plan, which
        // is JSON in the panel database and readable by anyone who can read a
        // plan (spec §12 rule 6).
        let plan = planned();
        let json = serde_json::to_string(&plan).unwrap();
        for secret in ["averyrealhash", "*ABC", "BEGIN PRIVATE KEY"] {
            assert!(
                !json.contains(secret),
                "the plan leaked `{secret}`:\n{json}"
            );
        }
    }

    #[test]
    fn the_database_dump_becomes_a_planned_database_with_a_new_user() {
        let plan = planned();
        assert_eq!(plan.databases.len(), 1);
        let db = &plan.databases[0];
        assert_eq!(db.source_name, "bob_wp");
        assert_eq!(db.target_name, "bob_wp");
        assert_ne!(db.target_user, "");
        assert_eq!(
            db.payload,
            DumpSource::TarMember {
                path: "bob/mysql/bob_wp.sql".into()
            }
        );
    }

    #[test]
    fn an_archive_with_two_top_level_directories_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("two.tar.gz");
        tar_gz(
            &path,
            &[
                ("bob/homedir/public_html/i.php", 0o644, b"x"),
                ("alice/homedir/public_html/i.php", 0o644, b"y"),
            ],
        );
        let err = plan(&path, 1, None, "fp".into(), Limits::default()).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidInput);
        assert!(err.detail.contains("top-level"), "{}", err.detail);
    }

    #[test]
    fn a_document_root_outside_the_home_is_unmapped_rather_than_guessed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("odd.tar.gz");
        tar_gz(
            &path,
            &[
                (
                    "bob/userdata/main",
                    0o644,
                    b"main_domain: example.com\nsub_domains: []\n",
                ),
                (
                    "bob/userdata/example.com",
                    0o644,
                    b"documentroot: /var/www/elsewhere\nhomedir: /home/bob\n",
                ),
                ("bob/homedir/public_html/i.php", 0o644, b"x"),
            ],
        );
        let plan = plan(&path, 1, None, "fp".into(), Limits::default()).unwrap();
        assert!(plan.sites.is_empty());
        assert!(
            plan.unmapped
                .iter()
                .any(|u| u.kind == UnmappedKind::Site && u.reason.contains("not inside")),
            "{:#?}",
            plan.unmapped
        );
    }

    #[test]
    fn the_yaml_subset_reads_the_shapes_cpanel_writes() {
        let doc = yaml::parse(
            "---\nmain_domain: example.com\naddon_domains:\n  a.com: a.example.com\n  \
             b.com: b.example.com\nparked_domains: []\nsub_domains:\n  - one.example.com\n\
             # a comment\nquoted: 'value'\n",
        );
        assert_eq!(doc.scalar("main_domain").as_deref(), Some("example.com"));
        assert_eq!(doc.scalar("quoted").as_deref(), Some("value"));
        assert_eq!(doc.seq("sub_domains"), vec!["one.example.com".to_string()]);
        assert!(doc.seq("parked_domains").is_empty());
        assert_eq!(
            doc.map("addon_domains"),
            vec![
                ("a.com".to_string(), "a.example.com".to_string()),
                ("b.com".to_string(), "b.example.com".to_string()),
            ]
        );
    }

    #[test]
    fn php_versions_are_read_from_the_shapes_cpanel_writes() {
        assert_eq!(parse_ea_php("ea-php82"), Some(PhpVersion::V82));
        assert_eq!(parse_ea_php("ea-php74"), Some(PhpVersion::V74));
        assert_eq!(parse_ea_php("8.3"), Some(PhpVersion::V83));
        // A version Unihelm does not offer must not be silently mapped onto one
        // that it does.
        assert_eq!(parse_ea_php("ea-php56"), None);
        assert_eq!(parse_ea_php("inherit"), None);
    }
}
