//! ModSecurity and the OWASP Core Rule Set (spec §11.9).
//!
//! # The limitation, stated first
//!
//! **On a stock Unihelm server this feature refuses to enable, and it says so.**
//! Unihelm installs nginx from nginx.org (`unihelm_distro::repos::nginx`), and
//! nginx.org publishes no ModSecurity module. Checked on 2026-08-28 against the
//! four package trees Unihelm can install from:
//!
//! | tree | modules published |
//! |---|---|
//! | `nginx.org/packages/debian/pool/nginx/n/` | acme, geoip, image-filter, njs, otel, perl, xslt |
//! | `nginx.org/packages/ubuntu/pool/nginx/n/` | the same set |
//! | `nginx.org/packages/mainline/debian/pool/nginx/n/` | the same set |
//! | `nginx.org/packages/centos/10/x86_64/RPMS/` | acme, image-filter, njs, otel, perl, xslt |
//!
//! No `nginx-module-modsecurity` in any of them. A ModSecurity connector *is*
//! packaged elsewhere — Debian and Ubuntu ship `libnginx-mod-http-modsecurity`,
//! EPEL 9 ships `nginx-mod-modsecurity` — but both are built against their own
//! distribution's nginx, and an nginx dynamic module records the nginx version
//! and build signature it was compiled against and is rejected at load time by
//! any other ("module ... is not binary compatible"). Installing the distro
//! package next to nginx.org's nginx therefore produces a module that cannot
//! load, not a working WAF.
//!
//! There is a second, independent blocker on the same servers. `load_module` is
//! a **main-context** directive, and nginx.org's `nginx.conf` — verified by
//! unpacking `nginx-1.30.4-1.el10.ngx.x86_64.rpm` and
//! `nginx_1.30.4-1~trixie_amd64.deb` — contains no main-context `include` at
//! all: its only include is `/etc/nginx/conf.d/*.conf`, inside `http`. So even
//! with a compatible module on disk there is nowhere to put the line that loads
//! it except `nginx.conf` itself, and editing `nginx.conf` is the one thing the
//! panel does not do (spec §10.4 rule 1, `unihelm_config::paths`).
//!
//! Spec §11.9's answer is "a prebuilt dynamic module from our own repo", the
//! same rule as brotli in §11.2. That repository does not exist in this build.
//! Rather than pretend, [`preflight`] detects both conditions and `waf.enable`
//! refuses with a message naming exactly what is missing. Everything below the
//! preflight is real and complete: give this code a loadable module and a place
//! to load it from — an operator's own build, a distro nginx, the future Unihelm
//! repo — and it configures, validates and reloads like any other nginx change.
//!
//! # How per-site policy works without touching a single vhost
//!
//! ModSecurity's nginx directives are valid at http, server and location level,
//! so the obvious design is `modsecurity on;` inside each site's server block.
//! Unihelm does not do that, for two reasons: it would mean re-rendering every
//! vhost to change one site's WAF, and a site whose owner has hand-edited their
//! vhost (which the config engine detects and refuses to overwrite) could not be
//! governed at all.
//!
//! Instead the engine is switched on once at http level in
//! `unihelm.d/03-waf.conf`, starting in `DetectionOnly`, and each site's policy
//! is a phase-1 `SecRule` matching that site's own hostnames which uses
//! `ctl:ruleEngine` and `setvar:tx.*_paranoia_level` to set the mode and the
//! paranoia level for that transaction. One generated file holds every site's
//! policy; turning a site on is one render and one reload.
//!
//! Requests whose `Host` matches no site match no rule and get the server-wide
//! default. That is the safe direction: unknown traffic inherits the strictest
//! configured position, never a site's relaxations.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use unihelm_config::apply::ApplyRequest;
use unihelm_config::managed::ManagedFile;
use unihelm_config::paths;
use unihelm_core::{ErrorCode, Permission, Result, SiteId, TenantScope, UnihelmError};
use unihelm_db::settings::keys;
use unihelm_db::{Db, NewWafExclusion, WafExclusion, WafMode};
use unihelm_distro::{Cmd, Family};

use crate::registry::{Execution, OpContext, TypedOperation};
use crate::services::{NginxValidator, UnitReloader};

// ---------------------------------------------------------------------------
// The pinned Core Rule Set
// ---------------------------------------------------------------------------

/// The OWASP Core Rule Set release Unihelm installs.
pub const CRS_VERSION: &str = "4.29.0";

/// The `minimal` tarball: rules, data files, `crs-setup.conf.example` and the
/// licence — no tests, no tooling, no CI fixtures. 272 KiB against several MiB
/// for the full source tree, and nothing the panel omits is read at runtime.
pub const CRS_URL: &str = "https://github.com/coreruleset/coreruleset/releases/download/v4.29.0/coreruleset-4.29.0-minimal.tar.gz";

/// SHA-256 of `coreruleset-4.29.0-minimal.tar.gz`, pinned.
///
/// Provenance, honestly. This value was computed on 2026-08-28 by downloading
/// the asset from [`CRS_URL`] and hashing the 278,138 bytes served. The GitHub
/// release API lists the same asset at the same size. Both observations come
/// from github.com, so this is a **single-source pin** in the sense of
/// `unihelm_distro::repos::UNVERIFIED_PINS`: it detects a later tampered or
/// truncated download, not a source that was already wrong on the day it was
/// pinned.
///
/// It could be stronger, and is not yet: the project publishes a detached
/// OpenPGP signature beside every asset (`…-minimal.tar.gz.asc`). Unihelm's
/// in-tree OpenPGP code (`unihelm_distro::pgp`) parses keys and computes
/// fingerprints — it does not verify signatures — so nothing in this build can
/// check that `.asc`. Verifying it, against a CRS signing key pinned by
/// fingerprint the way the repository keys are, is the upgrade this pin is
/// waiting on; [`CRS_PIN_PROVENANCE`] carries the current state to the API so
/// an operator does not have to read this file to learn it.
pub const CRS_SHA256: &str = "1aa1c5c8fc29e532d35293bcea36bf72de61db8f6ed4716a0f91ab14552b7fed";

/// Surfaced by `waf.status`, exactly as `db.adminer.status` surfaces Adminer's.
pub const CRS_PIN_PROVENANCE: &str =
    "single-source (github.com); the published .asc signature is not verified by this build";

/// Hard ceiling on the download. The pinned tarball is ~272 KiB; anything an
/// order of magnitude larger is not the file we pinned, and there is no point
/// buffering it to find that out from the hash.
const MAX_CRS_BYTES: usize = 8 * 1024 * 1024;

/// Ceiling on the *unpacked* tree — a decompression bomb guard. The real tree
/// is ~2 MiB across 70 entries.
const MAX_CRS_UNPACKED_BYTES: u64 = 64 * 1024 * 1024;
const MAX_CRS_ENTRIES: usize = 2_000;

// ---------------------------------------------------------------------------
// Rule id allocation
// ---------------------------------------------------------------------------

/// The base of Unihelm's per-site rule ids.
///
/// The Core Rule Set reserves 900,000–999,999 for itself and documents
/// 1–99,999 as the range for local rules. 20,000 keeps Unihelm clear of the
/// 1–9,999 block operators habitually use for their own hand-written rules.
/// The id is `base + site_id`, so a rule id in an audit log names exactly one
/// site.
pub const RULE_ID_BASE: i64 = 20_000;

/// One past the last id Unihelm will allocate.
pub const RULE_ID_CEILING: i64 = 30_000;

/// The module filename every ModSecurity nginx connector build uses.
const MODULE_FILENAME: &str = "ngx_http_modsecurity_module.so";

/// The drop-in the panel writes when it has to load the module itself.
const LOAD_MODULE_DROPIN: &str = "50-unihelm-modsecurity.conf";

// ---------------------------------------------------------------------------
// Preflight: is there a WAF to configure at all?
// ---------------------------------------------------------------------------

/// A packaged ModSecurity connector Unihelm knows about, and the truth about it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ModuleCandidate {
    pub package: &'static str,
    pub repository: &'static str,
    /// The nginx these packages are built against. Recorded because it is the
    /// whole reason installing one does not help on a Unihelm server.
    pub built_against: &'static str,
}

/// Every package that could plausibly provide the module on this family.
///
/// Deliberately *not* a list of things to install. It exists so the refusal can
/// name real package names and say why each one is not the answer, instead of
/// telling an operator "not available" and leaving them to search.
pub const fn module_candidates(family: Family) -> &'static [ModuleCandidate] {
    match family {
        Family::Debian => &[ModuleCandidate {
            package: "libnginx-mod-http-modsecurity",
            repository: "the Debian/Ubuntu distribution repositories",
            built_against: "the distribution's own nginx, not nginx.org's",
        }],
        Family::Rhel => &[ModuleCandidate {
            package: "nginx-mod-modsecurity",
            repository: "EPEL",
            built_against: "the EL AppStream nginx, not nginx.org's",
        }],
    }
}

/// Whether a loadable module exists on this machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ModuleState {
    /// A module file is on disk. Whether nginx will *accept* it is decided by
    /// `nginx -t`, which the config engine runs before any reload.
    Present { path: String },
    /// Nothing on disk.
    Absent { searched: String },
}

impl ModuleState {
    pub fn is_present(&self) -> bool {
        matches!(self, ModuleState::Present { .. })
    }
}

/// Look for the module in nginx's module directory.
///
/// Both nginx.org packages ship `/etc/nginx/modules` as a symlink to their real
/// module directory (`/usr/lib/nginx/modules` on deb, `/usr/lib64/nginx/modules`
/// on rpm), so one path covers both families.
pub fn module_state() -> ModuleState {
    let dir = paths::nginx_modules_dir();
    let candidate = dir.join(MODULE_FILENAME);
    if candidate.exists() {
        ModuleState::Present {
            path: candidate.display().to_string(),
        }
    } else {
        ModuleState::Absent {
            searched: candidate.display().to_string(),
        }
    }
}

/// Where a `load_module` line can live, if anywhere.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "plan", rename_all = "snake_case")]
pub enum LoadPlan {
    /// Something already loads the module — a distro module package's own
    /// drop-in, or a line an operator added. The panel writes nothing.
    AlreadyLoaded { by: String },
    /// nginx.conf includes a directory at main context and the panel will write
    /// its `load_module` line into a file there.
    Dropin { path: String },
    /// nginx.conf offers no main-context include, so `load_module` could only
    /// go into `nginx.conf` itself — which the panel does not edit.
    Nowhere,
}

/// The first `include` directive at main context, i.e. before `events {` or
/// `http {`.
///
/// Textual rather than a real nginx parser, and that is a considered trade: the
/// only thing this decides is *where to put a file*, the result is checked by
/// `nginx -t` before anything reloads, and being wrong costs a rolled-back
/// change rather than a broken server. Comments are skipped; a `#` inside a
/// value cannot occur in an `include` path that nginx would accept unquoted.
pub fn main_context_include(nginx_conf: &str) -> Option<String> {
    for raw in nginx_conf.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        // A block opening ends the main context. `events` and `http` are the
        // only two that can appear there in a configuration nginx accepts.
        let first = line.split_whitespace().next().unwrap_or("");
        if matches!(first, "events" | "http" | "stream" | "mail") {
            return None;
        }
        if let Some(rest) = line.strip_prefix("include") {
            let value = rest.trim().trim_end_matches(';').trim().trim_matches('"');
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

/// Decide how — or whether — the module gets loaded.
///
/// Pure, so the decision can be tested against the real `nginx.conf` files both
/// package families ship without a machine that has nginx on it.
/// `existing_dropins` is the (name, contents) of every file in the main-context
/// include directory.
pub fn plan_module_load(nginx_conf: &str, existing_dropins: &[(String, String)]) -> LoadPlan {
    if nginx_conf.contains(MODULE_FILENAME) {
        return LoadPlan::AlreadyLoaded {
            by: paths::nginx_conf().display().to_string(),
        };
    }
    for (name, contents) in existing_dropins {
        if contents.contains(MODULE_FILENAME) {
            return LoadPlan::AlreadyLoaded { by: name.clone() };
        }
    }
    match main_context_include(nginx_conf) {
        Some(glob) => {
            let dir = Path::new(&glob)
                .parent()
                .map(Path::to_path_buf)
                .unwrap_or_else(|| PathBuf::from("/etc/nginx"));
            LoadPlan::Dropin {
                path: dir.join(LOAD_MODULE_DROPIN).display().to_string(),
            }
        }
        None => LoadPlan::Nowhere,
    }
}

/// Something that stops the WAF from being enabled, with the reason and the fix.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Blocker {
    /// Stable, machine-readable. The UI keys its help text on this.
    pub code: &'static str,
    pub detail: String,
    pub remedy: String,
}

/// Everything the panel knows about whether a WAF can run here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Preflight {
    pub module: ModuleState,
    pub load: LoadPlan,
    pub candidates: &'static [ModuleCandidate],
    pub blockers: Vec<Blocker>,
}

impl Preflight {
    pub fn is_available(&self) -> bool {
        self.blockers.is_empty()
    }
}

/// Turn the two observed facts into blockers. Pure; see [`preflight`] for the
/// version that goes to disk.
pub fn assess(family: Family, module: ModuleState, load: LoadPlan) -> Preflight {
    let candidates = module_candidates(family);
    let mut blockers = Vec::new();

    if !module.is_present() {
        let ModuleState::Absent { searched } = &module else {
            unreachable!("just checked it is absent")
        };
        let named: Vec<String> = candidates
            .iter()
            .map(|c| {
                format!(
                    "`{}` in {} (built against {})",
                    c.package, c.repository, c.built_against
                )
            })
            .collect();
        blockers.push(Blocker {
            code: "module_missing",
            detail: format!(
                "no ModSecurity connector for nginx: `{searched}` does not exist. \
                 nginx here comes from nginx.org, which publishes no \
                 nginx-module-modsecurity package for any distribution it serves."
            ),
            remedy: format!(
                "There is a packaged connector — {} — but an nginx dynamic module \
                 only loads into the exact nginx build it was compiled against, so \
                 installing it beside nginx.org's nginx produces a module nginx \
                 refuses with \"is not binary compatible\". The supported fix is a \
                 module built for this nginx: spec §11.9 plans one in Unihelm's own \
                 package repository (the same rule as brotli in §11.2), and that \
                 repository does not exist in this build. Until it does, the WAF \
                 can only run on a server whose nginx and connector come from the \
                 same source.",
                named.join(", ")
            ),
        });
    }

    // Only worth reporting once a module actually exists: telling an operator
    // there is nowhere to load a module they do not have is noise on top of the
    // real problem.
    if module.is_present() && load == LoadPlan::Nowhere {
        blockers.push(Blocker {
            code: "no_main_context_include",
            detail: format!(
                "the module exists but `load_module` has nowhere to go: {} contains \
                 no `include` at main context, and `load_module` is not valid inside \
                 `http`. The nginx.org packages ship exactly this nginx.conf.",
                paths::nginx_conf().display()
            ),
            remedy: format!(
                "Add one line to {} — `include /etc/nginx/modules-enabled/*.conf;` \
                 above the `events` block — and create that directory. Unihelm will \
                 not make that edit itself: nginx.conf belongs to the nginx package, \
                 and the panel's entire footprint on files it does not own is a \
                 single include line (spec §10.4 rule 1).",
                paths::nginx_conf().display()
            ),
        });
    }

    Preflight {
        module,
        load,
        candidates,
        blockers,
    }
}

/// The preflight against this machine.
pub fn preflight(family: Family) -> Preflight {
    let module = module_state();
    let nginx_conf = std::fs::read_to_string(paths::nginx_conf()).unwrap_or_default();
    let dropins = match main_context_include(&nginx_conf) {
        Some(glob) => read_dropins(&glob),
        None => Vec::new(),
    };
    assess(family, module, plan_module_load(&nginx_conf, &dropins))
}

/// Read every file in the directory a main-context include glob names.
///
/// Failures are empty, not errors: an unreadable module directory means "we
/// found nothing that already loads the module", and the worst consequence is
/// that the panel writes a drop-in nginx then rejects as a duplicate — caught
/// by `nginx -t` before any reload.
fn read_dropins(glob: &str) -> Vec<(String, String)> {
    let Some(dir) = Path::new(glob).parent() else {
        return Vec::new();
    };
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if let Ok(contents) = std::fs::read_to_string(&path) {
            out.push((path.display().to_string(), contents));
        }
    }
    out.sort();
    out
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

/// One site as the rules template needs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SitePolicyView {
    pub site_id: i64,
    /// Every name nginx serves this site under: primary domain plus aliases.
    pub hostnames: Vec<String>,
    pub mode: WafMode,
    pub paranoia_level: i64,
    /// CRS rule ids excluded for this site alone.
    pub exclusions: Vec<i64>,
}

/// Escape a hostname for use inside a regular expression.
///
/// The hostnames reaching here are `Domain` newtypes, so they are already
/// restricted to letters, digits, dots and hyphens (spec §12 rule 3) — this is
/// the second layer, and the reason it exists is that a value reaching a regex
/// engine is a value that can change what the regex *means*, not just what it
/// matches. An unexpected character is refused rather than escaped: a hostname
/// this does not recognise is a hostname the panel should not be building rules
/// from at all.
pub fn escape_host(host: &str) -> Result<String> {
    let mut out = String::with_capacity(host.len() + 4);
    for ch in host.chars() {
        match ch {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' => out.push(ch),
            '.' => out.push_str(r"\."),
            other => {
                return Err(UnihelmError::new(
                    ErrorCode::InvalidInput,
                    format!(
                        "`{host}` contains `{other}`, which is not a character a \
                         hostname may hold; refusing to build a WAF rule from it"
                    ),
                )
                .with_field("hostnames"));
            }
        }
    }
    Ok(out)
}

/// The anchored alternation one site's rule matches on.
///
/// The optional `(?::[0-9]+)?` is not decoration: a `Host` header legitimately
/// carries a port (`example.com:8443`), and a pattern without it would silently
/// stop matching the moment a site was reached on a non-default port — which
/// would leave that traffic on the server-wide default rather than the site's
/// policy.
pub fn host_pattern(hostnames: &[String]) -> Result<String> {
    if hostnames.is_empty() {
        return Err(UnihelmError::internal(
            "a site with no server names cannot have a WAF rule",
        ));
    }
    let mut escaped = Vec::with_capacity(hostnames.len());
    for host in hostnames {
        escaped.push(escape_host(&host.to_ascii_lowercase())?);
    }
    Ok(format!(r"^(?:{})(?::[0-9]+)?$", escaped.join("|")))
}

/// The rule id for a site.
pub fn rule_id_for(site_id: i64) -> Result<i64> {
    let id = RULE_ID_BASE + site_id;
    if site_id < 1 || id >= RULE_ID_CEILING {
        return Err(UnihelmError::internal(format!(
            "site {site_id} falls outside the WAF rule id block \
             {RULE_ID_BASE}–{}; per-site WAF policy cannot be expressed for it \
             without moving the block, which would renumber every existing rule",
            RULE_ID_CEILING - 1
        )));
    }
    Ok(id)
}

/// The `ctl:`/`setvar:` action list for one site.
pub fn site_actions(view: &SitePolicyView) -> String {
    let mut actions = vec![format!("ctl:ruleEngine={}", view.mode.rule_engine())];
    // Nothing else is worth emitting when the engine is off for this site: the
    // paranoia level is a variable no rule will read.
    if view.mode != WafMode::Off {
        // Detection and blocking levels are set together. Splitting them is a
        // real CRS feature (score at 2, block at 1) and a real way to end up
        // with a site that logs a threat it does not act on; a panel should
        // offer one number until an operator asks for two.
        actions.push(format!(
            "setvar:tx.blocking_paranoia_level={}",
            view.paranoia_level
        ));
        actions.push(format!(
            "setvar:tx.detection_paranoia_level={}",
            view.paranoia_level
        ));
        for rule in &view.exclusions {
            actions.push(format!("ctl:ruleRemoveById={rule}"));
        }
    }
    actions.join(",")
}

/// Everything `modsecurity/main.conf` needs, as JSON for minijinja.
pub fn rules_context(
    default_mode: WafMode,
    sites: &[SitePolicyView],
    global_exclusions: &[&WafExclusion],
) -> Result<serde_json::Value> {
    let mut rendered_sites = Vec::with_capacity(sites.len());
    for view in sites {
        let description = match view.mode {
            WafMode::Off => "WAF off for this site".to_string(),
            WafMode::Detect => format!("log only, paranoia {}", view.paranoia_level),
            WafMode::Block => format!("blocking, paranoia {}", view.paranoia_level),
        };
        rendered_sites.push(serde_json::json!({
            "domain": view.hostnames.first().cloned().unwrap_or_default(),
            "description": description,
            "rule_id": rule_id_for(view.site_id)?,
            "host_pattern": host_pattern(&view.hostnames)?,
            "actions": site_actions(view),
        }));
    }

    Ok(serde_json::json!({
        // `DetectionOnly` and `On` are ModSecurity's spellings; `Off` here
        // would mean the engine parses the rules and ignores them, which is
        // what a server-wide `off` default is.
        "default_engine": match default_mode {
            WafMode::Off => "Off",
            WafMode::Detect => "DetectionOnly",
            WafMode::Block => "On",
        },
        "data_dir": paths::waf_data_dir().display().to_string(),
        "audit_log": paths::waf_audit_log().display().to_string(),
        "crs_dir": paths::waf_crs_release_dir(CRS_VERSION).display().to_string(),
        "crs_version": CRS_VERSION,
        "rule_id_base": RULE_ID_BASE,
        "sites": rendered_sites,
        "global_exclusions": global_exclusions
            .iter()
            .map(|e| serde_json::json!({ "rule_id": e.rule_id, "reason": e.reason }))
            .collect::<Vec<_>>(),
    }))
}

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------

/// The server-wide knobs, with the defaults spec §11.9 asks for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WafSettings {
    /// False on a fresh install. Turning it on is the point at which the panel
    /// first looks for a module.
    pub enabled: bool,
    /// What a site without a policy of its own gets. `detect` — log-only —
    /// because the CRS has not met this server's traffic yet.
    pub default_mode: WafMode,
    pub default_paranoia: i64,
}

impl Default for WafSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            default_mode: WafMode::Detect,
            default_paranoia: unihelm_db::waf::DEFAULT_PARANOIA,
        }
    }
}

impl WafSettings {
    pub async fn load(db: &Db) -> Self {
        let d = Self::default();
        Self {
            enabled: db.get_setting_or(keys::WAF_ENABLED, d.enabled).await,
            default_mode: db
                .get_setting_or(keys::WAF_DEFAULT_MODE, d.default_mode)
                .await,
            default_paranoia: db
                .get_setting_or(keys::WAF_DEFAULT_PARANOIA, d.default_paranoia)
                .await,
        }
    }

    pub async fn store(&self, db: &Db) -> Result<()> {
        validate_paranoia(self.default_paranoia)?;
        let e = UnihelmError::from;
        db.set_setting(keys::WAF_ENABLED, &self.enabled)
            .await
            .map_err(e)?;
        db.set_setting(keys::WAF_DEFAULT_MODE, &self.default_mode)
            .await
            .map_err(e)?;
        db.set_setting(keys::WAF_DEFAULT_PARANOIA, &self.default_paranoia)
            .await
            .map_err(e)?;
        Ok(())
    }
}

/// Reject a paranoia level CRS does not define.
///
/// The failure this prevents is quiet, which is what makes it worth a check: a
/// level outside 1–4 sets `tx.blocking_paranoia_level` to a value no CRS rule
/// tests, so the rule set behaves as if it were at level 1 while the panel
/// displays whatever the operator typed.
pub fn validate_paranoia(level: i64) -> Result<()> {
    if (unihelm_db::waf::MIN_PARANOIA..=unihelm_db::waf::MAX_PARANOIA).contains(&level) {
        return Ok(());
    }
    Err(UnihelmError::new(
        ErrorCode::InvalidInput,
        format!(
            "paranoia level must be between {} and {}; CRS defines no other level, \
             and a value it does not define would run as level {} while the panel \
             showed {level}",
            unihelm_db::waf::MIN_PARANOIA,
            unihelm_db::waf::MAX_PARANOIA,
            unihelm_db::waf::MIN_PARANOIA
        ),
    )
    .with_field("paranoia_level"))
}

// ---------------------------------------------------------------------------
// Fetching and unpacking the Core Rule Set
// ---------------------------------------------------------------------------

/// Fetches the CRS tarball. A trait so the verify-and-refuse path is testable
/// without a network, exactly as `adminer::ScriptFetcher` is.
#[async_trait]
pub trait CrsFetcher: Send + Sync {
    async fn fetch(&self, url: &str) -> Result<Vec<u8>>;
}

pub struct HttpsCrsFetcher;

#[async_trait]
impl CrsFetcher for HttpsCrsFetcher {
    async fn fetch(&self, url: &str) -> Result<Vec<u8>> {
        if !url.starts_with("https://") {
            return Err(UnihelmError::internal(format!(
                "refusing to fetch the Core Rule Set over `{url}`"
            )));
        }
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(120))
            .user_agent(concat!("unihelm/", env!("CARGO_PKG_VERSION")))
            // A redirect to http:// would drop the transport security the
            // checksum pin supplements rather than replaces.
            .https_only(true)
            .build()
            .map_err(|e| UnihelmError::internal(format!("could not build an HTTP client: {e}")))?;

        let response = client.get(url).send().await.map_err(|e| {
            UnihelmError::new(
                ErrorCode::PackageBackendFailed,
                format!("could not download {url}: {e}"),
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
        if bytes.len() > MAX_CRS_BYTES {
            return Err(UnihelmError::new(
                ErrorCode::PackageBackendFailed,
                format!(
                    "{url} served {} bytes; the pinned Core Rule Set tarball is ~272 KiB",
                    bytes.len()
                ),
            ));
        }
        Ok(bytes.to_vec())
    }
}

/// Refuse anything whose SHA-256 is not the pinned one.
pub fn verify_crs(bytes: &[u8], expected_hex: &str) -> Result<()> {
    let actual = hex::encode(Sha256::digest(bytes));
    if actual == expected_hex {
        return Ok(());
    }
    Err(UnihelmError::new(
        ErrorCode::PackageBackendFailed,
        format!(
            "the Core Rule Set download failed checksum verification: expected \
             sha256 {expected_hex}, got {actual} ({} bytes). Nothing was unpacked. \
             This is either a corrupted download or a tampered archive — do not \
             bypass this check.",
            bytes.len()
        ),
    ))
}

/// Unpack a verified CRS tarball under `dest`.
///
/// The checksum already proves these are the bytes we pinned, so in production
/// the guards below never fire. They are here because "the archive was verified"
/// is a property of *this* call site and archive extraction is a bug class
/// (spec §12 rule 5): a future caller that unpacks something less trusted
/// inherits a function that cannot be talked into writing outside `dest`,
/// rather than one that trusts its input.
///
/// Refused: absolute paths, any `..` component, anything that is not a regular
/// file or a directory (a symlink or a hard link entry is how an archive
/// escapes a directory it was extracted into), more than [`MAX_CRS_ENTRIES`]
/// entries, and more than [`MAX_CRS_UNPACKED_BYTES`] of content.
pub fn extract_crs(tar_gz: &[u8], dest: &Path) -> Result<usize> {
    use std::io::Read;

    let decoder = flate2::read::GzDecoder::new(tar_gz);
    let mut archive = tar::Archive::new(decoder);
    let entries = archive.entries().map_err(|e| {
        UnihelmError::internal(format!("the Core Rule Set archive is unreadable: {e}"))
    })?;

    let bad = |detail: String| {
        UnihelmError::new(
            ErrorCode::PackageBackendFailed,
            format!("refusing to unpack the Core Rule Set archive: {detail}"),
        )
    };

    std::fs::create_dir_all(dest)
        .map_err(|e| UnihelmError::internal(format!("could not create {}: {e}", dest.display())))?;

    let mut written = 0usize;
    let mut total_bytes = 0u64;
    for (index, entry) in entries.enumerate() {
        if index >= MAX_CRS_ENTRIES {
            return Err(bad(format!("more than {MAX_CRS_ENTRIES} entries")));
        }
        let mut entry = entry.map_err(|e| bad(format!("entry {index} is unreadable: {e}")))?;
        let path = entry
            .path()
            .map_err(|e| bad(format!("entry {index} has an unreadable path: {e}")))?
            .into_owned();

        if path.is_absolute() {
            return Err(bad(format!("`{}` is an absolute path", path.display())));
        }
        if path
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            return Err(bad(format!("`{}` walks out with ..", path.display())));
        }

        let kind = entry.header().entry_type();
        if !(kind.is_file() || kind.is_dir()) {
            return Err(bad(format!(
                "`{}` is a {kind:?} entry; only regular files and directories are unpacked",
                path.display()
            )));
        }

        let size = entry.header().size().unwrap_or(0);
        total_bytes = total_bytes.saturating_add(size);
        if total_bytes > MAX_CRS_UNPACKED_BYTES {
            return Err(bad(format!(
                "the unpacked tree exceeds {MAX_CRS_UNPACKED_BYTES} bytes"
            )));
        }

        let target = dest.join(&path);
        if kind.is_dir() {
            std::fs::create_dir_all(&target).map_err(|e| {
                UnihelmError::internal(format!("could not create {}: {e}", target.display()))
            })?;
            continue;
        }
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                UnihelmError::internal(format!("could not create {}: {e}", parent.display()))
            })?;
        }
        let mut buf = Vec::with_capacity(size as usize);
        entry
            .read_to_end(&mut buf)
            .map_err(|e| bad(format!("`{}` could not be read: {e}", path.display())))?;
        std::fs::write(&target, &buf).map_err(|e| {
            UnihelmError::internal(format!("could not write {}: {e}", target.display()))
        })?;
        written += 1;
    }
    Ok(written)
}

/// Put the pinned Core Rule Set on disk if it is not already there.
///
/// Returns whether anything was downloaded. Idempotent: a tree that already has
/// its `crs-setup.conf` is left alone, so re-running `waf.enable` after a
/// failure costs nothing.
pub async fn ensure_crs(ctx: &OpContext, fetcher: &dyn CrsFetcher) -> Result<bool> {
    let release = paths::waf_crs_release_dir(CRS_VERSION);
    let setup = release.join("crs-setup.conf");
    if setup.exists() {
        ctx.log(format!(
            "OWASP CRS {CRS_VERSION} is already unpacked at {}",
            release.display()
        ));
        return Ok(false);
    }

    ctx.log(format!(
        "downloading OWASP CRS {CRS_VERSION} from {CRS_URL}"
    ));
    ctx.log(format!("checksum provenance: {CRS_PIN_PROVENANCE}"));
    let bytes = fetcher.fetch(CRS_URL).await?;
    verify_crs(&bytes, CRS_SHA256)?;
    ctx.log(format!(
        "checksum verified ({} bytes); unpacking",
        bytes.len()
    ));

    let files = extract_crs(&bytes, &paths::waf_crs_dir())?;
    ctx.log(format!("unpacked {files} files"));

    // The tarball ships `crs-setup.conf.example`; CRS expects the operator to
    // copy it. Copying rather than including the `.example` directly means a
    // later CRS release cannot silently change settings underneath a running
    // server — the new release unpacks beside this one, with its own directory.
    let example = release.join("crs-setup.conf.example");
    if !example.exists() {
        return Err(UnihelmError::new(
            ErrorCode::PackageBackendFailed,
            format!(
                "the unpacked Core Rule Set has no {} — the archive layout is not \
                 what this version of Unihelm expects",
                example.display()
            ),
        ));
    }
    std::fs::copy(&example, &setup)
        .map_err(|e| UnihelmError::internal(format!("could not write {}: {e}", setup.display())))?;

    ctx.db()
        .set_setting(keys::WAF_CRS_VERSION, &CRS_VERSION)
        .await
        .map_err(UnihelmError::from)?;
    Ok(true)
}

// ---------------------------------------------------------------------------
// Applying the configuration
// ---------------------------------------------------------------------------

/// Gather every site's policy from the database.
///
/// Sites with no row of their own are omitted entirely rather than rendered
/// with the default: a rule that sets the default is a rule that does nothing,
/// and 400 of them would be 400 regex evaluations on every request.
async fn site_views(db: &Db) -> Result<Vec<SitePolicyView>> {
    let policies = db.waf_site_policies().await.map_err(UnihelmError::from)?;
    if policies.is_empty() {
        return Ok(Vec::new());
    }

    let exclusions = db.waf_exclusions().await.map_err(UnihelmError::from)?;
    let mut per_site: BTreeMap<i64, Vec<i64>> = BTreeMap::new();
    for exclusion in &exclusions {
        if let Some(site_id) = exclusion.site_id {
            per_site.entry(site_id).or_default().push(exclusion.rule_id);
        }
    }

    // `TenantScope::Global`: these operations are `ServerManage`, the WAF is one
    // host-wide engine, and a render that could only see one tenant's sites
    // would drop every other tenant's policy from the file.
    let sites = db.sites(&TenantScope::Global);
    let mut views = Vec::with_capacity(policies.len());
    for policy in policies {
        let site_id = SiteId::from(policy.site_id);
        let hostnames = match sites.server_names(site_id).await {
            Ok(names) => names,
            // A policy row whose site vanished between the two queries. The
            // foreign key makes this a race rather than a state, and skipping
            // is right: rendering a rule for a hostname nothing serves would
            // be worse than one fewer rule.
            Err(_) => continue,
        };
        views.push(SitePolicyView {
            site_id: policy.site_id,
            hostnames,
            mode: policy.mode,
            paranoia_level: policy.paranoia_level,
            exclusions: per_site.remove(&policy.site_id).unwrap_or_default(),
        });
    }
    Ok(views)
}

/// Render `main.conf` and the nginx include, validate and reload.
///
/// Both files go through the config engine in one order that matters: the rules
/// file first, the nginx include second. nginx only parses the rules file when
/// something points at it, so writing the rules first means the validation run
/// that follows the *second* apply is the one that sees both — and a broken
/// rules file therefore fails `nginx -t` and rolls the include back, leaving a
/// server that never loaded either.
/// Write the `load_module` drop-in, if the panel is the one who has to.
///
/// Three outcomes, all of them fine:
///
/// * [`LoadPlan::AlreadyLoaded`] — a distro module package's own drop-in, or a
///   line an operator added. Writing a second `load_module` for the same module
///   makes nginx refuse to start, so the panel writes nothing.
/// * [`LoadPlan::Dropin`] — the panel owns a file in nginx's main-context
///   include directory. It goes through the config engine like every other
///   managed file, which means `nginx -t` runs before any reload and an
///   ABI-mismatched module is caught here rather than at the next restart.
/// * [`LoadPlan::Nowhere`] — unreachable: [`assess`] turns it into a blocker
///   and `waf.enable` has already refused. Handled rather than `unreachable!`
///   because a panic in an operation is a worse outcome than an error.
async fn ensure_module_loaded(ctx: &OpContext, pre: &Preflight) -> Result<()> {
    let ModuleState::Present {
        path: module_path, ..
    } = &pre.module
    else {
        return Err(refusal(&pre.blockers));
    };

    match &pre.load {
        LoadPlan::AlreadyLoaded { by } => {
            ctx.log(format!("the ModSecurity module is already loaded by {by}"));
            Ok(())
        }
        LoadPlan::Nowhere => Err(refusal(&pre.blockers)),
        LoadPlan::Dropin { path } => {
            ctx.log(format!("loading {module_path} through {path}"));
            let distro = ctx.distro();
            ctx.config()
                .apply(ApplyRequest {
                    file: ManagedFile::nginx(PathBuf::from(path)),
                    template: "nginx/load-module.conf",
                    context: serde_json::json!({ "module_path": module_path }),
                    service: "nginx",
                    validator: &NginxValidator,
                    reloader: &UnitReloader::nginx(distro),
                    post_check: None,
                    // Never `true`: a file a human wrote in nginx's module
                    // directory is a module *they* load, and overwriting it
                    // would silently unload something the server needs.
                    force: false,
                    task_id: ctx.task_id().map(|t| t.to_string()),
                })
                .await?;
            Ok(())
        }
    }
}

async fn apply_config(ctx: &OpContext) -> Result<()> {
    let db = ctx.db();
    let settings = WafSettings::load(db).await;
    let views = site_views(db).await?;
    let exclusions = db.waf_exclusions().await.map_err(UnihelmError::from)?;
    let global: Vec<&WafExclusion> = exclusions.iter().filter(|e| e.site_id.is_none()).collect();

    let context = rules_context(settings.default_mode, &views, &global)?;

    // ModSecurity writes here at runtime; 0700 because the persistence
    // directory holds fragments of live requests.
    ensure_dir(&paths::waf_data_dir(), 0o700)?;
    ensure_dir(
        paths::waf_audit_log().parent().unwrap_or(Path::new("/")),
        0o750,
    )?;

    let distro = ctx.distro();
    ctx.config()
        .apply(ApplyRequest {
            file: ManagedFile::nginx(paths::waf_main_conf()),
            template: "modsecurity/main.conf",
            context,
            service: "nginx",
            // Validated by nginx, not by ModSecurity: nginx parses the rules
            // file at configuration load, so `nginx -t` is what catches a rule
            // ModSecurity cannot read.
            validator: &NginxValidator,
            reloader: &UnitReloader::nginx(distro),
            post_check: None,
            force: false,
            task_id: ctx.task_id().map(|t| t.to_string()),
        })
        .await?;

    ctx.config()
        .apply(ApplyRequest {
            file: ManagedFile::nginx(paths::nginx_waf()),
            template: "nginx/waf.conf",
            context: serde_json::json!({
                "rules_file": paths::waf_main_conf().display().to_string(),
            }),
            service: "nginx",
            validator: &NginxValidator,
            reloader: &UnitReloader::nginx(distro),
            post_check: None,
            force: false,
            task_id: ctx.task_id().map(|t| t.to_string()),
        })
        .await?;
    Ok(())
}

fn ensure_dir(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(path)
        .map_err(|e| UnihelmError::internal(format!("could not create {}: {e}", path.display())))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).map_err(|e| {
        UnihelmError::internal(format!("could not set mode on {}: {e}", path.display()))
    })?;
    Ok(())
}

/// The running nginx's version, for `waf.status`. `None` when nginx is not
/// installed — which is a fact worth reporting, not an error.
async fn nginx_version() -> Option<String> {
    // nginx writes `-v` output to stderr on success, which is why this reads
    // the failure text as well as stdout.
    let out = Cmd::new("nginx")
        .arg("-v")
        .timeout(Duration::from_secs(5))
        .run()
        .await
        .ok()?;
    let text = if out.trimmed_stdout().is_empty() {
        out.failure_text()
    } else {
        out.trimmed_stdout().to_string()
    };
    text.split("nginx/")
        .nth(1)
        .map(|rest| {
            rest.split_whitespace()
                .next()
                .unwrap_or(rest)
                .trim()
                .to_string()
        })
        .filter(|v| !v.is_empty())
}

/// The error a refused enable produces.
fn refusal(blockers: &[Blocker]) -> UnihelmError {
    let detail = blockers
        .iter()
        .map(|b| format!("{}: {} {}", b.code, b.detail, b.remedy))
        .collect::<Vec<_>>()
        .join("\n\n");
    // `Conflict`, not `NotImplemented`: the request is well formed and the
    // caller is allowed to make it. What is wrong is the state of this server,
    // and 409 is the status that tells a client "change the state, then retry"
    // rather than "this panel will never do that".
    UnihelmError::new(
        ErrorCode::Conflict,
        format!("the WAF cannot be enabled on this server.\n\n{detail}"),
    )
}

// ---------------------------------------------------------------------------
// Operations
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct StatusInput {}

#[derive(Debug, Serialize)]
pub struct SiteStatus {
    pub site_id: i64,
    pub domain: String,
    pub mode: WafMode,
    pub paranoia_level: i64,
    pub rule_id: i64,
    pub exclusions: Vec<i64>,
}

#[derive(Debug, Serialize)]
pub struct CrsStatus {
    pub pinned_version: &'static str,
    pub pinned_sha256: &'static str,
    pub pin_provenance: &'static str,
    pub url: &'static str,
    /// The version actually unpacked, when one is.
    pub installed_version: Option<String>,
    pub installed_path: String,
}

#[derive(Debug, Serialize)]
pub struct StatusOutput {
    /// What the operator asked for.
    pub enabled: bool,
    /// Whether this server could run a WAF at all. `false` with a populated
    /// `blockers` is the honest answer on a stock Unihelm server today.
    pub available: bool,
    pub blockers: Vec<Blocker>,
    pub module: ModuleState,
    pub load: LoadPlan,
    pub candidates: &'static [ModuleCandidate],
    pub nginx_version: Option<String>,
    pub default_mode: WafMode,
    pub default_paranoia: i64,
    pub crs: CrsStatus,
    pub sites: Vec<SiteStatus>,
    pub global_exclusions: Vec<WafExclusion>,
    pub audit_log: String,
}

/// `waf.status` — what a WAF would need here, and what is actually configured.
pub struct Status;

#[async_trait]
impl TypedOperation for Status {
    type Input = StatusInput;
    type Output = StatusOutput;

    const NAME: &'static str = "waf.status";
    const PERMISSION: Permission = Permission::ServerManage;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, _input: Self::Input) -> Result<Self::Output> {
        let db = ctx.db();
        let settings = WafSettings::load(db).await;
        let pre = preflight(ctx.distro().info.family);
        let views = site_views(db).await?;
        let exclusions = db.waf_exclusions().await.map_err(UnihelmError::from)?;

        let mut sites = Vec::with_capacity(views.len());
        for view in &views {
            sites.push(SiteStatus {
                site_id: view.site_id,
                domain: view.hostnames.first().cloned().unwrap_or_default(),
                mode: view.mode,
                paranoia_level: view.paranoia_level,
                rule_id: rule_id_for(view.site_id)?,
                exclusions: view.exclusions.clone(),
            });
        }

        let release = paths::waf_crs_release_dir(CRS_VERSION);
        Ok(StatusOutput {
            enabled: settings.enabled,
            available: pre.is_available(),
            blockers: pre.blockers.clone(),
            module: pre.module.clone(),
            load: pre.load.clone(),
            candidates: pre.candidates,
            nginx_version: nginx_version().await,
            default_mode: settings.default_mode,
            default_paranoia: settings.default_paranoia,
            crs: CrsStatus {
                pinned_version: CRS_VERSION,
                pinned_sha256: CRS_SHA256,
                pin_provenance: CRS_PIN_PROVENANCE,
                url: CRS_URL,
                installed_version: if release.join("crs-setup.conf").exists() {
                    db.get_setting(keys::WAF_CRS_VERSION)
                        .await
                        .ok()
                        .flatten()
                        .or_else(|| Some(CRS_VERSION.to_string()))
                } else {
                    None
                },
                installed_path: release.display().to_string(),
            },
            sites,
            global_exclusions: exclusions
                .into_iter()
                .filter(|e| e.site_id.is_none())
                .collect(),
            audit_log: paths::waf_audit_log().display().to_string(),
        })
    }
}

#[derive(Debug, Deserialize)]
pub struct EnableInput {
    /// Enable the WAF for one site. Absent means "switch the WAF on for this
    /// server", which is the prerequisite for any per-site policy.
    #[serde(default)]
    pub site_id: Option<i64>,
    /// `detect` (log only) or `block`. Absent keeps the current value, and on
    /// a first enable that is `detect`.
    #[serde(default)]
    pub mode: Option<WafMode>,
    #[serde(default)]
    pub paranoia_level: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct EnableOutput {
    pub scope: String,
    pub mode: WafMode,
    pub paranoia_level: i64,
    pub crs_version: &'static str,
    pub crs_downloaded: bool,
}

/// `waf.enable` — switch the WAF on, server-wide or for one site.
pub struct Enable {
    fetcher: Arc<dyn CrsFetcher>,
}

impl Enable {
    pub fn new(fetcher: Arc<dyn CrsFetcher>) -> Self {
        Self { fetcher }
    }

    pub fn live() -> Self {
        Self::new(Arc::new(HttpsCrsFetcher))
    }
}

#[async_trait]
impl TypedOperation for Enable {
    type Input = EnableInput;
    type Output = EnableOutput;

    const NAME: &'static str = "waf.enable";
    const PERMISSION: Permission = Permission::ServerManage;
    // A download, an unpack and a validate-and-reload cycle: seconds, and worth
    // a streamed log. Idempotent — the CRS tree and the rendered files are both
    // skipped when they already say what this run would say.
    const EXECUTION: Execution = Execution::Task {
        cancellable: false,
        idempotent: true,
    };

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let db = ctx.db();
        let mut settings = WafSettings::load(db).await;

        // The preflight comes first and applies to both scopes. Enabling a
        // site's policy on a server whose WAF cannot load would write a rules
        // file nothing reads and report success.
        let pre = preflight(ctx.distro().info.family);
        if !pre.is_available() {
            return Err(refusal(&pre.blockers));
        }

        // The `load_module` line, when the panel is the one that has to write
        // it. This is also the *real* ABI check: a module built against a
        // different nginx makes `nginx -t` answer "is not binary compatible"
        // here, and the config engine restores the previous state before
        // anything reloads. No amount of package-name inspection can prove
        // compatibility — only nginx can.
        ensure_module_loaded(ctx, &pre).await?;

        let crs_downloaded = ensure_crs(ctx, self.fetcher.as_ref()).await?;

        let (scope, mode, paranoia) = match input.site_id {
            None => {
                let mode = input.mode.unwrap_or(settings.default_mode);
                if mode == WafMode::Off {
                    return Err(UnihelmError::new(
                        ErrorCode::InvalidInput,
                        "`waf.enable` with mode `off` is a contradiction; use \
                         `waf.disable` to switch the WAF off",
                    )
                    .with_field("mode"));
                }
                let paranoia = input.paranoia_level.unwrap_or(settings.default_paranoia);
                validate_paranoia(paranoia)?;
                settings.enabled = true;
                settings.default_mode = mode;
                settings.default_paranoia = paranoia;
                settings.store(db).await?;
                ctx.log(format!(
                    "WAF enabled server-wide in `{}` mode at paranoia level {paranoia}",
                    mode.as_str()
                ));
                ("server".to_string(), mode, paranoia)
            }
            Some(site_id) => {
                if !settings.enabled {
                    return Err(UnihelmError::new(
                        ErrorCode::Conflict,
                        "the WAF is not enabled on this server, so a per-site \
                         policy would have nothing to configure; run `waf.enable` \
                         without a `site_id` first",
                    )
                    .with_field("site_id"));
                }
                let mode = input.mode.unwrap_or(WafMode::Detect);
                if mode == WafMode::Off {
                    return Err(UnihelmError::new(
                        ErrorCode::InvalidInput,
                        "`waf.enable` with mode `off` is a contradiction; use \
                         `waf.disable` with this `site_id` instead",
                    )
                    .with_field("mode"));
                }
                let paranoia = input.paranoia_level.unwrap_or(settings.default_paranoia);
                validate_paranoia(paranoia)?;
                let site = require_site(db, site_id).await?;
                db.set_waf_site_policy(site_id, mode, paranoia)
                    .await
                    .map_err(UnihelmError::from)?;
                ctx.log(format!(
                    "WAF `{}` at paranoia level {paranoia} for {site} (rule {})",
                    mode.as_str(),
                    rule_id_for(site_id)?
                ));
                (site, mode, paranoia)
            }
        };

        apply_config(ctx).await?;
        Ok(EnableOutput {
            scope,
            mode,
            paranoia_level: paranoia,
            crs_version: CRS_VERSION,
            crs_downloaded,
        })
    }
}

#[derive(Debug, Deserialize)]
pub struct DisableInput {
    /// Disable for one site. Absent switches the WAF off for the whole server.
    #[serde(default)]
    pub site_id: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct DisableOutput {
    pub scope: String,
    /// True when the nginx include was actually removed (server scope only).
    pub nginx_include_removed: bool,
}

/// `waf.disable` — switch the WAF off, server-wide or for one site.
pub struct Disable;

#[async_trait]
impl TypedOperation for Disable {
    type Input = DisableInput;
    type Output = DisableOutput;

    const NAME: &'static str = "waf.disable";
    const PERMISSION: Permission = Permission::ServerManage;
    const EXECUTION: Execution = Execution::Task {
        cancellable: false,
        idempotent: true,
    };

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let db = ctx.db();
        match input.site_id {
            Some(site_id) => {
                let site = require_site(db, site_id).await?;
                // An explicit `off` row rather than deleting the policy: a
                // deleted row means "inherit the server default", and if that
                // default is `block` then deleting would *enable* the WAF on a
                // site somebody just asked to switch it off for.
                db.set_waf_site_policy(site_id, WafMode::Off, unihelm_db::waf::DEFAULT_PARANOIA)
                    .await
                    .map_err(UnihelmError::from)?;
                ctx.log(format!("WAF off for {site}"));

                // Only re-render when the server-wide WAF is on; otherwise
                // there is no rules file to update and `nginx -t` would be run
                // for nothing.
                if WafSettings::load(db).await.enabled {
                    apply_config(ctx).await?;
                }
                Ok(DisableOutput {
                    scope: site,
                    nginx_include_removed: false,
                })
            }
            None => {
                let mut settings = WafSettings::load(db).await;
                settings.enabled = false;
                settings.store(db).await?;

                // Remove the include rather than render `modsecurity off;`: if
                // the module is not loaded, *any* `modsecurity` directive is an
                // unknown directive and nginx will not start. Removal is the
                // only spelling of "off" that is safe in both worlds.
                let distro = ctx.distro();
                let removed = ctx
                    .config()
                    .remove(
                        &ManagedFile::nginx(paths::nginx_waf()),
                        "nginx",
                        &NginxValidator,
                        &UnitReloader::nginx(distro),
                    )
                    .await?;
                ctx.log(if removed {
                    "WAF disabled server-wide; the nginx include has been removed"
                } else {
                    "WAF disabled server-wide; there was no nginx include to remove"
                });
                // `main.conf` is deliberately left in place. It holds no
                // secrets, nothing reads it once the include is gone, and
                // keeping it means re-enabling shows the operator the same
                // policy they had rather than a blank one.
                Ok(DisableOutput {
                    scope: "server".to_string(),
                    nginx_include_removed: removed,
                })
            }
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct RulesSetInput {
    /// The complete exclusion list. Sending `[]` clears it.
    pub exclusions: Vec<NewWafExclusion>,
}

#[derive(Debug, Serialize)]
pub struct RulesSetOutput {
    pub exclusions: Vec<WafExclusion>,
    /// False when the WAF is off, in which case the list was stored but nothing
    /// was rendered — said out loud so an operator does not read "stored" as
    /// "in effect".
    pub applied: bool,
}

/// `waf.rules.set` — replace the rule exclusion list.
pub struct RulesSet;

#[async_trait]
impl TypedOperation for RulesSet {
    type Input = RulesSetInput;
    type Output = RulesSetOutput;

    const NAME: &'static str = "waf.rules.set";
    const PERMISSION: Permission = Permission::ServerManage;
    const EXECUTION: Execution = Execution::Task {
        cancellable: false,
        idempotent: true,
    };

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let db = ctx.db();

        for exclusion in &input.exclusions {
            if exclusion.rule_id < 1 {
                return Err(UnihelmError::new(
                    ErrorCode::InvalidInput,
                    format!("`{}` is not a rule id", exclusion.rule_id),
                )
                .with_field("rule_id"));
            }
            if exclusion.reason.trim().is_empty() {
                return Err(UnihelmError::new(
                    ErrorCode::InvalidInput,
                    format!(
                        "rule {} needs a reason: an unexplained hole in a WAF is \
                         indistinguishable from an attacker's, and it will outlive \
                         whoever added it",
                        exclusion.rule_id
                    ),
                )
                .with_field("reason"));
            }
            // Newlines would break out of the `#` comment the reason renders
            // into and could inject directives into the rules file. The
            // template escapes nothing (config files, not HTML), so this is
            // where that is stopped.
            if exclusion.reason.contains(['\n', '\r']) {
                return Err(UnihelmError::new(
                    ErrorCode::InvalidInput,
                    "a reason may not contain line breaks; it is rendered as a \
                     comment in the ModSecurity rules file",
                )
                .with_field("reason"));
            }
            if let Some(site_id) = exclusion.site_id {
                require_site(db, site_id).await?;
            }
        }

        let stored = db
            .replace_waf_exclusions(&input.exclusions)
            .await
            .map_err(UnihelmError::from)?;
        ctx.log(format!("{} rule exclusion(s) stored", stored.len()));

        let applied = WafSettings::load(db).await.enabled;
        if applied {
            apply_config(ctx).await?;
        } else {
            ctx.log("the WAF is disabled, so the list is stored but not in effect");
        }
        Ok(RulesSetOutput {
            exclusions: stored,
            applied,
        })
    }
}

/// Resolve a site id to its domain, or fail with `not_found`.
async fn require_site(db: &Db, site_id: i64) -> Result<String> {
    db.sites(&TenantScope::Global)
        .by_id(SiteId::from(site_id))
        .await
        .map_err(UnihelmError::from)?
        .map(|s| s.domain)
        .ok_or_else(|| {
            UnihelmError::new(ErrorCode::NotFound, format!("no site with id {site_id}"))
                .with_field("site_id")
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    // The two `nginx.conf` files the nginx.org packages actually ship,
    // transcribed from `nginx-1.30.4-1.el10.ngx.x86_64.rpm` and
    // `nginx_1.30.4-1~trixie_amd64.deb` on 2026-08-28. Both are identical in
    // the part that matters, which is why the WAF refuses on both families.
    const NGINX_ORG_CONF: &str = "\
user  nginx;
worker_processes  auto;

error_log  /var/log/nginx/error.log notice;
pid        /run/nginx.pid;


events {
    worker_connections  1024;
}


http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;
    include /etc/nginx/conf.d/*.conf;
}
";

    /// Debian's *own* nginx package, which does offer a main-context include.
    const DEBIAN_NGINX_CONF: &str = "\
user www-data;
worker_processes auto;
pid /run/nginx.pid;
error_log /var/log/nginx/error.log;
include /etc/nginx/modules-enabled/*.conf;

events {
        worker_connections 768;
}

http {
        include /etc/nginx/conf.d/*.conf;
}
";

    #[test]
    fn nginx_orgs_own_config_offers_nowhere_to_load_a_module_from() {
        // This is the second, independent reason the WAF refuses on a stock
        // Unihelm server, and it is a property of the file nginx.org ships.
        assert_eq!(main_context_include(NGINX_ORG_CONF), None);
        assert_eq!(
            plan_module_load(NGINX_ORG_CONF, &[]),
            LoadPlan::Nowhere,
            "load_module is a main-context directive and nginx.org's nginx.conf \
             has no main-context include"
        );
    }

    #[test]
    fn a_distro_nginx_with_a_modules_enabled_directory_gets_a_dropin() {
        assert_eq!(
            main_context_include(DEBIAN_NGINX_CONF).as_deref(),
            Some("/etc/nginx/modules-enabled/*.conf")
        );
        match plan_module_load(DEBIAN_NGINX_CONF, &[]) {
            LoadPlan::Dropin { path } => {
                assert_eq!(
                    path,
                    "/etc/nginx/modules-enabled/50-unihelm-modsecurity.conf"
                )
            }
            other => panic!("expected a drop-in plan, got {other:?}"),
        }
    }

    #[test]
    fn an_include_inside_http_is_not_a_main_context_include() {
        // The bug this prevents: `/etc/nginx/conf.d/*.conf` is included from
        // inside `http`, so a `load_module` written there would be a
        // configuration nginx refuses to start with.
        assert_eq!(main_context_include(NGINX_ORG_CONF), None);
        assert_eq!(
            main_context_include("http {\n  include /etc/nginx/conf.d/*.conf;\n}\n"),
            None
        );
        assert_eq!(
            main_context_include("stream {\n  include /etc/nginx/stream.d/*.conf;\n}\n"),
            None
        );
    }

    #[test]
    fn a_commented_out_include_is_not_a_place_to_write() {
        assert_eq!(
            main_context_include("# include /etc/nginx/modules-enabled/*.conf;\nevents {}\n"),
            None
        );
    }

    #[test]
    fn a_module_already_loaded_by_somebody_else_is_left_alone() {
        // A distro module package ships its own drop-in. Writing a second
        // `load_module` for the same module makes nginx refuse to start.
        let dropins = vec![(
            "/etc/nginx/modules-enabled/50-mod-http-modsecurity.conf".to_string(),
            "load_module modules/ngx_http_modsecurity_module.so;\n".to_string(),
        )];
        match plan_module_load(DEBIAN_NGINX_CONF, &dropins) {
            LoadPlan::AlreadyLoaded { by } => assert!(by.contains("modsecurity")),
            other => panic!("expected AlreadyLoaded, got {other:?}"),
        }
        // And when the line is in nginx.conf itself.
        let hand_edited = format!("load_module modules/{MODULE_FILENAME};\n{}", NGINX_ORG_CONF);
        assert!(matches!(
            plan_module_load(&hand_edited, &[]),
            LoadPlan::AlreadyLoaded { .. }
        ));
    }

    #[test]
    fn a_missing_module_blocks_enabling_on_both_families_and_names_the_package() {
        for family in [Family::Debian, Family::Rhel] {
            let pre = assess(
                family,
                ModuleState::Absent {
                    searched: "/etc/nginx/modules/ngx_http_modsecurity_module.so".into(),
                },
                LoadPlan::Nowhere,
            );
            assert!(!pre.is_available());
            let codes: Vec<&str> = pre.blockers.iter().map(|b| b.code).collect();
            assert_eq!(
                codes,
                vec!["module_missing"],
                "a missing module is the only blocker worth reporting; \
                 'nowhere to load it from' is noise on top of it"
            );
            let text = format!("{:?}", pre.blockers);
            assert!(
                text.contains(module_candidates(family)[0].package),
                "the refusal must name the package that would provide it: {text}"
            );
            assert!(
                text.contains("binary compatible"),
                "and must say why installing it does not help: {text}"
            );
        }
    }

    #[test]
    fn a_present_module_with_nowhere_to_load_it_is_its_own_blocker() {
        let pre = assess(
            Family::Rhel,
            ModuleState::Present {
                path: "/etc/nginx/modules/ngx_http_modsecurity_module.so".into(),
            },
            LoadPlan::Nowhere,
        );
        assert!(!pre.is_available());
        assert_eq!(
            pre.blockers.iter().map(|b| b.code).collect::<Vec<_>>(),
            vec!["no_main_context_include"]
        );
    }

    #[test]
    fn a_present_module_with_somewhere_to_load_it_is_available() {
        let pre = assess(
            Family::Debian,
            ModuleState::Present {
                path: "/etc/nginx/modules/ngx_http_modsecurity_module.so".into(),
            },
            LoadPlan::Dropin {
                path: "/etc/nginx/modules-enabled/50-unihelm-modsecurity.conf".into(),
            },
        );
        assert!(
            pre.is_available(),
            "give this code a loadable module and a place to load it and the \
             feature must work; the refusal is about this server, not about \
             the implementation"
        );
    }

    // -- rendering ----------------------------------------------------------

    fn view(site_id: i64, mode: WafMode) -> SitePolicyView {
        SitePolicyView {
            site_id,
            hostnames: vec!["example.com".into(), "www.example.com".into()],
            mode,
            paranoia_level: 1,
            exclusions: Vec::new(),
        }
    }

    #[test]
    fn a_host_pattern_is_anchored_and_escapes_the_dots() {
        let pattern = host_pattern(&["a.example.com".into(), "b.example.com".into()]).unwrap();
        assert_eq!(
            pattern,
            r"^(?:a\.example\.com|b\.example\.com)(?::[0-9]+)?$"
        );
        // Unescaped, `a.example.com` would also match `aXexampleYcom` — and
        // an attacker who controls a hostname that matches a site's rule
        // inherits that site's relaxations.
        assert!(!pattern.contains("a.example"));
    }

    #[test]
    fn a_hostname_carrying_regex_metacharacters_is_refused_not_escaped() {
        // Domain newtypes make this unreachable through the API. The check is
        // the second layer: a value that reaches a regex engine can change what
        // the pattern *means*, so an unrecognised character is a refusal.
        for hostile in [
            "evil.com|.*",
            "(?:.*)",
            "a.com\nSecRuleEngine Off",
            "a.com$",
            "*.example.com",
        ] {
            assert!(
                host_pattern(&[hostile.to_string()]).is_err(),
                "`{hostile}` must be refused"
            );
        }
    }

    #[test]
    fn a_site_switched_off_sets_no_paranoia_variables() {
        // A paranoia level next to `ruleEngine=Off` is a variable nothing
        // reads, and reading it back would tell an operator a site is
        // configured at a level that does nothing.
        let actions = site_actions(&view(1, WafMode::Off));
        assert_eq!(actions, "ctl:ruleEngine=Off");
    }

    #[test]
    fn detect_mode_logs_and_block_mode_enforces() {
        assert!(site_actions(&view(1, WafMode::Detect)).contains("ctl:ruleEngine=DetectionOnly"));
        assert!(site_actions(&view(1, WafMode::Block)).contains("ctl:ruleEngine=On"));
    }

    #[test]
    fn a_sites_exclusions_are_scoped_to_that_site_by_ctl_actions() {
        let mut v = view(7, WafMode::Block);
        v.exclusions = vec![942100, 920420];
        let actions = site_actions(&v);
        assert!(actions.contains("ctl:ruleRemoveById=942100"));
        assert!(actions.contains("ctl:ruleRemoveById=920420"));
        // `SecRuleRemoveById` would remove the rule for *every* site; the
        // per-transaction `ctl:` form is what keeps one tenant's exclusion off
        // another tenant's traffic.
        assert!(!actions.contains("SecRuleRemoveById"));
    }

    #[test]
    fn rule_ids_stay_inside_the_block_the_core_rule_set_leaves_for_local_rules() {
        assert_eq!(rule_id_for(1).unwrap(), 20_001);
        // CRS owns 900000-999999; anything Unihelm emits must stay well clear.
        assert!(rule_id_for(9_999).unwrap() < 900_000);
        assert!(rule_id_for(10_000).is_err(), "the block has a ceiling");
        assert!(rule_id_for(0).is_err(), "site ids start at 1");
        assert!(rule_id_for(-1).is_err());
    }

    #[test]
    fn a_paranoia_level_crs_does_not_define_is_refused() {
        for level in [0, 5, 100, -3] {
            assert!(validate_paranoia(level).is_err(), "level {level}");
        }
        for level in 1..=4 {
            assert!(validate_paranoia(level).is_ok(), "level {level}");
        }
    }

    #[test]
    fn the_rules_file_renders_and_orders_setup_policy_rules_and_exclusions() {
        let templates = unihelm_config::TemplateSet::load().unwrap();
        let exclusion = WafExclusion {
            id: 1,
            site_id: None,
            rule_id: 942100,
            reason: "the page editor posts SQL".into(),
            created_at: time::OffsetDateTime::now_utc(),
        };
        let context =
            rules_context(WafMode::Detect, &[view(3, WafMode::Block)], &[&exclusion]).unwrap();
        let rendered = templates.render("modsecurity/main.conf", &context).unwrap();

        let at = |needle: &str| {
            rendered
                .find(needle)
                .unwrap_or_else(|| panic!("missing from the rendered file: {needle}"))
        };
        // The ordering is load-bearing: a per-site rule after the CRS rules
        // could not change the engine mode for the transaction, and a
        // SecRuleRemoveById before them would name a rule that does not exist
        // yet.
        assert!(at("SecRuleEngine DetectionOnly") < at("crs-setup.conf"));
        assert!(at("crs-setup.conf") < at("id:20003"));
        assert!(at("id:20003") < at("rules/*.conf"));
        assert!(at("rules/*.conf") < at("SecRuleRemoveById 942100"));
    }

    #[test]
    fn a_server_with_no_per_site_policy_renders_a_file_with_no_rules() {
        let templates = unihelm_config::TemplateSet::load().unwrap();
        let context = rules_context(WafMode::Detect, &[], &[]).unwrap();
        let rendered = templates.render("modsecurity/main.conf", &context).unwrap();
        assert!(!rendered.contains("SecRule REQUEST_HEADERS:Host"));
        assert!(rendered.contains("crs-setup.conf"));
        // Strict undefined would have failed the render if a variable were
        // missing; this asserts the empty case is a *file*, not an error.
        assert!(rendered.contains("SecRuleEngine"));
    }

    #[test]
    fn the_nginx_include_points_at_the_rules_file_and_nothing_else() {
        let templates = unihelm_config::TemplateSet::load().unwrap();
        let rendered = templates
            .render(
                "nginx/waf.conf",
                &serde_json::json!({ "rules_file": "/etc/unihelm/waf/main.conf" }),
            )
            .unwrap();
        assert!(rendered.contains("modsecurity on;"));
        assert!(rendered.contains("modsecurity_rules_file /etc/unihelm/waf/main.conf;"));
        // No server block: the whole design is that vhosts are untouched.
        assert!(!rendered.contains("server {"));
    }

    #[test]
    fn the_load_module_dropin_carries_exactly_one_load_module_line() {
        // A second `load_module` for a module nginx has already loaded makes it
        // refuse to start, so this file must never grow a fallback line.
        let templates = unihelm_config::TemplateSet::load().unwrap();
        let rendered = templates
            .render(
                "nginx/load-module.conf",
                &serde_json::json!({
                    "module_path": "/etc/nginx/modules/ngx_http_modsecurity_module.so"
                }),
            )
            .unwrap();
        let directives: Vec<&str> = rendered
            .lines()
            .filter(|l| l.trim_start().starts_with("load_module"))
            .collect();
        assert_eq!(
            directives,
            vec!["load_module /etc/nginx/modules/ngx_http_modsecurity_module.so;"]
        );
    }

    // -- through the registry -----------------------------------------------

    #[tokio::test]
    async fn a_customer_cannot_read_or_change_the_waf() {
        use crate::registry::testing::{auth_for, registry};
        use unihelm_core::Role;

        let (reg, _, customer) = registry().await;
        for (op, input) in [
            ("waf.status", serde_json::json!({})),
            ("waf.enable", serde_json::json!({})),
            ("waf.disable", serde_json::json!({})),
            ("waf.rules.set", serde_json::json!({ "exclusions": [] })),
        ] {
            let err = reg
                .dispatch(op, &auth_for(customer, Role::Customer), input, None)
                .await
                .unwrap_err();
            assert_eq!(err.code, ErrorCode::PermissionDenied, "{op}");
        }
    }

    #[tokio::test]
    async fn enabling_on_a_host_with_no_module_refuses_and_names_what_is_missing() {
        use crate::registry::testing::{auth_for, registry};
        use unihelm_core::Role;

        // Guarded on the observed state rather than assumed, so this never
        // becomes a flaky assertion on a machine that does happen to have a
        // connector installed.
        if module_state().is_present() {
            return;
        }

        let (reg, admin, _) = registry().await;
        let err = reg
            .dispatch(
                "waf.enable",
                &auth_for(admin, Role::Admin),
                serde_json::json!({}),
                None,
            )
            .await
            .unwrap_err();

        assert_eq!(
            err.code,
            ErrorCode::Conflict,
            "the request is well formed and permitted; it is the server that \
             cannot do it, which is what 409 means"
        );
        assert!(
            err.detail.contains("nginx.org"),
            "the refusal must say where nginx came from: {}",
            err.detail
        );
        assert!(
            err.detail.contains("module_missing"),
            "and carry the machine-readable blocker code: {}",
            err.detail
        );
    }

    #[tokio::test]
    async fn nothing_is_written_and_no_setting_changes_when_the_waf_refuses() {
        use crate::registry::testing::{auth_for, registry};
        use unihelm_core::Role;

        if module_state().is_present() {
            return;
        }

        let (reg, admin, _) = registry().await;
        let _ = reg
            .dispatch(
                "waf.enable",
                &auth_for(admin, Role::Admin),
                serde_json::json!({ "mode": "block", "paranoia_level": 4 }),
                None,
            )
            .await;

        // A refusal that had already flipped `waf.enabled` would leave the
        // panel reporting a WAF that does not exist.
        let settings = WafSettings::load(&reg.services().db).await;
        assert!(!settings.enabled);
        assert_eq!(settings.default_mode, WafMode::Detect);
    }

    #[tokio::test]
    async fn an_exclusion_reason_that_would_escape_its_comment_is_refused() {
        use crate::registry::testing::{auth_for, registry};
        use unihelm_core::Role;

        let (reg, admin, _) = registry().await;
        // The reason is rendered as a `#` comment in the rules file. A newline
        // would end the comment and put whatever follows into the rule set.
        for reason in ["ok\nSecRuleEngine Off", "ok\rSecRuleEngine Off", "   "] {
            let err = reg
                .dispatch(
                    "waf.rules.set",
                    &auth_for(admin, Role::Admin),
                    serde_json::json!({
                        "exclusions": [{ "rule_id": 942100, "reason": reason }]
                    }),
                    None,
                )
                .await
                .unwrap_err();
            assert_eq!(err.code, ErrorCode::InvalidInput, "{reason:?}");
        }

        // And nothing was stored on the way to refusing.
        assert!(reg.services().db.waf_exclusions().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn an_exclusion_naming_a_site_that_does_not_exist_is_not_found() {
        use crate::registry::testing::{auth_for, registry};
        use unihelm_core::Role;

        let (reg, admin, _) = registry().await;
        let err = reg
            .dispatch(
                "waf.rules.set",
                &auth_for(admin, Role::Admin),
                serde_json::json!({
                    "exclusions": [{ "site_id": 4242, "rule_id": 942100, "reason": "x" }]
                }),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::NotFound);
    }

    // -- the archive --------------------------------------------------------

    fn tar_gz(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        for (name, body) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(body.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append_data(&mut header, name, *body).unwrap();
        }
        let tar = builder.into_inner().unwrap();
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        std::io::Write::write_all(&mut encoder, &tar).unwrap();
        encoder.finish().unwrap()
    }

    #[test]
    fn a_wrong_checksum_stops_the_core_rule_set_before_anything_is_unpacked() {
        let bytes = b"not the core rule set";
        let err = verify_crs(bytes, CRS_SHA256).unwrap_err();
        assert_eq!(err.code, ErrorCode::PackageBackendFailed);
        assert!(err.detail.contains("Nothing was unpacked"));
        assert!(
            err.detail.contains("do not bypass"),
            "the message has to say what it is protecting"
        );
    }

    #[test]
    fn the_pinned_checksum_is_a_sha256_and_the_url_carries_the_pinned_version() {
        assert_eq!(CRS_SHA256.len(), 64);
        assert!(CRS_SHA256.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(
            CRS_URL.contains(CRS_VERSION),
            "the version, URL and checksum move together or the pin means nothing"
        );
        assert!(CRS_URL.starts_with("https://"));
    }

    /// A tar archive built byte by byte.
    ///
    /// The `tar` crate's `Builder` refuses to *write* an absolute or `..` path,
    /// which is the right default and exactly why it cannot produce the archive
    /// these tests need. A real attacker is not using `tar::Builder`, so neither
    /// is the fixture: this writes the 512-byte ustar header itself.
    fn hostile_tar_gz(name: &str, body: &[u8]) -> Vec<u8> {
        let mut header = [0u8; 512];
        let put = |header: &mut [u8; 512], at: usize, bytes: &[u8]| {
            header[at..at + bytes.len()].copy_from_slice(bytes);
        };
        put(&mut header, 0, name.as_bytes()); // name[100]
        put(&mut header, 100, b"0000644\0"); // mode
        put(&mut header, 108, b"0000000\0"); // uid
        put(&mut header, 116, b"0000000\0"); // gid
        put(
            &mut header,
            124,
            format!("{:011o}\0", body.len()).as_bytes(),
        ); // size[12]
        put(&mut header, 136, b"00000000000\0"); // mtime
        header[148..156].fill(b' '); // checksum field, blank while summing
        header[156] = b'0'; // typeflag: regular file
        put(&mut header, 257, b"ustar\0"); // magic
        put(&mut header, 263, b"00"); // version
        let sum: u32 = header.iter().map(|b| u32::from(*b)).sum();
        put(&mut header, 148, format!("{sum:06o}\0 ").as_bytes());

        let mut tar = header.to_vec();
        tar.extend_from_slice(body);
        tar.resize(tar.len().div_ceil(512) * 512, 0);
        tar.extend_from_slice(&[0u8; 1024]); // two empty blocks end an archive

        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        std::io::Write::write_all(&mut encoder, &tar).unwrap();
        encoder.finish().unwrap()
    }

    #[test]
    fn an_archive_entry_that_walks_out_of_the_destination_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let evil = hostile_tar_gz("../../etc/nginx/nginx.conf", b"owned");
        let err = extract_crs(&evil, dir.path()).unwrap_err();
        assert!(err.detail.contains("walks out with .."), "{}", err.detail);
        assert!(
            !dir.path().parent().unwrap().join("etc").exists(),
            "nothing may be written outside the destination"
        );
    }

    #[test]
    fn an_absolute_archive_entry_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let evil = hostile_tar_gz("/etc/unihelm/secret.key", b"owned");
        let err = extract_crs(&evil, dir.path()).unwrap_err();
        assert!(err.detail.contains("absolute path"), "{}", err.detail);
        assert!(!Path::new("/etc/unihelm/secret.key.test").exists());
    }

    #[test]
    fn a_symlink_entry_is_refused_rather_than_followed() {
        // The classic escape: unpack a symlink pointing outside the tree, then
        // unpack a file "into" it.
        let dir = tempfile::tempdir().unwrap();
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_size(0);
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_mode(0o777);
        builder
            .append_link(&mut header, "escape", "/etc/unihelm")
            .unwrap();
        let tar = builder.into_inner().unwrap();
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        std::io::Write::write_all(&mut encoder, &tar).unwrap();
        let evil = encoder.finish().unwrap();

        let err = extract_crs(&evil, dir.path()).unwrap_err();
        assert!(err.detail.contains("Symlink"), "{}", err.detail);
        assert!(!dir.path().join("escape").exists());
    }

    #[test]
    fn a_well_formed_archive_unpacks_and_reports_what_it_wrote() {
        let dir = tempfile::tempdir().unwrap();
        let good = tar_gz(&[
            (
                "coreruleset-4.29.0/crs-setup.conf.example",
                b"SecAction" as &[u8],
            ),
            (
                "coreruleset-4.29.0/rules/REQUEST-901-INITIALIZATION.conf",
                b"SecRule",
            ),
        ]);
        assert_eq!(extract_crs(&good, dir.path()).unwrap(), 2);
        assert!(
            dir.path()
                .join("coreruleset-4.29.0/rules/REQUEST-901-INITIALIZATION.conf")
                .exists()
        );
    }
}
