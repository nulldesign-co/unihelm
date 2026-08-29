//! `security.posture` — the one-page security advisor (spec §11.9, §11.15).
//!
//! # What this is allowed to say
//!
//! Every finding here is something the panel can **assert from evidence it
//! actually gathered**, not something it infers from a default it believes is
//! probably in place. That constraint is what separates an advisor an operator
//! trusts from a checklist they learn to ignore, and it is why this module is
//! shaped the way it is: [`gather`] does I/O and produces a [`PostureFacts`]
//! that says, per fact, what was observed *or that it could not be observed*;
//! [`evaluate`] is a pure function from those facts to findings and knows
//! nothing about files or commands.
//!
//! A check whose evidence could not be gathered produces a
//! [`Severity::Unknown`] finding naming what failed. It never produces silence,
//! and it never produces a clean tick. "We could not read sshd's configuration"
//! and "sshd is configured safely" are different answers, and an advisor that
//! renders them identically is worse than no advisor at all — it converts an
//! unknown into a reassurance.
//!
//! # Why sshd is read twice
//!
//! The effective SSH configuration is not any one file: `sshd_config` has an
//! `Include /etc/ssh/sshd_config.d/*.conf` on both families (it is how Ferrum's
//! own chrooted-SFTP block gets in — `ferrum_config::paths::sshd_dropin`), and
//! within sshd's "first value wins" semantics the include position decides
//! which file's `PasswordAuthentication` is the one in force. `sshd -T` prints
//! the settled answer, so it is asked first. When it cannot run — sshd not
//! installed, or the agent somehow not root — the files are parsed directly and
//! the finding says which route produced it, because the file-parsing route is
//! an approximation of sshd's own resolution and an operator deserves to know
//! which one they are looking at.
//!
//! Both routes use argv arrays and direct file reads. There is no shell
//! anywhere in this module (spec §12 rule 2), which also means no
//! `sshd -T | grep`: the parsing happens in Rust, where it can be tested.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::time::Duration;

use async_trait::async_trait;
use ferrum_config::paths;
use ferrum_core::{Permission, Result, TenantScope};
use ferrum_db::Db;
use ferrum_distro::{Cmd, Distro, Family};
use serde::{Deserialize, Serialize};

use crate::fwops::SentinelSettings;
use crate::registry::{Execution, OpContext, TypedOperation};

/// The port MariaDB listens on. A constant rather than a literal in the check
/// so the finding, the remedy and the probe cannot drift apart.
const MYSQL_PORT: u16 = 3306;

/// A panel certificate with fewer days than this left is worth saying out loud.
///
/// Fourteen, not thirty: the renewal scheduler already tries at thirty days
/// (`Certificate::due_for_renewal`), so a certificate at twenty-nine days is
/// normal and flagging it would teach an operator to ignore this page. Fourteen
/// means renewal has been failing for two weeks.
const PANEL_CERT_WARN_DAYS: i64 = 14;

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Reachable from the internet and exploitable without a credential, or a
    /// tenant-isolation failure.
    Critical,
    /// A materially larger attack surface than the panel's own defaults.
    High,
    /// Worth fixing; not what an attacker would use first.
    Medium,
    /// A hardening opportunity.
    Low,
    /// The check could not be run. Deliberately *not* the same as "clean".
    Unknown,
}

impl Severity {
    pub const fn as_str(self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
            Severity::Unknown => "unknown",
        }
    }
}

/// One thing worth telling an operator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    /// Stable identifier. The UI keys its "fix this" action on it, and it is
    /// what makes a finding referenceable in a support conversation.
    pub id: &'static str,
    pub severity: Severity,
    /// A short statement of *what is true*, not of what to do.
    pub title: String,
    /// Why it matters, in one sentence, in language a hosting customer would
    /// follow. No acronyms that are not expanded, no "consider hardening".
    pub risk: String,
    /// What to do about it, concretely enough to act on.
    pub remedy: String,
    /// The site, address or file this is about, when it is about one thing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
}

// ---------------------------------------------------------------------------
// The facts
// ---------------------------------------------------------------------------

/// What one observation produced: a value, or the reason there is none.
///
/// An `Option` would have collapsed "sshd says no" and "we could not ask sshd"
/// into the same `None`, and the whole point of this module is that those two
/// must not render the same.
///
/// Adjacently tagged, not internally tagged. An internal tag can only be folded
/// into a variant that serialises as a map, so `Known(T)` worked for
/// `SshdFacts` and failed at runtime for the two fields whose `T` is a sequence
/// or a number — `security.posture` could not return at all. Nothing consumed
/// the flattened shape, so the discriminator moved beside the value rather than
/// into it, which is uniform for every `T`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum Observed<T> {
    Known(T),
    Unavailable { reason: String },
}

impl<T> Observed<T> {
    pub fn known(&self) -> Option<&T> {
        match self {
            Observed::Known(v) => Some(v),
            Observed::Unavailable { .. } => None,
        }
    }
}

/// The effective sshd configuration, as far as it could be determined.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SshdFacts {
    /// `PasswordAuthentication yes`.
    pub password_authentication: bool,
    /// `KbdInteractiveAuthentication yes` — the PAM route to the same place.
    /// A server with `PasswordAuthentication no` and this left on still accepts
    /// passwords on most distributions, which is the trap this exists to catch.
    pub keyboard_interactive: bool,
    /// `PermitRootLogin yes`. `prohibit-password` and `forced-commands-only`
    /// are not this: they permit a key, not a password, and are a normal way to
    /// run a server.
    pub permit_root_login: String,
    /// How this was established, for the finding to disclose.
    pub source: SshdSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SshdSource {
    /// `sshd -T`: sshd's own settled answer, includes resolved.
    SshdT,
    /// `sshd_config` plus `sshd_config.d/*.conf`, parsed here. An
    /// approximation of sshd's resolution, and labelled as one.
    Files,
}

/// A listening TCP socket that is not on loopback.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PublicListener {
    pub address: String,
    pub port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FirewallFacts {
    /// `firewalld`, `ufw`, `nftables`, or `none`.
    pub backend: String,
    /// `None` when the backend could not be asked.
    pub active: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PanelTlsFacts {
    pub domain: Option<String>,
    /// `None` when no certificate row exists at all.
    pub days_remaining: Option<i64>,
    pub status: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SiteCertFact {
    pub site_id: i64,
    pub domain: String,
    pub has_certificate: bool,
}

/// Everything the checks reason over. Gathering is separate from judging so the
/// judging can be tested exhaustively without a machine to gather from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PostureFacts {
    pub sshd: Observed<SshdFacts>,
    pub firewall: FirewallFacts,
    /// Non-loopback listeners on [`MYSQL_PORT`].
    pub mysql_listeners: Observed<Vec<PublicListener>>,
    pub panel_tls: PanelTlsFacts,
    pub sites: Vec<SiteCertFact>,
    pub sentinel_enabled: bool,
    /// How many pending updates the package manager considers security
    /// updates.
    pub security_updates: Observed<usize>,
}

// ---------------------------------------------------------------------------
// sshd
// ---------------------------------------------------------------------------

/// Parse `sshd -T` output.
///
/// The format is one `keyword value` per line, keywords lowercased by sshd
/// itself. Unset keys keep the caller's defaults, which are OpenSSH's own
/// (`PasswordAuthentication yes`, `KbdInteractiveAuthentication yes`,
/// `PermitRootLogin prohibit-password`) — the safe direction is to assume the
/// upstream default rather than the safe value, because a check that assumes
/// safety when it sees nothing is a check that reports safety on a file it
/// failed to understand.
pub fn parse_sshd_t(output: &str) -> SshdFacts {
    let mut settings: BTreeMap<&str, &str> = BTreeMap::new();
    for line in output.lines() {
        let line = line.trim();
        if let Some((key, value)) = line.split_once(char::is_whitespace) {
            // sshd -T prints multi-valued keywords repeatedly; first wins here
            // for the same reason it wins in sshd's own resolution.
            settings.entry(key.trim()).or_insert(value.trim());
        }
    }
    let yes = |key: &str, default: bool| {
        settings
            .get(key)
            .map(|v| v.eq_ignore_ascii_case("yes"))
            .unwrap_or(default)
    };
    SshdFacts {
        password_authentication: yes("passwordauthentication", true),
        keyboard_interactive: yes("kbdinteractiveauthentication", true),
        permit_root_login: settings
            .get("permitrootlogin")
            .map(|v| v.to_ascii_lowercase())
            .unwrap_or_else(|| "prohibit-password".to_string()),
        source: SshdSource::SshdT,
    }
}

/// Parse `sshd_config`-style files in the order sshd would read them.
///
/// **First value wins**, which is sshd's rule and the opposite of nearly every
/// other configuration format — a `PasswordAuthentication no` at the bottom of
/// `sshd_config` does nothing if a drop-in already said `yes`. Getting this
/// backwards would make the advisor confidently wrong, so the caller passes
/// files already ordered the way sshd includes them and this function takes the
/// first occurrence of each keyword.
///
/// `Match` blocks are ignored, and the finding says so: everything after a
/// `Match` applies conditionally, and a conditional answer is not something to
/// summarise in one line. (Ferrum's own SFTP drop-in is exactly such a block,
/// which is why this matters here and not only in theory.)
pub fn parse_sshd_files(ordered: &[(String, String)]) -> SshdFacts {
    let mut settings: BTreeMap<String, String> = BTreeMap::new();
    for (_name, contents) in ordered {
        let mut in_match = false;
        for raw in contents.lines() {
            let line = raw.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let mut parts = line.splitn(2, char::is_whitespace);
            let key = parts.next().unwrap_or("").to_ascii_lowercase();
            let value = parts.next().unwrap_or("").trim().to_string();
            if key == "match" {
                in_match = true;
                continue;
            }
            if in_match {
                continue;
            }
            settings.entry(key).or_insert(value);
        }
    }
    let yes = |key: &str, default: bool| {
        settings
            .get(key)
            .map(|v| v.eq_ignore_ascii_case("yes"))
            .unwrap_or(default)
    };
    SshdFacts {
        password_authentication: yes("passwordauthentication", true),
        keyboard_interactive: yes("kbdinteractiveauthentication", true),
        permit_root_login: settings
            .get("permitrootlogin")
            .cloned()
            .map(|v| v.to_ascii_lowercase())
            .unwrap_or_else(|| "prohibit-password".to_string()),
        source: SshdSource::Files,
    }
}

/// Read `sshd_config` and every `sshd_config.d/*.conf`, ordered as sshd sees
/// them: the main file first (its `Include` is normally its first line, and
/// first-value-wins means order inside the directory is lexical).
fn read_sshd_files() -> Vec<(String, String)> {
    let mut out = Vec::new();
    let main = paths::sshd_config();
    if let Ok(contents) = std::fs::read_to_string(&main) {
        // The drop-ins come first when `Include` precedes the settings, which
        // is the layout both families ship. Rather than model sshd's include
        // position, the directory is read first: that matches the shipped
        // layout and is the conservative direction — a drop-in Ferrum or an
        // operator added is the value actually in force.
        out.push((main.display().to_string(), contents));
    }
    let mut dropins = Vec::new();
    if let Ok(entries) = std::fs::read_dir(paths::sshd_config_dir()) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("conf") {
                continue;
            }
            if let Ok(contents) = std::fs::read_to_string(&path) {
                dropins.push((path.display().to_string(), contents));
            }
        }
    }
    dropins.sort();
    // Lexical drop-ins ahead of the main file: first value wins, and that is
    // how a `50-ferrum.conf` overrides a stock `sshd_config`.
    dropins.extend(out);
    dropins
}

async fn gather_sshd() -> Observed<SshdFacts> {
    // `sshd -T` needs no connection spec for the global settings; it prints the
    // effective configuration and exits. argv, never a pipeline (spec §12
    // rule 2) — the grepping happens in `parse_sshd_t`, where it is testable.
    match Cmd::new("sshd")
        .arg("-T")
        .timeout(Duration::from_secs(10))
        .run()
        .await
    {
        Ok(out) if out.success() && !out.stdout.trim().is_empty() => {
            Observed::Known(parse_sshd_t(&out.stdout))
        }
        _ => {
            let files = read_sshd_files();
            if files.is_empty() {
                Observed::Unavailable {
                    reason: format!(
                        "`sshd -T` did not run and neither {} nor {} could be read",
                        paths::sshd_config().display(),
                        paths::sshd_config_dir().display()
                    ),
                }
            } else {
                Observed::Known(parse_sshd_files(&files))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Listening sockets
// ---------------------------------------------------------------------------

/// Non-loopback listeners on `port`, parsed from a `/proc/net/tcp`-format table.
///
/// Reading `/proc` rather than running `ss`: this is a security check, and a
/// check that depends on a tool being installed and its output format holding
/// still is a check that fails open on the day it matters. `/proc/net/tcp` has
/// been stable since Linux 2.2.
///
/// Columns: `sl local_address rem_address st ...`, where `local_address` is
/// `HEX_ADDR:HEX_PORT` (little-endian 32-bit words) and `st` is `0A` for
/// LISTEN.
pub fn listeners_on_port(proc_net_tcp: &str, port: u16) -> Vec<PublicListener> {
    let mut out = Vec::new();
    for line in proc_net_tcp.lines().skip(1) {
        let mut fields = line.split_whitespace();
        let _sl = fields.next();
        let Some(local) = fields.next() else { continue };
        let _remote = fields.next();
        let Some(state) = fields.next() else { continue };
        if state != "0A" {
            continue;
        }
        let Some((addr_hex, port_hex)) = local.rsplit_once(':') else {
            continue;
        };
        let Ok(found_port) = u16::from_str_radix(port_hex, 16) else {
            continue;
        };
        if found_port != port {
            continue;
        }
        let Some(addr) = parse_proc_address(addr_hex) else {
            continue;
        };
        // The unspecified address means "every interface", which includes every
        // public one — the exact state the live AlmaLinux box was found in.
        if addr.is_loopback() {
            continue;
        }
        out.push(PublicListener {
            address: addr.to_string(),
            port: found_port,
        });
    }
    out
}

/// `/proc/net/tcp` addresses are hex little-endian 32-bit words: 8 hex digits
/// for IPv4, 32 for IPv6.
fn parse_proc_address(hex: &str) -> Option<IpAddr> {
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
        .collect::<std::result::Result<_, _>>()
        .ok()?;
    match bytes.len() {
        4 => Some(IpAddr::from([bytes[3], bytes[2], bytes[1], bytes[0]])),
        16 => {
            let mut octets = [0u8; 16];
            for (word, chunk) in bytes.as_chunks::<4>().0.iter().enumerate() {
                octets[word * 4] = chunk[3];
                octets[word * 4 + 1] = chunk[2];
                octets[word * 4 + 2] = chunk[1];
                octets[word * 4 + 3] = chunk[0];
            }
            let v6 = std::net::Ipv6Addr::from(octets);
            // An IPv4-mapped listener is the IPv4 address it maps to; reporting
            // `::ffff:0.0.0.0` would be true and useless.
            Some(match v6.to_ipv4_mapped() {
                Some(v4) => IpAddr::V4(v4),
                None => IpAddr::V6(v6),
            })
        }
        _ => None,
    }
}

fn gather_listeners(port: u16) -> Observed<Vec<PublicListener>> {
    let mut found = Vec::new();
    let mut read_any = false;
    for path in ["/proc/net/tcp", "/proc/net/tcp6"] {
        if let Ok(text) = std::fs::read_to_string(path) {
            read_any = true;
            found.extend(listeners_on_port(&text, port));
        }
    }
    if read_any {
        Observed::Known(found)
    } else {
        Observed::Unavailable {
            reason: "/proc/net/tcp is not readable on this host, so listening \
                     sockets could not be enumerated"
                .to_string(),
        }
    }
}

// ---------------------------------------------------------------------------
// Pending security updates
// ---------------------------------------------------------------------------

/// Count security updates in `apt-get --simulate upgrade` output.
///
/// Each pending install prints `Inst <pkg> [old] (new Origin:suite [arch])`.
/// A security update names a suite containing `security` — `Debian-Security`,
/// `noble-security`. Counting only those is the difference between "17 packages
/// have newer versions" (which is always true and always ignored) and "3
/// security updates are pending" (which is worth interrupting somebody for).
pub fn count_apt_security_updates(output: &str) -> usize {
    output
        .lines()
        .filter(|l| l.starts_with("Inst "))
        .filter(|l| l.to_ascii_lowercase().contains("security"))
        .count()
}

/// Count security updates in `dnf --security check-update` output.
///
/// dnf prints one `name.arch  version  repo` line per update, plus headers,
/// blank lines and an `Obsoleting Packages` section. Lines are counted only
/// while they have three whitespace-separated fields and do not begin at column
/// zero with a section heading — dnf indents nothing, so the heading test is
/// "the line ends with a colon" or "it is one of the known section names".
pub fn count_dnf_security_updates(output: &str) -> usize {
    let mut count = 0;
    for line in output.lines() {
        let trimmed = line.trim_end();
        if trimmed.is_empty() || trimmed.ends_with(':') {
            continue;
        }
        if trimmed.starts_with("Last metadata")
            || trimmed.starts_with("Obsoleting")
            || trimmed.starts_with("Security:")
        {
            continue;
        }
        // `name.arch version repo` — exactly three fields, and the first must
        // carry the `.arch` suffix every RPM name has here.
        let fields: Vec<&str> = trimmed.split_whitespace().collect();
        if fields.len() == 3 && fields[0].contains('.') {
            count += 1;
        }
    }
    count
}

/// Ask the package manager, from cached metadata only.
///
/// `--cacheonly` / `--no-download`: this runs inside a read operation the UI
/// calls on page load, and a check that goes to the network turns a dashboard
/// into a thirty-second wait on a slow mirror. The consequence — a server whose
/// package index has not been refreshed reports stale counts — is why the
/// finding names the moment the metadata is from rather than claiming
/// freshness it does not have.
async fn gather_security_updates(distro: &Distro) -> Observed<usize> {
    let timeout = Duration::from_secs(20);
    let result = match distro.info.family {
        Family::Debian => {
            Cmd::new("apt-get")
                .args(["--simulate", "--quiet", "--no-download", "upgrade"])
                .env("DEBIAN_FRONTEND", "noninteractive")
                .timeout(timeout)
                .run()
                .await
        }
        Family::Rhel => {
            // `check-update` exits 100 when updates exist and 0 when none do,
            // so a non-zero status is not a failure here.
            Cmd::new("dnf")
                .args(["--cacheonly", "--quiet", "--security", "check-update"])
                .timeout(timeout)
                .run()
                .await
        }
    };

    match result {
        Ok(out) => {
            let counted = match distro.info.family {
                Family::Debian => count_apt_security_updates(&out.stdout),
                Family::Rhel => count_dnf_security_updates(&out.stdout),
            };
            // apt's simulate exits 0 even with nothing to do; dnf's 100 means
            // "updates found". Anything else from apt is a real failure.
            let failed = match distro.info.family {
                Family::Debian => !out.success(),
                Family::Rhel => !matches!(out.status, 0 | 100),
            };
            if failed {
                Observed::Unavailable {
                    reason: format!(
                        "the package manager could not be asked about pending \
                         updates: {}",
                        out.failure_text()
                    ),
                }
            } else {
                Observed::Known(counted)
            }
        }
        Err(e) => Observed::Unavailable {
            reason: format!("the package manager could not be asked about pending updates: {e}"),
        },
    }
}

// ---------------------------------------------------------------------------
// Gathering
// ---------------------------------------------------------------------------

/// Look at this machine.
pub async fn gather(distro: &Distro, db: &Db) -> Result<PostureFacts> {
    let firewall = FirewallFacts {
        backend: distro.fw.name().to_string(),
        active: distro.fw.is_active().await.ok(),
    };

    let panel_certificate = db.panel_certificate().await.ok().flatten();
    let panel_tls = PanelTlsFacts {
        domain: db
            .get_setting(ferrum_db::panel::DOMAIN_KEY)
            .await
            .ok()
            .flatten(),
        days_remaining: panel_certificate.as_ref().and_then(|c| c.days_remaining()),
        status: panel_certificate
            .as_ref()
            .map(|c| c.status.as_str().to_string()),
    };

    // `TenantScope::Global`: this is a server-wide report behind
    // `Permission::ServerRead`, and a scoped view would silently omit the
    // uncertificated sites belonging to everybody else.
    let sites_repo = db.sites(&TenantScope::Global);
    let mut sites = Vec::new();
    for site in sites_repo.list(500, 0).await.unwrap_or_default() {
        let has_certificate = db
            .active_certificate_for_site(site.id)
            .await
            .ok()
            .flatten()
            .is_some();
        sites.push(SiteCertFact {
            site_id: site.id.get(),
            domain: site.domain.clone(),
            has_certificate,
        });
    }

    Ok(PostureFacts {
        sshd: gather_sshd().await,
        firewall,
        mysql_listeners: gather_listeners(MYSQL_PORT),
        panel_tls,
        sites,
        sentinel_enabled: SentinelSettings::load(db).await.enabled,
        security_updates: gather_security_updates(distro).await,
    })
}

// ---------------------------------------------------------------------------
// Judging
// ---------------------------------------------------------------------------

/// Turn facts into findings. Pure — every branch is reachable from a test.
///
/// Ordered most severe first, and within a severity in the order the checks are
/// written: an operator reads the top of this list and stops, so the ordering
/// is part of the product.
pub fn evaluate(facts: &PostureFacts) -> Vec<Finding> {
    let mut findings = Vec::new();

    // -- SSH ----------------------------------------------------------------
    match &facts.sshd {
        Observed::Unavailable { reason } => findings.push(Finding {
            id: "ssh.unknown",
            severity: Severity::Unknown,
            title: "The SSH configuration could not be read".into(),
            risk: "The panel cannot tell whether this server accepts password \
                   logins over SSH, which is the single most common way a \
                   hosting server is taken over."
                .into(),
            remedy: format!("Check by hand: `sshd -T`. ({reason})"),
            subject: None,
        }),
        Observed::Known(sshd) => {
            let via = match sshd.source {
                SshdSource::SshdT => "reported by `sshd -T`",
                SshdSource::Files => {
                    "parsed from sshd_config and its drop-ins; `sshd -T` could \
                     not be run, so `Match` blocks were not evaluated"
                }
            };
            if sshd.password_authentication || sshd.keyboard_interactive {
                let which = match (sshd.password_authentication, sshd.keyboard_interactive) {
                    (true, true) => "PasswordAuthentication and KbdInteractiveAuthentication",
                    (true, false) => "PasswordAuthentication",
                    // The trap: turning PasswordAuthentication off is widely
                    // believed to be enough, and on most distributions it is
                    // not, because PAM keyboard-interactive still asks for the
                    // same password.
                    (false, true) => {
                        "KbdInteractiveAuthentication (which still accepts passwords \
                                      through PAM even with PasswordAuthentication off)"
                    }
                    (false, false) => unreachable!("guarded by the condition above"),
                };
                findings.push(Finding {
                    id: "ssh.password_auth",
                    severity: Severity::High,
                    title: format!("SSH accepts password logins ({which} are on)"),
                    risk: "Anybody on the internet can try passwords against \
                           every account on this server, for as long as they \
                           like. Automated guessing runs constantly on every \
                           public SSH port."
                        .into(),
                    remedy: format!(
                        "Add an SSH key for your account, confirm you can log in \
                         with it, then set `PasswordAuthentication no` and \
                         `KbdInteractiveAuthentication no` in \
                         /etc/ssh/sshd_config.d/ and reload sshd. Turn Sentinel on \
                         as well, so guessing attempts are banned rather than \
                         merely slowed. ({via})"
                    ),
                    subject: None,
                });
            }
            // `prohibit-password` and `forced-commands-only` permit a key, not
            // a password, and are how most servers are legitimately run.
            if sshd.permit_root_login == "yes" {
                findings.push(Finding {
                    id: "ssh.root_login",
                    severity: if sshd.password_authentication || sshd.keyboard_interactive {
                        // Root plus passwords is the combination that gets
                        // servers taken over, so it outranks either alone.
                        Severity::Critical
                    } else {
                        Severity::Medium
                    },
                    title: "SSH permits logging in directly as root".into(),
                    risk: "An attacker guessing one password gets the whole \
                           machine in one step, and every action afterwards is \
                           logged as `root` with nothing to say who it really \
                           was."
                        .into(),
                    remedy: format!(
                        "Set `PermitRootLogin prohibit-password` (key-only) or `no` \
                         in /etc/ssh/sshd_config.d/ and reload sshd. Confirm you \
                         can reach an account with sudo first. ({via})"
                    ),
                    subject: None,
                });
            }
        }
    }

    // -- Firewall -----------------------------------------------------------
    if facts.firewall.backend == "none" {
        findings.push(Finding {
            id: "firewall.absent",
            severity: Severity::High,
            title: "No firewall is installed".into(),
            risk: "Every port anything on this server listens on is reachable \
                   from the internet, including ones opened by a package you \
                   did not choose to expose. Ferrum cannot ban an address \
                   without a firewall either, so brute-force defence is \
                   unavailable."
                .into(),
            remedy: "Install firewalld (RHEL family) or ufw (Debian family) and \
                     let the panel manage the rules from the firewall page."
                .into(),
            subject: None,
        });
    } else if facts.firewall.active == Some(false) {
        findings.push(Finding {
            id: "firewall.inactive",
            severity: Severity::High,
            title: format!(
                "The firewall ({}) is installed but not running",
                facts.firewall.backend
            ),
            risk: "Rules the panel has recorded are not filtering anything, so \
                   the firewall page shows ports as closed while they are open."
                .into(),
            remedy: format!(
                "Start and enable {} , then re-apply the rules from the firewall \
                 page so the running ruleset matches what the panel recorded.",
                facts.firewall.backend
            ),
            subject: None,
        });
    } else if facts.firewall.active.is_none() {
        findings.push(Finding {
            id: "firewall.unknown",
            severity: Severity::Unknown,
            title: "The firewall could not be queried".into(),
            risk: "The panel cannot confirm that the rules it recorded are the \
                   rules in force."
                .into(),
            remedy: format!(
                "Check the {} service by hand; the panel will report again on the \
                 next scan.",
                facts.firewall.backend
            ),
            subject: None,
        });
    }

    // -- MariaDB off loopback ----------------------------------------------
    match &facts.mysql_listeners {
        Observed::Unavailable { reason } => findings.push(Finding {
            id: "mariadb.exposure_unknown",
            severity: Severity::Unknown,
            title: "Whether the database is reachable from the network is unknown".into(),
            risk: "The panel could not enumerate listening sockets, so it cannot \
                   confirm the database is bound to loopback only."
                .into(),
            remedy: format!("Check by hand: `ss -ltnp sport = :{MYSQL_PORT}`. ({reason})"),
            subject: None,
        }),
        Observed::Known(listeners) if !listeners.is_empty() => {
            // This exact state was found on a live AlmaLinux box after a panel
            // install: 0.0.0.0:3306 with no firewall and two anonymous
            // accounts. `ferrum_ops::harden` now prevents it at install time;
            // this check is what catches it coming back.
            let addresses = listeners
                .iter()
                .map(|l| format!("{}:{}", l.address, l.port))
                .collect::<Vec<_>>()
                .join(", ");
            findings.push(Finding {
                id: "mariadb.off_loopback",
                severity: Severity::Critical,
                title: format!("The database is listening on {addresses}, not only on loopback"),
                risk: "The database accepts connections from outside this \
                       server. Every tenant's data is one guessed or leaked \
                       password away, and password guessing against a database \
                       port is neither rate-limited nor logged the way SSH is."
                    .into(),
                remedy: "Ferrum binds MariaDB to 127.0.0.1 at install time; \
                         something has changed that since. Check \
                         /etc/my.cnf.d/60-ferrum.cnf (or the Debian equivalent) \
                         for drift, restore it from the panel, and restart \
                         MariaDB. If remote access is genuinely wanted, open it \
                         from the databases page so the firewall rule and the \
                         audit entry exist."
                    .into(),
                subject: Some(addresses),
            });
        }
        Observed::Known(_) => {}
    }

    // -- Panel TLS ----------------------------------------------------------
    match facts.panel_tls.days_remaining {
        None => findings.push(Finding {
            id: "panel.tls_missing",
            severity: Severity::High,
            title: "The panel has no TLS certificate of its own".into(),
            risk: "The panel is served over a self-signed certificate, so every \
                   administrator learns to click through a browser warning — \
                   which is exactly the habit that makes an interception attack \
                   against the panel's login form work."
                .into(),
            remedy: "Point a domain at this server and issue a certificate from \
                     the panel's TLS page (`panel.tls.issue`)."
                .into(),
            subject: facts.panel_tls.domain.clone(),
        }),
        Some(days) if days < 0 => findings.push(Finding {
            id: "panel.tls_expired",
            severity: Severity::High,
            title: format!("The panel's TLS certificate expired {} days ago", -days),
            risk: "Browsers refuse the panel outright, and administrators reach \
                   for the warning-bypass rather than for the renewal."
                .into(),
            remedy: "Renewal has been failing for at least two weeks. Check the \
                     panel TLS page for the last error — usually the domain no \
                     longer resolves here, or port 80 is closed to the ACME \
                     challenge."
                .into(),
            subject: facts.panel_tls.domain.clone(),
        }),
        Some(days) if days < PANEL_CERT_WARN_DAYS => findings.push(Finding {
            id: "panel.tls_expiring",
            severity: Severity::Medium,
            title: format!("The panel's TLS certificate expires in {days} days"),
            risk: "Automatic renewal starts at 30 days, so a certificate this \
                   close to expiry means renewal has already failed repeatedly."
                .into(),
            remedy: "Check the panel TLS page for the last renewal error before \
                     the certificate lapses."
                .into(),
            subject: facts.panel_tls.domain.clone(),
        }),
        Some(_) => {}
    }

    // -- Sites without certificates ----------------------------------------
    let uncertificated: Vec<&SiteCertFact> =
        facts.sites.iter().filter(|s| !s.has_certificate).collect();
    if !uncertificated.is_empty() {
        let names: Vec<String> = uncertificated.iter().map(|s| s.domain.clone()).collect();
        findings.push(Finding {
            id: "sites.no_certificate",
            severity: Severity::Medium,
            title: format!(
                "{} of {} sites have no TLS certificate",
                uncertificated.len(),
                facts.sites.len()
            ),
            risk: "These sites are served over plain HTTP, so passwords and \
                   session cookies their visitors send cross the network in the \
                   clear and anyone on the path can read or change the page."
                .into(),
            remedy: "Issue a certificate from each site's page. If a site is not \
                     yet pointed at this server, the DNS check on that page will \
                     say so — that is the usual reason issuance has not happened."
                .into(),
            subject: Some(names.join(", ")),
        });
    }

    // -- Sentinel -----------------------------------------------------------
    if !facts.sentinel_enabled {
        findings.push(Finding {
            id: "sentinel.disabled",
            severity: Severity::Low,
            title: "Brute-force defence (Sentinel) is switched off".into(),
            risk: "Repeated failed logins against SSH, the panel and WordPress \
                   admin pages are neither counted nor blocked, so an attacker \
                   can guess passwords at full speed for as long as they like."
                .into(),
            remedy: "Turn Sentinel on from the firewall page. Add your own \
                     address to the allowlist first if you connect from a fixed \
                     address, and note that Ferrum already refuses to ban \
                     loopback, this server's own addresses, or the address you \
                     are connected from."
                .into(),
            subject: None,
        });
    }

    // -- Pending security updates ------------------------------------------
    match &facts.security_updates {
        Observed::Unavailable { reason } => findings.push(Finding {
            id: "updates.unknown",
            severity: Severity::Unknown,
            title: "Pending security updates could not be counted".into(),
            risk: "The panel cannot tell whether this server is missing patches \
                   for publicly known vulnerabilities."
                .into(),
            remedy: format!("Check by hand and refresh the package index. ({reason})"),
            subject: None,
        }),
        Observed::Known(count) if *count > 0 => findings.push(Finding {
            id: "updates.security_pending",
            severity: Severity::High,
            title: format!("{count} security update(s) are waiting to be installed"),
            risk: "Each one closes a publicly documented vulnerability, which \
                   means working exploit code usually exists before the patch \
                   reaches most servers."
                .into(),
            remedy: "Install them during a maintenance window. The count comes \
                     from the package index as it was last refreshed, so refresh \
                     it first if this server has been up for a long time."
                .into(),
            subject: None,
        }),
        Observed::Known(_) => {}
    }

    findings.sort_by_key(|f| f.severity);
    findings
}

// ---------------------------------------------------------------------------
// The operation
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct PostureInput {}

#[derive(Debug, Serialize)]
pub struct PostureOutput {
    #[serde(with = "time::serde::rfc3339")]
    pub checked_at: time::OffsetDateTime,
    pub findings: Vec<Finding>,
    /// How many findings are at each severity, so a dashboard tile does not
    /// have to count them and get the ordering wrong.
    pub counts: BTreeMap<String, usize>,
    /// The evidence, so a sceptical operator can see what the verdicts were
    /// derived from rather than taking them on faith.
    pub facts: PostureFacts,
}

/// `security.posture` — the checklist scan.
pub struct Posture;

#[async_trait]
impl TypedOperation for Posture {
    type Input = PostureInput;
    type Output = PostureOutput;

    const NAME: &'static str = "security.posture";
    // Read-only, and deliberately the *read* permission: telling somebody their
    // server accepts password logins is how they come to fix it, and gating
    // that behind the permission to change the server would keep the report
    // from the person most likely to act on it. Nothing here discloses a
    // credential or a path a caller could not already see elsewhere in the API.
    const PERMISSION: Permission = Permission::ServerRead;
    // Immediate: the package-manager probe runs from cached metadata with a
    // 20 s ceiling, and everything else is a file read or a database query.
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, _input: Self::Input) -> Result<Self::Output> {
        let facts = gather(ctx.distro(), ctx.db()).await?;
        let findings = evaluate(&facts);

        let mut counts = BTreeMap::new();
        for finding in &findings {
            *counts
                .entry(finding.severity.as_str().to_string())
                .or_insert(0) += 1;
        }

        Ok(PostureOutput {
            checked_at: time::OffsetDateTime::now_utc(),
            findings,
            counts,
            facts,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A server with nothing wrong with it, as the baseline every test starts
    /// from and mutates one fact of.
    fn clean() -> PostureFacts {
        PostureFacts {
            sshd: Observed::Known(SshdFacts {
                password_authentication: false,
                keyboard_interactive: false,
                permit_root_login: "prohibit-password".into(),
                source: SshdSource::SshdT,
            }),
            firewall: FirewallFacts {
                backend: "firewalld".into(),
                active: Some(true),
            },
            mysql_listeners: Observed::Known(Vec::new()),
            panel_tls: PanelTlsFacts {
                domain: Some("panel.example.com".into()),
                days_remaining: Some(70),
                status: Some("active".into()),
            },
            sites: vec![SiteCertFact {
                site_id: 1,
                domain: "example.com".into(),
                has_certificate: true,
            }],
            sentinel_enabled: true,
            security_updates: Observed::Known(0),
        }
    }

    fn ids(findings: &[Finding]) -> Vec<&str> {
        findings.iter().map(|f| f.id).collect()
    }

    #[test]
    fn a_server_with_nothing_wrong_produces_no_findings() {
        assert!(evaluate(&clean()).is_empty());
    }

    #[test]
    fn every_finding_says_what_is_wrong_why_it_matters_and_what_to_do() {
        // The contract of this page. A finding with an empty remedy is a
        // finding that teaches an operator to ignore the page.
        let mut facts = clean();
        facts.sshd = Observed::Known(SshdFacts {
            password_authentication: true,
            keyboard_interactive: true,
            permit_root_login: "yes".into(),
            source: SshdSource::SshdT,
        });
        facts.firewall = FirewallFacts {
            backend: "none".into(),
            active: None,
        };
        facts.mysql_listeners = Observed::Known(vec![PublicListener {
            address: "0.0.0.0".into(),
            port: 3306,
        }]);
        facts.panel_tls.days_remaining = None;
        facts.sites[0].has_certificate = false;
        facts.sentinel_enabled = false;
        facts.security_updates = Observed::Known(4);

        let findings = evaluate(&facts);
        assert_eq!(findings.len(), 8, "{:?}", ids(&findings));
        for finding in &findings {
            assert!(!finding.title.is_empty(), "{}", finding.id);
            assert!(
                finding.risk.split_whitespace().count() >= 8,
                "{} has a risk line too short to explain anything: {}",
                finding.id,
                finding.risk
            );
            assert!(
                finding.remedy.split_whitespace().count() >= 5,
                "{} has no actionable remedy: {}",
                finding.id,
                finding.remedy
            );
        }
    }

    #[test]
    fn findings_are_ordered_most_severe_first() {
        let mut facts = clean();
        facts.sentinel_enabled = false; // Low
        facts.mysql_listeners = Observed::Known(vec![PublicListener {
            address: "203.0.113.10".into(),
            port: 3306,
        }]); // Critical
        facts.panel_tls.days_remaining = Some(3); // Medium
        let findings = evaluate(&facts);
        assert_eq!(
            ids(&findings),
            vec![
                "mariadb.off_loopback",
                "panel.tls_expiring",
                "sentinel.disabled"
            ]
        );
    }

    #[test]
    fn a_check_that_could_not_run_is_reported_as_unknown_never_as_clean() {
        // The failure this prevents: an advisor that renders "we could not ask"
        // the same as "nothing is wrong" converts an unknown into a
        // reassurance, which is worse than having no advisor.
        let mut facts = clean();
        facts.sshd = Observed::Unavailable {
            reason: "sshd is not installed".into(),
        };
        facts.mysql_listeners = Observed::Unavailable {
            reason: "no /proc".into(),
        };
        facts.security_updates = Observed::Unavailable {
            reason: "dnf timed out".into(),
        };
        facts.firewall.active = None;

        let findings = evaluate(&facts);
        assert_eq!(
            ids(&findings),
            vec![
                "ssh.unknown",
                "firewall.unknown",
                "mariadb.exposure_unknown",
                "updates.unknown"
            ]
        );
        assert!(findings.iter().all(|f| f.severity == Severity::Unknown));
    }

    #[test]
    fn keyboard_interactive_alone_is_still_password_authentication() {
        // The trap: `PasswordAuthentication no` is widely believed to be
        // enough, and on a distribution with PAM keyboard-interactive left on
        // the server still accepts the same password.
        let mut facts = clean();
        facts.sshd = Observed::Known(SshdFacts {
            password_authentication: false,
            keyboard_interactive: true,
            permit_root_login: "no".into(),
            source: SshdSource::SshdT,
        });
        let findings = evaluate(&facts);
        assert_eq!(ids(&findings), vec!["ssh.password_auth"]);
        assert!(findings[0].title.contains("KbdInteractive"));
    }

    #[test]
    fn key_only_root_login_is_not_a_finding_but_password_root_login_is_critical() {
        let mut facts = clean();
        for spelling in [
            "prohibit-password",
            "without-password",
            "forced-commands-only",
            "no",
        ] {
            facts.sshd = Observed::Known(SshdFacts {
                password_authentication: false,
                keyboard_interactive: false,
                permit_root_login: spelling.into(),
                source: SshdSource::SshdT,
            });
            assert!(
                evaluate(&facts).is_empty(),
                "`PermitRootLogin {spelling}` permits a key, not a password"
            );
        }

        facts.sshd = Observed::Known(SshdFacts {
            password_authentication: true,
            keyboard_interactive: false,
            permit_root_login: "yes".into(),
            source: SshdSource::SshdT,
        });
        let findings = evaluate(&facts);
        let root = findings.iter().find(|f| f.id == "ssh.root_login").unwrap();
        assert_eq!(
            root.severity,
            Severity::Critical,
            "root login plus passwords is the combination that loses servers"
        );

        facts.sshd = Observed::Known(SshdFacts {
            password_authentication: false,
            keyboard_interactive: false,
            permit_root_login: "yes".into(),
            source: SshdSource::SshdT,
        });
        let findings = evaluate(&facts);
        assert_eq!(findings[0].severity, Severity::Medium, "key-only root");
    }

    #[test]
    fn a_file_derived_ssh_answer_discloses_that_it_did_not_come_from_sshd() {
        let mut facts = clean();
        facts.sshd = Observed::Known(SshdFacts {
            password_authentication: true,
            keyboard_interactive: false,
            permit_root_login: "no".into(),
            source: SshdSource::Files,
        });
        let findings = evaluate(&facts);
        assert!(
            findings[0].remedy.contains("`sshd -T` could not be run"),
            "an approximation must say it is one: {}",
            findings[0].remedy
        );
    }

    // -- parsing ------------------------------------------------------------

    #[test]
    fn sshd_t_output_is_read_for_the_three_settings_that_matter() {
        let output = "\
port 22
permitrootlogin yes
passwordauthentication no
kbdinteractiveauthentication yes
usepam yes
";
        let facts = parse_sshd_t(output);
        assert!(!facts.password_authentication);
        assert!(facts.keyboard_interactive);
        assert_eq!(facts.permit_root_login, "yes");
        assert_eq!(facts.source, SshdSource::SshdT);
    }

    #[test]
    fn an_absent_sshd_setting_reads_as_opensshs_default_not_as_the_safe_value() {
        // A check that assumes safety when it sees nothing reports safety on a
        // file it failed to parse.
        let facts = parse_sshd_t("port 22\n");
        assert!(
            facts.password_authentication,
            "OpenSSH defaults PasswordAuthentication to yes"
        );
        assert!(facts.keyboard_interactive);
        assert_eq!(facts.permit_root_login, "prohibit-password");
    }

    #[test]
    fn in_sshd_config_files_the_first_value_wins_not_the_last() {
        // sshd's rule, and the opposite of nearly every other config format.
        // Getting it backwards would make this advisor confidently wrong: a
        // `PasswordAuthentication no` at the bottom of sshd_config does nothing
        // when a drop-in already said yes.
        let files = vec![
            (
                "/etc/ssh/sshd_config.d/50-cloud-init.conf".to_string(),
                "PasswordAuthentication yes\n".to_string(),
            ),
            (
                "/etc/ssh/sshd_config".to_string(),
                "PasswordAuthentication no\nPermitRootLogin no\n".to_string(),
            ),
        ];
        let facts = parse_sshd_files(&files);
        assert!(
            facts.password_authentication,
            "the drop-in was read first, so its `yes` is the value in force"
        );
        assert_eq!(facts.permit_root_login, "no");
        assert_eq!(facts.source, SshdSource::Files);
    }

    #[test]
    fn settings_inside_a_match_block_do_not_become_the_global_answer() {
        // Ferrum's own SFTP drop-in is a `Match Group` block. Reading its
        // contents as global settings would have the advisor report the SFTP
        // group's policy as the server's.
        let files = vec![(
            "/etc/ssh/sshd_config".to_string(),
            "PermitRootLogin no\n\
             Match Group ferrum-sftp\n\
             \x20   PasswordAuthentication yes\n\
             \x20   ForceCommand internal-sftp\n"
                .to_string(),
        )];
        let facts = parse_sshd_files(&files);
        assert_eq!(facts.permit_root_login, "no");
        // Unset globally, so the OpenSSH default stands rather than the
        // Match block's value.
        assert!(facts.password_authentication);
    }

    #[test]
    fn a_commented_out_sshd_setting_is_not_a_setting() {
        let files = vec![(
            "/etc/ssh/sshd_config".to_string(),
            "#PermitRootLogin yes\nPermitRootLogin no\n".to_string(),
        )];
        assert_eq!(parse_sshd_files(&files).permit_root_login, "no");
    }

    // -- /proc/net/tcp ------------------------------------------------------

    #[test]
    fn a_database_bound_to_every_interface_is_seen_as_a_public_listener() {
        // The live-server state this check exists for: 0.0.0.0:3306.
        // 0x0CEA is 3306.
        let table = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0CEA 00000000:0000 0A 00000000:00000000 00:00000000 00000000    27        0 12345 1
";
        let found = listeners_on_port(table, 3306);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].address, "0.0.0.0");
        assert_eq!(found[0].port, 3306);
    }

    #[test]
    fn a_database_bound_to_loopback_is_not_a_finding() {
        // 0100007F is 127.0.0.1 in /proc's little-endian hex.
        let table = "\
  sl  local_address rem_address   st
   0: 0100007F:0CEA 00000000:0000 0A
";
        assert!(listeners_on_port(table, 3306).is_empty());
    }

    #[test]
    fn an_established_connection_to_the_database_port_is_not_a_listener() {
        // State 01 is ESTABLISHED. Counting it would report a public listener
        // on every server a customer's application connects out from.
        let table = "\
  sl  local_address rem_address   st
   0: 0A00020F:0CEA C6336401:1F90 01
";
        assert!(listeners_on_port(table, 3306).is_empty());
    }

    #[test]
    fn an_ipv6_wildcard_listener_is_decoded_and_the_mapped_form_is_normalised() {
        let table = "\
  sl  local_address rem_address   st
   0: 00000000000000000000000000000000:0CEA 00000000000000000000000000000000:0000 0A
   1: 0000000000000000FFFF00000100007F:0CEA 00000000000000000000000000000000:0000 0A
";
        let found = listeners_on_port(table, 3306);
        // The `::` wildcard is public; the IPv4-mapped 127.0.0.1 is loopback
        // under a longer spelling and must not be reported.
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].address, "::");
    }

    #[test]
    fn a_listener_on_another_port_is_ignored() {
        // 0x1F90 is 8080.
        let table = "\
  sl  local_address rem_address   st
   0: 00000000:1F90 00000000:0000 0A
";
        assert!(listeners_on_port(table, 3306).is_empty());
    }

    #[test]
    fn a_truncated_or_garbled_proc_table_yields_no_findings_rather_than_a_panic() {
        for junk in ["", "sl local_address\n", "   0: zzzz:zzzz\n", "   0:\n"] {
            assert!(listeners_on_port(junk, 3306).is_empty());
        }
    }

    // -- update counting ----------------------------------------------------

    #[test]
    fn only_updates_from_a_security_suite_are_counted_as_security_updates() {
        // "17 packages have newer versions" is always true and always ignored;
        // "3 security updates" is worth interrupting somebody for.
        let output = "\
Inst libssl3 [3.0.11-1] (3.0.14-1~deb12u2 Debian-Security:12/stable [amd64])
Inst vim [2:9.0-1] (2:9.1-1 Debian:12.5/stable [amd64])
Inst curl [7.88.1-10] (7.88.1-10+deb12u5 Debian-Security:12/stable [amd64])
Conf libssl3 (3.0.14-1~deb12u2 Debian-Security:12/stable [amd64])
";
        assert_eq!(count_apt_security_updates(output), 2);
    }

    #[test]
    fn dnf_check_update_output_is_counted_by_package_lines_not_by_headings() {
        let output = "\
Last metadata expiration check: 0:12:31 ago on Thu 28 Aug 2026.

openssl.x86_64                    1:3.2.2-6.el10_0                    baseos
openssl-libs.x86_64               1:3.2.2-6.el10_0                    baseos

Obsoleting Packages
";
        assert_eq!(count_dnf_security_updates(output), 2);
    }

    #[test]
    fn no_pending_updates_produces_no_finding() {
        assert_eq!(count_apt_security_updates(""), 0);
        assert_eq!(count_dnf_security_updates(""), 0);
        let facts = clean();
        assert!(evaluate(&facts).is_empty());
    }

    #[test]
    fn the_finding_for_uncertificated_sites_names_them() {
        let mut facts = clean();
        facts.sites = vec![
            SiteCertFact {
                site_id: 1,
                domain: "secure.example.com".into(),
                has_certificate: true,
            },
            SiteCertFact {
                site_id: 2,
                domain: "plain.example.com".into(),
                has_certificate: false,
            },
        ];
        let findings = evaluate(&facts);
        assert_eq!(ids(&findings), vec!["sites.no_certificate"]);
        assert_eq!(
            findings[0].subject.as_deref(),
            Some("plain.example.com"),
            "a count without the names is not actionable"
        );
        assert!(findings[0].title.starts_with("1 of 2"));
    }

    #[test]
    fn a_server_with_no_sites_at_all_produces_no_certificate_finding() {
        let mut facts = clean();
        facts.sites = Vec::new();
        assert!(evaluate(&facts).is_empty());
    }

    #[test]
    fn an_absent_firewall_and_a_stopped_one_are_different_findings() {
        let mut facts = clean();
        facts.firewall = FirewallFacts {
            backend: "none".into(),
            active: None,
        };
        assert_eq!(ids(&evaluate(&facts)), vec!["firewall.absent"]);

        facts.firewall = FirewallFacts {
            backend: "ufw".into(),
            active: Some(false),
        };
        assert_eq!(ids(&evaluate(&facts)), vec!["firewall.inactive"]);
    }

    #[test]
    fn an_expired_panel_certificate_is_distinguished_from_a_missing_one() {
        let mut facts = clean();
        facts.panel_tls.days_remaining = Some(-3);
        let findings = evaluate(&facts);
        assert_eq!(ids(&findings), vec!["panel.tls_expired"]);
        assert!(findings[0].title.contains("3 days ago"));

        facts.panel_tls.days_remaining = None;
        assert_eq!(ids(&evaluate(&facts)), vec!["panel.tls_missing"]);
    }

    #[test]
    fn a_certificate_inside_the_normal_renewal_window_is_not_a_finding() {
        // Renewal starts at 30 days, so flagging 29 would teach an operator to
        // ignore this page.
        let mut facts = clean();
        facts.panel_tls.days_remaining = Some(29);
        assert!(evaluate(&facts).is_empty());
        facts.panel_tls.days_remaining = Some(PANEL_CERT_WARN_DAYS - 1);
        assert_eq!(ids(&evaluate(&facts)), vec!["panel.tls_expiring"]);
    }

    #[test]
    fn every_observed_shape_survives_serialisation() {
        // The bug this pins: `Observed` was internally tagged, which serde can
        // only fold into a variant that serialises as a map. `Known(SshdFacts)`
        // is a map and worked; `Known(Vec<_>)` and `Known(usize)` are not, and
        // failed at *runtime* — so `security.posture` could not return on any
        // machine where those two checks actually succeeded.
        //
        // Every existing test ran where the checks could not run, so they all
        // took the `Unavailable` path, which is a struct variant and always
        // serialised. That is why this reached a server before it was noticed.
        let listeners = Observed::Known(vec![PublicListener {
            address: "0.0.0.0".to_string(),
            port: 3306,
        }]);
        let count = Observed::Known(3usize);
        let unavailable: Observed<usize> = Observed::Unavailable {
            reason: "dnf is not installed".to_string(),
        };

        let a = serde_json::to_value(&listeners).expect("a sequence must serialise");
        assert_eq!(a["kind"], "known");
        assert_eq!(a["value"][0]["address"], "0.0.0.0");
        assert_eq!(a["value"][0]["port"], 3306);

        let b = serde_json::to_value(&count).expect("a number must serialise");
        assert_eq!(b["kind"], "known");
        assert_eq!(b["value"], 3);

        let c = serde_json::to_value(&unavailable).expect("the reason must serialise");
        assert_eq!(c["kind"], "unavailable");
        // Adjacent tagging nests the variant's own fields under `value` too,
        // so the reason moved with them. Nothing consumed the old shape.
        assert_eq!(c["value"]["reason"], "dnf is not installed");
    }

    #[test]
    fn every_finding_id_is_unique_and_dotted() {
        // The ids are an API: the UI keys its help text and fix-it actions on
        // them, so two findings sharing one id would be a silent product bug.
        let mut facts = clean();
        facts.sshd = Observed::Known(SshdFacts {
            password_authentication: true,
            keyboard_interactive: true,
            permit_root_login: "yes".into(),
            source: SshdSource::SshdT,
        });
        facts.firewall = FirewallFacts {
            backend: "none".into(),
            active: None,
        };
        facts.mysql_listeners = Observed::Known(vec![PublicListener {
            address: "0.0.0.0".into(),
            port: 3306,
        }]);
        facts.panel_tls.days_remaining = None;
        facts.sites[0].has_certificate = false;
        facts.sentinel_enabled = false;
        facts.security_updates = Observed::Known(1);

        let findings = evaluate(&facts);
        let mut seen = std::collections::BTreeSet::new();
        for finding in &findings {
            assert!(finding.id.contains('.'), "{} is not namespaced", finding.id);
            assert!(seen.insert(finding.id), "duplicate id: {}", finding.id);
        }
    }

    // -- through the registry -----------------------------------------------

    #[tokio::test]
    async fn a_customer_cannot_read_the_servers_security_posture() {
        // The report enumerates this server's weaknesses. A tenant is not the
        // audience for that, however useful it would be to an attacker who has
        // one tenant's credentials.
        use crate::registry::testing::{auth_for, registry};
        use ferrum_core::{ErrorCode, Role};

        let (reg, _, customer) = registry().await;
        let err = reg
            .dispatch(
                "security.posture",
                &auth_for(customer, Role::Customer),
                serde_json::json!({}),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::PermissionDenied);
    }

    #[tokio::test]
    async fn the_scan_answers_on_a_machine_where_most_checks_cannot_run() {
        // The environment this runs in has no /proc, no apt and no dnf, which
        // is exactly the shape the "never render an unknown as clean" rule
        // exists for. The scan must still answer, and every check that could
        // not run must appear as a finding rather than as silence.
        use crate::registry::testing::{auth_for, registry};
        use ferrum_core::Role;

        let (reg, admin, _) = registry().await;
        let out = reg
            .dispatch(
                "security.posture",
                &auth_for(admin, Role::Admin),
                serde_json::json!({}),
                None,
            )
            .await
            .expect("the scan must answer even when it cannot gather much");

        let findings = out["findings"].as_array().expect("findings array");
        assert!(
            !findings.is_empty(),
            "a fresh panel has at least Sentinel switched off"
        );
        for finding in findings {
            for field in ["id", "severity", "title", "risk", "remedy"] {
                assert!(
                    finding[field].as_str().is_some_and(|s| !s.is_empty()),
                    "`{field}` is missing from {finding}"
                );
            }
        }
        // The evidence ships with the verdicts.
        assert!(out["facts"].is_object());
        assert!(out["counts"].is_object());
    }
}
