//! Firewall management and Sentinel, the built-in brute-force defence
//! (spec §11.9).
//!
//! Three rules shape this module.
//!
//! **1. The backend is the truth; the database is the intent.** `fw_rules`
//! records what the panel was asked to open. Whether a rule is *live* is a
//! question only `FwBackend::list_rules` can answer, because an operator can
//! flush a ruleset from a shell at any moment and firewalld can be reloaded out
//! from under us. So writes go to the backend **first** and are recorded only
//! once the backend accepted them, and `fw.rules` returns the merge of the two
//! with the difference labelled as drift rather than hidden.
//!
//! **2. Never lock the operator out.** This is the hard requirement of the
//! whole feature and the reason fail2ban has burned so many people: a defence
//! that can ban the hand that feeds it turns a password-guessing nuisance into
//! an outage that needs console access to fix. [`refusal_reason`] refuses,
//! unconditionally and before anything reaches the firewall:
//!
//! * the loopback addresses — including the IPv4-mapped spellings of them,
//!   which is exactly the shape a `::ffff:127.0.0.1` in a log would take;
//! * every address bound to a local interface, so the server cannot ban itself
//!   through the address a customer's traffic arrives on;
//! * the address of the client making the request, filled in by the web layer
//!   from the live connection, so "ban this IP" typed by an admin who
//!   fat-fingered their own address is refused rather than obeyed;
//! * anything in the operator's `sentinel.allowlist`;
//! * the unspecified and multicast addresses, which are not hosts at all and
//!   which some backends would widen into a far larger drop than intended.
//!
//! The same rule governs `fw.enable`, where a single command turns a list of
//! recorded rules into an enforced default-deny policy. [`ensure_ssh_reachable`]
//! refuses to start a firewall that would not accept an SSH connection to the
//! port sshd actually answers on, from the address the operator is actually
//! calling from — and refuses just as flatly when it cannot work out what that
//! port is, because a guess in that direction costs the operator their server.
//!
//! **3. Sentinel is off until an operator turns it on** (`sentinel.enabled`,
//! default false). A fresh install has no allowlist, may be reached through a
//! NAT that makes an entire office look like one address, and belongs to
//! somebody who has not yet read this page. Banning on such a server is a
//! coin-flip on locking out its owner, so the scheduled tick bans nobody —
//! and reads no log line at all — unless the switch is on. It still lifts the
//! bans whose time has passed, because switching the defence off must not be
//! the thing that makes its bans permanent.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};
use unihelm_config::paths;
use unihelm_core::{ErrorCode, Permission, Result, UnihelmError};
use unihelm_db::audit::NewAuditEntry;
use unihelm_db::settings::keys;
use unihelm_db::{FwRuleRecord, SentinelBan};
use unihelm_distro::fw::{PortRule, Proto};

use crate::registry::{Execution, OpContext, TypedOperation};

// ---------------------------------------------------------------------------
// settings
// ---------------------------------------------------------------------------

/// Sentinel's knobs, with the defaults the spec asks for.
///
/// Defaults live here rather than as seeded rows, so an absent key reads as
/// "whatever this build considers sane" and a later release can change its mind
/// without having to migrate values it once wrote into every database.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SentinelSettings {
    /// The master switch. False on a fresh install; see the module docs.
    pub enabled: bool,
    /// Failed SSH authentications inside the window that earn a ban.
    pub ssh_threshold: u32,
    /// How far back each scan looks.
    pub window_minutes: u32,
    /// How long a ban lasts. Always finite for Sentinel's own bans.
    pub ban_minutes: u32,
    /// Addresses and CIDRs an operator has declared off-limits.
    pub allowlist: Vec<String>,
}

impl Default for SentinelSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            ssh_threshold: 6,
            window_minutes: 10,
            ban_minutes: 60,
            allowlist: Vec::new(),
        }
    }
}

impl SentinelSettings {
    /// Bounds that keep a typo from turning the defence into the attack.
    ///
    /// A threshold of 0 would ban every address that has ever appeared in the
    /// log, including the operator's; a window of days would let a single
    /// forgotten laptop accumulate a ban long after the person fixed it.
    pub fn validate(&self) -> Result<()> {
        let bad = |field: &'static str, detail: String| {
            Err(UnihelmError::new(ErrorCode::InvalidInput, detail).with_field(field))
        };
        if self.ssh_threshold == 0 {
            return bad(
                "ssh_threshold",
                "a threshold of 0 would ban every address in the log, including yours".into(),
            );
        }
        if !(1..=1440).contains(&self.window_minutes) {
            return bad(
                "window_minutes",
                "the scan window must be between 1 minute and 24 hours".into(),
            );
        }
        if !(1..=525_600).contains(&self.ban_minutes) {
            return bad(
                "ban_minutes",
                "a ban must last between 1 minute and a year".into(),
            );
        }
        for entry in &self.allowlist {
            if parse_cidr(entry).is_none() {
                return bad(
                    "allowlist",
                    format!("`{entry}` is not an IP address or CIDR"),
                );
            }
        }
        Ok(())
    }

    pub fn window(&self) -> Duration {
        Duration::minutes(i64::from(self.window_minutes))
    }

    pub fn ban_duration(&self) -> Duration {
        Duration::minutes(i64::from(self.ban_minutes))
    }

    /// Read from the settings table, key by key, each falling back to its
    /// default. Key-by-key rather than one blob so adding a knob does not
    /// invalidate the values an operator already set.
    pub async fn load(db: &unihelm_db::Db) -> Self {
        let d = Self::default();
        Self {
            enabled: db.get_setting_or(keys::SENTINEL_ENABLED, d.enabled).await,
            ssh_threshold: db
                .get_setting_or(keys::SENTINEL_SSH_THRESHOLD, d.ssh_threshold)
                .await,
            window_minutes: db
                .get_setting_or(keys::SENTINEL_WINDOW_MINUTES, d.window_minutes)
                .await,
            ban_minutes: db
                .get_setting_or(keys::SENTINEL_BAN_MINUTES, d.ban_minutes)
                .await,
            allowlist: db
                .get_setting_or(keys::SENTINEL_ALLOWLIST, d.allowlist)
                .await,
        }
    }

    pub async fn store(&self, db: &unihelm_db::Db) -> Result<()> {
        self.validate()?;
        let e = |e: unihelm_db::DbError| UnihelmError::from(e);
        db.set_setting(keys::SENTINEL_ENABLED, &self.enabled)
            .await
            .map_err(e)?;
        db.set_setting(keys::SENTINEL_SSH_THRESHOLD, &self.ssh_threshold)
            .await
            .map_err(e)?;
        db.set_setting(keys::SENTINEL_WINDOW_MINUTES, &self.window_minutes)
            .await
            .map_err(e)?;
        db.set_setting(keys::SENTINEL_BAN_MINUTES, &self.ban_minutes)
            .await
            .map_err(e)?;
        db.set_setting(keys::SENTINEL_ALLOWLIST, &self.allowlist)
            .await
            .map_err(e)?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// lockout prevention
// ---------------------------------------------------------------------------

/// Everything that must never be banned, gathered in one place so the decision
/// is a pure function of explicit inputs and can be tested without a firewall.
#[derive(Debug, Clone, Default)]
pub struct BanGuard {
    /// The address the request arrived from, as the web layer saw it.
    pub client_ip: Option<IpAddr>,
    /// Every address bound to a local interface (see [`local_addresses`]).
    pub local: Vec<IpAddr>,
    /// The operator's `sentinel.allowlist`, as literal addresses or CIDRs.
    pub allowlist: Vec<String>,
}

impl BanGuard {
    /// The guard used by an operation: the caller's address plus this host's.
    pub fn for_request(client_ip: Option<IpAddr>, settings: &SentinelSettings) -> Self {
        Self {
            client_ip,
            local: local_addresses(),
            allowlist: settings.allowlist.clone(),
        }
    }
}

/// An IPv4-mapped IPv6 address means the same host as its IPv4 form, so every
/// check has to see the same address whichever spelling arrived.
///
/// Without this, `::ffff:127.0.0.1` fails `is_loopback()` (Rust's answer is
/// correct — that is not `::1`) and a log line carrying that spelling would
/// walk straight past the loopback refusal.
pub fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    }
}

/// Why this address must not be banned, or `None` if banning it is safe.
///
/// The order is deliberate: the reasons an operator most needs to see come
/// first, because this string is what the API returns and what lands in the
/// task log.
pub fn refusal_reason(ip: IpAddr, guard: &BanGuard) -> Option<String> {
    let ip = canonical(ip);

    if ip.is_loopback() {
        return Some(format!(
            "{ip} is a loopback address; banning it would cut the panel off from itself"
        ));
    }
    if guard.client_ip.map(canonical) == Some(ip) {
        return Some(format!(
            "{ip} is the address this request came from; banning it would lock you out"
        ));
    }
    if guard.local.iter().copied().map(canonical).any(|l| l == ip) {
        return Some(format!(
            "{ip} is one of this server's own addresses; banning it would cut off its own traffic"
        ));
    }
    if let Some(entry) = guard
        .allowlist
        .iter()
        .find(|entry| cidr_contains(entry, ip))
    {
        return Some(format!("{ip} is covered by the allowlist entry `{entry}`"));
    }
    if is_unspecified_or_wildcard(ip) {
        return Some(format!(
            "{ip} is not a host address; banning it would drop far more than intended"
        ));
    }
    None
}

/// Addresses that are not a single host: the unspecified address (which several
/// backends read as "everything"), multicast, and the IPv4 broadcast address.
fn is_unspecified_or_wildcard(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_unspecified() || v4.is_multicast() || v4.is_broadcast(),
        IpAddr::V6(v6) => v6.is_unspecified() || v6.is_multicast(),
    }
}

/// A parsed `addr` or `addr/len`, kept as the address plus a prefix length.
fn parse_cidr(text: &str) -> Option<(IpAddr, u8)> {
    let (addr, prefix) = match text.split_once('/') {
        Some((a, p)) => (a, Some(p)),
        None => (text, None),
    };
    let ip: IpAddr = addr.trim().parse().ok()?;
    let max = if ip.is_ipv6() { 128 } else { 32 };
    let len = match prefix {
        None => max,
        Some(p) => {
            let len: u8 = p.trim().parse().ok()?;
            if len > max {
                return None;
            }
            len
        }
    };
    Some((canonical(ip), len))
}

/// Does `cidr` cover `ip`? A malformed entry covers nothing — an allowlist the
/// operator typoed must not silently widen into "allow everything".
pub fn cidr_contains(cidr: &str, ip: IpAddr) -> bool {
    let Some((network, prefix)) = parse_cidr(cidr) else {
        return false;
    };
    let ip = canonical(ip);
    match (network, ip) {
        (IpAddr::V4(net), IpAddr::V4(addr)) => {
            prefix_matches(&net.octets(), &addr.octets(), prefix)
        }
        (IpAddr::V6(net), IpAddr::V6(addr)) => {
            prefix_matches(&net.octets(), &addr.octets(), prefix)
        }
        // Different families never overlap; canonicalisation above already
        // folded the mapped-IPv4 case into V4.
        _ => false,
    }
}

/// Compare the first `prefix` bits of two equal-length byte strings.
fn prefix_matches(network: &[u8], addr: &[u8], prefix: u8) -> bool {
    let whole = usize::from(prefix / 8);
    let bits = prefix % 8;
    if network[..whole] != addr[..whole] {
        return false;
    }
    if bits == 0 {
        return true;
    }
    let mask = 0xFFu8 << (8 - bits);
    network[whole] & mask == addr[whole] & mask
}

/// Every address bound to a local interface.
///
/// `getifaddrs(3)` rather than parsing `ip addr`: this list is a lockout
/// guard, and a guard that depends on a command being installed and its output
/// format being stable is a guard that fails open on the day it matters.
#[cfg(unix)]
pub fn local_addresses() -> Vec<IpAddr> {
    let mut out = Vec::new();
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();

    // SAFETY: `getifaddrs` writes an owned linked list through the out-pointer
    // and returns non-zero without allocating on failure.
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        tracing::warn!(
            "could not enumerate this host's addresses; the self-ban guard is \
             running on loopback and client-address checks alone"
        );
        return out;
    }

    let mut cursor = head;
    while !cursor.is_null() {
        // SAFETY: `cursor` is a node of the list `getifaddrs` just built, and
        // the loop stops at the NULL terminator.
        let node = unsafe { &*cursor };
        if !node.ifa_addr.is_null() {
            // SAFETY: `ifa_addr` points at a `sockaddr` whose family field is
            // always initialised; the reads below are unaligned-safe and sized
            // by the family they matched.
            let family = i32::from(unsafe { (*node.ifa_addr).sa_family });
            if family == libc::AF_INET {
                let sa: libc::sockaddr_in =
                    unsafe { std::ptr::read_unaligned(node.ifa_addr.cast()) };
                out.push(IpAddr::V4(Ipv4Addr::from(u32::from_be(sa.sin_addr.s_addr))));
            } else if family == libc::AF_INET6 {
                let sa: libc::sockaddr_in6 =
                    unsafe { std::ptr::read_unaligned(node.ifa_addr.cast()) };
                out.push(IpAddr::V6(Ipv6Addr::from(sa.sin6_addr.s6_addr)));
            }
        }
        cursor = node.ifa_next;
    }

    // SAFETY: `head` came from `getifaddrs` and is freed exactly once, after
    // the walk has finished with every node.
    unsafe { libc::freeifaddrs(head) };
    out
}

#[cfg(not(unix))]
pub fn local_addresses() -> Vec<IpAddr> {
    Vec::new()
}

// ---------------------------------------------------------------------------
// reading SSH authentication failures out of the journal
// ---------------------------------------------------------------------------

/// One authentication failure, as read from a log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthFailure {
    pub ip: IpAddr,
    pub at: OffsetDateTime,
}

/// The argv for one journal read.
///
/// `+` is journalctl's OR between match groups, so one call covers every shape
/// an sshd authentication record arrives in — the alternative, running
/// journalctl once per shape, multiplies the cost of every tick.
///
/// It takes four groups because the unit names alone do not find the records on
/// a current distribution. Debian 13 and Ubuntu 24.04 socket-activate sshd, so
/// the connection that fails a password is logged under a per-connection
/// `ssh@N-<addr>.service`, which matches neither `ssh.service` nor `sshd.service`;
/// and OpenSSH 10 splits the authenticating half into `sshd-session`, which
/// carries its own syslog identifier. Missing them is silent by construction —
/// no matches is not an error, so Sentinel simply reported nothing to do while
/// the SSH jail defended nothing.
///
/// The identifier groups pair with `_UID=0`, which is what keeps them from
/// turning Sentinel into a weapon. `SYSLOG_IDENTIFIER` is whatever the sender
/// claimed, so on a panel host — which by design has unprivileged system users
/// for the sites it hosts — `logger -t sshd "Failed password for root from
/// <victim> port 22 ssh2"` repeated past the threshold would ban an address of
/// the forger's choosing. `_UID` is journald's own, taken from the socket
/// credentials and unforgeable, and OpenSSH relays every pre-auth log line
/// through its privileged monitor precisely because the chrooted child cannot
/// reach `/dev/log` — so a genuine failure is always uid 0. Matches for
/// different fields are ANDed within a group, which is what makes the pairing
/// hold.
///
/// The timestamp is absolute and explicitly UTC. journalctl reads a bare
/// timestamp in the host's local zone, and a panel that quietly asked for the
/// wrong hour twice a year would look like Sentinel had simply stopped working.
pub fn journal_argv(since: OffsetDateTime) -> Vec<String> {
    vec![
        "--no-pager".into(),
        "-o".into(),
        "json".into(),
        "--since".into(),
        format_journal_since(since),
        "SYSLOG_IDENTIFIER=sshd".into(),
        "_UID=0".into(),
        "+".into(),
        "SYSLOG_IDENTIFIER=sshd-session".into(),
        "_UID=0".into(),
        "+".into(),
        "_SYSTEMD_UNIT=sshd.service".into(),
        "+".into(),
        "_SYSTEMD_UNIT=ssh.service".into(),
    ]
}

/// `YYYY-MM-DD HH:MM:SS UTC`, the form `systemd.time(7)` documents.
fn format_journal_since(since: OffsetDateTime) -> String {
    let since = since.to_offset(time::UtcOffset::UTC);
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
        since.year(),
        u8::from(since.month()),
        since.day(),
        since.hour(),
        since.minute(),
        since.second(),
    )
}

/// Pull the message text out of one `journalctl -o json` record.
///
/// `MESSAGE` is a string when the line was valid UTF-8 and an **array of byte
/// values** when it was not — which is the shape a deliberately malformed
/// login attempt produces. Both are handled; anything else yields `None`
/// rather than a guess.
fn journal_message(record: &serde_json::Value) -> Option<String> {
    match record.get("MESSAGE")? {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Array(bytes) => {
            let raw: Vec<u8> = bytes
                .iter()
                .map(|b| b.as_u64().unwrap_or(0) as u8)
                .collect();
            Some(String::from_utf8_lossy(&raw).into_owned())
        }
        _ => None,
    }
}

/// `__REALTIME_TIMESTAMP` is microseconds since the epoch, as a *string*
/// (journald sends it that way because the value overflows a JSON number's
/// exact-integer range in some consumers).
fn journal_time(record: &serde_json::Value) -> Option<OffsetDateTime> {
    let raw = record.get("__REALTIME_TIMESTAMP")?;
    let micros: i128 = match raw {
        serde_json::Value::String(s) => s.parse().ok()?,
        serde_json::Value::Number(n) => i128::from(n.as_i64()?),
        _ => return None,
    };
    OffsetDateTime::from_unix_timestamp_nanos(micros.checked_mul(1_000)?).ok()
}

/// The offending address in an sshd failure line, if this line is one.
///
/// Only `Failed password …` and `Invalid user …` count (spec §11.9). The
/// address is taken from the **last** `from <ip> port <n>` triple in the line,
/// not the first, and that is a security property rather than a stylistic
/// choice: the username is attacker-controlled and lands in the middle of the
/// message, so an attacker connecting as the user
/// `from 203.0.113.1 port 22` produces
///
/// ```text
/// Invalid user from 203.0.113.1 port 22 from 198.51.100.9 port 55555
/// ```
///
/// and a first-match parser would ban whichever address the attacker named.
/// That turns a brute-force defence into a remote "ban anyone" primitive —
/// including, on a panel whose operator is behind a known address, a way to
/// lock the operator out.
pub fn parse_ssh_failure(message: &str) -> Option<IpAddr> {
    let message = message.trim();
    if !(message.starts_with("Failed password for") || message.starts_with("Invalid user")) {
        return None;
    }

    let tokens: Vec<&str> = message.split_whitespace().collect();
    let mut found = None;
    for i in 0..tokens.len() {
        if tokens[i] != "from" {
            continue;
        }
        // The full shape sshd writes: `from <addr> port <number>`. Requiring
        // all four parts is what keeps a username containing the bare word
        // "from" out of the result.
        let (Some(addr), Some(port_kw), Some(port)) =
            (tokens.get(i + 1), tokens.get(i + 2), tokens.get(i + 3))
        else {
            continue;
        };
        if *port_kw != "port" || port.trim_end_matches(':').parse::<u16>().is_err() {
            continue;
        }
        if let Ok(ip) = addr.parse::<IpAddr>() {
            found = Some(canonical(ip));
        }
    }
    found
}

/// Every SSH authentication failure in a `journalctl -o json` stream.
///
/// One JSON object per line. A line that does not parse is skipped rather than
/// failing the scan: journald interleaves records from every field type, and a
/// scanner that gave up on the first surprise would stop defending the host.
pub fn parse_journal(text: &str) -> Vec<AuthFailure> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(record) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        let (Some(message), Some(at)) = (journal_message(&record), journal_time(&record)) else {
            continue;
        };
        if let Some(ip) = parse_ssh_failure(&message) {
            out.push(AuthFailure { ip, at });
        }
    }
    out
}

/// Reads the journal. One seam, so the window logic and the ban decisions are
/// testable without systemd — and so a macOS dev instance runs the same code.
#[async_trait]
pub trait JournalReader: Send + Sync {
    async fn read(&self, since: OffsetDateTime) -> Result<String>;
}

/// The real thing: `journalctl` through an argv array, never a shell.
pub struct SystemJournal;

#[async_trait]
impl JournalReader for SystemJournal {
    async fn read(&self, since: OffsetDateTime) -> Result<String> {
        let out = unihelm_distro::Cmd::new("journalctl")
            .args(journal_argv(since))
            .timeout(std::time::Duration::from_secs(30))
            .run()
            .await
            .map_err(UnihelmError::from)?;
        // A journal with no matching unit exits non-zero on some versions and
        // prints nothing on others; both mean "no failures", not an error the
        // operator needs to see once a minute.
        if !out.success() {
            tracing::debug!(detail = %out.failure_text(), "journalctl returned nothing usable");
            return Ok(String::new());
        }
        Ok(out.stdout)
    }
}

// ---------------------------------------------------------------------------
// the threshold window
// ---------------------------------------------------------------------------

/// An address that has earned a ban, and what earned it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Offender {
    pub ip: IpAddr,
    pub failures: u32,
}

/// Which addresses crossed the threshold inside the window.
///
/// A pure function of (events, now, window, threshold) so the policy is
/// assertable without a clock, a journal or a firewall. Events outside the
/// window are ignored rather than decayed: the spec's promise is "N failures in
/// M minutes", and a decay function would make "why was I banned?" impossible
/// to answer from the ban list.
///
/// The result is sorted worst-first, then by address, so a tick's log reads the
/// same way twice.
pub fn offenders(
    events: &[AuthFailure],
    now: OffsetDateTime,
    window: Duration,
    threshold: u32,
) -> Vec<Offender> {
    let cutoff = now - window;
    let mut counts: BTreeMap<IpAddr, u32> = BTreeMap::new();
    for event in events {
        if event.at >= cutoff {
            *counts.entry(canonical(event.ip)).or_default() += 1;
        }
    }
    let mut out: Vec<Offender> = counts
        .into_iter()
        .filter(|(_, n)| *n >= threshold)
        .map(|(ip, failures)| Offender { ip, failures })
        .collect();
    out.sort_by(|a, b| b.failures.cmp(&a.failures).then(a.ip.cmp(&b.ip)));
    out
}

// ---------------------------------------------------------------------------
// the drift merge
// ---------------------------------------------------------------------------

/// One rule as the panel and the firewall each see it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MergedRule {
    pub port: u16,
    pub proto: String,
    pub source: Option<String>,
    pub comment: String,
    /// The panel has a record of asking for this rule.
    pub in_panel: bool,
    /// The firewall is enforcing it right now.
    pub in_backend: bool,
    /// `None` when the two agree.
    pub drift: Option<&'static str>,
}

/// A rule recorded but not enforced — someone flushed the ruleset, or the
/// firewall was reinstalled, and the port the panel promised is shut.
pub const DRIFT_MISSING: &str = "missing_from_backend";
/// A Unihelm-marked rule the firewall is enforcing that the panel has no record
/// of — a restored database, or a rule opened by an older build.
pub const DRIFT_UNRECORDED: &str = "unrecorded";

/// The identity of a rule: what makes two rules "the same hole".
fn rule_key(port: u16, proto: &str, source: Option<&str>) -> (u16, String, String) {
    (
        port,
        proto.to_ascii_lowercase(),
        // An empty source string and a NULL both mean "from anywhere"; keeping
        // them distinct would report every unrestricted rule as drift.
        source
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("")
            .to_string(),
    )
}

/// Merge what the firewall is enforcing with what the panel recorded.
///
/// Both directions are reported, because both are real failures with different
/// fixes: a rule the panel promised and the firewall lost needs re-applying,
/// while a rule in the firewall the panel never recorded needs an operator to
/// decide whether it should be there at all. Hiding either would let the
/// firewall page show a comfortable fiction.
pub fn merge_rules(backend: &[PortRule], intent: &[FwRuleRecord]) -> Vec<MergedRule> {
    let mut merged: BTreeMap<(u16, String, String), MergedRule> = BTreeMap::new();

    for rule in intent {
        let key = rule_key(rule.port, &rule.proto, rule.source.as_deref());
        merged.insert(
            key,
            MergedRule {
                port: rule.port,
                proto: rule.proto.to_ascii_lowercase(),
                source: rule.source.clone(),
                comment: rule.comment.clone(),
                in_panel: true,
                in_backend: false,
                drift: Some(DRIFT_MISSING),
            },
        );
    }

    for rule in backend {
        let key = rule_key(rule.port, rule.proto.as_str(), rule.source.as_deref());
        match merged.get_mut(&key) {
            Some(existing) => {
                existing.in_backend = true;
                existing.drift = None;
            }
            None => {
                merged.insert(
                    key,
                    MergedRule {
                        port: rule.port,
                        proto: rule.proto.as_str().to_string(),
                        source: rule.source.clone(),
                        comment: rule.comment.clone(),
                        in_panel: false,
                        in_backend: true,
                        drift: Some(DRIFT_UNRECORDED),
                    },
                );
            }
        }
    }

    merged.into_values().collect()
}

// ---------------------------------------------------------------------------
// shared input validation
// ---------------------------------------------------------------------------

/// Turn the wire's `{port, proto, source, comment}` into a validated
/// [`PortRule`]. The backend validates again (spec §12 rule 4); doing it here
/// too means the panel's own record is never written from an input the
/// firewall would have rejected.
fn port_rule(port: u16, proto: &str, source: Option<&str>, comment: &str) -> Result<PortRule> {
    let proto = Proto::parse(proto).ok_or_else(|| {
        UnihelmError::new(ErrorCode::InvalidInput, "proto must be `tcp` or `udp`")
            .with_field("proto")
    })?;
    let rule = PortRule {
        port,
        proto,
        source: source
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string),
        comment: comment.to_string(),
    };
    rule.validate().map_err(UnihelmError::from)?;
    Ok(rule)
}

/// Parse an address from the wire, refusing anything that is not literally one.
fn parse_ip(text: &str, field: &'static str) -> Result<IpAddr> {
    text.trim().parse::<IpAddr>().map(canonical).map_err(|_| {
        UnihelmError::new(
            ErrorCode::InvalidInput,
            format!("`{text}` is not an IP address"),
        )
        .with_field(field)
    })
}

// ---------------------------------------------------------------------------
// operations
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct PortInput {
    pub port: u16,
    pub proto: String,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub comment: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct PortOutput {
    pub port: u16,
    pub proto: String,
    pub source: Option<String>,
    pub comment: String,
    /// Which backend did the work: `firewalld`, `ufw`, `nftables`, `none`.
    pub backend: &'static str,
}

/// `fw.port.open` — open a port, then record that we did (spec §11.9).
pub struct PortOpen;

#[async_trait]
impl TypedOperation for PortOpen {
    type Input = PortInput;
    type Output = PortOutput;

    const NAME: &'static str = "fw.port.open";
    const PERMISSION: Permission = Permission::FirewallManage;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let comment = input.comment.unwrap_or_default();
        let rule = port_rule(input.port, &input.proto, input.source.as_deref(), &comment)?;
        let fw = &ctx.distro().fw;

        // The backend first. An `Unmanaged` host answers with its own message
        // ("no firewall is installed on this host…") and we let that surface
        // verbatim rather than dressing it up as success: a panel that says
        // "port opened" when nothing was opened is worse than one that says
        // nothing (spec §11.9, and the module docs of unihelm_distro::fw).
        fw.open_port(&rule).await.map_err(UnihelmError::from)?;

        // Only now is the intent worth recording. Ordering matters: a record
        // written first would outlive a failed apply and show as drift forever.
        ctx.db()
            .record_fw_rule(
                rule.port,
                rule.proto.as_str(),
                rule.source.as_deref(),
                &rule.comment,
            )
            .await
            .map_err(UnihelmError::from)?;

        ctx.log(format!(
            "opened {}/{} for {} via {}",
            rule.port,
            rule.proto.as_str(),
            rule.source.as_deref().unwrap_or("anywhere"),
            fw.name()
        ));

        Ok(PortOutput {
            port: rule.port,
            proto: rule.proto.as_str().to_string(),
            source: rule.source,
            comment: rule.comment,
            backend: fw.name(),
        })
    }
}

/// `fw.port.close` — close a port we opened, then forget it.
pub struct PortClose;

#[async_trait]
impl TypedOperation for PortClose {
    type Input = PortInput;
    type Output = PortOutput;

    const NAME: &'static str = "fw.port.close";
    const PERMISSION: Permission = Permission::FirewallManage;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let comment = input.comment.unwrap_or_default();
        let rule = port_rule(input.port, &input.proto, input.source.as_deref(), &comment)?;
        let fw = &ctx.distro().fw;

        fw.close_port(&rule).await.map_err(UnihelmError::from)?;

        ctx.db()
            .forget_fw_rule(rule.port, rule.proto.as_str(), rule.source.as_deref())
            .await
            .map_err(UnihelmError::from)?;

        ctx.log(format!(
            "closed {}/{} via {}",
            rule.port,
            rule.proto.as_str(),
            fw.name()
        ));

        Ok(PortOutput {
            port: rule.port,
            proto: rule.proto.as_str().to_string(),
            source: rule.source,
            comment: rule.comment,
            backend: fw.name(),
        })
    }
}

#[derive(Debug, Deserialize)]
pub struct RulesInput {}

#[derive(Debug, Serialize)]
pub struct RulesOutput {
    pub backend: &'static str,
    /// Is the firewall actually running? `false` with an `nftables` backend
    /// name means nothing is being enforced right now.
    pub active: bool,
    pub rules: Vec<MergedRule>,
}

/// `fw.rules` — the merged view: what the firewall enforces, what the panel
/// recorded, and where the two disagree.
pub struct Rules;

#[async_trait]
impl TypedOperation for Rules {
    type Input = RulesInput;
    type Output = RulesOutput;

    const NAME: &'static str = "fw.rules";
    // Reading the firewall reveals the host's exposed surface, so it needs the
    // same permission as changing it rather than a general read.
    const PERMISSION: Permission = Permission::FirewallManage;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, _input: Self::Input) -> Result<Self::Output> {
        let fw = &ctx.distro().fw;
        let live = fw.list_rules().await.map_err(UnihelmError::from)?;
        let intent = ctx.db().fw_rules().await.map_err(UnihelmError::from)?;
        Ok(RulesOutput {
            backend: fw.name(),
            active: fw.is_active().await.unwrap_or(false),
            rules: merge_rules(&live, &intent),
        })
    }
}

// ---------------------------------------------------------------------------
// starting and stopping the firewall itself
// ---------------------------------------------------------------------------

/// How a backend is switched on and off, or why it cannot be.
///
/// [`unihelm_distro::FwBackend`] has no lifecycle call, so the two backends
/// that have a switch are driven from here. The distinction between them is not
/// cosmetic: ufw and firewalld are started by different things, and the other
/// two are not started at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lifecycle {
    /// `ufw enable` / `ufw disable`, never the unit.
    ///
    /// `ufw.service` starts on every boot regardless and then does nothing
    /// while `/etc/ufw/ufw.conf` says `ENABLED=no` — which is exactly the state
    /// this feature exists for. `systemctl start ufw` there exits 0, changes
    /// nothing, and would have the panel report a success `ufw status` flatly
    /// contradicts.
    Ufw,
    /// `firewalld.service`. The daemon *is* the firewall; there is no second
    /// switch to throw.
    Firewalld,
    /// Nothing the panel can honestly claim to start or stop, and why.
    Unsupported(String),
}

/// firewalld's unit.
///
/// Deliberately not a [`unihelm_distro::ManagedUnit`]: that enum is the
/// whitelist of units `svc.action` may be *asked* for, and its job is to keep a
/// name off the wire from reaching systemd. This name is a constant in this
/// file and reachable only through `fw.enable`/`fw.disable`, which the firewall
/// permission already guards.
const FIREWALLD_UNIT: &str = "firewalld.service";

impl Lifecycle {
    pub fn for_backend(backend: &str) -> Self {
        match backend {
            "ufw" => Lifecycle::Ufw,
            "firewalld" => Lifecycle::Firewalld,
            // nftables has no on/off switch that belongs to us. Our accept
            // rules live in one `inet unihelm` table beside whatever else the
            // operator loaded; `nftables.service` loads `/etc/nftables.conf`, a
            // file the panel has never read, and stopping it flushes rules the
            // panel did not write. Both directions would be the panel changing
            // somebody else's firewall on their behalf.
            "nftables" => Lifecycle::Unsupported(
                "nftables has no service the panel owns. Starting one would load \
                 /etc/nftables.conf, a file Unihelm has never read, and stopping it would \
                 flush rules Unihelm did not add — so this is a change to make from a \
                 shell, where you can see the whole ruleset first."
                    .into(),
            ),
            "none" => Lifecycle::Unsupported(
                "no firewall is installed on this host (looked for firewalld, ufw and nft), \
                 so there is nothing to start or stop"
                    .into(),
            ),
            other => Lifecycle::Unsupported(format!(
                "the `{other}` firewall backend has no start or stop the panel can drive"
            )),
        }
    }

    /// The error for a backend with no switch, or `None` when there is one.
    pub fn refusal(&self) -> Option<UnihelmError> {
        match self {
            Lifecycle::Unsupported(reason) => {
                Some(UnihelmError::new(ErrorCode::NotImplemented, reason.clone()))
            }
            Lifecycle::Ufw | Lifecycle::Firewalld => None,
        }
    }
}

/// OpenSSH's own default, used only when nothing sets `Port` and labelled as an
/// assumption wherever it reaches the operator.
const DEFAULT_SSH_PORT: u16 = 22;

/// How the SSH port was established, so a refusal can say how it knows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SshPortSource {
    SshdT,
    Files,
    Default,
}

impl SshPortSource {
    /// The phrase the refusal message uses, which is also how the operator
    /// would check the same thing by hand.
    pub const fn describe(self) -> &'static str {
        match self {
            SshPortSource::SshdT => "reported by `sshd -T`",
            SshPortSource::Files => "read from sshd_config and its drop-ins",
            SshPortSource::Default => "OpenSSH's default, because nothing sets `Port`",
        }
    }
}

/// What is known about SSH on this host, in the three shapes that lead to three
/// different decisions about enabling.
///
/// Adjacently tagged for the reason `posture::Observed` is: the payload of one
/// variant is a map and of another is nothing at all, and an internal tag
/// cannot be folded into both.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum SshFacts {
    /// sshd accepts connections on these ports.
    Ports {
        ports: Vec<u16>,
        source: SshPortSource,
    },
    /// No sshd configuration on this host at all, so enabling has no SSH
    /// session to cut.
    Absent,
    /// sshd is here and the panel could not work out which port it uses. Fatal
    /// to an enable: a default-deny firewall holding the wrong port open is the
    /// outage this whole guard exists to prevent.
    Unknown { reason: String },
}

/// The ports in `sshd -T` output.
///
/// `port` is one of sshd's *multi-valued* keywords: every `Port` in the settled
/// configuration is printed on its own line and sshd listens on all of them.
/// That is the opposite of the first-value-wins rule `posture::parse_sshd_t`
/// applies to the keywords it reads, and getting it backwards here would leave
/// a second SSH port shut the moment the firewall came up.
pub fn parse_sshd_ports(output: &str) -> Vec<u16> {
    let mut ports: Vec<u16> = Vec::new();
    for line in output.lines() {
        let mut parts = line.split_whitespace();
        if parts.next() != Some("port") {
            continue;
        }
        if let Some(port) = parts.next().and_then(|p| p.parse::<u16>().ok())
            && port != 0
            && !ports.contains(&port)
        {
            ports.push(port);
        }
    }
    ports
}

/// The `Port` directives in `sshd_config`-style files, for when `sshd -T` will
/// not run.
///
/// Same accumulate-rather-than-override rule as above, and `Match` blocks are
/// skipped for the reason `posture::parse_sshd_files` skips them: what follows
/// a `Match` applies to some connections only, and this guard is about all of
/// them.
pub fn parse_sshd_config_ports(ordered: &[(String, String)]) -> Vec<u16> {
    let mut ports: Vec<u16> = Vec::new();
    for (_name, contents) in ordered {
        let mut in_match = false;
        for raw in contents.lines() {
            let line = raw.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let mut parts = line.splitn(2, char::is_whitespace);
            let key = parts.next().unwrap_or("").to_ascii_lowercase();
            if key == "match" {
                in_match = true;
                continue;
            }
            if in_match || key != "port" {
                continue;
            }
            if let Some(port) = parts.next().and_then(|v| v.trim().parse::<u16>().ok())
                && port != 0
                && !ports.contains(&port)
            {
                ports.push(port);
            }
        }
    }
    ports
}

/// ufw rule shapes that mean "SSH", by the names ufw accepts for it.
///
/// `ufw allow OpenSSH` is what Ubuntu's own documentation tells people to type
/// and `ufw limit ssh` is what everyone else types. A guard that only
/// understood `22/tcp` would tell both of them their SSH port is shut and
/// offer to open a rule they already have.
const UFW_SSH_ALIASES: &[&str] = &["ssh", "openssh"];

/// Read `ufw show added`.
///
/// `ufw status` is no use here and that is the whole reason this parser exists:
/// while ufw is inactive it prints `Status: inactive` and not one rule, so the
/// check that decides whether enabling is safe would see an empty ruleset on
/// exactly the machines it exists to protect. `show added` prints the
/// `ufw allow …` commands instead, running or not.
///
/// Only rules that would admit a *new inbound connection to this host* count.
/// `route` rules filter forwarded traffic, `out` rules leave the host, and
/// `on <iface>` binds a rule to one interface that cannot be matched against
/// the route the operator arrives by — none of the three is evidence that an
/// SSH connection would be accepted, so they are skipped rather than
/// generously assumed.
pub fn parse_ufw_added(text: &str) -> Vec<PortRule> {
    let mut rules = Vec::new();
    for line in text.lines() {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        let Some(at) = tokens.iter().position(|t| *t == "ufw") else {
            continue;
        };
        // Everything after `comment` is operator prose and is not read for any
        // purpose: `ufw allow 22/tcp comment 'ssh on the jump box'` is an
        // inbound rule, and a scan that saw the `on` in the prose would drop it
        // and tell that operator their SSH port is shut.
        let rest = match tokens[at + 1..].iter().position(|t| *t == "comment") {
            Some(end) => &tokens[at + 1..at + 1 + end],
            None => &tokens[at + 1..],
        };
        if rest.iter().any(|t| matches!(*t, "route" | "out" | "on")) {
            continue;
        }
        // `limit` is `allow` with rate limiting. `ufw limit ssh` is the most
        // widely recommended SSH rule there is, and reading it as "not allowed"
        // would make this guard refuse the hosts that did the right thing.
        let Some(action) = rest.first() else {
            continue;
        };
        if !matches!(*action, "allow" | "limit") {
            continue;
        }

        let body = &rest[1..];
        let mut source: Option<String> = None;
        let mut port: Option<u16> = None;
        let mut proto: Option<Proto> = None;
        let mut index = 0;
        while index < body.len() {
            match body[index] {
                "from" => {
                    source = body.get(index + 1).map(|s| (*s).to_string());
                    index += 2;
                }
                "port" => {
                    port = body.get(index + 1).and_then(|p| p.parse().ok());
                    index += 2;
                }
                "proto" => {
                    proto = body.get(index + 1).and_then(|p| Proto::parse(p));
                    index += 2;
                }
                "to" | "any" | "in" => index += 1,
                token => {
                    if port.is_none() {
                        let (number, spelled) = match token.split_once('/') {
                            Some((n, p)) => (n, Proto::parse(p)),
                            None => (token, None),
                        };
                        if let Ok(parsed) = number.parse::<u16>() {
                            port = Some(parsed);
                            proto = spelled.or(proto);
                        } else if UFW_SSH_ALIASES.contains(&token.to_ascii_lowercase().as_str()) {
                            port = Some(DEFAULT_SSH_PORT);
                            proto = Some(Proto::Tcp);
                        }
                    }
                    index += 1;
                }
            }
        }

        let Some(port) = port.filter(|p| *p != 0) else {
            continue;
        };
        rules.push(PortRule {
            port,
            // A bare `ufw allow 22` covers both protocols; recording it as TCP
            // is the half this guard asks about.
            proto: proto.unwrap_or(Proto::Tcp),
            source: source.filter(|s| validate_source(s)),
            comment: String::new(),
        });
    }
    rules
}

/// A source we are willing to reason about: a literal address or CIDR.
///
/// Anything else — `any`, an interface, a hostname — is dropped rather than
/// kept, because a source this code cannot evaluate must not be treated as
/// covering the operator.
fn validate_source(source: &str) -> bool {
    parse_cidr(source).is_some()
}

/// Would anything here accept an SSH connection to `port` from where the
/// operator is?
///
/// A source-restricted rule counts only when the caller is inside it. A
/// firewall that allows 22 from the office and nothing else still locks out the
/// admin working from home, and that is the same outage with a nicer name — so
/// is a restricted rule when the web layer could not tell us the caller's
/// address at all.
pub fn ssh_reachable(rules: &[PortRule], port: u16, client_ip: Option<IpAddr>) -> bool {
    rules.iter().any(|rule| {
        rule.port == port
            && rule.proto == Proto::Tcp
            && match &rule.source {
                None => true,
                Some(cidr) => client_ip.is_some_and(|ip| cidr_contains(cidr, ip)),
            }
    })
}

/// The SSH ports that would be shut the moment the firewall came up.
pub fn unprotected_ssh_ports(
    rules: &[PortRule],
    ssh_ports: &[u16],
    client_ip: Option<IpAddr>,
) -> Vec<u16> {
    ssh_ports
        .iter()
        .copied()
        .filter(|port| !ssh_reachable(rules, *port, client_ip))
        .collect()
}

/// Read `sshd_config` and every `sshd_config.d/*.conf`.
///
/// Order does not matter to [`parse_sshd_config_ports`] the way it matters to
/// `posture::parse_sshd_files` — every `Port` counts, whichever file it is in —
/// so this walk is deliberately the simpler one.
fn read_sshd_files(main: &std::path::Path, dir: &std::path::Path) -> Vec<(String, String)> {
    let mut out = Vec::new();
    if let Ok(contents) = std::fs::read_to_string(main) {
        out.push((main.display().to_string(), contents));
    }
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("conf") {
                continue;
            }
            if let Ok(contents) = std::fs::read_to_string(&path) {
                out.push((path.display().to_string(), contents));
            }
        }
    }
    out
}

/// Ask sshd, then its files, then admit we do not know.
///
/// The order is `posture::gather_sshd`'s, for its reason: `sshd -T` prints the
/// settled configuration with every `Include` resolved, and it is the only
/// answer that cannot be wrong about which drop-in won.
async fn ssh_facts() -> SshFacts {
    // argv, never a pipeline (spec §12 rule 2) — the parsing happens in
    // `parse_sshd_ports`, where it is testable.
    if let Ok(out) = unihelm_distro::Cmd::new("sshd")
        .arg("-T")
        .timeout(std::time::Duration::from_secs(10))
        .run()
        .await
        && out.success()
    {
        let ports = parse_sshd_ports(&out.stdout);
        if !ports.is_empty() {
            return SshFacts::Ports {
                ports,
                source: SshPortSource::SshdT,
            };
        }
    }

    let main = paths::sshd_config();
    let dir = paths::sshd_config_dir();
    let files = read_sshd_files(&main, &dir);
    if files.is_empty() {
        // A host with neither `sshd -T` nor a configuration file is a host with
        // no sshd. A host that has the file and would not give it to us is a
        // host we must not guess about.
        return if main.exists() || dir.exists() {
            SshFacts::Unknown {
                reason: format!(
                    "`sshd -T` did not run and {} could not be read",
                    main.display()
                ),
            }
        } else {
            SshFacts::Absent
        };
    }

    match parse_sshd_config_ports(&files) {
        ports if ports.is_empty() => SshFacts::Ports {
            ports: vec![DEFAULT_SSH_PORT],
            source: SshPortSource::Default,
        },
        ports => SshFacts::Ports {
            ports,
            source: SshPortSource::Files,
        },
    }
}

/// What the panel could see of the ruleset that is about to be enforced, and
/// what it could not.
///
/// The distinction is the whole point. A view that holds a matching rule proves
/// SSH is admitted. A view with nothing matching proves SSH is shut *only if it
/// is complete* — and on firewalld it very often is not, because a zone admits
/// SSH through a named service whose port list lives in a separate file. A
/// guard that treated an incomplete view as proof would tell a correctly
/// configured operator their SSH is shut and then offer to widen a firewall
/// that never needed widening.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct AdmittingView {
    /// Rules that would admit a new inbound connection to this host.
    pub rules: Vec<PortRule>,
    /// Parts of the ruleset the panel read but could not decode into ports —
    /// firewalld services whose definition would not open, rich rules in a
    /// shape this file does not know. Any of these may be what admits SSH.
    pub opaque: Vec<String>,
}

impl AdmittingView {
    /// Is this view good enough to conclude that SSH is *shut*?
    fn is_complete(&self) -> bool {
        self.opaque.is_empty()
    }
}

/// firewalld's offline client, used because the daemon is stopped.
///
/// `firewall-cmd` is a D-Bus client: with firewalld down every call fails, so
/// the permanent configuration cannot be read through it. That is the reason
/// the first version of this guard started the daemon and *then* checked, which
/// is a change to the host made before the check that decides whether to change
/// the host — and a rollback that could not put back hand-written netfilter
/// rules firewalld had already replaced. `firewall-offline-cmd` is what
/// firewalld ships for exactly this, and it reads and writes the same permanent
/// configuration the daemon will load when it comes up.
///
/// Only ever called while `is_active()` says the daemon is down; running it
/// against a live firewalld is what its own manual warns against.
const FIREWALLD_OFFLINE: &str = "firewall-offline-cmd";

/// Read the ports out of `firewall-offline-cmd --service=<n> --get-ports`,
/// which prints `22/tcp` or a space-separated list of the same.
fn parse_port_tokens(text: &str) -> Vec<PortRule> {
    text.split_whitespace()
        .filter_map(|token| {
            let (port, proto) = token.split_once('/')?;
            Some(PortRule {
                port: port.parse::<u16>().ok().filter(|p| *p != 0)?,
                proto: Proto::parse(proto)?,
                source: None,
                comment: String::new(),
            })
        })
        .collect()
}

/// Read one zone out of `firewall-offline-cmd --list-all`.
///
/// Returns the rules it could decode and the names of the services it could
/// not, which the caller resolves separately. `services:` is the line this
/// guard exists to read: a stock RHEL host admits SSH through the `ssh`
/// service and has no port rule for 22 at all, so a check that looked only at
/// `ports:` and `rich rules:` — which is all `FwBackend::list_rules` reads —
/// would find nothing on the most ordinary firewalld box there is.
pub fn parse_firewalld_zone(text: &str) -> (AdmittingView, Vec<String>) {
    let mut view = AdmittingView::default();
    let mut services = Vec::new();

    for raw in text.lines() {
        let line = raw.trim();
        if let Some(rest) = line.strip_prefix("ports:") {
            view.rules.extend(parse_port_tokens(rest));
        } else if let Some(rest) = line.strip_prefix("services:") {
            services.extend(rest.split_whitespace().map(str::to_string));
        } else if line.starts_with("rule ") {
            match parse_firewalld_rich_rule(line) {
                Some(rule) => view.rules.push(rule),
                // Not decoded and not dismissed: a rich rule this parser does
                // not understand may be the one holding SSH open.
                None if line.ends_with("accept") => view.opaque.push(line.to_string()),
                None => {}
            }
        }
    }

    (view, services)
}

/// The accepting rich rules whose port this file can name.
///
/// Deliberately narrow, like `unihelm_distro`'s own rich-rule parser: anything
/// else returns `None` and the caller records it as undecoded rather than as
/// absent. A rich rule that rejects or drops is not evidence of anything and is
/// not reported as opaque either — it cannot be what admits a connection.
fn parse_firewalld_rich_rule(line: &str) -> Option<PortRule> {
    if !line.ends_with("accept") {
        return None;
    }
    let attribute = |key: &str| -> Option<&str> {
        let at = line.find(key)?;
        let rest = &line[at + key.len()..];
        rest.strip_prefix('"')?.split('"').next()
    };

    let port = attribute("port port=")?.parse::<u16>().ok()?;
    let proto = Proto::parse(attribute("protocol=")?)?;
    Some(PortRule {
        port,
        proto,
        source: attribute("source address=")
            .map(str::to_string)
            .filter(|s| validate_source(s)),
        comment: String::new(),
    })
}

/// Run one `firewall-offline-cmd`, failing closed.
async fn firewalld_offline(args: &[&str]) -> Result<String> {
    let cmd = unihelm_distro::Cmd::new(FIREWALLD_OFFLINE).args(args);
    let out = cmd.run().await.map_err(UnihelmError::from)?;
    if !out.success() {
        return Err(UnihelmError::new(
            ErrorCode::CommandFailed,
            format!("`{}` failed: {}", cmd.display(), out.failure_text()),
        ));
    }
    Ok(out.stdout)
}

/// The rules the SSH guard reasons over, read the only way that works for this
/// backend in the state it is in.
async fn admitting_view(lifecycle: &Lifecycle) -> Result<AdmittingView> {
    match lifecycle {
        Lifecycle::Ufw => {
            let cmd = unihelm_distro::Cmd::new("ufw").args(["show", "added"]);
            let out = cmd.run().await.map_err(UnihelmError::from)?;
            if !out.success() {
                return Err(UnihelmError::new(
                    ErrorCode::CommandFailed,
                    format!("`{}` failed: {}", cmd.display(), out.failure_text()),
                ));
            }
            Ok(AdmittingView {
                rules: parse_ufw_added(&out.stdout),
                opaque: Vec::new(),
            })
        }
        Lifecycle::Firewalld => {
            let (mut view, services) =
                parse_firewalld_zone(&firewalld_offline(&["--list-all"]).await?);
            for name in services {
                // Resolved one at a time so a single unreadable definition
                // costs that service and not the whole answer.
                match firewalld_offline(&[&format!("--service={name}"), "--get-ports"]).await {
                    Ok(ports) => view.rules.extend(parse_port_tokens(&ports)),
                    Err(_) => view.opaque.push(name),
                }
            }
            Ok(view)
        }
        // Unreachable in practice: `Enable` turns these backends away before it
        // asks for a view. It still says no rather than substituting
        // `list_rules`, which reads a different thing on every backend — a
        // wrong view is worse here than no view, because the whole decision
        // downstream is "does anything in this admit SSH".
        Lifecycle::Unsupported(reason) => {
            Err(UnihelmError::new(ErrorCode::NotImplemented, reason.clone()))
        }
    }
}

/// Open one port ahead of the start, by whichever client works with this
/// backend stopped.
///
/// firewalld cannot go through [`unihelm_distro::FwBackend::open_port`] here:
/// that speaks to the daemon over D-Bus and the daemon is down, which is the
/// state this whole path is about. Writing the permanent configuration offline
/// keeps the ordering that matters — the port exists before anything starts
/// enforcing — instead of starting a default-deny firewall and racing to widen
/// it.
async fn open_before_start(ctx: &OpContext, lifecycle: &Lifecycle, rule: &PortRule) -> Result<()> {
    match lifecycle {
        Lifecycle::Firewalld => {
            firewalld_offline(&[&format!("--add-port={}/{}", rule.port, rule.proto.as_str())])
                .await?;
            Ok(())
        }
        // ufw reads and writes its rule list happily while stopped.
        _ => ctx
            .distro()
            .fw
            .open_port(rule)
            .await
            .map_err(UnihelmError::from),
    }
}

/// The guard: the one thing that must be true before a default-deny firewall
/// comes up. Returns the ports it had to open to make it true.
///
/// It refuses rather than guessing when it cannot tell which port sshd uses,
/// and it refuses rather than widening the ruleset unasked when SSH is shut —
/// opening a hole is the operator's decision, and `allow_ssh` is where they
/// make it.
async fn ensure_ssh_reachable(
    ctx: &OpContext,
    lifecycle: &Lifecycle,
    view: &AdmittingView,
    ssh: &SshFacts,
    client_ip: Option<IpAddr>,
    allow_ssh: bool,
) -> Result<Vec<u16>> {
    let (ports, source) = match ssh {
        SshFacts::Absent => {
            ctx.log("no sshd configuration on this host, so there is no SSH port to keep open");
            return Ok(Vec::new());
        }
        SshFacts::Unknown { reason } => {
            return Err(UnihelmError::new(
                ErrorCode::Conflict,
                format!(
                    "refusing to start the firewall: this host runs sshd and the panel could \
                     not work out which port it listens on ({reason}). Bringing up a \
                     default-deny firewall without a rule for that port ends every SSH \
                     session to this server and every one after it."
                ),
            ));
        }
        SshFacts::Ports { ports, source } => (ports, *source),
    };

    let unprotected = unprotected_ssh_ports(&view.rules, ports, client_ip);
    if unprotected.is_empty() {
        return Ok(Vec::new());
    }

    let listed = unprotected
        .iter()
        .map(|p| format!("{p}/tcp"))
        .collect::<Vec<_>>()
        .join(", ");

    if !allow_ssh {
        // Two different sentences, because they are two different claims. With
        // a complete view the panel knows SSH is shut and says so. With an
        // undecoded fragment in the ruleset it knows only that it cannot tell,
        // and stating the stronger claim would send an operator whose firewall
        // is fine chasing a lockout that is not there — and, if they believed
        // it, would have them open a port they already had open.
        let detail = if view.is_complete() {
            format!(
                "refusing to start the firewall: no rule in it would accept an SSH \
                 connection to {listed} ({}) from where you are, and its default policy \
                 for incoming traffic is deny. Open that port first, or ask again with \
                 `allow_ssh` to have the panel open it before starting.",
                source.describe()
            )
        } else {
            format!(
                "refusing to start the firewall: nothing the panel could read would accept \
                 an SSH connection to {listed} ({}), and it could not read all of this \
                 ruleset — {} is undecoded, and may be exactly what holds SSH open. Check \
                 that part by hand, or ask again with `allow_ssh` to have the panel open \
                 the port before starting.",
                source.describe(),
                view.opaque.join(", ")
            )
        };
        return Err(UnihelmError::new(ErrorCode::Conflict, detail).with_field("allow_ssh"));
    }

    for port in &unprotected {
        let rule = PortRule::anywhere(*port, Proto::Tcp, "ssh");
        // Backend first, record second — the ordering `fw.port.open` uses and
        // for its reason: a record written first would outlive a failed apply
        // and show as drift forever.
        open_before_start(ctx, lifecycle, &rule).await?;
        ctx.db()
            .record_fw_rule(rule.port, rule.proto.as_str(), None, &rule.comment)
            .await
            .map_err(UnihelmError::from)?;
        ctx.log(format!(
            "opened {port}/tcp from anywhere for SSH before starting the firewall"
        ));
    }
    Ok(unprotected)
}

/// ufw's own switch.
///
/// `--force` on the way in because a bare `ufw enable` asks "Command may
/// disrupt existing ssh connections. Proceed with operation (y|n)?" on a
/// terminal the agent does not have; without it the call sits until the command
/// timeout and reports a failure that never happened. The question it is asking
/// is the one [`ensure_ssh_reachable`] has already answered properly.
async fn ufw_switch(on: bool) -> Result<()> {
    let cmd = if on {
        unihelm_distro::Cmd::new("ufw").args(["--force", "enable"])
    } else {
        unihelm_distro::Cmd::new("ufw").arg("disable")
    };
    let out = cmd.run().await.map_err(UnihelmError::from)?;
    if out.success() {
        return Ok(());
    }
    Err(UnihelmError::new(
        ErrorCode::CommandFailed,
        format!("`{}` failed: {}", cmd.display(), out.failure_text()),
    ))
}

/// firewalld's unit, through the service backend like any other unit.
///
/// `--now` in both directions, so "started" and "stopped" both survive a
/// reboot. A firewall that comes back on its own after an operator stopped it —
/// or, worse, is gone again after they started it — is a firewall whose state
/// nobody can reason about.
async fn firewalld_switch(ctx: &OpContext, on: bool) -> Result<()> {
    let unit = unihelm_distro::UnitName::parse(FIREWALLD_UNIT).map_err(UnihelmError::from)?;
    let svc = &ctx.distro().svc;
    if on {
        svc.enable(&unit, true).await
    } else {
        svc.disable(&unit, true).await
    }
    .map_err(UnihelmError::from)
}

#[derive(Debug, Default, Deserialize)]
pub struct EnableInput {
    /// Open the SSH port first when nothing already admits it. Absent means
    /// refuse instead: starting a firewall is not the moment to widen a
    /// ruleset nobody asked to widen.
    #[serde(default)]
    pub allow_ssh: bool,
    /// The address the request arrived from, filled in by the web layer from
    /// the live connection exactly as `fw.ban`'s is. It is what decides whether
    /// a source-restricted SSH rule protects *this* operator.
    #[serde(default)]
    pub client_ip: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct EnableOutput {
    pub backend: &'static str,
    /// Read back from the backend after the switch, never assumed from an exit
    /// code.
    pub active: bool,
    /// What the panel found out about sshd, so the page can show the port it
    /// protected and where that number came from.
    pub ssh: SshFacts,
    /// Ports this call had to open before starting was safe.
    pub opened: Vec<u16>,
}

/// `fw.enable` — start the firewall, and refuse to do it in the one way that
/// takes the operator's server away from them.
///
/// The whole operation is the SSH check. A stopped ufw with a dozen recorded
/// rules and a default incoming policy of deny is one command away from
/// enforcing all of them, and if none of them is the port sshd answers on, the
/// operator's next login is refused by a firewall they can now only reach
/// through a console.
pub struct Enable;

#[async_trait]
impl TypedOperation for Enable {
    type Input = EnableInput;
    type Output = EnableOutput;

    const NAME: &'static str = "fw.enable";
    const PERMISSION: Permission = Permission::FirewallManage;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let fw = &ctx.distro().fw;
        let lifecycle = Lifecycle::for_backend(fw.name());
        if let Some(refusal) = lifecycle.refusal() {
            return Err(refusal);
        }

        let client_ip = input
            .client_ip
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .and_then(|s| s.parse::<IpAddr>().ok())
            .map(canonical);
        let ssh = ssh_facts().await;

        // Already running is the state the caller asked for. An error here
        // would send an operator who clicked twice looking for a problem that
        // is not there.
        if fw.is_active().await.unwrap_or(false) {
            return Ok(EnableOutput {
                backend: fw.name(),
                active: true,
                ssh,
                opened: Vec::new(),
            });
        }

        // Both backends are read and written while stopped — ufw through its
        // own client, firewalld through `firewall-offline-cmd` — so the guard
        // runs to completion before anything on the host changes and a refusal
        // leaves the machine untouched. That ordering is not a nicety: starting
        // firewalld to look at it replaces whatever is in netfilter, and
        // stopping it again does not put a hand-written ruleset back.
        let view = admitting_view(&lifecycle).await?;
        let opened =
            ensure_ssh_reachable(ctx, &lifecycle, &view, &ssh, client_ip, input.allow_ssh).await?;
        match lifecycle {
            Lifecycle::Ufw => ufw_switch(true).await?,
            _ => firewalld_switch(ctx, true).await?,
        }

        // Read back rather than trusting the exit code. "port opened" while
        // nothing is enforcing is the lie this module exists not to tell, and
        // "firewall started" is the same lie one level up.
        let active = fw.is_active().await.unwrap_or(false);
        if !active {
            return Err(UnihelmError::new(
                ErrorCode::CommandFailed,
                format!(
                    "{} reported that it started and then said it is not running; nothing is \
                     being enforced",
                    fw.name()
                ),
            ));
        }

        ctx.log(format!("started {}", fw.name()));
        Ok(EnableOutput {
            backend: fw.name(),
            active,
            ssh,
            opened,
        })
    }
}

#[derive(Debug, Deserialize)]
pub struct DisableInput {}

#[derive(Debug, Serialize)]
pub struct DisableOutput {
    pub backend: &'static str,
    pub active: bool,
    /// Rules the backend was enforcing a moment ago and now is not.
    pub rules_unenforced: usize,
    /// Addresses the backend was dropping a moment ago and now is not.
    pub bans_unenforced: usize,
}

/// `fw.disable` — stop the firewall.
///
/// Not destructive: every rule and every ban stays recorded, and `fw.rules`
/// starts labelling them "recorded, not enforced", which is the truth. What is
/// dangerous about it is the other direction — the host is unfiltered from the
/// moment this returns, including for the addresses Sentinel is banning — so
/// the counts of what stopped being enforced are read *before* the stop and
/// returned, and the UI confirms with them in front of the operator.
pub struct Disable;

#[async_trait]
impl TypedOperation for Disable {
    type Input = DisableInput;
    type Output = DisableOutput;

    const NAME: &'static str = "fw.disable";
    const PERMISSION: Permission = Permission::FirewallManage;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, _input: Self::Input) -> Result<Self::Output> {
        let fw = &ctx.distro().fw;
        let lifecycle = Lifecycle::for_backend(fw.name());
        if let Some(refusal) = lifecycle.refusal() {
            return Err(refusal);
        }

        if !fw.is_active().await.unwrap_or(false) {
            return Ok(DisableOutput {
                backend: fw.name(),
                active: false,
                rules_unenforced: 0,
                bans_unenforced: 0,
            });
        }

        // Counted before the stop: afterwards the backend has nothing left to
        // count, and the operator would be told "0 rules stopped being
        // enforced" about a firewall that was holding a dozen.
        let rules_unenforced = fw.list_rules().await.map(|r| r.len()).unwrap_or(0);
        let bans_unenforced = fw.list_bans().await.map(|b| b.len()).unwrap_or(0);

        match lifecycle {
            Lifecycle::Ufw => ufw_switch(false).await?,
            _ => firewalld_switch(ctx, false).await?,
        }

        ctx.log(format!(
            "stopped {}: {rules_unenforced} rule(s) and {bans_unenforced} ban(s) are no longer \
             enforced",
            fw.name()
        ));

        Ok(DisableOutput {
            backend: fw.name(),
            active: fw.is_active().await.unwrap_or(false),
            rules_unenforced,
            bans_unenforced,
        })
    }
}

#[derive(Debug, Deserialize)]
pub struct BanInput {
    pub ip: String,
    /// How long the ban lasts. Absent means "the configured default"; an
    /// explicit `0` means permanent, which is only ever an operator's choice —
    /// Sentinel itself always sets a TTL.
    #[serde(default)]
    pub minutes: Option<u32>,
    #[serde(default)]
    pub reason: Option<String>,
    /// The address the request arrived from, filled in by the web layer from
    /// the live connection. It exists so an admin cannot ban themselves; see
    /// the module docs.
    #[serde(default)]
    pub client_ip: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct BanOutput {
    pub ip: String,
    pub expires_at: Option<String>,
    pub backend: &'static str,
}

/// `fw.ban` — drop an address at the firewall.
pub struct Ban;

#[async_trait]
impl TypedOperation for Ban {
    type Input = BanInput;
    type Output = BanOutput;

    const NAME: &'static str = "fw.ban";
    const PERMISSION: Permission = Permission::FirewallManage;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let ip = parse_ip(&input.ip, "ip")?;
        let client_ip = input
            .client_ip
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .and_then(|s| s.parse::<IpAddr>().ok());

        let settings = SentinelSettings::load(ctx.db()).await;
        let guard = BanGuard::for_request(client_ip, &settings);
        // The refusal is checked before anything touches the firewall, and it
        // is a hard `Conflict` rather than a warning: there is no argument
        // that makes banning your own address the right outcome.
        if let Some(reason) = refusal_reason(ip, &guard) {
            return Err(UnihelmError::new(ErrorCode::Conflict, reason).with_field("ip"));
        }

        let minutes = input.minutes.unwrap_or(settings.ban_minutes);
        let expires_at =
            (minutes > 0).then(|| unihelm_db::now() + Duration::minutes(i64::from(minutes)));
        let ttl_seconds = (minutes > 0).then(|| minutes.saturating_mul(60));

        let fw = &ctx.distro().fw;
        fw.ban_ip(ip, ttl_seconds)
            .await
            .map_err(UnihelmError::from)?;

        let reason = input
            .reason
            .filter(|r| !r.trim().is_empty())
            .unwrap_or_else(|| "banned by an operator".into());
        ctx.db()
            .record_ban(&ip.to_string(), &reason, expires_at)
            .await
            .map_err(UnihelmError::from)?;

        ctx.log(format!("banned {ip} via {} ({reason})", fw.name()));

        Ok(BanOutput {
            ip: ip.to_string(),
            expires_at: expires_at.map(unihelm_db::to_sql_time),
            backend: fw.name(),
        })
    }
}

#[derive(Debug, Deserialize)]
pub struct UnbanInput {
    pub ip: String,
}

#[derive(Debug, Serialize)]
pub struct UnbanOutput {
    pub ip: String,
    /// How many open ban records this closed. Zero means the address was not
    /// banned by us — reported rather than papered over, because "unbanned!"
    /// for an address still blocked by an operator's own rule is a lie.
    pub lifted: u64,
    pub backend: &'static str,
}

/// `fw.unban` — lift a ban.
pub struct Unban;

#[async_trait]
impl TypedOperation for Unban {
    type Input = UnbanInput;
    type Output = UnbanOutput;

    const NAME: &'static str = "fw.unban";
    const PERMISSION: Permission = Permission::FirewallManage;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let ip = parse_ip(&input.ip, "ip")?;
        let fw = &ctx.distro().fw;

        // The firewall first, again: a record closed before the address is
        // actually released would leave somebody blocked with nothing in the
        // panel to explain it.
        fw.unban_ip(ip).await.map_err(UnihelmError::from)?;
        let lifted = ctx
            .db()
            .lift_bans_for(&ip.to_string())
            .await
            .map_err(UnihelmError::from)?;

        ctx.log(format!("unbanned {ip} via {}", fw.name()));
        Ok(UnbanOutput {
            ip: ip.to_string(),
            lifted,
            backend: fw.name(),
        })
    }
}

#[derive(Debug, Deserialize)]
pub struct BansInput {
    #[serde(default)]
    pub limit: Option<i64>,
}

/// A ban row plus whether the firewall is really holding it.
#[derive(Debug, Serialize)]
pub struct BanView {
    #[serde(flatten)]
    pub ban: SentinelBan,
    /// The address is in the backend's ban set right now.
    pub in_backend: bool,
}

#[derive(Debug, Serialize)]
pub struct BansOutput {
    pub backend: &'static str,
    pub bans: Vec<BanView>,
    /// Addresses the firewall is dropping that the panel has no open record
    /// for — the ban-list half of the same drift the rules view reports.
    pub unrecorded: Vec<String>,
}

/// `fw.bans` — the ban list, with the same panel-versus-backend honesty the
/// rules view has.
pub struct Bans;

#[async_trait]
impl TypedOperation for Bans {
    type Input = BansInput;
    type Output = BansOutput;

    const NAME: &'static str = "fw.bans";
    const PERMISSION: Permission = Permission::FirewallManage;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let fw = &ctx.distro().fw;
        let live: Vec<IpAddr> = fw
            .list_bans()
            .await
            .map_err(UnihelmError::from)?
            .into_iter()
            .map(canonical)
            .collect();

        let rows = ctx
            .db()
            .recent_bans(input.limit.unwrap_or(200))
            .await
            .map_err(UnihelmError::from)?;

        let mut open: Vec<IpAddr> = Vec::new();
        let bans: Vec<BanView> = rows
            .into_iter()
            .map(|ban| {
                let parsed = ban.ip.parse::<IpAddr>().ok().map(canonical);
                if ban.lifted_at.is_none()
                    && let Some(ip) = parsed
                {
                    open.push(ip);
                }
                let in_backend = parsed.is_some_and(|ip| live.contains(&ip));
                BanView { ban, in_backend }
            })
            .collect();

        let unrecorded = live
            .iter()
            .filter(|ip| !open.contains(ip))
            .map(|ip| ip.to_string())
            .collect();

        Ok(BansOutput {
            backend: fw.name(),
            bans,
            unrecorded,
        })
    }
}

/// `sentinel.settings` — read Sentinel's configuration.
pub struct SettingsGet;

#[derive(Debug, Deserialize)]
pub struct SettingsGetInput {}

#[async_trait]
impl TypedOperation for SettingsGet {
    type Input = SettingsGetInput;
    type Output = SentinelSettings;

    const NAME: &'static str = "sentinel.settings";
    const PERMISSION: Permission = Permission::FirewallManage;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, _input: Self::Input) -> Result<Self::Output> {
        Ok(SentinelSettings::load(ctx.db()).await)
    }
}

/// `sentinel.settings.set` — change it. This is the switch that turns the
/// defence on, so it is the one place a fresh install becomes a banning one.
pub struct SettingsSet;

#[async_trait]
impl TypedOperation for SettingsSet {
    type Input = SentinelSettings;
    type Output = SentinelSettings;

    const NAME: &'static str = "sentinel.settings.set";
    const PERMISSION: Permission = Permission::FirewallManage;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        input.store(ctx.db()).await?;
        ctx.log(format!(
            "sentinel {} (threshold {} in {} min, ban {} min)",
            if input.enabled { "enabled" } else { "disabled" },
            input.ssh_threshold,
            input.window_minutes,
            input.ban_minutes
        ));
        Ok(input)
    }
}

// ---------------------------------------------------------------------------
// the scan
// ---------------------------------------------------------------------------

/// One Sentinel pass, run by the agent's scheduler as `sentinel.scan`.
///
/// Returns a one-line summary for the scheduler's log, empty when there was
/// nothing to do — the same contract the other scheduled jobs use.
///
/// **It bans nothing while `sentinel.enabled` is false, and that check comes
/// before a single log line is read.** A fresh install has no allowlist, may
/// sit behind a NAT that makes a whole office look like one address, and
/// belongs to an operator who has not configured anything yet. Banning under
/// those conditions is a coin-flip on locking the owner out of their own
/// server, so the tick simply returns (spec §11.9).
///
/// It still releases the bans it already took, because turning the defence off
/// must not be what makes its bans permanent: ufw has no expiry of its own, so
/// this reaper is the only thing that ever lifts a ufw ban.
pub async fn sentinel_tick(ctx: &OpContext) -> Result<String> {
    sentinel_tick_with(ctx, &SystemJournal).await
}

/// The tick with its journal source injected, so the policy is testable
/// without systemd.
pub async fn sentinel_tick_with(ctx: &OpContext, journal: &dyn JournalReader) -> Result<String> {
    let db = ctx.db();
    let settings = SentinelSettings::load(db).await;

    let mut notes = Vec::new();

    // 1. Catch the bookkeeping up with the kernel. The firewalld and nftables
    //    backends expire their own set entries, so this mostly closes rows;
    //    for ufw, which has no expiry, it is what actually ends the ban.
    //
    //    Ahead of the `enabled` check on purpose: switching Sentinel off is not
    //    a decision to keep its bans forever, and on ufw nothing else lifts
    //    them, so the operator would be left unbanning by hand, one address at
    //    a time, for as long as the rows lived.
    let expired = db.expired_bans().await.map_err(UnihelmError::from)?;
    let mut lifted = 0usize;
    for ban in &expired {
        if let Ok(ip) = ban.ip.parse::<IpAddr>()
            && let Err(e) = ctx.distro().fw.unban_ip(ip).await
        {
            // Worth a line, not worth abandoning the tick: the row still needs
            // closing or the reaper will retry it forever.
            tracing::warn!(ip = %ban.ip, error = %e, "could not lift an expired ban at the firewall");
        }
        db.lift_bans_for(&ban.ip)
            .await
            .map_err(UnihelmError::from)?;
        lifted += 1;
    }
    if lifted > 0 {
        notes.push(format!("lifted {lifted} expired ban(s)"));
    }

    if !settings.enabled {
        return Ok(notes.join(", "));
    }

    // 2. Collect failures from both jails the spec asks for: sshd via the
    //    journal, and the panel's own login form via `login_attempts`.
    let now = unihelm_db::now();
    let since = now - settings.window();
    let mut events = parse_journal(&journal.read(since).await?);

    for (ip, count) in db
        .failed_logins_since(since)
        .await
        .map_err(UnihelmError::from)?
    {
        let Ok(parsed) = ip.parse::<IpAddr>() else {
            // `login_attempts.ip` is a label the web layer writes and can be
            // the literal "unknown"; it is not a ban target.
            continue;
        };
        // Counted at `now` on purpose: the query already restricted them to
        // the window, and re-deriving each row's timestamp would buy nothing.
        for _ in 0..count.clamp(0, i64::from(u32::MAX)) {
            events.push(AuthFailure {
                ip: parsed,
                at: now,
            });
        }
    }

    // 3. Ban whoever crossed the line and is not protected.
    let mut banned = 0usize;
    let mut spared = 0usize;
    // No client to protect: the scheduler is not a request. The loopback and
    // own-address refusals still apply, and they are the ones that matter here.
    let guard = BanGuard::for_request(None, &settings);
    let ttl = settings.ban_duration();

    for offender in offenders(&events, now, settings.window(), settings.ssh_threshold) {
        let ip = offender.ip.to_string();
        if let Some(reason) = refusal_reason(offender.ip, &guard) {
            tracing::info!(%ip, reason, "sentinel declined to ban a protected address");
            spared += 1;
            continue;
        }
        // Already serving a ban: re-banning would reset its TTL every minute
        // and turn a one-hour ban into a permanent one.
        if db.is_banned(&ip).await.map_err(UnihelmError::from)? {
            continue;
        }

        let ttl_seconds = u32::try_from(ttl.whole_seconds()).unwrap_or(u32::MAX);
        if let Err(e) = ctx.distro().fw.ban_ip(offender.ip, Some(ttl_seconds)).await {
            tracing::warn!(%ip, error = %e, "sentinel could not apply a ban");
            continue;
        }

        let reason = format!(
            "{} failed authentications in {} minutes",
            offender.failures, settings.window_minutes
        );
        db.record_ban(&ip, &reason, Some(now + ttl))
            .await
            .map_err(UnihelmError::from)?;

        // Audited like any other state change (spec §10.3): a ban that only
        // exists in a ban list cannot be correlated with anything else that
        // happened that night.
        let _ = db
            .record_audit(NewAuditEntry {
                actor_user_id: None,
                actor_username: "sentinel".into(),
                impersonator_id: None,
                ip: Some(ip.clone()),
                action: "sentinel.ban".into(),
                target: Some(ip.clone()),
                detail: serde_json::json!({
                    "failures": offender.failures,
                    "window_minutes": settings.window_minutes,
                    "ban_minutes": settings.ban_minutes,
                }),
                request_id: Some(ctx.auth().request_id.clone()),
                subscription_id: None,
            })
            .await;

        banned += 1;
    }

    if banned > 0 {
        notes.push(format!("banned {banned} address(es)"));
    }
    if spared > 0 {
        notes.push(format!("spared {spared} protected address(es)"));
    }
    Ok(notes.join(", "))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::testing::{auth_for, registry};
    use unihelm_core::Role;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    // -- lockout prevention -------------------------------------------------

    #[test]
    fn loopback_is_never_bannable_in_any_spelling() {
        let guard = BanGuard::default();
        for address in ["127.0.0.1", "127.0.0.53", "::1", "::ffff:127.0.0.1"] {
            let reason = refusal_reason(ip(address), &guard)
                .unwrap_or_else(|| panic!("{address} must be refused"));
            assert!(reason.contains("loopback"), "{address}: {reason}");
        }
    }

    #[test]
    fn the_requesting_clients_own_address_is_refused() {
        // The admin who types their own address into the ban box. Obeying
        // would end the session that issued the request.
        let guard = BanGuard {
            client_ip: Some(ip("203.0.113.7")),
            ..BanGuard::default()
        };
        let reason = refusal_reason(ip("203.0.113.7"), &guard).expect("must be refused");
        assert!(reason.contains("lock you out"), "{reason}");
        // And only that address: the guard is not an excuse to refuse
        // everything.
        assert!(refusal_reason(ip("203.0.113.8"), &guard).is_none());
    }

    #[test]
    fn the_clients_address_is_refused_across_ipv4_mapped_spellings() {
        // A dual-stack listener reports the peer as ::ffff:a.b.c.d while a log
        // or an operator would write the dotted form. Both are one host.
        let guard = BanGuard {
            client_ip: Some(ip("::ffff:203.0.113.7")),
            ..BanGuard::default()
        };
        assert!(refusal_reason(ip("203.0.113.7"), &guard).is_some());
    }

    #[test]
    fn the_servers_own_addresses_are_refused() {
        let guard = BanGuard {
            local: vec![ip("203.0.113.10"), ip("2001:db8::5")],
            ..BanGuard::default()
        };
        for address in ["203.0.113.10", "2001:db8::5"] {
            let reason = refusal_reason(ip(address), &guard)
                .unwrap_or_else(|| panic!("{address} must be refused"));
            assert!(reason.contains("own addresses"), "{address}: {reason}");
        }
    }

    #[test]
    fn an_allowlisted_network_is_refused() {
        let guard = BanGuard {
            allowlist: vec!["10.0.0.0/8".into(), "2001:db8::/32".into()],
            ..BanGuard::default()
        };
        assert!(refusal_reason(ip("10.1.2.3"), &guard).is_some());
        assert!(refusal_reason(ip("2001:db8::dead"), &guard).is_some());
        // Just outside the prefix: bannable.
        assert!(refusal_reason(ip("11.1.2.3"), &guard).is_none());
        assert!(refusal_reason(ip("2001:db9::dead"), &guard).is_none());
    }

    #[test]
    fn a_malformed_allowlist_entry_covers_nothing() {
        // Failing open here would turn one typo into "Sentinel never bans".
        let guard = BanGuard {
            allowlist: vec!["not-an-address".into(), "10.0.0.0/99".into(), String::new()],
            ..BanGuard::default()
        };
        assert!(refusal_reason(ip("10.1.2.3"), &guard).is_none());
    }

    #[test]
    fn wildcard_addresses_are_refused_because_they_are_not_hosts() {
        let guard = BanGuard::default();
        for address in ["0.0.0.0", "::", "224.0.0.1", "255.255.255.255"] {
            assert!(
                refusal_reason(ip(address), &guard).is_some(),
                "{address} must be refused"
            );
        }
    }

    #[test]
    fn an_ordinary_attacker_is_bannable() {
        // The guard must not be so broad that nothing can ever be banned.
        let guard = BanGuard {
            client_ip: Some(ip("203.0.113.7")),
            local: vec![ip("203.0.113.10")],
            allowlist: vec!["10.0.0.0/8".into()],
        };
        assert_eq!(refusal_reason(ip("198.51.100.44"), &guard), None);
    }

    #[test]
    fn cidr_prefixes_are_compared_bit_by_bit_not_by_octet() {
        // /12 splits an octet; a byte-only comparison would get this wrong.
        assert!(cidr_contains("172.16.0.0/12", ip("172.31.255.254")));
        assert!(!cidr_contains("172.16.0.0/12", ip("172.32.0.1")));
        // A bare address is an implicit /32 or /128.
        assert!(cidr_contains("203.0.113.9", ip("203.0.113.9")));
        assert!(!cidr_contains("203.0.113.9", ip("203.0.113.10")));
        // /0 really does cover everything, and a v4 prefix never covers v6.
        assert!(cidr_contains("0.0.0.0/0", ip("198.51.100.1")));
        assert!(!cidr_contains("0.0.0.0/0", ip("2001:db8::1")));
    }

    #[test]
    fn this_hosts_addresses_always_include_loopback() {
        // A smoke test for the getifaddrs walk: every machine has a loopback
        // interface, so an empty or loopback-free answer means the enumeration
        // silently failed and the guard is thinner than it looks.
        let local = local_addresses();
        assert!(
            local.iter().any(|a| a.is_loopback()),
            "expected a loopback address among {local:?}"
        );
    }

    // -- journal parsing ----------------------------------------------------

    /// Real-shaped `journalctl -o json` output. Field set trimmed to what a
    /// reader touches, values in the shapes journald actually emits:
    /// `__REALTIME_TIMESTAMP` as a decimal string of microseconds, `MESSAGE`
    /// as a string (and, in one record, as the byte array journald falls back
    /// to for a non-UTF-8 line).
    const JOURNAL: &str = r#"
{"__REALTIME_TIMESTAMP":"1756209600000000","_SYSTEMD_UNIT":"sshd.service","SYSLOG_IDENTIFIER":"sshd","PRIORITY":"6","MESSAGE":"Server listening on 0.0.0.0 port 22."}
{"__REALTIME_TIMESTAMP":"1756209660000000","_SYSTEMD_UNIT":"sshd.service","SYSLOG_IDENTIFIER":"sshd","PRIORITY":"5","MESSAGE":"Failed password for root from 203.0.113.9 port 55234 ssh2"}
{"__REALTIME_TIMESTAMP":"1756209661000000","_SYSTEMD_UNIT":"sshd.service","SYSLOG_IDENTIFIER":"sshd","PRIORITY":"5","MESSAGE":"Failed password for invalid user admin from 203.0.113.9 port 55240 ssh2"}
{"__REALTIME_TIMESTAMP":"1756209662000000","_SYSTEMD_UNIT":"ssh.service","SYSLOG_IDENTIFIER":"sshd","PRIORITY":"5","MESSAGE":"Invalid user oracle from 198.51.100.7 port 51000"}
{"__REALTIME_TIMESTAMP":"1756209663000000","_SYSTEMD_UNIT":"sshd.service","SYSLOG_IDENTIFIER":"sshd","PRIORITY":"6","MESSAGE":"Accepted publickey for deploy from 192.0.2.5 port 40000 ssh2: RSA SHA256:abc"}
{"__REALTIME_TIMESTAMP":"1756209664000000","_SYSTEMD_UNIT":"sshd.service","SYSLOG_IDENTIFIER":"sshd","PRIORITY":"5","MESSAGE":[70,97,105,108,101,100,32,112,97,115,115,119,111,114,100,32,102,111,114,32,114,111,111,116,32,102,114,111,109,32,49,57,56,46,53,49,46,49,48,48,46,55,32,112,111,114,116,32,50,50,32,115,115,104,50]}
not json at all
{"__REALTIME_TIMESTAMP":"1756209665000000","MESSAGE":"Failed password for root from not-an-address port 22 ssh2"}
{"_SYSTEMD_UNIT":"sshd.service","MESSAGE":"Failed password for root from 192.0.2.99 port 22 ssh2"}
"#;

    #[test]
    fn journal_json_yields_only_authentication_failures() {
        let events = parse_journal(JOURNAL);
        let addresses: Vec<String> = events.iter().map(|e| e.ip.to_string()).collect();
        assert_eq!(
            addresses,
            vec![
                "203.0.113.9",
                "203.0.113.9",
                "198.51.100.7",
                // The byte-array MESSAGE decodes to a normal failure line.
                "198.51.100.7",
            ],
            "a successful login, a listening banner, junk and a record with no \
             timestamp must all be skipped"
        );
        // Timestamps come back as real times, not zeroes.
        assert_eq!(
            events[0].at,
            OffsetDateTime::from_unix_timestamp(1_756_209_660).unwrap()
        );
    }

    #[test]
    fn an_attacker_supplied_username_cannot_choose_who_gets_banned() {
        // sshd interpolates the username into the middle of the line, so a
        // login as the user `from 203.0.113.1 port 22` produces a line with two
        // `from <ip> port <n>` triples. Taking the first would let anyone on
        // the internet have any address banned — including the operator's.
        let line = "Invalid user from 203.0.113.1 port 22 from 198.51.100.9 port 55555";
        assert_eq!(parse_ssh_failure(line), Some(ip("198.51.100.9")));

        let line = "Failed password for invalid user  from 10.0.0.1 port 22 \
                    from 198.51.100.9 port 40000 ssh2";
        assert_eq!(parse_ssh_failure(line), Some(ip("198.51.100.9")));
    }

    #[test]
    fn lines_that_are_not_authentication_failures_yield_nothing() {
        for line in [
            "Accepted password for root from 203.0.113.9 port 22 ssh2",
            "Connection closed by 203.0.113.9 port 22",
            "Received disconnect from 203.0.113.9 port 22:11: Bye Bye",
            "Failed password for root from 203.0.113.9",
            "Failed password for root",
            "Invalid user",
            "",
        ] {
            assert_eq!(parse_ssh_failure(line), None, "{line:?}");
        }
    }

    #[test]
    fn the_journal_query_finds_sshd_however_the_host_runs_it() {
        // The unit names alone miss the two shapes current distributions ship:
        // socket-activated sshd logs under `ssh@N-<addr>.service`, and OpenSSH 10
        // authenticates in `sshd-session`. Both carry a syslog identifier, so
        // the identifier groups are what keep the SSH jail seeing anything on
        // Debian 13 and Ubuntu 24.04.
        //
        // Each of those groups is pinned to `_UID=0` as well: an identifier is
        // whatever the sender claimed, so without it any local user could
        // `logger -t sshd` a burst of failures and pick who gets banned.
        let since = OffsetDateTime::from_unix_timestamp(1_756_209_600).unwrap();
        assert_eq!(
            journal_argv(since),
            vec![
                "--no-pager",
                "-o",
                "json",
                "--since",
                "2025-08-26 12:00:00 UTC",
                "SYSLOG_IDENTIFIER=sshd",
                "_UID=0",
                "+",
                "SYSLOG_IDENTIFIER=sshd-session",
                "_UID=0",
                "+",
                "_SYSTEMD_UNIT=sshd.service",
                "+",
                "_SYSTEMD_UNIT=ssh.service",
            ]
        );
    }

    // -- the threshold window ----------------------------------------------

    fn failure(address: &str, at: OffsetDateTime) -> AuthFailure {
        AuthFailure {
            ip: ip(address),
            at,
        }
    }

    #[test]
    fn the_window_counts_only_recent_failures() {
        let now = OffsetDateTime::from_unix_timestamp(1_756_209_600).unwrap();
        let window = Duration::minutes(10);
        let mut events = Vec::new();
        // Three inside the window, three long before it.
        for i in 0..3 {
            events.push(failure("203.0.113.9", now - Duration::minutes(i)));
            events.push(failure("203.0.113.9", now - Duration::hours(2)));
        }

        assert_eq!(offenders(&events, now, window, 3).len(), 1);
        assert_eq!(offenders(&events, now, window, 3)[0].failures, 3);
        // Six total failures, but only three are recent: a threshold of four
        // must not be crossed by the historical ones.
        assert!(offenders(&events, now, window, 4).is_empty());
    }

    #[test]
    fn the_threshold_is_inclusive_and_per_address() {
        let now = OffsetDateTime::from_unix_timestamp(1_756_209_600).unwrap();
        let window = Duration::minutes(10);
        let events = vec![
            failure("203.0.113.9", now),
            failure("203.0.113.9", now),
            failure("198.51.100.7", now),
        ];
        let over = offenders(&events, now, window, 2);
        assert_eq!(over.len(), 1, "{over:?}");
        assert_eq!(over[0].ip.to_string(), "203.0.113.9");
        assert_eq!(over[0].failures, 2, "exactly at the threshold counts");
        // One address's failures never contribute to another's.
        assert!(offenders(&events, now, window, 3).is_empty());
    }

    #[test]
    fn offenders_are_reported_worst_first_and_deterministically() {
        let now = OffsetDateTime::from_unix_timestamp(1_756_209_600).unwrap();
        let mut events = vec![failure("198.51.100.7", now), failure("198.51.100.7", now)];
        for _ in 0..5 {
            events.push(failure("203.0.113.9", now));
        }
        let over = offenders(&events, now, Duration::minutes(10), 2);
        assert_eq!(
            over.iter().map(|o| o.failures).collect::<Vec<_>>(),
            vec![5, 2]
        );
    }

    #[test]
    fn the_same_host_in_two_spellings_is_counted_once() {
        // Half the failures arriving as ::ffff:v4 would otherwise leave both
        // spellings below the threshold and the attacker un-banned.
        let now = OffsetDateTime::from_unix_timestamp(1_756_209_600).unwrap();
        let events = vec![
            failure("203.0.113.9", now),
            failure("::ffff:203.0.113.9", now),
            failure("203.0.113.9", now),
        ];
        let over = offenders(&events, now, Duration::minutes(10), 3);
        assert_eq!(over.len(), 1);
        assert_eq!(over[0].ip.to_string(), "203.0.113.9");
    }

    // -- the drift merge ----------------------------------------------------

    fn record(port: u16, proto: &str, source: Option<&str>, comment: &str) -> FwRuleRecord {
        FwRuleRecord {
            id: i64::from(port),
            port,
            proto: proto.into(),
            source: source.map(str::to_string),
            comment: comment.into(),
            created_at: OffsetDateTime::from_unix_timestamp(1_756_209_600).unwrap(),
        }
    }

    #[test]
    fn a_rule_in_both_places_is_not_drift() {
        let backend = vec![PortRule::anywhere(443, Proto::Tcp, "https")];
        let intent = vec![record(443, "tcp", None, "https")];
        let merged = merge_rules(&backend, &intent);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].drift, None);
        assert!(merged[0].in_panel && merged[0].in_backend);
    }

    #[test]
    fn a_recorded_rule_the_firewall_lost_is_reported_as_missing() {
        // Somebody flushed the ruleset. The port the panel promised is shut,
        // and the operator has to be told rather than shown a green tick.
        let merged = merge_rules(&[], &[record(443, "tcp", None, "https")]);
        assert_eq!(merged[0].drift, Some(DRIFT_MISSING));
        assert!(merged[0].in_panel && !merged[0].in_backend);
    }

    #[test]
    fn a_live_rule_the_panel_never_recorded_is_reported_as_unrecorded() {
        let backend = vec![PortRule::anywhere(8443, Proto::Tcp, "old build")];
        let merged = merge_rules(&backend, &[]);
        assert_eq!(merged[0].drift, Some(DRIFT_UNRECORDED));
        assert!(!merged[0].in_panel && merged[0].in_backend);
    }

    #[test]
    fn a_source_restricted_rule_is_a_different_rule_from_an_open_one() {
        let backend = vec![PortRule {
            port: 3306,
            proto: Proto::Tcp,
            source: Some("10.0.0.0/8".into()),
            comment: "office".into(),
        }];
        let intent = vec![record(3306, "tcp", None, "everyone")];
        let merged = merge_rules(&backend, &intent);
        assert_eq!(merged.len(), 2, "{merged:?}");
        assert!(merged.iter().any(|r| r.drift == Some(DRIFT_MISSING)));
        assert!(merged.iter().any(|r| r.drift == Some(DRIFT_UNRECORDED)));
    }

    #[test]
    fn an_empty_source_string_means_the_same_as_no_source() {
        // A record written by a client that sent `""` must not show as drift
        // against the backend's `None`.
        let backend = vec![PortRule::anywhere(80, Proto::Tcp, "http")];
        let intent = vec![record(80, "tcp", Some(""), "http")];
        let merged = merge_rules(&backend, &intent);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].drift, None);
    }

    // -- settings -----------------------------------------------------------

    #[tokio::test]
    async fn sentinel_is_disabled_on_a_fresh_install() {
        // The single most important default in this module: a server that has
        // just been installed must not start banning its own operator.
        let db = unihelm_db::Db::open_memory().await.unwrap();
        let settings = SentinelSettings::load(&db).await;
        assert!(!settings.enabled);
        assert_eq!(settings.ssh_threshold, 6);
        assert_eq!(settings.window_minutes, 10);
        assert_eq!(settings.ban_minutes, 60);
        assert!(settings.allowlist.is_empty());
    }

    #[tokio::test]
    async fn settings_round_trip_and_refuse_nonsense() {
        let db = unihelm_db::Db::open_memory().await.unwrap();
        let wanted = SentinelSettings {
            enabled: true,
            ssh_threshold: 3,
            window_minutes: 5,
            ban_minutes: 30,
            allowlist: vec!["10.0.0.0/8".into()],
        };
        wanted.store(&db).await.unwrap();
        assert_eq!(SentinelSettings::load(&db).await, wanted);

        let mut bad = wanted.clone();
        bad.ssh_threshold = 0;
        assert_eq!(
            bad.store(&db).await.unwrap_err().code,
            ErrorCode::InvalidInput
        );
        let mut bad = wanted.clone();
        bad.allowlist = vec!["example.com".into()];
        assert_eq!(
            bad.store(&db).await.unwrap_err().code,
            ErrorCode::InvalidInput
        );
        // And the refused write changed nothing.
        assert_eq!(SentinelSettings::load(&db).await, wanted);
    }

    // -- the operations, through dispatch ----------------------------------

    #[tokio::test]
    async fn a_customer_cannot_touch_the_firewall() {
        let (reg, _, customer) = registry().await;
        for (op, input) in [
            ("fw.rules", serde_json::json!({})),
            (
                "fw.port.open",
                serde_json::json!({ "port": 22, "proto": "tcp" }),
            ),
            ("fw.ban", serde_json::json!({ "ip": "198.51.100.9" })),
            ("fw.bans", serde_json::json!({})),
        ] {
            let err = reg
                .dispatch(op, &auth_for(customer, Role::Customer), input, None)
                .await
                .unwrap_err();
            assert_eq!(err.code, ErrorCode::PermissionDenied, "{op}");
        }
    }

    #[tokio::test]
    async fn opening_a_port_reaches_the_backend_and_then_the_record() {
        let (reg, admin, _) = registry().await;
        let out = reg
            .dispatch(
                "fw.port.open",
                &auth_for(admin, Role::Admin),
                serde_json::json!({
                    "port": 3306, "proto": "tcp",
                    "source": "10.0.0.0/8", "comment": "remote mysql"
                }),
                None,
            )
            .await
            .unwrap();
        assert_eq!(out["port"], 3306);

        // The record exists, and the merged view agrees with the backend.
        let rules = reg
            .dispatch(
                "fw.rules",
                &auth_for(admin, Role::Admin),
                serde_json::json!({}),
                None,
            )
            .await
            .unwrap();
        assert_eq!(rules["rules"].as_array().unwrap().len(), 1);
        assert_eq!(rules["rules"][0]["drift"], serde_json::Value::Null);
        assert_eq!(rules["rules"][0]["in_panel"], true);
        assert_eq!(rules["rules"][0]["in_backend"], true);

        // Closing removes both halves.
        reg.dispatch(
            "fw.port.close",
            &auth_for(admin, Role::Admin),
            serde_json::json!({ "port": 3306, "proto": "tcp", "source": "10.0.0.0/8" }),
            None,
        )
        .await
        .unwrap();
        let rules = reg
            .dispatch(
                "fw.rules",
                &auth_for(admin, Role::Admin),
                serde_json::json!({}),
                None,
            )
            .await
            .unwrap();
        assert!(rules["rules"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_rule_the_backend_refuses_is_never_recorded() {
        // Ordering discipline: the panel must not remember a hole the firewall
        // declined to make. A hostname source is rejected by PortRule.
        let (reg, admin, _) = registry().await;
        let err = reg
            .dispatch(
                "fw.port.open",
                &auth_for(admin, Role::Admin),
                serde_json::json!({ "port": 3306, "proto": "tcp", "source": "example.com" }),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidInput);
        assert!(
            reg.services().db.fw_rules().await.unwrap().is_empty(),
            "a refused rule must leave no record behind"
        );
    }

    #[tokio::test]
    async fn banning_your_own_client_address_is_refused_by_the_op() {
        let (reg, admin, _) = registry().await;
        let err = reg
            .dispatch(
                "fw.ban",
                &auth_for(admin, Role::Admin),
                serde_json::json!({ "ip": "203.0.113.7", "client_ip": "203.0.113.7" }),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::Conflict);
        assert!(err.detail.contains("lock you out"), "{}", err.detail);
        // Nothing reached the firewall or the ban list.
        assert!(reg.services().db.recent_bans(10).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn banning_loopback_is_refused_by_the_op() {
        let (reg, admin, _) = registry().await;
        for address in ["127.0.0.1", "::1"] {
            let err = reg
                .dispatch(
                    "fw.ban",
                    &auth_for(admin, Role::Admin),
                    serde_json::json!({ "ip": address }),
                    None,
                )
                .await
                .unwrap_err();
            assert_eq!(err.code, ErrorCode::Conflict, "{address}");
        }
        assert!(reg.services().db.recent_bans(10).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_ban_round_trips_through_the_backend_and_the_list() {
        let (reg, admin, _) = registry().await;
        let auth = auth_for(admin, Role::Admin);

        let out = reg
            .dispatch(
                "fw.ban",
                &auth,
                serde_json::json!({ "ip": "198.51.100.9", "minutes": 30, "reason": "testing" }),
                None,
            )
            .await
            .unwrap();
        assert_eq!(out["ip"], "198.51.100.9");
        assert!(out["expires_at"].is_string(), "a TTL must be recorded");

        let bans = reg
            .dispatch("fw.bans", &auth, serde_json::json!({}), None)
            .await
            .unwrap();
        assert_eq!(bans["bans"][0]["ip"], "198.51.100.9");
        assert_eq!(bans["bans"][0]["in_backend"], true);
        assert_eq!(bans["bans"][0]["reason"], "testing");

        let out = reg
            .dispatch(
                "fw.unban",
                &auth,
                serde_json::json!({ "ip": "198.51.100.9" }),
                None,
            )
            .await
            .unwrap();
        assert_eq!(out["lifted"], 1);

        let bans = reg
            .dispatch("fw.bans", &auth, serde_json::json!({}), None)
            .await
            .unwrap();
        // The history survives, the enforcement does not.
        assert_eq!(bans["bans"][0]["in_backend"], false);
        assert!(bans["bans"][0]["lifted_at"].is_string());
    }

    #[tokio::test]
    async fn unbanning_an_address_that_was_never_banned_reports_zero() {
        let (reg, admin, _) = registry().await;
        let out = reg
            .dispatch(
                "fw.unban",
                &auth_for(admin, Role::Admin),
                serde_json::json!({ "ip": "198.51.100.9" }),
                None,
            )
            .await
            .unwrap();
        assert_eq!(out["lifted"], 0);
    }

    #[tokio::test]
    async fn a_junk_address_is_refused_before_anything_runs() {
        let (reg, admin, _) = registry().await;
        for address in ["example.com", "10.0.0.0/8", "', drop", ""] {
            let err = reg
                .dispatch(
                    "fw.ban",
                    &auth_for(admin, Role::Admin),
                    serde_json::json!({ "ip": address }),
                    None,
                )
                .await
                .unwrap_err();
            assert_eq!(err.code, ErrorCode::InvalidInput, "{address}");
        }
    }

    // -- the scan -----------------------------------------------------------

    /// Replays canned journal text and records that it was asked.
    struct FakeJournal {
        text: String,
        reads: std::sync::atomic::AtomicUsize,
    }

    impl FakeJournal {
        fn new(text: impl Into<String>) -> Self {
            Self {
                text: text.into(),
                reads: std::sync::atomic::AtomicUsize::new(0),
            }
        }

        fn reads(&self) -> usize {
            self.reads.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl JournalReader for FakeJournal {
        async fn read(&self, _since: OffsetDateTime) -> Result<String> {
            self.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(self.text.clone())
        }
    }

    /// A journal with `count` fresh failures from `address`.
    fn journal_with(address: &str, count: usize) -> String {
        let base = (unihelm_db::now().unix_timestamp() as i128) * 1_000_000;
        (0..count)
            .map(|i| {
                format!(
                    r#"{{"__REALTIME_TIMESTAMP":"{}","MESSAGE":"Failed password for root from {address} port {} ssh2"}}"#,
                    base + i as i128,
                    40000 + i
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    async fn context(reg: &crate::OpRegistry) -> OpContext {
        OpContext::new(
            reg.services().clone(),
            unihelm_core::AuthContext::system("sentinel.scan"),
        )
    }

    #[tokio::test]
    async fn a_disabled_sentinel_never_reads_the_journal_or_bans_anyone() {
        // Not "reads the journal and declines to ban" — it must not even look,
        // because a fresh install is exactly the server most likely to have an
        // operator behind an address that looks like an attacker.
        let (reg, ..) = registry().await;
        let journal = FakeJournal::new(journal_with("198.51.100.9", 20));
        let ctx = context(&reg).await;

        assert_eq!(sentinel_tick_with(&ctx, &journal).await.unwrap(), "");
        assert_eq!(journal.reads(), 0, "the journal must not be read at all");
        assert!(reg.services().db.recent_bans(10).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_disabled_sentinel_still_releases_the_bans_it_already_took() {
        // Turning the defence off is not a decision to keep its bans forever,
        // and on ufw — the Debian default — this reaper is the only thing that
        // ever ends one, so skipping it made every live ban permanent.
        let (reg, ..) = registry().await;
        let db = &reg.services().db;
        db.record_ban(
            "198.51.100.9",
            "ssh",
            Some(unihelm_db::now() - Duration::minutes(1)),
        )
        .await
        .unwrap();

        let journal = FakeJournal::new(journal_with("203.0.113.5", 20));
        let ctx = context(&reg).await;
        let summary = sentinel_tick_with(&ctx, &journal).await.unwrap();

        assert!(summary.contains("lifted 1"), "{summary}");
        assert!(db.active_bans().await.unwrap().is_empty());
        assert_eq!(
            journal.reads(),
            0,
            "releasing what it took is not licence to go looking for more"
        );
        assert_eq!(
            db.recent_bans(10).await.unwrap().len(),
            1,
            "a disabled tick must not add a ban of its own"
        );
    }

    async fn enable(reg: &crate::OpRegistry, settings: SentinelSettings) {
        settings.store(&reg.services().db).await.unwrap();
    }

    #[tokio::test]
    async fn an_enabled_scan_bans_an_address_over_the_threshold_once() {
        let (reg, ..) = registry().await;
        enable(
            &reg,
            SentinelSettings {
                enabled: true,
                ssh_threshold: 3,
                ..SentinelSettings::default()
            },
        )
        .await;

        let journal = FakeJournal::new(journal_with("198.51.100.9", 4));
        let ctx = context(&reg).await;
        let summary = sentinel_tick_with(&ctx, &journal).await.unwrap();
        assert!(summary.contains("banned 1"), "{summary}");

        let bans = reg.services().db.active_bans().await.unwrap();
        assert_eq!(bans.len(), 1);
        assert_eq!(bans[0].ip, "198.51.100.9");
        assert!(
            bans[0].expires_at.is_some(),
            "Sentinel's own bans must always expire"
        );
        assert!(bans[0].reason.contains("4 failed"), "{}", bans[0].reason);

        // A second pass over the same failures must not re-ban and reset the
        // TTL — that would quietly turn an hour into forever.
        let summary = sentinel_tick_with(&ctx, &journal).await.unwrap();
        assert!(!summary.contains("banned"), "{summary}");
        assert_eq!(reg.services().db.active_bans().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn a_scan_never_bans_a_protected_address_however_many_failures_it_has() {
        let (reg, ..) = registry().await;
        enable(
            &reg,
            SentinelSettings {
                enabled: true,
                ssh_threshold: 2,
                allowlist: vec!["198.51.100.0/24".into()],
                ..SentinelSettings::default()
            },
        )
        .await;

        // Loopback (a misconfigured proxy makes every attempt look local) and
        // an allowlisted office range, both hammering the box.
        let text = format!(
            "{}\n{}",
            journal_with("127.0.0.1", 10),
            journal_with("198.51.100.9", 10)
        );
        let ctx = context(&reg).await;
        let summary = sentinel_tick_with(&ctx, &FakeJournal::new(text))
            .await
            .unwrap();

        assert!(summary.contains("spared 2"), "{summary}");
        assert!(
            reg.services().db.recent_bans(10).await.unwrap().is_empty(),
            "a protected address must never reach the ban list"
        );
    }

    #[tokio::test]
    async fn failed_panel_logins_count_towards_a_ban() {
        // Spec §11.9 ships a jail for the panel's own login form; its evidence
        // is the `login_attempts` table, not a log file.
        let (reg, ..) = registry().await;
        enable(
            &reg,
            SentinelSettings {
                enabled: true,
                ssh_threshold: 3,
                ..SentinelSettings::default()
            },
        )
        .await;

        let db = &reg.services().db;
        for _ in 0..3 {
            db.record_login_attempt("198.51.100.44", "admin", false)
                .await
                .unwrap();
        }
        // A label the web layer writes when it cannot see a peer address must
        // not become a ban target.
        db.record_login_attempt("unknown", "admin", false)
            .await
            .unwrap();

        let ctx = context(&reg).await;
        let summary = sentinel_tick_with(&ctx, &FakeJournal::new(""))
            .await
            .unwrap();
        assert!(summary.contains("banned 1"), "{summary}");
        assert_eq!(db.active_bans().await.unwrap()[0].ip, "198.51.100.44");
    }

    #[tokio::test]
    async fn the_scan_lifts_bans_whose_time_has_passed() {
        let (reg, ..) = registry().await;
        enable(
            &reg,
            SentinelSettings {
                enabled: true,
                ..SentinelSettings::default()
            },
        )
        .await;

        let db = &reg.services().db;
        db.record_ban(
            "198.51.100.9",
            "ssh",
            Some(unihelm_db::now() - Duration::minutes(1)),
        )
        .await
        .unwrap();

        let ctx = context(&reg).await;
        let summary = sentinel_tick_with(&ctx, &FakeJournal::new(""))
            .await
            .unwrap();
        assert!(summary.contains("lifted 1"), "{summary}");
        assert!(db.active_bans().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_ban_is_audited_so_it_can_be_explained_later() {
        let (reg, ..) = registry().await;
        enable(
            &reg,
            SentinelSettings {
                enabled: true,
                ssh_threshold: 2,
                ..SentinelSettings::default()
            },
        )
        .await;

        let ctx = context(&reg).await;
        sentinel_tick_with(&ctx, &FakeJournal::new(journal_with("198.51.100.9", 5)))
            .await
            .unwrap();

        let trail = reg
            .services()
            .db
            .audit(&unihelm_core::TenantScope::Global)
            .list_by_action("sentinel.", 10)
            .await
            .unwrap();
        assert_eq!(trail.len(), 1);
        assert_eq!(trail[0].target.as_deref(), Some("198.51.100.9"));
        assert_eq!(trail[0].detail["failures"], 5);
    }

    // -- starting and stopping the firewall ---------------------------------

    #[test]
    fn every_ssh_port_in_sshd_t_is_kept_not_just_the_first() {
        // `Port 22` and `Port 2222` both listen. First-value-wins is right for
        // the keywords posture.rs reads and wrong here, and taking only the
        // first would leave the second port shut the moment ufw came up.
        let output = "\
port 22\n\
port 2222\n\
passwordauthentication no\n\
permitrootlogin prohibit-password\n\
addressfamily any\n";
        assert_eq!(parse_sshd_ports(output), vec![22, 2222]);

        // sshd -T always prints the effective port, so an empty answer means
        // the command did not really run.
        assert!(parse_sshd_ports("permitrootlogin no\n").is_empty());
        assert!(parse_sshd_ports("port zero\nport 0\n").is_empty());
    }

    #[test]
    fn config_files_yield_every_port_and_nothing_from_a_match_block() {
        let files = vec![
            (
                "/etc/ssh/sshd_config.d/50-cloud.conf".to_string(),
                "Port 2222\n".to_string(),
            ),
            (
                "/etc/ssh/sshd_config".to_string(),
                "# Port 9999 is commented out\n\
                 Port 22\n\
                 PermitRootLogin no\n\
                 Match Address 10.0.0.0/8\n\
                 \x20   Port 2022\n"
                    .to_string(),
            ),
        ];
        // 2022 is behind a `Match`: it applies to some connections only, and a
        // guard that reported it as "the SSH port" would be describing a
        // conditional as a fact.
        assert_eq!(parse_sshd_config_ports(&files), vec![2222, 22]);
    }

    #[test]
    fn ufw_show_added_is_read_in_every_shape_ufw_prints() {
        // Copied from the shapes `ufw show added` actually emits, including the
        // two spellings of a source-restricted rule and our own `open_port`.
        let added = "\
Added user rules (see 'ufw status' for running firewall):\n\
ufw limit ssh\n\
ufw allow OpenSSH\n\
ufw allow 80/tcp\n\
ufw allow proto tcp to any port 443 comment 'unihelm: https'\n\
ufw allow from 10.0.0.0/8 proto tcp to any port 3306\n\
ufw allow from 203.0.113.0/24 to any port 5432 proto tcp\n\
ufw allow 53\n";
        let rules = parse_ufw_added(added);
        let ports: Vec<u16> = rules.iter().map(|r| r.port).collect();
        assert_eq!(ports, vec![22, 22, 80, 443, 3306, 5432, 53]);

        // A comment is operator prose: reading past it would let
        // `comment 'moved to 2222'` invent a rule nobody wrote.
        assert_eq!(rules[3].port, 443);
        assert_eq!(rules[3].source, None);
        assert_eq!(rules[4].source.as_deref(), Some("10.0.0.0/8"));
        assert_eq!(rules[5].source.as_deref(), Some("203.0.113.0/24"));
        assert_eq!(rules[5].proto, Proto::Tcp);
    }

    #[test]
    fn ufw_rules_that_do_not_admit_a_connection_to_this_host_are_not_counted() {
        // Each of these mentions 22 and none of them means "a new SSH
        // connection to this machine is accepted". Counting any of them would
        // clear the guard on a host where SSH is in fact shut.
        for line in [
            "ufw deny 22/tcp",
            "ufw reject 22/tcp",
            "ufw allow out 22/tcp",
            "ufw route allow proto tcp to any port 22",
            "ufw allow in on tailscale0 to any port 22",
        ] {
            assert!(parse_ufw_added(line).is_empty(), "{line}");
        }
    }

    #[test]
    fn a_source_restricted_ssh_rule_protects_only_the_operator_inside_it() {
        let rules = parse_ufw_added("ufw allow from 10.0.0.0/8 proto tcp to any port 22\n");
        assert!(ssh_reachable(&rules, 22, Some(ip("10.1.2.3"))));
        // The admin working from home. The rule exists, and it is not theirs.
        assert!(!ssh_reachable(&rules, 22, Some(ip("203.0.113.9"))));
        // And when the web layer could not tell us where they are, a restricted
        // rule is not evidence of anything.
        assert!(!ssh_reachable(&rules, 22, None));
    }

    #[test]
    fn an_unrestricted_rule_protects_anyone_but_only_on_its_own_port_and_proto() {
        let rules = parse_ufw_added("ufw allow 22/tcp\nufw allow 2222/udp\n");
        assert!(ssh_reachable(&rules, 22, None));
        // A UDP hole on 2222 does nothing for an SSH connection to 2222.
        assert!(!ssh_reachable(&rules, 2222, None));
        assert!(!ssh_reachable(&rules, 2022, None));
    }

    #[test]
    fn a_second_ssh_port_with_no_rule_is_reported_as_unprotected() {
        let rules = parse_ufw_added("ufw allow 22/tcp\n");
        assert_eq!(unprotected_ssh_ports(&rules, &[22, 2222], None), vec![2222]);
        assert!(unprotected_ssh_ports(&rules, &[22], None).is_empty());
    }

    #[test]
    fn only_the_backends_with_a_switch_have_one() {
        assert_eq!(Lifecycle::for_backend("ufw"), Lifecycle::Ufw);
        assert_eq!(Lifecycle::for_backend("firewalld"), Lifecycle::Firewalld);
        assert!(Lifecycle::for_backend("ufw").refusal().is_none());

        // nftables and "no firewall" each get their own sentence, because the
        // fix for them is different and "unsupported" tells nobody which.
        let nft = Lifecycle::for_backend("nftables")
            .refusal()
            .expect("nftables has no switch the panel owns");
        assert_eq!(nft.code, ErrorCode::NotImplemented);
        assert!(nft.detail.contains("/etc/nftables.conf"), "{}", nft.detail);

        let none = Lifecycle::for_backend("none")
            .refusal()
            .expect("nothing to start");
        assert!(
            none.detail.contains("no firewall is installed"),
            "{}",
            none.detail
        );
    }

    #[tokio::test]
    async fn starting_and_stopping_are_refused_on_a_backend_that_cannot_do_it() {
        // The mock backend is not one of the two with a lifecycle, so both
        // operations must say so by name rather than reporting a success no
        // firewall took.
        let (reg, ..) = registry().await;
        let ctx = context(&reg).await;

        let err = Enable
            .run(&ctx, EnableInput::default())
            .await
            .expect_err("a backend with no switch must refuse");
        assert_eq!(err.code, ErrorCode::NotImplemented);
        assert!(err.detail.contains("mock"), "{}", err.detail);

        let err = Disable
            .run(&ctx, DisableInput {})
            .await
            .expect_err("a backend with no switch must refuse");
        assert_eq!(err.code, ErrorCode::NotImplemented);
        assert!(err.detail.contains("mock"), "{}", err.detail);
    }

    #[tokio::test]
    async fn an_unknowable_ssh_port_refuses_the_start_rather_than_assuming_22() {
        // The lockout that costs a console visit: sshd is on 2222, the panel
        // could not read the configuration, and it opens 22 "helpfully".
        let (reg, ..) = registry().await;
        let ctx = context(&reg).await;
        let err = ensure_ssh_reachable(
            &ctx,
            &Lifecycle::Ufw,
            &AdmittingView::default(),
            &SshFacts::Unknown {
                reason: "`sshd -T` did not run".into(),
            },
            None,
            true,
        )
        .await
        .expect_err("an unknown SSH port must stop the start, even with allow_ssh");
        assert_eq!(err.code, ErrorCode::Conflict);
        assert!(err.detail.contains("sshd -T"), "{}", err.detail);
        // And nothing was touched on the way to saying no.
        assert!(reg.services().db.fw_rules().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_host_with_no_sshd_has_no_ssh_port_to_hold_open() {
        // A firewall on a box that does not run sshd must still be startable;
        // the guard exists to protect a session, not to forbid a state.
        let (reg, ..) = registry().await;
        let ctx = context(&reg).await;
        let opened = ensure_ssh_reachable(
            &ctx,
            &Lifecycle::Ufw,
            &AdmittingView::default(),
            &SshFacts::Absent,
            None,
            false,
        )
        .await
        .expect("no sshd means nothing to protect");
        assert!(opened.is_empty());
    }

    #[tokio::test]
    async fn a_shut_ssh_port_refuses_the_start_until_the_operator_asks_for_it() {
        // A view the panel read in full and that holds nothing: the shape of a
        // firewall about to come up with a deny-by-default policy and nothing
        // holding SSH open.
        let (reg, ..) = registry().await;
        let ctx = context(&reg).await;
        let ssh = SshFacts::Ports {
            ports: vec![2222],
            source: SshPortSource::SshdT,
        };
        let view = AdmittingView::default();

        let err = ensure_ssh_reachable(&ctx, &Lifecycle::Ufw, &view, &ssh, None, false)
            .await
            .expect_err("SSH is shut, so starting would end every session");
        assert_eq!(err.code, ErrorCode::Conflict);
        assert_eq!(err.field.as_deref(), Some("allow_ssh"));
        // The port and how the panel knows it, both in the sentence: an
        // operator has to be able to check the claim before agreeing to it.
        assert!(err.detail.contains("2222/tcp"), "{}", err.detail);
        assert!(err.detail.contains("sshd -T"), "{}", err.detail);
        assert!(
            reg.services().db.fw_rules().await.unwrap().is_empty(),
            "a refusal must leave the ruleset exactly as it was"
        );

        // Asked for explicitly, the same call opens the port and records it,
        // in that order, before returning it as changed.
        let opened = ensure_ssh_reachable(&ctx, &Lifecycle::Ufw, &view, &ssh, None, true)
            .await
            .expect("allow_ssh opens the port");
        assert_eq!(opened, vec![2222]);
        let recorded = reg.services().db.fw_rules().await.unwrap();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].port, 2222);
        assert_eq!(recorded[0].proto, "tcp");
        assert_eq!(recorded[0].source, None);
    }

    #[test]
    fn a_firewalld_zone_that_admits_ssh_by_service_is_not_read_as_shut() {
        // The stock RHEL host: SSH is admitted by the `ssh` *service* and there
        // is no port rule for 22 anywhere. `FwBackend::list_rules` reads only
        // `ports:` and the rich rules, so a guard built on it finds nothing
        // here — and tells an operator whose firewall is correct that starting
        // it would shut them out, then offers to open a port they already have.
        let listed = "\
public\n\
  target: default\n\
  interfaces: eth0\n\
  sources: \n\
  services: cockpit dhcpv6-client ssh\n\
  ports: 8088/tcp\n\
  protocols: \n\
  forward-ports: \n\
  rich rules: \n\
\trule family=\"ipv4\" source address=\"10.0.0.0/8\" port port=\"3306\" protocol=\"tcp\" accept\n";
        let (view, services) = parse_firewalld_zone(listed);

        assert_eq!(services, vec!["cockpit", "dhcpv6-client", "ssh"]);
        assert!(view.is_complete(), "{:?}", view.opaque);
        // The panel's own 8088 and the rich rule, both decoded from the zone.
        assert!(ssh_reachable(&view.rules, 8088, None));
        assert!(ssh_reachable(&view.rules, 3306, Some(ip("10.1.2.3"))));
        assert!(!ssh_reachable(&view.rules, 3306, Some(ip("203.0.113.9"))));
        // 22 is not here yet; it arrives when the `ssh` service is resolved.
        assert!(!ssh_reachable(&view.rules, 22, None));

        let resolved = parse_port_tokens("22/tcp");
        assert!(ssh_reachable(&resolved, 22, None));
    }

    #[test]
    fn a_rich_rule_that_cannot_be_decoded_is_carried_rather_than_dismissed() {
        // Anything the parser cannot turn into a port may be the thing holding
        // SSH open. Dropping it silently would let a firewall the panel only
        // half-read be reported as one it read completely.
        let (view, _) = parse_firewalld_zone(
            "  rich rules: \n\
             \trule family=\"ipv4\" service name=\"ssh\" accept\n\
             \trule family=\"ipv4\" source address=\"198.51.100.9\" drop\n",
        );
        assert!(view.rules.is_empty());
        // The drop rule cannot admit anything, so it is not carried; the
        // accepting one this parser does not understand is.
        assert_eq!(view.opaque.len(), 1, "{:?}", view.opaque);
        assert!(view.opaque[0].contains("service name=\"ssh\""));
        assert!(!view.is_complete());
    }

    #[tokio::test]
    async fn an_incompletely_read_ruleset_refuses_without_claiming_ssh_is_shut() {
        // Same refusal, deliberately not the same sentence. "No rule would
        // accept an SSH connection" is a claim about the ruleset, and the panel
        // is not entitled to make it about a ruleset it could not finish
        // reading.
        let (reg, ..) = registry().await;
        let ctx = context(&reg).await;
        let ssh = SshFacts::Ports {
            ports: vec![22],
            source: SshPortSource::SshdT,
        };
        let view = AdmittingView {
            rules: Vec::new(),
            opaque: vec!["cockpit".into()],
        };

        let err = ensure_ssh_reachable(&ctx, &Lifecycle::Ufw, &view, &ssh, None, false)
            .await
            .expect_err("an unreadable fragment is still a reason not to start");
        assert_eq!(err.code, ErrorCode::Conflict);
        assert_eq!(err.field.as_deref(), Some("allow_ssh"));
        assert!(err.detail.contains("could not read all"), "{}", err.detail);
        assert!(err.detail.contains("cockpit"), "{}", err.detail);
        assert!(
            !err.detail.contains("no rule in it would accept"),
            "a partial read must not be reported as a finding: {}",
            err.detail
        );
    }

    #[test]
    fn a_ufw_comment_is_never_read_as_part_of_the_rule() {
        // `on`, `out` and `route` decide whether a rule admits an inbound
        // connection, and all three are ordinary English words. Scanning into
        // the comment for them drops a perfectly good SSH rule and reports the
        // port as shut.
        let rules = parse_ufw_added("ufw allow 22/tcp comment 'ssh on the jump box'\n");
        assert!(ssh_reachable(&rules, 22, None));

        // The token still counts where ufw itself reads it.
        assert!(parse_ufw_added("ufw allow in on eth0 to any port 22 comment 'x'").is_empty());
    }
}
