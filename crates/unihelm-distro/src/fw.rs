//! Firewall backends (spec §7.2, §11.9).
//!
//! Three real backends and one honest absence. Which one you get depends on
//! **what is installed on the host**, not on the distro family, because the rule
//! is always the same: drive whatever already owns the ruleset. Writing nft
//! rules behind firewalld's back is how panels end up with rules that vanish on
//! the next reload, and the same is true of ufw.
//!
//! A host with no firewall at all gets [`UnmanagedBackend`], which reports
//! `is_active() == false` and refuses to pretend. An early version of this file
//! hard-wired the backend to the family, so a live AlmaLinux box with no
//! `firewall-cmd` installed cheerfully announced `fw: firewalld` on every boot.
//! A panel that reports "port opened" while there is no firewall is lying to its
//! operator, which is worse than saying nothing.
//!
//! Nothing here opens a port on its own initiative — every rule traces back to an
//! explicit, audited user action (spec §12 rule 8).

use std::net::IpAddr;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::exec::{Cmd, program_available};
use crate::{DistroError, Family, Result};

/// The comment we stamp on every rule we create.
///
/// It is how [`FwBackend::list_rules`] tells our rules from the operator's, and
/// it is why we never remove a rule we did not add.
const MARK: &str = "unihelm";

/// The nftables table we own outright.
const NFT_TABLE: &str = "unihelm";

/// Ban sets. Two of them, because a `hash:ip` set holds one address family.
const BAN_SET_V4: &str = "unihelm_bans";
const BAN_SET_V6: &str = "unihelm_bans6";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Proto {
    Tcp,
    Udp,
}

impl Proto {
    pub const fn as_str(self) -> &'static str {
        match self {
            Proto::Tcp => "tcp",
            Proto::Udp => "udp",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "tcp" => Some(Proto::Tcp),
            "udp" => Some(Proto::Udp),
            _ => None,
        }
    }
}

/// One managed hole in the firewall.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortRule {
    pub port: u16,
    pub proto: Proto,
    /// Restrict to a source CIDR. `None` means anywhere — which the UI marks
    /// clearly, since "remote database access from 0.0.0.0/0" is a decision, not
    /// a default.
    pub source: Option<String>,
    pub comment: String,
}

impl PortRule {
    /// A rule for a port open to the world.
    pub fn anywhere(port: u16, proto: Proto, comment: impl Into<String>) -> Self {
        Self {
            port,
            proto,
            source: None,
            comment: comment.into(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.port == 0 {
            return Err(DistroError::InvalidName(
                "port 0 is not a valid firewall rule".into(),
            ));
        }
        if let Some(src) = &self.source {
            validate_cidr(src)?;
        }
        if self.comment.len() > 128 || self.comment.chars().any(|c| c.is_control()) {
            return Err(DistroError::InvalidName(
                "rule comment is too long or contains control characters".into(),
            ));
        }
        Ok(())
    }

    /// The comment we actually write, so our own rules are recognisable.
    fn marked_comment(&self) -> String {
        format!("{MARK}: {}", self.comment)
    }
}

/// Accept only a literal `addr` or `addr/len` — never a hostname, which would
/// make the effective rule depend on DNS at apply time.
fn validate_cidr(src: &str) -> Result<()> {
    let (addr, prefix) = match src.split_once('/') {
        Some((a, p)) => (a, Some(p)),
        None => (src, None),
    };
    let ip: IpAddr = addr
        .parse()
        .map_err(|_| DistroError::InvalidName(format!("`{src}` is not an IP address or CIDR")))?;
    if let Some(prefix) = prefix {
        let max = if ip.is_ipv6() { 128 } else { 32 };
        let len: u8 = prefix.parse().map_err(|_| {
            DistroError::InvalidName(format!("`{src}` has a non-numeric prefix length"))
        })?;
        if len > max {
            return Err(DistroError::InvalidName(format!(
                "`{src}` prefix length exceeds /{max}"
            )));
        }
    }
    Ok(())
}

/// Is a CIDR in the v6 family?
fn cidr_is_v6(src: &str) -> bool {
    let addr = src.split_once('/').map(|(a, _)| a).unwrap_or(src);
    addr.parse::<IpAddr>()
        .map(|ip| ip.is_ipv6())
        .unwrap_or(false)
}

#[async_trait]
pub trait FwBackend: Send + Sync {
    fn name(&self) -> &'static str;

    /// Is the firewall actually running? A panel that reports "port opened" while
    /// the firewall is stopped is lying to its operator.
    async fn is_active(&self) -> Result<bool>;

    /// Open a port. Must be idempotent: opening 443 twice is one hole, and the
    /// second call is not an error.
    async fn open_port(&self, rule: &PortRule) -> Result<()>;

    /// Close a port **we opened**. A backend must never remove a rule it did not
    /// create; the [`MARK`] comment is how it tells.
    async fn close_port(&self, rule: &PortRule) -> Result<()>;

    /// The rules Unihelm manages. Not the whole ruleset — the operator's own
    /// rules are none of our business and must never appear as ours to delete.
    async fn list_rules(&self) -> Result<Vec<PortRule>>;

    /// Add an address to the ban set used by Sentinel (spec §11.9).
    async fn ban_ip(&self, ip: IpAddr, ttl_seconds: Option<u32>) -> Result<()>;
    async fn unban_ip(&self, ip: IpAddr) -> Result<()>;
    async fn list_bans(&self) -> Result<Vec<IpAddr>>;
}

// ---------------------------------------------------------------------------
// detection
// ---------------------------------------------------------------------------

/// Pick the backend that actually owns this host's ruleset.
///
/// `family` only decides the order we look in — a RHEL box with ufw installed
/// and firewalld absent still gets ufw, because ufw is what is filtering.
pub fn detect(family: Family) -> std::sync::Arc<dyn FwBackend> {
    use std::sync::Arc;

    let firewalld = program_available("firewall-cmd");
    let ufw = program_available("ufw");
    let nft = program_available("nft");

    let preference: &[&str] = match family {
        Family::Rhel => &["firewalld", "ufw", "nft"],
        Family::Debian => &["ufw", "nft", "firewalld"],
    };

    for choice in preference {
        match *choice {
            "firewalld" if firewalld => return Arc::new(FirewalldBackend::new()),
            "ufw" if ufw => return Arc::new(UfwBackend::new()),
            "nft" if nft => return Arc::new(NftablesBackend::new()),
            _ => {}
        }
    }
    Arc::new(UnmanagedBackend::new())
}

// ---------------------------------------------------------------------------
// firewalld (RHEL family)
// ---------------------------------------------------------------------------

/// Rules are added `--permanent` and then reloaded, so they survive a
/// `firewall-cmd --reload` and a reboot (spec §11.9 AC).
///
/// Bans go into an ipset rather than into rich rules. Sentinel can ban thousands
/// of addresses, and a thousand rich rules is a linear scan on every packet.
pub struct FirewalldBackend;

impl FirewalldBackend {
    pub fn new() -> Self {
        Self
    }

    fn cmd(&self) -> Cmd {
        Cmd::new("firewall-cmd")
    }

    /// firewalld exits non-zero for "already there" and "not there", which are
    /// both fine for an idempotent call. Anything else is a real failure.
    async fn run_tolerating(&self, cmd: Cmd, tolerated: &[&str]) -> Result<()> {
        let out = cmd.run().await?;
        if out.success() {
            return Ok(());
        }
        let text = out.failure_text();
        let lowered = text.to_lowercase();
        if tolerated.iter().any(|t| lowered.contains(t)) {
            tracing::debug!(cmd = %cmd.display(), detail = %text, "firewalld call was already satisfied");
            return Ok(());
        }
        Err(DistroError::CommandFailed {
            cmd: cmd.display(),
            status: out.status,
            output: text,
        })
    }

    async fn reload(&self) -> Result<()> {
        self.cmd().arg("--reload").run_checked().await?;
        Ok(())
    }

    /// A rich rule string for a source-restricted port.
    ///
    /// Every field is either a validated CIDR, a `u16`, or one of two constant
    /// protocol words, so there is nothing here a caller could inject through.
    fn rich_rule(rule: &PortRule, source: &str) -> String {
        let family = if cidr_is_v6(source) { "ipv6" } else { "ipv4" };
        format!(
            r#"rule family="{family}" source address="{source}" port port="{}" protocol="{}" accept"#,
            rule.port,
            rule.proto.as_str()
        )
    }

    /// Create the ban ipsets and the rule that drops anything in them.
    ///
    /// Idempotent, and called before every ban rather than at start-up, so a
    /// firewalld that was reinstalled underneath us heals on the next ban
    /// instead of silently dropping nothing.
    async fn ensure_ban_sets(&self) -> Result<()> {
        for (set, family) in [(BAN_SET_V4, "inet"), (BAN_SET_V6, "inet6")] {
            self.run_tolerating(
                self.cmd().args([
                    "--permanent",
                    &format!("--new-ipset={set}"),
                    "--type=hash:ip",
                    &format!("--option=family={family}"),
                    // Entries carry their own timeout, so a temporary ban expires
                    // by itself even if the panel is not running when it should
                    // have been lifted.
                    "--option=timeout=0",
                    "--option=maxelem=65536",
                ]),
                &["already exists", "name_conflict"],
            )
            .await?;

            self.run_tolerating(
                self.cmd().args([
                    "--permanent",
                    &format!(r#"--add-rich-rule=rule source ipset="{set}" drop"#),
                ]),
                &["already_enabled", "already enabled"],
            )
            .await?;
        }
        self.reload().await
    }

    fn ban_set_for(ip: IpAddr) -> &'static str {
        if ip.is_ipv6() { BAN_SET_V6 } else { BAN_SET_V4 }
    }
}

impl Default for FirewalldBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl FwBackend for FirewalldBackend {
    fn name(&self) -> &'static str {
        "firewalld"
    }

    async fn is_active(&self) -> Result<bool> {
        // `--state` prints "running" and exits 0, or prints "not running" and
        // exits 252. A missing binary is a spawn error, which is also "no".
        Ok(self
            .cmd()
            .arg("--state")
            .run()
            .await
            .map(|o| o.success() && o.trimmed_stdout() == "running")
            .unwrap_or(false))
    }

    async fn open_port(&self, rule: &PortRule) -> Result<()> {
        rule.validate()?;
        let arg = match &rule.source {
            None => format!("--add-port={}/{}", rule.port, rule.proto.as_str()),
            Some(src) => format!("--add-rich-rule={}", Self::rich_rule(rule, src)),
        };
        self.run_tolerating(
            self.cmd().args(["--permanent", &arg]),
            &["already_enabled", "already enabled"],
        )
        .await?;
        self.reload().await
    }

    async fn close_port(&self, rule: &PortRule) -> Result<()> {
        rule.validate()?;
        let arg = match &rule.source {
            None => format!("--remove-port={}/{}", rule.port, rule.proto.as_str()),
            Some(src) => format!("--remove-rich-rule={}", Self::rich_rule(rule, src)),
        };
        self.run_tolerating(
            self.cmd().args(["--permanent", &arg]),
            &["not_enabled", "not enabled"],
        )
        .await?;
        self.reload().await
    }

    async fn list_rules(&self) -> Result<Vec<PortRule>> {
        let mut rules = Vec::new();

        // `--list-ports` prints a single space-separated line: "80/tcp 443/tcp".
        let ports = self
            .cmd()
            .args(["--permanent", "--list-ports"])
            .run_checked()
            .await?;
        for token in ports.trimmed_stdout().split_whitespace() {
            if let Some((port, proto)) = token.split_once('/')
                && let (Ok(port), Some(proto)) = (port.parse::<u16>(), Proto::parse(proto))
            {
                rules.push(PortRule {
                    port,
                    proto,
                    source: None,
                    comment: String::new(),
                });
            }
        }

        // Rich rules, one per line. Only the port-accept shape is ours to report;
        // the ban rule and anything the operator wrote are skipped.
        let rich = self
            .cmd()
            .args(["--permanent", "--list-rich-rules"])
            .run_checked()
            .await?;
        for line in rich.stdout.lines() {
            if let Some(rule) = parse_rich_rule(line) {
                rules.push(rule);
            }
        }

        Ok(rules)
    }

    async fn ban_ip(&self, ip: IpAddr, ttl_seconds: Option<u32>) -> Result<()> {
        self.ensure_ban_sets().await?;
        let set = Self::ban_set_for(ip);
        let mut cmd = self
            .cmd()
            .args([&format!("--ipset={set}"), &format!("--add-entry={ip}")]);
        if let Some(ttl) = ttl_seconds {
            cmd = cmd.arg(format!("--timeout={ttl}"));
        }
        // Runtime, not permanent: a ban that outlives a reboot should be a
        // deliberate act, and Sentinel's bans are by nature temporary.
        self.run_tolerating(cmd, &["already_enabled", "already enabled"])
            .await
    }

    async fn unban_ip(&self, ip: IpAddr) -> Result<()> {
        let set = Self::ban_set_for(ip);
        self.run_tolerating(
            self.cmd()
                .args([&format!("--ipset={set}"), &format!("--remove-entry={ip}")]),
            &["not_enabled", "not enabled", "invalid_ipset"],
        )
        .await
    }

    async fn list_bans(&self) -> Result<Vec<IpAddr>> {
        let mut bans = Vec::new();
        for set in [BAN_SET_V4, BAN_SET_V6] {
            let out = self
                .cmd()
                .args([&format!("--ipset={set}"), "--get-entries"])
                .run()
                .await?;
            // A set that does not exist yet simply has no bans in it.
            if !out.success() {
                continue;
            }
            bans.extend(
                out.stdout
                    .split_whitespace()
                    .filter_map(|s| s.parse::<IpAddr>().ok()),
            );
        }
        Ok(bans)
    }
}

/// Pull a port rule back out of a firewalld rich rule line.
///
/// Deliberately narrow: it matches the exact shape [`FirewalldBackend::rich_rule`]
/// writes and returns `None` for anything else, so an operator's hand-written
/// rule never shows up in the panel as something Unihelm owns and may delete.
fn parse_rich_rule(line: &str) -> Option<PortRule> {
    let field = |key: &str| -> Option<String> {
        let at = line.find(key)?;
        let rest = &line[at + key.len()..];
        let rest = rest.strip_prefix('"')?;
        let end = rest.find('"')?;
        Some(rest[..end].to_string())
    };

    if !line.contains("accept") {
        return None;
    }
    let port: u16 = field("port port=")?.parse().ok()?;
    let proto = Proto::parse(&field("protocol=")?)?;
    let source = field("source address=")?;
    validate_cidr(&source).ok()?;
    Some(PortRule {
        port,
        proto,
        source: Some(source),
        comment: String::new(),
    })
}

// ---------------------------------------------------------------------------
// ufw (Debian family, when installed)
// ---------------------------------------------------------------------------

/// Debian and Ubuntu ship ufw and it owns the nftables ruleset when enabled, so
/// we drive it rather than writing rules it would overwrite on its next reload.
pub struct UfwBackend;

impl UfwBackend {
    pub fn new() -> Self {
        Self
    }

    fn cmd(&self) -> Cmd {
        // ufw asks for confirmation on some subcommands; `--force` is the
        // documented non-interactive form, not a way to skip a safety check.
        Cmd::new("ufw")
    }
}

impl Default for UfwBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl FwBackend for UfwBackend {
    fn name(&self) -> &'static str {
        "ufw"
    }

    async fn is_active(&self) -> Result<bool> {
        let out = self.cmd().arg("status").run().await?;
        Ok(out.success() && out.stdout.contains("Status: active"))
    }

    async fn open_port(&self, rule: &PortRule) -> Result<()> {
        rule.validate()?;
        // ufw is idempotent by itself: a duplicate `allow` prints "Skipping
        // adding existing rule" and exits 0.
        let mut cmd = self.cmd().arg("allow");
        match &rule.source {
            None => {
                cmd = cmd.args([
                    "proto",
                    rule.proto.as_str(),
                    "to",
                    "any",
                    "port",
                    &rule.port.to_string(),
                ]);
            }
            Some(src) => {
                cmd = cmd.args([
                    "from",
                    src,
                    "proto",
                    rule.proto.as_str(),
                    "to",
                    "any",
                    "port",
                    &rule.port.to_string(),
                ]);
            }
        }
        cmd.args(["comment", &rule.marked_comment()])
            .run_checked()
            .await?;
        Ok(())
    }

    async fn close_port(&self, rule: &PortRule) -> Result<()> {
        rule.validate()?;
        let mut cmd = self.cmd().args(["--force", "delete", "allow"]);
        match &rule.source {
            None => {
                cmd = cmd.args([
                    "proto",
                    rule.proto.as_str(),
                    "to",
                    "any",
                    "port",
                    &rule.port.to_string(),
                ]);
            }
            Some(src) => {
                cmd = cmd.args([
                    "from",
                    src,
                    "proto",
                    rule.proto.as_str(),
                    "to",
                    "any",
                    "port",
                    &rule.port.to_string(),
                ]);
            }
        }
        let out = cmd.run().await?;
        // "Could not delete non-existent rule" is the state we wanted anyway.
        if out.success() || out.failure_text().contains("non-existent") {
            return Ok(());
        }
        Err(DistroError::CommandFailed {
            cmd: cmd.display(),
            status: out.status,
            output: out.failure_text(),
        })
    }

    async fn list_rules(&self) -> Result<Vec<PortRule>> {
        let out = self.cmd().args(["status", "verbose"]).run_checked().await?;
        Ok(parse_ufw_status(&out.stdout))
    }

    async fn ban_ip(&self, ip: IpAddr, _ttl_seconds: Option<u32>) -> Result<()> {
        // ufw has no expiry of its own. The ban is recorded with our mark and
        // Sentinel lifts it on schedule; if the panel is down when it should
        // have expired, the ban outlives its welcome rather than disappearing
        // early, which is the safer of the two.
        self.cmd()
            .args([
                "insert",
                "1",
                "deny",
                "from",
                &ip.to_string(),
                "comment",
                &format!("{MARK}: ban"),
            ])
            .run_checked()
            .await?;
        Ok(())
    }

    async fn unban_ip(&self, ip: IpAddr) -> Result<()> {
        let out = self
            .cmd()
            .args(["--force", "delete", "deny", "from", &ip.to_string()])
            .run()
            .await?;
        if out.success() || out.failure_text().contains("non-existent") {
            return Ok(());
        }
        Err(DistroError::CommandFailed {
            cmd: format!("ufw delete deny from {ip}"),
            status: out.status,
            output: out.failure_text(),
        })
    }

    async fn list_bans(&self) -> Result<Vec<IpAddr>> {
        let out = self.cmd().args(["status", "verbose"]).run_checked().await?;
        Ok(out
            .stdout
            .lines()
            .filter(|l| l.contains("DENY") && l.contains(MARK))
            .filter_map(|l| l.split_whitespace().find_map(|t| t.parse::<IpAddr>().ok()))
            .collect())
    }
}

/// Read Unihelm's rules back out of `ufw status verbose`.
///
/// Lines look like:
/// `80/tcp                     ALLOW IN    Anywhere                   # unihelm: http`
fn parse_ufw_status(text: &str) -> Vec<PortRule> {
    let mut rules = Vec::new();
    for line in text.lines() {
        let Some((body, comment)) = line.split_once('#') else {
            continue;
        };
        let comment = comment.trim();
        let Some(comment) = comment.strip_prefix(&format!("{MARK}: ")) else {
            continue;
        };
        if !body.contains("ALLOW") {
            continue;
        }
        let mut fields = body.split_whitespace();
        let Some(target) = fields.next() else {
            continue;
        };
        let Some((port, proto)) = target.split_once('/') else {
            continue;
        };
        let (Ok(port), Some(proto)) = (port.parse::<u16>(), Proto::parse(proto)) else {
            continue;
        };
        // The source column is whatever follows "ALLOW IN"; "Anywhere" means
        // unrestricted. ufw appends "(v6)" to the v6 duplicate of a rule, which
        // is the same rule as far as we are concerned.
        let source = body
            .split("ALLOW IN")
            .nth(1)
            .map(str::trim)
            .filter(|s| !s.is_empty() && !s.starts_with("Anywhere"))
            .map(|s| s.split_whitespace().next().unwrap_or(s).to_string())
            .filter(|s| validate_cidr(s).is_ok());

        rules.push(PortRule {
            port,
            proto,
            source,
            comment: comment.to_string(),
        });
    }
    rules
}

// ---------------------------------------------------------------------------
// nftables (no other firewall present)
// ---------------------------------------------------------------------------

/// nftables directly, in a dedicated `inet unihelm` table so we never edit rules
/// somebody else owns.
///
/// One honest limitation, stated here because it would otherwise be a surprise:
/// netfilter runs **every** chain registered on a hook, and a terminal `accept`
/// in our chain ends our chain, not the packet's journey through the others. So
/// an accept rule here cannot punch through a `drop` in a table we do not own.
/// It is meaningful in the two cases that matter — a host with no other
/// filtering (where it documents intent and is ready if a policy is added) and a
/// host where Unihelm owns the policy. Bans are unaffected: `drop` **is**
/// immediately terminal, so a ban added here takes effect regardless of what
/// else is loaded.
pub struct NftablesBackend;

impl NftablesBackend {
    pub fn new() -> Self {
        Self
    }

    fn cmd(&self) -> Cmd {
        Cmd::new("nft")
    }

    /// Create our table, chain and ban sets if they are not already there.
    ///
    /// `nft -f -` would need a here-doc; `add` is idempotent in nftables by
    /// design ("add table" on an existing table is a no-op), so a sequence of
    /// argv calls does the same job without a shell anywhere near it.
    async fn ensure_table(&self) -> Result<()> {
        self.cmd()
            .args(["add", "table", "inet", NFT_TABLE])
            .run_checked()
            .await?;

        // priority filter(0) - 5: before the usual filter chains, so a ban drops
        // the packet before anything else spends time on it.
        self.cmd()
            .args([
                "add",
                "chain",
                "inet",
                NFT_TABLE,
                "input",
                "{ type filter hook input priority -5 ; policy accept ; }",
            ])
            .run_checked()
            .await?;

        for (set, ty) in [(BAN_SET_V4, "ipv4_addr"), (BAN_SET_V6, "ipv6_addr")] {
            self.cmd()
                .args([
                    "add",
                    "set",
                    "inet",
                    NFT_TABLE,
                    set,
                    &format!("{{ type {ty} ; flags timeout ; }}"),
                ])
                .run_checked()
                .await?;
        }

        // The two rules that consult the ban sets. `insert` puts them at the
        // head; running it twice would duplicate them, so they are added only
        // when the chain does not mention the set yet.
        let listing = self
            .cmd()
            .args(["list", "chain", "inet", NFT_TABLE, "input"])
            .run_checked()
            .await?;
        if !listing.stdout.contains(BAN_SET_V4) {
            self.cmd()
                .args([
                    "add",
                    "rule",
                    "inet",
                    NFT_TABLE,
                    "input",
                    "ip",
                    "saddr",
                    &format!("@{BAN_SET_V4}"),
                    "drop",
                ])
                .run_checked()
                .await?;
        }
        if !listing.stdout.contains(BAN_SET_V6) {
            self.cmd()
                .args([
                    "add",
                    "rule",
                    "inet",
                    NFT_TABLE,
                    "input",
                    "ip6",
                    "saddr",
                    &format!("@{BAN_SET_V6}"),
                    "drop",
                ])
                .run_checked()
                .await?;
        }
        Ok(())
    }

    /// The handle nftables assigned to the rule matching `rule`, if it is there.
    ///
    /// Deletion in nftables is by handle, so finding it is the only way to
    /// remove one rule without rewriting the chain.
    async fn handle_for(&self, rule: &PortRule) -> Result<Option<u64>> {
        let listing = self
            .cmd()
            .args(["-a", "list", "chain", "inet", NFT_TABLE, "input"])
            .run_checked()
            .await?;
        let want = rule.marked_comment();
        for line in listing.stdout.lines() {
            if !line.contains(&want) {
                continue;
            }
            if let Some(at) = line.find("# handle ") {
                let rest = &line[at + "# handle ".len()..];
                if let Ok(handle) = rest.trim().parse::<u64>() {
                    return Ok(Some(handle));
                }
            }
        }
        Ok(None)
    }

    fn ban_set_for(ip: IpAddr) -> &'static str {
        if ip.is_ipv6() { BAN_SET_V6 } else { BAN_SET_V4 }
    }
}

impl Default for NftablesBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl FwBackend for NftablesBackend {
    fn name(&self) -> &'static str {
        "nftables"
    }

    async fn is_active(&self) -> Result<bool> {
        Ok(program_available("nft") && self.cmd().args(["list", "ruleset"]).run().await?.success())
    }

    async fn open_port(&self, rule: &PortRule) -> Result<()> {
        rule.validate()?;
        self.ensure_table().await?;
        if self.handle_for(rule).await?.is_some() {
            return Ok(());
        }

        let mut args: Vec<String> = vec![
            "add".into(),
            "rule".into(),
            "inet".into(),
            NFT_TABLE.into(),
            "input".into(),
        ];
        if let Some(src) = &rule.source {
            args.push(if cidr_is_v6(src) {
                "ip6".into()
            } else {
                "ip".into()
            });
            args.push("saddr".into());
            args.push(src.clone());
        }
        args.push(rule.proto.as_str().into());
        args.push("dport".into());
        args.push(rule.port.to_string());
        args.push("accept".into());
        args.push("comment".into());
        args.push(format!("\"{}\"", rule.marked_comment()));

        self.cmd().args(args).run_checked().await?;
        Ok(())
    }

    async fn close_port(&self, rule: &PortRule) -> Result<()> {
        rule.validate()?;
        // No table means nothing of ours to remove, which is the desired state.
        let Some(handle) = self.handle_for(rule).await.unwrap_or(None) else {
            return Ok(());
        };
        self.cmd()
            .args([
                "delete",
                "rule",
                "inet",
                NFT_TABLE,
                "input",
                "handle",
                &handle.to_string(),
            ])
            .run_checked()
            .await?;
        Ok(())
    }

    async fn list_rules(&self) -> Result<Vec<PortRule>> {
        let out = self
            .cmd()
            .args(["list", "chain", "inet", NFT_TABLE, "input"])
            .run()
            .await?;
        if !out.success() {
            // No table yet: no managed rules.
            return Ok(Vec::new());
        }
        Ok(parse_nft_rules(&out.stdout))
    }

    async fn ban_ip(&self, ip: IpAddr, ttl_seconds: Option<u32>) -> Result<()> {
        self.ensure_table().await?;
        let set = Self::ban_set_for(ip);
        let element = match ttl_seconds {
            Some(ttl) => format!("{{ {ip} timeout {ttl}s }}"),
            None => format!("{{ {ip} }}"),
        };
        self.cmd()
            .args(["add", "element", "inet", NFT_TABLE, set, &element])
            .run_checked()
            .await?;
        Ok(())
    }

    async fn unban_ip(&self, ip: IpAddr) -> Result<()> {
        let set = Self::ban_set_for(ip);
        let out = self
            .cmd()
            .args([
                "delete",
                "element",
                "inet",
                NFT_TABLE,
                set,
                &format!("{{ {ip} }}"),
            ])
            .run()
            .await?;
        // "No such file or directory" is nftables for "it was not in the set".
        if out.success() || out.failure_text().contains("No such file") {
            return Ok(());
        }
        Err(DistroError::CommandFailed {
            cmd: format!("nft delete element inet {NFT_TABLE} {set} {{ {ip} }}"),
            status: out.status,
            output: out.failure_text(),
        })
    }

    async fn list_bans(&self) -> Result<Vec<IpAddr>> {
        let mut bans = Vec::new();
        for set in [BAN_SET_V4, BAN_SET_V6] {
            let out = self
                .cmd()
                .args(["list", "set", "inet", NFT_TABLE, set])
                .run()
                .await?;
            if !out.success() {
                continue;
            }
            bans.extend(parse_nft_set_elements(&out.stdout));
        }
        Ok(bans)
    }
}

/// Read our accept rules back out of `nft list chain`.
///
/// Only lines carrying the [`MARK`] comment count, so the operator's own rules
/// in some other table — or even in this one, if they put them there — are never
/// reported as Unihelm's to delete.
fn parse_nft_rules(text: &str) -> Vec<PortRule> {
    let mut rules = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if !line.contains(&format!("\"{MARK}: ")) || !line.contains("accept") {
            continue;
        }
        let mut fields = line.split_whitespace().peekable();
        let mut proto = None;
        let mut port = None;
        let mut source = None;
        while let Some(f) = fields.next() {
            match f {
                "saddr" => source = fields.next().map(str::to_string),
                "dport" => port = fields.next().and_then(|p| p.parse::<u16>().ok()),
                // Only when it introduces the dport match, not as part of a
                // set name.
                "tcp" | "udp" if fields.peek() == Some(&"dport") => proto = Proto::parse(f),
                _ => {}
            }
        }
        let comment = line
            .split_once(&format!("\"{MARK}: "))
            .and_then(|(_, rest)| rest.split_once('"'))
            .map(|(c, _)| c.to_string())
            .unwrap_or_default();

        if let (Some(proto), Some(port)) = (proto, port) {
            rules.push(PortRule {
                port,
                proto,
                source: source.filter(|s| validate_cidr(s).is_ok()),
                comment,
            });
        }
    }
    rules
}

/// Pull addresses out of `nft list set`, whose elements block looks like
/// `elements = { 10.0.0.1 timeout 1h expires 59m, 10.0.0.2 }` — and which nft
/// wraps across lines once there is more than one entry.
///
/// The braces of the `elements` block specifically, not the first and last brace
/// in the output: the set's own `{ … }` and the table's enclose it, so taking
/// the outermost pair swallows `type ipv4_addr` and loses the first address.
fn parse_nft_set_elements(text: &str) -> Vec<IpAddr> {
    let Some(at) = text.find("elements") else {
        return Vec::new();
    };
    let rest = &text[at..];
    let Some(open) = rest.find('{') else {
        return Vec::new();
    };
    let Some(close) = rest[open..].find('}') else {
        return Vec::new();
    };
    rest[open + 1..open + close]
        .split(',')
        .filter_map(|element| element.split_whitespace().next())
        .filter_map(|addr| addr.parse::<IpAddr>().ok())
        .collect()
}

// ---------------------------------------------------------------------------
// no firewall at all
// ---------------------------------------------------------------------------

/// The host has no firewall we can drive.
///
/// It reports itself plainly instead of impersonating one. Callers that only
/// want a port reachable should check [`FwBackend::is_active`] first and treat
/// "no firewall" as "already reachable" — which it is — rather than as a
/// failure.
pub struct UnmanagedBackend;

impl UnmanagedBackend {
    pub fn new() -> Self {
        Self
    }
}

impl Default for UnmanagedBackend {
    fn default() -> Self {
        Self::new()
    }
}

fn no_firewall(op: &str) -> DistroError {
    DistroError::CommandFailed {
        cmd: format!("firewall::{op}"),
        status: -1,
        output: "no firewall is installed on this host (looked for firewalld, ufw and nft), \
                 so there is nothing to change"
            .into(),
    }
}

#[async_trait]
impl FwBackend for UnmanagedBackend {
    fn name(&self) -> &'static str {
        "none"
    }

    async fn is_active(&self) -> Result<bool> {
        Ok(false)
    }

    async fn open_port(&self, rule: &PortRule) -> Result<()> {
        rule.validate()?;
        Err(no_firewall("open_port"))
    }

    async fn close_port(&self, rule: &PortRule) -> Result<()> {
        rule.validate()?;
        Err(no_firewall("close_port"))
    }

    async fn list_rules(&self) -> Result<Vec<PortRule>> {
        Ok(Vec::new())
    }

    async fn ban_ip(&self, _ip: IpAddr, _ttl_seconds: Option<u32>) -> Result<()> {
        Err(no_firewall("ban_ip"))
    }

    async fn unban_ip(&self, _ip: IpAddr) -> Result<()> {
        Err(no_firewall("unban_ip"))
    }

    async fn list_bans(&self) -> Result<Vec<IpAddr>> {
        Ok(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(source: Option<&str>) -> PortRule {
        PortRule {
            port: 3306,
            proto: Proto::Tcp,
            source: source.map(str::to_string),
            comment: "remote mysql".into(),
        }
    }

    #[test]
    fn cidr_validation_accepts_real_networks() {
        for ok in [
            "10.0.0.0/8",
            "203.0.113.4",
            "203.0.113.4/32",
            "2001:db8::/32",
            "::1",
        ] {
            assert!(rule(Some(ok)).validate().is_ok(), "{ok} should be accepted");
        }
    }

    #[test]
    fn cidr_validation_rejects_hostnames_and_nonsense() {
        for bad in [
            "example.com",
            "10.0.0.0/33",
            "2001:db8::/129",
            "10.0.0.0/abc",
            "'; drop",
            "",
        ] {
            assert!(
                rule(Some(bad)).validate().is_err(),
                "{bad} should be rejected"
            );
        }
    }

    #[test]
    fn port_zero_is_refused() {
        let mut r = rule(None);
        r.port = 0;
        assert!(r.validate().is_err());
    }

    #[test]
    fn comments_cannot_smuggle_newlines_into_a_ruleset() {
        let mut r = rule(None);
        r.comment = "ok\naccept all".into();
        assert!(r.validate().is_err());
    }

    #[test]
    fn a_rich_rule_carries_the_right_address_family() {
        let v4 = FirewalldBackend::rich_rule(&rule(Some("10.0.0.0/8")), "10.0.0.0/8");
        assert!(v4.contains(r#"family="ipv4""#), "{v4}");
        let v6 = FirewalldBackend::rich_rule(&rule(Some("2001:db8::/32")), "2001:db8::/32");
        assert!(v6.contains(r#"family="ipv6""#), "{v6}");
    }

    #[test]
    fn a_rich_rule_round_trips() {
        let original = rule(Some("203.0.113.0/24"));
        let text = FirewalldBackend::rich_rule(&original, "203.0.113.0/24");
        let parsed = parse_rich_rule(&text).expect("our own rule should parse");
        assert_eq!(parsed.port, original.port);
        assert_eq!(parsed.proto, original.proto);
        assert_eq!(parsed.source, original.source);
    }

    #[test]
    fn someone_elses_rich_rule_is_not_reported_as_ours() {
        // If we claimed this one, the panel would offer to delete a rule the
        // operator wrote by hand.
        for foreign in [
            r#"rule family="ipv4" source address="10.0.0.0/8" service name="ssh" accept"#,
            r#"rule family="ipv4" source address="10.0.0.0/8" drop"#,
            r#"rule source ipset="unihelm_bans" drop"#,
            "",
        ] {
            assert!(
                parse_rich_rule(foreign).is_none(),
                "{foreign} should not be read as a Unihelm port rule"
            );
        }
    }

    #[test]
    fn ufw_status_yields_only_our_rules() {
        let status = "\
Status: active

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW IN    Anywhere
80/tcp                     ALLOW IN    Anywhere                   # unihelm: http
443/tcp                    ALLOW IN    Anywhere                   # unihelm: https
3306/tcp                   ALLOW IN    10.0.0.0/8                 # unihelm: remote mysql
5432/tcp                   ALLOW IN    Anywhere                   # my own rule
";
        let rules = parse_ufw_status(status);
        assert_eq!(rules.len(), 3, "{rules:?}");
        assert_eq!(rules[0].port, 80);
        assert_eq!(rules[0].source, None);
        assert_eq!(rules[2].port, 3306);
        assert_eq!(rules[2].source.as_deref(), Some("10.0.0.0/8"));
        assert_eq!(rules[2].comment, "remote mysql");
        assert!(
            !rules.iter().any(|r| r.port == 22 || r.port == 5432),
            "rules we did not create must not be listed as ours"
        );
    }

    #[test]
    fn nft_rules_are_read_back_with_their_source_and_comment() {
        let listing = r#"
table inet unihelm {
  chain input {
    type filter hook input priority -5; policy accept;
    ip saddr @unihelm_bans drop
    tcp dport 80 accept comment "unihelm: http"
    ip saddr 10.0.0.0/8 tcp dport 3306 accept comment "unihelm: remote mysql"
    tcp dport 9999 accept comment "someone else"
  }
}
"#;
        let rules = parse_nft_rules(listing);
        assert_eq!(rules.len(), 2, "{rules:?}");
        assert_eq!((rules[0].port, rules[0].source.clone()), (80, None));
        assert_eq!(rules[1].port, 3306);
        assert_eq!(rules[1].source.as_deref(), Some("10.0.0.0/8"));
        assert_eq!(rules[1].comment, "remote mysql");
    }

    #[test]
    fn nft_set_elements_survive_their_timeout_annotations() {
        let listing = r#"
table inet unihelm {
  set unihelm_bans {
    type ipv4_addr
    flags timeout
    elements = { 10.0.0.1 timeout 1h expires 59m14s,
                 203.0.113.9 }
  }
}
"#;
        let bans = parse_nft_set_elements(listing);
        assert_eq!(bans.len(), 2, "{bans:?}");
        assert_eq!(bans[0].to_string(), "10.0.0.1");
        assert_eq!(bans[1].to_string(), "203.0.113.9");
    }

    #[tokio::test]
    async fn a_host_with_no_firewall_says_so_instead_of_pretending() {
        // The live bug this replaces: an AlmaLinux box with no firewall-cmd
        // installed announced `fw: firewalld` on every boot and would have
        // reported success for ports it never opened.
        let fw = UnmanagedBackend::new();
        assert_eq!(fw.name(), "none");
        assert!(!fw.is_active().await.unwrap());
        assert!(fw.list_rules().await.unwrap().is_empty());
        let err = fw.open_port(&rule(None)).await.unwrap_err().to_string();
        assert!(err.contains("no firewall"), "{err}");
    }

    #[tokio::test]
    async fn an_invalid_rule_is_refused_before_any_backend_is_consulted() {
        let mut bad = rule(None);
        bad.port = 0;
        for backend in [
            Box::new(UnmanagedBackend::new()) as Box<dyn FwBackend>,
            Box::new(FirewalldBackend::new()),
            Box::new(UfwBackend::new()),
            Box::new(NftablesBackend::new()),
        ] {
            let err = backend.open_port(&bad).await.unwrap_err().to_string();
            assert!(
                err.contains("port 0"),
                "{} accepted a zero port: {err}",
                backend.name()
            );
        }
    }
}
