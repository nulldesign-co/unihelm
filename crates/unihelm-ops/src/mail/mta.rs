//! The local mail transfer agent: a Postfix null client (spec §11.18).
//!
//! # What this replaces, and what that design cost
//!
//! Until this change mail was a **PHP feature**. Every site's FPM pool carried
//!
//! ```text
//! php_admin_value[sendmail_path] = msmtp --file=/etc/unihelm/mail/<domain>.msmtprc -t
//! ```
//!
//! and msmtp ran as the tenant, because PHP's `mail()` does. So the file it
//! reads had to be readable by the tenant. There is one relay row for the whole
//! server, so every one of those per-site files held the **same** secret: the
//! credential this machine authenticates to SendGrid, SES or Postmark with. Any
//! customer with a PHP site could read their own copy and send as the operator,
//! and the blacklisting that follows takes every other customer's mail down
//! with it.
//!
//! The second half of the cost was quieter. `sendmail_path` is a PHP-FPM pool
//! directive, so **only PHP could send at all**: a Node application had nothing
//! to hand a message to, a container had nothing, a server with no PHP
//! installed — an ordinary configuration for a panel that runs its databases as
//! containers — had no mail whatsoever, and `cron.rs` had been writing a
//! `MAILTO=` line into every tenant crontab for a mail system that did not
//! exist.
//!
//! # What is here instead
//!
//! ```text
//! PHP       mail()      → /usr/sbin/sendmail          ─┐
//! Node      nodemailer  → 127.0.0.1:25                 │
//! Python    smtplib     → 127.0.0.1:25                 ├→ Postfix (root, credential 0600) → relay
//! CLI       mail(1)     → the same                     │
//! cron      MAILTO=     → the same                     │
//! container anything    → host.docker.internal:25     ─┘
//! ```
//!
//! Postfix's `smtp(8)` opens the credential map in its pre-jail initialisation,
//! while it is still root, and only then drops privileges — so no account but
//! root ever needs to read the relay password, and none is given the chance.
//! The tenant hands over a message and never sees a credential. Mail stops
//! being a PHP feature and becomes a property of the server.
//!
//! # Three files, and why each one
//!
//! * [`unihelm_config::paths::postfix_main_cf`] — the null client itself. The
//!   one file the panel writes outside a directory of its own: `main.cf` has no
//!   `include` and no drop-in directory, so there is no single line to add the
//!   way there is for nginx or sshd. It is a full managed file with a hash
//!   header, so a human's edit — or the package's own `postconf -e` on upgrade
//!   — is detected and reported rather than thrown away.
//! * [`unihelm_config::paths::mail_sasl_passwd`] — the relay credential, `0600`
//!   and root-owned, in the panel's own directory rather than the package's.
//! * [`unihelm_config::paths::mail_sender_canonical`] — which envelope sender a
//!   message leaves as. SPF is evaluated against the envelope and the relay is
//!   authorised for exactly one identity, so every message has to leave as that
//!   one however the application addressed it. Same rule msmtp's `from` applied,
//!   and the `From:` header is deliberately left alone (see
//!   `sender_canonical_classes` in the render).
//!
//! Neither map is compiled: `main.cf` names them `texthash:`, which every
//! Postfix can read with no plugin package and no `postmap` — and therefore
//! with no second file holding the same password. The cost is that Postfix
//! caches a `texthash:` table when it opens it, so **the panel must reload
//! Postfix whenever it rewrites a map**, or a rotated credential is stored and
//! reported saved while the running daemons keep sending with the old one.
//! [`configure`] does that, and it is the reason it reloads on a map change and
//! not only on a `main.cf` change.
//!
//! # The one client that is not on the loopback, and what it cost to serve it
//!
//! A container has its own network namespace, so its `127.0.0.1` is the
//! container. [`crate::appcontainer`] already gives it a name for the host —
//! `host.docker.internal`, mapped to `host-gateway` — but a null client bound
//! `loopback-only` does not answer there, and `AppMode::Container` is what a
//! *new* application gets. So the common case could not send at all.
//!
//! Serving it means widening an MTA past the loopback, and there are exactly
//! two ways to do that. This module takes the second, and the reason is not a
//! preference:
//!
//! 1. **Name the bridge gateway addresses in `inet_interfaces`.** Tight — the
//!    listener exists only where containers are — and wrong for one reason that
//!    outweighs everything else: `inet_interfaces` is read by `master(8)` at
//!    start-up, and an address in it that cannot be bound is a **fatal** start,
//!    not a warning. The bridge gateways exist only while `dockerd` is running,
//!    nothing orders `postfix.service` after `docker.service`, and a network
//!    Docker recreates gets a different subnet. A boot that lost that race
//!    would leave the machine with **no mail at all** — PHP, cron and host-mode
//!    applications included — which is a strictly worse failure than the one
//!    being fixed, and a silent one. It also needs a restart, not a reload, to
//!    take effect.
//! 2. **`inet_interfaces = all`, with `mynetworks` doing the authorising.**
//!    Postfix always starts, and a network created later is a `Relay access
//!    denied` — loud, and visible in `mail.mta.status` — rather than a listener
//!    that is not there.
//!
//! The cost of the second is real and is not hidden: **port 25 answers on every
//! interface** on a machine that has Docker. Four things bound it, and the
//! fourth is the one an operator has to act on.
//!
//! * `mynetworks` names the loopback and the subnets of this machine's Docker
//!   bridge networks, and nothing else. Never `mynetworks_style = subnet`,
//!   which would take in whatever else the host is attached to.
//! * `smtpd_relay_restrictions = permit_mynetworks, reject_unauth_destination`,
//!   written out rather than inherited: Postfix's built-in default *defers*
//!   rather than rejects, and also carries `permit_sasl_authenticated`.
//! * `smtpd_client_restrictions = permit_mynetworks, reject`, so a client from
//!   outside those networks is refused whatever it asks for, not only when it
//!   asks to relay.
//! * The firewall. `mail.mta.install` opens 25 **from the Docker subnets only**
//!   — without it an enabled ufw drops container traffic to the bridge gateway,
//!   because that arrives on `INPUT` like any other packet — and
//!   [`crate::fwops`] refuses to open 25 to the world while this `main.cf` is
//!   the panel's. On a machine whose firewall is **not running**, none of that
//!   is enforced and the banner is reachable from the internet. It is not a
//!   relay — everything outside `mynetworks` is refused — but it is a service
//!   the machine did not have before, and [`describe_containers`] says so in
//!   the status rather than leaving the operator to find out.
//!
//! **A machine with no Docker is untouched**: no bridge network is found, so
//! `inet_interfaces` stays `loopback-only`, `mynetworks` is the loopback alone,
//! and no firewall rule is written. The widening is a consequence of there
//! being containers to serve, not of installing the MTA.
//!
//! # What this is still not
//!
//! No inbound mail, no mailboxes, no domains, no aliases. `mydestination` is
//! empty and `local_transport` is an error transport: this machine accepts mail
//! *from* the things running on it and delivers it *to* nobody locally. The
//! full Stalwart stack is still Phase 5 and still optional; a null client is not
//! a step towards it.
//!
//! # And it will not accept what it cannot deliver
//!
//! A null client with no relay behind it is a queue nobody drains: `sendmail`
//! exits 0, PHP's `mail()` returns `true`, and the message sits in
//! `/var/spool/postfix` until it is bounced days later. That is the panel
//! reporting success for mail that will never leave, which is the one thing
//! this codebase does not do — so [`MtaInstall`](super::MtaInstall) refuses to
//! configure an MTA before there is a live relay for it to hand messages to,
//! and [`state`] says in one sentence which of those states the machine is in.

use std::path::{Path, PathBuf};

use async_trait::async_trait;
use serde::Serialize;
use unihelm_config::managed::{self, POSTFIX_MAP_MODE};
use unihelm_config::{FileState, ManagedFile, paths};
use unihelm_core::{ErrorCode, Result, UnihelmError};
use unihelm_db::{MailRelay, TlsMode};
use unihelm_distro::pkg;
use unihelm_distro::svc::{ManagedUnit, SvcAction};

use crate::registry::OpContext;

/// What the panel calls the local MTA when it has to name it to a human.
///
/// Reported as `agent` by `mail.relay.get`, where it used to read `msmtp`. The
/// field kept its name because what it answers is unchanged — "what does this
/// server hand a message to" — and only the answer moved.
pub const AGENT: &str = "postfix";

/// Where an application that is not PHP hands a message over.
///
/// Documented in the operation output rather than left for a tenant to guess:
/// `nodemailer`, `smtplib` and every other library want a host and a port, and
/// the whole point of the change is that neither needs a credential.
pub const SUBMISSION_HOST: &str = "127.0.0.1";
pub const SUBMISSION_PORT: u16 = 25;

/// Where a *containerised* application hands a message over.
///
/// The same name [`crate::appcontainer`] maps to `host-gateway` on every
/// container it creates, spelled again here rather than shared, because the two
/// are true for different reasons: there it is how a container reaches a
/// database, here it is what this MTA has to be listening on. A change to
/// either has to be a decision about the other, which a shared constant would
/// hide.
pub const CONTAINER_SUBMISSION_HOST: &str = "host.docker.internal";

/// The loopback, in the spelling `mynetworks` wants.
///
/// Always present, whatever else is: PHP's `sendmail`, cron and every host-mode
/// application submit from here, and they are the clients that worked before
/// containers were served at all.
const LOOPBACK_NETWORKS: [&str; 2] = ["127.0.0.0/8", "[::1]/128"];

/// The `sendmail` PHP's compiled-in default runs, which Postfix provides.
///
/// Checked for existence rather than executed here: it is the one observable
/// difference between "this machine has an MTA" and "PHP's `mail()` returns
/// false".
pub const SENDMAIL_BINARY: &str = "sendmail";

/// The suffix a file we had to move out of the way is kept under.
///
/// Kept, never deleted, and never overwritten by a second adoption: the file it
/// holds is whatever configuration the machine had before the panel took over
/// `main.cf`, and that is the only copy of it.
const REPLACED_SUFFIX: &str = ".unihelm-replaced";

// ---------------------------------------------------------------------------
// naming
// ---------------------------------------------------------------------------

/// What `myhostname` becomes.
///
/// Postfix refuses to start when `myhostname` is not in fully-qualified form —
/// it is used to complete unqualified addresses and to introduce this machine
/// in `EHLO`, and a bare label is neither. A machine whose `/etc/hostname` is
/// `web-01` is an ordinary machine, not a misconfigured one, so the bare label
/// gets `.localdomain` appended the way Postfix's own installer does rather
/// than becoming a refusal an operator cannot act on.
///
/// The character set is checked rather than escaped: the value is written into
/// a line-oriented configuration file and handed to `debconf-set-selections`,
/// where a space or a newline is not a formatting problem but a way to set a
/// parameter nobody asked for.
pub fn my_hostname(raw: &str) -> Result<String> {
    let name = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    let plausible = !name.is_empty()
        && name.len() <= 253
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-'))
        && !name.starts_with(['.', '-'])
        && !name.ends_with('-')
        && !name.contains("..");
    if !plausible {
        return Err(UnihelmError::new(
            ErrorCode::InvalidInput,
            format!(
                "`{raw}` is not a host name Postfix can use as `myhostname`; set this \
                 machine's hostname to a fully-qualified name and run this again"
            ),
        ));
    }
    Ok(if name.contains('.') {
        name
    } else {
        format!("{name}.localdomain")
    })
}

/// `relayhost`, in the form that suppresses the MX lookup.
///
/// The square brackets are load-bearing: without them Postfix looks up the MX
/// records of the relay's name and delivers to those instead. A submission
/// service publishes MX records for the mail it *receives*, which is a
/// different set of hosts from the one it accepts submissions on, so the
/// unbracketed form is how mail ends up at the wrong end of the provider.
pub fn relayhost(host: &str, port: u16) -> String {
    format!("[{host}]:{port}")
}

// ---------------------------------------------------------------------------
// the networks a container could reach us from
// ---------------------------------------------------------------------------

/// One Docker network, as the panel found it.
///
/// The name is carried because it is what the operator sees in `docker network
/// ls` and the only handle they have on a network the panel cannot serve. The
/// driver is carried because it decides whether serving it is possible at all.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ContainerNetwork {
    pub name: String,
    pub driver: String,
    /// The subnets containers on it appear from, in CIDR form.
    pub subnets: Vec<String>,
}

/// Every network on this machine, split by whether its containers can reach us.
///
/// The two flags are separate on purpose. "No Docker" and "Docker whose daemon
/// did not answer" look identical from a distance and must not be treated the
/// same: the first has no networks to serve, the second has networks the panel
/// simply cannot see, and narrowing a configuration on the strength of the
/// second is how a machine stops sending the next time `dockerd` comes back.
/// See [`relay_subnets`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ContainerNetworks {
    /// Is there a `docker` on this machine at all?
    pub docker_installed: bool,
    /// Did its daemon answer?
    pub daemon_answered: bool,
    /// Bridge networks. A container on one of these reaches the host at the
    /// bridge gateway, which is what `host.docker.internal` resolves to.
    pub bridges: Vec<ContainerNetwork>,
    /// Networks on any other driver, kept so they can be *named* rather than
    /// silently dropped. A container on a `macvlan`, `ipvlan` or `overlay`
    /// network does not reach this host through a bridge gateway, and nothing
    /// in this module makes it able to send.
    pub others: Vec<ContainerNetwork>,
}

impl ContainerNetworks {
    /// Every bridge subnet, sorted and deduplicated.
    ///
    /// Sorted because the render has to be byte-stable: Docker lists networks
    /// in whatever order it likes, and an unsorted list would rewrite `main.cf`
    /// and reload Postfix on every pass for no change at all.
    pub fn bridge_subnets(&self) -> Vec<String> {
        let mut out: Vec<String> = self
            .bridges
            .iter()
            .flat_map(|n| n.subnets.iter().cloned())
            .collect();
        out.sort();
        out.dedup();
        out
    }
}

/// Which subnets `mynetworks` should carry, beyond the loopback.
///
/// Pure, and it takes what is already in `main.cf` as an argument, so the one
/// decision that is easy to get wrong is a decision a test can drive: a Docker
/// whose daemon is not answering must **keep** the networks the file already
/// names. Re-rendering the loopback-only configuration there would narrow
/// `inet_interfaces` back, and every container on the machine would stop being
/// able to send the moment `dockerd` came back — with nothing in the panel
/// having reported a change.
pub fn relay_subnets(found: &ContainerNetworks, on_disk: &[String]) -> Vec<String> {
    if !found.docker_installed {
        // No Docker, no bridge, nothing to widen for. This is the branch that
        // keeps a machine without containers exactly as it was.
        return Vec::new();
    }
    if !found.daemon_answered {
        let mut kept: Vec<String> = on_disk.to_vec();
        kept.sort();
        kept.dedup();
        return kept;
    }
    found.bridge_subnets()
}

/// A subnet, in the spelling Postfix's `mynetworks` requires.
///
/// IPv6 networks have to be bracketed there — `[fd00::]/64`, not `fd00::/64` —
/// and Postfix rejects the unbracketed form at start-up rather than ignoring
/// it, so a machine with an IPv6-enabled Docker network would refuse to start
/// the MTA at all.
fn as_mynetworks_entry(subnet: &str) -> String {
    if subnet.contains(':') && !subnet.starts_with('[') {
        match subnet.split_once('/') {
            Some((addr, prefix)) => format!("[{addr}]/{prefix}"),
            None => format!("[{subnet}]"),
        }
    } else {
        subnet.to_string()
    }
}

/// The argv that lists every network's id.
///
/// Split from the inspect below because `docker network inspect` with no
/// arguments is an error, not an empty answer, and the empty case is a real
/// one on a daemon that has had every network removed.
fn network_ls_argv() -> [&'static str; 3] {
    ["network", "ls", "--quiet"]
}

/// What `docker network inspect` is asked to print, per network.
///
/// Whitespace-separated fields rather than a JSON document: Docker's inspect
/// JSON has changed shape between releases, while a Go template of named fields
/// has been stable across all of them — the same reasoning, for the same
/// reason, as [`crate::docker`]'s row parsing. Whitespace is a safe separator
/// because a Docker network name cannot contain any (`[a-zA-Z0-9][a-zA-Z0-9_.-]*`),
/// and anything that somehow did would land in `others` and be reported rather
/// than quietly mis-parsed into `mynetworks`.
const NETWORK_FORMAT: &str = "{{.Name}} {{.Driver}} {{range .IPAM.Config}}{{.Subnet}} {{end}}";

/// Turn that output into networks.
///
/// A line the panel does not understand is skipped rather than guessed at: an
/// entry in `mynetworks` is a grant of the operator's relay credential, and a
/// half-parsed one is a grant to something nobody chose.
pub fn parse_networks(output: &str) -> (Vec<ContainerNetwork>, Vec<ContainerNetwork>) {
    let mut bridges = Vec::new();
    let mut others = Vec::new();
    for line in output.lines() {
        let mut fields = line.split_whitespace();
        let (Some(name), Some(driver)) = (fields.next(), fields.next()) else {
            continue;
        };
        let subnets: Vec<String> = fields
            // A CIDR and nothing else. Postfix reads `mynetworks` as a
            // whitespace-separated list, so a value with anything unexpected in
            // it would not be a parse error there but a different network.
            .filter(|s| is_cidr(s))
            .map(as_mynetworks_entry)
            .collect();
        let network = ContainerNetwork {
            name: name.to_string(),
            driver: driver.to_string(),
            subnets,
        };
        // A bridge with no subnet at all is not servable and is reported with
        // the rest: there is no address to admit.
        if network.driver == "bridge" && !network.subnets.is_empty() {
            bridges.push(network);
        } else {
            others.push(network);
        }
    }
    (bridges, others)
}

/// Is this a CIDR, in either family, and nothing else?
///
/// Deliberately a shape check rather than a parse: the value goes into a
/// line-oriented configuration file, so what matters is that it cannot be
/// anything but one network — no spaces, no second token, no `!` exclusion
/// Postfix would read as a rule of its own.
fn is_cidr(text: &str) -> bool {
    let Some((addr, prefix)) = text.split_once('/') else {
        return false;
    };
    if prefix.is_empty() || !prefix.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    !addr.is_empty()
        && addr
            .bytes()
            .all(|b| b.is_ascii_hexdigit() || matches!(b, b'.' | b':'))
}

// ---------------------------------------------------------------------------
// where the three files are
// ---------------------------------------------------------------------------

/// The three files the null client is made of.
///
/// Carried as a value rather than read from [`unihelm_config::paths`] at each
/// use, for the reason every other path seam in this codebase exists:
/// `paths::set_root` is a process-wide `OnceLock` that a parallel test cannot
/// claim, so a `configure` hard-wired to `/etc/postfix` could only ever be
/// tested by writing to `/etc/postfix`. With this, the whole pass — render,
/// compare, write, chmod, reload — runs against a temporary directory, which is
/// how the migration's ordering is asserted at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layout {
    /// Postfix's own configuration. The one file the panel writes outside a
    /// directory of its own; see [`unihelm_config::paths::postfix_dir`].
    pub main_cf: PathBuf,
    /// The relay credential, `0600`, in the panel's directory.
    pub sasl_passwd: PathBuf,
    /// The envelope-sender rewriting map.
    pub sender_canonical: PathBuf,
}

impl Layout {
    /// Where these live on a real machine.
    pub fn system() -> Self {
        Self {
            main_cf: paths::postfix_main_cf(),
            sasl_passwd: paths::mail_sasl_passwd(),
            sender_canonical: paths::mail_sender_canonical(),
        }
    }

    /// All three under one directory, for a test that owns that directory.
    pub fn under(dir: &Path) -> Self {
        Self {
            main_cf: dir.join("main.cf"),
            sasl_passwd: dir.join("sasl_passwd"),
            sender_canonical: dir.join("sender_canonical"),
        }
    }

    /// Has the panel written `main.cf`?
    ///
    /// `Drifted` is still ours. A human editing `main.cf` does not stop Postfix
    /// working, and treating an edited file as "never configured" would have
    /// the panel quietly fall back to the msmtp files it is trying to retire.
    pub fn state(&self) -> ConfigState {
        match managed::inspect(&self.main_cf) {
            FileState::Managed { .. } => ConfigState::Ours,
            FileState::Drifted { .. } => ConfigState::Edited,
            FileState::Absent | FileState::Foreign | FileState::Unreadable { .. } => {
                ConfigState::Unwritten
            }
        }
    }

    /// The non-loopback entries of `mynetworks` in the `main.cf` on disk.
    ///
    /// Read back out of the file rather than re-rendered from what the panel
    /// would write today, because those are different answers and only one of
    /// them is what Postfix is enforcing. A status built from the second would
    /// tell an operator that containers can send on a machine where a network
    /// was created after the last install — which is the exact failure this
    /// whole widening had to be careful of.
    ///
    /// Empty for a file the panel never wrote: there is nothing to read, and
    /// [`ConfigState::Unwritten`] is already how that is reported.
    pub fn configured_networks(&self) -> Vec<String> {
        let Ok(text) = std::fs::read_to_string(&self.main_cf) else {
            return Vec::new();
        };
        parse_mynetworks(&text)
    }
}

/// The non-loopback entries of a `main.cf`'s `mynetworks`.
///
/// The **last** assignment wins, because that is what Postfix does: `main.cf`
/// is read top to bottom and a later line replaces an earlier one, so a file a
/// human appended to has a different value from the one the panel wrote.
pub fn parse_mynetworks(main_cf: &str) -> Vec<String> {
    let mut found: Option<Vec<String>> = None;
    for line in main_cf.lines() {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        let Some(value) = line.strip_prefix("mynetworks") else {
            continue;
        };
        let Some(value) = value.trim_start().strip_prefix('=') else {
            // `mynetworks_style` starts the same way and is a different
            // parameter entirely.
            continue;
        };
        found = Some(
            value
                .split([',', ' ', '\t'])
                .map(str::trim)
                .filter(|e| !e.is_empty())
                .map(str::to_string)
                .collect(),
        );
    }
    found
        .unwrap_or_default()
        .into_iter()
        .filter(|e| !LOOPBACK_NETWORKS.contains(&e.as_str()))
        .collect()
}

// ---------------------------------------------------------------------------
// rendering
// ---------------------------------------------------------------------------

/// Everything the three files are rendered from.
///
/// A struct rather than six arguments so the renderers stay pure functions the
/// tests can call: nothing in here is read from the machine, so a test can
/// render the exact configuration a given relay produces without a Postfix, a
/// hostname, or root.
pub struct Settings<'a> {
    /// Already through [`my_hostname`].
    pub hostname: &'a str,
    /// The relay to hand everything to, or `None`/switched off — which renders
    /// a configuration that refuses rather than one that queues.
    pub relay: Option<&'a MailRelay>,
    /// The opened relay password, for the credential map only. Never reaches
    /// `main.cf`.
    pub password: Option<&'a str>,
    /// The distribution's CA bundle, for verifying the relay's certificate.
    pub trust_file: &'a str,
    /// Every domain this server hosts, sorted, for the sender map.
    pub domains: &'a [String],
    /// The Docker bridge subnets to relay for, beyond the loopback, already
    /// through [`relay_subnets`] and in Postfix's spelling.
    ///
    /// Empty is the whole of the no-Docker case and is what keeps the listener
    /// on the loopback: this list is the only thing that widens the MTA, so a
    /// machine with no containers cannot be widened by accident.
    pub container_networks: &'a [String],
    /// Where the three files go, and how `main.cf` has to name the other two.
    pub layout: &'a Layout,
}

impl Settings<'_> {
    /// The relay, if there is one and it is switched on.
    ///
    /// `is_live()` rather than `is_some()`, for the same reason the pool
    /// renderer used to ask it: "there is a row" must never become "mail
    /// works".
    fn live_relay(&self) -> Option<&MailRelay> {
        self.relay.filter(|r| r.is_live())
    }

    /// Is there a username *and* a password to authenticate with?
    fn credential(&self) -> Option<(&str, &str)> {
        let relay = self.live_relay()?;
        Some((relay.username.as_deref()?, self.password?))
    }
}

/// The null client's whole configuration.
///
/// Every parameter here is one Postfix would otherwise take from a compiled-in
/// default or from whatever the package's postinst decided, and each is either
/// what makes this a null client or what stops it being an open relay.
pub fn render_main_cf(settings: &Settings<'_>) -> String {
    let mut out = String::new();

    out.push_str(
        "# The Unihelm null client (spec §11.18).\n\
         #\n\
         # This machine sends mail and receives none. It accepts messages from\n\
         # the programs running on it — PHP's mail() through /usr/sbin/sendmail,\n\
         # anything else through 127.0.0.1:25 — and relays every one of them to\n\
         # the submission service configured in the panel.\n\
         #\n\
         # It replaces a per-site msmtp configuration that had to be readable by\n\
         # each tenant, and therefore put the server's one upstream relay\n\
         # credential in every customer's hands. Postfix reads that credential as\n\
         # root, before it drops privileges, out of a 0600 file no tenant can open.\n\n",
    );

    out.push_str("# --- who this machine says it is -----------------------------------\n");
    out.push_str(&format!("myhostname = {}\n", settings.hostname));
    // Unqualified senders — `www-data`, a tenant's Linux account, `root` — are
    // completed with this. It is `$myhostname` rather than a domain the
    // operator owns because it has to be true: the sender map below is what
    // turns it into an address the relay is authorised for.
    out.push_str("myorigin = $myhostname\n\n");

    out.push_str(
        "# --- this machine delivers no mail locally -------------------------\n\
         # An empty mydestination is what makes this a null client: there is no\n\
         # domain it considers its own, so nothing is ever delivered into a local\n\
         # mailbox. local_transport backs that up for anything addressed to an\n\
         # account here anyway, and alias_maps is empty because with no local\n\
         # delivery there is nothing to alias — naming /etc/aliases would only\n\
         # add a lookup table Postfix warns about when its compiled form is\n\
         # missing.\n",
    );
    out.push_str("mydestination =\n");
    out.push_str("alias_maps =\n");
    out.push_str(
        "local_transport = error:this server delivers no mail locally; \
         it relays through the panel's configured relay\n\n",
    );

    render_who_may_submit(&mut out, settings);
    out.push_str("smtpd_banner = $myhostname ESMTP\n");
    // Debian's package sets this; on a machine whose hostname has no domain
    // part it would otherwise silently append one to unqualified addresses.
    out.push_str("append_dot_mydomain = no\n");
    out.push_str("biff = no\n\n");

    out.push_str("# --- where everything goes -----------------------------------------\n");
    match settings.live_relay() {
        Some(relay) => {
            out.push_str(
                "# Bracketed, so the relay's name is used as given and its MX records\n\
                 # are not looked up: a submission service's MX records point at the\n\
                 # hosts that receive its mail, not the ones that accept ours.\n",
            );
            out.push_str(&format!(
                "relayhost = {}\n",
                relayhost(&relay.host, relay.port)
            ));
            // Everything, unconditionally. A null client has no reason to
            // deliver anything itself, and `default_transport` left alone would
            // have it try direct-to-MX for any address the relayhost did not
            // cover.
            out.push_str("default_transport = smtp\n\n");
            render_relay_security(&mut out, settings, relay);
        }
        None => {
            out.push_str(
                "# There is no relay configured, or it is switched off, so there is\n\
                 # nowhere for a message to go. This is deliberately an error\n\
                 # transport and not an empty relayhost: an empty one would make\n\
                 # Postfix try to deliver straight to each recipient's MX, from a\n\
                 # host with no reverse DNS and no SPF authority, which is how a\n\
                 # server ends up on a blocklist for mail it was never meant to\n\
                 # send. Every message is refused immediately, with this sentence,\n\
                 # rather than queued somewhere nothing drains.\n",
            );
            out.push_str("relayhost =\n");
            out.push_str(
                "default_transport = error:no outbound relay is configured in the Unihelm \
                 panel, so this server cannot send mail\n\n",
            );
        }
    }

    out.push_str(
        "# --- what every message leaves as ----------------------------------\n\
         # SPF is evaluated against the envelope sender, and the relay is\n\
         # authorised for exactly one identity, so a message that keeps the\n\
         # envelope its application chose is a message the relay rejects. The map\n\
         # below is the panel's record of the identities this machine produces;\n\
         # the static: entry after it is the guarantee — a site created since the\n\
         # last render is still rewritten to something the relay will accept\n\
         # rather than bouncing until something re-renders the file.\n\
         #\n\
         # envelope_sender only. The default classes include header_sender, which\n\
         # would rewrite the From: header of every message a customer's site\n\
         # sends — so the recipient still sees who really wrote to them, exactly\n\
         # as they did under msmtp, whose `from` also set the envelope alone.\n",
    );
    match settings.live_relay() {
        Some(relay) => {
            out.push_str(&format!(
                "sender_canonical_maps = {}, static:{}\n",
                paths::postfix_map_ref(&settings.layout.sender_canonical),
                relay.from_address
            ));
            out.push_str("sender_canonical_classes = envelope_sender\n");
        }
        None => {
            out.push_str(
                "# No relay, so no identity to rewrite to. Nothing is being sent\n\
                 # anyway — see the error transport above.\n",
            );
        }
    }

    out
}

/// Who may hand this machine a message, and where it listens for them.
///
/// The half of `main.cf` that is the difference between a null client and an
/// open relay, and the only half that changes when there are containers on the
/// machine. Both shapes are written out in full rather than one being a patch
/// on the other, because what an operator reading `/etc/postfix/main.cf` needs
/// is the configuration this machine is actually running.
fn render_who_may_submit(out: &mut String, settings: &Settings<'_>) {
    out.push_str("# --- who may hand us a message -------------------------------------\n");

    if settings.container_networks.is_empty() {
        out.push_str(
            "# The loopback, and nothing else. Port 25 is never bound on a public\n\
             # address, so there is no way to reach this MTA that does not start\n\
             # from a process on this machine. There is no Docker bridge network\n\
             # here, so there is nothing that needs more than this.\n",
        );
        out.push_str("inet_interfaces = loopback-only\n");
    } else {
        out.push_str(
            "# This machine has Docker bridge networks on it, and a container's\n\
             # 127.0.0.1 is the container — it reaches the host at the bridge\n\
             # gateway (`host.docker.internal`), which a loopback-only listener\n\
             # does not answer on. So the listener is opened and `mynetworks`\n\
             # below is what authorises, rather than the other way round.\n\
             #\n\
             # Naming the gateway addresses here instead would be tighter and is\n\
             # deliberately not done: Postfix binds `inet_interfaces` at start-up\n\
             # and a *fatal* start is what an address it cannot bind produces.\n\
             # Those addresses exist only while dockerd does, nothing orders this\n\
             # unit after docker.service, and a lost race would leave this\n\
             # machine with no mail at all — cron, PHP and host applications\n\
             # included. A network created after this file was written is instead\n\
             # a `Relay access denied`, which is loud and which\n\
             # `mail.mta.status` reports.\n",
        );
        out.push_str("inet_interfaces = all\n");
    }
    out.push_str("inet_protocols = all\n");

    out.push_str(
        "#\n\
         # Whatever is named here can send through the operator's upstream relay\n\
         # credential, so it is an explicit list and never `mynetworks_style =\n\
         # subnet`, which would take in whatever else this host is attached to.\n",
    );
    let mut networks: Vec<&str> = LOOPBACK_NETWORKS.to_vec();
    networks.extend(settings.container_networks.iter().map(String::as_str));
    out.push_str(&format!("mynetworks = {}\n", networks.join(", ")));

    out.push_str(
        "#\n\
         # Written out rather than inherited. Postfix's built-in default for\n\
         # smtpd_relay_restrictions *defers* an unauthorised destination instead\n\
         # of rejecting it — a queue that drains into a bounce days later — and\n\
         # also carries permit_sasl_authenticated, which is a second way in that\n\
         # this machine has no use for. The client restriction is the same rule\n\
         # one step earlier: a client outside mynetworks is refused whatever it\n\
         # asks for, not only when it asks to relay.\n",
    );
    out.push_str("smtpd_relay_restrictions = permit_mynetworks, reject_unauth_destination\n");
    out.push_str("smtpd_client_restrictions = permit_mynetworks, reject\n");
}

/// The TLS and SASL half of `main.cf`, which only exists when a relay does.
fn render_relay_security(out: &mut String, settings: &Settings<'_>, relay: &MailRelay) {
    match relay.tls_mode {
        TlsMode::Implicit => {
            out.push_str(
                "# Implicit TLS: encrypted from the first byte, conventionally 465.\n\
                 # wrappermode is what makes Postfix start the handshake before the\n\
                 # greeting rather than expecting a STARTTLS that never comes.\n",
            );
            out.push_str("smtp_tls_wrappermode = yes\n");
        }
        TlsMode::Starttls => {
            out.push_str(
                "# STARTTLS, and mandatory. `secure` means the handshake must\n\
                 # succeed *and* the certificate must be valid for the name we\n\
                 # dialled — anything less would be a downgrade from msmtp, which\n\
                 # verified both, and an attacker who can strip STARTTLS from the\n\
                 # greeting would otherwise get the whole session in the clear.\n",
            );
        }
        TlsMode::None => {
            out.push_str(
                "# The relay is configured without TLS, which the panel allows only\n\
                 # for a relay that authorises by source IP — a credential over a\n\
                 # plaintext session is refused at configuration time, so there is\n\
                 # none here to protect. `may` still uses TLS when the relay offers\n\
                 # it, because opportunistic encryption is strictly better than\n\
                 # none and cannot fail the delivery.\n",
            );
        }
    }
    out.push_str(&format!(
        "smtp_tls_security_level = {}\n",
        match relay.tls_mode {
            TlsMode::None => "may",
            // Not `encrypt`: that requires a handshake and accepts any
            // certificate, including one an interceptor generated.
            TlsMode::Starttls | TlsMode::Implicit => "secure",
        }
    ));
    out.push_str(&format!("smtp_tls_CAfile = {}\n", settings.trust_file));
    out.push_str("smtp_tls_loglevel = 1\n\n");

    match settings.credential() {
        Some(_) => {
            out.push_str(
                "# The credential, in a map only root can read. `noanonymous` alone,\n\
                 # deliberately: Postfix's default also carries `noplaintext`, which\n\
                 # rules out PLAIN and LOGIN — the only mechanisms these providers\n\
                 # offer — and produces an authentication failure that reads exactly\n\
                 # like a wrong password. The session is already encrypted; that is\n\
                 # what makes PLAIN safe here, and the panel refuses to store a\n\
                 # credential for a relay without TLS at all.\n",
            );
            out.push_str("smtp_sasl_auth_enable = yes\n");
            out.push_str(&format!(
                "smtp_sasl_password_maps = {}\n",
                paths::postfix_map_ref(&settings.layout.sasl_passwd)
            ));
            out.push_str("smtp_sasl_security_options = noanonymous\n");
            out.push_str("smtp_sasl_tls_security_options = noanonymous\n\n");
        }
        None => {
            out.push_str(
                "# No credential is stored, so this relay authorises by source IP.\n\
                 # SASL stays off rather than being enabled against an empty map,\n\
                 # which is an error at every delivery instead of a working one.\n",
            );
            out.push_str("smtp_sasl_auth_enable = no\n\n");
        }
    }
}

/// The credential map, or `None` when there is no credential to write.
///
/// `None` means the file is removed rather than written empty: an empty map
/// with `smtp_sasl_auth_enable = yes` fails every delivery, and a stale one
/// from a credential that has since been cleared is a password left on disk for
/// no reason.
///
/// The key has to be spelled exactly as `relayhost` is, brackets and all —
/// Postfix looks the map up by the next-hop destination it printed itself, so
/// `smtp.example.com:587` and `[smtp.example.com]:587` are different keys and
/// the wrong one silently authenticates nothing.
pub fn render_sasl_passwd(settings: &Settings<'_>) -> Option<String> {
    let relay = settings.live_relay()?;
    let (username, password) = settings.credential()?;
    Some(format!(
        "# The upstream relay credential (spec §11.18).\n\
         #\n\
         # One file for the whole server, mode 0600, root-owned. The design this\n\
         # replaced wrote one of these per site, readable by that site's tenant,\n\
         # every copy holding this same secret. Postfix opens it as root in\n\
         # smtp(8)'s pre-jail initialisation and never needs it again.\n\
         #\n\
         # The key must match `relayhost` in main.cf byte for byte, brackets\n\
         # included: Postfix looks this table up by the next hop it resolved.\n\
         {}\t{username}:{password}\n",
        relayhost(&relay.host, relay.port)
    ))
}

/// The sender-rewriting map: every identity this machine can produce.
///
/// `@domain` entries rather than one per account, because that is the form
/// canonical(5) offers that covers a whole domain — `uh_abc@this.host`,
/// `www-data@this.host` and `root@this.host` are one entry between them. The
/// hosted domains are here for the applications that set their own envelope
/// sender (PHPMailer passes `-f` when a Sender is configured, which is most
/// WordPress installations).
pub fn render_sender_canonical(settings: &Settings<'_>) -> Option<String> {
    let relay = settings.live_relay()?;
    let to = &relay.from_address;

    let mut out = String::from(
        "# Which envelope sender mail leaves this server as (spec §11.18).\n\
         #\n\
         # The relay is authorised for one identity, and SPF is evaluated against\n\
         # the envelope, so anything else is a rejection. The From: header is not\n\
         # touched — see sender_canonical_classes in main.cf — so a recipient\n\
         # still sees which site actually wrote to them.\n\
         #\n\
         # This file is the readable record; main.cf pairs it with a static: map\n\
         # so a domain added since the last render is still rewritten rather than\n\
         # bounced.\n",
    );

    // The unqualified-sender case first: `myorigin` completes a bare account
    // name with the machine's own name, so this one entry covers PHP-FPM's
    // pool user, every tenant account, cron and root.
    out.push_str(&format!("@{}\t{to}\n", settings.hostname));
    // Postfix's own fallbacks for a machine that cannot resolve its name.
    out.push_str(&format!("@localhost\t{to}\n"));
    out.push_str(&format!("@localhost.localdomain\t{to}\n"));

    let mut domains: Vec<&String> = settings.domains.iter().collect();
    domains.sort();
    domains.dedup();
    for domain in domains {
        // Rendered from `Site::domain`, which is a validated `Domain` by the
        // time a site exists — letters, digits, dots and hyphens, so nothing in
        // it can start a second entry in this line-oriented file.
        if domain == settings.hostname {
            continue;
        }
        out.push_str(&format!("@{domain}\t{to}\n"));
    }

    Some(out)
}

// ---------------------------------------------------------------------------
// writing
// ---------------------------------------------------------------------------

/// What happened to one file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum FileOutcome {
    /// Byte-identical to what was already there. No write, and nothing to
    /// reload for.
    Unchanged,
    /// Written, over a file the panel had written before or over nothing.
    Written,
    /// Written over a file the panel did not write, which was kept alongside.
    Adopted,
    /// Removed, because there is nothing for it to hold any more.
    Removed,
    /// Nothing was there and nothing needed to be.
    Absent,
}

impl FileOutcome {
    /// Did the file on disk actually change?
    pub const fn changed(self) -> bool {
        matches!(
            self,
            FileOutcome::Written | FileOutcome::Adopted | FileOutcome::Removed
        )
    }
}

/// Write one managed file, refusing to throw away work that is not ours.
///
/// The rules are spec §10.4's, with one addition this module needs and the
/// config engine's `apply` has no way to express: `main.cf` **always** exists
/// before we first write it, because the package's postinst generates one. A
/// foreign file is therefore the normal first-install state and cannot simply
/// be a refusal — but it can also be a real Postfix somebody is running, which
/// must not be silently replaced. So adoption is a decision the caller makes
/// (`mail.mta.install` takes it from the operator, and defaults to no), and the
/// file we displace is kept beside it rather than deleted.
pub fn put(file: &ManagedFile, body: &str, adopt: bool) -> Result<FileOutcome> {
    let path = file.path.clone();
    let contents = managed::with_header(body, file.comment_style);

    let outcome = match file.state() {
        FileState::Absent => {
            managed::write_atomic(&path, &contents, file.mode)?;
            FileOutcome::Written
        }
        FileState::Managed { .. } => {
            // Byte-compare the body, not the whole file: the header carries the
            // hash of the body, so identical bodies produce identical files and
            // a rewrite would be a reload nobody needed.
            if managed::read_body(&path)?.as_deref() == Some(body) {
                FileOutcome::Unchanged
            } else {
                managed::write_atomic(&path, &contents, file.mode)?;
                FileOutcome::Written
            }
        }
        FileState::Drifted { .. } | FileState::Foreign if !adopt => {
            return Err(UnihelmError::new(
                ErrorCode::ConfigDrift,
                format!(
                    "{} was not written by the panel, or was edited after it was. Nothing \
                     has been changed. Review it, then re-run this operation with `adopt` \
                     to take it over — the file will be kept as {}{REPLACED_SUFFIX}.",
                    path.display(),
                    path.display()
                ),
            ));
        }
        FileState::Drifted { .. } | FileState::Foreign => {
            keep_a_copy(&path)?;
            managed::write_atomic(&path, &contents, file.mode)?;
            FileOutcome::Adopted
        }
        FileState::Unreadable { reason } => {
            return Err(UnihelmError::internal(format!(
                "{} could not be read ({reason}), so it is not safe to write over",
                path.display()
            )));
        }
    };

    // On every pass, including the ones that wrote nothing: a file an older
    // panel created with a wider mode is only ever narrowed by a step that runs
    // on a file which already exists and is already correct in content.
    file.enforce_mode()?;
    Ok(outcome)
}

/// Remove a managed file, and say whether it was there.
///
/// Refuses to remove a file the panel did not write, for the same reason [`put`]
/// refuses to overwrite one.
pub fn remove(file: &ManagedFile) -> Result<FileOutcome> {
    match file.state() {
        FileState::Absent => Ok(FileOutcome::Absent),
        FileState::Managed { .. } | FileState::Drifted { .. } => {
            match std::fs::remove_file(&file.path) {
                Ok(()) => Ok(FileOutcome::Removed),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(FileOutcome::Absent),
                Err(e) => Err(UnihelmError::internal(format!(
                    "could not remove {}: {e}",
                    file.path.display()
                ))),
            }
        }
        FileState::Foreign | FileState::Unreadable { .. } => Ok(FileOutcome::Absent),
    }
}

/// Move a file we are about to replace out of the way, once.
///
/// Never overwrites an existing copy: the first one is the machine's original
/// configuration, and a second adoption would replace it with the panel's own
/// rendering — destroying the only thing anybody would want to look at.
fn keep_a_copy(path: &Path) -> Result<()> {
    let mut kept = path.as_os_str().to_os_string();
    kept.push(REPLACED_SUFFIX);
    let kept = PathBuf::from(kept);
    if kept.exists() {
        return Ok(());
    }
    std::fs::copy(path, &kept).map_err(|e| {
        UnihelmError::internal(format!(
            "could not keep a copy of {} before replacing it: {e}",
            path.display()
        ))
    })?;
    Ok(())
}

// ---------------------------------------------------------------------------
// the machine
// ---------------------------------------------------------------------------

/// Whether the configuration on disk is the panel's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConfigState {
    /// The panel has never written `main.cf`. Whatever Postfix does with a
    /// message here is whatever the package decided.
    Unwritten,
    /// The panel's, untouched.
    Ours,
    /// The panel's, edited since. Still Postfix's configuration and still
    /// working — but not the one the panel would render, and the panel will not
    /// overwrite it (spec §10.4 rule 2).
    Edited,
}

impl ConfigState {
    /// Did the panel write this, in either state?
    pub const fn is_ours(self) -> bool {
        matches!(self, ConfigState::Ours | ConfigState::Edited)
    }
}

/// The five things this module asks of the machine it runs on.
///
/// A trait for the same reason [`super::PoolWriter`] is one: the decisions —
/// what gets rendered, in what order, and what is reported — are the half worth
/// testing, and none of it is testable if exercising it installs an MTA on the
/// machine running the test.
#[async_trait]
pub trait MtaHost: Send + Sync {
    /// This machine's name, for `myhostname`.
    ///
    /// Whether the panel has *configured* the MTA is deliberately not asked
    /// here: that is a property of the files, which [`Layout::state`] reads
    /// directly, and a host that could answer it separately would be a second
    /// source of truth for the one question the migration turns on.
    fn hostname(&self) -> Result<String>;

    /// Is the MTA package installed?
    async fn installed(&self, ctx: &OpContext) -> Result<bool>;

    /// Install it, with its SASL mechanism plugin, in one transaction.
    async fn install(&self, ctx: &OpContext, hostname: &str) -> Result<()>;

    /// Enable it at boot and put the current configuration live.
    async fn activate(&self, ctx: &OpContext) -> Result<()>;

    /// Is it running now?
    async fn running(&self, ctx: &OpContext) -> Result<bool>;

    /// How many messages are waiting. `None` when that cannot be established,
    /// which is a different answer from zero and is reported as one.
    async fn queued(&self) -> Option<u64>;

    /// Which Docker networks a containerised application could reach us from.
    ///
    /// On the trait rather than read inline for the reason the other five are:
    /// this is the input that decides whether the MTA is opened past the
    /// loopback, and a test that could not set it could not exercise either
    /// half of the decision — including the one that matters most, a machine
    /// with no Docker on it.
    async fn container_networks(&self) -> ContainerNetworks;
}

/// The real machine.
pub struct LiveHost;

#[async_trait]
impl MtaHost for LiveHost {
    fn hostname(&self) -> Result<String> {
        let raw = unihelm_distro::os::hostname().map_err(|e| {
            UnihelmError::new(
                ErrorCode::ServiceUnavailable,
                format!(
                    "this server's hostname could not be read ({e}), and Postfix needs it to \
                     introduce itself to the relay"
                ),
            )
        })?;
        my_hostname(&raw)
    }

    async fn installed(&self, ctx: &OpContext) -> Result<bool> {
        let packages = pkg::postfix_packages(&ctx.distro().info).parsed()?;
        for package in &packages {
            if !ctx.distro().pkg.is_installed(package).await? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    async fn install(&self, ctx: &OpContext, hostname: &str) -> Result<()> {
        let distro = ctx.distro();
        // Before the install, not after: the answers decide what the package's
        // own postinst writes, and an `Internet Site` postfix binds port 25 on
        // every address of the machine from the moment apt finishes until the
        // panel's own main.cf lands.
        pkg::preseed_postfix(distro.info.family, hostname, ctx.log_sink()).await?;

        let packages = pkg::postfix_packages(&distro.info);
        ctx.log(format!(
            "installing {} from {}",
            packages.names().join(" and "),
            packages.repository
        ));
        distro
            .pkg
            .install(&packages.parsed()?, ctx.log_sink())
            .await?;
        Ok(())
    }

    async fn activate(&self, ctx: &OpContext) -> Result<()> {
        let distro = ctx.distro();
        let unit = ManagedUnit::Postfix.unit_name(distro.info.family);

        // Enabled *and* started: a mail system that does not survive a reboot
        // is a mail system that silently stops one Tuesday morning.
        distro.svc.enable(&unit, true).await?;

        // Then reload, because `enable(start_now)` is a no-op on a unit that
        // was already running and would leave Postfix on the configuration it
        // started with. A `texthash:` map is cached when it is opened, so
        // without this a rotated credential is stored, reported saved, and
        // never used.
        let status = distro.svc.status(&unit).await?;
        if status.is_active() {
            distro.svc.action(&unit, SvcAction::Reload).await?;
        }
        Ok(())
    }

    async fn running(&self, ctx: &OpContext) -> Result<bool> {
        let unit = ManagedUnit::Postfix.unit_name(ctx.distro().info.family);
        Ok(ctx.distro().svc.status(&unit).await?.is_active())
    }

    async fn queued(&self) -> Option<u64> {
        let out = unihelm_distro::exec::Cmd::new("postqueue")
            .arg("-p")
            .run()
            .await
            .ok()?;
        if !out.success() {
            return None;
        }
        parse_queue(&out.stdout)
    }

    async fn container_networks(&self) -> ContainerNetworks {
        let Ok(docker) = unihelm_distro::exec::resolve_program(DOCKER) else {
            return ContainerNetworks::default();
        };
        let docker = docker.to_string_lossy().into_owned();

        let Some(ids) = docker_output(&docker, &network_ls_argv()).await else {
            // Installed, but the daemon did not answer. The networks are still
            // there; only our view of them is missing, which is why this is a
            // different answer from "no Docker" and not a shorter one.
            return ContainerNetworks {
                docker_installed: true,
                ..ContainerNetworks::default()
            };
        };

        let ids: Vec<&str> = ids
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .collect();
        if ids.is_empty() {
            // A daemon with no networks at all. `network inspect` with no
            // arguments is an error rather than an empty answer, so this cannot
            // be left to fall through.
            return ContainerNetworks {
                docker_installed: true,
                daemon_answered: true,
                ..ContainerNetworks::default()
            };
        }

        let mut argv = vec!["network", "inspect", "--format", NETWORK_FORMAT];
        argv.extend(ids);
        let Some(text) = docker_output(&docker, &argv).await else {
            return ContainerNetworks {
                docker_installed: true,
                ..ContainerNetworks::default()
            };
        };
        let (bridges, others) = parse_networks(&text);
        ContainerNetworks {
            docker_installed: true,
            daemon_answered: true,
            bridges,
            others,
        }
    }
}

/// Docker's own client, not the daemon socket — the same choice, for the same
/// reason, as [`crate::docker`] and [`crate::appcontainer`].
const DOCKER: &str = "docker";

/// How long the panel waits for Docker before deciding it did not answer.
///
/// Bounded because this runs inside `mail.mta.status`, which is an immediate
/// operation behind a page: a daemon that is wedged rather than stopped would
/// otherwise hang the mail page instead of being reported as unavailable.
const DOCKER_BUDGET: std::time::Duration = std::time::Duration::from_secs(10);

/// One Docker read, or `None` for every way it can fail to answer.
///
/// Failure is not distinguished here because the caller does not act on the
/// difference: a missing socket, a permission error and a timeout all mean the
/// panel does not know what networks exist, and the one thing it must not do in
/// any of them is assume there are none.
async fn docker_output(docker: &str, args: &[&str]) -> Option<String> {
    let out = unihelm_distro::exec::Cmd::new(docker)
        .args(args)
        .timeout(DOCKER_BUDGET)
        .run()
        .await
        .ok()?;
    out.success().then(|| out.trimmed_stdout().to_string())
}

/// How many messages `postqueue -p` is reporting.
///
/// Parsed rather than counted from the spool directory: the queue is several
/// directories deep, only root can list some of them, and Postfix already
/// prints the number. `None` for output this does not recognise, because a
/// wrong number here would be reported to an operator as fact.
pub fn parse_queue(output: &str) -> Option<u64> {
    let text = output.trim();
    if text.is_empty() || text.contains("Mail queue is empty") {
        return Some(0);
    }
    // The summary line is last: `-- 5 Kbytes in 2 Requests.`
    let tokens: Vec<&str> = text.split_whitespace().collect();
    let at = tokens.iter().rposition(|t| t.starts_with("Request"))?;
    tokens.get(at.checked_sub(1)?)?.parse().ok()
}

// ---------------------------------------------------------------------------
// state
// ---------------------------------------------------------------------------

/// What the mail path on this machine actually is, in the panel's words.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct MtaState {
    /// What the server hands a message to. `postfix`.
    pub agent: &'static str,
    /// Is the package there?
    pub installed: bool,
    /// Has the panel written the null client configuration?
    pub configured: bool,
    /// Ours, but edited since. The configuration on disk is not the one the
    /// panel would render, and the panel will not overwrite it.
    pub drifted: bool,
    /// Is the unit running?
    pub running: bool,
    /// Is there a relay for it to hand messages to, switched on?
    pub relay_live: bool,
    /// Messages waiting in the queue, when that could be established.
    pub queued: Option<u64>,
    /// Per-site msmtp credential files still on disk from the design this
    /// replaced. Anything above zero is a copy of the relay password a tenant
    /// can still read.
    pub legacy_files: usize,
    /// Where anything that is not PHP hands a message over.
    pub submission: String,
    /// Whether a *containerised* application can, and what is stopping it when
    /// it cannot.
    pub containers: ContainerMail,
    /// The whole of the above in one sentence, because that is what gets read.
    pub summary: String,
}

/// What a containerised application can do with mail on this machine, as fact.
///
/// Every field here is read from the machine as it is now — the `mynetworks`
/// in the `main.cf` on disk, the networks Docker has this second, the firewall
/// the backend reports — and not from what the panel would render. The two
/// disagree exactly when something has changed since the last install, which is
/// the case this whole structure exists to make visible.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct ContainerMail {
    /// Is there a `docker` on this machine at all?
    pub docker_installed: bool,
    /// Did its daemon answer? `false` with `docker_installed` means the panel
    /// could not check, not that there is nothing to check.
    pub daemon_answered: bool,
    /// Where a container hands a message over, when one can. `None` when none
    /// can, so that nothing downstream can print an address that does not work.
    pub submission: Option<String>,
    /// The non-loopback networks the `main.cf` on disk relays for.
    pub relayed_for: Vec<String>,
    /// Bridge networks Docker has now whose subnets that file does not name.
    /// A container on one of these is refused with `Relay access denied`.
    pub uncovered: Vec<ContainerNetwork>,
    /// Networks on a driver whose containers do not reach this host through a
    /// bridge gateway. Nothing here makes those able to send.
    pub unsupported: Vec<ContainerNetwork>,
    /// What the firewall is doing about port 25.
    pub firewall: crate::fwops::MtaPortExposure,
}

/// Is `sendmail` on this machine at all?
pub fn sendmail_installed() -> bool {
    unihelm_distro::exec::program_available(SENDMAIL_BINARY)
}

/// Read the whole state of the local MTA.
pub async fn state(
    ctx: &OpContext,
    host: &dyn MtaHost,
    layout: &Layout,
    relay: Option<&MailRelay>,
    legacy_files: usize,
) -> MtaState {
    let installed = host.installed(ctx).await.unwrap_or(false);
    let configuration = layout.state();
    let configured = configuration.is_ours();
    let drifted = configuration == ConfigState::Edited;
    let running = host.running(ctx).await.unwrap_or(false);
    let relay_live = relay.is_some_and(|r| r.is_live());
    // Only worth asking when there is something that could have queued.
    let queued = if installed { host.queued().await } else { None };

    let containers = container_mail(
        &host.container_networks().await,
        &layout.configured_networks(),
        crate::fwops::mta_port_exposure(ctx).await,
    );

    let mut summary = describe(
        installed,
        configured,
        running,
        relay_live,
        queued,
        legacy_files,
    );
    // Appended rather than folded in, because it is a different question with a
    // different answer: the machine can be sending perfectly for everything on
    // its loopback while every container on it is refused.
    if configured && let Some(sentence) = describe_containers(&containers) {
        summary.push(' ');
        summary.push_str(&sentence);
    }

    MtaState {
        agent: AGENT,
        installed,
        configured,
        drifted,
        running,
        relay_live,
        queued,
        legacy_files,
        submission: format!("{SUBMISSION_HOST}:{SUBMISSION_PORT}"),
        containers,
        summary,
    }
}

/// Compare what Docker has against what `main.cf` relays for.
///
/// Pure, and takes all three readings as arguments, so every combination that
/// matters — a network created since the last install, a driver that cannot be
/// served, a firewall that is not running — is a test rather than a machine
/// somebody has to build.
pub fn container_mail(
    found: &ContainerNetworks,
    on_disk: &[String],
    firewall: crate::fwops::MtaPortExposure,
) -> ContainerMail {
    let relayed_for: Vec<String> = on_disk.to_vec();
    let uncovered: Vec<ContainerNetwork> = found
        .bridges
        .iter()
        .filter(|n| !n.subnets.iter().all(|s| relayed_for.contains(s)))
        .cloned()
        .collect();
    // An address only when there is a network the file relays for *and* the
    // firewall is not standing in front of it. Anything less would be the panel
    // printing a host and port that does not work.
    let submission = (!relayed_for.is_empty() && firewall.admits(&relayed_for))
        .then(|| format!("{CONTAINER_SUBMISSION_HOST}:{SUBMISSION_PORT}"));
    ContainerMail {
        docker_installed: found.docker_installed,
        daemon_answered: found.daemon_answered,
        submission,
        relayed_for,
        uncovered,
        unsupported: found.others.clone(),
        firewall,
    }
}

/// The container half of the summary, or `None` when there is nothing to say.
///
/// `None` is the machine with no Docker on it: it has no containers, nothing
/// about it changed, and a sentence explaining that containers are fine would
/// be a sentence about something that does not exist here.
pub fn describe_containers(mail: &ContainerMail) -> Option<String> {
    if !mail.docker_installed {
        return None;
    }
    if !mail.daemon_answered {
        return Some(format!(
            "Docker is installed but its daemon did not answer, so the panel could not check \
             which networks exist; the {} network(s) already in `mynetworks` were kept rather \
             than removed.",
            mail.relayed_for.len()
        ));
    }

    let mut sentence = match (&mail.submission, mail.relayed_for.is_empty()) {
        (Some(address), _) => format!(
            "A containerised application sends by talking to {address} — no credential, no \
             authentication — and this MTA relays for {} Docker network(s).",
            mail.relayed_for.len()
        ),
        (None, true) => "No Docker network is in `mynetworks`, so a containerised application \
             cannot send mail at all: its 127.0.0.1 is the container, and this MTA does not \
             relay for the bridge it would reach the host on. Run `mail.mta.install`."
            .to_string(),
        (None, false) => format!(
            "This MTA relays for {} Docker network(s), but the firewall does not admit \
             {}/tcp from them, so a containerised application's connection never arrives. \
             Run `mail.mta.install` again — it opens that port from those subnets and from \
             nowhere else.",
            mail.relayed_for.len(),
            crate::fwops::MTA_PORT,
        ),
    };

    if !mail.uncovered.is_empty() {
        sentence.push_str(&format!(
            " {} Docker network(s) exist that `mynetworks` does not name ({}); containers on \
             them are refused with `Relay access denied`. Run `mail.mta.install` again to add \
             them.",
            mail.uncovered.len(),
            names(&mail.uncovered),
        ));
    }
    if !mail.unsupported.is_empty() {
        sentence.push_str(&format!(
            " {} Docker network(s) are on a driver whose containers do not reach this host \
             through a bridge gateway ({}); nothing the panel can configure makes those able \
             to send.",
            mail.unsupported.len(),
            names(&mail.unsupported),
        ));
    }
    if !mail.relayed_for.is_empty() && mail.firewall.active != Some(true) {
        sentence.push_str(&format!(
            " Serving containers means {}/tcp is bound on every interface of this machine, and \
             no firewall is running to close it, so it answers from the internet. It is not a \
             relay — anything outside `mynetworks` is refused — but it is a service this \
             machine did not have before. `fw.enable` closes it; the panel never opens it to \
             the world.",
            crate::fwops::MTA_PORT,
        ));
    }
    Some(sentence)
}

/// The names of some networks, for a sentence an operator has to act on.
fn names(networks: &[ContainerNetwork]) -> String {
    networks
        .iter()
        .map(|n| n.name.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

/// The sentence.
///
/// Every branch of this says what *is* true, never what should be: an operator
/// reading "mail is configured" and finding nothing arrives is the failure this
/// whole change exists to remove, and a summary that rounds a half-configured
/// machine up to "configured" would put it straight back.
pub fn describe(
    installed: bool,
    configured: bool,
    running: bool,
    relay_live: bool,
    queued: Option<u64>,
    legacy_files: usize,
) -> String {
    let mut sentence = match (installed, configured, running, relay_live) {
        (false, _, _, false) => "No local mail transfer agent is installed and no relay is \
             configured, so nothing on this server can send mail. Configure a relay with \
             `mail.relay.set`, then run `mail.mta.install`."
            .to_string(),
        (false, _, _, true) => "A relay is configured but this server has no local mail \
             transfer agent, so only PHP sites still wired to the per-site msmtp files can \
             send anything. Run `mail.mta.install`."
            .to_string(),
        (true, false, _, _) => "Postfix is installed but the panel has not written its \
             configuration, so what this server does with a message is whatever the package \
             decided. Run `mail.mta.install`."
            .to_string(),
        (true, true, false, _) => "The null client is configured but Postfix is not running, \
             so messages handed to it are sitting in the queue and nothing is draining them. \
             Start it with `svc.action`, or run `mail.mta.install` again."
            .to_string(),
        (true, true, true, false) => "Postfix is running and configured, and there is no relay \
             for it to hand anything to. Every message is refused as it is submitted, with a \
             reason naming the panel — nothing is queued and nothing will leave this machine \
             until a relay is configured."
            .to_string(),
        // "anything on this server" is what this used to say, and it was the
        // one sentence in the file that was not true: a container is on this
        // server and was refused. The loopback clients are named, and the
        // containers get a sentence of their own from `describe_containers`.
        (true, true, true, true) => "Postfix accepts mail from anything on this server's \
             loopback — PHP's mail() through /usr/sbin/sendmail, everything else on \
             127.0.0.1:25 — and relays it upstream. The relay credential is held by root and \
             no tenant can read it."
            .to_string(),
    };

    if let Some(waiting) = queued.filter(|n| *n > 0) {
        sentence.push_str(&format!(
            " {waiting} message(s) are waiting in the queue; `postqueue -p` on the server says \
             why each one has not gone."
        ));
    }
    if legacy_files > 0 {
        sentence.push_str(&format!(
            " {legacy_files} per-site msmtp credential file(s) are still on disk from the \
             design this replaced, and each one holds the relay password in a place its \
             tenant can read. Run `mail.mta.install` to retire them."
        ));
    }
    sentence
}

// ---------------------------------------------------------------------------
// configure
// ---------------------------------------------------------------------------

/// What one configure pass did.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ConfigureReport {
    pub main_cf: FileOutcome,
    pub sasl_passwd: FileOutcome,
    pub sender_canonical: FileOutcome,
    /// Whether anything on disk changed — and therefore whether Postfix was
    /// reloaded. A second run of the same configuration reports `false` here,
    /// which is what idempotence looks like from outside.
    pub changed: bool,
    pub reloaded: bool,
}

/// Render the three files, and reload Postfix if any of them moved.
///
/// Idempotent by construction: every write is a byte-comparison first, and the
/// reload is conditional on at least one of them having actually changed. The
/// reload is *not* optional when a map changed — Postfix caches a `texthash:`
/// table when it opens it and never notices the file underneath changing, so a
/// rotated credential that is written and not reloaded is a credential the
/// running daemons will never use.
pub async fn configure(
    ctx: &OpContext,
    host: &dyn MtaHost,
    settings: &Settings<'_>,
    adopt: bool,
) -> Result<ConfigureReport> {
    // The maps first, then main.cf. Order matters on a first install: main.cf
    // names both maps, and Postfix logs an error for a table it cannot open —
    // writing the configuration last means there is never a moment where it
    // points at a file that does not exist yet.
    let sasl_file = ManagedFile::postfix_map(&settings.layout.sasl_passwd);
    let sasl_passwd = match render_sasl_passwd(settings) {
        Some(body) => put(&sasl_file, &body, adopt)?,
        // No credential stored, or no live relay: the file goes, rather than
        // being left holding a password nothing uses any more.
        None => remove(&sasl_file)?,
    };

    let sender_file = ManagedFile::postfix_map(&settings.layout.sender_canonical);
    let sender_canonical = match render_sender_canonical(settings) {
        Some(body) => put(&sender_file, &body, adopt)?,
        None => remove(&sender_file)?,
    };

    // Any compiled copy an operator's own `postmap` run left beside either map
    // holds the same secret with a mode of its own. The panel never makes one;
    // this is for the ones that are there anyway.
    for map in [&sasl_file.path, &sender_file.path] {
        for (companion, previous) in managed::enforce_map_companion_modes(map, POSTFIX_MAP_MODE)? {
            ctx.log(format!(
                "tightened {} from {previous:04o} to {POSTFIX_MAP_MODE:04o}: a `postmap` run \
                 left a compiled copy of the map beside it, holding the same relay password",
                companion.display()
            ));
        }
    }

    let main_file = ManagedFile::postfix_main_cf(&settings.layout.main_cf);
    let main_cf = put(&main_file, &render_main_cf(settings), adopt)?;
    if main_cf == FileOutcome::Adopted {
        ctx.log(format!(
            "{} was not written by the panel; the previous file was kept as {}{REPLACED_SUFFIX}",
            main_file.path.display(),
            main_file.path.display()
        ));
    }

    let changed = main_cf.changed() || sasl_passwd.changed() || sender_canonical.changed();
    let mut reloaded = false;
    if changed {
        host.activate(ctx).await?;
        reloaded = true;
        ctx.log("Postfix reloaded onto the panel's configuration");
    } else {
        ctx.log("the local MTA's configuration was already what it should be; nothing changed");
    }

    Ok(ConfigureReport {
        main_cf,
        sasl_passwd,
        sender_canonical,
        changed,
        reloaded,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use unihelm_db::MailRelay;

    fn relay() -> MailRelay {
        MailRelay {
            host: "smtp.postmarkapp.com".into(),
            port: 587,
            tls_mode: TlsMode::Starttls,
            username: Some("token-user".into()),
            password_sealed: None,
            from_address: "noreply@acme.example".into(),
            from_name: Some("Acme".into()),
            enabled: true,
            updated_at: time::OffsetDateTime::UNIX_EPOCH,
        }
    }

    /// The layout every render test uses. Absolute paths, because they are
    /// written into `main.cf` as map references and a relative one would be
    /// resolved against Postfix's queue directory rather than anything here.
    fn layout() -> Layout {
        Layout {
            main_cf: PathBuf::from("/etc/postfix/main.cf"),
            sasl_passwd: PathBuf::from("/etc/unihelm/mail/sasl_passwd"),
            sender_canonical: PathBuf::from("/etc/unihelm/mail/sender_canonical"),
        }
    }

    /// Only the lines Postfix actually reads.
    ///
    /// The rendered file explains itself at length, and several of those
    /// explanations name the very parameters a test is asserting are *absent*
    /// — `noplaintext`, `header_sender`. Asserting against the whole file
    /// would make the comments load-bearing in the wrong direction.
    fn directives(rendered: &str) -> Vec<&str> {
        rendered
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect()
    }

    fn settings<'a>(
        relay: Option<&'a MailRelay>,
        domains: &'a [String],
        layout: &'a Layout,
    ) -> Settings<'a> {
        Settings {
            hostname: "web-01.acme.example",
            relay,
            password: Some("token-secret"),
            trust_file: "/etc/ssl/certs/ca-certificates.crt",
            domains,
            // No Docker: the loopback-only shape, which every existing case in
            // this module was written against and must keep rendering.
            container_networks: &[],
            layout,
        }
    }

    #[test]
    fn a_bare_hostname_is_qualified_rather_than_refused() {
        // Postfix will not start with a myhostname that has no domain part, and
        // a machine called `web-01` is an ordinary machine, not a broken one.
        assert_eq!(my_hostname("web-01").unwrap(), "web-01.localdomain");
        assert_eq!(
            my_hostname("Web-01.Acme.Example.").unwrap(),
            "web-01.acme.example"
        );
    }

    #[test]
    fn a_hostname_that_could_add_a_line_to_a_config_file_is_refused() {
        // It reaches main.cf and `debconf-set-selections`, both line-oriented.
        for hostile in [
            "web-01\nmynetworks = 0.0.0.0/0",
            "web 01",
            "",
            "-web-01",
            "web..01",
        ] {
            assert!(my_hostname(hostile).is_err(), "{hostile:?} was accepted");
        }
    }

    #[test]
    fn the_relayhost_suppresses_the_mx_lookup() {
        // Without the brackets Postfix delivers to the relay's MX records,
        // which are the hosts that receive its mail rather than the ones that
        // accept ours.
        assert_eq!(relayhost("smtp.example.com", 587), "[smtp.example.com]:587");
    }

    #[test]
    fn the_null_client_listens_on_the_loopback_and_delivers_nothing_locally() {
        let out = render_main_cf(&settings(Some(&relay()), &[], &layout()));
        assert!(out.contains("inet_interfaces = loopback-only"), "{out}");
        // An explicit list, never `mynetworks_style`. `host` was what this
        // rendered before containers were served, and the styles are a family:
        // whoever widened it one step to `subnet` would have taken in whatever
        // else the host is attached to, which is the thing `mynetworks` exists
        // to keep out. Spelling the networks out has no adjacent wrong value.
        assert!(out.contains("mynetworks = 127.0.0.0/8, [::1]/128"), "{out}");
        // On a directive line, not in the prose — the comment above it names
        // `mynetworks_style = subnet` in order to say why it is not used, and
        // an assertion that cannot tell those apart would forbid explaining it.
        assert!(
            !out.lines()
                .any(|l| l.trim_start().starts_with("mynetworks_style")),
            "{out}"
        );
        // The empty mydestination is what makes it a null client. Rendered as a
        // bare `mydestination =`, which is a value, not an absent line.
        assert!(out.lines().any(|l| l.trim() == "mydestination ="), "{out}");
        assert!(out.contains("local_transport = error:"), "{out}");
    }

    #[test]
    fn the_credential_is_never_written_into_main_cf() {
        // The whole point of the change: main.cf is 0644 because every Postfix
        // daemon re-reads it after dropping privileges, so a password in it
        // would be readable by the `postfix` user and by anyone who can read
        // /etc/postfix.
        let out = render_main_cf(&settings(Some(&relay()), &[], &layout()));
        assert!(!out.contains("token-secret"), "{out}");
        assert!(out.contains("smtp_sasl_password_maps = texthash:"), "{out}");
    }

    #[test]
    fn an_authenticated_relay_gets_plain_enabled_and_a_verified_certificate() {
        let out = render_main_cf(&settings(Some(&relay()), &[], &layout()));
        // `noanonymous` alone: Postfix's default also carries `noplaintext`,
        // which rules out the only mechanisms these providers offer and reads
        // like a rejected password.
        assert!(
            out.contains("smtp_sasl_security_options = noanonymous"),
            "{out}"
        );
        assert!(
            !directives(&out).iter().any(|l| l.contains("noplaintext")),
            "{out}"
        );
        // `secure`, not `encrypt`: msmtp verified the certificate and the name,
        // and anything less here is a silent downgrade from the design this
        // replaces.
        assert!(out.contains("smtp_tls_security_level = secure"), "{out}");
        assert!(!out.contains("smtp_tls_wrappermode"), "{out}");
    }

    #[test]
    fn an_implicit_tls_relay_starts_the_handshake_before_the_greeting() {
        let mut implicit = relay();
        implicit.tls_mode = TlsMode::Implicit;
        implicit.port = 465;
        let out = render_main_cf(&settings(Some(&implicit), &[], &layout()));
        assert!(out.contains("smtp_tls_wrappermode = yes"), "{out}");
        assert!(
            out.contains("relayhost = [smtp.postmarkapp.com]:465"),
            "{out}"
        );
    }

    #[test]
    fn a_relay_without_a_credential_does_not_enable_sasl_against_an_empty_map() {
        let mut anonymous = relay();
        anonymous.username = None;
        anonymous.tls_mode = TlsMode::None;
        let layout = layout();
        let settings = Settings {
            password: None,
            ..settings(Some(&anonymous), &[], &layout)
        };
        let out = render_main_cf(&settings);
        assert!(out.contains("smtp_sasl_auth_enable = no"), "{out}");
        assert!(!out.contains("smtp_sasl_password_maps"), "{out}");
        // Opportunistic, because encryption that cannot fail a delivery is
        // still better than none.
        assert!(out.contains("smtp_tls_security_level = may"), "{out}");
        assert!(render_sasl_passwd(&settings).is_none());
    }

    #[test]
    fn no_relay_renders_a_configuration_that_refuses_rather_than_one_that_queues() {
        // The house rule, in one file: if the message cannot be delivered, do
        // not accept it. An empty relayhost would make Postfix try direct-to-MX
        // delivery from a host with no SPF authority; a queue with nothing
        // draining it would report every message as sent.
        let out = render_main_cf(&settings(None, &[], &layout()));
        assert!(out.contains("default_transport = error:"), "{out}");
        assert!(out.contains("no outbound relay is configured"), "{out}");
        assert!(out.lines().any(|l| l.trim() == "relayhost ="), "{out}");
        assert!(!out.contains("smtp_sasl_auth_enable = yes"), "{out}");
    }

    #[test]
    fn a_relay_that_is_switched_off_is_the_same_as_no_relay_at_all() {
        // `is_live()`, not `is_some()`: "there is a row" must never become
        // "mail works". Switching the relay off has to stop mail leaving, not
        // leave it queueing against a relay the operator disabled.
        let mut off = relay();
        off.enabled = false;
        let layout = layout();
        let settings = settings(Some(&off), &[], &layout);
        let out = render_main_cf(&settings);
        assert!(out.contains("default_transport = error:"), "{out}");
        assert!(render_sasl_passwd(&settings).is_none());
        assert!(render_sender_canonical(&settings).is_none());
    }

    #[test]
    fn the_credential_map_key_is_spelled_exactly_as_the_relayhost() {
        // Postfix looks this table up by the next hop it resolved, so
        // `smtp.postmarkapp.com:587` and `[smtp.postmarkapp.com]:587` are
        // different keys — and the wrong one authenticates nothing, silently.
        let map = render_sasl_passwd(&settings(Some(&relay()), &[], &layout())).unwrap();
        let entry = map
            .lines()
            .find(|l| !l.starts_with('#') && !l.trim().is_empty())
            .unwrap();
        assert_eq!(entry, "[smtp.postmarkapp.com]:587\ttoken-user:token-secret");

        let main_cf = render_main_cf(&settings(Some(&relay()), &[], &layout()));
        assert!(
            main_cf.contains("relayhost = [smtp.postmarkapp.com]:587"),
            "{main_cf}"
        );
    }

    #[test]
    fn every_sender_this_machine_can_produce_is_rewritten_to_the_one_the_relay_accepts() {
        let domains = vec!["shop.example".to_string(), "blog.example".to_string()];
        let layout = layout();
        let relay = relay();
        let settings = settings(Some(&relay), &domains, &layout);
        let map = render_sender_canonical(&settings).unwrap();

        // The unqualified case — PHP's pool user, a tenant account, cron, root
        // — all of which `myorigin` completes with the machine's own name.
        assert!(
            map.contains("@web-01.acme.example\tnoreply@acme.example"),
            "{map}"
        );
        assert!(map.contains("@shop.example\tnoreply@acme.example"), "{map}");
        assert!(map.contains("@blog.example\tnoreply@acme.example"), "{map}");

        let main_cf = render_main_cf(&settings);
        // The static: tail is what keeps a site created since the last render
        // from bouncing, and the classes line is what keeps the From: header
        // the customer's rather than the operator's.
        assert!(
            main_cf.contains("sender_canonical_maps = texthash:")
                && main_cf.contains(", static:noreply@acme.example"),
            "{main_cf}"
        );
        assert!(
            main_cf.contains("sender_canonical_classes = envelope_sender"),
            "{main_cf}"
        );
        assert!(
            !directives(&main_cf)
                .iter()
                .any(|l| l.contains("header_sender")),
            "{main_cf}"
        );
    }

    #[test]
    fn writing_the_same_configuration_twice_changes_nothing_the_second_time() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("main.cf");
        let file = ManagedFile::postfix_main_cf(&path);
        let body = render_main_cf(&settings(Some(&relay()), &[], &layout()));

        assert_eq!(put(&file, &body, false).unwrap(), FileOutcome::Written);
        assert_eq!(put(&file, &body, false).unwrap(), FileOutcome::Unchanged);

        // And a changed body is written, because a `texthash:` map that is
        // rewritten without a reload is a credential Postfix never picks up.
        let mut other = relay();
        other.port = 465;
        assert_eq!(
            put(
                &file,
                &render_main_cf(&settings(Some(&other), &[], &layout())),
                false
            )
            .unwrap(),
            FileOutcome::Written
        );
    }

    #[test]
    fn a_postfix_the_panel_did_not_configure_is_not_taken_over_without_being_asked() {
        // The package's postinst always leaves a main.cf behind, so "foreign"
        // is the ordinary first-install state — but it is also what a machine
        // running somebody's real mail server looks like, and replacing that
        // silently would take their mail down.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("main.cf");
        std::fs::write(
            &path,
            "myhostname = mail.somebody.example\nmydestination = $myhostname\n",
        )
        .unwrap();
        let file = ManagedFile::postfix_main_cf(&path);

        let err = put(&file, "myhostname = ours\n", false).unwrap_err();
        assert_eq!(err.code, ErrorCode::ConfigDrift);
        assert!(err.detail.contains("adopt"), "{}", err.detail);
        // Untouched: the refusal has to leave the machine exactly as it was.
        assert!(
            std::fs::read_to_string(&path).unwrap().contains("somebody"),
            "the foreign file was modified by a refused write"
        );

        assert_eq!(
            put(&file, "myhostname = ours\n", true).unwrap(),
            FileOutcome::Adopted
        );
        let kept = std::fs::read_to_string(path.with_extension("cf.unihelm-replaced")).unwrap();
        assert!(kept.contains("mail.somebody.example"), "{kept}");
    }

    #[test]
    fn adopting_twice_does_not_overwrite_the_copy_of_the_original() {
        // The kept file is the only copy of whatever the machine had before.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("main.cf");
        std::fs::write(&path, "the original\n").unwrap();
        let file = ManagedFile::postfix_main_cf(&path);

        put(&file, "first\n", true).unwrap();
        // Drifted now — the panel's file, edited by hand.
        std::fs::write(&path, "somebody edited this\n").unwrap();
        put(&file, "second\n", true).unwrap();

        let kept = std::fs::read_to_string(path.with_extension("cf.unihelm-replaced")).unwrap();
        assert_eq!(kept, "the original\n");
    }

    #[test]
    fn the_credential_map_is_written_where_no_tenant_can_read_it() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sasl_passwd");
        let file = ManagedFile::postfix_map(&path);
        put(
            &file,
            &render_sasl_passwd(&settings(Some(&relay()), &[], &layout())).unwrap(),
            false,
        )
        .unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "on disk: {mode:o}");
        assert_eq!(mode & 0o077, 0, "a tenant could read the relay password");
    }

    #[test]
    fn clearing_the_credential_removes_the_file_rather_than_leaving_it() {
        // A password on disk that nothing uses is a password on disk.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sasl_passwd");
        let file = ManagedFile::postfix_map(&path);
        put(&file, "old content\n", false).unwrap();
        assert_eq!(remove(&file).unwrap(), FileOutcome::Removed);
        assert!(!path.exists());
        assert_eq!(remove(&file).unwrap(), FileOutcome::Absent);
    }

    #[test]
    fn a_file_the_panel_did_not_write_is_not_removed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sasl_passwd");
        std::fs::write(&path, "somebody else's map\n").unwrap();
        assert_eq!(
            remove(&ManagedFile::postfix_map(&path)).unwrap(),
            FileOutcome::Absent
        );
        assert!(path.exists(), "a foreign file was deleted");
    }

    #[test]
    fn the_queue_length_is_a_number_or_an_admission_that_it_is_unknown() {
        assert_eq!(parse_queue("Mail queue is empty\n"), Some(0));
        assert_eq!(parse_queue(""), Some(0));
        assert_eq!(
            parse_queue(
                "-Queue ID-  --Size-- ----Arrival Time---- -Sender/Recipient-------\n\
                 3F1A2B0C1D*     1234 Tue Sep  9 10:11:12  noreply@acme.example\n\
                 \n\
                 -- 5 Kbytes in 2 Requests.\n"
            ),
            Some(2)
        );
        assert_eq!(parse_queue("-- 1 Kbytes in 1 Request.\n"), Some(1));
        // Unrecognised output is `None`, never zero: reporting an empty queue
        // that was never counted is the panel stating something it does not
        // know.
        assert_eq!(parse_queue("postqueue: fatal: open lock file\n"), None);
    }

    #[test]
    fn the_summary_never_rounds_a_half_configured_machine_up() {
        // Each of these is a state a real machine is in during the migration,
        // and the sentence has to name the one it is actually in.
        let nothing = describe(false, false, false, false, None, 0);
        assert!(
            nothing.contains("nothing on this server can send mail"),
            "{nothing}"
        );

        let relay_but_no_mta = describe(false, false, false, true, None, 0);
        assert!(
            relay_but_no_mta.contains("mail.mta.install"),
            "{relay_but_no_mta}"
        );

        let no_relay = describe(true, true, true, false, None, 0);
        assert!(
            no_relay.contains("nothing will leave this machine"),
            "{no_relay}"
        );
        assert!(
            no_relay.contains("refused as it is submitted"),
            "{no_relay}"
        );

        let working = describe(true, true, true, true, Some(0), 0);
        assert!(working.contains("relays it upstream"), "{working}");
        assert!(!working.contains("waiting in the queue"), "{working}");

        let backed_up = describe(true, true, true, true, Some(7), 0);
        assert!(
            backed_up.contains("7 message(s) are waiting"),
            "{backed_up}"
        );

        // The leftover credential files are named wherever they exist, whatever
        // else is true: each one is a copy of the relay password a tenant can
        // still read.
        let half_migrated = describe(true, true, true, true, Some(0), 3);
        assert!(
            half_migrated.contains("3 per-site msmtp credential file(s)"),
            "{half_migrated}"
        );
    }
}
