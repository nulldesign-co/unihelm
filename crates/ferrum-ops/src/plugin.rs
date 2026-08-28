//! The plugin system — **sidecar model only** (spec §6 plugin note, §14 Phase 6).
//!
//! Spec §6 does not leave this open: *"Do NOT let plugins run in-process as
//! root."* Everything in this module follows from that one sentence.
//!
//! A plugin is **a separate process**, started by the agent under a **dedicated
//! unprivileged system account**, inside a systemd unit carrying the same
//! hardening the panel's own `ferrum-web` unit does, speaking the panel's
//! **existing length-prefixed JSON framing** ([`ferrum_ipc::codec`]) over
//! **its own** Unix socket. There is no dynamic library, no `dlopen`, no ABI,
//! and no code path from a plugin into the agent's address space.
//!
//! # The four properties that make this safe
//!
//! **1. The manifest is the routing authority, and it is validated once.** A
//! plugin declares its extension points at install time; the agent stores that
//! list and routes only calls those points cover ([`extension_for_method`]).
//! A running sidecar cannot widen its own reach, because nothing ever asks it
//! what it provides.
//!
//! **2. A plugin can never register an operation.** The registry
//! (`crate::registry::OpRegistry`) is built from a fixed list in Rust; nothing
//! in this module inserts into it. That is deliberate and load-bearing: the
//! registry is where the permission check lives, so an extension point that
//! could add an operation would be an extension point that could add an
//! unchecked one. Plugins are reached *through* operations, never as them.
//!
//! **3. The payload is verified before it is ever executed.** The manifest
//! carries a `[files]` digest table covering every file in the tree, and the
//! manifest itself carries a detached minisign signature — the same
//! `SHA256SUMS` + minisign shape the release pipeline already uses, so the
//! trust model is one an operator has met before. An unsigned plugin is
//! refused unless `plugins.allow_unsigned` is explicitly on, which it is not
//! by default (`docs/plugins.md` explains why at length).
//!
//! **4. The sidecar's tree is read-only to the sidecar.** The install
//! directory is root-owned; the plugin account may read and execute, never
//! write. A plugin that could rewrite its own binary would have made the
//! signature check a one-time formality.
//!
//! # What this module deliberately does not do
//!
//! - **It does not fetch anything.** `plugin.install` takes a path to a tree
//!   already staged on the server. A marketplace client (spec §14 Phase 6)
//!   belongs above this layer, and would stage a tree exactly like this one.
//! - **It does not upgrade in place.** Installing over an existing slug is a
//!   conflict; remove and install. An in-place upgrade has to reconcile a
//!   running sidecar, a changed manifest and a changed extension set, and
//!   getting that half-right is worse than not offering it.

use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};
use std::time::Duration as StdDuration;

use async_trait::async_trait;
use ferrum_config::apply::{ApplyRequest, Reloader, Validator, managed_for};
use ferrum_config::paths;
use ferrum_core::{ErrorCode, FerrumError, Permission, Result};
use ferrum_db::{NewPlugin, PluginRecord, PluginSignature};
use ferrum_distro::svc::{UnitName, UnitState};
use ferrum_distro::{Cmd, Distro};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::registry::{Execution, OpContext, TypedOperation};

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------

/// Whether an unsigned plugin may be installed. **Defaults to false.**
///
/// The reasoning, at length, is in `docs/plugins.md`; the short version is that
/// a plugin is code the agent starts as a service on a machine full of other
/// people's websites, and "I downloaded it from somewhere" is not a trust
/// decision a panel should make on an operator's behalf.
pub const ALLOW_UNSIGNED_KEY: &str = "plugins.allow_unsigned";

/// The minisign public keys plugin manifests may be signed with, as a JSON
/// array of strings in the `RW...` format `minisign -p` prints.
///
/// Empty by default: this panel trusts nobody's plugins until an operator says
/// whose it trusts.
pub const TRUSTED_KEYS_KEY: &str = "plugins.trusted_keys";

/// The plugin protocol version this build speaks.
pub const PLUGIN_API_VERSION: u16 = 1;

/// Memory ceiling for a sidecar, in MiB.
///
/// Third-party code must not be able to spend the server's memory: the panel's
/// own budget is 150 MB idle (spec §3), and a plugin that leaks past this is
/// OOM-killed and restarted rather than taking the host with it.
const SIDECAR_MEMORY_MAX_MB: u32 = 128;

/// The serialisation key every systemd unit write shares — the same string
/// `nodeapp.rs` and `slices.rs` use, so the config engine serialises applies
/// across all three and a `daemon-reload` never races a half-written unit.
const SYSTEMD_SERVICE: &str = "systemd";

// ---------------------------------------------------------------------------
// Slug
// ---------------------------------------------------------------------------

/// A plugin's identity, validated once and used everywhere.
///
/// The alphabet is the intersection of three things the slug becomes: a
/// systemd unit name component, a Unix account name (`ferrum-plug-<slug>`,
/// which must fit in 32 characters with the prefix), and a path component. It
/// is therefore `[a-z0-9]` followed by up to 19 of `[a-z0-9-]`, ending in an
/// alphanumeric — no leading digit rule, because unit names and account names
/// both accept one, and no dots, because a dot in a unit name changes what
/// systemd thinks the unit *is*.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginSlug(String);

/// `ferrum-plug-` (12) + 19 = 31, one under the 32-character account limit
/// every distribution enforces.
const MAX_SLUG_LEN: usize = 19;

impl PluginSlug {
    pub fn parse(input: &str) -> Result<Self> {
        let s = input.trim();
        if s.is_empty() || s.len() > MAX_SLUG_LEN {
            return Err(FerrumError::new(
                ErrorCode::InvalidInput,
                format!("a plugin slug must be 1-{MAX_SLUG_LEN} characters"),
            )
            .with_field("slug"));
        }
        let bytes = s.as_bytes();
        let ends_ok = bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit();
        let last = bytes[bytes.len() - 1];
        let tail_ok = last.is_ascii_lowercase() || last.is_ascii_digit();
        if !ends_ok || !tail_ok {
            return Err(FerrumError::new(
                ErrorCode::InvalidInput,
                "a plugin slug must start and end with a lowercase letter or digit",
            )
            .with_field("slug"));
        }
        if !bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
        {
            return Err(FerrumError::new(
                ErrorCode::InvalidInput,
                "a plugin slug may contain only lowercase letters, digits and hyphens",
            )
            .with_field("slug"));
        }
        Ok(Self(s.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The dedicated system account this plugin's sidecar runs as.
    pub fn run_user(&self) -> String {
        format!("ferrum-plug-{}", self.0)
    }

    /// The sidecar's unit.
    ///
    /// Infallible: the slug alphabet is a strict subset of what [`UnitName`]
    /// accepts, and the length is far inside its budget. The test
    /// `every_valid_slug_yields_a_valid_unit_name` pins the reasoning.
    pub fn unit(&self) -> UnitName {
        UnitName::parse(&paths::plugin_unit_file_name(&self.0))
            .expect("a validated slug always forms a valid unit name")
    }
}

// ---------------------------------------------------------------------------
// Extension points
// ---------------------------------------------------------------------------

/// What a plugin may extend (spec §6: "app definitions, new
/// DnsProvider/BackupTarget/notifier implementations … and UI panels").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtensionPoint {
    /// App-store manifests: new installable application definitions.
    AppStore,
    /// A DNS-01 provider beside Cloudflare (spec §11.13).
    DnsProvider,
    /// A restic-compatible backup destination (spec §11.10).
    BackupTarget,
    /// An alert notifier channel (spec §11.11).
    Notifier,
    /// A micro-frontend mount point in the panel UI.
    UiPanel,
}

impl ExtensionPoint {
    pub const ALL: &'static [ExtensionPoint] = &[
        ExtensionPoint::AppStore,
        ExtensionPoint::DnsProvider,
        ExtensionPoint::BackupTarget,
        ExtensionPoint::Notifier,
        ExtensionPoint::UiPanel,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            ExtensionPoint::AppStore => "app_store",
            ExtensionPoint::DnsProvider => "dns_provider",
            ExtensionPoint::BackupTarget => "backup_target",
            ExtensionPoint::Notifier => "notifier",
            ExtensionPoint::UiPanel => "ui_panel",
        }
    }

    /// The method namespace this point owns on the sidecar protocol.
    pub const fn namespace(self) -> &'static str {
        match self {
            ExtensionPoint::AppStore => "app",
            ExtensionPoint::DnsProvider => "dns",
            ExtensionPoint::BackupTarget => "backup",
            ExtensionPoint::Notifier => "notify",
            ExtensionPoint::UiPanel => "ui",
        }
    }
}

/// Which extension point a sidecar method belongs to, or `None` if the method
/// is not part of the contract at all.
///
/// A closed mapping, not a prefix-strip-and-hope: `"../../etc"` and
/// `"registry.register"` both land in `None`, which is the answer that keeps
/// [`route_allowed`] from having to reason about them.
pub fn extension_for_method(method: &str) -> Option<ExtensionPoint> {
    let (namespace, rest) = method.split_once('.')?;
    if rest.is_empty() || !rest.bytes().all(|b| b.is_ascii_lowercase() || b == b'_') {
        return None;
    }
    ExtensionPoint::ALL
        .iter()
        .copied()
        .find(|point| point.namespace() == namespace)
}

/// May this plugin be asked to handle this method?
///
/// The declared list wins, always. A plugin that declares `notifier` and is
/// asked for `dns.present` is refused here, before a byte reaches its socket —
/// which is the difference between "the manifest documents what it does" and
/// "the manifest constrains what it does".
pub fn route_allowed(declared: &[String], method: &str) -> bool {
    let Some(point) = extension_for_method(method) else {
        return false;
    };
    declared.iter().any(|d| d == point.as_str())
}

// ---------------------------------------------------------------------------
// Manifest
// ---------------------------------------------------------------------------

/// A UI mount point a plugin contributes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UiMount {
    /// Router path under `/plugins/`, e.g. `acme-dns`. Not a full path: the
    /// panel owns its own routing table and a plugin does not get to name a
    /// route outside its own namespace.
    pub path: String,
    pub label_en: String,
    pub label_fa: String,
}

/// `plugin.toml`, as authored by the plugin and validated here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub slug: String,
    pub name: String,
    pub version: String,
    /// The program the sidecar unit runs, **relative to the install
    /// directory**. Absolute paths and traversal are refused: an operator who
    /// installs a plugin has not agreed to run `/usr/bin/anything`.
    pub entry: String,
    /// Which plugin protocol the payload speaks. Must equal
    /// [`PLUGIN_API_VERSION`]; a mismatch is refused at install time rather
    /// than discovered as a parse error on the socket at three in the morning.
    pub api_version: u16,
    /// The extension points this plugin registers. Non-empty: a plugin that
    /// extends nothing is a service, not a plugin.
    pub extensions: Vec<ExtensionPoint>,
    #[serde(default)]
    pub ui: Option<UiMount>,
    /// Every file in the payload, by path relative to the tree root, with its
    /// lowercase hex SHA-256.
    pub files: std::collections::BTreeMap<String, String>,
}

const MAX_NAME_LEN: usize = 64;
const MAX_VERSION_LEN: usize = 32;
const MAX_FILES: usize = 2000;

impl Manifest {
    /// Parse and validate `plugin.toml`.
    ///
    /// Everything that could later become a unit-file directive, a path or an
    /// account name is checked *here*, once, so no later step has to wonder.
    pub fn parse(source: &str) -> Result<(Self, PluginSlug)> {
        if source.len() > 512 * 1024 {
            return Err(FerrumError::new(
                ErrorCode::InvalidInput,
                "plugin.toml is implausibly large",
            ));
        }
        let manifest: Manifest = toml::from_str(source)
            .map_err(|e| FerrumError::new(ErrorCode::InvalidInput, format!("plugin.toml: {e}")))?;

        let slug = PluginSlug::parse(&manifest.slug)?;

        if manifest.api_version != PLUGIN_API_VERSION {
            return Err(FerrumError::new(
                ErrorCode::InvalidInput,
                format!(
                    "this plugin speaks protocol {} but this panel speaks {PLUGIN_API_VERSION}",
                    manifest.api_version
                ),
            )
            .with_field("api_version"));
        }
        check_text("name", &manifest.name, MAX_NAME_LEN)?;
        check_text("version", &manifest.version, MAX_VERSION_LEN)?;
        validate_entry(&manifest.entry)?;

        if manifest.extensions.is_empty() {
            return Err(FerrumError::new(
                ErrorCode::InvalidInput,
                "a plugin must declare at least one extension point",
            )
            .with_field("extensions"));
        }
        let mut seen: Vec<ExtensionPoint> = Vec::new();
        for point in &manifest.extensions {
            if seen.contains(point) {
                return Err(FerrumError::new(
                    ErrorCode::InvalidInput,
                    format!("`{}` is declared twice", point.as_str()),
                )
                .with_field("extensions"));
            }
            seen.push(*point);
        }

        if let Some(ui) = &manifest.ui {
            if !manifest.extensions.contains(&ExtensionPoint::UiPanel) {
                return Err(FerrumError::new(
                    ErrorCode::InvalidInput,
                    "a [ui] section needs the `ui_panel` extension point declared",
                )
                .with_field("ui"));
            }
            // The mount is a single path segment under the panel's own
            // `/plugins/` prefix: a plugin does not get to name a route
            // anywhere else in the application.
            PluginSlug::parse(&ui.path).map_err(|_| {
                FerrumError::new(
                    ErrorCode::InvalidInput,
                    "a UI mount path must be a single slug-shaped segment",
                )
                .with_field("ui.path")
            })?;
            check_text("ui.label_en", &ui.label_en, MAX_NAME_LEN)?;
            check_text("ui.label_fa", &ui.label_fa, MAX_NAME_LEN)?;
        }

        if manifest.files.is_empty() || manifest.files.len() > MAX_FILES {
            return Err(FerrumError::new(
                ErrorCode::InvalidInput,
                format!("[files] must list between 1 and {MAX_FILES} files"),
            )
            .with_field("files"));
        }
        for (path, digest) in &manifest.files {
            validate_entry(path)?;
            if path == "plugin.toml" || path == "plugin.toml.minisig" {
                return Err(FerrumError::new(
                    ErrorCode::InvalidInput,
                    "the manifest and its signature are not payload entries: a file \
                     cannot carry its own digest",
                )
                .with_field("files"));
            }
            if digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(FerrumError::new(
                    ErrorCode::InvalidInput,
                    format!("`{path}` has a digest that is not a hex SHA-256"),
                )
                .with_field("files"));
            }
        }
        if !manifest.files.contains_key(&manifest.entry) {
            return Err(FerrumError::new(
                ErrorCode::InvalidInput,
                "the entry point must appear in [files]; an unlisted file is \
                 an unverified file",
            )
            .with_field("entry"));
        }

        Ok((manifest, slug))
    }

    pub fn extension_names(&self) -> Vec<String> {
        self.extensions
            .iter()
            .map(|p| p.as_str().to_string())
            .collect()
    }
}

fn check_text(field: &'static str, value: &str, max: usize) -> Result<()> {
    if value.trim().is_empty() || value.len() > max {
        return Err(FerrumError::new(
            ErrorCode::InvalidInput,
            format!("`{field}` must be 1-{max} characters"),
        )
        .with_field(field));
    }
    if value.chars().any(char::is_control) {
        return Err(FerrumError::new(
            ErrorCode::InvalidInput,
            format!("`{field}` contains a control character"),
        )
        .with_field(field));
    }
    Ok(())
}

/// A relative, traversal-free path that is also safe inside a systemd
/// `ExecStart=`.
///
/// Three families of refusal, each for a different reason:
///
/// * **absolute or traversing** — the install directory is the boundary, and a
///   path that leaves it is a plugin choosing what the agent executes;
/// * **systemd syntax** — a space splits `ExecStart` into two arguments, `%`
///   is a specifier systemd expands before anything else reads the line, and a
///   quote unbalances it. Refused rather than escaped, because a plugin
///   binary whose path needs quoting is a packaging mistake worth naming;
/// * **control characters and NUL** — a newline ends the line and starts a
///   directive.
pub fn validate_entry(entry: &str) -> Result<()> {
    if entry.is_empty() || entry.len() > 255 {
        return Err(FerrumError::new(
            ErrorCode::InvalidPath,
            "a plugin path must be 1-255 characters",
        )
        .with_field("entry"));
    }
    let path = Path::new(entry);
    if path.is_absolute() {
        return Err(
            FerrumError::new(ErrorCode::InvalidPath, "a plugin path must be relative")
                .with_field("entry"),
        );
    }
    for component in path.components() {
        match component {
            Component::Normal(_) => {}
            _ => {
                return Err(FerrumError::new(
                    ErrorCode::InvalidPath,
                    format!("`{entry}` leaves the plugin directory"),
                )
                .with_field("entry"));
            }
        }
    }
    if let Some(bad) = entry.chars().find(|c| {
        c.is_control() || c.is_whitespace() || matches!(c, '%' | '"' | '\'' | '`' | '$' | '\\')
    }) {
        return Err(FerrumError::new(
            ErrorCode::InvalidPath,
            format!(
                "`{entry}` contains `{}`, which systemd would read as syntax in ExecStart",
                bad.escape_default()
            ),
        )
        .with_field("entry"));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// minisign verification
// ---------------------------------------------------------------------------

/// Verifying a detached minisign signature, in process.
///
/// The same ed25519/minisign format the installer verifies releases with
/// (`installer/install.sh`, spec §5.5), so an operator signing a plugin uses
/// the tool they already have. In process rather than by shelling out to
/// `minisign`, for two reasons: the binary is an EPEL package on the RHEL
/// family and may simply not be there, and a verification that silently
/// degrades to "skipped" when a tool is missing is not a verification.
pub mod minisign {
    use super::*;
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as B64;
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    /// `Ed`: the signature covers the message bytes directly.
    const ALG_LEGACY: [u8; 2] = [0x45, 0x64];
    /// `ED`: the signature covers BLAKE2b-512 of the message. What current
    /// minisign emits by default.
    const ALG_PREHASHED: [u8; 2] = [0x45, 0x44];

    #[derive(Debug, Clone, Copy)]
    pub struct PublicKey {
        pub key_id: [u8; 8],
        key: [u8; 32],
    }

    /// Parse the one-line `RW...` form `minisign -p` prints.
    pub fn parse_public_key(text: &str) -> Result<PublicKey> {
        // A public key *file* has an untrusted-comment line first; accept both
        // spellings so an operator can paste either.
        let line = text
            .lines()
            .map(str::trim)
            .find(|l| !l.is_empty() && !l.starts_with("untrusted comment:"))
            .ok_or_else(|| {
                FerrumError::new(ErrorCode::InvalidInput, "that is not a minisign public key")
            })?;

        let raw = B64.decode(line).map_err(|_| {
            FerrumError::new(
                ErrorCode::InvalidInput,
                "a minisign public key must be base64",
            )
        })?;
        if raw.len() != 42 {
            return Err(FerrumError::new(
                ErrorCode::InvalidInput,
                "a minisign public key decodes to 42 bytes",
            ));
        }
        if raw[0..2] != ALG_LEGACY {
            return Err(FerrumError::new(
                ErrorCode::InvalidInput,
                "unsupported minisign public key algorithm",
            ));
        }
        let mut key_id = [0u8; 8];
        key_id.copy_from_slice(&raw[2..10]);
        let mut key = [0u8; 32];
        key.copy_from_slice(&raw[10..42]);
        Ok(PublicKey { key_id, key })
    }

    struct ParsedSignature {
        alg: [u8; 2],
        key_id: [u8; 8],
        signature: [u8; 64],
        trusted_comment: String,
        global: [u8; 64],
    }

    fn parse_signature(text: &str) -> Result<ParsedSignature> {
        let mut lines = text.lines();
        // Line 1 is the untrusted comment; it is not covered by anything and
        // is therefore ignored entirely rather than shown to anyone.
        let _untrusted = lines.next();
        let sig_line = lines.next().unwrap_or_default().trim();
        let trusted_line = lines.next().unwrap_or_default();
        let global_line = lines.next().unwrap_or_default().trim();

        let raw = B64
            .decode(sig_line)
            .map_err(|_| malformed("the signature line is not base64"))?;
        if raw.len() != 74 {
            return Err(malformed("the signature line decodes to 74 bytes"));
        }
        let trusted_comment = trusted_line
            .strip_prefix("trusted comment: ")
            .ok_or_else(|| malformed("the trusted comment line is missing"))?
            .to_string();
        let global_raw = B64
            .decode(global_line)
            .map_err(|_| malformed("the global signature is not base64"))?;
        if global_raw.len() != 64 {
            return Err(malformed("the global signature decodes to 64 bytes"));
        }

        let mut alg = [0u8; 2];
        alg.copy_from_slice(&raw[0..2]);
        let mut key_id = [0u8; 8];
        key_id.copy_from_slice(&raw[2..10]);
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&raw[10..74]);
        let mut global = [0u8; 64];
        global.copy_from_slice(&global_raw);

        Ok(ParsedSignature {
            alg,
            key_id,
            signature,
            trusted_comment,
            global,
        })
    }

    fn malformed(detail: &str) -> FerrumError {
        FerrumError::new(
            ErrorCode::InvalidInput,
            format!("malformed minisign signature: {detail}"),
        )
    }

    /// Verify `signature` over `message` against any of `keys`.
    ///
    /// Returns the trusted comment on success — minisign's own convention for
    /// carrying signed metadata, and worth surfacing because it is the only
    /// part of the signature file that is both human-readable and
    /// authenticated.
    ///
    /// Both the payload signature **and** the global signature over
    /// `signature || trusted_comment` are checked. Skipping the second is the
    /// classic minisign implementation bug: it leaves the trusted comment —
    /// the field whose whole name promises it is trustworthy — freely editable
    /// by anyone holding the file.
    pub fn verify(message: &[u8], signature: &str, keys: &[PublicKey]) -> Result<String> {
        let parsed = parse_signature(signature)?;

        let key = keys
            .iter()
            .find(|k| k.key_id == parsed.key_id)
            .ok_or_else(|| {
                FerrumError::new(
                    ErrorCode::PermissionDenied,
                    "this plugin is signed by a key this panel does not trust",
                )
            })?;

        let verifying = VerifyingKey::from_bytes(&key.key).map_err(|_| {
            FerrumError::new(
                ErrorCode::InvalidInput,
                "the trusted key is not a valid ed25519 key",
            )
        })?;
        let sig = Signature::from_bytes(&parsed.signature);

        let signed: Vec<u8> = match parsed.alg {
            ALG_LEGACY => message.to_vec(),
            ALG_PREHASHED => {
                use blake2::Blake2b512;
                use blake2::Digest as _;
                let mut hasher = Blake2b512::new();
                hasher.update(message);
                hasher.finalize().to_vec()
            }
            _ => return Err(malformed("unsupported signature algorithm")),
        };

        verifying.verify(&signed, &sig).map_err(|_| {
            FerrumError::new(
                ErrorCode::PermissionDenied,
                "the plugin manifest does not match its signature",
            )
        })?;

        let mut global_message = parsed.signature.to_vec();
        global_message.extend_from_slice(parsed.trusted_comment.as_bytes());
        verifying
            .verify(&global_message, &Signature::from_bytes(&parsed.global))
            .map_err(|_| {
                FerrumError::new(
                    ErrorCode::PermissionDenied,
                    "the signature's trusted comment has been tampered with",
                )
            })?;

        Ok(parsed.trusted_comment)
    }
}

// ---------------------------------------------------------------------------
// Payload verification
// ---------------------------------------------------------------------------

/// Check a staged tree against its manifest's `[files]` table.
///
/// Both directions, and the second one is the important one:
///
/// * every listed file exists with the listed digest — no substitution;
/// * every regular file in the tree is listed — **no extras**. A checker that
///   only verifies what the manifest mentions can be defeated by shipping a
///   second binary the manifest does not mention, and the signature would
///   still verify.
///
/// Symlinks are refused outright, anywhere in the tree: a symlink has no
/// content to hash, and one pointing at `/etc/shadow` inside a directory the
/// agent is about to copy is the oldest trick there is.
pub fn verify_tree(dir: &Path, manifest: &Manifest) -> Result<()> {
    let mut found: Vec<String> = Vec::new();
    collect_files(dir, dir, &mut found)?;

    for relative in &found {
        // Two files are outside the digest table by construction, and both for
        // the same reason — a file cannot contain its own digest. The manifest
        // is covered by the *signature* instead, which is the stronger claim;
        // the signature file is covered by nothing, which is fine because it
        // is not executed and is not copied into the install directory.
        if relative == "plugin.toml" || relative == "plugin.toml.minisig" {
            continue;
        }
        if !manifest.files.contains_key(relative) {
            return Err(FerrumError::new(
                ErrorCode::InvalidInput,
                format!(
                    "`{relative}` is in the payload but not in [files]; every file must be listed"
                ),
            ));
        }
    }

    for (relative, expected) in &manifest.files {
        let path = dir.join(relative);
        let bytes = std::fs::read(&path).map_err(|e| {
            FerrumError::new(
                ErrorCode::NotFound,
                format!("`{relative}` is listed in [files] but could not be read: {e}"),
            )
        })?;
        let actual = hex::encode(Sha256::digest(&bytes));
        if !actual.eq_ignore_ascii_case(expected) {
            return Err(FerrumError::new(
                ErrorCode::PermissionDenied,
                format!("`{relative}` does not match the digest in [files]"),
            ));
        }
    }
    Ok(())
}

/// Every regular file under `dir`, as paths relative to `root`.
fn collect_files(root: &Path, dir: &Path, out: &mut Vec<String>) -> Result<()> {
    let entries = std::fs::read_dir(dir).map_err(|e| {
        FerrumError::new(
            ErrorCode::NotFound,
            format!("could not read {}: {e}", dir.display()),
        )
    })?;
    for entry in entries {
        let entry = entry.map_err(|e| FerrumError::internal(e.to_string()))?;
        // `symlink_metadata`, not `metadata`: the whole point is to see the
        // link rather than what it points at.
        let meta = entry
            .metadata()
            .map_err(|e| FerrumError::internal(e.to_string()))?;
        let path = entry.path();
        if meta.file_type().is_symlink() {
            return Err(FerrumError::new(
                ErrorCode::InvalidPath,
                format!(
                    "`{}` is a symlink; a plugin payload may not contain one",
                    path.strip_prefix(root).unwrap_or(&path).display()
                ),
            ));
        }
        if meta.is_dir() {
            collect_files(root, &path, out)?;
        } else if meta.is_file() {
            let relative = path
                .strip_prefix(root)
                .map_err(|_| FerrumError::internal("a payload path escaped its root"))?;
            out.push(relative.to_string_lossy().replace('\\', "/"));
        } else {
            return Err(FerrumError::new(
                ErrorCode::InvalidPath,
                format!(
                    "`{}` is neither a file nor a directory",
                    path.strip_prefix(root).unwrap_or(&path).display()
                ),
            ));
        }
    }
    Ok(())
}

/// A source path an operator may stage a plugin at.
///
/// Absolute, traversal-free, and **never inside `/home`**. That last rule is
/// the one worth stating: a tree staged in a tenant's home is a tree the
/// tenant can rewrite between the moment it is verified and the moment it is
/// copied, which would turn the whole signature check into theatre.
pub fn validate_source(source: &str) -> Result<PathBuf> {
    let path = Path::new(source);
    if !path.is_absolute() {
        return Err(FerrumError::new(
            ErrorCode::InvalidPath,
            "the plugin source must be an absolute path",
        )
        .with_field("source"));
    }
    if path
        .components()
        .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
    {
        return Err(FerrumError::new(
            ErrorCode::InvalidPath,
            "the plugin source path must be canonical (no `.` or `..`)",
        )
        .with_field("source"));
    }
    if path.starts_with(paths::home_root()) {
        return Err(FerrumError::new(
            ErrorCode::InvalidPath,
            "a plugin cannot be installed from a tenant home: the tenant could \
             rewrite the tree between verification and install",
        )
        .with_field("source"));
    }
    if path.starts_with(paths::plugin_root()) {
        return Err(FerrumError::new(
            ErrorCode::InvalidPath,
            "stage a plugin outside the installed-plugin directory",
        )
        .with_field("source"));
    }
    Ok(path.to_path_buf())
}

// ---------------------------------------------------------------------------
// The sidecar client
// ---------------------------------------------------------------------------

/// One call to a plugin. Deliberately **not** [`ferrum_ipc::RequestFrame`]:
/// that envelope carries an `AuthContext`, and a plugin has no business seeing
/// who the caller is, let alone what permissions they hold. The framing is
/// shared ([`ferrum_ipc::codec`]); the envelope is not.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginRequest {
    pub v: u16,
    pub id: String,
    /// `<namespace>.<verb>`, checked against the plugin's declared extension
    /// points before the socket is even opened.
    pub method: String,
    pub params: serde_json::Value,
}

/// What a sidecar answers. Untagged over `result`, matching the panel's own
/// response frame so the shape is familiar to anyone who has read §5.3.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "lowercase")]
pub enum PluginResponse {
    Ok {
        #[serde(default)]
        data: serde_json::Value,
    },
    Err {
        message: String,
    },
}

/// A plugin's reply must fit in this. Far smaller than the agent's own 8 MiB
/// ceiling: extension-point answers are DNS records, repository listings and
/// notification receipts, and a plugin that wants to send a megabyte is a
/// plugin doing something the contract does not cover.
pub const MAX_PLUGIN_FRAME: usize = 1024 * 1024;

/// How long the agent waits for a sidecar.
///
/// A plugin call happens inside an operation somebody is waiting on, so a
/// plugin that hangs must not become a panel that hangs.
pub const CALL_TIMEOUT: StdDuration = StdDuration::from_secs(15);

/// Call one plugin's declared extension point.
///
/// The order of the checks is the design: **routing first, socket second**. A
/// method the plugin did not declare is refused without any connection being
/// opened, so a plugin cannot learn that the panel tried.
pub async fn call(
    record: &PluginRecord,
    method: &str,
    params: serde_json::Value,
) -> Result<serde_json::Value> {
    if !record.enabled {
        return Err(FerrumError::new(
            ErrorCode::ServiceUnavailable,
            format!("plugin `{}` is not enabled", record.slug),
        ));
    }
    if !route_allowed(&record.extensions, method) {
        return Err(FerrumError::new(
            ErrorCode::PermissionDenied,
            format!(
                "plugin `{}` did not declare an extension point covering `{method}`",
                record.slug
            ),
        ));
    }
    let socket = paths::plugin_socket(&record.slug);
    call_at(&socket, method, params).await
}

/// The transport half, split out so it is testable against a socket a test
/// controls.
pub async fn call_at(
    socket: &Path,
    method: &str,
    params: serde_json::Value,
) -> Result<serde_json::Value> {
    let request = PluginRequest {
        v: PLUGIN_API_VERSION,
        id: uuid_like(),
        method: method.to_string(),
        params,
    };
    let payload = serde_json::to_vec(&request)
        .map_err(|e| FerrumError::internal(format!("plugin request: {e}")))?;

    let work = async {
        let mut stream = tokio::net::UnixStream::connect(socket).await.map_err(|e| {
            FerrumError::new(
                ErrorCode::ServiceUnavailable,
                format!("could not reach the plugin socket: {e}"),
            )
        })?;
        ferrum_ipc::codec::write_frame(&mut stream, &payload)
            .await
            .map_err(FerrumError::from)?;
        let frame = ferrum_ipc::codec::read_frame(&mut stream, MAX_PLUGIN_FRAME)
            .await
            .map_err(FerrumError::from)?
            .ok_or_else(|| {
                FerrumError::new(
                    ErrorCode::ServiceUnavailable,
                    "the plugin closed the connection without answering",
                )
            })?;
        let response: PluginResponse = serde_json::from_slice(&frame).map_err(|e| {
            FerrumError::new(
                ErrorCode::AgentProtocol,
                format!("the plugin sent something that is not a response: {e}"),
            )
        })?;
        match response {
            PluginResponse::Ok { data } => Ok(data),
            // The plugin's own words, bounded — it is third-party text on its
            // way to an operator's screen.
            PluginResponse::Err { message } => Err(FerrumError::new(
                ErrorCode::CommandFailed,
                message.chars().take(500).collect::<String>(),
            )),
        }
    };

    match tokio::time::timeout(CALL_TIMEOUT, work).await {
        Ok(result) => result,
        Err(_) => Err(FerrumError::new(
            ErrorCode::AgentTimeout,
            format!(
                "the plugin did not answer within {} seconds",
                CALL_TIMEOUT.as_secs()
            ),
        )),
    }
}

/// A correlation id for one call. Not a UUID crate dependency for one string:
/// the id is only ever echoed back, never parsed.
fn uuid_like() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

// ---------------------------------------------------------------------------
// Installing
// ---------------------------------------------------------------------------

/// What `systemd/plugin.service` renders from.
#[derive(Debug, Serialize)]
struct UnitContext {
    slug: String,
    run_user: String,
    install_dir: String,
    exec_start: String,
    socket_path: String,
    runtime_dir: String,
    api_version: u16,
    memory_max_mb: u32,
}

struct UnitVerify<'a> {
    path: &'a Path,
}

#[async_trait]
impl Validator for UnitVerify<'_> {
    fn name(&self) -> &'static str {
        "systemd-analyze verify"
    }

    async fn validate(&self) -> std::result::Result<(), String> {
        // Degrades to a skip where the tool is absent (minimal containers, a
        // developer's laptop), for the same reason `nodeapp.rs` does: an
        // unverifiable unit is a smaller risk than refusing to install on a
        // machine that merely lacks a diagnostic, and systemd rejects a bad
        // unit in isolation.
        if !ferrum_distro::exec::program_available("systemd-analyze") {
            return Ok(());
        }
        match Cmd::new("systemd-analyze")
            .args(["verify", "--"])
            .arg(self.path)
            .run()
            .await
        {
            Ok(out) if out.success() => Ok(()),
            Ok(out) => Err(out.failure_text()),
            Err(e) => Err(e.to_string()),
        }
    }
}

struct DaemonReload<'a> {
    distro: &'a Distro,
}

#[async_trait]
impl Reloader for DaemonReload<'_> {
    fn name(&self) -> &'static str {
        "systemctl daemon-reload"
    }

    async fn reload(&self) -> std::result::Result<(), String> {
        self.distro
            .svc
            .daemon_reload()
            .await
            .map_err(|e| e.to_string())
    }
}

/// Create the plugin's dedicated system account if it is not there.
///
/// `--system` (no aging, low uid), no home, and a login shell of `nologin`:
/// this account exists to be a `User=` in one unit and nothing else. Nobody
/// logs in as a plugin.
async fn ensure_plugin_user(ctx: &OpContext, slug: &PluginSlug) -> Result<String> {
    let user = slug.run_user();
    let exists = Cmd::new("getent")
        .args(["passwd", "--"])
        .arg(&user)
        .run()
        .await
        .map(|out| out.success())
        .unwrap_or(false);
    if exists {
        ctx.log(format!("account {user} already exists"));
        return Ok(user);
    }

    let nologin = match ctx.distro().info.family {
        ferrum_distro::Family::Debian => "/usr/sbin/nologin",
        ferrum_distro::Family::Rhel => "/sbin/nologin",
    };
    Cmd::new("useradd")
        .args([
            "--system",
            "--no-create-home",
            "--shell",
            nologin,
            "--comment",
            "Ferrum plugin",
        ])
        .arg("--")
        .arg(&user)
        .run_checked()
        .await?;
    ctx.log(format!("created account {user}"));
    Ok(user)
}

/// Copy a verified tree into the install directory, root-owned.
///
/// Written in Rust rather than delegated to `cp -a`: `cp` would preserve the
/// source's ownership and modes, and the source is a staging directory whose
/// permissions are whoever staged it. What is wanted is the opposite — every
/// mode set explicitly, by us, so the tree is readable and executable by the
/// plugin account and writable by nobody but root.
fn install_tree(source: &Path, dest: &Path, manifest: &Manifest) -> Result<()> {
    let io = |e: std::io::Error| FerrumError::internal(format!("installing the plugin: {e}"));
    std::fs::create_dir_all(dest).map_err(io)?;
    std::fs::set_permissions(dest, std::fs::Permissions::from_mode(0o755)).map_err(io)?;

    for relative in manifest.files.keys() {
        let from = source.join(relative);
        let to = dest.join(relative);
        if let Some(parent) = to.parent() {
            std::fs::create_dir_all(parent).map_err(io)?;
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o755)).map_err(io)?;
        }
        std::fs::copy(&from, &to).map_err(io)?;
        // 0755 for the entry point, 0644 for everything else. Nothing is
        // group- or world-writable, so the plugin account cannot rewrite the
        // code the agent is about to start as a service.
        let mode = if relative == &manifest.entry {
            0o755
        } else {
            0o644
        };
        std::fs::set_permissions(&to, std::fs::Permissions::from_mode(mode)).map_err(io)?;
    }

    // The manifest itself travels with the payload, so an operator reading the
    // install directory sees the same document the panel validated.
    std::fs::copy(paths::plugin_manifest(source), paths::plugin_manifest(dest)).map_err(io)?;
    std::fs::set_permissions(
        paths::plugin_manifest(dest),
        std::fs::Permissions::from_mode(0o644),
    )
    .map_err(io)?;
    Ok(())
}

/// Read the trusted minisign keys an operator has configured.
async fn trusted_keys(ctx: &OpContext) -> Result<Vec<minisign::PublicKey>> {
    let raw: Vec<String> = ctx
        .db()
        .get_setting_or(TRUSTED_KEYS_KEY, Vec::<String>::new())
        .await;
    raw.iter().map(|k| minisign::parse_public_key(k)).collect()
}

// ---------------------------------------------------------------------------
// Operations
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct ListInput {}

#[derive(Debug, Serialize)]
pub struct ListOutput {
    pub plugins: Vec<PluginRecord>,
    /// Every extension point this build knows how to route.
    pub extension_points: Vec<&'static str>,
    pub api_version: u16,
    pub allow_unsigned: bool,
    /// How many trusted signing keys are configured. The keys themselves are
    /// public, but the count is what an operator actually needs to see next to
    /// "unsigned plugins: refused".
    pub trusted_key_count: usize,
}

pub struct List;

#[async_trait]
impl TypedOperation for List {
    type Input = ListInput;
    type Output = ListOutput;

    const NAME: &'static str = "plugin.list";
    const PERMISSION: Permission = Permission::ServerRead;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, _input: Self::Input) -> Result<Self::Output> {
        let plugins = ctx.db().list_plugins().await.map_err(FerrumError::from)?;
        let allow_unsigned = ctx.db().get_setting_or(ALLOW_UNSIGNED_KEY, false).await;
        let keys: Vec<String> = ctx
            .db()
            .get_setting_or(TRUSTED_KEYS_KEY, Vec::<String>::new())
            .await;
        Ok(ListOutput {
            plugins,
            extension_points: ExtensionPoint::ALL.iter().map(|p| p.as_str()).collect(),
            api_version: PLUGIN_API_VERSION,
            allow_unsigned,
            trusted_key_count: keys.len(),
        })
    }
}

#[derive(Debug, Deserialize)]
pub struct InstallInput {
    /// Absolute path to a staged plugin tree containing `plugin.toml`.
    pub source: String,
}

#[derive(Debug, Serialize)]
pub struct InstallOutput {
    pub plugin: PluginRecord,
    /// The signature's trusted comment, when there was one — minisign's own
    /// authenticated metadata field, usually the release it came from.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trusted_comment: Option<String>,
}

pub struct Install;

#[async_trait]
impl TypedOperation for Install {
    type Input = InstallInput;
    type Output = InstallOutput;

    const NAME: &'static str = "plugin.install";
    const PERMISSION: Permission = Permission::ServerManage;
    // A task: hashing a payload, creating an account and writing a unit is
    // comfortably past the 300 ms round-trip budget, and the verification
    // steps are exactly what an operator wants to read afterwards.
    const EXECUTION: Execution = Execution::Task {
        cancellable: false,
        // Not idempotent: a second run over the same slug is a conflict, and
        // an interrupted install leaves a tree the operator should look at
        // rather than one the agent should silently reattempt.
        idempotent: false,
    };

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let source = validate_source(&input.source)?;
        ctx.log(format!(
            "reading {}",
            paths::plugin_manifest(&source).display()
        ));

        let manifest_text = std::fs::read_to_string(paths::plugin_manifest(&source))
            .map_err(|e| FerrumError::new(ErrorCode::NotFound, format!("plugin.toml: {e}")))?;
        let (manifest, slug) = Manifest::parse(&manifest_text)?;
        ctx.log(format!(
            "manifest ok: {} {} ({})",
            manifest.name,
            manifest.version,
            manifest.extension_names().join(", ")
        ));

        // --- authenticity -------------------------------------------------
        let signature_path = paths::plugin_signature(&source);
        let (signature_state, trusted_comment) = match std::fs::read_to_string(&signature_path) {
            Ok(signature) => {
                let keys = trusted_keys(ctx).await?;
                if keys.is_empty() {
                    return Err(FerrumError::new(
                        ErrorCode::PermissionDenied,
                        format!(
                            "this plugin is signed, but no trusted keys are configured — \
                             set `{TRUSTED_KEYS_KEY}` to the publisher's minisign public key"
                        ),
                    ));
                }
                let comment = minisign::verify(manifest_text.as_bytes(), &signature, &keys)?;
                ctx.log(format!("signature verified ({comment})"));
                (PluginSignature::Minisign, Some(comment))
            }
            Err(_) => {
                let allowed = ctx.db().get_setting_or(ALLOW_UNSIGNED_KEY, false).await;
                if !allowed {
                    return Err(FerrumError::new(
                        ErrorCode::PermissionDenied,
                        format!(
                            "`{}` has no signature. A plugin is code this panel starts as a \
                             service as root's neighbour; installing an unsigned one is a \
                             decision an operator has to make on purpose. Set `{ALLOW_UNSIGNED_KEY}` \
                             to true if that is what you mean (see docs/plugins.md).",
                            signature_path.display()
                        ),
                    ));
                }
                ctx.log(
                    "WARNING: installing an unsigned plugin because plugins.allow_unsigned is on",
                );
                (PluginSignature::Unsigned, None)
            }
        };

        // --- integrity ----------------------------------------------------
        verify_tree(&source, &manifest)?;
        ctx.log(format!(
            "{} file(s) match their digests",
            manifest.files.len()
        ));

        // --- the row is the lock -------------------------------------------
        // Written before anything on disk changes, so two concurrent installs
        // of one slug cannot both create an account and a unit.
        let install_dir = paths::plugin_dir(slug.as_str());
        let run_user = slug.run_user();
        let record = ctx
            .db()
            .create_plugin(NewPlugin {
                slug: slug.as_str().to_string(),
                name: manifest.name.clone(),
                version: manifest.version.clone(),
                manifest: serde_json::to_value(&manifest)
                    .map_err(|e| FerrumError::internal(format!("manifest: {e}")))?,
                extensions: manifest.extension_names(),
                install_dir: install_dir.to_string_lossy().into_owned(),
                run_user: run_user.clone(),
                signature: signature_state,
            })
            .await
            .map_err(FerrumError::from)?;

        // From here on, a failure has to unwind the row — otherwise the panel
        // would list a plugin that has no unit and no account.
        let outcome = place(ctx, &source, &slug, &manifest, &install_dir, &run_user).await;
        if let Err(e) = outcome {
            let _ = ctx.db().delete_plugin(slug.as_str()).await;
            if install_dir.starts_with(paths::plugin_root()) {
                let _ = std::fs::remove_dir_all(&install_dir);
            }
            let _ = std::fs::remove_file(paths::plugin_unit(slug.as_str()));
            return Err(e);
        }

        ctx.log(format!(
            "installed, disabled — run plugin.enable to start {}",
            slug.as_str()
        ));
        Ok(InstallOutput {
            plugin: record,
            trusted_comment,
        })
    }
}

/// The on-disk half of an install: account, tree, unit — in that order.
///
/// The order is what makes the unwind in `Install::run` sufficient. The
/// account comes first because it is the only step that is *not* undone on
/// failure (a system account with no files is inert, and deleting one is how a
/// uid gets recycled onto files somebody still owns); the tree and the unit
/// are both removable, and both are removed together.
async fn place(
    ctx: &OpContext,
    source: &Path,
    slug: &PluginSlug,
    manifest: &Manifest,
    install_dir: &Path,
    run_user: &str,
) -> Result<()> {
    ensure_plugin_user(ctx, slug).await?;
    install_tree(source, install_dir, manifest)?;
    ctx.log(format!("payload installed at {}", install_dir.display()));
    apply_unit(ctx, slug, manifest, install_dir, run_user).await?;
    ctx.log(format!(
        "unit written: {}",
        paths::plugin_unit(slug.as_str()).display()
    ));
    Ok(())
}

#[derive(Debug, Deserialize)]
pub struct SlugInput {
    pub slug: String,
}

#[derive(Debug, Serialize)]
pub struct StateOutput {
    pub plugin: PluginRecord,
    pub unit_state: String,
}

pub struct Enable;

#[async_trait]
impl TypedOperation for Enable {
    type Input = SlugInput;
    type Output = StateOutput;

    const NAME: &'static str = "plugin.enable";
    const PERMISSION: Permission = Permission::ServerManage;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let slug = PluginSlug::parse(&input.slug)?;
        let record = ctx
            .db()
            .plugin_by_slug(slug.as_str())
            .await
            .map_err(FerrumError::from)?
            .ok_or_else(|| FerrumError::not_found("plugin"))?;

        ctx.distro()
            .svc
            .enable(&slug.unit(), true)
            .await
            .map_err(|e| {
                FerrumError::new(
                    ErrorCode::ServiceActionFailed,
                    format!("could not start the plugin sidecar: {e}"),
                )
            })?;

        let updated = ctx
            .db()
            .set_plugin_enabled(slug.as_str(), true)
            .await
            .map_err(FerrumError::from)?;
        let state = unit_state(ctx, &slug).await;
        let _ = record;
        Ok(StateOutput {
            plugin: updated,
            unit_state: state,
        })
    }
}

pub struct Disable;

#[async_trait]
impl TypedOperation for Disable {
    type Input = SlugInput;
    type Output = StateOutput;

    const NAME: &'static str = "plugin.disable";
    const PERMISSION: Permission = Permission::ServerManage;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let slug = PluginSlug::parse(&input.slug)?;
        // The row is flipped **first**. If systemd refuses to stop the unit,
        // the panel must still stop routing to it — a plugin the registry
        // thinks is enabled is a plugin the agent will happily dial.
        let updated = ctx
            .db()
            .set_plugin_enabled(slug.as_str(), false)
            .await
            .map_err(FerrumError::from)?;

        if let Err(e) = ctx.distro().svc.disable(&slug.unit(), true).await {
            let _ = ctx
                .db()
                .set_plugin_error(slug.as_str(), &e.to_string())
                .await;
            return Err(FerrumError::new(
                ErrorCode::ServiceActionFailed,
                format!("the plugin is disabled in the panel, but its unit did not stop: {e}"),
            ));
        }
        let state = unit_state(ctx, &slug).await;
        Ok(StateOutput {
            plugin: updated,
            unit_state: state,
        })
    }
}

#[derive(Debug, Serialize)]
pub struct RemoveOutput {
    pub slug: String,
    /// The account is deliberately left behind; this says so rather than
    /// leaving an operator to discover it.
    pub account_left_behind: String,
}

pub struct Remove;

#[async_trait]
impl TypedOperation for Remove {
    type Input = SlugInput;
    type Output = RemoveOutput;

    const NAME: &'static str = "plugin.remove";
    const PERMISSION: Permission = Permission::ServerManage;
    const EXECUTION: Execution = Execution::Task {
        cancellable: false,
        // Safe to re-run: every step is "make sure this is gone".
        idempotent: true,
    };

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let slug = PluginSlug::parse(&input.slug)?;
        let record = ctx
            .db()
            .plugin_by_slug(slug.as_str())
            .await
            .map_err(FerrumError::from)?
            .ok_or_else(|| FerrumError::not_found("plugin"))?;

        // Stop first, and do not let a stop failure strand the row: a unit
        // that is already gone reports an error that means "already done".
        if let Err(e) = ctx.distro().svc.disable(&slug.unit(), true).await {
            ctx.log(format!("stopping the sidecar: {e} (continuing)"));
        }

        let unit_path = paths::plugin_unit(slug.as_str());
        if unit_path.exists() {
            std::fs::remove_file(&unit_path)
                .map_err(|e| FerrumError::internal(format!("removing the unit: {e}")))?;
            let _ = ctx.distro().svc.daemon_reload().await;
        }
        let dir = PathBuf::from(&record.install_dir);
        // Only ever under the directory the panel owns: a hand-edited
        // `install_dir` must not be able to make this a recursive delete of
        // somewhere else.
        if dir.starts_with(paths::plugin_root()) && dir.exists() {
            std::fs::remove_dir_all(&dir)
                .map_err(|e| FerrumError::internal(format!("removing the tree: {e}")))?;
        }
        ctx.db()
            .delete_plugin(slug.as_str())
            .await
            .map_err(FerrumError::from)?;

        // The account stays. `userdel` on a system account that might still
        // own a file somewhere is how a uid gets recycled onto files nobody
        // meant to hand over; an operator who wants it gone can say so.
        Ok(RemoveOutput {
            slug: slug.as_str().to_string(),
            account_left_behind: record.run_user,
        })
    }
}

async fn unit_state(ctx: &OpContext, slug: &PluginSlug) -> String {
    match ctx.distro().svc.status(&slug.unit()).await {
        Ok(status) => format!("{:?}", status.state).to_lowercase(),
        Err(_) => format!("{:?}", UnitState::Unknown).to_lowercase(),
    }
}

/// Render and apply one plugin's unit file.
///
/// Public because the install path is the only caller today, but the shape —
/// render, `systemd-analyze verify`, `daemon-reload`, rollback on failure — is
/// the config engine's contract (spec §10.4) and belongs beside the template
/// rather than inline in an operation body.
pub async fn apply_unit(
    ctx: &OpContext,
    slug: &PluginSlug,
    manifest: &Manifest,
    install_dir: &Path,
    run_user: &str,
) -> Result<()> {
    let path = paths::plugin_unit(slug.as_str());
    let context = UnitContext {
        slug: slug.as_str().to_string(),
        run_user: run_user.to_string(),
        install_dir: install_dir.to_string_lossy().into_owned(),
        exec_start: install_dir
            .join(&manifest.entry)
            .to_string_lossy()
            .into_owned(),
        socket_path: paths::plugin_socket(slug.as_str())
            .to_string_lossy()
            .into_owned(),
        runtime_dir: paths::plugin_runtime_dir_relative(slug.as_str()),
        api_version: PLUGIN_API_VERSION,
        memory_max_mb: SIDECAR_MEMORY_MAX_MB,
    };

    ctx.config()
        .apply(ApplyRequest {
            file: managed_for(&path),
            template: "systemd/plugin.service",
            context: serde_json::json!({ "plugin": context }),
            service: SYSTEMD_SERVICE,
            validator: &UnitVerify { path: &path },
            reloader: &DaemonReload {
                distro: ctx.distro(),
            },
            post_check: None,
            force: false,
            task_id: ctx.task_id().map(|t| t.to_string()),
        })
        .await
        .map_err(FerrumError::from)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as B64;
    use std::collections::BTreeMap;

    // -- slugs ---------------------------------------------------------------

    #[test]
    fn a_slug_that_could_become_a_path_or_a_unit_of_its_choosing_is_refused() {
        for hostile in [
            "../etc",
            "a/b",
            "a.service",
            "a.b",
            "UPPER",
            "-leading",
            "trailing-",
            "with space",
            "wi%th",
            "",
            "  ",
            "a\nb",
            "toolongtoolongtoolong",
        ] {
            assert!(
                PluginSlug::parse(hostile).is_err(),
                "accepted the slug {hostile:?}"
            );
        }
        assert_eq!(PluginSlug::parse("acme-dns").unwrap().as_str(), "acme-dns");
        assert_eq!(
            PluginSlug::parse(" acme-dns ").unwrap().as_str(),
            "acme-dns"
        );
    }

    #[test]
    fn every_valid_slug_yields_a_valid_unit_name_and_a_short_enough_account() {
        for slug in ["a", "acme-dns", "0", "a-b-c-d-e-f-g-h-i-j"] {
            let parsed = PluginSlug::parse(slug).expect(slug);
            assert!(parsed.unit().as_str().ends_with(".service"));
            assert!(
                parsed.run_user().len() <= 32,
                "`{}` would not fit in a Unix account name",
                parsed.run_user()
            );
        }
    }

    // -- routing -------------------------------------------------------------

    #[test]
    fn a_method_outside_the_contract_maps_to_no_extension_point() {
        for junk in [
            "",
            "dns",
            "dns.",
            ".present",
            "../../etc/passwd",
            "registry.register",
            "sys.ping",
            "dns.Present",
            "dns.present.extra",
            "dns.pre sent",
        ] {
            assert!(
                extension_for_method(junk).is_none(),
                "`{junk}` was routed somewhere"
            );
        }
        assert_eq!(
            extension_for_method("dns.present"),
            Some(ExtensionPoint::DnsProvider)
        );
        assert_eq!(
            extension_for_method("notify.send"),
            Some(ExtensionPoint::Notifier)
        );
    }

    /// The central claim of the sidecar model: the manifest constrains what a
    /// plugin can be asked to do, and a running plugin cannot widen it.
    #[test]
    fn a_plugin_is_only_reachable_on_the_points_it_declared() {
        let declared = vec!["notifier".to_string()];
        assert!(route_allowed(&declared, "notify.send"));
        for elsewhere in [
            "dns.present",
            "backup.list",
            "app.definitions",
            "ui.panel",
            "sys.ping",
        ] {
            assert!(
                !route_allowed(&declared, elsewhere),
                "a notifier plugin was routed `{elsewhere}`"
            );
        }
    }

    #[test]
    fn every_extension_point_owns_a_distinct_namespace() {
        let mut namespaces: Vec<&str> = ExtensionPoint::ALL.iter().map(|p| p.namespace()).collect();
        namespaces.sort_unstable();
        let before = namespaces.len();
        namespaces.dedup();
        assert_eq!(before, namespaces.len(), "two points share a namespace");
    }

    // -- entry paths ---------------------------------------------------------

    #[test]
    fn an_entry_path_that_leaves_the_tree_or_confuses_systemd_is_refused() {
        for hostile in [
            "/usr/bin/env",
            "../../usr/bin/env",
            "bin/../../etc/passwd",
            "./bin/plugin",
            "bin/my plugin",
            "bin/plugin%n",
            "bin/plugin\"",
            "bin/plugin$PATH",
            "bin/plugin\nExecStart=/bin/sh",
            "",
        ] {
            assert!(
                validate_entry(hostile).is_err(),
                "accepted the entry {hostile:?}"
            );
        }
        assert!(validate_entry("bin/plugin").is_ok());
        assert!(validate_entry("plugin").is_ok());
    }

    // -- manifests -----------------------------------------------------------

    fn digest_of(bytes: &[u8]) -> String {
        hex::encode(Sha256::digest(bytes))
    }

    fn manifest_toml(files: &BTreeMap<String, String>, extra: &str) -> String {
        let mut out = String::from(
            "slug = \"acme-dns\"\n\
             name = \"ACME DNS\"\n\
             version = \"1.0.0\"\n\
             entry = \"bin/plugin\"\n\
             api_version = 1\n\
             extensions = [\"dns_provider\"]\n",
        );
        out.push_str(extra);
        out.push_str("\n[files]\n");
        for (path, digest) in files {
            out.push_str(&format!("\"{path}\" = \"{digest}\"\n"));
        }
        out
    }

    fn one_file_manifest() -> (String, Vec<u8>) {
        let payload = b"#!/bin/true\n".to_vec();
        let mut files = BTreeMap::new();
        files.insert("bin/plugin".to_string(), digest_of(&payload));
        (manifest_toml(&files, ""), payload)
    }

    #[test]
    fn a_well_formed_manifest_parses_into_its_declared_points() {
        let (text, _) = one_file_manifest();
        let (manifest, slug) = Manifest::parse(&text).unwrap();
        assert_eq!(slug.as_str(), "acme-dns");
        assert_eq!(manifest.extensions, vec![ExtensionPoint::DnsProvider]);
        assert_eq!(manifest.extension_names(), vec!["dns_provider".to_string()]);
    }

    #[test]
    fn a_manifest_for_another_protocol_version_is_refused_at_install_time() {
        let (text, _) = one_file_manifest();
        let bumped = text.replace("api_version = 1", "api_version = 2");
        let err = Manifest::parse(&bumped).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidInput);
        assert!(err.detail.contains("protocol"), "{}", err.detail);
    }

    #[test]
    fn a_manifest_must_declare_at_least_one_extension_point() {
        let (text, _) = one_file_manifest();
        let none = text.replace("extensions = [\"dns_provider\"]", "extensions = []");
        assert!(Manifest::parse(&none).is_err());
        let twice = text.replace(
            "extensions = [\"dns_provider\"]",
            "extensions = [\"dns_provider\", \"dns_provider\"]",
        );
        assert!(Manifest::parse(&twice).is_err());
    }

    #[test]
    fn an_unlisted_entry_point_is_refused_because_it_would_be_unverified() {
        let payload = b"#!/bin/true\n".to_vec();
        let mut files = BTreeMap::new();
        files.insert("bin/other".to_string(), digest_of(&payload));
        let text = manifest_toml(&files, "");
        let err = Manifest::parse(&text).unwrap_err();
        assert!(err.detail.contains("[files]"), "{}", err.detail);
    }

    #[test]
    fn a_digest_that_is_not_a_sha256_is_refused() {
        let mut files = BTreeMap::new();
        files.insert("bin/plugin".to_string(), "not-a-digest".to_string());
        assert!(Manifest::parse(&manifest_toml(&files, "")).is_err());
    }

    #[test]
    fn a_ui_mount_needs_the_ui_panel_point_and_a_slug_shaped_path() {
        let (text, _) = one_file_manifest();
        let with_ui = text.replace(
            "\n[files]",
            "\n[ui]\npath = \"acme\"\nlabel_en = \"ACME\"\nlabel_fa = \"ای‌سی‌ام‌ای\"\n\n[files]",
        );
        // Declared `dns_provider` only: the mount is refused.
        assert!(Manifest::parse(&with_ui).is_err());

        let both = with_ui.replace(
            "extensions = [\"dns_provider\"]",
            "extensions = [\"dns_provider\", \"ui_panel\"]",
        );
        assert!(Manifest::parse(&both).is_ok());

        // A mount that tries to name a route outside its own namespace.
        let escaping = both.replace("path = \"acme\"", "path = \"../../admin\"");
        assert!(Manifest::parse(&escaping).is_err());
    }

    // -- payload verification ------------------------------------------------

    fn staged() -> (tempfile::TempDir, Manifest) {
        let dir = tempfile::tempdir().unwrap();
        let (text, payload) = one_file_manifest();
        std::fs::create_dir_all(dir.path().join("bin")).unwrap();
        std::fs::write(dir.path().join("bin/plugin"), &payload).unwrap();
        std::fs::write(paths::plugin_manifest(dir.path()), &text).unwrap();
        let (manifest, _) = Manifest::parse(&text).unwrap();
        (dir, manifest)
    }

    #[test]
    fn a_tree_that_matches_its_manifest_verifies() {
        let (dir, manifest) = staged();
        verify_tree(dir.path(), &manifest).unwrap();
    }

    #[test]
    fn a_substituted_file_is_caught_by_its_digest() {
        let (dir, manifest) = staged();
        std::fs::write(dir.path().join("bin/plugin"), b"#!/bin/false\n").unwrap();
        let err = verify_tree(dir.path(), &manifest).unwrap_err();
        assert_eq!(err.code, ErrorCode::PermissionDenied);
    }

    /// The attack a one-directional checker misses: ship a second binary the
    /// manifest never mentions, and the signature over the manifest still
    /// verifies perfectly.
    #[test]
    fn an_extra_file_nobody_signed_for_is_refused() {
        let (dir, manifest) = staged();
        std::fs::write(dir.path().join("bin/backdoor"), b"anything\n").unwrap();
        let err = verify_tree(dir.path(), &manifest).unwrap_err();
        assert!(err.detail.contains("backdoor"), "{}", err.detail);
    }

    #[test]
    fn a_symlink_anywhere_in_the_payload_is_refused() {
        let (dir, manifest) = staged();
        std::os::unix::fs::symlink("/etc/shadow", dir.path().join("bin/secrets")).unwrap();
        let err = verify_tree(dir.path(), &manifest).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidPath);
        assert!(err.detail.contains("symlink"), "{}", err.detail);
    }

    #[test]
    fn a_missing_listed_file_is_refused() {
        let (dir, manifest) = staged();
        std::fs::remove_file(dir.path().join("bin/plugin")).unwrap();
        assert!(verify_tree(dir.path(), &manifest).is_err());
    }

    // -- source paths --------------------------------------------------------

    #[test]
    fn a_plugin_cannot_be_installed_from_a_place_the_tenant_controls() {
        assert!(validate_source("/home/ft_ab12cd34/staged").is_err());
        assert!(validate_source("relative/path").is_err());
        assert!(validate_source("/opt/../home/ft_ab/x").is_err());
        assert!(
            validate_source(&paths::plugin_dir("acme-dns").to_string_lossy()).is_err(),
            "the installed directory is not a staging area"
        );
        assert!(validate_source("/opt/staged/acme-dns").is_ok());
    }

    // -- minisign ------------------------------------------------------------

    struct TestSigner {
        key: ed25519_dalek::SigningKey,
        key_id: [u8; 8],
    }

    impl TestSigner {
        fn new(seed: u8, key_id: [u8; 8]) -> Self {
            Self {
                key: ed25519_dalek::SigningKey::from_bytes(&[seed; 32]),
                key_id,
            }
        }

        fn public_key(&self) -> String {
            let mut raw = vec![0x45, 0x64];
            raw.extend_from_slice(&self.key_id);
            raw.extend_from_slice(self.key.verifying_key().as_bytes());
            B64.encode(raw)
        }

        /// A minisign detached signature file. `prehashed` picks the `ED`
        /// algorithm current minisign emits by default; `false` picks the
        /// legacy `Ed`, which older signatures still use.
        fn sign_file(&self, message: &[u8], prehashed: bool, comment: &str) -> String {
            use ed25519_dalek::Signer;
            let (alg, signed): ([u8; 2], Vec<u8>) = if prehashed {
                use blake2::{Blake2b512, Digest as _};
                let mut h = Blake2b512::new();
                h.update(message);
                ([0x45, 0x44], h.finalize().to_vec())
            } else {
                ([0x45, 0x64], message.to_vec())
            };
            let sig = self.key.sign(&signed).to_bytes();

            let mut line2 = alg.to_vec();
            line2.extend_from_slice(&self.key_id);
            line2.extend_from_slice(&sig);

            let mut global_message = sig.to_vec();
            global_message.extend_from_slice(comment.as_bytes());
            let global = self.key.sign(&global_message).to_bytes();

            format!(
                "untrusted comment: signature from a test key\n{}\ntrusted comment: {comment}\n{}\n",
                B64.encode(line2),
                B64.encode(global)
            )
        }
    }

    #[test]
    fn a_signature_from_a_trusted_key_verifies_in_both_algorithms() {
        let signer = TestSigner::new(7, *b"ferrumid");
        let keys = vec![minisign::parse_public_key(&signer.public_key()).unwrap()];
        let message = b"slug = \"acme-dns\"\n";
        for prehashed in [true, false] {
            let sig = signer.sign_file(message, prehashed, "release 1.0.0");
            let comment = minisign::verify(message, &sig, &keys).unwrap();
            assert_eq!(comment, "release 1.0.0");
        }
    }

    #[test]
    fn a_signature_from_an_untrusted_key_is_refused_by_key_id() {
        let ours = TestSigner::new(7, *b"ferrumid");
        let theirs = TestSigner::new(9, *b"stranger");
        let keys = vec![minisign::parse_public_key(&ours.public_key()).unwrap()];
        let message = b"slug = \"acme-dns\"\n";
        let err =
            minisign::verify(message, &theirs.sign_file(message, true, "x"), &keys).unwrap_err();
        assert_eq!(err.code, ErrorCode::PermissionDenied);
        assert!(err.detail.contains("does not trust"), "{}", err.detail);
    }

    /// The key id is a hint, not a credential: a signature claiming a trusted
    /// key id but made with another key must still fail.
    #[test]
    fn a_forged_key_id_does_not_help_an_attacker() {
        let ours = TestSigner::new(7, *b"ferrumid");
        let forger = TestSigner::new(9, *b"ferrumid");
        let keys = vec![minisign::parse_public_key(&ours.public_key()).unwrap()];
        let message = b"slug = \"acme-dns\"\n";
        let err =
            minisign::verify(message, &forger.sign_file(message, true, "x"), &keys).unwrap_err();
        assert_eq!(err.code, ErrorCode::PermissionDenied);
        assert!(err.detail.contains("does not match"), "{}", err.detail);
    }

    #[test]
    fn a_tampered_manifest_fails_its_signature() {
        let signer = TestSigner::new(7, *b"ferrumid");
        let keys = vec![minisign::parse_public_key(&signer.public_key()).unwrap()];
        let sig = signer.sign_file(b"slug = \"acme-dns\"\n", true, "x");
        assert!(minisign::verify(b"slug = \"evil\"\n", &sig, &keys).is_err());
    }

    /// The implementation bug this test exists for: verifying the payload
    /// signature but not the global one leaves the "trusted" comment freely
    /// editable by anyone holding the file.
    #[test]
    fn an_edited_trusted_comment_is_caught() {
        let signer = TestSigner::new(7, *b"ferrumid");
        let keys = vec![minisign::parse_public_key(&signer.public_key()).unwrap()];
        let message = b"slug = \"acme-dns\"\n";
        let sig = signer.sign_file(message, true, "release 1.0.0");
        let edited = sig.replace(
            "trusted comment: release 1.0.0",
            "trusted comment: audited by nobody",
        );
        let err = minisign::verify(message, &edited, &keys).unwrap_err();
        assert!(err.detail.contains("trusted comment"), "{}", err.detail);
    }

    #[test]
    fn a_malformed_signature_file_is_a_named_error_not_a_panic() {
        let signer = TestSigner::new(7, *b"ferrumid");
        let keys = vec![minisign::parse_public_key(&signer.public_key()).unwrap()];
        for junk in [
            "",
            "untrusted comment: only\n",
            "untrusted comment: x\nnot-base64!!\ntrusted comment: y\nz\n",
            "untrusted comment: x\nAAAA\ntrusted comment: y\nAAAA\n",
        ] {
            assert!(minisign::verify(b"m", junk, &keys).is_err(), "{junk:?}");
        }
    }

    #[test]
    fn a_public_key_that_is_not_one_is_refused() {
        for junk in [
            String::new(),
            "hello".to_string(),
            B64.encode([0u8; 41]),
            B64.encode([9u8; 42]),
        ] {
            assert!(minisign::parse_public_key(&junk).is_err(), "{junk:?}");
        }
    }

    // -- the sidecar transport ----------------------------------------------

    /// A fake sidecar: one connection, one framed request, one framed reply.
    fn fake_sidecar(
        socket: PathBuf,
        reply: PluginResponse,
    ) -> tokio::task::JoinHandle<Option<PluginRequest>> {
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.ok()?;
            let frame = ferrum_ipc::codec::read_frame(&mut stream, MAX_PLUGIN_FRAME)
                .await
                .ok()??;
            let request: PluginRequest = serde_json::from_slice(&frame).ok()?;
            let body = serde_json::to_vec(&reply).ok()?;
            ferrum_ipc::codec::write_frame(&mut stream, &body)
                .await
                .ok()?;
            Some(request)
        })
    }

    #[tokio::test]
    async fn a_call_round_trips_over_the_panels_own_framing() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("plugin.sock");
        let server = fake_sidecar(
            socket.clone(),
            PluginResponse::Ok {
                data: serde_json::json!({ "records": ["a"] }),
            },
        );

        let data = call_at(
            &socket,
            "dns.present",
            serde_json::json!({ "zone": "a.example" }),
        )
        .await
        .unwrap();
        assert_eq!(data["records"][0], "a");

        let seen = server.await.unwrap().expect("the sidecar saw a request");
        assert_eq!(seen.method, "dns.present");
        assert_eq!(seen.v, PLUGIN_API_VERSION);
        assert_eq!(seen.params["zone"], "a.example");
    }

    #[tokio::test]
    async fn a_plugins_error_arrives_as_a_bounded_command_failure() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("plugin.sock");
        let server = fake_sidecar(
            socket.clone(),
            PluginResponse::Err {
                message: "x".repeat(10_000),
            },
        );

        let err = call_at(&socket, "dns.present", serde_json::json!({}))
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::CommandFailed);
        assert_eq!(
            err.detail.chars().count(),
            500,
            "third-party text on its way to an operator's screen must be bounded"
        );
        let _ = server.await;
    }

    #[tokio::test]
    async fn an_absent_sidecar_is_service_unavailable_not_a_hang() {
        let dir = tempfile::tempdir().unwrap();
        let err = call_at(
            &dir.path().join("nothing.sock"),
            "dns.present",
            serde_json::json!({}),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::ServiceUnavailable);
    }

    fn record(slug: &str, extensions: &[&str], enabled: bool) -> PluginRecord {
        PluginRecord {
            slug: slug.into(),
            name: "n".into(),
            version: "1".into(),
            manifest: serde_json::json!({}),
            extensions: extensions.iter().map(|e| (*e).to_string()).collect(),
            install_dir: paths::plugin_dir(slug).to_string_lossy().into_owned(),
            run_user: format!("ferrum-plug-{slug}"),
            signature: PluginSignature::Minisign,
            enabled,
            last_error: None,
            installed_at: ferrum_db::now(),
            updated_at: ferrum_db::now(),
        }
    }

    #[tokio::test]
    async fn an_undeclared_method_is_refused_without_opening_a_socket() {
        let plugin = record("acme-dns", &["notifier"], true);
        let err = call(&plugin, "dns.present", serde_json::json!({}))
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::PermissionDenied);
        assert!(err.detail.contains("extension point"), "{}", err.detail);
    }

    #[tokio::test]
    async fn a_disabled_plugin_is_not_dialled_at_all() {
        let plugin = record("acme-dns", &["dns_provider"], false);
        let err = call(&plugin, "dns.present", serde_json::json!({}))
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::ServiceUnavailable);
    }

    // -- install refusals ----------------------------------------------------

    #[tokio::test]
    async fn an_unsigned_plugin_is_refused_unless_the_operator_opted_in() {
        use crate::registry::testing::{auth_for, registry};
        use ferrum_core::Role;

        let (reg, admin, _) = registry().await;
        let ctx = OpContext::new(reg.services().clone(), auth_for(admin, Role::Admin));
        let (dir, _) = staged();

        let err = Install
            .run(
                &ctx,
                InstallInput {
                    source: dir.path().to_string_lossy().into_owned(),
                },
            )
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::PermissionDenied);
        assert!(
            err.detail.contains(ALLOW_UNSIGNED_KEY),
            "the refusal must name the setting that would allow it: {}",
            err.detail
        );

        // And nothing was recorded: a refused install leaves no row behind.
        assert!(reg.services().db.list_plugins().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_signed_plugin_with_no_trusted_keys_configured_is_refused() {
        use crate::registry::testing::{auth_for, registry};
        use ferrum_core::Role;

        let (reg, admin, _) = registry().await;
        let ctx = OpContext::new(reg.services().clone(), auth_for(admin, Role::Admin));
        let (dir, _) = staged();

        let signer = TestSigner::new(7, *b"ferrumid");
        let manifest_bytes = std::fs::read(paths::plugin_manifest(dir.path())).unwrap();
        std::fs::write(
            paths::plugin_signature(dir.path()),
            signer.sign_file(&manifest_bytes, true, "release"),
        )
        .unwrap();

        let err = Install
            .run(
                &ctx,
                InstallInput {
                    source: dir.path().to_string_lossy().into_owned(),
                },
            )
            .await
            .unwrap_err();
        assert!(
            err.detail.contains(TRUSTED_KEYS_KEY),
            "a signed plugin with nobody to trust must say so: {}",
            err.detail
        );
    }

    #[tokio::test]
    async fn a_signature_by_a_stranger_is_refused_even_with_keys_configured() {
        use crate::registry::testing::{auth_for, registry};
        use ferrum_core::Role;

        let (reg, admin, _) = registry().await;
        let ctx = OpContext::new(reg.services().clone(), auth_for(admin, Role::Admin));
        let ours = TestSigner::new(7, *b"ferrumid");
        let stranger = TestSigner::new(9, *b"stranger");
        reg.services()
            .db
            .set_setting(TRUSTED_KEYS_KEY, &vec![ours.public_key()])
            .await
            .unwrap();

        let (dir, _) = staged();
        let manifest_bytes = std::fs::read(paths::plugin_manifest(dir.path())).unwrap();
        std::fs::write(
            paths::plugin_signature(dir.path()),
            stranger.sign_file(&manifest_bytes, true, "release"),
        )
        .unwrap();

        let err = Install
            .run(
                &ctx,
                InstallInput {
                    source: dir.path().to_string_lossy().into_owned(),
                },
            )
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::PermissionDenied);
        assert!(reg.services().db.list_plugins().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_customer_cannot_install_or_enable_a_plugin() {
        use crate::registry::testing::{auth_for, registry};
        use ferrum_core::Role;

        let (reg, _, customer) = registry().await;
        for op in ["plugin.install", "plugin.enable", "plugin.remove"] {
            let err = reg
                .dispatch(
                    op,
                    &auth_for(customer, Role::Customer),
                    serde_json::json!({ "source": "/opt/x", "slug": "x" }),
                    None,
                )
                .await
                .unwrap_err();
            assert_eq!(err.code, ErrorCode::PermissionDenied, "{op}");
        }
    }

    #[tokio::test]
    async fn the_unit_template_renders_a_hardened_unprivileged_service() {
        use crate::registry::testing::{auth_for, registry};
        use ferrum_core::Role;

        let (reg, admin, _) = registry().await;
        let ctx = OpContext::new(reg.services().clone(), auth_for(admin, Role::Admin));
        let (text, _) = one_file_manifest();
        let (manifest, slug) = Manifest::parse(&text).unwrap();
        let install_dir = paths::plugin_dir(slug.as_str());

        let context = UnitContext {
            slug: slug.as_str().to_string(),
            run_user: slug.run_user(),
            install_dir: install_dir.to_string_lossy().into_owned(),
            exec_start: install_dir
                .join(&manifest.entry)
                .to_string_lossy()
                .into_owned(),
            socket_path: paths::plugin_socket(slug.as_str())
                .to_string_lossy()
                .into_owned(),
            runtime_dir: paths::plugin_runtime_dir_relative(slug.as_str()),
            api_version: PLUGIN_API_VERSION,
            memory_max_mb: SIDECAR_MEMORY_MAX_MB,
        };
        let rendered = ctx
            .config()
            .templates()
            .render(
                "systemd/plugin.service",
                &serde_json::json!({ "plugin": context }),
            )
            .expect("the plugin unit template renders");

        // Spec §6: a plugin must not run in-process as root. The unit is where
        // that promise is kept, so these are asserted rather than trusted.
        assert!(rendered.contains("User=ferrum-plug-acme-dns"));
        assert!(!rendered.contains("User=root"));
        for hardening in [
            "NoNewPrivileges=yes",
            "ProtectSystem=strict",
            "ProtectHome=yes",
            "PrivateTmp=yes",
            "CapabilityBoundingSet=\n",
            "AmbientCapabilities=\n",
            "RestrictSUIDSGID=yes",
            "SystemCallFilter=@system-service",
            "MemoryMax=128M",
        ] {
            assert!(
                rendered.contains(hardening),
                "the plugin unit is missing `{hardening}`:\n{rendered}"
            );
        }
        // Nothing in the tree is writable by the sidecar.
        assert!(
            !rendered.contains("ReadWritePaths="),
            "a plugin gets no writable path: it asks the agent instead"
        );
    }
}
