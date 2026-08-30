//! Reading a hostile tarball without extracting it (spec §11.15, §12 rule 5).
//!
//! A cpmove archive is a file somebody uploaded. It is the most obviously
//! attacker-controlled input the importer touches, and the dry run has to read
//! it *before* anything is created — which is precisely when a naive reader
//! would happily walk `../../etc/cron.d/` or unpack 40 GB of zeros.
//!
//! So this module is a **read-only pass**, and it shares its guards with the
//! file manager's extractor rather than restating them:
//!
//! * entry names go through [`archive::split_entry_name`] — the same function
//!   `fs.extract` uses, so `..`, absolute paths, backslash separators and NUL
//!   are refused rather than normalised;
//! * the entry count, the total uncompressed size and the compression ratio are
//!   counted by [`archive::Budget`] against [`archive::Limits`], the same three
//!   caps and the same numbers;
//! * symlink, hardlink and device entries are never followed and never
//!   recreated — they are *recorded*, so the plan can tell the operator that N
//!   links will not survive the import;
//! * an entry name that is not valid UTF-8 is skipped rather than lossily
//!   converted, because a mangled name that then passes the component checks is
//!   a name nobody reviewed.
//!
//! Nothing here writes into a tenant's home. [`restage_subtree`] writes one
//! *new* archive containing only the vetted subtree the plan named, and that
//! archive is then unpacked by `fs.extract` — which applies every guard above a
//! second time, as the tenant's own uid. The untrusted bytes never reach a
//! filesystem through a root-owned code path.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use unihelm_core::{ErrorCode, Result, UnihelmError};

use crate::fsops::archive::{self, Limits};
use crate::fsops::safepath::SafePath;

/// The most one metadata member may be. cPanel's `userdata/main` on a busy
/// account is a few kilobytes; 256 KB is far past anything legitimate and small
/// enough that a hostile archive full of "metadata" cannot exhaust memory.
pub const MAX_META_BYTES: u64 = 256 * 1024;

/// Total metadata one scan will buffer, across all members.
pub const MAX_META_TOTAL: u64 = 8 * 1024 * 1024;

/// How many entry names one scan will remember for the caller. The unmapped
/// list is meant to be read by a person; past a couple of thousand items it
/// stops being a list and becomes a count, and [`TarIndex::names_truncated`]
/// says which one the operator is looking at.
const MAX_NAMES: usize = 2_000;

/// How many distinct directories the size index will track. Past this the
/// per-directory totals stop being collected and [`TarIndex::truncated`] says
/// so — a plan that under-reports sizes must say it is under-reporting.
const MAX_TRACKED_DIRS: usize = 200_000;

/// What the caller wants of one member.
///
/// The importers know which paths matter; the scanner knows how to read them
/// safely. This enum is the whole interface between the two, and it is what
/// keeps the scan single-pass over what can be a multi-gigabyte file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Want {
    /// Not interesting; only its size is counted.
    Nothing,
    /// Remember the name (an unmappable object: a DNS zone, a certificate).
    Name,
    /// Buffer the bytes (a small metadata file the importer parses).
    Content,
}

/// What one pass over the tarball learned.
#[derive(Debug, Default)]
pub struct TarIndex {
    /// Members the caller asked to buffer, by their full entry path.
    pub metadata: BTreeMap<String, Vec<u8>>,
    /// Names the caller asked to remember, in archive order.
    pub names: Vec<String>,
    /// [`MAX_NAMES`] was reached and `names` is a sample, not the whole set.
    pub names_truncated: bool,
    /// Every `.sql` member and its uncompressed size.
    pub sql_members: Vec<(String, u64)>,
    /// Regular-file count and byte total per containing directory. Subtree
    /// totals are sums over the keys under a prefix — see [`TarIndex::subtree`].
    pub dir_stats: BTreeMap<String, (u64, u64)>,
    /// Distinct top-level components seen (`bob`, or `cpmove-bob`).
    pub top_level: Vec<String>,
    /// Entries that exist in the archive but will never be created: symlinks,
    /// hardlinks, devices, and names that are not valid UTF-8. Each is
    /// `(name, why)`.
    pub skipped: Vec<(String, &'static str)>,
    /// Total regular files and bytes across the whole archive.
    pub files: u64,
    pub bytes: u64,
    /// The per-directory index stopped early; sizes below are lower bounds.
    pub truncated: bool,
}

impl TarIndex {
    /// Files and bytes under one entry prefix (the prefix itself included).
    pub fn subtree(&self, prefix: &str) -> (u64, u64) {
        let with_slash = format!("{prefix}/");
        self.dir_stats
            .iter()
            .filter(|(dir, _)| dir.as_str() == prefix || dir.starts_with(&with_slash))
            .fold((0, 0), |(f, b), (_, (files, bytes))| (f + files, b + bytes))
    }

    /// Is there anything at all under this prefix?
    pub fn has_subtree(&self, prefix: &str) -> bool {
        let (files, _) = self.subtree(prefix);
        files > 0
    }
}

/// Counts the compressed bytes the decompressor pulls in, so the ratio cap can
/// be checked against what actually came off the disk. Same device as
/// [`archive`]'s extractor, for the same reason: a header can lie about a
/// member's size, the pipe cannot lie about how much it read.
struct CountingReader<R> {
    inner: R,
    count: Arc<AtomicU64>,
}

impl<R: Read> Read for CountingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.count.fetch_add(n as u64, Ordering::Relaxed);
        Ok(n)
    }
}

/// A decompressing tar reader plus the counter that says how many *compressed*
/// bytes it has pulled off the disk — the pair every guarded pass needs.
type GuardedTar = (tar::Archive<Box<dyn Read>>, Arc<AtomicU64>);

fn open_tar_gz(path: &Path) -> Result<GuardedTar> {
    let file = std::fs::File::open(path).map_err(|e| {
        UnihelmError::new(
            ErrorCode::NotFound,
            format!("cannot open {}: {e}", path.display()),
        )
    })?;
    let consumed = Arc::new(AtomicU64::new(0));
    let counting = CountingReader {
        inner: file,
        count: consumed.clone(),
    };
    // cpmove archives are gzip in every cPanel version that produces them. A
    // `.tar` with no compression also works: `MultiGzDecoder` would refuse it,
    // and `GzDecoder` is what the file manager uses, so the two stay in step.
    let reader: Box<dyn Read> = Box::new(flate2::read::GzDecoder::new(counting));
    Ok((tar::Archive::new(reader), consumed))
}

fn bad_archive(e: impl std::fmt::Display) -> UnihelmError {
    UnihelmError::new(
        ErrorCode::InvalidInput,
        format!("the archive is not readable: {e}"),
    )
}

/// One guarded pass over the archive.
///
/// `want` decides, per member, whether to remember its name or buffer its
/// bytes — the importer's own metadata files and the objects it will report as
/// unmappable, never anything from the payload.
pub fn index(path: &Path, want: &dyn Fn(&str) -> Want, limits: Limits) -> Result<TarIndex> {
    let (mut tar, consumed) = open_tar_gz(path)?;
    let mut budget = archive::Budget::new(limits);
    let mut out = TarIndex::default();
    let mut meta_total: u64 = 0;

    let entries = tar.entries().map_err(bad_archive)?;
    for entry in entries {
        let mut entry = entry.map_err(bad_archive)?;
        budget.count_entry().map_err(safe_err)?;

        // Not `from_utf8_lossy`: a name whose bad bytes were replaced would then
        // pass the component checks under a spelling nobody wrote.
        let Ok(raw_name) = String::from_utf8(entry.path_bytes().into_owned()) else {
            out.skipped.push((
                "<non-utf8 name>".into(),
                "the entry name is not valid UTF-8",
            ));
            continue;
        };

        use tar::EntryType;
        match entry.header().entry_type() {
            EntryType::Regular | EntryType::Continuous | EntryType::GNUSparse => {}
            EntryType::Directory => {
                // Validated for its own sake: a hostile `../` directory entry
                // must fail the scan, not be quietly ignored because a
                // directory carries no bytes.
                let components = archive::split_entry_name(&raw_name).map_err(safe_err)?;
                if let Some(first) = components.first()
                    && !out.top_level.iter().any(|t| t == first)
                {
                    out.top_level.push((*first).to_string());
                }
                continue;
            }
            EntryType::Symlink => {
                out.skipped
                    .push((raw_name, "symlinks are never recreated by an import"));
                continue;
            }
            EntryType::Link => {
                out.skipped
                    .push((raw_name, "hardlinks are never recreated by an import"));
                continue;
            }
            _ => {
                // Devices, fifos, sockets, and the PAX/GNU pseudo-entries the
                // tar crate did not fold away. Nothing a web home needs, and
                // creating a device node from an archive is a privilege bug.
                out.skipped.push((raw_name, "not a regular file"));
                continue;
            }
        }

        let components = archive::split_entry_name(&raw_name).map_err(safe_err)?;
        let size = entry.header().size().map_err(bad_archive)?;
        budget.count_bytes(size).map_err(safe_err)?;

        // The stream ratio cap, checked per entry rather than per chunk: this
        // pass does not read most bodies, so the granularity of "how much came
        // out" is one member. A 10 GB member declared inside a 2 MB tarball
        // fails here, before anything is read.
        let cap = consumed
            .load(Ordering::Relaxed)
            .saturating_mul(limits.ratio)
            .saturating_add(limits.grace);
        if budget.written > cap {
            return Err(UnihelmError::new(
                ErrorCode::InvalidInput,
                "the archive declares more content than its compressed size allows \
                 (compression-ratio cap)",
            ));
        }

        if let Some(first) = components.first()
            && !out.top_level.iter().any(|t| t == first)
        {
            out.top_level.push((*first).to_string());
        }

        out.files += 1;
        out.bytes += size;

        // Index by the *canonical* joined form, so a name written `./a//b` and
        // one written `a/b` land in the same bucket.
        let joined = components.join("/");
        if let Some((dir, _)) = joined.rsplit_once('/') {
            if out.dir_stats.len() < MAX_TRACKED_DIRS || out.dir_stats.contains_key(dir) {
                let slot = out.dir_stats.entry(dir.to_string()).or_insert((0, 0));
                slot.0 += 1;
                slot.1 += size;
            } else {
                out.truncated = true;
            }
        }

        if joined.ends_with(".sql") {
            out.sql_members.push((joined.clone(), size));
        }

        match want(&joined) {
            Want::Nothing => {}
            Want::Name => {
                if out.names.len() < MAX_NAMES {
                    out.names.push(joined);
                } else {
                    out.names_truncated = true;
                }
            }
            Want::Content => {
                // Both caps matter: one member cannot be huge, and a thousand
                // small ones cannot add up to huge either.
                if size <= MAX_META_BYTES && meta_total + size <= MAX_META_TOTAL {
                    let mut buffer = Vec::with_capacity(size as usize);
                    entry
                        .by_ref()
                        .take(size)
                        .read_to_end(&mut buffer)
                        .map_err(bad_archive)?;
                    meta_total += buffer.len() as u64;
                    out.metadata.insert(joined, buffer);
                } else {
                    // Silently dropping it would make the plan wrong in a way
                    // nobody could see.
                    out.skipped
                        .push((joined, "metadata member is too large to parse"));
                }
            }
        }
    }

    Ok(out)
}

/// Read one member's bytes, bounded.
///
/// Used at apply time for database dumps: the plan named the member and its
/// size, and this refuses to hand back anything bigger than `max` — a source
/// that grew between plan and apply does not get to be loaded unexamined.
pub fn read_member(path: &Path, member: &str, max: u64, limits: Limits) -> Result<Vec<u8>> {
    let (mut tar, _consumed) = open_tar_gz(path)?;
    let mut budget = archive::Budget::new(limits);

    for entry in tar.entries().map_err(bad_archive)? {
        let mut entry = entry.map_err(bad_archive)?;
        budget.count_entry().map_err(safe_err)?;
        let Ok(raw_name) = String::from_utf8(entry.path_bytes().into_owned()) else {
            continue;
        };
        if !matches!(
            entry.header().entry_type(),
            tar::EntryType::Regular | tar::EntryType::Continuous | tar::EntryType::GNUSparse
        ) {
            continue;
        }
        let components = archive::split_entry_name(&raw_name).map_err(safe_err)?;
        if components.join("/") != member {
            continue;
        }

        let size = entry.header().size().map_err(bad_archive)?;
        if size > max {
            return Err(UnihelmError::new(
                ErrorCode::InvalidInput,
                format!("`{member}` is {size} bytes, past the {max} byte limit for this member"),
            ));
        }
        let mut buffer = Vec::with_capacity(size as usize);
        // `take(max)` and not `take(size)`: the header's size is the archive's
        // claim, and reading past it is how a lying header gets to allocate.
        entry
            .by_ref()
            .take(max)
            .read_to_end(&mut buffer)
            .map_err(bad_archive)?;
        return Ok(buffer);
    }

    Err(UnihelmError::new(
        ErrorCode::NotFound,
        format!("`{member}` is not in {}", path.display()),
    ))
}

/// Build a new `.tar.gz` at `out` holding only the subtree under `prefix`, with
/// entry names rewritten relative to it.
///
/// This is how a planned document root reaches a tenant: never by extracting
/// the source archive (which would scatter mail directories and cPanel
/// bookkeeping through the home), but by re-tarring exactly the vetted subtree
/// the operator approved and handing *that* to `fs.extract`, which unpacks it
/// as the tenant's own uid.
///
/// Returns (files, bytes).
pub fn restage_subtree(
    source: &Path,
    prefix: &str,
    out: &SafePath,
    limits: Limits,
) -> Result<(u64, u64)> {
    use std::os::unix::fs::OpenOptionsExt;

    let with_slash = format!("{prefix}/");
    let (mut tar, consumed) = open_tar_gz(source)?;
    let mut budget = archive::Budget::new(limits);

    // `create_new` + `O_NOFOLLOW`: this file is created inside a directory the
    // tenant owns, so the one thing that must be impossible is writing
    // *through* something they put there first. A pre-existing name — file or
    // symlink — fails the open instead of being followed or truncated.
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(libc::O_NOFOLLOW)
        .mode(0o600)
        .open(out.as_path())
        .map_err(|e| {
            UnihelmError::new(
                ErrorCode::Internal,
                format!("cannot create the staging archive {}: {e}", out.relative()),
            )
        })?;

    let encoder = flate2::write::GzEncoder::new(file, flate2::Compression::fast());
    let mut builder = tar::Builder::new(encoder);
    builder.follow_symlinks(false);

    let mut files = 0u64;
    let mut bytes = 0u64;
    let result = (|| -> Result<()> {
        for entry in tar.entries().map_err(bad_archive)? {
            let mut entry = entry.map_err(bad_archive)?;
            budget.count_entry().map_err(safe_err)?;

            let Ok(raw_name) = String::from_utf8(entry.path_bytes().into_owned()) else {
                continue;
            };
            if !matches!(
                entry.header().entry_type(),
                tar::EntryType::Regular | tar::EntryType::Continuous | tar::EntryType::GNUSparse
            ) {
                // Directories are recreated implicitly by the extractor from
                // the file paths; everything else is deliberately dropped.
                continue;
            }

            let components = archive::split_entry_name(&raw_name).map_err(safe_err)?;
            let joined = components.join("/");
            let Some(relative) = joined.strip_prefix(&with_slash) else {
                continue;
            };
            // The rewritten name is re-validated: it is what the extractor will
            // act on, and a prefix strip is exactly the kind of edit that can
            // turn a checked name into an unchecked one.
            archive::split_entry_name(relative).map_err(safe_err)?;

            let size = entry.header().size().map_err(bad_archive)?;
            budget.count_bytes(size).map_err(safe_err)?;
            let cap = consumed
                .load(Ordering::Relaxed)
                .saturating_mul(limits.ratio)
                .saturating_add(limits.grace);
            if budget.written > cap {
                return Err(UnihelmError::new(
                    ErrorCode::InvalidInput,
                    "the archive decompresses past the allowed compression ratio",
                ));
            }

            let mut header = tar::Header::new_gnu();
            header.set_size(size);
            // Permissions come from the source, minus setuid/setgid/sticky —
            // the same mask `archive::restore_mode` applies. An import must not
            // be a way to introduce a setuid binary into a tenant's home.
            header.set_mode(entry.header().mode().unwrap_or(0o644) & 0o777);
            header.set_mtime(entry.header().mtime().unwrap_or(0));
            header.set_entry_type(tar::EntryType::Regular);
            builder
                .append_data(&mut header, relative, entry.by_ref().take(size))
                .map_err(|e| {
                    UnihelmError::new(
                        ErrorCode::Internal,
                        format!("cannot stage `{relative}`: {e}"),
                    )
                })?;
            files += 1;
            bytes += size;
        }
        Ok(())
    })();

    let finish = builder
        .into_inner()
        .and_then(|encoder| encoder.finish())
        .map_err(|e| UnihelmError::new(ErrorCode::Internal, format!("staging archive: {e}")));

    if let Err(e) = result.and(finish.map(drop)) {
        // A half-written staging archive must not be left where an extract
        // could find it.
        let _ = std::fs::remove_file(out.as_path());
        return Err(e);
    }

    Ok((files, bytes))
}

/// Map a guard failure onto the panel's taxonomy. Every one of these is
/// "the archive is not something we will act on", which is an input error.
fn safe_err(e: crate::fsops::safepath::SafeError) -> UnihelmError {
    UnihelmError::new(ErrorCode::InvalidInput, e.message)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Build a `.tar.gz` from `(name, mode, content)` triples, writing names
    /// into the raw GNU header so a test can produce names a builder would
    /// refuse — which is what an attacker's tarball looks like.
    pub(crate) fn tar_gz(path: &Path, entries: &[(&str, u32, &[u8])]) {
        let file = std::fs::File::create(path).unwrap();
        let encoder = flate2::write::GzEncoder::new(file, flate2::Compression::fast());
        let mut builder = tar::Builder::new(encoder);
        for (name, mode, content) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(content.len() as u64);
            header.set_mode(*mode);
            header.set_entry_type(tar::EntryType::Regular);
            let bytes = name.as_bytes();
            header.as_gnu_mut().unwrap().name[..bytes.len()].copy_from_slice(bytes);
            header.set_cksum();
            builder.append(&header, *content).unwrap();
        }
        builder.into_inner().unwrap().finish().unwrap();
    }

    fn tmp() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    fn no_meta(_: &str) -> Want {
        Want::Nothing
    }

    #[test]
    fn an_entry_that_escapes_the_archive_root_fails_the_scan() {
        let dir = tmp();
        let path = dir.path().join("evil.tar.gz");
        tar_gz(
            &path,
            &[("../../etc/cron.d/pwn", 0o644, b"* * * * * root id")],
        );

        let err = index(&path, &no_meta, Limits::default()).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidInput, "{}", err.detail);
        assert!(
            err.detail.contains(".."),
            "the refusal should quote the offending name: {}",
            err.detail
        );
    }

    #[test]
    fn an_absolute_entry_fails_the_scan() {
        let dir = tmp();
        let path = dir.path().join("evil.tar.gz");
        tar_gz(&path, &[("/etc/shadow", 0o600, b"root:x:")]);
        let err = index(&path, &no_meta, Limits::default()).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidInput, "{}", err.detail);
    }

    #[test]
    fn a_declared_size_far_past_the_compressed_size_is_refused() {
        // The tar header claims 8 GB inside a tarball of a few hundred bytes.
        // Nothing is read; the ratio cap fires on the claim itself.
        let dir = tmp();
        let path = dir.path().join("bomb.tar.gz");
        let file = std::fs::File::create(&path).unwrap();
        let encoder = flate2::write::GzEncoder::new(file, flate2::Compression::fast());
        let mut builder = tar::Builder::new(encoder);
        let mut header = tar::Header::new_gnu();
        header.set_size(8 * 1024 * 1024 * 1024);
        header.set_mode(0o644);
        header.set_entry_type(tar::EntryType::Regular);
        header.as_gnu_mut().unwrap().name[..8].copy_from_slice(b"bomb.bin");
        header.set_cksum();
        // The body is not written; the header's claim is what is under test,
        // and the scan must reject it before trying to account for it.
        builder.append(&header, std::io::empty()).unwrap();
        builder.into_inner().unwrap().finish().unwrap();

        let err = index(&path, &no_meta, Limits::default()).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidInput, "{}", err.detail);
    }

    #[test]
    fn the_entry_count_cap_stops_a_scan() {
        let dir = tmp();
        let path = dir.path().join("many.tar.gz");
        let entries: Vec<(String, u32, Vec<u8>)> = (0..10)
            .map(|i| (format!("bob/homedir/f{i}"), 0o644u32, b"x".to_vec()))
            .collect();
        let refs: Vec<(&str, u32, &[u8])> = entries
            .iter()
            .map(|(n, m, c)| (n.as_str(), *m, c.as_slice()))
            .collect();
        tar_gz(&path, &refs);

        let limits = Limits {
            max_entries: 4,
            ..Limits::default()
        };
        let err = index(&path, &no_meta, limits).unwrap_err();
        assert!(err.detail.contains("entries"), "{}", err.detail);
    }

    #[test]
    fn symlink_and_device_entries_are_recorded_and_never_acted_on() {
        let dir = tmp();
        let path = dir.path().join("links.tar.gz");
        let file = std::fs::File::create(&path).unwrap();
        let encoder = flate2::write::GzEncoder::new(file, flate2::Compression::fast());
        let mut builder = tar::Builder::new(encoder);

        let mut link = tar::Header::new_gnu();
        link.set_size(0);
        link.set_mode(0o777);
        link.set_entry_type(tar::EntryType::Symlink);
        link.as_gnu_mut().unwrap().name[..18].copy_from_slice(b"bob/homedir/secret");
        link.as_gnu_mut().unwrap().linkname[..11].copy_from_slice(b"/etc/shadow");
        link.set_cksum();
        builder.append(&link, std::io::empty()).unwrap();

        let mut dev = tar::Header::new_gnu();
        dev.set_size(0);
        dev.set_mode(0o666);
        dev.set_entry_type(tar::EntryType::Char);
        dev.as_gnu_mut().unwrap().name[..15].copy_from_slice(b"bob/homedir/tty");
        dev.set_cksum();
        builder.append(&dev, std::io::empty()).unwrap();
        builder.into_inner().unwrap().finish().unwrap();

        let idx = index(&path, &no_meta, Limits::default()).unwrap();
        assert_eq!(idx.files, 0, "neither entry is a file the import will copy");
        assert_eq!(idx.skipped.len(), 2);
        assert!(idx.skipped.iter().any(|(n, _)| n.contains("secret")));
    }

    #[test]
    fn the_index_reports_per_subtree_sizes() {
        let dir = tmp();
        let path = dir.path().join("acct.tar.gz");
        tar_gz(
            &path,
            &[
                ("bob/homedir/public_html/index.php", 0o644, b"<?php"),
                ("bob/homedir/public_html/a/b.css", 0o644, b"body{}"),
                ("bob/homedir/mail/x", 0o600, b"mail"),
            ],
        );
        let idx = index(&path, &no_meta, Limits::default()).unwrap();
        let (files, bytes) = idx.subtree("bob/homedir/public_html");
        assert_eq!(files, 2);
        assert_eq!(bytes, 5 + 6);
        assert!(idx.has_subtree("bob/homedir/mail"));
        assert_eq!(idx.top_level, vec!["bob".to_string()]);
    }

    #[test]
    fn requested_metadata_members_are_buffered_and_others_are_not() {
        let dir = tmp();
        let path = dir.path().join("acct.tar.gz");
        tar_gz(
            &path,
            &[
                ("bob/userdata/main", 0o644, b"main_domain: example.com\n"),
                ("bob/homedir/public_html/index.php", 0o644, b"<?php"),
            ],
        );
        let idx = index(
            &path,
            &|name| {
                if name.ends_with("userdata/main") {
                    Want::Content
                } else {
                    Want::Nothing
                }
            },
            Limits::default(),
        )
        .unwrap();
        assert_eq!(idx.metadata.len(), 1);
        assert!(
            idx.metadata
                .get("bob/userdata/main")
                .is_some_and(|b| b.starts_with(b"main_domain")),
        );
    }

    #[test]
    fn restaging_copies_only_the_named_subtree_and_strips_setuid() {
        let dir = tmp();
        let source = dir.path().join("acct.tar.gz");
        tar_gz(
            &source,
            &[
                ("bob/homedir/public_html/index.php", 0o4755, b"<?php"),
                ("bob/homedir/mail/secret", 0o600, b"private"),
            ],
        );

        let home = std::fs::canonicalize(dir.path()).unwrap();
        let (parent, name) =
            crate::fsops::safepath::resolve_new(&home, Path::new("staged.tar.gz")).unwrap();
        let out = crate::fsops::safepath::child(&parent, &name).unwrap();
        let (files, bytes) =
            restage_subtree(&source, "bob/homedir/public_html", &out, Limits::default()).unwrap();
        assert_eq!(files, 1);
        assert_eq!(bytes, 5);

        // Read the staged archive back: one entry, renamed relative to the
        // document root, with the setuid bit gone.
        let staged = std::fs::File::open(out.as_path()).unwrap();
        let mut tar = tar::Archive::new(flate2::read::GzDecoder::new(staged));
        let mut names = Vec::new();
        for entry in tar.entries().unwrap() {
            let entry = entry.unwrap();
            names.push(entry.path().unwrap().to_string_lossy().into_owned());
            assert_eq!(
                entry.header().mode().unwrap() & 0o7000,
                0,
                "setuid must not survive an import"
            );
        }
        assert_eq!(names, vec!["index.php".to_string()]);
    }

    #[test]
    fn restaging_refuses_to_write_over_an_existing_name() {
        let dir = tmp();
        let source = dir.path().join("acct.tar.gz");
        tar_gz(&source, &[("bob/homedir/public_html/i.php", 0o644, b"x")]);
        let home = std::fs::canonicalize(dir.path()).unwrap();
        std::fs::write(home.join("staged.tar.gz"), b"i was here").unwrap();

        let (parent, name) =
            crate::fsops::safepath::resolve_new(&home, Path::new("staged.tar.gz")).unwrap();
        let out = crate::fsops::safepath::child(&parent, &name).unwrap();
        let err = restage_subtree(&source, "bob/homedir/public_html", &out, Limits::default())
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::Internal, "{}", err.detail);
        assert_eq!(
            std::fs::read(home.join("staged.tar.gz")).unwrap(),
            b"i was here"
        );
    }

    #[test]
    fn reading_a_member_refuses_one_bigger_than_its_bound() {
        let dir = tmp();
        let path = dir.path().join("acct.tar.gz");
        tar_gz(
            &path,
            &[("bob/mysql/wp.sql", 0o644, b"INSERT INTO t VALUES (1);")],
        );

        assert_eq!(
            read_member(&path, "bob/mysql/wp.sql", 1024, Limits::default()).unwrap(),
            b"INSERT INTO t VALUES (1);"
        );
        let err = read_member(&path, "bob/mysql/wp.sql", 4, Limits::default()).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidInput, "{}", err.detail);
        let missing =
            read_member(&path, "bob/mysql/nope.sql", 1024, Limits::default()).unwrap_err();
        assert_eq!(missing.code, ErrorCode::NotFound);
    }
}
