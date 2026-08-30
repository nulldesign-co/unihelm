//! Compress and extract tenant archives — with the guards that make a hostile
//! archive boring (spec §11.7, §12 rule 5).
//!
//! Everything here runs inside the privilege-dropped helper, so the OS is the
//! last line of defence. These checks exist so it never gets that far:
//!
//! * **Path traversal**: every entry name is split into components and each
//!   component passes the same checks [`super::safepath`] applies to API paths
//!   (`..`, absolute, empty, NUL — all refused, never normalised away).
//! * **Symlinks**: a symlink *entry* is skipped, never created — recreating a
//!   tenant-authored link is how `evil -> /etc` appears inside a home. And a
//!   write never descends *through* a link: directories are created and entered
//!   with the same refuse-all-symlinks walk, and files open with `O_NOFOLLOW`.
//! * **Zip bombs**: an entry count cap, a total-uncompressed cap, and a
//!   compression-ratio cap enforced *while streaming*, so the abort happens a
//!   megabyte in, not ten gigabytes in.

use std::io::{Read, Write};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use super::proto::{ArchiveFormat, FsErrorKind};
use super::safepath::{SafeError, SafePath, SafeResult};

/// How much we read or write per step; bounds memory, and sets the granularity
/// of the ratio checks.
const CHUNK: usize = 64 * 1024;

/// The bomb guards. One struct so tests can shrink them to sizes a test can
/// afford to build; production always uses [`Limits::default`].
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// An archive with more members than this is refused outright.
    pub max_entries: u64,
    /// Total uncompressed bytes an extraction may produce.
    pub max_total_bytes: u64,
    /// Output may be at most `ratio` times the compressed input...
    pub ratio: u64,
    /// ...plus this flat grace, so a tiny, honestly-compressed file (an empty
    /// database dump, a run of zeros in a log) is not refused for compressing
    /// *well*. 1 MB of slack on a 200x ratio is noise against a 10 GB budget.
    pub grace: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_entries: 100_000,
            max_total_bytes: 10 * 1024 * 1024 * 1024, // 10 GB
            ratio: 200,
            grace: 1024 * 1024, // 1 MB
        }
    }
}

/// Running totals for one extraction, checked against [`Limits`].
///
/// `pub(crate)` for the same reason [`split_entry_name`] is: the importers'
/// tarball scan enforces the same three caps (entries, total bytes, ratio) on
/// the same counters, and a second implementation of "how big is too big"
/// would be a second place to get it wrong.
pub(crate) struct Budget {
    limits: Limits,
    entries: u64,
    pub(crate) written: u64,
}

impl Budget {
    pub(crate) fn new(limits: Limits) -> Self {
        Self {
            limits,
            entries: 0,
            written: 0,
        }
    }

    pub(crate) fn count_entry(&mut self) -> SafeResult<()> {
        self.entries += 1;
        if self.entries > self.limits.max_entries {
            return Err(SafeError::new(
                FsErrorKind::UnsafeArchive,
                format!(
                    "the archive has more than {} entries",
                    self.limits.max_entries
                ),
            ));
        }
        Ok(())
    }

    pub(crate) fn count_bytes(&mut self, n: u64) -> SafeResult<()> {
        self.written += n;
        if self.written > self.limits.max_total_bytes {
            return Err(SafeError::new(
                FsErrorKind::TooLarge,
                format!(
                    "the archive expands past the {} byte extraction budget",
                    self.limits.max_total_bytes
                ),
            ));
        }
        Ok(())
    }
}

fn unsafe_entry(name: &str, why: &str) -> SafeError {
    SafeError::new(
        FsErrorKind::UnsafeArchive,
        format!("archive entry `{name}`: {why}"),
    )
}

// ---------------------------------------------------------------------------
// entry names
// ---------------------------------------------------------------------------

/// Split an archive entry name into components, refusing every shape a safe
/// relative path cannot have.
///
/// The component rules themselves live in [`SafePath::join_entry`] and are
/// applied again when the path is walked; this pass exists to reject the whole
/// name up front with an error that quotes it, and to strip the trailing `/`
/// a directory entry carries.
///
/// `pub(crate)` for the migration importers (spec §11.15): scanning a cpmove
/// tarball is a *read-only* pass and cannot reuse [`extract`], but it must
/// refuse exactly the same entry names — so it calls this rather than growing
/// a second, quietly divergent opinion about what a safe entry name is.
pub(crate) fn split_entry_name(name: &str) -> SafeResult<Vec<&str>> {
    if name.contains('\0') {
        return Err(unsafe_entry("<nul>", "name contains a NUL byte"));
    }
    if name.starts_with('/') {
        return Err(unsafe_entry(
            name,
            "absolute paths cannot come from a tenant archive",
        ));
    }
    // Windows-made archives sometimes separate with `\`. Treating it as a
    // literal character would let `..\..\x` pass the `/`-split checks below,
    // so it is refused rather than interpreted.
    if name.contains('\\') {
        return Err(unsafe_entry(
            name,
            "backslashes are not accepted in entry names",
        ));
    }

    let mut parts = Vec::new();
    for part in name.split('/') {
        match part {
            // `a//b` and the trailing `/` of a directory entry.
            "" => continue,
            "." => continue,
            ".." => {
                return Err(unsafe_entry(
                    name,
                    "path traversal (`..`) is refused, not normalised",
                ));
            }
            p => parts.push(p),
        }
    }
    if parts.is_empty() {
        return Err(unsafe_entry(name, "the name is empty"));
    }
    Ok(parts)
}

/// Step into `comp` under `dir`, creating it as a real directory if missing.
///
/// The refusal cases mirror [`super::helper`]'s `make_parents`: an existing
/// symlink is an escape (even one that points inside the home — it can be
/// repointed), and an existing file is a name collision, not something to
/// write through.
fn descend_create(dir: &SafePath, comp: &str) -> SafeResult<SafePath> {
    let next = dir.join_entry(comp)?;
    match std::fs::symlink_metadata(next.as_path()) {
        Ok(meta) if meta.file_type().is_symlink() => Err(SafeError::escape(next.as_path())),
        Ok(meta) if meta.is_dir() => Ok(next),
        Ok(_) => Err(SafeError::new(
            FsErrorKind::NotADirectory,
            format!("`{}` exists and is not a directory", next.relative()),
        )),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir(next.as_path()).map_err(|e| SafeError::io(next.as_path(), &e))?;
            Ok(next)
        }
        Err(e) => Err(SafeError::io(next.as_path(), &e)),
    }
}

/// Resolve where an entry's bytes will land: create the directory chain, and
/// return the final component's [`SafePath`].
fn entry_target(dest: &SafePath, components: &[&str]) -> SafeResult<SafePath> {
    let (name, dirs) = components
        .split_last()
        .expect("split_entry_name is non-empty");
    let mut dir = dest.clone();
    for comp in dirs {
        dir = descend_create(&dir, comp)?;
    }
    dir.join_entry(name)
}

/// Open an extraction target for writing.
///
/// `O_NOFOLLOW` is the point: [`entry_target`] proved there is no symlink in
/// the way *at check time*, and this makes the open itself fail if one appears
/// between the check and the use, instead of following it somewhere the tenant
/// chose. Overwriting a plain existing file is allowed — re-extracting an
/// archive over itself is the most common extract there is.
fn open_target(path: &SafePath) -> SafeResult<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;

    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path.as_path())
        .map_err(|e| SafeError::io(path.as_path(), &e))
}

/// Copy at most `max` bytes, running `check` (budget and ratio) every chunk.
///
/// Exceeding `max` is an [`FsErrorKind::UnsafeArchive`]: the entry produced
/// more bytes than its own declared/compressed size allows, which is the
/// definition of a bomb. The partial file is the caller's to clean up.
fn guarded_copy(
    src: &mut impl Read,
    dst: &mut impl Write,
    max: u64,
    check: &mut impl FnMut(u64) -> SafeResult<()>,
) -> SafeResult<u64> {
    let mut copied: u64 = 0;
    let mut buffer = vec![0u8; CHUNK];
    loop {
        let n = src
            .read(&mut buffer)
            .map_err(|e| SafeError::new(FsErrorKind::from_io(&e), format!("read: {e}")))?;
        if n == 0 {
            return Ok(copied);
        }
        copied += n as u64;
        if copied > max {
            return Err(SafeError::new(
                FsErrorKind::UnsafeArchive,
                "an entry decompressed past what its compressed size allows",
            ));
        }
        check(n as u64)?;
        dst.write_all(&buffer[..n])
            .map_err(|e| SafeError::new(FsErrorKind::from_io(&e), format!("write: {e}")))?;
    }
}

/// Counts compressed bytes as the decompressor pulls them through, so the
/// ratio check can compare what came *out* against what actually went *in*
/// (headers can lie; the pipe cannot).
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

// ---------------------------------------------------------------------------
// extract
// ---------------------------------------------------------------------------

/// Extract `archive` into the directory `dest`. Returns (files, bytes).
pub fn extract(archive: &SafePath, dest: &SafePath) -> SafeResult<(u64, u64)> {
    extract_with_limits(archive, dest, Limits::default())
}

pub(crate) fn extract_with_limits(
    archive: &SafePath,
    dest: &SafePath,
    limits: Limits,
) -> SafeResult<(u64, u64)> {
    let name = archive
        .as_path()
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default();
    let format = ArchiveFormat::from_name(name).ok_or_else(|| {
        SafeError::new(
            FsErrorKind::Invalid,
            format!("`{name}` is not a recognised archive format"),
        )
    })?;

    if !std::fs::metadata(dest.as_path())
        .map(|m| m.is_dir())
        .unwrap_or(false)
    {
        return Err(SafeError::new(
            FsErrorKind::NotADirectory,
            format!("`{}` is not a directory", dest.relative()),
        ));
    }

    match format {
        ArchiveFormat::Zip => extract_zip(archive, dest, limits),
        ArchiveFormat::TarGz | ArchiveFormat::TarZst => extract_tar(archive, dest, format, limits),
    }
}

fn extract_zip(archive: &SafePath, dest: &SafePath, limits: Limits) -> SafeResult<(u64, u64)> {
    let file =
        std::fs::File::open(archive.as_path()).map_err(|e| SafeError::io(archive.as_path(), &e))?;
    let mut zip = zip::ZipArchive::new(file).map_err(|e| zip_error(archive.as_path(), e))?;

    // The member count is in the end-of-central-directory record, so this cap
    // is checked before a single entry is touched.
    if zip.len() as u64 > limits.max_entries {
        return Err(SafeError::new(
            FsErrorKind::UnsafeArchive,
            format!("the archive has more than {} entries", limits.max_entries),
        ));
    }

    let mut budget = Budget::new(limits);
    let mut files = 0u64;

    for index in 0..zip.len() {
        let mut entry = zip
            .by_index(index)
            .map_err(|e| zip_error(archive.as_path(), e))?;
        budget.count_entry()?;

        let raw_name = entry.name().to_string();
        let components = split_entry_name(&raw_name)?;

        if entry.is_dir() {
            let mut dir = dest.clone();
            for comp in &components {
                dir = descend_create(&dir, comp)?;
            }
            continue;
        }

        // A zip symlink is a file entry whose mode says S_IFLNK and whose body
        // is the target. Skipped, not created (spec §11.7 AC): materialising it
        // would plant a tenant-chosen redirection for every later operation.
        if entry.unix_mode().is_some_and(|m| m & 0o170000 == 0o120000) {
            continue;
        }

        // Per-file ratio cap, from the entry's own compressed size. The
        // declared uncompressed size is checked first (an honest bomb), and
        // the stream is capped anyway (a lying one).
        let allowed = entry
            .compressed_size()
            .saturating_mul(limits.ratio)
            .saturating_add(limits.grace);
        if entry.size() > allowed {
            return Err(unsafe_entry(
                &raw_name,
                "declared size exceeds the ratio cap",
            ));
        }

        let target = entry_target(dest, &components)?;
        let mut out = open_target(&target)?;
        guarded_copy(&mut entry, &mut out, allowed, &mut |n| {
            budget.count_bytes(n)
        })
        .inspect_err(|_| {
            // Never leave a half-written bomb fragment behind.
            let _ = std::fs::remove_file(target.as_path());
        })?;

        restore_mode(&target, entry.unix_mode());
        files += 1;
    }

    Ok((files, budget.written))
}

fn extract_tar(
    archive: &SafePath,
    dest: &SafePath,
    format: ArchiveFormat,
    limits: Limits,
) -> SafeResult<(u64, u64)> {
    let file =
        std::fs::File::open(archive.as_path()).map_err(|e| SafeError::io(archive.as_path(), &e))?;
    let consumed = Arc::new(AtomicU64::new(0));
    let counting = CountingReader {
        inner: file,
        count: consumed.clone(),
    };

    let reader: Box<dyn Read> = match format {
        ArchiveFormat::TarGz => Box::new(flate2::read::GzDecoder::new(counting)),
        ArchiveFormat::TarZst => Box::new(
            zstd::stream::read::Decoder::new(counting)
                .map_err(|e| SafeError::io(archive.as_path(), &e))?,
        ),
        ArchiveFormat::Zip => unreachable!("zip is handled by extract_zip"),
    };

    let mut tar = tar::Archive::new(reader);
    let mut budget = Budget::new(limits);
    let mut files = 0u64;

    let entries = tar
        .entries()
        .map_err(|e| SafeError::io(archive.as_path(), &e))?;
    for entry in entries {
        let mut entry = entry.map_err(|e| SafeError::io(archive.as_path(), &e))?;
        budget.count_entry()?;

        let raw_name = String::from_utf8_lossy(&entry.path_bytes()).into_owned();
        use tar::EntryType;
        match entry.header().entry_type() {
            EntryType::Directory => {
                let components = split_entry_name(&raw_name)?;
                let mut dir = dest.clone();
                for comp in &components {
                    dir = descend_create(&dir, comp)?;
                }
            }
            EntryType::Regular | EntryType::Continuous | EntryType::GNUSparse => {
                let components = split_entry_name(&raw_name)?;
                let target = entry_target(dest, &components)?;
                let mut out = open_target(&target)?;

                // The tar reader itself stops each entry at its header's size,
                // so `max` here is the extraction budget; what makes a tar
                // bomb fail is the *stream* ratio below — output measured
                // against compressed bytes actually consumed from the disk.
                let declared = entry
                    .header()
                    .size()
                    .map_err(|e| SafeError::io(archive.as_path(), &e))?;
                let consumed = consumed.clone();
                let ratio_err = || {
                    SafeError::new(
                        FsErrorKind::UnsafeArchive,
                        "the archive decompresses past the allowed compression ratio",
                    )
                };
                guarded_copy(&mut entry, &mut out, declared, &mut |n| {
                    budget.count_bytes(n)?;
                    let cap = consumed
                        .load(Ordering::Relaxed)
                        .saturating_mul(limits.ratio)
                        .saturating_add(limits.grace);
                    if budget.written > cap {
                        return Err(ratio_err());
                    }
                    Ok(())
                })
                .inspect_err(|_| {
                    let _ = std::fs::remove_file(target.as_path());
                })?;

                restore_mode(&target, entry.header().mode().ok());
                files += 1;
            }
            // Symlinks and hardlinks are *skipped*, not created (spec §11.7
            // AC). A later entry whose path runs "through" the skipped link
            // then lands in a real directory created by `descend_create`, or
            // is refused if something else sits at that name — either way the
            // link target is never touched.
            EntryType::Symlink | EntryType::Link => continue,
            // Character/block devices, fifos, and the metadata pseudo-entries
            // (PAX headers, GNU long names the tar crate did not fold away):
            // nothing a web hosting home has a use for.
            _ => continue,
        }
    }

    Ok((files, budget.written))
}

/// Re-apply an entry's permission bits, through the same setuid/setgid filter
/// the file manager's own chmod applies.
fn restore_mode(path: &SafePath, mode: Option<u32>) {
    use std::os::unix::fs::PermissionsExt;

    let Some(mode) = mode else { return };
    let mode = mode & 0o777; // never setuid/setgid/sticky from an archive
    if mode == 0 {
        return;
    }
    let _ = std::fs::set_permissions(path.as_path(), std::fs::Permissions::from_mode(mode));
}

fn zip_error(path: &Path, e: zip::result::ZipError) -> SafeError {
    use zip::result::ZipError;
    match e {
        ZipError::Io(io) => SafeError::io(path, &io),
        ZipError::FileNotFound => SafeError::new(FsErrorKind::NotFound, "no such archive member"),
        other => SafeError::new(FsErrorKind::Invalid, format!("{}: {other}", path.display())),
    }
}

// ---------------------------------------------------------------------------
// compress
// ---------------------------------------------------------------------------

/// Build `out` from `entries` (one-level names under `root`). Returns the
/// archive's size in bytes.
///
/// Symlinks anywhere in the selected trees are skipped, the same policy as
/// copy: an archive is a way files leave the home, and a link is an address,
/// not a file.
pub fn compress(
    root: &SafePath,
    entries: &[String],
    out: &SafePath,
    format: ArchiveFormat,
) -> SafeResult<u64> {
    use std::os::unix::fs::OpenOptionsExt;

    if entries.is_empty() {
        return Err(SafeError::new(
            FsErrorKind::Invalid,
            "nothing selected to compress",
        ));
    }

    // `create_new`: refusing to overwrite means a stray second click cannot
    // silently replace an archive that finished a second ago.
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(out.as_path())
        .map_err(|e| SafeError::io(out.as_path(), &e))?;

    let result = match format {
        ArchiveFormat::Zip => compress_zip(root, entries, file),
        ArchiveFormat::TarGz => {
            let encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
            compress_tar(root, entries, encoder)
                .and_then(|e| e.finish().map_err(|e| SafeError::io(out.as_path(), &e)))
                .map(drop)
        }
        ArchiveFormat::TarZst => {
            // Level 3 is zstd's own default: the speed/size point the format
            // is chosen for.
            let encoder = zstd::stream::write::Encoder::new(file, 3)
                .map_err(|e| SafeError::io(out.as_path(), &e))?;
            compress_tar(root, entries, encoder)
                .and_then(|e| e.finish().map_err(|e| SafeError::io(out.as_path(), &e)))
                .map(drop)
        }
    };

    if let Err(e) = result {
        // A failed build must not leave a half-archive that looks downloadable.
        let _ = std::fs::remove_file(out.as_path());
        return Err(e);
    }

    std::fs::metadata(out.as_path())
        .map(|m| m.len())
        .map_err(|e| SafeError::io(out.as_path(), &e))
}

/// What [`walk_tree`] found at one path.
enum TreeItem {
    Dir,
    File { size: u64, mode: u32 },
}

/// Depth-first over one selected tree, calling `visit` with the path inside
/// the archive. Symlinks are skipped wherever they appear.
fn walk_tree(
    path: &SafePath,
    rel: &str,
    visit: &mut impl FnMut(&SafePath, &str, TreeItem) -> SafeResult<()>,
) -> SafeResult<()> {
    use std::os::unix::fs::PermissionsExt;

    let meta =
        std::fs::symlink_metadata(path.as_path()).map_err(|e| SafeError::io(path.as_path(), &e))?;
    if meta.file_type().is_symlink() {
        return Ok(());
    }

    if meta.is_file() {
        return visit(
            path,
            rel,
            TreeItem::File {
                size: meta.len(),
                mode: meta.permissions().mode() & 0o777,
            },
        );
    }
    if !meta.is_dir() {
        // Sockets and fifos have no archive representation worth keeping.
        return Ok(());
    }

    visit(path, rel, TreeItem::Dir)?;
    let read = std::fs::read_dir(path.as_path()).map_err(|e| SafeError::io(path.as_path(), &e))?;
    for item in read {
        let Ok(item) = item else { continue };
        let Some(name) = item.file_name().to_str().map(str::to_string) else {
            continue;
        };
        let Ok(child) = path.join_entry(&name) else {
            continue;
        };
        walk_tree(&child, &format!("{rel}/{name}"), visit)?;
    }
    Ok(())
}

/// Open a file for archiving without following a symlink swapped in after the
/// `symlink_metadata` check.
fn open_source(path: &SafePath) -> SafeResult<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;

    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path.as_path())
        .map_err(|e| SafeError::io(path.as_path(), &e))
}

fn compress_zip(root: &SafePath, entries: &[String], file: std::fs::File) -> SafeResult<()> {
    use zip::write::SimpleFileOptions;

    let mut zip = zip::ZipWriter::new(file);
    let base = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);

    for name in entries {
        let start = root.join_entry(name)?;
        walk_tree(&start, name, &mut |path, rel, item| match item {
            TreeItem::Dir => zip
                .add_directory(format!("{rel}/"), base)
                .map_err(|e| zip_error(path.as_path(), e)),
            TreeItem::File { size, mode } => {
                let options = base
                    .unix_permissions(mode)
                    // zip32 tops out at 4 GB; declare zip64 for anything that
                    // could plausibly cross it rather than fail at write time.
                    .large_file(size >= 0xFFFF_0000);
                zip.start_file(rel, options)
                    .map_err(|e| zip_error(path.as_path(), e))?;
                let mut src = open_source(path)?;
                std::io::copy(&mut src, &mut zip).map_err(|e| SafeError::io(path.as_path(), &e))?;
                Ok(())
            }
        })?;
    }

    zip.finish()
        .map(drop)
        .map_err(|e| zip_error(root.as_path(), e))
}

fn compress_tar<W: Write>(root: &SafePath, entries: &[String], writer: W) -> SafeResult<W> {
    let mut tar = tar::Builder::new(writer);
    // Symlinks are skipped by the walk before the builder ever sees one; this
    // is belt to that suspender.
    tar.follow_symlinks(false);

    for name in entries {
        let start = root.join_entry(name)?;
        walk_tree(&start, name, &mut |path, rel, item| match item {
            TreeItem::Dir => tar
                .append_dir(rel, path.as_path())
                .map_err(|e| SafeError::io(path.as_path(), &e)),
            TreeItem::File { .. } => {
                let mut src = open_source(path)?;
                tar.append_file(rel, &mut src)
                    .map_err(|e| SafeError::io(path.as_path(), &e))
            }
        })?;
    }

    tar.into_inner()
        .map_err(|e| SafeError::io(root.as_path(), &e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fsops::safepath;
    use std::path::PathBuf;

    struct Home {
        _dir: tempfile::TempDir,
        path: PathBuf,
    }

    impl Home {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            // The temp dir may itself be a symlink (/var -> /private/var on
            // macOS); hand around the canonical form like the real agent does.
            let path = std::fs::canonicalize(dir.path()).unwrap();
            Self { _dir: dir, path }
        }

        fn root(&self) -> SafePath {
            safepath::resolve(&self.path, Path::new("")).unwrap()
        }

        fn make_dest(&self, name: &str) -> SafePath {
            std::fs::create_dir(self.path.join(name)).unwrap();
            safepath::resolve(&self.path, Path::new(name)).unwrap()
        }

        fn write(&self, rel: &str, content: &[u8]) {
            let p = self.path.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, content).unwrap();
        }

        fn safe(&self, rel: &str) -> SafePath {
            safepath::resolve(&self.path, Path::new(rel)).unwrap()
        }

        /// A [`SafePath`] for a file that does not exist yet — the archive
        /// about to be written, resolved the way the helper resolves it.
        fn safe_new(&self, rel: &str) -> SafePath {
            let (dir, name) = safepath::resolve_new(&self.path, Path::new(rel)).unwrap();
            safepath::child(&dir, &name).unwrap()
        }
    }

    fn tiny_limits() -> Limits {
        Limits {
            max_entries: 4,
            max_total_bytes: 1024,
            ratio: 200,
            grace: 1024 * 1024,
        }
    }

    // -- round trips --------------------------------------------------------

    #[test]
    fn every_format_survives_a_compress_extract_round_trip() {
        for (format, archive_name) in [
            (ArchiveFormat::Zip, "site.zip"),
            (ArchiveFormat::TarGz, "site.tar.gz"),
            (ArchiveFormat::TarZst, "site.tar.zst"),
        ] {
            let home = Home::new();
            home.write("src/index.php", b"<?php echo 1;");
            home.write("src/assets/app.css", b"body{}");

            let root = home.root();
            compress(&root, &["src".into()], &home.safe_new(archive_name), format)
                .unwrap_or_else(|e| panic!("{archive_name}: {e:?}", e = e.message));

            let dest = home.make_dest("out");
            let (files, bytes) = extract(&home.safe(archive_name), &dest)
                .unwrap_or_else(|e| panic!("{archive_name}: {}", e.message));
            assert_eq!(files, 2, "{archive_name}");
            assert!(bytes > 0, "{archive_name}");
            assert_eq!(
                std::fs::read(home.path.join("out/src/index.php")).unwrap(),
                b"<?php echo 1;",
                "{archive_name}"
            );
            assert_eq!(
                std::fs::read(home.path.join("out/src/assets/app.css")).unwrap(),
                b"body{}",
                "{archive_name}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_in_the_source_tree_is_left_out_of_the_archive() {
        let home = Home::new();
        home.write("src/real.txt", b"data");
        std::os::unix::fs::symlink("/etc/passwd", home.path.join("src/leak")).unwrap();

        let root = home.root();
        compress(
            &root,
            &["src".into()],
            &home.safe_new("a.tar.gz"),
            ArchiveFormat::TarGz,
        )
        .unwrap();

        let dest = home.make_dest("out");
        let (files, _) = extract(&home.safe("a.tar.gz"), &dest).unwrap();
        assert_eq!(files, 1, "only the real file");
        assert!(!home.path.join("out/src/leak").exists());
    }

    // -- hostile entry names ------------------------------------------------

    fn tar_gz_with_entry(home: &Home, archive: &str, name: &[u8], content: &[u8]) {
        let file = std::fs::File::create(home.path.join(archive)).unwrap();
        let encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
        let mut tar = tar::Builder::new(encoder);

        let mut header = tar::Header::new_gnu();
        header.set_size(content.len() as u64);
        header.set_mode(0o644);
        header.set_entry_type(tar::EntryType::Regular);
        // Write the name into the raw header field, bypassing any sanitising
        // the builder might do: this is what an attacker's tar looks like.
        header.as_gnu_mut().unwrap().name[..name.len()].copy_from_slice(name);
        header.set_cksum();
        tar.append(&header, content).unwrap();
        tar.into_inner().unwrap().finish().unwrap();
    }

    #[test]
    fn a_dot_dot_entry_is_refused_not_normalised() {
        let home = Home::new();
        tar_gz_with_entry(&home, "evil.tar.gz", b"../escaped.txt", b"pwn");

        let dest = home.make_dest("out");
        let err = extract(&home.safe("evil.tar.gz"), &dest).unwrap_err();
        assert_eq!(err.kind, FsErrorKind::UnsafeArchive, "{}", err.message);
        // Not in the parent (the escape), and not anywhere else either.
        assert!(!home.path.join("escaped.txt").exists());
        assert!(!home.path.join("out/escaped.txt").exists());
    }

    #[test]
    fn an_absolute_entry_is_refused() {
        let home = Home::new();
        let marker = home.path.join("absolute-marker");
        let name = format!("{}", marker.display());
        tar_gz_with_entry(&home, "evil.tar.gz", name.as_bytes(), b"pwn");

        let dest = home.make_dest("out");
        let err = extract(&home.safe("evil.tar.gz"), &dest).unwrap_err();
        assert_eq!(err.kind, FsErrorKind::UnsafeArchive, "{}", err.message);
        assert!(!marker.exists());
    }

    #[test]
    fn a_backslash_entry_is_refused_rather_than_interpreted() {
        let home = Home::new();
        tar_gz_with_entry(&home, "evil.tar.gz", b"..\\..\\x.txt", b"pwn");

        let dest = home.make_dest("out");
        let err = extract(&home.safe("evil.tar.gz"), &dest).unwrap_err();
        assert_eq!(err.kind, FsErrorKind::UnsafeArchive, "{}", err.message);
    }

    #[cfg(unix)]
    #[test]
    fn a_tar_symlink_is_skipped_and_a_file_through_it_cannot_reach_the_target() {
        // The classic two-step: entry 1 is `link -> /etc`, entry 2 is
        // `link/unihelm-owned`. If the link were created, entry 2 would write
        // into /etc (as far as permissions allowed). It must not be created.
        let home = Home::new();
        let file = std::fs::File::create(home.path.join("evil.tar.gz")).unwrap();
        let encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
        let mut tar = tar::Builder::new(encoder);

        let mut link = tar::Header::new_gnu();
        link.set_size(0);
        link.set_mode(0o777);
        link.set_entry_type(tar::EntryType::Symlink);
        link.as_gnu_mut().unwrap().name[..4].copy_from_slice(b"link");
        // Raw field write: `set_link_name` refuses absolute targets, and an
        // attacker's tar suffers no such scruples.
        link.as_gnu_mut().unwrap().linkname[..4].copy_from_slice(b"/etc");
        link.set_cksum();
        tar.append(&link, std::io::empty()).unwrap();

        let mut through = tar::Header::new_gnu();
        let content: &[u8] = b"never lands in /etc";
        through.set_size(content.len() as u64);
        through.set_mode(0o644);
        through.set_entry_type(tar::EntryType::Regular);
        through.as_gnu_mut().unwrap().name[..18].copy_from_slice(b"link/unihelm-owned");
        through.set_cksum();
        tar.append(&through, content).unwrap();
        tar.into_inner().unwrap().finish().unwrap();

        let dest = home.make_dest("out");
        let (files, _) = extract(&home.safe("evil.tar.gz"), &dest).unwrap();
        assert_eq!(files, 1);

        // The symlink was never created; `link` is a real directory inside the
        // destination, and the file lives there — not in /etc.
        let link_path = home.path.join("out/link");
        let meta = std::fs::symlink_metadata(&link_path).unwrap();
        assert!(meta.is_dir() && !meta.file_type().is_symlink());
        assert_eq!(
            std::fs::read(link_path.join("unihelm-owned")).unwrap(),
            content
        );
        assert!(!Path::new("/etc/unihelm-owned").exists());
    }

    #[cfg(unix)]
    #[test]
    fn a_preexisting_symlink_in_the_destination_is_refused() {
        // Same attack, other order: the link already exists (from any earlier
        // operation) and the archive tries to write through it.
        let home = Home::new();
        let dest = home.make_dest("out");
        let outside = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), home.path.join("out/link")).unwrap();

        tar_gz_with_entry(&home, "evil.tar.gz", b"link/x.txt", b"pwn");
        let err = extract(&home.safe("evil.tar.gz"), &dest).unwrap_err();
        assert_eq!(err.kind, FsErrorKind::Escape, "{}", err.message);
        assert!(!outside.path().join("x.txt").exists());
    }

    // -- bombs --------------------------------------------------------------

    #[test]
    fn a_gzip_ratio_bomb_is_stopped_mid_stream() {
        // 16 MB of zeros gzips to a few kilobytes; the 200:1 cap plus 1 MB of
        // grace allows nowhere near 16 MB out of that, and the abort happens
        // during the copy, not after it.
        let home = Home::new();
        let file = std::fs::File::create(home.path.join("bomb.tar.gz")).unwrap();
        let encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
        let mut tar = tar::Builder::new(encoder);
        let zeros = vec![0u8; 16 * 1024 * 1024];
        let mut header = tar::Header::new_gnu();
        header.set_size(zeros.len() as u64);
        header.set_mode(0o644);
        header.set_entry_type(tar::EntryType::Regular);
        header.as_gnu_mut().unwrap().name[..8].copy_from_slice(b"bomb.bin");
        header.set_cksum();
        tar.append(&header, zeros.as_slice()).unwrap();
        tar.into_inner().unwrap().finish().unwrap();

        let dest = home.make_dest("out");
        let err = extract(&home.safe("bomb.tar.gz"), &dest).unwrap_err();
        assert_eq!(err.kind, FsErrorKind::UnsafeArchive, "{}", err.message);
        // The partial fragment was cleaned up.
        assert!(!home.path.join("out/bomb.bin").exists());
    }

    #[test]
    fn a_zip_ratio_bomb_is_refused_by_its_own_header() {
        let home = Home::new();
        home.write("big.bin", &vec![0u8; 8 * 1024 * 1024]);
        let root = home.root();
        compress(
            &root,
            &["big.bin".into()],
            &home.safe_new("bomb.zip"),
            ArchiveFormat::Zip,
        )
        .unwrap();

        let dest = home.make_dest("out");
        let err = extract(&home.safe("bomb.zip"), &dest).unwrap_err();
        assert_eq!(err.kind, FsErrorKind::UnsafeArchive, "{}", err.message);
        assert!(!home.path.join("out/big.bin").exists());
    }

    #[test]
    fn the_entry_count_cap_holds() {
        let home = Home::new();
        for i in 0..6 {
            home.write(&format!("many/f{i}"), b"x");
        }
        let root = home.root();
        compress(
            &root,
            &["many".into()],
            &home.safe_new("many.tar.gz"),
            ArchiveFormat::TarGz,
        )
        .unwrap();

        let dest = home.make_dest("out");
        let err = extract_with_limits(&home.safe("many.tar.gz"), &dest, tiny_limits()).unwrap_err();
        assert_eq!(err.kind, FsErrorKind::UnsafeArchive, "{}", err.message);
    }

    #[test]
    fn the_total_size_cap_holds() {
        let home = Home::new();
        home.write("data/blob", &[7u8; 4096]);
        let root = home.root();
        compress(
            &root,
            &["data".into()],
            &home.safe_new("data.tar.gz"),
            ArchiveFormat::TarGz,
        )
        .unwrap();

        let dest = home.make_dest("out");
        let err = extract_with_limits(&home.safe("data.tar.gz"), &dest, tiny_limits()).unwrap_err();
        assert_eq!(err.kind, FsErrorKind::TooLarge, "{}", err.message);
    }

    #[test]
    fn setuid_bits_do_not_survive_extraction() {
        let home = Home::new();
        tar_gz_with_entry(&home, "suid.tar.gz", b"tool", b"#!/bin/false");
        // Overwrite the mode in a fresh archive with 4755.
        let file = std::fs::File::create(home.path.join("suid.tar.gz")).unwrap();
        let encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
        let mut tar = tar::Builder::new(encoder);
        let content: &[u8] = b"#!/bin/false";
        let mut header = tar::Header::new_gnu();
        header.set_size(content.len() as u64);
        header.set_mode(0o4755);
        header.set_entry_type(tar::EntryType::Regular);
        header.as_gnu_mut().unwrap().name[..4].copy_from_slice(b"tool");
        header.set_cksum();
        tar.append(&header, content).unwrap();
        tar.into_inner().unwrap().finish().unwrap();

        let dest = home.make_dest("out");
        extract(&home.safe("suid.tar.gz"), &dest).unwrap();

        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(home.path.join("out/tool"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o7000,
            0,
            "setuid/setgid must be stripped, got {mode:o}"
        );
    }

    #[test]
    fn compress_refuses_to_overwrite_an_existing_archive() {
        let home = Home::new();
        home.write("a.txt", b"data");
        home.write("taken.zip", b"i was here first");
        let root = home.root();
        let err = compress(
            &root,
            &["a.txt".into()],
            &home.safe("taken.zip"),
            ArchiveFormat::Zip,
        )
        .unwrap_err();
        assert_eq!(err.kind, FsErrorKind::AlreadyExists);
        assert_eq!(
            std::fs::read(home.path.join("taken.zip")).unwrap(),
            b"i was here first"
        );
    }

    #[test]
    fn entry_names_that_are_not_relative_paths_are_refused() {
        for bad in [
            "/etc/x", "../x", "a/../b", "", ".", "..", "a\\b", "a/./../b",
        ] {
            assert!(split_entry_name(bad).is_err(), "{bad:?} should be refused");
        }
        for ok in ["a", "a/b/c", "./a", "a//b", "dir/"] {
            assert!(split_entry_name(ok).is_ok(), "{ok:?} should be accepted");
        }
    }
}
