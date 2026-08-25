//! The child process: everything here runs as the **tenant**, never as root.
//!
//! `ferrum-agentd --fs-helper` re-execs the agent binary, drops to the tenant's
//! uid and gid before `main` does anything else, reads one request from stdin,
//! answers on stdout, and exits. Nothing in this module has a privilege to
//! misuse: the worst a bug here can do is what the tenant's own shell could do
//! over SFTP (spec §5.2 rule 3).
//!
//! That is the point. The path checks in [`super::safepath`] keep the panel
//! honest about staying inside the home; the privilege drop is what makes a
//! failure of those checks boring rather than catastrophic.

use std::io::{self, BufRead, Read, Write};
use std::path::Path;

use super::archive;
use super::proto::*;
use super::safepath::{self, SafeError, SafePath, SafeResult};

/// Read the biggest chunk we ever hold in memory at once for file content.
const CHUNK: usize = 64 * 1024;

/// A file bigger than this is never read into the editor.
///
/// The API asks for its own limit as well; this is the backstop, so a helper
/// invoked with a nonsense limit still cannot be told to buffer a 40 GB log.
pub const MAX_EDITABLE: u64 = 16 * 1024 * 1024;

/// Entry point for `--fs-helper`. Returns the process exit code.
///
/// Errors are reported *in the reply*, not by exiting non-zero, so the agent
/// always gets a structured answer it can turn into an error code. A non-zero
/// exit means the helper itself broke.
pub fn run() -> i32 {
    let stdin = io::stdin();
    let mut reader = io::BufReader::new(stdin.lock());
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());

    let call = match read_call(&mut reader) {
        Ok(call) => call,
        Err(e) => {
            let _ = write_reply(
                &FsReply::Err {
                    kind: FsErrorKind::Invalid,
                    message: format!("could not read the request: {e}"),
                },
                &mut io::empty(),
                0,
                &mut out,
            );
            return 2;
        }
    };

    match serve_one(&call, &mut reader, &mut out) {
        Ok(()) => 0,
        Err(_) => 2,
    }
}

/// Handle one parsed request: dispatch it and write exactly one reply to `out`.
///
/// Operation failures become an `FsReply::Err` on `out` and an `Ok(())` here;
/// the returned error is reserved for a broken transport. This is the seam
/// [`super::run_local`] uses to run the helper in-process — the dev-mode and
/// test path, where the agent is not root and has no privilege to drop.
pub fn serve_one(
    call: &FsCall,
    payload: &mut impl BufRead,
    out: &mut impl Write,
) -> io::Result<()> {
    match dispatch(call, payload, out) {
        Ok(()) => Ok(()),
        Err(e) => write_reply(
            &FsReply::Err {
                kind: e.kind,
                message: e.message,
            },
            &mut io::empty(),
            0,
            out,
        ),
    }
}

/// Read exactly the header line, leaving the payload in the buffer.
///
/// `read_line` would be shorter, but it has no bound: a peer that never sends a
/// newline would make the helper buffer until the machine complained. This stops
/// at [`MAX_HEADER`] and reports it.
pub fn read_call(reader: &mut impl BufRead) -> io::Result<FsCall> {
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let n = reader.read(&mut byte)?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "the request ended before its newline",
            ));
        }
        if byte[0] == b'\n' {
            break;
        }
        line.push(byte[0]);
        if line.len() > MAX_HEADER {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the request header is too long",
            ));
        }
    }
    serde_json::from_slice(&line).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

fn dispatch(call: &FsCall, payload: &mut impl BufRead, out: &mut impl Write) -> SafeResult<()> {
    let home = call.home.as_path();

    match &call.request {
        FsRequest::List { path, show_hidden } => {
            let dir = safepath::resolve(home, path)?;
            let entries = list(&dir, *show_hidden)?;
            reply_data(FsData::Entries(entries), out)
        }

        FsRequest::Stat { path } => {
            let target = safepath::resolve(home, path)?;
            let entry = entry_for(&target)?;
            reply_data(FsData::Entry(entry), out)
        }

        FsRequest::Read {
            path,
            max_bytes,
            offset,
        } => {
            let target = safepath::resolve(home, path)?;
            read_file(&target, (*max_bytes).min(MAX_EDITABLE), *offset, out)
        }

        FsRequest::Write {
            path,
            len,
            create_parents,
            append,
        } => {
            let (dir, name) = if *create_parents {
                make_parents(home, path)?
            } else {
                safepath::resolve_new(home, path)?
            };
            let target = safepath::child(&dir, &name)?;
            if *append {
                append_file(&target, *len, payload)?;
            } else {
                write_file(&target, *len, payload)?;
            }
            reply_data(FsData::Done, out)
        }

        FsRequest::Mkdir { path } => {
            let (dir, name) = safepath::resolve_new(home, path)?;
            let target = safepath::child(&dir, &name)?;
            std::fs::create_dir(target.as_path())
                .map_err(|e| SafeError::io(target.as_path(), &e))?;
            reply_data(FsData::Entry(entry_for(&target)?), out)
        }

        FsRequest::Rename { from, to } => {
            let source = safepath::resolve(home, from)?;
            let (dir, name) = safepath::resolve_new(home, to)?;
            let dest = safepath::child(&dir, &name)?;
            if dest.as_path().exists() {
                return Err(SafeError::new(
                    FsErrorKind::AlreadyExists,
                    format!("`{}` already exists", dest.relative()),
                ));
            }
            std::fs::rename(source.as_path(), dest.as_path())
                .map_err(|e| SafeError::io(source.as_path(), &e))?;
            reply_data(FsData::Entry(entry_for(&dest)?), out)
        }

        FsRequest::Copy { from, to } => {
            let source = safepath::resolve(home, from)?;
            let (dir, name) = safepath::resolve_new(home, to)?;
            let dest = safepath::child(&dir, &name)?;
            if dest.as_path().exists() {
                return Err(SafeError::new(
                    FsErrorKind::AlreadyExists,
                    format!("`{}` already exists", dest.relative()),
                ));
            }
            let bytes = copy_tree(&source, &dest)?;
            reply_data(FsData::Bytes(bytes), out)
        }

        FsRequest::Remove { path } => {
            let target = safepath::resolve(home, path)?;
            if target.relative().is_empty() {
                return Err(SafeError::new(
                    FsErrorKind::Invalid,
                    "the home directory itself cannot be deleted",
                ));
            }
            remove_tree(&target)?;
            reply_data(FsData::Done, out)
        }

        FsRequest::Chmod {
            path,
            mode,
            recursive,
        } => {
            let target = safepath::resolve(home, path)?;
            let mode = safe_mode(*mode)?;
            chmod_tree(&target, mode, *recursive)?;
            reply_data(FsData::Done, out)
        }

        FsRequest::Search { root, query, limit } => {
            let dir = safepath::resolve(home, root)?;
            let entries = search(&dir, &query.to_lowercase(), (*limit).min(2000))?;
            reply_data(FsData::Entries(entries), out)
        }

        FsRequest::Usage { path } => {
            let target = safepath::resolve(home, path)?;
            reply_data(FsData::Bytes(usage(&target)), out)
        }

        FsRequest::Compress {
            root,
            entries,
            archive: archive_path,
            format,
        } => {
            let dir = safepath::resolve(home, root)?;
            let (parent, name) = safepath::resolve_new(home, archive_path)?;
            let target = safepath::child(&parent, &name)?;
            let bytes = archive::compress(&dir, entries, &target, *format)?;
            reply_data(FsData::Bytes(bytes), out)
        }

        FsRequest::Extract { archive: src, dest } => {
            let source = safepath::resolve(home, src)?;
            let target = safepath::resolve(home, dest)?;
            let (files, bytes) = archive::extract(&source, &target)?;
            reply_data(FsData::Extracted { files, bytes }, out)
        }
    }
}

// ---------------------------------------------------------------------------
// operations
// ---------------------------------------------------------------------------

fn list(dir: &SafePath, show_hidden: bool) -> SafeResult<Vec<FsEntry>> {
    let read = std::fs::read_dir(dir.as_path()).map_err(|e| SafeError::io(dir.as_path(), &e))?;
    let mut entries = Vec::new();

    for item in read {
        let item = match item {
            Ok(i) => i,
            // One unreadable entry must not abort the listing: a directory with
            // a single broken name would otherwise be permanently unbrowsable.
            Err(_) => continue,
        };
        let Some(name) = item.file_name().to_str().map(str::to_string) else {
            continue;
        };
        if !show_hidden && name.starts_with('.') {
            continue;
        }
        // `.trash` is the recycle bin, shown through its own view.
        if name == super::TRASH_DIR && dir.relative().is_empty() {
            continue;
        }
        let Ok(child) = dir.join_entry(&name) else {
            continue;
        };
        if let Ok(entry) = entry_for(&child) {
            entries.push(entry);
        }
    }

    // Directories first, then by name — the order every file manager uses,
    // decided here so every client agrees.
    entries.sort_by(|a, b| {
        let dir_first = (b.kind == EntryKind::Dir).cmp(&(a.kind == EntryKind::Dir));
        dir_first.then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });
    Ok(entries)
}

fn entry_for(path: &SafePath) -> SafeResult<FsEntry> {
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::fs::PermissionsExt;

    let meta =
        std::fs::symlink_metadata(path.as_path()).map_err(|e| SafeError::io(path.as_path(), &e))?;
    let ft = meta.file_type();

    let (kind, target, escapes) = if ft.is_symlink() {
        let raw = std::fs::read_link(path.as_path()).unwrap_or_default();
        // Reported, never followed. `escapes` is advisory for the UI; every
        // operation refuses symlinks outright.
        let escapes = raw.is_absolute() || raw.components().any(|c| c.as_os_str() == "..");
        (
            EntryKind::Symlink,
            Some(raw.to_string_lossy().into_owned()),
            escapes,
        )
    } else if ft.is_dir() {
        (EntryKind::Dir, None, false)
    } else if ft.is_file() {
        (EntryKind::File, None, false)
    } else {
        (EntryKind::Other, None, false)
    };

    Ok(FsEntry {
        name: path
            .as_path()
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default(),
        path: path.relative().to_string(),
        kind,
        size: meta.size(),
        mode: meta.permissions().mode() & 0o7777,
        modified: Some(meta.mtime()),
        target,
        escapes,
    })
}

fn read_file(path: &SafePath, max_bytes: u64, offset: u64, out: &mut impl Write) -> SafeResult<()> {
    use std::io::Seek;

    let meta = std::fs::metadata(path.as_path()).map_err(|e| SafeError::io(path.as_path(), &e))?;
    if meta.is_dir() {
        return Err(SafeError::new(
            FsErrorKind::IsADirectory,
            format!("`{}` is a directory", path.relative()),
        ));
    }

    let size = meta.len();
    // An offset past the end is an empty read, not an error: the chunked
    // downloader learns it is done the same way `read(2)` callers do.
    let start = offset.min(size);
    let take = (size - start).min(max_bytes);
    let truncated = start + take < size;

    let mut file =
        std::fs::File::open(path.as_path()).map_err(|e| SafeError::io(path.as_path(), &e))?;
    file.seek(std::io::SeekFrom::Start(start))
        .map_err(|e| SafeError::io(path.as_path(), &e))?;
    let mut buffer = Vec::with_capacity(take as usize);
    Read::by_ref(&mut file)
        .take(take)
        .read_to_end(&mut buffer)
        .map_err(|e| SafeError::io(path.as_path(), &e))?;

    // A truncated read can cut a multi-byte character in half, which would look
    // like a binary file. Judge on the whole prefix minus at most three bytes.
    // (A non-zero offset can start mid-character too; the editor always reads
    // from zero, and a chunked download does not care about this flag.)
    let judged = if truncated {
        &buffer[..buffer.len().saturating_sub(3)]
    } else {
        &buffer[..]
    };
    let binary = std::str::from_utf8(judged).is_err() || judged.contains(&0);

    let len = buffer.len() as u64;
    write_reply(
        &FsReply::Ok {
            data: FsData::Content {
                size,
                truncated,
                binary,
            },
            payload_len: len,
        },
        &mut buffer.as_slice(),
        len,
        out,
    )
    .map_err(|e| SafeError::io(path.as_path(), &e))
}

fn write_file(path: &SafePath, len: u64, payload: &mut impl BufRead) -> SafeResult<()> {
    // Write beside the target and rename into place, so a broken connection
    // leaves the old file intact rather than a half-written one. Same discipline
    // as the config engine.
    let temp = path.as_path().with_extension("ferrum-part");
    {
        let mut file =
            std::fs::File::create(&temp).map_err(|e| SafeError::io(path.as_path(), &e))?;
        let mut remaining = len;
        let mut buffer = vec![0u8; CHUNK];
        while remaining > 0 {
            let want = remaining.min(CHUNK as u64) as usize;
            payload
                .read_exact(&mut buffer[..want])
                .map_err(|e| SafeError::io(path.as_path(), &e))?;
            file.write_all(&buffer[..want])
                .map_err(|e| SafeError::io(path.as_path(), &e))?;
            remaining -= want as u64;
        }
        file.flush().map_err(|e| SafeError::io(path.as_path(), &e))?;
    }
    std::fs::rename(&temp, path.as_path()).map_err(|e| {
        let _ = std::fs::remove_file(&temp);
        SafeError::io(path.as_path(), &e)
    })
}

/// Append a chunk to an existing file (or start one), for resumable uploads.
///
/// No temp-and-rename here: append semantics are the caller saying "the file is
/// being built across calls", so a failed chunk is simply re-sent at the same
/// offset. `O_NOFOLLOW` closes the gap between [`safepath::resolve_new`]'s
/// symlink check and this open — a link planted in between makes the open fail
/// instead of redirecting the write.
fn append_file(path: &SafePath, len: u64, payload: &mut impl BufRead) -> SafeResult<()> {
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path.as_path())
        .map_err(|e| SafeError::io(path.as_path(), &e))?;

    let mut remaining = len;
    let mut buffer = vec![0u8; CHUNK];
    while remaining > 0 {
        let want = remaining.min(CHUNK as u64) as usize;
        payload
            .read_exact(&mut buffer[..want])
            .map_err(|e| SafeError::io(path.as_path(), &e))?;
        file.write_all(&buffer[..want])
            .map_err(|e| SafeError::io(path.as_path(), &e))?;
        remaining -= want as u64;
    }
    file.flush().map_err(|e| SafeError::io(path.as_path(), &e))
}

/// Resolve a path, creating any missing directories along the way.
///
/// Each level is created and then stepped into through the same symlink-refusing
/// walk, so `mkdir -p` cannot be tricked into descending through a link that
/// appears mid-way.
fn make_parents(home: &Path, path: &Path) -> SafeResult<(SafePath, String)> {
    let mut current = safepath::home_root(home)?;
    let relative = match safepath::resolve_new(home, path) {
        Ok(pair) => return Ok(pair),
        Err(e) if e.kind != FsErrorKind::NotFound => return Err(e),
        Err(_) => strip_home(home, path)?,
    };

    let mut components: Vec<&str> = relative.split('/').filter(|s| !s.is_empty()).collect();
    let Some(name) = components.pop() else {
        return Err(SafeError::new(
            FsErrorKind::Invalid,
            "cannot create the home directory itself",
        ));
    };

    for component in components {
        let next = current.join_entry(component)?;
        if !next.as_path().exists() {
            std::fs::create_dir(next.as_path())
                .map_err(|e| SafeError::io(next.as_path(), &e))?;
        }
        // Re-walk rather than trusting the join: if `component` turned out to be
        // a symlink placed between the create and here, this refuses it.
        current = safepath::resolve(home, Path::new(next.relative()))?;
    }
    Ok((current, name.to_string()))
}

fn strip_home(home: &Path, path: &Path) -> SafeResult<String> {
    let root = safepath::home_root(home)?;
    let relative = if path.is_absolute() {
        path.strip_prefix(root.as_path())
            .map_err(|_| SafeError::escape(path))?
    } else {
        path
    };
    let mut out = Vec::new();
    for component in relative.components() {
        match component {
            std::path::Component::Normal(p) => out.push(
                p.to_str()
                    .ok_or_else(|| SafeError::new(FsErrorKind::Invalid, "path is not UTF-8"))?,
            ),
            std::path::Component::CurDir => {}
            _ => return Err(SafeError::escape(path)),
        }
    }
    Ok(out.join("/"))
}

fn copy_tree(from: &SafePath, to: &SafePath) -> SafeResult<u64> {
    let meta =
        std::fs::symlink_metadata(from.as_path()).map_err(|e| SafeError::io(from.as_path(), &e))?;

    if meta.file_type().is_symlink() {
        return Err(SafeError::escape(from.as_path()));
    }

    if meta.is_file() {
        return std::fs::copy(from.as_path(), to.as_path())
            .map_err(|e| SafeError::io(from.as_path(), &e));
    }

    std::fs::create_dir(to.as_path()).map_err(|e| SafeError::io(to.as_path(), &e))?;
    let mut total = 0;
    for item in std::fs::read_dir(from.as_path()).map_err(|e| SafeError::io(from.as_path(), &e))? {
        let item = match item {
            Ok(i) => i,
            Err(_) => continue,
        };
        let Some(name) = item.file_name().to_str().map(str::to_string) else {
            continue;
        };
        let Ok(source) = from.join_entry(&name) else {
            continue;
        };
        let dest = to.join_entry(&name)?;
        // A symlink inside the tree is skipped rather than copied: recreating it
        // would put a link we did not audit into a new location.
        if std::fs::symlink_metadata(source.as_path())
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(false)
        {
            continue;
        }
        total += copy_tree(&source, &dest)?;
    }
    Ok(total)
}

fn remove_tree(path: &SafePath) -> SafeResult<()> {
    let meta =
        std::fs::symlink_metadata(path.as_path()).map_err(|e| SafeError::io(path.as_path(), &e))?;
    if meta.is_dir() && !meta.file_type().is_symlink() {
        // `remove_dir_all` follows nothing on modern Rust (it uses openat with
        // NOFOLLOW), so this cannot be redirected by a link inside the tree.
        std::fs::remove_dir_all(path.as_path()).map_err(|e| SafeError::io(path.as_path(), &e))
    } else {
        std::fs::remove_file(path.as_path()).map_err(|e| SafeError::io(path.as_path(), &e))
    }
}

/// Reject the mode bits a tenant must never set on their own files.
///
/// setuid, setgid and the sticky bit are all ways to turn a file the tenant
/// controls into something that behaves differently for someone else. There is
/// no legitimate file-manager reason to set them.
fn safe_mode(mode: u32) -> SafeResult<u32> {
    if mode & 0o7000 != 0 {
        return Err(SafeError::new(
            FsErrorKind::Invalid,
            "setuid, setgid and sticky bits cannot be set from the file manager",
        ));
    }
    if mode & !0o777 != 0 {
        return Err(SafeError::new(
            FsErrorKind::Invalid,
            "mode must be permission bits only",
        ));
    }
    Ok(mode)
}

fn chmod_tree(path: &SafePath, mode: u32, recursive: bool) -> SafeResult<()> {
    use std::os::unix::fs::PermissionsExt;

    let meta =
        std::fs::symlink_metadata(path.as_path()).map_err(|e| SafeError::io(path.as_path(), &e))?;
    if meta.file_type().is_symlink() {
        // chmod follows the link, so this would change the mode of whatever it
        // points at.
        return Err(SafeError::escape(path.as_path()));
    }

    std::fs::set_permissions(path.as_path(), std::fs::Permissions::from_mode(mode))
        .map_err(|e| SafeError::io(path.as_path(), &e))?;

    if recursive && meta.is_dir() {
        for item in
            std::fs::read_dir(path.as_path()).map_err(|e| SafeError::io(path.as_path(), &e))?
        {
            let Ok(item) = item else { continue };
            let Some(name) = item.file_name().to_str().map(str::to_string) else {
                continue;
            };
            let Ok(child) = path.join_entry(&name) else {
                continue;
            };
            // A failure deep in a tree does not undo what already worked; it is
            // reported and the walk continues, which is what `chmod -R` does.
            let _ = chmod_tree(&child, mode, true);
        }
    }
    Ok(())
}

fn search(dir: &SafePath, needle: &str, limit: usize) -> SafeResult<Vec<FsEntry>> {
    let mut found = Vec::new();
    let mut queue = vec![dir.clone()];
    // Bounded so a search in a home with a million files answers rather than
    // running until the request times out.
    let mut budget = 200_000usize;

    while let Some(current) = queue.pop() {
        if found.len() >= limit || budget == 0 {
            break;
        }
        let Ok(read) = std::fs::read_dir(current.as_path()) else {
            continue;
        };
        for item in read {
            budget = budget.saturating_sub(1);
            if found.len() >= limit || budget == 0 {
                break;
            }
            let Ok(item) = item else { continue };
            let Some(name) = item.file_name().to_str().map(str::to_string) else {
                continue;
            };
            let Ok(child) = current.join_entry(&name) else {
                continue;
            };
            let Ok(meta) = std::fs::symlink_metadata(child.as_path()) else {
                continue;
            };
            if name.to_lowercase().contains(needle)
                && let Ok(entry) = entry_for(&child)
            {
                found.push(entry);
            }
            // Never descend through a symlink: a link to `/` would make the
            // search walk the whole filesystem, and a link to a parent would
            // make it walk for ever.
            if meta.is_dir() && !meta.file_type().is_symlink() {
                queue.push(child);
            }
        }
    }
    Ok(found)
}

fn usage(path: &SafePath) -> u64 {
    use std::os::unix::fs::MetadataExt;

    let Ok(meta) = std::fs::symlink_metadata(path.as_path()) else {
        return 0;
    };
    if meta.file_type().is_symlink() {
        return 0;
    }
    if !meta.is_dir() {
        // Blocks, not length: a sparse file does not cost its apparent size, and
        // a quota counts what is on the disk.
        return meta.blocks() * 512;
    }

    let mut total = meta.blocks() * 512;
    let Ok(read) = std::fs::read_dir(path.as_path()) else {
        return total;
    };
    for item in read.flatten() {
        let Some(name) = item.file_name().to_str().map(str::to_string) else {
            continue;
        };
        let Ok(child) = path.join_entry(&name) else {
            continue;
        };
        total += usage(&child);
    }
    total
}

// ---------------------------------------------------------------------------
// framing
// ---------------------------------------------------------------------------

fn reply_data(data: FsData, out: &mut impl Write) -> SafeResult<()> {
    write_reply(
        &FsReply::Ok {
            data,
            payload_len: 0,
        },
        &mut io::empty(),
        0,
        out,
    )
    .map_err(|e| SafeError::new(FsErrorKind::Io, e.to_string()))
}

fn write_reply(
    reply: &FsReply,
    payload: &mut impl Read,
    payload_len: u64,
    out: &mut impl Write,
) -> io::Result<()> {
    let line = serde_json::to_string(reply)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    out.write_all(line.as_bytes())?;
    out.write_all(b"\n")?;
    if payload_len > 0 {
        io::copy(&mut payload.take(payload_len), out)?;
    }
    out.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn setuid_and_friends_are_refused() {
        // A tenant who can set the setuid bit on a file they own has a way to
        // hand themselves a different uid the moment anything else runs it.
        for bad in [0o4755, 0o2755, 0o1777, 0o104755] {
            assert!(safe_mode(bad).is_err(), "{bad:o} should be refused");
        }
        for ok in [0o644, 0o755, 0o600, 0o777] {
            assert_eq!(safe_mode(ok).unwrap(), ok);
        }
    }
}
