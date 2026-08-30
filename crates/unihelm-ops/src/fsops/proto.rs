//! The wire protocol between the agent and its file-system helper.
//!
//! One process per request. That costs a fork and an exec — about two
//! milliseconds — and buys a helper that starts from nothing, drops privilege
//! before it touches a byte, and cannot carry state from one tenant's request
//! into another's.
//!
//! Framing is a single JSON line followed by an optional binary payload whose
//! length that line declares. Keeping bulk data out of the JSON is what lets a
//! two-gigabyte upload pass through in constant memory (spec §11.7 AC) instead
//! of being base64'd into a string first.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// The largest JSON header we will read, in either direction.
///
/// A header is a few hundred bytes; a megabyte is room for a very long path
/// list and still a hard stop, so a confused peer cannot make us buffer for
/// ever.
pub const MAX_HEADER: usize = 1024 * 1024;

/// What the agent asks the helper to do.
///
/// Paths here are **absolute and already joined** by the agent, which has
/// validated the tenant-relative part through [`unihelm_core::TenantPath`]. The
/// helper does not trust that: it canonicalises everything again under its own
/// (tenant) privileges and re-asserts the home prefix, so a bug in the agent
/// lands on a second check and then on an OS permission check (spec §5.2
/// rule 3).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum FsRequest {
    List {
        path: PathBuf,
        show_hidden: bool,
    },
    Stat {
        path: PathBuf,
    },
    /// Read a file's bytes. The response payload carries the content.
    Read {
        path: PathBuf,
        max_bytes: u64,
        /// Byte offset to start from. This is what makes a chunked download of
        /// a file larger than one call's budget possible (spec §11.7 AC).
        #[serde(default)]
        offset: u64,
    },
    /// Write a file. The request payload carries the content.
    Write {
        path: PathBuf,
        len: u64,
        /// Create the parent directories if they are missing.
        create_parents: bool,
        /// Append to the file instead of replacing it — the second and later
        /// chunks of a resumable upload (spec §11.7 AC: a 2 GB upload must
        /// work in constant memory, so it arrives as appended chunks).
        #[serde(default)]
        append: bool,
    },
    Mkdir {
        path: PathBuf,
    },
    Rename {
        from: PathBuf,
        to: PathBuf,
    },
    Copy {
        from: PathBuf,
        to: PathBuf,
    },
    /// Delete for real. The recycle bin is a rename, done by the agent.
    Remove {
        path: PathBuf,
    },
    Chmod {
        path: PathBuf,
        mode: u32,
        recursive: bool,
    },
    Search {
        root: PathBuf,
        query: String,
        limit: usize,
    },
    /// Bytes used by a subtree, for the recycle bin's share of the quota.
    Usage {
        path: PathBuf,
    },
    Compress {
        root: PathBuf,
        /// Names relative to `root`. One level, no separators.
        entries: Vec<String>,
        archive: PathBuf,
        format: ArchiveFormat,
    },
    Extract {
        archive: PathBuf,
        dest: PathBuf,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArchiveFormat {
    Zip,
    TarGz,
    TarZst,
}

impl ArchiveFormat {
    pub const fn extension(self) -> &'static str {
        match self {
            ArchiveFormat::Zip => "zip",
            ArchiveFormat::TarGz => "tar.gz",
            ArchiveFormat::TarZst => "tar.zst",
        }
    }

    /// Guess from a file name, for extraction.
    pub fn from_name(name: &str) -> Option<Self> {
        let lower = name.to_ascii_lowercase();
        if lower.ends_with(".zip") {
            Some(ArchiveFormat::Zip)
        } else if lower.ends_with(".tar.gz") || lower.ends_with(".tgz") {
            Some(ArchiveFormat::TarGz)
        } else if lower.ends_with(".tar.zst") || lower.ends_with(".tzst") {
            Some(ArchiveFormat::TarZst)
        } else {
            None
        }
    }
}

/// The envelope the agent writes on the helper's stdin.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FsCall {
    /// The tenant's home. Everything the helper touches must resolve under it.
    pub home: PathBuf,
    pub request: FsRequest,
    /// Bytes of payload following this line.
    #[serde(default)]
    pub payload_len: u64,
}

/// One directory entry, as the UI sees it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FsEntry {
    /// Path relative to the tenant home, `/`-separated.
    pub path: String,
    pub name: String,
    pub kind: EntryKind,
    pub size: u64,
    /// Unix mode bits, permissions only.
    pub mode: u32,
    /// Seconds since the epoch; `None` if the filesystem would not say.
    pub modified: Option<i64>,
    /// For a symlink, where it points — verbatim, not resolved.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// True when a symlink leaves the tenant home. The UI shows these as
    /// broken rather than following them, and no operation will act through
    /// one.
    #[serde(default)]
    pub escapes: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    File,
    Dir,
    Symlink,
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FsData {
    Entries(Vec<FsEntry>),
    Entry(FsEntry),
    /// Payload follows: `size` bytes of file content.
    Content {
        size: u64,
        /// The file was longer than the caller's limit.
        truncated: bool,
        /// Contains bytes that are not valid UTF-8, so the editor must refuse.
        binary: bool,
    },
    Bytes(u64),
    Extracted {
        files: u64,
        bytes: u64,
    },
    Done,
}

/// What the helper writes back on stdout.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FsReply {
    Ok {
        data: FsData,
        #[serde(default)]
        payload_len: u64,
    },
    Err {
        kind: FsErrorKind,
        message: String,
    },
}

/// Why a request failed, in terms the API can map onto an error code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FsErrorKind {
    NotFound,
    PermissionDenied,
    AlreadyExists,
    NotADirectory,
    IsADirectory,
    /// The path resolved outside the tenant home.
    Escape,
    TooLarge,
    /// The archive looked like an attack rather than an archive.
    UnsafeArchive,
    Invalid,
    Io,
}

impl FsErrorKind {
    pub fn from_io(e: &std::io::Error) -> Self {
        use std::io::ErrorKind as K;
        match e.kind() {
            K::NotFound => FsErrorKind::NotFound,
            K::PermissionDenied => FsErrorKind::PermissionDenied,
            K::AlreadyExists => FsErrorKind::AlreadyExists,
            K::NotADirectory => FsErrorKind::NotADirectory,
            K::IsADirectory => FsErrorKind::IsADirectory,
            _ => FsErrorKind::Io,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_request_survives_a_round_trip() {
        let call = FsCall {
            home: PathBuf::from("/home/uh_x"),
            request: FsRequest::Write {
                path: PathBuf::from("/home/uh_x/a.txt"),
                len: 12,
                create_parents: false,
                append: false,
            },
            payload_len: 12,
        };
        let line = serde_json::to_string(&call).unwrap();
        assert!(!line.contains('\n'), "the frame is one line: {line}");
        let back: FsCall = serde_json::from_str(&line).unwrap();
        assert_eq!(back.payload_len, 12);
    }

    #[test]
    fn offset_and_append_default_off_for_old_frames() {
        // An agent one version behind must still speak to a newer helper: the
        // new fields deserialise to their do-nothing values when absent.
        let read: FsRequest =
            serde_json::from_str(r#"{"op":"read","path":"/h/a.txt","max_bytes":100}"#).unwrap();
        assert!(matches!(read, FsRequest::Read { offset: 0, .. }));

        let write: FsRequest = serde_json::from_str(
            r#"{"op":"write","path":"/h/a.txt","len":1,"create_parents":false}"#,
        )
        .unwrap();
        assert!(matches!(write, FsRequest::Write { append: false, .. }));
    }

    #[test]
    fn archive_formats_are_recognised_by_their_real_names() {
        for (name, want) in [
            ("site.zip", Some(ArchiveFormat::Zip)),
            ("SITE.ZIP", Some(ArchiveFormat::Zip)),
            ("backup.tar.gz", Some(ArchiveFormat::TarGz)),
            ("backup.tgz", Some(ArchiveFormat::TarGz)),
            ("backup.tar.zst", Some(ArchiveFormat::TarZst)),
            ("notes.txt", None),
            ("zip", None),
            ("evil.zip.php", None),
        ] {
            assert_eq!(ArchiveFormat::from_name(name), want, "{name}");
        }
    }

    #[test]
    fn an_unknown_operation_is_a_parse_error_not_a_default() {
        // A helper that silently defaulted an unrecognised op would be a way to
        // reach whichever variant serde picked first.
        assert!(serde_json::from_str::<FsRequest>(r#"{"op":"chown","path":"/x"}"#).is_err());
    }
}
