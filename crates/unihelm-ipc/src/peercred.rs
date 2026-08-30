//! Peer credential checks for the Unix socket (spec §5.1, §12 rule 1).
//!
//! The agent runs as root and its socket is the only door into privileged work.
//! Filesystem permissions (0700, owned by the `unihelm` user) are the first lock;
//! this is the second one, because the kernel tells us who is *actually* on the
//! other end regardless of how the socket got opened.

use std::os::unix::io::AsRawFd;

use crate::{IpcError, Result};

/// Who is on the other end of a connected Unix socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerCred {
    pub uid: u32,
    pub gid: u32,
    /// Linux reports the peer pid; other platforms do not.
    pub pid: Option<i32>,
}

/// Read the connected peer's credentials from the kernel.
#[cfg(target_os = "linux")]
pub fn peer_cred<F: AsRawFd>(sock: &F) -> Result<PeerCred> {
    // SAFETY: `getsockopt` writes at most `len` bytes into a correctly sized,
    // fully initialised `ucred`, and `fd` is a live socket for the call's duration.
    unsafe {
        let mut cred = libc::ucred {
            pid: 0,
            uid: 0,
            gid: 0,
        };
        let mut len = size_of::<libc::ucred>() as libc::socklen_t;
        let rc = libc::getsockopt(
            sock.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&raw mut cred).cast::<libc::c_void>(),
            &raw mut len,
        );
        if rc != 0 {
            return Err(IpcError::Io(std::io::Error::last_os_error()));
        }
        Ok(PeerCred {
            uid: cred.uid,
            gid: cred.gid,
            pid: Some(cred.pid),
        })
    }
}

/// macOS/BSD path — development machines only; production is Linux (spec §1.3).
#[cfg(not(target_os = "linux"))]
pub fn peer_cred<F: AsRawFd>(sock: &F) -> Result<PeerCred> {
    // SAFETY: both out-params are live, correctly typed locals and `fd` is a live
    // socket for the duration of the call.
    unsafe {
        let mut uid: libc::uid_t = 0;
        let mut gid: libc::gid_t = 0;
        let rc = libc::getpeereid(sock.as_raw_fd(), &raw mut uid, &raw mut gid);
        if rc != 0 {
            return Err(IpcError::Io(std::io::Error::last_os_error()));
        }
        Ok(PeerCred {
            uid,
            gid,
            pid: None,
        })
    }
}

/// Which peers a listening agent will talk to.
#[derive(Debug, Clone)]
pub struct PeerPolicy {
    /// uids allowed to connect — normally just the `unihelm` web user.
    pub allowed_uids: Vec<u32>,
    /// root is always allowed: the CLI and `unihelm doctor` run as root, and a
    /// root peer could bypass any check we could write anyway.
    pub allow_root: bool,
}

impl PeerPolicy {
    pub fn new(allowed_uids: Vec<u32>) -> Self {
        Self {
            allowed_uids,
            allow_root: true,
        }
    }

    /// Development escape hatch: accept whoever started the process.
    ///
    /// Never constructed by the packaged agent — `unihelm-agentd` resolves the
    /// real `unihelm` uid at startup and refuses to run without it.
    pub fn same_user_only() -> Self {
        // SAFETY: `getuid` is always safe; it reads process state and cannot fail.
        let me = unsafe { libc::getuid() };
        Self {
            allowed_uids: vec![me],
            allow_root: true,
        }
    }

    pub fn check(&self, cred: PeerCred) -> Result<()> {
        if (self.allow_root && cred.uid == 0) || self.allowed_uids.contains(&cred.uid) {
            return Ok(());
        }
        Err(IpcError::PeerRejected(format!(
            "uid {} is not permitted to use the agent socket",
            cred.uid
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::{UnixListener, UnixStream};

    #[tokio::test]
    async fn reads_our_own_credentials_over_a_real_socket() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.sock");
        let listener = UnixListener::bind(&path).unwrap();

        let client = tokio::spawn(async move { UnixStream::connect(&path).await.unwrap() });
        let (server_side, _) = listener.accept().await.unwrap();
        let _client = client.await.unwrap();

        let cred = peer_cred(&server_side).unwrap();
        // SAFETY: `getuid` cannot fail.
        assert_eq!(cred.uid, unsafe { libc::getuid() });
    }

    #[test]
    fn policy_rejects_strangers_and_allows_root() {
        let policy = PeerPolicy {
            allowed_uids: vec![1000],
            allow_root: true,
        };
        assert!(
            policy
                .check(PeerCred {
                    uid: 1000,
                    gid: 1000,
                    pid: None
                })
                .is_ok()
        );
        assert!(
            policy
                .check(PeerCred {
                    uid: 0,
                    gid: 0,
                    pid: None
                })
                .is_ok()
        );
        let err = policy
            .check(PeerCred {
                uid: 1001,
                gid: 1001,
                pid: None,
            })
            .unwrap_err();
        assert!(matches!(err, IpcError::PeerRejected(_)));
    }

    #[test]
    fn root_can_be_disallowed_explicitly() {
        let policy = PeerPolicy {
            allowed_uids: vec![1000],
            allow_root: false,
        };
        assert!(
            policy
                .check(PeerCred {
                    uid: 0,
                    gid: 0,
                    pid: None
                })
                .is_err()
        );
    }
}
