//! Pseudo-terminal allocation and the wiring that turns a child into a shell.
//!
//! Three things happen here and nothing else does:
//!
//! 1. [`open_pty`] allocates a master/slave pair through the POSIX sequence
//!    (`posix_openpt` → `grantpt` → `unlockpt` → open the slave by name).
//! 2. [`set_window_size`] pushes `TIOCSWINSZ`, which is what makes `vim` and
//!    `top` lay themselves out correctly, and what a browser resize turns into.
//! 3. [`attach_child_to_pty`] is the handful of calls a forked child makes
//!    between `fork` and `exec`: a new session, and the slave adopted as its
//!    *controlling* terminal. Without those two, Ctrl-C reaches nothing and job
//!    control does not work.
//!
//! # Why `posix_openpt` rather than `openpty`
//!
//! `openpty(3)` does all of step 1 in one call, but it lives in `libutil` — a
//! separate library on glibc before 2.34 and linked differently on each libc.
//! The four-call POSIX sequence is in libc proper everywhere the panel runs and
//! everywhere it is developed, so the code path the tests exercise on a
//! developer's machine is the same one that runs on the server.
//!
//! `ptsname` returns a pointer into a static buffer, which is why every call
//! here holds [`PTSNAME_LOCK`] and copies the name out before releasing it.
//! Nothing else in the process calls `ptsname`, so that lock is the whole of
//! the mutual exclusion this needs.

use std::ffi::CStr;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::PathBuf;
use std::sync::Mutex;

/// Serialises the `ptsname` static buffer (see the module docs).
static PTSNAME_LOCK: Mutex<()> = Mutex::new(());

/// A freshly allocated terminal pair.
///
/// The parent keeps `master` and reads/writes the shell's bytes through it; the
/// child gets `slave` as its stdin, stdout and stderr and never sees the master.
#[derive(Debug)]
pub struct PtyPair {
    pub master: OwnedFd,
    pub slave: OwnedFd,
    /// `/dev/pts/N`. Carried for the audit row: "which terminal was this?" is a
    /// question an incident review asks.
    pub slave_name: PathBuf,
}

fn last_error() -> io::Error {
    io::Error::last_os_error()
}

/// Mark a descriptor close-on-exec.
///
/// Set through `fcntl` rather than an `O_CLOEXEC` open flag because
/// `posix_openpt` only accepts the flag on some platforms, and this has to
/// hold everywhere the agent builds.
fn set_cloexec(fd: RawFd) -> io::Result<()> {
    // SAFETY: `fd` is a valid descriptor owned by the caller for this call.
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFD);
        if flags < 0 {
            return Err(last_error());
        }
        if libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) < 0 {
            return Err(last_error());
        }
    }
    Ok(())
}

/// Allocate a pty and set its initial window size.
pub fn open_pty(cols: u16, rows: u16) -> io::Result<PtyPair> {
    // O_NOCTTY on the master: the agent must not accidentally acquire this
    // terminal as its own controlling terminal. Only the child does that, and
    // only deliberately, in `attach_child_to_pty`.
    // SAFETY: a libc call taking flags and returning a fd or -1.
    let raw = unsafe { libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY) };
    if raw < 0 {
        return Err(last_error());
    }
    // Owned immediately, so every early return below closes it.
    // SAFETY: `raw` is a fresh, valid, exclusively-owned descriptor.
    let master = unsafe { OwnedFd::from_raw_fd(raw) };
    // The master is the agent's end. It must not survive the `execve` into the
    // tenant's shell: that shell runs as the tenant after `drop_privileges`,
    // and a descriptor to its own terminal's *master* would let it write its
    // own input and would keep the terminal alive after `kill()` closes our
    // copy. `attach_child_to_pty` already promises "no descriptor to the
    // terminal survives that the shell does not know about"; this is what
    // makes that true of the master as well as the slave.
    set_cloexec(master.as_raw_fd())?;

    // SAFETY: `master` is open for the duration of both calls.
    unsafe {
        if libc::grantpt(master.as_raw_fd()) != 0 {
            return Err(last_error());
        }
        if libc::unlockpt(master.as_raw_fd()) != 0 {
            return Err(last_error());
        }
    }

    let slave_name = ptsname(master.as_raw_fd())?;

    let c_name = std::ffi::CString::new(slave_name.as_os_str().to_string_lossy().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "pts name contains a NUL"))?;
    // The slave is opened O_NOCTTY here too: the *child* claims it as its
    // controlling terminal explicitly after `setsid`, which is the only place
    // that decision belongs.
    // SAFETY: `c_name` is a valid NUL-terminated path for the duration of the call.
    let raw_slave = unsafe { libc::open(c_name.as_ptr(), libc::O_RDWR | libc::O_NOCTTY) };
    if raw_slave < 0 {
        return Err(last_error());
    }
    // SAFETY: `raw_slave` is a fresh, valid, exclusively-owned descriptor.
    let slave = unsafe { OwnedFd::from_raw_fd(raw_slave) };
    // The child still receives the slave: it is passed as stdio, and both
    // `Stdio::from` and `attach_child_to_pty` reach it through `dup2`, which
    // clears `FD_CLOEXEC` on the descriptor it creates. What this stops is the
    // *original* leaking in alongside fds 0, 1 and 2.
    set_cloexec(slave.as_raw_fd())?;

    set_window_size(master.as_raw_fd(), cols, rows)?;

    Ok(PtyPair {
        master,
        slave,
        slave_name,
    })
}

/// The slave device's path, copied out from under [`PTSNAME_LOCK`].
fn ptsname(master: RawFd) -> io::Result<PathBuf> {
    let _guard = PTSNAME_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    // SAFETY: `master` is a valid pty master. The returned pointer aims at a
    // static libc buffer which is copied before the lock is released; a NULL
    // return is the documented failure and is handled.
    let name = unsafe {
        let ptr = libc::ptsname(master);
        if ptr.is_null() {
            return Err(last_error());
        }
        CStr::from_ptr(ptr).to_bytes().to_vec()
    };
    String::from_utf8(name)
        .map(PathBuf::from)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "pts name is not UTF-8"))
}

/// Push a new window size onto the terminal.
///
/// Zero is refused rather than passed through: a zero-column terminal makes
/// curses applications divide by it, and a browser tab that is still laying out
/// reports 0×0 for a frame or two.
pub fn set_window_size(master: RawFd, cols: u16, rows: u16) -> io::Result<()> {
    let size = libc::winsize {
        ws_row: rows.max(1),
        ws_col: cols.max(1),
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: TIOCSWINSZ takes a `*const winsize`; `size` outlives the call.
    let rc = unsafe { libc::ioctl(master, libc::TIOCSWINSZ as _, &size) };
    if rc != 0 {
        return Err(last_error());
    }
    Ok(())
}

/// Read a terminal's window size. Used by the tests, and by nothing else.
pub fn window_size(fd: RawFd) -> io::Result<(u16, u16)> {
    let mut size = libc::winsize {
        ws_row: 0,
        ws_col: 0,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: TIOCGWINSZ takes a `*mut winsize`; `size` outlives the call.
    let rc = unsafe { libc::ioctl(fd, libc::TIOCGWINSZ as _, &mut size) };
    if rc != 0 {
        return Err(last_error());
    }
    Ok((size.ws_col, size.ws_row))
}

/// Everything a forked child does to make `slave` its terminal, before `exec`.
///
/// # Safety
///
/// Call this only between `fork` and `exec` (or from a `pre_exec` closure),
/// where the process is single-threaded. Every call it makes is
/// async-signal-safe for exactly that reason.
///
/// The order is not negotiable:
///
/// * `setsid` first — a process that is already a session leader, or that still
///   belongs to the agent's session, cannot take a new controlling terminal.
///   It also detaches the shell from the agent's terminal, so a stray signal
///   sent to the agent's process group never reaches a tenant's shell.
/// * `TIOCSCTTY` second — this is the call that makes Ctrl-C, Ctrl-Z and `fg`
///   work. Without it the shell runs but has no job control at all.
/// * `dup2` last — the slave becomes fds 0, 1 and 2, and the original is
///   closed, so no descriptor to the terminal survives that the shell does not
///   know about.
pub unsafe fn attach_child_to_pty(slave: RawFd) -> Result<(), i32> {
    // SAFETY: the caller guarantees the post-fork, pre-exec, single-threaded
    // context these calls require.
    unsafe {
        if libc::setsid() < 0 {
            return Err(io::Error::last_os_error().raw_os_error().unwrap_or(-1));
        }
        if libc::ioctl(slave, libc::TIOCSCTTY as _, 0) < 0 {
            return Err(io::Error::last_os_error().raw_os_error().unwrap_or(-1));
        }
        for target in [libc::STDIN_FILENO, libc::STDOUT_FILENO, libc::STDERR_FILENO] {
            if libc::dup2(slave, target) < 0 {
                return Err(io::Error::last_os_error().raw_os_error().unwrap_or(-1));
            }
        }
        if slave > libc::STDERR_FILENO {
            libc::close(slave);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::os::fd::AsFd;

    fn read_some(fd: impl AsFd, want: usize) -> Vec<u8> {
        // Duplicated into a File so the read is a plain blocking read and the
        // fd stays owned by the caller.
        let dup = fd.as_fd().try_clone_to_owned().unwrap();
        let mut file = std::fs::File::from(dup);
        let mut out = Vec::new();
        let mut buf = [0u8; 1024];
        while out.len() < want {
            match file.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => out.extend_from_slice(&buf[..n]),
                Err(_) => break,
            }
        }
        out
    }

    #[test]
    fn neither_end_of_the_pty_survives_an_exec() {
        // The shell runs as the tenant. A descriptor to the master would let it
        // write its own terminal's input and would hold the terminal open after
        // the agent drops its copy, which is what `kill()` relies on to hang a
        // shell up. Both ends are therefore close-on-exec; the child still gets
        // the slave, because it arrives through `dup2`, which clears the flag.
        let pair = open_pty(80, 24).expect("a pty");
        for (what, fd) in [
            ("master", pair.master.as_raw_fd()),
            ("slave", pair.slave.as_raw_fd()),
        ] {
            // SAFETY: both descriptors are open and owned by `pair`.
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
            assert!(flags >= 0, "could not read the {what} descriptor flags");
            assert_eq!(
                flags & libc::FD_CLOEXEC,
                libc::FD_CLOEXEC,
                "the pty {what} must not be inherited across execve"
            );
        }
    }

    #[test]
    fn a_pty_pair_carries_bytes_from_the_slave_to_the_master() {
        // This is the whole data path a shell's output takes: the child writes
        // to the slave, the agent reads it from the master.
        let pty = open_pty(80, 24).unwrap();
        let mut slave = std::fs::File::from(pty.slave.try_clone().unwrap());
        slave.write_all(b"hello from the shell\n").unwrap();
        slave.flush().unwrap();

        let seen = read_some(&pty.master, 21);
        let text = String::from_utf8_lossy(&seen);
        assert!(
            text.contains("hello from the shell"),
            "master saw {text:?}"
        );
    }

    #[test]
    fn the_window_size_we_set_is_the_one_the_child_would_read() {
        let pty = open_pty(132, 43).unwrap();
        assert_eq!(window_size(pty.slave.as_raw_fd()).unwrap(), (132, 43));

        set_window_size(pty.master.as_raw_fd(), 80, 24).unwrap();
        assert_eq!(window_size(pty.slave.as_raw_fd()).unwrap(), (80, 24));
    }

    #[test]
    fn a_zero_sized_window_is_clamped_rather_than_passed_through() {
        // A browser tab mid-layout reports 0×0 for a frame or two, and a
        // zero-column terminal makes curses applications divide by it.
        let pty = open_pty(80, 24).unwrap();
        set_window_size(pty.master.as_raw_fd(), 0, 0).unwrap();
        assert_eq!(window_size(pty.slave.as_raw_fd()).unwrap(), (1, 1));
    }

    #[test]
    fn the_slave_name_is_a_terminal_device() {
        let pty = open_pty(80, 24).unwrap();
        let name = pty.slave_name.to_string_lossy().into_owned();
        assert!(
            name.starts_with("/dev/pts/") || name.starts_with("/dev/tty"),
            "unexpected pts name {name:?}"
        );
    }

    /// The full child-side sequence — fork, attach, exec — against a real
    /// program, proving the child ends up with a *controlling* terminal.
    ///
    /// `tty(1)` prints the name of the terminal on its standard input and exits
    /// non-zero with "not a tty" when there is none, so its own output is the
    /// assertion. Skipped where the binary is not installed rather than
    /// failing: this test is about our wiring, not about the host's coreutils.
    #[test]
    fn a_forked_child_lands_on_a_controlling_terminal() {
        let Some(tty_bin) = ["/usr/bin/tty", "/bin/tty"]
            .into_iter()
            .find(|p| std::path::Path::new(p).exists())
        else {
            eprintln!("skipping: no tty(1) on this host");
            return;
        };

        let pty = open_pty(80, 24).unwrap();
        let slave_fd = pty.slave.as_raw_fd();

        let program = std::ffi::CString::new(tty_bin).unwrap();
        let argv0 = std::ffi::CString::new("tty").unwrap();

        // SAFETY: the child branch touches nothing but async-signal-safe libc
        // calls and execs immediately, which is the contract `fork` imposes on
        // a multi-threaded parent.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed: {}", io::Error::last_os_error());
        if pid == 0 {
            // SAFETY: post-fork, pre-exec, single-threaded — exactly the
            // context `attach_child_to_pty` documents.
            unsafe {
                if attach_child_to_pty(slave_fd).is_err() {
                    libc::_exit(91);
                }
                let argv = [argv0.as_ptr(), std::ptr::null()];
                libc::execv(program.as_ptr(), argv.as_ptr());
                libc::_exit(92);
            }
        }

        // The parent must let go of the slave, or the master never sees EOF.
        drop(pty.slave);
        let seen = read_some(&pty.master, 8);
        let text = String::from_utf8_lossy(&seen);

        let mut status = 0i32;
        // SAFETY: reaping our own child with a valid out-pointer.
        unsafe { libc::waitpid(pid, &mut status, 0) };

        assert!(
            text.contains("/dev/pts/") || text.contains("/dev/tty"),
            "tty(1) reported {text:?} — the child had no controlling terminal"
        );
    }
}
