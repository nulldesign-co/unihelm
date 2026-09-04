//! `sd_notify` — the systemd readiness and watchdog protocol (spec §5.5).
//!
//! Implemented directly rather than through a crate: it is one datagram write to
//! the socket in `$NOTIFY_SOCKET`, and the whole point of this project is that
//! every dependency has to earn its megabytes.
//!
//! Both daemons use this. `Type=notify` means systemd knows the difference
//! between "the process started" and "the panel is actually ready", and
//! `WatchdogSec` means a wedged daemon gets restarted instead of hanging around
//! looking alive — the specific failure that makes other panels feel unreliable.

use std::os::unix::net::UnixDatagram;
use std::time::Duration;

/// Send a raw notification. Silently does nothing when not run by systemd.
fn notify(message: &str) {
    let Ok(path) = std::env::var("NOTIFY_SOCKET") else {
        return;
    };
    if path.is_empty() {
        return;
    }

    // A leading '@' means an abstract socket; Rust's UnixDatagram wants a NUL.
    let path = if let Some(rest) = path.strip_prefix('@') {
        format!("\0{rest}")
    } else {
        path
    };

    let Ok(sock) = UnixDatagram::unbound() else {
        return;
    };
    if let Err(e) = sock.send_to(message.as_bytes(), &path) {
        // No tracing here: `unihelm-core` stays dependency-light, and a failed
        // notification is not something a caller can act on.
        let _ = e;
    }
}

/// "Startup finished; dependent units may proceed."
pub fn ready() {
    notify("READY=1");
}

/// Watchdog heartbeat. Must arrive more often than `WatchdogSec` or systemd
/// restarts us — which is the intended behaviour if we ever wedge.
pub fn watchdog() {
    notify("WATCHDOG=1");
}

pub fn stopping() {
    notify("STOPPING=1");
}

/// A one-line status shown by `systemctl status`.
pub fn status(text: &str) {
    // Newlines would split the datagram into separate assignments.
    notify(&format!("STATUS={}", text.replace('\n', " ")));
}

/// How often to send a heartbeat, derived from `$WATCHDOG_USEC`.
///
/// systemd's guidance is to ping at half the configured interval; that leaves
/// room for one missed beat under load before we get restarted.
pub fn watchdog_interval() -> Option<Duration> {
    let usec: u64 = std::env::var("WATCHDOG_USEC").ok()?.parse().ok()?;
    // `WATCHDOG_PID`, when set, names the process systemd expects beats from.
    if let Ok(pid) = std::env::var("WATCHDOG_PID")
        && pid.parse::<u32>().ok() != Some(std::process::id())
    {
        return None;
    }
    (usec > 0).then(|| Duration::from_micros(usec / 2))
}

// The heartbeat loop itself lives in each binary: `unihelm-core` links no async
// runtime, and driving a timer is three lines where tokio is already present.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notifications_are_a_no_op_outside_systemd() {
        // SAFETY: single-threaded test; no other thread reads the environment.
        unsafe { std::env::remove_var("NOTIFY_SOCKET") };
        ready();
        watchdog();
        status("still here");
    }

    /// These two tests set and clear the same process-wide variables, and cargo
    /// runs tests in one binary on several threads — so without this they
    /// interleave, and one reads a `WATCHDOG_PID` the other had just set. It
    /// failed roughly one run in five, which is the worst frequency: often
    /// enough to redden CI, rarely enough to look like something else.
    static ENV: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn watchdog_interval_is_half_the_configured_timeout() {
        let _guard = ENV.lock().unwrap_or_else(|e| e.into_inner());
        // SAFETY: as above.
        unsafe {
            std::env::remove_var("WATCHDOG_PID");
            std::env::set_var("WATCHDOG_USEC", "30000000");
        }
        assert_eq!(watchdog_interval(), Some(Duration::from_secs(15)));

        unsafe { std::env::set_var("WATCHDOG_USEC", "0") };
        assert_eq!(watchdog_interval(), None);

        unsafe { std::env::remove_var("WATCHDOG_USEC") };
        assert_eq!(watchdog_interval(), None);
    }

    #[test]
    fn a_watchdog_meant_for_another_pid_is_ignored() {
        let _guard = ENV.lock().unwrap_or_else(|e| e.into_inner());
        // SAFETY: as above.
        unsafe {
            std::env::set_var("WATCHDOG_USEC", "30000000");
            std::env::set_var("WATCHDOG_PID", "1");
        }
        assert_eq!(watchdog_interval(), None);
        unsafe {
            std::env::remove_var("WATCHDOG_PID");
            std::env::remove_var("WATCHDOG_USEC");
        }
    }
}
