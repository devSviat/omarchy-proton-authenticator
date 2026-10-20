use std::io::Write;
use std::path::PathBuf;
use std::process::{Child, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use crate::error::{ErrorCode, Result};
use crate::proc::{child_pgid, kill_and_reap, run_bounded, scrubbed_command, spawn_error};
use crate::sys::{self, Signal};

const DEFAULT_WL_COPY: &str = "/usr/bin/wl-copy";
const POLL_INTERVAL: Duration = Duration::from_millis(10);
const TERM_GRACE: Duration = Duration::from_millis(500);
const CLEAR_TIMEOUT: Duration = Duration::from_secs(2);

pub trait Clipboard {
    /// Puts `code` on the clipboard and clears it after `clear_after`, unless
    /// another client has taken the selection by then.
    fn hold(&self, code: Zeroizing<String>, clear_after: Duration) -> Result<()>;
}

/// Holds the selection with `wl-copy --foreground --sensitive --type text/plain`.
///
/// The child process owning the selection is the only ownership signal: it
/// exits as soon as another client copies something. So deciding whether to
/// clear never needs the code again, and no copy or hash of it outlives the
/// write to the child's stdin.
///
/// The explicit MIME type stops wl-copy from inferring one by running
/// xdg-mime on a temporary copy of the code. wl-copy may still buffer the
/// data in a tmpfs file of its own, which is outside this process's control.
///
/// A copy made by another client within milliseconds of the deadline can race
/// the ownership check and be cleared.
pub struct WlCopy {
    program: PathBuf,
}

impl WlCopy {
    pub fn new(program: PathBuf) -> Self {
        Self { program }
    }

    fn clear(&self) -> Result<()> {
        match run_bounded(&self.program, &["--clear"], None, 0, CLEAR_TIMEOUT)? {
            (0, _) => Ok(()),
            _ => Err(ErrorCode::Internal),
        }
    }

    /// The code may already be on the clipboard when holding fails, so the
    /// selection is cleared even though it might belong to someone else by now.
    fn abort(&self, child: &mut Child, e: ErrorCode) -> ErrorCode {
        kill_and_reap(child);
        let _ = self.clear();
        e
    }
}

impl Default for WlCopy {
    fn default() -> Self {
        Self::new(PathBuf::from(DEFAULT_WL_COPY))
    }
}

fn feed(child: &mut Child, code: Zeroizing<String>) -> Result<()> {
    let mut stdin = child.stdin.take().ok_or(ErrorCode::Internal)?;
    stdin
        .write_all(code.as_bytes())
        .map_err(|_| ErrorCode::Internal)
}

fn wait_exit(pgid: i32, deadline: Instant) -> Result<bool> {
    loop {
        if sys::has_exited(pgid)? {
            return Ok(true);
        }
        if Instant::now() >= deadline {
            return Ok(false);
        }
        thread::sleep(POLL_INTERVAL);
    }
}

impl Clipboard for WlCopy {
    fn hold(&self, code: Zeroizing<String>, clear_after: Duration) -> Result<()> {
        let deadline = Instant::now()
            .checked_add(clear_after)
            .ok_or(ErrorCode::Internal)?;
        let mut child = scrubbed_command(&self.program)
            .args(["--foreground", "--sensitive", "--type", "text/plain"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| spawn_error(&e))?;

        let held = feed(&mut child, code)
            .and_then(|()| child_pgid(&child))
            .and_then(|pgid| Ok((pgid, wait_exit(pgid, deadline)?)));
        let pgid = match held {
            Ok((_, true)) => {
                child.wait().map_err(|_| ErrorCode::Internal)?;
                return Ok(());
            }
            Ok((pgid, false)) => pgid,
            Err(e) => return Err(self.abort(&mut child, e)),
        };

        let terminated = sys::kill_process_group(pgid, Signal::Term)
            .and_then(|()| wait_exit(pgid, Instant::now() + TERM_GRACE))
            .unwrap_or(false);
        let reaped = if terminated {
            let _ = sys::kill_process_group(pgid, Signal::Kill);
            child.wait().map(drop).map_err(|_| ErrorCode::Internal)
        } else {
            kill_and_reap(&mut child);
            Ok(())
        };
        let cleared = self.clear();
        reaped.and(cleared)
    }
}
