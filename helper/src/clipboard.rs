use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use crate::error::{ErrorCode, Result};
use crate::proc::{child_pgid, kill_and_reap, reap, run_bounded, scrubbed_command, spawn_tracked};
use crate::sys::{self, Signal};

pub const WL_COPY: &str = "/usr/bin/wl-copy";
const POLL_INTERVAL: Duration = Duration::from_millis(10);
const TERM_GRACE: Duration = Duration::from_millis(500);
const CLEAR_TIMEOUT: Duration = Duration::from_secs(2);

pub trait Clipboard {
    /// Puts `code` on the clipboard. The returned hold clears it once
    /// `clear_after` has passed since this call, unless another client has
    /// taken the selection by then.
    fn start(&self, code: Zeroizing<String>, clear_after: Duration) -> Result<Box<dyn Hold>>;

    /// [`Clipboard::start`] followed by [`Hold::wait_and_clear`].
    fn hold(&self, code: Zeroizing<String>, clear_after: Duration) -> Result<()> {
        self.start(code, clear_after)?.wait_and_clear()
    }
}

/// A code on the clipboard that still has to be cleared.
pub trait Hold {
    /// Blocks until another client takes the selection or the deadline
    /// passes, then clears the selection in the latter case.
    fn wait_and_clear(self: Box<Self>) -> Result<()>;

    /// Gives up holding at once and clears the selection.
    fn abort(self: Box<Self>);
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
///
/// The child gets SIGTERM if the thread that called [`Clipboard::start`]
/// ends, so killing the holding process takes the code off the clipboard too.
pub struct WlCopy {
    program: PathBuf,
}

impl WlCopy {
    pub fn new(program: PathBuf) -> Self {
        Self { program }
    }
}

impl Default for WlCopy {
    fn default() -> Self {
        Self::new(PathBuf::from(WL_COPY))
    }
}

fn clear(program: &Path) -> Result<()> {
    match run_bounded(program, &["--clear"], None, 0, CLEAR_TIMEOUT)? {
        (0, _) => Ok(()),
        _ => Err(ErrorCode::Internal),
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

struct WlCopyHold {
    program: PathBuf,
    child: Child,
    pgid: i32,
    deadline: Instant,
    settled: bool,
}

impl WlCopyHold {
    /// The code may already be on the clipboard when holding fails, so the
    /// selection is cleared even though it might belong to someone else by now.
    fn fail(&mut self, e: ErrorCode) -> ErrorCode {
        self.settled = true;
        kill_and_reap(&mut self.child);
        let _ = clear(&self.program);
        e
    }
}

/// A hold dropped without `wait_and_clear` or `abort` (an early return or a
/// future caller's mistake) must not leave the code on the clipboard.
impl Drop for WlCopyHold {
    fn drop(&mut self) {
        if !self.settled {
            self.fail(ErrorCode::Internal);
        }
    }
}

impl Clipboard for WlCopy {
    fn start(&self, code: Zeroizing<String>, clear_after: Duration) -> Result<Box<dyn Hold>> {
        let deadline = Instant::now()
            .checked_add(clear_after)
            .ok_or(ErrorCode::Internal)?;
        let mut command = scrubbed_command(&self.program);
        command
            .args(["--foreground", "--sensitive", "--type", "text/plain"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        sys::term_when_parent_dies(&mut command);
        let mut child = spawn_tracked(&mut command)?;
        let pgid = match child_pgid(&child) {
            Ok(pgid) => pgid,
            Err(e) => {
                kill_and_reap(&mut child);
                return Err(e);
            }
        };
        let mut hold = WlCopyHold {
            program: self.program.clone(),
            child,
            pgid,
            deadline,
            settled: false,
        };
        match feed(&mut hold.child, code) {
            Ok(()) => Ok(Box::new(hold)),
            Err(e) => Err(hold.fail(e)),
        }
    }
}

impl Hold for WlCopyHold {
    fn wait_and_clear(mut self: Box<Self>) -> Result<()> {
        self.settled = true;
        match wait_exit(self.pgid, self.deadline) {
            Ok(true) => return reap(&mut self.child).map(drop),
            Ok(false) => {}
            Err(e) => return Err(self.fail(e)),
        }
        let terminated = sys::kill_process_group(self.pgid, Signal::Term)
            .and_then(|()| wait_exit(self.pgid, Instant::now() + TERM_GRACE))
            .unwrap_or(false);
        let reaped = if terminated {
            let _ = sys::kill_process_group(self.pgid, Signal::Kill);
            reap(&mut self.child).map(drop)
        } else {
            kill_and_reap(&mut self.child);
            Ok(())
        };
        let cleared = clear(&self.program);
        reaped.and(cleared)
    }

    fn abort(mut self: Box<Self>) {
        self.fail(ErrorCode::Internal);
    }
}
