//! The process that keeps a copied code on the clipboard until its deadline.
//!
//! `copy` hands the code to `pa-helper hold --clear-after <N>`, a fresh exec
//! of the same binary in its own process group, and exits once the holder
//! confirms. The caller may then kill the `copy` process and its whole group
//! (a shell restart, a plugin reload) without stranding the code.

use std::ffi::OsString;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdout, ExitCode, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use zeroize::{Zeroize, Zeroizing};

use crate::clipboard::Clipboard;
use crate::error::{ErrorCode, Result};
use crate::otp::{STEAM_ALPHABET, STEAM_LENGTH};
use crate::proc::{
    self, kill_and_reap, read_capped, release, scrubbed_command, spawn_tracked, IO_THREAD_STACK,
};
use crate::sys;
use crate::watchdog::Watchdog;

const STATUS_OK: u8 = b'K';
const STATUS_DEPENDENCY_MISSING: u8 = b'D';
const STATUS_FAILED: u8 = b'E';

/// How long `copy` waits for the holder to confirm that wl-copy has the code.
const STATUS_TIMEOUT: Duration = Duration::from_secs(3);
/// Covers the ownership check, wl-copy's TERM grace and `wl-copy --clear`
/// after the deadline.
const HOLD_MARGIN: Duration = Duration::from_secs(5);

const MIN_DIGITS: usize = 5;
pub const MAX_CODE_LEN: usize = 10;

/// Whether `code` is something `copy` can produce: 5 to 10 ASCII digits, or a
/// Steam Guard code.
pub fn valid_code(code: &[u8]) -> bool {
    let digits =
        (MIN_DIGITS..=MAX_CODE_LEN).contains(&code.len()) && code.iter().all(u8::is_ascii_digit);
    let steam = code.len() == STEAM_LENGTH && code.iter().all(|b| STEAM_ALPHABET.contains(b));
    digits || steam
}

/// Starts holder processes for `copy`.
pub struct Holder {
    program: Option<PathBuf>,
    prefix: Vec<OsString>,
}

impl Holder {
    /// Runs this very binary. The link is read once, here; if it is
    /// unavailable, every hand-off fails with `Internal`.
    pub fn current_exe() -> Self {
        let program = std::fs::read_link("/proc/self/exe")
            .ok()
            .filter(|p| p.is_absolute());
        Self {
            program,
            prefix: Vec::new(),
        }
    }

    /// Runs `program` with `prefix` before the `hold` arguments, for a test
    /// harness that re-executes itself.
    pub fn new(program: PathBuf, prefix: Vec<OsString>) -> Self {
        Self {
            program: Some(program),
            prefix,
        }
    }

    /// Starts a holder for `code` and returns once it has put the code on the
    /// clipboard. The code reaches the holder only through its stdin.
    ///
    /// Errors: `DependencyMissing` if wl-copy is missing; `Internal` for any
    /// other failure, including a holder that does not confirm within
    /// [`STATUS_TIMEOUT`]. On error the holder's group has been killed.
    pub fn hand_off(&self, code: Zeroizing<String>, clear_after: Duration) -> Result<()> {
        let program = self.program.as_deref().ok_or(ErrorCode::Internal)?;
        let mut command = scrubbed_command(program);
        command
            .args(&self.prefix)
            .args(["hold", "--clear-after", &clear_after.as_secs().to_string()])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let mut child = spawn_tracked(&mut command).map_err(|_| ErrorCode::Internal)?;
        match feed_and_confirm(&mut child, code) {
            Ok(()) => {
                release(child);
                Ok(())
            }
            Err(e) => {
                kill_and_reap(&mut child);
                Err(e)
            }
        }
    }
}

fn feed_and_confirm(child: &mut Child, code: Zeroizing<String>) -> Result<()> {
    let stdout = child.stdout.take().ok_or(ErrorCode::Internal)?;
    let mut stdin = child.stdin.take().ok_or(ErrorCode::Internal)?;
    stdin
        .write_all(code.as_bytes())
        .map_err(|_| ErrorCode::Internal)?;
    drop(stdin);
    drop(code);
    match read_status(stdout)? {
        STATUS_OK => Ok(()),
        STATUS_DEPENDENCY_MISSING => Err(ErrorCode::DependencyMissing),
        _ => Err(ErrorCode::Internal),
    }
}

fn read_status(mut stdout: ChildStdout) -> Result<u8> {
    let (tx, rx) = mpsc::channel();
    thread::Builder::new()
        .stack_size(IO_THREAD_STACK)
        .spawn(move || {
            let mut status = [0u8; 1];
            let _ = tx.send(stdout.read_exact(&mut status).map(|()| status[0]));
        })
        .map_err(|_| ErrorCode::Internal)?;
    match rx.recv_timeout(STATUS_TIMEOUT) {
        Ok(Ok(status)) => Ok(status),
        _ => Err(ErrorCode::Internal),
    }
}

fn read_code() -> Result<Zeroizing<String>> {
    let mut input = read_capped(io::stdin().lock(), MAX_CODE_LEN)?;
    if !valid_code(&input) {
        return Err(ErrorCode::InvalidArgument);
    }
    String::from_utf8(std::mem::take(&mut *input))
        .map(Zeroizing::new)
        .map_err(|e| {
            e.into_bytes().zeroize();
            ErrorCode::Internal
        })
}

fn report(status: u8) -> io::Result<()> {
    let mut out = io::stdout().lock();
    out.write_all(&[status])?;
    out.flush()
}

fn status_of(e: ErrorCode) -> u8 {
    match e {
        ErrorCode::DependencyMissing => STATUS_DEPENDENCY_MISSING,
        _ => STATUS_FAILED,
    }
}

/// The holder's watchdog action. Killing wl-copy takes the code off the
/// clipboard, so nothing is left to clear.
fn abandon() {
    let _frozen = proc::kill_active_groups();
    std::process::exit(1);
}

/// `pa-helper hold`: reads one code from stdin, puts it on the clipboard,
/// answers with one status byte on stdout, closes stdout and holds the code
/// until `clear_after` has passed. Never touches the vault or the keyring.
///
/// Its own watchdog ends it at `clear_after` plus a margin; the run budget of
/// other commands does not apply.
pub fn hold(clear_after: Duration, clipboard: &dyn Clipboard) -> ExitCode {
    let watchdog = match clear_after
        .checked_add(HOLD_MARGIN)
        .ok_or(ErrorCode::Internal)
        .and_then(|after| Watchdog::arm(after, abandon))
    {
        Ok(watchdog) => watchdog,
        Err(e) => {
            let _ = report(status_of(e));
            return ExitCode::FAILURE;
        }
    };
    let started = sys::detach_session()
        .and_then(|()| read_code())
        .and_then(|code| clipboard.start(code, clear_after));
    let hold = match started {
        Ok(hold) => hold,
        Err(e) => {
            watchdog.cancel();
            let _ = report(status_of(e));
            return ExitCode::FAILURE;
        }
    };
    if report(STATUS_OK).is_err() || sys::close_stdout().is_err() {
        hold.abort();
        watchdog.cancel();
        return ExitCode::FAILURE;
    }
    let cleared = hold.wait_and_clear();
    watchdog.cancel();
    if cleared.is_ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_codes_copy_can_produce() {
        for ok in [
            "12345",
            "123456",
            "12345678",
            "1234567890",
            "2BCDF",
            "YXWVT",
            "23456",
        ] {
            assert!(valid_code(ok.as_bytes()), "{ok}");
        }
        for bad in [
            "",
            "1234",
            "12345678901",
            "123456\n",
            " 123456",
            "12a456",
            "ABCDE",
            "2bcdf",
            "2BCDF6",
            "1BCDF",
            "１２３４５",
        ] {
            assert!(!valid_code(bad.as_bytes()), "{bad:?}");
        }
    }
}
