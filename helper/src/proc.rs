use std::io::{Read, Write};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::sync::{Mutex, MutexGuard, TryLockError};
use std::thread;
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use crate::error::{ErrorCode, Result};
use crate::sys::{self, Signal};

const ALLOWED_ENV: [&str; 4] = [
    "HOME",
    "XDG_RUNTIME_DIR",
    "WAYLAND_DISPLAY",
    "DBUS_SESSION_BUS_ADDRESS",
];
const POLL_INTERVAL: Duration = Duration::from_millis(10);

type Captured = Result<Zeroizing<Vec<u8>>>;

/// Reader and writer threads only shuttle bytes through heap buffers, so a
/// small stack is enough; under `mlockall` every stack counts against the
/// locked-memory budget.
pub(crate) const IO_THREAD_STACK: usize = 64 * 1024;

/// A command for `program` with a cleared environment plus the allow-listed
/// variables, running in its own process group so it can be killed as a whole.
pub(crate) fn scrubbed_command(program: &Path) -> Command {
    let mut command = scrubbed_env_command(program);
    command.process_group(0);
    command
}

/// [`scrubbed_command`] without the process group, for a caller that makes
/// the child lead a group of its own another way.
pub(crate) fn scrubbed_env_command(program: &Path) -> Command {
    let mut command = Command::new(program);
    command.env_clear();
    for name in ALLOWED_ENV {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    command
}

pub(crate) fn spawn_error(e: &std::io::Error) -> ErrorCode {
    match e.kind() {
        std::io::ErrorKind::NotFound => ErrorCode::DependencyMissing,
        _ => ErrorCode::Internal,
    }
}

pub(crate) fn child_pgid(child: &Child) -> Result<i32> {
    i32::try_from(child.id()).map_err(|_| ErrorCode::Internal)
}

/// Process groups of children spawned and not yet reaped. Spawning, reaping
/// and [`kill_active_groups`] all hold this lock, so a recorded group id always
/// names one of our live or zombie children, never a reused pid.
static ACTIVE_GROUPS: Mutex<Vec<i32>> = Mutex::new(Vec::new());

fn active_groups() -> MutexGuard<'static, Vec<i32>> {
    ACTIVE_GROUPS.lock().unwrap_or_else(|e| e.into_inner())
}

/// Spawns `command` (built by [`scrubbed_command`], so the child leads its own
/// group) and records its group for [`kill_active_groups`].
pub(crate) fn spawn_tracked(command: &mut Command) -> Result<Child> {
    let mut groups = active_groups();
    let child = command.spawn().map_err(|e| spawn_error(&e))?;
    match child_pgid(&child) {
        Ok(pgid) => groups.push(pgid),
        Err(e) => {
            drop(groups);
            let mut child = child;
            let _ = child.kill();
            let _ = child.wait();
            return Err(e);
        }
    }
    Ok(child)
}

fn untrack(groups: &mut Vec<i32>, child: &Child) {
    if let Ok(pgid) = child_pgid(child) {
        groups.retain(|g| *g != pgid);
    }
}

/// Reaps a child started by [`spawn_tracked`] and forgets its group.
pub(crate) fn reap(child: &mut Child) -> Result<ExitStatus> {
    let mut groups = active_groups();
    untrack(&mut groups, child);
    child.wait().map_err(|_| ErrorCode::Internal)
}

/// Forgets a child started by [`spawn_tracked`] without reaping or killing
/// it, so it outlives this process and a later watchdog expiry spares it.
pub(crate) fn release(child: Child) {
    let mut groups = active_groups();
    untrack(&mut groups, &child);
}

/// Kills the child's whole process group, then reaps the child. The child is
/// still unreaped here, so its pid cannot have been reused as another group id.
pub(crate) fn kill_and_reap(child: &mut Child) {
    let mut groups = active_groups();
    untrack(&mut groups, child);
    match child_pgid(child) {
        Ok(pgid) => {
            let _ = sys::kill_process_group(pgid, Signal::Kill);
        }
        Err(_) => {
            let _ = child.kill();
        }
    }
    let _ = child.wait();
}

/// How long the watchdog waits for the group lock. The main thread holds it
/// only around `spawn` and around reaping a child that has already exited or
/// been SIGKILLed, but a child stuck in uninterruptible sleep could stall
/// either, and a timeout must still end the process.
const KILL_LOCK_PATIENCE: Duration = Duration::from_millis(200);
const KILL_LOCK_STEP: Duration = Duration::from_millis(10);

/// SIGKILLs every group recorded by [`spawn_tracked`] and returns the lock, so
/// no child can be spawned or reaped until the caller drops it. Meant for a
/// caller that is about to end the process. Returns `None`, killing nothing,
/// if the lock stays busy for the whole wait.
pub fn kill_active_groups() -> Option<MutexGuard<'static, Vec<i32>>> {
    kill_active_groups_within(KILL_LOCK_PATIENCE)
}

fn kill_active_groups_within(patience: Duration) -> Option<MutexGuard<'static, Vec<i32>>> {
    let deadline = Instant::now() + patience;
    let groups = loop {
        match ACTIVE_GROUPS.try_lock() {
            Ok(groups) => break groups,
            Err(TryLockError::Poisoned(e)) => break e.into_inner(),
            Err(TryLockError::WouldBlock) if Instant::now() < deadline => {
                thread::sleep(KILL_LOCK_STEP);
            }
            Err(TryLockError::WouldBlock) => return None,
        }
    };
    for pgid in groups.iter() {
        let _ = sys::kill_process_group(*pgid, Signal::Kill);
    }
    Some(groups)
}

/// Runs `program` by absolute path with a scrubbed environment and returns
/// its exit code (-1 if killed by a signal) and stdout.
///
/// The whole call, including waiting for stdout to reach EOF after the child
/// has exited, is bounded by `timeout`; a descendant that keeps the pipe open
/// past the deadline yields `Timeout`. On every error the child's process
/// group gets SIGKILL, so lingering descendants die with it. Reader and writer
/// threads are never joined, so a descendant outside the group cannot block
/// the caller; the reader drops its zeroizing buffer on exit.
///
/// Stdout is read into a buffer allocated once at `max_out + 1` bytes and
/// never reallocated, so no unzeroized copies are left behind.
pub fn run_bounded(
    program: &Path,
    args: &[&str],
    stdin: Option<&[u8]>,
    max_out: usize,
    timeout: Duration,
) -> Result<(i32, Zeroizing<Vec<u8>>)> {
    let deadline = Instant::now() + timeout;
    let mut command = scrubbed_command(program);
    command
        .args(args)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::null());

    let mut child = spawn_tracked(&mut command)?;

    let result = drive(&mut child, stdin, max_out, deadline);
    if result.is_err() {
        kill_and_reap(&mut child);
    }
    result
}

fn drive(
    child: &mut Child,
    stdin: Option<&[u8]>,
    max_out: usize,
    deadline: Instant,
) -> Result<(i32, Zeroizing<Vec<u8>>)> {
    let stdout = child.stdout.take().ok_or(ErrorCode::Internal)?;
    let pipe = child.stdin.take();
    let (tx, rx) = mpsc::channel();
    thread::Builder::new()
        .stack_size(IO_THREAD_STACK)
        .spawn(move || {
            let _ = tx.send(read_capped(stdout, max_out));
        })
        .map_err(|_| ErrorCode::Internal)?;

    if let (Some(data), Some(mut pipe)) = (stdin, pipe) {
        let data = Zeroizing::new(data.to_vec());
        thread::Builder::new()
            .stack_size(IO_THREAD_STACK)
            .spawn(move || {
                let _ = pipe.write_all(&data);
            })
            .map_err(|_| ErrorCode::Internal)?;
    }

    wait_for_both(child, &rx, max_out, deadline)
}

fn wait_for_both(
    child: &mut Child,
    rx: &Receiver<Captured>,
    max_out: usize,
    deadline: Instant,
) -> Result<(i32, Zeroizing<Vec<u8>>)> {
    let pid = child_pgid(child)?;
    let mut exited = false;
    let mut output = None;
    loop {
        if !exited {
            exited = sys::has_exited(pid)?;
        }
        if output.is_none() {
            match rx.try_recv() {
                Ok(Ok(buf)) if buf.len() > max_out => return Err(ErrorCode::OutputTooLarge),
                Ok(Ok(buf)) => output = Some(buf),
                Ok(Err(code)) => return Err(code),
                Err(TryRecvError::Empty) => {}
                Err(TryRecvError::Disconnected) => return Err(ErrorCode::Internal),
            }
        }
        if exited {
            if let Some(buf) = output.take() {
                let status = reap(child)?;
                return Ok((status.code().unwrap_or(-1), buf));
            }
        }
        if Instant::now() >= deadline {
            return Err(ErrorCode::Timeout);
        }
        thread::sleep(POLL_INTERVAL);
    }
}

fn read_capped(mut source: impl Read, max_out: usize) -> Captured {
    let limit = max_out + 1;
    let mut buf = Zeroizing::new(Vec::with_capacity(limit));
    buf.resize(limit, 0);
    let mut filled = 0;
    while filled < limit {
        match source.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return Err(ErrorCode::Internal),
        }
    }
    buf.truncate(filled);
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kill_active_groups_gives_up_on_a_held_lock() {
        let held = active_groups();
        let start = Instant::now();
        let outcome =
            thread::spawn(|| kill_active_groups_within(Duration::from_millis(100)).is_some())
                .join()
                .unwrap();
        let waited = start.elapsed();
        drop(held);
        assert!(!outcome);
        assert!(waited >= Duration::from_millis(100), "{waited:?}");
        assert!(waited < Duration::from_secs(1), "{waited:?}");
    }

    const TIMEOUT: Duration = Duration::from_secs(5);

    #[test]
    fn run_bounded_caps_output() {
        let r = run_bounded(
            Path::new("/usr/bin/head"),
            &["-c", "100", "/dev/zero"],
            None,
            64,
            TIMEOUT,
        );
        assert_eq!(r.unwrap_err(), ErrorCode::OutputTooLarge);
    }

    #[test]
    fn run_bounded_accepts_exact_limit() {
        let (code, out) = run_bounded(
            Path::new("/usr/bin/head"),
            &["-c", "64", "/dev/zero"],
            None,
            64,
            TIMEOUT,
        )
        .unwrap();
        assert_eq!(code, 0);
        assert_eq!(out.len(), 64);
    }

    #[test]
    fn run_bounded_times_out() {
        let start = Instant::now();
        let r = run_bounded(
            Path::new("/usr/bin/sleep"),
            &["5"],
            None,
            64,
            Duration::from_millis(200),
        );
        assert_eq!(r.unwrap_err(), ErrorCode::Timeout);
        assert!(start.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn run_bounded_missing_program() {
        let r = run_bounded(
            Path::new("/usr/bin/pa-no-such-program"),
            &[],
            None,
            64,
            TIMEOUT,
        );
        assert_eq!(r.unwrap_err(), ErrorCode::DependencyMissing);
    }

    #[test]
    fn run_bounded_clears_env() {
        let (code, out) =
            run_bounded(Path::new("/usr/bin/env"), &[], None, 65536, TIMEOUT).unwrap();
        assert_eq!(code, 0);
        for line in String::from_utf8_lossy(&out).lines() {
            let key = line.split('=').next().unwrap();
            assert!(ALLOWED_ENV.contains(&key), "unexpected env var {key}");
        }
    }

    #[test]
    fn run_bounded_passes_stdin() {
        let (code, out) = run_bounded(
            Path::new("/usr/bin/cat"),
            &[],
            Some(b"hello\x00\xff"),
            64,
            TIMEOUT,
        )
        .unwrap();
        assert_eq!(code, 0);
        assert_eq!(&out[..], b"hello\x00\xff");
    }

    #[test]
    fn run_bounded_reports_exit_code() {
        let (code, out) = run_bounded(Path::new("/usr/bin/false"), &[], None, 64, TIMEOUT).unwrap();
        assert_eq!(code, 1);
        assert!(out.is_empty());
    }

    #[test]
    fn run_bounded_timeout_with_lingering_grandchild() {
        let start = Instant::now();
        let r = run_bounded(
            Path::new("/bin/sh"),
            &["-c", "sleep 3 & sleep 10"],
            None,
            64,
            Duration::from_millis(200),
        );
        assert_eq!(r.unwrap_err(), ErrorCode::Timeout);
        assert!(start.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn run_bounded_timeout_kills_process_group() {
        let dir = tempfile::tempdir().unwrap();
        let pid_file = dir.path().join("pgid");
        let script = format!(
            "echo $$ > {}; /usr/bin/sleep 30 & /usr/bin/sleep 30",
            pid_file.display()
        );
        let r = run_bounded(
            Path::new("/bin/sh"),
            &["-c", &script],
            None,
            64,
            Duration::from_millis(200),
        );
        assert_eq!(r.unwrap_err(), ErrorCode::Timeout);
        let pgid: i32 = std::fs::read_to_string(&pid_file)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        while crate::sys::process_group_exists(pgid) {
            assert!(Instant::now() < deadline, "process group {pgid} survived");
            thread::sleep(POLL_INTERVAL);
        }
    }

    #[test]
    fn run_bounded_success_does_not_wait_for_grandchild() {
        let start = Instant::now();
        let r = run_bounded(
            Path::new("/bin/sh"),
            &["-c", "sleep 3 & exit 0"],
            None,
            64,
            Duration::from_millis(500),
        );
        assert_eq!(r.unwrap_err(), ErrorCode::Timeout);
        assert!(start.elapsed() < Duration::from_secs(1));
    }
}
