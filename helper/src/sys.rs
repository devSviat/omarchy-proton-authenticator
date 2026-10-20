#![allow(unsafe_code)]

use std::fs::OpenOptions;
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::process::Command;

use crate::error::{ErrorCode, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signal {
    Term,
    Kill,
}

impl Signal {
    fn raw(self) -> libc::c_int {
        match self {
            Self::Term => libc::SIGTERM,
            Self::Kill => libc::SIGKILL,
        }
    }
}

fn errno() -> Option<i32> {
    io::Error::last_os_error().raw_os_error()
}

/// Makes the process non-dumpable, disables core files and locks all current
/// and future pages in RAM (on fault, so untouched reservations stay free).
///
/// Errors: `MemlockFailed` if `mlockall` is refused, e.g. because the mapped
/// size exceeds `RLIMIT_MEMLOCK`; `Internal` for the other two calls.
pub fn harden() -> Result<()> {
    // SAFETY: PR_SET_DUMPABLE takes one integer argument and touches no memory.
    if unsafe {
        libc::prctl(
            libc::PR_SET_DUMPABLE,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
        )
    } != 0
    {
        return Err(ErrorCode::Internal);
    }
    let no_core = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `no_core` is a valid rlimit that outlives the call.
    if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &no_core) } != 0 {
        return Err(ErrorCode::Internal);
    }
    // SAFETY: mlockall only takes flags and touches no Rust-visible memory.
    if unsafe { libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE | libc::MCL_ONFAULT) } != 0 {
        return Err(ErrorCode::MemlockFailed);
    }
    Ok(())
}

pub fn is_dumpable() -> bool {
    // SAFETY: PR_GET_DUMPABLE takes no pointer arguments.
    let dumpable = unsafe {
        libc::prctl(
            libc::PR_GET_DUMPABLE,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
        )
    };
    dumpable != 0
}

/// Marks every descriptor above stderr close-on-exec, so descriptors the
/// caller leaked without `FD_CLOEXEC` never reach the exec'd program.
///
/// Marking instead of closing keeps std's own close-on-exec pipe, through
/// which a failed exec (a missing program) is reported. Kernels before 5.11
/// lack the flag (ENOSYS or EINVAL) and are left as they are.
///
/// Async-signal-safe: one raw syscall, no allocation.
fn cloexec_inherited_fds() -> io::Result<()> {
    // SAFETY: close_range takes three plain integers and touches no memory;
    // with CLOSE_RANGE_CLOEXEC it only sets descriptor flags.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_close_range,
            3 as libc::c_long,
            libc::c_long::from(u32::MAX),
            libc::CLOSE_RANGE_CLOEXEC as libc::c_long,
        )
    };
    match rc {
        0 => Ok(()),
        _ if matches!(errno(), Some(libc::ENOSYS | libc::EINVAL)) => Ok(()),
        _ => Err(io::Error::last_os_error()),
    }
}

/// Makes the child that `command` spawns start a new session before exec,
/// so it leads its own session and process group (pgid == pid) and has no
/// controlling terminal: signals to the caller's group or a terminal hangup
/// never reach it. Must not be combined with `process_group`. Inherited
/// descriptors beyond stdio are not passed on.
pub fn new_session_on_spawn(command: &mut Command) {
    // SAFETY: the closure runs in the child between fork and exec and makes
    // only async-signal-safe calls (setsid, close_range) without allocating;
    // an OS error is stored inline in io::Error.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(io::Error::last_os_error());
            }
            cloexec_inherited_fds()
        });
    }
}

/// Reads up to `buf.len()` bytes from fd 0 straight into `buf`, until EOF or
/// the buffer is full, and returns how many were read. Unlike `io::stdin()`,
/// this leaves no copy in a process-wide buffer.
pub fn read_stdin_unbuffered(buf: &mut [u8]) -> Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        let rest = &mut buf[filled..];
        // SAFETY: `rest` is a valid, writable buffer of `rest.len()` bytes for
        // the duration of the call; fd 0 is only read, never closed.
        let n = unsafe { libc::read(libc::STDIN_FILENO, rest.as_mut_ptr().cast(), rest.len()) };
        match n {
            0 => break,
            n if n > 0 => filled += n as usize,
            _ if errno() == Some(libc::EINTR) => {}
            _ => return Err(ErrorCode::Internal),
        }
    }
    Ok(filled)
}

/// Points fd 1 at `/dev/null`, so a reader of our stdout sees EOF while the
/// process keeps running.
pub fn close_stdout() -> Result<()> {
    let null = OpenOptions::new()
        .write(true)
        .open("/dev/null")
        .map_err(|_| ErrorCode::Internal)?;
    // SAFETY: `null` is an open descriptor owned by this frame; dup2 atomically
    // replaces fd 1, which std keeps using as an ordinary descriptor.
    if unsafe { libc::dup2(null.as_raw_fd(), libc::STDOUT_FILENO) } == -1 {
        return Err(ErrorCode::Internal);
    }
    Ok(())
}

/// Makes the child that `command` spawns receive SIGTERM once the spawning
/// thread ends, so a killed holder never leaves its clipboard owner behind.
/// Inherited descriptors beyond stdio are not passed on.
///
/// The signal follows the thread, not the process: spawn from a thread that
/// lives as long as the child is needed.
pub fn term_when_parent_dies(command: &mut Command) {
    let parent = std::process::id() as libc::pid_t;
    // SAFETY: the closure runs in the child between fork and exec and makes
    // only async-signal-safe calls (prctl, getppid, close_range) without
    // allocating; an OS error is stored inline in io::Error.
    unsafe {
        command.pre_exec(move || {
            if libc::prctl(
                libc::PR_SET_PDEATHSIG,
                libc::SIGTERM as libc::c_ulong,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
            ) != 0
            {
                return Err(io::Error::last_os_error());
            }
            // The parent may have died before prctl took effect.
            if libc::getppid() != parent {
                return Err(io::Error::from_raw_os_error(libc::ESRCH));
            }
            cloexec_inherited_fds()
        });
    }
}

/// Sends `signal` to every process in group `pgid`. A group that no longer
/// exists is not an error.
///
/// The caller must not have reaped the group leader yet: once its pid is
/// freed, the number could name an unrelated group.
///
/// Our own group is refused, so a stale or wrong id can never signal us.
pub fn kill_process_group(pgid: i32, signal: Signal) -> Result<()> {
    // SAFETY: getpgrp has no arguments and cannot fail.
    if pgid <= 1 || pgid == unsafe { libc::getpgrp() } {
        return Err(ErrorCode::Internal);
    }
    // SAFETY: kill takes plain integers; a negative pid addresses the group,
    // and pgid > 1 rules out "every process" (-1) and our own group (0).
    if unsafe { libc::kill(-pgid, signal.raw()) } == 0 || errno() == Some(libc::ESRCH) {
        Ok(())
    } else {
        Err(ErrorCode::Internal)
    }
}

/// Whether any process, zombies included, is still in group `pgid`.
pub fn process_group_exists(pgid: i32) -> bool {
    if pgid <= 1 {
        return false;
    }
    // SAFETY: signal 0 only checks existence and permission.
    let rc = unsafe { libc::kill(-pgid, 0) };
    rc == 0 || errno() == Some(libc::EPERM)
}

/// Whether child `pid` has exited, without reaping it, so its pid (and thus
/// its process group id) stays reserved until the caller waits on it.
pub fn has_exited(pid: i32) -> Result<bool> {
    let id = libc::id_t::try_from(pid).map_err(|_| ErrorCode::Internal)?;
    // SAFETY: siginfo_t is plain data for which all-zero bytes are valid.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    // SAFETY: `info` is a valid, writable siginfo_t for the duration of the call.
    let rc = unsafe {
        libc::waitid(
            libc::P_PID,
            id,
            &mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    if rc != 0 {
        return Err(ErrorCode::Internal);
    }
    // SAFETY: waitid succeeded, so `info` is initialized; with WNOHANG si_pid
    // stays 0 when the child has not changed state.
    Ok(unsafe { info.si_pid() } != 0)
}
