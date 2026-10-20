#![allow(unsafe_code)]

use std::fs::OpenOptions;
use std::io;
use std::os::fd::AsRawFd;

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
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
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
    let dumpable = unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) };
    dumpable != 0
}

/// Starts a new session so the process outlives the caller's process group.
pub fn detach_session() -> Result<()> {
    // SAFETY: setsid has no arguments and no memory effects.
    if unsafe { libc::setsid() } == -1 {
        return Err(ErrorCode::Internal);
    }
    Ok(())
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

/// Sends `signal` to every process in group `pgid`. A group that no longer
/// exists is not an error.
///
/// The caller must not have reaped the group leader yet: once its pid is
/// freed, the number could name an unrelated group.
pub fn kill_process_group(pgid: i32, signal: Signal) -> Result<()> {
    if pgid <= 1 {
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
