use std::io::{Read, Write};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::thread;
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use crate::error::{ErrorCode, Result};

const ALLOWED_ENV: [&str; 4] = [
    "HOME",
    "XDG_RUNTIME_DIR",
    "WAYLAND_DISPLAY",
    "DBUS_SESSION_BUS_ADDRESS",
];
const POLL_INTERVAL: Duration = Duration::from_millis(10);

type Captured = Result<Zeroizing<Vec<u8>>>;

/// Runs `program` by absolute path with a scrubbed environment and returns
/// its exit code (-1 if killed by a signal) and stdout.
///
/// The whole call, including waiting for stdout to reach EOF after the child
/// has exited, is bounded by `timeout`; a descendant that keeps the pipe open
/// past the deadline yields `Timeout`. Only the direct child is killed: the
/// child runs in its own process group, but killing the group needs `unsafe`.
/// Reader and writer threads are never joined, so a lingering descendant
/// cannot block the caller; the reader drops its zeroizing buffer on exit.
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
    let mut command = Command::new(program);
    command
        .args(args)
        .env_clear()
        .process_group(0)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    for name in ALLOWED_ENV {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }

    let mut child = command.spawn().map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => ErrorCode::DependencyMissing,
        _ => ErrorCode::Internal,
    })?;

    let result = drive(&mut child, stdin, max_out, deadline);
    if result.is_err() {
        let _ = child.kill();
        let _ = child.wait();
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
    thread::spawn(move || {
        let _ = tx.send(read_capped(stdout, max_out));
    });

    if let (Some(data), Some(mut pipe)) = (stdin, pipe) {
        let data = Zeroizing::new(data.to_vec());
        thread::spawn(move || {
            let _ = pipe.write_all(&data);
        });
    }

    wait_for_both(child, &rx, max_out, deadline)
}

fn wait_for_both(
    child: &mut Child,
    rx: &Receiver<Captured>,
    max_out: usize,
    deadline: Instant,
) -> Result<(i32, Zeroizing<Vec<u8>>)> {
    let mut exit_code = None;
    let mut output = None;
    loop {
        if exit_code.is_none() {
            match child.try_wait() {
                Ok(Some(status)) => exit_code = Some(status.code().unwrap_or(-1)),
                Ok(None) => {}
                Err(_) => return Err(ErrorCode::Internal),
            }
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
        if let Some(code) = exit_code {
            if let Some(buf) = output.take() {
                return Ok((code, buf));
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
