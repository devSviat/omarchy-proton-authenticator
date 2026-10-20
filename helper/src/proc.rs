use std::io::{Read, Write};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
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

/// Runs `program` by absolute path with a scrubbed environment and returns
/// its exit code (-1 if killed by a signal) and stdout.
///
/// Stdout is read into a buffer that is allocated once at `max_out + 1`
/// bytes and never reallocated, so no unzeroized copies are left behind.
pub fn run_bounded(
    program: &Path,
    args: &[&str],
    stdin: Option<&[u8]>,
    max_out: usize,
    timeout: Duration,
) -> Result<(i32, Zeroizing<Vec<u8>>)> {
    let mut command = Command::new(program);
    command
        .args(args)
        .env_clear()
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

    let stdout = child.stdout.take().ok_or(ErrorCode::Internal)?;
    let overflow = Arc::new(AtomicBool::new(false));
    let reader = {
        let overflow = Arc::clone(&overflow);
        thread::spawn(move || read_capped(stdout, max_out, &overflow))
    };

    let writer = match (stdin, child.stdin.take()) {
        (Some(data), Some(mut pipe)) => {
            let data = Zeroizing::new(data.to_vec());
            Some(thread::spawn(move || {
                let _ = pipe.write_all(&data);
            }))
        }
        _ => None,
    };

    let outcome = wait_until(&mut child, timeout, &overflow);
    if outcome.is_err() {
        let _ = child.kill();
        let _ = child.wait();
    }
    if let Some(writer) = writer {
        let _ = writer.join();
    }
    let buf = reader.join().map_err(|_| ErrorCode::Internal)?;
    let code = outcome?;

    if buf.len() > max_out {
        return Err(ErrorCode::OutputTooLarge);
    }
    Ok((code, buf))
}

fn wait_until(child: &mut Child, timeout: Duration, overflow: &AtomicBool) -> Result<i32> {
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status.code().unwrap_or(-1)),
            Ok(None) => {}
            Err(_) => return Err(ErrorCode::Internal),
        }
        if overflow.load(Ordering::Acquire) {
            return Err(ErrorCode::OutputTooLarge);
        }
        if Instant::now() >= deadline {
            return Err(ErrorCode::Timeout);
        }
        thread::sleep(POLL_INTERVAL);
    }
}

fn read_capped(mut source: impl Read, max_out: usize, overflow: &AtomicBool) -> Zeroizing<Vec<u8>> {
    let limit = max_out + 1;
    let mut buf = Zeroizing::new(Vec::with_capacity(limit));
    buf.resize(limit, 0);
    let mut filled = 0;
    while filled < limit {
        match source.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
    buf.truncate(filled);
    if filled > max_out {
        overflow.store(true, Ordering::Release);
    }
    buf
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
        std::env::set_var("FOO", "bar");
        let (code, out) =
            run_bounded(Path::new("/usr/bin/env"), &[], None, 65536, TIMEOUT).unwrap();
        assert_eq!(code, 0);
        let text = String::from_utf8_lossy(&out);
        assert!(!text.contains("FOO"));
        assert!(text
            .lines()
            .all(|l| ALLOWED_ENV.iter().any(|a| l.starts_with(&format!("{a}=")))));
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
}
