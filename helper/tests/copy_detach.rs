//! Runs without the libtest harness: the child half calls `cli::run`, which
//! closes stdout, starts a new session and calls `process::exit` from the
//! watchdog, so it needs a process of its own. The binary re-executes itself
//! as that child with a fake `wl-copy`, so the real clipboard is never used.

use std::ffi::OsString;
use std::fs;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use pa_helper::cli;
use pa_helper::clipboard::WlCopy;
use pa_helper::otp::{totp, Algorithm};
use pa_helper::proc::run_bounded;
use pa_helper::sys::process_group_exists;
use pa_helper::watchdog::Watchdog;

const CHILD: &str = "--child";
const BOUNDED_CHILD: &str = "--bounded-child";
const RFC6238_SHA1_SEED: &[u8] = b"12345678901234567890";

fn millis(arg: Option<OsString>) -> Duration {
    Duration::from_millis(arg.unwrap().into_string().unwrap().parse().unwrap())
}

fn child(mut args: impl Iterator<Item = OsString>) -> ExitCode {
    let timeout = millis(args.next());
    let wl_copy = PathBuf::from(args.next().unwrap());
    let rest: Vec<OsString> = args.collect();
    let timeouts = cli::Timeouts {
        run: timeout,
        prompt: timeout,
    };
    cli::run(&rest, &WlCopy::new(wl_copy), &timeouts)
}

/// Runs `program` through `run_bounded` with a long timeout of its own, under
/// a watchdog that expires first.
fn bounded_child(mut args: impl Iterator<Item = OsString>) -> ExitCode {
    let timeout = millis(args.next());
    let program = PathBuf::from(args.next().unwrap());
    let _watchdog = Watchdog::arm(timeout, cli::time_out).unwrap();
    let _ = run_bounded(&program, &[], None, 64, Duration::from_secs(60));
    ExitCode::SUCCESS
}

fn fake_wl_copy(dir: &Path) -> PathBuf {
    let d = dir.display();
    let script = format!(
        "#!/bin/sh\n\
         if [ \"$1\" = --clear ]; then echo clear >> {d}/clear; exit 0; fi\n\
         /usr/bin/cat > {d}/stdin\n\
         trap 'exit 143' TERM\n\
         /usr/bin/sleep 300 &\n\
         wait\n"
    );
    let program = dir.join("wl-copy");
    fs::write(&program, script).unwrap();
    fs::set_permissions(&program, fs::Permissions::from_mode(0o700)).unwrap();
    program
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

struct Run {
    stdout: String,
    eof_after: Duration,
}

fn spawn_child(
    dir: &Path,
    timeout_ms: u64,
    args: &[&str],
    group_leader: bool,
) -> std::process::Child {
    let mut cmd = Command::new(std::env::current_exe().unwrap());
    cmd.env_clear()
        .arg(CHILD)
        .arg(timeout_ms.to_string())
        .arg(fake_wl_copy(dir))
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    if group_leader {
        cmd.process_group(0);
    }
    cmd.spawn().unwrap()
}

fn read_until_eof(child: &mut std::process::Child) -> Run {
    let start = Instant::now();
    let mut stdout = child.stdout.take().unwrap();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let mut text = String::new();
        stdout.read_to_string(&mut text).unwrap();
        tx.send(text).unwrap();
    });
    let stdout = rx
        .recv_timeout(Duration::from_secs(3))
        .expect("stdout did not reach EOF");
    Run {
        stdout,
        eof_after: start.elapsed(),
    }
}

fn wait_exit(child: &mut std::process::Child, limit: Duration) -> std::process::ExitStatus {
    let deadline = Instant::now() + limit;
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        assert!(Instant::now() < deadline, "child still running");
        thread::sleep(Duration::from_millis(20));
    }
}

fn copy_replies_then_holds(group_leader: bool) {
    let dir = tempfile::tempdir().unwrap();
    let start = Instant::now();
    let started = unix_now();
    // A 1 s watchdog would kill the holder long before the 5 s clear unless
    // it is cancelled before holding starts.
    let mut child = spawn_child(
        dir.path(),
        1000,
        &["copy", "demo-github", "--demo", "--clear-after", "5"],
        group_leader,
    );
    let run = read_until_eof(&mut child);
    let replied = unix_now();
    assert_eq!(run.stdout, "{\"ok\":true,\"protocol\":1}\n");
    assert!(
        run.eof_after < Duration::from_secs(2),
        "{:?}",
        run.eof_after
    );
    assert!(child.try_wait().unwrap().is_none(), "holder exited early");

    thread::sleep(Duration::from_millis(1500));
    assert!(
        child.try_wait().unwrap().is_none(),
        "holder died with the watchdog"
    );
    let code = fs::read_to_string(dir.path().join("stdin")).unwrap();
    assert!(!dir.path().join("clear").exists());

    let status = wait_exit(&mut child, Duration::from_secs(8));
    assert!(status.success(), "{status:?}");
    assert!(start.elapsed() >= Duration::from_secs(5));
    assert_eq!(
        fs::read_to_string(dir.path().join("clear")).unwrap(),
        "clear\n"
    );

    let candidates: Vec<String> = (started..=replied)
        .flat_map(|t| [t, t + 30])
        .map(|t| totp(RFC6238_SHA1_SEED, t, 30, Algorithm::Sha1, 6))
        .collect();
    assert!(
        candidates.contains(&code),
        "{code} is not a demo GitHub code"
    );
}

fn stalled_run_times_out() {
    let dir = tempfile::tempdir().unwrap();
    let start = Instant::now();
    let mut cmd = Command::new(std::env::current_exe().unwrap());
    let mut child = cmd
        .env_clear()
        .env("XDG_STATE_HOME", dir.path())
        .args([CHILD, "300"])
        .arg(fake_wl_copy(dir.path()))
        .args(["prefs", "set"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let held_stdin = child.stdin.take();
    let run = read_until_eof(&mut child);
    let status = wait_exit(&mut child, Duration::from_secs(2));
    drop(held_stdin);
    assert_eq!(
        run.stdout,
        "{\"ok\":false,\"protocol\":1,\"error\":\"TIMEOUT\"}\n"
    );
    assert_eq!(status.code(), Some(1));
    let elapsed = start.elapsed();
    assert!(
        (Duration::from_millis(300)..Duration::from_secs(2)).contains(&elapsed),
        "{elapsed:?}"
    );
    assert!(!dir.path().join("sviat.proton-authenticator").exists());
}

fn missing_wl_copy_is_reported() {
    let dir = tempfile::tempdir().unwrap();
    let mut child = Command::new(std::env::current_exe().unwrap())
        .env_clear()
        .args([CHILD, "5000"])
        .arg(dir.path().join("wl-copy"))
        .args(["copy", "demo-github", "--demo"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let run = read_until_eof(&mut child);
    let status = wait_exit(&mut child, Duration::from_secs(2));
    assert_eq!(
        run.stdout,
        "{\"ok\":false,\"protocol\":1,\"error\":\"DEPENDENCY_MISSING\"}\n"
    );
    assert_eq!(status.code(), Some(1));
}

fn wait_group_gone(pgid: i32) -> bool {
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        if !process_group_exists(pgid) {
            return true;
        }
        thread::sleep(Duration::from_millis(20));
    }
    false
}

fn watchdog_kills_the_running_child_group() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path().display();
    let program = dir.path().join("slow");
    fs::write(
        &program,
        format!("#!/bin/sh\necho $$ > {d}/pid\n/usr/bin/sleep 300 &\nwait\n"),
    )
    .unwrap();
    fs::set_permissions(&program, fs::Permissions::from_mode(0o700)).unwrap();

    let start = Instant::now();
    let mut child = Command::new(std::env::current_exe().unwrap())
        .env_clear()
        .args([BOUNDED_CHILD, "500"])
        .arg(&program)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let run = read_until_eof(&mut child);
    let status = wait_exit(&mut child, Duration::from_secs(2));
    assert_eq!(
        run.stdout,
        "{\"ok\":false,\"protocol\":1,\"error\":\"TIMEOUT\"}\n"
    );
    assert_eq!(status.code(), Some(1));
    assert!(start.elapsed() < Duration::from_secs(3));
    let pgid: i32 = fs::read_to_string(dir.path().join("pid"))
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    assert!(wait_group_gone(pgid), "child group {pgid} survived");
}

fn main() -> ExitCode {
    let mut args = std::env::args_os().skip(1);
    match args.next() {
        Some(mode) if mode == CHILD => return child(args),
        Some(mode) if mode == BOUNDED_CHILD => return bounded_child(args),
        _ => {}
    }
    let tests: [(&str, fn()); 5] = [
        ("copy_replies_then_holds", || copy_replies_then_holds(false)),
        ("copy_as_group_leader_replies_then_holds", || {
            copy_replies_then_holds(true)
        }),
        ("stalled_run_times_out", stalled_run_times_out),
        ("missing_wl_copy_is_reported", missing_wl_copy_is_reported),
        (
            "watchdog_kills_the_running_child_group",
            watchdog_kills_the_running_child_group,
        ),
    ];
    for (name, test) in tests {
        test();
        eprintln!("test {name} ... ok");
    }
    ExitCode::SUCCESS
}
