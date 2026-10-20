//! Runs without the libtest harness: the child half calls `cli::run` after
//! `harden()`, and the watchdog calls `process::exit`, so it needs a process
//! of its own. The binary re-executes itself as that child, and the child
//! re-executes itself as the clipboard holder, both with a fake `wl-copy`, so
//! the real clipboard is never used.
//!
//! `harden()` locks memory, so like `hardening` this suite needs the shipped
//! `RLIMIT_MEMLOCK` of 8 MiB.

use std::ffi::OsString;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use pa_helper::cli;
use pa_helper::clipboard::WlCopy;
use pa_helper::holder::Holder;
use pa_helper::otp::{totp, Algorithm};
use pa_helper::proc::run_bounded;
use pa_helper::sys::{self, kill_process_group, process_group_exists, Signal};
use pa_helper::watchdog::Watchdog;

const CHILD: &str = "--child";
const BOUNDED_CHILD: &str = "--bounded-child";
/// Like `CHILD`, but the holder runs under an 8 KiB `RLIMIT_MEMLOCK`.
const STARVED_HOLDER_CHILD: &str = "--starved-holder-child";
const RFC6238_SHA1_SEED: &[u8] = b"12345678901234567890";
const BUDGET_KIB: u64 = 8192;

fn millis(arg: &OsString) -> Duration {
    Duration::from_millis(arg.to_str().unwrap().parse().unwrap())
}

/// Mirrors `main`, with a fake wl-copy and a holder that re-enters `CHILD`
/// mode through `/proc/self/exe`.
fn child(mut args: impl Iterator<Item = OsString>, starved_holder: bool) -> ExitCode {
    let timeout_arg = args.next().unwrap();
    let wl_copy = args.next().unwrap();
    let hardened = sys::harden();
    let rest: Vec<OsString> = args.collect();
    if let Err(code) = hardened {
        return cli::harden_failed(&rest, code);
    }
    let timeout = millis(&timeout_arg);
    let timeouts = cli::Timeouts {
        run: timeout,
        prompt: timeout,
    };
    let reentry = vec![CHILD.into(), timeout_arg, wl_copy.clone()];
    let holder = if starved_holder {
        let mut prefix: Vec<OsString> = vec![
            "--memlock=8192".into(),
            "--".into(),
            std::env::current_exe().unwrap().into(),
        ];
        prefix.extend(reentry);
        Holder::new(PathBuf::from("/usr/bin/prlimit"), prefix)
    } else {
        Holder::new(PathBuf::from("/proc/self/exe"), reentry)
    };
    cli::run(
        &rest,
        &WlCopy::new(PathBuf::from(wl_copy)),
        &holder,
        &timeouts,
    )
}

/// Runs `program` through `run_bounded` with a long timeout of its own, under
/// a watchdog that expires first.
fn bounded_child(mut args: impl Iterator<Item = OsString>) -> ExitCode {
    let timeout = millis(&args.next().unwrap());
    let program = PathBuf::from(args.next().unwrap());
    let _watchdog = Watchdog::arm(timeout, cli::time_out).unwrap();
    let _ = run_bounded(&program, &[], None, 64, Duration::from_secs(60));
    ExitCode::SUCCESS
}

/// Records its start, its parent (the holder) and the code it was fed, then
/// holds until killed.
fn fake_wl_copy(dir: &Path) -> PathBuf {
    let d = dir.display();
    let script = format!(
        "#!/bin/sh\n\
         if [ \"$1\" = --clear ]; then echo clear >> {d}/clear; exit 0; fi\n\
         echo $PPID > {d}/holder\n\
         /usr/bin/cat > {d}/stdin\n\
         /usr/bin/sleep 300 &\n\
         trap 'echo term >> {d}/killed; kill $!; exit 143' TERM\n\
         echo $$ > {d}/pid\n\
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

fn helper_command(dir: &Path, timeout_ms: u64, args: &[&str]) -> Command {
    let mut cmd = Command::new(std::env::current_exe().unwrap());
    cmd.env_clear()
        .arg(CHILD)
        .arg(timeout_ms.to_string())
        .arg(fake_wl_copy(dir))
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    cmd
}

fn read_until_eof(child: &mut std::process::Child) -> String {
    let mut stdout = child.stdout.take().unwrap();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let mut text = String::new();
        stdout.read_to_string(&mut text).unwrap();
        tx.send(text).unwrap();
    });
    rx.recv_timeout(Duration::from_secs(3))
        .expect("stdout did not reach EOF")
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

fn wait_until(limit: Duration, mut done: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + limit;
    while Instant::now() < deadline {
        if done() {
            return true;
        }
        thread::sleep(Duration::from_millis(20));
    }
    done()
}

fn read_file(dir: &Path, name: &str) -> Option<String> {
    fs::read_to_string(dir.join(name)).ok()
}

fn wait_file(dir: &Path, name: &str, limit: Duration) -> String {
    assert!(
        wait_until(limit, || read_file(dir, name).is_some()),
        "{name} never appeared"
    );
    thread::sleep(Duration::from_millis(50));
    read_file(dir, name).unwrap()
}

fn pid_in(dir: &Path, name: &str) -> i32 {
    wait_file(dir, name, Duration::from_secs(2))
        .trim()
        .parse()
        .unwrap()
}

/// Alive and not a zombie. The holder is not our child, so it is reaped by
/// whoever inherited it.
fn running(pid: i32) -> bool {
    fs::read_to_string(format!("/proc/{pid}/stat"))
        .map(|stat| {
            let state = stat[stat.rfind(')').unwrap() + 2..].chars().next();
            state != Some('Z')
        })
        .unwrap_or(false)
}

/// Pids whose command line mentions `needle`, other than this process.
fn processes_mentioning(needle: &Path) -> Vec<i32> {
    let needle = needle.as_os_str().as_encoded_bytes();
    fs::read_dir("/proc")
        .unwrap()
        .filter_map(|e| e.ok()?.file_name().to_str()?.parse::<i32>().ok())
        .filter(|pid| *pid != std::process::id() as i32 && running(*pid))
        .filter(|pid| {
            fs::read(format!("/proc/{pid}/cmdline"))
                .is_ok_and(|c| c.windows(needle.len()).any(|w| w == needle))
        })
        .collect()
}

fn our_uid() -> u32 {
    fs::metadata("/proc/self/environ").unwrap().uid()
}

/// Process group and session ids from /proc/<pid>/stat.
fn group_and_session(pid: i32) -> (i32, i32) {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
    let mut fields = stat[stat.rfind(')').unwrap() + 2..].split(' ').skip(2);
    let pgrp = fields.next().unwrap().parse().unwrap();
    let session = fields.next().unwrap().parse().unwrap();
    (pgrp, session)
}

/// A non-dumpable process's /proc entries belong to root.
fn assert_hardened(pid: i32) {
    if our_uid() != 0 {
        let owner = fs::metadata(format!("/proc/{pid}/environ")).unwrap().uid();
        assert_eq!(owner, 0, "process {pid} is dumpable");
    }
}

/// The code must not be in `pid`'s argv, nor in its environment unless that
/// is unreadable to us.
fn assert_not_exposed(pid: i32, code: &str) {
    let code = code.as_bytes();
    let contains = |data: &[u8]| data.windows(code.len()).any(|w| w == code);
    let cmdline = fs::read(format!("/proc/{pid}/cmdline")).unwrap();
    assert!(!contains(&cmdline), "code in argv of {pid}");
    match fs::read(format!("/proc/{pid}/environ")) {
        Ok(environ) => assert!(!contains(&environ), "code in environ of {pid}"),
        Err(e) => assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied),
    }
}

fn demo_code_candidates(from: u64, to: u64) -> Vec<String> {
    (from..=to)
        .flat_map(|t| [t, t + 30])
        .map(|t| totp(RFC6238_SHA1_SEED, t, 30, Algorithm::Sha1, 6))
        .collect()
}

/// `copy` replies and exits at once; the holder keeps the code until the
/// deadline whatever happens to the caller, then clears it.
fn copy_exits_and_holder_clears(kill_caller_group: bool) {
    let dir = tempfile::tempdir().unwrap();
    let start = Instant::now();
    let started = unix_now();
    // A 1 s run budget: the holder must outlive the caller's watchdog.
    let mut cmd = helper_command(
        dir.path(),
        1000,
        &["copy", "demo-github", "--demo", "--clear-after", "5"],
    );
    if kill_caller_group {
        cmd.process_group(0);
    }
    let mut child = cmd.spawn().unwrap();
    let caller = child.id() as i32;
    let caller_cmdline = fs::read(format!("/proc/{caller}/cmdline")).ok();
    let reply = read_until_eof(&mut child);
    let replied = unix_now();
    assert_eq!(reply, "{\"ok\":true,\"protocol\":1}\n");
    if kill_caller_group {
        kill_process_group(caller, Signal::Kill).unwrap();
    }
    let status = wait_exit(&mut child, Duration::from_secs(1));
    if !kill_caller_group {
        assert!(status.success(), "{status:?}");
    }
    assert!(
        start.elapsed() < Duration::from_secs(2),
        "{:?}",
        start.elapsed()
    );

    let holder = pid_in(dir.path(), "holder");
    let owner = pid_in(dir.path(), "pid");
    let code = wait_file(dir.path(), "stdin", Duration::from_secs(2));
    assert!(
        demo_code_candidates(started, replied).contains(&code),
        "{code} is not a demo GitHub code"
    );
    assert_ne!(holder, caller);
    assert_eq!(group_and_session(holder), (holder, holder));
    assert_hardened(holder);
    assert_not_exposed(holder, &code);
    assert_not_exposed(owner, &code);
    if let Some(cmdline) = caller_cmdline {
        let code = code.as_bytes();
        assert!(!cmdline.windows(code.len()).any(|w| w == code));
    }

    thread::sleep(Duration::from_millis(1500));
    assert!(running(holder), "holder died with the caller");
    assert!(running(owner), "wl-copy died with the caller");
    assert_eq!(read_file(dir.path(), "clear"), None);

    assert!(
        wait_until(Duration::from_secs(8), || !running(holder)),
        "holder outlived its deadline"
    );
    assert!(start.elapsed() >= Duration::from_secs(5));
    assert_eq!(read_file(dir.path(), "clear").as_deref(), Some("clear\n"));
    assert_eq!(read_file(dir.path(), "killed").as_deref(), Some("term\n"));
    assert!(!running(owner));
}

/// The clipboard owner dies with its holder, so a killed holder never leaves
/// the code on the clipboard.
fn killed_holder_takes_the_code_along() {
    let dir = tempfile::tempdir().unwrap();
    let mut child = helper_command(
        dir.path(),
        1000,
        &["copy", "demo-github", "--demo", "--clear-after", "60"],
    )
    .spawn()
    .unwrap();
    assert_eq!(read_until_eof(&mut child), "{\"ok\":true,\"protocol\":1}\n");
    wait_exit(&mut child, Duration::from_secs(1));
    let holder = pid_in(dir.path(), "holder");
    let owner = pid_in(dir.path(), "pid");
    kill_process_group(holder, Signal::Kill).unwrap();
    assert_eq!(
        wait_file(dir.path(), "killed", Duration::from_secs(2)),
        "term\n"
    );
    assert!(wait_until(Duration::from_secs(2), || !running(owner)));
}

/// Exits with `status` shortly after reading the code: 1 as wl-copy does
/// when it cannot take the selection, 0 as when another client takes it.
fn early_exit_wl_copy(dir: &Path, status: u8) -> PathBuf {
    let d = dir.display();
    let script = format!(
        "#!/bin/sh\n\
         if [ \"$1\" = --clear ]; then echo clear >> {d}/clear; exit 0; fi\n\
         /usr/bin/cat > {d}/stdin\n\
         /usr/bin/sleep 0.05\n\
         exit {status}\n"
    );
    let program = dir.join("wl-copy");
    fs::write(&program, script).unwrap();
    fs::set_permissions(&program, fs::Permissions::from_mode(0o700)).unwrap();
    program
}

fn failing_wl_copy_is_reported() {
    let dir = tempfile::tempdir().unwrap();
    let mut child = Command::new(std::env::current_exe().unwrap())
        .env_clear()
        .args([CHILD, "5000"])
        .arg(early_exit_wl_copy(dir.path(), 1))
        .args(["copy", "demo-github", "--demo", "--clear-after", "5"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let reply = read_until_eof(&mut child);
    let status = wait_exit(&mut child, Duration::from_secs(2));
    assert_eq!(
        reply,
        "{\"ok\":false,\"protocol\":1,\"error\":\"INTERNAL\"}\n"
    );
    assert_eq!(status.code(), Some(1));
    assert!(read_file(dir.path(), "stdin").is_some());
    assert_eq!(read_file(dir.path(), "clear"), None);
    assert!(wait_until(Duration::from_secs(2), || processes_mentioning(
        dir.path()
    )
    .is_empty()));
}

/// A clipboard manager taking the selection right away is not a failure: the
/// code reached the clipboard, and nothing is cleared.
fn selection_taken_at_once_is_reported_as_copied() {
    let dir = tempfile::tempdir().unwrap();
    let mut child = Command::new(std::env::current_exe().unwrap())
        .env_clear()
        .args([CHILD, "5000"])
        .arg(early_exit_wl_copy(dir.path(), 0))
        .args(["copy", "demo-github", "--demo", "--clear-after", "5"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    assert_eq!(read_until_eof(&mut child), "{\"ok\":true,\"protocol\":1}\n");
    assert!(wait_exit(&mut child, Duration::from_secs(2)).success());
    assert!(read_file(dir.path(), "stdin").is_some());
    assert!(wait_until(Duration::from_secs(2), || processes_mentioning(
        dir.path()
    )
    .is_empty()));
    assert_eq!(read_file(dir.path(), "clear"), None);
}

/// Fds the caller leaks without `FD_CLOEXEC` (as Quickshell does) must not
/// reach the holder or wl-copy. Fd 7 duplicates the caller's stdout pipe, so
/// a process that kept it would hold off EOF until the clipboard deadline.
/// The holder is not dumpable, so its /proc/<pid>/fd cannot be listed
/// directly; the EOF stands in for that.
fn inherited_fds_are_closed() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path().display();
    let script = format!(
        "#!/bin/sh\n\
         if [ \"$1\" = --clear ]; then exit 0; fi\n\
         /usr/bin/cat > {d}/stdin\n\
         for fd in /proc/$$/fd/*; do echo \"${{fd##*/}}\"; done > {d}/fds\n\
         /usr/bin/sleep 300 &\n\
         trap 'kill $!; exit 143' TERM\n\
         wait\n"
    );
    let program = dir.path().join("wl-copy");
    fs::write(&program, script).unwrap();
    fs::set_permissions(&program, fs::Permissions::from_mode(0o700)).unwrap();

    let start = Instant::now();
    let mut child = Command::new("/bin/sh")
        .env_clear()
        .args(["-c", "exec 7>&1; exec \"$0\" \"$@\""])
        .arg(std::env::current_exe().unwrap())
        .args([CHILD, "1000"])
        .arg(&program)
        .args(["copy", "demo-github", "--demo", "--clear-after", "5"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    assert_eq!(read_until_eof(&mut child), "{\"ok\":true,\"protocol\":1}\n");
    assert!(start.elapsed() < Duration::from_secs(3));
    wait_exit(&mut child, Duration::from_secs(1));
    let fds = wait_file(dir.path(), "fds", Duration::from_secs(2));
    assert!(
        !fds.lines().any(|fd| fd == "7"),
        "wl-copy inherited fd 7: {fds}"
    );
}

fn holder_memlock_failure_is_reported() {
    let dir = tempfile::tempdir().unwrap();
    let mut child = Command::new(std::env::current_exe().unwrap())
        .env_clear()
        .arg(STARVED_HOLDER_CHILD)
        .arg("1000")
        .arg(fake_wl_copy(dir.path()))
        .args(["copy", "demo-github", "--demo", "--clear-after", "5"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let reply = read_until_eof(&mut child);
    let status = wait_exit(&mut child, Duration::from_secs(2));
    assert_eq!(
        reply,
        "{\"ok\":false,\"protocol\":1,\"error\":\"MEMLOCK_FAILED\"}\n"
    );
    assert_eq!(status.code(), Some(1));
    assert_eq!(read_file(dir.path(), "holder"), None);
    assert_eq!(processes_mentioning(dir.path()), Vec::<i32>::new());
}

fn hold_rejects_non_codes() {
    for input in [
        &b""[..],
        b"abcdef",
        b"12345678901",
        b"123456\n",
        b"1234",
        b"2bcdf",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let mut child = helper_command(dir.path(), 1000, &["hold", "--clear-after", "5"])
            .stdin(Stdio::piped())
            .spawn()
            .unwrap();
        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(input).unwrap();
        drop(stdin);
        let out = read_until_eof(&mut child);
        let status = wait_exit(&mut child, Duration::from_secs(2));
        assert_eq!(out, "E", "{input:?}");
        assert_eq!(status.code(), Some(1), "{input:?}");
        assert_eq!(read_file(dir.path(), "holder"), None, "{input:?}");
    }
}

fn hold_rejects_bad_arguments() {
    for args in [
        &["hold"][..],
        &["hold", "--clear-after", "4"],
        &["hold", "--clear-after", "121"],
        &["hold", "--clear-after", "5", "--demo"],
    ] {
        let dir = tempfile::tempdir().unwrap();
        let mut child = helper_command(dir.path(), 1000, args)
            .stdin(Stdio::piped())
            .spawn()
            .unwrap();
        let mut stdin = child.stdin.take().unwrap();
        let _ = stdin.write_all(b"123456");
        drop(stdin);
        let out = read_until_eof(&mut child);
        let status = wait_exit(&mut child, Duration::from_secs(2));
        assert_eq!(
            out, "{\"ok\":false,\"protocol\":1,\"error\":\"INVALID_ARGUMENT\"}\n",
            "{args:?}"
        );
        assert_eq!(status.code(), Some(1));
        assert_eq!(read_file(dir.path(), "holder"), None, "{args:?}");
    }
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
    let reply = read_until_eof(&mut child);
    let status = wait_exit(&mut child, Duration::from_secs(2));
    drop(held_stdin);
    assert_eq!(
        reply,
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
    let reply = read_until_eof(&mut child);
    let status = wait_exit(&mut child, Duration::from_secs(2));
    assert_eq!(
        reply,
        "{\"ok\":false,\"protocol\":1,\"error\":\"DEPENDENCY_MISSING\"}\n"
    );
    assert_eq!(status.code(), Some(1));
    assert_eq!(processes_mentioning(dir.path()), Vec::<i32>::new());
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
    let reply = read_until_eof(&mut child);
    let status = wait_exit(&mut child, Duration::from_secs(2));
    assert_eq!(
        reply,
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

fn memlock_fits() -> bool {
    let limits = fs::read_to_string("/proc/self/limits").unwrap();
    let row = limits
        .lines()
        .find(|l| l.starts_with("Max locked memory"))
        .unwrap();
    let soft = row["Max locked memory".len()..]
        .split_whitespace()
        .next()
        .unwrap();
    match soft.parse::<u64>() {
        Ok(bytes) if bytes / 1024 < BUDGET_KIB => {
            assert!(
                std::env::var_os("CI").is_none(),
                "RLIMIT_MEMLOCK is below 8 MiB; CI must run with the shipped limit"
            );
            false
        }
        _ => true,
    }
}

fn main() -> ExitCode {
    let mut args = std::env::args_os().skip(1);
    match args.next() {
        Some(mode) if mode == CHILD => return child(args, false),
        Some(mode) if mode == STARVED_HOLDER_CHILD => return child(args, true),
        Some(mode) if mode == BOUNDED_CHILD => return bounded_child(args),
        _ => {}
    }
    if !memlock_fits() {
        eprintln!("copy_detach: skipped, RLIMIT_MEMLOCK is below 8 MiB");
        return ExitCode::SUCCESS;
    }
    let tests: [(&str, fn()); 12] = [
        ("copy_exits_and_holder_clears", || {
            copy_exits_and_holder_clears(false)
        }),
        ("killing_the_caller_group_spares_the_holder", || {
            copy_exits_and_holder_clears(true)
        }),
        (
            "killed_holder_takes_the_code_along",
            killed_holder_takes_the_code_along,
        ),
        (
            "holder_memlock_failure_is_reported",
            holder_memlock_failure_is_reported,
        ),
        ("hold_rejects_non_codes", hold_rejects_non_codes),
        ("hold_rejects_bad_arguments", hold_rejects_bad_arguments),
        ("stalled_run_times_out", stalled_run_times_out),
        ("missing_wl_copy_is_reported", missing_wl_copy_is_reported),
        ("failing_wl_copy_is_reported", failing_wl_copy_is_reported),
        (
            "selection_taken_at_once_is_reported_as_copied",
            selection_taken_at_once_is_reported_as_copied,
        ),
        ("inherited_fds_are_closed", inherited_fds_are_closed),
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
