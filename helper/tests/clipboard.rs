use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use pa_helper::clipboard::{Clipboard, WlCopy};
use pa_helper::error::ErrorCode;
use pa_helper::sys::{kill_process_group, process_group_exists, Signal};
use tempfile::TempDir;
use zeroize::Zeroizing;

const CODE: &str = "493817";

// Writing an executable while another test thread forks can make exec fail
// with ETXTBSY, so script creation and use are serialized.
static SERIAL: Mutex<()> = Mutex::new(());

enum Mode {
    Hold,
    /// Outlives the start-up grace period, then exits as wl-copy does when
    /// another client takes the selection.
    ExitAfter500ms,
    /// Loses the selection at once, as when a clipboard manager re-offers it.
    ExitAfter50ms,
    FailAfter50ms,
    FailAfter500ms,
}

struct Fake {
    dir: TempDir,
    program: PathBuf,
}

impl Fake {
    fn new(mode: Mode) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path().display();
        let tail = match mode {
            Mode::Hold => "/usr/bin/sleep 30 &\nwait",
            Mode::ExitAfter500ms => "/usr/bin/sleep 0.5",
            Mode::ExitAfter50ms => "/usr/bin/sleep 0.05",
            Mode::FailAfter50ms => "/usr/bin/sleep 0.05\nexit 1",
            Mode::FailAfter500ms => "/usr/bin/sleep 0.5\nexit 1",
        };
        let script = format!(
            "#!/bin/sh\n\
             if [ \"$1\" = --clear ]; then echo clear >> {d}/clear; exit 0; fi\n\
             printf '%s\\n' \"$0\" \"$@\" > {d}/argv\n\
             /usr/bin/cat > {d}/stdin\n\
             echo $$ > {d}/pid\n\
             trap 'echo term >> {d}/killed; exit 143' TERM\n\
             {tail}\n"
        );
        let program = dir.path().join("wl-copy");
        std::fs::write(&program, script).unwrap();
        let mut perms = std::fs::metadata(&program).unwrap().permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o700);
        std::fs::set_permissions(&program, perms).unwrap();
        Self { dir, program }
    }

    fn read(&self, name: &str) -> Option<String> {
        std::fs::read_to_string(self.dir.path().join(name)).ok()
    }

    fn pid(&self) -> i32 {
        self.read("pid").unwrap().trim().parse().unwrap()
    }
}

fn hold(program: &Path, clear_after: Duration) -> Result<(), ErrorCode> {
    WlCopy::new(program.to_path_buf()).hold(Zeroizing::new(CODE.to_string()), clear_after)
}

fn wait_group_gone(pgid: i32) -> bool {
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        if !process_group_exists(pgid) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    false
}

#[test]
fn holder_kills_owner_at_deadline() {
    let _guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let fake = Fake::new(Mode::Hold);
    let start = Instant::now();
    hold(&fake.program, Duration::from_millis(300)).unwrap();
    let elapsed = start.elapsed();
    assert!(elapsed >= Duration::from_millis(300), "{elapsed:?}");
    assert!(elapsed < Duration::from_secs(2), "{elapsed:?}");
    assert_eq!(fake.read("killed").as_deref(), Some("term\n"));
    assert_eq!(fake.read("clear").as_deref(), Some("clear\n"));
    assert!(
        wait_group_gone(fake.pid()),
        "fake wl-copy group still alive"
    );
}

#[test]
fn holder_leaves_newer_clipboard_alone() {
    let _guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let fake = Fake::new(Mode::ExitAfter500ms);
    let start = Instant::now();
    hold(&fake.program, Duration::from_secs(3)).unwrap();
    assert!(start.elapsed() < Duration::from_secs(1));
    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(fake.read("clear"), None);
    assert_eq!(fake.read("killed"), None);
}

#[test]
fn code_reaches_stdin_not_argv() {
    let _guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let fake = Fake::new(Mode::ExitAfter500ms);
    hold(&fake.program, Duration::from_secs(3)).unwrap();
    assert_eq!(fake.read("stdin").as_deref(), Some(CODE));
    let argv = fake.read("argv").unwrap();
    let args: Vec<&str> = argv.lines().skip(1).collect();
    assert_eq!(
        args,
        ["--foreground", "--sensitive", "--type", "text/plain"]
    );
    assert!(!args.iter().any(|a| a.chars().any(|c| c.is_ascii_digit())));
}

#[test]
fn missing_program_is_dependency_missing() {
    let _guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let dir = tempfile::tempdir().unwrap();
    let r = hold(&dir.path().join("wl-copy"), Duration::from_millis(100));
    assert_eq!(r.unwrap_err(), ErrorCode::DependencyMissing);
}

#[test]
fn overflowing_deadline_is_internal_before_spawning() {
    let _guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let fake = Fake::new(Mode::ExitAfter500ms);
    assert_eq!(
        hold(&fake.program, Duration::MAX).unwrap_err(),
        ErrorCode::Internal
    );
    assert_eq!(fake.read("argv"), None);
}

fn own_process_group() -> i32 {
    let stat = std::fs::read_to_string("/proc/self/stat").unwrap();
    let after_comm = &stat[stat.rfind(')').unwrap() + 2..];
    after_comm.split(' ').nth(2).unwrap().parse().unwrap()
}

#[test]
fn own_process_group_is_never_signalled() {
    assert_eq!(
        kill_process_group(own_process_group(), Signal::Term).unwrap_err(),
        ErrorCode::Internal
    );
}

#[test]
fn dropped_hold_kills_owner_and_clears() {
    let _guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let fake = Fake::new(Mode::Hold);
    let hold = WlCopy::new(fake.program.clone())
        .start(Zeroizing::new(CODE.to_string()), Duration::from_secs(30))
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    while fake.read("pid").is_none() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    let pgid = fake.pid();
    let start = Instant::now();
    drop(hold);
    assert!(start.elapsed() < Duration::from_secs(2));
    assert_eq!(fake.read("clear").as_deref(), Some("clear\n"));
    assert!(wait_group_gone(pgid), "fake wl-copy group still alive");
}

#[test]
fn wl_copy_failing_at_once_is_an_error() {
    let _guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let fake = Fake::new(Mode::FailAfter50ms);
    let start = Instant::now();
    let started = WlCopy::new(fake.program.clone())
        .start(Zeroizing::new(CODE.to_string()), Duration::from_secs(30));
    assert_eq!(started.err(), Some(ErrorCode::Internal));
    assert!(start.elapsed() < Duration::from_secs(1));
    assert_eq!(fake.read("stdin").as_deref(), Some(CODE));
    // Its selection died with it, so a clear could only hit someone else's.
    assert_eq!(fake.read("clear"), None);
}

#[test]
fn wl_copy_failing_later_is_an_error() {
    let _guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let fake = Fake::new(Mode::FailAfter500ms);
    let hold = WlCopy::new(fake.program.clone())
        .start(Zeroizing::new(CODE.to_string()), Duration::from_secs(30))
        .unwrap();
    assert_eq!(hold.wait_and_clear().unwrap_err(), ErrorCode::Internal);
    assert_eq!(fake.read("clear"), None);
}

#[test]
fn selection_taken_at_once_is_success_without_clearing() {
    let _guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let fake = Fake::new(Mode::ExitAfter50ms);
    let start = Instant::now();
    let hold = WlCopy::new(fake.program.clone())
        .start(Zeroizing::new(CODE.to_string()), Duration::from_secs(30))
        .unwrap();
    hold.wait_and_clear().unwrap();
    assert!(start.elapsed() < Duration::from_secs(1));
    assert_eq!(fake.read("stdin").as_deref(), Some(CODE));
    assert_eq!(fake.read("clear"), None);
    assert_eq!(fake.read("killed"), None);
}
