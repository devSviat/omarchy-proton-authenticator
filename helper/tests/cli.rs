//! Runs the shipped binary. It calls `harden()` first, so these tests need the
//! shipped `RLIMIT_MEMLOCK` of 8 MiB: below it they are skipped, or fail when
//! `CI` is set.

use std::ffi::OsStr;
use std::fs;
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use pa_helper::otp::{totp, Algorithm};
use serde_json::{json, Value};
use tempfile::TempDir;

const HELPER: &str = env!("CARGO_BIN_EXE_pa-helper");
const BUDGET_KIB: u64 = 8192;
const RFC6238_SHA1_SEED: &[u8] = b"12345678901234567890";

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
            eprintln!("skipped: RLIMIT_MEMLOCK is below 8 MiB");
            false
        }
        _ => true,
    }
}

struct Sandbox {
    home: TempDir,
    state: TempDir,
    runtime: TempDir,
}

impl Sandbox {
    fn new() -> Self {
        Self {
            home: TempDir::new().unwrap(),
            state: TempDir::new().unwrap(),
            runtime: TempDir::new().unwrap(),
        }
    }

    fn command<S: AsRef<OsStr>>(&self, args: &[S]) -> Command {
        let mut cmd = Command::new(HELPER);
        cmd.env_clear()
            .env("HOME", self.home.path())
            .env("XDG_STATE_HOME", self.state.path())
            .env("XDG_RUNTIME_DIR", self.runtime.path())
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        cmd
    }

    fn run<S: AsRef<OsStr>>(&self, args: &[S]) -> Output {
        self.command(args).output().unwrap()
    }

    fn run_with_stdin<S: AsRef<OsStr>>(&self, args: &[S], input: &[u8]) -> Output {
        let mut child = self.command(args).stdin(Stdio::piped()).spawn().unwrap();
        let mut stdin = child.stdin.take().unwrap();
        // A helper that rejects oversized input exits before reading it all.
        let _ = stdin.write_all(input);
        drop(stdin);
        child.wait_with_output().unwrap()
    }

    fn prefs_dir(&self) -> PathBuf {
        self.state.path().join("sviat.proton-authenticator")
    }
}

fn line(out: &Output) -> String {
    assert!(out.stderr.is_empty(), "stderr: {:?}", out.stderr);
    let text = String::from_utf8(out.stdout.clone()).unwrap();
    let mut lines = text.lines();
    let first = lines.next().unwrap_or_default().to_owned();
    assert_eq!(lines.next(), None, "more than one line: {text:?}");
    assert!(text.ends_with('\n'));
    first
}

fn reply(out: &Output) -> Value {
    let value: Value = serde_json::from_str(&line(out)).unwrap();
    assert_eq!(value["protocol"], 1);
    let ok = value["ok"].as_bool().unwrap();
    assert_eq!(out.status.success(), ok, "exit status vs ok: {value}");
    value
}

fn error_of(out: &Output) -> String {
    let value = reply(out);
    assert_eq!(value["ok"], false);
    assert_eq!(value.as_object().unwrap().len(), 3, "{value}");
    value["error"].as_str().unwrap().to_owned()
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[test]
fn version_reply() {
    if !memlock_fits() {
        return;
    }
    let out = Sandbox::new().run(&["version"]);
    assert_eq!(line(&out), r#"{"ok":true,"protocol":1,"version":"0.1.0"}"#);
    assert!(out.status.success());
}

#[test]
fn unknown_command_is_invalid_argument() {
    if !memlock_fits() {
        return;
    }
    let sandbox = Sandbox::new();
    let cases: &[&[&str]] = &[
        &[],
        &["frobnicate"],
        &["version", "extra"],
        &["codes", "--bogus"],
        &["codes", "--demo", "--demo"],
        &["codes", "--only"],
        &["check", "--allow-prompt"],
        &["prefs"],
        &["prefs", "delete"],
        &["copy"],
        &["copy", "demo-github", "--demo", "extra"],
        &["--demo"],
    ];
    for args in cases {
        let out = sandbox.run(args);
        assert_eq!(error_of(&out), "INVALID_ARGUMENT", "{args:?}");
        assert_eq!(
            line(&out),
            r#"{"ok":false,"protocol":1,"error":"INVALID_ARGUMENT"}"#
        );
    }
}

#[test]
fn non_utf8_argument_is_invalid_argument() {
    if !memlock_fits() {
        return;
    }
    let sandbox = Sandbox::new();
    let bad = OsStr::from_bytes(b"demo-\xff");
    let out = sandbox.run(&[OsStr::new("copy"), bad, OsStr::new("--demo")]);
    assert_eq!(error_of(&out), "INVALID_ARGUMENT");
    let out = sandbox.run(&[OsStr::from_bytes(b"\xfe")]);
    assert_eq!(error_of(&out), "INVALID_ARGUMENT");
}

#[test]
fn bad_id_is_invalid_argument() {
    if !memlock_fits() {
        return;
    }
    let sandbox = Sandbox::new();
    let long = "a".repeat(129);
    let cases: &[&[&str]] = &[
        &["copy", "../x"],
        &["copy", "../x", "--demo"],
        &["copy", ""],
        &["copy", long.as_str(), "--demo"],
        &["copy", "a b", "--demo"],
        &["codes", "--only", "../x", "--demo"],
        &["copy", "demo-github", "--demo", "--clear-after", "4"],
        &["copy", "demo-github", "--demo", "--clear-after", "121"],
        &["copy", "demo-github", "--demo", "--clear-after", "+20"],
        &["copy", "demo-github", "--demo", "--clear-after", "abc"],
        &["copy", "demo-github", "--demo", "--clear-after"],
    ];
    for args in cases {
        assert_eq!(error_of(&sandbox.run(args)), "INVALID_ARGUMENT", "{args:?}");
    }
}

#[test]
fn demo_codes_shape() {
    if !memlock_fits() {
        return;
    }
    let before = now();
    let out = Sandbox::new().run(&["codes", "--demo"]);
    let after = now();
    let text = line(&out);
    assert!(!text.to_lowercase().contains("secret"), "{text}");
    let value = reply(&out);
    assert_eq!(value["ok"], true);
    let mut keys: Vec<&String> = value.as_object().unwrap().keys().collect();
    keys.sort();
    assert_eq!(keys, ["entries", "now", "ok", "protocol"]);
    let at = value["now"].as_u64().unwrap();
    assert!((before..=after).contains(&at));

    let entries = value["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 6);
    let issuers: Vec<&str> = entries
        .iter()
        .map(|e| e["issuer"].as_str().unwrap())
        .collect();
    assert_eq!(
        issuers,
        ["AWS", "Discord", "GitHub", "Google", "Proton", "Tailscale"]
    );
    for entry in entries {
        let mut fields: Vec<&String> = entry.as_object().unwrap().keys().collect();
        fields.sort();
        assert_eq!(
            fields,
            [
                "account",
                "code",
                "digits",
                "id",
                "issuer",
                "kind",
                "nextCode",
                "period",
                "remaining"
            ]
        );
        let code = entry["code"].as_str().unwrap();
        assert_eq!(code.len() as u64, entry["digits"].as_u64().unwrap());
        assert_ne!(entry["code"], entry["nextCode"]);
        let period = entry["period"].as_u64().unwrap();
        assert_eq!(entry["remaining"].as_u64().unwrap(), period - at % period);
    }
    assert_eq!(entries.iter().filter(|e| e["kind"] == "steam").count(), 1);
    assert_eq!(entries.iter().filter(|e| e["digits"] == 8).count(), 1);

    let github = entries.iter().find(|e| e["issuer"] == "GitHub").unwrap();
    assert_eq!(github["kind"], "totp");
    assert_eq!(
        github["code"],
        totp(RFC6238_SHA1_SEED, at, 30, Algorithm::Sha1, 6)
    );
}

#[test]
fn demo_codes_only() {
    if !memlock_fits() {
        return;
    }
    let sandbox = Sandbox::new();
    let value = reply(&sandbox.run(&["codes", "--demo", "--only", "demo-github"]));
    let entries = value["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["id"], "demo-github");
    let out = sandbox.run(&["codes", "--only", "demo-nope", "--demo"]);
    assert_eq!(error_of(&out), "ITEM_NOT_FOUND");
    let out = sandbox.run(&["copy", "demo-nope", "--demo"]);
    assert_eq!(error_of(&out), "ITEM_NOT_FOUND");
}

#[test]
fn check_without_vault() {
    if !memlock_fits() {
        return;
    }
    let sandbox = Sandbox::new();
    let out = sandbox.run(&["check"]);
    assert_eq!(
        line(&out),
        r#"{"ok":true,"protocol":1,"status":"VAULT_NOT_FOUND","vaultMtime":null}"#
    );
    assert!(out.status.success());
    let out = sandbox.run(&["codes"]);
    assert_eq!(error_of(&out), "VAULT_NOT_FOUND");
    let out = sandbox.run(&["copy", "some-id"]);
    assert_eq!(error_of(&out), "VAULT_NOT_FOUND");
}

#[test]
fn check_demo_is_ready() {
    if !memlock_fits() {
        return;
    }
    let sandbox = Sandbox::new();
    let first = line(&sandbox.run(&["check", "--demo"]));
    assert_eq!(
        first,
        r#"{"ok":true,"protocol":1,"status":"READY","vaultMtime":1767225600}"#
    );
    std::thread::sleep(Duration::from_millis(1100));
    assert_eq!(line(&sandbox.run(&["check", "--demo"])), first);
}

#[test]
fn flags_are_never_taken_for_ids() {
    if !memlock_fits() {
        return;
    }
    // HOME has no vault: reading it would answer VAULT_NOT_FOUND instead.
    let sandbox = Sandbox::new();
    assert_eq!(error_of(&sandbox.run(&["codes"])), "VAULT_NOT_FOUND");
    let cases: &[&[&str]] = &[
        &["copy", "--demo"],
        &["copy", "--clear-after", "5"],
        &["codes", "--only", "--demo"],
        &["codes", "--only", "--allow-prompt"],
    ];
    for args in cases {
        assert_eq!(error_of(&sandbox.run(args)), "INVALID_ARGUMENT", "{args:?}");
    }
}

fn mode(path: &Path) -> u32 {
    fs::symlink_metadata(path).unwrap().permissions().mode() & 0o7777
}

#[test]
fn prefs_roundtrip_and_perms() {
    if !memlock_fits() {
        return;
    }
    let sandbox = Sandbox::new();
    assert_eq!(
        line(&sandbox.run(&["prefs", "get"])),
        r#"{"ok":true,"protocol":1,"pinned":[],"recent":[],"privacy":false}"#
    );
    assert!(!sandbox.prefs_dir().exists());

    let input = json!({
        "pinned": ["a", "b:c", "a"],
        "recent": ["r1", "r2", "r3", "r4", "r5", "r6", "r7"],
        "privacy": true,
    });
    let out = sandbox.run_with_stdin(&["prefs", "set"], input.to_string().as_bytes());
    let expected = r#"{"ok":true,"protocol":1,"pinned":["a","b:c"],"recent":["r1","r2","r3","r4","r5"],"privacy":true}"#;
    assert_eq!(line(&out), expected);
    assert_eq!(line(&sandbox.run(&["prefs", "get"])), expected);

    let dir = sandbox.prefs_dir();
    assert_eq!(mode(&dir), 0o700);
    assert_eq!(mode(&dir.join("prefs.json")), 0o600);
    let names: Vec<_> = fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(names, ["prefs.json"]);
}

#[test]
fn prefs_caps_pinned_at_100() {
    if !memlock_fits() {
        return;
    }
    let sandbox = Sandbox::new();
    let pinned: Vec<String> = (0..150).map(|i| format!("id-{i}")).collect();
    let input = json!({"pinned": pinned, "recent": [], "privacy": false});
    let out = sandbox.run_with_stdin(&["prefs", "set"], input.to_string().as_bytes());
    let value = reply(&out);
    let stored = value["pinned"].as_array().unwrap();
    assert_eq!(stored.len(), 100);
    assert_eq!(stored[99], "id-99");
}

#[test]
fn prefs_existing_dir_is_tightened() {
    if !memlock_fits() {
        return;
    }
    let sandbox = Sandbox::new();
    let dir = sandbox.prefs_dir();
    fs::create_dir(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
    let input = br#"{"pinned":[],"recent":["x"],"privacy":false}"#;
    assert_eq!(
        reply(&sandbox.run_with_stdin(&["prefs", "set"], input))["ok"],
        true
    );
    assert_eq!(mode(&dir), 0o700);
}

#[test]
fn prefs_set_rejects_bad_input() {
    if !memlock_fits() {
        return;
    }
    let sandbox = Sandbox::new();
    let oversized = format!(
        r#"{{"pinned":[],"recent":[],"privacy":false,"pad":"{}"}}"#,
        "x".repeat(64 * 1024)
    );
    let cases: &[&[u8]] = &[
        br#"{"pinned":["../x"],"recent":[],"privacy":false}"#,
        br#"{"pinned":[],"recent":[""],"privacy":false}"#,
        br#"{"pinned":[],"recent":[],"privacy":"yes"}"#,
        br#"{"pinned":[],"recent":[],"privacy":false,"extra":1}"#,
        br#"{"pinned":[],"recent":[]}"#,
        b"not json",
        b"",
        oversized.as_bytes(),
    ];
    for input in cases {
        let out = sandbox.run_with_stdin(&["prefs", "set"], input);
        assert_eq!(
            error_of(&out),
            "INVALID_ARGUMENT",
            "{}",
            String::from_utf8_lossy(&input[..input.len().min(80)])
        );
    }
    assert!(!sandbox.prefs_dir().join("prefs.json").exists());
}

#[test]
fn prefs_rejects_symlink() {
    if !memlock_fits() {
        return;
    }
    let sandbox = Sandbox::new();
    let dir = sandbox.prefs_dir();
    fs::create_dir(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    let target = sandbox.home.path().join("target.json");
    let original = r#"{"pinned":["keep"],"recent":[],"privacy":false}"#;
    fs::write(&target, original).unwrap();
    symlink(&target, dir.join("prefs.json")).unwrap();

    assert_eq!(error_of(&sandbox.run(&["prefs", "get"])), "INTERNAL");
    let input = br#"{"pinned":["new"],"recent":[],"privacy":true}"#;
    assert_eq!(
        error_of(&sandbox.run_with_stdin(&["prefs", "set"], input)),
        "INTERNAL"
    );
    assert_eq!(fs::read_to_string(&target).unwrap(), original);
    assert!(fs::symlink_metadata(dir.join("prefs.json"))
        .unwrap()
        .file_type()
        .is_symlink());
}

#[test]
fn prefs_rejects_symlinked_dir() {
    if !memlock_fits() {
        return;
    }
    let sandbox = Sandbox::new();
    let elsewhere = TempDir::new().unwrap();
    symlink(elsewhere.path(), sandbox.prefs_dir()).unwrap();
    let input = br#"{"pinned":[],"recent":[],"privacy":true}"#;
    assert_eq!(
        error_of(&sandbox.run_with_stdin(&["prefs", "set"], input)),
        "INTERNAL"
    );
    assert_eq!(fs::read_dir(elsewhere.path()).unwrap().count(), 0);
}

#[test]
fn prefs_stale_tmp_is_replaced() {
    if !memlock_fits() {
        return;
    }
    let sandbox = Sandbox::new();
    let dir = sandbox.prefs_dir();
    fs::create_dir(&dir).unwrap();
    let tmp = dir.join("prefs.json.tmp");
    fs::write(&tmp, "partial").unwrap();
    fs::File::options()
        .write(true)
        .open(&tmp)
        .unwrap()
        .set_modified(SystemTime::now() - Duration::from_secs(60))
        .unwrap();
    let input = br#"{"pinned":[],"recent":["x"],"privacy":false}"#;
    assert_eq!(
        reply(&sandbox.run_with_stdin(&["prefs", "set"], input))["recent"],
        json!(["x"])
    );
    assert!(!tmp.exists());
}

#[test]
fn prefs_fresh_tmp_means_busy() {
    if !memlock_fits() {
        return;
    }
    let sandbox = Sandbox::new();
    let dir = sandbox.prefs_dir();
    fs::create_dir(&dir).unwrap();
    fs::write(dir.join("prefs.json.tmp"), "in progress").unwrap();
    let input = br#"{"pinned":[],"recent":["x"],"privacy":false}"#;
    assert_eq!(
        error_of(&sandbox.run_with_stdin(&["prefs", "set"], input)),
        "INTERNAL"
    );
    assert_eq!(
        fs::read_to_string(dir.join("prefs.json.tmp")).unwrap(),
        "in progress"
    );
}

#[test]
fn watchdog_times_out_stalled_run() {
    if !memlock_fits() {
        return;
    }
    let sandbox = Sandbox::new();
    let start = Instant::now();
    let mut child = sandbox
        .command(&["prefs", "set"])
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    let stdin = child.stdin.take().unwrap();
    let out = child.wait_with_output().unwrap();
    drop(stdin);
    let elapsed = start.elapsed();
    assert_eq!(error_of(&out), "TIMEOUT");
    assert!(
        (Duration::from_secs(10)..Duration::from_secs(13)).contains(&elapsed),
        "{elapsed:?}"
    );
}
