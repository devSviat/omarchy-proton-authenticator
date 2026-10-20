//! Command-line protocol: parses the arguments, runs one command and writes
//! exactly one JSON line to stdout.

use std::ffi::OsString;
use std::io::{self, Read, Write};
use std::ops::RangeInclusive;
use std::path::Path;
use std::process::ExitCode;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Serialize;

use crate::app::{self, valid_item_id, CodesRequest, PrivateRequest};
use crate::clipboard::{Clipboard, WL_COPY};
use crate::demo;
use crate::domain::{EntryView, PrivateEntry};
use crate::error::{ErrorCode, Result};
use crate::keyring::{SecretToolKeys, SECRET_TOOL};
use crate::output::{render, render_err, Rendered};
use crate::prefs::{self, Prefs};
use crate::proc;
use crate::sys;
use crate::vault::ProtonIdbVault;
use crate::watchdog::Watchdog;

/// Upper bounds on one helper run. The clipboard hold after `copy` has
/// replied is not covered; it has its own deadline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timeouts {
    pub run: Duration,
    /// For `codes --allow-prompt`, both the whole run and the keyring lookup:
    /// that lookup waits for the user to answer an unlock prompt.
    pub prompt: Duration,
}

pub const TIMEOUTS: Timeouts = Timeouts {
    run: Duration::from_secs(10),
    prompt: Duration::from_secs(120),
};

impl Timeouts {
    pub fn for_command(&self, command: &Command) -> Duration {
        match command {
            Command::Codes {
                allow_prompt: true,
                demo: false,
                ..
            } => self.prompt,
            _ => self.run,
        }
    }

    pub fn keys(&self, allow_prompt: bool) -> SecretToolKeys {
        if allow_prompt {
            SecretToolKeys::with_lookup_timeout(self.prompt)
        } else {
            SecretToolKeys::new()
        }
    }
}

const CLEAR_AFTER_SECS: RangeInclusive<u64> = 5..=120;
const DEFAULT_CLEAR_AFTER_SECS: u64 = 20;
const READY: &str = "READY";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Version,
    Check {
        demo: bool,
    },
    Codes {
        only: Option<String>,
        allow_prompt: bool,
        demo: bool,
        /// Labels only, except the `reveal` entry; excludes `only`.
        private: bool,
        reveal: Option<String>,
    },
    Copy {
        id: String,
        clear_after: Duration,
        demo: bool,
    },
    PrefsGet,
    PrefsSet,
}

#[derive(Serialize)]
struct VersionBody {
    version: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CheckBody {
    status: &'static str,
    vault_mtime: Option<u64>,
}

#[derive(Serialize)]
struct CodesBody<E> {
    now: u64,
    entries: Vec<E>,
}

#[derive(Serialize)]
struct EmptyBody {}

fn set_once(flag: &mut bool) -> Result<()> {
    if std::mem::replace(flag, true) {
        return Err(ErrorCode::InvalidArgument);
    }
    Ok(())
}

/// [`valid_item_id`] refuses a leading `-`, so a flag is never taken for an id.
fn item_id(arg: Option<&str>) -> Result<String> {
    match arg {
        Some(id) if valid_item_id(id) => Ok(id.to_owned()),
        _ => Err(ErrorCode::InvalidArgument),
    }
}

fn clear_after(arg: Option<&str>) -> Result<Duration> {
    let secs = arg
        .filter(|s| !s.is_empty() && s.len() <= 3 && s.bytes().all(|b| b.is_ascii_digit()))
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|s| CLEAR_AFTER_SECS.contains(s))
        .ok_or(ErrorCode::InvalidArgument)?;
    Ok(Duration::from_secs(secs))
}

fn parse_codes(rest: &[&str]) -> Result<Command> {
    let (mut only, mut allow_prompt, mut demo) = (None, false, false);
    let (mut private, mut reveal) = (false, None);
    let mut args = rest.iter().copied();
    while let Some(arg) = args.next() {
        match arg {
            "--only" if only.is_none() => only = Some(item_id(args.next())?),
            "--allow-prompt" => set_once(&mut allow_prompt)?,
            "--demo" => set_once(&mut demo)?,
            "--private" => set_once(&mut private)?,
            "--reveal" if reveal.is_none() => reveal = Some(item_id(args.next())?),
            _ => return Err(ErrorCode::InvalidArgument),
        }
    }
    if (reveal.is_some() && !private) || (private && only.is_some()) {
        return Err(ErrorCode::InvalidArgument);
    }
    Ok(Command::Codes {
        only,
        allow_prompt,
        demo,
        private,
        reveal,
    })
}

fn parse_copy(rest: &[&str]) -> Result<Command> {
    let mut args = rest.iter().copied();
    let id = item_id(args.next())?;
    let (mut seconds, mut demo) = (None, false);
    while let Some(arg) = args.next() {
        match arg {
            "--clear-after" if seconds.is_none() => seconds = Some(clear_after(args.next())?),
            "--demo" => set_once(&mut demo)?,
            _ => return Err(ErrorCode::InvalidArgument),
        }
    }
    Ok(Command::Copy {
        id,
        clear_after: seconds.unwrap_or(Duration::from_secs(DEFAULT_CLEAR_AFTER_SECS)),
        demo,
    })
}

/// Parses the arguments after the program name. Anything unknown, repeated,
/// missing or not UTF-8 is `InvalidArgument`.
pub fn parse(args: &[OsString]) -> Result<Command> {
    let args: Vec<&str> = args
        .iter()
        .map(|a| a.to_str().ok_or(ErrorCode::InvalidArgument))
        .collect::<Result<_>>()?;
    let Some((command, rest)) = args.split_first() else {
        return Err(ErrorCode::InvalidArgument);
    };
    match (*command, rest) {
        ("version", []) => Ok(Command::Version),
        ("check", []) => Ok(Command::Check { demo: false }),
        ("check", ["--demo"]) => Ok(Command::Check { demo: true }),
        ("codes", rest) => parse_codes(rest),
        ("copy", rest) => parse_copy(rest),
        ("prefs", ["get"]) => Ok(Command::PrefsGet),
        ("prefs", ["set"]) => Ok(Command::PrefsSet),
        _ => Err(ErrorCode::InvalidArgument),
    }
}

fn unix_now() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| ErrorCode::Internal)
}

fn real_vault() -> Result<ProtonIdbVault> {
    Ok(ProtonIdbVault::new(ProtonIdbVault::default_root()?))
}

fn check(demo: bool) -> Result<CheckBody> {
    if demo {
        return Ok(CheckBody {
            status: READY,
            vault_mtime: Some(demo::VAULT_MTIME),
        });
    }
    let report = match real_vault() {
        Ok(vault) => app::check(
            &vault,
            &SecretToolKeys::new(),
            &[Path::new(WL_COPY), Path::new(SECRET_TOOL)],
        ),
        Err(e) => app::CheckReport {
            status: Err(e),
            vault_mtime: None,
        },
    };
    Ok(CheckBody {
        status: report.status.map_or_else(ErrorCode::as_str, |()| READY),
        vault_mtime: report.vault_mtime,
    })
}

fn codes(
    only: Option<String>,
    allow_prompt: bool,
    demo: bool,
    timeouts: &Timeouts,
) -> Result<CodesBody<EntryView>> {
    let now = unix_now()?;
    let entries = if demo {
        let mut entries = demo::entries(now);
        if let Some(only) = &only {
            entries.retain(|e| e.id == *only);
            if entries.is_empty() {
                return Err(ErrorCode::ItemNotFound);
            }
        }
        entries
    } else {
        let req = CodesRequest {
            only,
            allow_prompt,
            unix: now,
        };
        app::codes(&real_vault()?, &timeouts.keys(allow_prompt), &req)?
    };
    Ok(CodesBody { now, entries })
}

fn codes_private(
    reveal: Option<String>,
    allow_prompt: bool,
    demo: bool,
    timeouts: &Timeouts,
) -> Result<CodesBody<PrivateEntry>> {
    let now = unix_now()?;
    let entries = if demo {
        demo::private_entries(now, reveal.as_deref())?
    } else {
        let req = PrivateRequest {
            reveal,
            allow_prompt,
            unix: now,
        };
        app::codes_private(&real_vault()?, &timeouts.keys(allow_prompt), &req)?
    };
    Ok(CodesBody { now, entries })
}

fn read_stdin_capped() -> Result<Vec<u8>> {
    let mut input = Vec::new();
    io::stdin()
        .lock()
        .take(prefs::MAX_INPUT_BYTES as u64 + 1)
        .read_to_end(&mut input)
        .map_err(|_| ErrorCode::InvalidArgument)?;
    Ok(input)
}

fn prefs_set() -> Result<Prefs> {
    let prefs = Prefs::from_input(&read_stdin_capped()?)?;
    prefs::store(&prefs::default_dir()?, &prefs)?;
    Ok(prefs)
}

/// Writes one reply line. A reader that went away is not an error worth
/// reporting: there is nobody left to report it to.
pub fn emit(line: &str) {
    let mut out = io::stdout().lock();
    let _ = writeln!(out, "{line}");
    let _ = out.flush();
}

/// The watchdog's action: kill the running child's process group, report
/// `TIMEOUT` and end the process. The guard keeps any other child from being
/// spawned until the process is gone; if the lock stays busy, the process
/// ends without the kill rather than hang.
pub fn time_out() {
    let _frozen = proc::kill_active_groups();
    emit(&render_err(ErrorCode::Timeout));
    std::process::exit(1);
}

fn exit_code(ok: bool) -> ExitCode {
    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// Cancels the watchdog before writing, so its `TIMEOUT` line can never
/// follow or interleave with the reply.
fn finish(watchdog: Watchdog, reply: Rendered) -> ExitCode {
    watchdog.cancel();
    emit(&reply.line);
    exit_code(reply.ok)
}

/// Puts the code on the clipboard before replying, so a missing or failing
/// wl-copy is still reported. Then holds it from a detached session with
/// stdout closed, so the caller sees EOF and is free to exit while the code
/// is still on the clipboard.
fn copy(
    id: String,
    clear_after: Duration,
    demo: bool,
    clipboard: &dyn Clipboard,
    watchdog: Watchdog,
    timeouts: &Timeouts,
) -> ExitCode {
    let started = codes(Some(id), false, demo, timeouts)
        .and_then(|body| {
            body.entries
                .into_iter()
                .next()
                .ok_or(ErrorCode::ItemNotFound)
        })
        .and_then(app::copy_code)
        .and_then(|code| clipboard.start(code, clear_after));
    let hold = match started {
        Ok(hold) => hold,
        Err(e) => return finish(watchdog, render::<EmptyBody>(Err(e))),
    };
    finish(watchdog, render(Ok(EmptyBody {})));
    if sys::close_stdout().is_err() || sys::detach_session().is_err() {
        hold.abort();
        return ExitCode::FAILURE;
    }
    exit_code(hold.wait_and_clear().is_ok())
}

/// Runs one helper invocation after `harden()`: parses `args` (without the
/// program name), arms a watchdog that ends the process with `TIMEOUT` once
/// the command's budget from `timeouts` is spent, dispatches, and writes the
/// reply.
pub fn run(args: &[OsString], clipboard: &dyn Clipboard, timeouts: &Timeouts) -> ExitCode {
    let command = match parse(args) {
        Ok(command) => command,
        Err(e) => {
            emit(&render_err(e));
            return ExitCode::FAILURE;
        }
    };
    let watchdog = match Watchdog::arm(timeouts.for_command(&command), time_out) {
        Ok(watchdog) => watchdog,
        Err(e) => {
            emit(&render_err(e));
            return ExitCode::FAILURE;
        }
    };
    let reply = match command {
        Command::Version => render(Ok(VersionBody {
            version: env!("CARGO_PKG_VERSION"),
        })),
        Command::Check { demo } => render(check(demo)),
        Command::Codes {
            private: true,
            reveal,
            allow_prompt,
            demo,
            ..
        } => render(codes_private(reveal, allow_prompt, demo, timeouts)),
        Command::Codes {
            only,
            allow_prompt,
            demo,
            ..
        } => render(codes(only, allow_prompt, demo, timeouts)),
        Command::Copy {
            id,
            clear_after,
            demo,
        } => return copy(id, clear_after, demo, clipboard, watchdog, timeouts),
        Command::PrefsGet => render(prefs::default_dir().and_then(|dir| prefs::load(&dir))),
        Command::PrefsSet => render(prefs_set()),
    };
    finish(watchdog, reply)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_strs(args: &[&str]) -> Result<Command> {
        let args: Vec<OsString> = args.iter().map(OsString::from).collect();
        parse(&args)
    }

    #[test]
    fn parses_every_command() {
        assert_eq!(parse_strs(&["version"]), Ok(Command::Version));
        assert_eq!(
            parse_strs(&["check", "--demo"]),
            Ok(Command::Check { demo: true })
        );
        assert_eq!(
            parse_strs(&["codes", "--allow-prompt", "--only", "a:b", "--demo"]),
            Ok(Command::Codes {
                only: Some("a:b".into()),
                allow_prompt: true,
                demo: true,
                private: false,
                reveal: None,
            })
        );
        assert_eq!(
            parse_strs(&["codes", "--private", "--allow-prompt", "--reveal", "a:b"]),
            Ok(Command::Codes {
                only: None,
                allow_prompt: true,
                demo: false,
                private: true,
                reveal: Some("a:b".into()),
            })
        );
        assert_eq!(
            parse_strs(&["codes", "--reveal", "a:b", "--private"]),
            Ok(Command::Codes {
                only: None,
                allow_prompt: false,
                demo: false,
                private: true,
                reveal: Some("a:b".into()),
            })
        );
        assert_eq!(
            parse_strs(&["copy", "x", "--clear-after", "120"]),
            Ok(Command::Copy {
                id: "x".into(),
                clear_after: Duration::from_secs(120),
                demo: false,
            })
        );
        assert_eq!(
            parse_strs(&["copy", "x"]),
            Ok(Command::Copy {
                id: "x".into(),
                clear_after: Duration::from_secs(20),
                demo: false,
            })
        );
        assert_eq!(parse_strs(&["prefs", "get"]), Ok(Command::PrefsGet));
        assert_eq!(parse_strs(&["prefs", "set"]), Ok(Command::PrefsSet));
    }

    #[test]
    fn allow_prompt_gets_the_prompt_budget() {
        let timeouts = Timeouts {
            run: Duration::from_secs(3),
            prompt: Duration::from_secs(7),
        };
        let budget = |args: &[&str]| timeouts.for_command(&parse_strs(args).unwrap());
        assert_eq!(budget(&["codes", "--allow-prompt"]), timeouts.prompt);
        assert_eq!(
            budget(&["codes", "--only", "x", "--allow-prompt"]),
            timeouts.prompt
        );
        assert_eq!(budget(&["codes"]), timeouts.run);
        assert_eq!(
            budget(&["codes", "--private", "--reveal", "x", "--allow-prompt"]),
            timeouts.prompt
        );
        assert_eq!(
            budget(&["codes", "--private", "--reveal", "x"]),
            timeouts.run
        );
        assert_eq!(budget(&["codes", "--private"]), timeouts.run);
        assert_eq!(budget(&["codes", "--allow-prompt", "--demo"]), timeouts.run);
        assert_eq!(budget(&["copy", "x"]), timeouts.run);
        assert_eq!(budget(&["check"]), timeouts.run);
        assert_eq!(budget(&["prefs", "set"]), timeouts.run);
        assert_eq!(timeouts.keys(true).lookup_timeout(), timeouts.prompt);
        assert_eq!(
            timeouts.keys(false).lookup_timeout(),
            Duration::from_secs(10)
        );
    }

    #[test]
    fn shipped_budgets() {
        assert_eq!(TIMEOUTS.run, Duration::from_secs(10));
        assert_eq!(TIMEOUTS.prompt, Duration::from_secs(120));
    }

    #[test]
    fn flags_are_never_taken_for_ids() {
        for args in [
            &["copy", "--demo"][..],
            &["copy", "--clear-after", "5"],
            &["copy", "-x", "--demo"],
            &["codes", "--only", "--demo"],
            &["codes", "--only", "--allow-prompt"],
            &["codes", "--only", "-"],
            &["codes", "--private", "--reveal", "--demo"],
            &["codes", "--private", "--reveal", "-"],
        ] {
            assert_eq!(
                parse_strs(args),
                Err(ErrorCode::InvalidArgument),
                "{args:?}"
            );
        }
    }

    #[test]
    fn rejects_repeats_and_out_of_range() {
        for args in [
            &["codes", "--only", "a", "--only", "b"][..],
            &["codes", "--allow-prompt", "--allow-prompt"],
            &["codes", "--private", "--private"],
            &["codes", "--private", "--reveal", "a", "--reveal", "b"],
            &["codes", "--reveal", "a"],
            &["codes", "--private", "--only", "a"],
            &["codes", "--only", "a", "--private", "--reveal", "a"],
            &["copy", "x", "--clear-after", "5", "--clear-after", "6"],
            &["copy", "x", "--clear-after", "0005"],
            &["copy", "x", "--clear-after", "-5"],
            &["copy", "x", "--demo", "--demo"],
            &["check", "--demo", "--demo"],
        ] {
            assert_eq!(
                parse_strs(args),
                Err(ErrorCode::InvalidArgument),
                "{args:?}"
            );
        }
        assert!(parse_strs(&["copy", "x", "--clear-after", "5"]).is_ok());
    }

    fn keys_of<T: Serialize>(body: &T) -> Vec<String> {
        match serde_json::to_value(body).unwrap() {
            serde_json::Value::Object(map) => map.keys().cloned().collect(),
            other => panic!("not an object: {other}"),
        }
    }

    #[test]
    fn bodies_never_carry_envelope_fields() {
        let bodies = [
            keys_of(&VersionBody { version: "0" }),
            keys_of(&CheckBody {
                status: READY,
                vault_mtime: None,
            }),
            keys_of(&CodesBody {
                now: 0,
                entries: demo::entries(0),
            }),
            keys_of(&EmptyBody {}),
            keys_of(&Prefs::default()),
        ];
        for keys in bodies {
            assert!(
                !keys.iter().any(|k| k == "ok" || k == "protocol"),
                "{keys:?}"
            );
        }
    }

    #[test]
    fn empty_body_renders_bare_envelope() {
        assert_eq!(render(Ok(EmptyBody {})).line, r#"{"ok":true,"protocol":1}"#);
    }
}
