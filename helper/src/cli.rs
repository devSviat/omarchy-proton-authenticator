//! Command-line protocol: parses the arguments, runs one command and writes
//! exactly one JSON line to stdout.

use std::ffi::OsString;
use std::io::{self, Read, Write};
use std::ops::RangeInclusive;
use std::path::Path;
use std::process::ExitCode;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Serialize;

use crate::app::{self, valid_item_id, CodesRequest};
use crate::clipboard::{Clipboard, WL_COPY};
use crate::demo;
use crate::domain::EntryView;
use crate::error::{ErrorCode, Result};
use crate::keyring::{SecretToolKeys, SECRET_TOOL};
use crate::output::{render, render_err, Rendered};
use crate::prefs::{self, Prefs};
use crate::sys;
use crate::vault::ProtonIdbVault;
use crate::watchdog::Watchdog;

/// Upper bound on one helper run, except the clipboard hold after `copy`
/// has replied, which has its own deadline.
pub const RUN_TIMEOUT: Duration = Duration::from_secs(10);
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
struct CodesBody {
    now: u64,
    entries: Vec<EntryView>,
}

#[derive(Serialize)]
struct EmptyBody {}

fn set_once(flag: &mut bool) -> Result<()> {
    if std::mem::replace(flag, true) {
        return Err(ErrorCode::InvalidArgument);
    }
    Ok(())
}

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
    let mut args = rest.iter().copied();
    while let Some(arg) = args.next() {
        match arg {
            "--only" if only.is_none() => only = Some(item_id(args.next())?),
            "--allow-prompt" => set_once(&mut allow_prompt)?,
            "--demo" => set_once(&mut demo)?,
            _ => return Err(ErrorCode::InvalidArgument),
        }
    }
    Ok(Command::Codes {
        only,
        allow_prompt,
        demo,
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
            vault_mtime: Some(unix_now()?),
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

fn codes(only: Option<String>, allow_prompt: bool, demo: bool) -> Result<CodesBody> {
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
        app::codes(&real_vault()?, &SecretToolKeys::new(), &req)?
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

/// The watchdog's action: report `TIMEOUT` and end the process.
pub fn time_out() {
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

/// Replies first, then holds the clipboard from a detached session with
/// stdout closed, so the caller sees EOF and is free to exit while the code
/// is still on the clipboard.
fn copy(
    id: String,
    clear_after: Duration,
    demo: bool,
    clipboard: &dyn Clipboard,
    watchdog: Watchdog,
) -> ExitCode {
    let picked = codes(Some(id), false, demo)
        .and_then(|body| {
            body.entries
                .into_iter()
                .next()
                .ok_or(ErrorCode::ItemNotFound)
        })
        .and_then(app::copy_code);
    let code = match picked {
        Ok(code) => code,
        Err(e) => return finish(watchdog, render::<EmptyBody>(Err(e))),
    };
    finish(watchdog, render(Ok(EmptyBody {})));
    if sys::close_stdout().is_err() || sys::detach_session().is_err() {
        return ExitCode::FAILURE;
    }
    exit_code(clipboard.hold(code, clear_after).is_ok())
}

/// Runs one helper invocation after `harden()`: arms a watchdog that ends the
/// process with `TIMEOUT` after `timeout`, parses `args` (without the program
/// name), dispatches, and writes the reply.
pub fn run(args: &[OsString], clipboard: &dyn Clipboard, timeout: Duration) -> ExitCode {
    let watchdog = match Watchdog::arm(timeout, time_out) {
        Ok(watchdog) => watchdog,
        Err(e) => {
            emit(&render_err(e));
            return ExitCode::FAILURE;
        }
    };
    let reply = match parse(args) {
        Err(e) => render::<EmptyBody>(Err(e)),
        Ok(Command::Version) => render(Ok(VersionBody {
            version: env!("CARGO_PKG_VERSION"),
        })),
        Ok(Command::Check { demo }) => render(check(demo)),
        Ok(Command::Codes {
            only,
            allow_prompt,
            demo,
        }) => render(codes(only, allow_prompt, demo)),
        Ok(Command::Copy {
            id,
            clear_after,
            demo,
        }) => return copy(id, clear_after, demo, clipboard, watchdog),
        Ok(Command::PrefsGet) => render(prefs::default_dir().and_then(|dir| prefs::load(&dir))),
        Ok(Command::PrefsSet) => render(prefs_set()),
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
    fn rejects_repeats_and_out_of_range() {
        for args in [
            &["codes", "--only", "a", "--only", "b"][..],
            &["codes", "--allow-prompt", "--allow-prompt"],
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
