use std::path::PathBuf;
use std::time::Duration;

use zeroize::Zeroizing;

use crate::app::{KeyProvider, LockState};
use crate::error::{ErrorCode, Result};
use crate::proc::run_bounded;

const GDBUS: &str = "/usr/bin/gdbus";
const SECRET_TOOL: &str = "/usr/bin/secret-tool";
const SERVICE: &str = "com.proton.authenticator";
const ROOT_KEY_LEN: usize = 32;
const SECRET_TOOL_MAX_OUT: usize = 64;
const SECRET_TOOL_TIMEOUT: Duration = Duration::from_secs(10);
const GDBUS_MAX_OUT: usize = 4096;
const GDBUS_TIMEOUT: Duration = Duration::from_secs(5);
const SECRETS_PATH_PREFIX: &str = "/org/freedesktop/secrets/";
const KEY_ID_MAX_LEN: usize = 128;

/// Key provider backed by the Secret Service, via `gdbus` and `secret-tool`
/// run by absolute path.
pub struct SecretToolKeys {
    gdbus: PathBuf,
    secret_tool: PathBuf,
}

impl SecretToolKeys {
    pub fn new() -> Self {
        Self {
            gdbus: PathBuf::from(GDBUS),
            secret_tool: PathBuf::from(SECRET_TOOL),
        }
    }
}

impl Default for SecretToolKeys {
    fn default() -> Self {
        Self::new()
    }
}

/// The id is interpolated into a GVariant text argument, so it must not be
/// able to close the quote.
fn check_key_id(id: &str) -> Result<()> {
    let bytes = id.as_bytes();
    let Some((first, rest)) = bytes.split_first() else {
        return Err(ErrorCode::InvalidArgument);
    };
    let ok = bytes.len() <= KEY_ID_MAX_LEN
        && (first.is_ascii_alphanumeric() || *first == b'_')
        && rest
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b':' | b'-'));
    if ok {
        Ok(())
    } else {
        Err(ErrorCode::InvalidArgument)
    }
}

impl KeyProvider for SecretToolKeys {
    fn lock_state(&self, key_id: &str) -> Result<LockState> {
        check_key_id(key_id)?;
        let attributes = format!("{{'service': '{SERVICE}', 'username': '{key_id}'}}");
        let (code, out) = run_bounded(
            &self.gdbus,
            &[
                "call",
                "--session",
                "--dest",
                "org.freedesktop.secrets",
                "--object-path",
                "/org/freedesktop/secrets",
                "--method",
                "org.freedesktop.Secret.Service.SearchItems",
                &attributes,
            ],
            None,
            GDBUS_MAX_OUT,
            GDBUS_TIMEOUT,
        )?;
        if code != 0 {
            return Err(ErrorCode::KeyringUnavailable);
        }
        let text = std::str::from_utf8(&out).map_err(|_| ErrorCode::KeyringUnavailable)?;
        parse_search_items(text)
    }

    fn root_key(&self, key_id: &str) -> Result<Zeroizing<[u8; 32]>> {
        check_key_id(key_id)?;
        let (code, out) = run_bounded(
            &self.secret_tool,
            &["lookup", "service", SERVICE, "username", key_id],
            None,
            SECRET_TOOL_MAX_OUT,
            SECRET_TOOL_TIMEOUT,
        )?;
        if code != 0 {
            return Err(ErrorCode::KeyNotFound);
        }
        if out.len() != ROOT_KEY_LEN {
            return Err(ErrorCode::DecryptFailed);
        }
        let mut key = Zeroizing::new([0u8; ROOT_KEY_LEN]);
        key.copy_from_slice(&out);
        Ok(key)
    }
}

/// Parses the `(unlocked, locked)` object-path lists printed by gdbus for
/// `SearchItems`. Any other shape is an error.
pub fn parse_search_items(out: &str) -> Result<LockState> {
    parse_pair(out.strip_suffix('\n').unwrap_or(out)).ok_or(ErrorCode::KeyringUnavailable)
}

fn parse_pair(s: &str) -> Option<LockState> {
    let s = s.strip_prefix('(')?;
    let (unlocked, s) = parse_list(s)?;
    let s = s.strip_prefix(", ")?;
    let (locked, s) = parse_list(s)?;
    if s != ")" {
        return None;
    }
    match (unlocked, locked) {
        (true, false) => Some(LockState::Unlocked),
        (false, true) => Some(LockState::Locked),
        (false, false) => Some(LockState::Missing),
        (true, true) => None,
    }
}

/// Returns whether the list is non-empty, and the remaining input.
fn parse_list(s: &str) -> Option<(bool, &str)> {
    if let Some(rest) = s.strip_prefix("@ao []") {
        return Some((false, rest));
    }
    let mut s = s.strip_prefix("[objectpath ")?;
    loop {
        let (path, rest) = parse_quoted_path(s)?;
        if !valid_object_path(path) {
            return None;
        }
        if let Some(rest) = rest.strip_prefix(']') {
            return Some((true, rest));
        }
        s = rest.strip_prefix(", ")?;
    }
}

fn parse_quoted_path(s: &str) -> Option<(&str, &str)> {
    let s = s.strip_prefix('\'')?;
    let end = s.find('\'')?;
    Some((&s[..end], &s[end + 1..]))
}

fn valid_object_path(path: &str) -> bool {
    path.strip_prefix(SECRETS_PATH_PREFIX).is_some_and(|tail| {
        !tail.is_empty()
            && tail
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'/'))
            && !tail.ends_with('/')
            && !tail.contains("//")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const ITEM: &str = "'/org/freedesktop/secrets/collection/login/12'";

    #[test]
    fn parse_search_items_states() {
        assert_eq!(
            parse_search_items(&format!("([objectpath {ITEM}], @ao [])\n")),
            Ok(LockState::Unlocked)
        );
        assert_eq!(
            parse_search_items(&format!("(@ao [], [objectpath {ITEM}])")),
            Ok(LockState::Locked)
        );
        assert_eq!(
            parse_search_items("(@ao [], @ao [])\n"),
            Ok(LockState::Missing)
        );
    }

    #[test]
    fn parse_search_items_multiple_paths() {
        let two = "'/org/freedesktop/secrets/collection/login/13'";
        assert_eq!(
            parse_search_items(&format!("([objectpath {ITEM}, {two}], @ao [])")),
            Ok(LockState::Unlocked)
        );
    }

    #[test]
    fn parse_search_items_rejects_garbage() {
        let bad = [
            "",
            "garbage",
            "()",
            "(@ao [])",
            "(@ao [], @ao [], @ao [])",
            "(@ao [], @ao []) trailing",
            "(@ao [], @ao [])\n\n",
            "([], [])",
            "(@ao [],@ao [])",
            "([objectpath ''], @ao [])",
            "([objectpath '/etc/passwd'], @ao [])",
            "([objectpath '/org/freedesktop/secrets/'], @ao [])",
            "([objectpath '/org/freedesktop/secrets/a b'], @ao [])",
            "([objectpath '/org/freedesktop/secrets/a'",
            "([objectpath '/org/freedesktop/secrets/a/'], @ao [])",
            "([objectpath '/org/freedesktop/secrets/a//b'], @ao [])",
            "([objectpath '/org/freedesktop/secrets/a'], [objectpath '/org/freedesktop/secrets/b'])",
        ];
        for text in bad {
            assert_eq!(
                parse_search_items(text),
                Err(ErrorCode::KeyringUnavailable),
                "{text:?}"
            );
        }
    }

    #[test]
    fn rejects_unsafe_key_ids_without_running_anything() {
        let keys = SecretToolKeys {
            gdbus: PathBuf::from("/nonexistent/gdbus"),
            secret_tool: PathBuf::from("/nonexistent/secret-tool"),
        };
        for id in ["", "a'b", "a b", "-lead", ".lead", "a\n", &"x".repeat(129)] {
            assert_eq!(
                keys.lock_state(id),
                Err(ErrorCode::InvalidArgument),
                "{id:?}"
            );
            assert_eq!(keys.root_key(id).unwrap_err(), ErrorCode::InvalidArgument);
        }
    }

    #[test]
    fn missing_binaries_map_to_dependency_missing() {
        let keys = SecretToolKeys {
            gdbus: PathBuf::from("/nonexistent/gdbus"),
            secret_tool: PathBuf::from("/nonexistent/secret-tool"),
        };
        assert_eq!(keys.lock_state("abc"), Err(ErrorCode::DependencyMissing));
        assert_eq!(
            keys.root_key("abc").unwrap_err(),
            ErrorCode::DependencyMissing
        );
    }
}
