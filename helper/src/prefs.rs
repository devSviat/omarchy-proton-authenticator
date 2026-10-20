//! UI preferences: pinned and recently used item ids plus the privacy flag.
//! The only file the helper ever writes.

use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};

use crate::app::valid_item_id;
use crate::error::{ErrorCode, Result};

pub const MAX_INPUT_BYTES: usize = 64 * 1024;
const MAX_RECENT: usize = 5;
const MAX_PINNED: usize = 100;
const APP_DIR: &str = "sviat.proton-authenticator";
const FILE_NAME: &str = "prefs.json";
const TMP_NAME: &str = "prefs.json.tmp";
const DIR_MODE: u32 = 0o700;
const FILE_MODE: u32 = 0o600;
/// Longer than any helper run (the watchdog ends each one after 10 s), so an
/// older temp file was left by a writer that died, not one still writing.
const STALE_TMP_AGE: Duration = Duration::from_secs(30);

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Prefs {
    pub pinned: Vec<String>,
    pub recent: Vec<String>,
    pub privacy: bool,
}

impl Prefs {
    /// Parses and validates prefs sent by the UI. Every id must be valid;
    /// duplicates are dropped and the lists are capped.
    pub fn from_input(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_INPUT_BYTES {
            return Err(ErrorCode::InvalidArgument);
        }
        let prefs: Self = serde_json::from_slice(bytes).map_err(|_| ErrorCode::InvalidArgument)?;
        if !prefs
            .pinned
            .iter()
            .chain(&prefs.recent)
            .all(|id| valid_item_id(id))
        {
            return Err(ErrorCode::InvalidArgument);
        }
        Ok(prefs.normalized())
    }

    fn normalized(self) -> Self {
        Self {
            pinned: dedup_capped(self.pinned, MAX_PINNED),
            recent: dedup_capped(self.recent, MAX_RECENT),
            privacy: self.privacy,
        }
    }
}

fn dedup_capped(ids: Vec<String>, cap: usize) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(cap.min(ids.len()));
    for id in ids {
        if out.len() == cap {
            break;
        }
        if !out.contains(&id) {
            out.push(id);
        }
    }
    out
}

/// `$XDG_STATE_HOME` if it is absolute, else `~/.local/state`, joined with
/// the plugin's directory.
pub fn default_dir() -> Result<PathBuf> {
    let absolute = |name| {
        std::env::var_os(name)
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
    };
    let base = match absolute("XDG_STATE_HOME") {
        Some(state) => state,
        None => absolute("HOME")
            .ok_or(ErrorCode::Internal)?
            .join(".local/state"),
    };
    Ok(base.join(APP_DIR))
}

/// Reads the stored prefs; a missing file or directory yields the defaults.
/// A symlink, or anything but a regular file, is refused.
pub fn load(dir: &Path) -> Result<Prefs> {
    match fs::symlink_metadata(dir) {
        Ok(meta) if meta.is_dir() => {}
        Ok(_) => return Err(ErrorCode::Internal),
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(Prefs::default()),
        Err(_) => return Err(ErrorCode::Internal),
    }
    // O_NONBLOCK keeps a FIFO planted at the path from blocking the open.
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(dir.join(FILE_NAME))
    {
        Ok(file) => file,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(Prefs::default()),
        Err(_) => return Err(ErrorCode::Internal),
    };
    if !file.metadata().is_ok_and(|m| m.is_file()) {
        return Err(ErrorCode::Internal);
    }
    let mut bytes = Vec::new();
    file.take(MAX_INPUT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ErrorCode::Internal)?;
    // The file is only ever written by `store`, so content that no longer
    // parses (a newer format, a truncated disk) falls back to the defaults
    // instead of leaving the panel without prefs.
    let Ok(stored) = serde_json::from_slice::<Prefs>(&bytes) else {
        return Ok(Prefs::default());
    };
    let pinned = stored.pinned.into_iter().filter(|id| valid_item_id(id));
    let recent = stored.recent.into_iter().filter(|id| valid_item_id(id));
    Ok(Prefs {
        pinned: pinned.collect(),
        recent: recent.collect(),
        privacy: stored.privacy,
    }
    .normalized())
}

/// Atomically replaces the stored prefs: writes a fresh 0600 temp file next
/// to it, syncs it, and renames it over `prefs.json` in a 0700 directory.
pub fn store(dir: &Path, prefs: &Prefs) -> Result<()> {
    ensure_dir(dir)?;
    match fs::symlink_metadata(dir.join(FILE_NAME)) {
        Ok(meta) if meta.is_file() => {}
        Ok(_) => return Err(ErrorCode::Internal),
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        Err(_) => return Err(ErrorCode::Internal),
    }
    let body = serde_json::to_vec(prefs).map_err(|_| ErrorCode::Internal)?;
    let tmp = dir.join(TMP_NAME);
    let mut file = create_tmp(&tmp)?;
    let written = file
        .set_permissions(fs::Permissions::from_mode(FILE_MODE))
        .and_then(|()| file.write_all(&body))
        .and_then(|()| file.sync_all());
    drop(file);
    if written.is_err() {
        let _ = fs::remove_file(&tmp);
        return Err(ErrorCode::Internal);
    }
    if fs::rename(&tmp, dir.join(FILE_NAME)).is_err() {
        let _ = fs::remove_file(&tmp);
        return Err(ErrorCode::Internal);
    }
    File::open(dir)
        .and_then(|d| d.sync_all())
        .map_err(|_| ErrorCode::Internal)
}

fn ensure_dir(dir: &Path) -> Result<()> {
    if let Some(parent) = dir.parent() {
        DirBuilder::new()
            .recursive(true)
            .mode(DIR_MODE)
            .create(parent)
            .map_err(|_| ErrorCode::Internal)?;
    }
    match DirBuilder::new().mode(DIR_MODE).create(dir) {
        Ok(()) => {}
        Err(e) if e.kind() == ErrorKind::AlreadyExists => {}
        Err(_) => return Err(ErrorCode::Internal),
    }
    let meta = fs::symlink_metadata(dir).map_err(|_| ErrorCode::Internal)?;
    if !meta.is_dir() {
        return Err(ErrorCode::Internal);
    }
    if meta.permissions().mode() & 0o7777 != DIR_MODE {
        fs::set_permissions(dir, fs::Permissions::from_mode(DIR_MODE))
            .map_err(|_| ErrorCode::Internal)?;
    }
    Ok(())
}

fn open_new(path: &Path) -> std::io::Result<File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(FILE_MODE)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
}

/// Creates the temp file exclusively. One left behind by a writer that died
/// is removed first; a fresh one means another writer is busy, so this fails.
fn create_tmp(path: &Path) -> Result<File> {
    match open_new(path) {
        Ok(file) => return Ok(file),
        Err(e) if e.kind() == ErrorKind::AlreadyExists => {}
        Err(_) => return Err(ErrorCode::Internal),
    }
    let meta = fs::symlink_metadata(path).map_err(|_| ErrorCode::Internal)?;
    let age = meta
        .modified()
        .ok()
        .and_then(|m| SystemTime::now().duration_since(m).ok());
    if !age.is_some_and(|a| a > STALE_TMP_AGE) {
        return Err(ErrorCode::Internal);
    }
    fs::remove_file(path).map_err(|_| ErrorCode::Internal)?;
    open_new(path).map_err(|_| ErrorCode::Internal)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dedup_keeps_first_occurrence_and_caps() {
        let ids = ["a", "b", "a", "c", "b", "d"].map(String::from).to_vec();
        assert_eq!(dedup_capped(ids, 3), ["a", "b", "c"]);
    }

    #[test]
    fn load_filters_invalid_ids_from_the_file() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(
            tmp.path().join(FILE_NAME),
            r#"{"pinned":["ok","../bad"],"recent":["r","r"],"privacy":true}"#,
        )
        .unwrap();
        let prefs = load(tmp.path()).unwrap();
        assert_eq!(prefs.pinned, ["ok"]);
        assert_eq!(prefs.recent, ["r"]);
        assert!(prefs.privacy);
    }

    #[test]
    fn unparsable_file_yields_defaults() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join(FILE_NAME), "{").unwrap();
        assert_eq!(load(tmp.path()).unwrap(), Prefs::default());
    }

    #[test]
    fn fifo_is_refused_without_blocking() {
        let tmp = tempfile::tempdir().unwrap();
        let status = std::process::Command::new("/usr/bin/mkfifo")
            .arg(tmp.path().join(FILE_NAME))
            .status()
            .unwrap();
        assert!(status.success());
        assert_eq!(load(tmp.path()).unwrap_err(), ErrorCode::Internal);
    }
}
