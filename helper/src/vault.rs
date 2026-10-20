use std::ffi::OsString;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use zeroize::Zeroizing;

use crate::error::{ErrorCode, Result};
use crate::sqlite_file::{Column, Image};
use crate::ssv::{self, Value};
use crate::wal;

const DB_FILE_NAME: &str = "IndexedDB.sqlite3";
const MAX_WALK_DEPTH: usize = 6;
const MAX_CANDIDATES: usize = 32;
const MAX_DIR_ENTRIES: usize = 10_000;
const MAX_ITEMS: usize = 1000;
const MAX_MAIN_BYTES: u64 = 2 * 1024 * 1024;
const MAX_WAL_BYTES: u64 = 2 * 1024 * 1024;
const MAX_IMAGE_BYTES: usize = 2 * 1024 * 1024;
const STABLE_RETRIES: usize = 3;
const STABLE_PAUSE: Duration = Duration::from_millis(50);

pub struct StorageKeyRef {
    pub id: String,
    pub adapter_key_id: Option<String>,
    pub salt: Zeroizing<Vec<u8>>,
    pub source: i32,
    pub has_unsafe_key: bool,
}

impl fmt::Debug for StorageKeyRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StorageKeyRef")
            .field("source", &self.source)
            .field("has_unsafe_key", &self.has_unsafe_key)
            .finish_non_exhaustive()
    }
}

pub struct EncryptedItem {
    pub id: String,
    pub issuer: String,
    pub name: String,
    pub order: i32,
    pub data: Vec<u8>,
}

impl fmt::Debug for EncryptedItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptedItem")
            .field("order", &self.order)
            .finish_non_exhaustive()
    }
}

pub trait VaultSource {
    fn modified(&self) -> Result<u64>;
    fn load(&self) -> Result<(StorageKeyRef, Vec<EncryptedItem>)>;
}

pub struct ProtonIdbVault {
    root: PathBuf,
}

struct Candidate {
    mtime: SystemTime,
    path: PathBuf,
}

enum Probe {
    NoMatch,
    Match(Matched),
}

struct Matched {
    image: Zeroizing<Vec<u8>>,
    records_root: u32,
    items_id: i64,
    key_id: i64,
}

/// Raw bytes of the database file and its `-wal`, read as one consistent view.
pub struct RawFiles {
    pub main: Zeroizing<Vec<u8>>,
    pub wal: Option<Zeroizing<Vec<u8>>>,
}

impl ProtonIdbVault {
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    pub fn default_root() -> Result<PathBuf> {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
            .ok_or(ErrorCode::VaultNotFound)?;
        Ok(home.join(".local/share/me.proton.authenticator/databases/indexeddb"))
    }

    fn select(&self) -> Result<(Candidate, Matched)> {
        let mut candidates: Vec<Candidate> = find_candidates(&self.root)
            .into_iter()
            .filter_map(|path| {
                let mtime = effective_mtime(&path)?;
                Some(Candidate { mtime, path })
            })
            .collect();
        candidates.sort_by_key(|c| std::cmp::Reverse(c.mtime));
        for candidate in candidates {
            match probe(&candidate.path)? {
                Probe::NoMatch => continue,
                Probe::Match(matched) => return Ok((candidate, matched)),
            }
        }
        Err(ErrorCode::VaultNotFound)
    }
}

impl VaultSource for ProtonIdbVault {
    fn modified(&self) -> Result<u64> {
        let (candidate, _) = self.select()?;
        Ok(candidate
            .mtime
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()))
    }

    fn load(&self) -> Result<(StorageKeyRef, Vec<EncryptedItem>)> {
        let (_, matched) = self.select()?;
        let key_ref = read_key_ref(&matched)?;
        let items = read_items(&matched)?;
        Ok((key_ref, items))
    }
}

fn find_candidates(root: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut visited = 0usize;
    match fs::symlink_metadata(root) {
        Ok(meta) if meta.is_dir() => {}
        _ => return found,
    }
    let mut stack = vec![(root.to_path_buf(), 0usize)];
    while let Some((dir, depth)) = stack.pop() {
        let Ok(read) = fs::read_dir(&dir) else {
            continue;
        };
        let mut entries: Vec<_> = read
            .take(MAX_DIR_ENTRIES + 1)
            .filter_map(|e| e.ok())
            .collect();
        entries.sort_by_key(|e| e.file_name());
        let mut subdirs = Vec::new();
        for entry in entries {
            visited += 1;
            if visited > MAX_DIR_ENTRIES {
                return found;
            }
            let Ok(meta) = fs::symlink_metadata(entry.path()) else {
                continue;
            };
            if meta.is_file() && entry.file_name() == DB_FILE_NAME {
                found.push(entry.path());
                if found.len() >= MAX_CANDIDATES {
                    return found;
                }
            } else if meta.is_dir() && depth < MAX_WALK_DEPTH {
                subdirs.push((entry.path(), depth + 1));
            }
        }
        stack.extend(subdirs.into_iter().rev());
    }
    found
}

fn effective_mtime(db: &Path) -> Option<SystemTime> {
    let main = fs::symlink_metadata(db).and_then(|m| m.modified()).ok()?;
    let wal = fs::symlink_metadata(wal_path(db))
        .and_then(|m| m.modified())
        .ok();
    Some(wal.map_or(main, |w| main.max(w)))
}

fn wal_path(db: &Path) -> PathBuf {
    let mut name = OsString::from(db.as_os_str());
    name.push("-wal");
    PathBuf::from(name)
}

#[derive(PartialEq, Clone, Copy)]
struct Signature {
    dev: u64,
    ino: u64,
    len: u64,
    mtime_sec: i64,
    mtime_nsec: i64,
}

impl Signature {
    fn of(meta: &fs::Metadata) -> Self {
        Self {
            dev: meta.dev(),
            ino: meta.ino(),
            len: meta.len(),
            mtime_sec: meta.mtime(),
            mtime_nsec: meta.mtime_nsec(),
        }
    }
}

enum Attempt {
    Unstable,
    Skip,
    Done(RawFiles),
}

fn open_nofollow(path: &Path) -> std::io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
}

fn signature_of_path(path: &Path) -> std::io::Result<Option<Signature>> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.is_file() => Ok(Some(Signature::of(&meta))),
        Ok(_) => Err(std::io::Error::from(std::io::ErrorKind::InvalidInput)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

fn read_exact_file(file: &File, expected: Signature) -> Result<Option<Zeroizing<Vec<u8>>>> {
    let meta = file.metadata().map_err(|_| ErrorCode::Internal)?;
    if !meta.is_file() || Signature::of(&meta) != expected {
        return Ok(None);
    }
    let len = usize::try_from(expected.len).map_err(|_| ErrorCode::VaultFormatChanged)?;
    let mut buf = Zeroizing::new(Vec::with_capacity(len));
    file.take(expected.len + 1)
        .read_to_end(&mut buf)
        .map_err(|_| ErrorCode::Internal)?;
    Ok((buf.len() == len).then_some(buf))
}

fn read_attempt(path: &Path, wal: &Path, hook: &mut dyn FnMut()) -> Result<Attempt> {
    let Ok(Some(main_before)) = signature_of_path(path) else {
        return Ok(Attempt::Skip);
    };
    let wal_before = signature_of_path(wal).map_err(|_| ErrorCode::VaultFormatChanged)?;
    if main_before.len > MAX_MAIN_BYTES || wal_before.is_some_and(|s| s.len > MAX_WAL_BYTES) {
        return Err(ErrorCode::VaultFormatChanged);
    }

    let Ok(main_file) = open_nofollow(path) else {
        return Ok(Attempt::Unstable);
    };
    let Some(main) = read_exact_file(&main_file, main_before)? else {
        return Ok(Attempt::Unstable);
    };
    let mut wal_file = None;
    let mut wal_bytes = None;
    if let Some(sig) = wal_before {
        let Ok(file) = open_nofollow(wal) else {
            return Ok(Attempt::Unstable);
        };
        let Some(bytes) = read_exact_file(&file, sig)? else {
            return Ok(Attempt::Unstable);
        };
        wal_file = Some(file);
        wal_bytes = Some(bytes);
    }

    hook();

    let main_stable = signature_of_path(path).ok().flatten() == Some(main_before)
        && main_file
            .metadata()
            .is_ok_and(|m| Signature::of(&m) == main_before);
    let wal_stable = signature_of_path(wal).ok() == Some(wal_before)
        && match (&wal_file, wal_before) {
            (Some(file), Some(sig)) => file.metadata().is_ok_and(|m| Signature::of(&m) == sig),
            _ => true,
        };
    if !(main_stable && wal_stable) {
        return Ok(Attempt::Unstable);
    }
    Ok(Attempt::Done(RawFiles {
        main,
        wal: wal_bytes,
    }))
}

/// Reads the database and its `-wal` without SQLite touching either, retrying
/// when either file changes during the read. `Ok(None)` means the path is not
/// a readable regular file. `hook` runs after the reads, before the final stat.
pub fn read_stable(path: &Path, hook: &mut dyn FnMut()) -> Result<Option<RawFiles>> {
    let wal = wal_path(path);
    for attempt in 0..=STABLE_RETRIES {
        if attempt > 0 {
            thread::sleep(STABLE_PAUSE);
        }
        match read_attempt(path, &wal, hook)? {
            Attempt::Done(files) => return Ok(Some(files)),
            Attempt::Skip => return Ok(None),
            Attempt::Unstable => {}
        }
    }
    Err(ErrorCode::VaultBusy)
}

fn probe(path: &Path) -> Result<Probe> {
    let Some(files) = read_stable(path, &mut || {})? else {
        return Ok(Probe::NoMatch);
    };
    if !wal::has_sqlite_header(&files.main) {
        return Ok(Probe::NoMatch);
    }
    let image = wal::build_image(
        &files.main,
        files.wal.as_ref().map(|w| w.as_slice()),
        MAX_IMAGE_BYTES,
    )?;
    drop(files);

    let parsed = Image::parse(&image)?;
    let Some(store_info_root) = parsed.table_root("ObjectStoreInfo")? else {
        return Ok(Probe::NoMatch);
    };
    let mut items_id = None;
    let mut key_id = None;
    parsed.scan(store_info_root, |rowid, columns| {
        let [Column::Null, Column::Text(name), ..] = columns else {
            return Err(ErrorCode::VaultFormatChanged);
        };
        match *name {
            "items" => items_id = Some(rowid),
            "storageKey" => key_id = Some(rowid),
            _ => {}
        }
        Ok(())
    })?;
    let (Some(items_id), Some(key_id)) = (items_id, key_id) else {
        return Ok(Probe::NoMatch);
    };
    let records_root = parsed
        .table_root("Records")?
        .ok_or(ErrorCode::VaultFormatChanged)?;
    Ok(Probe::Match(Matched {
        image,
        records_root,
        items_id,
        key_id,
    }))
}

fn records(matched: &Matched, store: i64, limit: usize) -> Result<Vec<Zeroizing<Vec<u8>>>> {
    records_capped(matched, store, limit, MAX_IMAGE_BYTES)
}

fn records_capped(
    matched: &Matched,
    store: i64,
    limit: usize,
    max_bytes: usize,
) -> Result<Vec<Zeroizing<Vec<u8>>>> {
    let parsed = Image::parse(&matched.image)?;
    let mut out = Vec::new();
    let mut copied = 0usize;
    parsed.scan(matched.records_root, |_, columns| {
        let [Column::Int(store_id), Column::Text(_) | Column::Blob(_), Column::Blob(value), Column::Null, ..] =
            columns
        else {
            return Err(ErrorCode::VaultFormatChanged);
        };
        if *store_id == store && out.len() < limit {
            copied = copied
                .checked_add(value.len())
                .filter(|&n| n <= max_bytes)
                .ok_or(ErrorCode::VaultFormatChanged)?;
            out.push(Zeroizing::new(value.to_vec()));
        }
        Ok(())
    })?;
    Ok(out)
}

fn string_field(record: &Value, name: &str) -> Result<String> {
    match ssv::get(record, name) {
        Some(Value::String(s)) => Ok(s.clone()),
        _ => Err(ErrorCode::VaultFormatChanged),
    }
}

fn int_field(record: &Value, name: &str) -> Result<i32> {
    match ssv::get(record, name) {
        Some(Value::Int(n)) => Ok(*n),
        _ => Err(ErrorCode::VaultFormatChanged),
    }
}

fn bytes_field(record: &Value, name: &str) -> Result<Vec<u8>> {
    match ssv::get(record, name) {
        Some(Value::Bytes(b)) => Ok(b.to_vec()),
        _ => Err(ErrorCode::VaultFormatChanged),
    }
}

fn read_key_ref(matched: &Matched) -> Result<StorageKeyRef> {
    let mut blobs = records(matched, matched.key_id, 2)?;
    if blobs.len() != 1 {
        return Err(ErrorCode::VaultFormatChanged);
    }
    let record = ssv::decode(&blobs.remove(0))?;
    let adapter_key_id = match ssv::get(&record, "adapterKeyId") {
        None | Some(Value::Undefined | Value::Null) => None,
        Some(Value::String(s)) => Some(s.clone()),
        Some(_) => return Err(ErrorCode::VaultFormatChanged),
    };
    let has_unsafe_key = !matches!(
        ssv::get(&record, "unsafe_key"),
        None | Some(Value::Undefined)
    );
    Ok(StorageKeyRef {
        id: string_field(&record, "id")?,
        adapter_key_id,
        salt: Zeroizing::new(bytes_field(&record, "salt")?),
        source: int_field(&record, "source")?,
        has_unsafe_key,
    })
}

fn read_items(matched: &Matched) -> Result<Vec<EncryptedItem>> {
    let blobs = records(matched, matched.items_id, MAX_ITEMS + 1)?;
    if blobs.len() > MAX_ITEMS {
        return Err(ErrorCode::OutputTooLarge);
    }
    blobs
        .iter()
        .map(|blob| {
            let record = ssv::decode(blob)?;
            Ok(EncryptedItem {
                id: string_field(&record, "id")?,
                issuer: string_field(&record, "issuer")?,
                name: string_field(&record, "name")?,
                order: int_field(&record, "order")?,
                data: bytes_field(&record, "__encryptedData")?,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SCHEMA: &str = "
        CREATE TABLE Records (objectStoreID INTEGER NOT NULL, key TEXT NOT NULL, value NOT NULL, recordID INTEGER PRIMARY KEY);
        CREATE TABLE ObjectStoreInfo (id INTEGER PRIMARY KEY, name TEXT NOT NULL, keyPath BLOB NOT NULL, autoInc INTEGER NOT NULL);
        INSERT INTO ObjectStoreInfo VALUES (1, 'items', x'', 0), (2, 'storageKey', x'', 0);
        INSERT INTO Records (objectStoreID, key, value) VALUES
            (1, 'a', zeroblob(800)), (1, 'b', zeroblob(800)), (2, 'k', zeroblob(10));
    ";

    #[test]
    fn copied_bytes_are_capped() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join(DB_FILE_NAME);
        rusqlite::Connection::open(&path)
            .unwrap()
            .execute_batch(SCHEMA)
            .unwrap();
        let Probe::Match(matched) = probe(&path).unwrap() else {
            panic!("fixture must match");
        };
        assert_eq!(records_capped(&matched, 1, 10, 1600).unwrap().len(), 2);
        assert_eq!(
            records_capped(&matched, 1, 10, 1599).unwrap_err(),
            ErrorCode::VaultFormatChanged
        );
        assert_eq!(records_capped(&matched, 2, 10, 10).unwrap().len(), 1);
    }
}
