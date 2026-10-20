use std::cmp::Ordering;
use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rusqlite::backup::{Backup, StepResult};
use rusqlite::{Connection, OpenFlags, OptionalExtension};
use zeroize::Zeroizing;

use crate::error::{ErrorCode, Result};
use crate::ssv::{self, Value};

const DB_FILE_NAME: &str = "IndexedDB.sqlite3";
const MAX_WALK_DEPTH: usize = 6;
const MAX_CANDIDATES: usize = 32;
const MAX_DIR_ENTRIES: usize = 10_000;
const MAX_ITEMS: usize = 1000;
const BUSY_RETRIES: usize = 3;
const BUSY_PAUSE: Duration = Duration::from_millis(100);

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

struct Selected {
    path: PathBuf,
    snapshot: Connection,
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

    fn select(&self) -> Result<Selected> {
        let mut best: Option<(SystemTime, Selected)> = None;
        let mut saw_busy = false;
        for path in find_candidates(&self.root) {
            let snapshot = match snapshot_with_retry(&path) {
                Ok(conn) => conn,
                Err(SnapshotError::Busy) => {
                    saw_busy = true;
                    continue;
                }
                Err(SnapshotError::Other) => continue,
            };
            if !has_required_stores(&snapshot) {
                continue;
            }
            let Some(mtime) = effective_mtime(&path) else {
                continue;
            };
            if best.as_ref().is_none_or(|(t, _)| mtime > *t) {
                best = Some((mtime, Selected { path, snapshot }));
            }
        }
        match best {
            Some((_, selected)) => Ok(selected),
            None if saw_busy => Err(ErrorCode::VaultBusy),
            None => Err(ErrorCode::VaultNotFound),
        }
    }
}

impl VaultSource for ProtonIdbVault {
    fn modified(&self) -> Result<u64> {
        let selected = self.select()?;
        let mtime = effective_mtime(&selected.path).ok_or(ErrorCode::VaultNotFound)?;
        Ok(mtime.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs()))
    }

    fn load(&self) -> Result<(StorageKeyRef, Vec<EncryptedItem>)> {
        let selected = self.select()?;
        let conn = &selected.snapshot;
        let key_ref = read_key_ref(conn)?;
        let items = read_items(conn)?;
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
        let mut entries: Vec<_> = read.filter_map(|e| e.ok()).collect();
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
    let mut wal_name = OsString::from(db.as_os_str());
    wal_name.push("-wal");
    let wal = fs::symlink_metadata(PathBuf::from(wal_name))
        .and_then(|m| m.modified())
        .ok();
    Some(wal.map_or(main, |w| main.max(w)))
}

enum SnapshotError {
    Busy,
    Other,
}

fn is_busy(err: &rusqlite::Error) -> bool {
    matches!(
        err,
        rusqlite::Error::SqliteFailure(e, _)
            if matches!(
                e.code,
                rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked
            )
    )
}

fn register_collation(conn: &Connection) -> rusqlite::Result<()> {
    conn.create_collation("IDBKEY", |a, b| -> Ordering {
        a.as_bytes().cmp(b.as_bytes())
    })
}

fn snapshot_once(path: &Path) -> rusqlite::Result<Option<Connection>> {
    let source = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
    )?;
    source.busy_timeout(Duration::ZERO)?;
    register_collation(&source)?;
    let mut memory = Connection::open_in_memory()?;
    register_collation(&memory)?;
    let backup = Backup::new(&source, &mut memory)?;
    match backup.step(-1)? {
        StepResult::Done => {}
        StepResult::Busy | StepResult::Locked => return Ok(None),
        _ => return Err(rusqlite::Error::InvalidQuery),
    }
    drop(backup);
    Ok(Some(memory))
}

fn snapshot_with_retry(path: &Path) -> std::result::Result<Connection, SnapshotError> {
    for attempt in 0..=BUSY_RETRIES {
        if attempt > 0 {
            thread::sleep(BUSY_PAUSE);
        }
        match snapshot_once(path) {
            Ok(Some(conn)) => return Ok(conn),
            Ok(None) => {}
            Err(e) if is_busy(&e) => {}
            Err(_) => return Err(SnapshotError::Other),
        }
    }
    Err(SnapshotError::Busy)
}

fn store_id(conn: &Connection, name: &str) -> rusqlite::Result<Option<i64>> {
    conn.query_row(
        "SELECT id FROM ObjectStoreInfo WHERE name = ?1",
        [name],
        |row| row.get(0),
    )
    .optional()
}

fn has_required_stores(conn: &Connection) -> bool {
    matches!(store_id(conn, "items"), Ok(Some(_)))
        && matches!(store_id(conn, "storageKey"), Ok(Some(_)))
}

fn records(conn: &Connection, store: &str, limit: usize) -> Result<Vec<Vec<u8>>> {
    let id = store_id(conn, store)
        .map_err(|_| ErrorCode::VaultFormatChanged)?
        .ok_or(ErrorCode::VaultFormatChanged)?;
    let mut stmt = conn
        .prepare("SELECT value FROM Records WHERE objectStoreID = ?1 ORDER BY recordID LIMIT ?2")
        .map_err(|_| ErrorCode::VaultFormatChanged)?;
    let rows = stmt
        .query_map(rusqlite::params![id, limit as i64], |row| {
            row.get::<_, Vec<u8>>(0)
        })
        .map_err(|_| ErrorCode::VaultFormatChanged)?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|_| ErrorCode::VaultFormatChanged)
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

fn read_key_ref(conn: &Connection) -> Result<StorageKeyRef> {
    let mut blobs = records(conn, "storageKey", 2)?;
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

fn read_items(conn: &Connection) -> Result<Vec<EncryptedItem>> {
    let blobs = records(conn, "items", MAX_ITEMS + 1)?;
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
