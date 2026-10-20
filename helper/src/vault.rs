use std::cmp::Ordering;
use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rusqlite::backup::{Backup, StepResult};
use rusqlite::config::DbConfig;
use rusqlite::limits::Limit;
use rusqlite::{Connection, OpenFlags, OptionalExtension};
use zeroize::Zeroizing;

use crate::error::{ErrorCode, Result};
use crate::ssv::{self, Value};

const DB_FILE_NAME: &str = "IndexedDB.sqlite3";
const MAX_WALK_DEPTH: usize = 6;
const MAX_CANDIDATES: usize = 32;
const MAX_DIR_ENTRIES: usize = 10_000;
const MAX_ITEMS: usize = 1000;
const MAX_DB_BYTES: u64 = 16 * 1024 * 1024;
const SOURCE_CACHE_KIB: i64 = 256;
const LIMIT_LENGTH_BYTES: i32 = 1024 * 1024;
const LIMIT_SQL_LENGTH_BYTES: i32 = 4096;
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

struct Candidate {
    mtime: SystemTime,
    path: PathBuf,
}

enum Probe {
    NoMatch,
    Match(Option<Connection>),
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

    fn select(&self, want_snapshot: bool) -> Result<(Candidate, Option<Connection>)> {
        let mut candidates: Vec<Candidate> = find_candidates(&self.root)
            .into_iter()
            .filter_map(|path| {
                let mtime = effective_mtime(&path)?;
                Some(Candidate { mtime, path })
            })
            .collect();
        candidates.sort_by_key(|c| std::cmp::Reverse(c.mtime));
        for candidate in candidates {
            match probe_with_retry(&candidate.path, want_snapshot)? {
                Probe::NoMatch => continue,
                Probe::Match(snapshot) => return Ok((candidate, snapshot)),
            }
        }
        Err(ErrorCode::VaultNotFound)
    }
}

impl VaultSource for ProtonIdbVault {
    fn modified(&self) -> Result<u64> {
        let (candidate, _) = self.select(false)?;
        Ok(candidate
            .mtime
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()))
    }

    fn load(&self) -> Result<(StorageKeyRef, Vec<EncryptedItem>)> {
        let (_, snapshot) = self.select(true)?;
        let conn = snapshot.ok_or(ErrorCode::Internal)?;
        let key_ref = read_key_ref(&conn)?;
        let items = read_items(&conn)?;
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

fn is_corrupt(err: &rusqlite::Error) -> bool {
    matches!(
        err,
        rusqlite::Error::SqliteFailure(e, _) if e.code == rusqlite::ErrorCode::DatabaseCorrupt
    )
}

fn is_cant_open(err: &rusqlite::Error) -> bool {
    matches!(
        err,
        rusqlite::Error::SqliteFailure(e, _) if e.code == rusqlite::ErrorCode::CannotOpen
    )
}

fn register_collation(conn: &Connection) -> rusqlite::Result<()> {
    conn.create_collation("IDBKEY", |a, b| -> Ordering {
        a.as_bytes().cmp(b.as_bytes())
    })
}

fn wal_path(db: &Path) -> PathBuf {
    let mut name = OsString::from(db.as_os_str());
    name.push("-wal");
    PathBuf::from(name)
}

fn percent_encode_path(path: &Path) -> String {
    let mut out = String::new();
    for &b in path.as_os_str().as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'/' | b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Applies SQLite's guidance for untrusted database files before any query.
pub fn harden(conn: &Connection) -> rusqlite::Result<()> {
    conn.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)?;
    conn.set_db_config(DbConfig::SQLITE_DBCONFIG_TRUSTED_SCHEMA, false)?;
    conn.set_db_config(DbConfig::SQLITE_DBCONFIG_ENABLE_TRIGGER, false)?;
    conn.set_db_config(DbConfig::SQLITE_DBCONFIG_ENABLE_VIEW, false)?;
    conn.set_limit(Limit::SQLITE_LIMIT_LENGTH, LIMIT_LENGTH_BYTES)?;
    conn.set_limit(Limit::SQLITE_LIMIT_SQL_LENGTH, LIMIT_SQL_LENGTH_BYTES)?;
    conn.set_limit(Limit::SQLITE_LIMIT_ATTACHED, 0)?;
    conn.pragma_update(None, "cell_size_check", true)?;
    conn.pragma_update(None, "mmap_size", 0)?;
    register_collation(conn)
}

// readonly_shm keeps SQLite from creating or writing the -shm file of a WAL
// database; without a live -shm the open fails instead of touching the dir.
pub fn open_source(path: &Path) -> rusqlite::Result<Connection> {
    let absolute =
        std::path::absolute(path).map_err(|_| rusqlite::Error::InvalidPath(path.into()))?;
    let uri = format!(
        "file:{}?mode=ro&readonly_shm=1",
        percent_encode_path(&absolute)
    );
    let conn = Connection::open_with_flags(
        uri,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_URI
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    conn.busy_timeout(Duration::ZERO)?;
    harden(&conn)?;
    conn.pragma_update(None, "cache_size", -SOURCE_CACHE_KIB)?;
    Ok(conn)
}

pub fn open_memory() -> rusqlite::Result<Connection> {
    let conn = Connection::open_in_memory()?;
    harden(&conn)?;
    conn.pragma_update(None, "temp_store", "MEMORY")?;
    Ok(conn)
}

fn probe_once(path: &Path, want_snapshot: bool) -> Result<Option<Probe>> {
    let source = match open_source(path) {
        Ok(conn) => conn,
        Err(e) if is_busy(&e) => return Ok(None),
        Err(e) if is_cant_open(&e) && wal_path(path).exists() => return Err(ErrorCode::VaultBusy),
        Err(_) => return Ok(Some(Probe::NoMatch)),
    };
    match has_required_stores(&source) {
        Ok(true) => {}
        Ok(false) => return Ok(Some(Probe::NoMatch)),
        Err(e) if is_corrupt(&e) => return Err(ErrorCode::VaultFormatChanged),
        Err(e) if is_busy(&e) => return Ok(None),
        Err(e) if is_cant_open(&e) && wal_path(path).exists() => return Err(ErrorCode::VaultBusy),
        Err(_) => return Ok(Some(Probe::NoMatch)),
    }
    match is_table(&source, "Records") {
        Ok(true) => {}
        Ok(false) => return Err(ErrorCode::VaultFormatChanged),
        Err(e) if is_busy(&e) => return Ok(None),
        Err(_) => return Err(ErrorCode::VaultFormatChanged),
    }
    let size = fs::symlink_metadata(path)
        .map_err(|_| ErrorCode::VaultNotFound)?
        .len();
    if size > MAX_DB_BYTES {
        return Err(ErrorCode::VaultFormatChanged);
    }
    if !want_snapshot {
        return Ok(Some(Probe::Match(None)));
    }
    match snapshot(&source) {
        Ok(Some(memory)) => Ok(Some(Probe::Match(Some(memory)))),
        Ok(None) => Ok(None),
        Err(e) if is_busy(&e) => Ok(None),
        Err(e) if is_cant_open(&e) && wal_path(path).exists() => Err(ErrorCode::VaultBusy),
        Err(_) => Err(ErrorCode::VaultFormatChanged),
    }
}

fn snapshot(source: &Connection) -> rusqlite::Result<Option<Connection>> {
    let mut memory = open_memory()?;
    let backup = Backup::new(source, &mut memory)?;
    match backup.step(-1)? {
        StepResult::Done => {}
        StepResult::Busy | StepResult::Locked => return Ok(None),
        _ => return Err(rusqlite::Error::InvalidQuery),
    }
    drop(backup);
    if !quick_check_ok(&memory)? {
        return Err(rusqlite::Error::InvalidQuery);
    }
    Ok(Some(memory))
}

fn probe_with_retry(path: &Path, want_snapshot: bool) -> Result<Probe> {
    for attempt in 0..=BUSY_RETRIES {
        if attempt > 0 {
            thread::sleep(BUSY_PAUSE);
        }
        if let Some(probe) = probe_once(path, want_snapshot)? {
            return Ok(probe);
        }
    }
    Err(ErrorCode::VaultBusy)
}

fn quick_check_ok(conn: &Connection) -> rusqlite::Result<bool> {
    let mut stmt = conn.prepare("PRAGMA quick_check")?;
    let rows = stmt
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows == ["ok"])
}

fn is_table(conn: &Connection, name: &str) -> rusqlite::Result<bool> {
    let kind: Option<String> = conn
        .query_row(
            "SELECT type FROM sqlite_schema WHERE name = ?1",
            [name],
            |row| row.get(0),
        )
        .optional()?;
    Ok(kind.as_deref() == Some("table"))
}

fn store_id(conn: &Connection, name: &str) -> rusqlite::Result<Option<i64>> {
    conn.query_row(
        "SELECT id FROM ObjectStoreInfo WHERE name = ?1",
        [name],
        |row| row.get(0),
    )
    .optional()
}

fn has_required_stores(conn: &Connection) -> rusqlite::Result<bool> {
    if !is_table(conn, "ObjectStoreInfo")? {
        return Ok(false);
    }
    Ok(store_id(conn, "items")?.is_some() && store_id(conn, "storageKey")?.is_some())
}

fn records(conn: &Connection, store: &str, limit: usize) -> Result<Vec<Zeroizing<Vec<u8>>>> {
    let id = store_id(conn, store)
        .map_err(|_| ErrorCode::VaultFormatChanged)?
        .ok_or(ErrorCode::VaultFormatChanged)?;
    let mut stmt = conn
        .prepare("SELECT value FROM Records WHERE objectStoreID = ?1 ORDER BY recordID LIMIT ?2")
        .map_err(|_| ErrorCode::VaultFormatChanged)?;
    let rows = stmt
        .query_map(rusqlite::params![id, limit as i64], |row| {
            row.get::<_, Vec<u8>>(0).map(Zeroizing::new)
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
