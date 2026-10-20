#![allow(dead_code)]

use std::path::{Path, PathBuf};

use pa_helper::ssv::Value;
use rusqlite::{params, Connection};

use super::ssv_writer::encode;

pub const DB_NAME: &str = "IndexedDB.sqlite3";

const SCHEMA: &str = "
CREATE TABLE Records (objectStoreID INTEGER NOT NULL ON CONFLICT FAIL, key TEXT COLLATE IDBKEY NOT NULL ON CONFLICT FAIL, value NOT NULL ON CONFLICT FAIL, recordID INTEGER PRIMARY KEY);
CREATE UNIQUE INDEX RecordsIndex ON Records (objectStoreID, key);
CREATE TABLE ObjectStoreInfo (id INTEGER PRIMARY KEY NOT NULL ON CONFLICT FAIL UNIQUE ON CONFLICT FAIL, name TEXT NOT NULL ON CONFLICT FAIL UNIQUE ON CONFLICT FAIL, keyPath BLOB NOT NULL ON CONFLICT FAIL, autoInc INTEGER NOT NULL ON CONFLICT FAIL);
";

pub fn db_path(dir: &Path) -> PathBuf {
    dir.join(DB_NAME)
}

pub fn open(path: &Path) -> Connection {
    let conn = Connection::open(path).unwrap();
    conn.create_collation("IDBKEY", |a, b| a.as_bytes().cmp(b.as_bytes()))
        .unwrap();
    conn
}

pub fn create_schema(conn: &Connection, stores: &[&str]) {
    conn.execute_batch(SCHEMA).unwrap();
    for (i, name) in stores.iter().enumerate() {
        conn.execute(
            "INSERT INTO ObjectStoreInfo (id, name, keyPath, autoInc) VALUES (?1, ?2, x'', 0)",
            params![i as i64 + 1, name],
        )
        .unwrap();
    }
}

pub fn insert_record(conn: &Connection, store: &str, key: &[u8], value: &Value) {
    conn.execute(
        "INSERT INTO Records (objectStoreID, key, value)
         VALUES ((SELECT id FROM ObjectStoreInfo WHERE name = ?1), ?2, ?3)",
        params![store, key, encode(value)],
    )
    .unwrap();
}

fn populate(conn: &Connection, key_ref: &Value, items: &[Value]) {
    create_schema(conn, &["items", "storageKey"]);
    insert_record(conn, "storageKey", b"storageKey", key_ref);
    for (i, item) in items.iter().enumerate() {
        insert_record(conn, "items", format!("item-{i}").as_bytes(), item);
    }
}

pub fn write_vault(dir: &Path, key_ref: &Value, items: &[Value]) {
    std::fs::create_dir_all(dir).unwrap();
    let conn = open(&db_path(dir));
    populate(&conn, key_ref, items);
}

/// Returns the writer connection: closing the last connection checkpoints
/// and removes the -wal file, so the caller must keep it alive.
pub fn write_vault_wal(dir: &Path, key_ref: &Value, items: &[Value]) -> Connection {
    std::fs::create_dir_all(dir).unwrap();
    let conn = open(&db_path(dir));
    conn.pragma_update(None, "journal_mode", "wal").unwrap();
    conn.pragma_update(None, "wal_autocheckpoint", 0).unwrap();
    populate(&conn, key_ref, items);
    conn
}

pub fn write_decoy(dir: &Path) {
    std::fs::create_dir_all(dir).unwrap();
    let conn = open(&db_path(dir));
    create_schema(&conn, &["mutexes"]);
}

/// Leaves un-checkpointed frames in `-wal` after the last connection closes.
pub fn write_vault_wal_closed(dir: &Path, key_ref: &Value, items: &[Value]) {
    use rusqlite::config::DbConfig;
    std::fs::create_dir_all(dir).unwrap();
    let conn = open(&db_path(dir));
    conn.set_db_config(DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, true)
        .unwrap();
    conn.pragma_update(None, "journal_mode", "wal").unwrap();
    conn.pragma_update(None, "wal_autocheckpoint", 0).unwrap();
    populate(&conn, key_ref, items);
}

pub fn write_vault_records_as_view(dir: &Path, key_ref: &Value, items: &[Value]) {
    std::fs::create_dir_all(dir).unwrap();
    let conn = open(&db_path(dir));
    populate(&conn, key_ref, items);
    conn.execute_batch(
        "ALTER TABLE Records RENAME TO RealRecords;
         CREATE VIEW Records AS SELECT * FROM RealRecords;",
    )
    .unwrap();
}

pub fn wal_path(dir: &Path) -> PathBuf {
    dir.join(format!("{DB_NAME}-wal"))
}

pub fn shm_path(dir: &Path) -> PathBuf {
    dir.join(format!("{DB_NAME}-shm"))
}

/// Cleanly closed WAL database: the last connection checkpoints and removes the sidecars.
pub fn write_vault_wal_clean(dir: &Path, key_ref: &Value, items: &[Value]) {
    std::fs::create_dir_all(dir).unwrap();
    let conn = open(&db_path(dir));
    conn.pragma_update(None, "journal_mode", "wal").unwrap();
    populate(&conn, key_ref, items);
}

/// Many transactions, a full checkpoint, then a few more: the WAL restarts
/// with new salts and keeps stale frames from the first round behind the new ones.
pub fn write_vault_wal_restarted(dir: &Path, key_ref: &Value, first: &[Value], second: &[Value]) {
    use rusqlite::config::DbConfig;
    std::fs::create_dir_all(dir).unwrap();
    let conn = open(&db_path(dir));
    conn.set_db_config(DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, true)
        .unwrap();
    conn.pragma_update(None, "journal_mode", "wal").unwrap();
    conn.pragma_update(None, "wal_autocheckpoint", 0).unwrap();
    populate(&conn, key_ref, first);
    conn.query_row("PRAGMA wal_checkpoint(PASSIVE)", [], |_| Ok(()))
        .unwrap();
    for (i, item) in second.iter().enumerate() {
        insert_record(&conn, "items", format!("later-{i}").as_bytes(), item);
    }
}

pub fn copy_db_files(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    std::fs::copy(db_path(from), db_path(to)).unwrap();
    if wal_path(from).exists() {
        std::fs::copy(wal_path(from), wal_path(to)).unwrap();
    }
}

/// What SQLite itself reads from a copy of the main file and `-wal`.
pub fn sqlite_records(dir: &Path) -> Vec<(i64, Vec<u8>)> {
    let conn = open(&db_path(dir));
    let mut stmt = conn
        .prepare("SELECT objectStoreID, value FROM Records ORDER BY recordID")
        .unwrap();
    stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .map(|r| r.unwrap())
        .collect()
}

pub fn insert_raw(conn: &Connection, store: &str, key: &[u8], value: &[u8]) {
    conn.execute(
        "INSERT INTO Records (objectStoreID, key, value)
         VALUES ((SELECT id FROM ObjectStoreInfo WHERE name = ?1), ?2, ?3)",
        params![store, key, value],
    )
    .unwrap();
}
