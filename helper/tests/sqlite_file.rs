mod support;

use std::fs;
use std::path::Path;

use pa_helper::error::ErrorCode;
use pa_helper::sqlite_file::{Column, Image};
use pa_helper::vault::{ProtonIdbVault, VaultSource};
use pa_helper::wal::build_image;
use rusqlite::Connection;
use support::fixture::{self, db_path, shm_path, wal_path};
use tempfile::TempDir;

type RecordRow = (i64, Vec<u8>, Vec<u8>, i64);
type StoreRow = (i64, String);
type Dump = (Vec<StoreRow>, Vec<RecordRow>);

fn blob_of(seed: u64, len: usize) -> Vec<u8> {
    let mut state = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state >> 24) as u8
        })
        .collect()
}

fn ours(image: &[u8]) -> pa_helper::error::Result<Dump> {
    let parsed = Image::parse(image)?;
    let mut stores = Vec::new();
    if let Some(root) = parsed.table_root("ObjectStoreInfo")? {
        parsed.scan(root, |rowid, cols| {
            let [Column::Null, Column::Text(name), ..] = cols else {
                return Err(ErrorCode::VaultFormatChanged);
            };
            stores.push((rowid, (*name).to_string()));
            Ok(())
        })?;
    }
    let mut records = Vec::new();
    if let Some(root) = parsed.table_root("Records")? {
        parsed.scan(root, |rowid, cols| {
            let [Column::Int(store), key, Column::Blob(value), Column::Null, ..] = cols else {
                return Err(ErrorCode::VaultFormatChanged);
            };
            let key = match key {
                Column::Blob(b) => b.to_vec(),
                Column::Text(t) => t.as_bytes().to_vec(),
                _ => return Err(ErrorCode::VaultFormatChanged),
            };
            records.push((*store, key, value.to_vec(), rowid));
            Ok(())
        })?;
    }
    Ok((stores, records))
}

fn oracle(conn: &Connection) -> Dump {
    let mut stmt = conn
        .prepare("SELECT id, name FROM ObjectStoreInfo ORDER BY id")
        .unwrap();
    let stores = stmt
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    let mut stmt = conn
        .prepare("SELECT objectStoreID, key, value, recordID FROM Records ORDER BY recordID")
        .unwrap();
    let records = stmt
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    (stores, records)
}

fn assert_file_matches_sqlite(path: &Path) {
    let bytes = fs::read(path).unwrap();
    let expected = oracle(&fixture::open(path));
    let actual = ours(&bytes).unwrap();
    assert_eq!(actual.0, expected.0);
    assert_eq!(actual.1.len(), expected.1.len());
    assert!(actual.1 == expected.1, "record mismatch");
    assert_eq!(fs::read(path).unwrap(), bytes);
}

fn fresh_db(dir: &Path, page_size: u32) -> Connection {
    fs::create_dir_all(dir).unwrap();
    let conn = fixture::open(&db_path(dir));
    conn.pragma_update(None, "page_size", page_size).unwrap();
    fixture::create_schema(&conn, &["items", "storageKey", "other"]);
    conn
}

#[test]
fn page_sizes_512_4096_65536() {
    for page_size in [512u32, 4096, 65536] {
        let tmp = TempDir::new().unwrap();
        let conn = fresh_db(tmp.path(), page_size);
        for i in 0..80u64 {
            let store = ["items", "storageKey", "other"][(i % 3) as usize];
            fixture::insert_raw(
                &conn,
                store,
                format!("k{i}").as_bytes(),
                &blob_of(i, 30 + (i as usize * 7) % 300),
            );
        }
        drop(conn);
        let bytes = fs::read(db_path(tmp.path())).unwrap();
        assert_eq!(bytes.len() % page_size as usize, 0);
        assert_file_matches_sqlite(&db_path(tmp.path()));
    }
}

#[test]
fn overflow_chains_and_interior_pages() {
    for page_size in [512u32, 4096] {
        let tmp = TempDir::new().unwrap();
        let conn = fresh_db(tmp.path(), page_size);
        for i in 0..2000u64 {
            fixture::insert_raw(&conn, "items", format!("k{i}").as_bytes(), &blob_of(i, 24));
        }
        fixture::insert_raw(&conn, "items", b"big-10k", &blob_of(7, 10 * 1024));
        fixture::insert_raw(&conn, "storageKey", b"big-200k", &blob_of(9, 200 * 1024));
        fixture::insert_raw(
            &conn,
            "other",
            b"edge",
            &blob_of(11, page_size as usize - 60),
        );
        drop(conn);
        assert_file_matches_sqlite(&db_path(tmp.path()));
        let (_, records) = ours(&fs::read(db_path(tmp.path())).unwrap()).unwrap();
        assert_eq!(records.len(), 2003);
        assert!(records.iter().any(|r| r.2.len() == 200 * 1024));
    }
}

#[test]
fn deletes_and_vacuum() {
    let tmp = TempDir::new().unwrap();
    let conn = fresh_db(tmp.path(), 1024);
    for i in 0..400u64 {
        fixture::insert_raw(
            &conn,
            "items",
            format!("k{i}").as_bytes(),
            &blob_of(i, 3000),
        );
    }
    conn.execute("DELETE FROM Records WHERE recordID % 10 != 0", [])
        .unwrap();
    drop(conn);
    assert_file_matches_sqlite(&db_path(tmp.path()));

    let conn = fixture::open(&db_path(tmp.path()));
    conn.execute_batch("VACUUM").unwrap();
    drop(conn);
    assert_file_matches_sqlite(&db_path(tmp.path()));
}

#[test]
fn wal_commit_that_shrinks_the_db() {
    let tmp = TempDir::new().unwrap();
    {
        let conn = fresh_db(tmp.path(), 1024);
        conn.set_db_config(
            rusqlite::config::DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE,
            true,
        )
        .unwrap();
        conn.pragma_update(None, "journal_mode", "wal").unwrap();
        conn.pragma_update(None, "wal_autocheckpoint", 0).unwrap();
        for i in 0..300u64 {
            fixture::insert_raw(
                &conn,
                "items",
                format!("k{i}").as_bytes(),
                &blob_of(i, 2000),
            );
        }
        conn.query_row("PRAGMA wal_checkpoint(PASSIVE)", [], |_| Ok(()))
            .unwrap();
        conn.execute("DELETE FROM Records WHERE recordID % 20 != 0", [])
            .unwrap();
        conn.execute_batch("VACUUM").unwrap();
    }
    let _ = fs::remove_file(shm_path(tmp.path()));
    let main = fs::read(db_path(tmp.path())).unwrap();
    let wal = fs::read(wal_path(tmp.path())).unwrap();
    let image = build_image(&main, Some(&wal), 8 * 1024 * 1024).unwrap();
    assert!(image.len() < main.len(), "commit must shrink the database");

    let copy = TempDir::new().unwrap();
    fixture::copy_db_files(tmp.path(), copy.path());
    let expected = oracle(&fixture::open(&db_path(copy.path())));
    let actual = ours(&image).unwrap();
    assert_eq!(actual.0, expected.0);
    assert!(actual.1 == expected.1);
    assert_eq!(actual.1.len(), 15);
}

#[test]
fn view_named_records_is_format_changed() {
    let tmp = TempDir::new().unwrap();
    fixture::write_vault_records_as_view(tmp.path(), &simple_key_ref(), &[]);
    assert_eq!(
        ProtonIdbVault::new(tmp.path().to_path_buf())
            .load()
            .unwrap_err(),
        ErrorCode::VaultFormatChanged
    );
}

fn simple_key_ref() -> pa_helper::ssv::Value {
    use pa_helper::ssv::Value;
    Value::Object(vec![
        ("id".into(), Value::String("k".into())),
        (
            "salt".into(),
            Value::Bytes(zeroize::Zeroizing::new(vec![1; 32])),
        ),
        ("source".into(), Value::Int(0)),
    ])
}

#[test]
fn utf16_database_is_format_changed() {
    let tmp = TempDir::new().unwrap();
    let conn = fixture::open(&db_path(tmp.path()));
    conn.pragma_update(None, "encoding", "UTF-16le").unwrap();
    fixture::create_schema(&conn, &["items", "storageKey"]);
    drop(conn);
    assert_eq!(
        ProtonIdbVault::new(tmp.path().to_path_buf())
            .load()
            .unwrap_err(),
        ErrorCode::VaultFormatChanged
    );
}

fn multi_page_image() -> Vec<u8> {
    let tmp = TempDir::new().unwrap();
    let conn = fresh_db(tmp.path(), 512);
    for i in 0..300u64 {
        let store = ["items", "storageKey"][(i % 2) as usize];
        fixture::insert_raw(&conn, store, format!("k{i}").as_bytes(), &blob_of(i, 20));
    }
    fixture::insert_raw(&conn, "items", b"big", &blob_of(1, 3000));
    fixture::insert_raw(&conn, "other", b"big2", &blob_of(2, 1300));
    drop(conn);
    fs::read(db_path(tmp.path())).unwrap()
}

fn check_no_panic(image: &[u8]) {
    match ours(image) {
        Ok(_) | Err(ErrorCode::VaultFormatChanged) => {}
        Err(other) => panic!("unexpected error {other}"),
    }
}

#[test]
fn every_truncation_is_ok_or_format_changed() {
    let image = multi_page_image();
    assert!(image.len() > 40 * 512);
    for len in 0..=image.len() {
        check_no_panic(&image[..len]);
    }
}

#[test]
fn ten_thousand_mutations_never_panic() {
    let mut image = multi_page_image();
    let mut state = 0x2545_F491_4F6C_DD1Du64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for _ in 0..10_000 {
        let edits = 1 + (next() % 4) as usize;
        let mut saved = Vec::new();
        for _ in 0..edits {
            let at = if next() % 2 == 0 {
                (next() as usize) % image.len()
            } else {
                ((next() as usize) % (image.len() / 512)) * 512 + (next() as usize) % 24
            };
            saved.push((at, image[at]));
            image[at] = next() as u8;
        }
        check_no_panic(&image);
        for (at, byte) in saved.into_iter().rev() {
            image[at] = byte;
        }
    }
    assert!(ours(&image).is_ok());
}

#[test]
fn fragmented_pages_after_random_updates_and_deletes() {
    for page_size in [512u32, 4096] {
        let tmp = TempDir::new().unwrap();
        let conn = fresh_db(tmp.path(), page_size);
        let mut state = 0x9E37_79B9u64 + u64::from(page_size);
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for i in 0..600u64 {
            let len = (next() % 900) as usize;
            fixture::insert_raw(&conn, "items", format!("k{i}").as_bytes(), &blob_of(i, len));
            match next() % 4 {
                0 => {
                    conn.execute(
                        "DELETE FROM Records WHERE recordID = ?1",
                        [1 + (next() % (i + 1)) as i64],
                    )
                    .unwrap();
                }
                1 => {
                    conn.execute(
                        "UPDATE Records SET value = ?1 WHERE recordID = ?2",
                        rusqlite::params![
                            blob_of(next(), (next() % 1500) as usize),
                            1 + (next() % (i + 1)) as i64
                        ],
                    )
                    .unwrap();
                }
                _ => {}
            }
        }
        drop(conn);
        assert_file_matches_sqlite(&db_path(tmp.path()));
    }
}
