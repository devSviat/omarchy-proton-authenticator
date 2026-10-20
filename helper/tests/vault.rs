mod support;

use std::fs::{self, File};
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use pa_helper::error::ErrorCode;
use pa_helper::ssv::Value;
use pa_helper::vault::{ProtonIdbVault, VaultSource};
use support::fixture::{self, db_path, write_decoy, write_vault, write_vault_wal};
use tempfile::TempDir;
use zeroize::Zeroizing;

fn bytes(b: &[u8]) -> Value {
    Value::Bytes(Zeroizing::new(b.to_vec()))
}

fn s(v: &str) -> Value {
    Value::String(v.to_string())
}

fn obj(props: Vec<(&str, Value)>) -> Value {
    Value::Object(props.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}

fn key_ref() -> Value {
    obj(vec![
        ("id", s("key-1")),
        ("adapterKeyId", s("adapter-1")),
        ("salt", bytes(&[7; 32])),
        ("source", Value::Int(0)),
    ])
}

fn item(n: i32) -> Value {
    obj(vec![
        ("id", s(&format!("item-{n}"))),
        ("issuer", s("GitHub")),
        ("name", s("me@example.com")),
        ("order", Value::Int(n)),
        ("__encryptedData", bytes(&[n as u8; 40])),
    ])
}

fn vault(root: &Path) -> ProtonIdbVault {
    ProtonIdbVault::new(root.to_path_buf())
}

fn listing(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

fn unix_secs(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH).unwrap().as_secs()
}

fn set_mtime(path: &Path, secs: u64) {
    File::options()
        .write(true)
        .open(path)
        .unwrap()
        .set_modified(UNIX_EPOCH + Duration::from_secs(secs))
        .unwrap();
}

#[test]
fn loads_key_ref_and_items() {
    let tmp = TempDir::new().unwrap();
    write_vault(tmp.path(), &key_ref(), &[item(1), item(2)]);

    let (key, mut items) = vault(tmp.path()).load().unwrap();
    assert_eq!(key.id, "key-1");
    assert_eq!(key.adapter_key_id.as_deref(), Some("adapter-1"));
    assert_eq!(key.salt.as_slice(), &[7; 32]);
    assert_eq!(key.source, 0);
    assert!(!key.has_unsafe_key);

    items.sort_by_key(|i| i.order);
    assert_eq!(items.len(), 2);
    assert_eq!(items[0].id, "item-1");
    assert_eq!(items[0].issuer, "GitHub");
    assert_eq!(items[0].name, "me@example.com");
    assert_eq!(items[0].order, 1);
    assert_eq!(items[0].data, vec![1; 40]);
}

#[test]
fn adapter_key_id_is_optional() {
    let tmp = TempDir::new().unwrap();
    let legacy = obj(vec![
        ("id", s("key-1")),
        ("salt", bytes(&[7; 32])),
        ("source", Value::Int(0)),
    ]);
    write_vault(tmp.path(), &legacy, &[]);
    let (key, items) = vault(tmp.path()).load().unwrap();
    assert_eq!(key.adapter_key_id, None);
    assert!(items.is_empty());
}

#[test]
fn unsafe_key_is_flagged_but_never_exposed() {
    let tmp = TempDir::new().unwrap();
    let with_unsafe = obj(vec![
        ("id", s("key-1")),
        ("salt", bytes(&[7; 32])),
        ("source", Value::Int(2)),
        ("unsafe_key", bytes(&[9; 32])),
    ]);
    write_vault(tmp.path(), &with_unsafe, &[]);
    let (key, _) = vault(tmp.path()).load().unwrap();
    assert!(key.has_unsafe_key);
    assert!(!format!("{key:?}").contains('9'));
}

#[test]
fn undefined_unsafe_key_is_not_flagged() {
    let tmp = TempDir::new().unwrap();
    let k = obj(vec![
        ("id", s("key-1")),
        ("salt", bytes(&[7; 32])),
        ("source", Value::Int(0)),
        ("unsafe_key", Value::Undefined),
    ]);
    write_vault(tmp.path(), &k, &[]);
    assert!(!vault(tmp.path()).load().unwrap().0.has_unsafe_key);
}

#[test]
fn picks_db_with_both_stores() {
    let tmp = TempDir::new().unwrap();
    write_decoy(&tmp.path().join("a"));
    write_vault(&tmp.path().join("b"), &key_ref(), &[item(1)]);

    let (key, items) = vault(tmp.path()).load().unwrap();
    assert_eq!(key.id, "key-1");
    assert_eq!(items.len(), 1);
}

#[test]
fn newest_matching_db_wins() {
    let tmp = TempDir::new().unwrap();
    let other = obj(vec![
        ("id", s("key-new")),
        ("salt", bytes(&[7; 32])),
        ("source", Value::Int(0)),
    ]);
    write_vault(&tmp.path().join("old"), &key_ref(), &[]);
    write_vault(&tmp.path().join("new"), &other, &[]);
    set_mtime(&db_path(&tmp.path().join("old")), 1_000_000);
    set_mtime(&db_path(&tmp.path().join("new")), 2_000_000);

    assert_eq!(vault(tmp.path()).load().unwrap().0.id, "key-new");
    assert_eq!(vault(tmp.path()).modified().unwrap(), 2_000_000);
}

#[test]
fn missing_root_is_vault_not_found() {
    let tmp = TempDir::new().unwrap();
    let err = vault(&tmp.path().join("nope")).load().unwrap_err();
    assert_eq!(err, ErrorCode::VaultNotFound);
    assert_eq!(
        vault(&tmp.path().join("nope")).modified().unwrap_err(),
        ErrorCode::VaultNotFound
    );
}

#[test]
fn only_decoy_is_vault_not_found() {
    let tmp = TempDir::new().unwrap();
    write_decoy(tmp.path());
    assert_eq!(
        vault(tmp.path()).load().unwrap_err(),
        ErrorCode::VaultNotFound
    );
}

#[test]
fn non_sqlite_file_is_skipped() {
    let tmp = TempDir::new().unwrap();
    fs::create_dir(tmp.path().join("junk")).unwrap();
    fs::write(db_path(&tmp.path().join("junk")), b"not a database at all").unwrap();
    write_vault(&tmp.path().join("real"), &key_ref(), &[]);
    assert_eq!(vault(tmp.path()).load().unwrap().0.id, "key-1");
}

#[test]
fn two_storage_keys_is_format_changed() {
    let tmp = TempDir::new().unwrap();
    write_vault(tmp.path(), &key_ref(), &[]);
    let conn = fixture::open(&db_path(tmp.path()));
    fixture::insert_record(&conn, "storageKey", b"second", &key_ref());
    drop(conn);
    assert_eq!(
        vault(tmp.path()).load().unwrap_err(),
        ErrorCode::VaultFormatChanged
    );
}

#[test]
fn zero_storage_keys_is_format_changed() {
    let tmp = TempDir::new().unwrap();
    write_vault(tmp.path(), &key_ref(), &[]);
    let conn = fixture::open(&db_path(tmp.path()));
    conn.execute("DELETE FROM Records", []).unwrap();
    drop(conn);
    assert_eq!(
        vault(tmp.path()).load().unwrap_err(),
        ErrorCode::VaultFormatChanged
    );
}

#[test]
fn wrongly_typed_or_missing_fields_are_format_changed() {
    let bad_key_refs = [
        obj(vec![
            ("id", s("k")),
            ("salt", bytes(&[7; 32])),
            ("source", s("0")),
        ]),
        obj(vec![("id", s("k")), ("source", Value::Int(0))]),
        obj(vec![
            ("id", Value::Int(1)),
            ("salt", bytes(&[7; 32])),
            ("source", Value::Int(0)),
        ]),
        obj(vec![
            ("id", s("k")),
            ("adapterKeyId", Value::Int(3)),
            ("salt", bytes(&[7; 32])),
            ("source", Value::Int(0)),
        ]),
        obj(vec![
            ("id", s("k")),
            ("salt", s("not bytes")),
            ("source", Value::Int(0)),
        ]),
    ];
    for bad in &bad_key_refs {
        let tmp = TempDir::new().unwrap();
        write_vault(tmp.path(), bad, &[]);
        assert_eq!(
            vault(tmp.path()).load().unwrap_err(),
            ErrorCode::VaultFormatChanged
        );
    }

    let bad_items = [
        obj(vec![
            ("id", s("i")),
            ("issuer", s("x")),
            ("name", s("y")),
            ("order", s("1")),
            ("__encryptedData", bytes(&[1; 20])),
        ]),
        obj(vec![
            ("id", s("i")),
            ("issuer", s("x")),
            ("name", s("y")),
            ("order", Value::Int(1)),
        ]),
        obj(vec![
            ("id", s("i")),
            ("issuer", Value::Null),
            ("name", s("y")),
            ("order", Value::Int(1)),
            ("__encryptedData", bytes(&[1; 20])),
        ]),
    ];
    for bad in &bad_items {
        let tmp = TempDir::new().unwrap();
        write_vault(tmp.path(), &key_ref(), std::slice::from_ref(bad));
        assert_eq!(
            vault(tmp.path()).load().unwrap_err(),
            ErrorCode::VaultFormatChanged
        );
    }
}

#[test]
fn undecodable_value_is_format_changed() {
    let tmp = TempDir::new().unwrap();
    write_vault(tmp.path(), &key_ref(), &[]);
    let conn = fixture::open(&db_path(tmp.path()));
    conn.execute(
        "UPDATE Records SET value = x'0102' WHERE key = CAST('storageKey' AS BLOB)",
        [],
    )
    .unwrap();
    drop(conn);
    assert_eq!(
        vault(tmp.path()).load().unwrap_err(),
        ErrorCode::VaultFormatChanged
    );
}

#[test]
fn more_than_1000_items_is_output_too_large() {
    let tmp = TempDir::new().unwrap();
    let items: Vec<Value> = (0..1001).map(item).collect();
    write_vault(tmp.path(), &key_ref(), &items);
    assert_eq!(
        vault(tmp.path()).load().unwrap_err(),
        ErrorCode::OutputTooLarge
    );

    let tmp = TempDir::new().unwrap();
    write_vault(tmp.path(), &key_ref(), &items[..1000]);
    assert_eq!(vault(tmp.path()).load().unwrap().1.len(), 1000);
}

#[test]
fn does_not_follow_symlinked_dirs() {
    let outside = TempDir::new().unwrap();
    write_vault(outside.path(), &key_ref(), &[]);
    let root = TempDir::new().unwrap();
    symlink(outside.path(), root.path().join("link")).unwrap();
    assert_eq!(
        vault(root.path()).load().unwrap_err(),
        ErrorCode::VaultNotFound
    );
}

#[test]
fn does_not_follow_symlinked_db_file() {
    let outside = TempDir::new().unwrap();
    write_vault(outside.path(), &key_ref(), &[]);
    let root = TempDir::new().unwrap();
    symlink(db_path(outside.path()), db_path(root.path())).unwrap();
    assert_eq!(
        vault(root.path()).load().unwrap_err(),
        ErrorCode::VaultNotFound
    );
}

#[test]
fn symlinked_root_is_not_followed() {
    let real = TempDir::new().unwrap();
    write_vault(real.path(), &key_ref(), &[]);
    let holder = TempDir::new().unwrap();
    let link = holder.path().join("root");
    symlink(real.path(), &link).unwrap();
    assert_eq!(vault(&link).load().unwrap_err(), ErrorCode::VaultNotFound);
}

fn nested(root: &Path, depth: usize) -> PathBuf {
    let mut p = root.to_path_buf();
    for i in 0..depth {
        p.push(format!("d{i}"));
    }
    p
}

#[test]
fn walk_depth_is_bounded() {
    let tmp = TempDir::new().unwrap();
    write_vault(&nested(tmp.path(), 6), &key_ref(), &[]);
    assert!(vault(tmp.path()).load().is_ok());

    let tmp = TempDir::new().unwrap();
    write_vault(&nested(tmp.path(), 7), &key_ref(), &[]);
    assert_eq!(
        vault(tmp.path()).load().unwrap_err(),
        ErrorCode::VaultNotFound
    );
}

#[test]
fn candidate_count_is_capped() {
    let tmp = TempDir::new().unwrap();
    for i in 0..40 {
        write_decoy(&tmp.path().join(format!("a{i:02}")));
    }
    write_vault(&tmp.path().join("zz"), &key_ref(), &[]);
    assert_eq!(
        vault(tmp.path()).load().unwrap_err(),
        ErrorCode::VaultNotFound
    );
}

#[test]
fn opens_read_only() {
    let tmp = TempDir::new().unwrap();
    write_vault(tmp.path(), &key_ref(), &[item(1)]);
    let db = db_path(tmp.path());
    fs::set_permissions(&db, fs::Permissions::from_mode(0o444)).unwrap();
    let before = fs::read(&db).unwrap();
    let names = listing(tmp.path());

    vault(tmp.path()).load().unwrap();

    assert_eq!(fs::read(&db).unwrap(), before);
    assert_eq!(listing(tmp.path()), names);
}

#[test]
fn reads_uncheckpointed_wal_changes() {
    let tmp = TempDir::new().unwrap();
    let _writer = write_vault_wal(tmp.path(), &key_ref(), &[item(1), item(2), item(3)]);
    let wal = tmp.path().join(format!("{}-wal", fixture::DB_NAME));
    assert!(fs::metadata(&wal).unwrap().len() > 0);

    let (key, items) = vault(tmp.path()).load().unwrap();
    assert_eq!(key.id, "key-1");
    assert_eq!(items.len(), 3);
}

#[test]
fn modified_is_max_of_db_and_wal() {
    let tmp = TempDir::new().unwrap();
    let _writer = write_vault_wal(tmp.path(), &key_ref(), &[item(1)]);
    let db = db_path(tmp.path());
    let wal = tmp.path().join(format!("{}-wal", fixture::DB_NAME));

    set_mtime(&db, 1_000_000);
    set_mtime(&wal, 2_000_000);
    assert_eq!(vault(tmp.path()).modified().unwrap(), 2_000_000);

    set_mtime(&db, 3_000_000);
    assert_eq!(vault(tmp.path()).modified().unwrap(), 3_000_000);
}

#[test]
fn modified_without_wal_uses_db_mtime() {
    let tmp = TempDir::new().unwrap();
    write_vault(tmp.path(), &key_ref(), &[]);
    let expected = unix_secs(
        fs::metadata(db_path(tmp.path()))
            .unwrap()
            .modified()
            .unwrap(),
    );
    assert_eq!(vault(tmp.path()).modified().unwrap(), expected);
}

#[test]
fn default_root_is_under_home_local_share() {
    let root = ProtonIdbVault::default_root().unwrap();
    assert!(root.ends_with(".local/share/me.proton.authenticator/databases/indexeddb"));
}

fn snapshot_dir(dir: &Path) -> Vec<(String, Vec<u8>)> {
    listing(dir)
        .into_iter()
        .map(|n| {
            let bytes = if n.ends_with("-shm") {
                Vec::new()
            } else {
                fs::read(dir.join(&n)).unwrap()
            };
            (n, bytes)
        })
        .collect()
}

#[test]
fn wal_vault_with_live_shm_is_untouched() {
    let tmp = TempDir::new().unwrap();
    let _writer = write_vault_wal(tmp.path(), &key_ref(), &[item(1)]);
    let before = snapshot_dir(tmp.path());

    assert_eq!(vault(tmp.path()).load().unwrap().1.len(), 1);

    assert_eq!(snapshot_dir(tmp.path()), before);
}

#[test]
fn path_with_uri_special_chars_is_opened() {
    let tmp = TempDir::new().unwrap();
    write_vault(&tmp.path().join("a?b#c%d e"), &key_ref(), &[]);
    assert!(vault(tmp.path()).load().is_ok());
}

#[test]
fn rejects_view_disguised_as_table() {
    let tmp = TempDir::new().unwrap();
    fixture::write_vault_records_as_view(tmp.path(), &key_ref(), &[item(1)]);
    assert_eq!(
        vault(tmp.path()).load().unwrap_err(),
        ErrorCode::VaultFormatChanged
    );
}

#[test]
fn corrupted_pages_are_format_changed() {
    let tmp = TempDir::new().unwrap();
    let items: Vec<Value> = (0..20).map(item).collect();
    write_vault(tmp.path(), &key_ref(), &items);
    let db = db_path(tmp.path());
    let mut data = fs::read(&db).unwrap();
    assert!(data.len() > 4096);
    data[4096..].fill(0xA5);
    fs::write(&db, data).unwrap();
    assert_eq!(
        vault(tmp.path()).load().unwrap_err(),
        ErrorCode::VaultFormatChanged
    );
}

#[test]
fn partially_corrupted_db_never_panics() {
    let tmp = TempDir::new().unwrap();
    let items: Vec<Value> = (0..20).map(item).collect();
    write_vault(tmp.path(), &key_ref(), &items);
    let db = db_path(tmp.path());
    let mut data = fs::read(&db).unwrap();
    let mid = data.len() / 2;
    data[mid..mid + 600].fill(0xA5);
    fs::write(&db, data).unwrap();
    let _ = vault(tmp.path()).load();
}

#[test]
fn broken_newer_candidate_does_not_fall_back_to_older() {
    let tmp = TempDir::new().unwrap();
    write_vault(&tmp.path().join("old"), &key_ref(), &[item(1)]);
    write_vault(&tmp.path().join("new"), &key_ref(), &[item(1)]);
    set_mtime(&db_path(&tmp.path().join("old")), 1_000_000);
    set_mtime(&db_path(&tmp.path().join("new")), 2_000_000);
    assert!(vault(tmp.path()).load().is_ok());

    let new_db = db_path(&tmp.path().join("new"));
    let mut data = fs::read(&new_db).unwrap();
    data[4096..].fill(0xA5);
    fs::write(&new_db, data).unwrap();
    set_mtime(&new_db, 2_000_000);
    assert_eq!(
        vault(tmp.path()).load().unwrap_err(),
        ErrorCode::VaultFormatChanged
    );

    File::options()
        .write(true)
        .open(&new_db)
        .unwrap()
        .set_len(3 * 1024 * 1024)
        .unwrap();
    set_mtime(&new_db, 2_000_000);
    assert_eq!(
        vault(tmp.path()).load().unwrap_err(),
        ErrorCode::VaultFormatChanged
    );
}

fn write_custom_schema_vault(dir: &Path, schema: &str) {
    use rusqlite::params;
    use support::ssv_writer::encode;
    fs::create_dir_all(dir).unwrap();
    let conn = fixture::open(&db_path(dir));
    conn.execute_batch(schema).unwrap();
    conn.execute(
        "INSERT INTO ObjectStoreInfo (id, name, keyPath, autoInc) VALUES (1, 'items', x'', 0), (2, 'storageKey', x'', 0)",
        [],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO Records (objectStoreID, key, value, recordID) VALUES (2, 'storageKey', ?1, 1), (1, 'item-0', ?2, 2)",
        params![encode(&key_ref()), encode(&item(0))],
    )
    .unwrap();
}

#[test]
fn object_store_id_must_be_rowid_alias() {
    let tmp = TempDir::new().unwrap();
    write_custom_schema_vault(
        tmp.path(),
        "CREATE TABLE Records (objectStoreID INTEGER NOT NULL, key TEXT NOT NULL, value NOT NULL, recordID INTEGER PRIMARY KEY);
         CREATE TABLE ObjectStoreInfo (id INTEGER NOT NULL, name TEXT NOT NULL, keyPath BLOB NOT NULL, autoInc INTEGER NOT NULL);",
    );
    assert_eq!(
        vault(tmp.path()).load().unwrap_err(),
        ErrorCode::VaultFormatChanged
    );
}

#[test]
fn record_id_must_be_rowid_alias() {
    let tmp = TempDir::new().unwrap();
    write_custom_schema_vault(
        tmp.path(),
        "CREATE TABLE Records (objectStoreID INTEGER NOT NULL, key TEXT NOT NULL, value NOT NULL, recordID INTEGER);
         CREATE TABLE ObjectStoreInfo (id INTEGER PRIMARY KEY, name TEXT NOT NULL, keyPath BLOB NOT NULL, autoInc INTEGER NOT NULL);",
    );
    assert_eq!(
        vault(tmp.path()).load().unwrap_err(),
        ErrorCode::VaultFormatChanged
    );
}

#[test]
fn many_pointers_to_one_large_payload_are_rejected_without_copying() {
    use pa_helper::sqlite_file::Image;
    use support::ssv_writer::encode;

    const PAGE: usize = 65536;
    let tmp = TempDir::new().unwrap();
    let db = db_path(tmp.path());
    {
        let conn = fixture::open(&db);
        conn.pragma_update(None, "page_size", PAGE as u32).unwrap();
        fixture::create_schema(&conn, &["items", "storageKey"]);
        fixture::insert_raw(&conn, "storageKey", b"storageKey", &encode(&key_ref()));
        let big = obj(vec![
            ("id", s("item-0")),
            ("issuer", s("GitHub")),
            ("name", s("me@example.com")),
            ("order", Value::Int(0)),
            ("__encryptedData", bytes(&[9; 60_000])),
        ]);
        fixture::insert_raw(&conn, "items", b"item-0", &encode(&big));
    }
    assert!(vault(tmp.path()).load().is_ok());

    let mut data = fs::read(&db).unwrap();
    let root = Image::parse(&data)
        .unwrap()
        .table_root("Records")
        .unwrap()
        .unwrap() as usize;
    let page = &mut data[(root - 1) * PAGE..root * PAGE];
    assert_eq!(page[0], 0x0D);
    assert_eq!(u16::from_be_bytes([page[3], page[4]]), 2);
    let big_cell = [page[10], page[11]];
    assert!(usize::from(u16::from_be_bytes(big_cell)) > 8 + 2 * 1001);
    page[3..5].copy_from_slice(&1001u16.to_be_bytes());
    for i in 1..1001 {
        page[8 + 2 * i..10 + 2 * i].copy_from_slice(&big_cell);
    }
    fs::write(&db, &data).unwrap();

    let mut rows_seen = 0;
    let scanned = Image::parse(&data).unwrap().scan(root as u32, |_, _| {
        rows_seen += 1;
        Ok(())
    });
    assert_eq!(scanned.unwrap_err(), ErrorCode::VaultFormatChanged);
    assert_eq!(rows_seen, 0);

    let started = std::time::Instant::now();
    assert_eq!(
        vault(tmp.path()).load().unwrap_err(),
        ErrorCode::VaultFormatChanged
    );
    assert!(started.elapsed() < Duration::from_secs(2));
}
