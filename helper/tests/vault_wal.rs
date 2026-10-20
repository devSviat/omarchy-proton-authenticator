mod support;

use std::fs;
use std::path::Path;
use std::time::Duration;

use pa_helper::error::ErrorCode;
use pa_helper::ssv::{decode, get, Value};
use pa_helper::vault::{read_stable, ProtonIdbVault};
use pa_helper::wal::{apply_wal, Applied};
use support::fixture::{self, db_path, shm_path, wal_path};
use support::load::LoadAll;
use support::wal_writer;
use tempfile::TempDir;
use zeroize::Zeroizing;

fn s(v: &str) -> Value {
    Value::String(v.to_string())
}

fn obj(props: Vec<(&str, Value)>) -> Value {
    Value::Object(props.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}

fn key_ref() -> Value {
    obj(vec![
        ("id", s("key-1")),
        ("salt", Value::Bytes(Zeroizing::new(vec![7; 32]))),
        ("source", Value::Int(0)),
    ])
}

fn item(n: i32) -> Value {
    obj(vec![
        ("id", s(&format!("item-{n}"))),
        ("issuer", s("GitHub")),
        ("name", s("me@example.com")),
        ("order", Value::Int(n)),
        (
            "__encryptedData",
            Value::Bytes(Zeroizing::new(vec![n as u8; 40])),
        ),
    ])
}

fn items(range: std::ops::Range<i32>) -> Vec<Value> {
    range.map(item).collect()
}

fn all_files(dir: &Path) -> Vec<(String, Vec<u8>)> {
    let mut v: Vec<_> = fs::read_dir(dir)
        .unwrap()
        .map(|e| {
            let e = e.unwrap();
            (
                e.file_name().to_string_lossy().into_owned(),
                fs::read(e.path()).unwrap(),
            )
        })
        .collect();
    v.sort();
    v
}

fn item_ids_from_sqlite(dir: &Path) -> Vec<String> {
    let copy = TempDir::new().unwrap();
    fixture::copy_db_files(dir, copy.path());
    let mut ids: Vec<String> = fixture::sqlite_records(copy.path())
        .into_iter()
        .filter_map(|(_, blob)| {
            let v = decode(&blob).unwrap();
            match (get(&v, "issuer"), get(&v, "id")) {
                (Some(_), Some(Value::String(id))) => Some(id.clone()),
                _ => None,
            }
        })
        .collect();
    ids.sort();
    ids
}

fn our_item_ids(dir: &Path) -> Vec<String> {
    let (key, items) = ProtonIdbVault::new(dir.to_path_buf()).load().unwrap();
    assert_eq!(key.id, "key-1");
    let mut ids: Vec<String> = items.into_iter().map(|i| i.id).collect();
    ids.sort();
    ids
}

fn assert_matches_sqlite_and_untouched(dir: &Path) {
    let before = all_files(dir);
    let ours = our_item_ids(dir);
    let theirs = item_ids_from_sqlite(dir);
    assert_eq!(ours, theirs);
    assert_eq!(all_files(dir), before);
}

#[test]
fn a_cleanly_closed_wal_db_without_sidecars() {
    let tmp = TempDir::new().unwrap();
    fixture::write_vault_wal_clean(tmp.path(), &key_ref(), &items(0..3));
    assert!(!wal_path(tmp.path()).exists());
    assert!(!shm_path(tmp.path()).exists());
    assert_matches_sqlite_and_untouched(tmp.path());
    assert_eq!(our_item_ids(tmp.path()).len(), 3);
    assert!(!wal_path(tmp.path()).exists());
    assert!(!shm_path(tmp.path()).exists());
    assert!(ProtonIdbVault::new(tmp.path().to_path_buf()).load().is_ok());
}

#[test]
fn b_writer_open_with_uncheckpointed_frames() {
    let tmp = TempDir::new().unwrap();
    let _writer = fixture::write_vault_wal(tmp.path(), &key_ref(), &items(0..5));
    assert!(shm_path(tmp.path()).exists());
    assert_matches_sqlite_and_untouched(tmp.path());
    assert_eq!(our_item_ids(tmp.path()).len(), 5);
}

#[test]
fn c_writer_closed_with_wal_and_shm_present() {
    let tmp = TempDir::new().unwrap();
    fixture::write_vault_wal_closed(tmp.path(), &key_ref(), &items(0..5));
    assert!(wal_path(tmp.path()).exists());
    assert_matches_sqlite_and_untouched(tmp.path());
    assert_eq!(our_item_ids(tmp.path()).len(), 5);
}

#[test]
fn d_wal_present_shm_deleted() {
    let tmp = TempDir::new().unwrap();
    fixture::write_vault_wal_closed(tmp.path(), &key_ref(), &items(0..5));
    let _ = fs::remove_file(shm_path(tmp.path()));
    assert_matches_sqlite_and_untouched(tmp.path());
    assert!(!shm_path(tmp.path()).exists());
    assert_eq!(our_item_ids(tmp.path()).len(), 5);
}

#[test]
fn e_truncated_mid_frame_keeps_last_complete_commit() {
    let tmp = TempDir::new().unwrap();
    fixture::write_vault_wal_closed(tmp.path(), &key_ref(), &items(0..6));
    let _ = fs::remove_file(shm_path(tmp.path()));
    let wal = wal_path(tmp.path());
    let len = fs::metadata(&wal).unwrap().len();
    fs::File::options()
        .write(true)
        .open(&wal)
        .unwrap()
        .set_len(len - 1000)
        .unwrap();
    assert_matches_sqlite_and_untouched(tmp.path());
    assert!(our_item_ids(tmp.path()).len() < 6);
}

#[test]
fn f_garbage_frame_after_last_commit_is_ignored() {
    let tmp = TempDir::new().unwrap();
    fixture::write_vault_wal_closed(tmp.path(), &key_ref(), &items(0..4));
    let _ = fs::remove_file(shm_path(tmp.path()));
    let wal = wal_path(tmp.path());
    let mut bytes = fs::read(&wal).unwrap();
    bytes.extend(std::iter::repeat_n(0xFF, 24 + 4096));
    fs::write(&wal, bytes).unwrap();
    assert_matches_sqlite_and_untouched(tmp.path());
    assert_eq!(our_item_ids(tmp.path()).len(), 4);
}

#[test]
fn g_stale_salt_frames_after_wal_restart_are_ignored() {
    let tmp = TempDir::new().unwrap();
    fixture::write_vault_wal_restarted(tmp.path(), &key_ref(), &items(0..30), &items(100..102));
    let _ = fs::remove_file(shm_path(tmp.path()));
    let wal = wal_path(tmp.path());
    let bytes = fs::read(&wal).unwrap();
    let frames = (bytes.len() - 32) / (24 + 4096);
    let valid_salts = wal_writer::salts(&bytes);
    let stale = bytes[32..]
        .as_chunks::<{ 24 + 4096 }>()
        .0
        .iter()
        .filter(|f| u32::from_be_bytes(f[8..12].try_into().unwrap()) != valid_salts.0)
        .count();
    assert!(
        stale > 0,
        "fixture must leave stale frames ({frames} total)"
    );
    assert_matches_sqlite_and_untouched(tmp.path());
    assert_eq!(our_item_ids(tmp.path()).len(), 32);
}

#[test]
fn h_big_endian_checksum_wal() {
    let le = TempDir::new().unwrap();
    fixture::write_vault_wal_closed(le.path(), &key_ref(), &items(0..5));
    let _ = fs::remove_file(shm_path(le.path()));
    let le_wal = fs::read(wal_path(le.path())).unwrap();
    let frames = wal_writer::parse_frames(&le_wal, 4096);
    let be_wal = wal_writer::build(true, 4096, wal_writer::salts(&le_wal), &frames);
    assert_eq!(&be_wal[..4], &0x377f_0683u32.to_be_bytes());

    let be = TempDir::new().unwrap();
    fs::copy(db_path(le.path()), db_path(be.path())).unwrap();
    fs::write(wal_path(be.path()), be_wal).unwrap();
    let before = all_files(be.path());
    assert_eq!(our_item_ids(be.path()), item_ids_from_sqlite(le.path()));
    assert_eq!(our_item_ids(be.path()).len(), 5);
    assert_eq!(all_files(be.path()), before);
}

#[test]
fn i_wal_larger_than_image_is_streamed() {
    let tmp = TempDir::new().unwrap();
    fixture::write_vault_wal_closed(tmp.path(), &key_ref(), &items(0..600));
    let wal_len = fs::metadata(wal_path(tmp.path())).unwrap().len();
    assert!(
        (4 * 1024 * 1024..16 * 1024 * 1024).contains(&wal_len),
        "{wal_len}"
    );
    assert_matches_sqlite_and_untouched(tmp.path());
    assert_eq!(our_item_ids(tmp.path()).len(), 600);
}

#[test]
fn rebuilt_little_endian_wal_roundtrips() {
    let tmp = TempDir::new().unwrap();
    fixture::write_vault_wal_closed(tmp.path(), &key_ref(), &items(0..5));
    let _ = fs::remove_file(shm_path(tmp.path()));
    let wal = fs::read(wal_path(tmp.path())).unwrap();
    let rebuilt = wal_writer::build(
        false,
        4096,
        wal_writer::salts(&wal),
        &wal_writer::parse_frames(&wal, 4096),
    );
    assert_eq!(rebuilt, wal);
}

#[test]
fn oversized_main_is_format_changed() {
    let tmp = TempDir::new().unwrap();
    fixture::write_vault(tmp.path(), &key_ref(), &[]);
    fs::File::options()
        .write(true)
        .open(db_path(tmp.path()))
        .unwrap()
        .set_len(5 * 1024 * 1024)
        .unwrap();
    assert_eq!(
        ProtonIdbVault::new(tmp.path().to_path_buf())
            .load()
            .unwrap_err(),
        ErrorCode::VaultFormatChanged
    );
}

#[test]
fn oversized_wal_is_format_changed() {
    let tmp = TempDir::new().unwrap();
    fixture::write_vault(tmp.path(), &key_ref(), &[]);
    fs::File::create(wal_path(tmp.path()))
        .unwrap()
        .set_len(16 * 1024 * 1024 + 1)
        .unwrap();
    assert_eq!(
        ProtonIdbVault::new(tmp.path().to_path_buf())
            .load()
            .unwrap_err(),
        ErrorCode::VaultFormatChanged
    );
}

#[test]
fn wal_page_size_mismatch_is_format_changed() {
    let tmp = TempDir::new().unwrap();
    fixture::write_vault(tmp.path(), &key_ref(), &[]);
    let wal = wal_writer::build(
        false,
        8192,
        (1, 2),
        &[wal_writer::Frame {
            page: 1,
            commit_pages: 1,
            data: vec![0; 8192],
        }],
    );
    fs::write(wal_path(tmp.path()), wal).unwrap();
    assert_eq!(
        ProtonIdbVault::new(tmp.path().to_path_buf())
            .load()
            .unwrap_err(),
        ErrorCode::VaultFormatChanged
    );
}

#[test]
fn huge_commit_size_is_format_changed_not_a_panic() {
    let tmp = TempDir::new().unwrap();
    fixture::write_vault(tmp.path(), &key_ref(), &[]);
    let wal = wal_writer::build(
        false,
        4096,
        (1, 2),
        &[wal_writer::Frame {
            page: 1,
            commit_pages: u32::MAX,
            data: vec![0; 4096],
        }],
    );
    fs::write(wal_path(tmp.path()), wal).unwrap();
    assert_eq!(
        ProtonIdbVault::new(tmp.path().to_path_buf())
            .load()
            .unwrap_err(),
        ErrorCode::VaultFormatChanged
    );
}

#[test]
fn invalid_wal_header_means_main_file_alone() {
    let tmp = TempDir::new().unwrap();
    fixture::write_vault(tmp.path(), &key_ref(), &items(0..2));
    fs::write(wal_path(tmp.path()), vec![0x5Au8; 5000]).unwrap();
    assert_eq!(our_item_ids(tmp.path()).len(), 2);
    fs::write(wal_path(tmp.path()), b"").unwrap();
    assert_eq!(our_item_ids(tmp.path()).len(), 2);
}

#[test]
fn mutated_wals_never_panic() {
    let tmp = TempDir::new().unwrap();
    fixture::write_vault_wal_closed(tmp.path(), &key_ref(), &items(0..4));
    let _ = fs::remove_file(shm_path(tmp.path()));
    let main = fs::read(db_path(tmp.path())).unwrap();
    let wal = fs::read(wal_path(tmp.path())).unwrap();
    let mut state = 0x9E37_79B9_7F4A_7C15u64;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for _ in 0..300 {
        let mut w = wal.clone();
        for _ in 0..(next() % 8) {
            let i = (next() as usize) % w.len();
            w[i] = next() as u8;
        }
        w.truncate((next() as usize) % (w.len() + 1));
        let mut m = main.clone();
        if next() % 4 == 0 {
            let i = (next() as usize) % m.len();
            m[i] = next() as u8;
        }
        let _ = pa_helper::wal::build_image(&m, Some(&w), 8 * 1024 * 1024);
    }
}

#[test]
fn consistency_failure_on_every_attempt_is_vault_busy() {
    let tmp = TempDir::new().unwrap();
    fixture::write_vault_wal_closed(tmp.path(), &key_ref(), &items(0..2));
    let wal = wal_path(tmp.path());
    let mut calls = 0;
    let started = std::time::Instant::now();
    let result = read_stable(&db_path(tmp.path()), &mut || {
        calls += 1;
        let mut f = fs::File::options().append(true).open(&wal).unwrap();
        std::io::Write::write_all(&mut f, &[0]).unwrap();
    });
    assert_eq!(result.err(), Some(ErrorCode::VaultBusy));
    assert_eq!(calls, 4);
    assert!(started.elapsed() >= Duration::from_millis(150));
}

#[test]
fn consistency_failure_once_is_retried() {
    let tmp = TempDir::new().unwrap();
    fixture::write_vault_wal_closed(tmp.path(), &key_ref(), &items(0..2));
    let main = db_path(tmp.path());
    let mut calls = 0;
    let result = read_stable(&main, &mut || {
        calls += 1;
        if calls == 1 {
            let f = fs::File::options().write(true).open(&main).unwrap();
            f.set_modified(std::time::UNIX_EPOCH + Duration::from_secs(1_000_000))
                .unwrap();
        }
    });
    assert!(result.unwrap().is_some());
    assert_eq!(calls, 2);
}

#[test]
fn wal_appearing_during_read_is_unstable_then_picked_up() {
    let tmp = TempDir::new().unwrap();
    fixture::write_vault(tmp.path(), &key_ref(), &[]);
    let wal = wal_path(tmp.path());
    let mut calls = 0;
    let image = read_stable(&db_path(tmp.path()), &mut || {
        calls += 1;
        if calls == 1 {
            fs::write(&wal, b"x").unwrap();
        }
    })
    .unwrap()
    .unwrap();
    assert_eq!(calls, 2);
    assert_eq!(image.as_slice(), fs::read(db_path(tmp.path())).unwrap());
}

/// Serves `first` until the second rewind, then `second`.
struct ChangingWal {
    first: Vec<u8>,
    second: Vec<u8>,
    rewinds: usize,
    pos: usize,
}

impl std::io::Read for ChangingWal {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let src = if self.rewinds < 2 {
            &self.first
        } else {
            &self.second
        };
        let n = buf.len().min(src.len().saturating_sub(self.pos));
        buf[..n].copy_from_slice(&src[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

impl std::io::Seek for ChangingWal {
    fn seek(&mut self, to: std::io::SeekFrom) -> std::io::Result<u64> {
        assert_eq!(to, std::io::SeekFrom::Start(0));
        self.rewinds += 1;
        self.pos = 0;
        Ok(0)
    }
}

#[test]
fn wal_changing_between_passes_is_reported() {
    let tmp = TempDir::new().unwrap();
    fixture::write_vault_wal_closed(tmp.path(), &key_ref(), &items(0..4));
    let main = fs::read(db_path(tmp.path())).unwrap();
    let wal = fs::read(wal_path(tmp.path())).unwrap();
    let mut image = Zeroizing::new(Vec::with_capacity(2 * 1024 * 1024));
    image.extend_from_slice(&main);
    let mut reader = ChangingWal {
        second: wal[..32 + 24 + 4096].to_vec(),
        first: wal,
        rewinds: 0,
        pos: 0,
    };
    let applied = apply_wal(&mut image, Some(&mut reader), 2 * 1024 * 1024).unwrap();
    assert_eq!(applied, Applied::Changed);
    assert_eq!(reader.rewinds, 2);
}
