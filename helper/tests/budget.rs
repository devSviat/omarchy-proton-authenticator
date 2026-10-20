//! Locked-memory budget of the heaviest load path, measured in the
//! `pa-budget-probe` process so that SQLite, which only this test needs for
//! the fixture, is not mapped into the hardened address space.
//! Run with `cargo test --locked --features budget-probe --test budget`.
#![cfg(feature = "budget-probe")]

mod support;

use std::path::Path;
use std::process::Command;

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit};
use hkdf::Hkdf;
use pa_helper::ssv::Value;
use rusqlite::config::DbConfig;
use rusqlite::params;
use sha2::Sha256;
use support::fixture::{create_schema, db_path, insert_record, open, wal_path};
use support::ssv_writer::encode;
use zeroize::Zeroizing;

const PROBE: &str = env!("CARGO_BIN_EXE_pa-budget-probe");
const SHIPPED_MEMLOCK_BYTES: u64 = 8 * 1024 * 1024;
/// Leaves at least 1 MiB of the 8 MiB limit for the keyring call and output.
const MAX_LOCKED_KB: u64 = 7168;
/// Address space of the release helper right after `harden()`, measured on
/// Arch (glibc 2.44): 3668 kB. Debug builds map more code, so they are held
/// to the growth budget derived from it rather than to the absolute cap.
const RELEASE_BASELINE_KB: u64 = 3668;
const MAX_LOAD_GROWTH_KB: u64 = MAX_LOCKED_KB - RELEASE_BASELINE_KB;
const ROOT: [u8; 32] = [0x11; 32];
const SALT: [u8; 32] = [0x22; 32];
const ITEMS: usize = 1000;
const NOTE_LEN: usize = 1400;
const ROWS_PER_UPDATE: usize = 1;
const MIB: u64 = 1024 * 1024;

fn s(v: &str) -> Value {
    Value::String(v.to_string())
}

fn bytes(b: &[u8]) -> Value {
    Value::Bytes(Zeroizing::new(b.to_vec()))
}

fn obj(props: Vec<(&str, Value)>) -> Value {
    Value::Object(props.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}

fn sealed_item(cipher: &Aes256Gcm, i: usize, round: u8) -> Value {
    let issuer = format!("Issuer{i:04}");
    let note = "n".repeat(NOTE_LEN);
    let plain = format!(
        r#"{{"entryType":"Totp","note":"{note}","period":30,"secret":"JBSWY3DPEHPK3PXP","uri":"otpauth://totp/{issuer}:user{i}?secret=JBSWY3DPEHPK3PXP&issuer={issuer}&digits=8&algorithm=SHA512"}}"#
    );
    let mut iv = [(i % 251) as u8; 12];
    iv[0] = round;
    let ct = cipher
        .encrypt(
            (&iv).into(),
            Payload {
                msg: plain.as_bytes(),
                aad: b"authenticator;item",
            },
        )
        .unwrap();
    obj(vec![
        ("id", s(&format!("item-{i}"))),
        ("issuer", s(&issuer)),
        ("name", s(&format!("user{i}@example.com"))),
        ("order", Value::Int(i as i32)),
        ("__encryptedData", bytes(&[iv.as_slice(), &ct].concat())),
    ])
}

/// 1000 items, a main file just under the 2 MiB image cap, and a WAL of
/// several MiB that rewrites every item in small transactions.
fn write_max_vault(dir: &Path) {
    let mut key = [0u8; 32];
    Hkdf::<Sha256>::new(Some(&SALT), &ROOT)
        .expand(b"authenticator;storage-key", &mut key)
        .unwrap();
    let cipher = Aes256Gcm::new_from_slice(&key).unwrap();

    let conn = open(&db_path(dir));
    conn.set_db_config(DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, true)
        .unwrap();
    conn.pragma_update(None, "journal_mode", "wal").unwrap();
    conn.pragma_update(None, "wal_autocheckpoint", 0).unwrap();
    create_schema(&conn, &["items", "storageKey"]);
    let key_ref = obj(vec![
        ("id", s("key-1")),
        ("adapterKeyId", s("adapter-1")),
        ("salt", bytes(&SALT)),
        ("source", Value::Int(0)),
    ]);
    insert_record(&conn, "storageKey", b"storageKey", &key_ref);
    for i in 0..ITEMS {
        insert_record(
            &conn,
            "items",
            format!("item-{i:04}").as_bytes(),
            &sealed_item(&cipher, i, 0),
        );
    }
    conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))
        .unwrap();
    for chunk in (0..ITEMS).collect::<Vec<_>>().chunks(ROWS_PER_UPDATE) {
        conn.execute_batch("BEGIN").unwrap();
        for &i in chunk {
            conn.execute(
                "UPDATE Records SET value = ?1 WHERE key = ?2",
                params![
                    encode(&sealed_item(&cipher, i, 1)),
                    format!("item-{i:04}").as_bytes()
                ],
            )
            .unwrap();
        }
        conn.execute_batch("COMMIT").unwrap();
    }
}

/// Hard `RLIMIT_MEMLOCK` of this process in bytes, `None` when unlimited.
fn memlock_hard_limit() -> Option<u64> {
    let limits = std::fs::read_to_string("/proc/self/limits").unwrap();
    let row = limits
        .lines()
        .find(|l| l.starts_with("Max locked memory"))
        .unwrap();
    row.split_whitespace().nth(4).unwrap().parse().ok()
}

fn kb_field(line: &str, name: &str) -> u64 {
    line.split_whitespace()
        .find_map(|w| w.strip_prefix(name)?.strip_prefix('='))
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(|| panic!("{name} missing in {line:?}"))
}

#[test]
fn max_vault_fits_memlock_budget() {
    if memlock_hard_limit().is_some_and(|hard| hard < SHIPPED_MEMLOCK_BYTES) {
        eprintln!("budget: skipped, hard RLIMIT_MEMLOCK is below 8 MiB");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    write_max_vault(tmp.path());
    let main_len = std::fs::metadata(db_path(tmp.path())).unwrap().len();
    let wal_len = std::fs::metadata(wal_path(tmp.path())).unwrap().len();
    eprintln!("fixture: main {main_len} B, wal {wal_len} B");
    assert!((19 * MIB / 10..=2 * MIB).contains(&main_len), "{main_len}");
    assert!((39 * MIB / 10..=16 * MIB).contains(&wal_len), "{wal_len}");

    let limit = format!("--memlock={SHIPPED_MEMLOCK_BYTES}");
    let out = Command::new("/usr/bin/prlimit")
        .args([limit.as_str(), "--", PROBE])
        .arg(tmp.path())
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    eprintln!("probe: {stdout}");
    assert!(
        out.status.success(),
        "probe failed: {:?} {stdout}",
        out.status
    );
    let line = stdout.lines().next().unwrap();
    assert!(
        line.starts_with(&format!("result=OK items={ITEMS} codes={ITEMS} ")),
        "{line}"
    );
    // Under mlockall every mapping is locked, so the peak address space bounds
    // the peak of locked memory, which VmLck alone (a current value) does not show.
    let peak = kb_field(line, "peak_kb");
    let growth = peak - kb_field(line, "base_peak_kb");
    assert!(
        growth <= MAX_LOAD_GROWTH_KB,
        "load path grew the locked set by {growth} kB > {MAX_LOAD_GROWTH_KB} kB"
    );
    if !cfg!(debug_assertions) {
        let locked = kb_field(line, "lck_kb");
        assert!(
            locked <= MAX_LOCKED_KB,
            "VmLck {locked} kB > {MAX_LOCKED_KB} kB"
        );
        assert!(
            peak <= MAX_LOCKED_KB,
            "VmPeak {peak} kB > {MAX_LOCKED_KB} kB"
        );
    }
}
