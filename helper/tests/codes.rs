mod support;

use std::cell::Cell;
use std::path::Path;

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit};
use hkdf::Hkdf;
use pa_helper::app::{
    check, codes, codes_private, copy_code, CodesRequest, KeyProvider, LockState, PrivateRequest,
};
use pa_helper::base32::base32_decode;
use pa_helper::domain::{EntryView, PrivateEntry};
use pa_helper::error::{ErrorCode, Result};
use pa_helper::otp::{steam, totp, Algorithm};
use pa_helper::ssv::Value;
use pa_helper::vault::ProtonIdbVault;
use sha2::Sha256;
use support::fixture::write_vault;
use tempfile::TempDir;
use zeroize::Zeroizing;

const ROOT: [u8; 32] = [0x11; 32];
const SALT: [u8; 32] = [0x22; 32];
const SECRET: &str = "JBSWY3DPEHPK3PXP";
const UNIX: u64 = 1_700_000_000;

fn bytes(b: &[u8]) -> Value {
    Value::Bytes(Zeroizing::new(b.to_vec()))
}

fn s(v: &str) -> Value {
    Value::String(v.to_string())
}

fn obj(props: Vec<(&str, Value)>) -> Value {
    Value::Object(props.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}

fn storage_key(root: &[u8], salt: &[u8]) -> [u8; 32] {
    let mut key = [0u8; 32];
    Hkdf::<Sha256>::new(Some(salt), root)
        .expand(b"authenticator;storage-key", &mut key)
        .unwrap();
    key
}

fn seal(key: &[u8; 32], plaintext: &str) -> Vec<u8> {
    let cipher = Aes256Gcm::new_from_slice(key).unwrap();
    let iv = [0x33u8; 12];
    let ct = cipher
        .encrypt(
            (&iv).into(),
            Payload {
                msg: plaintext.as_bytes(),
                aad: b"authenticator;item",
            },
        )
        .unwrap();
    [iv.as_slice(), &ct].concat()
}

fn plaintext(entry_type: &str, uri: &str) -> String {
    format!(
        r#"{{"entryType":"{entry_type}","note":"","period":30,"secret":"{SECRET}","uri":"{uri}"}}"#
    )
}

fn item(id: &str, issuer: &str, name: &str, order: i32, data: Vec<u8>) -> Value {
    obj(vec![
        ("id", s(id)),
        ("issuer", s(issuer)),
        ("name", s(name)),
        ("order", Value::Int(order)),
        ("__encryptedData", bytes(&data)),
    ])
}

fn totp_item(id: &str, issuer: &str, name: &str) -> Value {
    let uri = format!("otpauth://totp/{issuer}:{name}?secret={SECRET}&issuer={issuer}");
    item(
        id,
        issuer,
        name,
        0,
        seal(&storage_key(&ROOT, &SALT), &plaintext("Totp", &uri)),
    )
}

fn steam_item(id: &str, issuer: &str, name: &str) -> Value {
    let uri = format!("steam://{SECRET}");
    item(
        id,
        issuer,
        name,
        1,
        seal(&storage_key(&ROOT, &SALT), &plaintext("Steam", &uri)),
    )
}

fn key_ref(adapter: Option<&str>, salt: &[u8], source: i32) -> Value {
    let mut props = vec![("id", s("key-1"))];
    if let Some(a) = adapter {
        props.push(("adapterKeyId", s(a)));
    }
    props.push(("salt", bytes(salt)));
    props.push(("source", Value::Int(source)));
    obj(props)
}

fn vault_with(dir: &Path, key_ref: &Value, items: &[Value]) -> ProtonIdbVault {
    write_vault(dir, key_ref, items);
    ProtonIdbVault::new(dir.to_path_buf())
}

fn standard(dir: &Path) -> ProtonIdbVault {
    vault_with(
        dir,
        &key_ref(Some("adapter-1"), &SALT, 0),
        &[
            totp_item("t1", "GitHub", "me@example.com"),
            steam_item("s1", "Steam", "gamer"),
        ],
    )
}

struct FakeKeys {
    state: LockState,
    root: [u8; 32],
    root_calls: Cell<u32>,
    lock_calls: Cell<u32>,
    last_key_id: std::cell::RefCell<String>,
}

impl FakeKeys {
    fn new(state: LockState) -> Self {
        Self {
            state,
            root: ROOT,
            root_calls: Cell::new(0),
            lock_calls: Cell::new(0),
            last_key_id: Default::default(),
        }
    }
}

impl KeyProvider for FakeKeys {
    fn lock_state(&self, _key_id: &str) -> Result<LockState> {
        self.lock_calls.set(self.lock_calls.get() + 1);
        Ok(self.state)
    }

    fn root_key(&self, key_id: &str) -> Result<Zeroizing<[u8; 32]>> {
        self.root_calls.set(self.root_calls.get() + 1);
        *self.last_key_id.borrow_mut() = key_id.to_string();
        Ok(Zeroizing::new(self.root))
    }
}

fn req(only: Option<&str>, allow_prompt: bool) -> CodesRequest {
    CodesRequest {
        only: only.map(str::to_string),
        allow_prompt,
        unix: UNIX,
    }
}

#[test]
fn codes_end_to_end() {
    let tmp = TempDir::new().unwrap();
    let keys = FakeKeys::new(LockState::Unlocked);
    let views = codes(&standard(tmp.path()), &keys, &req(None, false)).unwrap();

    let key = base32_decode(SECRET).unwrap();
    assert_eq!(views.len(), 2);
    assert_eq!(views[0].id, "t1");
    assert_eq!(views[0].issuer, "GitHub");
    assert_eq!(views[0].account, "me@example.com");
    assert_eq!(views[0].kind, "totp");
    assert_eq!(
        views[0].code.as_deref(),
        Some(totp(&key, UNIX, 30, Algorithm::Sha1, 6).as_str())
    );
    assert_eq!(views[1].id, "s1");
    assert_eq!(views[1].kind, "steam");
    assert_eq!(views[1].code.as_deref(), Some(steam(&key, UNIX).as_str()));
    assert_eq!(*keys.last_key_id.borrow(), "adapter-1");
}

#[test]
fn locked_keyring_without_prompt() {
    let tmp = TempDir::new().unwrap();
    let keys = FakeKeys::new(LockState::Locked);
    let err = codes(&standard(tmp.path()), &keys, &req(None, false)).unwrap_err();
    assert_eq!(err, ErrorCode::KeyringLocked);
    assert_eq!(keys.root_calls.get(), 0);
}

#[test]
fn missing_key_without_prompt() {
    let tmp = TempDir::new().unwrap();
    let keys = FakeKeys::new(LockState::Missing);
    let err = codes(&standard(tmp.path()), &keys, &req(None, false)).unwrap_err();
    assert_eq!(err, ErrorCode::KeyNotFound);
    assert_eq!(keys.root_calls.get(), 0);
}

#[test]
fn allow_prompt_skips_lock_check() {
    let tmp = TempDir::new().unwrap();
    let keys = FakeKeys::new(LockState::Locked);
    let views = codes(&standard(tmp.path()), &keys, &req(None, true)).unwrap();
    assert_eq!(views.len(), 2);
    assert_eq!(keys.root_calls.get(), 1);
}

#[test]
fn password_source_is_app_locked() {
    let tmp = TempDir::new().unwrap();
    let vault = vault_with(tmp.path(), &key_ref(Some("a"), &SALT, 1), &[]);
    let keys = FakeKeys::new(LockState::Unlocked);
    let err = codes(&vault, &keys, &req(None, true)).unwrap_err();
    assert_eq!(err, ErrorCode::AppLocked);
    assert_eq!(keys.root_calls.get(), 0);
}

#[test]
fn fallback_source_is_unsafe_key_storage() {
    let tmp = TempDir::new().unwrap();
    let vault = vault_with(tmp.path(), &key_ref(Some("a"), &SALT, 2), &[]);
    let keys = FakeKeys::new(LockState::Unlocked);
    let err = codes(&vault, &keys, &req(None, true)).unwrap_err();
    assert_eq!(err, ErrorCode::UnsafeKeyStorage);
    assert_eq!(keys.root_calls.get(), 0);
}

#[test]
fn unknown_source_is_format_changed() {
    for source in [3, -1, 99] {
        let tmp = TempDir::new().unwrap();
        let vault = vault_with(tmp.path(), &key_ref(Some("a"), &SALT, source), &[]);
        let keys = FakeKeys::new(LockState::Unlocked);
        let err = codes(&vault, &keys, &req(None, true)).unwrap_err();
        assert_eq!(err, ErrorCode::VaultFormatChanged, "source {source}");
    }
}

#[test]
fn wrong_salt_length_is_format_changed() {
    for salt in [&[0x22u8; 31][..], &[0x22; 33][..], &[][..]] {
        let tmp = TempDir::new().unwrap();
        let vault = vault_with(tmp.path(), &key_ref(Some("a"), salt, 0), &[]);
        let keys = FakeKeys::new(LockState::Unlocked);
        let err = codes(&vault, &keys, &req(None, true)).unwrap_err();
        assert_eq!(err, ErrorCode::VaultFormatChanged);
        assert_eq!(keys.root_calls.get(), 0);
    }
}

#[test]
fn invalid_key_id_is_format_changed() {
    let long = "a".repeat(129);
    for id in [
        "",
        "-leading-dash",
        ".dot",
        "has space",
        "semi;colon",
        "a/b",
        &long,
    ] {
        let tmp = TempDir::new().unwrap();
        let vault = vault_with(tmp.path(), &key_ref(Some(id), &SALT, 0), &[]);
        let keys = FakeKeys::new(LockState::Unlocked);
        let err = codes(&vault, &keys, &req(None, true)).unwrap_err();
        assert_eq!(err, ErrorCode::VaultFormatChanged, "id {id:?}");
        assert_eq!(keys.root_calls.get(), 0);
    }
}

#[test]
fn key_id_charset_and_length_accepted() {
    let max = format!("_{}", "a".repeat(127));
    for id in ["_x", "A.b:c-d_e", "0", max.as_str()] {
        let tmp = TempDir::new().unwrap();
        let vault = vault_with(
            tmp.path(),
            &key_ref(Some(id), &SALT, 0),
            &[totp_item("t1", "GitHub", "me")],
        );
        let keys = FakeKeys::new(LockState::Unlocked);
        codes(&vault, &keys, &req(None, true)).unwrap();
        assert_eq!(*keys.last_key_id.borrow(), id);
    }
}

#[test]
fn wrong_key_is_decrypt_failed() {
    let tmp = TempDir::new().unwrap();
    let mut keys = FakeKeys::new(LockState::Unlocked);
    keys.root = [0x99; 32];
    let err = codes(&standard(tmp.path()), &keys, &req(None, false)).unwrap_err();
    assert_eq!(err, ErrorCode::DecryptFailed);
}

#[test]
fn one_bad_item_fails_the_whole_call() {
    let tmp = TempDir::new().unwrap();
    let mut bad = seal(
        &storage_key(&ROOT, &SALT),
        &plaintext("Totp", "otpauth://totp/x"),
    );
    *bad.last_mut().unwrap() ^= 1;
    let vault = vault_with(
        tmp.path(),
        &key_ref(Some("a"), &SALT, 0),
        &[
            totp_item("t1", "GitHub", "me"),
            item("bad", "X", "y", 2, bad),
        ],
    );
    let keys = FakeKeys::new(LockState::Unlocked);
    let err = codes(&vault, &keys, &req(None, false)).unwrap_err();
    assert_eq!(err, ErrorCode::DecryptFailed);
}

#[test]
fn short_ciphertext_is_decrypt_failed() {
    let tmp = TempDir::new().unwrap();
    let vault = vault_with(
        tmp.path(),
        &key_ref(Some("a"), &SALT, 0),
        &[item("t", "X", "y", 0, vec![1; 20])],
    );
    let keys = FakeKeys::new(LockState::Unlocked);
    let err = codes(&vault, &keys, &req(None, false)).unwrap_err();
    assert_eq!(err, ErrorCode::DecryptFailed);
}

#[test]
fn authenticated_but_malformed_plaintext_is_format_changed() {
    let tmp = TempDir::new().unwrap();
    let data = seal(&storage_key(&ROOT, &SALT), "not json");
    let vault = vault_with(
        tmp.path(),
        &key_ref(Some("a"), &SALT, 0),
        &[item("t", "X", "y", 0, data)],
    );
    let keys = FakeKeys::new(LockState::Unlocked);
    let err = codes(&vault, &keys, &req(None, false)).unwrap_err();
    assert_eq!(err, ErrorCode::VaultFormatChanged);
}

#[test]
fn only_filters_and_unknown_is_item_not_found() {
    let tmp = TempDir::new().unwrap();
    let vault = standard(tmp.path());
    let keys = FakeKeys::new(LockState::Unlocked);

    let views = codes(&vault, &keys, &req(Some("s1"), false)).unwrap();
    assert_eq!(views.len(), 1);
    assert_eq!(views[0].id, "s1");

    let err = codes(&vault, &keys, &req(Some("nope"), false)).unwrap_err();
    assert_eq!(err, ErrorCode::ItemNotFound);
}

#[test]
fn only_skips_decrypting_other_items() {
    let tmp = TempDir::new().unwrap();
    let vault = vault_with(
        tmp.path(),
        &key_ref(Some("a"), &SALT, 0),
        &[
            totp_item("good", "GitHub", "me"),
            item("bad", "X", "y", 2, vec![0; 40]),
        ],
    );
    let keys = FakeKeys::new(LockState::Unlocked);
    let views = codes(&vault, &keys, &req(Some("good"), false)).unwrap();
    assert_eq!(views.len(), 1);
}

#[test]
fn legacy_ref_without_adapter_key_id_uses_id() {
    let tmp = TempDir::new().unwrap();
    let vault = vault_with(
        tmp.path(),
        &key_ref(None, &SALT, 0),
        &[totp_item("t1", "GitHub", "me")],
    );
    let keys = FakeKeys::new(LockState::Unlocked);
    codes(&vault, &keys, &req(None, false)).unwrap();
    assert_eq!(*keys.last_key_id.borrow(), "key-1");
}

#[test]
fn sorted_by_issuer_then_account_case_insensitive() {
    let tmp = TempDir::new().unwrap();
    let vault = vault_with(
        tmp.path(),
        &key_ref(Some("a"), &SALT, 0),
        &[
            totp_item("1", "github", "zed"),
            totp_item("2", "Amazon", "bob"),
            totp_item("3", "GitHub", "Alice"),
            totp_item("4", "amazon", "Aaron"),
        ],
    );
    let keys = FakeKeys::new(LockState::Unlocked);
    let ids: Vec<String> = codes(&vault, &keys, &req(None, false))
        .unwrap()
        .into_iter()
        .map(|v| v.id)
        .collect();
    assert_eq!(ids, ["4", "2", "3", "1"]);
}

#[test]
fn empty_vault_returns_nothing_without_touching_keys() {
    let tmp = TempDir::new().unwrap();
    let vault = vault_with(tmp.path(), &key_ref(Some("a"), &SALT, 0), &[]);
    let keys = FakeKeys::new(LockState::Locked);
    assert!(codes(&vault, &keys, &req(None, false)).unwrap().is_empty());
    assert!(codes(&vault, &keys, &req(None, true)).unwrap().is_empty());
    assert_eq!(keys.root_calls.get(), 0);
}

#[test]
fn invalid_item_id_is_format_changed() {
    let long = "a".repeat(129);
    for id in [
        "",
        "has space",
        "a/b",
        "semi;colon",
        "ü",
        "-lead",
        "--demo",
        long.as_str(),
    ] {
        let tmp = TempDir::new().unwrap();
        let vault = vault_with(
            tmp.path(),
            &key_ref(Some("a"), &SALT, 0),
            &[totp_item("ok", "GitHub", "me"), totp_item(id, "X", "y")],
        );
        let keys = FakeKeys::new(LockState::Unlocked);
        let err = codes(&vault, &keys, &req(None, true)).unwrap_err();
        assert_eq!(err, ErrorCode::VaultFormatChanged, "id {id:?}");
        assert_eq!(keys.root_calls.get(), 0);
    }
}

#[test]
fn item_id_charset_and_length_accepted() {
    let max = "a".repeat(128);
    let tmp = TempDir::new().unwrap();
    let vault = vault_with(
        tmp.path(),
        &key_ref(Some("a"), &SALT, 0),
        &[totp_item("A.b:c_d-", "A", "x"), totp_item(&max, "B", "x")],
    );
    let keys = FakeKeys::new(LockState::Unlocked);
    assert_eq!(codes(&vault, &keys, &req(None, false)).unwrap().len(), 2);
}

fn executable(dir: &Path, name: &str) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let path = dir.join(name);
    std::fs::write(&path, "#!/bin/sh\n").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    path
}

#[test]
fn check_ready_never_reads_the_key() {
    let tmp = TempDir::new().unwrap();
    let bin = TempDir::new().unwrap();
    let dep = executable(bin.path(), "wl-copy");
    let keys = FakeKeys::new(LockState::Unlocked);
    let report = check(&standard(tmp.path()), &keys, &[dep.as_path()]);
    assert_eq!(report.status, Ok(()));
    assert!(report.vault_mtime.is_some());
    assert_eq!(keys.root_calls.get(), 0);
}

#[test]
fn check_stops_at_the_first_failing_step() {
    let tmp = TempDir::new().unwrap();
    let report = check(
        &ProtonIdbVault::new(tmp.path().join("none")),
        &FakeKeys::new(LockState::Unlocked),
        &[],
    );
    assert_eq!(report.status, Err(ErrorCode::VaultNotFound));
    assert_eq!(report.vault_mtime, None);

    for (source, expected) in [(1, ErrorCode::AppLocked), (2, ErrorCode::UnsafeKeyStorage)] {
        let tmp = TempDir::new().unwrap();
        let vault = vault_with(tmp.path(), &key_ref(None, &SALT, source), &[]);
        let keys = FakeKeys::new(LockState::Unlocked);
        let report = check(&vault, &keys, &[]);
        assert_eq!(report.status, Err(expected));
        assert!(report.vault_mtime.is_some());
        assert_eq!(keys.root_calls.get(), 0);
    }

    for (state, expected) in [
        (LockState::Locked, ErrorCode::KeyringLocked),
        (LockState::Missing, ErrorCode::KeyNotFound),
    ] {
        let tmp = TempDir::new().unwrap();
        let keys = FakeKeys::new(state);
        let report = check(&standard(tmp.path()), &keys, &[]);
        assert_eq!(report.status, Err(expected));
        assert_eq!(keys.root_calls.get(), 0);
    }

    let tmp = TempDir::new().unwrap();
    let bin = TempDir::new().unwrap();
    let present = executable(bin.path(), "secret-tool");
    let missing = bin.path().join("wl-copy");
    let report = check(
        &standard(tmp.path()),
        &FakeKeys::new(LockState::Unlocked),
        &[present.as_path(), missing.as_path()],
    );
    assert_eq!(report.status, Err(ErrorCode::DependencyMissing));
}

fn view_with(code: Option<&str>, next: Option<&str>, remaining: u64) -> EntryView {
    EntryView {
        id: "x".into(),
        issuer: "I".into(),
        account: "a".into(),
        kind: "totp",
        code: code.map(str::to_string),
        next_code: next.map(str::to_string),
        period: 30,
        digits: 6,
        remaining,
    }
}

#[test]
fn copy_code_switches_to_next_near_the_boundary() {
    let pick = |remaining| copy_code(view_with(Some("111111"), Some("222222"), remaining));
    assert_eq!(pick(30).unwrap().as_str(), "111111");
    assert_eq!(pick(5).unwrap().as_str(), "111111");
    assert_eq!(pick(4).unwrap().as_str(), "222222");
    assert_eq!(pick(1).unwrap().as_str(), "222222");
    assert_eq!(
        copy_code(view_with(None, None, 0)).unwrap_err(),
        ErrorCode::InvalidArgument
    );
}

fn private_req(reveal: Option<&str>, allow_prompt: bool) -> PrivateRequest {
    PrivateRequest {
        reveal: reveal.map(str::to_string),
        allow_prompt,
        unix: UNIX,
    }
}

fn private_json(entries: &[PrivateEntry]) -> Vec<serde_json::Value> {
    entries
        .iter()
        .map(|e| serde_json::to_value(e).unwrap())
        .collect()
}

const CODE_FIELDS: [&str; 6] = ["kind", "code", "nextCode", "period", "digits", "remaining"];

fn assert_hidden(entry: &serde_json::Value) {
    let map = entry.as_object().unwrap();
    assert_eq!(map.len(), 9, "{entry}");
    for field in CODE_FIELDS {
        assert!(map[field].is_null(), "{field} in {entry}");
    }
}

#[test]
fn private_without_reveal_never_touches_the_keyring() {
    for state in [LockState::Locked, LockState::Missing, LockState::Unlocked] {
        let tmp = TempDir::new().unwrap();
        let vault = standard(tmp.path());
        let keys = FakeKeys::new(state);
        for allow_prompt in [false, true] {
            let entries = codes_private(&vault, &keys, &private_req(None, allow_prompt)).unwrap();
            let json = private_json(&entries);
            assert_eq!(json.len(), 2);
            assert_eq!(json[0]["id"], "t1");
            assert_eq!(json[0]["issuer"], "GitHub");
            assert_eq!(json[0]["account"], "me@example.com");
            assert_eq!(json[1]["id"], "s1");
            assert_eq!(json[1]["issuer"], "Steam");
            assert_eq!(json[1]["account"], "gamer");
            json.iter().for_each(assert_hidden);
        }
        assert_eq!(keys.lock_calls.get(), 0);
        assert_eq!(keys.root_calls.get(), 0);
    }
}

#[test]
fn private_without_reveal_decrypts_nothing() {
    let tmp = TempDir::new().unwrap();
    let vault = vault_with(
        tmp.path(),
        &key_ref(Some("a"), &SALT, 0),
        &[
            totp_item("good", "GitHub", "me"),
            item("bad", "X", "y", 2, vec![0; 40]),
        ],
    );
    let keys = FakeKeys::new(LockState::Unlocked);
    let entries = codes_private(&vault, &keys, &private_req(None, false)).unwrap();
    assert_eq!(entries.len(), 2);
    private_json(&entries).iter().for_each(assert_hidden);
}

#[test]
fn private_reveal_computes_only_that_entry() {
    let tmp = TempDir::new().unwrap();
    let keys = FakeKeys::new(LockState::Unlocked);
    let entries = codes_private(
        &standard(tmp.path()),
        &keys,
        &private_req(Some("t1"), false),
    )
    .unwrap();
    let json = private_json(&entries);
    let key = base32_decode(SECRET).unwrap();
    assert_eq!(json.len(), 2);
    assert_eq!(json[0]["id"], "t1");
    assert_eq!(json[0]["kind"], "totp");
    assert_eq!(json[0]["code"], totp(&key, UNIX, 30, Algorithm::Sha1, 6));
    assert_eq!(
        json[0]["nextCode"],
        totp(&key, UNIX + 30, 30, Algorithm::Sha1, 6)
    );
    assert_eq!(json[0]["period"], 30);
    assert_eq!(json[0]["digits"], 6);
    assert_eq!(json[0]["remaining"], 30 - UNIX % 30);
    assert_eq!(json[1]["id"], "s1");
    assert_hidden(&json[1]);
    assert_eq!(keys.root_calls.get(), 1);
    assert_eq!(keys.lock_calls.get(), 1);
}

#[test]
fn private_reveal_decrypts_only_the_revealed_item() {
    let tmp = TempDir::new().unwrap();
    let vault = vault_with(
        tmp.path(),
        &key_ref(Some("a"), &SALT, 0),
        &[
            totp_item("good", "GitHub", "me"),
            item("bad", "X", "y", 2, vec![0; 40]),
        ],
    );
    let keys = FakeKeys::new(LockState::Unlocked);
    let entries = codes_private(&vault, &keys, &private_req(Some("good"), false)).unwrap();
    let json = private_json(&entries);
    assert_eq!(json[0]["id"], "good");
    assert!(json[0]["code"].is_string());
    assert_hidden(&json[1]);
}

#[test]
fn private_reveal_unknown_is_item_not_found() {
    let tmp = TempDir::new().unwrap();
    let keys = FakeKeys::new(LockState::Unlocked);
    let err = codes_private(
        &standard(tmp.path()),
        &keys,
        &private_req(Some("nope"), false),
    )
    .unwrap_err();
    assert_eq!(err, ErrorCode::ItemNotFound);
    assert_eq!(keys.lock_calls.get(), 0);
    assert_eq!(keys.root_calls.get(), 0);
}

#[test]
fn private_reveal_follows_the_lock_rules() {
    let tmp = TempDir::new().unwrap();
    let vault = standard(tmp.path());
    let keys = FakeKeys::new(LockState::Locked);
    let err = codes_private(&vault, &keys, &private_req(Some("t1"), false)).unwrap_err();
    assert_eq!(err, ErrorCode::KeyringLocked);
    assert_eq!(keys.root_calls.get(), 0);

    let keys = FakeKeys::new(LockState::Missing);
    let err = codes_private(&vault, &keys, &private_req(Some("t1"), false)).unwrap_err();
    assert_eq!(err, ErrorCode::KeyNotFound);

    let keys = FakeKeys::new(LockState::Locked);
    let entries = codes_private(&vault, &keys, &private_req(Some("t1"), true)).unwrap();
    assert!(serde_json::to_value(&entries[0]).unwrap()["code"].is_string());
    assert_eq!(keys.lock_calls.get(), 0);
    assert_eq!(keys.root_calls.get(), 1);
}

#[test]
fn private_keeps_the_vault_checks() {
    let tmp = TempDir::new().unwrap();
    let vault = vault_with(
        tmp.path(),
        &key_ref(Some("a"), &SALT, 0),
        &[totp_item("ok", "GitHub", "me"), totp_item("-bad", "X", "y")],
    );
    let keys = FakeKeys::new(LockState::Unlocked);
    let err = codes_private(&vault, &keys, &private_req(None, false)).unwrap_err();
    assert_eq!(err, ErrorCode::VaultFormatChanged);

    let tmp = TempDir::new().unwrap();
    let vault = vault_with(
        tmp.path(),
        &key_ref(Some("a"), &SALT, 1),
        &[totp_item("ok", "GitHub", "me")],
    );
    let err = codes_private(&vault, &keys, &private_req(None, false)).unwrap_err();
    assert_eq!(err, ErrorCode::AppLocked);
    assert_eq!(keys.lock_calls.get() + keys.root_calls.get(), 0);
}

#[test]
fn private_sorts_and_truncates_like_codes() {
    let tmp = TempDir::new().unwrap();
    let long = "é".repeat(300);
    let vault = vault_with(
        tmp.path(),
        &key_ref(Some("a"), &SALT, 0),
        &[
            totp_item("1", "github", "zed"),
            totp_item("2", "Amazon", "bob"),
            totp_item("3", "GitHub", "Alice"),
            totp_item("4", "amazon", "Aaron"),
            totp_item("5", &long, &long),
        ],
    );
    let keys = FakeKeys::new(LockState::Unlocked);
    let json = private_json(&codes_private(&vault, &keys, &private_req(Some("3"), false)).unwrap());
    let ids: Vec<&str> = json.iter().map(|e| e["id"].as_str().unwrap()).collect();
    assert_eq!(ids, ["4", "2", "3", "1", "5"]);
    let last = &json[4];
    assert_eq!(last["issuer"].as_str().unwrap().chars().count(), 256);
    assert_eq!(last["account"].as_str().unwrap().chars().count(), 256);
}
