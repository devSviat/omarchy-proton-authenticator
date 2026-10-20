mod support;

use std::cell::Cell;
use std::path::Path;

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit};
use hkdf::Hkdf;
use pa_helper::app::{codes, CodesRequest, KeyProvider, LockState};
use pa_helper::base32::base32_decode;
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
    last_key_id: std::cell::RefCell<String>,
}

impl FakeKeys {
    fn new(state: LockState) -> Self {
        Self {
            state,
            root: ROOT,
            root_calls: Cell::new(0),
            last_key_id: Default::default(),
        }
    }
}

impl KeyProvider for FakeKeys {
    fn lock_state(&self, _key_id: &str) -> Result<LockState> {
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
        let vault = vault_with(tmp.path(), &key_ref(Some(id), &SALT, 0), &[]);
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
