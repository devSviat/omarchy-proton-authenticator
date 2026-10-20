# Proton Authenticator Omarchy Plugin Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** An Omarchy bar plugin (`sviat.proton-authenticator`) that shows the official Proton Authenticator's TOTP codes in a fast keyboard-driven panel. A small Rust helper reads the official vault read-only and is the only place secrets ever exist.

**Architecture:** There are two parts.
- **`helper/`** is a Rust crate, `pa-helper`, built as a functional core plus ports & adapters. Pure modules (`otp`, `uri`, `ssv`, `crypto`) do no I/O. `app` holds the use-cases and talks to the outside only through the `KeyProvider`, `VaultSource` and `Clipboard` traits. A thin `main` hardens the process, parses arguments, runs one use-case and prints one bounded JSON line.
- **The QML plugin** mirrors `~/Projects/omarchy-nightlight`. `Service.qml` is the singleton: it owns all state and is the only place that runs the helper. `Panel.qml` and `components/` only render. `Model.js` holds the pure logic (search, ordering, formatting).

**Tech Stack:**
- Rust (edition 2024, stable 1.99 via rustup).
- Crates: `aes-gcm`, `hkdf`, `hmac`, `sha1`, `sha2`, `zeroize`, `rusqlite` (system libsqlite3, no `bundled`), `serde`, `serde_json`, `libc`.
- Quickshell/QML (omarchy-shell 4.0.6) and plain JS (`Model.js`) tested with node.
- External tools, always by absolute path: `/usr/bin/secret-tool` (libsecret), `/usr/bin/gdbus` (glib2), `/usr/bin/wl-copy` (wl-clipboard ≥ 2.3).

**Spec:** `docs/superpowers/specs/2026-10-20-proton-authenticator-plugin-design.md`. Read it before starting any task.

> Several decisions changed during implementation (most notably: no SQLite in the shipped helper — the vault is read by an in-house WAL applier and B-tree reader; the clipboard holder keeps no hash of the code; `codes --allow-prompt` has a 120 s budget). The spec records the current design; where this plan and the spec disagree, the spec wins.

## Global Constraints

- Secrets (TOTP seeds, the vault root key, the derived storage key) exist only inside `pa-helper`.
  - Never in QML, argv, env, files, logs or notifications.
  - Never in `Debug`/`Display` output or error messages.
- No network code and no network crates. No temp files. Nothing written to disk except `prefs.json` (Task 9).
- The vault is opened read-only (`mode=ro`) and copied with the SQLite backup API into an in-memory database before reading.
- Every external program is run by absolute path, with `env_clear()` plus only the variables it needs: `HOME`, `XDG_RUNTIME_DIR`, `WAYLAND_DISPLAY`, `DBUS_SESSION_BUS_ADDRESS`.
- Process hardening runs first in `main`, before argument parsing:
  - `prctl(PR_SET_DUMPABLE, 0)`;
  - `setrlimit(RLIMIT_CORE, 0)`;
  - `mlockall(MCL_CURRENT | MCL_FUTURE | MCL_ONFAULT)`. If it fails, the helper exits with `MEMLOCK_FAILED` (fail closed). The user's `ulimit -l` is 8192 KiB.
- `unsafe` is allowed **only** in `helper/src/sys.rs`. `lib.rs` carries `#![deny(unsafe_code)]`, and `sys.rs` alone has `#![allow(unsafe_code)]`, with a `// SAFETY:` comment on every block.
- Release profile: `panic = "abort"`, `lto = true`, `codegen-units = 1`, `strip = true`.
- Build gates: `cargo build --locked`, `cargo clippy --all-targets --locked -- -D warnings`, `cargo fmt --check`, `cargo deny check` (licenses, advisories, sources = crates.io only).
- Protocol: one JSON line on stdout, at most 1 MiB, field names in camelCase. Every reply carries `"protocol": 1`. Errors look like `{"ok":false,"protocol":1,"error":"<ERROR_CODE>"}` and carry no message text.
- Bounds:
  - at most 1000 entries;
  - issuer/account truncated to 256 chars;
  - `secret-tool` stdout at most 64 bytes;
  - a whole helper run times out after 10 s (`TIMEOUT`);
  - item id regex `^[A-Za-z0-9._:-]{1,128}$`;
  - `adapterKeyId` regex `^[A-Za-z0-9_][A-Za-z0-9_.:-]{0,127}$`.
- Vault facts. The source of truth is the official WebClients code in `applications/authenticator/src/lib/` (`storage-key/*`, `db/entities/*`, `crypto.ts`) and `src-tauri/src/storage_key.rs`.
  - DB file: the `IndexedDB.sqlite3` under `~/.local/share/me.proton.authenticator/databases/indexeddb/` whose `ObjectStoreInfo` has both `items` and `storageKey`.
  - The `storageKey` record has `id`, `adapterKeyId?`, `salt` (Uint8Array, exactly 32 bytes), `source` (0 KEYRING, 1 PASSWORD, 2 FALLBACK) and `unsafe_key?`.
  - Keyring item: service `com.proton.authenticator`, username `adapterKeyId` (or `id` if `adapterKeyId` is absent, the pre-1.1.4 layout). The secret is raw 32 bytes.
  - Storage key = HKDF-SHA256(ikm = keyring secret, salt = `salt`, info = `authenticator;storage-key`, 32 bytes).
  - An `items` record has `id`, `issuer`, `name`, `order` (Int) and `__encryptedData` (Uint8Array = 12-byte IV ‖ AES-256-GCM ciphertext+tag, AAD `authenticator;item`).
  - The plaintext is JSON `{entryType: "Totp"|"Steam", note, period, secret, uri, syncMetadata?}`. Digits and algorithm come from the `uri` query; `secret` and `period` come from the fields.
  - `source == 1` → `APP_LOCKED`. `source == 2` → `UNSAFE_KEY_STORAGE`: refuse, and never read `unsafe_key`.
- UI copy is English (published plugin).
- Code comments follow the user's global rules: default none; only why, constraints and invariants; no comments about the edit; never Russian.
- Git:
  - work on `dev` (or `feature/*` branches merged into `dev`);
  - commits in the user's name with no assistant attribution;
  - `main` only via a PR that the user merges.
- **Every task ends with a code review and a separate security review of the task's diff**, with findings fixed before the next task. Task 14 adds a full-repo security audit.

## Review Focus

1. **The vault changes while the helper reads it.** The official app writes during a sync, so the helper must use the backup API snapshot and must never see a half-written WAL state. A `SQLITE_BUSY` during backup is retried 3 times, 100 ms apart. If it still fails, the error is `VAULT_BUSY`, never `VAULT_FORMAT_CHANGED`. Test in Task 5.
2. **The keyring is locked after boot (autologin).** `check` and plain `codes` must return `KEYRING_LOCKED` without ever opening a prompt. Only `codes --allow-prompt` may prompt. Test in Task 7 with a fake gdbus output.
3. **An entry is malformed or unsupported** (HOTP uri, digits 9, empty secret, bad base32). That one entry gets `kind: "unsupported"` with no code, and the rest of the list still renders. Test in Task 3.
4. **The clipboard is replaced before the clear timer fires.** The user's newer clipboard content must never be cleared. Test in Task 8.
5. **Panel closes or the shell restarts while the helper runs.** No orphaned helper may keep secrets in memory past its timeout, and no `wl-copy` may keep serving a code past `clearClipboardSeconds`. Test in Task 8 (holder deadline) and Task 1 (global timeout).

---

### Task 1: Crate skeleton, error codes, JSON envelope, CI

**Files:**
- Create: `helper/Cargo.toml`, `helper/deny.toml`, `helper/rustfmt.toml`, `helper/src/lib.rs`, `helper/src/main.rs`, `helper/src/error.rs`, `helper/src/output.rs`, `.github/workflows/ci.yml`, `helper/tests/envelope.rs`
- Modify: `.gitignore` (add `/helper/target/`)

**Interfaces:**
- Produces:
  - `pub enum ErrorCode`. Variants: `VaultNotFound, VaultBusy, VaultFormatChanged, KeyringLocked, KeyringUnavailable, KeyNotFound, DecryptFailed, AppLocked, UnsafeKeyStorage, DependencyMissing, ItemNotFound, InvalidArgument, MemlockFailed, Timeout, OutputTooLarge, Internal`. It serializes as SCREAMING_SNAKE_CASE. `impl std::error::Error`, `Display` = the code only.
  - `pub type Result<T> = std::result::Result<T, ErrorCode>`.
  - `pub const PROTOCOL: u32 = 1`.
  - `pub fn render_ok<T: Serialize>(body: &T) -> String` merges `{"ok":true,"protocol":1}` into `body`'s object.
  - `pub fn render_err(code: ErrorCode) -> String`.
  - Both enforce the 1 MiB cap and return `render_err(OutputTooLarge)` when it is exceeded.
  - `main` prints `render_err(InvalidArgument)` for now. A `version` command prints `{"ok":true,"protocol":1,"version":"<CARGO_PKG_VERSION>"}`.

- [ ] **Step 1: Write failing tests** in `helper/tests/envelope.rs`:
  - `error_codes_serialize_screaming`: `serde_json::to_string(&ErrorCode::KeyringLocked) == "\"KEYRING_LOCKED\""`.
  - `render_err_has_no_message`: `render_err(ErrorCode::DecryptFailed) == r#"{"ok":false,"protocol":1,"error":"DECRYPT_FAILED"}"#`.
  - `render_ok_merges_envelope`: rendering a struct `{a:1}` parses to `ok==true, protocol==1, a==1`.
  - `render_ok_caps_size`: a body with a 2 MiB string renders as `OUTPUT_TOO_LARGE`.
- [ ] **Step 2:** Run `cargo test --locked`. Expected: compile errors (items missing).
- [ ] **Step 3:** Implement `error.rs` and `output.rs`. Set up `Cargo.toml` with the release profile from Global Constraints and `rust-version = "1.85"`. Write `deny.toml` (allow MIT/Apache-2.0/BSD-3-Clause/Unicode-3.0/ISC; deny unknown registries and git sources). Write the CI workflow: fmt, clippy `-D warnings`, test, `cargo deny check`, all with `--locked` and `working-directory: helper`.
- [ ] **Step 4:** Run `cargo test --locked && cargo clippy --all-targets --locked -- -D warnings && cargo fmt --check`. Expected: all pass.
- [ ] **Step 5:** Commit: `git add helper .github .gitignore && git commit -m "Add helper crate skeleton with error codes and JSON envelope"`.
- [ ] **Step 6:** Code review and security review of the diff. Fix the findings, then commit.

### Task 2: OTP core (base32, HOTP/TOTP, Steam)

**Files:**
- Create: `helper/src/otp.rs`, `helper/src/base32.rs`
- Test: inline `#[cfg(test)]` modules

**Interfaces:**
- Produces:
  - `pub enum Algorithm { Sha1, Sha256, Sha512 }`
  - `pub fn base32_decode(s: &str) -> Option<Zeroizing<Vec<u8>>>`. RFC 4648 alphabet, case-insensitive. Ignores spaces and `=` padding. Rejects any other character.
  - `pub fn hotp(key: &[u8], counter: u64, alg: Algorithm, digits: u32) -> String`. Zero-padded. `digits` must be in 6..=8 (the caller validates).
  - `pub fn totp(key: &[u8], unix: u64, period: u64, alg: Algorithm, digits: u32) -> String`
  - `pub fn steam(key: &[u8], unix: u64) -> String`. HMAC-SHA1, period 30, 5 chars from the alphabet `23456789BCDFGHJKMNPQRTVWXY`.

- [ ] **Step 1: Write failing tests:**
  - `rfc4226_vectors`: key `b"12345678901234567890"`, counters 0..=9 give `755224, 287082, 359152, 969429, 338314, 254676, 287922, 162583, 399871, 520489`.
  - `rfc6238_vectors_8_digits`, for times `59, 1111111109, 1111111111, 1234567890, 2000000000, 20000000000`:
    - SHA1 (key `"12345678901234567890"`): `94287082, 07081804, 14050471, 89005924, 69279037, 65353130`;
    - SHA256 (key = 32 bytes `"12345678901234567890123456789012"`): `46119246, 68084774, 67062674, 91819424, 90698825, 77737706`;
    - SHA512 (key = 64 bytes `"1234567890123456789012345678901234567890123456789012345678901234"`): `90693936, 25091201, 99943326, 93441116, 38618901, 47863826`.
  - `base32_rfc4648`: `"MZXW6YTBOI======"` → `b"foobar"`; lowercase and spaces accepted; `"MZXW1"` → `None`.
  - `steam_is_five_chars_from_alphabet`: for any key, the output has length 5 and only alphabet chars. Plus one fixed vector: compute the expected value once by hand from the algorithm (HMAC-SHA1 truncation, then 5 × `%26`) and assert it.
- [ ] **Step 2:** Run `cargo test --locked otp base32`. Expected: FAIL.
- [ ] **Step 3:** Implement with `hmac` + `sha1`/`sha2`. Dynamic truncation per RFC 4226 §5.3.
- [ ] **Step 4:** Run the tests again. Expected: PASS.
- [ ] **Step 5:** Commit: `"Add HOTP/TOTP/Steam generators with RFC vectors"`.
- [ ] **Step 6:** Code review and security review. Fix, then commit.

### Task 3: Domain types and entry parsing

**Files:**
- Create: `helper/src/domain.rs`, `helper/src/uri.rs`

**Interfaces:**
- Consumes: `Algorithm`, `base32_decode` (Task 2).
- Produces:
  - `pub struct Secret(Zeroizing<Vec<u8>>)`
    - `Debug` prints `Secret([REDACTED])`;
    - **no** `Clone`, `Serialize` or `Display`;
    - `pub fn expose(&self) -> &[u8]`;
    - `impl From<Vec<u8>> for Secret`.
  - `pub enum OtpKind { Totp { alg: Algorithm, digits: u32, period: u64 }, Steam, Unsupported }`
  - `pub struct Entry { pub id: String, pub issuer: String, pub account: String, pub kind: OtpKind, pub secret: Option<Secret> }`
  - `pub struct ItemPlaintext`: the deserialized JSON. Fields: `entry_type: String` (`entryType`), `secret: Zeroizing<String>`, `period: Option<u64>`, `uri: Zeroizing<String>`. Unknown fields are ignored.
  - `pub fn parse_otpauth(uri: &str) -> Option<UriParams>` with `UriParams { alg: Algorithm, digits: u32, period: Option<u64>, is_hotp: bool }`. Percent-decodes; parameter names are case-insensitive. Defaults: SHA1/6.
  - `pub fn build_entry(id: String, issuer: String, account: String, p: ItemPlaintext) -> Entry`. Never fails. Anything invalid becomes `kind: Unsupported, secret: None`.
  - `pub struct EntryView { id, issuer, account, kind: &'static str /* "totp"|"steam"|"unsupported" */, code: Option<String>, next_code: Option<String>, period: u64, digits: u32, remaining: u64 }`. It derives `Serialize` (camelCase) and has **no secret field**.
  - `pub fn view(entry: &Entry, unix: u64) -> EntryView`. Truncates labels to 256 chars.

- [ ] **Step 1: Write failing tests:**
  - `secret_debug_is_redacted`: `format!("{:?}", Secret::from(vec![1,2,3]))` contains `REDACTED` and not `1, 2, 3`.
  - `parse_otpauth_defaults_and_params`: `otpauth://totp/GitHub:me?secret=JBSWY3DPEHPK3PXP&issuer=GitHub` gives `Sha1, 6, None`. `...&algorithm=SHA256&digits=8&period=60` gives `Sha256, 8, Some(60)`. `otpauth://hotp/x?secret=A&counter=1` gives `is_hotp == true`.
  - `build_entry_variants`, five cases:
    - Totp with a valid secret → `Totp{Sha1,6,30}`;
    - Steam → `Steam`;
    - HOTP uri → `Unsupported`;
    - digits 9 → `Unsupported`;
    - bad base32 → `Unsupported`.
  - `view_never_contains_secret`: `serde_json::to_string(&view(..))` does not contain the base32 secret or the word `secret`.
  - `view_counts_down`: period 30, unix 1000 → `remaining == 20`. `next_code` equals `totp(.., 1030, ..)`.
  - `labels_truncated`: a 300-char issuer becomes 256 chars.
- [ ] **Step 2:** Run. Expected: FAIL.
- [ ] **Step 3:** Implement. Period precedence: the `period` field, then the uri `period`, then 30. Validate `1..=86400`.
- [ ] **Step 4:** Run. Expected: PASS.
- [ ] **Step 5:** Commit: `"Add domain types, otpauth parsing and redacted views"`.
- [ ] **Step 6:** Code review and security review. Fix, then commit.

### Task 4: WebKit SerializedScriptValue decoder (strict subset)

**Files:**
- Create: `helper/src/ssv.rs`, `helper/tests/support/ssv_writer.rs` (test-only encoder, shared with Task 5)

**Interfaces:**
- Produces:
  - `pub enum Value { Undefined, Null, Bool(bool), Int(i32), Double(f64), String(String), Bytes(Zeroizing<Vec<u8>>) /* Uint8Array */, Object(Vec<(String, Value)>) }`
  - `pub fn decode(blob: &[u8]) -> Result<Value>`. Any unexpected byte → `Err(VaultFormatChanged)`.
  - `pub fn get<'a>(obj: &'a Value, key: &str) -> Option<&'a Value>`
  - Test support: `ssv_writer::encode(&Value) -> Vec<u8>`, the exact inverse for the same subset.
  - The decoder maps the Zero tag to `Int(0)` and the One tag to `Int(1)`. The writer encodes `Int(0)` as Zero and `Int(1)` as One, matching WebKit.
- **Grammar** (all integers little-endian; reference: WebKit `Source/WebCore/bindings/js/SerializedScriptValue.cpp`):
  - The blob starts with a `u32` version, which must be `15` (`SUPPORTED_VERSIONS = [15]`). Then one value.
  - Tags (`u8`): `0x02` Object, `0x03` Undefined, `0x04` Null, `0x05` Int (`i32`), `0x06` Zero, `0x07` One, `0x08` False, `0x09` True, `0x0A` Double (`f64`), `0x10` String, `0x11` EmptyString, `0x16` ArrayBufferView.
  - **Object:** repeated `(name: string-body, value)` pairs, terminated by `u32 0xFFFFFFFF`.
  - **string-body:** a `u32` length. The high bit `0x80000000` set means 8-bit Latin-1 with `len & 0x7FFFFFFF` bytes; clear means UTF-16LE with `len` code units. `0xFFFFFFFE` (string pool reference) → `VaultFormatChanged`.
  - **ArrayBufferView:** subtag `u8` (must be `0x02`, Uint8Array), `u64` byteOffset (must be 0), `u64` byteLength, then a nested `0x15` ArrayBuffer tag, `u64` length (must equal byteLength), then the bytes.
  - Limits: nesting depth ≤ 4, total properties ≤ 64, string ≤ 64 KiB, bytes ≤ 64 KiB. Trailing bytes after the root value are allowed only if all of them are zero; otherwise `VaultFormatChanged`.

- [ ] **Step 1: Write failing tests:**
  - `roundtrip_item_shape`: encode an object `{id:"a1", issuer:"GitHub", name:"me", order:Int(3), __encryptedData:Bytes([9;40])}` and decode it back equal.
  - `roundtrip_storage_key_shape`: `{source:Int(0) /* encode as Zero tag */, salt:Bytes([7;32]), id:"k", adapterKeyId:"adapter::0::abc", unsafe_key:Undefined}`.
  - `utf16_string`: an issuer `"Привіт"` encoded as UTF-16 decodes correctly.
  - `rejects_unknown_version`, `rejects_string_pool_ref`, `rejects_unknown_tag`, `rejects_truncated` (each byte prefix of a valid blob): all `Err(VaultFormatChanged)`.
  - `rejects_view_length_mismatch`.
- [ ] **Step 2:** Run. Expected: FAIL.
- [ ] **Step 3:** Implement a cursor-based decoder with checked arithmetic. No `unwrap` on input-derived values.
- [ ] **Step 4:** Run. Expected: PASS.
- [ ] **Step 5:** Commit: `"Add strict WebKit SerializedScriptValue decoder"`.
- [ ] **Step 6:** Code review and security review (fuzz-style: run the truncation and random-mutation test over 10k mutated blobs; no panics). Fix, then commit.

### Task 5: Vault source (read-only SQLite snapshot)

**Files:**
- Create: `helper/src/vault.rs`, `helper/tests/support/fixture.rs`, `helper/tests/vault.rs`

**Interfaces:**
- Consumes: `ssv::decode`, `ssv::get` (Task 4).
- Produces:
  - `pub struct StorageKeyRef { pub id: String, pub adapter_key_id: Option<String>, pub salt: Zeroizing<Vec<u8>>, pub source: i32, pub has_unsafe_key: bool }`
  - `pub struct EncryptedItem { pub id: String, pub issuer: String, pub name: String, pub order: i32, pub data: Vec<u8> }`
  - `pub trait VaultSource { fn modified(&self) -> Result<u64>; fn load(&self) -> Result<(StorageKeyRef, Vec<EncryptedItem>)>; }`
  - `pub struct ProtonIdbVault { root: PathBuf }`
    - `ProtonIdbVault::default_root()` = `$HOME/.local/share/me.proton.authenticator/databases/indexeddb`.
    - `modified()` = the max mtime of the chosen `IndexedDB.sqlite3` and its `-wal`, in unix seconds.
  - Test support: `fixture::write_vault(dir: &Path, key_ref: &Value, items: &[Value])`. It creates a SQLite file with tables `ObjectStoreInfo(id INTEGER, name TEXT)` and `Records(objectStoreID INTEGER, key BLOB, value BLOB)`, using the real WebKit column names. Check the real DB's schema with `sqlite3 -readonly <db> .schema` (schema only, never data) and mirror the columns used.
- Selection rule: among `IndexedDB.sqlite3` files under `root` (max depth 6, no symlink following), take those whose `ObjectStoreInfo` contains both `items` and `storageKey`. If several match, use the newest mtime. If none match → `VaultNotFound`.
- Register a collation named `IDBKEY` (byte compare) on every connection; WebKit tables reference it.
- Snapshot: `Connection::open_with_flags(path, SQLITE_OPEN_READ_ONLY | SQLITE_OPEN_URI)`, then `backup` into `Connection::open_in_memory()`. On `SQLITE_BUSY`/`LOCKED`, retry 3× with 100 ms sleeps, then `VaultBusy`.
- Exactly one `storageKey` record, else `VaultFormatChanged`. More than 1000 items → `OutputTooLarge`.

- [ ] **Step 1: Write failing tests** in `tests/vault.rs` (tempdir fixture):
  - `loads_key_ref_and_items`;
  - `picks_db_with_both_stores` (also writes a decoy DB with only `mutexes`);
  - `missing_root_is_vault_not_found`;
  - `two_storage_keys_is_format_changed`;
  - `does_not_follow_symlinked_dirs`;
  - `opens_read_only`: chmod the fixture file to 0444 and check that loading succeeds and the file's bytes are unchanged afterwards;
  - `busy_vault_retries_then_vault_busy`: hold an `EXCLUSIVE` transaction from a second connection.
- [ ] **Step 2:** Run. Expected: FAIL.
- [ ] **Step 3:** Implement `vault.rs`.
- [ ] **Step 4:** Run. Expected: PASS.
- [ ] **Step 5:** Commit: `"Add read-only Proton IndexedDB vault source"`.
- [ ] **Step 6:** Code review and security review. Fix, then commit.

### Task 6: Storage-key crypto and the `codes` use-case

**Files:**
- Create: `helper/src/crypto.rs`, `helper/src/app.rs`, `helper/tests/codes.rs`

**Interfaces:**
- Consumes: `VaultSource` (Task 5), `build_entry`/`view` (Task 3).
- Produces:
  - `pub fn derive_storage_key(root: &[u8; 32], salt: &[u8]) -> Zeroizing<[u8; 32]>`. HKDF-SHA256, info `b"authenticator;storage-key"`.
  - `pub fn decrypt_item(key: &[u8; 32], data: &[u8]) -> Result<Zeroizing<Vec<u8>>>`. IV = the first 12 bytes, AAD `b"authenticator;item"`. A failure → `DecryptFailed`.
  - `pub trait KeyProvider { fn lock_state(&self, key_id: &str) -> Result<LockState>; fn root_key(&self, key_id: &str) -> Result<Zeroizing<[u8; 32]>>; }` with `pub enum LockState { Unlocked, Locked, Missing }`.
  - `pub struct CodesRequest { pub only: Option<String>, pub allow_prompt: bool, pub unix: u64 }`
  - `pub fn codes(vault: &dyn VaultSource, keys: &dyn KeyProvider, req: &CodesRequest) -> Result<Vec<EntryView>>`
- Flow:
  - `source` 1 → `AppLocked`; 2 → `UnsafeKeyStorage`; any other value besides 0 → `VaultFormatChanged`.
  - Salt length ≠ 32 → `VaultFormatChanged`.
  - The key id is `adapter_key_id` or `id`, validated by regex.
  - If `!allow_prompt`, `lock_state` must be `Unlocked`, else `KeyringLocked` (Locked) or `KeyNotFound` (Missing).
  - Decrypt each item. If **any** item fails to decrypt → `DecryptFailed` for the whole call. A wrong key means a wrong vault, so no partial lists.
  - `only` filters before decrypting; an unknown id → `ItemNotFound`.
  - Sort by issuer then account (case-insensitive). The UI re-orders anyway.

- [ ] **Step 1: Write failing tests** in `tests/codes.rs` (fixture plus a `FakeKeys`). The fixture encrypts with `aes-gcm` using a known root key `[0x11; 32]` and salt `[0x22; 32]`.
  - `codes_end_to_end`: two items (Totp `JBSWY3DPEHPK3PXP`, Steam). The codes equal `otp::totp`/`otp::steam` at `unix = 1_700_000_000`.
  - `locked_keyring_without_prompt` → `KeyringLocked`, and `root_key` was **never called** (assert on the fake's counter).
  - `allow_prompt_skips_lock_check`;
  - `password_source_is_app_locked`;
  - `fallback_source_is_unsafe_key_storage`;
  - `wrong_key_is_decrypt_failed`;
  - `only_filters_and_unknown_is_item_not_found`;
  - `legacy_ref_without_adapter_key_id_uses_id`.
- [ ] **Step 2:** Run. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run. Expected: PASS.
- [ ] **Step 5:** Commit: `"Add storage-key derivation, item decryption and codes use-case"`.
- [ ] **Step 6:** Code review and security review. Fix, then commit.

### Task 7: Process runner and keyring adapter

**Files:**
- Create: `helper/src/proc.rs`, `helper/src/keyring.rs`

**Interfaces:**
- Produces:
  - `pub fn run_bounded(program: &Path, args: &[&str], stdin: Option<&[u8]>, max_out: usize, timeout: Duration) -> Result<(i32, Zeroizing<Vec<u8>>)>`
    - `env_clear()` plus the allow-listed vars;
    - stderr goes to null;
    - over `max_out` → `OutputTooLarge`;
    - over the timeout → kill the child, then `Timeout`;
    - a missing program → `DependencyMissing`.
  - `pub struct SecretToolKeys`, which implements `KeyProvider`:
    - `lock_state` runs `/usr/bin/gdbus call --session --dest org.freedesktop.secrets --object-path /org/freedesktop/secrets --method org.freedesktop.Secret.Service.SearchItems "{'service': 'com.proton.authenticator', 'username': '<id>'}"`. The id is already regex-validated, so it cannot break the GVariant quoting.
    - Output `([objectpath '…'], @ao [])` → Unlocked. `(@ao [], [objectpath '…'])` → Locked. `(@ao [], @ao [])` → Missing. Anything else, or no D-Bus → `KeyringUnavailable`.
    - `root_key` runs `/usr/bin/secret-tool lookup service com.proton.authenticator username <id>` with max 64 bytes and a 10 s timeout. Exit ≠ 0 → `KeyNotFound`. Exactly 32 bytes is the key. Any other length → `DecryptFailed`.
  - `pub fn parse_search_items(out: &str) -> Result<LockState>`. A pure function, tested.

- [ ] **Step 1: Write failing tests:**
  - `parse_search_items_states`: the three shapes above, plus garbage → `KeyringUnavailable`.
  - `run_bounded_caps_output`: `/usr/bin/head -c 100 /dev/zero` with `max_out` 64 → `OutputTooLarge`.
  - `run_bounded_times_out`: `/usr/bin/sleep 5` with 200 ms → `Timeout`, and it returns in < 1 s.
  - `run_bounded_missing_program` → `DependencyMissing`.
  - `run_bounded_clears_env`: `/usr/bin/env` with `FOO=bar` set in the test process; the output has no `FOO`.
  - `run_bounded_passes_stdin`: `/usr/bin/cat` echoes the stdin bytes.
- [ ] **Step 2:** Run. Expected: FAIL.
- [ ] **Step 3:** Implement. Read stdout on a thread with `take(max_out + 1)` and enforce the deadline with `try_wait` polling every 10 ms.
- [ ] **Step 4:** Run. Expected: PASS.
- [ ] **Step 5:** Commit: `"Add bounded process runner and Secret Service key provider"`.
- [ ] **Step 6:** Code review and security review. Fix, then commit.

### Task 8: Process hardening and the clipboard holder

**Files:**
- Create: `helper/src/sys.rs`, `helper/src/clipboard.rs`, `helper/tests/hardening.rs`, `helper/tests/clipboard.rs`

**Interfaces:**
- Produces:
  - `sys::harden() -> Result<()>` (dumpable 0, core rlimit 0, `mlockall` with ONFAULT; failure → `MemlockFailed`).
  - `sys::detach_session() -> Result<()>` (`setsid`).
  - `sys::close_stdout()`: `dup2` of `/dev/null` onto fd 1, so the QML `StdioCollector` sees EOF while the holder keeps running.
  - `pub trait Clipboard { fn hold(&self, code: Zeroizing<String>, clear_after: Duration) -> Result<()>; }`
  - `pub struct WlCopy { program: PathBuf }`, default `/usr/bin/wl-copy`. `hold`:
    1. spawns `wl-copy --foreground --sensitive` with a cleared env plus the Wayland vars, and writes the code to its stdin, then closes it;
    2. drops and zeroizes the code;
    3. waits until the child exits or `clear_after` elapses;
    4. on the deadline, if the child is still alive (meaning it still owns the selection), sends SIGTERM and then runs `wl-copy --clear`;
    5. if the child exited earlier (another client took the selection), does nothing.
  - Rationale (put it in a short doc comment): no copy or hash of the code needs to outlive step 2.

- [ ] **Step 1: Write failing tests:**
  - `tests/hardening.rs::harden_sets_flags`: after `harden()`, `prctl(PR_GET_DUMPABLE) == 0` (through a `sys::is_dumpable()` helper) and `/proc/self/status` has `VmLck:` > 0 kB.
  - `tests/clipboard.rs` uses a fake wl-copy script written by the test into a tempdir. It records its stdin to a file and sleeps, or exits immediately, depending on a mode argument.
    - `holder_kills_owner_at_deadline` (`clear_after` 300 ms): the fake is killed and the clear command runs.
    - `holder_leaves_newer_clipboard_alone`: the fake exits at 100 ms; no clear runs.
    - `code_reaches_stdin_not_argv`: the recorded argv of the fake contains no digits of the code.
- [ ] **Step 2:** Run. Expected: FAIL.
- [ ] **Step 3:** Implement `sys.rs` (the only `unsafe`) and `clipboard.rs`. `WlCopy` takes its program path in its constructor so tests can inject the fake.
- [ ] **Step 4:** Run. Expected: PASS. Also run `ulimit -l 8192` and then `cargo test --test hardening` to check that 8 MiB is enough.
- [ ] **Step 5:** Commit: `"Add process hardening and self-clearing clipboard holder"`.
- [ ] **Step 6:** Code review and security review. Fix, then commit.

### Task 9: CLI, `check`/`copy`/`prefs`/demo, and live verification

**Files:**
- Create: `helper/src/cli.rs`, `helper/src/prefs.rs`, `helper/src/demo.rs`, `helper/tests/cli.rs`
- Modify: `helper/src/main.rs`, `helper/src/app.rs`

**Interfaces:**
- Consumes: everything above.
- Produces the **protocol**, which Task 10 depends on exactly. Every reply includes `ok` and `protocol`.
  - `pa-helper version` → `{"version":"0.1.0"}`
  - `pa-helper check` → `{"status":"READY"|<ERROR_CODE>,"vaultMtime":<u64|null>}`. It never decrypts or prompts. It stops at the first failing step: vault found, then storageKey readable with source 0, then `lock_state` = Unlocked.
  - `pa-helper codes [--only <id>] [--allow-prompt] [--demo]` → `{"now":<u64>,"entries":[EntryView…]}`
  - `pa-helper copy <id> [--clear-after <5..=120>] [--demo]` → `{}`.
    - Code choice: the current code, or the next one if `remaining < 5`.
    - Prints the reply, then `close_stdout()` and `detach_session()`, then `Clipboard::hold`.
  - `pa-helper prefs get` → `{"pinned":[id…],"recent":[id…],"privacy":bool}`
  - `pa-helper prefs set`: reads that same JSON from stdin (max 64 KiB). Validates every id. `recent` is capped at 5 and `pinned` at 100.
    - File: `$XDG_STATE_HOME` (absolute) or `~/.local/state`, joined with `sviat.proton-authenticator/prefs.json`.
    - Dir created 0700 (an existing dir with other perms → fix with chmod).
    - Write to `prefs.json.tmp` opened with `O_CREAT|O_EXCL|O_NOFOLLOW` at 0600, fsync, rename.
    - Reads use `O_NOFOLLOW`.
  - `--demo` uses fixed public RFC seeds for six fake accounts (GitHub, Proton, Google, AWS, Discord, Tailscale; one with 8 digits, one Steam). It never touches the vault or the keyring.
  - Unknown command or flag → `INVALID_ARGUMENT`. A global 10 s watchdog thread prints `TIMEOUT` and exits 1. The watchdog is cancelled before `copy` starts holding, and the holder has its own deadline.

- [ ] **Step 1: Write failing tests** in `tests/cli.rs`, running the built binary via `env!("CARGO_BIN_EXE_pa-helper")`:
  - `version_reply`;
  - `unknown_command_is_invalid_argument`;
  - `bad_id_is_invalid_argument` (`copy '../x'`);
  - `demo_codes_shape`: 6 entries, no `secret` substring in stdout;
  - `prefs_roundtrip_and_perms` (`XDG_STATE_HOME` = tempdir; file mode 0600, dir 0700);
  - `prefs_rejects_symlink` (pre-create `prefs.json` as a symlink → error, target untouched);
  - `check_without_vault` (`HOME` = empty tempdir → `status == "VAULT_NOT_FOUND"`).
- [ ] **Step 2:** Run. Expected: FAIL.
- [ ] **Step 3:** Implement `cli.rs` (hand-written parser), `prefs.rs`, `demo.rs`, and wire `main.rs`: `harden()`, then parse, then dispatch, then render.
- [ ] **Step 4:** Run the full suite. Expected: PASS.
- [ ] **Step 5: Live verification** on the user's real vault. Print nothing secret: for codes, compare them by eye in the terminal and then clear it.
  - [ ] `cargo build --release --locked`, then `target/release/pa-helper check` → `"status":"READY"`.
  - [ ] Run `pa-helper codes | jq '.entries | length'`, then `jq '.entries[] | {issuer, kind}'`. Expected: 33 entries, kinds plausible. Open the official app; the user confirms that 2–3 codes match.
  - [ ] Check the hardening while the process is alive: `pa-helper copy <id> --clear-after 30 &`, then `grep -E 'VmLck' /proc/$!/status` (> 0) and `cat /proc/$!/cmdline | tr '\0' ' '` (no code). After 30 s the clipboard is empty and Omarchy clipboard history doesn't contain the code.
  - [ ] Run `strace -f -e trace=openat,connect,sendto,write -o <scratchpad>/st.txt target/release/pa-helper codes >/dev/null` and check the trace. Expected:
    - no `openat` with `O_WRONLY`/`O_CREAT` outside `/dev/null`;
    - `connect` only to the D-Bus session socket, from the child processes;
    - no secret bytes in any `write`. Grep for the base32 alphabet runs of length ≥ 16; expect none.
- [ ] **Step 6:** Commit: `"Add CLI protocol, prefs store and demo mode"`.
- [ ] **Step 7:** Code review and security review. Fix, then commit.

### Task 10: Plugin skeleton: manifest, install script, Service, bar indicator

**Files:**
- Create: `manifest.json`, `install.sh`, `Service.qml`, `HelperClient.qml`, `indicators/ProtonAuth.qml`, `Model.js` (stub with `pluginDirFromUrl`, copied in spirit from nightlight's `Model.js`)
- Modify: `.gitignore` (add `/bin/pa-helper`, already present)

**Interfaces:**
- Consumes: the Task 9 protocol.
- Produces:
  - `manifest.json`:
    - `schemaVersion 1`, `id "sviat.proton-authenticator"`, `name "Proton Authenticator"`, `version "0.1.0"`, `author "devSviat"`, `license "MIT"`;
    - `kinds ["service","bar-widget"]`, `entryPoints {service:"Service.qml", barWidget:"Panel.qml"}`;
    - `barWidget`: `displayName`, `category "Security"`, aliases (`2fa`, `totp`, `otp`, `authenticator`, `proton`), `allowMultiple false`, `defaultSection "right"`;
    - `schema`: `clearClipboardSeconds` integer 5–120 step 5 default 20; `closeOnCopy` boolean default true; `staleHours` integer 1–168 default 24.
  - `install.sh`:
    - `set -euo pipefail`. Refuses to run when `$0` is not a file inside the repo (blocks `curl | bash`). Never uses sudo.
    - Checks `cargo`, `/usr/bin/secret-tool`, `/usr/bin/gdbus`, `/usr/bin/wl-copy` (`--sensitive` in its `--help`), `/usr/lib/libsqlite3.so`, `/usr/bin/proton-authenticator`, and prints the pacman/AUR package name for each missing one.
    - Runs `CARGO_TARGET_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/sviat.proton-authenticator/target" cargo build --release --locked --manifest-path helper/Cargo.toml`, then `install -m 0755` to `bin/pa-helper`, then runs `bin/pa-helper version` and checks `protocol == 1`.
  - `HelperClient.qml`: `function call(args: list, stdinText: string, onReply: function)`.
    - Uses a pool of `Process` objects, with the command `[pluginDir + "/bin/pa-helper", ...args]`.
    - Collects stdout up to 1 MiB, then `JSON.parse`. A parse failure or `protocol !== 1` → `{ok:false,error:"HELPER_OUTDATED"}`. A missing binary → `{ok:false,error:"HELPER_MISSING"}`.
    - Never logs replies.
  - `Service.qml` (singleton pattern as in `~/Projects/omarchy-nightlight/Service.qml`):
    - `property string status` (`"LOADING"` | `"READY"` | an error code);
    - `property var entries: []`, `property int now`, `property var prefs`, `property int vaultMtime`;
    - methods: `refreshStatus()`, `loadCodes(onlyId)`, `clearCodes()`, `copy(id)`, `unlock()`, `openProton()`, `setPinned(id, bool)`, `noteRecent(id)`, `setPrivacy(bool)`;
    - `IpcHandler { target: "sviat.proton-authenticator" }` exposing `status()`, the same shape as nightlight.
    - Polls `check` every 60 s while the panel is closed and every 5 s while it is open. A `vaultMtime` change while open → `loadCodes`.
  - `indicators/ProtonAuth.qml`: visual only (`BarIndicator`), glyph by status (`READY` "󰯄", `KEYRING_LOCKED` "󰌾", anything else "󰀦"), tooltip with a one-line English explanation per error code. Click → `omarchy-shell shell toggle sviat.proton-authenticator`.

- [ ] **Step 1:** Write `manifest.json` and run `omarchy-plugin-validate .`. Expected: valid.
- [ ] **Step 2:** Write `install.sh`. Run `bash install.sh`. Expected: builds, and `bin/pa-helper version` prints protocol 1. Run `bash -c "$(cat install.sh)"`. Expected: refuses.
- [ ] **Step 3:** Write `HelperClient.qml`, `Service.qml` and the indicator. Link the plugin for development: `ln -s ~/Projects/omarchy-proton-authenticator ~/.config/omarchy/plugins/sviat.proton-authenticator`, then `omarchy-shell shell rescanPlugins` and `omarchy plugin enable sviat.proton-authenticator`.
- [ ] **Step 4:** Verify `omarchy-shell sviat.proton-authenticator status` → `READY`. Rename `bin/pa-helper` temporarily → the indicator shows `HELPER_MISSING`. Restore it.
- [ ] **Step 5:** Commit: `"Add plugin manifest, installer, service and bar indicator"`.
- [ ] **Step 6:** Code review and security review (QML: no reply logging, absolute helper path, no shell-string commands). Fix, then commit.

### Task 11: `Model.js` — search, ordering, formatting

**Files:**
- Modify: `Model.js`
- Create: `tests/model.test.mjs`, `tests/load-model.mjs` (strips `.pragma library` and evaluates the file as a module for node)

**Interfaces:**
- Produces (pure functions):
  - `filterAndOrder(entries, query, prefs) -> entries`:
    - an empty query → pinned (in `prefs.pinned` order), then recent (in `prefs.recent` order, not already pinned), then the rest by issuer/account, case-insensitive;
    - a query → only matches, scored: issuer prefix 3 > word-start match 2 > subsequence 1, ties broken by the empty-query order.
  - `fuzzyScore(text, query) -> int` (0 = no match).
  - `groupCode(code) -> string`: 6 → `"482 913"`, 7 → `"482 9130"`, 8 → `"4829 1307"`, otherwise unchanged.
  - `isUrgent(remaining) -> bool` (`remaining <= 5`).
  - `ageLabel(nowSec, mtimeSec) -> string`: `"just now"` under 60 s, `"N min ago"`, `"N h ago"`, `"N d ago"`.
  - `isStale(nowSec, mtimeSec, staleHours) -> bool`.
  - `pluginDirFromUrl(url) -> string`.

- [ ] **Step 1: Write failing tests** with `node --test tests/`:
  - `gh` matches GitHub before `Gitea (home)` (word-start vs subsequence);
  - pinned first;
  - recent after pinned without duplicates;
  - `groupCode` cases;
  - `ageLabel` boundaries 59 s / 60 s / 3599 s / 3600 s / 86400 s;
  - `isStale` with 24 h.
- [ ] **Step 2:** Run `node --test tests/`. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run. Expected: PASS.
- [ ] **Step 5:** Commit: `"Add search, ordering and formatting model"`.
- [ ] **Step 6:** Code review and security review. Fix, then commit.

### Task 12: Panel UI (layout A)

**Files:**
- Create: `Panel.qml`, `components/EntryRow.qml`, `components/SearchField.qml`, `components/PanelFooter.qml`, `components/EmptyState.qml`, `components/CountdownRing.qml`

**Interfaces:**
- Consumes: the `Service.qml` API (Task 10) and `Model.js` (Task 11).
- Behaviour (spec section "UX and UI"; the mockup is in `.superpowers/brainstorm/*/content/layout.html`, which is local only):
  - `Panel { moduleName/ipcTarget: "sviat.proton-authenticator"; manageIpc: false }`, as in nightlight.
  - On open: `Service.loadCodes(privacy ? selectedId : "")`, then focus the search field.
  - On close: `Service.clearCodes()`.
  - Each row: an initial badge (first letter of the issuer), the issuer, the elided account, the grouped code in `bar.fontFamily` at a large size, and `CountdownRing`.
  - Urgent → the code and ring use `bar.urgent`.
  - `next_code` is shown only on the selected row while urgent.
  - Unsupported entries show `"unsupported"` dimmed and cannot be copied.
  - Keys:
    - `Enter` → `Service.copy(id)`. Shows `Copied ✓` for 600 ms, then closes if `closeOnCopy`;
    - `↑/↓`, `Ctrl+J/K`, `PgUp/PgDn` move the selection;
    - `Esc` clears the query, or closes if it is already empty;
    - `Ctrl+P` pins or unpins;
    - `Ctrl+H` toggles privacy.
  - Privacy on: codes are hidden as `••• •••` on non-selected rows. The Service loads with `--only <selectedId>`, debounced 150 ms on selection change, so hidden codes never enter QML.
  - Refresh: a single `Timer` fires at the smallest `remaining` + 300 ms and calls `loadCodes`. A 1 s local tick updates the rings and remaining time without spawning the helper.
  - Footer: `Updated <ageLabel>`, a `Sync` action, and the hint `↵ copy`. When `isStale`, the footer shows `Not synced for <ageLabel> — Sync`.
  - Empty and error states (`EmptyState`), keyed by `Service.status`:
    - `KEYRING_LOCKED` → "Keyring is locked" + `Unlock` (`Service.unlock()` → `codes --allow-prompt`);
    - `VAULT_NOT_FOUND` → "Proton Authenticator not found" + `Open Proton`;
    - `VAULT_FORMAT_CHANGED`/`DECRYPT_FAILED` → "Vault format not recognised — the app may have updated" + `Open Proton`;
    - `APP_LOCKED` → "App lock is on — this plugin can't read a password-locked vault";
    - `UNSAFE_KEY_STORAGE` → "Proton is storing its key outside the keyring — open Proton and fix keyring access";
    - `HELPER_MISSING`/`HELPER_OUTDATED` → "Run install.sh" with the exact path;
    - no entries → "No accounts yet" + `Open Proton`.
  - Colors and fonts only from `bar.*` / `qs.Commons` `Style`, as nightlight does. No hard-coded hex colors.

- [ ] **Step 1:** Build the panel against `--demo` (a temporary `Service` flag `demo: true`, set from `setting("demo", false)`, not in the published schema). Run `omarchy-shell shell toggle sviat.proton-authenticator`. Expected: 6 demo rows, typing filters, Enter copies (the code is visible in `wl-paste`, and is absent from Omarchy clipboard history).
- [ ] **Step 2:** Walk through each key binding and each empty state, forcing each one by renaming the vault dir or binary, or by locking the keyring with `/usr/bin/gdbus call --session --dest org.freedesktop.secrets --object-path /org/freedesktop/secrets --method org.freedesktop.Secret.Service.Lock "[objectpath '/org/freedesktop/secrets/collection/login']"`. Expected: each shows its copy, and the locked state never pops a prompt until `Unlock` is pressed. Locking the login collection also affects other apps, such as Proton VPN. Tell the user before doing it, and unlock right after.
- [ ] **Step 3:** Switch to the real vault. Expected: the panel opens instantly and shows the 33 entries. Privacy mode keeps hidden codes out of the model; check with a temporary `Service.entries.length` debug, then remove it.
- [ ] **Step 4:** Commit: `"Add keyboard-driven panel UI"`.
- [ ] **Step 5:** Code review and security review (visual check with the user on the Abstract Black theme). Fix, then commit.

### Task 13: Sync button and tray behaviour

**Files:**
- Modify: `Service.qml` (`openProton()`)

- [ ] **Step 1:** Investigate background start. Run `/usr/bin/proton-authenticator --help` and check `strings` for CLI flags such as `--hidden`/`--minimized`, and the app's Settings UI for "start minimized" / "close to tray". Record the finding in `docs/notes/proton-tray.md`.
- [ ] **Step 2:** Implement `openProton()` with `Quickshell.execDetached(["/usr/bin/proton-authenticator", ...flagsIfAny])`. If no background mode exists, it simply opens the window.
- [ ] **Step 3:** Verify: add an account on the phone, press `Sync`, and once the app has synced, the panel (still open) shows the new entry within about 5 s without a shell restart.
- [ ] **Step 4:** Commit: `"Add sync action"`.
- [ ] **Step 5:** Code review and security review. Fix, then commit.

### Task 14: README, hotkey, release audit, PR

**Files:**
- Create: `README.md`, `preview.png` (from `--demo` only)
- Modify: `~/.config/hypr/bindings.lua` (user machine, not the repo)

- [ ] **Step 1:** Write `README.md`:
  - what the plugin does and why;
  - an honest threat model (spec "Non-goals"): it does not protect against malware running as the same user; a vault protected by the app password is reported as `APP_LOCKED`;
  - dependencies, `install.sh`, and the `omarchy plugin add` flow with "Manual setup";
  - how sync works;
  - what to do after a Proton update breaks the format;
  - the recommended hotkey `o.bind("SUPER + ALT + A", "Proton Authenticator", "omarchy-shell shell toggle sviat.proton-authenticator")`, with a note to check that it is free with `omarchy menu keybindings --print`;
  - a security design summary: helper hardening, no network, clipboard holder.
- [ ] **Step 2:** Add that `o.bind` line to `~/.config/hypr/bindings.lua`, near the other personal bindings. Verify `hyprctl binds -j` shows `SUPER+ALT+A`, and that pressing it toggles the panel.
- [ ] **Step 3:** Run the full-repo security audit (the `security-audit` skill or a `claude-security` scan) plus the manual checklist from Task 9 Step 5 against the release build. Fix the findings.
- [ ] **Step 4:** Test the real catalog path once:
  - run `omarchy plugin add https://github.com/devSviat/omarchy-proton-authenticator` into a scratch `XDG_CONFIG_HOME`, or temporarily replace the symlink and restore it after;
  - run `install.sh` from that clone;
  - Expected: works, and `omarchy-plugin-validate` passes.
- [ ] **Step 5:** Commit and push `dev`. Open the PR `dev → main` (`gh pr create --base main --head dev`) with a summary and test evidence. **Do not merge.** The user merges it.
