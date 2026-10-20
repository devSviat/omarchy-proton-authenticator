use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use zeroize::Zeroizing;

use crate::crypto::{derive_storage_key, ItemCipher};
use crate::domain::{build_entry, view, EntryView, ItemPlaintext};
use crate::error::{ErrorCode, Result};
use crate::vault::{EncryptedItem, Snapshot, StorageKeyRef, VaultSource};

const SALT_LEN: usize = 32;
const SOURCE_KEYRING: i32 = 0;
const SOURCE_PASSWORD: i32 = 1;
const SOURCE_FALLBACK: i32 = 2;
const KEY_ID_MAX_LEN: usize = 128;
const ITEM_ID_MAX_LEN: usize = 128;
/// A code with less time left than this is likely to expire before it is
/// pasted, so `copy` takes the next one instead.
const COPY_MIN_REMAINING: u64 = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockState {
    Unlocked,
    Locked,
    Missing,
}

pub trait KeyProvider {
    fn lock_state(&self, key_id: &str) -> Result<LockState>;
    fn root_key(&self, key_id: &str) -> Result<Zeroizing<[u8; 32]>>;
}

#[derive(Debug)]
pub struct CodesRequest {
    pub only: Option<String>,
    pub allow_prompt: bool,
    pub unix: u64,
}

/// Matches `^[A-Za-z0-9_][A-Za-z0-9_.:-]{0,127}$`.
fn valid_key_id(id: &str) -> bool {
    let bytes = id.as_bytes();
    let Some((first, rest)) = bytes.split_first() else {
        return false;
    };
    bytes.len() <= KEY_ID_MAX_LEN
        && (first.is_ascii_alphanumeric() || *first == b'_')
        && rest
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b':' | b'-'))
}

/// Matches `^[A-Za-z0-9._:-]{1,128}$` without a leading `-`, so an id can
/// never be mistaken for a command-line flag.
pub fn valid_item_id(id: &str) -> bool {
    (1..=ITEM_ID_MAX_LEN).contains(&id.len())
        && !id.starts_with('-')
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'))
}

fn check_source(source: i32) -> Result<()> {
    match source {
        SOURCE_KEYRING => Ok(()),
        SOURCE_PASSWORD => Err(ErrorCode::AppLocked),
        SOURCE_FALLBACK => Err(ErrorCode::UnsafeKeyStorage),
        _ => Err(ErrorCode::VaultFormatChanged),
    }
}

fn decode_view(cipher: &ItemCipher, item: EncryptedItem, unix: u64) -> Result<EntryView> {
    let plain = cipher.decrypt(&item.data)?;
    let parsed: ItemPlaintext =
        serde_json::from_slice(&plain).map_err(|_| ErrorCode::VaultFormatChanged)?;
    drop(plain);
    let entry = build_entry(item.id, item.issuer, item.name, parsed);
    Ok(view(&entry, unix))
}

/// The storage-key record, checked to be keyring-backed and well formed.
fn usable_key_ref(snapshot: &dyn Snapshot) -> Result<StorageKeyRef> {
    let key_ref = snapshot.key_ref()?;
    check_source(key_ref.source)?;
    if key_ref.salt.len() != SALT_LEN || !valid_key_id(keyring_id(&key_ref)) {
        return Err(ErrorCode::VaultFormatChanged);
    }
    Ok(key_ref)
}

/// Vaults created before 1.1.4 have no `adapterKeyId` and use `id` instead.
fn keyring_id(key_ref: &StorageKeyRef) -> &str {
    key_ref.adapter_key_id.as_deref().unwrap_or(&key_ref.id)
}

fn require_unlocked(keys: &dyn KeyProvider, key_id: &str) -> Result<()> {
    match keys.lock_state(key_id)? {
        LockState::Unlocked => Ok(()),
        LockState::Locked => Err(ErrorCode::KeyringLocked),
        LockState::Missing => Err(ErrorCode::KeyNotFound),
    }
}

pub fn sort_entries(views: &mut [EntryView]) {
    views.sort_by_cached_key(|v| (v.issuer.to_lowercase(), v.account.to_lowercase()));
}

pub struct CheckReport {
    pub status: Result<()>,
    pub vault_mtime: Option<u64>,
}

/// Readiness without decrypting or prompting. Stops at the first failing
/// step: vault found, storage key keyring-backed, keyring item unlocked, then
/// every path in `programs` executable.
pub fn check(vault: &dyn VaultSource, keys: &dyn KeyProvider, programs: &[&Path]) -> CheckReport {
    let vault_mtime = match vault.modified() {
        Ok(mtime) => mtime,
        Err(e) => {
            return CheckReport {
                status: Err(e),
                vault_mtime: None,
            }
        }
    };
    let status = vault
        .snapshot()
        .and_then(|snapshot| usable_key_ref(&*snapshot))
        .and_then(|key_ref| require_unlocked(keys, keyring_id(&key_ref)))
        .and_then(|()| {
            if programs.iter().all(|p| is_executable(p)) {
                Ok(())
            } else {
                Err(ErrorCode::DependencyMissing)
            }
        });
    CheckReport {
        status,
        vault_mtime: Some(vault_mtime),
    }
}

fn is_executable(path: &Path) -> bool {
    std::fs::metadata(path).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

/// The code `copy` puts on the clipboard.
pub fn copy_code(mut view: EntryView) -> Result<Zeroizing<String>> {
    let current = Zeroizing::new(view.code.take());
    let next = Zeroizing::new(view.next_code.take());
    let mut chosen = if view.remaining < COPY_MIN_REMAINING {
        next
    } else {
        current
    };
    chosen
        .take()
        .map(Zeroizing::new)
        .ok_or(ErrorCode::InvalidArgument)
}

pub fn codes(
    vault: &dyn VaultSource,
    keys: &dyn KeyProvider,
    req: &CodesRequest,
) -> Result<Vec<EntryView>> {
    let snapshot = vault.snapshot()?;
    let key_ref = usable_key_ref(&*snapshot)?;
    let key_id = keyring_id(&key_ref);

    let wanted = |item: &EncryptedItem| req.only.as_ref().is_none_or(|only| *only == item.id);
    // The snapshot is walked twice: ids are validated before the keyring is
    // touched, and ciphertexts are decrypted one at a time instead of all
    // being held next to the 2 MiB image.
    let mut matching = 0usize;
    snapshot.for_each_item(&mut |item| {
        if !valid_item_id(&item.id) {
            return Err(ErrorCode::VaultFormatChanged);
        }
        matching += usize::from(wanted(&item));
        Ok(())
    })?;
    if matching == 0 {
        return match req.only {
            Some(_) => Err(ErrorCode::ItemNotFound),
            None => Ok(Vec::new()),
        };
    }

    if !req.allow_prompt {
        require_unlocked(keys, key_id)?;
    }

    let root = keys.root_key(key_id)?;
    let storage_key = derive_storage_key(&root, &key_ref.salt)?;
    drop(root);
    let cipher = ItemCipher::new(&storage_key);
    drop(storage_key);

    let mut views = Vec::with_capacity(matching);
    snapshot.for_each_item(&mut |item| {
        if wanted(&item) {
            views.push(decode_view(&cipher, item, req.unix)?);
        }
        Ok(())
    })?;
    sort_entries(&mut views);
    Ok(views)
}
