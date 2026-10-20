use zeroize::Zeroizing;

use crate::crypto::{derive_storage_key, ItemCipher};
use crate::domain::{build_entry, view, EntryView, ItemPlaintext};
use crate::error::{ErrorCode, Result};
use crate::vault::{EncryptedItem, VaultSource};

const SALT_LEN: usize = 32;
const SOURCE_KEYRING: i32 = 0;
const SOURCE_PASSWORD: i32 = 1;
const SOURCE_FALLBACK: i32 = 2;
const KEY_ID_MAX_LEN: usize = 128;
const ITEM_ID_MAX_LEN: usize = 128;

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

/// Matches `^[A-Za-z0-9._:-]{1,128}$`.
fn valid_item_id(id: &str) -> bool {
    (1..=ITEM_ID_MAX_LEN).contains(&id.len())
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

fn decode_view(cipher: &ItemCipher, item: &EncryptedItem, unix: u64) -> Result<EntryView> {
    let plain = cipher.decrypt(&item.data)?;
    let parsed: ItemPlaintext =
        serde_json::from_slice(&plain).map_err(|_| ErrorCode::VaultFormatChanged)?;
    drop(plain);
    let entry = build_entry(
        item.id.clone(),
        item.issuer.clone(),
        item.name.clone(),
        parsed,
    );
    Ok(view(&entry, unix))
}

pub fn codes(
    vault: &dyn VaultSource,
    keys: &dyn KeyProvider,
    req: &CodesRequest,
) -> Result<Vec<EntryView>> {
    let (key_ref, mut items) = vault.load()?;
    check_source(key_ref.source)?;
    if key_ref.salt.len() != SALT_LEN {
        return Err(ErrorCode::VaultFormatChanged);
    }
    let key_id = key_ref.adapter_key_id.as_deref().unwrap_or(&key_ref.id);
    if !valid_key_id(key_id) {
        return Err(ErrorCode::VaultFormatChanged);
    }

    if !items.iter().all(|i| valid_item_id(&i.id)) {
        return Err(ErrorCode::VaultFormatChanged);
    }

    if let Some(only) = &req.only {
        items.retain(|i| &i.id == only);
        if items.is_empty() {
            return Err(ErrorCode::ItemNotFound);
        }
    }
    if items.is_empty() {
        return Ok(Vec::new());
    }

    if !req.allow_prompt {
        match keys.lock_state(key_id)? {
            LockState::Unlocked => {}
            LockState::Locked => return Err(ErrorCode::KeyringLocked),
            LockState::Missing => return Err(ErrorCode::KeyNotFound),
        }
    }

    let root = keys.root_key(key_id)?;
    let storage_key = derive_storage_key(&root, &key_ref.salt)?;
    drop(root);
    let cipher = ItemCipher::new(&storage_key);
    drop(storage_key);

    let mut views = items
        .iter()
        .map(|item| decode_view(&cipher, item, req.unix))
        .collect::<Result<Vec<_>>>()?;
    views.sort_by_cached_key(|v| (v.issuer.to_lowercase(), v.account.to_lowercase()));
    Ok(views)
}
