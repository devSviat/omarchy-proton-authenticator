use aes_gcm::aead::AeadInOut;
use aes_gcm::{Aes256Gcm, KeyInit};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::{ErrorCode, Result};

const IV_LEN: usize = 12;
const TAG_LEN: usize = 16;
const STORAGE_KEY_INFO: &[u8] = b"authenticator;storage-key";
const ITEM_AAD: &[u8] = b"authenticator;item";

pub fn derive_storage_key(root: &[u8; 32], salt: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(salt), root)
        .expand(STORAGE_KEY_INFO, &mut *key)
        .expect("32 bytes is within the HKDF-SHA256 output limit");
    key
}

pub fn decrypt_item(key: &[u8; 32], data: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if data.len() < IV_LEN + TAG_LEN {
        return Err(ErrorCode::DecryptFailed);
    }
    let (iv, sealed) = data.split_at(IV_LEN);
    let mut buffer = Zeroizing::new(sealed.to_vec());
    let cipher = Aes256Gcm::new(key.into());
    let nonce = iv.try_into().map_err(|_| ErrorCode::DecryptFailed)?;
    cipher
        .decrypt_in_place(nonce, ITEM_AAD, &mut *buffer)
        .map_err(|_| ErrorCode::DecryptFailed)?;
    Ok(buffer)
}
