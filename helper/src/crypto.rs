use aes_gcm::aead::AeadInOut;
use aes_gcm::{Aes256Gcm, KeyInit};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use crate::error::{ErrorCode, Result};

const IV_LEN: usize = 12;
const TAG_LEN: usize = 16;
const STORAGE_KEY_INFO: &[u8] = b"authenticator;storage-key";
const ITEM_AAD: &[u8] = b"authenticator;item";

pub fn derive_storage_key(root: &[u8; 32], salt: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let mut key = Zeroizing::new([0u8; 32]);
    let (mut prk, hkdf) = Hkdf::<Sha256>::extract(Some(salt), root);
    prk.as_mut_slice().zeroize();
    hkdf.expand(STORAGE_KEY_INFO, &mut *key)
        .map_err(|_| ErrorCode::Internal)?;
    Ok(key)
}

pub struct ItemCipher(Aes256Gcm);

impl ItemCipher {
    pub fn new(key: &[u8; 32]) -> Self {
        Self(Aes256Gcm::new(key.into()))
    }

    pub fn decrypt(&self, data: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        if data.len() < IV_LEN + TAG_LEN {
            return Err(ErrorCode::DecryptFailed);
        }
        let (iv, sealed) = data.split_at(IV_LEN);
        let nonce = iv.try_into().map_err(|_| ErrorCode::DecryptFailed)?;
        let mut buffer = Zeroizing::new(sealed.to_vec());
        self.0
            .decrypt_in_place(nonce, ITEM_AAD, &mut *buffer)
            .map_err(|_| ErrorCode::DecryptFailed)?;
        Ok(buffer)
    }
}
