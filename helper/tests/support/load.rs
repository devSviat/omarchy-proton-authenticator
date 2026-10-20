#![allow(dead_code)]

use pa_helper::error::Result;
use pa_helper::vault::{EncryptedItem, StorageKeyRef, VaultSource};

/// Collects a whole snapshot. Test-only: the shipped paths stream items to
/// stay inside the memlock budget.
pub trait LoadAll {
    fn load(&self) -> Result<(StorageKeyRef, Vec<EncryptedItem>)>;
}

impl<T: VaultSource + ?Sized> LoadAll for T {
    fn load(&self) -> Result<(StorageKeyRef, Vec<EncryptedItem>)> {
        let snapshot = self.snapshot()?;
        let key_ref = snapshot.key_ref()?;
        let mut items = Vec::new();
        snapshot.for_each_item(&mut |item| {
            items.push(item);
            Ok(())
        })?;
        Ok((key_ref, items))
    }
}
