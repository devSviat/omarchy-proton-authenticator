use std::fmt;

use serde::{Serialize, Serializer};

/// Serialized as [`ErrorCode::as_str`], so the wire name has one source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    VaultNotFound,
    VaultBusy,
    VaultFormatChanged,
    KeyringLocked,
    KeyringUnavailable,
    KeyNotFound,
    DecryptFailed,
    AppLocked,
    UnsafeKeyStorage,
    DependencyMissing,
    ItemNotFound,
    InvalidArgument,
    MemlockFailed,
    Timeout,
    OutputTooLarge,
    Internal,
}

impl ErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::VaultNotFound => "VAULT_NOT_FOUND",
            Self::VaultBusy => "VAULT_BUSY",
            Self::VaultFormatChanged => "VAULT_FORMAT_CHANGED",
            Self::KeyringLocked => "KEYRING_LOCKED",
            Self::KeyringUnavailable => "KEYRING_UNAVAILABLE",
            Self::KeyNotFound => "KEY_NOT_FOUND",
            Self::DecryptFailed => "DECRYPT_FAILED",
            Self::AppLocked => "APP_LOCKED",
            Self::UnsafeKeyStorage => "UNSAFE_KEY_STORAGE",
            Self::DependencyMissing => "DEPENDENCY_MISSING",
            Self::ItemNotFound => "ITEM_NOT_FOUND",
            Self::InvalidArgument => "INVALID_ARGUMENT",
            Self::MemlockFailed => "MEMLOCK_FAILED",
            Self::Timeout => "TIMEOUT",
            Self::OutputTooLarge => "OUTPUT_TOO_LARGE",
            Self::Internal => "INTERNAL",
        }
    }
}

impl Serialize for ErrorCode {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::error::Error for ErrorCode {}

pub type Result<T> = std::result::Result<T, ErrorCode>;

#[cfg(test)]
mod tests {
    use super::ErrorCode::{self, *};

    const ALL: [ErrorCode; 16] = [
        VaultNotFound,
        VaultBusy,
        VaultFormatChanged,
        KeyringLocked,
        KeyringUnavailable,
        KeyNotFound,
        DecryptFailed,
        AppLocked,
        UnsafeKeyStorage,
        DependencyMissing,
        ItemNotFound,
        InvalidArgument,
        MemlockFailed,
        Timeout,
        OutputTooLarge,
        Internal,
    ];

    /// Exhaustive on purpose: a new variant fails to compile here until it is
    /// added to `ALL` as well.
    fn position(code: ErrorCode) -> usize {
        match code {
            VaultNotFound => 0,
            VaultBusy => 1,
            VaultFormatChanged => 2,
            KeyringLocked => 3,
            KeyringUnavailable => 4,
            KeyNotFound => 5,
            DecryptFailed => 6,
            AppLocked => 7,
            UnsafeKeyStorage => 8,
            DependencyMissing => 9,
            ItemNotFound => 10,
            InvalidArgument => 11,
            MemlockFailed => 12,
            Timeout => 13,
            OutputTooLarge => 14,
            Internal => 15,
        }
    }

    fn screaming_snake(name: &str) -> String {
        let mut out = String::new();
        for (i, c) in name.char_indices() {
            if c.is_ascii_uppercase() && i > 0 {
                out.push('_');
            }
            out.push(c.to_ascii_uppercase());
        }
        out
    }

    #[test]
    fn every_variant_serializes_as_its_screaming_name() {
        for (i, code) in ALL.into_iter().enumerate() {
            assert_eq!(position(code), i);
            let name = code.as_str();
            assert_eq!(name, screaming_snake(&format!("{code:?}")));
            assert_eq!(serde_json::to_string(&code).unwrap(), format!("\"{name}\""));
            assert_eq!(code.to_string(), name);
        }
    }
}
