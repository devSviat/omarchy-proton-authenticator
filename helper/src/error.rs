use std::fmt;

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
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

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::error::Error for ErrorCode {}

pub type Result<T> = std::result::Result<T, ErrorCode>;
