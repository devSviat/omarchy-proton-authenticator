//! Fake accounts for screenshots and UI work. The seeds are the public test
//! vectors of RFC 4226 and RFC 6238; nothing here touches the vault or keyring.
//! No two accounts share seed, algorithm and period, so no code is a suffix of
//! another on screenshots.

use crate::app::{sort_entries, sort_private};
use crate::domain::{view, Entry, EntryView, HiddenEntry, OtpKind, PrivateEntry, Secret};
use crate::error::{ErrorCode, Result};
use crate::otp::Algorithm;

const SEED_SHA1: &[u8] = b"12345678901234567890";
const SEED_SHA256: &[u8] = b"12345678901234567890123456789012";
const SEED_SHA512: &[u8] = b"1234567890123456789012345678901234567890123456789012345678901234";

/// Fixed so a UI that reloads on a changed vault mtime does not reload on
/// every demo poll. 2026-01-01T00:00:00Z.
pub const VAULT_MTIME: u64 = 1_767_225_600;

struct DemoAccount {
    id: &'static str,
    issuer: &'static str,
    account: &'static str,
    kind: OtpKind,
    seed: &'static [u8],
}

const fn totp(alg: Algorithm, digits: u32, period: u64) -> OtpKind {
    OtpKind::Totp {
        alg,
        digits,
        period,
    }
}

const ACCOUNTS: [DemoAccount; 6] = [
    DemoAccount {
        id: "demo-github",
        issuer: "GitHub",
        account: "octocat@example.com",
        kind: totp(Algorithm::Sha1, 6, 30),
        seed: SEED_SHA1,
    },
    DemoAccount {
        id: "demo-proton",
        issuer: "Proton",
        account: "alex@proton.example",
        kind: totp(Algorithm::Sha256, 6, 30),
        seed: SEED_SHA256,
    },
    DemoAccount {
        id: "demo-google",
        issuer: "Google",
        account: "alex@example.com",
        kind: totp(Algorithm::Sha512, 6, 30),
        seed: SEED_SHA512,
    },
    DemoAccount {
        id: "demo-aws",
        issuer: "AWS",
        account: "root@example.com",
        kind: totp(Algorithm::Sha512, 8, 60),
        seed: SEED_SHA512,
    },
    DemoAccount {
        id: "demo-discord",
        issuer: "Discord",
        account: "alex#0001",
        kind: OtpKind::Steam,
        seed: SEED_SHA1,
    },
    DemoAccount {
        id: "demo-tailscale",
        issuer: "Tailscale",
        account: "alex@example.com",
        kind: totp(Algorithm::Sha1, 6, 60),
        seed: SEED_SHA1,
    },
];

fn account_view(a: &DemoAccount, unix: u64) -> EntryView {
    let entry = Entry {
        id: a.id.to_owned(),
        issuer: a.issuer.to_owned(),
        account: a.account.to_owned(),
        kind: a.kind,
        secret: Some(Secret::from(a.seed.to_vec())),
    };
    view(&entry, unix)
}

/// Views of the demo accounts at `unix`, sorted like real vault entries.
pub fn entries(unix: u64) -> Vec<EntryView> {
    let mut views: Vec<EntryView> = ACCOUNTS.iter().map(|a| account_view(a, unix)).collect();
    sort_entries(&mut views);
    views
}

/// The demo counterpart of [`crate::app::codes_private`].
pub fn private_entries(unix: u64, reveal: Option<&str>) -> Result<Vec<PrivateEntry>> {
    if reveal.is_some_and(|id| ACCOUNTS.iter().all(|a| a.id != id)) {
        return Err(ErrorCode::ItemNotFound);
    }
    let mut entries: Vec<PrivateEntry> = ACCOUNTS
        .iter()
        .map(|a| {
            if reveal == Some(a.id) {
                PrivateEntry::Revealed(account_view(a, unix))
            } else {
                PrivateEntry::Hidden(HiddenEntry::new(a.id.to_owned(), a.issuer, a.account))
            }
        })
        .collect();
    sort_private(&mut entries);
    Ok(entries)
}
