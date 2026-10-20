use std::fmt;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::base32::base32_decode;
use crate::otp::{steam, totp, Algorithm, STEAM_PERIOD};
use crate::uri::parse_otpauth;

const LABEL_MAX_CHARS: usize = 256;
const DEFAULT_PERIOD: u64 = 30;
const MAX_PERIOD: u64 = 86_400;
const STEAM_DIGITS: u32 = 5;

pub struct Secret(Zeroizing<Vec<u8>>);

impl Secret {
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for Secret {
    fn from(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret([REDACTED])")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtpKind {
    Totp {
        alg: Algorithm,
        digits: u32,
        period: u64,
    },
    Steam,
    Unsupported,
}

#[derive(Debug)]
pub struct Entry {
    pub id: String,
    pub issuer: String,
    pub account: String,
    pub kind: OtpKind,
    pub secret: Option<Secret>,
}

#[derive(Deserialize)]
pub struct ItemPlaintext {
    #[serde(rename = "entryType")]
    pub entry_type: String,
    pub secret: Zeroizing<String>,
    #[serde(default)]
    pub period: Option<u64>,
    pub uri: Zeroizing<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EntryView {
    pub id: String,
    pub issuer: String,
    pub account: String,
    pub kind: &'static str,
    pub code: Option<String>,
    pub next_code: Option<String>,
    pub period: u64,
    pub digits: u32,
    pub remaining: u64,
}

/// An entry listed without its code, for privacy mode. The code fields are
/// unit-typed, so they always serialize as `null` and can never carry a code.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HiddenEntry {
    pub id: String,
    pub issuer: String,
    pub account: String,
    kind: (),
    code: (),
    next_code: (),
    period: (),
    digits: (),
    remaining: (),
}

impl HiddenEntry {
    pub fn new(id: String, issuer: &str, account: &str) -> Self {
        Self {
            id,
            issuer: truncate_label(issuer),
            account: truncate_label(account),
            kind: (),
            code: (),
            next_code: (),
            period: (),
            digits: (),
            remaining: (),
        }
    }
}

/// One row of `codes --private`: the revealed entry in full, every other one
/// hidden. Both variants serialize with the same keys.
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum PrivateEntry {
    Revealed(EntryView),
    Hidden(HiddenEntry),
}

impl PrivateEntry {
    /// `(id, issuer, account)`.
    pub fn sort_fields(&self) -> (&str, &str, &str) {
        match self {
            Self::Revealed(v) => (&v.id, &v.issuer, &v.account),
            Self::Hidden(h) => (&h.id, &h.issuer, &h.account),
        }
    }
}

fn unsupported(id: String, issuer: String, account: String) -> Entry {
    Entry {
        id,
        issuer,
        account,
        kind: OtpKind::Unsupported,
        secret: None,
    }
}

fn totp_kind(p: &ItemPlaintext) -> Option<OtpKind> {
    let params = parse_otpauth(&p.uri)?;
    if params.is_hotp || !(6..=8).contains(&params.digits) {
        return None;
    }
    let period = p.period.or(params.period).unwrap_or(DEFAULT_PERIOD);
    if !(1..=MAX_PERIOD).contains(&period) {
        return None;
    }
    Some(OtpKind::Totp {
        alg: params.alg,
        digits: params.digits,
        period,
    })
}

pub fn build_entry(id: String, issuer: String, account: String, p: ItemPlaintext) -> Entry {
    let kind = match p.entry_type.as_str() {
        "Totp" => totp_kind(&p),
        "Steam" => Some(OtpKind::Steam),
        _ => None,
    };
    let Some(kind) = kind else {
        return unsupported(id, issuer, account);
    };
    let Some(mut decoded) = base32_decode(&p.secret) else {
        return unsupported(id, issuer, account);
    };
    Entry {
        id,
        issuer,
        account,
        kind,
        secret: Some(Secret::from(std::mem::take(&mut *decoded))),
    }
}

fn truncate_label(s: &str) -> String {
    s.chars().take(LABEL_MAX_CHARS).collect()
}

pub fn view(entry: &Entry, unix: u64) -> EntryView {
    let mut v = EntryView {
        id: entry.id.clone(),
        issuer: truncate_label(&entry.issuer),
        account: truncate_label(&entry.account),
        kind: "unsupported",
        code: None,
        next_code: None,
        period: 0,
        digits: 0,
        remaining: 0,
    };
    let Some(secret) = &entry.secret else {
        return v;
    };
    match entry.kind {
        OtpKind::Totp {
            alg,
            digits,
            period,
        } => {
            v.kind = "totp";
            v.code = Some(totp(secret.expose(), unix, period, alg, digits));
            v.next_code = Some(totp(
                secret.expose(),
                unix.saturating_add(period),
                period,
                alg,
                digits,
            ));
            v.period = period;
            v.digits = digits;
            v.remaining = period - unix % period;
        }
        OtpKind::Steam => {
            v.kind = "steam";
            v.code = Some(steam(secret.expose(), unix));
            v.next_code = Some(steam(secret.expose(), unix.saturating_add(STEAM_PERIOD)));
            v.period = STEAM_PERIOD;
            v.digits = STEAM_DIGITS;
            v.remaining = STEAM_PERIOD - unix % STEAM_PERIOD;
        }
        OtpKind::Unsupported => {}
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    const B32: &str = "JBSWY3DPEHPK3PXP";

    fn plain(entry_type: &str, secret: &str, period: Option<u64>, uri: &str) -> ItemPlaintext {
        ItemPlaintext {
            entry_type: entry_type.into(),
            secret: Zeroizing::new(secret.into()),
            period,
            uri: Zeroizing::new(uri.into()),
        }
    }

    fn build(p: ItemPlaintext) -> Entry {
        build_entry("id".into(), "Issuer".into(), "me".into(), p)
    }

    fn totp_entry(period: Option<u64>) -> Entry {
        build(plain(
            "Totp",
            B32,
            period,
            "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP",
        ))
    }

    #[test]
    fn secret_debug_is_redacted() {
        let s = format!("{:?}", Secret::from(vec![1, 2, 3]));
        assert!(s.contains("REDACTED"));
        assert!(!s.contains("1, 2, 3"));
    }

    #[test]
    fn build_entry_variants() {
        let e = totp_entry(None);
        assert_eq!(
            e.kind,
            OtpKind::Totp {
                alg: Algorithm::Sha1,
                digits: 6,
                period: 30
            }
        );
        assert!(e.secret.is_some());

        let e = build(plain("Steam", B32, None, "steam://JBSWY3DPEHPK3PXP"));
        assert_eq!(e.kind, OtpKind::Steam);
        assert!(e.secret.is_some());

        let e = build(plain("Totp", B32, None, "otpauth://hotp/x?counter=1"));
        assert_eq!(e.kind, OtpKind::Unsupported);
        assert!(e.secret.is_none());

        let e = build(plain("Totp", B32, None, "otpauth://totp/x?digits=9"));
        assert_eq!(e.kind, OtpKind::Unsupported);
        assert!(e.secret.is_none());

        let e = build(plain("Totp", "!!!", None, "otpauth://totp/x"));
        assert_eq!(e.kind, OtpKind::Unsupported);
        assert!(e.secret.is_none());
    }

    #[test]
    fn build_entry_period_precedence_and_bounds() {
        let uri = "otpauth://totp/x?period=60";
        let e = build(plain("Totp", B32, Some(45), uri));
        assert!(matches!(e.kind, OtpKind::Totp { period: 45, .. }));
        let e = build(plain("Totp", B32, None, uri));
        assert!(matches!(e.kind, OtpKind::Totp { period: 60, .. }));
        for bad in [0, 86_401, u64::MAX] {
            let e = build(plain("Totp", B32, Some(bad), uri));
            assert_eq!(e.kind, OtpKind::Unsupported);
        }
        let e = build(plain("Totp", B32, None, "otpauth://totp/x?period=0"));
        assert_eq!(e.kind, OtpKind::Unsupported);
    }

    #[test]
    fn build_entry_digits_bounds_and_unknown_type() {
        for digits in [5, 9, 10, 0] {
            let uri = format!("otpauth://totp/x?digits={digits}");
            assert_eq!(
                build(plain("Totp", B32, None, &uri)).kind,
                OtpKind::Unsupported
            );
        }
        let e = build(plain("Totp", B32, None, "otpauth://totp/x?digits=8"));
        assert!(matches!(e.kind, OtpKind::Totp { digits: 8, .. }));
        assert_eq!(
            build(plain("Other", B32, None, "otpauth://totp/x")).kind,
            OtpKind::Unsupported
        );
    }

    #[test]
    fn view_never_contains_secret() {
        let e = totp_entry(None);
        let json = serde_json::to_string(&view(&e, 1000)).unwrap();
        assert!(!json.contains(B32));
        assert!(!json.to_lowercase().contains("secret"));
    }

    #[test]
    fn hidden_entry_has_view_keys_and_null_codes() {
        let hidden = serde_json::to_value(PrivateEntry::Hidden(HiddenEntry::new(
            "id".into(),
            &"é".repeat(300),
            "me",
        )))
        .unwrap();
        let full = serde_json::to_value(view(&totp_entry(None), 1000)).unwrap();
        let keys = |v: &serde_json::Value| {
            let mut k: Vec<String> = v.as_object().unwrap().keys().cloned().collect();
            k.sort();
            k
        };
        assert_eq!(keys(&hidden), keys(&full));
        for field in ["kind", "code", "nextCode", "period", "digits", "remaining"] {
            assert!(hidden[field].is_null(), "{field}");
        }
        assert_eq!(hidden["issuer"].as_str().unwrap().chars().count(), 256);
    }

    #[test]
    fn view_counts_down() {
        let e = totp_entry(Some(30));
        let v = view(&e, 1000);
        assert_eq!(v.kind, "totp");
        assert_eq!(v.remaining, 20);
        let key = base32_decode(B32).unwrap();
        assert_eq!(
            v.next_code.unwrap(),
            totp(&key, 1030, 30, Algorithm::Sha1, 6)
        );
        assert_eq!(v.code.unwrap(), totp(&key, 1000, 30, Algorithm::Sha1, 6));
    }

    #[test]
    fn view_steam_and_unsupported() {
        let e = build(plain("Steam", B32, Some(999), "steam://x"));
        let v = view(&e, 1000);
        assert_eq!(
            (v.kind, v.period, v.digits, v.remaining),
            ("steam", 30, 5, 20)
        );
        assert_eq!(v.code.unwrap().len(), 5);

        let e = build(plain("Totp", B32, None, "otpauth://hotp/x"));
        let v = view(&e, 1000);
        assert_eq!(v.kind, "unsupported");
        assert!(v.code.is_none() && v.next_code.is_none());
    }

    #[test]
    fn view_survives_extreme_time() {
        let e = totp_entry(Some(86_400));
        let v = view(&e, u64::MAX);
        assert!(v.code.is_some());
    }

    #[test]
    fn labels_truncated() {
        let e = build_entry(
            "id".into(),
            "é".repeat(300),
            "a".repeat(300),
            plain("Totp", B32, None, "otpauth://totp/x"),
        );
        let v = view(&e, 0);
        assert_eq!(v.issuer.chars().count(), 256);
        assert_eq!(v.account.chars().count(), 256);
    }

    #[test]
    fn item_plaintext_deserializes_ignoring_unknown_fields() {
        let json = r#"{"entryType":"Totp","note":"n","period":30,"secret":"JBSWY3DPEHPK3PXP","uri":"otpauth://totp/x","syncMetadata":{"a":1}}"#;
        let p: ItemPlaintext = serde_json::from_str(json).unwrap();
        assert_eq!(p.entry_type, "Totp");
        assert_eq!(p.period, Some(30));
    }
}
