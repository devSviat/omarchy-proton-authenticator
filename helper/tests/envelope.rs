use pa_helper::error::ErrorCode;
use pa_helper::output::{render_err, render_ok};
use serde::Serialize;

#[derive(Serialize)]
struct Body {
    a: u32,
}

#[derive(Serialize)]
struct Big {
    blob: String,
}

#[test]
fn error_codes_serialize_screaming() {
    assert_eq!(
        serde_json::to_string(&ErrorCode::KeyringLocked).unwrap(),
        "\"KEYRING_LOCKED\""
    );
}

#[test]
fn render_err_has_no_message() {
    assert_eq!(
        render_err(ErrorCode::DecryptFailed),
        r#"{"ok":false,"protocol":1,"error":"DECRYPT_FAILED"}"#
    );
}

#[test]
fn render_ok_merges_envelope() {
    let v: serde_json::Value = serde_json::from_str(&render_ok(&Body { a: 1 })).unwrap();
    assert_eq!(v["ok"], true);
    assert_eq!(v["protocol"], 1);
    assert_eq!(v["a"], 1);
}

#[test]
fn render_ok_caps_size() {
    let big = Big {
        blob: "x".repeat(2 * 1024 * 1024),
    };
    assert_eq!(
        render_ok(&big),
        r#"{"ok":false,"protocol":1,"error":"OUTPUT_TOO_LARGE"}"#
    );
}
