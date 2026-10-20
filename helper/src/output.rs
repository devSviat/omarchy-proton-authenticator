use serde::Serialize;

use crate::error::ErrorCode;

pub const PROTOCOL: u32 = 1;
pub const MAX_OUTPUT_BYTES: usize = 1024 * 1024;

#[derive(Serialize)]
struct OkEnvelope<'a, T: Serialize> {
    ok: bool,
    protocol: u32,
    #[serde(flatten)]
    body: &'a T,
}

#[derive(Serialize)]
struct ErrEnvelope {
    ok: bool,
    protocol: u32,
    error: ErrorCode,
}

pub fn render_ok<T: Serialize>(body: &T) -> String {
    let envelope = OkEnvelope {
        ok: true,
        protocol: PROTOCOL,
        body,
    };
    match serde_json::to_string(&envelope) {
        Ok(rendered) if rendered.len() <= MAX_OUTPUT_BYTES => rendered,
        Ok(_) => render_err(ErrorCode::OutputTooLarge),
        Err(_) => render_err(ErrorCode::Internal),
    }
}

pub fn render_err(code: ErrorCode) -> String {
    let envelope = ErrEnvelope {
        ok: false,
        protocol: PROTOCOL,
        error: code,
    };
    serde_json::to_string(&envelope)
        .unwrap_or_else(|_| r#"{"ok":false,"protocol":1,"error":"INTERNAL"}"#.to_owned())
}
