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

/// One rendered reply line and whether it reports success.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rendered {
    pub line: String,
    pub ok: bool,
}

fn try_render_ok<T: Serialize>(body: &T) -> Result<String, ErrorCode> {
    let envelope = OkEnvelope {
        ok: true,
        protocol: PROTOCOL,
        body,
    };
    match serde_json::to_string(&envelope) {
        Ok(rendered) if rendered.len() <= MAX_OUTPUT_BYTES => Ok(rendered),
        Ok(_) => Err(ErrorCode::OutputTooLarge),
        Err(_) => Err(ErrorCode::Internal),
    }
}

pub fn render_ok<T: Serialize>(body: &T) -> String {
    try_render_ok(body).unwrap_or_else(render_err)
}

pub fn render<T: Serialize>(result: Result<T, ErrorCode>) -> Rendered {
    match result.and_then(|body| try_render_ok(&body)) {
        Ok(line) => Rendered { line, ok: true },
        Err(code) => Rendered {
            line: render_err(code),
            ok: false,
        },
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
