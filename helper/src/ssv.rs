use std::fmt;

use zeroize::Zeroizing;

use crate::error::{ErrorCode, Result};

// Format source: WebKit Source/WebCore/bindings/js/SerializedScriptValue.cpp
const SUPPORTED_VERSION: u32 = 15;
const MAX_DEPTH: usize = 4;
const MAX_PROPERTIES: usize = 64;
const MAX_STRING_BYTES: usize = 64 * 1024;
const MAX_BYTES: usize = 64 * 1024;

const TAG_OBJECT: u8 = 0x02;
const TAG_UNDEFINED: u8 = 0x03;
const TAG_NULL: u8 = 0x04;
const TAG_INT: u8 = 0x05;
const TAG_ZERO: u8 = 0x06;
const TAG_ONE: u8 = 0x07;
const TAG_FALSE: u8 = 0x08;
const TAG_TRUE: u8 = 0x09;
const TAG_DOUBLE: u8 = 0x0A;
const TAG_STRING: u8 = 0x10;
const TAG_EMPTY_STRING: u8 = 0x11;
const TAG_ARRAY_BUFFER: u8 = 0x15;
const TAG_ARRAY_BUFFER_VIEW: u8 = 0x16;

const SUBTAG_UINT8_ARRAY: u8 = 0x02;
const TERMINATOR: u32 = 0xFFFF_FFFF;
const EIGHT_BIT_FLAG: u32 = 0x8000_0000;
const POOL_REF: u32 = 0xFFFF_FFFE;

/// Subset of JS values that can appear in a Proton Authenticator vault record.
/// `Debug` never prints string or byte contents.
#[derive(PartialEq)]
pub enum Value {
    Undefined,
    Null,
    Bool(bool),
    Int(i32),
    Double(f64),
    String(String),
    Bytes(Zeroizing<Vec<u8>>),
    Object(Vec<(String, Value)>),
}

impl fmt::Debug for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Undefined => f.write_str("Undefined"),
            Self::Null => f.write_str("Null"),
            Self::Bool(b) => write!(f, "Bool({b})"),
            Self::Int(n) => write!(f, "Int({n})"),
            Self::Double(d) => write!(f, "Double({d})"),
            Self::String(_) => f.write_str("String(..)"),
            Self::Bytes(b) => write!(f, "Bytes(len={})", b.len()),
            Self::Object(props) => write!(f, "Object(props={})", props.len()),
        }
    }
}

/// Looks up a property of an `Object`; `None` if missing or `obj` is not an object.
pub fn get<'a>(obj: &'a Value, key: &str) -> Option<&'a Value> {
    match obj {
        Value::Object(props) => props.iter().find(|(k, _)| k == key).map(|(_, v)| v),
        _ => None,
    }
}

/// Decodes a WebKit SerializedScriptValue blob (version 15, strict subset).
/// Any unexpected or truncated input fails with `VaultFormatChanged`.
pub fn decode(blob: &[u8]) -> Result<Value> {
    let mut r = Reader {
        buf: blob,
        pos: 0,
        properties: 0,
        pool: Vec::new(),
    };
    if r.u32()? != SUPPORTED_VERSION {
        return Err(ErrorCode::VaultFormatChanged);
    }
    let value = r.value(1)?;
    if r.rest().iter().any(|&b| b != 0) {
        return Err(ErrorCode::VaultFormatChanged);
    }
    Ok(value)
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
    properties: usize,
    pool: Vec<String>,
}

fn bad<T>() -> Result<T> {
    Err(ErrorCode::VaultFormatChanged)
}

impl<'a> Reader<'a> {
    fn rest(&self) -> &'a [u8] {
        self.buf.get(self.pos..).unwrap_or(&[])
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or(ErrorCode::VaultFormatChanged)?;
        let slice = self
            .buf
            .get(self.pos..end)
            .ok_or(ErrorCode::VaultFormatChanged)?;
        self.pos = end;
        Ok(slice)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.take(N)?
            .try_into()
            .map_err(|_| ErrorCode::VaultFormatChanged)
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.array::<1>()?[0])
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    fn value(&mut self, depth: usize) -> Result<Value> {
        match self.u8()? {
            TAG_OBJECT => self.object(depth),
            TAG_UNDEFINED => Ok(Value::Undefined),
            TAG_NULL => Ok(Value::Null),
            TAG_INT => Ok(Value::Int(i32::from_le_bytes(self.array()?))),
            TAG_ZERO => Ok(Value::Int(0)),
            TAG_ONE => Ok(Value::Int(1)),
            TAG_FALSE => Ok(Value::Bool(false)),
            TAG_TRUE => Ok(Value::Bool(true)),
            TAG_DOUBLE => Ok(Value::Double(f64::from_le_bytes(self.array()?))),
            TAG_EMPTY_STRING => Ok(Value::String(String::new())),
            TAG_STRING => {
                let len = self.u32()?;
                Ok(Value::String(self.string_body(len)?))
            }
            TAG_ARRAY_BUFFER_VIEW => self.view(),
            _ => bad(),
        }
    }

    fn object(&mut self, depth: usize) -> Result<Value> {
        if depth > MAX_DEPTH {
            return bad();
        }
        let mut props = Vec::new();
        loop {
            let head = self.u32()?;
            if head == TERMINATOR {
                return Ok(Value::Object(props));
            }
            self.properties = self
                .properties
                .checked_add(1)
                .ok_or(ErrorCode::VaultFormatChanged)?;
            if self.properties > MAX_PROPERTIES {
                return bad();
            }
            let name = self.string_body(head)?;
            let value = self.value(depth + 1)?;
            if props.iter().any(|(k, _)| *k == name) {
                return bad();
            }
            props.push((name, value));
        }
    }

    fn string_body(&mut self, head: u32) -> Result<String> {
        if head == POOL_REF {
            return self.pool_ref();
        }
        let decoded = if head & EIGHT_BIT_FLAG != 0 {
            let len = (head & !EIGHT_BIT_FLAG) as usize;
            if len > MAX_STRING_BYTES {
                return bad();
            }
            self.take(len)?.iter().map(|&b| char::from(b)).collect()
        } else {
            let byte_len = (head as usize)
                .checked_mul(2)
                .ok_or(ErrorCode::VaultFormatChanged)?;
            if byte_len > MAX_STRING_BYTES {
                return bad();
            }
            let raw = self.take(byte_len)?;
            let units = raw
                .as_chunks::<2>()
                .0
                .iter()
                .map(|c| u16::from_le_bytes(*c));
            match char::decode_utf16(units).collect::<std::result::Result<String, _>>() {
                Ok(s) => s,
                Err(_) => return bad(),
            }
        };
        if !decoded.is_empty() {
            self.pool.push(decoded.clone());
        }
        Ok(decoded)
    }

    fn pool_ref(&mut self) -> Result<String> {
        let index = match self.pool.len() {
            0..=0xFF => u64::from(self.u8()?),
            0x100..=0xFFFF => u64::from(u16::from_le_bytes(self.array()?)),
            _ => u64::from(self.u32()?),
        };
        usize::try_from(index)
            .ok()
            .and_then(|i| self.pool.get(i))
            .cloned()
            .ok_or(ErrorCode::VaultFormatChanged)
    }

    fn view(&mut self) -> Result<Value> {
        if self.u8()? != SUBTAG_UINT8_ARRAY || self.u64()? != 0 {
            return bad();
        }
        let view_len = self.u64()?;
        if self.u8()? != TAG_ARRAY_BUFFER || self.u64()? != view_len {
            return bad();
        }
        let len = usize::try_from(view_len).map_err(|_| ErrorCode::VaultFormatChanged)?;
        if len > MAX_BYTES {
            return bad();
        }
        Ok(Value::Bytes(Zeroizing::new(self.take(len)?.to_vec())))
    }
}
