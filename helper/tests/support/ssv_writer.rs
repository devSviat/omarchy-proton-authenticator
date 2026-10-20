#![allow(dead_code)]

use pa_helper::ssv::Value;

pub const VERSION: u32 = 15;

pub fn encode(value: &Value) -> Vec<u8> {
    let mut out = VERSION.to_le_bytes().to_vec();
    write_value(&mut out, value);
    out
}

pub fn encode_with_version(version: u32, value: &Value) -> Vec<u8> {
    let mut out = version.to_le_bytes().to_vec();
    write_value(&mut out, value);
    out
}

pub fn write_value(out: &mut Vec<u8>, value: &Value) {
    match value {
        Value::Undefined => out.push(0x03),
        Value::Null => out.push(0x04),
        Value::Bool(false) => out.push(0x08),
        Value::Bool(true) => out.push(0x09),
        Value::Int(0) => out.push(0x06),
        Value::Int(1) => out.push(0x07),
        Value::Int(n) => {
            out.push(0x05);
            out.extend_from_slice(&n.to_le_bytes());
        }
        Value::Double(d) => {
            out.push(0x0A);
            out.extend_from_slice(&d.to_le_bytes());
        }
        Value::String(s) if s.is_empty() => out.push(0x11),
        Value::String(s) => {
            out.push(0x10);
            write_string_body(out, s);
        }
        Value::Bytes(b) => {
            out.push(0x16);
            out.push(0x02);
            out.extend_from_slice(&0u64.to_le_bytes());
            out.extend_from_slice(&(b.len() as u64).to_le_bytes());
            out.push(0x15);
            out.extend_from_slice(&(b.len() as u64).to_le_bytes());
            out.extend_from_slice(b);
        }
        Value::Object(props) => {
            out.push(0x02);
            for (name, v) in props {
                write_string_body(out, name);
                write_value(out, v);
            }
            out.extend_from_slice(&u32::MAX.to_le_bytes());
        }
    }
}

pub fn write_string_body(out: &mut Vec<u8>, s: &str) {
    if s.chars().all(|c| (c as u32) <= 0xFF) {
        out.extend_from_slice(&(s.chars().count() as u32 | 0x8000_0000).to_le_bytes());
        out.extend(s.chars().map(|c| c as u8));
    } else {
        let units: Vec<u16> = s.encode_utf16().collect();
        out.extend_from_slice(&(units.len() as u32).to_le_bytes());
        for u in units {
            out.extend_from_slice(&u.to_le_bytes());
        }
    }
}
