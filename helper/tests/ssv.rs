mod support;

use pa_helper::error::ErrorCode;
use pa_helper::ssv::{decode, get, Value};
use support::ssv_writer::{encode, encode_with_version, write_raw_string_body};
use zeroize::Zeroizing;

fn bytes(b: &[u8]) -> Value {
    Value::Bytes(Zeroizing::new(b.to_vec()))
}

fn s(v: &str) -> Value {
    Value::String(v.to_string())
}

fn obj(props: Vec<(&str, Value)>) -> Value {
    Value::Object(props.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}

fn item() -> Value {
    obj(vec![
        ("id", s("a1")),
        ("issuer", s("GitHub")),
        ("name", s("me")),
        ("order", Value::Int(3)),
        ("__encryptedData", bytes(&[9; 40])),
    ])
}

fn storage_key() -> Value {
    obj(vec![
        ("source", Value::Int(0)),
        ("salt", bytes(&[7; 32])),
        ("id", s("k")),
        ("adapterKeyId", s("adapter::0::abc")),
        ("unsafe_key", Value::Undefined),
    ])
}

fn fmt_changed<T: std::fmt::Debug>(r: Result<T, ErrorCode>) {
    assert_eq!(r.unwrap_err(), ErrorCode::VaultFormatChanged);
}

#[test]
fn roundtrip_item_shape() {
    let v = item();
    assert_eq!(decode(&encode(&v)).unwrap(), v);
}

#[test]
fn roundtrip_storage_key_shape() {
    let v = storage_key();
    assert_eq!(decode(&encode(&v)).unwrap(), v);
}

#[test]
fn roundtrip_scalars_and_nesting() {
    let v = obj(vec![
        ("n", Value::Null),
        ("t", Value::Bool(true)),
        ("f", Value::Bool(false)),
        ("one", Value::Int(1)),
        ("neg", Value::Int(-5)),
        ("d", Value::Double(1.5)),
        ("e", s("")),
        ("inner", obj(vec![("x", Value::Int(70000))])),
    ]);
    assert_eq!(decode(&encode(&v)).unwrap(), v);
}

#[test]
fn get_finds_property() {
    let v = item();
    assert_eq!(get(&v, "issuer"), Some(&s("GitHub")));
    assert_eq!(get(&v, "missing"), None);
    assert_eq!(get(&Value::Null, "id"), None);
}

#[test]
fn utf16_string() {
    let v = obj(vec![("issuer", s("Привіт"))]);
    let blob = encode(&v);
    let mut utf16_marker = Vec::new();
    write_raw_string_body(&mut utf16_marker, "Привіт");
    assert_eq!(utf16_marker[3] & 0x80, 0);
    assert_eq!(decode(&blob).unwrap(), v);
}

#[test]
fn rejects_unknown_version() {
    fmt_changed(decode(&encode_with_version(14, &item())));
    fmt_changed(decode(&encode_with_version(16, &item())));
}

#[test]
fn pool_ref_for_repeated_name_and_value() {
    let v = obj(vec![
        ("id", s("k")),
        ("issuer", s("same")),
        ("name", s("same")),
        ("adapterKeyId", s("k")),
        ("id2", s("id")),
    ]);
    let blob = encode(&v);
    assert!(blob.windows(4).any(|w| w == 0xFFFF_FFFEu32.to_le_bytes()));
    assert_eq!(decode(&blob).unwrap(), v);
}

#[test]
fn pool_ref_wire_layout() {
    let mut blob = 15u32.to_le_bytes().to_vec();
    blob.push(0x02);
    blob.extend_from_slice(&[0x01, 0x00, 0x00, 0x80, b'a']);
    blob.extend_from_slice(&[0x10, 0x01, 0x00, 0x00, 0x80, b'x']);
    blob.extend_from_slice(&[0xFE, 0xFF, 0xFF, 0xFF, 0x01]);
    blob.push(0x10);
    blob.extend_from_slice(&[0xFE, 0xFF, 0xFF, 0xFF, 0x00]);
    blob.extend_from_slice(&[0xFF; 4]);
    assert_eq!(
        decode(&blob).unwrap(),
        obj(vec![("a", s("x")), ("x", s("a"))])
    );
}

#[test]
fn rejects_pool_ref_out_of_range() {
    let mut blob = 15u32.to_le_bytes().to_vec();
    blob.push(0x02);
    blob.extend_from_slice(&0xFFFF_FFFEu32.to_le_bytes());
    blob.push(0);
    fmt_changed(decode(&blob));

    let mut blob = 15u32.to_le_bytes().to_vec();
    blob.extend_from_slice(&[0x02, 0x01, 0x00, 0x00, 0x80, b'a', 0x10]);
    blob.extend_from_slice(&0xFFFF_FFFEu32.to_le_bytes());
    blob.push(5);
    fmt_changed(decode(&blob));

    let mut blob = 15u32.to_le_bytes().to_vec();
    blob.push(0x10);
    blob.extend_from_slice(&0xFFFF_FFFEu32.to_le_bytes());
    fmt_changed(decode(&blob));
}

#[test]
fn empty_strings_are_not_pooled() {
    let mut blob = 15u32.to_le_bytes().to_vec();
    blob.push(0x02);
    blob.extend_from_slice(&[0x00, 0x00, 0x00, 0x80]);
    blob.push(0x11);
    blob.extend_from_slice(&[0x01, 0x00, 0x00, 0x80, b'a', 0x10]);
    blob.extend_from_slice(&0xFFFF_FFFEu32.to_le_bytes());
    blob.push(0);
    blob.extend_from_slice(&[0xFF; 4]);
    assert_eq!(
        decode(&blob).unwrap(),
        obj(vec![("", s("")), ("a", s("a"))])
    );
}

#[test]
fn rejects_duplicate_property_names() {
    let v = obj(vec![("a", Value::Null), ("a", Value::Null)]);
    fmt_changed(decode(&encode(&v)));
}

#[test]
fn rejects_unknown_tag() {
    for tag in [0x00u8, 0x01, 0x0B, 0x12, 0x15, 0x17, 0xFF] {
        let mut blob = 15u32.to_le_bytes().to_vec();
        blob.push(tag);
        fmt_changed(decode(&blob));
    }
}

#[test]
fn rejects_truncated() {
    for v in [item(), storage_key()] {
        let blob = encode(&v);
        for n in 0..blob.len() {
            fmt_changed(decode(&blob[..n]));
        }
    }
}

#[test]
fn rejects_view_length_mismatch() {
    let mut blob = encode(&obj(vec![("b", bytes(&[1, 2, 3, 4]))]));
    let pos = blob.iter().position(|&b| b == 0x15).unwrap();
    blob[pos + 1] = 5;
    fmt_changed(decode(&blob));
}

#[test]
fn rejects_view_nonzero_offset_and_wrong_subtag() {
    let base = encode(&obj(vec![("b", bytes(&[1, 2, 3, 4]))]));
    let pos = base.iter().position(|&b| b == 0x16).unwrap();
    let mut off = base.clone();
    off[pos + 2] = 1;
    fmt_changed(decode(&off));
    let mut sub = base.clone();
    sub[pos + 1] = 0x03;
    fmt_changed(decode(&sub));
}

#[test]
fn rejects_huge_declared_lengths_without_allocating() {
    let mut blob = 15u32.to_le_bytes().to_vec();
    blob.extend_from_slice(&[0x02, 0x01, 0x00, 0x00, 0x80, b'b', 0x16, 0x02]);
    blob.extend_from_slice(&0u64.to_le_bytes());
    blob.extend_from_slice(&u64::MAX.to_le_bytes());
    blob.push(0x15);
    blob.extend_from_slice(&u64::MAX.to_le_bytes());
    fmt_changed(decode(&blob));

    let mut blob = 15u32.to_le_bytes().to_vec();
    blob.push(0x10);
    blob.extend_from_slice(&0x7FFF_FFFFu32.to_le_bytes());
    fmt_changed(decode(&blob));
}

#[test]
fn trailing_bytes_only_if_zero() {
    let mut blob = encode(&item());
    blob.extend_from_slice(&[0, 0, 0]);
    assert_eq!(decode(&blob).unwrap(), item());
    blob.push(1);
    fmt_changed(decode(&blob));
}

#[test]
fn rejects_excess_depth() {
    let mut v = obj(vec![]);
    for _ in 0..4 {
        v = obj(vec![("a", v)]);
    }
    fmt_changed(decode(&encode(&v)));
    let mut ok = obj(vec![]);
    for _ in 0..3 {
        ok = obj(vec![("a", ok)]);
    }
    assert!(decode(&encode(&ok)).is_ok());
}

#[test]
fn rejects_too_many_properties() {
    let many = |n: usize| Value::Object((0..n).map(|i| (format!("k{i}"), Value::Null)).collect());
    assert!(decode(&encode(&many(64))).is_ok());
    fmt_changed(decode(&encode(&many(65))));
}

#[test]
fn string_limit_is_64_kib_of_input_bytes() {
    let ok = obj(vec![("s", s(&"a".repeat(65536)))]);
    assert!(decode(&encode(&ok)).is_ok());
    fmt_changed(decode(&encode(&obj(vec![("s", s(&"a".repeat(65537)))]))));
    let ok16 = obj(vec![("s", s(&"Я".repeat(32768)))]);
    assert!(decode(&encode(&ok16)).is_ok());
    let big16 = obj(vec![("s", s(&"Ж\u{0416}".repeat(16385)))]);
    fmt_changed(decode(&encode(&big16)));
}

#[test]
fn rejects_oversized_bytes() {
    assert!(decode(&encode(&obj(vec![("b", bytes(&vec![0; 65536]))]))).is_ok());
    fmt_changed(decode(&encode(&obj(vec![("b", bytes(&vec![0; 65537]))]))));
}

#[test]
fn rejects_lone_surrogate() {
    let mut blob = 15u32.to_le_bytes().to_vec();
    blob.push(0x10);
    blob.extend_from_slice(&1u32.to_le_bytes());
    blob.extend_from_slice(&0xD800u16.to_le_bytes());
    fmt_changed(decode(&blob));
}

#[test]
fn debug_output_is_redacted() {
    assert_eq!(format!("{:?}", bytes(&[0xAB; 8])), "Bytes(len=8)");
    assert_eq!(format!("{:?}", s("secret")), "String(..)");
    assert_eq!(format!("{:?}", obj(vec![("k", s("v"))])), "Object(props=1)");
}

struct XorShift(u64);

impl XorShift {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

#[test]
fn fuzz_truncations_and_mutations_never_panic() {
    let blobs = [encode(&item()), encode(&storage_key())];
    for blob in &blobs {
        for n in 0..=blob.len() {
            let _ = decode(&blob[..n]);
        }
    }
    let mut rng = XorShift(0x9E37_79B9_7F4A_7C15);
    for i in 0..10_000 {
        let mut blob = blobs[i % blobs.len()].clone();
        let flips = 1 + (rng.next() % 4) as usize;
        for _ in 0..flips {
            let at = (rng.next() % blob.len() as u64) as usize;
            blob[at] = rng.next() as u8;
        }
        if rng.next().is_multiple_of(4) {
            let keep = (rng.next() % blob.len() as u64) as usize;
            blob.truncate(keep);
        }
        let _ = decode(&blob);
    }
}
