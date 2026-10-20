use zeroize::Zeroizing;

pub fn base32_decode(s: &str) -> Option<Zeroizing<Vec<u8>>> {
    let mut out = Zeroizing::new(Vec::with_capacity(s.len() * 5 / 8));
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for byte in s.bytes() {
        let value = match byte {
            b' ' | b'=' => continue,
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a',
            b'2'..=b'7' => byte - b'2' + 26,
            _ => return None,
        };
        acc = (acc << 5) | u32::from(value);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    if out.is_empty() {
        return None;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base32_rfc4648() {
        assert_eq!(
            base32_decode("MZXW6YTBOI======").unwrap().as_slice(),
            b"foobar"
        );
        assert_eq!(base32_decode("mzxw 6ytb oi").unwrap().as_slice(), b"foobar");
        assert!(base32_decode("MZXW1").is_none());
    }
}
