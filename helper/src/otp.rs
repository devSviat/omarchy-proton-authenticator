use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    Sha1,
    Sha256,
    Sha512,
}

pub const STEAM_ALPHABET: &[u8; 26] = b"23456789BCDFGHJKMNPQRTVWXY";
pub const STEAM_PERIOD: u64 = 30;
pub const STEAM_LENGTH: usize = 5;

fn mac<M: Mac + KeyInit>(key: &[u8], counter: u64) -> Vec<u8> {
    let mut mac = <M as KeyInit>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(&counter.to_be_bytes());
    mac.finalize().into_bytes().to_vec()
}

fn truncated(key: &[u8], counter: u64, alg: Algorithm) -> u32 {
    let digest = match alg {
        Algorithm::Sha1 => mac::<Hmac<Sha1>>(key, counter),
        Algorithm::Sha256 => mac::<Hmac<Sha256>>(key, counter),
        Algorithm::Sha512 => mac::<Hmac<Sha512>>(key, counter),
    };
    // RFC 4226 section 5.3: dynamic truncation, top bit masked to avoid sign ambiguity.
    let offset = usize::from(digest[digest.len() - 1] & 0x0f);
    u32::from_be_bytes([
        digest[offset] & 0x7f,
        digest[offset + 1],
        digest[offset + 2],
        digest[offset + 3],
    ])
}

pub fn hotp(key: &[u8], counter: u64, alg: Algorithm, digits: u32) -> String {
    let code = truncated(key, counter, alg) % 10u32.pow(digits);
    format!("{code:0width$}", width = digits as usize)
}

pub fn totp(key: &[u8], unix: u64, period: u64, alg: Algorithm, digits: u32) -> String {
    hotp(key, unix / period, alg, digits)
}

pub fn steam(key: &[u8], unix: u64) -> String {
    let mut code = truncated(key, unix / STEAM_PERIOD, Algorithm::Sha1);
    let mut out = String::with_capacity(STEAM_LENGTH);
    for _ in 0..STEAM_LENGTH {
        out.push(char::from(STEAM_ALPHABET[(code % 26) as usize]));
        code /= 26;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const TIMES: [u64; 6] = [
        59,
        1111111109,
        1111111111,
        1234567890,
        2000000000,
        20000000000,
    ];

    #[test]
    fn rfc4226_vectors() {
        let expected = [
            "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583",
            "399871", "520489",
        ];
        for (counter, want) in expected.iter().enumerate() {
            assert_eq!(
                hotp(b"12345678901234567890", counter as u64, Algorithm::Sha1, 6),
                *want
            );
        }
    }

    #[test]
    fn rfc6238_vectors_8_digits() {
        let cases: [(&[u8], Algorithm, [&str; 6]); 3] = [
            (
                b"12345678901234567890",
                Algorithm::Sha1,
                [
                    "94287082", "07081804", "14050471", "89005924", "69279037", "65353130",
                ],
            ),
            (
                b"12345678901234567890123456789012",
                Algorithm::Sha256,
                [
                    "46119246", "68084774", "67062674", "91819424", "90698825", "77737706",
                ],
            ),
            (
                b"1234567890123456789012345678901234567890123456789012345678901234",
                Algorithm::Sha512,
                [
                    "90693936", "25091201", "99943326", "93441116", "38618901", "47863826",
                ],
            ),
        ];
        for (key, alg, want) in cases {
            for (time, expected) in TIMES.iter().zip(want) {
                assert_eq!(totp(key, *time, 30, alg, 8), expected, "{alg:?} t={time}");
            }
        }
    }

    #[test]
    fn steam_is_five_chars_from_alphabet() {
        const ALPHABET: &str = "23456789BCDFGHJKMNPQRTVWXY";
        for seed in 0u8..20 {
            let key = [seed; 20];
            let code = steam(&key, 1_700_000_000 + u64::from(seed) * 31);
            assert_eq!(code.len(), 5);
            assert!(code.chars().all(|c| ALPHABET.contains(c)), "{code}");
        }
    }

    #[test]
    fn steam_fixed_vector() {
        assert_eq!(steam(b"12345678901234567890", 1111111109), "PY4YB");
    }
}
