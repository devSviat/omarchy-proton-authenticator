use crate::otp::Algorithm;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UriParams {
    pub alg: Algorithm,
    pub digits: u32,
    pub period: Option<u64>,
    pub is_hotp: bool,
}

fn percent_decode(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                let hex = s.get(i + 1..i + 3)?;
                out.push(u8::from_str_radix(hex, 16).ok()?);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

fn parse_algorithm(value: &str) -> Option<Algorithm> {
    match value.to_ascii_uppercase().as_str() {
        "SHA1" => Some(Algorithm::Sha1),
        "SHA256" => Some(Algorithm::Sha256),
        "SHA512" => Some(Algorithm::Sha512),
        _ => None,
    }
}

pub fn parse_otpauth(uri: &str) -> Option<UriParams> {
    let rest = uri.strip_prefix("otpauth://")?;
    let (kind, after_kind) = rest.split_once('/')?;
    let is_hotp = match kind.to_ascii_lowercase().as_str() {
        "totp" => false,
        "hotp" => true,
        _ => return None,
    };
    let query = after_kind.split_once('?').map_or("", |(_, q)| q);
    let query = query.split('#').next().unwrap_or("");

    let mut params = UriParams {
        alg: Algorithm::Sha1,
        digits: 6,
        period: None,
        is_hotp,
    };
    let mut seen = [false; 3];
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        let key = percent_decode(key)?.to_ascii_lowercase();
        let slot = match key.as_str() {
            "algorithm" => 0,
            "digits" => 1,
            "period" => 2,
            _ => continue,
        };
        if std::mem::replace(&mut seen[slot], true) {
            continue;
        }
        let value = percent_decode(value)?;
        match slot {
            0 => params.alg = parse_algorithm(&value)?,
            1 => params.digits = value.trim().parse().ok()?,
            _ => params.period = Some(value.trim().parse().ok()?),
        }
    }
    Some(params)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_otpauth_defaults_and_params() {
        let p = parse_otpauth("otpauth://totp/GitHub:me?secret=JBSWY3DPEHPK3PXP&issuer=GitHub")
            .unwrap();
        assert_eq!(
            p,
            UriParams {
                alg: Algorithm::Sha1,
                digits: 6,
                period: None,
                is_hotp: false
            }
        );
        let p =
            parse_otpauth("otpauth://totp/x?secret=A&Algorithm=SHA256&DIGITS=8&period=60").unwrap();
        assert_eq!(p.alg, Algorithm::Sha256);
        assert_eq!(p.digits, 8);
        assert_eq!(p.period, Some(60));
        assert!(
            parse_otpauth("otpauth://hotp/x?secret=A&counter=1")
                .unwrap()
                .is_hotp
        );
    }

    #[test]
    fn parse_otpauth_percent_decodes_and_rejects_garbage() {
        let p = parse_otpauth("otpauth://totp/x?%61lgorithm=SHA%35%31%32&digits=%38").unwrap();
        assert_eq!(p.alg, Algorithm::Sha512);
        assert_eq!(p.digits, 8);
        assert!(parse_otpauth("https://totp/x").is_none());
        assert!(parse_otpauth("otpauth://steam/x?secret=A").is_none());
        assert!(parse_otpauth("otpauth://totp/x?algorithm=MD5").is_none());
        assert!(parse_otpauth("otpauth://totp/x?digits=abc").is_none());
        assert!(parse_otpauth("otpauth://totp/x?digits=%zz").is_none());
    }
}
