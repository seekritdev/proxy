//! base64url (RFC 4648 §5), no padding — the encoding every seekrit blob uses.
//! Small and dependency-free; a malformed input is a decode error, never a
//! panic. Matches `packages/crypto/src/encoding.ts`.

const INVALID: u8 = 0xFF;

/// Reverse lookup table: base64url char -> 6-bit value (0xFF = not allowed).
const fn decode_table() -> [u8; 256] {
    let mut t = [INVALID; 256];
    let mut i = 0u8;
    while i < 26 {
        t[(b'A' + i) as usize] = i; // A-Z -> 0..25
        t[(b'a' + i) as usize] = 26 + i; // a-z -> 26..51
        i += 1;
    }
    let mut d = 0u8;
    while d < 10 {
        t[(b'0' + d) as usize] = 52 + d; // 0-9 -> 52..61
        d += 1;
    }
    t[b'-' as usize] = 62;
    t[b'_' as usize] = 63;
    t
}

static DECODE: [u8; 256] = decode_table();

/// base64url alphabet (RFC 4648 §5): A-Z a-z 0-9 - _.
const ENCODE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Encode bytes as base64url with no padding — the inverse of [`decode`], and a
/// match for `toBase64Url` in `packages/crypto/src/encoding.ts`.
pub fn encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for &b in input {
        acc = (acc << 8) | b as u32;
        bits += 8;
        while bits >= 6 {
            bits -= 6;
            out.push(ENCODE[((acc >> bits) & 0x3f) as usize] as char);
        }
    }
    // Flush the final partial group, left-aligned (low bits zero-padded).
    if bits > 0 {
        out.push(ENCODE[((acc << (6 - bits)) & 0x3f) as usize] as char);
    }
    out
}

/// Decode a base64url string (no padding; `-`/`_` alphabet) into bytes.
pub fn decode(input: &str) -> Result<Vec<u8>, String> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3 + 3);
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for (i, &c) in bytes.iter().enumerate() {
        let v = DECODE[c as usize];
        if v == INVALID {
            return Err(format!("invalid base64url character at position {i}"));
        }
        acc = (acc << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    // Any leftover bits must be zero padding (< 8 bits, i.e. a valid tail).
    if bits >= 8 || (acc & ((1 << bits) - 1)) != 0 {
        return Err("invalid base64url padding".to_string());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::{decode, encode};

    #[test]
    fn decodes_known_values() {
        assert_eq!(decode("").unwrap(), b"");
        assert_eq!(decode("Zg").unwrap(), b"f");
        assert_eq!(decode("Zm8").unwrap(), b"fo");
        assert_eq!(decode("Zm9v").unwrap(), b"foo");
        assert_eq!(decode("Zm9vYg").unwrap(), b"foob");
        assert_eq!(decode("Zm9vYmE").unwrap(), b"fooba");
        assert_eq!(decode("Zm9vYmFy").unwrap(), b"foobar");
    }

    #[test]
    fn encodes_known_values() {
        assert_eq!(encode(b""), "");
        assert_eq!(encode(b"f"), "Zg");
        assert_eq!(encode(b"fo"), "Zm8");
        assert_eq!(encode(b"foo"), "Zm9v");
        assert_eq!(encode(b"foob"), "Zm9vYg");
        assert_eq!(encode(b"fooba"), "Zm9vYmE");
        assert_eq!(encode(b"foobar"), "Zm9vYmFy");
        // url-safe alphabet: 0xfb 0xef 0xff -> "--__".
        assert_eq!(encode(&[0xfb, 0xef, 0xff]), "--__");
    }

    #[test]
    fn round_trips() {
        for len in 0..64 {
            let bytes: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
            assert_eq!(decode(&encode(&bytes)).unwrap(), bytes);
        }
    }

    #[test]
    fn handles_url_alphabet() {
        // 0xFB 0xFF 0xBF -> "-_-_" in std base64 becomes "+/+/"; url-safe uses -_.
        let bytes = decode("--__").unwrap();
        assert_eq!(bytes, vec![0xfb, 0xef, 0xff]);
    }

    #[test]
    fn rejects_padding_and_bad_chars() {
        assert!(decode("Zg==").is_err()); // no padding allowed
        assert!(decode("Zm9v!").is_err()); // illegal char
        assert!(decode("Z").is_err()); // 6 bits, non-zero remainder is impossible but len 1 invalid tail
    }
}
