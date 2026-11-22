// pf_xmldsig - shared building blocks for proving statements about EFI messages signed with
// enveloped XML-DSig (exc-C14N, SHA-256, RSA-2048 PKCS#1 v1.5).
//
// Rule of the house: no function here accepts "a SignedInfo" from the prover. SignedInfo is rebuilt
// from a fixed template around the document digest, so a proof can only exist for the exact
// canonical SignedInfo the signer produced.

use bignum::{params::BigNumParams, RuntimeBigNum};
use noir_rsa::rsa::verify_sha256_pkcs1v15;
use poseidon::poseidon2::Poseidon2;

// Domain separator for key hashes: ASCII "PF-RSAKEY1".
global DOMAIN_RSA_KEY: Field = 0x50462d5253414b455931;
// Domain separator: ASCII "PF-RSATAG1".
global DOMAIN_RSA_TAG: Field = 0x50462d52534154414731;

// --- Canonical SignedInfo = SI_HEAD || URI || SI_MID || base64(digest) || SI_TAIL ---
global SI_HEAD: [u8; 270] = "<SignedInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"></CanonicalizationMethod><SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"></SignatureMethod><Reference URI=\"#"
    .as_bytes();
global SI_MID: [u8; 285] = "\"><Transforms><Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"></Transform><Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"></Transform></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"></DigestMethod><DigestValue>"
    .as_bytes();
global SI_TAIL: [u8; 39] = "</DigestValue></Reference></SignedInfo>".as_bytes();
global URI_RESPONSE: [u8; 8] = "Response".as_bytes();
global URI_REQUEST: [u8; 7] = "Request".as_bytes();

// The first 512 bytes of the canonical SignedInfo are the same for every message of a kind, so
// their SHA-256 state is a constant. Only what follows is hashed in the circuit: the rest of the
// fixed text up to the digest, the base64 digest and SI_TAIL (three blocks instead of eleven).
// The unit tests check both against a plain SHA-256 of the full text.
global SI_STATE_RESPONSE: [u32; 8] = [0x944fdbd6, 0xf9cd7bf1, 0x7f93babe, 0x5746b793, 0xe176949a, 0x7d88b3f2, 0x6fc05f33, 0xb321c4b3];
global SI_REST_RESPONSE: [u8; 51] = "2001/04/xmlenc#sha256\"></DigestMethod><DigestValue>".as_bytes();
global SI_STATE_REQUEST: [u32; 8] = [0x66163296, 0x41574ecf, 0x618f9e5d, 0x20a1f078, 0x61463b66, 0xdfaae167, 0x9897e6c3, 0xf0b2f805];
global SI_REST_REQUEST: [u8; 50] = "001/04/xmlenc#sha256\"></DigestMethod><DigestValue>".as_bytes();

global B64_ALPHABET: [u8; 64] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    .as_bytes();

/// Standard base64 of a 32-byte digest (43 characters + one '=').
pub fn base64_encode_32(d: [u8; 32]) -> [u8; 44] {
    let mut out: [u8; 44] = [0; 44];
    for g in 0..10 {
        let v: u32 = ((d[3 * g] as u32) << 16) | ((d[3 * g + 1] as u32) << 8) | (d[3 * g + 2] as u32);
        out[4 * g] = B64_ALPHABET[(v >> 18) & 63];
        out[4 * g + 1] = B64_ALPHABET[(v >> 12) & 63];
        out[4 * g + 2] = B64_ALPHABET[(v >> 6) & 63];
        out[4 * g + 3] = B64_ALPHABET[v & 63];
    }
    let v: u32 = ((d[30] as u32) << 16) | ((d[31] as u32) << 8);
    out[40] = B64_ALPHABET[(v >> 18) & 63];
    out[41] = B64_ALPHABET[(v >> 12) & 63];
    out[42] = B64_ALPHABET[(v >> 6) & 63];
    out[43] = 61; // '='
    out
}

/// Finishes the SHA-256 of a canonical SignedInfo from the state after its first 512 bytes:
/// `rest` (fixed text up to the digest), the base64 digest, SI_TAIL, then SHA-256 padding.
fn finish_signed_info<let R: u32>(state_512: [u32; 8], rest: [u8; R], doc_digest: [u8; 32]) -> [u8; 32] {
    let b64 = base64_encode_32(doc_digest);
    let n = R + 44 + 39; // bytes after the first 512
    assert(n + 9 <= 192); // message, 0x80 and the 8-byte length fit in three blocks
    let mut buf: [u8; 192] = [0; 192];
    for i in 0..R {
        buf[i] = rest[i];
    }
    for i in 0..44 {
        buf[R + i] = b64[i];
    }
    for i in 0..39 {
        buf[R + 44 + i] = SI_TAIL[i];
    }
    buf[n] = 0x80;
    // total length in bits, big-endian, in the last eight bytes
    let mut bit_length: u64 = ((512 + n) as u64) * 8;
    for i in 0..8 {
        buf[191 - i] = (bit_length % 256) as u8;
        bit_length = bit_length / 256;
    }

    let mut state = state_512;
    for b in 0..3 {
        let mut w: [u32; 16] = [0; 16];
        for j in 0..16 {
            let o = 64 * b + 4 * j;
            w[j] = ((buf[o] as u32) << 24)
                | ((buf[o + 1] as u32) << 16)
                | ((buf[o + 2] as u32) << 8)
                | (buf[o + 3] as u32);
        }
        state = std::hash::sha256_compression(w, state);
    }

    let mut out: [u8; 32] = [0; 32];
    for j in 0..8 {
        out[4 * j] = (state[j] >> 24) as u8;
        out[4 * j + 1] = ((state[j] >> 16) & 0xff) as u8;
        out[4 * j + 2] = ((state[j] >> 8) & 0xff) as u8;
        out[4 * j + 3] = (state[j] & 0xff) as u8;
    }
    out
}

/// SHA-256 of the canonical SignedInfo whose single Reference is URI="#Response".
pub fn signed_info_digest_response(doc_digest: [u8; 32]) -> [u8; 32] {
    finish_signed_info(SI_STATE_RESPONSE, SI_REST_RESPONSE, doc_digest)
}

/// SHA-256 of the canonical SignedInfo whose single Reference is URI="#Request".
pub fn signed_info_digest_request(doc_digest: [u8; 32]) -> [u8; 32] {
    finish_signed_info(SI_STATE_REQUEST, SI_REST_REQUEST, doc_digest)
}

/// Limbs of an RSA-2048 modulus: 120-bit, little-endian, the top limb non-zero (a genuine 2048-bit
/// modulus).
fn assert_modulus_limbs(modulus: [u128; 18]) {
    for i in 0..17 {
        (modulus[i] as Field).assert_max_bit_size::<120>();
    }
    (modulus[17] as Field).assert_max_bit_size::<8>();
    assert(modulus[17] != 0, "rsa key: modulus is not 2048 bits");
}

fn hash_modulus(domain: Field, modulus: [u128; 18]) -> Field {
    let mut pre: [Field; 19] = [0; 19];
    pre[0] = domain;
    for i in 0..18 {
        pre[i + 1] = modulus[i] as Field;
    }
    Poseidon2::hash(pre, 19)
}

/// Hash that pins an RSA-2048 public key (e = 65537) to one field element. This is the value the
/// circuits publish for a key.
pub fn rsa_key_hash(modulus: [u128; 18]) -> Field {
    assert_modulus_limbs(modulus);
    hash_modulus(DOMAIN_RSA_KEY, modulus)
}

/// A second hash of the same key, which the circuits never publish. A value derived from it can be
/// recomputed by someone who holds the key (its certificate), but not from the published key hash.
pub fn rsa_key_tag(modulus: [u128; 18]) -> Field {
    assert_modulus_limbs(modulus);
    hash_modulus(DOMAIN_RSA_TAG, modulus)
}

/// RSA-2048 PKCS#1 v1.5 / SHA-256 with e = 65537. `redc_param` only feeds unconstrained Barrett
/// hints: a wrong value makes proving fail, it cannot make a bad signature pass.
pub fn assert_rsa_sha256(
    digest: [u8; 32],
    signature: [u128; 18],
    modulus: [u128; 18],
    redc_param: [u128; 18],
) {
    assert_modulus_limbs(modulus);
    let params: BigNumParams<18, 2048> = BigNumParams::new(false, modulus, redc_param);
    let sig: RuntimeBigNum<18, 2048> = RuntimeBigNum::from_array(params, signature);
    sig.validate_in_range();
    assert(verify_sha256_pkcs1v15(digest, sig, 65537), "rsa: signature invalid");
}

// --- Character-class-checked field parsers ---
fn hex_values() -> [u8; 256] {
    let mut t: [u8; 256] = [255; 256];
    for i in 0..10 {
        t[48 + i] = i as u8; // '0'..'9'
    }
    for i in 0..6 {
        t[65 + i] = 10 + i as u8; // 'A'..'F'
        t[97 + i] = 10 + i as u8; // 'a'..'f'
    }
    t
}

// Value of each byte as a hexadecimal digit, 255 for bytes that are not one.
global HEX_VALUE: [u8; 256] = hex_values();

/// One hexadecimal character -> its value. Rejects everything else.
pub fn hex_nibble(c: u8) -> u8 {
    let v = HEX_VALUE[c as u32];
    assert(v != 255, "hex: character is not hexadecimal");
    v
}

/// 32 hexadecimal characters -> 128-bit value.
pub fn parse_hex32(s: [u8; 32]) -> Field {
    let mut acc: Field = 0;
    for i in 0..32 {
        acc = acc * 16 + (hex_nibble(s[i]) as Field);
    }
    acc
}

/// 8-4-4-4-12 UUID text -> 128-bit value. Every one of the 36 characters is constrained.
pub fn parse_uuid(s: [u8; 36]) -> Field {
    let mut acc: Field = 0;
    for i in 0..36 {
        if (i == 8) | (i == 13) | (i == 18) | (i == 23) {
            assert(s[i] == 45, "uuid: expected '-'");
        } else {
            acc = acc * 16 + (hex_nibble(s[i]) as Field);
        }
    }
    acc
}

pub fn digit(c: u8) -> u64 {
    assert((c >= 48) & (c <= 57), "expected a digit");
    (c - 48) as u64
}

/// A date and time as the schema writes it (UTCSType): "YYYY-MM-DDThh:mm:ss" followed by "Z" or by
/// an offset "+hh:mm" / "-hh:mm".
pub struct DateTime {
    /// YYYYMMDDhhmmss, the digits as written.
    pub written: Field,
    /// How the zone is written: 10000 + hhmm for "+hh:mm", 20000 + hhmm for "-hh:mm", 30000 for
    /// "Z". Together with `written` it gives back the exact text.
    pub zone: Field,
    pub year: u32,
    /// month * 100 + day, as written.
    pub month_day: u32,
    /// Minutes since midnight, as written.
    pub minute_of_day: u32,
    /// Distance from UTC in minutes (0 for "Z"), and whether it is written with '-'.
    pub offset_minutes: u32,
    pub offset_negative: bool,
    /// Characters the text takes: 20 when it ends in "Z", 25 with an offset.
    pub len: u32,
}

/// A date and time (see `DateTime`) followed by the '"' that closes the attribute value. Every
/// character up to and including that quote is constrained: month, day and time of day are in
/// range and the offset is at most 14:00. When the text ends in "Z" the five bytes after the
/// quote belong to whatever follows and are not looked at.
pub fn parse_datetime_until_quote(s: [u8; 26]) -> DateTime {
    assert(s[4] == 45, "datetime: expected '-'");
    assert(s[7] == 45, "datetime: expected '-'");
    assert(s[10] == 84, "datetime: expected 'T'");
    assert(s[13] == 58, "datetime: expected ':'");
    assert(s[16] == 58, "datetime: expected ':'");

    let year = digit(s[0]) * 1000 + digit(s[1]) * 100 + digit(s[2]) * 10 + digit(s[3]);
    let month = digit(s[5]) * 10 + digit(s[6]);
    let day = digit(s[8]) * 10 + digit(s[9]);
    let hour = digit(s[11]) * 10 + digit(s[12]);
    let minute = digit(s[14]) * 10 + digit(s[15]);
    let second = digit(s[17]) * 10 + digit(s[18]);
    assert((month >= 1) & (month <= 12), "datetime: month out of range");
    assert((day >= 1) & (day <= 31), "datetime: day out of range");
    assert(hour <= 23, "datetime: hour out of range");
    assert((minute <= 59) & (second <= 59), "datetime: minute or second out of range");

    let utc = s[19] == 90; // 'Z'
    let mut offset_hours: u64 = 0;
    let mut offset_minutes: u64 = 0;
    let mut offset_negative = false;
    if utc {
        assert(s[20] == 34, "datetime: not closed after 'Z'");
    } else {
        assert((s[19] == 43) | (s[19] == 45), "datetime: expected '+', '-' or 'Z'");
        offset_negative = s[19] == 45;
        offset_hours = digit(s[20]) * 10 + digit(s[21]);
        assert(s[22] == 58, "datetime: expected ':'");
        offset_minutes = digit(s[23]) * 10 + digit(s[24]);
        assert(
            ((offset_hours <= 13) & (offset_minutes <= 59)) | ((offset_hours == 14) & (offset_minutes == 0)),
            "datetime: offset out of range",
        );
        assert(s[25] == 34, "datetime: not closed after the offset");
    }

    let written = ((((year * 100 + month) * 100 + day) * 100 + hour) * 100 + minute) * 100 + second;
    let zone = if utc {
        30000
    } else {
        (if offset_negative { 20000 } else { 10000 }) + offset_hours * 100 + offset_minutes
    };
    DateTime {
        written: written as Field,
        zone: zone as Field,
        year: year as u32,
        month_day: (month * 100 + day) as u32,
        minute_of_day: (hour * 60 + minute) as u32,
        offset_minutes: (offset_hours * 60 + offset_minutes) as u32,
        offset_negative,
        len: if utc { 20 } else { 25 },
    }
}

/// A date and time that takes all 25 characters given, that is, one written with an offset.
pub fn parse_datetime(s: [u8; 25]) -> DateTime {
    let mut closed: [u8; 26] = [34; 26];
    for i in 0..25 {
        closed[i] = s[i];
    }
    let dt = parse_datetime_until_quote(closed);
    assert(dt.len == 25, "datetime: expected an offset");
    dt
}

/// (year, month * 100 + day) of the moment on a clock `minutes_east` minutes ahead of UTC, exact
/// where the year on that clock is not the year as written: a time written in UTC or with another
/// offset can fall on the other side of New Year. On every other day the date is given as
/// written, which can be one day off.
pub fn date_on_clock(dt: DateTime, minutes_east: u32) -> (u32, u32) {
    assert(minutes_east <= 840);
    // Minutes since the written day began, counted on that clock, plus 840 so that it cannot go
    // below zero (offsets reach 14 hours either way).
    let t = if dt.offset_negative {
        dt.minute_of_day + minutes_east + 840 + dt.offset_minutes
    } else {
        dt.minute_of_day + minutes_east + 840 - dt.offset_minutes
    };
    let next_year = (dt.month_day == 1231) & (t >= 1440 + 840);
    let previous_year = (dt.month_day == 101) & (t < 840);
    if next_year {
        (dt.year + 1, 101)
    } else if previous_year {
        (dt.year - 1, 1231)
    } else {
        (dt.year, dt.month_day)
    }
}

/// EFI registration code "[a-z]{2}[0-9]{3}[a-z]{2}[0-9]{3}" -> its 10 bytes packed big-endian.
pub fn parse_registration_code(s: [u8; 10]) -> Field {
    let mut acc: Field = 0;
    for i in 0..10 {
        let c = s[i];
        if (i == 0) | (i == 1) | (i == 5) | (i == 6) {
            assert((c >= 97) & (c <= 122), "registration code: expected a-z");
        } else {
            assert((c >= 48) & (c <= 57), "registration code: expected a digit");
        }
        acc = acc * 256 + (c as Field);
    }
    acc
}

/// Decimal digits terminated by '"' (1 to N-1 digits, the first not '0') -> value, at least 1.
pub fn parse_uint_until_quote<let N: u32>(b: [u8; N]) -> u64 {
    let mut acc: u64 = 0;
    let mut digits: u32 = 0;
    let mut done = false;
    for j in 0..N {
        if !done {
            if b[j] == 34 {
                assert(digits >= 1, "integer: empty");
                done = true;
            } else {
                let d = digit(b[j]);
                if digits == 0 {
                    assert(d != 0, "integer: leading zero");
                }
                acc = acc * 10 + d;
                digits += 1;
            }
        }
    }
    assert(done, "integer: not terminated");
    acc
}

/// EFI amount terminated by '"': "-?([1-9][0-9]*|0)\.[0-9]{2}" or plain "0" -> (negative, cents).
pub fn parse_amount_until_quote(b: [u8; 16]) -> (bool, u64) {
    let mut neg = false;
    let mut cents: u64 = 0;
    let mut int_digits: u32 = 0;
    let mut frac_digits: u32 = 0;
    let mut seen_dot = false;
    let mut leading_zero = false;
    let mut done = false;
    for j in 0..16 {
        let c = b[j];
        if !done {
            if c == 34 {
                let plain_zero = !seen_dot & !neg & (int_digits == 1) & (cents == 0);
                assert((seen_dot & (frac_digits == 2)) | plain_zero, "amount: malformed");
                assert(!leading_zero | (int_digits == 1), "amount: leading zero");
                assert(!neg | (cents != 0), "amount: negative zero");
                done = true;
            } else if c == 45 {
                assert(j == 0, "amount: '-' only allowed first");
                neg = true;
            } else if c == 46 {
                assert(!seen_dot & (int_digits >= 1), "amount: misplaced '.'");
                seen_dot = true;
            } else {
                let d = digit(c);
                if !seen_dot & (int_digits == 0) {
                    leading_zero = d == 0;
                }
                cents = cents * 10 + d;
                if seen_dot {
                    frac_digits += 1;
                } else {
                    int_digits += 1;
                }
            }
        }
    }
    assert(done, "amount: not terminated");
    (neg, cents)
}

// --- Tests ---
/// Test helper: fit a literal into a fixed buffer (zero-padded or truncated).
fn pad<let N: u32, let M: u32>(s: [u8; N]) -> [u8; M] {
    let mut out: [u8; M] = [0; M];
    for i in 0..N {
        if i < M {
            out[i] = s[i];
        }
    }
    out
}

/// Test reference: the full canonical SignedInfo text for a digest, built the plain way.
fn full_signed_info<let U: u32, let N: u32>(uri: [u8; U], doc_digest: [u8; 32]) -> [u8; N] {
    let b64 = base64_encode_32(doc_digest);
    let mut si: [u8; N] = [0; N];
    for i in 0..270 {
        si[i] = SI_HEAD[i];
    }
    for i in 0..U {
        si[270 + i] = uri[i];
    }
    for i in 0..285 {
        si[270 + U + i] = SI_MID[i];
    }
    for i in 0..44 {
        si[555 + U + i] = b64[i];
    }
    for i in 0..39 {
        si[599 + U + i] = SI_TAIL[i];
    }
    si
}

#[test]
fn test_signed_info_digest_matches_plain_sha256() {
    let digests: [[u8; 32]; 3] = [[0; 32], [255; 32], sha256::digest("any document".as_bytes())];
    for k in 0..3 {
        let response: [u8; 646] = full_signed_info(URI_RESPONSE, digests[k]);
        assert(signed_info_digest_response(digests[k]) == sha256::digest(response));
        let request: [u8; 645] = full_signed_info(URI_REQUEST, digests[k]);
        assert(signed_info_digest_request(digests[k]) == sha256::digest(request));
    }
}

#[test]
fn test_hex_nibble_values() {
    assert(hex_nibble(48) == 0);
    assert(hex_nibble(57) == 9);
    assert(hex_nibble(97) == 10);
    assert(hex_nibble(102) == 15);
    assert(hex_nibble(65) == 10);
    assert(hex_nibble(70) == 15);
}

#[test(should_fail_with = "hex: character is not hexadecimal")]
fn test_hex_nibble_rejects_g() {
    let _ = hex_nibble(103);
}

#[test(should_fail_with = "hex: character is not hexadecimal")]
fn test_hex_nibble_rejects_slash() {
    let _ = hex_nibble(47);
}

#[test]
fn test_base64_known_vector() {
    // SHA-256("") = e3b0c442...b855 -> "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="
    let d: [u8; 32] = [
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
        0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
    ];
    assert(base64_encode_32(d) == "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=".as_bytes());
    assert(sha256::digest([0; 0]) == d);
}

#[test]
fn test_parse_uuid() {
    let v = parse_uuid("00000000-0000-4000-8000-0000000000ff".as_bytes());
    assert(v == 0x00000000000040008000_0000000000ff);
    assert(parse_uuid("ABCDEF00-0000-4000-8000-000000000001".as_bytes())
        == parse_uuid("abcdef00-0000-4000-8000-000000000001".as_bytes()));
}

#[test(should_fail_with = "hex: character is not hexadecimal")]
fn test_parse_uuid_rejects_markup() {
    let _ = parse_uuid("0000000<-0000-4000-8000-0000000000ff".as_bytes());
}

#[test(should_fail_with = "uuid: expected '-'")]
fn test_parse_uuid_rejects_shifted_dash() {
    let _ = parse_uuid("000000000-000-4000-8000-0000000000ff".as_bytes());
}

#[test]
fn test_parse_datetime() {
    let a = parse_datetime("2026-03-14T09:26:53+01:00".as_bytes());
    assert(a.written == 20260314092653);
    assert(a.zone == 10100);
    assert(a.year == 2026);
    assert(a.month_day == 314);
    assert(a.minute_of_day == 9 * 60 + 26);
    assert(a.offset_minutes == 60);
    assert(!a.offset_negative);
    assert(a.len == 25);
    let b = parse_datetime("2026-07-31T23:59:59+02:00".as_bytes());
    assert(b.written == 20260731235959);
    assert(b.zone == 10200);
}

#[test]
fn test_parse_datetime_reads_every_way_the_schema_writes_the_zone() {
    // UTC as "Z": 20 characters, then the closing quote; what follows is not looked at.
    let z = parse_datetime_until_quote("2026-03-14T08:26:53Z\" UUID".as_bytes());
    assert(z.written == 20260314082653);
    assert(z.zone == 30000);
    assert(z.offset_minutes == 0);
    assert(z.len == 20);
    // UTC as an offset of zero, with either sign.
    let p = parse_datetime_until_quote("2026-03-14T08:26:53+00:00\"".as_bytes());
    assert(p.zone == 10000);
    assert(p.offset_minutes == 0);
    assert(p.len == 25);
    let m = parse_datetime_until_quote("2026-03-14T08:26:53-00:00\"".as_bytes());
    assert(m.zone == 20000);
    assert(m.offset_negative);
    // West of UTC, and the largest offsets there are.
    let w = parse_datetime_until_quote("2026-03-14T03:56:53-04:30\"".as_bytes());
    assert(w.zone == 20430);
    assert(w.offset_minutes == 270);
    assert(w.offset_negative);
    assert(parse_datetime_until_quote("2026-03-14T22:26:53+14:00\"".as_bytes()).offset_minutes == 840);
    assert(parse_datetime_until_quote("2026-03-13T18:26:53-14:00\"".as_bytes()).zone == 21400);
    assert(parse_datetime_until_quote("2026-03-14T13:11:53+05:45\"".as_bytes()).zone == 10545);
}

#[test]
fn test_the_three_spellings_of_utc_differ_in_what_is_committed() {
    let z = parse_datetime_until_quote("2026-03-14T08:26:53Z\"     ".as_bytes());
    let p = parse_datetime_until_quote("2026-03-14T08:26:53+00:00\"".as_bytes());
    let m = parse_datetime_until_quote("2026-03-14T08:26:53-00:00\"".as_bytes());
    assert(z.written == p.written);
    assert((z.zone != p.zone) & (p.zone != m.zone) & (z.zone != m.zone));
}

#[test(should_fail_with = "datetime: month out of range")]
fn test_parse_datetime_rejects_month_13() {
    let _ = parse_datetime("2026-13-14T09:26:53+01:00".as_bytes());
}

#[test(should_fail_with = "datetime: day out of range")]
fn test_parse_datetime_rejects_day_0() {
    let _ = parse_datetime("2026-03-00T09:26:53+01:00".as_bytes());
}

#[test(should_fail_with = "datetime: hour out of range")]
fn test_parse_datetime_rejects_hour_24() {
    let _ = parse_datetime("2026-03-14T24:00:00+01:00".as_bytes());
}

#[test(should_fail_with = "datetime: offset out of range")]
fn test_parse_datetime_rejects_offset_above_14_hours() {
    let _ = parse_datetime("2026-12-31T23:30:00+14:01".as_bytes());
}

#[test(should_fail_with = "datetime: offset out of range")]
fn test_parse_datetime_rejects_offset_of_15_hours() {
    let _ = parse_datetime("2026-12-31T23:30:00-15:00".as_bytes());
}

#[test(should_fail_with = "datetime: offset out of range")]
fn test_parse_datetime_rejects_60_minutes_of_offset() {
    let _ = parse_datetime("2026-12-31T23:30:00+01:60".as_bytes());
}

#[test(should_fail_with = "datetime: expected 'T'")]
fn test_parse_datetime_rejects_space() {
    let _ = parse_datetime("2026-03-14 09:26:53+01:00".as_bytes());
}

#[test(should_fail_with = "datetime: expected '+', '-' or 'Z'")]
fn test_parse_datetime_rejects_missing_zone() {
    let _ = parse_datetime_until_quote("2026-03-14T09:26:53\" UUID=".as_bytes());
}

#[test(should_fail_with = "datetime: expected '+', '-' or 'Z'")]
fn test_parse_datetime_rejects_lower_case_z() {
    let _ = parse_datetime_until_quote("2026-03-14T09:26:53z\" UUID".as_bytes());
}

#[test(should_fail_with = "datetime: expected '+', '-' or 'Z'")]
fn test_parse_datetime_rejects_fraction_of_a_second() {
    let _ = parse_datetime_until_quote("2026-03-14T09:26:53.123Z\" ".as_bytes());
}

#[test(should_fail_with = "datetime: not closed after 'Z'")]
fn test_parse_datetime_rejects_text_after_z() {
    let _ = parse_datetime_until_quote("2026-03-14T09:26:53Z+01:00".as_bytes());
}

#[test(should_fail_with = "datetime: not closed after the offset")]
fn test_parse_datetime_rejects_text_after_offset() {
    let _ = parse_datetime_until_quote("2026-03-14T09:26:53+01:000".as_bytes());
}

#[test(should_fail_with = "datetime: expected ':'")]
fn test_parse_datetime_rejects_offset_without_colon() {
    let _ = parse_datetime_until_quote("2026-03-14T09:26:53+0100\"\"".as_bytes());
}

#[test(should_fail_with = "expected a digit")]
fn test_parse_datetime_rejects_one_digit_offset() {
    let _ = parse_datetime_until_quote("2026-03-14T09:26:53+1:00\"\"".as_bytes());
}

#[test(should_fail_with = "datetime: expected an offset")]
fn test_fixed_width_datetime_rejects_z() {
    // In a place that holds 25 characters, a "Z" time would have to bring its own closing quote.
    let _ = parse_datetime("2026-03-14T09:26:53Z\"abcd".as_bytes());
}

fn on_clock(text: str<26>) -> (u32, u32) {
    date_on_clock(parse_datetime_until_quote(text.as_bytes()), 60)
}

#[test]
fn test_date_on_the_countrys_clock() {
    // Written on that clock: the year is the one written.
    assert(on_clock("2027-01-01T00:30:00+01:00\"") == (2027, 101));
    assert(on_clock("2026-12-31T23:59:59+01:00\"") == (2026, 1231));
    // Half past midnight on New Year's Day there, written in UTC: still 31 December in the text.
    assert(on_clock("2026-12-31T23:30:00Z\"     ") == (2027, 101));
    assert(on_clock("2026-12-31T23:30:00+00:00\"") == (2027, 101));
    assert(on_clock("2026-12-31T23:00:00Z\"     ") == (2027, 101));
    assert(on_clock("2026-12-31T22:59:59Z\"     ") == (2026, 1231));
    // The same moment written west of UTC.
    assert(on_clock("2026-12-31T18:30:00-05:00\"") == (2027, 101));
    assert(on_clock("2026-12-31T17:59:00-05:00\"") == (2026, 1231));
    // Written ahead of that clock: 00:30 at +02:00 on 1 January is still 23:30 on 31 December there.
    assert(on_clock("2027-01-01T00:30:00+02:00\"") == (2026, 1231));
    assert(on_clock("2027-01-01T01:00:00+02:00\"") == (2027, 101));
    assert(on_clock("2027-01-01T12:59:00+14:00\"") == (2026, 1231));
    assert(on_clock("2027-01-01T13:00:00+14:00\"") == (2027, 101));
    // Other days of the year are given as written.
    assert(on_clock("2026-06-30T23:30:00Z\"     ") == (2026, 630));
    assert(on_clock("2026-01-02T00:10:00+02:00\"") == (2026, 102));
}

#[test]
fn test_parse_amount() {
    assert(parse_amount_until_quote(pad("17.15\" TotPriceWo".as_bytes())) == (false, 1715));
    assert(parse_amount_until_quote(pad("-1250.00\" TotPric".as_bytes())) == (true, 125000));
    assert(parse_amount_until_quote(pad("0\" TotPriceWoVAT=".as_bytes())) == (false, 0));
    assert(parse_amount_until_quote(pad("0.05\" TotPriceWoV".as_bytes())) == (false, 5));
}

#[test(should_fail_with = "amount: leading zero")]
fn test_parse_amount_rejects_leading_zero() {
    let _ = parse_amount_until_quote(pad("017.15\" TotPriceW".as_bytes()));
}

#[test(should_fail_with = "amount: negative zero")]
fn test_parse_amount_rejects_negative_zero() {
    let _ = parse_amount_until_quote(pad("-0.00\" TotPriceWo".as_bytes()));
}

#[test(should_fail_with = "integer: leading zero")]
fn test_parse_uint_rejects_leading_zero() {
    let _ = parse_uint_until_quote::<16>(pad("007\" InvType=".as_bytes()));
}

#[test(should_fail_with = "integer: leading zero")]
fn test_parse_uint_rejects_zero() {
    let _ = parse_uint_until_quote::<16>(pad("0\" InvType=".as_bytes()));
}

#[test]
fn test_key_tag_differs_from_key_hash() {
    let mut modulus: [u128; 18] = [7; 18];
    modulus[17] = 0x80;
    assert(rsa_key_tag(modulus) != rsa_key_hash(modulus));
}

#[test(should_fail_with = "amount: malformed")]
fn test_parse_amount_rejects_one_decimal() {
    let _ = parse_amount_until_quote(pad("17.1\" TotPriceWoV".as_bytes()));
}

#[test(should_fail_with = "expected a digit")]
fn test_parse_amount_rejects_comma() {
    let _ = parse_amount_until_quote(pad("17,15\" TotPriceWo".as_bytes()));
}

#[test(should_fail_with = "amount: malformed")]
fn test_parse_amount_rejects_bare_integer() {
    let _ = parse_amount_until_quote(pad("17\" TotPriceWoVAT".as_bytes()));
}

#[test(should_fail_with = "amount: not terminated")]
fn test_parse_amount_rejects_overlong() {
    let _ = parse_amount_until_quote(pad("1234567890123.45".as_bytes()));
}

#[test]
fn test_parse_uint_and_code() {
    assert(parse_uint_until_quote::<16>(pad("1\" InvType=".as_bytes())) == 1);
    assert(parse_uint_until_quote::<16>(pad("4294967295\"".as_bytes())) == 4294967295);
    assert(parse_registration_code("xy987zw654".as_bytes()) == 0x78793938377a77363534);
}

#[test(should_fail_with = "registration code: expected a-z")]
fn test_registration_code_rejects_uppercase() {
    let _ = parse_registration_code("XY987zw654".as_bytes());
}
