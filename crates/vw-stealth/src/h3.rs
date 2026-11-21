//! Minimal HTTP/3 (RFC 9114) framing and QPACK (RFC 9204) static-table coding,
//! just enough for extended CONNECT (RFC 9220) + CONNECT-UDP (RFC 9298).
//!
//! We advertise `SETTINGS_QPACK_MAX_TABLE_CAPACITY = 0` and
//! `SETTINGS_QPACK_BLOCKED_STREAMS = 0`, so a conforming peer never references
//! the dynamic table. We never Huffman-encode; Huffman-encoded strings from
//! peers are carried as "undecodable" (only `:status`, which servers send as a
//! static index, matters for the client).

use std::io;

use tokio::io::{AsyncRead, AsyncReadExt};

pub const FRAME_DATA: u64 = 0x00;
pub const FRAME_HEADERS: u64 = 0x01;
pub const FRAME_SETTINGS: u64 = 0x04;
pub const FRAME_GOAWAY: u64 = 0x07;

pub const STREAM_CONTROL: u64 = 0x00;

pub const SETTINGS_QPACK_MAX_TABLE_CAPACITY: u64 = 0x01;
pub const SETTINGS_QPACK_BLOCKED_STREAMS: u64 = 0x07;
pub const SETTINGS_ENABLE_CONNECT_PROTOCOL: u64 = 0x08;
pub const SETTINGS_H3_DATAGRAM: u64 = 0x33;

/// H3_NO_ERROR / H3_GENERAL_PROTOCOL_ERROR / H3_REQUEST_REJECTED.
pub const H3_NO_ERROR: u32 = 0x100;
pub const H3_GENERAL_PROTOCOL_ERROR: u32 = 0x101;

/// Largest frame payload we buffer (HEADERS / SETTINGS).
pub const MAX_FRAME: usize = 16 * 1024;

// ---------------------------------------------------------------- varints

/// Append a QUIC variable-length integer (RFC 9000 §16).
pub fn put_varint(v: u64, out: &mut Vec<u8>) {
    if v < 1 << 6 {
        out.push(v as u8);
    } else if v < 1 << 14 {
        out.extend_from_slice(&((v as u16) | 0x4000).to_be_bytes());
    } else if v < 1 << 30 {
        out.extend_from_slice(&((v as u32) | 0x8000_0000).to_be_bytes());
    } else {
        debug_assert!(v < 1 << 62);
        out.extend_from_slice(&(v | 0xc000_0000_0000_0000).to_be_bytes());
    }
}

/// Decode a varint from the front of `b`: `(value, bytes consumed)`.
pub fn get_varint(b: &[u8]) -> Option<(u64, usize)> {
    let first = *b.first()?;
    let len = 1usize << (first >> 6);
    let bytes = b.get(..len)?;
    let mut v = u64::from(first & 0x3f);
    for x in &bytes[1..] {
        v = (v << 8) | u64::from(*x);
    }
    Some((v, len))
}

pub async fn read_varint<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<u64> {
    let first = r.read_u8().await?;
    let len = 1usize << (first >> 6);
    let mut v = u64::from(first & 0x3f);
    for _ in 1..len {
        v = (v << 8) | u64::from(r.read_u8().await?);
    }
    Ok(v)
}

// ---------------------------------------------------------------- frames

pub fn frame(ty: u64, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 4);
    put_varint(ty, &mut out);
    put_varint(payload.len() as u64, &mut out);
    out.extend_from_slice(payload);
    out
}

pub fn settings_frame(settings: &[(u64, u64)]) -> Vec<u8> {
    let mut p = Vec::new();
    for (k, v) in settings {
        put_varint(*k, &mut p);
        put_varint(*v, &mut p);
    }
    frame(FRAME_SETTINGS, &p)
}

pub fn parse_settings(mut p: &[u8]) -> Option<Vec<(u64, u64)>> {
    let mut out = Vec::new();
    while !p.is_empty() {
        let (k, a) = get_varint(p)?;
        let (v, b) = get_varint(&p[a..])?;
        out.push((k, v));
        p = &p[a + b..];
    }
    Some(out)
}

/// Read one frame. `Ok(None)` on a clean end of stream at a frame boundary.
/// Frames larger than [`MAX_FRAME`] are rejected.
pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<Option<(u64, Vec<u8>)>> {
    let ty = match read_varint(r).await {
        Ok(t) => t,
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    };
    let len = read_varint(r).await?;
    if len > MAX_FRAME as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "h3 frame too large",
        ));
    }
    let mut payload = vec![0u8; len as usize];
    r.read_exact(&mut payload).await?;
    Ok(Some((ty, payload)))
}

/// Read frames until a HEADERS frame (skipping unknown / reserved frame
/// types, RFC 9114 §9). Returns `None` at end of stream.
pub async fn read_headers<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<Option<Vec<u8>>> {
    loop {
        match read_frame(r).await? {
            None => return Ok(None),
            Some((FRAME_HEADERS, p)) => return Ok(Some(p)),
            Some((FRAME_DATA | FRAME_SETTINGS | FRAME_GOAWAY, _)) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unexpected h3 frame on request stream",
                ))
            }
            Some(_) => continue,
        }
    }
}

// ---------------------------------------------------------------- QPACK

/// QPACK static table (RFC 9204 Appendix A).
const STATIC: [(&str, &str); 99] = [
    (":authority", ""),
    (":path", "/"),
    ("age", "0"),
    ("content-disposition", ""),
    ("content-length", "0"),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("referer", ""),
    ("set-cookie", ""),
    (":method", "CONNECT"),
    (":method", "DELETE"),
    (":method", "GET"),
    (":method", "HEAD"),
    (":method", "OPTIONS"),
    (":method", "POST"),
    (":method", "PUT"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "103"),
    (":status", "200"),
    (":status", "304"),
    (":status", "404"),
    (":status", "503"),
    ("accept", "*/*"),
    ("accept", "application/dns-message"),
    ("accept-encoding", "gzip, deflate, br"),
    ("accept-ranges", "bytes"),
    ("access-control-allow-headers", "cache-control"),
    ("access-control-allow-headers", "content-type"),
    ("access-control-allow-origin", "*"),
    ("cache-control", "max-age=0"),
    ("cache-control", "max-age=2592000"),
    ("cache-control", "max-age=604800"),
    ("cache-control", "no-cache"),
    ("cache-control", "no-store"),
    ("cache-control", "public, max-age=31536000"),
    ("content-encoding", "br"),
    ("content-encoding", "gzip"),
    ("content-type", "application/dns-message"),
    ("content-type", "application/javascript"),
    ("content-type", "application/json"),
    ("content-type", "application/x-www-form-urlencoded"),
    ("content-type", "image/gif"),
    ("content-type", "image/jpeg"),
    ("content-type", "image/png"),
    ("content-type", "text/css"),
    ("content-type", "text/html; charset=utf-8"),
    ("content-type", "text/plain"),
    ("content-type", "text/plain;charset=utf-8"),
    ("range", "bytes=0-"),
    ("strict-transport-security", "max-age=31536000"),
    (
        "strict-transport-security",
        "max-age=31536000; includesubdomains",
    ),
    (
        "strict-transport-security",
        "max-age=31536000; includesubdomains; preload",
    ),
    ("vary", "accept-encoding"),
    ("vary", "origin"),
    ("x-content-type-options", "nosniff"),
    ("x-xss-protection", "1; mode=block"),
    (":status", "100"),
    (":status", "204"),
    (":status", "206"),
    (":status", "302"),
    (":status", "400"),
    (":status", "403"),
    (":status", "421"),
    (":status", "425"),
    (":status", "500"),
    ("accept-language", ""),
    ("access-control-allow-credentials", "FALSE"),
    ("access-control-allow-credentials", "TRUE"),
    ("access-control-allow-headers", "*"),
    ("access-control-allow-methods", "get"),
    ("access-control-allow-methods", "get, post, options"),
    ("access-control-allow-methods", "options"),
    ("access-control-expose-headers", "content-length"),
    ("access-control-request-headers", "content-type"),
    ("access-control-request-method", "get"),
    ("access-control-request-method", "post"),
    ("alt-svc", "clear"),
    ("authorization", ""),
    (
        "content-security-policy",
        "script-src 'none'; object-src 'none'; base-uri 'none'",
    ),
    ("early-data", "1"),
    ("expect-ct", ""),
    ("forwarded", ""),
    ("if-range", ""),
    ("origin", ""),
    ("purpose", "prefetch"),
    ("server", ""),
    ("timing-allow-origin", "*"),
    ("upgrade-insecure-requests", "1"),
    ("user-agent", ""),
    ("x-forwarded-for", ""),
    ("x-frame-options", "deny"),
    ("x-frame-options", "sameorigin"),
];

/// RFC 7541 §5.1 prefixed integer; `flags` holds the bits above the prefix.
fn put_prefixed(flags: u8, prefix: u8, mut v: u64, out: &mut Vec<u8>) {
    let max = (1u64 << prefix) - 1;
    if v < max {
        out.push(flags | v as u8);
        return;
    }
    out.push(flags | max as u8);
    v -= max;
    while v >= 128 {
        out.push((v % 128) as u8 | 0x80);
        v /= 128;
    }
    out.push(v as u8);
}

fn get_prefixed(b: &[u8], pos: &mut usize, prefix: u8) -> Option<u64> {
    let max = (1u64 << prefix) - 1;
    let mut v = u64::from(*b.get(*pos)?) & max;
    *pos += 1;
    if v < max {
        return Some(v);
    }
    let mut shift = 0u32;
    loop {
        let byte = *b.get(*pos)?;
        *pos += 1;
        if shift > 56 {
            return None;
        }
        v = v.checked_add(u64::from(byte & 0x7f) << shift)?;
        shift += 7;
        if byte & 0x80 == 0 {
            return Some(v);
        }
    }
}

/// Append a string literal (never Huffman) with `prefix`-bit length; the H
/// flag is the bit just above the prefix and stays 0.
fn put_string(flags: u8, prefix: u8, s: &str, out: &mut Vec<u8>) {
    put_prefixed(flags, prefix, s.len() as u64, out);
    out.extend_from_slice(s.as_bytes());
}

/// Read a string literal whose H flag is bit `prefix` of the first byte.
/// Returns `None` inside the option for Huffman-coded strings.
fn get_string(b: &[u8], pos: &mut usize, prefix: u8) -> Option<Option<String>> {
    let huffman = *b.get(*pos)? & (1 << prefix) != 0;
    let len = get_prefixed(b, pos, prefix)? as usize;
    let bytes = b.get(*pos..pos.checked_add(len)?)?;
    *pos += len;
    if huffman {
        return Some(None);
    }
    Some(Some(String::from_utf8(bytes.to_vec()).ok()?))
}

/// Encode a field section with static-table references only.
pub fn qpack_encode(fields: &[(&str, &str)]) -> Vec<u8> {
    // Required Insert Count = 0, Delta Base = 0.
    let mut out = vec![0x00, 0x00];
    for (name, value) in fields {
        if let Some(i) = STATIC.iter().position(|(n, v)| n == name && v == value) {
            // Indexed field line, static (1 T=1 index:6).
            put_prefixed(0xc0, 6, i as u64, &mut out);
        } else if let Some(i) = STATIC.iter().position(|(n, _)| n == name) {
            // Literal with static name reference (01 N=0 T=1 index:4).
            put_prefixed(0x50, 4, i as u64, &mut out);
            put_string(0x00, 7, value, &mut out);
        } else {
            // Literal with literal name (001 N=0 H=0 len:3).
            put_string(0x20, 3, name, &mut out);
            put_string(0x00, 7, value, &mut out);
        }
    }
    out
}

/// A decoded field; `value` is `None` when the peer Huffman-coded it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Field {
    pub name: String,
    pub value: Option<String>,
}

/// Decode a field section that uses only the static table. Fields whose name
/// is Huffman-coded are skipped.
pub fn qpack_decode(b: &[u8]) -> Option<Vec<Field>> {
    let mut pos = 0;
    let ric = get_prefixed(b, &mut pos, 8)?;
    let _delta_base = get_prefixed(b, &mut pos, 7)?;
    if ric != 0 {
        return None;
    }
    let mut out = Vec::new();
    while pos < b.len() {
        let first = b[pos];
        if first & 0x80 != 0 {
            if first & 0x40 == 0 {
                return None; // dynamic table
            }
            let i = get_prefixed(b, &mut pos, 6)? as usize;
            let (n, v) = STATIC.get(i)?;
            out.push(Field {
                name: (*n).into(),
                value: Some((*v).into()),
            });
        } else if first & 0x40 != 0 {
            if first & 0x10 == 0 {
                return None;
            }
            let i = get_prefixed(b, &mut pos, 4)? as usize;
            let (n, _) = STATIC.get(i)?;
            let value = get_string(b, &mut pos, 7)?;
            out.push(Field {
                name: (*n).into(),
                value,
            });
        } else if first & 0x20 != 0 {
            let name = get_string(b, &mut pos, 3)?;
            let value = get_string(b, &mut pos, 7)?;
            if let Some(name) = name {
                out.push(Field { name, value });
            }
        } else {
            return None; // post-base references (dynamic table)
        }
    }
    Some(out)
}

/// First decodable value of `name`.
pub fn field<'a>(fields: &'a [Field], name: &str) -> Option<&'a str> {
    fields
        .iter()
        .find(|f| f.name == name)
        .and_then(|f| f.value.as_deref())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varints() {
        for v in [
            0u64,
            37,
            63,
            64,
            15293,
            16383,
            16384,
            494_878_333,
            (1 << 30) + 5,
            (1 << 62) - 1,
        ] {
            let mut b = Vec::new();
            put_varint(v, &mut b);
            assert_eq!(get_varint(&b), Some((v, b.len())));
        }
        // RFC 9000 §A.1 examples.
        assert_eq!(get_varint(&[0x7b, 0xbd]), Some((15293, 2)));
        assert_eq!(
            get_varint(&[0x9d, 0x7f, 0x3e, 0x7d]),
            Some((494_878_333, 4))
        );
        assert_eq!(get_varint(&[0x40]), None);
    }

    #[tokio::test]
    async fn async_frames() {
        let mut data = frame(0x21, b"grease");
        data.extend(frame(FRAME_HEADERS, b"abc"));
        let mut r = &data[..];
        assert_eq!(read_headers(&mut r).await.unwrap().unwrap(), b"abc");
        assert!(read_frame(&mut r).await.unwrap().is_none());
        let s = settings_frame(&[
            (SETTINGS_H3_DATAGRAM, 1),
            (SETTINGS_ENABLE_CONNECT_PROTOCOL, 1),
        ]);
        let mut r = &s[..];
        let (ty, p) = read_frame(&mut r).await.unwrap().unwrap();
        assert_eq!(ty, FRAME_SETTINGS);
        assert_eq!(parse_settings(&p).unwrap(), vec![(0x33, 1), (0x08, 1)]);
    }

    #[test]
    fn static_table_indices() {
        assert_eq!(STATIC[15], (":method", "CONNECT"));
        assert_eq!(STATIC[25], (":status", "200"));
        assert_eq!(STATIC[27], (":status", "404"));
        assert_eq!(STATIC[72], ("accept-language", ""));
        assert_eq!(STATIC[98], ("x-frame-options", "sameorigin"));
    }

    #[test]
    fn qpack_round_trip() {
        let long = "x".repeat(300);
        let fields = [
            (":method", "CONNECT"),
            (":protocol", "connect-udp"),
            (":scheme", "https"),
            (":authority", "node.example:443"),
            (":path", long.as_str()),
            ("capsule-protocol", "?1"),
            (":status", "200"),
        ];
        let enc = qpack_encode(&fields);
        // :method CONNECT is a one-byte static index (0xc0 | 15).
        assert_eq!(enc[2], 0xcf);
        let dec = qpack_decode(&enc).unwrap();
        assert_eq!(dec.len(), fields.len());
        for (f, (n, v)) in dec.iter().zip(fields) {
            assert_eq!(f.name, n);
            assert_eq!(f.value.as_deref(), Some(v));
        }
        assert_eq!(field(&dec, ":path"), Some(long.as_str()));
    }

    #[test]
    fn qpack_rejects_dynamic_and_skips_huffman() {
        // Required Insert Count != 0.
        assert!(qpack_decode(&[0x01, 0x00, 0xd9]).is_none());
        // Dynamic indexed field line.
        assert!(qpack_decode(&[0x00, 0x00, 0x80]).is_none());
        // ":status 200" indexed + "server: <huffman>" literal-with-name-ref.
        let b = [0x00, 0x00, 0xd9, 0x5f, 0x4d, 0x82, 0xaa, 0xbb];
        let dec = qpack_decode(&b).unwrap();
        assert_eq!(field(&dec, ":status"), Some("200"));
        assert_eq!(dec[1].name, "server");
        assert_eq!(dec[1].value, None);
        // Truncated.
        assert!(qpack_decode(&[0x00, 0x00, 0x5f, 0x1d, 0x05, b'a']).is_none());
    }
}
