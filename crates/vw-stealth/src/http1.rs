//! Tiny HTTP/1.1 head reader/parser and IMF-fixdate formatter for TLS-WS.

use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncRead, AsyncReadExt};

/// Largest request/response head we accept.
pub const MAX_HEAD: usize = 8 * 1024;

/// Read until the blank line ending an HTTP head.
/// Returns `(head without the final CRLFCRLF, bytes read past it)`.
pub async fn read_head<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<(Vec<u8>, Vec<u8>)> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        let n = r.read(&mut chunk).await?;
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        let start = buf.len().saturating_sub(3);
        buf.extend_from_slice(&chunk[..n]);
        if let Some(i) = buf[start..].windows(4).position(|w| w == b"\r\n\r\n") {
            let end = start + i;
            let rest = buf[end + 4..].to_vec();
            buf.truncate(end);
            return Ok((buf, rest));
        }
        if buf.len() > MAX_HEAD {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "http head too large",
            ));
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Head {
    /// Request: (method, target, version). Response: (version, status, reason).
    pub line: (String, String, String),
    pub headers: Vec<(String, String)>,
}

impl Head {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// True if the comma-separated header `name` contains `token` (case-insensitive).
    pub fn header_has_token(&self, name: &str, token: &str) -> bool {
        self.headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case(name))
            .flat_map(|(_, v)| v.split(','))
            .any(|t| t.trim().eq_ignore_ascii_case(token))
    }
}

pub fn parse_head(head: &[u8]) -> Option<Head> {
    let text = std::str::from_utf8(head).ok()?;
    let mut lines = text.split("\r\n");
    let first = lines.next()?;
    let mut parts = first.splitn(3, ' ');
    let line = (
        parts.next()?.to_string(),
        parts.next()?.to_string(),
        parts.next().unwrap_or("").to_string(),
    );
    let mut headers = Vec::new();
    for l in lines {
        let (k, v) = l.split_once(':')?;
        if k.is_empty() || k.contains(' ') {
            return None;
        }
        headers.push((k.to_string(), v.trim().to_string()));
    }
    Some(Head { line, headers })
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

/// RFC 9110 IMF-fixdate, e.g. `Sun, 06 Nov 1994 08:49:37 GMT`.
pub fn http_date_unix(secs: u64) -> String {
    const WD: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    const MO: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let days = secs / 86_400;
    let rem = secs % 86_400;
    let (y, m, d) = civil_from_days(days as i64);
    format!(
        "{}, {:02} {} {} {:02}:{:02}:{:02} GMT",
        WD[((days + 4) % 7) as usize],
        d,
        MO[(m - 1) as usize],
        y,
        rem / 3600,
        rem / 60 % 60,
        rem % 60
    )
}

pub fn http_date_now() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    http_date_unix(secs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates() {
        assert_eq!(http_date_unix(784_111_777), "Sun, 06 Nov 1994 08:49:37 GMT");
        assert_eq!(http_date_unix(0), "Thu, 01 Jan 1970 00:00:00 GMT");
        assert_eq!(
            http_date_unix(1_709_210_096),
            "Thu, 29 Feb 2024 12:34:56 GMT"
        );
        assert!(http_date_now().ends_with(" GMT"));
    }

    #[tokio::test]
    async fn heads() {
        let raw = b"GET /x HTTP/1.1\r\nHost: a\r\nConnection: keep-alive, Upgrade\r\n\r\nLEFT";
        let mut r = &raw[..];
        let (head, rest) = read_head(&mut r).await.unwrap();
        assert_eq!(rest, b"LEFT");
        let h = parse_head(&head).unwrap();
        assert_eq!(h.line.0, "GET");
        assert_eq!(h.line.1, "/x");
        assert_eq!(h.header("host"), Some("a"));
        assert!(h.header_has_token("connection", "upgrade"));
        assert!(!h.header_has_token("connection", "close"));
        assert!(parse_head(b"GET / HTTP/1.1\r\nbad header").is_none());

        let big = vec![b'a'; MAX_HEAD + 2048];
        let mut r = &big[..];
        assert!(read_head(&mut r).await.is_err());
    }
}
