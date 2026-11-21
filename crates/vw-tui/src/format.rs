//! Human-readable formatting helpers (pure).

/// Binary-prefixed byte count: `512 B`, `1.5 KiB`, `12.3 MiB`.
pub fn bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["KiB", "MiB", "GiB", "TiB", "PiB"];
    if n < 1024 {
        return format!("{n} B");
    }
    let mut v = n as f64 / 1024.0;
    let mut i = 0;
    while v >= 1024.0 && i + 1 < UNITS.len() {
        v /= 1024.0;
        i += 1;
    }
    if v >= 100.0 {
        format!("{v:.0} {}", UNITS[i])
    } else if v >= 10.0 {
        format!("{v:.1} {}", UNITS[i])
    } else {
        format!("{v:.2} {}", UNITS[i])
    }
}

/// Transfer rate: `0 B/s`, `1.50 KiB/s`, `12.3 MiB/s`.
pub fn rate(bytes_per_sec: u64) -> String {
    format!("{}/s", bytes(bytes_per_sec))
}

/// `3d 04:05:06` or `04:05:06`.
pub fn uptime(secs: u64) -> String {
    let d = secs / 86_400;
    let h = (secs % 86_400) / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    if d > 0 {
        format!("{d}d {h:02}:{m:02}:{s:02}")
    } else {
        format!("{h:02}:{m:02}:{s:02}")
    }
}

/// Thousands separators: `1234567` → `1,234,567`.
pub fn count(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// `HH:MM:SS UTC` of a unix timestamp.
pub fn utc_clock(unix: u64) -> String {
    let t = unix % 86_400;
    format!("{:02}:{:02}:{:02} UTC", t / 3600, (t % 3600) / 60, t % 60)
}

/// First 12 characters of a proof digest.
pub fn short_proof(proof: &str) -> &str {
    let end = proof
        .char_indices()
        .nth(12)
        .map(|(i, _)| i)
        .unwrap_or(proof.len());
    &proof[..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_units() {
        assert_eq!(bytes(0), "0 B");
        assert_eq!(bytes(1023), "1023 B");
        assert_eq!(bytes(1536), "1.50 KiB");
        assert_eq!(bytes(10 * 1024 * 1024 + 300 * 1024), "10.3 MiB");
        assert_eq!(bytes(500 * 1024 * 1024 * 1024), "500 GiB");
        assert_eq!(rate(2048), "2.00 KiB/s");
        assert_eq!(rate(3 * 1024 * 1024), "3.00 MiB/s");
    }

    #[test]
    fn clocks_and_counts() {
        assert_eq!(uptime(59), "00:00:59");
        assert_eq!(uptime(3_723), "01:02:03");
        assert_eq!(uptime(90_061), "1d 01:01:01");
        assert_eq!(count(0), "0");
        assert_eq!(count(999), "999");
        assert_eq!(count(1_000), "1,000");
        assert_eq!(count(1_234_567), "1,234,567");
        assert_eq!(utc_clock(86_400 + 3_661), "01:01:01 UTC");
        assert_eq!(short_proof("0123456789abcdef"), "0123456789ab");
        assert_eq!(short_proof("abc"), "abc");
    }
}
