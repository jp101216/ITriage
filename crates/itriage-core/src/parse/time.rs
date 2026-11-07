//! Timestamp parsing without pulling in a date-time crate.

/// Parse an ISO-8601 UTC timestamp such as `2026-11-06T19:22:31.1234567Z`
/// (the `SystemTime` attribute in Windows event XML) into Unix seconds.
/// Fractional seconds are ignored. Returns `None` for anything malformed.
pub fn iso8601_utc_to_epoch(s: &str) -> Option<u64> {
    let s = s.trim();
    let b = s.as_bytes();
    if b.len() < 19
        || b[4] != b'-'
        || b[7] != b'-'
        || (b[10] != b'T' && b[10] != b' ')
        || b[13] != b':'
        || b[16] != b':'
    {
        return None;
    }
    let num = |r: std::ops::Range<usize>| s.get(r)?.parse::<i64>().ok();
    let (year, month, day) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (hour, minute, second) = (num(11..13)?, num(14..16)?, num(17..19)?);
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return None;
    }
    let days = days_from_civil(year, month as u32, day as u32);
    u64::try_from(days * 86_400 + hour * 3_600 + minute * 60 + second).ok()
}

/// Days since 1970-01-01 for a proleptic Gregorian date
/// (Howard Hinnant's `days_from_civil`).
pub fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400; // [0, 399]
    let mp = (month as i64 + 9) % 12; // March = 0
    let doy = (153 * mp + 2) / 5 + day as i64 - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146_097 + doe - 719_468
}

/// The civil date for a day count since 1970-01-01 (Hinnant's
/// `civil_from_days`, the inverse of [`days_from_civil`]).
pub fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11], March = 0
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

/// Unix seconds as an RFC 3339 UTC timestamp: `2026-11-06T19:22:31Z`.
pub fn epoch_to_rfc3339(secs: u64) -> String {
    let (y, m, d) = civil_from_days((secs / 86_400) as i64);
    let rem = secs % 86_400;
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3_600,
        (rem % 3_600) / 60,
        rem % 60
    )
}

/// A Windows FILETIME (100 ns ticks since 1601-01-01) as Unix seconds.
pub fn filetime_to_epoch(filetime: u64) -> Option<u64> {
    (filetime / 10_000_000).checked_sub(11_644_473_600)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_and_round_trips() {
        assert_eq!(epoch_to_rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(epoch_to_rfc3339(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(epoch_to_rfc3339(1_793_992_951), "2026-11-06T19:22:31Z");
        for secs in [0u64, 86_399, 951_782_400, 1_709_164_800, 1_793_992_951, 4_102_444_800] {
            assert_eq!(iso8601_utc_to_epoch(&epoch_to_rfc3339(secs)), Some(secs));
        }
        for days in [-1_000_000i64, -1, 0, 59, 10_957, 19_782, 2_000_000] {
            let (y, m, d) = civil_from_days(days);
            assert_eq!(days_from_civil(y, m, d), days, "{y}-{m}-{d}");
        }
    }

    #[test]
    fn converts_filetime() {
        // 2026-11-06T19:22:31Z as a FILETIME
        let ft = (1_793_992_951u64 + 11_644_473_600) * 10_000_000 + 1234;
        assert_eq!(filetime_to_epoch(ft), Some(1_793_992_951));
        assert_eq!(filetime_to_epoch(0), None);
    }

    #[test]
    fn civil_days() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(2000, 1, 1), 10_957);
        assert_eq!(days_from_civil(2024, 2, 29), 19_782);
    }

    #[test]
    fn parses_event_timestamps() {
        assert_eq!(iso8601_utc_to_epoch("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(iso8601_utc_to_epoch("2000-02-29T00:00:00.0000000Z"), Some(951_782_400));
        assert_eq!(iso8601_utc_to_epoch("2026-11-06T19:22:31.1234567Z"), Some(1_793_992_951));
        assert_eq!(iso8601_utc_to_epoch("not a date"), None);
        assert_eq!(iso8601_utc_to_epoch("2026-13-01T00:00:00Z"), None);
    }
}
