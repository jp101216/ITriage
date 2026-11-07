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

#[cfg(test)]
mod tests {
    use super::*;

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
