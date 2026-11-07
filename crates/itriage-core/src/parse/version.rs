//! Version strings as installers report them ("24.2.0.187", "10.0.26100.2314",
//! "v1.95.1", "2.0-beta"), compared segment by segment with numbers compared
//! numerically, so 24.10 sorts after 24.9.

use std::cmp::Ordering;

#[derive(Debug, PartialEq)]
enum Seg {
    Num(u64),
    Text(String),
}

/// Runs of digits become numbers, runs of letters stay text, and separators
/// (`.`, `-`, `_`, `+`, spaces, brackets) are dropped. Anything before the
/// first digit ("Version ", "v") is ignored.
fn segments(v: &str) -> Vec<Seg> {
    let v = v.trim_start_matches(|c: char| !c.is_ascii_digit());
    let mut out = Vec::new();
    let mut digits = String::new();
    let mut letters = String::new();
    let flush = |digits: &mut String, letters: &mut String, out: &mut Vec<Seg>| {
        if !digits.is_empty() {
            out.push(Seg::Num(digits.parse().unwrap_or(u64::MAX)));
            digits.clear();
        }
        if !letters.is_empty() {
            out.push(Seg::Text(letters.to_ascii_lowercase()));
            letters.clear();
        }
    };
    for c in v.chars() {
        if c.is_ascii_digit() {
            if !letters.is_empty() {
                flush(&mut digits, &mut letters, &mut out);
            }
            digits.push(c);
        } else if c.is_alphabetic() {
            if !digits.is_empty() {
                flush(&mut digits, &mut letters, &mut out);
            }
            letters.push(c);
        } else {
            flush(&mut digits, &mut letters, &mut out);
        }
    }
    flush(&mut digits, &mut letters, &mut out);
    out
}

/// Compare two version strings. Missing trailing zeros don't matter
/// (1.0 == 1.0.0); a trailing text part marks a pre-release (2.0-beta < 2.0).
pub fn compare(a: &str, b: &str) -> Ordering {
    let (x, y) = (segments(a), segments(b));
    for i in 0..x.len().max(y.len()) {
        let o = match (x.get(i), y.get(i)) {
            (Some(Seg::Num(p)), Some(Seg::Num(q))) => p.cmp(q),
            (Some(Seg::Text(p)), Some(Seg::Text(q))) => p.cmp(q),
            (Some(Seg::Text(_)), Some(Seg::Num(_))) => Ordering::Less,
            (Some(Seg::Num(_)), Some(Seg::Text(_))) => Ordering::Greater,
            (Some(Seg::Num(n)), None) => n.cmp(&0),
            (None, Some(Seg::Num(n))) => 0.cmp(n),
            (Some(Seg::Text(_)), None) => Ordering::Less,
            (None, Some(Seg::Text(_))) => Ordering::Greater,
            (None, None) => Ordering::Equal,
        };
        if o != Ordering::Equal {
            return o;
        }
    }
    Ordering::Equal
}

/// Is `installed` at least `minimum`? An unreadable version never passes.
pub fn meets(installed: &str, minimum: &str) -> bool {
    !segments(installed).is_empty() && compare(installed, minimum) != Ordering::Less
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numeric_segments_compare_as_numbers() {
        assert_eq!(compare("24.10", "24.9"), Ordering::Greater);
        assert_eq!(compare("10.0.26100.2314", "10.0.26100.999"), Ordering::Greater);
        assert_eq!(compare("1.0", "1.0.0"), Ordering::Equal);
        assert_eq!(compare("v1.95.1", "1.95.1"), Ordering::Equal);
        assert_eq!(compare("Version 24.2", "24.2.0.187"), Ordering::Less);
    }

    #[test]
    fn pre_releases_sort_before_releases() {
        assert_eq!(compare("2.0-beta", "2.0"), Ordering::Less);
        assert_eq!(compare("2.0.rc1", "2.0.1"), Ordering::Less);
        assert_eq!(compare("2.0b", "2.0a"), Ordering::Greater);
    }

    #[test]
    fn minimum_versions() {
        assert!(meets("24.2.0.187", "24.2"));
        assert!(meets("24.5.10.20", "24.2"));
        assert!(!meets("23.11.1.45", "24.2"));
        assert!(!meets("", "1.0"));
        assert!(!meets("unknown", "1.0"));
    }
}
