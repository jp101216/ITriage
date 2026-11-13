//! Microsoft 365 Apps facts: which update channel a Click-to-Run install
//! follows, and how close an Outlook data file is to its size limit.
//!
//! The channel GUIDs are the ones Microsoft lists for Click-to-Run's
//! `CDNBaseUrl` / `UpdateChannel` (`http://officecdn.microsoft.com/pr/<GUID>`)
//! on "Update Microsoft 365 Apps with the Settings Catalog in Intune",
//! November 2026. Copy new ones from there.

pub const CHANNELS: &[(&str, &str)] = &[
    ("492350f6-3a01-4f97-b9c0-c7c6ddf67d60", "Current Channel"),
    ("64256afe-f5d9-4f86-8936-8840a6a4f5be", "Current Channel (Preview)"),
    ("55336b82-a18d-4dd6-b5f6-9e5095c314a6", "Monthly Enterprise Channel"),
    ("7ffbc6bf-bc32-4f92-8982-f9dd17fd3114", "Semi-Annual Enterprise Channel"),
    ("b8f9b850-328d-4355-9145-c59439a0c4cf", "Semi-Annual Enterprise Channel (Preview)"),
    ("5440fd1f-7ecb-4221-8110-145efaa6372f", "Beta Channel"),
];

/// The channel a CDN URL (or bare GUID) points at.
pub fn channel(url: &str) -> Option<&'static str> {
    let guid = url.trim().trim_end_matches('/').rsplit('/').next()?.trim_matches(['{', '}']).to_ascii_lowercase();
    CHANNELS.iter().find(|(g, _)| *g == guid).map(|(_, name)| *name)
}

/// Outlook's own limits for Unicode .ost/.pst files when no policy sets
/// them: it warns at 47.5 GB (48,640 MB) and stops growing the file at
/// 50 GB (51,200 MB).
pub const DEFAULT_WARN_MB: u64 = 48_640;
pub const DEFAULT_MAX_MB: u64 = 51_200;

/// How full an Outlook data file is against its limits.
pub fn data_file(size_bytes: u64, warn_mb: u64, max_mb: u64) -> (crate::model::Severity, String) {
    use crate::model::Severity;
    let mb = size_bytes / (1024 * 1024);
    let pct = if max_mb > 0 { mb as f64 / max_mb as f64 * 100.0 } else { 0.0 };
    let words = format!("{} · {pct:.0}% of the {} limit", crate::util::human_bytes(size_bytes), crate::util::human_bytes(max_mb * 1024 * 1024));
    if mb >= max_mb {
        (Severity::Critical, format!("{words}: full, Outlook stops adding mail to it"))
    } else if mb >= warn_mb {
        (Severity::Warning, format!("{words}: past Outlook's warning size"))
    } else if pct >= 80.0 {
        (Severity::Info, words)
    } else {
        (Severity::Ok, words)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Severity;

    #[test]
    fn names_channels_from_their_cdn_url() {
        assert_eq!(channel("http://officecdn.microsoft.com/pr/55336b82-a18d-4dd6-b5f6-9e5095c314a6"), Some("Monthly Enterprise Channel"));
        assert_eq!(channel("http://officecdn.microsoft.com/pr/492350F6-3A01-4F97-B9C0-C7C6DDF67D60/"), Some("Current Channel"));
        assert_eq!(channel("http://officecdn.microsoft.com/pr/00000000-0000-0000-0000-000000000000"), None);
        let mut seen = std::collections::HashSet::new();
        assert!(CHANNELS.iter().all(|(g, _)| seen.insert(*g) && g.len() == 36 && *g == g.to_ascii_lowercase()));
    }

    #[test]
    fn grades_outlook_data_files() {
        let gb = 1024 * 1024 * 1024u64;
        assert_eq!(data_file(12 * gb, DEFAULT_WARN_MB, DEFAULT_MAX_MB).0, Severity::Ok);
        assert_eq!(data_file(42 * gb, DEFAULT_WARN_MB, DEFAULT_MAX_MB).0, Severity::Info);
        assert_eq!(data_file(48 * gb, DEFAULT_WARN_MB, DEFAULT_MAX_MB).0, Severity::Warning);
        let (sev, words) = data_file(50 * gb, DEFAULT_WARN_MB, DEFAULT_MAX_MB);
        assert_eq!(sev, Severity::Critical);
        assert!(words.ends_with("full, Outlook stops adding mail to it"), "{words}");
        assert_eq!(data_file(5 * gb, 4_000, 5_000).0, Severity::Critical, "a policy's smaller limit counts");
    }
}
