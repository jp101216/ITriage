//! "A newer ITriage is out." It tells; it never downloads or installs.
//!
//! One request a day to GitHub's public releases API, remembered in a small
//! file so starting the app twice doesn't ask twice. A site switches it off
//! with `[updates] notify = false`, and it's off whenever the profile turns
//! off public probes (`[network] public_probes = false`): a PC that isn't
//! meant to talk to the internet doesn't.
//!
//! Nothing in the answer is trusted beyond the version number. The link the
//! app opens is built here from that number, so a tampered answer can't send
//! anyone anywhere but this project's own release page.

use crate::profile::Profile;
use crate::util::now_epoch;
use serde::{Deserialize, Serialize};
use std::time::Duration;

const RELEASES_API: &str = "https://api.github.com/repos/jp101216/ITriage/releases/latest";
const RELEASE_PAGE: &str = "https://github.com/jp101216/ITriage/releases/tag/";
const CHECK_EVERY: u64 = 24 * 3600;
/// After a failed check, how long before the next try.
const RETRY_AFTER: u64 = 3600;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Notice {
    pub current: String,
    pub latest: String,
    /// The release's page on GitHub.
    pub url: String,
    pub newer: bool,
}

#[derive(Serialize, Deserialize)]
struct Remembered {
    checked: u64,
    /// Empty when the last check got no answer.
    tag: String,
}

pub fn enabled(profile: &Profile) -> bool {
    profile.updates.notify && profile.network.public_probes
}

/// The latest release compared with this build. `None` when the check is
/// switched off or GitHub couldn't be asked.
pub fn check(profile: &Profile) -> Option<Notice> {
    if !enabled(profile) {
        return None;
    }
    let file = crate::paths::state_dir()?.join("update-check.json");
    let now = now_epoch();
    let remembered: Option<Remembered> = std::fs::read_to_string(&file).ok().and_then(|t| serde_json::from_str(&t).ok());
    let tag = match remembered {
        Some(r) if now.saturating_sub(r.checked) < if r.tag.is_empty() { RETRY_AFTER } else { CHECK_EVERY } => r.tag,
        _ => {
            let tag = crate::net::http_get(RELEASES_API, Duration::from_secs(8)).ok().and_then(|body| latest_tag(&body)).unwrap_or_default();
            if let Some(dir) = file.parent() {
                let _ = std::fs::create_dir_all(dir);
            }
            let _ = std::fs::write(&file, serde_json::to_string(&Remembered { checked: now, tag: tag.clone() }).unwrap_or_default());
            tag
        }
    };
    (!tag.is_empty()).then(|| notice(env!("CARGO_PKG_VERSION"), &tag))
}

/// The release tag in GitHub's answer, if it's shaped like a version.
pub fn latest_tag(body: &str) -> Option<String> {
    let tag = serde_json::from_str::<serde_json::Value>(body).ok()?.get("tag_name")?.as_str()?.trim().to_string();
    let version = tag.trim_start_matches('v');
    let shaped = !version.is_empty()
        && tag.len() <= 32
        && version.starts_with(|c: char| c.is_ascii_digit())
        && version.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-');
    shaped.then_some(tag)
}

pub fn notice(current: &str, tag: &str) -> Notice {
    let latest = tag.trim_start_matches('v');
    Notice {
        current: current.to_string(),
        latest: latest.to_string(),
        url: format!("{RELEASE_PAGE}{tag}"),
        newer: crate::parse::version::compare(latest, current) == std::cmp::Ordering::Greater,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_only_a_version_from_the_answer() {
        let body = r#"{"url":"https://api.github.com/x","tag_name":"v0.7.1","html_url":"https://evil.example/download","draft":false}"#;
        assert_eq!(latest_tag(body).as_deref(), Some("v0.7.1"));
        for bad in [
            r#"{"tag_name":"../../x"}"#,
            r#"{"tag_name":"v1.0 && calc"}"#,
            r#"{"tag_name":""}"#,
            r#"{"tag_name":"latest"}"#,
            r#"{"message":"Not Found"}"#,
            "<html>captive portal</html>",
        ] {
            assert_eq!(latest_tag(bad), None, "{bad}");
        }
    }

    #[test]
    fn compares_versions_and_builds_its_own_link() {
        let newer = notice("0.7.0", "v0.7.1");
        assert!(newer.newer);
        assert_eq!(newer.url, "https://github.com/jp101216/ITriage/releases/tag/v0.7.1");
        assert_eq!(newer.latest, "0.7.1");
        assert!(!notice("0.7.0", "v0.7.0").newer);
        assert!(!notice("0.8.0", "v0.7.9").newer, "a build ahead of the last release isn't told to go back");
        assert!(notice("0.7.0", "v0.10.0").newer, "compared as numbers, not text");
    }

    #[test]
    fn a_site_can_switch_it_off() {
        assert!(enabled(&Profile::default()));
        assert!(!enabled(&Profile::from_toml("[updates]\nnotify = false").unwrap()));
        assert!(!enabled(&Profile::from_toml("[network]\npublic_probes = false").unwrap()), "no public probes means no call home either");
        assert_eq!(check(&Profile::from_toml("[updates]\nnotify = false").unwrap()), None);
    }
}
