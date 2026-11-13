//! Attack surface reduction (ASR) rule GUIDs and their names.
//!
//! Copied from Microsoft's "Attack surface reduction rules reference"
//! (learn.microsoft.com/defender-endpoint/attack-surface-reduction-rules-reference)
//! and checked GUID by GUID against the ASR rules table on the "Attack
//! surface reduction rules overview" page, November 2026. Not typed from
//! memory: when Microsoft adds a rule, copy it from that page.
//!
//! Defender writes the GUID into ASR events (1121, 1122) in whatever case
//! the policy used, so lookups ignore case and braces.

/// (GUID in lowercase, rule name) for every ASR rule.
pub const RULES: &[(&str, &str)] = &[
    ("56a863a9-875e-4185-98a7-b882c64b5ce5", "Block abuse of exploited vulnerable signed drivers"),
    ("7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c", "Block Adobe Reader from creating child processes"),
    ("d4f940ab-401b-4efc-aadc-ad5f3c50688a", "Block all Office applications from creating child processes"),
    ("9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2", "Block credential stealing from the Windows local security authority subsystem (lsass.exe)"),
    ("be9ba2d9-53ea-4cdc-84e5-9b1eeee46550", "Block executable content from email client and webmail"),
    ("01443614-cd74-433a-b99e-2ecdc07bfc25", "Block executable files from running unless they meet a prevalence, age, or trusted list criterion"),
    ("5beb7efe-fd9a-4556-801d-275e5ffc04cc", "Block execution of potentially obfuscated scripts"),
    ("d3e037e1-3eb8-44c8-a917-57927947596d", "Block JavaScript or VBScript from launching downloaded executable content"),
    ("3b576869-a4ec-4529-8536-b80a7769e899", "Block Office applications from creating executable content"),
    ("75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84", "Block Office applications from injecting code into other processes"),
    ("26190899-1602-49e8-8b27-eb1d0a1ce869", "Block Office communication application from creating child processes"),
    ("e6db77e5-3df2-4cf1-b95a-636979351e5b", "Block persistence through WMI event subscription"),
    ("d1e49aac-8f56-4280-b9ba-993a6d77406c", "Block process creations originating from PSExec and WMI commands"),
    ("33ddedf1-c6e0-47cb-833e-de6133960387", "Block rebooting machine in Safe Mode"),
    ("b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4", "Block untrusted and unsigned processes that run from USB"),
    ("c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb", "Block use of copied or impersonated system tools"),
    ("a8f5898e-1dc8-49a9-9878-85004b8a61e6", "Block Webshell creation for Servers"),
    ("92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b", "Block Win32 API calls from Office macros"),
    ("c1db55ab-c21a-4637-bb3f-a12568109d35", "Use advanced protection against ransomware"),
];

/// The rule's name, whatever case or braces the GUID came in.
pub fn rule_name(guid: &str) -> Option<&'static str> {
    let wanted = guid.trim().trim_matches(['{', '}']).to_ascii_lowercase();
    RULES.iter().find(|(id, _)| *id == wanted).map(|(_, name)| *name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guids_are_unique_lowercase_and_well_formed() {
        let mut seen = std::collections::HashSet::new();
        for (guid, name) in RULES {
            assert!(seen.insert(*guid), "{guid} is listed twice");
            assert_eq!(*guid, guid.to_ascii_lowercase(), "{guid} isn't lowercase");
            let groups: Vec<&str> = guid.split('-').collect();
            assert_eq!(groups.iter().map(|g| g.len()).collect::<Vec<_>>(), [8, 4, 4, 4, 12], "{guid}");
            assert!(guid.chars().all(|c| c == '-' || c.is_ascii_hexdigit()), "{guid}");
            assert!(name.starts_with("Block ") || name.starts_with("Use "), "{name}");
        }
        assert_eq!(RULES.len(), 19, "the reference listed 19 rules in November 2026");
    }

    #[test]
    fn looks_up_whatever_case_defender_wrote() {
        assert_eq!(rule_name("D4F940AB-401B-4EFC-AADC-AD5F3C50688A"), Some("Block all Office applications from creating child processes"));
        assert_eq!(rule_name("{92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b}"), Some("Block Win32 API calls from Office macros"));
        assert_eq!(rule_name("00000000-0000-0000-0000-000000000000"), None);
    }
}
