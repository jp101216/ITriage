//! Security-policy block events: what stopped a program or a file write,
//! and which rule did it. Windows: Defender attack surface reduction (ASR),
//! Controlled folder access, antivirus detections, AppLocker and App Control
//! for Business (WDAC). Linux: AppArmor and SELinux denials.
//!
//! The Windows field names are the ones in each provider's event manifest
//! (dumped from Windows Server 2025 in November 2026); the Defender fixture
//! is a real capture. Values are matched loosely (case and spaces ignored)
//! because AppLocker writes its fields under `UserData`, where the element
//! names can differ from the manifest's data names.

use crate::parse::evtxml::{parse_system, payload};
use crate::parse::time::iso8601_utc_to_epoch;

/// Where a block came from, as a technician would name it.
pub const ASR: &str = "ASR rule";
pub const FOLDERS: &str = "Controlled folder access";
pub const ANTIVIRUS: &str = "Antivirus";
pub const APPLOCKER: &str = "AppLocker";
pub const APP_CONTROL: &str = "App Control";
pub const APPARMOR: &str = "AppArmor";
pub const SELINUX: &str = "SELinux";

#[derive(Debug, Clone, PartialEq)]
pub struct PolicyEvent {
    pub epoch: u64,
    /// One of the constants above.
    pub source: &'static str,
    /// Blocked (`true`), or only recorded by a rule in audit mode.
    pub enforced: bool,
    /// The rule or policy, in words.
    pub rule: String,
    /// What was blocked: the program, script or file.
    pub path: String,
    /// The program that tried, when the event names one.
    pub process: String,
    /// The account it happened to (a SID for AppLocker), when known.
    pub user: String,
}

/// A value by name, ignoring case, spaces and a trailing `Buffer`
/// (AppLocker's manifest calls `FilePath` `FilePathBuffer`).
pub fn field<'a>(data: &'a [(String, String)], names: &[&str]) -> Option<&'a str> {
    let norm = |s: &str| {
        let s: String = s.chars().filter(|c| !c.is_whitespace() && *c != '_').collect::<String>().to_ascii_lowercase();
        s.strip_suffix("buffer").map(str::to_string).unwrap_or(s)
    };
    names.iter().find_map(|want| {
        let want = norm(want);
        data.iter().find(|(k, v)| norm(k) == want && !v.trim().is_empty()).map(|(_, v)| v.trim())
    })
}

/// Defender writes resources as `file:_C:\path`, several joined by `;`.
fn defender_path(raw: &str) -> String {
    let first = raw.split(';').map(str::trim).find(|p| !p.is_empty()).unwrap_or_default();
    first
        .strip_prefix("file:_")
        .or_else(|| first.strip_prefix("containerfile:_"))
        .or_else(|| first.strip_prefix("process:_pid:"))
        .unwrap_or(first)
        .to_string()
}

/// One Windows event as a block, or `None` for an event that isn't one.
pub fn from_event(xml: &str) -> Option<PolicyEvent> {
    let system = parse_system(xml)?;
    let epoch = iso8601_utc_to_epoch(system.time_created.as_deref()?)?;
    let data = payload(xml);
    let get = |names: &[&str]| field(&data, names).unwrap_or_default().to_string();
    let provider = system.provider.to_ascii_lowercase();
    let id = system.event_id;
    let (source, enforced, rule, path, process, user) = if provider.contains("windows defender") {
        match id {
            1121 | 1122 => {
                let guid = get(&["ID"]);
                let rule = crate::parse::asr::rule_name(&guid)
                    .map(str::to_string)
                    .unwrap_or_else(|| if guid.is_empty() { "an ASR rule".into() } else { format!("ASR rule {guid}") });
                (ASR, id == 1121, rule, get(&["Path"]), get(&["Process Name"]), get(&["User"]))
            }
            1123 | 1124 => (FOLDERS, id == 1123, "Controlled folder access".to_string(), get(&["Path"]), get(&["Process Name"]), get(&["User"])),
            // 1116 is the detection, 1117 the action taken on it.
            1116 | 1117 => {
                let threat = get(&["Threat Name"]);
                let rule = if threat.is_empty() { "a detection".to_string() } else { format!("detected {threat}") };
                (ANTIVIRUS, id == 1117, rule, defender_path(&get(&["Path"])), get(&["Process Name"]), get(&["Detection User"]))
            }
            _ => return None,
        }
    } else if provider.contains("applocker") {
        // 8004 and 8007 were blocked; 8003 and 8006 only would have been.
        let enforced = match id {
            8004 | 8007 => true,
            8003 | 8006 => false,
            _ => return None,
        };
        let policy = get(&["PolicyName"]);
        let name = get(&["RuleName"]);
        let rule = match (policy.is_empty(), name.is_empty() || name == "-") {
            (false, false) => format!("{policy} rules: {name}"),
            (false, true) => format!("{policy} rules: no rule allows it"),
            (true, false) => name,
            (true, true) => "AppLocker policy".to_string(),
        };
        let path = field(&data, &["FullFilePath"]).or_else(|| field(&data, &["FilePath"])).unwrap_or_default().to_string();
        (APPLOCKER, enforced, rule, path, String::new(), get(&["TargetUser"]))
    } else if provider.contains("codeintegrity") {
        let enforced = match id {
            3077 => true,
            3076 => false,
            _ => return None,
        };
        let policy = get(&["PolicyName"]);
        let rule = if policy.is_empty() { "App Control for Business policy".to_string() } else { format!("policy {policy}") };
        (APP_CONTROL, enforced, rule, get(&["File Name"]), get(&["Process Name"]), String::new())
    } else {
        return None;
    };
    if path.is_empty() && process.is_empty() {
        return None;
    }
    Some(PolicyEvent { epoch, source, enforced, rule, path, process, user })
}

/// `key="value"` and `key=value` pairs from an audit line, in order.
pub fn audit_fields(line: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        // A key: letters, digits and underscores right before '='.
        let start = i;
        while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
            i += 1;
        }
        if i == start || i >= bytes.len() || bytes[i] != b'=' {
            i = i.max(start + 1);
            continue;
        }
        let key = &line[start..i];
        i += 1;
        let value = if bytes.get(i) == Some(&b'"') {
            let rest = &line[i + 1..];
            let end = rest.find('"').unwrap_or(rest.len());
            i += end + 2;
            rest[..end].to_string()
        } else {
            let rest = &line[i..];
            let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
            i += end;
            unhex(&rest[..end]).unwrap_or_else(|| rest[..end].to_string())
        };
        out.push((key.to_string(), value));
    }
    out
}

/// AppArmor writes a name with spaces or odd characters as unquoted hex.
fn unhex(s: &str) -> Option<String> {
    if s.len() < 4 || !s.len().is_multiple_of(2) || !s.bytes().all(|b| b.is_ascii_hexdigit()) || s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let bytes: Option<Vec<u8>> = (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect();
    let text = String::from_utf8(bytes?).ok()?;
    text.chars().all(|c| !c.is_control()).then_some(text)
}

/// One kernel or audit journal message as an AppArmor or SELinux block.
pub fn from_audit_line(message: &str, epoch: u64) -> Option<PolicyEvent> {
    if message.contains("apparmor=") {
        let f = audit_fields(message);
        let get = |k: &str| f.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone()).unwrap_or_default();
        let enforced = match get("apparmor").as_str() {
            "DENIED" => true,
            // A profile in complain mode records what it would have denied.
            "ALLOWED" => false,
            _ => return None,
        };
        let operation = get("operation");
        let profile = get("profile");
        let rule = match (profile.is_empty(), operation.is_empty()) {
            (false, false) => format!("profile {profile} ({operation})"),
            (false, true) => format!("profile {profile}"),
            _ => "an AppArmor profile".to_string(),
        };
        return Some(PolicyEvent { epoch, source: APPARMOR, enforced, rule, path: get("name"), process: get("comm"), user: String::new() });
    }
    let avc = message.find("avc:")?;
    let rest = &message[avc + 4..];
    if !rest.trim_start().starts_with("denied") {
        return None;
    }
    let perms = rest.split_once('{').and_then(|(_, r)| r.split_once('}')).map(|(p, _)| p.trim().to_string()).unwrap_or_default();
    let f = audit_fields(rest);
    let get = |k: &str| f.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone()).unwrap_or_default();
    // system_u:system_r:httpd_t:s0 → httpd_t
    let domain = |context: String| context.split(':').nth(2).map(str::to_string).unwrap_or(context);
    let (source_type, target_type, class) = (domain(get("scontext")), domain(get("tcontext")), get("tclass"));
    let rule = format!("{source_type} may not {perms} {class} labelled {target_type}").split_whitespace().collect::<Vec<_>>().join(" ");
    let path = Some(get("path")).filter(|p| !p.is_empty()).unwrap_or_else(|| get("name"));
    Some(PolicyEvent { epoch, source: SELINUX, enforced: get("permissive") != "1", rule, path, process: get("comm"), user: String::new() })
}

/// Blocks of one rule on one file, folded together.
#[derive(Debug, Clone, PartialEq)]
pub struct BlockGroup {
    pub source: &'static str,
    pub rule: String,
    pub path: String,
    pub process: String,
    pub user: String,
    pub enforced: bool,
    pub count: usize,
    pub first: u64,
    pub last: u64,
}

impl BlockGroup {
    /// The file's name alone: `C:\…\dragon.exe` → `dragon.exe`.
    pub fn file_name(&self) -> &str {
        let target = if self.path.is_empty() { &self.process } else { &self.path };
        target.rsplit(['\\', '/']).find(|p| !p.is_empty()).unwrap_or(target)
    }
}

/// Fold events by (source, rule, path), enforced ones first, newest first.
pub fn group(events: &[PolicyEvent]) -> Vec<BlockGroup> {
    let mut groups: Vec<BlockGroup> = Vec::new();
    for e in events {
        let key_path = e.path.to_lowercase();
        match groups.iter_mut().find(|g| g.source == e.source && g.rule == e.rule && g.path.to_lowercase() == key_path) {
            Some(g) => {
                g.count += 1;
                g.enforced |= e.enforced;
                g.first = g.first.min(e.epoch);
                if e.epoch >= g.last {
                    g.last = e.epoch;
                    if !e.process.is_empty() {
                        g.process = e.process.clone();
                    }
                }
            }
            None => groups.push(BlockGroup {
                source: e.source,
                rule: e.rule.clone(),
                path: e.path.clone(),
                process: e.process.clone(),
                user: e.user.clone(),
                enforced: e.enforced,
                count: 1,
                first: e.epoch,
                last: e.epoch,
            }),
        }
    }
    groups.sort_by(|a, b| b.enforced.cmp(&a.enforced).then(b.last.cmp(&a.last)));
    groups
}

/// Does a blocked path belong to an application the site requires? The
/// app's name as a whole, run together, or its first word when that's
/// distinctive ("Dragon Medical One" → a path with "dragon" in it).
pub fn names_app(path: &str, app: &str) -> bool {
    let path = path.to_lowercase();
    let app = app.trim().to_lowercase();
    if app.len() < 3 {
        return false;
    }
    let joined: String = app.chars().filter(|c| !c.is_whitespace()).collect();
    let first = app.split_whitespace().next().unwrap_or_default();
    path.contains(&app)
        || path.contains(&joined)
        || (first.len() >= 5 && !["microsoft", "windows", "program", "google", "adobe"].contains(&first) && path.contains(first))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real Defender detection (EVTX-ATTACK-SAMPLES, Atomic Red Team), host
    /// and user names replaced, and the time written the way Windows
    /// renders it.
    const DEFENDER_1117: &str = include_str!("fixtures/defender-1117.xml");

    /// Shaped on the manifest's field list for 1121 (v0); not a capture.
    const ASR_1121: &str = "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Windows Defender' Guid='{11cd958a-c507-4ef3-b3f2-5fd9dfbd2c78}'/>\
        <EventID>1121</EventID><Version>0</Version><Level>3</Level><TimeCreated SystemTime='2026-11-12T13:02:11.5123456Z'/></System>\
        <EventData><Data Name='Product Name'>%%827</Data><Data Name='Product Version'>4.18.25100.9</Data><Data Name='Unused'></Data>\
        <Data Name='ID'>D4F940AB-401B-4EFC-AADC-AD5F3C50688A</Data><Data Name='Detection Time'>2026-11-12T13:02:11.497Z</Data>\
        <Data Name='User'>CORP\\jparker</Data><Data Name='Path'>C:\\Program Files (x86)\\Nuance\\Dragon\\natspeak.exe</Data>\
        <Data Name='Process Name'>C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE</Data>\
        <Data Name='Security intelligence Version'>1.421.123.0</Data><Data Name='Engine Version'>1.1.25100.2</Data>\
        <Data Name='RuleType'>0</Data><Data Name='Target Commandline'></Data><Data Name='Parent Commandline'></Data>\
        <Data Name='Involved File'></Data><Data Name='Inhertiance Flags'>0</Data></EventData></Event>";

    #[test]
    fn reads_a_real_defender_action() {
        let e = from_event(DEFENDER_1117).expect("a block");
        assert_eq!((e.source, e.enforced), (ANTIVIRUS, true));
        assert_eq!(e.rule, "detected Trojan:PowerShell/Powersploit.M");
        assert_eq!(e.path, r"C:\AtomicRedTeam\atomic-red-team-master\atomics\T1056\Get-Keystrokes.ps1", "file:_ is Defender's prefix");
        assert_eq!(e.process, r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe");
        assert_eq!(e.user, r"WS-07\jparker");
        assert_eq!(e.epoch, iso8601_utc_to_epoch("2019-07-18T20:51:50Z").unwrap());
    }

    #[test]
    fn names_the_asr_rule_and_tells_audit_from_block() {
        let e = from_event(ASR_1121).unwrap();
        assert_eq!((e.source, e.enforced), (ASR, true));
        assert_eq!(e.rule, "Block all Office applications from creating child processes");
        assert!(e.path.ends_with("natspeak.exe") && e.process.ends_with("WINWORD.EXE"));
        let audit = from_event(&ASR_1121.replace("<EventID>1121</EventID>", "<EventID>1122</EventID>")).unwrap();
        assert!(!audit.enforced);
        let unknown = from_event(&ASR_1121.replace("D4F940AB-401B-4EFC-AADC-AD5F3C50688A", "11111111-2222-3333-4444-555555555555")).unwrap();
        assert_eq!(unknown.rule, "ASR rule 11111111-2222-3333-4444-555555555555");
    }

    #[test]
    fn reads_applocker_and_app_control_whichever_names_they_use() {
        // AppLocker's fields as rendered under UserData, and with the
        // manifest's "Buffer" names: both read the same.
        for (policy, rule, path) in [("PolicyName", "RuleName", "FullFilePath"), ("PolicyNameBuffer", "RuleNameBuffer", "FullFilePathBuffer")] {
            let xml = format!(
                "<Event><System><Provider Name='Microsoft-Windows-AppLocker'/><EventID>8004</EventID><Level>2</Level><TimeCreated SystemTime='2026-11-12T13:00:00.0000000Z'/></System>\
                 <UserData><RuleAndFileData xmlns='http://schemas.microsoft.com/schemas/event/Microsoft.Windows/1.0.0.0'><PolicyNameLength>3</PolicyNameLength><{policy}>EXE</{policy}>\
                 <RuleId>{{00000000-0000-0000-0000-000000000000}}</RuleId><RuleNameLength>1</RuleNameLength><{rule}>-</{rule}><TargetUser>S-1-5-21-1-2-3-1104</TargetUser>\
                 <FilePathLength>40</FilePathLength><FilePath>%OSDRIVE%\\USERS\\JPARKER\\DOWNLOADS\\TOOL.EXE</FilePath><{path}>C:\\Users\\jparker\\Downloads\\tool.exe</{path}></RuleAndFileData></UserData></Event>"
            );
            let e = from_event(&xml).unwrap();
            assert_eq!((e.source, e.enforced), (APPLOCKER, true));
            assert_eq!(e.rule, "EXE rules: no rule allows it");
            assert_eq!(e.path, r"C:\Users\jparker\Downloads\tool.exe", "the full path beats the %OSDRIVE% one");
        }
        let wdac = "<Event><System><Provider Name='Microsoft-Windows-CodeIntegrity'/><EventID>3077</EventID><Level>2</Level><TimeCreated SystemTime='2026-11-12T13:00:00Z'/></System>\
            <EventData><Data Name='FileNameLength'>40</Data><Data Name='File Name'>\\Device\\HarddiskVolume3\\Tools\\plugin.dll</Data><Data Name='ProcessNameLength'>20</Data>\
            <Data Name='Process Name'>\\Device\\HarddiskVolume3\\Program Files\\App\\app.exe</Data><Data Name='Status'>0xc0e90002</Data><Data Name='PolicyNameLength'>9</Data><Data Name='PolicyName'>Ward PCs</Data></EventData></Event>";
        let e = from_event(wdac).unwrap();
        assert_eq!((e.source, e.enforced, e.rule.as_str()), (APP_CONTROL, true, "policy Ward PCs"));
        assert!(from_event(&wdac.replace(">3077<", ">3089<")).is_none(), "a signature-details event isn't a block");
    }

    #[test]
    fn reads_apparmor_and_selinux_denials() {
        let aa = r#"audit: type=1400 audit(1794600000.123:812): apparmor="DENIED" operation="open" class="file" profile="/usr/bin/evince" name="/home/jparker/Private/scan.pdf" pid=4242 comm="evince" requested_mask="r" denied_mask="r" fsuid=1000 ouid=1000"#;
        let e = from_audit_line(aa, 1_794_600_000).unwrap();
        assert_eq!((e.source, e.enforced), (APPARMOR, true));
        assert_eq!(e.rule, "profile /usr/bin/evince (open)");
        assert_eq!((e.path.as_str(), e.process.as_str()), ("/home/jparker/Private/scan.pdf", "evince"));
        let complain = from_audit_line(&aa.replace("DENIED", "ALLOWED"), 1).unwrap();
        assert!(!complain.enforced);
        assert!(from_audit_line(&aa.replace("DENIED", "STATUS"), 1).is_none(), "profile loads aren't blocks");
        // A name with a space is written as hex.
        let hex = from_audit_line(r#"apparmor="DENIED" operation="open" profile="snap.app" name=2F746D702F6D7920646F632E747874 comm="app""#, 1).unwrap();
        assert_eq!(hex.path, "/tmp/my doc.txt");

        let avc = "audit: type=1400 audit(1794600000.5:90): avc:  denied  { read } for  pid=812 comm=\"httpd\" name=\"index.html\" dev=\"dm-0\" ino=4012 scontext=system_u:system_r:httpd_t:s0 tcontext=unconfined_u:object_r:user_home_t:s0 tclass=file permissive=0";
        let e = from_audit_line(avc, 5).unwrap();
        assert_eq!((e.source, e.enforced), (SELINUX, true));
        assert_eq!(e.rule, "httpd_t may not read file labelled user_home_t");
        assert_eq!((e.path.as_str(), e.process.as_str()), ("index.html", "httpd"));
        assert!(!from_audit_line(&avc.replace("permissive=0", "permissive=1"), 5).unwrap().enforced);
        assert!(from_audit_line("avc:  granted  { setenforce } for pid=1", 5).is_none());
        assert!(from_audit_line("usb 1-1: new device", 5).is_none());
    }

    #[test]
    fn folds_repeats_and_puts_blocks_first() {
        let ev = |epoch: u64, enforced: bool, path: &str| PolicyEvent {
            epoch,
            source: ASR,
            enforced,
            rule: "Block all Office applications from creating child processes".into(),
            path: path.into(),
            process: "WINWORD.EXE".into(),
            user: String::new(),
        };
        let groups = group(&[ev(10, false, r"C:\a\x.exe"), ev(30, true, r"C:\A\X.EXE"), ev(20, true, r"C:\a\x.exe"), ev(40, false, r"C:\b\y.exe")]);
        assert_eq!(groups.len(), 2);
        assert_eq!((groups[0].count, groups[0].first, groups[0].last, groups[0].enforced), (3, 10, 30, true), "case doesn't split a path");
        assert_eq!(groups[0].file_name(), "x.exe");
        assert!(!groups[1].enforced, "audit-only comes after blocks, however recent");
    }

    #[test]
    fn matches_blocked_paths_to_required_apps() {
        assert!(names_app(r"C:\Program Files (x86)\Nuance\Dragon\natspeak.exe", "Dragon Medical One"));
        assert!(names_app(r"C:\Program Files\Citrix\ICA Client\CitrixWorkspace.exe", "Citrix Workspace"));
        assert!(!names_app(r"C:\Program Files\Microsoft Office\root\WINWORD.EXE", "Microsoft Teams"), "a vendor name alone isn't the app");
        assert!(!names_app(r"C:\x.exe", "x"));
    }
}
