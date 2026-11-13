//! A sign-in as a waterfall: how long the user's profile took to load, how
//! long Group Policy took, and which client-side extension (Folder
//! Redirection, Scripts, Drive Maps…) took that time.
//!
//! Field names are the ones in the GroupPolicy and User Profiles Service
//! event manifests (dumped from Windows Server 2025, November 2026),
//! including Microsoft's spelling: `PolicyElaspedTimeInSeconds` and
//! `CSEElaspedTimeInMilliSeconds`. Events of one policy cycle share an
//! ActivityID in `<Correlation>`; 4000 and 4001 also carry it as
//! `PolicyActivityId`.

use crate::parse::blocks::field;
use crate::parse::evtxml::{activity_id, parse_system, payload};
use crate::parse::time::iso8601_utc_to_epoch;

pub const GP_CHANNEL: &str = "Microsoft-Windows-GroupPolicy/Operational";
pub const PROFILE_CHANNEL: &str = "Microsoft-Windows-User Profile Service/Operational";

/// One event, reduced to what the waterfall needs.
#[derive(Debug, Clone, PartialEq)]
pub struct GpEvent {
    pub epoch: u64,
    /// Milliseconds within the second, so events in one second keep order.
    pub millis: u32,
    pub id: u32,
    pub activity: String,
    pub data: Vec<(String, String)>,
}

pub fn from_event(xml: &str) -> Option<GpEvent> {
    let system = parse_system(xml)?;
    let time = system.time_created.as_deref()?;
    let epoch = iso8601_utc_to_epoch(time)?;
    let millis = time.get(20..23).and_then(|m| m.parse().ok()).unwrap_or(0);
    let data = payload(xml);
    let activity = activity_id(xml)
        .or_else(|| field(&data, &["PolicyActivityId"]).map(str::to_string))
        .unwrap_or_default()
        .trim_matches(['{', '}'])
        .to_ascii_lowercase();
    Some(GpEvent { epoch, millis, id: system.event_id, activity, data })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Ok,
    Warning,
    Failed,
}

/// One client-side extension's part of the cycle.
#[derive(Debug, Clone, PartialEq)]
pub struct Phase {
    pub name: String,
    pub ms: u64,
    pub outcome: Outcome,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Waterfall {
    /// User sign-in (`true`) or computer startup policy.
    pub user: bool,
    pub started: u64,
    /// Whole policy processing, from 8001/8000. `None` if it never finished
    /// in the log (still running, or the log rolled over).
    pub policy_ms: Option<u64>,
    /// Slowest first.
    pub phases: Vec<Phase>,
    pub applied: Option<usize>,
    pub filtered: Option<usize>,
    pub principal: String,
    pub error: Option<String>,
    /// The ActivityID, to tie a 1129/1058 to its cycle.
    pub activity: String,
}

impl Waterfall {
    /// The extensions in the order they took longest.
    pub fn slowest(&self, n: usize) -> &[Phase] {
        &self.phases[..self.phases.len().min(n)]
    }
}

fn number(data: &[(String, String)], names: &[&str]) -> Option<u64> {
    let v = field(data, names)?;
    v.parse::<u64>().ok().or_else(|| v.parse::<f64>().ok().filter(|f| f.is_finite() && *f >= 0.0).map(|f| f.round() as u64))
}

/// The error code as it reads in Windows' tools, or `None` for success.
fn error_code(data: &[(String, String)]) -> Option<String> {
    let raw = field(data, &["ErrorCode"])?;
    let code: i64 = if let Some(hex) = raw.strip_prefix("0x") { i64::from_str_radix(hex, 16).ok()? } else { raw.parse().ok()? };
    (code != 0).then(|| if raw.starts_with("0x") { raw.to_string() } else { format!("{code}") })
}

fn yes(data: &[(String, String)], name: &str) -> Option<bool> {
    field(data, &[name]).map(|v| matches!(v.to_ascii_lowercase().as_str(), "true" | "1"))
}

/// How many GPOs a 5312 (applied) or 5313 (filtered out) lists. The list
/// is a block of `<GPO>` entries; failing that, a line each.
fn gpo_count(data: &[(String, String)]) -> Option<usize> {
    let list = field(data, &["GPOInfoList"])?;
    let tags = list.matches("<GPO").count();
    Some(if tags > 0 { tags } else { list.lines().filter(|l| !l.trim().is_empty()).count() })
}

/// Every complete-enough policy cycle in `events`, newest first.
/// Background refreshes are left out: only startup and sign-in processing.
pub fn waterfalls(events: &[GpEvent]) -> Vec<Waterfall> {
    let mut out = Vec::new();
    for start in events.iter().filter(|e| matches!(e.id, 4000 | 4001) && !e.activity.is_empty()) {
        if yes(&start.data, "IsBackgroundProcessing") == Some(true) {
            continue;
        }
        let same: Vec<&GpEvent> = events.iter().filter(|e| e.activity == start.activity).collect();
        let end = same.iter().find(|e| matches!(e.id, 8000 | 8001));
        let mut phases: Vec<Phase> = same
            .iter()
            .filter(|e| matches!(e.id, 5016 | 6016 | 7016))
            .map(|e| Phase {
                name: field(&e.data, &["CSEExtensionName"]).unwrap_or("Unnamed extension").to_string(),
                ms: number(&e.data, &["CSEElaspedTimeInMilliSeconds", "CSEElapsedTimeInMilliseconds"]).unwrap_or(0),
                outcome: match e.id {
                    5016 => Outcome::Ok,
                    6016 => Outcome::Warning,
                    _ => Outcome::Failed,
                },
                error: error_code(&e.data),
            })
            .collect();
        phases.sort_by_key(|p| std::cmp::Reverse(p.ms));
        out.push(Waterfall {
            user: start.id == 4001,
            started: start.epoch,
            policy_ms: end.and_then(|e| number(&e.data, &["PolicyElaspedTimeInSeconds", "PolicyElapsedTimeInSeconds"])).map(|s| s * 1000),
            phases,
            applied: same.iter().find(|e| e.id == 5312).and_then(|e| gpo_count(&e.data)),
            filtered: same.iter().find(|e| e.id == 5313).and_then(|e| gpo_count(&e.data)),
            principal: field(&start.data, &["PrincipalSamName"]).unwrap_or_default().to_string(),
            error: end.and_then(|e| error_code(&e.data)),
            activity: start.activity.clone(),
        });
    }
    out.sort_by_key(|w| std::cmp::Reverse(w.started));
    out
}

/// Profile load: User Profiles Service 1 ("received user logon
/// notification on session N") to 2 ("finished processing"), the latest
/// pair that starts at or before `before`. Milliseconds.
pub fn profile_load_ms(events: &[GpEvent], before: u64) -> Option<u64> {
    let session = |e: &GpEvent| field(&e.data, &["Session"]).unwrap_or_default().to_string();
    let mut starts: Vec<&GpEvent> = events.iter().filter(|e| e.id == 1 && e.epoch <= before + 1).collect();
    starts.sort_by_key(|e| std::cmp::Reverse((e.epoch, e.millis)));
    let start = starts.first()?;
    let at = |e: &GpEvent| e.epoch * 1000 + u64::from(e.millis);
    let finish = events
        .iter()
        .filter(|e| e.id == 2 && session(e) == session(start) && at(e) >= at(start))
        .min_by_key(|e| at(e))?;
    Some(at(finish) - at(start))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gp(id: u32, at: &str, activity: &str, data: &[(&str, &str)]) -> String {
        let fields: String = data.iter().map(|(k, v)| format!("<Data Name='{k}'>{v}</Data>")).collect();
        format!(
            "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-GroupPolicy' Guid='{{aea1b4fa-97d1-45f2-a64c-4d69fffd92c9}}'/>\
             <EventID>{id}</EventID><Version>1</Version><Level>4</Level><TimeCreated SystemTime='{at}'/><Correlation ActivityID='{{{activity}}}'/>\
             <Execution ProcessID='1312' ThreadID='4012'/><Channel>Microsoft-Windows-GroupPolicy/Operational</Channel></System><EventData>{fields}</EventData></Event>"
        )
    }

    const A: &str = "6C1A4F2E-8B3D-4E5F-9A0B-1C2D3E4F5A6B";

    fn sign_in() -> Vec<GpEvent> {
        [
            gp(4001, "2026-11-12T13:01:13.1000000Z", A, &[("PolicyActivityId", "{6c1a4f2e-8b3d-4e5f-9a0b-1c2d3e4f5a6b}"), ("PrincipalSamName", "CORP\\jparker"), ("IsMachine", "0"), ("IsBackgroundProcessing", "false")]),
            gp(5312, "2026-11-12T13:01:14.0000000Z", A, &[("DescriptionString", "Ward PCs\nDefault Domain Policy\nFolder Redirection\n"), ("GPOInfoList", "<GPO ID=\"{1}\"><Name>Ward PCs</Name></GPO><GPO ID=\"{2}\"><Name>Default Domain Policy</Name></GPO><GPO ID=\"{3}\"><Name>Folder Redirection</Name></GPO>")]),
            gp(5313, "2026-11-12T13:01:14.0000000Z", A, &[("GPOInfoList", "<GPO ID=\"{4}\"><Name>Labs</Name></GPO>")]),
            gp(5016, "2026-11-12T13:01:55.0000000Z", A, &[("CSEElaspedTimeInMilliSeconds", "41012"), ("ErrorCode", "0"), ("CSEExtensionName", "Folder Redirection"), ("CSEExtensionId", "{25537BA6-77A8-11D2-9B6C-0000F8080861}")]),
            gp(5016, "2026-11-12T13:02:01.0000000Z", A, &[("CSEElaspedTimeInMilliSeconds", "5110"), ("ErrorCode", "0"), ("CSEExtensionName", "Scripts"), ("CSEExtensionId", "{42B5FAAE-6536-11D2-AE5A-0000F87571E3}")]),
            gp(7016, "2026-11-12T13:02:03.0000000Z", A, &[("CSEElaspedTimeInMilliSeconds", "2021"), ("ErrorCode", "2"), ("CSEExtensionName", "Group Policy Drive Maps"), ("CSEExtensionId", "{5794DAFD-BE60-433f-88A2-1A31939AC01F}")]),
            gp(8001, "2026-11-12T13:02:11.0000000Z", A, &[("PolicyElaspedTimeInSeconds", "58"), ("ErrorCode", "0"), ("PrincipalSamName", "CORP\\jparker"), ("IsMachine", "0"), ("IsConnectivityFailure", "false")]),
        ]
        .iter()
        .map(|x| from_event(x).unwrap())
        .collect()
    }

    #[test]
    fn builds_a_sign_in_waterfall_from_one_activity() {
        let w = waterfalls(&sign_in());
        assert_eq!(w.len(), 1);
        let w = &w[0];
        assert!(w.user);
        assert_eq!(w.policy_ms, Some(58_000));
        assert_eq!(w.principal, "CORP\\jparker");
        assert_eq!((w.applied, w.filtered), (Some(3), Some(1)));
        assert_eq!(w.slowest(3).iter().map(|p| (p.name.as_str(), p.ms)).collect::<Vec<_>>(), [("Folder Redirection", 41_012), ("Scripts", 5_110), ("Group Policy Drive Maps", 2_021)]);
        assert_eq!((w.phases[2].outcome, w.phases[2].error.as_deref()), (Outcome::Failed, Some("2")));
        assert_eq!(w.error, None);
        assert_eq!(w.activity, "6c1a4f2e-8b3d-4e5f-9a0b-1c2d3e4f5a6b", "case and braces don't split a cycle");
    }

    #[test]
    fn background_refreshes_and_other_cycles_stay_apart() {
        let mut events = sign_in();
        let b = "11111111-2222-3333-4444-555555555555";
        events.push(from_event(&gp(4001, "2026-11-12T14:31:00.0000000Z", b, &[("IsBackgroundProcessing", "true")])).unwrap());
        events.push(from_event(&gp(5016, "2026-11-12T14:31:05.0000000Z", b, &[("CSEElaspedTimeInMilliSeconds", "90000"), ("CSEExtensionName", "Registry")])).unwrap());
        let c = "99999999-2222-3333-4444-555555555555";
        events.push(from_event(&gp(4000, "2026-11-12T08:00:00.0000000Z", c, &[("IsMachine", "1"), ("IsBackgroundProcessing", "false")])).unwrap());
        events.push(from_event(&gp(8000, "2026-11-12T08:00:12.0000000Z", c, &[("PolicyElaspedTimeInSeconds", "12"), ("ErrorCode", "1355")])).unwrap());
        let w = waterfalls(&events);
        assert_eq!(w.len(), 2, "the background refresh isn't a sign-in");
        assert!(w[0].user && !w[1].user, "newest first");
        assert_eq!((w[1].policy_ms, w[1].error.as_deref()), (Some(12_000), Some("1355")));
        assert!(w[1].phases.is_empty());
    }

    #[test]
    fn measures_profile_load_on_the_same_session() {
        let profile = |id: u32, at: &str, session: &str| {
            from_event(&format!(
                "<Event><System><Provider Name='Microsoft-Windows-User Profiles Service'/><EventID>{id}</EventID><Level>4</Level><TimeCreated SystemTime='{at}'/></System><EventData><Data Name='Session'>{session}</Data></EventData></Event>"
            ))
            .unwrap()
        };
        let events = vec![
            profile(1, "2026-11-12T13:01:09.250Z", "2"),
            profile(1, "2026-11-12T13:01:10.000Z", "3"),
            profile(2, "2026-11-12T13:01:11.000Z", "3"),
            profile(2, "2026-11-12T13:01:12.750Z", "2"),
        ];
        let at = iso8601_utc_to_epoch("2026-11-12T13:01:13Z").unwrap();
        assert_eq!(profile_load_ms(&events, at), Some(1_000), "the latest start, matched on its session");
        assert_eq!(profile_load_ms(&events[..1], at), None, "no finish, no measurement");
    }
}
