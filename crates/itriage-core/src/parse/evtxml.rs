#![cfg_attr(not(windows), allow(dead_code))]
//! The `<System>` block of a Windows event rendered as XML
//! (`EvtRender(.., EvtRenderEventXml, ..)`).
//!
//! A full XML parser is overkill for the four fields we need, which have a
//! fixed, machine-generated shape.

#[derive(Debug, Clone, PartialEq)]
pub struct EvtSystem {
    pub provider: String,
    pub event_id: u32,
    /// 1 = Critical, 2 = Error, 3 = Warning, 4 = Information.
    pub level: u8,
    pub time_created: Option<String>,
}

pub fn parse_system(xml: &str) -> Option<EvtSystem> {
    let provider = attr(xml, "Provider", "Name")?;
    let event_id = text(xml, "EventID")?.trim().parse().ok()?;
    let level = text(xml, "Level")
        .and_then(|t| t.trim().parse().ok())
        .unwrap_or(0);
    let time_created = attr(xml, "TimeCreated", "SystemTime");
    Some(EvtSystem {
        provider,
        event_id,
        level,
        time_created,
    })
}

/// The ActivityID in `<Correlation>`: the same for every event of one
/// operation (a Group Policy cycle, say). `None` when it's empty.
pub fn activity_id(xml: &str) -> Option<String> {
    attr(xml, "Correlation", "ActivityID").filter(|id| !id.trim().is_empty())
}

/// The named values in an event's `<EventData>`: `<Data Name='TargetUserName'>jparker</Data>`.
/// Unnamed and empty entries are skipped.
pub fn event_data(xml: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let Some(start) = find_tag(xml, "EventData") else {
        return out;
    };
    let body = &xml[start..];
    let body = &body[..body.find("</EventData>").unwrap_or(body.len())];
    let mut rest = body;
    while let Some(at) = find_tag(rest, "Data") {
        let element = &rest[at..];
        let Some(open_end) = element.find('>') else { break };
        let name = attr(&element[..=open_end], "Data", "Name");
        if element[..open_end].ends_with('/') {
            rest = &element[open_end + 1..];
            continue;
        }
        let Some(close) = element.find("</Data>") else { break };
        if let Some(name) = name {
            let value = unescape(element[open_end + 1..close].trim());
            if !value.is_empty() {
                out.push((name, value));
            }
        }
        rest = &element[close + "</Data>".len()..];
    }
    out
}

/// Everything an event carries, in order, for showing to a person: named
/// `<Data Name='x'>` values under their name, unnamed ones (classic
/// providers such as MsiInstaller and User32) under their position ("1",
/// "2", …), and the fields of a `<UserData>` block (servicing and driver
/// installation events). Empty and "(NULL)" values are skipped.
pub fn payload(xml: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    if let Some(start) = find_tag(xml, "EventData") {
        let body = &xml[start..];
        let body = &body[..body.find("</EventData>").unwrap_or(body.len())];
        let mut rest = body;
        let mut position = 0;
        while let Some(at) = find_tag(rest, "Data") {
            position += 1;
            let element = &rest[at..];
            let Some(open_end) = element.find('>') else { break };
            if element[..open_end].ends_with('/') {
                rest = &element[open_end + 1..];
                continue;
            }
            let Some(close) = element.find("</Data>") else { break };
            let name = attr(&element[..=open_end], "Data", "Name").unwrap_or_else(|| position.to_string());
            let value = unescape(element[open_end + 1..close].trim());
            if !value.is_empty() && value != "(NULL)" {
                out.push((name, value));
            }
            rest = &element[close + "</Data>".len()..];
        }
    }
    if let Some(start) = find_tag(xml, "UserData") {
        let body = &xml[start..];
        let body = &body[..body.find("</UserData>").unwrap_or(body.len())];
        out.extend(leaves(body));
    }
    out
}

/// The elements that hold text and nothing else: `<Name>text</Name>`.
fn leaves(body: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut rest = body;
    while let Some(open) = rest.find('<') {
        let after = &rest[open + 1..];
        let Some(end) = after.find('>') else { break };
        let tag = &after[..end];
        rest = &after[end + 1..];
        if tag.starts_with(['/', '?', '!']) || tag.ends_with('/') {
            continue;
        }
        let name = tag.split([' ', '\t', '\r', '\n']).next().unwrap_or_default();
        let Some(next) = rest.find('<') else { break };
        let close = format!("</{name}>");
        if !name.is_empty() && rest[next..].starts_with(&close) {
            let value = unescape(rest[..next].trim());
            if !value.is_empty() && value != "(NULL)" {
                // A namespace prefix says nothing to a reader.
                out.push((name.rsplit(':').next().unwrap_or(name).to_string(), value));
            }
            rest = &rest[next + close.len()..];
        }
    }
    out
}

/// Value of `name` on the first `<tag …>` element; handles ' or " quoting.
fn attr(xml: &str, tag: &str, name: &str) -> Option<String> {
    let start = find_tag(xml, tag)?;
    let end = xml[start..].find('>')? + start;
    let element = &xml[start..end];
    let key = format!(" {name}=");
    let i = element.find(&key)? + key.len();
    let quote = element[i..].chars().next()?;
    if quote != '\'' && quote != '"' {
        return None;
    }
    let rest = &element[i + 1..];
    let j = rest.find(quote)?;
    Some(unescape(&rest[..j]))
}

/// Text content of the first `<tag>…</tag>`; attributes on the open tag are fine.
fn text(xml: &str, tag: &str) -> Option<String> {
    let start = find_tag(xml, tag)?;
    let open_end = xml[start..].find('>')? + start + 1;
    if xml[..open_end].ends_with("/>") {
        return None;
    }
    let close = format!("</{tag}>");
    let end = xml[open_end..].find(&close)? + open_end;
    Some(unescape(&xml[open_end..end]))
}

/// Byte offset of `<tag` where the name really ends there (so `<EventID`
/// doesn't match `<EventIDx`).
fn find_tag(xml: &str, tag: &str) -> Option<usize> {
    let needle = format!("<{tag}");
    let mut from = 0;
    while let Some(i) = xml[from..].find(&needle) {
        let at = from + i;
        match xml[at + needle.len()..].chars().next() {
            Some(' ' | '>' | '/' | '\t' | '\r' | '\n') => return Some(at),
            _ => from = at + needle.len(),
        }
    }
    None
}

fn unescape(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

#[cfg(test)]
mod tests {
    use super::*;

    const KERNEL_POWER: &str = "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>\
        <Provider Name='Microsoft-Windows-Kernel-Power' Guid='{331c3b3a-2005-44c2-ac5e-77220c37d6b4}'/>\
        <EventID>41</EventID><Version>8</Version><Level>1</Level><Task>63</Task><Opcode>0</Opcode>\
        <Keywords>0x8000400000000002</Keywords><TimeCreated SystemTime='2026-11-06T14:02:11.5000000Z'/>\
        <EventRecordID>91022</EventRecordID></System></Event>";

    const SCM: &str = r#"<Event><System><Provider Name="Service Control Manager" Guid="{555908d1-a6d7-4695-8e1e-26931d2012f4}" EventSourceName="Service Control Manager"/><EventID Qualifiers="49152">7031</EventID><Level>2</Level><TimeCreated SystemTime="2026-11-06T16:40:00.000Z"/></System></Event>"#;

    #[test]
    fn parses_single_quoted_xml() {
        let s = parse_system(KERNEL_POWER).unwrap();
        assert_eq!(s.provider, "Microsoft-Windows-Kernel-Power");
        assert_eq!(s.event_id, 41);
        assert_eq!(s.level, 1);
        assert_eq!(s.time_created.as_deref(), Some("2026-11-06T14:02:11.5000000Z"));
    }

    #[test]
    fn parses_qualified_event_ids_and_double_quotes() {
        let s = parse_system(SCM).unwrap();
        assert_eq!(s.provider, "Service Control Manager");
        assert_eq!(s.event_id, 7031);
        assert_eq!(s.level, 2);
    }

    #[test]
    fn reads_event_data() {
        let xml = "<Event><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4625</EventID></System>\
            <EventData><Data Name='TargetUserName'>jparker</Data><Data Name='TargetDomainName'>CORP</Data>\
            <Data Name='LogonType'>3</Data><Data Name='Empty'/><Data Name='ProcessName'>C:\\Program Files\\A &amp; B\\app.exe</Data>\
            <Data>unnamed</Data><Data Name='IpAddress'>-</Data></EventData></Event>";
        let data = event_data(xml);
        let get = |k: &str| data.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
        assert_eq!(get("TargetUserName"), Some("jparker"));
        assert_eq!(get("LogonType"), Some("3"));
        assert_eq!(get("ProcessName"), Some(r"C:\Program Files\A & B\app.exe"));
        assert_eq!(get("Empty"), None);
        assert_eq!(data.len(), 5);
        assert!(event_data("<Event><System/></Event>").is_empty());
    }

    #[test]
    fn payload_keeps_unnamed_values_and_user_data() {
        // MsiInstaller is a classic provider: its values have no names.
        let msi = "<Event><System><Provider Name='MsiInstaller'/><EventID Qualifiers='0'>1033</EventID></System>\
            <EventData><Data>Contoso Client</Data><Data>24.2.0.187</Data><Data>1033</Data><Data>0</Data>\
            <Data>Contoso Ltd</Data><Data>(NULL)</Data><Data/><Binary>7B31</Binary></EventData></Event>";
        assert_eq!(
            payload(msi),
            [("1", "Contoso Client"), ("2", "24.2.0.187"), ("3", "1033"), ("4", "0"), ("5", "Contoso Ltd")]
                .map(|(k, v)| (k.to_string(), v.to_string()))
        );
        // Servicing writes its fields as elements under UserData.
        let cbs = "<Event><System><Provider Name='Microsoft-Windows-Servicing'/><EventID>2</EventID></System>\
            <UserData><CbsPackageChangeState xmlns='http://manifests.microsoft.com/win/2004/08/windows/setup_provider'>\
            <PackageIdentifier>KB5031356</PackageIdentifier><IntendedPackageState>5112</IntendedPackageState>\
            <IntendedPackageStateTextized>Installed</IntendedPackageStateTextized><ErrorCode>0x0</ErrorCode>\
            <Client>UpdateAgentLCU</Client></CbsPackageChangeState></UserData></Event>";
        let data = payload(cbs);
        assert_eq!(data[0], ("PackageIdentifier".to_string(), "KB5031356".to_string()));
        assert_eq!(data.len(), 5);
        assert!(data.iter().all(|(k, _)| k != "CbsPackageChangeState"), "the wrapper holds elements, not text");
        // Named values keep their names, and nothing is invented for an empty event.
        let named = "<Event><System/><EventData><Data Name='param1'>Spooler</Data><Data Name='Empty'></Data></EventData></Event>";
        assert_eq!(payload(named), [("param1".to_string(), "Spooler".to_string())]);
        assert!(payload("<Event><System/></Event>").is_empty());
    }

    #[test]
    fn rejects_garbage() {
        assert_eq!(parse_system("<Event/>"), None);
    }
}
