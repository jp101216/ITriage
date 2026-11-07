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
    fn rejects_garbage() {
        assert_eq!(parse_system("<Event/>"), None);
    }
}
