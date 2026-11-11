//! Windows Event Log through the Vista+ `Evt*` API: query a channel for recent
//! Critical/Error events, render each one as XML, and format messages.

use crate::parse::evtxml::{parse_system, EvtSystem};
use std::collections::{HashMap, HashSet};
use windows::core::{HSTRING, PCWSTR};
use windows::Win32::System::EventLog::{
    DeregisterEventSource, EvtClose, EvtFormatMessage, EvtFormatMessageEvent, EvtNext,
    EvtOpenPublisherMetadata, EvtQuery, EvtQueryChannelPath, EvtQueryReverseDirection, EvtRender,
    EvtRenderEventXml, RegisterEventSourceW, ReportEventW, EVENTLOG_INFORMATION_TYPE,
    EVENTLOG_WARNING_TYPE, EVT_HANDLE,
};

/// Write one event to the Application log under `source` (the audit trail).
/// Registers the source first when running elevated, so messages render
/// cleanly; unregistered sources still log, just with Event Viewer's
/// "description cannot be found" preamble.
pub fn report(source: &str, id: u32, ok: bool, message: &str) {
    if crate::host::is_elevated() {
        super::registry::ensure_event_source(source);
    }
    let name = HSTRING::from(source);
    let text = HSTRING::from(message);
    // SAFETY: the handle is deregistered on every path; the string array
    // points at `text`, which outlives the call.
    unsafe {
        let Ok(handle) = RegisterEventSourceW(PCWSTR::null(), &name) else {
            return;
        };
        let strings = [PCWSTR(text.as_ptr())];
        let kind = if ok { EVENTLOG_INFORMATION_TYPE } else { EVENTLOG_WARNING_TYPE };
        let _ = ReportEventW(handle, kind, 0, id, None, 0, Some(&strings), None);
        let _ = DeregisterEventSource(handle);
    }
}

pub struct RawEvent {
    pub system: EvtSystem,
    /// The formatted message, filled in only for the newest event of each
    /// (provider, event id). Formatting is the expensive part, and older
    /// repeats of the same event would only be counted anyway.
    pub message: Option<String>,
}

struct Handle(EVT_HANDLE);

impl Drop for Handle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            // SAFETY: we own the handle and close it exactly once.
            unsafe {
                let _ = EvtClose(self.0);
            }
        }
    }
}

/// Critical (level 1) and Error (level 2) events from `channel` in the last
/// `hours`, newest first, at most `max` of them.
pub fn recent_errors(channel: &str, hours: u32, max: usize) -> Result<Vec<RawEvent>, String> {
    let query = format!(
        "*[System[(Level=1 or Level=2) and TimeCreated[timediff(@SystemTime) <= {}]]]",
        u64::from(hours) * 3_600_000
    );
    let path = HSTRING::from(channel);
    let query = HSTRING::from(query);
    let flags = EvtQueryChannelPath.0 | EvtQueryReverseDirection.0;
    // SAFETY: valid wide strings; the result-set handle is wrapped for closing.
    let results = unsafe { EvtQuery(None, &path, &query, flags) }
        .map_err(|e| super::err(&format!("can't read the {channel} log"), &e))?;
    let results = Handle(results);

    let mut publishers: HashMap<String, Option<Handle>> = HashMap::new();
    let mut seen: HashSet<(String, u32)> = HashSet::new();
    let mut events = Vec::new();
    let mut batch = [0isize; 64]; // raw EVT_HANDLE values

    while events.len() < max {
        let mut returned = 0u32;
        // Fails with ERROR_NO_MORE_ITEMS at the end of the result set.
        if unsafe { EvtNext(results.0, &mut batch, 2_000, 0, &mut returned) }.is_err() || returned == 0 {
            break;
        }
        for &raw in &batch[..returned as usize] {
            let event = Handle(EVT_HANDLE(raw)); // closed at the end of this iteration
            let Some(xml) = (unsafe { render_xml(event.0) }) else {
                continue;
            };
            let Some(system) = parse_system(&xml) else {
                continue;
            };
            let first = seen.insert((system.provider.clone(), system.event_id));
            let message = if first {
                unsafe { format_message(&mut publishers, &system.provider, event.0) }
            } else {
                None
            };
            events.push(RawEvent { system, message });
        }
    }
    Ok(events)
}

/// Events from `channel` matching a fixed XPath `query`, newest first, at
/// most `max`, each rendered as XML. The query is always one of ITriage's
/// own constants; values to match on are compared afterwards, in Rust.
pub fn query_xml(channel: &str, query: &'static str, max: usize) -> Result<Vec<String>, String> {
    Ok(query_events(channel, query, max, false)?.into_iter().map(|e| e.xml).collect())
}

/// One event as XML, and as Windows words it for a person ("The start type
/// of the Print Spooler service was changed from auto start to disabled.").
pub struct Rendered {
    pub xml: String,
    /// `None` when the event's provider has no message text installed.
    pub message: Option<String>,
}

/// `query_xml`, with each event's message as well. Formatting a message is
/// the slow part (a few milliseconds each), so ask for what will be shown.
pub fn query_rendered(channel: &str, query: &'static str, max: usize) -> Result<Vec<Rendered>, String> {
    query_events(channel, query, max, true)
}

fn query_events(channel: &str, query: &'static str, max: usize, messages: bool) -> Result<Vec<Rendered>, String> {
    let path = HSTRING::from(channel);
    let query = HSTRING::from(query);
    let flags = EvtQueryChannelPath.0 | EvtQueryReverseDirection.0;
    // SAFETY: valid wide strings; every handle is wrapped for closing.
    let results = unsafe { EvtQuery(None, &path, &query, flags) }
        .map_err(|e| super::err(&format!("can't read the {channel} log"), &e))?;
    let results = Handle(results);
    let mut publishers: HashMap<String, Option<Handle>> = HashMap::new();
    let mut events = Vec::new();
    let mut batch = [0isize; 64];
    while events.len() < max {
        let mut returned = 0u32;
        if unsafe { EvtNext(results.0, &mut batch, 2_000, 0, &mut returned) }.is_err() || returned == 0 {
            break;
        }
        for &raw in &batch[..returned as usize] {
            // Every handle in the batch is closed, kept or not.
            let event = Handle(EVT_HANDLE(raw));
            if events.len() >= max {
                continue;
            }
            let Some(xml) = (unsafe { render_xml(event.0) }) else {
                continue;
            };
            let message = if messages {
                parse_system(&xml).and_then(|s| unsafe { format_message(&mut publishers, &s.provider, event.0) })
            } else {
                None
            };
            events.push(Rendered { xml, message });
        }
    }
    Ok(events)
}

unsafe fn render_xml(event: EVT_HANDLE) -> Option<String> {
    let mut used = 0u32;
    let mut properties = 0u32;
    // Sizing call: fails with ERROR_INSUFFICIENT_BUFFER and reports bytes needed.
    let _ = EvtRender(None, event, EvtRenderEventXml.0, 0, None, &mut used, &mut properties);
    if used == 0 {
        return None;
    }
    let mut buf = vec![0u16; (used as usize).div_ceil(2) + 1];
    EvtRender(
        None,
        event,
        EvtRenderEventXml.0,
        (buf.len() * 2) as u32,
        Some(buf.as_mut_ptr() as *mut core::ffi::c_void),
        &mut used,
        &mut properties,
    )
    .ok()?;
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    Some(String::from_utf16_lossy(&buf[..len]))
}

unsafe fn format_message(
    publishers: &mut HashMap<String, Option<Handle>>,
    provider: &str,
    event: EVT_HANDLE,
) -> Option<String> {
    let metadata = publishers.entry(provider.to_string()).or_insert_with(|| {
        let name = HSTRING::from(provider);
        EvtOpenPublisherMetadata(None, &name, PCWSTR::null(), 0, 0)
            .ok()
            .map(Handle)
    });
    let metadata = metadata.as_ref()?.0;

    let mut used = 0u32; // in characters, for EvtFormatMessage
    let _ = EvtFormatMessage(Some(metadata), Some(event), 0, None, EvtFormatMessageEvent.0, None, &mut used);
    if used == 0 {
        return None;
    }
    let mut buf = vec![0u16; used as usize];
    EvtFormatMessage(
        Some(metadata),
        Some(event),
        0,
        None,
        EvtFormatMessageEvent.0,
        Some(&mut buf),
        &mut used,
    )
    .ok()?;
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    let text = String::from_utf16_lossy(&buf[..len]).trim().to_string();
    (!text.is_empty()).then_some(text)
}
