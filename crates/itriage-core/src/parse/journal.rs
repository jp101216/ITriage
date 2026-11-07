#![cfg_attr(windows, allow(dead_code))]
//! `journalctl --output=json` lines.

#[derive(Debug, Clone, PartialEq)]
pub struct JournalEntry {
    /// syslog priority: 0 emerg … 3 err … 7 debug.
    pub priority: u8,
    /// SYSLOG_IDENTIFIER, else the unit, else the command name.
    pub source: String,
    pub message: String,
    pub epoch: Option<u64>,
}

/// Parse one JSON line. MESSAGE is a string, or an array of bytes when the
/// payload isn't valid UTF-8.
pub fn parse_line(line: &str) -> Option<JournalEntry> {
    let v: serde_json::Value = serde_json::from_str(line).ok()?;
    let field = |k: &str| v.get(k).and_then(|x| x.as_str()).map(str::to_string);

    let priority = field("PRIORITY")?.parse().ok()?;
    let message = match v.get("MESSAGE")? {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Array(bytes) => {
            let raw: Vec<u8> = bytes
                .iter()
                .filter_map(|b| b.as_u64())
                .map(|b| b as u8)
                .collect();
            String::from_utf8_lossy(&raw).into_owned()
        }
        _ => return None,
    };
    let source = field("SYSLOG_IDENTIFIER")
        .or_else(|| field("_SYSTEMD_UNIT"))
        .or_else(|| field("_COMM"))
        .unwrap_or_else(|| "unknown".to_string());
    let epoch = field("__REALTIME_TIMESTAMP")
        .and_then(|t| t.parse::<u64>().ok())
        .map(|micros| micros / 1_000_000);

    Some(JournalEntry {
        priority,
        source,
        message,
        epoch,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_string_and_byte_messages() {
        let e = parse_line(
            r#"{"__REALTIME_TIMESTAMP":"1793992951000000","PRIORITY":"3","SYSLOG_IDENTIFIER":"kernel","MESSAGE":"ACPI Error: AE_NOT_FOUND"}"#,
        )
        .unwrap();
        assert_eq!(e.priority, 3);
        assert_eq!(e.source, "kernel");
        assert_eq!(e.message, "ACPI Error: AE_NOT_FOUND");
        assert_eq!(e.epoch, Some(1_793_992_951));

        let bytes = parse_line(r#"{"PRIORITY":"2","_SYSTEMD_UNIT":"foo.service","MESSAGE":[104,105]}"#).unwrap();
        assert_eq!(bytes.message, "hi");
        assert_eq!(bytes.source, "foo.service");
        assert_eq!(bytes.epoch, None);
    }

    #[test]
    fn skips_lines_without_priority_or_message() {
        assert_eq!(parse_line(r#"{"MESSAGE":"x"}"#), None);
        assert_eq!(parse_line("not json"), None);
    }
}
