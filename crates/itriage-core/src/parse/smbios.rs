//! Machine identity from SMBIOS: make, model, serial number, BIOS version and
//! date, motherboard, and chassis type.
//!
//! On Windows the raw table comes from `GetSystemFirmwareTable('RSMB')`; on
//! Linux the kernel already exposes the same strings under
//! `/sys/class/dmi/id`. Both end up in [`Identity`], cleaned the same way.

/// What the firmware says this machine is.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Identity {
    pub manufacturer: Option<String>,
    pub model: Option<String>,
    pub family: Option<String>,
    pub serial: Option<String>,
    pub bios_vendor: Option<String>,
    pub bios_version: Option<String>,
    /// `YYYY-MM-DD` when the firmware gives a parseable date.
    pub bios_date: Option<String>,
    pub board_maker: Option<String>,
    pub board_product: Option<String>,
    /// SMBIOS chassis type (3 = desktop, 10 = notebook, …).
    pub chassis: Option<u8>,
}

impl Identity {
    /// Laptops, tablets and convertibles: the machines that can be on battery.
    pub fn portable(&self) -> bool {
        matches!(self.chassis, Some(8 | 9 | 10 | 11 | 14 | 30 | 31 | 32))
    }

    pub fn chassis_name(&self) -> Option<&'static str> {
        Some(match self.chassis? {
            3 => "Desktop",
            4 => "Low-profile desktop",
            5 => "Pizza box",
            6 => "Mini tower",
            7 => "Tower",
            8 => "Portable",
            9 => "Laptop",
            10 => "Notebook",
            11 => "Handheld",
            13 => "All-in-one",
            14 => "Sub-notebook",
            15 => "Space-saving",
            17 => "Main server chassis",
            23 => "Rack mount",
            24 => "Sealed-case PC",
            30 => "Tablet",
            31 => "Convertible",
            32 => "Detachable",
            33 => "IoT gateway",
            34 => "Embedded PC",
            35 => "Mini PC",
            36 => "Stick PC",
            _ => return None,
        })
    }

    /// "Dell Inc. Latitude 7450", without repeating the maker when the model
    /// already starts with it ("HP HP EliteBook…").
    pub fn make_and_model(&self) -> Option<String> {
        match (&self.manufacturer, &self.model) {
            (Some(m), Some(p)) if p.to_lowercase().starts_with(&m.to_lowercase()) => Some(p.clone()),
            (Some(m), Some(p)) => Some(format!("{m} {p}")),
            (Some(m), None) => Some(m.clone()),
            (None, Some(p)) => Some(p.clone()),
            (None, None) => None,
        }
    }

    /// "ASUSTeK COMPUTER INC. PRIME B550M-A".
    pub fn motherboard(&self) -> Option<String> {
        let joined = [self.board_maker.as_deref(), self.board_product.as_deref()]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .join(" ");
        (!joined.is_empty()).then_some(joined)
    }

    /// "1.21.0 · released 2026-05-14".
    pub fn bios(&self) -> Option<String> {
        match (&self.bios_version, &self.bios_date) {
            (Some(v), Some(d)) => Some(format!("{v} · released {d}")),
            (Some(v), None) => Some(v.clone()),
            (None, Some(d)) => Some(format!("released {d}")),
            (None, None) => None,
        }
    }
}

/// Placeholder strings boards ship with instead of a real value.
pub fn clean(raw: &str) -> Option<String> {
    let s = raw.trim().trim_matches('\0').trim();
    const PLACEHOLDERS: [&str; 18] = [
        "to be filled by o.e.m.",
        "to be filled by oem",
        "default string",
        "not specified",
        "not applicable",
        "none",
        "n/a",
        "na",
        "o.e.m.",
        "oem",
        "system serial number",
        "system product name",
        "system manufacturer",
        "system version",
        "base board serial number",
        "chassis serial number",
        "invalid",
        "unknown",
    ];
    let lower = s.to_ascii_lowercase();
    if s.is_empty() || PLACEHOLDERS.contains(&lower.as_str()) || s.chars().all(|c| c == '0' || c == ' ') {
        return None;
    }
    Some(s.to_string())
}

/// SMBIOS dates are `MM/DD/YYYY` (sometimes `MM/DD/YY`). Anything else is
/// kept as it came.
pub fn normalize_date(raw: &str) -> Option<String> {
    let s = clean(raw)?;
    let parts: Vec<&str> = s.split('/').collect();
    if let [m, d, y] = parts[..] {
        let (m, d) = (m.parse::<u32>().ok(), d.parse::<u32>().ok());
        let y = y.parse::<u32>().ok().map(|y| if y < 100 { 1900 + y + if y < 80 { 100 } else { 0 } } else { y });
        if let (Some(m), Some(d), Some(y)) = (m, d, y) {
            if (1..=12).contains(&m) && (1..=31).contains(&d) {
                return Some(format!("{y:04}-{m:02}-{d:02}"));
            }
        }
    }
    Some(s)
}

/// Parse the buffer `GetSystemFirmwareTable('RSMB')` fills: an 8-byte
/// `RawSMBIOSData` header, then the structure table.
pub fn parse_raw(buf: &[u8]) -> Option<Identity> {
    if buf.len() < 8 {
        return None;
    }
    let len = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]) as usize;
    let table = buf.get(8..8 + len.min(buf.len() - 8))?;
    Some(parse_table(table))
}

/// Walk the SMBIOS structure table and pick out the identity strings.
pub fn parse_table(data: &[u8]) -> Identity {
    let mut id = Identity::default();
    let mut pos = 0usize;
    while pos + 4 <= data.len() {
        let kind = data[pos];
        let len = data[pos + 1] as usize;
        if len < 4 || pos + len > data.len() {
            break;
        }
        let formatted = &data[pos..pos + len];
        // The string set follows the formatted area and ends with a double NUL.
        let mut end = pos + len;
        while end + 1 < data.len() && !(data[end] == 0 && data[end + 1] == 0) {
            end += 1;
        }
        let strings: Vec<&[u8]> = data[pos + len..end.min(data.len())]
            .split(|&b| b == 0)
            .filter(|s| !s.is_empty())
            .collect();
        let text = |offset: usize| -> Option<String> {
            let index = *formatted.get(offset)? as usize;
            let raw = strings.get(index.checked_sub(1)?)?;
            clean(&String::from_utf8_lossy(raw))
        };
        match kind {
            0 => {
                id.bios_vendor = id.bios_vendor.or_else(|| text(0x04));
                id.bios_version = id.bios_version.or_else(|| text(0x05));
                id.bios_date = id.bios_date.or_else(|| text(0x08).and_then(|d| normalize_date(&d)));
            }
            1 => {
                id.manufacturer = id.manufacturer.or_else(|| text(0x04));
                id.model = id.model.or_else(|| text(0x05));
                id.serial = id.serial.or_else(|| text(0x07));
                id.family = id.family.or_else(|| text(0x1A));
            }
            2 => {
                id.board_maker = id.board_maker.or_else(|| text(0x04));
                id.board_product = id.board_product.or_else(|| text(0x05));
            }
            3 => {
                if id.chassis.is_none() {
                    id.chassis = formatted.get(0x05).map(|b| b & 0x7F);
                }
            }
            127 => break,
            _ => {}
        }
        pos = end + 2;
    }
    id
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One SMBIOS structure: header, formatted bytes, then its strings.
    fn structure(kind: u8, formatted: &[u8], strings: &[&str]) -> Vec<u8> {
        let mut out = vec![kind, (formatted.len() + 4) as u8, 0, 0];
        out.extend_from_slice(formatted);
        if strings.is_empty() {
            out.extend_from_slice(&[0, 0]);
        } else {
            for s in strings {
                out.extend_from_slice(s.as_bytes());
                out.push(0);
            }
            out.push(0);
        }
        out
    }

    fn sample() -> Vec<u8> {
        let mut t = Vec::new();
        // Type 0: vendor=1, version=2, start seg (2 bytes), date=3, rom size.
        t.extend(structure(0, &[1, 2, 0, 0, 3, 0], &["Dell Inc.", "1.21.0", "05/14/2026"]));
        // Type 1: maker=1, product=2, version=3, serial=4, UUID(16), wake, sku=5, family=6.
        let mut sys = vec![1, 2, 3, 4];
        sys.extend([0u8; 16]);
        sys.extend([6, 5, 6]);
        t.extend(structure(1, &sys, &["Dell Inc.", "Latitude 7450", "Not Specified", "7FHXW37", "0C1A", "Latitude"]));
        // Type 2: maker=1, product=2, version=3, serial=4.
        t.extend(structure(2, &[1, 2, 3, 4], &["Dell Inc.", "0K0X5C", "A00", "/7FHXW37/CNCMK0047A0123/"]));
        // Type 3: maker=1, type=10 (notebook) with the lock bit set.
        t.extend(structure(3, &[1, 0x80 | 10], &["Dell Inc."]));
        t.extend(structure(127, &[], &[]));
        t
    }

    #[test]
    fn reads_identity_from_the_structure_table() {
        let id = parse_table(&sample());
        assert_eq!(id.manufacturer.as_deref(), Some("Dell Inc."));
        assert_eq!(id.model.as_deref(), Some("Latitude 7450"));
        assert_eq!(id.serial.as_deref(), Some("7FHXW37"));
        assert_eq!(id.family.as_deref(), Some("Latitude"));
        assert_eq!(id.bios_version.as_deref(), Some("1.21.0"));
        assert_eq!(id.bios_date.as_deref(), Some("2026-05-14"));
        assert_eq!(id.motherboard().as_deref(), Some("Dell Inc. 0K0X5C"));
        assert_eq!(id.chassis, Some(10));
        assert!(id.portable());
        assert_eq!(id.make_and_model().as_deref(), Some("Dell Inc. Latitude 7450"));
        assert_eq!(id.bios().as_deref(), Some("1.21.0 · released 2026-05-14"));
    }

    #[test]
    fn reads_the_raw_firmware_table_header() {
        let table = sample();
        let mut raw = vec![0, 3, 4, 0];
        raw.extend((table.len() as u32).to_le_bytes());
        raw.extend(&table);
        assert_eq!(parse_raw(&raw).unwrap().model.as_deref(), Some("Latitude 7450"));
        assert!(parse_raw(&[1, 2]).is_none());
    }

    #[test]
    fn whitebox_placeholders_are_dropped() {
        let mut t = structure(1, &[1, 2, 0, 3], &["To Be Filled By O.E.M.", "System Product Name", "Default string"]);
        t.extend(structure(2, &[1, 2], &["ASUSTeK COMPUTER INC.", "PRIME B550M-A"]));
        let id = parse_table(&t);
        assert_eq!((&id.manufacturer, &id.model, &id.serial), (&None, &None, &None));
        assert_eq!(id.motherboard().as_deref(), Some("ASUSTeK COMPUTER INC. PRIME B550M-A"));
    }

    #[test]
    fn survives_truncated_tables() {
        let t = sample();
        for cut in 0..t.len() {
            let _ = parse_table(&t[..cut]);
        }
        assert_eq!(normalize_date("12/31/99").as_deref(), Some("1999-12-31"));
        assert_eq!(normalize_date("2024-01-05").as_deref(), Some("2024-01-05"));
        assert_eq!(clean("  0000000  "), None);
        assert!(!Identity { chassis: Some(3), ..Default::default() }.portable());
    }
}
