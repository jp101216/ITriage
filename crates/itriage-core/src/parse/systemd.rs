#![cfg_attr(windows, allow(dead_code))]
//! `systemctl list-units --plain --no-legend` rows.

#[derive(Debug, Clone, PartialEq)]
pub struct UnitRow {
    pub unit: String,
    pub load: String,
    pub active: String,
    pub sub: String,
    pub description: String,
}

pub fn unit_rows(out: &str) -> Vec<UnitRow> {
    out.lines()
        .filter_map(|l| {
            // Older systemd prints a "●" marker on failed units even with --plain.
            let l = l.trim_start_matches(|c: char| c == '●' || c == '*' || c.is_whitespace());
            let mut it = l.split_whitespace();
            let unit = it.next()?;
            let (load, active, sub) = (it.next()?, it.next()?, it.next()?);
            if !unit.contains('.') {
                return None;
            }
            Some(UnitRow {
                unit: unit.to_string(),
                load: load.to_string(),
                active: active.to_string(),
                sub: sub.to_string(),
                description: it.collect::<Vec<_>>().join(" "),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_failed_units() {
        let out = "nginx.service loaded failed failed A high performance web server\n\
                   ● apport-autoreport.path loaded failed failed Process error reports when automatic reporting is enabled\n";
        let rows = unit_rows(out);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].unit, "nginx.service");
        assert_eq!(rows[0].active, "failed");
        assert_eq!(rows[0].description, "A high performance web server");
        assert_eq!(rows[1].unit, "apport-autoreport.path");
        assert!(unit_rows("").is_empty());
    }
}
