#![cfg_attr(not(windows), allow(dead_code))]
//! `winget upgrade` output.

use super::text::strip_ansi;

#[derive(Debug, Clone, PartialEq)]
pub struct WingetRow {
    pub name: String,
    pub id: String,
    pub version: String,
    pub available: String,
}

/// Parse the first table in `winget upgrade` output.
///
/// Column boundaries come from the header row (the line above the `----`
/// rule) rather than from the English header words, so localised headers
/// still parse. Rows end at the first line that doesn't fit the columns, such
/// as the "12 upgrades available." footer.
pub fn parse_upgrade_table(out: &str) -> Vec<WingetRow> {
    // What a terminal would show: the text after the last bare CR (winget draws
    // its spinner with CRs before printing the table).
    let lines: Vec<String> = out
        .lines()
        .map(|l| strip_ansi(l.rsplit('\r').next().unwrap_or(l)))
        .collect();

    let Some(rule) = lines.iter().position(|l| {
        let t = l.trim();
        t.len() >= 10 && t.chars().all(|c| c == '-')
    }) else {
        return Vec::new();
    };
    if rule == 0 {
        return Vec::new();
    }

    let header: Vec<char> = lines[rule - 1].chars().collect();
    let starts = column_starts(&header);
    if starts.len() < 4 {
        return Vec::new();
    }

    let mut rows = Vec::new();
    for line in &lines[rule + 1..] {
        let chars: Vec<char> = line.chars().collect();
        if chars.len() <= starts[3] {
            break;
        }
        let col = |i: usize| -> String {
            let a = starts[i];
            let b = starts.get(i + 1).copied().unwrap_or(chars.len()).min(chars.len());
            if a >= b {
                return String::new();
            }
            chars[a..b].iter().collect::<String>().trim().to_string()
        };
        let (name, id, version, available) = (col(0), col(1), col(2), col(3));
        if id.is_empty() || id.contains(' ') || available.is_empty() {
            break;
        }
        rows.push(WingetRow {
            name,
            id,
            version,
            available,
        });
    }
    rows
}

/// Start index of each header word (a non-space that follows a space).
fn column_starts(header: &[char]) -> Vec<usize> {
    let mut starts = vec![0];
    for i in 1..header.len() {
        if header[i] != ' ' && header[i - 1] == ' ' {
            starts.push(i);
        }
    }
    starts
}

/// What happened during `winget upgrade --all`, read from its transcript.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct UpgradeTally {
    pub upgraded: usize,
    pub failed: usize,
    pub nothing_to_do: bool,
}

/// Count successes and failures in a `winget upgrade --all` transcript.
/// winget's messages are localised, so these are English-language heuristics;
/// the exit code is the authoritative signal and is reported alongside.
pub fn tally_upgrade(transcript: &str) -> UpgradeTally {
    let mut t = UpgradeTally::default();
    for line in transcript.lines() {
        if line.contains("Successfully installed") {
            t.upgraded += 1;
        } else if line.contains("Installer failed") || line.contains("failed with exit code") {
            t.failed += 1;
        }
    }
    t.nothing_to_do = t.upgraded == 0
        && (transcript.contains("No installed package found")
            || transcript.contains("No available upgrade found")
            || transcript.contains("No applicable upgrade found"));
    t
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(cols: [&str; 5]) -> String {
        format!("{:<29}{:<23}{:<15}{:<15}{}", cols[0], cols[1], cols[2], cols[3], cols[4])
    }

    #[test]
    fn parses_table_with_spinner_and_footer() {
        let out = [
            format!("   - \r   \\ \r{}", row(["Name", "Id", "Version", "Available", "Source"])),
            "-".repeat(90),
            row(["Google Chrome", "Google.Chrome", "130.0.6723.92", "131.0.6778.70", "winget"]),
            row(["7-Zip 23.01 (x64)", "7zip.7zip", "23.01", "24.08", "winget"]),
            row(["Microsoft Visual Studio Code", "Microsoft.VisualStudio…", "1.94.2", "1.95.1", "winget"]),
            "3 upgrades available.".to_string(),
        ]
        .join("\r\n");

        let rows = parse_upgrade_table(&out);
        assert_eq!(rows.len(), 3, "{rows:?}");
        assert_eq!(
            rows[0],
            WingetRow {
                name: "Google Chrome".into(),
                id: "Google.Chrome".into(),
                version: "130.0.6723.92".into(),
                available: "131.0.6778.70".into(),
            }
        );
        assert_eq!(rows[1].name, "7-Zip 23.01 (x64)");
        assert_eq!(rows[2].available, "1.95.1");
    }

    #[test]
    fn empty_when_nothing_to_upgrade() {
        assert!(parse_upgrade_table("No installed package found matching input criteria.").is_empty());
        assert!(parse_upgrade_table("").is_empty());
    }

    #[test]
    fn tallies_upgrade_transcripts() {
        let t = tally_upgrade(
            "Found Google Chrome [Google.Chrome] Version 131\nSuccessfully installed\n\
             Found 7-Zip [7zip.7zip] Version 24.08\nInstaller failed with exit code: 1603\n",
        );
        assert_eq!(t, UpgradeTally { upgraded: 1, failed: 1, nothing_to_do: false });
        assert!(tally_upgrade("No installed package found matching input criteria.").nothing_to_do);
    }
}
