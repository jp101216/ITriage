#![cfg_attr(windows, allow(dead_code))]
//! Linux package-manager and fwupd output → pending updates.

#[derive(Debug, Clone, PartialEq)]
pub struct PkgUpdate {
    pub name: String,
    pub from: Option<String>,
    pub to: String,
}

impl PkgUpdate {
    /// "1.2 → 1.3", or just the new version when the old one isn't known.
    pub fn change(&self) -> String {
        match &self.from {
            Some(from) => format!("{from} → {}", self.to),
            None => format!("→ {}", self.to),
        }
    }
}

/// `apt-get -s --with-new-pkgs upgrade`, which simulates exactly what the
/// installer will do (including held-back packages). Lines look like
/// `Inst libssl3 [3.0.2-0ubuntu1.17] (3.0.2-0ubuntu1.18 Ubuntu:24.04/noble-updates [amd64])`,
/// or with no `[old]` for a newly pulled-in package (e.g. a new kernel).
pub fn apt_simulation(out: &str) -> Vec<PkgUpdate> {
    out.lines()
        .filter_map(|l| {
            let rest = l.strip_prefix("Inst ")?;
            let (name, rest) = rest.split_once(' ')?;
            let rest = rest.trim_start();
            let (from, rest) = match rest.strip_prefix('[') {
                Some(r) => {
                    let (old, r) = r.split_once(']')?;
                    (Some(old.to_string()), r.trim_start())
                }
                None => (None, rest),
            };
            let to = rest.strip_prefix('(')?.split_whitespace().next()?.to_string();
            Some(PkgUpdate {
                name: name.to_string(),
                from,
                to,
            })
        })
        .collect()
}

/// `dnf check-update`: `name.arch  version  repo` rows. Stops at the
/// "Obsoleting Packages" section.
pub fn dnf_check_update(out: &str) -> Vec<PkgUpdate> {
    const ARCHES: &[&str] = &["x86_64", "noarch", "i686", "aarch64", "armv7hl", "ppc64le", "s390x"];
    let mut updates = Vec::new();
    for line in out.lines() {
        let t = line.trim();
        if t.starts_with("Obsoleting") {
            break;
        }
        let parts: Vec<&str> = t.split_whitespace().collect();
        if parts.len() != 3 {
            continue;
        }
        let Some((name, arch)) = parts[0].rsplit_once('.') else {
            continue;
        };
        if !ARCHES.contains(&arch) || !parts[1].chars().any(|c| c.is_ascii_digit()) {
            continue;
        }
        updates.push(PkgUpdate {
            name: name.to_string(),
            from: None,
            to: parts[1].to_string(),
        });
    }
    updates
}

/// `checkupdates` / `pacman -Qu`: `name old -> new`, sometimes with `[ignored]`.
pub fn pacman_updates(out: &str) -> Vec<PkgUpdate> {
    out.lines()
        .filter_map(|l| {
            let p: Vec<&str> = l.split_whitespace().collect();
            (p.len() >= 4 && p[2] == "->").then(|| PkgUpdate {
                name: p[0].to_string(),
                from: Some(p[1].to_string()),
                to: p[3].to_string(),
            })
        })
        .collect()
}

/// `zypper list-updates` table rows: `v | Repo | Name | Current | Available | Arch`.
pub fn zypper_updates(out: &str) -> Vec<PkgUpdate> {
    out.lines()
        .filter_map(|l| {
            let cols: Vec<&str> = l.split('|').map(str::trim).collect();
            (cols.len() >= 6 && cols[0] == "v").then(|| PkgUpdate {
                name: cols[2].to_string(),
                from: Some(cols[3].to_string()),
                to: cols[4].to_string(),
            })
        })
        .collect()
}

/// The "N upgraded, M newly installed, …" line apt prints for an upgrade.
pub fn apt_result_line(out: &str) -> Option<String> {
    out.lines()
        .map(str::trim)
        .rev()
        .find(|l| l.contains(" upgraded, ") && l.contains(" newly installed"))
        .map(str::to_string)
}

/// `fwupdmgr get-updates --json`: devices that have a newer release. The JSON
/// can be preceded by warnings and followed by other text, so parse just the
/// first JSON value starting at the first `{`.
pub fn fwupd_updates(out: &str) -> Vec<PkgUpdate> {
    let Some(start) = out.find('{') else {
        return Vec::new();
    };
    let Some(Ok(v)) = serde_json::Deserializer::from_str(&out[start..])
        .into_iter::<serde_json::Value>()
        .next()
    else {
        return Vec::new();
    };
    let Some(devices) = v.get("Devices").and_then(|d| d.as_array()) else {
        return Vec::new();
    };
    devices
        .iter()
        .filter_map(|d| {
            let to = d.get("Releases")?.as_array()?.first()?.get("Version")?.as_str()?;
            Some(PkgUpdate {
                name: d.get("Name")?.as_str()?.to_string(),
                from: d.get("Version").and_then(|x| x.as_str()).map(str::to_string),
                to: to.to_string(),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apt_simulation_rows() {
        let out = "NOTE: This is only a simulation!\n\
            Reading package lists... Done\n\
            Inst libssl3t64 [3.0.13-0ubuntu3.4] (3.0.13-0ubuntu3.5 Ubuntu:24.04/noble-updates [amd64])\n\
            Inst linux-image-6.8.0-49-generic (6.8.0-49.49 Ubuntu:24.04/noble-updates [amd64])\n\
            Conf libssl3t64 (3.0.13-0ubuntu3.5 Ubuntu:24.04/noble-updates [amd64])\n";
        let rows = apt_simulation(out);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].name, "libssl3t64");
        assert_eq!(rows[0].change(), "3.0.13-0ubuntu3.4 → 3.0.13-0ubuntu3.5");
        assert_eq!(rows[1].from, None);
        assert_eq!(rows[1].to, "6.8.0-49.49");
    }

    #[test]
    fn dnf_rows() {
        let out = "Last metadata expiration check: 0:12:01 ago on Fri 06 Nov 2026 02:00:00 PM EST.\n\n\
            kernel.x86_64                     6.11.5-300.fc41          updates\n\
            firefox.x86_64                    132.0-1.fc41             updates\n\
            Obsoleting Packages\n\
            grub2-tools.x86_64                1:2.12-4.fc41            updates\n";
        let rows = dnf_check_update(out);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].name, "kernel");
        assert_eq!(rows[1].to, "132.0-1.fc41");
    }

    #[test]
    fn pacman_and_zypper_rows() {
        let p = pacman_updates("linux 6.11.5.arch1-1 -> 6.11.6.arch1-1\nmesa 1:24.2.5-1 -> 1:24.2.6-1 [ignored]\n");
        assert_eq!(p.len(), 2);
        assert_eq!(p[0].change(), "6.11.5.arch1-1 → 6.11.6.arch1-1");

        let z = zypper_updates(
            "Loading repository data...\n\
             S | Repository | Name   | Current Version | Available Version | Arch\n\
             --+------------+--------+-----------------+-------------------+-------\n\
             v | Main       | kernel | 6.4.0-150600    | 6.4.0-150700      | x86_64\n",
        );
        assert_eq!(z.len(), 1);
        assert_eq!(z[0].name, "kernel");
        assert_eq!(z[0].to, "6.4.0-150700");
    }

    #[test]
    fn apt_summary_line() {
        let out = "Reading state information...\n12 upgraded, 1 newly installed, 0 to remove and 0 not upgraded.\nSetting up ...";
        assert_eq!(
            apt_result_line(out).as_deref(),
            Some("12 upgraded, 1 newly installed, 0 to remove and 0 not upgraded.")
        );
    }

    #[test]
    fn fwupd_json() {
        let out = "WARNING: metadata is 31 days old\n{\"Devices\":[{\"Name\":\"System Firmware\",\"Version\":\"1.19.0\",\"Releases\":[{\"Version\":\"1.21.0\"}]},{\"Name\":\"TPM\",\"Version\":\"7.2\",\"Releases\":[]}]}\ntrailing text";
        let rows = fwupd_updates(out);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].name, "System Firmware");
        assert_eq!(rows[0].change(), "1.19.0 → 1.21.0");
        assert!(fwupd_updates("No updatable devices").is_empty());
    }
}
