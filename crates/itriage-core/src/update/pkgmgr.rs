//! Linux package managers: how to list pending upgrades without root, and the
//! non-interactive script that installs them (run as root through pkexec).

use crate::parse::pkg::{apt_simulation, dnf_check_update, pacman_updates, zypper_updates, PkgUpdate};
use crate::parse::text::first_line;
use crate::util::{capture, cmd, command_exists};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PkgMgr {
    Apt,
    Dnf,
    Pacman,
    Zypper,
}

impl PkgMgr {
    /// The first supported package manager on this system.
    pub fn detect() -> Option<Self> {
        [PkgMgr::Apt, PkgMgr::Dnf, PkgMgr::Pacman, PkgMgr::Zypper]
            .into_iter()
            .find(|m| command_exists(m.binary()))
    }

    fn binary(self) -> &'static str {
        match self {
            PkgMgr::Apt => "apt-get",
            PkgMgr::Dnf => "dnf",
            PkgMgr::Pacman => "pacman",
            PkgMgr::Zypper => "zypper",
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            PkgMgr::Apt => "apt",
            PkgMgr::Dnf => "dnf",
            PkgMgr::Pacman => "pacman",
            PkgMgr::Zypper => "zypper",
        }
    }

    /// Caveat shown with the scan, where the listing can be stale.
    pub fn scan_note(self) -> Option<&'static str> {
        match self {
            PkgMgr::Apt => Some("Based on the cached package lists; installing refreshes them first."),
            PkgMgr::Pacman if !command_exists("checkupdates") => {
                Some("Based on the local sync database; install pacman-contrib for a fresh check.")
            }
            PkgMgr::Zypper => Some("Based on cached repository metadata."),
            _ => None,
        }
    }

    /// Pending upgrades, listed without root.
    pub fn pending(self) -> Result<Vec<PkgUpdate>, String> {
        match self {
            PkgMgr::Apt => {
                // A simulation is exactly what the installer will do, held-back
                // packages included, and works as a normal user.
                let out = run(&["apt-get", "-s", "--with-new-pkgs", "upgrade"])?;
                expect(&out, &[0], "apt-get -s upgrade")?;
                Ok(apt_simulation(&out.stdout))
            }
            PkgMgr::Dnf => {
                let out = run(&["dnf", "-q", "check-update"])?;
                expect(&out, &[0, 100], "dnf check-update")?; // 100 = updates available
                Ok(dnf_check_update(&out.stdout))
            }
            PkgMgr::Pacman => {
                if command_exists("checkupdates") {
                    let out = run(&["checkupdates"])?;
                    expect(&out, &[0, 2], "checkupdates")?; // 2 = nothing to update
                    Ok(pacman_updates(&out.stdout))
                } else {
                    let out = run(&["pacman", "-Qu"])?;
                    expect(&out, &[0, 1], "pacman -Qu")?; // 1 = nothing to update
                    Ok(pacman_updates(&out.stdout))
                }
            }
            PkgMgr::Zypper => {
                let out = run(&["zypper", "--non-interactive", "--no-refresh", "list-updates"])?;
                expect(&out, &[0], "zypper list-updates")?;
                Ok(zypper_updates(&out.stdout))
            }
        }
    }

    /// A fixed shell script (no user input is interpolated) that refreshes
    /// metadata and upgrades everything non-interactively. A failed refresh
    /// (one dead third-party repo, say) shouldn't block security updates from
    /// the repos that still work, so refresh and upgrade are joined with `;`.
    pub fn upgrade_script(self) -> &'static str {
        match self {
            PkgMgr::Apt => {
                "export DEBIAN_FRONTEND=noninteractive; \
                 apt-get -o DPkg::Lock::Timeout=120 update; \
                 apt-get -y -o DPkg::Lock::Timeout=120 \
                   -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold \
                   --with-new-pkgs upgrade"
            }
            PkgMgr::Dnf => "dnf -y upgrade --refresh",
            PkgMgr::Pacman => "pacman -Syu --noconfirm",
            PkgMgr::Zypper => "zypper --non-interactive refresh; zypper --non-interactive update",
        }
    }
}

fn run(argv: &[&str]) -> Result<crate::util::CmdOutput, String> {
    let mut c = cmd(argv[0]);
    c.args(&argv[1..]).env("LC_ALL", "C");
    capture(c)
}

fn expect(out: &crate::util::CmdOutput, ok_codes: &[i32], what: &str) -> Result<(), String> {
    match out.code {
        Some(c) if ok_codes.contains(&c) => Ok(()),
        _ => Err(format!("{what} failed: {}", first_line(&out.combined()))),
    }
}

/// Debian/Ubuntu drop this file when an installed update needs a reboot.
pub fn reboot_required() -> Option<String> {
    if !std::path::Path::new("/var/run/reboot-required").exists() {
        return None;
    }
    let pkgs = std::fs::read_to_string("/var/run/reboot-required.pkgs").unwrap_or_default();
    let mut list: Vec<&str> = pkgs.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
    list.dedup();
    Some(if list.is_empty() {
        "an installed update needs a reboot".to_string()
    } else {
        format!("needed by: {}", list.join(", "))
    })
}
