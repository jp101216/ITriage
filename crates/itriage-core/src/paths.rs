//! Where itriage keeps things on disk, per platform.
//!
//! | what            | Windows                    | Linux                                   |
//! |-----------------|----------------------------|-----------------------------------------|
//! | managed profile | `%ProgramData%\itriage`    | `/etc/itriage`                          |
//! | user profile    | `%APPDATA%\itriage`        | `$XDG_CONFIG_HOME/itriage` (~/.config)  |
//! | run history     | `%LOCALAPPDATA%\itriage`   | `$XDG_DATA_HOME/itriage` (~/.local/share) |
//! | audit log       | `%LOCALAPPDATA%\itriage`   | `$XDG_STATE_HOME/itriage` (~/.local/state) |

use std::path::PathBuf;

/// Machine-wide, admin-writable configuration (the managed profile).
pub fn managed_dir() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        Some(crate::win::dirs::program_data().join("itriage"))
    }
    #[cfg(not(windows))]
    {
        Some(PathBuf::from("/etc/itriage"))
    }
}

/// Per-user configuration (the personal profile).
pub fn config_dir() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        std::env::var_os("APPDATA").map(|p| PathBuf::from(p).join("itriage"))
    }
    #[cfg(not(windows))]
    {
        xdg("XDG_CONFIG_HOME", ".config")
    }
}

/// Per-user data (run history).
pub fn data_dir() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        std::env::var_os("LOCALAPPDATA").map(|p| PathBuf::from(p).join("itriage"))
    }
    #[cfg(not(windows))]
    {
        xdg("XDG_DATA_HOME", ".local/share")
    }
}

/// Per-user state (the audit log).
pub fn state_dir() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        data_dir()
    }
    #[cfg(not(windows))]
    {
        xdg("XDG_STATE_HOME", ".local/state")
    }
}

#[cfg(not(windows))]
fn xdg(var: &str, fallback: &str) -> Option<PathBuf> {
    let base = std::env::var_os(var)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(fallback)))?;
    Some(base.join("itriage"))
}
