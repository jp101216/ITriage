//! Pure text parsers for the output of the tools itriage drives.
//!
//! Deliberately OS-independent: the Windows formats (winget tables, rendered
//! event XML) and the Linux ones (apt/dnf/pacman/zypper, journald JSON,
//! systemctl) are all plain-string functions, so every one of them is
//! unit-tested on any host. The OS-specific code stays thin: call the tool or
//! API, hand the text to a parser here.

pub mod battery;
pub mod devices;
pub mod diskstats;
pub mod dns;
pub mod evtxml;
pub mod journal;
pub mod net;
pub mod ping;
pub mod pkg;
pub mod printer;
pub mod route;
pub mod smbios;
pub mod sntp;
pub mod systemd;
pub mod text;
pub mod time;
pub mod version;
pub mod winget;
