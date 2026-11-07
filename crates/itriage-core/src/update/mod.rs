//! Update modules: one read-only scan, plus two installers split by risk.
//!
//! * `update.scan`     lists what's pending and installs nothing.
//! * `update.apply`    installs OS & app updates (Windows Update + winget, or
//!   the Linux package manager).
//! * `update.firmware` installs drivers, BIOS and firmware (OEM tool or Windows
//!   Update drivers, or fwupd on Linux).
//!
//! The installers are kept separate so you can patch an OS without also
//! flashing a BIOS.

pub mod apply;
pub mod firmware;
pub mod scan;

pub(crate) mod oem;
#[cfg(windows)]
pub(crate) mod winget;

#[cfg(not(windows))]
pub(crate) mod pkgmgr;

/// How many individual packages/updates a card lists before summarising.
pub(crate) const LIST_MAX: usize = 25;
