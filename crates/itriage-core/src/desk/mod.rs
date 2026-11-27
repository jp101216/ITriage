//! Service-desk workstation checks: the things a Tier 1/2 technician looks at
//! first on a shared or clinical PC. All read-only; problems they find carry
//! one-click fixes from `crate::actions` where a safe one exists.

pub mod account;
pub mod battery;
pub mod browser;
pub mod certs;
pub mod devices;
pub mod domain;
pub mod intune;
pub mod logon;
pub mod m365;
pub mod printers;
pub mod profile;
pub mod time;
pub mod wifi;
