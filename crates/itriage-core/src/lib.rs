//! itriage-core — the IT triage + update engine.
//!
//! GUI-agnostic on purpose: this crate knows how to inspect and patch a box
//! and hand back serializable results. The Tauri app and the command line
//! ([`cli`]) are both shells that call [`registry`] / [`run_selected`] and
//! render [`ModuleResult`]s.
//!
//! Layout:
//! * `triage`, `net`, `desk`, `site`, `fixes`, `update`: the modules, mostly
//!   one file each. `net` holds the network checks beyond basic connectivity
//!   (latency, proxy, destination test) and the shared network layer, `desk`
//!   the service-desk workstation checks, `site` the checks a site profile
//!   drives, `fixes` the repairs and maintenance (Invoke-EndpointTuneUp).
//! * `module`: the module trait, run context (preview, remote-safe, target,
//!   cancel), the registry, presets and the exit code.
//! * `actions`: the one-click fixes findings can offer, policy-checked and audited.
//! * `profile`, `audit`, `report`: site policy and settings, the audit trail,
//!   and saved runs with their before/after comparison.
//! * `cli`: the command line, for remote shells, scheduled tasks and RMM tools.
//! * `win`: thin native Windows wrappers (SCM, Event Log, Windows Update
//!   Agent, IP Helper, WinHTTP, PDH, SMBIOS, spooler, SetupAPI, WLAN,
//!   certificates…) and the fixed PowerShell scripts a few repairs need.
//!   Windows only.
//! * `parse`: pure, OS-independent parsers for tool output, unit-tested on any host.
//! * `util`, `host`: process execution (captured, streamed, privileged),
//!   PATH lookup, formatting, machine identity and elevation.
//! * `trust`: which files an elevated run may start or obey (only ones a
//!   standard user couldn't have put there).
//! * `telemetry`: the stateful sampler behind the live HUD charts.

pub mod actions;
pub mod audit;
pub mod bitlocker;
pub mod cli;
pub mod desk;
pub mod host;
pub mod insight;
pub mod model;
pub mod module;
pub mod net;
pub mod parse;
pub mod paths;
pub mod profile;
pub mod report;
pub mod security;
pub mod site;
pub mod telemetry;
pub mod trust;
pub mod util;

#[cfg(windows)]
pub(crate) mod win;

pub mod triage {
    pub mod disk;
    pub mod eventlog;
    pub mod memory;
    pub mod network;
    pub mod processes;
    pub mod reliability;
    pub mod services;
    pub mod system;
}

pub mod fixes;

pub mod update;

// Re-exports so shells can `use itriage_core::{registry, ModuleResult, …}`.
pub use host::{host_context, relaunch_elevated, HostContext};
pub use model::{Category, Finding, FixRef, KbLink, Metric, ModuleInfo, ModuleResult, Severity, Target};
pub use module::{catalogue, exit_code, preset, registry, run_selected, Preset, RunContext, TriageModule, PRESETS};
pub use profile::{Profile, ProfileStatus};
pub use insight::Insight;
pub use report::{Report, ReportDiff, ReportMeta};
pub use telemetry::{Sampler, Telemetry};
