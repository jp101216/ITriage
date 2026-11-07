//! itriage-core — the IT triage + update engine.
//!
//! GUI-agnostic on purpose: this crate knows how to inspect and patch a box
//! and hand back serializable results. The Tauri app and the CLI example are
//! both shells that call [`registry`] / [`run_selected`] and render
//! [`ModuleResult`]s.
//!
//! Layout:
//! * `triage`, `fixes`, `update`: the modules, one file each.
//! * `win`: thin native Windows wrappers (SCM, Event Log, Windows Update
//!   Agent, token, registry, ShellExecute). Windows only.
//! * `parse`: pure, OS-independent parsers for tool output, unit-tested on any host.
//! * `util`, `host`: process execution (captured, streamed, privileged),
//!   PATH lookup, formatting, and elevation.
//! * `telemetry`: the stateful sampler behind the live HUD charts.

pub mod host;
pub mod model;
pub mod module;
pub mod parse;
pub mod telemetry;
pub mod util;

#[cfg(windows)]
pub(crate) mod win;

pub mod triage {
    pub mod disk;
    pub mod eventlog;
    pub mod memory;
    pub mod network;
    pub mod processes;
    pub mod services;
    pub mod system;
}

pub mod fixes {
    pub mod dns;
    pub mod temp;
}

pub mod update;

// Re-exports so shells can `use itriage_core::{registry, ModuleResult, …}`.
pub use host::{host_context, relaunch_elevated, HostContext};
pub use model::{Category, Finding, ModuleInfo, ModuleResult, Severity};
pub use module::{registry, run_selected, RunContext, TriageModule};
pub use telemetry::{Sampler, Telemetry};
