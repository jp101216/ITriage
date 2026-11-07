//! Native Windows API wrappers built on the `windows` crate. Compiled only on
//! Windows (see the `#[cfg(windows)]` on `mod win` in lib.rs).
//!
//! Everything here is a thin, safe wrapper: call the API, close the handles,
//! return plain Rust data. Interpretation (what counts as a problem, how to
//! word it) lives in the triage/update modules, and text parsing in `parse`.

pub mod com;
pub mod eventlog;
pub mod registry;
pub mod scm;
pub mod shell;
pub mod token;
pub mod wua;

/// "context: message (0x80070005)" for a windows-rs error.
pub(crate) fn err(context: &str, e: &windows::core::Error) -> String {
    let message = e.message();
    let message = message.trim();
    let hr = e.code().0 as u32;
    if message.is_empty() {
        format!("{context}: 0x{hr:08X}")
    } else {
        format!("{context}: {message} (0x{hr:08X})")
    }
}
