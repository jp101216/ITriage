//! COM apartment lifetime.

use windows::Win32::System::Com::{CoInitializeEx, CoUninitialize, COINIT_MULTITHREADED};

/// Joins the multithreaded apartment for as long as the guard lives. Modules
/// run on worker threads that the Tauri runtime reuses, so each COM user
/// brackets its own work rather than assuming the thread's state.
pub struct ComGuard {
    owns: bool,
}

impl ComGuard {
    pub fn init() -> Self {
        // SAFETY: standard COM initialisation; balanced in Drop when it
        // succeeded. S_FALSE (already initialised) also needs the balance call.
        let hr = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
        ComGuard { owns: hr.is_ok() }
    }
}

impl Drop for ComGuard {
    fn drop(&mut self) {
        if self.owns {
            // SAFETY: balances the successful CoInitializeEx above, same thread.
            unsafe { CoUninitialize() };
        }
    }
}
