//! Service Control Manager: enumerate Win32 services with their state, exit
//! code, start mode and whether they're trigger-started.

use windows::core::{HSTRING, PCWSTR};
use windows::Win32::Foundation::ERROR_MORE_DATA;
use windows::Win32::System::Services::{
    CloseServiceHandle, EnumServicesStatusExW, OpenSCManagerW, OpenServiceW, QueryServiceConfig2W,
    QueryServiceConfigW, ENUM_SERVICE_STATUS_PROCESSW, QUERY_SERVICE_CONFIGW, SC_ENUM_PROCESS_INFO,
    SC_HANDLE, SC_MANAGER_CONNECT, SC_MANAGER_ENUMERATE_SERVICE, SERVICE_AUTO_START,
    SERVICE_CONFIG_DELAYED_AUTO_START_INFO, SERVICE_CONFIG_TRIGGER_INFO, SERVICE_DELAYED_AUTO_START_INFO,
    SERVICE_DEMAND_START, SERVICE_DISABLED, SERVICE_QUERY_CONFIG, SERVICE_RUNNING, SERVICE_STATE_ALL,
    SERVICE_STATUS_PROCESS, SERVICE_TRIGGER_INFO, SERVICE_WIN32,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StartMode {
    Auto,
    AutoDelayed,
    Manual,
    Disabled,
    Unknown,
}

#[derive(Clone, Debug)]
pub struct Service {
    pub name: String,
    pub display_name: String,
    pub running: bool,
    pub start: StartMode,
    /// Started on demand by an event (device arrival, network change, …) and
    /// expected to stop again. Never a problem just for being stopped.
    pub trigger_start: bool,
    /// Win32 exit code from the last stop: 0 = clean, 1077 = never started.
    pub exit_code: u32,
    pub service_type: u32,
}

impl Service {
    /// Per-user service *templates* (e.g. `CDPUserSvc`) are Automatic but never
    /// run themselves; Windows runs per-session copies (`CDPUserSvc_1a2b3`).
    pub fn is_user_template(&self) -> bool {
        const USER_SERVICE: u32 = 0x40;
        const USER_SERVICE_INSTANCE: u32 = 0x80;
        self.service_type & USER_SERVICE != 0 && self.service_type & USER_SERVICE_INSTANCE == 0
    }
}

struct ScHandle(SC_HANDLE);

impl Drop for ScHandle {
    fn drop(&mut self) {
        // SAFETY: we own this handle and close it exactly once.
        unsafe {
            let _ = CloseServiceHandle(self.0);
        }
    }
}

/// Every Win32 service. Start mode and triggers are looked up only for
/// services that aren't running, since those are the only ones judged.
pub fn services() -> Result<Vec<Service>, String> {
    // SAFETY: SCM handles are wrapped so they're closed on every path.
    unsafe {
        let scm = OpenSCManagerW(
            PCWSTR::null(),
            PCWSTR::null(),
            SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE,
        )
        .map_err(|e| super::err("can't open the Service Control Manager", &e))?;
        let scm = ScHandle(scm);

        let mut out = Vec::new();
        for (name, display_name, status) in enumerate(scm.0)? {
            let running = status.dwCurrentState == SERVICE_RUNNING;
            let (start, trigger_start) = if running {
                (StartMode::Unknown, false)
            } else {
                start_mode(scm.0, &name)
            };
            out.push(Service {
                name,
                display_name,
                running,
                start,
                trigger_start,
                exit_code: status.dwWin32ExitCode,
                service_type: status.dwServiceType.0,
            });
        }
        Ok(out)
    }
}

unsafe fn enumerate(scm: SC_HANDLE) -> Result<Vec<(String, String, SERVICE_STATUS_PROCESS)>, String> {
    let mut out = Vec::new();
    let mut resume = 0u32;
    let mut needed = 0u32;
    let mut returned = 0u32;

    // Sizing call; expected to fail with ERROR_MORE_DATA.
    let _ = EnumServicesStatusExW(
        scm,
        SC_ENUM_PROCESS_INFO,
        SERVICE_WIN32,
        SERVICE_STATE_ALL,
        None,
        &mut needed,
        &mut returned,
        Some(&mut resume),
        PCWSTR::null(),
    );

    loop {
        // u64 backing keeps the buffer 8-byte aligned for the pointer-bearing
        // ENUM_SERVICE_STATUS_PROCESSW records the API writes into it.
        let mut backing = vec![0u64; needed as usize / 8 + 1];
        let bytes = std::slice::from_raw_parts_mut(backing.as_mut_ptr() as *mut u8, backing.len() * 8);
        let result = EnumServicesStatusExW(
            scm,
            SC_ENUM_PROCESS_INFO,
            SERVICE_WIN32,
            SERVICE_STATE_ALL,
            Some(bytes),
            &mut needed,
            &mut returned,
            Some(&mut resume),
            PCWSTR::null(),
        );
        let entries = std::slice::from_raw_parts(
            backing.as_ptr() as *const ENUM_SERVICE_STATUS_PROCESSW,
            returned as usize,
        );
        for e in entries {
            // The name pointers point into `backing`; copy them out now.
            out.push((
                e.lpServiceName.to_string().unwrap_or_default(),
                e.lpDisplayName.to_string().unwrap_or_default(),
                e.ServiceStatusProcess,
            ));
        }
        match result {
            Ok(()) => return Ok(out),
            Err(e) if e.code() == ERROR_MORE_DATA.to_hresult() => continue, // resume handle advanced
            Err(e) => return Err(super::err("can't list services", &e)),
        }
    }
}

unsafe fn start_mode(scm: SC_HANDLE, name: &str) -> (StartMode, bool) {
    let wide = HSTRING::from(name);
    let Ok(handle) = OpenServiceW(scm, &wide, SERVICE_QUERY_CONFIG) else {
        return (StartMode::Unknown, false); // protected service; skip it
    };
    let handle = ScHandle(handle);

    let mut needed = 0u32;
    let _ = QueryServiceConfigW(handle.0, None, 0, &mut needed);
    if needed == 0 {
        return (StartMode::Unknown, false);
    }
    let mut backing = vec![0u64; needed as usize / 8 + 1];
    let config = backing.as_mut_ptr() as *mut QUERY_SERVICE_CONFIGW;
    if QueryServiceConfigW(handle.0, Some(config), (backing.len() * 8) as u32, &mut needed).is_err() {
        return (StartMode::Unknown, false);
    }
    let start_type = (*config).dwStartType;

    let mode = if start_type == SERVICE_AUTO_START {
        if delayed(handle.0) {
            StartMode::AutoDelayed
        } else {
            StartMode::Auto
        }
    } else if start_type == SERVICE_DEMAND_START {
        StartMode::Manual
    } else if start_type == SERVICE_DISABLED {
        StartMode::Disabled
    } else {
        StartMode::Unknown
    };
    let trigger = mode != StartMode::Disabled && has_triggers(handle.0);
    (mode, trigger)
}

unsafe fn delayed(service: SC_HANDLE) -> bool {
    let mut info = SERVICE_DELAYED_AUTO_START_INFO::default();
    let mut needed = 0u32;
    let bytes = std::slice::from_raw_parts_mut(
        &mut info as *mut SERVICE_DELAYED_AUTO_START_INFO as *mut u8,
        std::mem::size_of::<SERVICE_DELAYED_AUTO_START_INFO>(),
    );
    QueryServiceConfig2W(service, SERVICE_CONFIG_DELAYED_AUTO_START_INFO, Some(bytes), &mut needed).is_ok()
        && info.fDelayedAutostart.as_bool()
}

unsafe fn has_triggers(service: SC_HANDLE) -> bool {
    let mut needed = 0u32;
    let _ = QueryServiceConfig2W(service, SERVICE_CONFIG_TRIGGER_INFO, None, &mut needed);
    if needed == 0 {
        return false;
    }
    let mut backing = vec![0u64; needed as usize / 8 + 1];
    let bytes = std::slice::from_raw_parts_mut(backing.as_mut_ptr() as *mut u8, backing.len() * 8);
    if QueryServiceConfig2W(service, SERVICE_CONFIG_TRIGGER_INFO, Some(bytes), &mut needed).is_err() {
        return false;
    }
    let info = &*(backing.as_ptr() as *const SERVICE_TRIGGER_INFO);
    info.cTriggers > 0
}
