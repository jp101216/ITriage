//! Present devices and their Device Manager problem codes (SetupAPI + CfgMgr32).

use windows::core::PCWSTR;
use windows::Win32::Devices::DeviceAndDriverInstallation::{
    CM_Get_DevNode_Status, CM_Get_Device_IDW, CM_Get_Parent, SetupDiDestroyDeviceInfoList, SetupDiEnumDeviceInfo,
    SetupDiGetClassDevsW, SetupDiGetDeviceInstanceIdW, SetupDiGetDeviceRegistryPropertyW, CM_DEVNODE_STATUS_FLAGS, CM_PROB, CR_SUCCESS, DIGCF_ALLCLASSES,
    DIGCF_PRESENT, DN_HAS_PROBLEM, HDEVINFO, SETUP_DI_REGISTRY_PROPERTY, SPDRP_CLASS, SPDRP_DEVICEDESC,
    SPDRP_FRIENDLYNAME, SPDRP_HARDWAREID, SP_DEVINFO_DATA,
};

#[derive(Clone, Debug)]
pub struct Device {
    pub name: String,
    pub class: String,
    /// Device Manager problem code (the "Code 43" number), if it has one.
    pub problem: Option<u32>,
    /// `USB\VID_0C2E&PID_0B61\…`, upper case.
    pub instance_id: String,
    /// The USB device this one is, or hangs off (a HID scanner's USB
    /// parent), for its power settings. `None` when it isn't on USB.
    pub usb: Option<String>,
}

/// Every device currently present.
pub fn present() -> Result<Vec<Device>, String> {
    // SAFETY: the device-info set is destroyed on every path; property
    // buffers are sized by the API's own size reports.
    unsafe {
        let set = SetupDiGetClassDevsW(None, PCWSTR::null(), None, DIGCF_PRESENT | DIGCF_ALLCLASSES)
            .map_err(|e| super::err("can't list devices", &e))?;
        let mut out = Vec::new();
        let mut index = 0u32;
        loop {
            let mut data = SP_DEVINFO_DATA {
                cbSize: std::mem::size_of::<SP_DEVINFO_DATA>() as u32,
                ..Default::default()
            };
            if SetupDiEnumDeviceInfo(set, index, &mut data).is_err() {
                break; // ERROR_NO_MORE_ITEMS
            }
            index += 1;
            // Driverless devices often have neither name; Device Manager calls
            // them "Unknown device", and the hardware ID is what identifies them.
            let name = property(set, &data, SPDRP_FRIENDLYNAME)
                .or_else(|| property(set, &data, SPDRP_DEVICEDESC))
                .or_else(|| property(set, &data, SPDRP_HARDWAREID).map(|id| format!("Unknown device ({id})")))
                .unwrap_or_else(|| "Unknown device".to_string());
            let class = property(set, &data, SPDRP_CLASS).unwrap_or_default();
            let mut status = CM_DEVNODE_STATUS_FLAGS::default();
            let mut problem = CM_PROB::default();
            let has_problem = CM_Get_DevNode_Status(&mut status, &mut problem, data.DevInst, 0) == CR_SUCCESS
                && (status.0 & DN_HAS_PROBLEM.0) != 0;
            let instance_id = instance(set, &data).unwrap_or_default();
            out.push(Device {
                name,
                class,
                problem: has_problem.then_some(problem.0),
                usb: usb_ancestor(data.DevInst, &instance_id),
                instance_id,
            });
        }
        let _ = SetupDiDestroyDeviceInfoList(set);
        Ok(out)
    }
}

unsafe fn instance(set: HDEVINFO, data: &SP_DEVINFO_DATA) -> Option<String> {
    let mut buf = [0u16; 512];
    SetupDiGetDeviceInstanceIdW(set, data, Some(&mut buf), None).ok()?;
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    Some(String::from_utf16_lossy(&buf[..end]).to_ascii_uppercase())
}

/// The nearest device at or above this one whose instance starts `USB\`,
/// four levels up at most (USB device → composite interface → HID → …).
unsafe fn usb_ancestor(devinst: u32, own_id: &str) -> Option<String> {
    if own_id.starts_with("USB\\") {
        return Some(own_id.to_string());
    }
    let mut node = devinst;
    for _ in 0..4 {
        let mut parent = 0u32;
        if CM_Get_Parent(&mut parent, node, 0) != CR_SUCCESS {
            return None;
        }
        let mut buf = [0u16; 512];
        if CM_Get_Device_IDW(parent, &mut buf, 0) != CR_SUCCESS {
            return None;
        }
        let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        let id = String::from_utf16_lossy(&buf[..end]).to_ascii_uppercase();
        if id.starts_with("USB\\") {
            return Some(id);
        }
        node = parent;
    }
    None
}

unsafe fn property(set: HDEVINFO, data: &SP_DEVINFO_DATA, prop: SETUP_DI_REGISTRY_PROPERTY) -> Option<String> {
    let mut buf = vec![0u8; 512];
    let mut needed = 0u32;
    SetupDiGetDeviceRegistryPropertyW(set, data, prop, None, Some(&mut buf), Some(&mut needed)).ok()?;
    let wide = std::slice::from_raw_parts(buf.as_ptr() as *const u16, buf.len() / 2);
    let end = wide.iter().position(|&c| c == 0).unwrap_or(wide.len());
    let s = String::from_utf16_lossy(&wide[..end]).trim().to_string();
    (!s.is_empty()).then_some(s)
}
