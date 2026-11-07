//! Present devices and their Device Manager problem codes (SetupAPI + CfgMgr32).

use windows::core::PCWSTR;
use windows::Win32::Devices::DeviceAndDriverInstallation::{
    CM_Get_DevNode_Status, SetupDiDestroyDeviceInfoList, SetupDiEnumDeviceInfo, SetupDiGetClassDevsW,
    SetupDiGetDeviceRegistryPropertyW, CM_DEVNODE_STATUS_FLAGS, CM_PROB, CR_SUCCESS, DIGCF_ALLCLASSES,
    DIGCF_PRESENT, DN_HAS_PROBLEM, HDEVINFO, SETUP_DI_REGISTRY_PROPERTY, SPDRP_CLASS, SPDRP_DEVICEDESC,
    SPDRP_FRIENDLYNAME, SP_DEVINFO_DATA,
};

#[derive(Clone, Debug)]
pub struct Device {
    pub name: String,
    pub class: String,
    /// Device Manager problem code (the "Code 43" number), if it has one.
    pub problem: Option<u32>,
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
            let name = property(set, &data, SPDRP_FRIENDLYNAME)
                .or_else(|| property(set, &data, SPDRP_DEVICEDESC))
                .unwrap_or_default();
            let class = property(set, &data, SPDRP_CLASS).unwrap_or_default();
            let mut status = CM_DEVNODE_STATUS_FLAGS::default();
            let mut problem = CM_PROB::default();
            let has_problem = CM_Get_DevNode_Status(&mut status, &mut problem, data.DevInst, 0) == CR_SUCCESS
                && (status.0 & DN_HAS_PROBLEM.0) != 0;
            out.push(Device {
                name,
                class,
                problem: has_problem.then_some(problem.0),
            });
        }
        let _ = SetupDiDestroyDeviceInfoList(set);
        Ok(out)
    }
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
