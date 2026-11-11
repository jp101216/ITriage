//! Wi-Fi state through the native WLAN API (wlanapi), so it doesn't depend on
//! parsing localised `netsh wlan` output.

use windows::Win32::Foundation::HANDLE;
use windows::Win32::NetworkManagement::WiFi::{
    wlan_interface_state_connected, wlan_intf_opcode_channel_number, wlan_intf_opcode_current_connection,
    WlanCloseHandle, WlanEnumInterfaces, WlanFreeMemory, WlanOpenHandle, WlanQueryInterface,
    WLAN_CONNECTION_ATTRIBUTES, WLAN_INTERFACE_INFO_LIST,
};

#[derive(Clone, Debug)]
pub struct Wifi {
    pub adapter: String,
    pub connected: bool,
    pub ssid: Option<String>,
    /// The access point's address (`aa:bb:cc:dd:ee:ff`): it changes when
    /// the PC roams to another one on the same network.
    pub bssid: Option<String>,
    /// 0–100, as Windows reports it.
    pub signal: Option<u32>,
    /// DOT11_AUTH_ALGORITHM value.
    pub auth: Option<i32>,
    pub one_x: bool,
    /// Receive and transmit rates in kbps.
    pub rx_kbps: Option<u32>,
    pub tx_kbps: Option<u32>,
    /// DOT11_PHY_TYPE (7 = 802.11n, 8 = ac, 10 = ax, 11 = be).
    pub phy: Option<i32>,
    pub channel: Option<u32>,
}

/// Every wireless interface. `Err` when the WLAN service isn't available
/// (wired-only PCs, servers).
pub fn interfaces() -> Result<Vec<Wifi>, String> {
    // SAFETY: every buffer the API returns is freed with WlanFreeMemory and
    // the client handle is closed on all paths.
    unsafe {
        let mut negotiated = 0u32;
        let mut handle = HANDLE::default();
        let rc = WlanOpenHandle(2, None, &mut negotiated, &mut handle);
        if rc != 0 {
            return Err(format!("the WLAN service isn't available (error {rc})"));
        }
        let mut list: *mut WLAN_INTERFACE_INFO_LIST = std::ptr::null_mut();
        let rc = WlanEnumInterfaces(handle, None, &mut list);
        if rc != 0 || list.is_null() {
            let _ = WlanCloseHandle(handle, None);
            return Err(format!("can't list Wi-Fi adapters (error {rc})"));
        }
        let count = (*list).dwNumberOfItems as usize;
        let infos = std::slice::from_raw_parts((*list).InterfaceInfo.as_ptr(), count);
        let mut out = Vec::new();
        for info in infos {
            let adapter = wide(&info.strInterfaceDescription);
            let connected = info.isState == wlan_interface_state_connected;
            let mut wifi = Wifi {
                adapter,
                connected,
                ssid: None,
                bssid: None,
                signal: None,
                auth: None,
                one_x: false,
                rx_kbps: None,
                tx_kbps: None,
                phy: None,
                channel: None,
            };
            if connected {
                let mut size = 0u32;
                let mut data: *mut core::ffi::c_void = std::ptr::null_mut();
                let rc = WlanQueryInterface(
                    handle,
                    &info.InterfaceGuid,
                    wlan_intf_opcode_current_connection,
                    None,
                    &mut size,
                    &mut data,
                    None,
                );
                if rc == 0 && !data.is_null() {
                    let attrs = &*(data as *const WLAN_CONNECTION_ATTRIBUTES);
                    let assoc = &attrs.wlanAssociationAttributes;
                    let len = (assoc.dot11Ssid.uSSIDLength as usize).min(32);
                    let ssid = String::from_utf8_lossy(&assoc.dot11Ssid.ucSSID[..len]).into_owned();
                    // Windows 11 24H2+ withholds the SSID from apps without
                    // location permission; the signal still comes through.
                    wifi.ssid = (!ssid.is_empty()).then_some(ssid);
                    let ap = assoc.dot11Bssid;
                    wifi.bssid = ap.iter().any(|b| *b != 0).then(|| ap.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":"));
                    wifi.signal = Some(assoc.wlanSignalQuality);
                    wifi.rx_kbps = Some(assoc.ulRxRate);
                    wifi.tx_kbps = Some(assoc.ulTxRate);
                    wifi.phy = Some(assoc.dot11PhyType.0);
                    wifi.auth = Some(attrs.wlanSecurityAttributes.dot11AuthAlgorithm.0);
                    wifi.one_x = attrs.wlanSecurityAttributes.bOneXEnabled.as_bool();
                    WlanFreeMemory(data);
                }
                let mut size = 0u32;
                let mut data: *mut core::ffi::c_void = std::ptr::null_mut();
                let rc = WlanQueryInterface(
                    handle,
                    &info.InterfaceGuid,
                    wlan_intf_opcode_channel_number,
                    None,
                    &mut size,
                    &mut data,
                    None,
                );
                if rc == 0 && !data.is_null() {
                    wifi.channel = Some(*(data as *const u32));
                    WlanFreeMemory(data);
                }
            }
            out.push(wifi);
        }
        WlanFreeMemory(list as *const core::ffi::c_void);
        let _ = WlanCloseHandle(handle, None);
        Ok(out)
    }
}

fn wide(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}
