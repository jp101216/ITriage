//! Network adapters through IP Helper (for spotting VPN tunnels).

use windows::Win32::NetworkManagement::IpHelper::{
    GetAdaptersAddresses, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST,
    IP_ADAPTER_ADDRESSES_LH,
};
use windows::Win32::NetworkManagement::Ndis::IfOperStatusUp;

#[derive(Clone, Debug)]
pub struct Adapter {
    pub name: String,
    pub description: String,
    pub up: bool,
}

pub fn adapters() -> Result<Vec<Adapter>, String> {
    const AF_UNSPEC: u32 = 0;
    const ERROR_BUFFER_OVERFLOW: u32 = 111;
    let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    let mut size = 16 * 1024u32;
    // SAFETY: the u64-backed buffer is sized from the API's report and stays
    // alive while the linked list inside it is walked.
    unsafe {
        let mut backing: Vec<u64>;
        loop {
            backing = vec![0u64; size as usize / 8 + 1];
            let head = backing.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH;
            let rc = GetAdaptersAddresses(AF_UNSPEC, flags, None, Some(head), &mut size);
            if rc == 0 {
                break;
            }
            if rc != ERROR_BUFFER_OVERFLOW {
                return Err(format!("can't list network adapters (error {rc})"));
            }
        }
        let mut out = Vec::new();
        let mut node = backing.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
        while !node.is_null() {
            let a = &*node;
            out.push(Adapter {
                name: a.FriendlyName.to_string().unwrap_or_default(),
                description: a.Description.to_string().unwrap_or_default(),
                up: a.OperStatus == IfOperStatusUp,
            });
            node = a.Next;
        }
        Ok(out)
    }
}
