//! Printers through the spooler API (winspool).

use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Graphics::Printing::{
    EnumPrinterDriversW, EnumPrintersW, GetDefaultPrinterW, DRIVER_INFO_8W, PRINTER_DRIVER_PACKAGE_AWARE,
    PRINTER_ENUM_CONNECTIONS, PRINTER_ENUM_LOCAL, PRINTER_INFO_2W,
};

#[derive(Clone, Debug)]
pub struct Printer {
    pub name: String,
    pub port: String,
    pub driver: String,
    /// PRINTER_STATUS_* flags (see `parse::printer`).
    pub status: u32,
    /// PRINTER_ATTRIBUTE_* flags.
    pub attributes: u32,
    pub jobs: u32,
    /// The print server for a shared printer (`\\PRINT01`), empty for a local one.
    pub server: String,
}

/// Local and connected printers. Fails (RPC server unavailable) when the
/// Print Spooler isn't running.
pub fn printers() -> Result<Vec<Printer>, windows::core::Error> {
    let flags = PRINTER_ENUM_LOCAL | PRINTER_ENUM_CONNECTIONS;
    let mut needed = 0u32;
    let mut returned = 0u32;
    // SAFETY: two-call pattern; the buffer is u64-backed for the
    // pointer-bearing PRINTER_INFO_2W records and outlives the reads.
    unsafe {
        if let Err(e) = EnumPrintersW(flags, PCWSTR::null(), 2, None, &mut needed, &mut returned) {
            if needed == 0 {
                return Err(e);
            }
        }
        let mut backing = vec![0u64; needed as usize / 8 + 1];
        let bytes = std::slice::from_raw_parts_mut(backing.as_mut_ptr() as *mut u8, backing.len() * 8);
        EnumPrintersW(flags, PCWSTR::null(), 2, Some(bytes), &mut needed, &mut returned)?;
        let infos = std::slice::from_raw_parts(backing.as_ptr() as *const PRINTER_INFO_2W, returned as usize);
        Ok(infos
            .iter()
            .map(|p| Printer {
                name: text(p.pPrinterName),
                port: text(p.pPortName),
                driver: text(p.pDriverName),
                status: p.Status,
                attributes: p.Attributes,
                jobs: p.cJobs,
                server: text(p.pServerName),
            })
            .collect())
    }
}

/// Installed printer drivers by name, and whether each is package-aware
/// (installs from a signed driver package, which Package Point and Print
/// requires).
pub fn drivers() -> Vec<(String, bool)> {
    let mut needed = 0u32;
    let mut returned = 0u32;
    // SAFETY: two-call pattern with a u64-backed buffer for the
    // pointer-bearing DRIVER_INFO_8W records, as in printers().
    unsafe {
        let _ = EnumPrinterDriversW(PCWSTR::null(), PCWSTR::null(), 8, None, &mut needed, &mut returned);
        if needed == 0 {
            return Vec::new();
        }
        let mut backing = vec![0u64; needed as usize / 8 + 1];
        let bytes = std::slice::from_raw_parts_mut(backing.as_mut_ptr() as *mut u8, backing.len() * 8);
        if EnumPrinterDriversW(PCWSTR::null(), PCWSTR::null(), 8, Some(bytes), &mut needed, &mut returned).is_err() {
            return Vec::new();
        }
        let infos = std::slice::from_raw_parts(backing.as_ptr() as *const DRIVER_INFO_8W, returned as usize);
        infos.iter().map(|d| (text(d.pName), d.dwPrinterDriverAttributes & PRINTER_DRIVER_PACKAGE_AWARE != 0)).collect()
    }
}

/// The current user's default printer.
pub fn default_printer() -> Option<String> {
    let mut buf = [0u16; 512];
    let mut len = buf.len() as u32;
    // SAFETY: `buf` holds `len` characters and outlives the call.
    let ok = unsafe { GetDefaultPrinterW(Some(PWSTR(buf.as_mut_ptr())), &mut len) }.as_bool();
    if !ok {
        return None;
    }
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    Some(String::from_utf16_lossy(&buf[..end])).filter(|s| !s.is_empty())
}

unsafe fn text(p: PWSTR) -> String {
    if p.is_null() {
        String::new()
    } else {
        p.to_string().unwrap_or_default()
    }
}
