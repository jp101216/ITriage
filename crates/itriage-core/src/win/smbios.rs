//! The raw SMBIOS table, for make, model, serial number, BIOS and board.

use crate::parse::smbios::{self, Identity};
use windows::Win32::System::SystemInformation::{GetSystemFirmwareTable, RSMB};

pub fn identity() -> Option<Identity> {
    // SAFETY: the first call reports the size; the second fills a buffer of
    // exactly that size.
    unsafe {
        let size = GetSystemFirmwareTable(RSMB, 0, None);
        if size == 0 {
            return None;
        }
        let mut buf = vec![0u8; size as usize];
        let written = GetSystemFirmwareTable(RSMB, 0, Some(&mut buf));
        if written == 0 || written > size {
            return None;
        }
        smbios::parse_raw(&buf[..written as usize])
    }
}
