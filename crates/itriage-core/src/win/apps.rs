//! Installed programs, as Settings → Apps lists them: the Uninstall keys
//! (64-bit, 32-bit and per-user).

use super::registry::{read_dword, read_string, subkeys, HKCU, HKLM};

#[derive(Clone, Debug)]
pub struct Program {
    pub name: String,
    pub version: String,
}

const UNINSTALL: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
const UNINSTALL_32: &str = r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall";

pub fn installed() -> Vec<Program> {
    let mut out: Vec<Program> = Vec::new();
    for (root, base) in [(HKLM, UNINSTALL), (HKLM, UNINSTALL_32), (HKCU, UNINSTALL)] {
        for sub in subkeys(root, base) {
            let path = format!(r"{base}\{sub}");
            let Some(name) = read_string(root, &path, "DisplayName") else { continue };
            // Components and patches that Settings hides.
            if read_dword(root, &path, "SystemComponent") == Some(1)
                || read_string(root, &path, "ParentKeyName").is_some()
            {
                continue;
            }
            let version = read_string(root, &path, "DisplayVersion").unwrap_or_default();
            if out.iter().any(|p| p.name == name && p.version == version) {
                continue;
            }
            out.push(Program { name, version });
        }
    }
    out
}
