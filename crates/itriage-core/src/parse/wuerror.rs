//! What a Windows Update or servicing error code means, and what usually
//! causes it.
//!
//! Every entry comes from Microsoft, in this order of preference:
//! * "Windows Update common errors and mitigation"
//!   (learn.microsoft.com/troubleshoot/windows-client/deployment/common-windows-update-errors),
//!   for the cause and what to do;
//! * "Troubleshoot problems updating Windows" (support.microsoft.com/help/10164),
//!   for the client codes that page covers (0x800F0922, 0x80240034, 0x80248014…);
//! * the Windows Update error reference
//!   (learn.microsoft.com/windows/deployment/update/windows-update-error-reference)
//!   and the System Error Codes, for names only.
//!
//! A code that isn't here is shown as its number, with no guess.

/// What kind of problem a code points at; it picks the next step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cause {
    /// The component store is damaged: DISM /RestoreHealth and SFC.
    Corruption,
    /// The download cache (SoftwareDistribution, catroot2) is bad.
    Cache,
    /// Windows Update can't reach its source: proxy, firewall, DNS, TLS.
    Network,
    /// Not enough free space.
    Space,
    /// A restart is needed first, or a pending operation is stuck.
    Restart,
    /// Something blocked it: antivirus, permissions, a locked file.
    Blocked,
    /// The Windows Update service (or what it relies on) isn't running.
    Service,
    /// A driver: the update can't go on with one installed or missing.
    Driver,
    /// Servicing ran out of time.
    Timeout,
    /// Anything else Microsoft names.
    Other,
}

impl Cause {
    /// The next step, in one sentence.
    pub fn next(self) -> &'static str {
        match self {
            Cause::Corruption => "Run Clean up & check system files (DISM /RestoreHealth, then SFC), restart, then install the update again.",
            Cause::Cache => "Stop the Windows Update service, rename SoftwareDistribution\\DataStore, SoftwareDistribution\\Download and System32\\catroot2 to .bak, start it again and retry.",
            Cause::Network => "Check the proxy settings and that this PC can reach its update source (Windows Update, WSUS or Configuration Manager) without signing in to the proxy.",
            Cause::Space => "Free up space on the system drive (Microsoft asks for 20 GB on 64-bit Windows), disconnect any VPN, and retry.",
            Cause::Restart => "Restart the PC so the pending update can finish, then retry.",
            Cause::Blocked => "Check the antivirus isn't blocking SoftwareDistribution or the servicing files, and that the account can install updates; the last CBS.log names what was denied.",
            Cause::Service => "Start the Windows Update service and check a policy isn't disabling it.",
            Cause::Driver => "Update or remove the driver the update trips over (often the network or display driver), then retry.",
            Cause::Timeout => "Let the install run with the PC awake and on power; on a virtual machine, give it more processor and memory.",
            Cause::Other => "Look the code up in Microsoft's Windows Update error reference; the CBS.log entry at that time has the detail.",
        }
    }
}

#[derive(Debug)]
pub struct Known {
    pub code: u32,
    pub name: &'static str,
    /// What it means, in plain words.
    pub meaning: &'static str,
    pub cause: Cause,
}

const fn k(code: u32, name: &'static str, meaning: &'static str, cause: Cause) -> Known {
    Known { code, name, meaning, cause }
}

pub const KNOWN: &[Known] = &[
    // --- The component store is damaged (common errors page; 0x80073712
    // is ERROR_SXS_COMPONENT_STORE_CORRUPT, system error 14098).
    k(0x800F_081F, "CBS_E_SOURCE_MISSING", "files the update needs are missing from the component store (corruption)", Cause::Corruption),
    k(0x800F_0831, "CBS_E_STORE_CORRUPTION", "the component store is corrupted", Cause::Corruption),
    k(0x800F_0825, "CBS_E_CANNOT_UNINSTALL", "a component is left partly installed (component store corruption)", Cause::Corruption),
    k(0x8007_0570, "ERROR_FILE_CORRUPT", "a file in the component store is corrupted", Cause::Corruption),
    k(0x8007_3701, "ERROR_SXS_ASSEMBLY_MISSING", "a component is left partly installed (component store corruption)", Cause::Corruption),
    k(0x8007_371B, "ERROR_SXS_TRANSACTION_CLOSURE_INCOMPLETE", "parts of the update are missing from the component store (corruption)", Cause::Corruption),
    k(0x8007_3712, "ERROR_SXS_COMPONENT_STORE_CORRUPT", "the component store is corrupted", Cause::Corruption),
    // The support page groups these two: corrupted files, permissions or configuration; run SFC.
    k(0x8007_0057, "E_INVALIDARG", "corrupted system files, permissions or configuration", Cause::Corruption),
    k(0x8008_0005, "CO_E_SERVER_EXEC_FAILURE", "corrupted system files, permissions or configuration", Cause::Corruption),
    // --- The download cache.
    k(0x8007_000D, "ERROR_INVALID_DATA", "the downloaded update is invalid or the update cache is corrupted", Cause::Cache),
    k(0x8024_2006, "WU_E_UH_INVALIDMETADATA", "the update's metadata is invalid", Cause::Cache),
    k(0x8024_200D, "WU_E_UH_NEEDANOTHERDOWNLOAD", "the update has to be downloaded again", Cause::Cache),
    // --- Reaching the update source.
    k(0x8007_2EFD, "TIME_OUT_ERRORS", "the connection to the update source timed out", Cause::Network),
    k(0x8007_2EFE, "WININET_E_CONNECTION_ABORTED", "the connection to the update source closed partway through the download", Cause::Network),
    k(0x80D0_2002, "TIME_OUT_ERRORS", "the download timed out", Cause::Network),
    k(0x8007_2EE2, "WININET_E_TIMEOUT", "the update source didn't answer in time", Cause::Network),
    k(0x8007_2EE7, "ERROR_INTERNET_NAME_NOT_RESOLVED", "the update server's name couldn't be resolved", Cause::Network),
    k(0x8007_2F8F, "WININET_E_DECODING_FAILED", "the reply couldn't be decoded: TLS 1.2 isn't set up correctly", Cause::Network),
    k(0x8024_402C, "WU_E_PT_WINHTTP_NAME_NOT_RESOLVED", "the proxy or update server's name couldn't be resolved", Cause::Network),
    k(0x8024_401C, "WU_E_PT_HTTP_STATUS_REQUEST_TIMEOUT", "the update server timed out (HTTP 408)", Cause::Network),
    k(0x8024_401B, "WU_E_PT_HTTP_STATUS_PROXY_AUTH_REQ", "the proxy asked for a sign-in (HTTP 407)", Cause::Network),
    k(0x8024_4022, "WU_E_PT_HTTP_STATUS_SERVICE_UNAVAIL", "the update source was unavailable (HTTP 503)", Cause::Network),
    k(0x8024_402F, "WU_E_PT_ECP_SUCCEEDED_WITH_ERRORS", "web filtering interfered with the update's files", Cause::Network),
    k(0x8020_0053, "BG_E_VALIDATION_FAILED", "a firewall filtering downloads changed what arrived", Cause::Network),
    k(0x8024_0034, "WU_E_DOWNLOAD_FAILED", "the update didn't download (an incomplete update or a connection problem)", Cause::Network),
    k(0x8024_4007, "WU_E_PT_SOAPCLIENT_SOAPFAULT", "Windows couldn't renew its Windows Update cookies (often a WSUS scan problem)", Cause::Network),
    // --- Free space (the support page's reading of 0x800F0922 on Windows client).
    k(0x8007_0070, "ERROR_DISK_FULL", "there wasn't enough space on the disk", Cause::Space),
    k(0x800F_0922, "CBS_E_INSTALLERS_FAILED", "a servicing step failed; Microsoft lists too little free space, the .NET Framework, or a VPN connection", Cause::Space),
    // --- A restart first.
    k(0x8024_2014, "WU_E_UH_POSTREBOOTSTILLPENDING", "the update is still waiting to finish after a restart", Cause::Restart),
    k(0x8007_0BC9, "ERROR_FAIL_REBOOT_REQUIRED", "an operation needs a restart to roll back; a policy setting the Windows Installer or TrustedInstaller start type can cause it", Cause::Restart),
    k(0x8024_0016, "WU_E_INSTALL_NOT_ALLOWED", "another installation was running or a restart was pending", Cause::Restart),
    // --- Blocked.
    k(0x8007_0005, "E_ACCESSDENIED", "access was denied: permissions on a servicing file or registry key changed, or the account can't install updates", Cause::Blocked),
    k(0x8007_0020, "ERROR_SHARING_VIOLATION", "a file was in use, usually locked by a non-Microsoft filter driver such as antivirus", Cause::Blocked),
    k(0x8024_0022, "WU_E_ALL_UPDATES_FAILED", "every update failed, most often because antivirus blocks the SoftwareDistribution folder", Cause::Blocked),
    k(0x8024_6017, "WU_E_DM_UNAUTHORIZED_LOCAL_USER", "the account isn't allowed to download updates (it needs to be an administrator)", Cause::Blocked),
    k(0x8024_0044, "WU_E_PER_MACHINE_UPDATE_ACCESS_DENIED", "only administrators can install updates for the whole PC", Cause::Blocked),
    // --- The service.
    k(0x8007_0422, "ERROR_SERVICE_DISABLED", "the Windows Update service is disabled", Cause::Service),
    k(0x8024_8014, "WU_E_DS_UNKNOWNSERVICE", "the Windows Update database or service isn't working", Cause::Service),
    k(0x8024_6008, "WU_E_DM_FAILTOCONNECTTOBITS", "Windows Update couldn't connect to the Background Intelligent Transfer Service (BITS)", Cause::Service),
    // --- Drivers.
    k(0xC190_0101, "", "an incompatible driver stopped the update", Cause::Driver),
    k(0x8007_0490, "ERROR_NOT_FOUND", "a driver in the update is missing details (such as its architecture) in the registry", Cause::Driver),
    // --- Out of time.
    k(0x800F_0821, "CBS_E_ABORT", "the servicing operation took longer than its time limit", Cause::Timeout),
    k(0x800F_0920, "CBS_E_HANG_DETECTED", "servicing stopped responding (it follows 0x800F0821)", Cause::Timeout),
    k(0x8007_05B4, "ERROR_TIMEOUT", "the update took too long to install or was interrupted", Cause::Timeout),
    k(0x8024_A10A, "USO_E_SERVICE_SHUTTING_DOWN", "the update service shut down after the PC sat idle", Cause::Timeout),
    // --- Other names Microsoft gives.
    k(0x8024_0020, "WU_E_NO_INTERACTIVE_USER", "it needs someone signed in to the PC to finish", Cause::Other),
    k(0x8024_000B, "WU_E_CALL_CANCELLED", "the install was cancelled by the user or the service", Cause::Other),
    k(0x8024_001E, "WU_E_SERVICE_STOP", "the service or PC was shutting down", Cause::Restart),
    k(0x8024_000E, "WU_E_XML_INVALID", "the update's data wasn't valid (some drivers carry extra metadata)", Cause::Other),
    k(0x8007_0643, "ERROR_INSTALL_FAILURE", "the installer reported a fatal error", Cause::Other),
    k(0x8007_0003, "ERROR_PATH_NOT_FOUND", "servicing couldn't reach a path it needs", Cause::Other),
    k(0x8007_0002, "ERROR_FILE_NOT_FOUND", "the update failed to install (a file it needed wasn't there)", Cause::Other),
    k(0x8024_0FFF, "WU_E_UNEXPECTED", "Windows Update failed for a reason with no specific code", Cause::Other),
];

pub fn lookup(code: u32) -> Option<&'static Known> {
    KNOWN.iter().find(|k| k.code == code)
}

/// `0x800F081F`.
pub fn hex(code: u32) -> String {
    format!("0x{code:08X}")
}

/// "0x800F081F (CBS_E_SOURCE_MISSING): files the update needs are missing…",
/// or just the number when it isn't a code Microsoft documents here.
pub fn describe(code: u32) -> String {
    match lookup(code) {
        Some(k) if k.name.is_empty() => format!("{}: {}", hex(code), k.meaning),
        Some(k) => format!("{} ({}): {}", hex(code), k.name, k.meaning),
        None => hex(code),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_code_is_listed_once() {
        let mut seen = std::collections::HashSet::new();
        for k in KNOWN {
            assert!(seen.insert(k.code), "{} is listed twice", hex(k.code));
        }
    }

    #[test]
    fn system_error_codes_map_to_their_hresults() {
        // HRESULT_FROM_WIN32: 0x8007 in front of the Win32 code.
        let win32 = |code: u32| 0x8007_0000 | code;
        assert_eq!(lookup(win32(112)).unwrap().name, "ERROR_DISK_FULL");
        assert_eq!(lookup(win32(14098)).unwrap().name, "ERROR_SXS_COMPONENT_STORE_CORRUPT");
        assert_eq!(lookup(win32(1603)).unwrap().name, "ERROR_INSTALL_FAILURE");
        assert_eq!(lookup(win32(1058)).unwrap().name, "ERROR_SERVICE_DISABLED");
        assert_eq!(lookup(win32(12007)).unwrap().name, "ERROR_INTERNET_NAME_NOT_RESOLVED");
    }

    #[test]
    fn describes_known_and_unknown_codes() {
        assert_eq!(describe(0x800F_081F), "0x800F081F (CBS_E_SOURCE_MISSING): files the update needs are missing from the component store (corruption)");
        assert_eq!(describe(0xC190_0101), "0xC1900101: an incompatible driver stopped the update");
        assert_eq!(describe(0x8000_4005), "0x80004005");
        assert_eq!(lookup(0x800F_0922).unwrap().cause, Cause::Space);
        assert!(Cause::Corruption.next().contains("Clean up & check system files"));
    }
}
