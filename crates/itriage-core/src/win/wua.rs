//! Windows Update Agent (WUA) over COM. It's the same API that Settings →
//! Windows Update and PSWindowsUpdate use. Searching is read-only; installing
//! needs an elevated process.

use super::com::ComGuard;
use crate::module::RunContext;
use windows::core::{Interface, BSTR};
use windows::Win32::Foundation::VARIANT_BOOL;
use windows::Win32::System::Com::{CoCreateInstance, CLSCTX_INPROC_SERVER};
use windows::Win32::System::UpdateAgent::{
    orcSucceeded, orcSucceededWithErrors, ISystemInformation, IUpdate, IUpdate3, IUpdateCollection,
    IUpdateSession, OperationResultCode, SystemInformation, UpdateCollection, UpdateSession,
};

/// Which class of update to search for.
#[derive(Clone, Copy, Debug)]
pub enum Kind {
    /// OS security/quality updates, .NET, Defender definitions…
    Software,
    /// Hardware drivers (and some firmware) published to Windows Update.
    Driver,
}

impl Kind {
    fn criteria(self) -> &'static str {
        match self {
            Kind::Software => "IsInstalled=0 and IsHidden=0 and Type='Software'",
            Kind::Driver => "IsInstalled=0 and IsHidden=0 and Type='Driver'",
        }
    }
}

/// A pending update, as plain data.
#[derive(Clone, Debug)]
pub struct Pending {
    /// The update's identity (a GUID), for installing just this one.
    pub id: String,
    pub title: String,
    pub kb: Option<String>,
    /// MSRC severity ("Critical", "Important", …) for security updates.
    pub msrc: Option<String>,
    /// Optional/preview updates ("browse only" in WUA terms).
    pub optional: bool,
}

impl Pending {
    /// Short label: the KB number when there is one.
    pub fn label(&self) -> String {
        self.kb.clone().unwrap_or_else(|| "Update".to_string())
    }
}

pub enum Outcome {
    Installed,
    InstalledWithErrors,
    Failed(String),
    DownloadFailed(String),
    /// Not attempted because the run was cancelled.
    Skipped,
}

impl Outcome {
    pub fn succeeded(&self) -> bool {
        matches!(self, Outcome::Installed | Outcome::InstalledWithErrors)
    }
    pub fn label(&self) -> String {
        match self {
            Outcome::Installed => "installed".into(),
            Outcome::InstalledWithErrors => "installed, with errors".into(),
            Outcome::Failed(why) => format!("install failed ({why})"),
            Outcome::DownloadFailed(why) => format!("download failed ({why})"),
            Outcome::Skipped => "skipped (run cancelled)".into(),
        }
    }
}

pub struct InstallReport {
    pub results: Vec<(Pending, Outcome)>,
    pub reboot_required: bool,
}

fn yes(v: VARIANT_BOOL) -> bool {
    v.0 != 0
}

/// A WUA error with a plain-English hint for the codes people actually hit.
pub fn describe_error(context: &str, e: &windows::core::Error) -> String {
    let hr = e.code().0 as u32;
    let hint = match hr {
        0x8024_0016 => " — another Windows Update install is already running; let it finish, then retry",
        0x8024_402C | 0x8007_2EE7 | 0x8024_401C => " — can't reach Windows Update (network, DNS or proxy)",
        0x8024_0044 => " — this account can't install updates; relaunch as administrator",
        0x8024_001E => " — the Windows Update service is stopping (restart or shutdown in progress)",
        0x8007_0422 => " — the Windows Update service is disabled",
        _ => "",
    };
    format!("{context}: 0x{hr:08X}{hint}")
}

fn wu(context: &'static str) -> impl Fn(windows::core::Error) -> String {
    move |e| describe_error(context, &e)
}

fn new_session() -> windows::core::Result<IUpdateSession> {
    // SAFETY: COM is initialised by the caller's ComGuard; CLSIDs are from the SDK.
    unsafe {
        let session: IUpdateSession = CoCreateInstance(&UpdateSession, None, CLSCTX_INPROC_SERVER)?;
        session.SetClientApplicationID(&BSTR::from("itriage"))?;
        Ok(session)
    }
}

fn search(session: &IUpdateSession, criteria: &str) -> windows::core::Result<IUpdateCollection> {
    // SAFETY: valid session; criteria is a well-formed WUA query built from
    // constants and a validated GUID.
    unsafe {
        let searcher = session.CreateUpdateSearcher()?;
        searcher.Search(&BSTR::from(criteria))?.Updates()
    }
}

fn describe(u: &IUpdate) -> windows::core::Result<Pending> {
    // SAFETY: property getters on a live IUpdate.
    unsafe {
        let title = u.Title()?.to_string();
        let id = u.Identity().and_then(|i| i.UpdateID()).map(|b| b.to_string()).unwrap_or_default();
        let kbs = u.KBArticleIDs()?;
        let kb = if kbs.Count()? > 0 {
            Some(format!("KB{}", kbs.get_Item(0)?))
        } else {
            None
        };
        let msrc = u
            .MsrcSeverity()
            .ok()
            .map(|s| s.to_string())
            .filter(|s| !s.is_empty());
        // BrowseOnly ("optional update") lives on IUpdate3 (WUA 7+, i.e. every
        // supported Windows). If the cast ever fails, treat it as not optional.
        let optional = u
            .cast::<IUpdate3>()
            .and_then(|u3| u3.BrowseOnly())
            .map(yes)
            .unwrap_or(false);
        Ok(Pending {
            id,
            title,
            kb,
            msrc,
            optional,
        })
    }
}

fn collection() -> windows::core::Result<IUpdateCollection> {
    // SAFETY: COM initialised by the caller.
    unsafe { CoCreateInstance(&UpdateCollection, None, CLSCTX_INPROC_SERVER) }
}

/// List pending updates of `kind`. Read-only: it contacts Windows Update but
/// changes nothing.
pub fn pending(kind: Kind) -> Result<Vec<Pending>, String> {
    let _com = ComGuard::init();
    let session = new_session().map_err(wu("Windows Update unavailable"))?;
    let found = search(&session, kind.criteria()).map_err(wu("Windows Update search failed"))?;
    let count = unsafe { found.Count() }.map_err(wu("reading search results"))?;
    (0..count)
        .map(|i| {
            unsafe { found.get_Item(i) }
                .and_then(|u| describe(&u))
                .map_err(wu("reading an update"))
        })
        .collect()
}

/// Whether Windows reports a restart pending from an earlier install.
pub fn reboot_pending() -> Option<bool> {
    let _com = ComGuard::init();
    // SAFETY: COM initialised above; read-only property.
    unsafe {
        let info: ISystemInformation =
            CoCreateInstance(&SystemInformation, None, CLSCTX_INPROC_SERVER).ok()?;
        info.RebootRequired().ok().map(yes)
    }
}

/// Download and install pending updates of `kind`; optional/preview ones only
/// when `include_optional`. Downloads go one at a time so progress is visible;
/// the install runs as a single batch, the way Windows Update itself does it,
/// so servicing-stack ordering is respected.
pub fn install(kind: Kind, include_optional: bool, ctx: &RunContext) -> Result<InstallReport, String> {
    install_matching(kind.criteria(), include_optional, ctx)
}

/// Install one update by its identity (Invoke-UpdateSystem's `-UpdateId`).
pub fn install_update(id: &str, ctx: &RunContext) -> Result<String, String> {
    if !crate::actions::valid_update_id(id) {
        return Err(format!("`{id}` isn't a Windows Update identity."));
    }
    let report = install_matching(&format!("UpdateID='{id}' and IsInstalled=0"), true, ctx)?;
    let Some((p, outcome)) = report.results.first() else {
        return Ok("That update is no longer offered (it may already be installed).".into());
    };
    let restart = if report.reboot_required { " Restart to finish." } else { "" };
    if outcome.succeeded() {
        Ok(format!("{}: {}.{restart}", p.label(), outcome.label()))
    } else {
        Err(format!("{}: {}", p.label(), outcome.label()))
    }
}

fn install_matching(criteria: &str, include_optional: bool, ctx: &RunContext) -> Result<InstallReport, String> {
    let _com = ComGuard::init();
    let session = new_session().map_err(wu("Windows Update unavailable"))?;

    ctx.log("Searching Windows Update…");
    let found = search(&session, criteria).map_err(wu("Windows Update search failed"))?;
    let count = unsafe { found.Count() }.map_err(wu("reading search results"))?;

    let mut chosen: Vec<(IUpdate, Pending)> = Vec::new();
    for i in 0..count {
        let u = unsafe { found.get_Item(i) }.map_err(wu("reading an update"))?;
        let p = describe(&u).map_err(wu("reading an update"))?;
        if p.optional && !include_optional {
            continue;
        }
        chosen.push((u, p));
    }
    if chosen.is_empty() {
        ctx.log("Nothing to install.");
        return Ok(InstallReport {
            results: Vec::new(),
            reboot_required: false,
        });
    }
    let total = chosen.len();
    ctx.log(format!("{total} update(s) to install"));

    // --- download, one at a time ---
    let downloader = unsafe { session.CreateUpdateDownloader() }.map_err(wu("starting the downloader"))?;
    let mut ready: Vec<(IUpdate, Pending)> = Vec::new();
    let mut results: Vec<(Pending, Outcome)> = Vec::new();

    let mut announced = false;
    for (n, (u, p)) in chosen.into_iter().enumerate() {
        // Cancelling is safe between downloads: nothing is half-installed.
        if ctx.cancelled() {
            if !announced {
                ctx.log("Cancelled: skipping the remaining downloads.");
                announced = true;
            }
            results.push((p, Outcome::Skipped));
            continue;
        }
        // SAFETY: property calls on a live IUpdate.
        unsafe {
            if !yes(u.EulaAccepted().map_err(wu("reading EULA state"))?) {
                u.AcceptEula().map_err(wu("accepting the license terms"))?;
            }
            if yes(u.IsDownloaded().map_err(wu("reading download state"))?) {
                ctx.log(format!("Already downloaded {}/{total}: {}", n + 1, p.title));
                ready.push((u, p));
                continue;
            }
        }
        ctx.log(format!("Downloading {}/{total}: {}", n + 1, p.title));
        let attempt = collection().and_then(|one| unsafe {
            one.Add(&u)?;
            downloader.SetUpdates(&one)?;
            downloader.Download()?.ResultCode()
        });
        match attempt {
            Ok(code) if code == orcSucceeded || code == orcSucceededWithErrors => ready.push((u, p)),
            Ok(code) => results.push((p, Outcome::DownloadFailed(format!("result code {}", code.0)))),
            Err(e) => results.push((p, Outcome::DownloadFailed(describe_error("download", &e)))),
        }
    }

    if ready.is_empty() {
        return Ok(InstallReport {
            results,
            reboot_required: false,
        });
    }
    // Last safe point: once the batch starts it runs to completion.
    if ctx.cancelled() {
        ctx.log("Cancelled before installing; downloaded updates stay cached for next time.");
        results.extend(ready.into_iter().map(|(_, p)| (p, Outcome::Skipped)));
        return Ok(InstallReport {
            results,
            reboot_required: false,
        });
    }

    // --- install, as one batch ---
    ctx.log(format!("Installing {} update(s); this can take a while…", ready.len()));
    let batch = collection().map_err(wu("preparing the install"))?;
    for (u, _) in &ready {
        unsafe { batch.Add(u) }.map_err(wu("preparing the install"))?;
    }
    let installer = unsafe { session.CreateUpdateInstaller() }.map_err(wu("starting the installer"))?;
    unsafe { installer.SetUpdates(&batch) }.map_err(wu("starting the installer"))?;
    let result = unsafe { installer.Install() }.map_err(wu("install failed"))?;
    let reboot_required = unsafe { result.RebootRequired() }.map(yes).unwrap_or(false);

    for (i, (_, p)) in ready.into_iter().enumerate() {
        let outcome = match unsafe { result.GetUpdateResult(i as i32) } {
            Ok(r) => {
                let code = unsafe { r.ResultCode() }.unwrap_or(OperationResultCode(4));
                if code == orcSucceeded {
                    Outcome::Installed
                } else if code == orcSucceededWithErrors {
                    Outcome::InstalledWithErrors
                } else {
                    let hr = unsafe { r.HResult() }.unwrap_or(0) as u32;
                    Outcome::Failed(format!("0x{hr:08X}"))
                }
            }
            Err(e) => Outcome::Failed(describe_error("no result", &e)),
        };
        ctx.log(format!("{}: {}", p.label(), outcome.label()));
        results.push((p, outcome));
    }

    Ok(InstallReport {
        results,
        reboot_required,
    })
}
