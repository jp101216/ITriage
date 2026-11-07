/* itriage frontend logic — v0.4.
 *
 * Two views over the same engine:
 *   • Technician: the red HUD console. Module rail, streaming report, one-click
 *     fixes, KB links, run history and compare, export formats, cancel.
 *   • Self-service: a calm teal "check my computer" page for the person at the
 *     PC, with the computer name up front, plain-language results, a few safe
 *     fixes and a "copy details for the service desk" button.
 *
 * Runs in two modes from the same code:
 *   • Inside the Tauri window → window.__TAURI__ exists; calls the real Rust
 *     commands, listens for streamed progress events, and polls live telemetry.
 *   • In a plain browser → no __TAURI__; a mock drives the same UI with sample
 *     data and a simulated telemetry feed, so the interface can be previewed
 *     without building anything.
 */
(function () {
  "use strict";

  const isTauri = !!(window.__TAURI__ && window.__TAURI__.core);
  const VERSION = "v0.4";

  /* ----------------------------- icons ----------------------------- */
  const sv = (body, extra) =>
    `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"${extra || ""}>${body}</svg>`;
  const I = {
    logo: '<svg viewBox="0 0 24 24" fill="none" stroke="#ff3b36" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M2 12h4l2-5 3 10 2.5-7 1.5 2H22"/></svg>',
    logoCalm: '<svg viewBox="0 0 24 24" fill="none" stroke="#3ccfbc" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M2 12h4l2-5 3 10 2.5-7 1.5 2H22"/></svg>',
    check: '<svg viewBox="0 0 24 24" fill="none" stroke="#1a0304" stroke-width="3.6" stroke-linecap="round" stroke-linejoin="round"><path d="M4 12l5 5L20 6"/></svg>',
    play: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M7 4v16l13-8z"/></svg>',
    stop: '<svg viewBox="0 0 24 24" fill="currentColor"><rect x="6" y="6" width="12" height="12" rx="1"/></svg>',
    caret: sv('<path d="M9 6l6 6-6 6"/>', ' stroke-width="2.4"'),
    warn: sv('<path d="M12 9v4m0 4h.01M10.3 3.9 2 18a2 2 0 0 0 1.7 3h16.6a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/>'),
    shield: sv('<path d="M12 3l8 3v6c0 4.5-3.4 8.3-8 9-4.6-.7-8-4.5-8-9V6z"/>'),
    term: sv('<path d="M4 17l6-5-6-5M12 19h8"/>'),
    rack: sv('<rect x="3" y="4" width="18" height="6" rx="1"/><rect x="3" y="14" width="18" height="6" rx="1"/><path d="M7 7h.01M7 17h.01M11 7h6M11 17h6"/>'),
    alert: sv('<path d="M12 9v4m0 4h.01M10.3 3.9 2 18a2 2 0 0 0 1.7 3h16.6a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/>'),
    trash: sv('<path d="M4 7h16M10 11v6M14 11v6M5 7l1 13h12l1-13M9 7V4h6v3"/>'),
    refresh: sv('<path d="M20 11a8 8 0 1 0-2.3 5.7M20 4v7h-7"/>'),
    radar: sv('<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="5"/><path d="M12 12l6-6"/>'),
    download: sv('<path d="M12 3v12m0 0l-5-5m5 5l5-5M4 21h16"/>'),
    chip: sv('<rect x="6" y="6" width="12" height="12" rx="1"/><path d="M9 2v4M15 2v4M9 18v4M15 18v4M2 9h4M2 15h4M18 9h4M18 15h4"/>'),
    clock: sv('<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>'),
    domain: sv('<rect x="9" y="3" width="6" height="5" rx="1"/><rect x="3" y="16" width="6" height="5" rx="1"/><rect x="15" y="16" width="6" height="5" rx="1"/><path d="M12 8v4M6 16v-4h12v4"/>'),
    printer: sv('<path d="M7 9V3h10v6"/><rect x="3" y="9" width="18" height="8" rx="1.5"/><path d="M7 14h10v7H7z"/>'),
    plug: sv('<path d="M9 2v5M15 2v5"/><path d="M6 7h12v4a6 6 0 0 1-12 0z"/><path d="M12 17v5"/>'),
    wifi: sv('<path d="M2.5 9a14 14 0 0 1 19 0M5.5 12.5a9.5 9.5 0 0 1 13 0M8.6 16a5 5 0 0 1 6.8 0"/><circle cx="12" cy="19.2" r="1.2" fill="currentColor" stroke="none"/>'),
    cert: sv('<rect x="3" y="4" width="18" height="12" rx="1.5"/><path d="M7 8h6M7 11h4"/><circle cx="16.5" cy="12.5" r="2.5"/><path d="M15 14.5V21l1.5-1 1.5 1v-6.5"/>'),
    battery: sv('<rect x="2.5" y="7" width="17" height="10" rx="1.5"/><path d="M21.5 10.5v3M5.5 10v4M8.5 10v4M11.5 10v4"/>'),
    apps: sv('<rect x="4" y="4" width="6" height="6" rx="1"/><rect x="14" y="4" width="6" height="6" rx="1"/><rect x="4" y="14" width="6" height="6" rx="1"/><rect x="14" y="14" width="6" height="6" rx="1"/>'),
    target: sv('<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="4.5"/><path d="M12 2v4M12 18v4M2 12h4M18 12h4"/>'),
    lock: sv('<rect x="5" y="11" width="14" height="10" rx="1.5"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/>'),
    open: sv('<path d="M12 15V3m0 0L7 8m5-5 5 5M4 21h16"/>'),
    export: sv('<path d="M14 4h6v6M20 4l-9 9"/><path d="M18 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h5"/>'),
    book: sv('<path d="M4 5.5A1.5 1.5 0 0 1 5.5 4H11v16H5.5A1.5 1.5 0 0 1 4 18.5zM20 5.5A1.5 1.5 0 0 0 18.5 4H13v16h5.5a1.5 1.5 0 0 0 1.5-1.5z"/>'),
    bolt: sv('<path d="M13 2 4 14h7l-1 8 9-12h-7z"/>'),
    copy: sv('<rect x="8" y="8" width="12" height="12" rx="1.5"/><path d="M16 8V5.5A1.5 1.5 0 0 0 14.5 4h-9A1.5 1.5 0 0 0 4 5.5v9A1.5 1.5 0 0 0 5.5 16H8"/>'),
    okc: sv('<circle cx="12" cy="12" r="9"/><path d="M8 12.5l2.5 2.5L16 9.5"/>'),
    xc: sv('<circle cx="12" cy="12" r="9"/><path d="M9 9l6 6M15 9l-6 6"/>'),
    swap: sv('<path d="M7 7h12l-3-3M17 17H5l3 3"/>'),
    nodes:
      '<svg viewBox="0 0 92 26" fill="none" stroke="currentColor" stroke-width="1.2">' +
      '<path d="M46 13 62 4M46 13 70 15M46 13 58 23M46 13 30 6M46 13 26 19M62 4 84 7M70 15 84 7M70 15 86 20" opacity=".7"/>' +
      '<g fill="currentColor" stroke="none"><circle cx="46" cy="13" r="4.2"/><circle cx="62" cy="4" r="2.2"/><circle cx="70" cy="15" r="2.6"/>' +
      '<circle cx="84" cy="7" r="2.2"/><circle cx="86" cy="20" r="2"/><circle cx="58" cy="23" r="2"/></g>' +
      '<circle cx="30" cy="6" r="2.2"/><circle cx="26" cy="19" r="2.2"/></svg>',
    radarBig:
      '<svg class="radar" viewBox="0 0 100 100" fill="none" stroke="currentColor" stroke-width="1.4" aria-hidden="true">' +
      '<circle cx="50" cy="50" r="46" opacity=".5"/><circle cx="50" cy="50" r="31" opacity=".4"/><circle cx="50" cy="50" r="16" opacity=".35"/>' +
      '<path d="M50 4v92M4 50h92" opacity=".25"/>' +
      '<g class="sweep"><path d="M50 50 L50 4 A46 46 0 0 1 82.5 17.5 Z" fill="currentColor" fill-opacity=".18" stroke="none"/><path d="M50 50 L50 4"/></g>' +
      '<circle cx="68" cy="34" r="2.5" fill="currentColor" stroke="none"/></svg>',
  };

  /* --------- module catalogue (mirrors itriage-core::registry) ------ *
   * Drives the browser preview and the very first paint. In the Tauri app
   * the list then comes live from Rust (with OS-specific descriptions and
   * the site policy's locks). */
  const mod = (id, title, category, description, extra) =>
    Object.assign(
      { id, title, category, description, mutating: false, requires_admin: false, platforms: ["windows", "linux"] },
      extra || {}
    );
  const WIN = { platforms: ["windows"] };
  const CATALOGUE = [
    mod("system.info", "System information", "system", "OS, kernel, hostname, uptime, CPU and total memory."),
    mod("system.disk", "Disk usage", "system", "Free vs. total space per volume. Warns under 10% free, critical under 5%."),
    mod("system.memory", "Memory usage", "system", "RAM and swap in use. Warns over 85% used, critical over 95%."),
    mod("proc.top", "Top processes", "processes", "The biggest memory users plus any CPU hogs. Flags anything pinning a core or holding a quarter of RAM."),
    mod("proc.services", "Services", "processes", "Automatic services that aren't running, with exit codes. Skips trigger-start services that stop by design."),
    mod("net.connectivity", "Network connectivity", "network", "Interface IPs, DNS resolution, and an outbound TCP reachability test."),
    mod("eventlog.errors", "Recent errors", "eventlog", "Critical and error events from the System and Application logs in the last 24 hours, grouped by source and event ID."),
    mod("desk.time", "Clock & time sync", "workstation", "Clock offset against the time server, where the time comes from, and the time zone. Domain sign-in fails past 5 minutes of drift."),
    mod("desk.domain", "Domain & Group Policy", "workstation", "Domain membership, whether a domain controller or cached credentials signed you in, the AD site, and when Group Policy last applied.", WIN),
    mod("desk.printers", "Printers & print queue", "workstation", "Print Spooler state, every printer's status, stuck jobs, the default printer, and label printers."),
    mod("desk.devices", "Devices & peripherals", "workstation", "Devices with driver problems (the Code 43s), microphones, cameras and card readers, plus devices the site profile requires."),
    mod("desk.wifi", "Wi-Fi & VPN", "workstation", "The connected Wi-Fi network, signal strength, security (802.1X or not), link rate, and any VPN tunnel."),
    mod("desk.certs", "Machine certificates", "workstation", "Computer certificates (used for 802.1X Wi-Fi and VPN) and when they expire. Warns 14 days out.", WIN),
    mod("desk.battery", "Battery health", "workstation", "Charge, power source, and battery wear (capacity left vs. design, cycle count). Flags batteries under 80%."),
    mod("site.apps", "Required & clinical apps", "site", "Apps the site profile requires (with minimum versions), plus which clinical clients are installed: Citrix, Imprivata, Epic, Dragon, VPN, EDR."),
    mod("site.checks", "Site services & endpoints", "site", "Services the site profile requires are running, and the servers it lists (EHR, file, print, license) answer."),
    mod("fix.temp", "Clear temp files", "fixes", "Deletes the contents of the user temp directory. Skips files in use.", {
      mutating: true,
      warning: "Permanently deletes everything in your temp folder that isn't currently in use.",
    }),
    mod("fix.dns", "Flush DNS cache", "fixes", "Clears the OS DNS resolver cache (ipconfig / resolvectl).", {
      mutating: true,
      warning: "Clears cached DNS lookups. The next few page loads may be a little slower.",
    }),
    mod("update.scan", "Available updates", "updates", "Pending Windows Update patches, winget app upgrades, restart state, and the OEM driver/BIOS tool. Installs nothing."),
    mod("update.apply", "Install OS & app updates", "updates", "Installs pending Windows Update patches (security & quality) and upgrades winget apps. Optional/preview updates are skipped.", {
      mutating: true,
      requires_admin: true,
      warning: "Installs every pending Windows update and app upgrade. This can take 30+ minutes, apps being upgraded may close, and a restart is usually needed afterwards.",
    }),
    mod("update.firmware", "Install drivers & firmware", "updates", "Drivers, BIOS and firmware through the OEM tool (Dell, HP, Lenovo), or Windows Update drivers when there isn't one.", {
      mutating: true,
      requires_admin: true,
      warning: "May flash BIOS/firmware. Keep laptops on AC power and don't power off until it finishes. A restart is usually needed; BitLocker may ask for its recovery key if it isn't suspended first.",
    }),
  ];

  const CAT_ORDER = ["system", "processes", "network", "eventlog", "workstation", "site", "fixes", "updates"];
  const CAT_LABEL = {
    system: "System",
    processes: "Processes & services",
    network: "Network",
    eventlog: "Event log",
    workstation: "Workstation",
    site: "Site & clinical",
    fixes: "Fixes",
    updates: "Updates",
  };
  /** Short HUD codes shown next to each module title. */
  const CODES = {
    "system.info": "SYS-INF", "system.disk": "DSK-USE", "system.memory": "MEM-USE",
    "proc.top": "PROC-TOP", "proc.services": "SVC-HLT", "net.connectivity": "NET-CON",
    "eventlog.errors": "EVT-ERR", "desk.time": "CLK-SYN", "desk.domain": "DOM-GPO",
    "desk.printers": "PRN-QUE", "desk.devices": "DEV-MGR", "desk.wifi": "WLAN-VPN",
    "desk.certs": "CRT-EXP", "desk.battery": "BAT-HLT", "site.apps": "APP-REQ",
    "site.checks": "SITE-CHK", "fix.temp": "FIX-TMP", "fix.dns": "FIX-DNS",
    "update.scan": "UPD-SCN", "update.apply": "UPD-INS", "update.firmware": "UPD-FRM",
  };
  /** Cards with a live mini-chart fed by the telemetry sampler. */
  const LIVE_GLYPH = { "system.info": "cpu", "system.disk": "disk", "system.memory": "mem", "proc.top": "cores" };
  const STATIC_GLYPH = {
    "net.connectivity": I.nodes, "proc.services": I.rack, "eventlog.errors": I.alert,
    "desk.time": I.clock, "desk.domain": I.domain, "desk.printers": I.printer, "desk.devices": I.plug,
    "desk.wifi": I.wifi, "desk.certs": I.cert, "desk.battery": I.battery,
    "site.apps": I.apps, "site.checks": I.target,
    "fix.temp": I.trash, "fix.dns": I.refresh, "update.scan": I.radar,
    "update.apply": I.download, "update.firmware": I.chip,
  };

  /** One-click fixes (mirrors itriage-core::actions::FIXES). */
  const FIX_CATALOGUE = [
    { id: "restart-spooler", label: "Restart Print Spooler", requires_admin: true,
      description: "Restarts the print service (Print Spooler or CUPS). A job that is printing right now starts over." },
    { id: "clear-print-queue", label: "Clear print queue", requires_admin: true,
      description: "Stops the print service, deletes every waiting print job, and starts it again. People will need to print those documents again." },
    { id: "resync-time", label: "Resync clock", requires_admin: true,
      description: "Tells the time service to synchronise with its time source now." },
    { id: "gpupdate", label: "Refresh Group Policy", requires_admin: false,
      description: "Runs gpupdate /force to reapply computer and user policy. It can take a minute." },
    { id: "start-service", label: "Start service", requires_admin: true, description: "Starts the stopped service." },
    { id: "flush-dns", label: "Flush DNS cache", requires_admin: false,
      description: "Clears cached DNS lookups so names are looked up fresh." },
  ];

  /** Self-service: the checks it runs, in plain words. */
  const SS_TITLES = {
    "system.info": "This computer", "system.disk": "Storage space", "system.memory": "Memory",
    "net.connectivity": "Internet & network", "desk.time": "Clock", "desk.domain": "Sign-in & policies",
    "desk.printers": "Printers", "desk.devices": "Devices", "desk.wifi": "Wi-Fi & VPN",
    "desk.battery": "Battery", "site.apps": "Required apps", "site.checks": "Work systems",
  };
  const SOURCE = {
    managed: ["MANAGED", "Machine-wide, set by IT"],
    env: ["TEST", "From ITRIAGE_PROFILE (testing)"],
    user: ["PERSONAL", "This user's own profile"],
    "built-in": ["DEFAULT", "Built-in default (no profile file found)"],
  };
  const RANK = { ok: 0, info: 1, warning: 2, critical: 3 };

  /* --------------------- sample data for the preview ---------------- */
  const ADMIN_REQUIRED =
    'Administrator rights required. Use "Relaunch as admin" in the header (or right-click itriage → Run as administrator).';
  const MOCK_HOST = {
    hostname: "WS-FLINT-07",
    os: "Windows 11 Pro 24H2",
    platform: "windows",
    elevated: false,
    can_relaunch_elevated: true,
    elevation_note: "Install modules need administrator rights. Use Relaunch as admin.",
  };
  const MOCK_FIXES = ["restart-spooler", "clear-print-queue", "resync-time", "gpupdate", "flush-dns", "start-service:Spooler", "start-service:W32Time"];
  const MOCK_PROFILE = {
    source: "managed",
    path: "C:\\ProgramData\\itriage\\profile.toml",
    error: null,
    name: "Clinical workstation (example)",
    description: "Shared nursing-unit PC: badge-tap sign-in, virtual desktop, label printer",
    policy: { allow_changes: true, allow_installs: false, fixes: MOCK_FIXES, start_in: "technician", technician_view: true },
    requirements: 8,
    kb_rules: 3,
  };
  const A = (id, target) => {
    const spec = FIX_CATALOGUE.find((f) => f.id === id);
    const a = { id, label: id === "start-service" && target ? `Start ${target}` : spec.label, requires_admin: spec.requires_admin };
    if (target) a.target = target;
    return a;
  };
  const K = (title, url) => ({ title, url });
  const F = (label, value, severity, detail, extra) => {
    const f = { label, value, severity: severity || "info" };
    if (detail) f.detail = detail;
    return Object.assign(f, extra || {});
  };
  const R = (module_id, title, category, summary, duration_ms, findings) => ({
    module_id, title, category, findings, summary, error: null, duration_ms,
  });
  const KB_QUEUE = K("Clear a stuck print queue", "https://kb.example.org/printing/stuck-queue");
  const KB_TIME = K("Clock drift and sign-in failures", "https://kb.example.org/windows/time-sync");
  const KB_WIFI = K("Report a Wi-Fi dead spot", "https://kb.example.org/network/wifi-coverage");
  const CU_TITLE = "2026-11 Cumulative Update for Windows 11 Version 24H2 for x64-based Systems";
  const NET_TITLE = "2026-11 Cumulative Update for .NET Framework 3.5 and 4.8.1 for Windows 11, version 24H2";
  const DEF_TITLE = "Security Intelligence Update for Microsoft Defender Antivirus";
  const MOCK_RESULTS = {
    "system.info": R("system.info", "System information", "system", "WS-FLINT-07, up 3d 7h 12m", 41, [
      F("Hostname", "WS-FLINT-07"), F("OS", "Windows 11 Pro 24H2 (build 26100.2314)"), F("Kernel", "26100"),
      F("Architecture", "x86_64"), F("CPU", "Intel(R) Core(TM) Ultra 7 165U (14 logical cores)"),
      F("Total memory", "16.0 GB"), F("Uptime", "3d 7h 12m"), F("Manufacturer", "Dell Inc."),
    ]),
    "system.disk": R("system.disk", "Disk usage", "system", "Low free space on at least one volume.", 18, [
      F("C:\\", "7.2 GB free of 476.9 GB (98% used) · NTFS", "critical"),
      F("D:\\", "812.4 GB free of 1.8 TB (56% used) · NTFS", "ok"),
    ]),
    "system.memory": R("system.memory", "Memory usage", "system", "62% RAM in use", 6, [
      F("RAM", "9.9 GB used of 16.0 GB (62%), 6.1 GB available", "ok"),
      F("Swap / page file", "1.2 GB used of 9.0 GB (13%)", "ok"),
    ]),
    "proc.top": R("proc.top", "Top processes", "processes", "214 processes running · 1 using heavy CPU or memory", 214, [
      F("MsMpEng.exe (pid 2680)", "640.0 MB RAM · 87.5% CPU", "warning"),
      F("CDViewer.exe (pid 8124)", "2.1 GB RAM · 3.4% CPU"),
      F("chrome.exe (pid 4410)", "1.4 GB RAM · 1.1% CPU"),
      F("Teams.exe (pid 9332)", "402.0 MB RAM · 0.9% CPU"),
      F("explorer.exe (pid 5120)", "188.0 MB RAM · 0.2% CPU"),
    ]),
    "proc.services": R("proc.services", "Services", "processes", "187 running · 1 automatic service not running", 96, [
      F("Running services", "187", "ok"),
      F("Windows Defender Firewall (mpssvc)", "stopped · Automatic", "warning"),
      F("Windows Search (WSearch)", "stopped · Automatic (delayed)", "info"),
      F("Stopped by design (skipped)", "41 trigger-start/per-user, 3 self-stopping updaters"),
    ]),
    "net.connectivity": R("net.connectivity", "Network connectivity", "network", "Connectivity OK.", 3140, [
      F("Interface Wi-Fi", "10.20.33.118/22, fe80::1a2b/64"),
      F("DNS resolution (example.com)", "resolved", "ok"),
      F("Outbound TCP (1.1.1.1:443)", "reachable", "ok"),
    ]),
    "eventlog.errors": R("eventlog.errors", "Recent errors", "eventlog", "1 critical, 11 errors in the last 24h (4 sources)", 380, [
      F("Kernel-Power 41 · System", "1× · last 5h ago", "critical",
        "The system has rebooted without cleanly shutting down first. This error could be caused if the system stopped responding, crashed, or lost power unexpectedly."),
      F("Service Control Manager 7031 · System", "2× · last 3h ago", "warning",
        "The Print Spooler service terminated unexpectedly. It has done this 2 time(s). The following corrective action will be taken in 60000 milliseconds: Restart the service."),
      F("Application Error 1000 · Application", "3× · last 47m ago", "warning",
        "Faulting application name: Teams.exe, version: 24295.605.3225.8804, time stamp: 0x6720a1b3 Faulting module name: KERNELBASE.dll, version: 10.0.26100.2314"),
      F("DistributedCOM 10016 · System", "6× · last 12m ago", "info",
        "The application-specific permission settings do not grant Local Activation permission for the COM Server application (known DCOM noise, safe to ignore)"),
    ]),
    "desk.time": R("desk.time", "Clock & time sync", "workstation", "Clock is 41.6 s slow against DC01", 64, [
      F("Time source", "domain hierarchy (signed in via DC01)", "ok"),
      F("Offset vs DC01", "41.6 s slow", "warning", "round trip 3 ms · server stratum 2", { action: A("resync-time"), kb: KB_TIME }),
      F("Time zone", "Eastern Standard Time"),
      F("Windows Time service", "running", "ok"),
    ]),
    "desk.domain": R("desk.domain", "Domain & Group Policy", "workstation", "Joined to CORP.EXAMPLE.ORG · policy applied 3d ago", 22, [
      F("Domain", "CORP.EXAMPLE.ORG", "ok"),
      F("Signed in via", "DC01", "ok"),
      F("AD site", "Main-Campus"),
      F("Group Policy (computer)", "applied 3d ago · 2026-11-03 07:14:02 UTC", "warning", null, { action: A("gpupdate") }),
    ]),
    "desk.printers": R("desk.printers", "Printers & print queue", "workstation", "2 printers · 1 needs attention", 48, [
      F("Print Spooler", "running", "ok"),
      F("Ward 4 LaserJet (default)", "in an error state · 3 jobs stuck", "warning", "HP Universal Printing PCL 6 · port IP_10.20.30.40",
        { action: A("clear-print-queue"), kb: KB_QUEUE }),
      F("Specimen labels (label printer)", "ready", "ok", "ZDesigner ZD421-203dpi ZPL · port USB001"),
      F("Default printer", "Ward 4 LaserJet"),
      F("Software printers (PDF, XPS, OneNote, fax)", "3"),
    ]),
    "desk.devices": R("desk.devices", "Devices & peripherals", "workstation", "214 devices · 1 with driver problem", 310, [
      F("USB Composite Device (USB)", "Code 43: stopped after reporting problems (Code 43)", "warning"),
      F("Badge reader", "detected: RFIDeas pcProx USB", "ok"),
      F("Dictation microphone", "detected: Microphone (Nuance PowerMic III)", "ok"),
      F("Microphones", "Microphone (Nuance PowerMic III), Microphone (Realtek(R) Audio)"),
      F("Cameras", "Integrated Webcam"),
      F("Smart card readers", "Microsoft Usbccid Smartcard Reader (WUDF)"),
    ]),
    "desk.wifi": R("desk.wifi", "Wi-Fi & VPN", "workstation", "Wi-Fi Clinical-Secure, signal weak", 35, [
      F("Network", "Clinical-Secure", "ok", "Intel(R) Wi-Fi 6E AX211 160MHz"),
      F("Signal", "34% · weak", "warning", "Weak signal drops remote sessions as the device moves. Note where it happens for the network team.", { kb: KB_WIFI }),
      F("Security", "WPA2-Enterprise · 802.1X", "ok"),
      F("Link rate", "144 Mbps"),
      F("VPN (Cisco Secure Client)", "installed, not connected", "info", "Ethernet 3 · Cisco AnyConnect Secure Mobility Client Virtual Miniport Adapter for Windows x64"),
    ]),
    "desk.certs": R("desk.certs", "Machine certificates", "workstation", "1 machine certificate expired or expiring within 14 days", 12, [
      F("WS-FLINT-07.corp.example.org", "expires in 9 days · 2026-11-15", "warning", "Issued by Example Issuing CA 2 · has a private key"),
      F("WS-FLINT-07", "valid for 301 more days · 2027-09-03", "ok", "Issued by Example Device CA · has a private key"),
    ]),
    "desk.battery": R("desk.battery", "Battery health", "workstation", "Battery wearing: 76% of design capacity left", 1840, [
      F("Charge", "86% · on AC power", "ok"),
      F("Health (SMP DELL 7FHXW37)", "76% of design · 48.1 of 63.0 Wh", "warning", "Plan a battery replacement; runtime is noticeably shorter than new."),
      F("Charge cycles (SMP DELL 7FHXW37)", "311"),
    ]),
    "site.apps": R("site.apps", "Required & clinical apps", "site", "1 of 2 required apps missing or out of date", 140, [
      F("Citrix Workspace", "23.11.1.45 · needs 24.2 or later", "warning", "Citrix Workspace 2311"),
      F("Badge-tap SSO agent", "7.11.0", "ok", "Imprivata OneSign Agent"),
      F("Dictation", "Dragon Medical One 2024.1"),
      F("Endpoint security", "CrowdStrike Windows Sensor 7.18.18604.0"),
    ]),
    "site.checks": R("site.checks", "Site services & endpoints", "site", "3 of 4 site requirements met", 3020, [
      F("Print Spooler", "running", "ok"),
      F("Windows Time", "running", "ok"),
      F("EHR gateway", "ehr-gateway.example.org:443 reachable · 18 ms", "ok"),
      F("Print server", "print01.example.org:445 unreachable (timed out)", "critical"),
    ]),
    "fix.temp": R("fix.temp", "Clear temp files", "fixes", "Freed 1.8 GB (342 removed, 7 skipped)", 820, [
      F("Temp directory", "C:\\Users\\jparker\\AppData\\Local\\Temp"),
      F("Entries removed", "342", "ok"), F("Space freed", "1.8 GB"),
      F("Entries skipped (in use / locked)", "7"),
    ]),
    "fix.dns": R("fix.dns", "Flush DNS cache", "fixes", "DNS resolver cache flushed.", 240, [
      F("ipconfig /flushdns", "Successfully flushed the DNS Resolver Cache.", "ok"),
    ]),
    "update.scan": R("update.scan", "Available updates", "updates", "3 Windows updates · restart pending · 4 app upgrades", 41_380, [
      F("Windows Update", "3 important · 1 optional", "warning"),
      F("KB5070001", CU_TITLE, "critical", "MSRC severity: Critical"),
      F("KB5070002", NET_TITLE, "warning", "MSRC severity: Important"),
      F("KB2267602", DEF_TITLE),
      F("Restart pending", "yes; restart to finish earlier updates", "warning"),
      F("winget apps", "4 upgradable", "warning"),
      F("Google Chrome (Google.Chrome)", "130.0.6723.92 → 131.0.6778.70"),
      F("Mozilla Firefox (Mozilla.Firefox)", "131.0.3 → 132.0.1"),
      F("7-Zip 23.01 (x64) (7zip.7zip)", "23.01 → 24.08"),
      F("Microsoft Visual Studio Code (Microsoft.VisualStudioCode)", "1.94.2 → 1.95.1"),
      F("Driver/BIOS tool (Dell Inc.)", "Dell Command | Update is installed", "ok"),
    ]),
    "update.apply": R("update.apply", "Install OS & app updates", "updates", "Installed 3 Windows updates and 4 app upgrades; restart required", 1_412_000, [
      F("Windows Update", "3 installed, 0 failed", "ok"),
      F("KB5070001", "installed", "ok", CU_TITLE),
      F("KB5070002", "installed", "ok", NET_TITLE),
      F("KB2267602", "installed", "ok", DEF_TITLE),
      F("winget apps", "4 upgraded, 0 failed", "ok"),
      F("Restart required", "yes", "warning"),
    ]),
    "update.firmware": R("update.firmware", "Install drivers & firmware", "updates", "Dell Command | Update: updates applied; restart required", 486_000, [
      F("Manufacturer", "Dell Inc."),
      F("Dell Command | Update", "updates applied; restart required (exit 1)", "warning", "Logs and reports: C:\\ProgramData\\itriage"),
    ]),
  };
  const MOCK_LOGS = {
    "eventlog.errors": ["Reading the System log…", "Reading the Application log…"],
    "desk.time": ["Measuring the clock against DC01 (SNTP, UDP 123)…"],
    "desk.battery": ["Running powercfg /batteryreport…"],
    "site.apps": ["Reading the installed-programs list…"],
    "site.checks": ["Checking 2 endpoint(s)…"],
    "fix.temp": ["Clearing C:\\Users\\jparker\\AppData\\Local\\Temp"],
    "update.scan": ["Searching Windows Update…", "Checking winget for app upgrades…"],
  };
  /** What a finding looks like once its fix has worked (preview only). */
  const FIXED_VALUE = {
    "clear-print-queue": "ready", "restart-spooler": "running", "resync-time": "4 ms slow",
    gpupdate: "applied just now", "start-service": "running", "flush-dns": "resolved",
  };
  const FIX_MESSAGES = {
    "restart-spooler": () => "Print Spooler restarted.",
    "clear-print-queue": () => "Removed 6 spooled files and restarted the Print Spooler.",
    "resync-time": () => "Clock resynchronised with its time source.",
    gpupdate: () => "Group Policy refreshed.",
    "start-service": (t) => `${t} started.`,
    "flush-dns": () => "Successfully flushed the DNS Resolver Cache.",
  };
  const MOCK_DIFF = {
    against: "2026-11-05T19:02:11Z",
    changes: [
      { module_id: "desk.printers", module: "Printers & print queue", label: "Ward 4 LaserJet (default)", kind: "new", before: "ok", after: "warning", value: "in an error state · 3 jobs stuck" },
      { module_id: "desk.time", module: "Clock & time sync", label: "Offset vs DC01", kind: "new", before: "ok", after: "warning", value: "41.6 s slow" },
      { module_id: "system.disk", module: "Disk usage", label: "C:\\", kind: "changed", before: "warning", after: "critical", value: "7.2 GB free of 476.9 GB (98% used) · NTFS" },
      { module_id: "proc.services", module: "Services", label: "Print Spooler (Spooler)", kind: "resolved", before: "critical", after: null, value: "stopped · exit 1067 · Automatic" },
    ],
  };
  const HIST_DIR = "C:\\Users\\jparker\\AppData\\Local\\itriage\\history\\";
  const MOCK_HISTORY = [
    { path: HIST_DIR + "20261105T190211Z_WS-FLINT-07.json", generated: "2026-11-05T19:02:11Z", hostname: "WS-FLINT-07", modules: 16, worst: "critical", cancelled: false },
    { path: HIST_DIR + "20261103T141530Z_WS-FLINT-07.json", generated: "2026-11-03T14:15:30Z", hostname: "WS-FLINT-07", modules: 9, worst: "warning", cancelled: false },
    { path: HIST_DIR + "20261102T091044Z_WS-ED-12.json", generated: "2026-11-02T09:10:44Z", hostname: "WS-ED-12", modules: 12, worst: "critical", cancelled: false },
    { path: HIST_DIR + "20261029T162201Z_WS-FLINT-07.json", generated: "2026-10-29T16:22:01Z", hostname: "WS-FLINT-07", modules: 4, worst: "ok", cancelled: true },
  ];

  /* --------------------------- state ------------------------------- */
  const STORE_KEY = "itriage.selection.v3";
  const HISTORY = 90; // telemetry samples kept (one per second)
  let catalogue = CATALOGUE;
  let fixCatalogue = FIX_CATALOGUE;
  let profile = isTauri ? null : MOCK_PROFILE;
  let host = isTauri ? null : Object.assign({}, MOCK_HOST);
  let mode = "tech";
  const selected = new Set(loadSelection());
  let running = false;
  let cancelRequested = false;
  let fixBusy = false;
  /** The latest run in this session (both views render from it). */
  let live = { results: [], report: null, diff: null };
  /** A saved or opened report being looked at instead of the live run. */
  let viewing = null;
  let diffIndex = new Map();
  const logs = new Map(); // module id → output lines
  const liveCards = new Map(); // module id → running card element
  const lastSev = new Map(); // module id → severity of its last result (rail LEDs)
  const dirty = new Set(); // module ids whose live log needs repainting
  let flushQueued = false;
  const hist = { cpu: [], mem: [], net: [], disk: [] };
  let tele = null;
  let teleBusy = false;

  const mockSample = isTauri ? null : mockTelemetry();
  const api = isTauri ? realApi() : mockApi();

  /* --------------------------- mount ------------------------------- */
  const root = document.getElementById("app");
  root.innerHTML = `
    <section class="hud brackets" id="hud" aria-label="Live telemetry">
      <div class="hud-main">
        <div class="hud-title">TELEMETRY: <span class="v">${isTauri ? "LIVE" : "SIMULATED"}</span>
          <span class="hud-state" id="hudState">[READY]</span></div>
        <div class="scope big" data-scope="cpu"><canvas></canvas>
          <span class="scope-label"><b>CPU</b><span id="lblCpu">—</span></span></div>
      </div>
      <div class="hud-grid">
        <div class="scope" data-scope="net"><canvas></canvas><span class="scope-label"><b>NET</b><span id="lblNet">—</span></span></div>
        <div class="scope" data-scope="cores"><canvas></canvas><span class="scope-label"><b>CORES</b><span id="lblCores">—</span></span></div>
        <div class="scope" data-scope="mem"><canvas></canvas><span class="scope-label"><b>MEM</b><span id="lblMem">—</span></span></div>
        <div class="scope" data-scope="disk"><canvas></canvas><span class="scope-label"><b>DISK</b><span id="lblDisk">—</span></span></div>
      </div>
    </section>
    <header class="brandbar" id="brandbar">
      <div class="brand">
        <span class="logo">${I.logo}</span>
        <span class="name">itriage</span>
        <span class="brk">${VERSION}</span>
        ${isTauri ? "" : '<span class="tag preview">PREVIEW · SAMPLE DATA</span>'}
        <button class="tag profile" id="profileTag" type="button" title="Site profile"><span id="profileIcon">${I.shield}</span><span id="profileName">PROFILE —</span></button>
        <button class="bk-btn xs view-switch" id="toSelf" type="button" title="The simple view end users see">${I.swap}Self-service view</button>
      </div>
      <dl class="stats">
        <div><dt>TARGET:</dt><dd class="hot" id="stTarget">—</dd></div>
        <div><dt>PRIV</dt><dd id="stPriv">—</dd></div>
        <div><dt>OS:</dt><dd id="stOs">—</dd></div>
        <div><dt>STATUS</dt><dd class="hot" id="stStatus">[READY]</dd></div>
      </dl>
    </header>
    <div class="profile-warn" id="profileWarn" hidden>${I.warn}<span id="profileWarnText"></span></div>
    <div class="workspace" id="workspace">
      <aside class="rail">
        <div class="rail-head">
          <h2>MODULES <span id="modTotal">[00]</span></h2>
          <span class="sel-count" id="count" title="Selected">0</span>
        </div>
        <div class="rail-actions">
          <button class="bk-btn hot" id="allChecks" type="button" title="Selects every read-only check. Modules that change the system stay off.">All checks</button>
          <button class="bk-btn" id="none" type="button">Clear</button>
        </div>
        <div class="modules" id="modules"></div>
        <div class="run-dock">
          <button class="run-btn" id="run" type="button"><span class="plate"><span id="runIcon">${I.play}</span><span id="runLabel">RUN DIAGNOSTIC SEQUENCE</span><span id="runk">[00]</span></span></button>
          <div class="micro"><span>ITRIAGE // DIAGNOSTIC CORE ${VERSION}</span><span id="microPlat"></span></div>
        </div>
      </aside>
      <main class="report">
        <div class="report-bar">
          <span class="status" id="status"><span class="dot"></span><span id="statusText">Idle</span></span>
          <span class="elapsed" id="elapsed"></span>
          <div class="spacer"></div>
          <div class="bar-actions">
            <button class="bk-btn sm" id="historyBtn" type="button" title="Saved runs on this machine">History</button>
            <button class="bk-btn sm" id="openBtn" type="button" title="Open an exported or remote report (.json)">Open</button>
            <div class="menu-wrap">
              <button class="bk-btn sm hot" id="exportBtn" type="button" aria-haspopup="menu" aria-expanded="false" disabled>Export</button>
              <div class="menu" id="exportMenu" role="menu" hidden>
                <button type="button" role="menuitem" data-fmt="plain">${I.term}<span>Ticket text<small>Plain text · ServiceNow, email, work notes</small></span></button>
                <button type="button" role="menuitem" data-fmt="rich">${I.export}<span>Rich text<small>Formatted table · TeamDynamix, Outlook</small></span></button>
                <button type="button" role="menuitem" data-fmt="md">${I.book}<span>Markdown<small>Teams, GitHub, wikis</small></span></button>
                <button type="button" role="menuitem" data-fmt="json">${I.download}<span>JSON report<small>Re-open in itriage, or attach to the ticket</small></span></button>
              </div>
            </div>
          </div>
          <input type="file" id="fileInput" accept=".json,application/json" hidden>
        </div>
        <div class="progress-wrap"><div class="progress-bar" id="progress"></div></div>
        <div class="results" id="results"></div>
      </main>
    </div>
    <div class="ss" id="ss" hidden></div>`;

  const el = (id) => document.getElementById(id);
  const modulesEl = el("modules"), countEl = el("count"), modTotal = el("modTotal"),
    runBtn = el("run"), runIcon = el("runIcon"), runLabel = el("runLabel"), runK = el("runk"),
    statusEl = el("status"), statusText = el("statusText"), elapsedEl = el("elapsed"),
    progressEl = el("progress"), resultsEl = el("results"),
    exportBtn = el("exportBtn"), exportMenu = el("exportMenu"), fileInput = el("fileInput"),
    stTarget = el("stTarget"), stPriv = el("stPriv"), stOs = el("stOs"), stStatus = el("stStatus"),
    hudState = el("hudState"), microPlat = el("microPlat"),
    hudEl = el("hud"), brandEl = el("brandbar"), workspaceEl = el("workspace"), ssEl = el("ss"),
    profileTag = el("profileTag"), profileName = el("profileName"), profileIcon = el("profileIcon"),
    profileWarn = el("profileWarn"), profileWarnText = el("profileWarnText");
  const scope = (name) => document.querySelector(`[data-scope="${name}"] canvas`);
  const scopes = { cpu: scope("cpu"), net: scope("net"), cores: scope("cores"), mem: scope("mem"), disk: scope("disk") };
  const lbl = { cpu: el("lblCpu"), net: el("lblNet"), cores: el("lblCores"), mem: el("lblMem"), disk: el("lblDisk") };

  el("allChecks").onclick = () => {
    if (running) return;
    catalogue.forEach((m) => { if (!m.mutating && !m.locked) selected.add(m.id); });
    syncRows();
  };
  el("none").onclick = () => { if (!running) { selected.clear(); syncRows(); } };
  runBtn.onclick = () => (running ? requestCancel() : onRun());
  el("historyBtn").onclick = openHistory;
  el("openBtn").onclick = () => fileInput.click();
  fileInput.onchange = onFilePicked;
  el("toSelf").onclick = () => setMode("self");
  profileTag.onclick = showProfile;
  exportBtn.onclick = (e) => { e.stopPropagation(); toggleMenu(); };
  exportMenu.querySelectorAll("[data-fmt]").forEach((b) => {
    b.onclick = () => { toggleMenu(false); doExport(b.dataset.fmt); };
  });
  document.addEventListener("click", (e) => { if (!exportMenu.hidden && !exportMenu.contains(e.target)) toggleMenu(false); });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape" && !exportMenu.hidden) { toggleMenu(false); exportBtn.focus(); } });

  // Paint immediately from the bundled catalogue so the first frame is
  // complete, then refresh from the live source (Rust, in the Tauri app).
  if (mockSample) for (let i = 0; i < HISTORY; i++) ingest(mockSample());
  renderHost();
  renderProfile();
  renderModules();
  syncRows();
  setPhase("ready");
  showEmpty();
  boot();

  pollTelemetry();
  setInterval(pollTelemetry, 1000);
  document.addEventListener("visibilitychange", () => { if (!document.hidden) pollTelemetry(); });
  window.addEventListener("resize", () => requestAnimationFrame(paintTelemetry));

  async function boot() {
    try {
      const list = await api.listModules();
      if (Array.isArray(list) && list.length) catalogue = list;
    } catch (_) { /* keep the bundled catalogue */ }
    try { fixCatalogue = (await api.listFixes()) || fixCatalogue; } catch (_) { /* keep the bundled list */ }
    try { profile = await api.getProfile(); } catch (_) { /* no profile info */ }
    const usable = new Set(catalogue.filter((m) => !m.locked).map((m) => m.id));
    [...selected].forEach((id) => { if (!usable.has(id)) selected.delete(id); });
    try { host = await api.hostContext(); } catch (_) { /* stats stay minimal */ }
    renderHost();
    renderProfile();
    renderModules(); // re-render so WIN/LIN chips and locks reflect this host
    syncRows();
    const pol = profile && profile.policy;
    if (pol && (pol.technician_view === false || pol.start_in === "self-service")) setMode("self");
  }

  /* ------------------------- view switch --------------------------- */
  function canTech() {
    return !profile || !profile.policy || profile.policy.technician_view !== false;
  }

  function setMode(next) {
    if (next === "tech" && !canTech()) return;
    mode = next;
    const self = mode === "self";
    document.body.classList.toggle("calm", self);
    hudEl.hidden = brandEl.hidden = workspaceEl.hidden = self;
    profileWarn.hidden = self || !(profile && profile.error);
    ssEl.hidden = !self;
    toggleMenu(false);
    if (self) {
      renderSelf();
    } else {
      if (!viewing) renderLive();
      requestAnimationFrame(paintTelemetry);
    }
  }

  /* ------------------------- telemetry ----------------------------- */
  function ingest(t) {
    tele = t;
    const push = (arr, v) => { arr.push(v); if (arr.length > HISTORY) arr.shift(); };
    push(hist.cpu, t.cpu);
    push(hist.mem, t.mem_pct);
    push(hist.net, t.net_rx + t.net_tx);
    push(hist.disk, t.disk_read + t.disk_write);
  }

  async function pollTelemetry() {
    if (teleBusy || document.hidden || mode === "self") return;
    teleBusy = true;
    try {
      ingest(await api.telemetry());
      paintTelemetry();
    } catch (_) {
      /* keep the last frame */
    } finally {
      teleBusy = false;
    }
  }

  function paintTelemetry() {
    if (!tele || mode === "self") return;
    const t = tele;
    drawTrace(scopes.cpu, hist.cpu, { max: 100, fill: true, head: true, top: 16 });
    drawTrace(scopes.net, hist.net, { max: autoMax(hist.net), top: 15 });
    drawBars(scopes.cores, t.cores, { top: 15 });
    drawTrace(scopes.mem, hist.mem, { max: 100, top: 15 });
    drawTrace(scopes.disk, hist.disk, { max: autoMax(hist.disk), fill: true, top: 15 });

    const peak = t.cores.length ? Math.round(Math.max(...t.cores)) : 0;
    lbl.cpu.textContent = `${Math.round(t.cpu)}%`;
    lbl.net.textContent = `↓${rate(t.net_rx)} ↑${rate(t.net_tx)}`;
    lbl.cores.textContent = `${t.cores.length} · PEAK ${peak}%`;
    lbl.mem.textContent = `${Math.round(t.mem_pct)}% · ${gb(t.mem_used)}/${gb(t.mem_total)} GB`;
    lbl.disk.textContent = `R ${rate(t.disk_read)} · W ${rate(t.disk_write)}`;

    modulesEl.querySelectorAll("canvas[data-mini]").forEach((c) => {
      const kind = c.dataset.mini;
      if (kind === "cpu") drawTrace(c, hist.cpu.slice(-40), { max: 100, cap: 40, fill: true, glow: 4, width: 1.3 });
      else if (kind === "mem") drawTrace(c, hist.mem.slice(-40), { max: 100, cap: 40, glow: 4, width: 1.3 });
      else if (kind === "cores") drawBars(c, t.cores, { glow: 2 });
      else if (kind === "disk") drawGauge(c, t.fullest_pct);
    });
  }

  /** Size a canvas to its box at device resolution and clear it. */
  function fit(c) {
    if (!c) return null;
    const w = c.clientWidth, h = c.clientHeight;
    if (!w || !h) return null;
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    const W = Math.round(w * dpr), H = Math.round(h * dpr);
    if (c.width !== W || c.height !== H) { c.width = W; c.height = H; }
    const ctx = c.getContext("2d");
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, w, h);
    return { ctx, w, h };
  }

  /** A glowing oscilloscope trace, newest sample at the right edge. */
  function drawTrace(c, data, o) {
    const f = fit(c);
    if (!f || !data.length) return;
    const { ctx, w, h } = f;
    const cap = o.cap || HISTORY;
    const top = o.top ?? 3, bottom = h - 3;
    const span = w - 4;
    const step = span / Math.max(cap - 1, 1);
    const x0 = span - (data.length - 1) * step;
    const y = (v) => bottom - (clamp(v, 0, o.max) / o.max) * (bottom - top);
    const path = () => {
      ctx.beginPath();
      data.forEach((v, i) => (i ? ctx.lineTo(x0 + i * step, y(v)) : ctx.moveTo(x0, y(v))));
    };
    if (o.fill) {
      path();
      ctx.lineTo(span, h);
      ctx.lineTo(x0, h);
      ctx.closePath();
      const g = ctx.createLinearGradient(0, top, 0, h);
      g.addColorStop(0, "rgba(255, 59, 54, 0.30)");
      g.addColorStop(1, "rgba(255, 59, 54, 0)");
      ctx.fillStyle = g;
      ctx.fill();
    }
    path();
    ctx.lineJoin = "round";
    ctx.lineWidth = o.width || 1.6;
    ctx.strokeStyle = "#ff4a43";
    ctx.shadowColor = "rgba(255, 40, 34, 0.95)";
    ctx.shadowBlur = o.glow ?? 8;
    ctx.stroke();
    if (o.head) {
      ctx.beginPath();
      ctx.arc(span, y(data[data.length - 1]), 2.6, 0, Math.PI * 2);
      ctx.fillStyle = "#ffd6d0";
      ctx.shadowBlur = 12;
      ctx.fill();
    }
    ctx.shadowBlur = 0;
  }

  /** One bar per logical core; hot cores glow brighter. */
  function drawBars(c, values, o) {
    const f = fit(c);
    if (!f || !values || !values.length) return;
    const { ctx, w, h } = f;
    const top = (o && o.top) ?? 3;
    const n = values.length, gap = n > 32 ? 1 : 2;
    const bw = Math.max(1, (w - 4 - gap * (n - 1)) / n);
    values.forEach((v, i) => {
      const bh = Math.max(1.5, (clamp(v, 0, 100) / 100) * (h - top - 3));
      const hot = v >= 85;
      ctx.fillStyle = hot ? "#ff7a70" : "rgba(255, 59, 54, 0.85)";
      ctx.shadowColor = "rgba(255, 40, 34, 0.9)";
      ctx.shadowBlur = hot ? 8 : ((o && o.glow) ?? 3);
      ctx.fillRect(2 + i * (bw + gap), h - 3 - bh, bw, bh);
    });
    ctx.shadowBlur = 0;
  }

  /** Segmented fill gauge for the fullest volume, with a hazard mark ≥ 90%. */
  function drawGauge(c, pct) {
    const f = fit(c);
    if (!f) return;
    const { ctx, w, h } = f;
    const warn = pct >= 90;
    let x = 0;
    if (warn) {
      const s = Math.min(h - 6, 16), ty = (h - s) / 2;
      ctx.fillStyle = "#ff3b36";
      ctx.shadowColor = "rgba(255, 40, 34, 0.9)";
      ctx.shadowBlur = 6;
      ctx.beginPath();
      ctx.moveTo(s / 2, ty);
      ctx.lineTo(s, ty + s);
      ctx.lineTo(0, ty + s);
      ctx.closePath();
      ctx.fill();
      ctx.shadowBlur = 0;
      ctx.fillStyle = "#1a0304";
      ctx.fillRect(s / 2 - 0.9, ty + s * 0.36, 1.8, s * 0.32);
      ctx.fillRect(s / 2 - 0.9, ty + s * 0.76, 1.8, 1.8);
      x = s + 6;
    }
    const segs = 16, gap = 2;
    const sw = (w - x - gap * (segs - 1)) / segs;
    const sh = Math.min(10, h - 8), sy = (h - sh) / 2;
    const lit = Math.round((clamp(pct, 0, 100) / 100) * segs);
    for (let i = 0; i < segs; i++) {
      const on = i < lit;
      ctx.fillStyle = on ? (warn && i >= segs - 3 ? "#ff7a70" : "#ff3b36") : "rgba(255, 59, 54, 0.16)";
      ctx.shadowColor = "rgba(255, 40, 34, 0.8)";
      ctx.shadowBlur = on ? 4 : 0;
      ctx.fillRect(x + i * (sw + gap), sy, sw, sh);
    }
    ctx.shadowBlur = 0;
  }

  function autoMax(series) {
    return Math.max(65536, ...series) * 1.2; // floor keeps idle noise from filling the scope
  }
  function rate(b) {
    if (b < 1024) return `${Math.round(b)} B/s`;
    if (b < 1048576) return `${(b / 1024).toFixed(b < 10240 ? 1 : 0)} KB/s`;
    if (b < 1073741824) return `${(b / 1048576).toFixed(1)} MB/s`;
    return `${(b / 1073741824).toFixed(2)} GB/s`;
  }
  function gb(b) {
    return (b / 1073741824).toFixed(1);
  }

  /* ---------------------- header & status ------------------------- */
  function renderHost() {
    stTarget.textContent = host ? host.hostname : "—";
    stOs.textContent = host ? host.os : "—";
    stOs.title = host ? host.os : "";
    if (!host) {
      stPriv.textContent = "—";
    } else {
      const label = host.elevated ? (host.platform === "windows" ? "[ADMIN]" : "[ROOT]") : "[USER]";
      stPriv.innerHTML =
        `<span class="${host.elevated ? "good" : ""}" title="${esc(host.elevation_note)}">${label}</span>` +
        (!host.elevated && host.can_relaunch_elevated
          ? ' <button class="bk-btn xs hot" id="relaunch" type="button" title="Relaunch as administrator">Elevate</button>'
          : "");
      const btn = document.getElementById("relaunch");
      if (btn) btn.onclick = relaunch;
    }
    microPlat.textContent = host ? `${host.platform.toUpperCase()} // ${host.hostname}` : "";
    if (mode === "self") renderSelf();
  }

  function renderProfile() {
    const p = profile;
    if (!p) {
      profileName.textContent = "PROFILE —";
      return;
    }
    const [tag] = SOURCE[p.source] || [p.source.toUpperCase()];
    profileName.innerHTML = `<b>${esc(tag)}</b> ${esc(p.name)}`;
    profileIcon.innerHTML = p.source === "managed" ? I.lock : I.shield;
    profileTag.classList.toggle("err", !!p.error);
    profileTag.title = `Site profile: ${p.name}. Click for details.`;
    profileWarnText.textContent = p.error ? `Site profile problem: ${p.error}` : "";
    profileWarn.hidden = mode === "self" || !p.error;
  }

  function showProfile() {
    const p = profile;
    if (!p) return;
    const pol = p.policy || {};
    const fixes = pol.fixes == null ? "every built-in fix" : pol.fixes.length ? pol.fixes.join(", ") : "none";
    const where = host && host.platform === "linux" ? "/etc/itriage/profile.toml" : "%ProgramData%\\itriage\\profile.toml";
    const [, sourceText] = SOURCE[p.source] || ["", p.source];
    modal({
      title: `${I.shield} Site profile`,
      body: `
        ${p.error ? `<div class="errbox">${esc(p.error)}</div>` : ""}
        <dl class="kv">
          <dt>Name</dt><dd>${esc(p.name)}</dd>
          ${p.description ? `<dt>About</dt><dd>${esc(p.description)}</dd>` : ""}
          <dt>Source</dt><dd>${esc(sourceText)}${p.path ? `<br><code>${esc(p.path)}</code>` : ""}</dd>
          <dt>Changes</dt><dd>${pol.allow_changes ? "allowed" : "blocked: read-only"}</dd>
          <dt>Installs</dt><dd>${pol.allow_changes && pol.allow_installs ? "allowed" : "blocked: updates are deployed centrally"}</dd>
          <dt>Fixes</dt><dd>${esc(pol.allow_changes ? fixes : "none (read-only)")}</dd>
          <dt>Requirements</dt><dd>${p.requirements} (services, apps, endpoints, devices)</dd>
          <dt>KB links</dt><dd>${p.kb_rules} rule${p.kb_rules === 1 ? "" : "s"}</dd>
          <dt>Opens in</dt><dd>${pol.start_in === "self-service" ? "self-service view" : "technician view"}${pol.technician_view === false ? " · technician view turned off" : ""}</dd>
        </dl>
        <p>A machine-wide profile at <code>${esc(where)}</code> wins over a personal one, and a broken one locks itriage to read-only.</p>`,
      actions: [{ label: "Close", hot: true, value: true }],
    });
  }

  async function relaunch() {
    try {
      await api.relaunchElevated(); // the Tauri app exits when this succeeds
    } catch (e) {
      toast(errText(e) || "Elevation was cancelled");
    }
  }

  /** ready | running | done(worst) → the STATUS word, the HUD tag and the report bar. */
  function setPhase(phase, worst) {
    let word = "READY", tone = "hot", bar = "";
    if (phase === "running") {
      word = "RUNNING";
      bar = "running";
    } else if (phase === "done") {
      if (worst === "critical") { word = "ALERT"; tone = "crit"; bar = "alert"; }
      else if (worst === "warning") { word = "CAUTION"; tone = "warn"; bar = "caution"; }
      else { word = "COMPLETE"; tone = "good"; bar = "complete"; }
    } else if (phase === "cancelled") {
      word = "CANCELLED";
      tone = "warn";
      bar = "caution";
    }
    stStatus.textContent = `[${word}]`;
    stStatus.className = tone;
    hudState.textContent = `[${word}]`;
    hudState.className = `hud-state ${tone}`;
    statusEl.className = `status ${bar}`.trim();
    return word;
  }

  /* ----------------------- render checklist ------------------------ */
  function renderModules() {
    const byCat = {};
    catalogue.forEach((m) => { (byCat[m.category] = byCat[m.category] || []).push(m); });
    let html = "";
    CAT_ORDER.forEach((cat) => {
      const mods = byCat[cat];
      if (!mods || !mods.length) return;
      html += `<div class="cat">${CAT_LABEL[cat] || cat}</div>`;
      mods.forEach((m) => {
        const plats = ["windows", "linux"]
          .filter((p) => (m.platforms || []).includes(p))
          .map((p) => `<span class="plat${host && host.platform === p ? " on" : ""}">${p === "windows" ? "WIN" : "LIN"}</span>`)
          .join("");
        const badges =
          (m.locked ? `<span class="badge lock" title="${esc(m.locked)}">${I.lock}LOCKED</span>` : "") +
          (m.mutating && !m.locked ? '<span class="badge mut">CHANGES SYSTEM</span>' : "") +
          (m.requires_admin && !m.locked ? '<span class="badge admin">ADMIN</span>' : "");
        const live = LIVE_GLYPH[m.id];
        const glyph = live ? `<canvas data-mini="${live}"></canvas>` : STATIC_GLYPH[m.id] || "";
        html += `
          <div class="mod${m.locked ? " locked" : ""}" data-id="${esc(m.id)}" role="checkbox" tabindex="0" aria-checked="false"${m.locked ? ' aria-disabled="true"' : ""}>
            <span class="box"><span class="plus">+</span>${I.check}</span>
            <span class="body">
              <span class="t">
                <span class="title">${esc(m.title)}</span>
                <span class="code">[${esc(CODES[m.id] || m.id.toUpperCase().replace(/\./g, "-"))}]</span>
                <span class="led" title="Last result"></span>
                <span class="chips">${plats}${badges}</span>
              </span>
              <span class="d">${esc(m.locked || m.description)}</span>
            </span>
            <span class="glyph" aria-hidden="true">${glyph}</span>
          </div>`;
      });
    });
    modulesEl.innerHTML = html;
    modTotal.textContent = `[${pad2(catalogue.length)}]`;
    modulesEl.querySelectorAll(".mod").forEach((row) => {
      const id = row.dataset.id;
      const m = catalogue.find((x) => x.id === id);
      if (lastSev.has(id)) row.dataset.sev = lastSev.get(id);
      const toggle = () => {
        if (running) return;
        if (m && m.locked) { toast(m.locked); return; }
        selected.has(id) ? selected.delete(id) : selected.add(id);
        syncRows();
      };
      row.addEventListener("click", toggle);
      row.addEventListener("keydown", (e) => {
        if (e.key === " " || e.key === "Enter") { e.preventDefault(); toggle(); }
      });
    });
    paintTelemetry(); // fresh canvases need a frame
  }

  function syncRows() {
    modulesEl.querySelectorAll(".mod").forEach((row) => {
      const on = selected.has(row.dataset.id);
      row.classList.toggle("on", on);
      row.setAttribute("aria-checked", on ? "true" : "false");
    });
    const n = selected.size;
    countEl.textContent = n;
    if (!running) runK.textContent = `[${pad2(n)}]`;
    runBtn.disabled = running ? cancelRequested : n === 0;
    saveSelection();
  }

  /* ----------------------------- run ------------------------------- */
  async function onRun() {
    if (running || selected.size === 0) return;
    const chosen = catalogue.filter((m) => selected.has(m.id) && !m.locked);
    if (!chosen.length) return;
    const mutating = chosen.filter((m) => m.mutating);
    if (mutating.length && !(await confirmRun(mutating))) return;
    await startRun(chosen.map((m) => m.id));
  }

  function requestCancel() {
    if (!running || cancelRequested) return;
    cancelRequested = true;
    Promise.resolve(api.cancel()).catch(() => {});
    runLabel.textContent = "STOPPING AFTER THIS STEP";
    statusText.textContent = "Stopping at the next safe point…";
    syncRows();
  }

  async function startRun(ids) {
    const total = ids.length;
    viewing = null;
    running = true;
    cancelRequested = false;
    live = { results: [], report: null, diff: null };
    setDiff(null);
    logs.clear();
    liveCards.clear();
    lastSev.clear();
    modulesEl.querySelectorAll(".mod[data-sev]").forEach((r) => r.removeAttribute("data-sev"));
    syncRows();
    el("toSelf").disabled = true;
    runBtn.classList.add("running");
    runIcon.innerHTML = I.stop;
    runLabel.textContent = "ABORT SEQUENCE";
    runK.textContent = `[00/${pad2(total)}]`;
    exportBtn.disabled = true;
    setPhase("running");
    statusText.textContent = "Running sequence";
    resultsEl.innerHTML = "";
    if (!isTauri) {
      const note = document.createElement("div");
      note.className = "sample-note";
      note.innerHTML = `${I.warn}<span>Preview: these are sample results, not a real scan of this machine.</span>`;
      resultsEl.appendChild(note);
    }
    setProgress(0);

    const t0 = performance.now();
    const timer = setInterval(() => {
      elapsedEl.textContent = "T+ " + fmtSecs((performance.now() - t0) / 1000);
      const now = Date.now();
      liveCards.forEach((card) => {
        const dur = card.querySelector(".dur");
        dur.textContent = fmtSecs((now - Number(dur.dataset.started)) / 1000);
      });
    }, 200);

    try {
      const outcome = await api.run(ids, {
        onStart: ({ id, title, index, total: n }) => {
          setProgress(index / Math.max(n, 1));
          if (!cancelRequested) statusText.textContent = `Running · ${index + 1}/${n}`;
          runK.textContent = `[${pad2(index + 1)}/${pad2(n)}]`;
          startCard(id, title);
        },
        onLog: ({ id, line }) => appendLog(id, line),
        onDone: (res) => {
          live.results.push(res);
          finishCard(res);
          setProgress(live.results.length / Math.max(total, 1));
        },
      });
      if (outcome && outcome.report) {
        live.report = outcome.report;
        live.results = outcome.report.results;
        live.diff = outcome.diff || null;
        if (outcome.save_error) toast("Couldn't save this run to history: " + outcome.save_error);
      }
    } catch (e) {
      toast("The run stopped: " + errText(e));
    } finally {
      clearInterval(timer);
      elapsedEl.textContent = "T+ " + fmtSecs((performance.now() - t0) / 1000);
      running = false;
      const cancelled = cancelRequested || !!(live.report && live.report.cancelled);
      cancelRequested = false;
      el("toSelf").disabled = false;
      runBtn.classList.remove("running");
      runIcon.innerHTML = I.play;
      runLabel.textContent = "RUN DIAGNOSTIC SEQUENCE";
      liveCards.forEach((card) => card.remove());
      liveCards.clear();
      syncRows();
      setDiff(live.diff);
      if (live.diff) {
        resultsEl.insertBefore(diffBanner(live.diff), resultsEl.querySelector(".card"));
        applyBadges();
      }
      statusText.textContent = runSummary(live.results, cancelled, total);
      exportBtn.disabled = live.results.length === 0;
      setProgress(1);
      setTimeout(() => setProgress(0), 600);
    }
  }

  function runSummary(results, cancelled, total) {
    const n = results.length;
    if (cancelled) {
      setPhase("cancelled");
      return `Cancelled · ${n} of ${total} module${total === 1 ? "" : "s"} ran`;
    }
    const worst = worstOf(results);
    const word = setPhase("done", worst);
    return `${word} · ${n} module${n === 1 ? "" : "s"}` + (worst ? ` · worst: ${worst}` : "");
  }

  function setProgress(fraction) {
    progressEl.style.width = Math.round(clamp(fraction, 0, 1) * 100) + "%";
  }

  /** Keep the newest output in view, unless the user has scrolled up to read. */
  function sticky(fn) {
    const atBottom = resultsEl.scrollHeight - resultsEl.scrollTop - resultsEl.clientHeight < 80;
    fn();
    if (atBottom) resultsEl.scrollTop = resultsEl.scrollHeight;
  }

  function startCard(id, title) {
    sticky(() => {
      const card = document.createElement("div");
      card.className = "card running open";
      card.innerHTML = `
        <div class="card-head">
          <span class="chip run"><span class="spin"></span>running</span>
          <span class="meta"><span class="ct">${esc(title)}</span><span class="cs">Working…</span></span>
          <span class="dur" data-started="${Date.now()}">0.0 s</span>
        </div>
        <pre class="log live" hidden></pre>`;
      resultsEl.appendChild(card);
      liveCards.set(id, card);
    });
  }

  function appendLog(id, line) {
    const arr = logs.get(id) || [];
    arr.push(line);
    if (arr.length > 800) arr.shift();
    logs.set(id, arr);
    dirty.add(id);
    if (!flushQueued) {
      flushQueued = true;
      requestAnimationFrame(flushLogs); // repaint at most once per frame
    }
  }

  function flushLogs() {
    flushQueued = false;
    sticky(() => {
      dirty.forEach((id) => {
        const card = liveCards.get(id);
        const lines = logs.get(id);
        if (!card || !lines) return;
        const pre = card.querySelector(".log");
        pre.hidden = false;
        pre.textContent = lines.slice(-8).join("\n");
        card.querySelector(".cs").textContent = lines[lines.length - 1];
      });
    });
    dirty.clear();
  }

  function finishCard(res) {
    const sev = statusOf(res);
    lastSev.set(res.module_id, sev);
    const row = modulesEl.querySelector(`.mod[data-id="${CSS.escape(res.module_id)}"]`);
    if (row) row.dataset.sev = sev;
    sticky(() => {
      const done = buildCard(res, { live: true });
      const card = liveCards.get(res.module_id);
      if (card) card.replaceWith(done);
      else resultsEl.appendChild(done);
      liveCards.delete(res.module_id);
    });
  }

  /** A finished module's card. `live` cards offer fixes; saved ones don't. */
  function buildCard(res, opts) {
    const o = opts || {};
    const sev = statusOf(res);
    const lines = logs.get(res.module_id) || [];
    const card = document.createElement("div");
    card.className = `card sev-${sev} open`;
    card.dataset.mod = res.module_id;
    const note = o.note
      ? `<div class="fr"><span class="fdot sev-ok"></span><span class="fl">Fix applied</span><span class="fv">${esc(o.note)} · re-checked</span></div>`
      : "";
    const rows = res.error
      ? `<div class="fr err"><span class="fdot sev-critical"></span><span class="fl">Couldn't run</span><span class="fv">${esc(res.error)}</span></div>`
      : res.findings.map((f, i) => findingRow(res, f, i, o.live)).join("");
    const logLabel = (shown) => `${shown ? "Hide" : "Show"} log · ${lines.length} line${lines.length === 1 ? "" : "s"}`;
    const logBlock = lines.length
      ? `<button class="log-toggle" type="button" aria-expanded="false">${I.term}<span>${logLabel(false)}</span></button>
         <pre class="log" hidden>${esc(lines.join("\n"))}</pre>`
      : "";
    card.innerHTML = `
      <div class="card-head" role="button" tabindex="0" aria-expanded="true">
        <span class="chip sev-${sev}">${res.error ? "failed" : sev}</span>
        <span class="meta"><span class="ct">${esc(res.title)}</span>
          <span class="cs">${esc(res.error ? "Couldn't run" : res.summary)}</span></span>
        <span class="dur">${fmtMs(res.duration_ms)}</span>
        <span class="caret">${I.caret}</span>
      </div>
      <div class="findings">${note}${rows}${logBlock}</div>`;

    const head = card.querySelector(".card-head");
    const toggle = () => head.setAttribute("aria-expanded", card.classList.toggle("open") ? "true" : "false");
    head.onclick = toggle;
    head.onkeydown = (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); toggle(); } };
    const lt = card.querySelector(".log-toggle");
    if (lt) {
      lt.onclick = () => {
        const pre = card.querySelector("pre.log");
        pre.hidden = !pre.hidden;
        lt.setAttribute("aria-expanded", pre.hidden ? "false" : "true");
        lt.querySelector("span").textContent = logLabel(!pre.hidden);
      };
    }
    card.querySelectorAll("[data-fix]").forEach((btn) => {
      const f = res.findings[Number(btn.dataset.fix)];
      btn.onclick = () => onFix(btn, f, res);
    });
    card.querySelectorAll("[data-kb]").forEach((a) => wireKb(a));
    return card;
  }

  function findingRow(res, f, i, liveCard) {
    // A re-check after a fix can move a finding on; only badge what still holds.
    const c = changeFor(res.module_id, f.label);
    const change = c && c.after === f.severity ? c : null;
    const admin = f.action && f.action.requires_admin && host && !host.elevated;
    const fix = f.action && liveCard
      ? `<button class="fix-btn" type="button" data-fix="${i}" title="${esc(fixDescription(f.action))}">${I.bolt}${esc(f.action.label)}${admin ? '<span class="adm">ADMIN</span>' : ""}</button>`
      : "";
    const kb = f.kb ? `<a class="kb-link" data-kb href="${esc(f.kb.url)}" target="_blank" rel="noopener noreferrer">${I.book}${esc(f.kb.title)}</a>` : "";
    const fx = fix || kb ? `<div class="fx">${fix}${kb}<span class="fix-slot"></span></div>` : "";
    return `
      <div class="fr" data-label="${esc(f.label)}"><span class="fdot sev-${esc(f.severity)}"></span>
        <span class="fl">${esc(f.label)}${change ? badgeHtml(change) : ""}</span>
        <span class="fv">${esc(f.value)}</span>
        ${f.detail ? `<span class="fd">${esc(f.detail)}</span>` : ""}
        ${fx}
      </div>`;
  }

  function wireKb(a) {
    a.addEventListener("click", (e) => {
      e.preventDefault();
      Promise.resolve(api.openLink(a.getAttribute("href"))).catch((err) => toast(errText(err)));
    });
  }

  function fixDescription(action) {
    const spec = fixCatalogue.find((x) => x.id === action.id);
    return spec ? spec.description : action.label;
  }

  function showEmpty() {
    resultsEl.innerHTML = `
      <div class="empty">
        ${I.radarBig}
        <h3>AWAITING SEQUENCE</h3>
        <p>Select modules on the left, then run the diagnostic sequence. Results stream in as each module finishes.
           Every run is saved to History, and the next run on this machine shows what changed.</p>
      </div>`;
  }

  /** Repaint the report pane from the live run (after viewing a saved one). */
  function renderLive() {
    viewing = null;
    resultsEl.innerHTML = "";
    setDiff(live.diff);
    if (!live.results.length) {
      setPhase("ready");
      statusText.textContent = "Idle";
      exportBtn.disabled = true;
      showEmpty();
      return;
    }
    if (live.diff) resultsEl.appendChild(diffBanner(live.diff));
    live.results.forEach((r) => {
      resultsEl.appendChild(buildCard(r, { live: true }));
      lastSev.set(r.module_id, statusOf(r));
    });
    modulesEl.querySelectorAll(".mod").forEach((row) => {
      if (lastSev.has(row.dataset.id)) row.dataset.sev = lastSev.get(row.dataset.id);
    });
    statusText.textContent = runSummary(live.results, !!(live.report && live.report.cancelled), live.results.length);
    exportBtn.disabled = false;
  }

  /* -------------------------- one-click fixes -------------------------- */
  async function onFix(btn, f, res) {
    if (running) { toast("Wait for the run to finish first."); return; }
    if (fixBusy) return;
    if (!(await confirmFix(f.action, f))) return;
    const slot = btn.parentElement.querySelector(".fix-slot");
    fixBusy = true;
    setFixButtons(false);
    slot.innerHTML = '<span class="fix-note busy"><span class="spin"></span>Running fix…</span>';
    let message = null;
    try {
      message = await api.runFix(f.action.id, f.action.target || null);
      slot.innerHTML = `<span class="fix-note ok">${I.okc}${esc(message)}</span><span class="fix-note busy">Re-checking…</span>`;
    } catch (e) {
      slot.innerHTML = `<span class="fix-note err">${I.xc}${esc(errText(e))}</span>`;
    } finally {
      fixBusy = false;
      setFixButtons(true);
    }
    if (message != null) {
      toast(message);
      await recheck(res.module_id, message);
    }
  }

  function setFixButtons(on) {
    document.querySelectorAll(".fix-btn, .ss-fix").forEach((b) => { b.disabled = !on; });
  }

  /** Run one module again (not saved to history) and swap its result in. */
  async function recheck(moduleId, note) {
    let res;
    try {
      res = await api.recheck(moduleId);
    } catch (e) {
      toast("Re-check failed: " + errText(e));
      return null;
    }
    if (!res) return null;
    const i = live.results.findIndex((r) => r.module_id === moduleId);
    if (i >= 0) live.results[i] = res;
    if (live.report) {
      const j = live.report.results.findIndex((r) => r.module_id === moduleId);
      if (j >= 0) live.report.results[j] = res;
    }
    lastSev.set(moduleId, statusOf(res));
    const row = modulesEl.querySelector(`.mod[data-id="${CSS.escape(moduleId)}"]`);
    if (row) row.dataset.sev = statusOf(res);
    if (mode === "tech" && !viewing) {
      const old = resultsEl.querySelector(`.card[data-mod="${CSS.escape(moduleId)}"]`);
      const fresh = buildCard(res, { live: true, note });
      fresh.classList.add("flash");
      if (old) old.replaceWith(fresh);
      else resultsEl.appendChild(fresh);
      statusText.textContent = runSummary(live.results, false, live.results.length);
    }
    return res;
  }

  function confirmFix(action, f) {
    let notice = "";
    if (action.requires_admin && host && !host.elevated) {
      notice = host.platform === "windows"
        ? `<div class="warnbox">${I.shield}<div><p><b>Needs administrator rights.</b> It will stop with an error until itriage runs elevated.</p>
             ${host.can_relaunch_elevated ? '<button class="bk-btn xs" data-x="relaunch" type="button">Relaunch as admin</button>' : ""}</div></div>`
        : `<div class="notebox">${I.shield}<p>Needs root: you'll be asked for your password.</p></div>`;
    }
    const log = host && host.platform === "linux" ? "syslog" : "the Windows Application event log";
    return modal({
      title: `${I.bolt} ${esc(action.label)}`,
      body: `
        <p>${esc(fixDescription(action))}</p>
        <ul><li><b>${esc(f.label)}</b>: ${esc(f.value)}</li></ul>
        ${notice}
        <p>It's recorded in the audit log and in ${log}.</p>`,
      actions: [
        { label: "Cancel", value: false, focus: true },
        { label: notice && host.platform === "windows" ? "Run anyway" : "Run fix", hot: true, value: true },
      ],
      onMount: (scrim, close) => {
        const rl = scrim.querySelector('[data-x="relaunch"]');
        if (rl) rl.onclick = () => { close(false); relaunch(); };
      },
    });
  }

  /* -------------------------- compare ---------------------------- */
  function setDiff(diff) {
    diffIndex = new Map((diff ? diff.changes : []).map((c) => [c.module_id + "\n" + c.label, c]));
  }
  function changeFor(moduleId, label) {
    return diffIndex.get(moduleId + "\n" + label);
  }
  function badgeHtml(c) {
    if (c.kind === "new") return '<span class="dbadge new" title="Not a problem last run">NEW</span>';
    if (c.kind === "changed") {
      return RANK[c.after] > RANK[c.before]
        ? '<span class="dbadge worse" title="Worse than last run">WORSE</span>'
        : '<span class="dbadge better" title="Better than last run">BETTER</span>';
    }
    if (c.kind === "resolved" && c.after) return '<span class="dbadge better" title="A problem last run">BETTER</span>';
    return "";
  }
  function applyBadges() {
    resultsEl.querySelectorAll(".card[data-mod]").forEach((card) => {
      card.querySelectorAll(".fr[data-label]").forEach((row) => {
        const c = changeFor(card.dataset.mod, row.dataset.label);
        const fl = row.querySelector(".fl");
        if (c && fl && !fl.querySelector(".dbadge")) fl.insertAdjacentHTML("beforeend", badgeHtml(c));
      });
    });
  }

  function diffBanner(diff) {
    const box = document.createElement("div");
    box.className = "banner diff";
    const total = diff.new_issues + diff.resolved + diff.changed;
    const counts = total
      ? [
          diff.new_issues ? `<span class="count new">${diff.new_issues} new</span>` : "",
          diff.resolved ? `<span class="count resolved">${diff.resolved} resolved</span>` : "",
          diff.changed ? `<span class="count changed">${diff.changed} changed</span>` : "",
        ].join("")
      : '<span class="count none">no change in problems</span>';
    box.innerHTML = `
      <div class="banner-row">
        <span class="ttl">Since last run</span>
        <span class="sub">${esc(fmtLocal(diff.against))}</span>
        <span class="counts">${counts}</span>
        <span class="grow"></span>
        ${total ? '<button class="bk-btn xs" type="button" data-x="toggle" aria-expanded="false">Details</button>' : ""}
      </div>
      <ul class="diff-list" hidden>${diff.changes
        .map((c) => `
          <li><span class="k ${esc(c.kind)}">${esc(c.kind)}</span>
            <span class="w">${esc(c.label)} · ${esc(c.value)}<small>${esc(c.module)} · ${sevWord(c.before)} → ${sevWord(c.after)}</small></span></li>`)
        .join("")}</ul>`;
    const t = box.querySelector('[data-x="toggle"]');
    if (t) {
      t.onclick = () => {
        const list = box.querySelector(".diff-list");
        list.hidden = !list.hidden;
        t.setAttribute("aria-expanded", list.hidden ? "false" : "true");
        t.textContent = list.hidden ? "Details" : "Hide";
      };
    }
    return box;
  }
  function sevWord(s) {
    return s ? s : "gone";
  }

  /* ------------------------ report viewer ------------------------ */
  function showReport(report, diff, source, path) {
    if (running) { toast("Wait for the run to finish first."); return; }
    if (mode === "self") setMode("tech");
    viewing = { report, diff, source, path };
    resultsEl.innerHTML = "";
    setDiff(diff);
    logs.clear();
    const box = document.createElement("div");
    box.className = "banner viewing";
    const h = report.host || {};
    box.innerHTML = `
      <div class="banner-row">
        <span class="ttl">${source === "file" ? "Opened report" : "Saved run"}</span>
        <span class="sub">${esc(h.hostname || "unknown host")} · ${esc(fmtLocal(report.generated))} · ${report.results.length} module${report.results.length === 1 ? "" : "s"}${report.profile ? " · " + esc(report.profile) : ""}${report.cancelled ? " · cancelled" : ""}</span>
        <span class="grow"></span>
        <button class="bk-btn xs" type="button" data-x="back">${live.results.length ? "Back to this run" : "Close"}</button>
      </div>`;
    box.querySelector('[data-x="back"]').onclick = renderLive;
    resultsEl.appendChild(box);
    if (diff) resultsEl.appendChild(diffBanner(diff));
    report.results.forEach((r) => resultsEl.appendChild(buildCard(r, { live: false })));
    const worst = worstOf(report.results);
    statusEl.className = "status";
    statusText.textContent = `Viewing · ${report.results.length} module${report.results.length === 1 ? "" : "s"}` + (worst ? ` · worst: ${worst}` : "");
    exportBtn.disabled = report.results.length === 0;
    resultsEl.scrollTop = 0;
  }

  async function openHistory() {
    const scrim = document.createElement("div");
    scrim.className = "drawer-scrim";
    const d = document.createElement("aside");
    d.className = "drawer";
    d.setAttribute("role", "dialog");
    d.setAttribute("aria-modal", "true");
    d.setAttribute("aria-label", "Run history");
    d.innerHTML = `
      <div class="drawer-head"><h3>RUN HISTORY</h3><button class="bk-btn xs" data-x="close" type="button">Close</button></div>
      <div class="drawer-body"><div class="empty-note">Loading…</div></div>
      <div class="drawer-foot">
        <button class="bk-btn sm" data-x="open" type="button">${I.open}Open report</button>
        <button class="bk-btn sm" data-x="folder" type="button">Show folder</button>
      </div>`;
    const close = () => { scrim.remove(); d.remove(); document.removeEventListener("keydown", onKey); };
    const onKey = (e) => { if (e.key === "Escape") close(); };
    scrim.onclick = close;
    d.querySelector('[data-x="close"]').onclick = close;
    d.querySelector('[data-x="open"]').onclick = () => { close(); fileInput.click(); };
    d.querySelector('[data-x="folder"]').onclick = () => Promise.resolve(api.openHistoryFolder()).catch((e) => toast(errText(e)));
    document.addEventListener("keydown", onKey);
    document.body.append(scrim, d);
    d.querySelector('[data-x="close"]').focus();

    let list = [];
    try { list = await api.listHistory(); } catch (e) { toast(errText(e)); }
    const body = d.querySelector(".drawer-body");
    if (!list.length) {
      body.innerHTML = '<div class="empty-note">No saved runs yet. Every run is saved here automatically.</div>';
      return;
    }
    const current = viewing && viewing.path;
    body.innerHTML = list
      .map((m, i) => `
        <button class="hist${current === m.path ? " current" : ""}" type="button" data-i="${i}">
          <span class="when">${esc(fmtLocal(m.generated))}</span>
          <span class="chip sev-${esc(m.worst)}">${esc(m.worst)}</span>
          <span class="what">${esc(m.hostname)} · ${m.modules} module${m.modules === 1 ? "" : "s"}${m.cancelled ? " · cancelled" : ""}</span>
        </button>`)
      .join("");
    body.querySelectorAll(".hist").forEach((b) => {
      b.onclick = async () => {
        const m = list[Number(b.dataset.i)];
        try {
          const report = await api.loadReport(m.path);
          const diff = await api.compareWithPrevious(report);
          close();
          showReport(report, diff, "history", m.path);
        } catch (e) {
          toast(errText(e));
        }
      };
    });
  }

  async function onFilePicked() {
    const file = fileInput.files && fileInput.files[0];
    fileInput.value = "";
    if (!file) return;
    if (file.size > 20 * 1024 * 1024) { toast("That file is too big to be an itriage report."); return; }
    try {
      const text = await file.text();
      const r = await api.importReport(text);
      showReport(r.report, r.diff, "file");
      toast(r.saved ? "Report opened and added to history" : "Report opened");
    } catch (e) {
      toast(errText(e));
    }
  }

  /* --------------------------- export ------------------------------ */
  function toggleMenu(force) {
    const open = force === undefined ? exportMenu.hidden : force;
    if (open && exportBtn.disabled) return;
    exportMenu.hidden = !open;
    exportBtn.setAttribute("aria-expanded", open ? "true" : "false");
    if (open) exportMenu.querySelector("button").focus();
  }

  /** The report the user is looking at: a saved one, or the live run. */
  function currentReport() {
    if (viewing) return { report: viewing.report, diff: viewing.diff };
    const report = live.report || {
      schema: 1,
      generated: new Date().toISOString().replace(/\.\d+Z$/, "Z"),
      host,
      profile: profile && profile.source !== "built-in" ? profile.name : null,
      cancelled: false,
      results: live.results,
    };
    return { report, diff: live.diff };
  }

  function doExport(fmt) {
    const { report, diff } = currentReport();
    if (!report.results.length) return;
    if (fmt === "plain") copy(plainText(report, diff), "Ticket text copied");
    else if (fmt === "md") copy(markdown(report, diff), "Markdown copied");
    else if (fmt === "json") copy(JSON.stringify(report, null, 2), "JSON report copied");
    else if (fmt === "rich") copyRich(richHtml(report, diff), plainText(report, diff));
  }

  function hostLine(report) {
    const h = report.host || {};
    const parts = [h.hostname, h.os, h.elevated ? "elevated" : "standard user"].filter(Boolean);
    if (report.profile) parts.push("profile: " + report.profile);
    return parts.join(" · ");
  }
  function diffLine(diff) {
    if (!diff) return "";
    const bits = [];
    if (diff.new_issues) bits.push(`${diff.new_issues} new`);
    if (diff.resolved) bits.push(`${diff.resolved} resolved`);
    if (diff.changed) bits.push(`${diff.changed} changed`);
    return `Since the last run (${fmtUtc(diff.against)}): ${bits.length ? bits.join(", ") : "no change in problems"}`;
  }

  function plainText(report, diff) {
    const lines = [`itriage report — ${fmtUtc(report.generated)}`, hostLine(report)];
    if (report.cancelled) lines.push("Run was cancelled before every module finished.");
    if (diff) lines.push(diffLine(diff));
    lines.push("=".repeat(52), "");
    report.results.forEach((res) => {
      const sev = res.error ? "FAILED" : statusOf(res).toUpperCase();
      lines.push(`[${sev}] ${res.title}: ${res.error ? "couldn't run" : res.summary}`);
      if (res.error) {
        lines.push(`    error: ${res.error}`);
      } else {
        res.findings.forEach((f) => {
          const c = diff ? changeIn(diff, res.module_id, f.label) : null;
          lines.push(`    ${f.label}: ${f.value}${c && c.kind === "new" ? "  [NEW]" : ""}`);
          if (f.detail) lines.push(`        ${f.detail}`);
          if (f.kb) lines.push(`        KB: ${f.kb.title} <${f.kb.url}>`);
        });
      }
      lines.push("");
    });
    return lines.join("\n");
  }

  function markdown(report, diff) {
    const cell = (s) => String(s).replace(/\|/g, "\\|").replace(/\s*\n\s*/g, " ");
    const tag = { ok: "OK", info: "INFO", warning: "WARN", critical: "CRIT" };
    const out = [`## itriage report · ${report.host ? report.host.hostname : ""}`, "", `${fmtUtc(report.generated)} · ${hostLine(report)}`];
    if (diff) out.push("", `**${diffLine(diff)}**`);
    report.results.forEach((res) => {
      const sev = res.error ? "FAILED" : (tag[statusOf(res)] || "INFO");
      out.push("", `### [${sev}] ${res.title}: ${res.error ? "couldn't run" : res.summary}`, "");
      if (res.error) {
        out.push(`> ${res.error}`);
        return;
      }
      out.push("| | Finding | Value |", "|---|---|---|");
      res.findings.forEach((f) => {
        let value = cell(f.value);
        if (f.detail) value += `<br>${cell(f.detail)}`;
        if (f.kb) value += `<br>[${cell(f.kb.title)}](${f.kb.url})`;
        out.push(`| ${tag[f.severity] || "INFO"} | ${cell(f.label)} | ${value} |`);
      });
    });
    return out.join("\n") + "\n";
  }

  /** An HTML table with inline styles only: ticket editors (TeamDynamix,
   *  Outlook) keep inline styles and drop classes. */
  function richHtml(report, diff) {
    const color = { ok: "#1a7f37", info: "#57606a", warning: "#9a6700", critical: "#cf222e" };
    const base = "padding:4px 8px;border-top:1px solid #d0d7de;vertical-align:top";
    const sevCell = (s) =>
      `<td style="${base};color:${color[s] || color.info};font-weight:600;white-space:nowrap">${esc(String(s).toUpperCase())}</td>`;
    let rows = "";
    report.results.forEach((res) => {
      const s = res.error ? "critical" : statusOf(res);
      rows += `<tr><td colspan="3" style="padding:10px 8px 4px;border-top:2px solid #d0d7de;color:${color[s]}"><b>[${res.error ? "FAILED" : s.toUpperCase()}] ${esc(res.title)}</b> <span style="color:#1f2328">· ${esc(res.error ? "couldn't run" : res.summary)}</span></td></tr>`;
      if (res.error) {
        rows += `<tr>${sevCell("critical")}<td style="${base}" colspan="2">${esc(res.error)}</td></tr>`;
        return;
      }
      res.findings.forEach((f) => {
        const extra = (f.detail ? `<br><span style="color:#57606a">${esc(f.detail)}</span>` : "") +
          (f.kb ? `<br><a href="${esc(f.kb.url)}">${esc(f.kb.title)}</a>` : "");
        rows += `<tr>${sevCell(f.severity)}<td style="${base}">${esc(f.label)}</td><td style="${base}">${esc(f.value)}${extra}</td></tr>`;
      });
    });
    return `<div style="font-family:Segoe UI,Arial,sans-serif;font-size:13px;color:#1f2328">
      <p style="margin:0 0 6px"><b>itriage report</b> · ${esc(fmtUtc(report.generated))}<br>${esc(hostLine(report))}</p>
      ${diff ? `<p style="margin:0 0 8px"><b>${esc(diffLine(diff))}</b></p>` : ""}
      <table style="border-collapse:collapse;font-size:13px">${rows}</table></div>`;
  }

  function changeIn(diff, moduleId, label) {
    return diff.changes.find((c) => c.module_id === moduleId && c.label === label) || null;
  }

  async function copyRich(html, plain) {
    try {
      if (window.ClipboardItem && navigator.clipboard && navigator.clipboard.write) {
        await navigator.clipboard.write([
          new ClipboardItem({
            "text/html": new Blob([html], { type: "text/html" }),
            "text/plain": new Blob([plain], { type: "text/plain" }),
          }),
        ]);
        toast("Rich text copied: paste it into the ticket");
        return;
      }
    } catch (_) { /* fall back to plain text */ }
    copy(plain, "Copied as plain text (rich copy isn't available here)");
  }

  async function copy(text, okMsg) {
    try {
      await navigator.clipboard.writeText(text);
      toast(okMsg);
    } catch (_) {
      copyFallback(text);
    }
  }

  function copyFallback(text) {
    modal({
      title: "Copy",
      body: '<p>Direct copying was blocked here. Select all and copy:</p><textarea class="copy-fallback" readonly></textarea>',
      actions: [{ label: "Close", hot: true, value: true }],
      onMount: (scrim) => {
        const ta = scrim.querySelector("textarea");
        ta.value = text;
        ta.focus();
        ta.select();
      },
    });
  }

  /* ---------------------- self-service view ---------------------- */
  function selfIds() {
    return catalogue.filter((m) => SS_TITLES[m.id] && !m.mutating && !m.locked).map((m) => m.id);
  }

  function renderSelf() {
    const p = profile;
    const sub = p && p.source !== "built-in" ? p.name : "Quick health check";
    ssEl.innerHTML = `
      <div class="ss-wrap">
        <div class="ss-top">
          <span class="ss-logo">${I.logoCalm}</span>
          <span class="ss-brand"><b>Computer check</b><span>${esc(sub)}</span></span>
          <span class="grow"></span>
          ${canTech() ? '<button class="ss-tech" id="ssTech" type="button">Technician view</button>' : ""}
        </div>
        <section class="ss-pc" aria-label="This computer">
          <div class="ss-label">Your computer's name</div>
          <div class="ss-name"><code>${esc(host ? host.hostname : "—")}</code>
            <button class="ss-copy" id="ssCopyName" type="button">${I.copy}Copy</button></div>
          <p class="ss-meta">${host ? `<span>${esc(host.os)}</span>` : ""}<span>Give this name to the service desk when you call.</span></p>
        </section>
        <button class="ss-go" id="ssGo" type="button"${running ? " disabled" : ""}>${I.radar}<span>${running ? "Checking…" : live.results.length ? "Check again" : "Check my computer"}</span></button>
        <p class="ss-hint">Takes about a minute. Nothing on your computer is changed.</p>
        <div class="ss-progress" id="ssProg" hidden><div class="bar"><i id="ssBar"></i></div><p id="ssStep">Starting…</p></div>
        <div class="ss-results" id="ssResults"></div>
        <p class="ss-foot">itriage ${VERSION}${isTauri ? "" : " · preview with sample results"}</p>
      </div>`;
    const tech = el("ssTech");
    if (tech) tech.onclick = () => setMode("tech");
    el("ssCopyName").onclick = () => host && copy(host.hostname, "Computer name copied");
    el("ssGo").onclick = runSelf;
    if (live.results.length && !running) renderSelfResults();
  }

  async function runSelf() {
    if (running) return;
    const ids = selfIds();
    if (!ids.length) return;
    running = true;
    viewing = null;
    live = { results: [], report: null, diff: null };
    setDiff(null);
    logs.clear();
    const go = el("ssGo"), prog = el("ssProg"), bar = el("ssBar"), step = el("ssStep");
    const tech = el("ssTech");
    if (tech) tech.disabled = true;
    go.disabled = true;
    go.querySelector("span").textContent = "Checking…";
    prog.hidden = false;
    el("ssResults").innerHTML = "";
    try {
      const outcome = await api.run(ids, {
        onStart: ({ id, index, total }) => {
          step.textContent = `Checking ${(SS_TITLES[id] || "your computer").toLowerCase()}…`;
          bar.style.width = Math.round((index / Math.max(total, 1)) * 100) + "%";
        },
        onLog: ({ id, line }) => appendLog(id, line),
        onDone: (res) => {
          live.results.push(res);
          bar.style.width = Math.round((live.results.length / ids.length) * 100) + "%";
        },
      });
      if (outcome && outcome.report) {
        live.report = outcome.report;
        live.results = outcome.report.results;
        live.diff = outcome.diff || null;
      }
    } catch (e) {
      toast("The check stopped: " + errText(e));
    } finally {
      running = false;
      live.results.forEach((r) => lastSev.set(r.module_id, statusOf(r)));
      exportBtn.disabled = live.results.length === 0;
      if (mode === "self") renderSelf();
    }
  }

  function renderSelfResults() {
    const box = el("ssResults");
    if (!box) return;
    const results = live.results.filter((r) => SS_TITLES[r.module_id]);
    const issues = [], good = [], unchecked = [];
    results.forEach((r) => {
      const title = SS_TITLES[r.module_id];
      if (r.error) { unchecked.push(title); return; }
      const bad = r.findings.filter((f) => RANK[f.severity] >= 2);
      if (!bad.length) good.push(title);
      bad.forEach((f) => issues.push({ r, f, title }));
    });
    const n = issues.length;
    const verdict = n
      ? `<div class="ss-verdict bad">${I.warn}<div><h2>${n} thing${n === 1 ? " needs" : "s need"} attention</h2>
           <p>Try a fix below if there is one. If that doesn't sort it out, copy the details for the service desk.</p></div></div>`
      : `<div class="ss-verdict good">${I.okc}<div><h2>Everything looks good</h2>
           <p>We checked ${results.length} areas of this computer and found nothing that needs attention.</p></div></div>`;
    const cards = issues
      .map(({ r, f, title }, i) => {
        const fixable = f.action && (!f.action.requires_admin || (host && host.elevated));
        return `
          <div class="ss-issue${f.severity === "critical" ? " crit" : ""}">
            <h4>${esc(title)}: ${esc(f.label)}</h4>
            <p>${esc(f.value)}${f.detail ? ". " + esc(f.detail) : ""}</p>
            <div class="row">
              ${fixable ? `<button class="ss-fix" type="button" data-i="${i}">${I.bolt}${esc(f.action.label)}</button>` : '<span class="ss-desk">The service desk can help with this.</span>'}
              ${f.kb ? `<a class="ss-kb" data-kb href="${esc(f.kb.url)}" target="_blank" rel="noopener noreferrer">How to fix it: ${esc(f.kb.title)}</a>` : ""}
              <span class="ss-slot"></span>
            </div>
          </div>`;
      })
      .join("");
    const chips = good.map((t) => `<span class="ss-chip">${I.okc}${esc(t)}</span>`).join("");
    box.innerHTML = `
      ${verdict}
      ${cards}
      ${good.length ? `<div class="ss-good"><h3>Looks good</h3><div class="ss-chips">${chips}</div></div>` : ""}
      ${unchecked.length ? `<p class="ss-hint">Couldn't check: ${esc(unchecked.join(", "))}.</p>` : ""}
      <div class="ss-share">
        <p>Calling or emailing the service desk? Copy the details and paste them into your message.</p>
        <button class="ss-copy" id="ssShare" type="button">${I.copy}Copy details for the service desk</button>
      </div>`;
    el("ssShare").onclick = () => {
      const { report, diff } = currentReport();
      copy(plainText(report, diff), "Details copied: paste them into your message");
    };
    box.querySelectorAll("[data-kb]").forEach((a) => wireKb(a));
    box.querySelectorAll(".ss-fix").forEach((b) => {
      const it = issues[Number(b.dataset.i)];
      b.onclick = () => selfFix(b, it);
    });
  }

  async function selfFix(btn, it) {
    if (fixBusy || running) return;
    const ok = await modal({
      title: esc(it.f.action.label),
      body: `<p>${esc(fixDescription(it.f.action))}</p>`,
      actions: [{ label: "Not now", value: false, focus: true }, { label: "Go ahead", hot: true, value: true }],
    });
    if (!ok) return;
    const slot = btn.parentElement.querySelector(".ss-slot");
    fixBusy = true;
    setFixButtons(false);
    slot.innerHTML = '<span class="ss-note">Working…</span>';
    let message = null;
    try {
      message = await api.runFix(it.f.action.id, it.f.action.target || null);
    } catch (e) {
      slot.innerHTML = `<span class="ss-note err">${I.xc}That didn't work: ${esc(errText(e))}</span>`;
    } finally {
      fixBusy = false;
      setFixButtons(true);
    }
    if (message != null) {
      toast(message);
      await recheck(it.r.module_id, message);
      if (mode === "self") renderSelfResults();
    }
  }

  /* -------------------------- modals ------------------------------ */
  /** A dialog. Resolves with the chosen action's value (undefined if dismissed). */
  function modal({ title, body, actions, onMount }) {
    return new Promise((resolve) => {
      const scrim = document.createElement("div");
      scrim.className = "scrim";
      scrim.innerHTML = `
        <div class="modal" role="dialog" aria-modal="true" aria-labelledby="m-title">
          <div class="hazard"></div>
          <div class="modal-body">
            <h3 id="m-title">${title}</h3>
            ${body}
            <div class="modal-actions">${actions
              .map((a, i) => `<button class="bk-btn${a.hot ? " hot" : ""}" data-i="${i}" type="button">${esc(a.label)}</button>`)
              .join("")}</div>
          </div>
        </div>`;
      const close = (v) => { scrim.remove(); document.removeEventListener("keydown", onKey); resolve(v); };
      const onKey = (e) => { if (e.key === "Escape") close(undefined); };
      scrim.addEventListener("click", (e) => { if (e.target === scrim) close(undefined); });
      scrim.querySelectorAll("[data-i]").forEach((b) => { b.onclick = () => close(actions[Number(b.dataset.i)].value); });
      document.addEventListener("keydown", onKey);
      document.body.appendChild(scrim);
      if (onMount) onMount(scrim, close);
      const fi = Math.max(0, actions.findIndex((a) => a.focus));
      if (!scrim.querySelector("textarea")) scrim.querySelector(`[data-i="${fi}"]`).focus();
    });
  }

  function confirmRun(mods) {
    const needAdmin = mods.filter((m) => m.requires_admin);
    let notice = "";
    if (needAdmin.length && host && !host.elevated) {
      const names = needAdmin.map((m) => `<b>${esc(m.title)}</b>`).join(" and ");
      notice = host.platform === "windows"
        ? `<div class="warnbox">${I.shield}<div><p><b>Not running as administrator.</b> ${names}
             will stop with an error until itriage runs elevated.</p>
             ${host.can_relaunch_elevated ? '<button class="bk-btn xs" data-x="relaunch" type="button">Relaunch as admin</button>' : ""}
           </div></div>`
        : `<div class="notebox">${I.shield}<p>${esc(host.elevation_note)} Applies to ${names}.</p></div>`;
    }
    return modal({
      title: `${I.warn} Confirm system changes`,
      body: `
        <p>These selected modules modify the system, not just read it:</p>
        <ul>${mods.map((m) => `<li><b>${esc(m.title)}</b>: ${esc(m.warning || m.description)}</li>`).join("")}</ul>
        ${notice}`,
      actions: [
        { label: "Cancel", value: false, focus: true }, // safe default for a destructive prompt
        { label: notice && host.platform === "windows" ? "Run anyway" : "Run", hot: true, value: true },
      ],
      onMount: (scrim, close) => {
        const rl = scrim.querySelector('[data-x="relaunch"]');
        if (rl) rl.onclick = () => { close(false); relaunch(); };
      },
    }).then(Boolean);
  }

  let toastTimer;
  function toast(msg) {
    const old = document.querySelector(".toast");
    if (old) old.remove();
    const t = document.createElement("div");
    t.className = "toast";
    t.setAttribute("role", "status");
    t.textContent = msg;
    document.body.appendChild(t);
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => t.remove(), 3200);
  }

  /* --------------------------- helpers ----------------------------- */
  function statusOf(res) {
    if (res.error) return "critical";
    let worst = "ok";
    res.findings.forEach((f) => { if ((RANK[f.severity] ?? 1) > RANK[worst]) worst = f.severity; });
    return worst;
  }
  function worstOf(results) {
    const order = ["ok", "info", "warning", "critical"];
    let idx = -1;
    results.forEach((r) => { idx = Math.max(idx, order.indexOf(statusOf(r))); });
    return idx >= 2 ? order[idx] : null; // only worth calling out at warning and above
  }
  function errText(e) {
    return String(e && e.message ? e.message : e);
  }
  function fmtLocal(iso) {
    const d = new Date(iso);
    if (isNaN(d)) return String(iso);
    try {
      return d.toLocaleString([], { dateStyle: "medium", timeStyle: "short" });
    } catch (_) {
      return d.toLocaleString();
    }
  }
  /** "2026-11-06 19:22 UTC": unambiguous for tickets that cross time zones. */
  function fmtUtc(iso) {
    return String(iso).replace("T", " ").replace(/:\d\d(\.\d+)?Z$/, " UTC");
  }
  function clamp(v, lo, hi) {
    return Math.min(Math.max(v, lo), hi);
  }
  function pad2(n) {
    return String(n).padStart(2, "0");
  }
  function fmtSecs(s) {
    if (s < 60) return s.toFixed(1) + " s";
    const m = Math.floor(s / 60);
    return `${m}m ${Math.floor(s - m * 60)}s`;
  }
  function fmtMs(ms) {
    return ms < 1000 ? `${ms} ms` : fmtSecs(ms / 1000);
  }
  function esc(s) {
    return String(s).replace(/[&<>"']/g, (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  }
  function loadSelection() {
    const defaults = CATALOGUE.filter((m) => !m.mutating).map((m) => m.id);
    try {
      const saved = JSON.parse(localStorage.getItem(STORE_KEY) || "null");
      if (Array.isArray(saved)) return saved.filter((x) => typeof x === "string");
    } catch (_) { /* storage unavailable */ }
    return defaults;
  }
  function saveSelection() {
    try { localStorage.setItem(STORE_KEY, JSON.stringify([...selected])); } catch (_) { /* ignore */ }
  }

  /* --------------------------- bridges ----------------------------- */
  function realApi() {
    const { invoke } = window.__TAURI__.core;
    const { listen } = window.__TAURI__.event;
    return {
      listModules: () => invoke("list_modules"),
      listFixes: () => invoke("list_fixes"),
      getProfile: () => invoke("get_profile"),
      hostContext: () => invoke("get_host_context"),
      telemetry: () => invoke("get_telemetry"),
      relaunchElevated: () => invoke("relaunch_elevated"),
      run: async (ids, h) => {
        const offs = await Promise.all([
          listen("module-start", (e) => h.onStart(e.payload)),
          listen("module-log", (e) => h.onLog(e.payload)),
          listen("module-done", (e) => h.onDone(e.payload)),
        ]);
        try {
          return await invoke("run_modules", { selected: ids });
        } finally {
          offs.forEach((off) => off());
        }
      },
      cancel: () => invoke("cancel_run"),
      recheck: async (id) => {
        const outcome = await invoke("run_modules", { selected: [id], record: false });
        return (outcome && outcome.report.results[0]) || null;
      },
      runFix: (id, target) => invoke("run_fix", { id, target }),
      listHistory: () => invoke("list_history"),
      loadReport: (path) => invoke("load_report", { path }),
      importReport: (text) => invoke("import_report", { text }),
      compareWithPrevious: (report) => invoke("compare_with_previous", { report }),
      openLink: (url) => invoke("open_link", { url }),
      openHistoryFolder: () => invoke("open_history_folder"),
    };
  }

  /** Simulated telemetry for the browser preview: random walks with spikes,
   *  busier while a sequence runs. */
  function mockTelemetry() {
    const total = 16 * 1073741824;
    let cpu = 16, mem = 62, net = 2.2e5, disk = 9e5;
    const cores = Array.from({ length: 14 }, () => 8 + Math.random() * 16);
    const walk = (v, lo, hi, jitter, pull, target) =>
      clamp(v + (Math.random() - 0.5) * jitter + (target - v) * pull, lo, hi);
    return () => {
      cpu = walk(cpu, 2, 100, 16, 0.25, running ? 42 : 14);
      if (Math.random() < 0.07) cpu = Math.min(100, cpu + 25 + Math.random() * 30);
      cores.forEach((v, i) => {
        cores[i] = walk(v, 0, 100, 26, 0.35, cpu) + (running && i === 3 ? 45 : 0);
        cores[i] = clamp(cores[i], 0, 100);
      });
      mem = walk(mem, 30, 92, 1.2, 0.05, running ? 66 : 62);
      net = walk(net, 2e3, 9e6, 4e5, 0.2, running ? 2.4e6 : 1.8e5) * (Math.random() < 0.1 ? 3 : 1);
      disk = walk(disk, 0, 3e8, 2e6, 0.3, running ? 3.5e7 : 6e5) * (Math.random() < 0.12 ? 4 : 1);
      return {
        cpu, cores: cores.slice(), mem_pct: mem, mem_used: (mem / 100) * total, mem_total: total,
        net_rx: net * 0.86, net_tx: net * 0.14, disk_read: disk * 0.7, disk_write: disk * 0.3,
        fullest_pct: 98.5, fullest_mount: "C:\\",
      };
    };
  }

  function mockApi() {
    const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
    const clone = (x) => JSON.parse(JSON.stringify(x));
    const fixed = new Set();
    const saved = new Map();
    let cancelFlag = false;
    const allowed = (id, target) =>
      MOCK_FIXES.some((e) => (e.includes(":") ? e === `${id}:${target}` : e === id && (id !== "start-service" || !target)));
    const lockFor = (m) =>
      m.mutating && m.id.startsWith("update.") && !MOCK_PROFILE.policy.allow_installs
        ? "Blocked by site policy: updates are deployed centrally here."
        : undefined;
    /** A sample result, with fixes the user already ran showing as fixed. */
    const result = (id, rechecked) => {
      const m = CATALOGUE.find((x) => x.id === id);
      const r = clone(MOCK_RESULTS[id] || R(id, m ? m.title : id, m ? m.category : "system", "(no sample)", 5, []));
      let changed = false;
      r.findings = r.findings.map((f) => {
        if (f.action && !allowed(f.action.id, f.action.target)) delete f.action;
        if (f.action && fixed.has(f.action.id + ":" + (f.action.target || ""))) {
          changed = true;
          return { label: f.label, value: FIXED_VALUE[f.action.id] || "fixed", severity: "ok" };
        }
        return f;
      });
      if (changed || rechecked) {
        const left = r.findings.filter((f) => RANK[f.severity] >= 2).length;
        r.summary = left ? `${left} item${left === 1 ? "" : "s"} still need${left === 1 ? "s" : ""} attention` : "All clear";
      }
      return r;
    };
    const diffFor = (results) => {
      const byMod = new Map(results.map((r) => [r.module_id, r]));
      const changes = MOCK_DIFF.changes.filter((c) => {
        const r = byMod.get(c.module_id);
        if (!r) return false;
        if (c.kind === "resolved") return true;
        const f = r.findings.find((x) => x.label === c.label);
        return !!f && RANK[f.severity] >= 2;
      });
      const count = (k) => changes.filter((c) => c.kind === k).length;
      return { against: MOCK_DIFF.against, changes, new_issues: count("new"), resolved: count("resolved"), changed: count("changed") };
    };
    /** The run before the latest: Spooler down, printers and clock fine. */
    const savedReport = (meta) => {
      if (saved.has(meta.path)) return clone(saved.get(meta.path));
      const ids = CATALOGUE.filter((m) => !m.mutating).map((m) => m.id).slice(0, meta.modules);
      const results = ids.map((id) => clone(MOCK_RESULTS[id])).map((r) => {
        r.findings.forEach((f) => { delete f.action; });
        if (r.module_id === "proc.services") {
          r.summary = "184 running · 2 automatic services not running";
          r.findings.splice(1, 0, F("Print Spooler (Spooler)", "stopped · exit 1067 · Automatic", "critical", "The process terminated unexpectedly. (os error 1067)"));
        }
        if (r.module_id === "desk.printers") {
          r.summary = "2 printers ready";
          r.findings[1] = F("Ward 4 LaserJet (default)", "ready", "ok", "HP Universal Printing PCL 6 · port IP_10.20.30.40");
        }
        if (r.module_id === "desk.time") {
          r.summary = "Clock in sync with DC01";
          r.findings[1] = F("Offset vs DC01", "412 ms slow", "ok", "round trip 3 ms · server stratum 2");
        }
        if (r.module_id === "system.disk") r.findings[0] = F("C:\\", "38.1 GB free of 476.9 GB (92% used) · NTFS", "warning");
        return r;
      });
      const h = meta.hostname === MOCK_HOST.hostname ? clone(MOCK_HOST) : Object.assign(clone(MOCK_HOST), { hostname: meta.hostname, os: "Windows 11 Enterprise 23H2" });
      return { schema: 1, generated: meta.generated, host: h, profile: MOCK_PROFILE.name, cancelled: meta.cancelled, results };
    };
    return {
      listModules: async () => CATALOGUE.map((m) => Object.assign({}, m, lockFor(m) ? { locked: lockFor(m) } : {})),
      listFixes: async () => FIX_CATALOGUE,
      getProfile: async () => MOCK_PROFILE,
      hostContext: async () => host,
      telemetry: async () => mockSample(),
      relaunchElevated: async () => {
        await sleep(250);
        host = Object.assign({}, host, { elevated: true, can_relaunch_elevated: false, elevation_note: "Running as administrator." });
        renderHost();
        if (mode === "tech" && !viewing) renderLive();
        toast("Preview: now shown running as administrator");
      },
      run: async (ids, h) => {
        cancelFlag = false;
        const chosen = CATALOGUE.filter((m) => ids.includes(m.id));
        const total = chosen.length;
        const results = [];
        for (let i = 0; i < total && !cancelFlag; i++) {
          const m = chosen[i];
          h.onStart({ id: m.id, title: m.title, index: i, total });
          let res;
          if (m.requires_admin && !host.elevated) {
            await sleep(180);
            res = { module_id: m.id, title: m.title, category: m.category, findings: [], summary: "", error: ADMIN_REQUIRED, duration_ms: 1 };
          } else {
            for (const line of MOCK_LOGS[m.id] || []) {
              await sleep(110 + Math.random() * 170);
              h.onLog({ id: m.id, line });
            }
            await sleep(220 + Math.random() * 320);
            res = result(m.id, false);
          }
          results.push(res);
          h.onDone(res);
        }
        const report = {
          schema: 1, generated: new Date().toISOString().replace(/\.\d+Z$/, "Z"), host: clone(host),
          profile: MOCK_PROFILE.name, cancelled: cancelFlag, results,
        };
        const stamp = report.generated.replace(/[-:]/g, "");
        const path = `${HIST_DIR}${stamp}_${host.hostname}.json`;
        saved.set(path, clone(report));
        MOCK_HISTORY.unshift({ path, generated: report.generated, hostname: host.hostname, modules: results.length, worst: worstOf(results) || (results.some((r) => statusOf(r) === "info") ? "info" : "ok"), cancelled: report.cancelled });
        return { report, saved: path, save_error: null, diff: report.cancelled ? null : diffFor(results) };
      },
      cancel: async () => { cancelFlag = true; return true; },
      recheck: async (id) => { await sleep(650); return result(id, true); },
      runFix: async (id, target) => {
        await sleep(900 + Math.random() * 500);
        const spec = FIX_CATALOGUE.find((f) => f.id === id);
        if (!spec) throw `Unknown fix \`${id}\`.`;
        if (!allowed(id, target)) throw "Blocked by site policy: this fix isn't allowed on this machine.";
        if (spec.requires_admin && !host.elevated) throw ADMIN_REQUIRED;
        fixed.add(id + ":" + (target || ""));
        return FIX_MESSAGES[id](target);
      },
      listHistory: async () => { await sleep(120); return MOCK_HISTORY.slice(); },
      loadReport: async (path) => {
        await sleep(120);
        const meta = MOCK_HISTORY.find((m) => m.path === path);
        if (!meta) throw "That file isn't in the run history.";
        return savedReport(meta);
      },
      importReport: async (text) => {
        let r;
        try { r = JSON.parse(text); } catch (e) { throw "Not an itriage report: " + e.message; }
        if (!r || !Array.isArray(r.results) || !r.host || !r.generated) throw "Not an itriage report: missing host, generated or results.";
        return { report: r, diff: null, saved: null };
      },
      compareWithPrevious: async (report) =>
        report.generated === "2026-11-05T19:02:11Z"
          ? { against: "2026-11-03T14:15:30Z", new_issues: 1, resolved: 0, changed: 0,
              changes: [{ module_id: "proc.services", module: "Services", label: "Print Spooler (Spooler)", kind: "new", before: null, after: "critical", value: "stopped · exit 1067 · Automatic" }] }
          : null,
      openLink: async (url) => toast("Preview: this opens " + url),
      openHistoryFolder: async () => toast("Preview: this opens " + HIST_DIR.replace(/\\$/, "")),
    };
  }
})();
