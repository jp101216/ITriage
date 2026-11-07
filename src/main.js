/* itriage frontend logic — red HUD edition.
 *
 * Runs in two modes from the same code:
 *   • Inside the Tauri window → window.__TAURI__ exists; calls the real Rust
 *     commands, listens for streamed progress events, and polls live telemetry.
 *   • In a plain browser → no __TAURI__; a mock drives the same UI with
 *     sample data and a simulated telemetry feed, so the interface can be
 *     previewed without building anything.
 */
(function () {
  "use strict";

  const isTauri = !!(window.__TAURI__ && window.__TAURI__.core);
  const VERSION = "v0.3";

  /* ----------------------------- icons ----------------------------- */
  const sv = (body, extra) =>
    `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"${extra || ""}>${body}</svg>`;
  const I = {
    logo: '<svg viewBox="0 0 24 24" fill="none" stroke="#ff3b36" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M2 12h4l2-5 3 10 2.5-7 1.5 2H22"/></svg>',
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
   * the list then comes live from Rust (with OS-specific descriptions). */
  const mod = (id, title, category, description, extra) =>
    Object.assign(
      { id, title, category, description, mutating: false, requires_admin: false, platforms: ["windows", "linux"] },
      extra || {}
    );
  const CATALOGUE = [
    mod("system.info", "System information", "system", "OS, kernel, hostname, uptime, CPU and total memory."),
    mod("system.disk", "Disk usage", "system", "Free vs. total space per volume. Warns under 10% free, critical under 5%."),
    mod("system.memory", "Memory usage", "system", "RAM and swap in use. Warns over 85% used, critical over 95%."),
    mod("proc.top", "Top processes", "processes", "The biggest memory users plus any CPU hogs. Flags anything pinning a core or holding a quarter of RAM."),
    mod("proc.services", "Services", "processes", "Automatic services that aren't running, with exit codes. Skips trigger-start services that stop by design."),
    mod("net.connectivity", "Network connectivity", "network", "Interface IPs, DNS resolution, and an outbound TCP reachability test."),
    mod("eventlog.errors", "Recent errors", "eventlog", "Critical and error events from the System and Application logs in the last 24 hours, grouped by source and event ID."),
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

  const CAT_ORDER = ["system", "processes", "network", "eventlog", "fixes", "updates"];
  const CAT_LABEL = {
    system: "System",
    processes: "Processes & services",
    network: "Network",
    eventlog: "Event log",
    fixes: "Fixes",
    updates: "Updates",
  };
  /** Short HUD codes shown next to each module title. */
  const CODES = {
    "system.info": "SYS-INF", "system.disk": "DSK-USE", "system.memory": "MEM-USE",
    "proc.top": "PROC-TOP", "proc.services": "SVC-HLT", "net.connectivity": "NET-CON",
    "eventlog.errors": "EVT-ERR", "fix.temp": "FIX-TMP", "fix.dns": "FIX-DNS",
    "update.scan": "UPD-SCN", "update.apply": "UPD-INS", "update.firmware": "UPD-FRM",
  };
  /** Cards with a live mini-chart fed by the telemetry sampler. */
  const LIVE_GLYPH = { "system.info": "cpu", "system.disk": "disk", "system.memory": "mem", "proc.top": "cores" };
  const STATIC_GLYPH = {
    "net.connectivity": I.nodes, "proc.services": I.rack, "eventlog.errors": I.alert,
    "fix.temp": I.trash, "fix.dns": I.refresh, "update.scan": I.radar,
    "update.apply": I.download, "update.firmware": I.chip,
  };

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
  const F = (label, value, severity, detail) => {
    const f = { label, value, severity: severity || "info" };
    if (detail) f.detail = detail;
    return f;
  };
  const R = (module_id, title, category, summary, duration_ms, findings) => ({
    module_id, title, category, findings, summary, error: null, duration_ms,
  });
  const CU_TITLE = "2026-11 Cumulative Update for Windows 11 Version 24H2 for x64-based Systems";
  const NET_TITLE = "2026-11 Cumulative Update for .NET Framework 3.5 and 4.8.1 for Windows 11, version 24H2";
  const DEF_TITLE = "Security Intelligence Update for Microsoft Defender Antivirus";
  const MOCK_RESULTS = {
    "system.info": R("system.info", "System information", "system", "WS-FLINT-07, up 3d 7h 12m", 41, [
      F("Hostname", "WS-FLINT-07"), F("OS", "Windows 11 Pro 24H2"), F("Kernel", "10.0.26100"),
      F("Architecture", "x86_64"), F("CPU", "AMD Ryzen 9 7900X (24 logical cores)"),
      F("Total memory", "64.0 GB"), F("Uptime", "3d 7h 12m"), F("Manufacturer", "Dell Inc."),
    ]),
    "system.disk": R("system.disk", "Disk usage", "system", "Low free space on at least one volume.", 18, [
      F("C:\\", "7.2 GB free of 476.9 GB (98% used) · NTFS", "warning"),
      F("D:\\", "812.4 GB free of 1.8 TB (56% used) · NTFS", "ok"),
    ]),
    "system.memory": R("system.memory", "Memory usage", "system", "41% RAM in use", 6, [
      F("RAM", "26.1 GB used of 64.0 GB (41%), 37.9 GB available", "ok"),
      F("Swap / page file", "1.2 GB used of 9.0 GB (13%)", "ok"),
    ]),
    "proc.top": R("proc.top", "Top processes", "processes", "214 processes running · 1 using heavy CPU or memory", 214, [
      F("MsMpEng.exe (pid 2680)", "640.0 MB RAM · 87.5% CPU", "warning"),
      F("chrome.exe (pid 8124)", "2.1 GB RAM · 3.4% CPU"),
      F("Code.exe (pid 4410)", "1.4 GB RAM · 1.1% CPU"),
      F("Teams.exe (pid 9332)", "402.0 MB RAM · 0.9% CPU"),
      F("explorer.exe (pid 5120)", "188.0 MB RAM · 0.2% CPU"),
    ]),
    "proc.services": R("proc.services", "Services", "processes", "187 running · 2 automatic services not running", 96, [
      F("Running services", "187", "ok"),
      F("Print Spooler (Spooler)", "stopped · exit 1067 · Automatic", "critical", "The process terminated unexpectedly. (os error 1067)"),
      F("Windows Defender Firewall (mpssvc)", "stopped · Automatic", "warning"),
      F("Windows Search (WSearch)", "stopped · Automatic (delayed)", "info"),
      F("Stopped by design (skipped)", "41 trigger-start/per-user, 3 self-stopping updaters"),
    ]),
    "net.connectivity": R("net.connectivity", "Network connectivity", "network", "Connectivity OK.", 3140, [
      F("Interface Ethernet", "192.168.1.42/24, fe80::1a2b/64"),
      F("DNS resolution (example.com)", "resolved", "ok"),
      F("Outbound TCP (1.1.1.1:443)", "reachable", "ok"),
    ]),
    "eventlog.errors": R("eventlog.errors", "Recent errors", "eventlog", "1 critical, 11 errors in the last 24h (4 sources)", 380, [
      F("Kernel-Power 41 · System", "1× · last 5h ago", "critical",
        "The system has rebooted without cleanly shutting down first. This error could be caused if the system stopped responding, crashed, or lost power unexpectedly."),
      F("Service Control Manager 7031 · System", "2× · last 3h ago", "warning",
        "The Print Spooler service terminated unexpectedly. It has done this 2 time(s). The following corrective action will be taken in 60000 milliseconds: Restart the service."),
      F("Application Error 1000 · Application", "3× · last 47m ago", "warning",
        "Faulting application name: Teams.exe, version: 24295.605.3225.8804, time stamp: 0x6720a1b3"),
      F("DistributedCOM 10016 · System", "6× · last 12m ago", "info",
        "The application-specific permission settings do not grant Local Activation permission for the COM Server application (known DCOM noise, safe to ignore)"),
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
    "fix.temp": ["Clearing C:\\Users\\jparker\\AppData\\Local\\Temp"],
    "update.scan": ["Searching Windows Update…", "Checking winget for app upgrades…"],
    "update.apply": [
      "Searching Windows Update…",
      "3 update(s) to install",
      "Downloading 1/3: " + CU_TITLE,
      "Downloading 2/3: " + NET_TITLE,
      "Already downloaded 3/3: " + DEF_TITLE,
      "Installing 3 update(s); this can take a while…",
      "KB5070001: installed",
      "KB5070002: installed",
      "KB2267602: installed",
      "Upgrading apps with winget…",
      "Found Google Chrome [Google.Chrome] Version 131.0.6778.70",
      "This application is licensed to you by its owner.",
      "Successfully verified installer hash",
      "Starting package install...",
      "Successfully installed",
      "Found Mozilla Firefox [Mozilla.Firefox] Version 132.0.1",
      "Successfully installed",
      "Found 7-Zip [7zip.7zip] Version 24.08",
      "Successfully installed",
      "Found Microsoft Visual Studio Code [Microsoft.VisualStudioCode] Version 1.95.1",
      "Successfully installed",
    ],
    "update.firmware": [
      "Dell Inc. detected; running Dell Command | Update",
      "Checking for updates...",
      "Scanning system devices...",
      "Determining available updates...",
      "2 updates found",
      "Downloading: Intel Wi-Fi 6E AX211 Driver",
      "Downloading: Dell System BIOS 1.23.0",
      "Installing: Intel Wi-Fi 6E AX211 Driver",
      "Installing: Dell System BIOS 1.23.0",
      "Execution completed. A restart is required.",
    ],
  };

  /* --------------------------- state ------------------------------- */
  const STORE_KEY = "itriage.selection.v2";
  const HISTORY = 90; // telemetry samples kept (one per second)
  let catalogue = CATALOGUE;
  const selected = new Set(loadSelection());
  let running = false;
  let lastResults = [];
  let host = isTauri ? null : Object.assign({}, MOCK_HOST);
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
    <section class="hud brackets" aria-label="Live telemetry">
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
    <header class="brandbar">
      <div class="brand">
        <span class="logo">${I.logo}</span>
        <span class="name">itriage</span>
        <span class="brk">${VERSION}</span>
        ${isTauri ? "" : '<span class="tag preview">PREVIEW · SAMPLE DATA</span>'}
      </div>
      <dl class="stats">
        <div><dt>TARGET:</dt><dd class="hot" id="stTarget">—</dd></div>
        <div><dt>PRIV</dt><dd id="stPriv">—</dd></div>
        <div><dt>OS:</dt><dd id="stOs">—</dd></div>
        <div><dt>STATUS</dt><dd class="hot" id="stStatus">[READY]</dd></div>
      </dl>
    </header>
    <div class="workspace">
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
          <button class="bk-btn sm" id="copyJson" type="button" disabled>JSON</button>
          <button class="bk-btn sm" id="copyTicket" type="button" disabled>Ticket text</button>
        </div>
        <div class="progress-wrap"><div class="progress-bar" id="progress"></div></div>
        <div class="results" id="results"></div>
      </main>
    </div>`;

  const el = (id) => document.getElementById(id);
  const modulesEl = el("modules"), countEl = el("count"), modTotal = el("modTotal"),
    runBtn = el("run"), runIcon = el("runIcon"), runLabel = el("runLabel"), runK = el("runk"),
    statusEl = el("status"), statusText = el("statusText"), elapsedEl = el("elapsed"),
    progressEl = el("progress"), resultsEl = el("results"),
    copyJsonBtn = el("copyJson"), copyTicketBtn = el("copyTicket"),
    stTarget = el("stTarget"), stPriv = el("stPriv"), stOs = el("stOs"), stStatus = el("stStatus"),
    hudState = el("hudState"), microPlat = el("microPlat");
  const scope = (name) => document.querySelector(`[data-scope="${name}"] canvas`);
  const scopes = { cpu: scope("cpu"), net: scope("net"), cores: scope("cores"), mem: scope("mem"), disk: scope("disk") };
  const lbl = { cpu: el("lblCpu"), net: el("lblNet"), cores: el("lblCores"), mem: el("lblMem"), disk: el("lblDisk") };

  el("allChecks").onclick = () => {
    if (running) return;
    catalogue.forEach((m) => { if (!m.mutating) selected.add(m.id); });
    syncRows();
  };
  el("none").onclick = () => { if (!running) { selected.clear(); syncRows(); } };
  runBtn.onclick = onRun;
  copyJsonBtn.onclick = () => copy(JSON.stringify(exportJson(), null, 2), "JSON copied");
  copyTicketBtn.onclick = () => copy(ticketText(lastResults), "Ticket text copied");

  // Paint immediately from the bundled catalogue so the first frame is
  // complete, then refresh from the live source (Rust, in the Tauri app).
  if (mockSample) for (let i = 0; i < HISTORY; i++) ingest(mockSample());
  renderHost();
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
      const live = await api.listModules();
      if (Array.isArray(live) && live.length) catalogue = live;
    } catch (_) { /* keep the bundled catalogue */ }
    const known = new Set(catalogue.map((m) => m.id));
    [...selected].forEach((id) => { if (!known.has(id)) selected.delete(id); });
    try { host = await api.hostContext(); } catch (_) { /* stats stay minimal */ }
    renderHost();
    renderModules(); // re-render so WIN/LIN chips reflect this host
    syncRows();
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
    if (teleBusy || document.hidden) return;
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
    if (!tele) return;
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
  }

  async function relaunch() {
    try {
      await api.relaunchElevated(); // the Tauri app exits when this succeeds
    } catch (e) {
      toast(String(e && e.message ? e.message : e) || "Elevation was cancelled");
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
          (m.mutating ? '<span class="badge mut">CHANGES SYSTEM</span>' : "") +
          (m.requires_admin ? '<span class="badge admin">ADMIN</span>' : "");
        const live = LIVE_GLYPH[m.id];
        const glyph = live ? `<canvas data-mini="${live}"></canvas>` : STATIC_GLYPH[m.id] || "";
        html += `
          <div class="mod" data-id="${esc(m.id)}" role="checkbox" tabindex="0" aria-checked="false">
            <span class="box"><span class="plus">+</span>${I.check}</span>
            <span class="body">
              <span class="t">
                <span class="title">${esc(m.title)}</span>
                <span class="code">[${esc(CODES[m.id] || m.id.toUpperCase().replace(/\./g, "-"))}]</span>
                <span class="led" title="Last result"></span>
                <span class="chips">${plats}${badges}</span>
              </span>
              <span class="d">${esc(m.description)}</span>
            </span>
            <span class="glyph" aria-hidden="true">${glyph}</span>
          </div>`;
      });
    });
    modulesEl.innerHTML = html;
    modTotal.textContent = `[${pad2(catalogue.length)}]`;
    modulesEl.querySelectorAll(".mod").forEach((row) => {
      const id = row.dataset.id;
      if (lastSev.has(id)) row.dataset.sev = lastSev.get(id);
      const toggle = () => {
        if (running) return;
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
    runBtn.disabled = running || n === 0;
    saveSelection();
  }

  /* ----------------------------- run ------------------------------- */
  async function onRun() {
    if (running || selected.size === 0) return;
    const chosen = catalogue.filter((m) => selected.has(m.id));
    const mutating = chosen.filter((m) => m.mutating);
    if (mutating.length && !(await confirmRun(mutating))) return;
    await startRun(chosen.length);
  }

  async function startRun(total) {
    running = true;
    lastResults = [];
    logs.clear();
    liveCards.clear();
    lastSev.clear();
    modulesEl.querySelectorAll(".mod[data-sev]").forEach((r) => r.removeAttribute("data-sev"));
    syncRows();
    runBtn.classList.add("running");
    runIcon.innerHTML = I.stop;
    runLabel.textContent = "SEQUENCE RUNNING";
    runK.textContent = `[00/${pad2(total)}]`;
    copyJsonBtn.disabled = copyTicketBtn.disabled = true;
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
      await api.run([...selected], {
        onStart: ({ id, title, index, total: n }) => {
          setProgress(index / Math.max(n, 1));
          statusText.textContent = `Running · ${index + 1}/${n}`;
          runK.textContent = `[${pad2(index + 1)}/${pad2(n)}]`;
          startCard(id, title);
        },
        onLog: ({ id, line }) => appendLog(id, line),
        onDone: (res) => {
          lastResults.push(res);
          finishCard(res);
          setProgress(lastResults.length / Math.max(total, 1));
        },
      });
    } catch (e) {
      toast("The run stopped: " + String(e && e.message ? e.message : e));
    } finally {
      clearInterval(timer);
      elapsedEl.textContent = "T+ " + fmtSecs((performance.now() - t0) / 1000);
      running = false;
      runBtn.classList.remove("running");
      runIcon.innerHTML = I.play;
      runLabel.textContent = "RUN DIAGNOSTIC SEQUENCE";
      syncRows();
      const worst = worstOf(lastResults);
      const word = setPhase("done", worst);
      statusText.textContent =
        `${word} · ${lastResults.length} module${lastResults.length === 1 ? "" : "s"}` + (worst ? ` · worst: ${worst}` : "");
      copyJsonBtn.disabled = copyTicketBtn.disabled = lastResults.length === 0;
      setProgress(1);
      setTimeout(() => setProgress(0), 600);
    }
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
      const done = buildCard(res);
      const live = liveCards.get(res.module_id);
      if (live) live.replaceWith(done);
      else resultsEl.appendChild(done);
      liveCards.delete(res.module_id);
    });
  }

  function buildCard(res) {
    const sev = statusOf(res);
    const lines = logs.get(res.module_id) || [];
    const card = document.createElement("div");
    card.className = `card sev-${sev} open`;
    const rows = res.error
      ? `<div class="fr err"><span class="fdot sev-critical"></span><span class="fl">Couldn't run</span><span class="fv">${esc(res.error)}</span></div>`
      : res.findings.map((f) => `
          <div class="fr"><span class="fdot sev-${esc(f.severity)}"></span>
            <span class="fl">${esc(f.label)}</span>
            <span class="fv">${esc(f.value)}</span>
            ${f.detail ? `<span class="fd">${esc(f.detail)}</span>` : ""}
          </div>`).join("");
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
      <div class="findings">${rows}${logBlock}</div>`;

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
    return card;
  }

  function showEmpty() {
    resultsEl.innerHTML = `
      <div class="empty">
        ${I.radarBig}
        <h3>AWAITING SEQUENCE</h3>
        <p>Select modules on the left, then run the diagnostic sequence. Results stream in here as each module
           finishes, and long installs show their live output while they work.</p>
      </div>`;
  }

  /* -------------------------- confirm ------------------------------ */
  function confirmRun(mods) {
    return new Promise((resolve) => {
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
      const scrim = document.createElement("div");
      scrim.className = "scrim";
      scrim.innerHTML = `
        <div class="modal" role="dialog" aria-modal="true" aria-labelledby="confirm-title">
          <div class="hazard"></div>
          <div class="modal-body">
            <h3 id="confirm-title">${I.warn} Confirm system changes</h3>
            <p>These selected modules modify the system, not just read it:</p>
            <ul>${mods.map((m) => `<li><b>${esc(m.title)}</b>: ${esc(m.warning || m.description)}</li>`).join("")}</ul>
            ${notice}
            <div class="modal-actions">
              <button class="bk-btn" data-x="no" type="button">Cancel</button>
              <button class="bk-btn hot" data-x="yes" type="button">${notice && host.platform === "windows" ? "Run anyway" : "Run"}</button>
            </div>
          </div>
        </div>`;
      const close = (v) => { scrim.remove(); document.removeEventListener("keydown", onKey); resolve(v); };
      const onKey = (e) => { if (e.key === "Escape") close(false); };
      scrim.addEventListener("click", (e) => { if (e.target === scrim) close(false); });
      scrim.querySelector('[data-x="no"]').onclick = () => close(false);
      scrim.querySelector('[data-x="yes"]').onclick = () => close(true);
      const rl = scrim.querySelector('[data-x="relaunch"]');
      if (rl) rl.onclick = () => { close(false); relaunch(); };
      document.addEventListener("keydown", onKey);
      document.body.appendChild(scrim);
      scrim.querySelector('[data-x="no"]').focus(); // safe default for a destructive prompt
    });
  }

  /* --------------------------- export ------------------------------ */
  function exportJson() {
    return { generated: new Date().toISOString(), host, results: lastResults };
  }

  function ticketText(results) {
    const stamp = new Date().toISOString().replace("T", " ").slice(0, 19) + " UTC";
    const lines = [`itriage report — ${stamp}`];
    if (host) lines.push(`${host.hostname} · ${host.os} · ${host.elevated ? "elevated" : "standard user"}`);
    lines.push("=".repeat(52), "");
    results.forEach((res) => {
      const sev = res.error ? "FAILED" : statusOf(res).toUpperCase();
      lines.push(`[${sev}] ${res.title}: ${res.error ? "couldn't run" : res.summary}`);
      if (res.error) {
        lines.push(`    error: ${res.error}`);
      } else {
        res.findings.forEach((f) => {
          lines.push(`    ${f.label}: ${f.value}`);
          if (f.detail) lines.push(`        ${f.detail}`);
        });
      }
      lines.push("");
    });
    return lines.join("\n");
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
    const scrim = document.createElement("div");
    scrim.className = "scrim";
    scrim.innerHTML = `
      <div class="modal">
        <div class="hazard"></div>
        <div class="modal-body">
          <h3>Copy report</h3>
          <p>Your system blocked direct copying. Select all and copy:</p>
          <textarea class="copy-fallback" id="copy-fallback" readonly></textarea>
          <div class="modal-actions"><button class="bk-btn hot" data-x="ok" type="button">Close</button></div>
        </div>
      </div>`;
    const ta = scrim.querySelector("textarea");
    ta.value = text;
    scrim.querySelector('[data-x="ok"]').onclick = () => scrim.remove();
    scrim.addEventListener("click", (e) => { if (e.target === scrim) scrim.remove(); });
    document.body.appendChild(scrim);
    ta.focus();
    ta.select();
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
    toastTimer = setTimeout(() => t.remove(), 2600);
  }

  /* --------------------------- helpers ----------------------------- */
  function statusOf(res) {
    if (res.error) return "critical";
    const order = { ok: 0, info: 1, warning: 2, critical: 3 };
    let worst = "ok";
    res.findings.forEach((f) => { if ((order[f.severity] ?? 1) > order[worst]) worst = f.severity; });
    return worst;
  }
  function worstOf(results) {
    const order = ["ok", "info", "warning", "critical"];
    let idx = -1;
    results.forEach((r) => { idx = Math.max(idx, order.indexOf(statusOf(r))); });
    return idx >= 2 ? order[idx] : null; // only worth calling out at warning and above
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
          await invoke("run_modules", { selected: ids });
        } finally {
          offs.forEach((off) => off());
        }
      },
    };
  }

  /** Simulated telemetry for the browser preview: random walks with spikes,
   *  busier while a sequence runs. */
  function mockTelemetry() {
    const total = 64 * 1073741824;
    let cpu = 16, mem = 41, net = 2.2e5, disk = 9e5;
    const cores = Array.from({ length: 24 }, () => 8 + Math.random() * 16);
    const walk = (v, lo, hi, jitter, pull, target) =>
      clamp(v + (Math.random() - 0.5) * jitter + (target - v) * pull, lo, hi);
    return () => {
      cpu = walk(cpu, 2, 100, 16, 0.25, running ? 42 : 14);
      if (Math.random() < 0.07) cpu = Math.min(100, cpu + 25 + Math.random() * 30);
      cores.forEach((v, i) => {
        cores[i] = walk(v, 0, 100, 26, 0.35, cpu) + (running && i === 3 ? 45 : 0);
        cores[i] = clamp(cores[i], 0, 100);
      });
      mem = walk(mem, 30, 92, 1.2, 0.05, running ? 47 : 41);
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
    return {
      listModules: async () => CATALOGUE.map((m) => Object.assign({}, m)),
      hostContext: async () => host,
      telemetry: async () => mockSample(),
      relaunchElevated: async () => {
        await sleep(250);
        host = Object.assign({}, host, { elevated: true, can_relaunch_elevated: false, elevation_note: "Running as administrator." });
        renderHost();
        toast("Preview: now shown running as administrator");
      },
      run: async (ids, h) => {
        const chosen = CATALOGUE.filter((m) => ids.includes(m.id));
        const total = chosen.length;
        for (let i = 0; i < total; i++) {
          const m = chosen[i];
          h.onStart({ id: m.id, title: m.title, index: i, total });
          if (m.requires_admin && !host.elevated) {
            await sleep(180);
            h.onDone({ module_id: m.id, title: m.title, category: m.category, findings: [], summary: "", error: ADMIN_REQUIRED, duration_ms: 1 });
            continue;
          }
          for (const line of MOCK_LOGS[m.id] || []) {
            await sleep(110 + Math.random() * 170);
            h.onLog({ id: m.id, line });
          }
          await sleep(220 + Math.random() * 320);
          h.onDone(MOCK_RESULTS[m.id] || R(m.id, m.title, m.category, "(no sample)", 5, []));
        }
      },
    };
  }
})();
