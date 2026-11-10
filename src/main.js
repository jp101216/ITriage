/* ITriage frontend logic — v0.7.1.
 *
 * Two views over the same engine:
 *   • Technician: the HUD console (red by default, eight more themes in the
 *     picker). Module rail, streaming report, one-click fixes, KB links, run
 *     history and compare, export formats, cancel.
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
  const VERSION = "v0.7.1";

  /* ----------------------------- icons ----------------------------- */
  const sv = (body, extra) =>
    `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"${extra || ""}>${body}</svg>`;
  const I = {
    logo: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M2 12h4l2-5 3 10 2.5-7 1.5 2H22"/></svg>',
    logoCalm: '<svg viewBox="0 0 24 24" fill="none" stroke="#3ccfbc" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M2 12h4l2-5 3 10 2.5-7 1.5 2H22"/></svg>',
    check: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3.6" stroke-linecap="round" stroke-linejoin="round"><path d="M4 12l5 5L20 6"/></svg>',
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
    gauge: sv('<path d="M4 17a8 8 0 1 1 16 0"/><path d="M12 17l4.5-5"/><circle cx="12" cy="17" r="1.4" fill="currentColor" stroke="none"/>'),
    globe: sv('<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c3 3.2 3 14.8 0 18M12 3c-3 3.2-3 14.8 0 18"/>'),
    aim: sv('<circle cx="11" cy="11" r="6"/><path d="M11 3v3M11 16v3M3 11h3M16 11h3M15.5 15.5 21 21"/>'),
    layers: sv('<path d="M12 3 3 8l9 5 9-5z"/><path d="M3 13l9 5 9-5"/>'),
    nic: sv('<rect x="3" y="7" width="18" height="10" rx="1.5"/><path d="M7 11v2M10 11v2M13 11v2M16 11v2"/>'),
    sliders: sv('<path d="M4 6h9M17 6h3M4 12h3M11 12h9M4 18h11M19 18h1"/><circle cx="15" cy="6" r="2"/><circle cx="9" cy="12" r="2"/><circle cx="17" cy="18" r="2"/>'),
    wrench: sv('<path d="M15 4a5 5 0 0 0-4.6 6.9L4 17.3V20h2.7l6.4-6.4A5 5 0 0 0 20 9l-3 3-3-1-1-3z"/>'),
    power: sv('<path d="M12 3v8M7 6.3a8 8 0 1 0 10 0"/>'),
    pulse: sv('<path d="M3 12h4l2-6 4 12 2-6h6"/>'),
    key: sv('<circle cx="8" cy="15" r="4"/><path d="M11 12l9-9M16 7l3 3M13.5 9.5l2 2"/>'),
    trend: sv('<path d="M3 17l6-6 4 4 8-8M15 7h6v6"/>'),
    bulb: sv('<path d="M9 18h6M10 21h4M12 3a6 6 0 0 0-4 10.5c.7.7 1 1.5 1 2.5h6c0-1 .3-1.8 1-2.5A6 6 0 0 0 12 3z"/>'),
    eye: sv('<path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/>'),
    palette: sv('<path d="M12 3a9 9 0 0 0 0 18c1.2 0 2-.8 2-1.9 0-.5-.2-1-.5-1.3-.3-.4-.5-.8-.5-1.3 0-1 .8-1.9 1.9-1.9H17a4 4 0 0 0 4-4C21 6.5 17 3 12 3z"/>' +
      '<g fill="currentColor" stroke="none"><circle cx="7.5" cy="11" r="1.2"/><circle cx="10" cy="7" r="1.2"/><circle cx="14.5" cy="7" r="1.2"/><circle cx="17" cy="11" r="1.2"/></g>'),
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
   * the site policy's and remote-safe mode's locks). */
  const mod = (id, title, category, description, extra) =>
    Object.assign(
      { id, title, category, description, mutating: false, requires_admin: false, platforms: ["windows", "linux"], disruptive: false, takes_target: false },
      extra || {}
    );
  const WIN = { platforms: ["windows"] };
  const CHANGE = (warning, extra) => Object.assign({ mutating: true, warning }, extra || {});
  const ADMIN = { requires_admin: true };
  const DROP = { requires_admin: true, disruptive: true };
  const CATALOGUE = [
    mod("system.info", "System information", "system", "OS, CPU and memory, make and model, serial number, BIOS version, who is signed in, uptime (warns past 7 days) and any pending restart."),
    mod("system.disk", "Disk space & latency", "system", "Free vs. total space per volume (warns under 15% free) and disk latency with queue length (warns at 15 ms)."),
    mod("system.memory", "Memory usage", "system", "RAM and swap in use. Warns at 80% used, critical at 90% (the site profile can change both)."),
    mod("system.reliability", "Drive health & reliability", "system", "Each drive's health, wear and errors (SMART), and the last 30 days of blue screens, unexpected shutdowns, disk errors and the apps that crash most."),
    mod("system.changes", "Recent changes timeline", "system", "Recent updates, installer, driver, service, policy and restart evidence. Timing is a possible link, not proof of causation."),
    mod("proc.top", "Top processes", "processes", "Overall CPU load (warns at 75%), the busiest processes right now, and the biggest memory users. Flags anything pinning a core or holding a quarter of RAM."),
    mod("proc.services", "Services", "processes", "Automatic services that aren't running, with exit codes. Skips trigger-start services that stop by design."),
    mod("net.connectivity", "Network connectivity", "network", "Adapters and addresses, the route in use with its gateway and DNS servers, a timed DNS lookup, an outbound TCP test and the public IP."),
    mod("net.latency", "Latency & packet loss", "network", "Round trip and packet loss to the gateway and the first DNS server over ICMP. Warns at 20 ms or 1% loss to the gateway."),
    mod("net.proxy", "Proxy settings", "network", "The machine-wide WinHTTP proxy, and the signed-in user's proxy, PAC script or auto-detect setting."),
    mod("net.target", "Destination test", "network", "DNS, a TCP connect on each port, the route the PC picks, and ping, for one host you type in (ports default to 443, 80, 445, 3389).", { takes_target: true }),
    mod("net.applications", "Application connections", "network", "Site application URLs: DNS, route, TCP, proxy context, validated TLS, and expected HTTP statuses."),
    mod("net.wifi-auth", "Wi-Fi & wired authentication history", "network", "Association, disconnect, roaming and 802.1X / certificate evidence from existing logs."),
    mod("eventlog.errors", "Recent errors", "eventlog", "Critical and error events from the System and Application logs in the last 24 hours, grouped by source and event ID."),
    mod("desk.time", "Clock & time sync", "workstation", "Clock offset against the time server, where the time comes from, and the time zone. Domain sign-in fails past 5 minutes of drift."),
    mod("desk.domain", "Domain & Group Policy", "workstation", "Domain membership, whether a domain controller or cached credentials signed you in, the AD site, and when Group Policy last applied.", WIN),
    mod("desk.account", "Sign-in & account lockouts", "workstation", "Whether the signed-in account is locked, disabled or about to need a new password, mapped drives, and what on this PC keeps locking it: saved credentials, stale sessions, services, scheduled tasks and failed sign-ins."),
    mod("desk.identity", "Entra & Microsoft 365 sign-in", "workstation", "Device join and authentication, Windows Hello and affected-user PRT/WAM diagnostic status. Reads no tokens.", WIN),
    mod("desk.printers", "Printers & print queue", "workstation", "Print Spooler state, every printer's status, stuck jobs, the default printer, and label printers."),
    mod("desk.devices", "Devices & peripherals", "workstation", "Devices with driver problems (the Code 43s), microphones, cameras and card readers, plus devices the site profile requires."),
    mod("desk.wifi", "Wi-Fi & VPN", "workstation", "The connected Wi-Fi network, signal strength (warns at 70%), security (802.1X or not), radio and link rate, and VPN client and tunnel evidence."),
    mod("desk.certs", "Machine certificates", "workstation", "Computer certificates (used for 802.1X Wi-Fi and VPN) and when they expire. Warns 14 days out.", WIN),
    mod("desk.battery", "Battery health", "workstation", "Charge, power source, and battery wear (capacity left vs. design, cycle count). Flags batteries under 80%."),
    mod("sec.posture", "Security posture", "security", "Disk encryption, antivirus and how old its definitions are, the firewall, Secure Boot, the TPM, and who is an administrator of this PC."),
    mod("site.apps", "Required & clinical apps", "site", "Apps the site profile requires (with minimum versions), plus which clinical clients are installed: Citrix, Imprivata, Epic, Dragon, VPN, EDR."),
    mod("site.checks", "Site services & endpoints", "site", "Services the site profile requires are running, and the servers it lists (EHR, file, print, license) answer, with connect times."),
    mod("fix.dns", "Flush & re-register DNS", "repair", "Flushes the DNS resolver cache (ipconfig /flushdns) and re-registers this PC's DNS records (ipconfig /registerdns).",
      CHANGE("Clears cached DNS lookups, so the next few page loads may be a little slower.")),
    mod("fix.netcache", "Purge ARP & NetBIOS caches", "repair", "Purges the ARP cache (netsh interface ip delete arpcache) and the NetBIOS name cache (nbtstat -R / -RR).",
      CHANGE("Forgets every cached neighbour address; connections pause for a moment while they're looked up again.", DROP)),
    mod("fix.tcp", "TCP autotuning & NIC power", "repair", "Sets TCP receive autotuning back to normal and turns off the adapters' sleep settings (DeviceSleepOnDisconnect, SelectiveSuspend).",
      CHANGE("Changes TCP and adapter power settings. The adapter settings apply the next time each adapter restarts.", Object.assign({}, DROP, WIN))),
    mod("fix.netstack", "Reset network stack", "repair", "Resets the Winsock catalog and the TCP/IP stack (IPv4 and IPv6). Applies after a restart. Refused when any address is static.",
      CHANGE("Resets Winsock and TCP/IP to defaults. Static IP settings would be lost (ITriage refuses if it finds any), and a restart is needed.", Object.assign({}, DROP, WIN))),
    mod("fix.adapters", "Restart adapters & renew DHCP", "repair", "Restarts every physical network adapter that's up, waits for each to come back, then renews DHCP (ipconfig /release, /renew).",
      CHANGE("Every network connection drops for up to a minute. A remote session will disconnect and should reconnect on its own.", DROP)),
    mod("fix.temp", "Clear temp files", "fixes", "Deletes temp files older than a day from every user profile and C:\\Windows\\Temp (only your own without admin). Skips files in use.",
      CHANGE("Permanently deletes temp files older than a day. Files in use are skipped.")),
    mod("fix.recycle", "Empty Recycle Bin", "fixes", "Permanently deletes what's in the Recycle Bin (the Trash on Linux) for the account ITriage runs as.",
      CHANGE("Permanently deletes files the user may still expect to recover. Ask them first.")),
    mod("fix.repair", "Clean up & check system files", "fixes", "DISM component-store cleanup, then System File Checker (sfc /scannow). Takes 15–45 minutes; use when corruption is suspected or space is critical.",
      CHANGE("Runs DISM and SFC, which take 15–45 minutes and keep the disk busy. Don't restart until they finish.", Object.assign({}, ADMIN, WIN))),
    mod("fix.optimize", "Optimize system drive", "fixes", "Optimises the system drive: TRIM on an SSD, defragmentation on a hard disk (defrag /O).",
      CHANGE("Keeps the disk busy for a few minutes (longer on a hard disk).", ADMIN)),
    mod("fix.gpupdate", "Refresh Group Policy", "fixes", "Reapplies computer and user Group Policy (gpupdate /force).",
      CHANGE("Reapplies every policy. Network and proxy policies can blip connections while they apply.", Object.assign({ disruptive: true }, WIN))),
    mod("fix.sccm", "Run Configuration Manager actions", "fixes", "Triggers the SCCM/MECM client's machine policy, application deployment and hardware inventory cycles, if the client is installed.",
      CHANGE("Asks the Configuration Manager client to fetch policy and evaluate deployments now; software it's told to install may start installing.", Object.assign({}, DROP, WIN))),
    mod("update.scan", "Available updates", "updates", "Pending Windows Update patches and drivers, winget app upgrades, restart state, the current BIOS and the OEM driver/BIOS tool. Installs nothing."),
    mod("update.apply", "Install OS & app updates", "updates", "Installs pending Windows Update patches (security & quality) and upgrades winget apps. Optional/preview updates are skipped.",
      CHANGE("Installs every pending Windows update and app upgrade. This can take 30+ minutes, apps being upgraded may close, and a restart is usually needed afterwards.", ADMIN)),
    mod("update.firmware", "Install drivers & firmware", "updates", "Drivers, BIOS and firmware through the manufacturer's tool (Dell, HP, Lenovo), and Windows Update drivers. Won't run on battery.",
      CHANGE("May flash BIOS/firmware. Keep laptops on AC power and don't power off until it finishes. A restart is usually needed; BitLocker may ask for its recovery key if it isn't suspended first.", ADMIN)),
    mod("fix.restart", "Restart the PC", "fixes", "Restarts in 60 seconds, warning the signed-in user to save their work. Runs last in a sequence; Cancel restart stops it.",
      CHANGE("The PC restarts one minute after this runs. Unsaved work is lost if the user doesn't save it.", DROP)),
  ];

  /** Ready-made selections (mirrors itriage-core::module::PRESETS). */
  const PRESET_CATALOGUE = [
    { id: "triage", title: "Slowness triage", script: "Invoke-NetTriage",
      description: "System baseline, performance, network, latency, proxy, Wi-Fi and VPN, the site's servers, and a destination if you give one. Changes nothing.",
      modules: ["system.info", "system.disk", "system.memory", "proc.top", "net.connectivity", "net.latency", "net.proxy", "net.target", "desk.wifi", "site.checks"] },
    { id: "tuneup", title: "Tune-up", script: "Invoke-EndpointTuneUp",
      description: "DNS, address caches, TCP and adapter power, network stack and adapters, temp files, drive optimisation, Group Policy and Configuration Manager. Recycle Bin, system file repair and restart stay opt-in.",
      modules: ["fix.dns", "fix.netcache", "fix.tcp", "fix.netstack", "fix.adapters", "fix.temp", "fix.optimize", "fix.gpupdate", "fix.sccm"] },
    { id: "updates", title: "Drivers & firmware", script: "Invoke-UpdateSystem",
      description: "Identity and BIOS, what's pending, then drivers, BIOS and firmware through the manufacturer's tool and Windows Update.",
      modules: ["system.info", "update.scan", "update.firmware"] },
    { id: "lockout", title: "Account lockout", script: "",
      description: "Why an account keeps locking or can't sign in: its state on the domain controller, what on this PC still holds an old password, the domain connection, the clock and the network. Changes nothing.",
      modules: ["desk.account", "desk.domain", "desk.time", "net.connectivity"] },
    { id: "health", title: "Health check", script: "",
      description: "Is this PC sound: drive health and crashes, free space, security posture, battery wear and what's waiting to be installed. Changes nothing.",
      modules: ["system.info", "system.disk", "system.reliability", "sec.posture", "desk.battery", "update.scan"] },
  ];

  const CAT_ORDER = ["system", "processes", "network", "eventlog", "workstation", "security", "site", "repair", "fixes", "updates"];
  const CAT_LABEL = {
    system: "System",
    processes: "Processes & services",
    network: "Network",
    eventlog: "Event log",
    workstation: "Workstation",
    security: "Security",
    site: "Site & clinical",
    repair: "Network repair",
    fixes: "Cleanup & maintenance",
    updates: "Updates",
  };
  /** Short HUD codes shown next to each module title. */
  const CODES = {
    "system.info": "SYS-INF", "system.disk": "DSK-LAT", "system.memory": "MEM-USE",
    "proc.top": "PROC-TOP", "proc.services": "SVC-HLT", "net.connectivity": "NET-CON",
    "net.latency": "NET-LAT", "net.proxy": "NET-PRX", "net.target": "NET-DST",
    "eventlog.errors": "EVT-ERR", "desk.time": "CLK-SYN", "desk.domain": "DOM-GPO",
    "desk.printers": "PRN-QUE", "desk.devices": "DEV-MGR", "desk.wifi": "WLAN-VPN",
    "desk.certs": "CRT-EXP", "desk.battery": "BAT-HLT", "site.apps": "APP-REQ",
    "site.checks": "SITE-CHK", "fix.dns": "FIX-DNS", "fix.netcache": "FIX-ARP", "fix.tcp": "FIX-TCP",
    "fix.netstack": "FIX-STK", "fix.adapters": "FIX-NIC", "fix.temp": "FIX-TMP", "fix.recycle": "FIX-BIN",
    "fix.repair": "FIX-SFC", "fix.optimize": "FIX-OPT", "fix.gpupdate": "FIX-GPO", "fix.sccm": "FIX-CCM",
    "update.scan": "UPD-SCN", "update.apply": "UPD-INS", "update.firmware": "UPD-FRM", "fix.restart": "SYS-RST",
    "system.reliability": "DRV-HLT", "desk.account": "ACC-LCK", "sec.posture": "SEC-PST",
  };
  /** Cards with a live mini-chart fed by the telemetry sampler. */
  const LIVE_GLYPH = { "system.info": "cpu", "system.disk": "disk", "system.memory": "mem", "proc.top": "cores" };
  const STATIC_GLYPH = {
    "net.connectivity": I.nodes, "net.latency": I.gauge, "net.proxy": I.globe, "net.target": I.aim,
    "proc.services": I.rack, "eventlog.errors": I.alert,
    "desk.time": I.clock, "desk.domain": I.domain, "desk.printers": I.printer, "desk.devices": I.plug,
    "desk.wifi": I.wifi, "desk.certs": I.cert, "desk.battery": I.battery,
    "site.apps": I.apps, "site.checks": I.target,
    "fix.dns": I.refresh, "fix.netcache": I.swap, "fix.tcp": I.sliders, "fix.netstack": I.layers, "fix.adapters": I.nic,
    "fix.temp": I.trash, "fix.recycle": I.trash, "fix.repair": I.wrench, "fix.optimize": I.bolt,
    "fix.gpupdate": I.domain, "fix.sccm": I.apps, "fix.restart": I.power,
    "update.scan": I.radar, "update.apply": I.download, "update.firmware": I.chip,
    "system.reliability": I.pulse, "desk.account": I.key, "sec.posture": I.shield,
  };

  /** One-click fixes (mirrors itriage-core::actions::FIXES). */
  const FIX_CATALOGUE = [
    { id: "restart-spooler", label: "Restart Print Spooler", requires_admin: true, disruptive: false,
      description: "Restarts the print service (Print Spooler or CUPS). A job that is printing right now starts over." },
    { id: "clear-print-queue", label: "Clear print queue", requires_admin: true, disruptive: false,
      description: "Stops the print service, deletes every waiting print job, and starts it again. People will need to print those documents again." },
    { id: "resync-time", label: "Resync clock", requires_admin: true, disruptive: false,
      description: "Tells the time service to synchronise with its time source now." },
    { id: "gpupdate", label: "Refresh Group Policy", requires_admin: false, disruptive: true,
      description: "Runs gpupdate /force to reapply computer and user policy. It can take a minute, and network policies can blip connections." },
    { id: "start-service", label: "Start service", requires_admin: true, disruptive: false, description: "Starts the stopped service." },
    { id: "flush-dns", label: "Flush DNS cache", requires_admin: false, disruptive: false,
      description: "Clears cached DNS lookups so names are looked up fresh." },
    { id: "restart-computer", label: "Restart in 60 s", requires_admin: false, disruptive: true,
      description: "Restarts this PC in 60 seconds. The signed-in user is warned to save their work, and Cancel restart stops it." },
    { id: "cancel-restart", label: "Cancel restart", requires_admin: false, disruptive: false, description: "Cancels a scheduled restart." },
    { id: "install-oem-tool", label: "Install the OEM tool", requires_admin: true, disruptive: false, technician_only: true,
      description: "Installs the manufacturer's driver and BIOS tool with winget, so driver and firmware updates can go through it." },
    { id: "install-update", label: "Install this update", requires_admin: true, disruptive: false, technician_only: true,
      description: "Downloads and installs this one update from Windows Update. A restart may be needed afterwards." },
    { id: "clear-saved-credentials", label: "Remove saved credentials", requires_admin: false, disruptive: false,
      description: "Removes the credentials saved in Credential Manager under the signed-in account's name (file servers, Remote Desktop hosts, Office sign-ins). Windows asks for the password the next time each is used. Other accounts' saved credentials are left alone." },
    { id: "logoff-session", label: "Sign out the session", requires_admin: true, disruptive: false, technician_only: true,
      description: "Signs out this person's disconnected session on this PC. Programs still open in it are closed, and unsaved work in it is lost." },
    { id: "unlock-account", label: "Unlock the account", requires_admin: true, disruptive: false, technician_only: true,
      description: "Clears the account's lockout. It needs an account that's allowed to unlock users. If something is still using the old password, the account locks again." },
    { id: "revert-tuneup", label: "Revert tune-up", requires_admin: true, disruptive: true, technician_only: true,
      description: "Puts TCP receive autotuning and the adapters' sleep settings back to what they were before TCP autotuning & NIC power last changed them. Adapter settings apply the next time each adapter restarts." },
  ];

  /** Self-service: the checks it runs, in plain words. */
  const SS_TITLES = {
    "system.info": "This computer", "system.disk": "Storage space", "system.memory": "Memory",
    "net.connectivity": "Internet & network", "net.latency": "Network speed", "desk.time": "Clock", "desk.domain": "Sign-in & policies",
    "desk.printers": "Printers", "desk.devices": "Devices", "desk.wifi": "Wi-Fi & VPN",
    "desk.battery": "Battery", "site.apps": "Required apps", "site.checks": "Work systems",
    "desk.account": "Your account", "system.reliability": "Drive & crashes",
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
    'Administrator rights required. Use "Relaunch as admin" in the header (or right-click ITriage → Run as administrator).';
  const REMOTE_SAFE_REASON =
    "Remote-safe mode is on: this could drop the remote session or restart the PC. Switch remote-safe off to run it.";
  const MOCK_HOST = {
    hostname: "WS-FLINT-07",
    os: "Windows 11 Pro 24H2",
    platform: "windows",
    elevated: false,
    can_relaunch_elevated: true,
    elevation_note: "Install modules need administrator rights. Use Relaunch as admin.",
  };
  const MOCK_FIXES = ["restart-spooler", "clear-print-queue", "resync-time", "gpupdate", "flush-dns", "start-service:Spooler", "start-service:W32Time",
    "restart-computer", "cancel-restart", "install-oem-tool", "install-update",
    "clear-saved-credentials", "logoff-session:3", "unlock-account:CORP\\jparker", "revert-tuneup"];
  const MOCK_PROFILE = {
    source: "managed",
    path: "C:\\ProgramData\\itriage\\profile.toml",
    error: null,
    name: "Clinical workstation (example)",
    description: "Shared nursing-unit PC: badge-tap sign-in, virtual desktop, label printer",
    policy: { allow_changes: true, allow_installs: true, fixes: MOCK_FIXES, start_in: "technician", technician_view: true, remote_safe: false },
    requirements: 8,
    kb_rules: 3,
    ui: { theme: null },
  };
  const A = (id, target, label) => {
    const spec = FIX_CATALOGUE.find((f) => f.id === id);
    const named = { "start-service": "Start ", "unlock-account": "Unlock ", "logoff-session": "Sign out session " }[id];
    const a = { id, label: label || (named && target ? named + target : spec.label), requires_admin: spec.requires_admin };
    if (target) a.target = target;
    return a;
  };
  const K = (title, url) => ({ title, url });
  const M = (value, unit, worse) => ({ value, unit, higher_is_worse: worse !== false });
  const F = (label, value, severity, detail, extra) => {
    const f = { label, value, severity: severity || "info" };
    if (detail) f.detail = detail;
    return Object.assign(f, extra || {});
  };
  const R = (module_id, title, category, summary, duration_ms, findings, extra) =>
    Object.assign({ module_id, title, category, findings, summary, error: null, duration_ms }, extra || {});
  const KB_QUEUE = K("Clear a stuck print queue", "https://kb.example.org/printing/stuck-queue");
  const KB_TIME = K("Clock drift and sign-in failures", "https://kb.example.org/windows/time-sync");
  const KB_WIFI = K("Report a Wi-Fi dead spot", "https://kb.example.org/network/wifi-coverage");
  const CU_TITLE = "2026-11 Cumulative Update for Windows 11 Version 24H2 for x64-based Systems";
  const NET_TITLE = "2026-11 Cumulative Update for .NET Framework 3.5 and 4.8.1 for Windows 11, version 24H2";
  const DEF_TITLE = "Security Intelligence Update for Microsoft Defender Antivirus";
  const DRV_TITLE = "Intel Corporation - Net - 23.80.0.6";
  const UID = { cu: "8c1e5a71-2f0b-4b7e-9d0a-3c5f6e7a8b91", net: "1f4d2c3b-6a7e-4f80-8b9c-0d1e2f3a4b5c", def: "e2b9c4d1-7f3a-4e6b-a5c8-9d0f1e2a3b4c", drv: "5a6b7c8d-9e0f-4a1b-8c2d-3e4f5a6b7c8d" };
  const RESTART_MSG = "IT maintenance is complete. This PC will restart in 1 minute - please save your work.";
  const MOCK_RESULTS = {
    "system.changes": R("system.changes", "Recent changes timeline", "system", "2 recent change events (sample)", 5, [F("2026-11-10T16:52:00Z · Driver activity", "Kernel-PnP event 410", "info", "Sample Wi-Fi driver installation activity; confirm against the actual failure onset."),F("2026-11-10T16:55:00Z · Policy activity", "GroupPolicy event 8004", "info", "Sample policy processing event. Timing does not establish causation.")]),
    "net.applications": R("net.applications", "Application connections", "network", "1 application (sample)", 15, [F("Clinical portal · DNS", "1 address", "ok"),F("Clinical portal · HTTP", "HTTP 401 · first response 142 ms", "ok", "Expected [200, 401]. Authentication response is expected for an unauthenticated health probe."),F("Clinical portal · TLS", "Certificate chain and host name accepted", "ok")]),
    "net.wifi-auth": R("net.wifi-auth", "Wi-Fi & wired authentication history", "network", "2 authentication events (sample)", 8, [F("2026-11-10T16:57:00Z · WLAN event 8003", "Disconnect · reason 4", "info", "Sample event; a disconnect alone does not prove a roaming fault."),F("2026-11-10T16:57:04Z · WLAN event 8001", "Association completed", "info")]),
    "desk.identity": R("desk.identity", "Entra & Microsoft 365 sign-in", "workstation", "Device identity (sample)", 10, [F("Device join", "Microsoft Entra hybrid joined"),F("Entra device authentication", "device is present and enabled", "ok"),F("User SSO checks", "not graded in an elevated or different-user context", "info", "Run without elevation as the affected user for PRT/WAM status.")]),
    "system.info": R("system.info", "System information", "system", "WS-FLINT-07, up 15d 4h 12m; restart pending", 41, [
      F("Hostname", "WS-FLINT-07"), F("OS", "Windows 11 Pro 24H2 (build 26100.2314)"), F("Kernel", "26100"),
      F("Architecture", "x86_64"), F("CPU", "Intel(R) Core(TM) Ultra 7 165U (14 logical cores)"),
      F("Total memory", "16.0 GB"),
      F("Model", "Dell Inc. Latitude 7450", "info", "Latitude · Notebook"),
      F("Serial number", "7FHXW37"),
      F("BIOS", "1.21.0 · released 2026-05-14", "info", "Dell Inc."),
      F("Motherboard", "Dell Inc. 0K0X5C"),
      F("Signed-in user", "CORP\\jparker"),
      F("Uptime", "15d 4h 12m", "warning", "Up 15.2 days: consider a restart.", { metric: M(15.2, "days") }),
      F("Restart pending", "yes: Windows Update", "warning", null, { action: A("restart-computer") }),
    ]),
    "system.disk": R("system.disk", "Disk space & latency", "system", "Critically low free space · disk latency 23 ms", 1018, [
      F("C:\\", "7.2 GB free of 476.9 GB (98% used) · NTFS", "critical", null, { metric: M(2, "% free", false) }),
      F("D:\\", "812.4 GB free of 1.8 TB (56% used) · NTFS", "ok", null, { metric: M(44, "% free", false) }),
      F("Disk latency", "23.4 ms per transfer · queue 1.8", "warning",
        "Slow storage makes everything feel slow: check for a failing drive, full disk, or heavy background I/O (indexing, scans, updates).", { metric: M(23.4, "ms") }),
    ]),
    "system.memory": R("system.memory", "Memory usage", "system", "62% RAM in use", 6, [
      F("RAM", "9.9 GB used of 16.0 GB (62%), 6.1 GB available", "ok", null, { metric: M(62, "%") }),
      F("Swap / page file", "1.2 GB used of 9.0 GB (13%)", "ok"),
    ]),
    "system.reliability": R("system.reliability", "Drive health & reliability", "system", "Blue screens: 2 · App crashes: 11 crashes and 3 hangs across 3 apps", 3410, [
      F("Drive (PM9A1 NVMe Samsung 512GB)", "healthy · SSD · NVMe · 476.9 GB", "ok"),
      F("Drive counters", "wear, temperature and error counts are only reported to an administrator"),
      F("Blue screens (30 days)", "2 · last 6d ago", "warning", "0x0000009F DRIVER_POWER_STATE_FAILURE ×2 (usually a driver that mishandles sleep)", { metric: M(2, "") }),
      F("Unexpected shutdowns (30 days)", "none", "ok", null, { metric: M(0, "") }),
      F("Disk errors (30 days)", "none logged", "ok", null, { metric: M(0, "") }),
      F("App crashes (30 days)", "11 crashes and 3 hangs across 3 apps", "warning",
        "CDViewer.exe crashed 8×, hung 2×, last 1d ago; OUTLOOK.EXE crashed 2×, hung 1×, last 3d ago; msedge.exe crashed 1×, last 9d ago", { metric: M(14, "") }),
    ]),
    "proc.top": R("proc.top", "Top processes", "processes", "CPU 87% · 214 processes running · 1 using heavy CPU or memory", 1012, [
      F("CPU load", "87%", "warning", "Busiest: MsMpEng (31%), CDViewer (9%), chrome (4%)", { metric: M(87, "%") }),
      F("MsMpEng.exe (pid 2680)", "640.0 MB RAM · 31.2% CPU", "warning"),
      F("CDViewer.exe (pid 8124)", "2.1 GB RAM · 9.4% CPU"),
      F("chrome.exe (pid 4410)", "1.4 GB RAM · 4.1% CPU"),
      F("Teams.exe (pid 9332)", "402.0 MB RAM · 0.9% CPU"),
      F("explorer.exe (pid 5120)", "188.0 MB RAM · 0.2% CPU"),
    ]),
    "proc.services": R("proc.services", "Services", "processes", "187 running · 1 automatic service not running", 96, [
      F("Running services", "187", "ok"),
      F("Windows Defender Firewall (mpssvc)", "stopped · Automatic", "warning"),
      F("Windows Search (WSearch)", "stopped · Automatic (delayed)", "info"),
      F("Stopped by design (skipped)", "41 trigger-start/per-user, 3 self-stopping updaters"),
    ]),
    "net.connectivity": R("net.connectivity", "Network connectivity", "network", "Connectivity OK", 1840, [
      F("Interface Wi-Fi", "10.20.33.118/22, fe80::1a2b:3c4d/64", "info", "Intel(R) Wi-Fi 6E AX211 160MHz"),
      F("Default route", "via 10.20.32.1 on Wi-Fi (from 10.20.33.118)", "ok"),
      F("DNS servers", "10.20.0.53, 10.20.0.54"),
      F("DNS lookup (www.microsoft.com)", "resolved in 23 ms · 4 addresses", "ok", null, { metric: M(23, "ms") }),
      F("DNS server 10.20.0.53", "answers in 11 ms", "ok", null, { metric: M(11, "ms") }),
      F("DNS server 10.20.0.54", "answers in 14 ms", "ok", null, { metric: M(14, "ms") }),
      F("Outbound TCP (8.8.8.8:53)", "connected in 19 ms", "ok", null, { metric: M(19, "ms") }),
      F("Public IP", "203.0.113.47"),
    ]),
    "net.latency": R("net.latency", "Latency & packet loss", "network", "Gateway 38 ms, 0% loss · DNS server 12 ms, 0% loss", 4120, [
      F("Gateway 10.20.32.1 round trip", "avg 38 ms (min 4 ms / max 121 ms)", "warning", null, { metric: M(38, "ms") }),
      F("Gateway 10.20.32.1 packet loss", "0% (4 of 4 replies)", "ok", null, { metric: M(0, "%") }),
      F("DNS server 10.20.0.53 round trip", "avg 12 ms (min 9 ms / max 16 ms)", "ok", null, { metric: M(12, "ms") }),
      F("DNS server 10.20.0.53 packet loss", "0% (4 of 4 replies)", "ok", null, { metric: M(0, "%") }),
    ]),
    "net.proxy": R("net.proxy", "Proxy settings", "network", "User via PAC", 28, [
      F("WinHTTP proxy (machine)", "Direct (no proxy)"),
      F("User proxy (CORP\\jparker)", "PAC: http://pac.example.org/proxy.pac", "info", "auto-detect is also on"),
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
    "desk.account": R("desk.account", "Sign-in & account lockouts", "workstation", "Locked out · 2 possible lockout source(s) on this PC · 1 mapped drive unreachable", 2890, [
      F("Account", "CORP\\jparker · domain account", "info", "Checked on DC01."),
      F("Account status", "locked out", "critical",
        "Unlocking it doesn't stop whatever is using the old password: clear the sources below first, or it locks again. It unlocks by itself 30 minutes after the last wrong password.",
        { action: A("unlock-account", "CORP\\jparker") }),
      F("Password", "expires in 88 days · changed 2 days ago", "ok", null, { metric: M(88, "days", false) }),
      F("Lockout policy", "locks after 5 wrong passwords within 30 minutes; unlocks by itself after 30 minutes"),
      F("Lockout sources on this PC", "2 possible: 2 saved credentials, 1 disconnected session", "warning",
        "Each one can hold the old password and keep trying it. Clear them before unlocking the account, or it locks again."),
      F("Saved credentials", "2 saved under this account", "warning",
        "fs01 (Windows credential, saved 41d ago); TERMSRV/rds-clin01 (app credential, saved 97d ago). Each holds a copy of the password and keeps using it after the password changes.",
        { action: A("clear-saved-credentials") }),
      F("Disconnected session 3", "CORP\\jparker is still signed in", "warning",
        "A session left behind keeps the password it signed in with. After a password change, everything in it that reaches the network uses the old one. Signing it out closes its programs; unsaved work in it is lost.",
        { action: A("logoff-session", "3") }),
      F("Failed sign-ins on this PC (24 h)", "not checked: reading the Security log needs administrator rights"),
      F("Mapped drive H:", "\\\\fs01\\home$\\jparker · fs01 answers", "ok"),
      F("Mapped drive S:", "\\\\scan01\\inbox · can't reach scan01 (10.20.8.31 timed out)", "warning"),
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
    "desk.wifi": R("desk.wifi", "Wi-Fi & VPN", "workstation", "Wi-Fi Clinical-Secure, signal weak · VPN: Client running - tunnel unverified - Zscaler", 35, [
      F("Network", "Clinical-Secure", "ok", "Intel(R) Wi-Fi 6E AX211 160MHz"),
      F("Signal", "34% · weak", "critical", "Weak signal drops remote sessions as the device moves. Note where it happens for the network team.",
        { kb: KB_WIFI, metric: M(34, "%", false) }),
      F("Security", "WPA2-Enterprise · 802.1X", "ok"),
      F("Radio", "Wi-Fi 6 (802.11ax) · channel 149"),
      F("Link rate", "receive 144 Mbps · send 86 Mbps"),
      F("VPN (Cisco Secure Client)", "installed, not connected", "info", "Ethernet 3 · Cisco AnyConnect Secure Mobility Client Virtual Miniport Adapter for Windows x64"),
      F("VPN (Zscaler)", "client running, tunnel unverified", "info",
        "The client is running but no tunnel adapter is up: a cloud-proxy client (Zscaler) works this way, a full-tunnel VPN shouldn't."),
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
    "sec.posture": R("sec.posture", "Security posture", "security", "1 to look at: antivirus definitions", 4180, [
      F("Disk encryption", "C: BitLocker is on (XtsAes256)", "ok"),
      F("Antivirus", "Microsoft Defender: real-time protection on · tamper protection on", "ok"),
      F("Antivirus definitions", "version 1.421.33.0 · updated 5 days ago", "warning", null, { metric: M(5, "days") }),
      F("EDR sensor (CrowdStrike Falcon)", "running", "ok"),
      F("Firewall", "Windows Firewall is on for Domain, Private and Public", "ok", "In use now: Domain."),
      F("Secure Boot", "on", "ok"),
      F("TPM", "Trusted Platform Module 2.0", "ok"),
      F("User Account Control", "on", "ok"),
      F("Administrators of this PC", "3: Administrator, CORP\\Domain Admins, CORP\\Workstation Admins"),
    ]),
    "site.apps": R("site.apps", "Required & clinical apps", "site", "1 of 2 required apps missing or out of date", 140, [
      F("Citrix Workspace", "23.11.1.45 · needs 24.2 or later", "warning", "Citrix Workspace 2311"),
      F("Badge-tap SSO agent", "7.11.0", "ok", "Imprivata OneSign Agent"),
      F("Dictation", "Dragon Medical One 2024.1"),
      F("Endpoint security", "CrowdStrike Windows Sensor 7.18.18604.0"),
    ]),
    "site.checks": R("site.checks", "Site services & endpoints", "site", "3 of 4 site requirements met", 1520, [
      F("Print Spooler", "running", "ok"),
      F("Windows Time", "running", "ok"),
      F("EHR gateway", "ehr-gateway.example.org:443 reachable · 18 ms", "ok", "connected to 10.40.2.15", { metric: M(18, "ms") }),
      F("Print server", "print01.example.org:445 unreachable (10.40.8.20 timed out)", "critical"),
    ]),
    "fix.dns": R("fix.dns", "Flush & re-register DNS", "repair", "DNS cache flushed and records re-registered", 1240, [
      F("ipconfig /flushdns", "Successfully flushed the DNS Resolver Cache.", "ok"),
      F("ipconfig /registerdns", "Registration of the DNS resource records for all adapters of this computer has been initiated.", "ok"),
    ]),
    "fix.netcache": R("fix.netcache", "Purge ARP & NetBIOS caches", "repair", "ARP and NetBIOS caches purged", 2210, [
      F("ARP cache", "Ok.", "ok"),
      F("NetBIOS name cache (purge)", "Successful purge and preload of the NBT Remote Cache Name Table.", "ok"),
      F("NetBIOS names (re-register)", "The NETBIOS names registered by this computer have been refreshed.", "ok"),
    ]),
    "fix.tcp": R("fix.tcp", "TCP autotuning & NIC power", "repair", "TCP autotuning normal; NIC sleep settings off (3 steps)", 6120, [
      F("TCP receive autotuning", "Ok.", "ok"),
      F("Wi-Fi", "DeviceSleepOnDisconnect, SelectiveSuspend turned off (applies at the next adapter restart)", "ok"),
      F("Ethernet", "sleep settings were already off", "ok"),
      F("Undo", "the settings from 2026-11-09 14:02:11 UTC are saved", "info", "Revert would set DeviceSleepOnDisconnect and SelectiveSuspend on Wi-Fi.", { action: A("revert-tuneup") }),
    ]),
    "fix.netstack": R("fix.netstack", "Reset network stack", "repair", "Network stack reset; restart to apply", 7410, [
      F("Static address check", "every address is from DHCP or autoconfiguration", "ok"),
      F("netsh winsock reset", "Sucessfully reset the Winsock Catalog. You must restart the computer in order to complete the reset.", "ok"),
      F("netsh int ip reset", "Restart the computer to complete this action.", "ok"),
      F("netsh int ipv6 reset", "Restart the computer to complete this action.", "ok"),
    ], { restart_required: true }),
    "fix.adapters": R("fix.adapters", "Restart adapters & renew DHCP", "repair", "Adapters restarted and addresses renewed", 21_400, [
      F("Wi-Fi", "restarted and back up", "ok"),
      F("DHCP release", "exit 1: An error occurred while releasing interface Loopback Pseudo-Interface 1 : The system cannot find the file specified.", "warning"),
      F("DHCP renew", "Wireless LAN adapter Wi-Fi: Connection-specific DNS Suffix  . : corp.example.org", "ok"),
      F("Wi-Fi now", "10.20.33.140/22, fe80::1a2b:3c4d/64"),
    ]),
    "fix.temp": R("fix.temp", "Clear temp files", "fixes", "Freed 2.3 GB from 4 temp folders (5214 files removed)", 9820, [
      F("C:\\Windows\\Temp", "deleted 1204 files (412.0 MB) · 88 recent kept · 3 in use", "ok"),
      F("C:\\Users\\jparker\\AppData\\Local\\Temp", "deleted 3880 files (1.8 GB) and 42 empty folders · 340 recent kept · 7 in use", "ok"),
      F("C:\\Users\\nurse.station\\AppData\\Local\\Temp", "deleted 130 files (96.4 MB) · 12 recent kept", "ok"),
      F("C:\\Users\\Default\\AppData\\Local\\Temp", "deleted 0 files (0 B)", "ok"),
      F("Free space (C:\\)", "7.2 GB → 9.5 GB"),
    ]),
    "fix.recycle": R("fix.recycle", "Empty Recycle Bin", "fixes", "Freed 640.2 MB from the Recycle Bin", 1210, [
      F("Recycle Bin", "emptied: 37 items (640.2 MB)", "ok"),
    ]),
    "fix.repair": R("fix.repair", "Clean up & check system files", "fixes", "Component store cleaned; system files checked", 1_820_000, [
      F("DISM component-store cleanup", "The operation completed successfully.", "ok"),
      F("System File Checker", "Windows Resource Protection did not find any integrity violations.", "ok"),
    ]),
    "fix.optimize": R("fix.optimize", "Optimize system drive", "fixes", "C: optimised", 48_000, [
      F("Optimize C:", "Retrim: 100% complete.", "ok"),
    ]),
    "fix.gpupdate": R("fix.gpupdate", "Refresh Group Policy", "fixes", "Group Policy refreshed", 14_200, [
      F("gpupdate /force", "User Policy update has completed successfully.", "ok"),
    ]),
    "fix.sccm": R("fix.sccm", "Run Configuration Manager actions", "fixes", "Triggered 3 Configuration Manager actions", 3100, [
      F("Machine policy retrieval & evaluation", "triggered", "ok"),
      F("Application deployment evaluation", "triggered", "ok"),
      F("Hardware inventory", "triggered", "ok"),
    ]),
    "fix.restart": R("fix.restart", "Restart the PC", "fixes", "Restarting in 60 seconds", 120, [
      F("Restart", "scheduled in 60 seconds; the signed-in user was warned", "warning", null, { action: A("cancel-restart") }),
    ]),
    "update.scan": R("update.scan", "Available updates", "updates", "3 Windows updates · 1 driver update · restart pending · 4 app upgrades", 41_380, [
      F("Windows Update", "3 important · 1 optional", "warning"),
      F("KB5070001", CU_TITLE, "critical", "MSRC severity: Critical", { action: A("install-update", UID.cu) }),
      F("KB5070002", NET_TITLE, "warning", "MSRC severity: Important", { action: A("install-update", UID.net) }),
      F("KB2267602", DEF_TITLE, "info", null, { action: A("install-update", UID.def) }),
      F("Windows Update drivers", "1 offered", "info"),
      F("Driver", DRV_TITLE, "info", null, { action: A("install-update", UID.drv) }),
      F("Restart pending", "yes; restart to finish earlier updates", "warning", null, { action: A("restart-computer") }),
      F("winget apps", "4 upgradable", "warning"),
      F("Google Chrome (Google.Chrome)", "130.0.6723.92 → 131.0.6778.70"),
      F("Mozilla Firefox (Mozilla.Firefox)", "131.0.3 → 132.0.1"),
      F("7-Zip 23.01 (x64) (7zip.7zip)", "23.01 → 24.08"),
      F("Microsoft Visual Studio Code (Microsoft.VisualStudioCode)", "1.94.2 → 1.95.1"),
      F("Current BIOS", "1.21.0 · released 2026-05-14"),
      F("Driver/BIOS tool (Dell Inc.)", "Dell Command | Update isn't installed; install Dell Command | Update from Dell's support site to get BIOS and firmware updates", "info",
        null, { action: A("install-oem-tool", "Dell.CommandUpdate", "Install Dell Command | Update") }),
    ]),
    "update.apply": R("update.apply", "Install OS & app updates", "updates", "Installed 3 Windows updates and 4 app upgrades; restart required", 1_412_000, [
      F("Windows Update", "3 installed, 0 failed", "ok"),
      F("KB5070001", "installed", "ok", CU_TITLE),
      F("KB5070002", "installed", "ok", NET_TITLE),
      F("KB2267602", "installed", "ok", DEF_TITLE),
      F("winget apps", "4 upgraded, 0 failed", "ok"),
      F("Restart required", "yes", "warning", null, { action: A("restart-computer") }),
    ], { restart_required: true }),
    "update.firmware": R("update.firmware", "Install drivers & firmware", "updates", "Dell Command | Update: updates applied; restart required", 486_000, [
      F("Model", "Dell Inc. Latitude 7450"),
      F("Current BIOS", "1.21.0 · released 2026-05-14"),
      F("Motherboard", "Dell Inc. 0K0X5C"),
      F("Power", "on AC power", "ok"),
      F("OEM tool (Dell Command | Update)", "Dell Command | Update is installed", "ok", "C:\\Program Files\\Dell\\CommandUpdate\\dcu-cli.exe · matched on the manufacturer"),
      F("Dell Command | Update", "updates applied; restart required (exit 1)", "warning", "Logs and reports: C:\\ProgramData\\itriage"),
      F("Windows Update drivers", "skipped: the OEM tool handles drivers"),
      F("Restart required", "yes", "warning", null, { action: A("restart-computer") }),
    ], { restart_required: true }),
  };
  /** What each module that changes the machine says in a preview. */
  const MOCK_PREVIEW = {
    "fix.dns": ["would flush the DNS cache", [["Would run", "ipconfig /flushdns"], ["Would skip", "ipconfig /registerdns (needs administrator rights)"]]],
    "fix.netcache": ["would purge the address caches", [["Would run", "netsh interface ip delete arpcache"], ["Would run", "nbtstat -R"], ["Would run", "nbtstat -RR"]]],
    "fix.tcp": ["would normalise TCP and adapter power settings", [["Would run", "netsh int tcp set global autotuninglevel=normal"],
      ["Wi-Fi", "would turn off DeviceSleepOnDisconnect, SelectiveSuspend"], ["Ethernet", "sleep settings already off"],
      ["Undo", "the current settings would be saved first, so Revert tune-up can set DeviceSleepOnDisconnect and SelectiveSuspend on Wi-Fi"]]],
    "fix.netstack": ["would reset Winsock and TCP/IP; a restart would be needed", [["Static address check", "every address is from DHCP or autoconfiguration", "ok"],
      ["Would run", "netsh winsock reset"], ["Would run", "netsh int ip reset"], ["Would run", "netsh int ipv6 reset"]]],
    "fix.adapters": ["would restart these adapters and renew DHCP", [["Would restart Wi-Fi", "10.20.33.118/22, fe80::1a2b:3c4d/64"],
      ["Would run", "ipconfig /release"], ["Would run", "ipconfig /renew"]]],
    "fix.temp": ["would delete 5214 files (2.3 GB) from 4 folders", [["C:\\Windows\\Temp", "would delete 1204 files (412.0 MB) · 88 recent kept"],
      ["C:\\Users\\jparker\\AppData\\Local\\Temp", "would delete 3880 files (1.8 GB) · 340 recent kept"],
      ["C:\\Users\\nurse.station\\AppData\\Local\\Temp", "would delete 130 files (96.4 MB) · 12 recent kept"],
      ["C:\\Users\\Default\\AppData\\Local\\Temp", "would delete 0 files (0 B)"]]],
    "fix.recycle": ["nothing was deleted", [["Would delete", "37 items (640.2 MB)"]]],
    "fix.repair": ["would clean the component store and check system files (15–45 minutes)",
      [["Would run", "dism /Online /Cleanup-Image /StartComponentCleanup /NoRestart"], ["Would run", "sfc /scannow"]]],
    "fix.optimize": ["would optimise the system drive", [["Would run", "defrag C: /O /U"]]],
    "fix.gpupdate": ["would reapply Group Policy", [["Would run", "gpupdate /force"]]],
    "fix.sccm": ["would trigger the client's policy, deployment and inventory cycles", [["Configuration Manager client", "running", "ok"],
      ["Would run", "Machine policy retrieval & evaluation"], ["Would run", "Application deployment evaluation"], ["Would run", "Hardware inventory"]]],
    "fix.restart": ["would restart in 60 seconds", [["Would tell the user", RESTART_MSG]]],
    "update.apply": ["would install 3 Windows updates and 4 app upgrades", [["Windows Update", "would install 3 updates"], ["KB5070001", CU_TITLE],
      ["KB5070002", NET_TITLE], ["KB2267602", DEF_TITLE], ["winget apps", "would upgrade 4 apps"],
      ["Google Chrome (Google.Chrome)", "130.0.6723.92 → 131.0.6778.70"], ["Mozilla Firefox (Mozilla.Firefox)", "131.0.3 → 132.0.1"],
      ["7-Zip 23.01 (x64) (7zip.7zip)", "23.01 → 24.08"], ["Microsoft Visual Studio Code (Microsoft.VisualStudioCode)", "1.94.2 → 1.95.1"]]],
    "update.firmware": ["nothing was installed", [["Model", "Dell Inc. Latitude 7450"], ["Current BIOS", "1.21.0 · released 2026-05-14"], ["Power", "on AC power", "ok"],
      ["OEM tool (Dell Command | Update)", "Dell Command | Update is installed and will run", "ok"],
      ["Would run", "C:\\Program Files\\Dell\\CommandUpdate\\dcu-cli.exe /applyUpdates -silent -reboot=disable"]]],
  };
  const MOCK_LOGS = {
    "system.disk": ["Measuring disk latency for a second…"],
    "net.connectivity": ["Reading network adapters…", "Resolving www.microsoft.com…", "Asking 2 DNS server(s) directly…", "Connecting to 8.8.8.8:53…", "Looking up the public IP…"],
    "net.latency": ["Pinging 10.20.32.1 and 10.20.0.53 (4 echoes each)…"],
    "eventlog.errors": ["Reading the System log…", "Reading the Application log…"],
    "desk.time": ["Measuring the clock against DC01 (SNTP, UDP 123)…"],
    "desk.account": ["Checking CORP\\jparker…"],
    "desk.battery": ["Running powercfg /batteryreport…"],
    "site.apps": ["Reading the installed-programs list…"],
    "site.checks": ["Checking 2 endpoint(s)…"],
    "fix.dns": ["› ipconfig /registerdns", "Registration of the DNS resource records for all adapters of this computer has been initiated."],
    "fix.netstack": ["› netsh winsock reset", "Sucessfully reset the Winsock Catalog.", "› netsh int ip reset", "Resetting Interface, OK!", "› netsh int ipv6 reset"],
    "fix.adapters": ["Before: Wi-Fi: 10.20.33.118/22", "Restarting physical adapters; the connection will drop for a moment…", "› ipconfig /release", "› ipconfig /renew", "After: Wi-Fi: 10.20.33.140/22"],
    "fix.temp": ["Clearing C:\\Windows\\Temp", "Clearing C:\\Users\\jparker\\AppData\\Local\\Temp", "Clearing C:\\Users\\nurse.station\\AppData\\Local\\Temp", "Clearing C:\\Users\\Default\\AppData\\Local\\Temp"],
    "update.scan": ["Searching Windows Update…", "Searching Windows Update for drivers…", "Checking winget for app upgrades…"],
    "update.firmware": ["Running Dell Command | Update…", "Checking for updates...", "Installing: Intel Wi-Fi 6E AX211 driver (1 of 2)", "Installing: Dell BIOS 1.22.0 (2 of 2)"],
  };
  /** What a finding looks like once its fix has worked (preview only). */
  const FIXED_VALUE = {
    "clear-print-queue": "ready", "restart-spooler": "running", "resync-time": "4 ms slow",
    gpupdate: "applied just now", "start-service": "running", "flush-dns": "resolved",
    "install-update": "installed", "install-oem-tool": "Dell Command | Update is installed",
    "clear-saved-credentials": "none saved under this account", "logoff-session": "signed out",
    "unlock-account": "active", "revert-tuneup": "put back",
  };
  const FIX_MESSAGES = {
    "restart-spooler": () => "Print Spooler restarted.",
    "clear-print-queue": () => "Removed 6 spooled files and restarted the Print Spooler.",
    "resync-time": () => "Clock resynchronised with its time source.",
    gpupdate: () => "Group Policy refreshed.",
    "start-service": (t) => `${t} started.`,
    "flush-dns": () => "Successfully flushed the DNS Resolver Cache.",
    "restart-computer": () => "Restart scheduled in 60 seconds; the signed-in user was warned.",
    "cancel-restart": () => "Restart cancelled.",
    "install-oem-tool": () => "Dell Command | Update installed. Run Install drivers & firmware to use it.",
    "install-update": () => "KB5070001: installed. Restart to finish.",
    "clear-saved-credentials": () => "Removed 2 saved credentials: fs01, TERMSRV/rds-clin01. Windows asks for the password the next time each is used.",
    "logoff-session": (t) => `Asked Windows to sign out CORP\\jparker's disconnected session ${t}.`,
    "unlock-account": (t) => `${t} is unlocked. If something is still using the old password, it will lock again: clear the sources the report lists.`,
    "revert-tuneup": () => "Put back the settings from before the tune-up. Wi-Fi: DeviceSleepOnDisconnect, SelectiveSuspend turned back on (applies at the next adapter restart).",
  };
  const MOCK_DIFF = {
    against: "2026-11-05T19:02:11Z",
    changes: [
      { module_id: "desk.printers", module: "Printers & print queue", label: "Ward 4 LaserJet (default)", kind: "new", before: "ok", after: "warning", value: "in an error state · 3 jobs stuck", was: "ready" },
      { module_id: "desk.time", module: "Clock & time sync", label: "Offset vs DC01", kind: "new", before: "ok", after: "warning", value: "41.6 s slow", was: "412 ms slow" },
      { module_id: "system.disk", module: "Disk space & latency", label: "C:\\", kind: "changed", before: "warning", after: "critical", value: "7.2 GB free of 476.9 GB (98% used) · NTFS", was: "38.1 GB free of 476.9 GB (92% used) · NTFS" },
      { module_id: "desk.wifi", module: "Wi-Fi & VPN", label: "Signal", kind: "changed", before: "warning", after: "critical", value: "34% · weak", was: "61% · good" },
      { module_id: "site.apps", module: "Required & clinical apps", label: "Citrix Workspace", kind: "ongoing", before: "warning", after: "warning", value: "23.11.1.45 · needs 24.2 or later" },
      { module_id: "proc.services", module: "Services", label: "Print Spooler (Spooler)", kind: "resolved", before: "critical", after: null, value: "stopped · exit 1067 · Automatic" },
    ],
    metrics: [
      { module_id: "net.latency", module: "Latency & packet loss", label: "Gateway 10.20.32.1 round trip", unit: "ms", before: 12, after: 38, delta: 26, trend: "worse" },
      { module_id: "desk.wifi", module: "Wi-Fi & VPN", label: "Signal", unit: "%", before: 61, after: 34, delta: -27, trend: "worse" },
      { module_id: "system.disk", module: "Disk space & latency", label: "C:\\", unit: "% free", before: 8, after: 2, delta: -6, trend: "worse" },
      { module_id: "system.disk", module: "Disk space & latency", label: "Disk latency", unit: "ms", before: 31.2, after: 23.4, delta: -7.8, trend: "better" },
      { module_id: "net.connectivity", module: "Network connectivity", label: "DNS lookup (www.microsoft.com)", unit: "ms", before: 25, after: 23, delta: -2, trend: "same" },
      { module_id: "site.checks", module: "Site services & endpoints", label: "EHR gateway", unit: "ms", before: 21, after: 18, delta: -3, trend: "same" },
    ],
    added: [],
    removed: [],
    gaps: [],
  };
  const HIST_DIR = "C:\\Users\\jparker\\AppData\\Local\\itriage\\history\\";
  const MOCK_HISTORY = [
    { path: HIST_DIR + "20261105T190211Z_WS-FLINT-07_INC0048213.json", generated: "2026-11-05T19:02:11Z", hostname: "WS-FLINT-07", modules: 16, worst: "critical", cancelled: false, ticket: "INC0048213" },
    { path: HIST_DIR + "20261103T141530Z_WS-FLINT-07.json", generated: "2026-11-03T14:15:30Z", hostname: "WS-FLINT-07", modules: 9, worst: "warning", cancelled: false },
    { path: HIST_DIR + "20261102T091044Z_WS-ED-12.json", generated: "2026-11-02T09:10:44Z", hostname: "WS-ED-12", modules: 12, worst: "critical", cancelled: false },
    { path: HIST_DIR + "20261029T162201Z_WS-FLINT-07.json", generated: "2026-10-29T16:22:01Z", hostname: "WS-FLINT-07", modules: 4, worst: "ok", cancelled: true },
  ];

  /* --------------------------- state ------------------------------- */
  const STORE_KEY = "itriage.selection.v4";
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
  let presets = PRESET_CATALOGUE;
  /** Preview (what-if): modules that change the machine only say what they'd do. */
  let previewMode = false;
  /** Remote-safe: anything that could drop the session or restart the PC is locked. */
  let remoteSafe = false;
  let destination = loadDest();
  let metricIndex = new Map();
  /** "scheduled" once a restart has been scheduled in this session. */
  let restartState = null;
  /** The ticket this visit is for. Typed per run; never remembered. */
  let ticket = "";

  const mockSample = isTauri ? null : mockTelemetry();
  const api = isTauri ? realApi() : window.ITriageCases.mockBridge(mockApi(), () => host, () => mockSample());
  const cases = window.ITriageCases.create({api,modal,toast,currentReport,startRun,recordCase,cancel:requestCancel,busy:()=>running||fixBusy,attach:(report)=>{if(viewing)viewing.report=report;else live.report=report;}});

  /* ---------------------------- themes ----------------------------- */
  // How the technician console looks: html[data-skin] picks a token set in
  // styles.css. A technician's own choice is remembered on this computer;
  // without one, the site profile's [ui] theme; without that, Critical Red.
  const SKINS = [
    { id: "red", name: "Critical Red Alert", note: "High-contrast tactical console. The default." },
    { id: "amber", name: "Wasteland Amber", note: "Old-school amber terminal with scanlines." },
    { id: "phosphor", name: "Atomic Phosphor", note: "Classic green phosphor CRT." },
    { id: "radar", name: "Sub Radar", note: "Cold blue sonar screen, easy on the eyes at night." },
    { id: "cyber", name: "Cyber-Tactical", note: "Slate dashboard with cyan, amber and red signals." },
    { id: "holo", name: "Holographic HUD", note: "Cyan glass panels with a holographic glow." },
    { id: "tactical", name: "Tactical", note: "Armored charcoal and red, with cut corners." },
    { id: "minimal", name: "Sleek Minimalist", note: "Flat and quiet: no glow, no scanlines." },
    { id: "glass", name: "Enterprise Glass", note: "Frosted panels over a soft gradient." },
  ];
  const SKIN_KEY = "itriage.skin.v1";
  /** The site profile's theme at the last start, so a site default doesn't flash red. */
  const SITE_SKIN_KEY = "itriage.skin.site.v1";
  /** Canvas colours read from the theme (see pal()); cleared when it changes. */
  let PAL = null;
  setSkin(savedSkin() || storedSkin(SITE_SKIN_KEY) || "red");

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
        <span class="name">ITriage</span>
        <span class="brk">${VERSION}</span>
        ${isTauri ? "" : '<span class="tag preview">PREVIEW · SAMPLE DATA</span><a class="tag getapp" href="https://github.com/jp101216/ITriage/releases/latest" target="_blank" rel="noopener" title="Download ITriage for Windows or Linux">GET THE APP ↗</a>'}
        <button class="tag profile" id="profileTag" type="button" title="Site profile"><span id="profileIcon">${I.shield}</span><span id="profileName">PROFILE —</span></button>
        <button class="tag update" id="updateTag" type="button" hidden></button>
        <span class="tag mode-tag pv" id="tagPreview" hidden title="Preview (what-if) is on: nothing will be changed">${I.eye}PREVIEW</span>
        <span class="tag mode-tag safe" id="tagSafe" hidden title="Remote-safe is on: nothing that could drop the session or restart the PC can run">${I.shield}REMOTE-SAFE</span>
        <button class="bk-btn xs view-switch" id="toSelf" type="button" title="The simple view end users see">${I.swap}Self-service view</button>
        <button class="bk-btn xs" id="skinBtn" type="button" title="Change how the console looks">${I.palette}Theme</button>
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
        <div class="presets" id="presets" role="group" aria-label="Presets"></div>
        <div class="modules" id="modules"></div>
        <div class="run-dock">
          <div class="run-opts">
            <label class="opt" title="Modules that change the machine only say what they would do. Nothing is changed.">
              <input type="checkbox" id="optPreview"><span class="sw" aria-hidden="true"></span><span class="ol">PREVIEW<small>WHAT-IF</small></span></label>
            <label class="opt" title="Locks anything that could drop a remote session or restart the PC.">
              <input type="checkbox" id="optSafe"><span class="sw" aria-hidden="true"></span><span class="ol">REMOTE-SAFE<small>KEEP SESSION</small></span></label>
            <input class="ticket" id="ticket" type="text" maxlength="40" spellcheck="false" autocomplete="off" placeholder="TICKET" aria-label="Ticket number"
              title="The ticket this visit is for. It goes on the report, into its file name and into the audit log with every change. It isn't remembered.">
          </div>
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
                <button type="button" role="menuitem" data-fmt="plain">${I.term}<span>Ticket text<small>Plain text · key findings first · ServiceNow, email, work notes</small></span></button>
                <button type="button" role="menuitem" data-fmt="transcript">${I.copy}<span>Full transcript<small>Every module's log too · for an escalation</small></span></button>
                <button type="button" role="menuitem" data-fmt="rich">${I.export}<span>Rich text<small>Formatted table · TeamDynamix, Outlook</small></span></button>
                <button type="button" role="menuitem" data-fmt="md">${I.book}<span>Markdown<small>Teams, GitHub, wikis</small></span></button>
                <button type="button" role="menuitem" data-fmt="json">${I.download}<span>JSON report<small>Re-open in ITriage, or attach to the ticket</small></span></button>
              </div>
            </div>
          </div>
          <input type="file" id="fileInput" accept=".json,application/json" hidden>
        </div>
        <div class="case-toolbar" role="group" aria-label="Investigation tools">
          <button class="bk-btn sm" id="guidedBtn" type="button">Troubleshoot</button>
          <button class="bk-btn sm" id="recordBtn" type="button">Record issue</button>
          <button class="bk-btn sm" id="timelineBtn" type="button">Timeline</button>
          <button class="bk-btn sm" id="baselineBtn" type="button">Working PC</button>
          <button class="bk-btn sm" id="bundleBtn" type="button">Case bundle</button>
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
    catalogue.forEach((m) => {
      if (!m.mutating && !m.locked && (!m.takes_target || destination.trim())) selected.add(m.id);
    });
    syncRows();
  };
  el("ticket").oninput = (e) => { ticket = e.target.value; };
  el("optPreview").onchange = (e) => setPreview(e.target.checked);
  el("optSafe").onchange = (e) => setRemoteSafe(e.target.checked);
  el("none").onclick = () => { if (!running) { selected.clear(); syncRows(); } };
  runBtn.onclick = () => (running ? requestCancel() : onRun());
  el("historyBtn").onclick = openHistory;
  el("guidedBtn").onclick = cases.guided;
  el("recordBtn").onclick = cases.record;
  el("timelineBtn").onclick = cases.timeline;
  el("baselineBtn").onclick = cases.baseline;
  el("bundleBtn").onclick = cases.bundle;
  el("openBtn").onclick = () => fileInput.click();
  fileInput.onchange = onFilePicked;
  el("toSelf").onclick = () => setMode("self");
  el("skinBtn").onclick = openSkins;
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
  renderPresets();
  renderModules();
  syncRows();
  setPhase("ready");
  showEmpty();
  boot();

  if (api.onCloseRequested) api.onCloseRequested(askBeforeClosing);

  pollTelemetry();
  setInterval(pollTelemetry, 1000);
  document.addEventListener("visibilitychange", () => { if (!document.hidden) pollTelemetry(); });
  window.addEventListener("resize", () => requestAnimationFrame(() => { paintTelemetry(); tipClipped(); }));

  async function boot() {
    try { profile = await api.getProfile(); } catch (_) { /* no profile info */ }
    applyProfileSkin();
    remoteSafe = !!(profile && profile.policy && profile.policy.remote_safe);
    el("optSafe").checked = remoteSafe;
    el("tagSafe").hidden = !remoteSafe;
    try {
      const list = await api.listModules(remoteSafe);
      if (Array.isArray(list) && list.length) catalogue = list;
    } catch (_) { /* keep the bundled catalogue */ }
    try { fixCatalogue = (await api.listFixes()) || fixCatalogue; } catch (_) { /* keep the bundled list */ }
    try { presets = (await api.listPresets()) || presets; } catch (_) { /* keep the bundled presets */ }
    dropLocked();
    try { host = await api.hostContext(); } catch (_) { /* stats stay minimal */ }
    renderHost();
    renderProfile();
    renderPresets();
    renderModules(); // re-render so WIN/LIN chips and locks reflect this host
    syncRows();
    const pol = profile && profile.policy;
    if (pol && (pol.technician_view === false || pol.start_in === "self-service")) setMode("self");
    checkForUpdate();
  }

  /** Show a tag when a newer release exists. It links to the release page;
   *  nothing is downloaded or installed from here. The engine asks at most
   *  once a day, and not at all when the site profile says not to. */
  function checkForUpdate() {
    if (!api.checkUpdate) return;
    Promise.resolve(api.checkUpdate())
      .then((n) => {
        const tag = el("updateTag");
        if (!n || !n.newer) { tag.hidden = true; return; }
        tag.hidden = false;
        tag.innerHTML = `${I.download}<span></span>`;
        tag.querySelector("span").textContent = `UPDATE v${n.latest}`;
        tag.title = `ITriage ${n.latest} is out; this is ${n.current}. Opens the release page. Nothing is downloaded or installed from here.`;
        tag.onclick = () => Promise.resolve(api.openLink(n.url)).catch((e) => toast(errText(e)));
      })
      .catch(() => { /* no notice */ });
  }

  /** The typed ticket, or null, read from the field itself so a paste or an
   *  autofill counts too. The engine cleans it up. */
  function ticketValue() {
    const field = el("ticket");
    if (field) ticket = field.value;
    return ticket.trim() || null;
  }

  /** Drop selections the catalogue no longer offers (locked, or not on this OS). */
  function dropLocked() {
    const usable = new Set(catalogue.filter((m) => !m.locked).map((m) => m.id));
    [...selected].forEach((id) => { if (!usable.has(id)) selected.delete(id); });
  }

  /* ------------------------ presets & modes ------------------------- */
  function renderPresets() {
    const box = el("presets");
    box.innerHTML = '<span class="pl">PRESETS</span>' + presets
      .map((p) => `<button class="preset" type="button" data-p="${esc(p.id)}" title="${esc((p.script ? p.script + ": " : "") + p.description)}">${esc(p.title)}</button>`)
      .join("");
    box.querySelectorAll("[data-p]").forEach((b) => { b.onclick = () => applyPreset(b.dataset.p); });
    // The presets sit on one line and scroll sideways when the rail is
    // narrower than they are; let an ordinary mouse wheel do that.
    if (!box.dataset.wheel) {
      box.dataset.wheel = "1";
      box.addEventListener("wheel", (e) => {
        if (box.scrollWidth <= box.clientWidth || Math.abs(e.deltaY) <= Math.abs(e.deltaX)) return;
        box.scrollLeft += e.deltaY;
        e.preventDefault();
      }, { passive: false });
    }
  }

  function applyPreset(id) {
    if (running) return;
    const p = presets.find((x) => x.id === id);
    if (!p) return;
    selected.clear();
    let locked = 0;
    p.modules.forEach((mid) => {
      const m = catalogue.find((x) => x.id === mid);
      if (!m) return; // not on this OS
      if (m.locked) { locked++; return; }
      if (m.takes_target && !destination.trim()) return;
      selected.add(mid);
    });
    syncRows();
    const changes = [...selected].some((mid) => (catalogue.find((x) => x.id === mid) || {}).mutating);
    toast(`${p.title}${p.script ? ` (${p.script})` : ""}: ${selected.size} selected` +
      (locked ? ` · ${locked} locked` : "") +
      (changes && !previewMode ? " · turn on PREVIEW to see the changes first" : ""));
  }

  function setPreview(on) {
    previewMode = !!on;
    el("tagPreview").hidden = !previewMode;
    document.body.classList.toggle("previewing", previewMode);
    syncRows();
  }

  async function setRemoteSafe(on) {
    remoteSafe = !!on;
    el("tagSafe").hidden = !remoteSafe;
    try {
      const list = await api.listModules(remoteSafe);
      if (Array.isArray(list) && list.length) catalogue = list;
    } catch (_) { /* keep the current list */ }
    dropLocked();
    renderModules();
    syncRows();
    toast(remoteSafe
      ? "Remote-safe on: anything that could drop the session or restart the PC is locked"
      : "Remote-safe off: network repairs and restarts can run");
  }

  function idleLabel() {
    return previewMode ? "RUN PREVIEW (WHAT-IF)" : "RUN DIAGNOSTIC SEQUENCE";
  }

  async function validateDest(input) {
    const err = input.parentElement.querySelector(".dest-err");
    if (!destination.trim()) { err.hidden = true; return false; }
    try {
      await api.checkTarget(destination);
      err.hidden = true;
      input.classList.remove("bad");
      return true;
    } catch (e) {
      err.textContent = errText(e);
      err.hidden = false;
      input.classList.add("bad");
      return false;
    }
  }

  /* ------------------------- view switch --------------------------- */
  function canTech() {
    return !profile || !profile.policy || profile.policy.technician_view !== false;
  }

  function setMode(next) {
    if (running || fixBusy) return;
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
    drawBars(scopes.cores, t.cores, { top: 15, tone: "action" });
    drawTrace(scopes.mem, hist.mem, { max: 100, top: 15, tone: "action" });
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

  /** The theme's canvas colours, read from its tokens once per theme. */
  function pal() {
    if (PAL) return PAL;
    const cs = getComputedStyle(document.documentElement);
    const trip = (name, fallback) => {
      const v = cs.getPropertyValue(name).trim().split(/\s+/).map(Number);
      return v.length === 3 && v.every(Number.isFinite) ? v : fallback;
    };
    const fx = parseFloat(cs.getPropertyValue("--fx"));
    PAL = {
      fx: Number.isFinite(fx) ? fx : 1,
      accent: trip("--accent-rgb", [255, 59, 54]),
      glow: trip("--glow-rgb", [255, 40, 34]),
      action: trip("--action-rgb", [255, 59, 54]),
      crit: trip("--crit-rgb", [255, 46, 85]),
      bg: trip("--bg-rgb", [10, 4, 5]),
    };
    return PAL;
  }
  /** rgba() for an [r, g, b] triplet, lifted toward white by `lift` (0–1). */
  function col(c, a = 1, lift = 0) {
    const m = (x) => Math.round(x + (255 - x) * lift);
    return `rgba(${m(c[0])}, ${m(c[1])}, ${m(c[2])}, ${a})`;
  }
  /** A scope's colour and glow: the theme's accent, or its action colour. */
  function tone(name) {
    const p = pal();
    return name === "action" ? { c: p.action, g: p.action } : { c: p.accent, g: p.glow };
  }
  /** Glow alpha and blur, scaled by the theme's --fx (0 turns glow off). */
  function glowA(a) {
    return Math.min(1, a * pal().fx);
  }
  function blur(px) {
    return pal().fx > 0 ? px : 0;
  }

  /** A glowing oscilloscope trace, newest sample at the right edge. */
  function drawTrace(c, data, o) {
    const f = fit(c);
    if (!f || !data.length) return;
    const { ctx, w, h } = f;
    const t = tone(o.tone);
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
      g.addColorStop(0, col(t.c, 0.3));
      g.addColorStop(1, col(t.c, 0));
      ctx.fillStyle = g;
      ctx.fill();
    }
    path();
    ctx.lineJoin = "round";
    ctx.lineWidth = o.width || 1.6;
    ctx.strokeStyle = col(t.c, 1, 0.07);
    ctx.shadowColor = col(t.g, glowA(0.95));
    ctx.shadowBlur = blur(o.glow ?? 8);
    ctx.stroke();
    if (o.head) {
      ctx.beginPath();
      ctx.arc(span, y(data[data.length - 1]), 2.6, 0, Math.PI * 2);
      ctx.fillStyle = col(t.c, 1, 0.8);
      ctx.shadowBlur = blur(12);
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
    const t = tone(o && o.tone);
    const n = values.length, gap = n > 32 ? 1 : 2;
    const bw = Math.max(1, (w - 4 - gap * (n - 1)) / n);
    values.forEach((v, i) => {
      const bh = Math.max(1.5, (clamp(v, 0, 100) / 100) * (h - top - 3));
      const hot = v >= 85;
      ctx.fillStyle = hot ? col(t.c, 1, 0.3) : col(t.c, 0.85);
      ctx.shadowColor = col(t.g, glowA(0.9));
      ctx.shadowBlur = blur(hot ? 8 : ((o && o.glow) ?? 3));
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
    const p = pal(), t = tone("accent");
    let x = 0;
    if (warn) {
      const s = Math.min(h - 6, 16), ty = (h - s) / 2;
      ctx.fillStyle = col(p.crit);
      ctx.shadowColor = col(p.crit, glowA(0.9));
      ctx.shadowBlur = blur(6);
      ctx.beginPath();
      ctx.moveTo(s / 2, ty);
      ctx.lineTo(s, ty + s);
      ctx.lineTo(0, ty + s);
      ctx.closePath();
      ctx.fill();
      ctx.shadowBlur = 0;
      ctx.fillStyle = col(p.bg);
      ctx.fillRect(s / 2 - 0.9, ty + s * 0.36, 1.8, s * 0.32);
      ctx.fillRect(s / 2 - 0.9, ty + s * 0.76, 1.8, 1.8);
      x = s + 6;
    }
    const segs = 16, gap = 2;
    const sw = (w - x - gap * (segs - 1)) / segs;
    const sh = Math.min(10, h - 8), sy = (h - sh) / 2;
    const lit = Math.round((clamp(pct, 0, 100) / 100) * segs);
    for (let i = 0; i < segs; i++) {
      const on = i < lit, hot = on && warn && i >= segs - 3;
      ctx.fillStyle = hot ? col(p.crit) : on ? col(t.c) : col(t.c, 0.16);
      ctx.shadowColor = col(hot ? p.crit : t.g, glowA(0.8));
      ctx.shadowBlur = on ? blur(4) : 0;
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
          ${profileSkin() ? `<dt>Theme</dt><dd>${esc(profileSkin().name)} by default</dd>` : ""}
        </dl>
        <p>A machine-wide profile at <code>${esc(where)}</code> wins over a personal one, and a broken one locks ITriage to read-only.</p>`,
      actions: [{ label: "Close", hot: true, value: true }],
    });
  }

  async function relaunch() {
    // Relaunching closes this copy, and with it whatever it's in the middle of.
    if (running || fixBusy) {
      toast("Something is still running. Wait for it to finish, or cancel it, before relaunching as administrator.");
      return;
    }
    try {
      await api.relaunchElevated(); // the Tauri app exits when this succeeds
    } catch (e) {
      toast(errText(e) || "Elevation was cancelled");
    }
  }

  /** The window was asked to close while a run or a fix is going. */
  let closeAsking = false;
  async function askBeforeClosing() {
    if (closeAsking) return;
    closeAsking = true;
    const what = fixBusy && !running
      ? "<p>A fix is running. ITriage can close as soon as it finishes; stopping it part-way isn't safe.</p>"
      : `<p>A run is in progress. Closing now would cut off whatever it's doing.</p>
         <ul><li><b>Keep running</b> leaves it alone.</li>
         <li><b>Stop and close</b> stops at the next safe point (an install that has started always finishes), saves what ran, then closes.</li></ul>`;
    const stop = await modal({
      title: `${I.warn} ITriage is still working`,
      body: what,
      actions: [
        { label: "Keep running", value: false, focus: true },
        { label: fixBusy && !running ? "Close when it finishes" : "Stop and close", hot: true, value: true },
      ],
    });
    closeAsking = false;
    try {
      if (stop) {
        if (running && !cancelRequested) {
          cancelRequested = true;
          runLabel.textContent = "STOPPING, THEN CLOSING";
          statusText.textContent = "Stopping at the next safe point, then closing…";
          syncRows();
        }
        await api.closeWhenDone();
      } else {
        await api.keepRunning();
      }
    } catch (e) {
      toast(errText(e));
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
          (m.disruptive && !m.locked ? '<span class="badge drop" title="Can drop network connections or restart the PC; remote-safe mode locks it">DISRUPTIVE</span>' : "") +
          (m.requires_admin && !m.locked ? '<span class="badge admin">ADMIN</span>' : "");
        const dest = m.takes_target && !m.locked
          ? `<span class="dest-wrap"><input class="dest" type="text" spellcheck="false" autocomplete="off" aria-label="Destination to test"
               placeholder="host or IP, ports optional (fileserver01:445,3389)" value="${esc(destination)}"><span class="dest-err" hidden></span></span>`
          : "";
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
              ${dest}
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
      const input = row.querySelector("input.dest");
      if (input) {
        ["click", "keydown", "mousedown"].forEach((ev) => input.addEventListener(ev, (e) => e.stopPropagation()));
        input.addEventListener("input", () => {
          destination = input.value;
          saveDest();
          input.classList.remove("bad");
          if (destination.trim() && !selected.has(id) && !running) { selected.add(id); syncRows(); }
        });
        input.addEventListener("change", () => validateDest(input));
      }
    });
    paintTelemetry(); // fresh canvases need a frame
    tipClipped();
  }

  /** In a short window a description shows two lines; the rest goes in its tooltip. */
  function tipClipped() {
    modulesEl.querySelectorAll(".mod .d").forEach((d) => {
      if (d.scrollHeight > d.clientHeight + 1) d.title = d.textContent;
      else d.removeAttribute("title");
    });
  }

  function syncRows() {
    document.querySelectorAll(".case-toolbar button").forEach((b)=>{b.disabled=running||fixBusy;});
    modulesEl.querySelectorAll(".mod").forEach((row) => {
      const on = selected.has(row.dataset.id);
      row.classList.toggle("on", on);
      row.setAttribute("aria-checked", on ? "true" : "false");
    });
    const n = selected.size;
    countEl.textContent = n;
    if (!running) {
      runK.textContent = `[${pad2(n)}]`;
      runLabel.textContent = idleLabel();
    }
    runBtn.disabled = fixBusy || (running ? cancelRequested : n === 0);
    saveSelection();
  }

  /* ----------------------------- run ------------------------------- */
  async function onRun() {
    if (running || fixBusy || selected.size === 0) return;
    const chosen = catalogue.filter((m) => selected.has(m.id) && !m.locked);
    if (!chosen.length) return;
    if (chosen.some((m) => m.takes_target)) {
      const input = modulesEl.querySelector("input.dest");
      if (!destination.trim()) {
        toast("Type a destination for the Destination test first");
        if (input) input.focus();
        return;
      }
      if (input && !(await validateDest(input))) { input.focus(); return; }
    }
    const mutating = chosen.filter((m) => m.mutating);
    if (mutating.length && !previewMode && !(await confirmRun(mutating))) return;
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

  async function startRun(ids, runbook) {
    // A destination validation or confirmation may have yielded meanwhile.
    if (running || fixBusy) return;
    let total = ids.length;
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
    statusText.textContent = previewMode ? "Running preview: nothing will be changed" : "Running sequence";
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
        preview: previewMode,
        remoteSafe,
        target: destination.trim() || null,
        ticket: ticketValue(),
        runbook,
        onStart: ({ id, title, index, total: n, reason }) => {
          total = n;
          setProgress(index / Math.max(n, 1));
          if (!cancelRequested) statusText.textContent = `Running · ${index + 1}/${n}${reason ? " · " + reason : ""}`;
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
      runLabel.textContent = idleLabel();
      liveCards.forEach((card) => card.remove());
      liveCards.clear();
      syncRows();
      setDiff(live.diff);
      const first = resultsEl.querySelector(".card");
      const banners = topBanners(live.results, live.diff, "Since last run", true, live.report && live.report.likely);
      banners.forEach((b) => resultsEl.insertBefore(b, first));
      cases.decorate(live.report,resultsEl);
      if (live.diff) applyBadges();
      // A restart or preview notice needs reading before the cards, so bring it into view.
      if (banners.some((b) => b.matches(".banner.restart, .banner.preview"))) resultsEl.scrollTo({ top: 0, behavior: "smooth" });
      statusText.textContent = runSummary(live.results, cancelled, total);
      exportBtn.disabled = live.results.length === 0;
      setProgress(1);
      setTimeout(() => setProgress(0), 600);
    }
  }

  async function recordCase(config,target,onSample) {
    if(running||fixBusy)throw "An operation is already running.";
    const base = currentReport().report;
    if(base.results.length && base.host.hostname.toLowerCase() !== host.hostname.toLowerCase())throw "Return to this PC's live report before recording local measurements.";
    running=true;cancelRequested=false;el("toSelf").disabled=true;syncRows();
    runBtn.classList.add("running");runIcon.innerHTML=I.stop;runLabel.textContent="STOP RECORDING";setPhase("running");statusText.textContent="Recording intermittent issue…";
    try {
      const outcome=await api.recordProblem(config,target,ticketValue(),(sample)=>{statusText.textContent=`Recording · CPU ${sample.cpu_pct.toFixed(1)}% · RAM ${sample.memory_pct.toFixed(1)}%`;onSample(sample);},base.results.length?base:null);
      live={report:outcome.report,results:outcome.report.results,diff:null};viewing=null;
      if(outcome.save_error)toast("Couldn't save recording: "+outcome.save_error);
    } finally {
      running=false;cancelRequested=false;el("toSelf").disabled=false;runBtn.classList.remove("running");runIcon.innerHTML=I.play;syncRows();renderLive();
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
    const notes = [];
    if (results.some((r) => r.preview)) notes.push("preview, nothing changed");
    if (results.some((r) => r.restart_required && !r.preview)) notes.push("restart needed");
    return `${word} · ${n} module${n === 1 ? "" : "s"}` + (worst ? ` · worst: ${worst}` : "") + notes.map((t) => " · " + t).join("");
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
    const lines = logs.get(res.module_id) || res.log || [];
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
        ${res.preview ? '<span class="chip pv" title="Preview: nothing was changed">preview</span>' : ""}
        ${res.restart_required && !res.preview ? '<span class="chip rs" title="A restart is needed to finish this">restart</span>' : ""}
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
    const mc = metricFor(res.module_id, f.label);
    // After a fix re-checks a finding its value moves on, so only tag what still holds.
    const delta = mc && mc.trend !== "same" && f.metric && f.metric.value === mc.after ? deltaHtml(mc) : "";
    const admin = f.action && f.action.requires_admin && host && !host.elevated;
    const fix = f.action && liveCard
      ? `<button class="fix-btn" type="button" data-fix="${i}" title="${esc(fixDescription(f.action))}">${I.bolt}${esc(f.action.label)}${admin ? '<span class="adm">ADMIN</span>' : ""}</button>`
      : "";
    const kb = f.kb ? `<a class="kb-link" data-kb href="${esc(f.kb.url)}" target="_blank" rel="noopener noreferrer">${I.book}${esc(f.kb.title)}</a>` : "";
    const fx = fix || kb ? `<div class="fx">${fix}${kb}<span class="fix-slot"></span></div>` : "";
    return `
      <div class="fr" data-label="${esc(f.label)}"><span class="fdot sev-${esc(f.severity)}"></span>
        <span class="fl">${esc(f.label)}${change ? badgeHtml(change) : ""}${delta}</span>
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
        <p>Select modules on the left (or a preset), then run the sequence. Results stream in as each module finishes.
           Turn on PREVIEW to see what the repair and update modules would change first. Every run is saved to History
           with its log, and the next run on this machine shows what changed.</p>
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
    topBanners(live.results, live.diff, "Since last run", true, live.report && live.report.likely).forEach((b) => resultsEl.appendChild(b));
    live.results.forEach((r) => {
      resultsEl.appendChild(buildCard(r, { live: true }));
      lastSev.set(r.module_id, statusOf(r));
    });
    cases.decorate(live.report,resultsEl);
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
    if (running || fixBusy) return;
    const slot = btn.parentElement.querySelector(".fix-slot");
    setFixBusy(true);
    slot.innerHTML = '<span class="fix-note busy"><span class="spin"></span>Running fix…</span>';
    const again = !["restart-computer", "cancel-restart"].includes(f.action.id) && recheckMode(res) !== null;
    let message = null;
    try {
      message = await api.runFix(f.action.id, f.action.target || null, remoteSafe, ticketValue());
      slot.innerHTML = `<span class="fix-note ok">${I.okc}${esc(message)}</span>` + (again ? '<span class="fix-note busy">Re-checking…</span>' : "");
    } catch (e) {
      slot.innerHTML = `<span class="fix-note err">${I.xc}${esc(errText(e))}</span>`;
    }
    try {
      if (message != null) {
        toast(message);
        if (f.action.id === "restart-computer") restartState = "scheduled";
        if (f.action.id === "cancel-restart") restartState = null;
        if (again && !(await recheck(res, message))) {
          slot.querySelectorAll(".fix-note.busy").forEach((n) => n.remove());
          const warning = document.createElement("span");
          warning.className = "fix-note err";
          warning.textContent = "The fix finished, but the re-check couldn't finish. Run the check again.";
          slot.appendChild(warning);
        }
      }
    } finally {
      setFixBusy(false);
    }
  }

  /** The fix and its re-check form one operation: a new run must not clear
   *  the live report while either is still using it. */
  function setFixBusy(on) {
    fixBusy = on;
    setFixButtons(!on);
    syncRows();
    el("toSelf").disabled = on || running;
    for (const id of ["ssGo", "ssTech"]) {
      const button = el(id);
      if (button) button.disabled = on || running;
    }
  }

  function setFixButtons(on) {
    document.querySelectorAll(".fix-btn, .ss-fix").forEach((b) => { b.disabled = !on; });
  }

  /** How a result may be re-checked after a fix. A check just runs again. A
   *  module that changes the machine never does: nobody confirmed a second
   *  run, so its preview is refreshed as a preview, and the record of a real
   *  run is left as it is (null). */
  function recheckMode(res) {
    const m = catalogue.find((x) => x.id === res.module_id);
    if (m && !m.mutating) return "check";
    return res.preview ? "preview" : null;
  }

  /** Run one module again (not saved to history) and swap its result in. */
  async function recheck(old, note) {
    const moduleId = old.module_id;
    const how = recheckMode(old);
    if (!how) return null;
    let res;
    try {
      res = await api.recheck(moduleId, { preview: how === "preview", remoteSafe, target: destination.trim() || null });
    } catch (e) {
      toast("Re-check failed: " + errText(e));
      return null;
    }
    if (!res) return null;
    logs.set(moduleId, res.log || []);
    const i = live.results.findIndex((r) => r.module_id === moduleId);
    if (i >= 0) live.results[i] = res;
    if (live.report) {
      const j = live.report.results.findIndex((r) => r.module_id === moduleId);
      if (j >= 0) live.report.results[j] = res;
      // Never export the old diagnosis or verdict if refreshing fails.
      live.report.likely = [];
      delete live.report.exit_code;
      live.diff = null;
      try {
        const updated = await api.refreshReport(live.report);
        live.report = updated.report;
        live.results = updated.report.results;
        live.diff = updated.diff || null;
      } catch (e) {
        toast("The check finished, but the report couldn't be refreshed: " + errText(e));
      }
    }
    setDiff(live.diff);
    lastSev.set(moduleId, statusOf(res));
    const row = modulesEl.querySelector(`.mod[data-id="${CSS.escape(moduleId)}"]`);
    if (row) row.dataset.sev = statusOf(res);
    if (mode === "tech" && !viewing) {
      const old = resultsEl.querySelector(`.card[data-mod="${CSS.escape(moduleId)}"]`);
      const fresh = buildCard(res, { live: true, note });
      fresh.classList.add("flash");
      if (old) old.replaceWith(fresh);
      else resultsEl.appendChild(fresh);
      statusText.textContent = runSummary(live.results, !!(live.report && live.report.cancelled), live.results.length);
      refreshLiveBanners();
      applyBadges();
    }
    return res;
  }

  function confirmFix(action, f) {
    let notice = "";
    if (action.requires_admin && host && !host.elevated) {
      notice = host.platform === "windows"
        ? `<div class="warnbox">${I.shield}<div><p><b>Needs administrator rights.</b> It will stop with an error until ITriage runs elevated.</p>
             ${host.can_relaunch_elevated ? '<button class="bk-btn xs" data-x="relaunch" type="button">Relaunch as admin</button>' : ""}</div></div>`
        : `<div class="notebox">${I.shield}<p>Needs root: you'll be asked for your password.</p></div>`;
    }
    const spec = fixCatalogue.find((x) => x.id === action.id) || {};
    if (spec.disruptive && remoteSafe) {
      notice += `<div class="warnbox">${I.shield}<div><p><b>Remote-safe mode is on.</b> This fix could drop the session or restart the PC, so it will be refused. Switch REMOTE-SAFE off first.</p></div></div>`;
    } else if (spec.disruptive) {
      notice += `<div class="notebox">${I.warn}<p>This can drop a remote session or restart the PC.</p></div>`;
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
    metricIndex = new Map((diff && diff.metrics ? diff.metrics : []).map((m) => [m.module_id + "\n" + m.label, m]));
  }
  function changeFor(moduleId, label) {
    return diffIndex.get(moduleId + "\n" + label);
  }
  function metricFor(moduleId, label) {
    return metricIndex.get(moduleId + "\n" + label);
  }
  /** "38 ms", "34%", "2% free", "15.2 days" (mirrors report::metric_text). */
  function metricText(value, unit) {
    const v = Math.abs(value - Math.round(value)) < 0.05 ? String(Math.round(value)) : value.toFixed(1);
    if (unit === "%") return `${v}%`;
    if (unit === "% free") return `${v}% free`;
    if (unit === "days" && v === "1") return "1 day";
    return unit ? `${v} ${unit}` : v;
  }
  function badgeHtml(c) {
    if (c.kind === "new") return '<span class="dbadge new" title="Not a problem last run">NEW</span>';
    if (c.kind === "changed") {
      return RANK[c.after] > RANK[c.before]
        ? '<span class="dbadge worse" title="Worse than last run">WORSE</span>'
        : '<span class="dbadge better" title="Better than last run">BETTER</span>';
    }
    if (c.kind === "ongoing") return '<span class="dbadge still" title="A problem last run too">STILL</span>';
    if (c.kind === "resolved" && c.after) return '<span class="dbadge better" title="A problem last run">BETTER</span>';
    return "";
  }
  function deltaHtml(mc) {
    return `<span class="mdelta ${esc(mc.trend)}" title="Was ${esc(metricText(mc.before, mc.unit))} last run">${mc.delta > 0 ? "+" : ""}${esc(metricText(mc.delta, mc.unit))}</span>`;
  }
  /** Badge the cards already on screen once the comparison arrives. */
  function applyBadges() {
    resultsEl.querySelectorAll(".card[data-mod]").forEach((card) => {
      card.querySelectorAll(".fr[data-label]").forEach((row) => {
        const fl = row.querySelector(".fl");
        if (!fl) return;
        fl.querySelectorAll(".dbadge, .mdelta").forEach((b) => b.remove());
        const c = changeFor(card.dataset.mod, row.dataset.label);
        if (c) fl.insertAdjacentHTML("beforeend", badgeHtml(c));
        const mc = metricFor(card.dataset.mod, row.dataset.label);
        if (mc && mc.trend !== "same") fl.insertAdjacentHTML("beforeend", deltaHtml(mc));
      });
    });
  }

  const KIND_WORD = { new: "new", resolved: "resolved", changed: "changed", ongoing: "still failing" };

  /** The banners above the cards: restart needed, preview, and what changed. */
  function topBanners(results, diff, label, liveRun, likely) {
    return [liveRun ? restartBanner(results) : null, previewBanner(results, liveRun), likelyBanner(likely), diff ? diffBanner(diff, label) : null].filter(Boolean);
  }

  /** "Likely cause": what the engine's rules make of the findings, each
   *  with the findings it rests on and what to do next. */
  function likelyBanner(insights) {
    if (!insights || !insights.length) return null;
    const box = document.createElement("div");
    box.className = "banner likely";
    box.innerHTML = `
      <div class="banner-row">
        <span class="ttl">${I.bulb}Likely cause</span>
        <span class="sub">Worked out from the findings below, which it names so you can check it.</span>
      </div>
      <ol class="likely-list">${insights
        .map((i) => `
          <li class="sev-${esc(i.severity)}">
            <p class="cause"><span class="fdot sev-${esc(i.severity)}"></span>${esc(i.cause)}</p>
            ${(i.evidence || []).length ? `<p class="why"><b>Because</b>${i.evidence.map(esc).join("; ")}</p>` : ""}
            <p class="next"><b>Next</b>${esc(i.next)}</p>
          </li>`)
        .join("")}</ol>`;
    return box;
  }

  /** Refresh every derived banner after a re-check, including comparison. */
  function refreshLiveBanners() {
    if (mode !== "tech" || viewing) return;
    resultsEl.querySelectorAll(":scope > .banner").forEach((b) => b.remove());
    const first = resultsEl.querySelector(".card");
    topBanners(live.results, live.diff, "Since last run", true, live.report && live.report.likely)
      .forEach((b) => resultsEl.insertBefore(b, first));
  }

  function diffBanner(diff, label) {
    const box = document.createElement("div");
    box.className = "banner diff";
    const metrics = diff.metrics || [];
    const better = metrics.filter((m) => m.trend === "better").length;
    const worse = metrics.filter((m) => m.trend === "worse").length;
    const ongoing = diff.ongoing || 0;
    const counts = [
      diff.new_issues ? `<span class="count new">${diff.new_issues} new</span>` : "",
      diff.resolved ? `<span class="count resolved">${diff.resolved} resolved</span>` : "",
      diff.changed ? `<span class="count changed">${diff.changed} changed</span>` : "",
      ongoing ? `<span class="count ongoing">${ongoing} still failing</span>` : "",
      worse ? `<span class="count worse">${worse} measurement${worse === 1 ? "" : "s"} worse</span>` : "",
      better ? `<span class="count better">${better} better</span>` : "",
    ].join("") || '<span class="count none">no change in problems</span>';
    const changes = (diff.changes || [])
      .map((c) => `
        <li><span class="k ${esc(c.kind)}">${esc(KIND_WORD[c.kind] || c.kind)}</span>
          <span class="w">${esc(c.label)} · ${esc(c.value)}<small>${esc(c.module)} · ${sevWord(c.before)} → ${sevWord(c.after)}${c.was ? " · was: " + esc(c.was) : ""}</small></span></li>`)
      .join("");
    const moved = metrics.filter((m) => m.trend !== "same");
    const same = metrics.length - moved.length;
    const mrows = moved
      .map((m) => `
        <tr><td>${esc(m.label)}<small>${esc(m.module)}</small></td>
          <td class="num">${esc(metricText(m.before, m.unit))}</td><td class="num">${esc(metricText(m.after, m.unit))}</td>
          <td class="num ${esc(m.trend)}">${m.delta > 0 ? "+" : ""}${esc(metricText(m.delta, m.unit))} · ${m.trend}</td></tr>`)
      .join("");
    const section = (title, body) => (body ? `<div class="dsec"><h4>${title}</h4>${body}</div>` : "");
    const added = diff.added || [], removed = diff.removed || [], gaps = diff.gaps || [];
    const details =
      section("Problems", changes ? `<ul class="diff-list">${changes}</ul>` : "") +
      section("Measurements",
        (mrows ? `<div class="mwrap"><table class="mtable"><thead><tr><th>Measurement</th><th>Before</th><th>After</th><th>Change</th></tr></thead><tbody>${mrows}</tbody></table></div>` : "") +
        (same ? `<p class="dnote">${same} measurement${same === 1 ? "" : "s"} about the same.</p>` : "")) +
      section("Checks",
        (added.length ? `<p class="dnote">Only this time: ${esc(added.join(", "))}</p>` : "") +
        (removed.length ? `<p class="dnote">Only last time: ${esc(removed.join(", "))}</p>` : "")) +
      section("Gaps", gaps.length ? `<ul class="gap-list">${gaps.map((g) => `<li>${esc(g)}</li>`).join("")}</ul>` : "");
    box.innerHTML = `
      <div class="banner-row">
        <span class="ttl">${esc(label || "Since last run")}</span>
        <span class="sub">${esc(fmtLocal(diff.against))}</span>
        <span class="counts">${counts}</span>
        <span class="grow"></span>
        ${details ? '<button class="bk-btn xs" type="button" data-x="toggle" aria-expanded="false">Details</button>' : ""}
      </div>
      <div class="diff-details" hidden>${details}</div>`;
    const t = box.querySelector('[data-x="toggle"]');
    if (t) {
      t.onclick = () => {
        const d = box.querySelector(".diff-details");
        d.hidden = !d.hidden;
        t.setAttribute("aria-expanded", d.hidden ? "false" : "true");
        t.textContent = d.hidden ? "Details" : "Hide";
      };
    }
    return box;
  }
  function sevWord(s) {
    return s ? s : "gone";
  }

  function previewBanner(results, liveRun) {
    const n = results.filter((r) => r.preview).length;
    if (!n) return null;
    const box = document.createElement("div");
    box.className = "banner preview";
    box.innerHTML = `
      <div class="banner-row">
        <span class="ttl">${I.eye}Preview</span>
        <span class="sub">${n} module${n === 1 ? "" : "s"} said what ${n === 1 ? "it" : "they"} would change. Nothing was changed.</span>
        <span class="grow"></span>
        ${liveRun && previewMode ? '<button class="bk-btn xs hot" type="button" data-x="real">Turn preview off</button>' : ""}
      </div>`;
    const b = box.querySelector('[data-x="real"]');
    if (b) {
      b.onclick = () => {
        el("optPreview").checked = false;
        setPreview(false);
        b.remove();
        toast("Preview is off: the next run makes the changes");
      };
    }
    return box;
  }

  function restartBanner(results) {
    const need = results.filter((r) => r.restart_required && !r.preview);
    if (!need.length) return null;
    const box = document.createElement("div");
    box.className = "banner restart";
    const render = () => {
      const scheduled = restartState === "scheduled";
      box.innerHTML = `
        <div class="banner-row">
          <span class="ttl">${I.power}${scheduled ? "Restart scheduled" : "Restart needed"}</span>
          <span class="sub">${scheduled
            ? "This PC restarts within a minute. The signed-in user was warned to save their work."
            : "To finish: " + esc(need.map((r) => r.title).join(", "))}</span>
          <span class="grow"></span>
          ${scheduled
            ? '<button class="bk-btn xs" type="button" data-x="cancel">Cancel restart</button>'
            : `<button class="bk-btn xs hot" type="button" data-x="restart"${remoteSafe ? ' disabled title="Remote-safe mode is on"' : ""}>Restart in 60 s</button>
               <button class="bk-btn xs" type="button" data-x="later">Later</button>`}
        </div>`;
      const go = box.querySelector('[data-x="restart"]');
      if (go) {
        go.onclick = async () => {
          if (running || fixBusy) return;
          const ok = await modal({
            title: `${I.power} Restart this PC`,
            body: `<p>Restarts in 60 seconds. The signed-in user sees this message:</p>
              <ul><li>${esc(RESTART_MSG)}</li></ul>
              <div class="notebox">${I.warn}<p>A remote session will disconnect. Cancel restart stops it within the minute.</p></div>`,
            actions: [{ label: "Not now", value: false, focus: true }, { label: "Restart in 60 s", hot: true, value: true }],
          });
          if (!ok || running || fixBusy) return;
          setFixBusy(true);
          try {
            toast(await api.runFix("restart-computer", null, remoteSafe, ticketValue()));
            restartState = "scheduled";
            render();
          } catch (e) {
            toast(errText(e));
          } finally {
            setFixBusy(false);
          }
        };
      }
      const cancel = box.querySelector('[data-x="cancel"]');
      if (cancel) {
        cancel.onclick = async () => {
          if (running || fixBusy) return;
          setFixBusy(true);
          try {
            toast(await api.runFix("cancel-restart", null, remoteSafe, ticketValue()));
            restartState = null;
            render();
          } catch (e) {
            toast(errText(e));
          } finally {
            setFixBusy(false);
          }
        };
      }
      const later = box.querySelector('[data-x="later"]');
      if (later) later.onclick = () => box.remove();
    };
    render();
    return box;
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
        <span class="ttl">${source === "file" ? "Opened report" : source === "compare" ? "Comparison" : "Saved run"}</span>
        <span class="sub">${esc(h.hostname || "unknown host")} · ${esc(fmtLocal(report.generated))} · ${report.results.length} module${report.results.length === 1 ? "" : "s"}${report.profile ? " · " + esc(report.profile) : ""}${report.ticket ? " · ticket " + esc(report.ticket) : ""}${report.cancelled ? " · cancelled" : ""}</span>
        <span class="grow"></span>
        <button class="bk-btn xs" type="button" data-x="back">${live.results.length ? "Back to this run" : "Close"}</button>
      </div>`;
    box.querySelector('[data-x="back"]').onclick = renderLive;
    resultsEl.appendChild(box);
    topBanners(report.results, diff, source === "compare" ? "Compared with" : "Since the run before", false, report.likely).forEach((b) => resultsEl.appendChild(b));
    report.results.forEach((r) => resultsEl.appendChild(buildCard(r, { live: false })));
    cases.decorate(report,resultsEl);
    if (diff) applyBadges();
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
      <p class="drawer-hint">Open a run, or tick two runs of the same PC to compare them (before and after a fix).</p>
      <div class="drawer-body"><div class="empty-note">Loading…</div></div>
      <div class="drawer-foot">
        <button class="bk-btn sm hot" data-x="compare" type="button" disabled>Compare 2 ticked</button>
        <button class="bk-btn sm" data-x="trends" type="button" title="How each measurement has moved over this PC's saved runs">${I.trend}Trends</button>
        <button class="bk-btn sm" data-x="open" type="button">${I.open}Open report</button>
        <button class="bk-btn sm" data-x="folder" type="button">Show folder</button>
      </div>`;
    const close = () => { scrim.remove(); d.remove(); document.removeEventListener("keydown", onKey); };
    const onKey = (e) => { if (e.key === "Escape") close(); };
    scrim.onclick = close;
    d.querySelector('[data-x="close"]').onclick = close;
    d.querySelector('[data-x="open"]').onclick = () => { close(); fileInput.click(); };
    d.querySelector('[data-x="trends"]').onclick = () => { close(); openTrends(); };
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
        <div class="hist-row">
          <input class="pick" type="checkbox" data-pick="${i}" aria-label="Tick to compare">
          <button class="hist${current === m.path ? " current" : ""}" type="button" data-i="${i}">
            <span class="when">${esc(fmtLocal(m.generated))}</span>
            <span class="chip sev-${esc(m.worst)}">${esc(m.worst)}</span>
            <span class="what">${esc(m.hostname)} · ${m.modules} module${m.modules === 1 ? "" : "s"}${m.ticket ? " · " + esc(m.ticket) : ""}${m.cancelled ? " · cancelled" : ""}</span>
          </button>
        </div>`)
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
    const picks = [];
    const compareBtn = d.querySelector('[data-x="compare"]');
    body.querySelectorAll(".pick").forEach((c) => {
      c.onchange = () => {
        const i = Number(c.dataset.pick);
        if (c.checked) {
          picks.push(i);
          if (picks.length > 2) {
            const drop = picks.shift();
            const old = body.querySelector(`.pick[data-pick="${drop}"]`);
            if (old) old.checked = false;
          }
        } else {
          picks.splice(picks.indexOf(i), 1);
        }
        compareBtn.disabled = picks.length !== 2;
      };
    });
    compareBtn.onclick = async () => {
      if (picks.length !== 2) return;
      try {
        const [a, b] = await Promise.all(picks.map((i) => api.loadReport(list[i].path)));
        const diff = await api.compareReports(a, b);
        const newer = a.generated >= b.generated ? a : b;
        const path = list[picks[a.generated >= b.generated ? 0 : 1]].path;
        close();
        showReport(newer, diff, "compare", path);
      } catch (e) {
        toast(errText(e));
      }
    };
  }

  /* ---------------------------- trends ----------------------------- */
  /** Better, worse or the same from the first point to the last. */
  function trendWord(s) {
    const first = s.points[0].value, last = s.points[s.points.length - 1].value;
    const moved = last - first;
    const floor = { ms: 2, "%": 1, "% free": 1, days: 0.5 }[s.unit] || 0;
    if (Math.abs(moved) <= Math.max(floor, Math.abs(first) * 0.1)) return "about the same";
    return (moved > 0) === s.higher_is_worse ? "worse" : "better";
  }

  function trendNote(s) {
    const first = s.points[0], last = s.points[s.points.length - 1];
    return `${metricText(last.value, s.unit)} now, ${metricText(first.value, s.unit)} on ${fmtLocal(first.generated)}: ${trendWord(s)} over ${s.points.length} runs.`;
  }

  /** One measurement over this PC's saved runs: a picker, a line chart with
   *  a crosshair readout, and the same numbers as a table. */
  async function openTrends() {
    let series = [];
    try { series = (await api.trends()) || []; } catch (e) { toast(errText(e)); return; }
    series = series.filter((s) => s.points && s.points.length >= 2);
    if (!series.length) {
      toast("No trends yet: a measurement needs at least two saved runs of this PC.");
      return;
    }
    const options = series.map((s, i) => `<option value="${i}">${esc(s.module)} · ${esc(s.label)}</option>`).join("");
    modal({
      title: `${I.trend} Trends`,
      cls: "wide",
      body: `
        <p>How one measurement has moved over the saved runs of ${esc(host ? host.hostname : "this PC")}.</p>
        <select class="trend-pick" aria-label="Measurement">${options}</select>
        <p class="trend-note" aria-live="polite"></p>
        <div class="trend-chart" tabindex="0" role="img"></div>
        <details class="trend-table"><summary>The same numbers as a table</summary><div class="mwrap"></div></details>`,
      actions: [{ label: "Close", value: true, focus: true }],
      onMount: (scrim) => {
        const pick = scrim.querySelector(".trend-pick");
        const show = () => {
          const s = series[Number(pick.value)];
          scrim.querySelector(".trend-note").textContent = trendNote(s);
          drawTrend(scrim.querySelector(".trend-chart"), s);
          trendTable(scrim.querySelector(".trend-table .mwrap"), s);
        };
        // Open on what got worse, if anything did.
        const worse = series.findIndex((s) => trendWord(s) === "worse");
        if (worse > 0) pick.value = String(worse);
        pick.onchange = show;
        requestAnimationFrame(show);
      },
    });
  }

  function trendTable(box, s) {
    const table = document.createElement("table");
    table.className = "mtable";
    table.innerHTML = "<thead><tr><th>Run</th><th>Value</th><th>Result</th></tr></thead>";
    const body = document.createElement("tbody");
    s.points.slice().reverse().forEach((p) => {
      const tr = document.createElement("tr");
      [fmtLocal(p.generated), metricText(p.value, s.unit), p.severity].forEach((text, i) => {
        const td = document.createElement("td");
        td.textContent = text;
        if (i === 1) td.className = "num";
        tr.appendChild(td);
      });
      body.appendChild(tr);
    });
    table.appendChild(body);
    box.replaceChildren(table);
  }

  /** A single-series line over time. The line wears the theme's accent; a
   *  run that was a warning or worse is marked in that colour, and says so
   *  in the readout and the table, never by colour alone. */
  function drawTrend(box, s) {
    const NS = "http://www.w3.org/2000/svg";
    const W = Math.max(320, box.clientWidth || 640), H = 230;
    const pad = { l: 52, r: 20, t: 16, b: 30 };
    const svg = (tag, attrs, parent) => {
      const n = document.createElementNS(NS, tag);
      Object.keys(attrs || {}).forEach((k) => n.setAttribute(k, attrs[k]));
      if (parent) parent.appendChild(n);
      return n;
    };
    const pts = s.points.map((p) => ({ t: Date.parse(p.generated), v: p.value, sev: p.severity, when: p.generated }));
    const t0 = pts[0].t, t1 = pts[pts.length - 1].t;
    const byTime = Number.isFinite(t0) && Number.isFinite(t1) && t1 > t0;
    // Round numbers on the axis: a step of 1, 2 or 5 times a power of ten.
    let min = Math.min(...pts.map((p) => p.v)), max = Math.max(...pts.map((p) => p.v));
    // A flat line still needs a scale; a count or a share doesn't go below zero.
    if (min === max) { max += 1; if (min >= 1 || min < 0) min -= 1; }
    const raw = (max - min) / 3, mag = Math.pow(10, Math.floor(Math.log10(raw))), n = raw / mag;
    const step = (n <= 1 ? 1 : n <= 2 ? 2 : n <= 5 ? 5 : 10) * mag;
    let lo = Math.floor(min / step) * step;
    const hi = Math.ceil(max / step) * step;
    if (min >= 0) lo = Math.max(0, lo);
    const ticks = [];
    for (let t = lo; t <= hi + step / 1000; t += step) ticks.push(Math.round(t / step) * step);
    const x = (p, i) => pad.l + (byTime ? (p.t - t0) / (t1 - t0) : i / (pts.length - 1)) * (W - pad.l - pad.r);
    const y = (v) => pad.t + (1 - (v - lo) / (hi - lo)) * (H - pad.t - pad.b);

    const root = svg("svg", { viewBox: `0 0 ${W} ${H}`, width: W, height: H, class: "trend-svg", "aria-hidden": "true" });
    // Recessive grid: a hairline per step, with the value it stands for.
    ticks.forEach((v) => {
      const gy = y(v);
      svg("line", { x1: pad.l, x2: W - pad.r, y1: gy, y2: gy, class: "grid" }, root);
      svg("text", { x: pad.l - 8, y: gy + 4, class: "axis", "text-anchor": "end" }, root).textContent = metricText(v, s.unit === "% free" ? "%" : s.unit);
    });
    const day = (iso) => { const d = new Date(iso); return Number.isNaN(d.getTime()) ? "" : `${d.getMonth() + 1}/${d.getDate()}`; };
    svg("text", { x: pad.l, y: H - 8, class: "axis" }, root).textContent = day(pts[0].when);
    svg("text", { x: W - pad.r, y: H - 8, class: "axis", "text-anchor": "end" }, root).textContent = day(pts[pts.length - 1].when);

    svg("path", { d: pts.map((p, i) => `${i ? "L" : "M"}${x(p, i).toFixed(1)} ${y(p.v).toFixed(1)}`).join(" "), class: "line" }, root);
    const cross = svg("line", { y1: pad.t, y2: H - pad.b, class: "cross", visibility: "hidden" }, root);
    const dots = pts.map((p, i) => svg("circle", { cx: x(p, i), cy: y(p.v), r: 4, class: `dot sev-${p.sev}` }, root));
    // The latest value is the one people came for: label it on the chart.
    const last = pts[pts.length - 1];
    svg("text", { x: W - pad.r, y: Math.max(pad.t + 10, y(last.v) - 10), class: "value", "text-anchor": "end" }, root).textContent = metricText(last.v, s.unit);

    const tip = document.createElement("div");
    tip.className = "trend-tip";
    tip.hidden = true;
    box.replaceChildren(root, tip);
    box.setAttribute("aria-label", `${s.module}, ${s.label}: ${trendNote(s)} Use the left and right arrow keys to read each run.`);

    let at = -1;
    const point = (i) => {
      at = i;
      dots.forEach((d, j) => d.setAttribute("r", j === i ? 6 : 4));
      if (i < 0) { cross.setAttribute("visibility", "hidden"); tip.hidden = true; return; }
      const p = pts[i], px = x(p, i);
      cross.setAttribute("x1", px); cross.setAttribute("x2", px);
      cross.setAttribute("visibility", "visible");
      tip.replaceChildren();
      const value = document.createElement("b");
      value.textContent = metricText(p.v, s.unit);
      const rest = document.createElement("span");
      rest.textContent = `${fmtLocal(p.when)} · ${p.sev}`;
      tip.append(value, rest);
      tip.hidden = false;
      const scale = (box.clientWidth || W) / W;
      const left = clamp(px * scale - tip.offsetWidth / 2, 0, Math.max(0, (box.clientWidth || W) - tip.offsetWidth));
      tip.style.left = `${left}px`;
      tip.style.top = `${Math.max(0, y(p.v) * scale - tip.offsetHeight - 12)}px`;
    };
    // The pointer only has to be nearest in time, never on the line.
    box.onpointermove = (e) => {
      const r = box.getBoundingClientRect();
      const px = ((e.clientX - r.left) / r.width) * W;
      let best = 0;
      pts.forEach((p, i) => { if (Math.abs(x(p, i) - px) < Math.abs(x(pts[best], best) - px)) best = i; });
      point(best);
    };
    box.onpointerleave = () => point(-1);
    box.onblur = () => point(-1);
    box.onkeydown = (e) => {
      if (e.key !== "ArrowLeft" && e.key !== "ArrowRight") return;
      e.preventDefault();
      const next = at < 0 ? pts.length - 1 : at + (e.key === "ArrowRight" ? 1 : -1);
      point(clamp(next, 0, pts.length - 1));
    };
  }

  async function onFilePicked() {
    const file = fileInput.files && fileInput.files[0];
    fileInput.value = "";
    if (!file) return;
    if (file.size > 20 * 1024 * 1024) { toast("That file is too big to be an ITriage report."); return; }
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

  async function doExport(fmt) {
    const { report, diff } = currentReport();
    if (!report.results.length) return;
    if (fmt === "plain") copy(await ticketText(report, diff, false), "Ticket text copied");
    else if (fmt === "transcript") copy(await ticketText(report, diff, true), "Full transcript copied");
    else if (fmt === "md") copy(markdown(report, diff), "Markdown copied");
    else if (fmt === "json") copy(JSON.stringify(report, null, 2), "JSON report copied");
    else if (fmt === "rich") copyRich(richHtml(report, diff), await ticketText(report, diff, false));
  }

  /** The plain-text report. In the app it's the engine's rendering, the same
   *  text the command line prints and the history folder keeps, so a ticket
   *  reads the same wherever it came from. plainText() below stands in for
   *  it in the browser preview. */
  async function ticketText(report, diff, withLogs) {
    try {
      return await api.reportText(report, diff, withLogs);
    } catch (_) {
      return plainText(report, diff, withLogs);
    }
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
    if (diff.ongoing) bits.push(`${diff.ongoing} still failing`);
    const ms = diff.metrics || [];
    const better = ms.filter((m) => m.trend === "better").length, worse = ms.filter((m) => m.trend === "worse").length;
    if (better + worse) bits.push(`${better} measurement${better === 1 ? "" : "s"} better, ${worse} worse`);
    return `Since the last run (${fmtUtc(diff.against)}): ${bits.length ? bits.join(", ") : "no change in problems"}`;
  }

  /** Warnings, criticals and failures: NetTriage's KEY FINDINGS. */
  function keyFindings(report) {
    const out = [];
    report.results.forEach((r) => {
      if (r.error) out.push({ tag: "FAILED", sev: "critical", text: `${r.title}: ${r.error}` });
      r.findings.forEach((f) => {
        if (RANK[f.severity] >= 2) out.push({ tag: f.severity === "critical" ? "CRIT" : "WARN", sev: f.severity, text: `${r.title}: ${f.label}: ${f.value}` });
      });
    });
    return out;
  }

  /** Compare-NetTriage's BEFORE AND AFTER text (mirrors report::render_diff). */
  function diffText(diff, hostname) {
    const tag = { ok: "OK", info: "INFO", warning: "WARN", critical: "CRIT" };
    const lines = ["BEFORE AND AFTER", `Computer  ${hostname}`, `Before    ${fmtUtc(diff.against)}`, `After     ${fmtUtc(diff.generated || "")}`, "", "CHECK RESULTS",
      `Resolved ${diff.resolved || 0} · New ${diff.new_issues || 0} · Changed ${diff.changed || 0} · Still failing ${diff.ongoing || 0} · Added ${(diff.added || []).length} · Removed ${(diff.removed || []).length}`];
    (diff.changes || []).forEach((c) => {
      lines.push(`- ${(KIND_WORD[c.kind] || c.kind).padEnd(13)} ${c.module}: ${c.label}  (${tag[c.before] || "—"} → ${tag[c.after] || "—"}) ${c.value}`);
      if (c.was) lines.push(`                was: ${c.was}`);
    });
    if ((diff.added || []).length) lines.push(`- Added         ${diff.added.join(", ")}`);
    if ((diff.removed || []).length) lines.push(`- Removed       ${diff.removed.join(", ")}`);
    lines.push("", "LATENCY AND QUALITY");
    const ms = diff.metrics || [];
    const moved = ms.filter((m) => m.trend !== "same");
    moved.forEach((m) => lines.push(`- ${m.module}: ${m.label}  ${metricText(m.before, m.unit)} → ${metricText(m.after, m.unit)} (${m.delta > 0 ? "+" : ""}${metricText(m.delta, m.unit)}, ${m.trend})`));
    if (!ms.length) lines.push("- No measurements in common.");
    else if (ms.length > moved.length) lines.push(`- ${ms.length - moved.length} measurement${ms.length - moved.length === 1 ? "" : "s"} about the same`);
    if ((diff.gaps || []).length) { lines.push("", "GAPS"); diff.gaps.forEach((g) => lines.push(`- ${g}`)); }
    return lines.join("\n");
  }

  function plainText(report, diff, withLogs) {
    const lines = [`ITriage report — ${fmtUtc(report.generated)}`, hostLine(report)];
    if (report.ticket) lines.push(`Ticket: ${report.ticket}`);
    if (report.cancelled) lines.push("Run was cancelled before every module finished.");
    if (report.results.some((r) => r.preview)) lines.push("PREVIEW: modules that change the machine only said what they would do.");
    if (report.results.some((r) => r.restart_required && !r.preview)) lines.push("A restart is needed to finish the changes.");
    if (diff) lines.push(diffLine(diff));
    lines.push("=".repeat(52));
    if ((report.likely || []).length) {
      lines.push("LIKELY CAUSE");
      report.likely.forEach((i) => {
        lines.push(`- ${i.cause}`);
        if ((i.evidence || []).length) lines.push(`    Because: ${i.evidence.join("; ")}`);
        lines.push(`    Next: ${i.next}`);
      });
      lines.push("");
    }
    lines.push("KEY FINDINGS");
    const key = keyFindings(report);
    if (key.length) key.forEach((k) => lines.push(`- [${k.tag}] ${k.text}`));
    else lines.push("- Nothing needs attention.");
    lines.push("");
    report.results.forEach((res) => {
      const sev = res.error ? "FAILED" : statusOf(res).toUpperCase();
      lines.push(`[${sev}] ${res.title}${res.preview ? " (preview)" : ""}: ${res.error ? "couldn't run" : res.summary}`);
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
      const log = res.log && res.log.length ? res.log : logs.get(res.module_id) || [];
      if (withLogs && log.length) {
        lines.push("    log:");
        log.forEach((l) => lines.push(`      | ${l}`));
      }
      lines.push("");
    });
    if (diff) lines.push(diffText(diff, report.host ? report.host.hostname : ""));
    return lines.join("\n");
  }

  function markdown(report, diff) {
    const cell = (s) => String(s).replace(/\|/g, "\\|").replace(/\s*\n\s*/g, " ");
    const tag = { ok: "OK", info: "INFO", warning: "WARN", critical: "CRIT" };
    const out = [`## ITriage report · ${report.host ? report.host.hostname : ""}`, "", `${fmtUtc(report.generated)} · ${hostLine(report)}${report.ticket ? " · ticket " + cell(report.ticket) : ""}`];
    if (report.results.some((r) => r.preview)) out.push("", "> **Preview:** modules that change the machine only said what they would do.");
    if (diff) out.push("", `**${diffLine(diff)}**`);
    if ((report.likely || []).length) {
      out.push("", "### Likely cause", "");
      report.likely.forEach((i) => {
        out.push(`- **${cell(i.cause)}**`);
        if ((i.evidence || []).length) out.push(`  - Because: ${cell(i.evidence.join("; "))}`);
        out.push(`  - Next: ${cell(i.next)}`);
      });
    }
    const key = keyFindings(report);
    out.push("", "### Key findings", "");
    if (key.length) key.forEach((k) => out.push(`- **${k.tag}** ${cell(k.text)}`));
    else out.push("- Nothing needs attention.");
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
    if (diff && (diff.metrics || []).some((m) => m.trend !== "same")) {
      out.push("", "### What moved since the last run", "", "| Measurement | Before | After | Change |", "|---|---|---|---|");
      diff.metrics.filter((m) => m.trend !== "same").forEach((m) => out.push(
        `| ${cell(m.module + ": " + m.label)} | ${metricText(m.before, m.unit)} | ${metricText(m.after, m.unit)} | ${m.delta > 0 ? "+" : ""}${metricText(m.delta, m.unit)} (${m.trend}) |`));
    }
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
      <p style="margin:0 0 6px"><b>ITriage report</b> · ${esc(fmtUtc(report.generated))}<br>${esc(hostLine(report))}${report.ticket ? "<br>Ticket: " + esc(report.ticket) : ""}</p>
      ${diff ? `<p style="margin:0 0 8px"><b>${esc(diffLine(diff))}</b></p>` : ""}
      ${likelyHtml(report)}
      ${keyHtml(report, color)}
      <table style="border-collapse:collapse;font-size:13px">${rows}</table></div>`;
  }

  function likelyHtml(report) {
    const likely = report.likely || [];
    if (!likely.length) return "";
    const items = likely
      .map((i) => `<li><b>${esc(i.cause)}</b>${(i.evidence || []).length ? `<br><span style="color:#57606a">Because: ${esc(i.evidence.join("; "))}</span>` : ""}<br>Next: ${esc(i.next)}</li>`)
      .join("");
    return `<p style="margin:8px 0 2px"><b>Likely cause</b></p><ul style="margin:0 0 10px;padding-left:18px">${items}</ul>`;
  }

  function keyHtml(report, color) {
    const key = keyFindings(report);
    const items = key.length
      ? key.map((k) => `<li><b style="color:${color[k.sev] || color.info}">${esc(k.tag)}</b> ${esc(k.text)}</li>`).join("")
      : "<li>Nothing needs attention.</li>";
    return `<p style="margin:8px 0 2px"><b>Key findings</b></p><ul style="margin:0 0 10px;padding-left:18px">${items}</ul>`;
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
        <button class="ss-go" id="ssGo" type="button"${running || fixBusy ? " disabled" : ""}>${I.radar}<span>${running ? "Checking…" : live.results.length ? "Check again" : "Check my computer"}</span></button>
        <p class="ss-hint">Takes about a minute. Nothing on your computer is changed.</p>
        <div class="ss-progress" id="ssProg" hidden><div class="bar"><i id="ssBar"></i></div><p id="ssStep">Starting…</p></div>
        <div class="ss-results" id="ssResults"></div>
        <p class="ss-foot">ITriage ${VERSION}${isTauri ? "" : " · preview with sample results"}</p>
      </div>`;
    const tech = el("ssTech");
    if (tech) {
      tech.disabled = running || fixBusy;
      tech.onclick = () => setMode("tech");
    }
    el("ssCopyName").onclick = () => host && copy(host.hostname, "Computer name copied");
    el("ssGo").onclick = runSelf;
    if (live.results.length && !running) renderSelfResults();
  }

  async function runSelf() {
    if (running || fixBusy) return;
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
        preview: false,
        remoteSafe,
        target: null,
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
        if (outcome.save_error) toast("Couldn't save this run to history: " + outcome.save_error);
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
        // Fixes that act on someone else's sign-in, or install things, are the desk's.
        const spec = f.action && fixCatalogue.find((x) => x.id === f.action.id);
        const fixable = f.action && !(spec && spec.technician_only) && (!f.action.requires_admin || (host && host.elevated));
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
    const first = n && live.report && (live.report.likely || [])[0];
    const likely = first
      ? `<div class="ss-likely"><h3>What's most likely going on</h3><p>${esc(first.cause)}</p></div>`
      : "";
    box.innerHTML = `
      ${verdict}
      ${likely}
      ${cards}
      ${good.length ? `<div class="ss-good"><h3>Looks good</h3><div class="ss-chips">${chips}</div></div>` : ""}
      ${unchecked.length ? `<p class="ss-hint">Couldn't check: ${esc(unchecked.join(", "))}.</p>` : ""}
      <div class="ss-share">
        <p>Calling or emailing the service desk? Copy the details and paste them into your message.</p>
        <button class="ss-copy" id="ssShare" type="button">${I.copy}Copy details for the service desk</button>
      </div>`;
    el("ssShare").onclick = async () => {
      const { report, diff } = currentReport();
      copy(await ticketText(report, diff, false), "Details copied: paste them into your message");
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
    if (!ok || running || fixBusy) return;
    const slot = btn.parentElement.querySelector(".ss-slot");
    setFixBusy(true);
    slot.innerHTML = '<span class="ss-note">Working…</span>';
    let message = null;
    try {
      message = await api.runFix(it.f.action.id, it.f.action.target || null, remoteSafe, ticketValue());
    } catch (e) {
      slot.innerHTML = `<span class="ss-note err">${I.xc}That didn't work: ${esc(errText(e))}</span>`;
    }
    try {
      if (message != null) {
        toast(message);
        if (await recheck(it.r, message)) {
          if (mode === "self") renderSelfResults();
        } else {
          slot.textContent = "The fix finished, but the re-check couldn't finish. Check the computer again.";
        }
      }
    } finally {
      setFixBusy(false);
    }
  }

  /* -------------------------- modals ------------------------------ */
  /** A dialog. Resolves with the chosen action's value (undefined if dismissed). */
  function modal({ title, body, actions, onMount, cls }) {
    return new Promise((resolve) => {
      const scrim = document.createElement("div");
      scrim.className = "scrim";
      scrim.innerHTML = `
        <div class="modal${cls ? " " + cls : ""}" role="dialog" aria-modal="true" aria-labelledby="m-title">
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

  /* -------------------------- themes ------------------------------ */
  function skinById(id) {
    const key = String(id || "").trim().toLowerCase();
    return SKINS.find((s) => s.id === key) || null;
  }
  function currentSkin() {
    return document.documentElement.dataset.skin || "red";
  }
  function storedSkin(key) {
    try {
      const s = skinById(localStorage.getItem(key));
      return s ? s.id : null;
    } catch (_) {
      return null;
    }
  }
  /** This technician's own pick, if they applied one. */
  function savedSkin() {
    return storedSkin(SKIN_KEY);
  }
  function saveSkin(id) {
    try { localStorage.setItem(SKIN_KEY, id); } catch (_) { /* ignore */ }
  }
  /** Switch the whole console to a theme (unknown ids fall back to red). */
  function setSkin(id) {
    const s = skinById(id) || SKINS[0];
    document.documentElement.dataset.skin = s.id;
    PAL = null;
    return s.id;
  }
  /** The site profile's default theme ([ui] theme), if it names a known one. */
  function profileSkin() {
    return skinById(profile && profile.ui && profile.ui.theme);
  }
  /** Use the profile's theme (or red), unless this technician has picked their own. */
  function applyProfileSkin() {
    const s = profileSkin();
    try {
      if (s) localStorage.setItem(SITE_SKIN_KEY, s.id);
      else localStorage.removeItem(SITE_SKIN_KEY);
    } catch (_) { /* ignore */ }
    const want = s ? s.id : "red";
    if (savedSkin() || want === currentSkin()) return;
    setSkin(want);
    paintTelemetry();
  }

  /** The theme picker: Equip tries a theme on the whole console, Apply keeps it. */
  function openSkins() {
    const before = currentSkin();
    let chosen = before;
    const site = profileSkin();
    const card = (s) => `
      <button class="skin" type="button" data-id="${s.id}" aria-pressed="${s.id === chosen}">
        <span class="skin-thumb" data-skin="${s.id}" aria-hidden="true">
          <span class="st-top"><span class="st-logo">${I.logo}</span><span class="st-name">ITriage</span><span class="st-ver">${VERSION}</span></span>
          <span class="st-mod on"><span class="st-box"></span><span class="st-lines"><i></i><i></i></span></span>
          <span class="st-mod"><span class="st-box"></span><span class="st-lines"><i></i><i></i></span></span>
          <span class="st-run"><b>RUN</b></span>
        </span>
        <span class="skin-meta"><span class="skin-name">${esc(s.name)}</span><span class="skin-note">${esc(s.note)}</span></span>
        <span class="skin-state">${s.id === chosen ? "ACTIVE" : "EQUIP"}</span>
      </button>`;
    modal({
      cls: "wide",
      title: `${I.palette}<span class="skin-ttl">Select GUI skin / theme</span>`,
      body: `
        <p>Equip a theme to try it on the whole console, then apply it to keep it on this computer.${site ? ` This site's default is ${esc(site.name)}.` : ""}
          The self-service view keeps its own calm look.</p>
        <div class="skins" role="group" aria-label="Themes">${SKINS.map(card).join("")}</div>`,
      actions: [{ label: "Cancel / Close", value: false }, { label: "Apply changes", hot: true, value: true }],
      onMount: (scrim) => {
        const cards = scrim.querySelectorAll(".skin");
        cards.forEach((b) => {
          b.onclick = () => {
            chosen = setSkin(b.dataset.id);
            cards.forEach((x) => {
              const on = x.dataset.id === chosen;
              x.setAttribute("aria-pressed", String(on));
              x.querySelector(".skin-state").textContent = on ? "ACTIVE" : "EQUIP";
            });
            paintTelemetry();
          };
        });
        // Start on the current theme rather than the first button.
        requestAnimationFrame(() => {
          const cur = scrim.querySelector('.skin[aria-pressed="true"]');
          if (cur) cur.focus();
        });
      },
    }).then((apply) => {
      if (apply) {
        saveSkin(chosen);
        toast(`Theme: ${skinById(chosen).name}`);
      } else if (currentSkin() !== before) {
        setSkin(before);
        paintTelemetry();
      }
    });
  }

  function confirmRun(mods) {
    const needAdmin = mods.filter((m) => m.requires_admin);
    let notice = "";
    if (needAdmin.length && host && !host.elevated) {
      const names = needAdmin.map((m) => `<b>${esc(m.title)}</b>`).join(" and ");
      notice = host.platform === "windows"
        ? `<div class="warnbox">${I.shield}<div><p><b>Not running as administrator.</b> ${names}
             will stop with an error until ITriage runs elevated.</p>
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
  /** The ticked checks from last time. Modules that change the machine are
   *  never remembered: they're picked on purpose, each time. */
  function loadSelection() {
    const changes = new Set(CATALOGUE.filter((m) => m.mutating).map((m) => m.id));
    const defaults = CATALOGUE.filter((m) => !m.mutating && !m.takes_target).map((m) => m.id);
    try {
      const saved = JSON.parse(localStorage.getItem(STORE_KEY) || "null");
      if (Array.isArray(saved)) return saved.filter((x) => typeof x === "string" && !changes.has(x));
    } catch (_) { /* storage unavailable */ }
    return defaults;
  }
  function saveSelection() {
    const checks = [...selected].filter((id) => !(catalogue.find((m) => m.id === id) || {}).mutating);
    try { localStorage.setItem(STORE_KEY, JSON.stringify(checks)); } catch (_) { /* ignore */ }
  }
  function loadDest() {
    try { return localStorage.getItem("itriage.destination.v1") || ""; } catch (_) { return ""; }
  }
  function saveDest() {
    try { localStorage.setItem("itriage.destination.v1", destination); } catch (_) { /* ignore */ }
  }

  /* --------------------------- bridges ----------------------------- */
  function realApi() {
    const { invoke } = window.__TAURI__.core;
    const { listen } = window.__TAURI__.event;
    return {
      listModules: (remoteSafe) => invoke("list_modules", { remoteSafe: !!remoteSafe }),
      listPresets: () => invoke("list_presets"),
      listFixes: () => invoke("list_fixes"),
      checkTarget: (text) => invoke("check_target", { text }),
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
          return await invoke("run_modules", {
            selected: ids,
            preview: !!h.preview,
            remoteSafe: !!h.remoteSafe,
            target: h.target || null,
            ticket: h.ticket || null,
            runbook: h.runbook || null,
          });
        } finally {
          offs.forEach((off) => off());
        }
      },
      cancel: () => invoke("cancel_run"),
      listRunbooks: () => invoke("list_runbooks"),
      runbookPlan: (id) => invoke("runbook_plan",{id}),
      recordProblem: async (config,target,ticket,onSample,baseReport) => {
        const off = await listen("recording-sample",(e)=>onSample(e.payload));
        try { return await invoke("record_problem",{config,target:target||null,ticket:ticket||null,baseReport:baseReport||null}); } finally { off(); }
      },
      markRecording: (label) => invoke("mark_recording",{label}),
      compareBaseline: (baseline,current) => invoke("compare_baseline",{baseline,current}),
      timelineNear: (report,problemAt,windowSeconds) => invoke("timeline_near",{report,problemAt,windowSeconds}),
      previewCaseBundle: (report,options) => invoke("preview_case_bundle",{report,options}),
      exportCaseBundle: (report,options) => invoke("export_case_bundle",{report,options}),
      openCasesFolder: () => invoke("open_cases_folder"),
      recheck: async (id, o) => {
        const outcome = await invoke("run_modules", {
          selected: [id],
          record: false,
          preview: !!(o && o.preview),
          remoteSafe: !!(o && o.remoteSafe),
          target: (o && o.target) || null,
        });
        return (outcome && outcome.report.results[0]) || null;
      },
      runFix: (id, target, remoteSafe, ticket) => invoke("run_fix", { id, target, remoteSafe: !!remoteSafe, ticket: ticket || null }),
      trends: () => invoke("trends", { hostname: null }),
      likelyCauses: (results) => invoke("likely_causes", { results }),
      checkUpdate: () => invoke("check_update"),
      listHistory: () => invoke("list_history"),
      loadReport: (path) => invoke("load_report", { path }),
      importReport: (text) => invoke("import_report", { text }),
      compareWithPrevious: (report) => invoke("compare_with_previous", { report }),
      refreshReport: (report) => invoke("refresh_report", { report }),
      compareReports: (a, b) => invoke("compare_reports", { a, b }),
      reportText: (report, diff, logs) => invoke("report_text", { report, diff: diff || null, logs: !!logs }),
      openLink: (url) => invoke("open_link", { url }),
      openHistoryFolder: () => invoke("open_history_folder"),
      onCloseRequested: (handler) => listen("close-requested", () => handler()),
      closeWhenDone: () => invoke("close_when_done"),
      keepRunning: () => invoke("keep_running"),
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

  /** Target::parse, for the preview. */
  function mockParseTarget(text) {
    const input = String(text || "").trim();
    const parts = input.split(/\s+/);
    let host = parts[0] || "";
    let portsText = parts.slice(1).join(" ");
    let explicitPorts = parts.length > 1;
    const inlinePorts = (text) => {
      if (explicitPorts) throw "Give ports once, after ':' or a space, like fileserver01:445,3389.";
      explicitPorts = true;
      portsText = text;
    };
    const v6 = host.match(/^\[([^\]]+)\](?::(.*))?$/);
    if (v6) {
      host = v6[1];
      try { new URL(`http://[${host.split("%")[0]}]`); }
      catch (_) { throw "Brackets are only used around an IPv6 address."; }
      if (v6[2] !== undefined) inlinePorts(v6[2]);
    } else if ((host.match(/:/g) || []).length === 1) {
      const [h, pp] = host.split(":");
      host = h;
      inlinePorts(pp);
    }
    if (!host || host.length > 253 || host.startsWith("-") || !/^[A-Za-z0-9._:%-]+$/.test(host)) {
      throw `\`${host}\` isn't a host name or IP address.`;
    }
    const ports = [];
    for (const part of portsText.split(/[,\s;]+/).filter(Boolean)) {
      const n = Number(part);
      if (!/^\+?[0-9]+$/.test(part) || !Number.isInteger(n) || n < 1 || n > 65535) throw `\`${part}\` isn't a port number (1–65535). Ports go after the host, like fileserver01:445,3389.`;
      if (!ports.includes(n)) ports.push(n);
    }
    if (ports.length > 16) throw "Up to 16 ports at a time.";
    if (explicitPorts && !ports.length) throw "Give at least one port number (1–65535) after the host.";
    return { host, ports, explicit_ports: explicitPorts };
  }

  /** A stand-in for the engine's likely-cause rules, enough for the sample
   *  data (the real ones are in itriage-core::insight). */
  function mockLikely(results) {
    const usable = results.filter((r) => !r.error && !r.preview);
    const find = (id, test) => {
      const r = usable.find((x) => x.module_id === id);
      const f = r && r.findings.find(test);
      return f ? { r, f, cite: `${r.title}: ${f.label}: ${f.value}` } : null;
    };
    const bad = (f) => RANK[f.severity] >= 2;
    const head = (v) => v.split(" · ")[0];
    const found = [];
    const add = (rank, severity, cause, evidence, next) => found.push({ rank, severity, cause, evidence, next });
    const locked = find("desk.account", (f) => f.label === "Account status" && f.severity === "critical");
    if (locked) {
      const sources = find("desk.account", (f) => f.label === "Lockout sources on this PC" && f.severity !== "ok");
      add(96, "critical", "The account is locked out, so sign-in, mapped drives and mail all fail.", [locked.cite].concat(sources ? [sources.cite] : []),
        "Clear the lockout sources listed under Sign-in & account lockouts, then unlock the account. Unlocking alone doesn't last.");
    }
    const bsod = find("system.reliability", (f) => f.label.startsWith("Blue screens") && bad(f));
    if (bsod) {
      const n = head(bsod.f.value);
      add(86, bsod.f.severity, `Windows has crashed with a blue screen ${n === "1" ? "once" : n === "2" ? "twice" : n + " times"} in the last 30 days. The most common stop code usually means a driver that mishandles sleep.`,
        [bsod.cite], "Update drivers, BIOS and firmware. If the stop code names hardware, run the manufacturer's diagnostics.");
    }
    const full = find("system.disk", (f) => bad(f) && f.metric && f.metric.unit === "% free");
    if (full) {
      add(full.f.severity === "critical" ? 82 : 56, full.f.severity,
        `${full.f.label} is nearly full (${head(full.f.value)}). The PC slows down, and updates and saves start failing, when it runs out of space.`,
        [full.cite], "Clear temp files and empty the Recycle Bin, then move or remove large files.");
    }
    const wifi = find("desk.wifi", (f) => f.label === "Signal" && bad(f));
    if (wifi) {
      const gw = find("net.latency", (f) => f.label.startsWith("Gateway") && bad(f));
      add(gw ? 78 : 62, wifi.f.severity, `Weak Wi-Fi (${head(wifi.f.value)}) is the most likely reason for a slow or dropping connection.`,
        [wifi.cite].concat(gw ? [gw.cite] : []), "Move closer to the access point or use a wired connection, then run the triage again.");
    }
    const clock = find("desk.time", (f) => f.label.startsWith("Offset vs") && bad(f));
    if (clock) {
      add(clock.f.severity === "critical" ? 90 : 45, clock.f.severity, "The clock is wrong. Past five minutes of drift, domain sign-in, Wi-Fi (802.1X) and secure sites fail.",
        [clock.cite], "Resync the clock, then check where it gets its time from.");
    }
    const up = find("system.info", (f) => f.label === "Uptime" && bad(f));
    if (up) {
      add(40, "warning", `This PC has been up for ${up.f.value}. A restart clears most slow-downs that build up over time.`, [up.cite], "Restart the PC at a time that suits the person using it.");
    }
    return found.sort((a, b) => b.rank - a.rank).slice(0, 3).map(({ severity, cause, evidence, next }) => ({ severity, cause, evidence, next }));
  }

  /** Sample trends: six runs of this PC, ending at today's sample values. */
  function mockTrends() {
    const when = ["2026-10-22T15:10:00Z", "2026-10-27T13:40:00Z", "2026-10-29T16:22:01Z", "2026-11-03T14:15:30Z", "2026-11-05T19:02:11Z", new Date().toISOString().replace(/\.\d+Z$/, "Z")];
    const series = (module_id, module, label, unit, worse, values, warn, crit) => ({
      module_id, module, label, unit, higher_is_worse: worse,
      points: values.map((value, i) => {
        const over = (limit) => limit != null && (worse ? value >= limit : value <= limit);
        return { generated: when[i], value, severity: over(crit) ? "critical" : over(warn) ? "warning" : "ok" };
      }),
    });
    return [
      series("system.info", "System information", "Uptime", "days", true, [2.1, 7, 1.3, 9.2, 11.1, 15.2], 7, 14),
      series("system.disk", "Disk space & latency", "C:\\", "% free", false, [19, 16, 14, 11, 8, 2], 15, 10),
      series("system.disk", "Disk space & latency", "Disk latency", "ms", true, [9.1, 11.4, 14.8, 22, 31.2, 23.4], 15, 30),
      series("system.reliability", "Drive health & reliability", "Blue screens (30 days)", "", true, [0, 0, 0, 1, 1, 2], 1, 3),
      series("net.latency", "Latency & packet loss", "Gateway 10.20.32.1 round trip", "ms", true, [6, 7, 9, 11, 12, 38], 20, 50),
      series("desk.wifi", "Wi-Fi & VPN", "Signal", "%", false, [72, 70, 66, 64, 61, 34], 70, 50),
      series("sec.posture", "Security posture", "Antivirus definitions", "days", true, [0, 1, 0, 2, 1, 5], 3, 7),
    ];
  }

  function mockApi() {
    const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
    const clone = (x) => JSON.parse(JSON.stringify(x));
    const fixed = new Set();
    const saved = new Map();
    let cancelFlag = false;
    const allowed = (id, target) =>
      MOCK_FIXES.some((e) => (e.includes(":") ? e === `${id}:${target}` : e === id && (id !== "start-service" || !target)));
    const lockFor = (m, safe) => {
      if (m.mutating && m.id.startsWith("update.") && !MOCK_PROFILE.policy.allow_installs) return "Blocked by site policy: updates are deployed centrally here.";
      if (safe && m.disruptive) return REMOTE_SAFE_REASON;
      return undefined;
    };
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
    const previewResult = (m) => {
      const pv = MOCK_PREVIEW[m.id];
      const summary = !pv
        ? `Preview: ${m.title} would run. Nothing was changed.`
        : pv[0].startsWith("nothing") ? `Preview: ${pv[0]}.` : `Preview: ${pv[0]}. Nothing was changed.`;
      const findings = pv ? pv[1].map(([l, v, sev]) => F(l, v, sev || "info")) : [F("Would", m.description)];
      return R(m.id, m.title, m.category, summary, 30 + Math.round(Math.random() * 400), findings, { preview: true });
    };
    const targetResult = (text) => {
      if (!text) {
        return R("net.target", "Destination test", "network", "Skipped: no destination given", 1,
          [F("Destination", "none given: type a host name or address, with ports if they aren't 443, 80, 445 and 3389")]);
      }
      const t = mockParseTarget(text);
      const ports = t.ports.length ? t.ports : [443, 80, 445, 3389];
      const literal = /^[\d.]+$/.test(t.host) || t.host.includes(":");
      const ip = literal ? t.host : "10.40.8.20";
      const findings = [literal
        ? F(`DNS ${t.host}`, "an address; no lookup needed")
        : F(`DNS ${t.host}`, `${ip} · resolved in 9 ms`, "ok", null, { metric: M(9, "ms") })];
      let open = 0;
      ports.forEach((port) => {
        if (port === 3389 || port === 80) {
          // As in the engine: a port that was typed and is closed is the
          // answer to the question; a default one is only information.
          const why = `no connection: ${ip} ${port === 80 ? "refused" : "timed out"}`;
          findings.push(t.explicit_ports
            ? F(`${t.host}:${port}`, why, "critical")
            : F(`${t.host}:${port}`, why, "info", "One of the default ports; not every host listens on it."));
        } else {
          open++;
          const ms = port === 445 ? 14 : port === 443 ? 21 : 17;
          findings.push(F(`${t.host}:${port}`, `open · connected in ${ms} ms${literal ? "" : ` (${ip})`}`, "ok", null, { metric: M(ms, "ms") }));
        }
      });
      findings.push(F(`Route to ${t.host}`, "via 10.20.32.1 on Wi-Fi (from 10.20.33.118)", "info", "DNS servers on that interface: 10.20.0.53, 10.20.0.54"));
      findings.push(F(`Ping ${t.host}`, "avg 16 ms (min 12 ms / max 24 ms) · 0% loss", "ok", null, { metric: M(16, "ms") }));
      return R("net.target", "Destination test", "network",
        `${t.host}: ${open} of ${ports.length} port${ports.length === 1 ? "" : "s"} open · ping 16 ms`, 1610, findings);
    };
    const NEW_THIS_VERSION = ["net.latency", "net.proxy", "net.target"];
    const diffFor = (results) => {
      const byMod = new Map(results.map((r) => [r.module_id, r]));
      const changes = MOCK_DIFF.changes.filter((c) => {
        const r = byMod.get(c.module_id);
        if (!r || r.preview) return false;
        if (c.kind === "resolved") return true;
        const f = r.findings.find((x) => x.label === c.label);
        return !!f && RANK[f.severity] >= 2;
      });
      const metrics = MOCK_DIFF.metrics.filter((m) => byMod.has(m.module_id) && !byMod.get(m.module_id).preview);
      const count = (k) => changes.filter((c) => c.kind === k).length;
      return {
        against: MOCK_DIFF.against, generated: new Date().toISOString().replace(/\.\d+Z$/, "Z"),
        changes, metrics, new_issues: count("new"), resolved: count("resolved"), changed: count("changed"), ongoing: count("ongoing"),
        added: results.filter((r) => NEW_THIS_VERSION.includes(r.module_id)).map((r) => r.title), removed: [], gaps: [],
      };
    };
    /** The run before the latest: Spooler down, printers and clock fine. */
    const savedReport = (meta) => {
      if (saved.has(meta.path)) return clone(saved.get(meta.path));
      const ids = CATALOGUE.filter((m) => !m.mutating && !m.takes_target).map((m) => m.id).slice(0, meta.modules);
      const results = ids.map((id) => clone(MOCK_RESULTS[id])).filter(Boolean).map((r) => {
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
        if (r.module_id === "system.disk") {
          r.findings[0] = F("C:\\", "38.1 GB free of 476.9 GB (92% used) · NTFS", "warning", null, { metric: M(8, "% free", false) });
          r.findings[2] = F("Disk latency", "31.2 ms per transfer · queue 2.6", "critical", null, { metric: M(31.2, "ms") });
        }
        if (r.module_id === "desk.wifi") r.findings[1] = F("Signal", "61% · good", "warning", null, { metric: M(61, "%", false) });
        return r;
      });
      const h = meta.hostname === MOCK_HOST.hostname ? clone(MOCK_HOST) : Object.assign(clone(MOCK_HOST), { hostname: meta.hostname, os: "Windows 11 Enterprise 23H2" });
      const report = { schema: 1, generated: meta.generated, host: h, profile: MOCK_PROFILE.name, cancelled: meta.cancelled, results };
      if (meta.ticket) report.ticket = meta.ticket;
      const likely = mockLikely(results);
      if (likely.length) report.likely = likely;
      return report;
    };
    return {
      listModules: async (safe) => CATALOGUE.map((m) => Object.assign({}, m, lockFor(m, safe) ? { locked: lockFor(m, safe) } : {})),
      listPresets: async () => PRESET_CATALOGUE,
      listFixes: async () => FIX_CATALOGUE,
      checkTarget: async (text) => mockParseTarget(text),
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
          if (m.mutating && h.preview) {
            await sleep(160 + Math.random() * 220);
            res = previewResult(m);
          } else if (h.remoteSafe && m.disruptive) {
            await sleep(80);
            res = R(m.id, m.title, m.category, "", 0, [], { error: REMOTE_SAFE_REASON });
          } else if (m.requires_admin && !host.elevated) {
            await sleep(180);
            res = R(m.id, m.title, m.category, "", 1, [], { error: ADMIN_REQUIRED });
          } else {
            const lines = MOCK_LOGS[m.id] || [];
            for (const line of lines) {
              await sleep(110 + Math.random() * 170);
              h.onLog({ id: m.id, line });
            }
            await sleep(220 + Math.random() * 320);
            res = m.id === "net.target" ? targetResult(h.target) : result(m.id, false);
            if (lines.length) res.log = lines.slice();
          }
          results.push(res);
          h.onDone(res);
        }
        // As report::clean_ticket: what a ticket reference is made of, 40 at most.
        const ref = String(h.ticket || "").trim().replace(/[^\p{L}\p{N}\-_#./: ]/gu, "").slice(0, 40).trim() || null;
        const report = {
          schema: 1, generated: new Date().toISOString().replace(/\.\d+Z$/, "Z"), host: clone(host),
          profile: MOCK_PROFILE.name, cancelled: cancelFlag, results,
        };
        if (ref) report.ticket = ref;
        const likely = mockLikely(results);
        if (likely.length) report.likely = likely;
        const stamp = report.generated.replace(/[-:]/g, "");
        const path = `${HIST_DIR}${stamp}_${host.hostname}${ref ? "_" + ref.replace(/[^A-Za-z0-9-]/g, "_") : ""}.json`;
        saved.set(path, clone(report));
        MOCK_HISTORY.unshift({ path, generated: report.generated, hostname: host.hostname, modules: results.length, worst: worstOf(results) || (results.some((r) => statusOf(r) === "info") ? "info" : "ok"), cancelled: report.cancelled, ticket: ref });
        const comparable = results.some((r) => !r.preview && !(CATALOGUE.find((m) => m.id === r.module_id) || {}).mutating);
        return { report, saved: path, save_error: null, diff: report.cancelled || !comparable ? null : diffFor(results) };
      },
      cancel: async () => { cancelFlag = true; return true; },
      recheck: async (id, o) => {
        await sleep(650);
        // As in the engine: a re-check previews anything that changes the machine.
        const m = CATALOGUE.find((x) => x.id === id);
        if (m && m.mutating) return previewResult(m);
        return id === "net.target" ? targetResult(o && o.target) : result(id, true);
      },
      runFix: async (id, target, safe) => {
        await sleep(900 + Math.random() * 500);
        const spec = FIX_CATALOGUE.find((f) => f.id === id);
        if (!spec) throw `Unknown fix \`${id}\`.`;
        if (!allowed(id, target)) throw "Blocked by site policy: this fix isn't allowed on this machine.";
        if (spec.disruptive && safe) throw "Remote-safe mode is on: this could drop the remote session or restart the PC.";
        if (spec.requires_admin && !host.elevated) throw ADMIN_REQUIRED;
        if (!["restart-computer", "cancel-restart"].includes(id)) fixed.add(id + ":" + (target || ""));
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
        try { r = JSON.parse(text); } catch (e) { throw "Not an ITriage report: " + e.message; }
        if (!r || !Array.isArray(r.results) || !r.host || !r.generated) throw "Not an ITriage report: missing host, generated or results.";
        return { report: r, diff: null, saved: null };
      },
      compareWithPrevious: async (report) =>
        report.generated === "2026-11-05T19:02:11Z"
          ? { against: "2026-11-03T14:15:30Z", generated: report.generated, new_issues: 1, resolved: 0, changed: 0, ongoing: 1,
              changes: [
                { module_id: "proc.services", module: "Services", label: "Print Spooler (Spooler)", kind: "new", before: null, after: "critical", value: "stopped · exit 1067 · Automatic" },
                { module_id: "site.apps", module: "Required & clinical apps", label: "Citrix Workspace", kind: "ongoing", before: "warning", after: "warning", value: "23.11.1.45 · needs 24.2 or later" },
              ],
              metrics: [{ module_id: "system.disk", module: "Disk space & latency", label: "C:\\", unit: "% free", before: 11, after: 8, delta: -3, trend: "worse" }],
              added: ["Wi-Fi & VPN", "Battery health"], removed: [], gaps: [] }
          : null,
      compareReports: async (a, b) => {
        await sleep(150);
        if (a.host.hostname.toLowerCase() !== b.host.hostname.toLowerCase()) {
          throw `These runs are from different computers (${a.host.hostname} and ${b.host.hostname}), so they can't be compared.`;
        }
        const [older, newer] = a.generated <= b.generated ? [a, b] : [b, a];
        const d = diffFor(newer.results);
        const olderIds = new Set(older.results.map((r) => r.module_id));
        const newerIds = new Set(newer.results.map((r) => r.module_id));
        d.against = older.generated;
        d.generated = newer.generated;
        d.added = newer.results.filter((r) => !olderIds.has(r.module_id)).map((r) => r.title);
        d.removed = older.results.filter((r) => !newerIds.has(r.module_id)).map((r) => r.title);
        if (older.cancelled) d.gaps.push("The earlier run was cancelled, so some of its checks didn't finish.");
        return d;
      },
      reportText: async (report, diff, withLogs) => plainText(report, diff, withLogs),
      trends: async () => { await sleep(120); return mockTrends(); },
      likelyCauses: async (results) => mockLikely(results),
      refreshReport: async (report) => ({
        report: Object.assign({}, clone(report), { likely: mockLikely(report.results) }),
        diff: report.cancelled ? null : diffFor(report.results),
      }),
      // The preview has no release to compare with; ?update=1 shows the tag.
      checkUpdate: async () => (/[?&]update=1\b/.test(location.search)
        ? { current: VERSION.slice(1), latest: "0.7.2", url: "https://github.com/jp101216/ITriage/releases/tag/v0.7.2", newer: true }
        : null),
      openLink: async (url) => toast("Preview: this opens " + url),
      openHistoryFolder: async () => toast("Preview: this opens " + HIST_DIR.replace(/\\$/, "")),
    };
  }
})();
