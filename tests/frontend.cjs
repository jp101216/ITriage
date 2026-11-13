// Drive the actual frontend through a controllable Tauri bridge. All repairs
// and checks here are fixtures; this suite never changes the host machine.
const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const { createServer } = require("node:http");
const { readFile } = require("node:fs/promises");
const { resolve, extname } = require("node:path");
const { chromium } = require("playwright");

let server, browser, base;
before(async () => {
  const root = resolve(__dirname, "../src");
  const types = { ".html": "text/html", ".js": "text/javascript", ".css": "text/css", ".woff2": "font/woff2" };
  server = createServer(async (req, res) => {
    const path = resolve(root, "." + new URL(req.url, "http://localhost").pathname.replace(/\/$/, "/index.html"));
    if (!path.startsWith(root + "/")) { res.writeHead(403).end(); return; }
    try {
      const body = await readFile(path);
      res.writeHead(200, { "content-type": types[extname(path)] || "application/octet-stream" }).end(body);
    } catch { res.writeHead(404).end(); }
  });
  await new Promise((done) => server.listen(0, "127.0.0.1", done));
  base = `http://127.0.0.1:${server.address().port}`;
  browser = await chromium.launch({ executablePath: process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE || undefined });
});
after(async () => {
  if (browser) await browser.close();
  if (server) await new Promise((done) => server.close(done));
});

async function pageFor(t, options = {}) {
  const page = await browser.newPage({ viewport: { width: 1240, height: 880 } });
  const errors = [];
  page.on("pageerror", (e) => errors.push(e.message));
  t.after(async () => { await page.close(); assert.deepEqual(errors, [], "no frontend exceptions"); });
  if (!options.preview) await page.addInitScript((options) => {
    const state = window.testState = { calls: [], args: [], fixDone: null, recheckDone: null, copied: null, recordingDone:null, markers:[] };
    Object.defineProperty(navigator, "clipboard", { value: { writeText: async (text) => { state.copied = text; } } });
    const listeners = new Map();
    const emit = (name, payload) => { for (const listener of listeners.get(name) || []) listener({ payload }); };
    const host = { hostname: "TEST-PC", os: "Windows 11", platform: "windows", elevated: true, can_relaunch_elevated: false, elevation_note: "Test fixture" };
    const modules = [
      { id: "system.disk", title: "Disk space & latency", category: "system" },
      { id: "desk.printers", title: "Printers & print queue", category: "workstation" },
    ].concat(options.timeline ? [{id:"system.changes",title:"Recent changes timeline",category:"system"},{id:"net.wifi-auth",title:"Network authentication history",category:"network"}] : []).map((m) => Object.assign(m, { description: "Fixture", platforms: ["windows", "linux"], mutating: false, disruptive: false, takes_target: false, requires_admin: false }));
    const result = (id, fixed = false) => {
      const module = modules.find((m) => m.id === id);
      if (id === "system.changes" && options.events) {
        const rows = Array.from({ length: options.events }, (_, i) => ({ label: `2026-11-10T12:${String(59 - i).padStart(2, "0")}:00Z · Package change`, value: `Installed lib${i}`, severity: "info" }));
        rows.splice(15, 0, { label: "2026-11-10T11:00:00Z · Windows update", value: "Failed to install: KB1", severity: "warning" });
        rows.push({ label: "Timeline coverage", value: "the last seven days", severity: "info" });
        return { module_id: id, title: module.title, category: module.category, summary: `${options.events} change events`, findings: rows, error: null,
          preview: false, restart_required: false, duration_ms: 1, log: [] };
      }
      const finding = id === "desk.printers" && !fixed
        ? { label: "Queue", value: "1 stuck job", severity: "warning", action: { id: "restart-spooler", label: "Restart Print Spooler", requires_admin: false } }
        : { label: id === "desk.printers" ? "Queue" : "Free", value: "healthy", severity: "ok" };
      return { module_id: id, title: module.title, category: module.category, summary: finding.value, findings: [finding], error: null,
        preview: false, restart_required: false, duration_ms: 1, log: [fixed ? "After the fix" : "Before the fix"] };
    };
    const report = (results) => ({ schema: 1, tool_version: "0.7.0", generated: "2026-11-10T17:00:00Z", host, results, cancelled: false, exit_code: 0, likely: [] });
    const diff = (fixed) => ({ against: "2026-11-09T17:00:00Z", generated: "2026-11-10T17:00:00Z",
      new_issues: 0, resolved: fixed ? 1 : 0, changed: 0, ongoing: fixed ? 0 : 1,
      changes: [{ module_id: "desk.printers", module: "Printers & print queue", label: "Queue", kind: fixed ? "resolved" : "ongoing",
        before: "warning", after: fixed ? "ok" : "warning", value: fixed ? "healthy" : "1 stuck job" }], metrics: [], added: [], removed: [], gaps: [] });
    window.__TAURI__ = {
      event: { listen: async (name, listener) => {
        if (!listeners.has(name)) listeners.set(name, new Set());
        listeners.get(name).add(listener);
        return () => listeners.get(name).delete(listener);
      } },
      core: { invoke: async (command, args = {}) => {
        state.calls.push(command);
        state.args.push({command,args});
        switch (command) {
          case "list_modules": return modules;
          case "list_presets": return [];
          case "list_fixes": return [{ id: "restart-spooler", label: "Restart Print Spooler", description: "Restarts the print service.", technician_only: false, requires_admin: false, disruptive: false }];
          case "get_host_context": return host;
          case "get_profile": return { source: "built-in", name: "UI regression test", requirements: 0, kb_rules: 0,
            policy: { start_in: options.self ? "self-service" : "technician", technician_view: true, allow_changes: true, allow_installs: true } };
          case "get_telemetry": return { cpu: 1, cores: [1], mem_pct: 10, mem_used: 100, mem_total: 1000, net_rx: 0, net_tx: 0, disk_read: 0, disk_write: 0, fullest_pct: 10, fullest_mount: "C:" };
          case "check_update": return null;
          case "list_runbooks": return [{id:"printing",title:"Printing fails",symptom:"Read-only diagnostic steps"}];
          case "runbook_plan": return {modules:["desk.printers","system.disk"],reason:"Inspect printing and storage first."};
          case "record_problem": {
            const sample = {at_ms:Date.now(),cpu_pct:17,memory_pct:42,disk_read:10,disk_write:2500000,net_rx:30,net_tx:40,tcp_ms:12,tcp_error:null,dns_ms:2,dns_error:null,wifi:"TEST-NET",wifi_signal:71,wifi_bssid:"aa:aa:aa:aa:aa:01"};
            emit("recording-sample",sample);
            await new Promise((done)=>{state.recordingDone=done;});
            const r = args.baseReport || report([]);
            // A second sample after the marker: the PC has moved access point and the connection fails.
            const later = Object.assign({}, sample, {at_ms:Date.now()+1000,cpu_pct:64,tcp_ms:null,tcp_error:"timed out",wifi_signal:38,wifi_bssid:"aa:aa:aa:aa:aa:02"});
            r.recording={started:new Date(sample.at_ms).toISOString(),config:args.config,target:args.target,samples:[sample,later],markers:state.markers,stopped_early:true,gaps:["Fixture collection"]};
            r.results.push({module_id:"capture.recording",title:"Intermittent problem recording",category:"system",summary:"1 sample",findings:[],error:null,log:[],duration_ms:1});
            return {report:r,saved:"fixture-case.json"};
          }
          case "mark_recording": {const marker={at_ms:Date.now(),label:args.label||"Problem happened now"};state.markers.push(marker);return marker;}
          case "cancel_run": if(state.recordingDone)state.recordingDone();return true;
          case "list_history": return [{path:"mine.json",generated:"2026-11-10T16:00:00Z",hostname:"test-pc",modules:2,cancelled:false}]
            .concat(options.onlyOwnHistory ? [] : [{path:"good.json",generated:"2026-11-09T17:00:00Z",hostname:"WORKING-PC",modules:9,cancelled:false}]);
          case "load_report": return Object.assign(report([result("system.disk",true)]),{host:Object.assign({},host,{hostname:"WORKING-PC"})});
          case "compare_baseline": return {baseline_host:args.baseline.host.hostname,current_host:args.current.host.hostname,differences:[{module:"system.info",label:"OS",baseline:"24H2",current:"23H2"}],gaps:["Confirm matching workstation roles."]};
          case "timeline_near": return [{at:args.problemAt,source:"System",description:"Driver installation activity",detail:"Timing alone does not establish causation."}];
          case "timeline_rows": return [{at:"2026-11-10T16:21:08Z",until:"2026-11-10T16:38:50Z",source:"Recent changes timeline",kind:"Windows update",description:"31 events until 2026-11-10T16:38:50Z: Package KB1: Installed; and 30 more",detail:"Setup"}];
          case "preview_case_bundle": {
            const r=JSON.parse(JSON.stringify(args.report));if(args.options.redact_identifiers)r.host.hostname="[host-1]";
            const text=JSON.stringify(r,null,2),contents={"report.json":text,"report.txt":text};if(args.options.include_logs)contents["logs/fixture.txt"]="Reviewed fixture log";
            return {contents,files:Object.entries(contents).map(([name,text])=>({name,bytes:text.length,sha256:"a".repeat(64)})),bytes:text.length,note:"Review every file.",redacted:args.options.redact_identifiers};
          }
          case "export_case_bundle": return "C:\\cases\\reviewed.zip";
          case "open_cases_folder": return;
          case "run_modules": {
            if (args.record === false) {
              if (options.failRecheck) throw "Controlled re-check failure";
              await new Promise((done) => { state.recheckDone = done; });
              return { report: report([result(args.selected[0], true)]) };
            }
            const results = args.selected.map((id, index) => {
              emit("module-start", { id, title: modules.find((m) => m.id === id).title, index, total: args.selected.length });
              const r = result(id);
              emit("module-log", { id, line: "Before the fix" });
              emit("module-done", r);
              return r;
            });
            if(options.failCaseRefresh && args.baseReport)throw "Controlled case refresh failure";
            const r=args.baseReport ? Object.assign({},args.baseReport,{results:args.baseReport.results.filter((old)=>!results.some((n)=>n.module_id===old.module_id)).concat(results),evidence_updated:"2026-11-10T17:01:00Z"}) : report(results);
            if(args.runbook)r.runbook={id:args.runbook,steps:[{modules:args.selected,reason:"Inspect printing and storage first."}],finished:true,conclusion:"Review findings; completing checks does not mean the issue is repaired."};
            if(options.incident)r.known_incidents=[{id:"INC0012345",title:"Print server outage <b>now</b>",url:"https://status.example.org/INC0012345",because:"Printers & print queue: Print Spooler: stopped"}];
            return { report:r, diff: diff(false), save_error: options.saveError || null };
          }
          case "preview_fix": return "Preview: would restart the Print Spooler; 1 job is waiting. Nothing was changed.";
          case "run_fix": await new Promise((done) => { state.fixDone = done; }); return "Print Spooler restarted.";
          case "refresh_report": {
            if (options.failRefresh) throw "Controlled refresh failure";
            return { report: Object.assign({}, args.report, { likely: [], exit_code: 0 }), diff: diff(true) };
          }
          case "likely_causes": return [];
          default: throw `Unexpected command: ${command}`;
        }
      } },
    };
  }, options);
  await page.goto(base);
  if (!options.preview) await page.waitForFunction(() => document.getElementById("profileName").textContent.includes("UI regression test"));
  return page;
}

async function runAndFix(page, self = false) {
  await page.locator(self ? "#ssGo" : "#run").click();
  const button = page.locator(self ? ".ss-fix" : ".fix-btn").first();
  await button.waitFor();
  await button.click();
  if (!self) {
    // The confirmation says what the fix would do here, from its preview.
    const preview = page.locator(".modal .fix-preview");
    await preview.waitFor();
    assert.match(await preview.textContent(), /1 job is waiting/);
  }
  await page.getByRole("button", { name: self ? "Go ahead" : "Run fix", exact: true }).click();
  await page.waitForFunction(() => typeof testState.fixDone === "function");
}

test("a fix and its re-check block new runs without clearing the live results", async (t) => {
  const page = await pageFor(t);
  await runAndFix(page);
  assert.equal(await page.locator("#run").isDisabled(), true);
  assert.equal(await page.locator("#toSelf").isDisabled(), true);
  await page.locator("#run").evaluate((button) => button.click());
  assert.equal(await page.locator("#results .card").count(), 2);
  await page.evaluate(() => testState.fixDone());
  await page.waitForFunction(() => typeof testState.recheckDone === "function");
  assert.equal(await page.locator("#run").isDisabled(), true, "the re-check is part of the same operation");
  await page.evaluate(() => testState.recheckDone());
  await page.waitForFunction(() => !document.getElementById("run").disabled);
  assert.equal(await page.locator("#results .card").count(), 2);
  assert.equal(await page.evaluate(() => testState.calls.filter((c) => c === "run_modules").length), 2);
});

test("a successful re-check refreshes comparison, export metadata and displayed logs", async (t) => {
  const page = await pageFor(t);
  await runAndFix(page);
  await page.evaluate(() => testState.fixDone());
  await page.waitForFunction(() => typeof testState.recheckDone === "function");
  await page.evaluate(() => testState.recheckDone());
  await page.waitForFunction(() => !document.getElementById("run").disabled);
  assert.match(await page.locator(".banner.diff").innerText(), /1 resolved/);
  assert.doesNotMatch(await page.locator(".banner.diff").innerText(), /1 still failing/);
  const card = page.locator('.card[data-mod="desk.printers"]');
  assert.match(await card.locator("pre.log").textContent(), /After the fix/);
  assert.doesNotMatch(await card.locator("pre.log").textContent(), /Before the fix/);
  await page.locator("#exportBtn").click();
  await page.locator('[data-fmt="json"]').click();
  const exported = await page.evaluate(() => JSON.parse(testState.copied));
  assert.equal(exported.exit_code, 0);
  assert.equal(exported.results.find((r) => r.module_id === "desk.printers").findings[0].severity, "ok");
  assert.equal(await page.evaluate(() => testState.calls.includes("refresh_report")), true);
});

test("a failed re-check leaves a clear result and releases the controls", async (t) => {
  const page = await pageFor(t, { failRecheck: true });
  await runAndFix(page);
  await page.evaluate(() => testState.fixDone());
  await page.waitForFunction(() => !document.getElementById("run").disabled);
  assert.equal(await page.locator(".fix-slot .busy").count(), 0);
  assert.match(await page.locator(".fix-slot").innerText(), /re-check couldn't finish/);
});

test("self-service keeps its controls locked until the fix has been checked", async (t) => {
  const page = await pageFor(t, { self: true });
  await runAndFix(page, true);
  assert.equal(await page.locator("#ssGo").isDisabled(), true);
  assert.equal(await page.locator("#ssTech").isDisabled(), true);
  await page.evaluate(() => testState.fixDone());
  await page.waitForFunction(() => typeof testState.recheckDone === "function");
  assert.equal(await page.locator("#ssGo").isDisabled(), true);
  await page.evaluate(() => testState.recheckDone());
  await page.waitForFunction(() => !document.getElementById("ssGo").disabled);
  assert.match(await page.locator("#ssResults").innerText(), /Everything looks good/);
});

test("a known incident goes above everything, escaped, and into the ticket text", async (t) => {
  const page = await pageFor(t, { incident: true });
  await page.locator("#run").click();
  const banner = page.locator("#results > .banner.incident");
  await banner.waitFor();
  assert.equal(await page.locator("#results > .banner").first().getAttribute("class"), "banner incident");
  assert.match(await banner.textContent(), /INC0012345 Print server outage <b>now<\/b>/);
  assert.equal(await banner.locator("b", { hasText: "now" }).count(), 0, "feed text is escaped");
  assert.equal(await banner.locator("a.kb-link").getAttribute("href"), "https://status.example.org/INC0012345");
});

test("self-service reports a history save failure", async (t) => {
  const page = await pageFor(t, { self: true, saveError: "Disk full" });
  await page.locator("#ssGo").click();
  await page.locator(".ss-fix").waitFor();
  assert.match(await page.locator(".toast").innerText(), /Couldn't save this run.*Disk full/);
});

test("the browser preview rejects malformed and conflicting destination ports", async (t) => {
  const page = await pageFor(t, { preview: true });
  const input = page.locator("input.dest");
  for (const text of ["[::1]:", "[::1]garbage", "[server]:443", "server:", "server:,;", "server:443 80", "server:1e3"]) {
    await input.fill(text);
    await input.blur();
    assert.equal(await page.locator(".dest-err").isVisible(), true, text);
  }
  await input.fill("[::1]:443");
  await input.blur();
  assert.equal(await page.locator(".dest-err").isVisible(), false);
});

test("guided troubleshooting preserves the reason for its diagnostic steps",async(t)=>{
  const page=await pageFor(t);
  await page.locator("#guidedBtn").click();
  await page.getByRole("button",{name:/Printing fails/}).click();
  await page.locator(".case-note").waitFor();
  assert.match(await page.locator(".case-note").innerText(),/completing checks does not mean.*repaired/);
  await page.getByText("Why these checks ran").click();
  assert.match(await page.locator(".case-note").innerText(),/Inspect printing and storage first/);
  assert.equal(await page.evaluate(()=>testState.args.find((c)=>c.command==="run_modules").args.runbook),"printing");
});

test("recording keeps existing evidence, accepts markers, stops and replays",async(t)=>{
  const page=await pageFor(t);await page.locator("#run").click();await page.locator("#results .card").first().waitFor();
  await page.locator("#recordBtn").click();await page.locator("#caseStart").click();
  await page.waitForFunction(()=>typeof testState.recordingDone==="function");
  assert.equal(await page.locator("#guidedBtn").isDisabled(),true);
  await page.locator("#caseMarker").fill("Print job stalled");await page.locator("#caseMark").click();
  await page.getByText(/Print job stalled/).last().waitFor();await page.locator("#caseStop").click();
  await page.getByText(/Capture finished/).waitFor();await page.getByRole("button",{name:"Close",exact:true}).click();
  assert.equal(await page.locator("#results .card").count(),3,"capture attaches to existing diagnostic results");
  await page.getByRole("button",{name:"Replay recording",exact:true}).click();
  await page.locator(".case-marker-pick").selectOption("0");
  assert.match(await page.locator(".case-samples").innerText(),/TEST-NET/);
  assert.match(await page.locator(".case-samples").innerText(),/17.0/);
});

test("case exports require a fresh preview after privacy options change",async(t)=>{
  const page=await pageFor(t);await page.locator("#run").click();await page.locator("#results .card").first().waitFor();
  await page.locator("#bundleBtn").click();assert.equal(await page.locator("#caseExport").isDisabled(),true);
  await page.locator("#casePreview").click();await page.waitForFunction(()=>!document.querySelector("#caseExport").disabled);
  assert.match(await page.locator("#caseBundleText").inputValue(),/\[host-1\]/);
  assert.doesNotMatch(await page.locator("#caseBundleText").inputValue(),/TEST-PC/);
  await page.locator("#caseLogs").check();assert.equal(await page.locator("#caseExport").isDisabled(),true);
  await page.locator("#casePreview").click();await page.waitForFunction(()=>!document.querySelector("#caseExport").disabled);
  await page.locator("#caseInspect").selectOption("logs/fixture.txt");assert.equal(await page.locator("#caseBundleText").inputValue(),"Reviewed fixture log");
  await page.locator("#caseExport").click();await page.getByText(/Case saved:.*reviewed.zip/).waitFor();
  assert.equal(await page.evaluate(()=>testState.args.find((c)=>c.command==="export_case_bundle").args.options.include_logs),true);
});

test("working-PC comparison keeps the baseline and current direction explicit",async(t)=>{
  const page=await pageFor(t);await page.locator("#run").click();await page.locator("#results .card").first().waitFor();
  await page.locator("#baselineBtn").click();await page.locator("#caseCompareBaseline").click();
  await page.getByText(/Working baseline: WORKING-PC.*Current: TEST-PC/).waitFor();
  assert.match(await page.locator("#caseBaselineResult").innerText(),/24H2/);
  const args=await page.evaluate(()=>testState.args.find((c)=>c.command==="compare_baseline").args);
  assert.equal(args.baseline.host.hostname,"WORKING-PC");assert.equal(args.current.host.hostname,"TEST-PC");
});

test("timeline uses the chosen onset and explains temporal uncertainty",async(t)=>{
  const page=await pageFor(t);await page.locator("#run").click();await page.locator("#results .card").first().waitFor();
  await page.locator("#timelineBtn").click();await page.getByText("Driver installation activity").waitFor();
  assert.match(await page.getByRole("dialog").innerText(),/timing alone does not establish the cause/);
  await page.locator("#caseOnset").fill("2026-11-10T12:34");await page.locator("#caseWindow").selectOption("900");await page.locator("#caseFindChanges").click();
  await page.waitForFunction(()=>testState.args.some((c)=>c.command==="timeline_near"&&c.args.windowSeconds===900));
});

test("post-incident timeline collection retains a case recording and its markers",async(t)=>{
  const page=await pageFor(t,{timeline:true});await page.locator("#run").click();await page.locator("#results .card").first().waitFor();
  await page.locator("#recordBtn").click();await page.locator("#caseStart").click();await page.waitForFunction(()=>typeof testState.recordingDone==="function");
  await page.locator("#caseMarker").fill("VPN dropped");await page.locator("#caseMark").click();await page.getByText(/VPN dropped/).last().waitFor();
  await page.locator("#caseStop").click();await page.getByText(/Capture finished/).waitFor();await page.getByRole("button",{name:"Close",exact:true}).click();
  await page.locator("#timelineBtn").click();await page.locator("#caseCollectTimeline").click();
  await page.waitForFunction(()=>testState.args.some((c)=>c.command==="run_modules"&&c.args.baseReport));
  await page.getByRole("button",{name:"Replay recording",exact:true}).waitFor();
  assert.equal(await page.locator("#results .card").count(),5);
  await page.locator("#bundleBtn").click();await page.locator("#casePreview").click();await page.waitForFunction(()=>!document.querySelector("#caseExport").disabled);
  const call=await page.evaluate(()=>testState.args.filter((c)=>c.command==="preview_case_bundle").at(-1));
  assert.equal(call.args.report.recording.markers[0].label,"VPN dropped");assert.ok(call.args.report.evidence_updated);
});

test("a failed case refresh preserves the report and its recording",async(t)=>{
  const page=await pageFor(t,{timeline:true,failCaseRefresh:true});await page.locator("#run").click();await page.locator("#results .card").first().waitFor();
  await page.locator("#recordBtn").click();await page.locator("#caseStart").click();await page.waitForFunction(()=>typeof testState.recordingDone==="function");await page.locator("#caseStop").click();await page.getByText(/Capture finished/).waitFor();await page.getByRole("button",{name:"Close",exact:true}).click();
  await page.locator("#timelineBtn").click();await page.locator("#caseCollectTimeline").click();
  await page.getByText(/Controlled case refresh failure/).waitFor();await page.getByRole("button",{name:"Replay recording",exact:true}).waitFor();
  assert.equal(await page.locator("#results .card").count(),5);assert.equal(await page.locator("#run").isDisabled(),false);
});

test("the checks filter narrows the list without touching what is ticked",async(t)=>{
  const page=await pageFor(t,{timeline:true});
  const ticked=()=>page.evaluate(()=>[...document.querySelectorAll('.mod[aria-checked="true"]')].map((m)=>m.dataset.id).sort());
  const before=await ticked();assert.ok(before.length>=2);
  await page.locator("body").press("/");
  assert.equal(await page.evaluate(()=>document.activeElement.id),"modFilter","/ jumps to the filter");
  await page.keyboard.type("print");
  assert.deepEqual(await page.locator(".mod:visible").evaluateAll((rows)=>rows.map((r)=>r.dataset.id)),["desk.printers"]);
  assert.deepEqual(await page.locator(".cat:visible").allInnerTexts().then((c)=>c.map((x)=>x.toLowerCase())),["workstation"],"a heading with nothing under it goes too");
  assert.deepEqual(await ticked(),before,"hidden checks keep their ticks");
  await page.locator("#modFilter").fill("no such check");
  assert.match(await page.locator(".no-match").innerText(),/No check matches "no such check"/);
  await page.locator("#modFilter").press("Escape");
  assert.equal(await page.locator("#modFilter").inputValue(),"");
  assert.equal(await page.locator(".mod:visible").count(),4);
  assert.equal(await page.locator(".no-match").count(),0);
});

test("a long history shows its newest rows, and exports say what they left out",async(t)=>{
  const page=await pageFor(t,{timeline:true,events:30});
  await page.locator("#run").click();
  const card=page.locator('.card[data-mod="system.changes"]');await card.waitFor();
  // Twelve events and the flagged one show; the coverage note at the end stays in sight.
  assert.equal(await card.locator(".fr:visible").count(),12+1+1);
  assert.match(await card.locator(".fr:visible").allInnerTexts().then((r)=>r.join("\n")),/Failed to install: KB1[\s\S]*Timeline coverage/);
  assert.match(await card.locator(".more-rows").innerText(),/Show 18 older event rows/);
  await page.locator("#exportBtn").click();await page.locator('[data-fmt="md"]').click();
  const md=await page.evaluate(()=>testState.copied);
  assert.match(md,/Installed lib7 \|/);assert.doesNotMatch(md,/Installed lib8 \|/);
  assert.match(md,/Failed to install: KB1/,"a flagged row is never left out");
  assert.match(md,/7 more event rows: in the full transcript/);assert.match(md,/15 more event rows/);
  await card.locator(".more-rows").click();
  assert.equal(await card.locator(".fr:visible").count(),30+1+1);
  assert.equal(await card.locator(".more-rows").count(),0);
});

test("a working PC is another PC, and the dialog says so when there is none",async(t)=>{
  const page=await pageFor(t);await page.locator("#run").click();await page.locator("#results .card").first().waitFor();
  await page.locator("#baselineBtn").click();
  assert.deepEqual(await page.locator("#caseBaselinePick option").evaluateAll((o)=>o.map((x)=>x.value)),["good.json"],"this PC's own reports aren't offered");
  assert.match(await page.locator("#caseBaselinePick option").innerText(),/WORKING-PC · .* · 9 checks/);
  await page.getByRole("button",{name:"Close",exact:true}).click();
  const alone=await pageFor(t,{onlyOwnHistory:true});await alone.locator("#run").click();await alone.locator("#results .card").first().waitFor();
  await alone.locator("#baselineBtn").click();
  assert.match(await alone.getByRole("dialog").innerText(),/No report from another PC is here yet/);
  assert.equal(await alone.locator("#caseCompareBaseline").count(),0);
});

test("a replay opens at its top and draws the marker, the move and the failure",async(t)=>{
  const page=await pageFor(t);await page.setViewportSize({width:1240,height:560});
  await page.locator("#run").click();await page.locator("#results .card").first().waitFor();
  await page.locator("#recordBtn").click();await page.locator("#caseStart").click();
  await page.waitForFunction(()=>typeof testState.recordingDone==="function");
  await page.locator("#caseMarker").fill("Call dropped");await page.locator("#caseMarker").press("Enter");
  await page.locator("#caseMarkers li").filter({hasText:/^1: .*Call dropped$/}).waitFor();
  await page.locator("#caseStop").click();await page.getByText(/Capture finished/).waitFor();
  await page.getByRole("button",{name:"Close",exact:true}).click();
  assert.match(await page.locator(".case-note").first().innerText(),/2 samples · 1 marker · 1 failed connection/);
  await page.getByRole("button",{name:"Replay recording",exact:true}).click();
  const dialog=page.getByRole("dialog");
  assert.equal(await dialog.evaluate((m)=>m.scrollTop),0,"a dialog taller than the window opens at its top");
  assert.ok(await dialog.evaluate((m)=>m.scrollHeight>m.clientHeight),"and this one is taller than the window");
  assert.match(await dialog.innerText(),/2 samples · 1 marker · no TCP target · 1 failed connection · moved access point once/);
  assert.equal(await dialog.locator("svg .mk").count(),1);
  assert.equal(await dialog.locator("svg .roam").count(),1);
  assert.equal(await dialog.locator("svg rect.fail").count(),1);
  assert.match(await dialog.locator("svg").getAttribute("aria-label"),/1 marker, 1 failed connection/);
  await dialog.locator(".case-marker-pick").selectOption("fails");
  const rows=await dialog.locator(".case-samples tbody tr").allInnerTexts();
  assert.equal(rows.length,1);assert.match(rows[0],/failed: timed out/);assert.match(rows[0],/2\.4 MB\/s/,"rates are written for people");
  assert.match(rows[0],/1: Call dropped/,"the marker is on the first sample after it");
});

test("exports carry what the investigation added",async(t)=>{
  const page=await pageFor(t);
  await page.locator("#guidedBtn").click();await page.getByRole("button",{name:/Printing fails/}).click();
  await page.locator(".case-note").waitFor();
  await page.locator("#baselineBtn").click();await page.locator("#caseCompareBaseline").click();
  await page.getByText(/Working baseline: WORKING-PC/).waitFor();await page.getByRole("button",{name:"Close",exact:true}).click();
  await page.locator("#exportBtn").click();await page.locator('[data-fmt="md"]').click();
  const md=await page.evaluate(()=>testState.copied);
  assert.match(md,/### Investigation/);
  assert.match(md,/- Troubleshooting: printing — Review findings/);
  assert.match(md,/  - Phase 1: Inspect printing and storage first\. \[desk\.printers, system\.disk\]/);
  assert.match(md,/- Working-PC baseline: WORKING-PC -> TEST-PC: 1 configuration difference\(s\)/);
  assert.match(md,/  - system\.info · OS: 24H2 -> 23H2/);
});

test("the timeline can show everything collected, with each row placed against the onset",async(t)=>{
  const page=await pageFor(t);await page.locator("#run").click();await page.locator("#results .card").first().waitFor();
  await page.locator("#timelineBtn").click();await page.getByText("Driver installation activity").waitFor();
  await page.locator("#caseOnset").fill("2026-11-10T16:40");
  await page.locator("#caseWindow").selectOption("all");await page.locator("#caseFindChanges").click();
  await page.getByText(/Package KB1: Installed/).waitFor();
  const row=await page.locator("#caseTimelineRows tbody tr").innerText();
  assert.match(row,/Windows update/);assert.match(row,/before|after/);
  assert.match(row,/31 events: Package KB1/,"the end of a burst is in the When column, not repeated in the text");
  assert.equal(await page.evaluate(()=>testState.calls.includes("timeline_rows")),true);
});
