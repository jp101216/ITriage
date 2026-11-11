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
            const sample = {at_ms:Date.now(),cpu_pct:17,memory_pct:42,disk_read:10,disk_write:20,net_rx:30,net_tx:40,tcp_ms:12,tcp_error:null,dns_ms:2,dns_error:null,wifi:"TEST-NET"};
            emit("recording-sample",sample);
            await new Promise((done)=>{state.recordingDone=done;});
            const r = args.baseReport || report([]);
            r.recording={started:new Date(sample.at_ms).toISOString(),config:args.config,target:args.target,samples:[sample],markers:state.markers,stopped_early:true,gaps:["Fixture collection"]};
            r.results.push({module_id:"capture.recording",title:"Intermittent problem recording",category:"system",summary:"1 sample",findings:[],error:null,log:[],duration_ms:1});
            return {report:r,saved:"fixture-case.json"};
          }
          case "mark_recording": {const marker={at_ms:Date.now(),label:args.label||"Problem happened now"};state.markers.push(marker);return marker;}
          case "cancel_run": if(state.recordingDone)state.recordingDone();return true;
          case "list_history": return [{path:"good.json",generated:"2026-11-09T17:00:00Z",hostname:"WORKING-PC",cancelled:false}];
          case "load_report": return Object.assign(report([result("system.disk",true)]),{host:Object.assign({},host,{hostname:"WORKING-PC"})});
          case "compare_baseline": return {baseline_host:args.baseline.host.hostname,current_host:args.current.host.hostname,differences:[{module:"system.info",label:"OS",baseline:"24H2",current:"23H2"}],gaps:["Confirm matching workstation roles."]};
          case "timeline_near": return [{at:args.problemAt,source:"System",description:"Driver installation activity",detail:"Timing alone does not establish causation."}];
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
            return { report:r, diff: diff(false), save_error: options.saveError || null };
          }
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
