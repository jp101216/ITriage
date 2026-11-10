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
    const state = window.testState = { calls: [], fixDone: null, recheckDone: null, copied: null };
    Object.defineProperty(navigator, "clipboard", { value: { writeText: async (text) => { state.copied = text; } } });
    const listeners = new Map();
    const emit = (name, payload) => { for (const listener of listeners.get(name) || []) listener({ payload }); };
    const host = { hostname: "TEST-PC", os: "Windows 11", platform: "windows", elevated: true, can_relaunch_elevated: false, elevation_note: "Test fixture" };
    const modules = [
      { id: "system.disk", title: "Disk space & latency", category: "system" },
      { id: "desk.printers", title: "Printers & print queue", category: "workstation" },
    ].map((m) => Object.assign(m, { description: "Fixture", platforms: ["windows", "linux"], mutating: false, disruptive: false, takes_target: false, requires_admin: false }));
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
        switch (command) {
          case "list_modules": return modules;
          case "list_presets": return [];
          case "list_fixes": return [{ id: "restart-spooler", label: "Restart Print Spooler", description: "Restarts the print service.", technician_only: false, requires_admin: false, disruptive: false }];
          case "get_host_context": return host;
          case "get_profile": return { source: "built-in", name: "UI regression test", requirements: 0, kb_rules: 0,
            policy: { start_in: options.self ? "self-service" : "technician", technician_view: true, allow_changes: true, allow_installs: true } };
          case "get_telemetry": return { cpu: 1, cores: [1], mem_pct: 10, mem_used: 100, mem_total: 1000, net_rx: 0, net_tx: 0, disk_read: 0, disk_write: 0, fullest_pct: 10, fullest_mount: "C:" };
          case "check_update": return null;
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
            return { report: report(results), diff: diff(false), save_error: options.saveError || null };
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
