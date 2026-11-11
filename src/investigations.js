/* Technician case workflows. The desktop bridge owns collection, policy,
 * persistence and privacy processing; this file renders evidence only. */
(function () {
  "use strict";
  const esc = (s) =>
    String(s == null ? "" : s).replace(
      /[&<>"']/g,
      (c) =>
        ({
          "&": "&amp;",
          "<": "&lt;",
          ">": "&gt;",
          '"': "&quot;",
          "'": "&#39;",
        })[c],
    );
  const stamp = (ms) => new Date(ms).toLocaleString();
  const button = (id, label) =>
    `<button class="bk-btn" type="button" id="${id}">${label}</button>`;
  const table = (heads, rows) =>
    `<div class="case-scroll"><table class="mtable"><thead><tr>${heads.map((h) => `<th>${esc(h)}</th>`).join("")}</tr></thead><tbody>${rows.map((r) => `<tr>${r.map((v) => `<td>${esc(v)}</td>`).join("")}</tr>`).join("")}</tbody></table></div>`;
  const sampleTable = (rows) =>
    table(
      [
        "Time",
        "CPU %",
        "RAM %",
        "TCP ms / failure",
        "DNS ms / failure",
        "Disk R/W B/s",
        "Network Rx/Tx B/s",
        "Wi-Fi",
      ],
      rows.map((s) => [
        stamp(s.at_ms),
        Number(s.cpu_pct).toFixed(1),
        Number(s.memory_pct).toFixed(1),
        s.tcp_error || (s.tcp_ms == null ? "not sampled" : s.tcp_ms.toFixed(1)),
        s.dns_error || (s.dns_ms == null ? "not sampled" : s.dns_ms.toFixed(1)),
        `${s.disk_read} / ${s.disk_write}`,
        `${s.net_rx} / ${s.net_tx}`,
        s.wifi || "unavailable",
      ]),
    );
  function chart(samples) {
    if (!samples.length) return "<p>Waiting for the first sample…</p>";
    const first = samples[0].at_ms,
      span = Math.max(1000, samples[samples.length - 1].at_ms - first);
    const points = (key) =>
      samples
        .map(
          (s) =>
            `${40 + ((s.at_ms - first) / span) * 590},${160 - Math.min(100, Math.max(0, s[key])) * 1.4}`,
        )
        .join(" ");
    return `<svg class="case-chart" viewBox="0 0 650 195" role="img" aria-label="CPU and RAM percentage over the recording; exact values in the sample table">
      <path d="M40 20V160H630" stroke="currentColor" fill="none" opacity=".4"/>
      <text x="4" y="25">100%</text><text x="18" y="164">0%</text><text x="40" y="187">0 s</text><text x="565" y="187">${Math.round(span / 1000)} s</text>
      <polyline points="${points("cpu_pct")}" fill="none" stroke="var(--accent)" stroke-width="2"/>
      <polyline points="${points("memory_pct")}" fill="none" stroke="currentColor" stroke-dasharray="6 4" stroke-width="2"/>
    </svg><p class="case-legend">CPU: solid accent line · RAM: dashed line · local samples, not process tracing</p>`;
  }
  function create(c) {
    const { api, modal, toast } = c;
    const ready = () => {
      if (c.busy()) {
        toast("Wait for the current operation to finish first.");
        return false;
      }
      return true;
    };
    const current = () => {
      const r = c.currentReport().report;
      if (!r || !r.results.length) {
        toast("Run checks or open a report first.");
        return null;
      }
      return r;
    };
    async function guided() {
      if (!ready()) return;
      try {
        const books = await api.listRunbooks();
        modal({
          title: "Troubleshoot a symptom",
          cls: "wide",
          body: `<p>Each runbook starts with read-only checks, then chooses its next checks from the evidence. Its report explains each phase. Offered repairs still require their usual confirmation.</p><div class="case-runbooks">${books.map((b) => `<button class="bk-btn case-runbook" data-book="${esc(b.id)}" type="button"><strong>${esc(b.title)}</strong><span>${esc(b.symptom)}</span></button>`).join("")}</div>`,
          actions: [{ label: "Close" }],
          onMount: (root, close) => {
            root.querySelectorAll("[data-book]").forEach(
              (b) =>
                (b.onclick = async () => {
                  b.disabled = true;
                  try {
                    const plan = await api.runbookPlan(b.dataset.book);
                    close();
                    await c.startRun(plan.modules, b.dataset.book);
                  } catch (e) {
                    toast(String(e));
                    b.disabled = false;
                  }
                }),
            );
          },
        });
      } catch (e) {
        toast(String(e));
      }
    }
    function record() {
      if (!ready()) return;
      modal({
        title: "Record an intermittent issue",
        cls: "wide",
        body: `<p>Capture CPU, RAM, disk/network rates, short TCP/DNS probes and available Wi-Fi state while the user reproduces the issue. Mark the moment it happens. No packet bodies, screenshots or tokens are captured.</p>
        <div class="case-fields"><label>Duration (seconds)<input id="caseSeconds" type="number" min="5" max="1800" value="60"></label><label>Interval (seconds)<select id="caseInterval"><option value="1000">1</option><option value="2000">2</option><option value="5000">5</option><option value="10000">10</option></select></label><label>Optional target (host:port)<input id="caseTarget" maxlength="2048" placeholder="appserver:443"></label></div>
        <div class="case-actions">${button("caseStart", "Start recording")}${button("caseStop", "Stop recording")}</div><p id="caseRecordStatus" role="status">Ready. Site network-probe policy applies.</p><div id="caseCaptureChart"></div>
        <div class="case-fields"><label>Problem marker<input id="caseMarker" maxlength="200" placeholder="App froze / sign-in prompt / disconnect"></label>${button("caseMark", "Problem happened now")}</div><ul id="caseMarkers"></ul>`,
        actions: [{ label: "Close" }],
        onMount: (root) => {
          const q = (s) => root.querySelector(s),
            samples = [];
          let active = false;
          q("#caseStop").disabled = q("#caseMark").disabled = true;
          q("#caseStart").onclick = async () => {
            const seconds = Number(q("#caseSeconds").value);
            if (!Number.isInteger(seconds) || seconds < 5 || seconds > 1800) {
              toast("Choose a duration from 5 to 1800 seconds.");
              return;
            }
            if (c.busy()) return;
            active = true;
            samples.length = 0;
            q("#caseMarkers").replaceChildren();
            root
              .querySelectorAll(".case-fields input,.case-fields select")
              .forEach((n) => (n.disabled = true));
            q("#caseMarker").disabled = false;
            q("#caseStart").disabled = true;
            q("#caseStop").disabled = q("#caseMark").disabled = false;
            q("#caseRecordStatus").textContent =
              "Recording. You can close this dialog and stop from the main run button; the capture will continue.";
            try {
              await c.recordCase(
                { seconds, interval_ms: Number(q("#caseInterval").value) },
                q("#caseTarget").value.trim(),
                (s) => {
                  samples.push(s);
                  if (!root.isConnected) return;
                  q("#caseCaptureChart").innerHTML = chart(samples);
                  q("#caseRecordStatus").textContent =
                    `Recording · ${samples.length} sample(s) · CPU ${s.cpu_pct.toFixed(1)}% · RAM ${s.memory_pct.toFixed(1)}%`;
                },
              );
              if (root.isConnected)
                q("#caseRecordStatus").textContent =
                  "Capture finished. The saved report contains the recording, markers and coverage gaps. Use Replay recording to inspect it.";
            } catch (e) {
              toast(String(e));
              if (root.isConnected)
                q("#caseRecordStatus").textContent =
                  "Recording could not finish: " + String(e);
            } finally {
              active = false;
              if (root.isConnected) {
                q("#caseStop").disabled = q("#caseMark").disabled = true;
              }
            }
          };
          q("#caseStop").onclick = () => {
            q("#caseStop").disabled = true;
            c.cancel();
          };
          q("#caseMark").onclick = async () => {
            if (!active) return;
            try {
              const m = await api.markRecording(q("#caseMarker").value);
              if (root.isConnected) {
                const li = document.createElement("li");
                li.textContent = stamp(m.at_ms) + " · " + m.label;
                q("#caseMarkers").appendChild(li);
              }
            } catch (e) {
              toast(String(e));
            }
          };
        },
      });
    }
    function replay(r) {
      const recording = r.recording;
      if (!recording) return;
      modal({
        title: "Replay recording",
        cls: "wide",
        body: `<p>${recording.samples.length} samples · ${recording.markers.length} markers · ${esc(recording.target || "no TCP target")}${recording.stopped_early ? " · stopped early" : ""}</p>${chart(recording.samples)}
        <label>Inspect near a marker<select class="case-marker-pick"><option value="all">All samples (first 120 shown)</option>${recording.markers.map((m, i) => `<option value="${i}">${esc(stamp(m.at_ms) + " · " + m.label)}</option>`).join("")}</select></label><p>Marker views show samples within 10 seconds. JSON and case exports retain every sample.</p><div class="case-samples"></div><ul>${recording.gaps.map((g) => `<li>${esc(g)}</li>`).join("")}</ul>`,
        actions: [{ label: "Close" }],
        onMount: (root) => {
          const pick = root.querySelector("select"),
            show = () => {
              const m = recording.markers[Number(pick.value)];
              const rows =
                pick.value === "all"
                  ? recording.samples
                  : recording.samples.filter(
                      (s) => Math.abs(s.at_ms - m.at_ms) <= 10000,
                    );
              root.querySelector(".case-samples").innerHTML = rows.length
                ? sampleTable(rows.slice(0, 120))
                : "<p>No samples in this marker window.</p>";
            };
          pick.onchange = show;
          show();
        },
      });
    }
    async function timeline() {
      if (!ready()) return;
      const report = current();
      if (!report) return;
      const has = report.results.some((r) =>
        ["system.changes", "net.wifi-auth"].includes(r.module_id),
      );
      modal({
        title: "Change timeline",
        cls: "wide",
        body: `<p>Find changes near the user's reported onset. Nearby events are possible links; timing alone does not establish the cause.</p>${has ? "" : "<p>No timeline checks were collected in this report.</p>"}<div class="case-actions">${button("caseCollectTimeline", "Collect change and network-authentication history")}</div>
        <div class="case-fields"><label>Problem began (local time)<input id="caseOnset" type="datetime-local" step="1"></label><label>Window either side<select id="caseWindow"><option value="3600">1 hour</option><option value="900">15 minutes</option><option value="86400">24 hours</option></select></label>${button("caseFindChanges", "Find nearby changes")}</div><div id="caseTimelineRows" aria-live="polite"></div>`,
        actions: [{ label: "Close" }],
        onMount: (root, close) => {
          const q = (s) => root.querySelector(s),
            date = new Date(report.generated);
          date.setMinutes(date.getMinutes() - date.getTimezoneOffset());
          q("#caseOnset").value = date.toISOString().slice(0, 19);
          q("#caseCollectTimeline").onclick = () => {
            close();
            c.startRun(["system.changes", "net.wifi-auth"]);
          };
          q("#caseFindChanges").onclick = async () => {
            try {
              const at = new Date(q("#caseOnset").value);
              if (!Number.isFinite(at.getTime()))
                throw "Enter the problem's onset time.";
              const rows = await api.timelineNear(
                report,
                at.toISOString(),
                Number(q("#caseWindow").value),
              );
              q("#caseTimelineRows").innerHTML = rows.length
                ? table(
                    ["UTC time", "Source", "Activity", "Evidence"],
                    rows.map((e) => [e.at, e.source, e.description, e.detail]),
                  )
                : "<p>No recorded events in this window. This does not rule out a change; check log availability, retention and collection limits.</p>";
            } catch (e) {
              toast(String(e));
            }
          };
          q("#caseFindChanges").click();
        },
      });
    }
    async function baseline() {
      if (!ready()) return;
      const report = current();
      if (!report) return;
      try {
        const history = await api.listHistory();
        modal({
          title: "Compare with a working PC",
          cls: "wide",
          body: `<p>Current report: <strong>${esc(report.host.hostname)}</strong>. Choose a finished report from a PC that performs the same role and is known to work. Import its JSON through Open if it is not listed.</p><p>Compares observed configuration and required app versions. Unique identities, addresses and live performance are excluded. A difference is not automatically a fault.</p><select id="caseBaselinePick">${history
            .filter((h) => !h.cancelled)
            .map(
              (h) =>
                `<option value="${esc(h.path)}">${esc(h.hostname + " · " + h.generated)}</option>`,
            )
            .join(
              "",
            )}</select><div class="case-actions">${button("caseCompareBaseline", "Compare configuration")}</div><div id="caseBaselineResult" aria-live="polite"></div>`,
          actions: [{ label: "Close" }],
          onMount: (root) => {
            root.querySelector("#caseCompareBaseline").onclick = async () => {
              try {
                const path = root.querySelector("select").value;
                if (!path) throw "Import a finished working-PC report first.";
                const good = await api.loadReport(path);
                const diff = await api.compareBaseline(good, report);
                report.baseline = diff;
                c.attach(report);
                root.querySelector("#caseBaselineResult").innerHTML =
                  `<p><strong>Working baseline: ${esc(diff.baseline_host)} → Current: ${esc(diff.current_host)}</strong></p><p>${diff.differences.length} configuration difference(s). Comparison attached to this report for export.</p>${table(
                    ["Check", "Setting", "Working PC", "Current PC"],
                    diff.differences.map((d) => [
                      d.module,
                      d.label,
                      d.baseline == null ? "not observed" : d.baseline,
                      d.current == null ? "not observed" : d.current,
                    ]),
                  )}<ul>${diff.gaps.map((g) => `<li>${esc(g)}</li>`).join("")}</ul>`;
              } catch (e) {
                toast(String(e));
              }
            };
          },
        });
      } catch (e) {
        toast(String(e));
      }
    }
    function bundle() {
      if (!ready()) return;
      const report = current();
      if (!report) return;
      // Freeze the evidence for the lifetime of the preview/export dialog.
      const snapshot = JSON.parse(JSON.stringify(report));
      modal({
        title: "Escalation case bundle",
        cls: "wide",
        body: `<p>Build a local ZIP from this report, its recording, timeline, guided decisions and attached baseline. File digests support integrity checking.</p><label class="case-check"><input id="caseRedact" type="checkbox" checked> Pseudonymize known identifiers consistently</label><label class="case-check"><input id="caseLogs" type="checkbox"> Include logs already captured in this report</label><label>Extra privacy terms (one per line)<textarea id="caseTerms" rows="3" maxlength="10000" placeholder="A site name or sensitive identifier"></textarea></label><div class="case-actions">${button("casePreview", "Preview contents")}${button("caseExport", "Export reviewed ZIP")}</div><p id="caseBundleStatus" role="status">Preview the current options before exporting. Review all files for site-specific sensitive text.</p><div id="caseBundleFiles"></div><label>Inspect a file<select id="caseInspect"></select></label><textarea id="caseBundleText" rows="12" readonly aria-label="Case file contents"></textarea>`,
        actions: [{ label: "Close" }],
        onMount: (root) => {
          const q = (s) => root.querySelector(s);
          let reviewed = null,
            generation = 0;
          const opts = () => ({
            redact_identifiers: q("#caseRedact").checked,
            include_logs: q("#caseLogs").checked,
            custom_terms: q("#caseTerms")
              .value.split(/\r?\n/)
              .map((s) => s.trim())
              .filter(Boolean),
          });
          const invalidate = () => {
            generation++;
            reviewed = null;
            q("#caseExport").disabled = true;
            q("#caseBundleStatus").textContent =
              "Options changed. Preview again before exporting.";
          };
          q("#caseExport").disabled = true;
          ["#caseRedact", "#caseLogs", "#caseTerms"].forEach((s) =>
            q(s).addEventListener("input", invalidate),
          );
          q("#casePreview").onclick = async () => {
            const selected = opts(),
              mine = ++generation;
            q("#casePreview").disabled = true;
            reviewed = null;
            q("#caseExport").disabled = true;
            try {
              const preview = await api.previewCaseBundle(snapshot, selected);
              if (mine !== generation || !root.isConnected) return;
              reviewed = selected;
              q("#caseBundleFiles").innerHTML = table(
                ["File", "Bytes", "SHA-256"],
                preview.files.map((f) => [f.name, f.bytes, f.sha256]),
              );
              q("#caseBundleStatus").textContent =
                `${preview.bytes} uncompressed bytes. ${preview.note}`;
              const names = Object.keys(preview.contents);
              q("#caseInspect").innerHTML = names
                .map((n) => `<option>${esc(n)}</option>`)
                .join("");
              q("#caseInspect").onchange = () => {
                q("#caseBundleText").value =
                  preview.contents[q("#caseInspect").value] || "";
              };
              q("#caseInspect").value = names.includes("report.txt")
                ? "report.txt"
                : names[0];
              q("#caseInspect").onchange();
              q("#caseExport").disabled = false;
            } catch (e) {
              toast(String(e));
            } finally {
              if (root.isConnected) q("#casePreview").disabled = false;
            }
          };
          q("#caseExport").onclick = async () => {
            if (!reviewed) return;
            const selected = reviewed;
            q("#caseExport").disabled = true;
            try {
              const path = await api.exportCaseBundle(snapshot, selected);
              q("#caseBundleStatus").textContent = "Case saved: " + path;
              const open = document.createElement("button");
              open.type = "button";
              open.className = "bk-btn";
              open.textContent = "Open cases folder";
              open.onclick = () =>
                api.openCasesFolder().catch((e) => toast(String(e)));
              q("#caseBundleStatus").appendChild(open);
            } catch (e) {
              toast(String(e));
              q("#caseExport").disabled = false;
            }
          };
        },
      });
    }
    function decorate(report, container) {
      if (!report) return;
      if (report.runbook) {
        const box = document.createElement("div");
        box.className = "case-note";
        box.innerHTML = `<strong>Guided troubleshooting · ${esc(report.runbook.id)}</strong><p>${esc(report.runbook.conclusion)}</p><details><summary>Why these checks ran</summary><ol>${report.runbook.steps.map((s) => `<li>${esc(s.reason)}<br><small>${esc(s.modules.join(", "))}</small></li>`).join("")}</ol></details>`;
        container.prepend(box);
      }
      if (report.recording) {
        const box = document.createElement("div");
        box.className = "case-note";
        box.innerHTML = `<strong>Intermittent issue · ${report.recording.samples.length} samples · ${report.recording.markers.length} markers</strong><p>CPU, RAM, disk/network rates, connection probes and available Wi-Fi state.</p>`;
        const b = document.createElement("button");
        b.type = "button";
        b.className = "bk-btn";
        b.textContent = "Replay recording";
        b.onclick = () => replay(report);
        box.appendChild(b);
        container.prepend(box);
      }
    }
    return { guided, record, timeline, baseline, bundle, decorate };
  }
  // The browser preview uses sample evidence only; the native Rust bridge
  // remains authoritative for collection and privacy processing.
  function mockBridge(base, host, sample) {
    const saved = new Map(),
      meta = [];
    let recording = null,
      stopped = false;
    const clone = (v) => JSON.parse(JSON.stringify(v));
    const books = [
      {
        id: "printing",
        title: "Printing fails",
        symptom: "A printer is unavailable or jobs stay queued.",
      },
      {
        id: "vpn",
        title: "VPN connects but apps don't",
        symptom: "Check the tunnel, routing, proxy and application path.",
      },
      {
        id: "sign-in",
        title: "Sign-in keeps prompting",
        symptom: "Check account state, clock and device / SSO diagnostics.",
      },
      {
        id: "slow-app",
        title: "An application is slow",
        symptom:
          "Separate resources, application connectivity and recent changes.",
      },
    ];
    const initial = {
      printing: ["desk.printers", "proc.services"],
      vpn: ["desk.wifi", "net.connectivity", "net.proxy"],
      "sign-in": ["desk.identity", "desk.account", "desk.time"],
      "slow-app": [
        "proc.top",
        "system.memory",
        "system.disk",
        "net.applications",
      ],
    };
    const follow = {
      printing: ["site.checks", "net.connectivity", "site.apps"],
      vpn: ["site.checks", "net.applications", "net.wifi-auth", "desk.time"],
      "sign-in": [
        "desk.domain",
        "net.connectivity",
        "net.proxy",
        "site.checks",
      ],
      "slow-app": [
        "site.apps",
        "site.checks",
        "system.reliability",
        "system.changes",
      ],
    };
    const keep = (r) => {
      const path = "sample-case-" + Date.now() + "-" + meta.length + ".json";
      saved.set(path, clone(r));
      meta.unshift({
        path,
        generated: r.generated,
        hostname: r.host.hostname,
        modules: r.results.length,
        worst: "info",
        cancelled: !!r.cancelled,
      });
      return path;
    };
    const rows = (report) =>
      report.results
        .filter(
          (m) =>
            ["system.changes", "net.wifi-auth"].includes(m.module_id) &&
            !m.error &&
            !m.preview,
        )
        .flatMap((m) =>
          m.findings
            .filter((f) => /^\d{4}-\d\d-\d\dT/.test(f.label))
            .map((f) => ({
              at: f.label.split(" ")[0],
              source: m.title,
              kind: "Recorded event",
              description: f.value,
              detail: f.detail || "",
            })),
        );
    const hash = async (text) =>
      Array.from(
        new Uint8Array(
          await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)),
        ),
      )
        .map((n) => n.toString(16).padStart(2, "0"))
        .join("");
    async function preview(report, options) {
      const r = clone(report);
      if (!options.include_logs) r.results.forEach((m) => (m.log = []));
      const terms = [...(options.custom_terms || [])];
      if (terms.length > 100 || terms.some((s) => s.length > 512))
        throw "Use at most 100 privacy terms of 512 bytes each.";
      if (options.redact_identifiers) {
        terms.push(r.host.hostname);
        const all = JSON.stringify(r);
        terms.push(
          ...(all.match(
            /[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}|(?:\d{1,3}\.){3}\d{1,3}/g,
          ) || []),
        );
      }
      const dictionary = [...new Set(terms.filter(Boolean))].sort(
        (a, b) => b.length - a.length,
      );
      const scrub = (v) => {
        if (typeof v === "string") {
          const matches = [];
          dictionary.forEach((s, i) => {
            const re = new RegExp(
              s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"),
              "gi",
            );
            for (const m of v.matchAll(re))
              matches.push({
                at: m.index,
                end: m.index + m[0].length,
                text: `[identifier-${i + 1}]`,
              });
          });
          matches.sort((a, b) => a.at - b.at || b.end - a.end);
          let out = "",
            end = 0;
          matches.forEach((m) => {
            if (m.at >= end) {
              out += v.slice(end, m.at) + m.text;
              end = m.end;
            }
          });
          return out + v.slice(end);
        }
        if (Array.isArray(v)) return v.map(scrub);
        if (v && typeof v === "object")
          return Object.fromEntries(
            Object.entries(v).map(([k, val]) => [k, scrub(val)]),
          );
        return v;
      };
      const safe = scrub(r),
        text = await base.reportText(safe, null, !!options.include_logs),
        contents = {
          "report.json": JSON.stringify(safe, null, 2),
          "report.txt": text,
          "versions.txt": "ITriage browser preview — sample evidence only\n",
          "timeline.json": JSON.stringify(rows(safe), null, 2),
        };
      if (safe.recording)
        contents["recording.csv"] =
          "at_ms,cpu_pct,memory_pct,tcp_ms,dns_ms\n" +
          safe.recording.samples
            .map((s) =>
              [s.at_ms, s.cpu_pct, s.memory_pct, s.tcp_ms, s.dns_ms].join(","),
            )
            .join("\n");
      if (safe.baseline)
        contents["baseline.json"] = JSON.stringify(safe.baseline, null, 2);
      if (safe.runbook)
        contents["runbook.json"] = JSON.stringify(safe.runbook, null, 2);
      if (options.include_logs)
        safe.results.forEach((m, i) => {
          if ((m.log || []).length)
            contents[`logs/${i}.txt`] = m.log.join("\n");
        });
      const entries = async () =>
        Promise.all(
          Object.entries(contents)
            .sort(([a], [b]) => a.localeCompare(b))
            .map(async ([name, t]) => ({
              name,
              bytes: new TextEncoder().encode(t).length,
              sha256: await hash(t),
            })),
        );
      contents["manifest.json"] = JSON.stringify(await entries(), null, 2);
      contents["SHA256SUMS.txt"] = (await entries())
        .map((f) => `${f.sha256}  ${f.name}\n`)
        .join("");
      const files = await entries();
      return {
        files,
        contents,
        text,
        bytes: files.reduce((n, f) => n + f.bytes, 0),
        redacted: options.redact_identifiers,
        note: "Browser preview: sample evidence only. Review all files for site-specific sensitive text. The desktop app performs native privacy processing.",
      };
    }
    function zip(contents) {
      const out = [],
        central = [];
      const u16 = (a, n) => a.push(n & 255, (n >>> 8) & 255),
        u32 = (a, n) => {
          u16(a, n);
          u16(a, n >>> 16);
        };
      const crc = (bytes) => {
        let c = 0xffffffff;
        for (const b of bytes) {
          c ^= b;
          for (let i = 0; i < 8; i++) c = (c >>> 1) ^ (c & 1 ? 0xedb88320 : 0);
        }
        return (c ^ 0xffffffff) >>> 0;
      };
      for (const [name, text] of Object.entries(contents).sort(([a], [b]) =>
        a.localeCompare(b),
      )) {
        const n = new TextEncoder().encode(name),
          bytes = new TextEncoder().encode(text),
          offset = out.length,
          sum = crc(bytes);
        u32(out, 0x04034b50);
        [20, 0x800, 0, 0, 33].forEach((v) => u16(out, v));
        [sum, bytes.length, bytes.length].forEach((v) => u32(out, v));
        u16(out, n.length);
        u16(out, 0);
        for (const b of n) out.push(b);
        for (const b of bytes) out.push(b);
        u32(central, 0x02014b50);
        [20, 20, 0x800, 0, 0, 33].forEach((v) => u16(central, v));
        [sum, bytes.length, bytes.length].forEach((v) => u32(central, v));
        [n.length, 0, 0, 0, 0].forEach((v) => u16(central, v));
        u32(central, 0);
        u32(central, offset);
        for (const b of n) central.push(b);
      }
      const offset = out.length;
      for (const b of central) out.push(b);
      u32(out, 0x06054b50);
      [
        0,
        0,
        Object.keys(contents).length,
        Object.keys(contents).length,
      ].forEach((v) => u16(out, v));
      u32(out, central.length);
      u32(out, offset);
      u16(out, 0);
      return new Uint8Array(out);
    }
    return Object.assign({}, base, {
      listRunbooks: async () => books,
      runbookPlan: async (id) => {
        if (!initial[id]) throw "Unknown runbook";
        return {
          modules: initial[id],
          reason: "Start with the checks closest to the symptom.",
        };
      },
      run: async (ids, h) => {
        if (!h.runbook) return base.run(ids, h);
        const first = await base.run(initial[h.runbook], h),
          steps = [
            {
              modules: initial[h.runbook],
              reason:
                "Start with the checks closest to the symptom (sample plan).",
            },
          ];
        let results = first.report.results;
        if (!first.report.cancelled) {
          const bad = results.some(
            (r) =>
              r.error ||
              r.findings.some((f) =>
                ["warning", "critical"].includes(f.severity),
              ),
          );
          if (["vpn", "slow-app"].includes(h.runbook) || bad) {
            const more = follow[h.runbook].filter(
              (id) => !results.some((r) => r.module_id === id),
            );
            steps.push({
              modules: more,
              reason:
                "Check the site's dependencies and related evidence before choosing a fix (sample plan).",
            });
            const second = await base.run(
              more,
              Object.assign({}, h, {
                onStart: (p) =>
                  h.onStart(
                    Object.assign({}, p, {
                      index: p.index + results.length,
                      total: p.total + results.length,
                    }),
                  ),
              }),
            );
            first.report.cancelled = second.report.cancelled;
            results = results.concat(second.report.results);
          }
        }
        first.report.results = results;
        first.report.runbook = {
          id: h.runbook,
          steps,
          finished: !first.report.cancelled,
          conclusion:
            "Review the sample findings and coverage gaps. Completing a runbook does not mean the problem was repaired.",
        };
        first.saved = keep(first.report);
        return first;
      },
      recordProblem: async (config, target, ticket, onSample, previous) => {
        stopped = false;
        recording = {
          started: new Date().toISOString(),
          config,
          target: target || null,
          samples: [],
          markers: [],
          stopped_early: false,
          gaps: ["Browser preview: all measurements are simulated."],
        };
        const capture = recording,
          start = Date.now();
        try {
          while (Date.now() - start < config.seconds * 1000 && !stopped) {
            const t = sample(),
              s = {
                at_ms: Date.now(),
                cpu_pct: t.cpu,
                memory_pct: t.mem_pct,
                disk_read: t.disk_read,
                disk_write: t.disk_write,
                net_rx: t.net_rx,
                net_tx: t.net_tx,
                tcp_ms: target ? 14 + Math.random() * 8 : null,
                tcp_error: null,
                dns_ms: 3,
                dns_error: null,
                wifi: "Sample Wi-Fi · 71%",
              };
            capture.samples.push(s);
            onSample(s);
            await new Promise((r) => setTimeout(r, config.interval_ms));
          }
          capture.stopped_early = stopped;
          const report = previous
            ? clone(previous)
            : {
                schema: 1,
                tool_version: "0.8.0",
                generated: new Date().toISOString(),
                host: clone(host()),
                ticket: ticket || null,
                cancelled: false,
                results: [],
              };
          report.results = report.results.filter(
            (r) => r.module_id !== "capture.recording",
          );
          report.results.push({
            module_id: "capture.recording",
            title: "Intermittent problem recording",
            category: "system",
            summary: `${capture.samples.length} sample(s) · ${capture.markers.length} marker(s)`,
            findings: [
              {
                label: "Collection",
                value: "Simulated measurements in browser preview",
                severity: "info",
              },
            ],
            error: null,
            log: [],
            duration_ms: Date.now() - start,
          });
          report.recording = capture;
          return { report, saved: keep(report), diff: null };
        } finally {
          recording = null;
        }
      },
      markRecording: async (label) => {
        if (!recording) throw "No recording is running.";
        if (recording.markers.length >= 100) throw "Marker limit reached.";
        const m = {
          at_ms: Date.now(),
          label:
            String(label)
              .trim()
              .replace(/[\x00-\x1f]/g, "")
              .slice(0, 200) || "Problem happened now",
        };
        recording.markers.push(m);
        return m;
      },
      cancel: async () => {
        stopped = true;
        return base.cancel();
      },
      timelineNear: async (r, at, window) =>
        rows(r).filter(
          (e) => Math.abs(Date.parse(e.at) - Date.parse(at)) <= window * 1000,
        ),
      compareBaseline: async (a, b) => {
        if (a.cancelled || b.cancelled) throw "Choose finished reports.";
        if (a.host.platform !== b.host.platform)
          throw "Choose the same operating-system platform.";
        if (a.role && b.role && a.role !== b.role)
          throw "Choose the same workstation role.";
        const obs = (r) =>
          new Map(
            r.results
              .filter(
                (m) =>
                  !m.error &&
                  !m.preview &&
                  [
                    "system.info",
                    "site.apps",
                    "proc.services",
                    "sec.posture",
                    "desk.devices",
                  ].includes(m.module_id),
              )
              .flatMap((m) =>
                m.findings
                  .filter(
                    (f) =>
                      !f.metric &&
                      !/serial|hostname|user|session|uptime|PID|thumbprint|address|running services/i.test(
                        f.label,
                      ),
                  )
                  .map((f) => [m.module_id + "\n" + f.label, f.value]),
              ),
          );
        const old = obs(a),
          now = obs(b);
        if (!old.size || !now.size)
          throw "Both reports need configuration checks.";
        return {
          baseline_host: a.host.hostname,
          current_host: b.host.hostname,
          baseline_generated: a.generated,
          current_generated: b.generated,
          role: b.role || a.role || null,
          differences: [...new Set([...old.keys(), ...now.keys()])]
            .filter((k) => old.get(k) !== now.get(k))
            .map((k) => ({
              module: k.split("\n")[0],
              label: k.split("\n")[1],
              baseline: old.get(k) || null,
              current: now.get(k) || null,
            })),
          gaps: [
            "Browser sample comparison. An unobserved finding does not establish a missing component. Confirm matching workstation roles.",
          ],
        };
      },
      previewCaseBundle: preview,
      exportCaseBundle: async (r, o) => {
        const p = await preview(r, o),
          url = URL.createObjectURL(
            new Blob([zip(p.contents)], { type: "application/zip" }),
          ),
          a = document.createElement("a");
        a.href = url;
        a.download = "ITriage-sample-case.zip";
        a.click();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
        return "ITriage-sample-case.zip (browser download)";
      },
      openCasesFolder: async () => {},
      listHistory: async () => meta.concat(await base.listHistory()),
      loadReport: async (path) =>
        saved.has(path) ? clone(saved.get(path)) : base.loadReport(path),
      importReport: async (text) => {
        const outcome = await base.importReport(text);
        outcome.saved = keep(outcome.report);
        return outcome;
      },
    });
  }
  window.ITriageCases = { create, mockBridge };
})();
