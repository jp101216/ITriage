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
  const clock = (ms) => new Date(ms).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  const count = (n, one, many) => `${n} ${n === 1 ? one : many || one + "s"}`;
  /** Bytes a second, in the unit a person reads. */
  const rate = (n) => {
    const v = Number(n) || 0;
    if (v >= 1048576) return (v / 1048576).toFixed(1) + " MB/s";
    if (v >= 1024) return (v / 1024).toFixed(0) + " KB/s";
    return Math.round(v) + " B/s";
  };
  const button = (id, label, title) =>
    `<button class="bk-btn" type="button" id="${id}"${title ? ` title="${esc(title)}"` : ""}>${label}</button>`;
  const table = (heads, rows, cls) =>
    `<div class="case-scroll"><table class="mtable${cls ? " " + cls : ""}"><thead><tr>${heads.map((h) => `<th>${esc(h)}</th>`).join("")}</tr></thead><tbody>${rows.map((r) => `<tr>${r.map((v) => `<td>${esc(v)}</td>`).join("")}</tr>`).join("")}</tbody></table></div>`;
  /** The marker a sample carries: the first sample at or after it (the
   *  last one, for a marker made after that). The CSV does the same. */
  function markersBySample(recording) {
    const out = recording.samples.map(() => []);
    recording.markers.forEach((m, n) => {
      if (!out.length) return;
      const at = recording.samples.findIndex((s) => s.at_ms >= m.at_ms);
      out[at < 0 ? out.length - 1 : at].push({ n: n + 1, label: m.label });
    });
    return out;
  }
  /** Moves to another access point: the samples where the address changed. */
  function roamSamples(samples) {
    const out = [];
    let last = null;
    samples.forEach((s, i) => {
      const ap = s.wifi_bssid ? String(s.wifi_bssid).toLowerCase() : null;
      if (!ap) return;
      if (last && ap !== last) out.push(i);
      last = ap;
    });
    return out;
  }
  const sampleTable = (recording, rows) => {
    const marks = markersBySample(recording);
    return table(
      ["Time", "CPU", "RAM", "Connection", "DNS", "Disk read / write", "Network in / out", "Wi-Fi", "Marker"],
      rows.map((i) => {
        const s = recording.samples[i];
        return [
          clock(s.at_ms),
          Number(s.cpu_pct).toFixed(1) + "%",
          Number(s.memory_pct).toFixed(1) + "%",
          s.tcp_error ? "failed: " + s.tcp_error : s.tcp_ms == null ? "not sampled" : s.tcp_ms < 1 ? "under 1 ms" : s.tcp_ms.toFixed(0) + " ms",
          s.dns_error ? "failed: " + s.dns_error : s.dns_ms == null ? "" : s.dns_ms < 1 ? "under 1 ms" : s.dns_ms.toFixed(0) + " ms",
          `${rate(s.disk_read)} / ${rate(s.disk_write)}`,
          `${rate(s.net_rx)} / ${rate(s.net_tx)}`,
          s.wifi || "",
          marks[i].map((m) => `${m.n}: ${m.label}`).join(" | "),
        ];
      }),
      "case-samples-table",
    );
  };
  /** CPU, memory and Wi-Fi signal over a recording, with its markers, the
   *  moves between access points and the failed probes. Colour is never the
   *  only cue: each line has its own dash, each mark its own shape, and the
   *  sample table has every figure. */
  function chartSvg(recording) {
    const samples = recording.samples;
    if (!samples.length) return "<p>Waiting for the first sample…</p>";
    const X0 = 40, X1 = 630, Y0 = 20, Y1 = 150, FAIL_Y = 168;
    const first = samples[0].at_ms,
      span = Math.max(1000, samples[samples.length - 1].at_ms - first);
    const x = (ms) => X0 + (Math.min(Math.max(ms - first, 0), span) / span) * (X1 - X0);
    const y = (pct) => Y1 - (Math.min(100, Math.max(0, pct)) / 100) * (Y1 - Y0);
    const line = (key) =>
      samples
        .filter((s) => s[key] != null)
        .map((s) => `${x(s.at_ms).toFixed(1)},${y(s[key]).toFixed(1)}`)
        .join(" ");
    const wifi = samples.some((s) => s.wifi_signal != null);
    const tcpFails = samples.filter((s) => s.tcp_error),
      dnsFails = samples.filter((s) => s.dns_error);
    const marks = recording.markers
      .map((m, n) => {
        const mx = x(m.at_ms).toFixed(1);
        return `<g class="mk"><title>${esc(`Marker ${n + 1}: ${m.label} (${clock(m.at_ms)})`)}</title><line x1="${mx}" y1="${Y0}" x2="${mx}" y2="${FAIL_Y + 6}"/><rect x="${mx - 7}" y="${Y0 - 15}" width="14" height="14" rx="2"/><text x="${mx}" y="${Y0 - 4}" text-anchor="middle">${n + 1}</text></g>`;
      })
      .join("");
    const roams = roamSamples(samples)
      .map((i) => {
        const s = samples[i], rx = x(s.at_ms), ry = y(s.wifi_signal == null ? 50 : s.wifi_signal);
        return `<path class="roam" d="M${rx - 5} ${ry - 9}h10l-5 8z"><title>${esc(`Moved to another access point at ${clock(s.at_ms)}`)}</title></path>`;
      })
      .join("");
    const fails =
      tcpFails.map((s) => `<rect class="fail" x="${(x(s.at_ms) - 3).toFixed(1)}" y="${FAIL_Y - 3}" width="6" height="6"><title>${esc(`Connection failed at ${clock(s.at_ms)}: ${s.tcp_error}`)}</title></rect>`).join("") +
      dnsFails.map((s) => `<circle class="fail hollow" cx="${x(s.at_ms).toFixed(1)}" cy="${FAIL_Y}" r="4"><title>${esc(`DNS probe failed at ${clock(s.at_ms)}: ${s.dns_error}`)}</title></circle>`).join("");
    const legend = [
      '<span><i class="k cpu"></i>CPU</span>',
      '<span><i class="k ram"></i>RAM</span>',
      wifi ? '<span><i class="k sig"></i>Wi-Fi signal</span>' : "",
      recording.markers.length ? '<span><i class="k mark">1</i>Marker</span>' : "",
      roams ? '<span><i class="k move"></i>Moved access point</span>' : "",
      tcpFails.length ? '<span><i class="k bad"></i>Connection failed</span>' : "",
      dnsFails.length ? '<span><i class="k bad hollow"></i>DNS probe failed</span>' : "",
    ].join("");
    const said = `CPU and memory use${wifi ? " and Wi-Fi signal" : ""} over ${Math.round(span / 1000)} seconds, with ${count(recording.markers.length, "marker")}, ${count(tcpFails.length, "failed connection")} and ${count(dnsFails.length, "failed DNS probe")}. Every figure is in the sample table.`;
    return `<div class="case-plot"><svg class="case-chart" viewBox="0 0 650 196" role="img" aria-label="${esc(said)}">
      <path class="axis" d="M${X0} ${Y0}V${Y1}H${X1}"/><path class="grid" d="M${X0} ${y(50)}H${X1}"/>
      <text x="${X0 - 6}" y="${Y0 + 4}" text-anchor="end">100%</text><text x="${X0 - 6}" y="${y(50) + 4}" text-anchor="end">50%</text><text x="${X0 - 6}" y="${Y1 + 4}" text-anchor="end">0%</text>
      <text x="${X0}" y="190">${esc(clock(first))}</text><text x="${X1}" y="190" text-anchor="end">${esc(clock(first + span))}</text>
      ${tcpFails.length + dnsFails.length ? `<text x="${X0 - 6}" y="${FAIL_Y + 4}" text-anchor="end">fail</text>` : ""}
      ${wifi ? `<polyline class="sig" points="${line("wifi_signal")}"/>` : ""}
      <polyline class="ram" points="${line("memory_pct")}"/>
      <polyline class="cpu" points="${line("cpu_pct")}"/>
      ${roams}${fails}${marks}
      <line class="cross" x1="0" y1="${Y0}" x2="0" y2="${FAIL_Y + 6}" hidden/>
    </svg><div class="case-tip" hidden></div></div><p class="case-legend">${legend}<span>Local samples, not process tracing</span></p>`;
  }
  /** Draw a recording into `box`, with a readout that follows the pointer. */
  function mountChart(box, recording) {
    box.innerHTML = chartSvg(recording);
    const svg = box.querySelector("svg"),
      tip = box.querySelector(".case-tip"),
      cross = box.querySelector(".cross"),
      samples = recording.samples;
    if (!svg || !samples.length) return;
    const first = samples[0].at_ms,
      span = Math.max(1000, samples[samples.length - 1].at_ms - first);
    const marks = markersBySample(recording);
    const show = (e) => {
      const r = svg.getBoundingClientRect();
      const vx = ((e.clientX - r.left) / r.width) * 650;
      const at = first + (Math.min(Math.max(vx, 40), 630) - 40) / 590 * span;
      let i = 0;
      samples.forEach((s, n) => { if (Math.abs(s.at_ms - at) < Math.abs(samples[i].at_ms - at)) i = n; });
      const s = samples[i],
        sx = 40 + ((s.at_ms - first) / span) * 590;
      cross.setAttribute("x1", sx);
      cross.setAttribute("x2", sx);
      cross.removeAttribute("hidden");
      const rows = [
        ["CPU", Number(s.cpu_pct).toFixed(1) + "%"],
        ["RAM", Number(s.memory_pct).toFixed(1) + "%"],
        s.tcp_error ? ["Connection", "failed"] : s.tcp_ms != null ? ["Connection", s.tcp_ms < 1 ? "under 1 ms" : s.tcp_ms.toFixed(0) + " ms"] : null,
        s.wifi_signal != null ? ["Wi-Fi", s.wifi_signal + "%"] : null,
        marks[i].length ? ["Marker", marks[i].map((m) => m.label).join(" | ")] : null,
      ].filter(Boolean);
      tip.innerHTML = `<b>${esc(clock(s.at_ms))}</b>${rows.map(([k, v]) => `<span><em>${esc(k)}</em>${esc(v)}</span>`).join("")}`;
      tip.hidden = false;
      const left = (sx / 650) * r.width;
      tip.style.left = Math.min(Math.max(left + 10, 0), Math.max(r.width - tip.offsetWidth, 0)) + "px";
      if (left + 10 + tip.offsetWidth > r.width) tip.style.left = Math.max(left - tip.offsetWidth - 10, 0) + "px";
    };
    const hide = () => { tip.hidden = true; cross.setAttribute("hidden", ""); };
    svg.addEventListener("pointermove", show);
    svg.addEventListener("pointerdown", show);
    svg.addEventListener("pointerleave", hide);
  }
  function create(c) {
    const { api, modal, toast } = c;
    const local = c.fmtLocal || ((iso) => new Date(iso).toLocaleString());
    const titleOf = c.titleOf || ((id) => id);
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
            live = { samples: [], markers: [] };
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
            live.samples.length = live.markers.length = 0;
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
                  live.samples.push(s);
                  if (!root.isConnected) return;
                  mountChart(q("#caseCaptureChart"), live);
                  q("#caseRecordStatus").textContent =
                    `Recording · ${count(live.samples.length, "sample")} · CPU ${s.cpu_pct.toFixed(1)}% · RAM ${s.memory_pct.toFixed(1)}%${s.tcp_error ? " · connection failed" : ""}`;
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
          const mark = async () => {
            if (!active) return;
            try {
              const m = await api.markRecording(q("#caseMarker").value);
              live.markers.push(m);
              if (root.isConnected) {
                const li = document.createElement("li");
                li.textContent = `${live.markers.length}: ${clock(m.at_ms)} · ${m.label}`;
                q("#caseMarkers").appendChild(li);
                if (live.samples.length) mountChart(q("#caseCaptureChart"), live);
                q("#caseMarker").select();
              }
            } catch (e) {
              toast(String(e));
            }
          };
          q("#caseMark").onclick = mark;
          // Enter in the marker box marks the moment: no reaching for the mouse.
          q("#caseMarker").onkeydown = (e) => {
            if (e.key === "Enter") {
              e.preventDefault();
              mark();
            }
          };
        },
      });
    }
    function replay(r) {
      const recording = r.recording;
      if (!recording) return;
      const fails = recording.samples.filter((s) => s.tcp_error).length,
        moves = roamSamples(recording.samples).length;
      const facts = [
        count(recording.samples.length, "sample"),
        count(recording.markers.length, "marker"),
        recording.target ? "target " + recording.target : "no TCP target",
        fails ? count(fails, "failed connection") : "",
        moves ? `moved access point ${moves === 1 ? "once" : moves + " times"}` : "",
        recording.stopped_early ? "stopped early" : "",
      ].filter(Boolean);
      modal({
        title: "Replay recording",
        cls: "wide",
        body: `<p>${esc(facts.join(" · "))} · started ${esc(local(recording.started))}</p><div class="case-replay-chart"></div>
        <label>Show samples<select class="case-marker-pick"><option value="all">All samples (first 120)</option>${fails ? '<option value="fails">Failed connections only</option>' : ""}${recording.markers.map((m, i) => `<option value="${i}">Within 10 seconds of marker ${i + 1}: ${esc(m.label)} (${esc(clock(m.at_ms))})</option>`).join("")}</select></label><div class="case-samples"></div>${recording.gaps.length ? `<p class="case-legend">Coverage</p><ul>${recording.gaps.map((g) => `<li>${esc(g)}</li>`).join("")}</ul>` : ""}<p class="case-legend">The JSON report and a case bundle keep every sample.</p>`,
        actions: [{ label: "Close" }],
        onMount: (root) => {
          mountChart(root.querySelector(".case-replay-chart"), recording);
          const pick = root.querySelector("select"),
            all = recording.samples.map((_, i) => i),
            show = () => {
              const m = recording.markers[Number(pick.value)];
              const rows =
                pick.value === "all"
                  ? all
                  : pick.value === "fails"
                    ? all.filter((i) => recording.samples[i].tcp_error)
                    : all.filter((i) => Math.abs(recording.samples[i].at_ms - m.at_ms) <= 10000);
              root.querySelector(".case-samples").innerHTML = rows.length
                ? sampleTable(recording, rows.slice(0, 120))
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
        body: `<p>Find changes near the user's reported onset. Nearby events are possible links; timing alone does not establish the cause.</p>${has ? "" : "<p>No timeline checks were collected in this report.</p>"}<div class="case-actions">${button("caseCollectTimeline", "Collect history now", "Collect change and network-authentication history into this report")}</div>
        <div class="case-fields"><label>Problem began (local time)<input id="caseOnset" type="datetime-local" step="1"></label><label>Show<select id="caseWindow"><option value="3600">1 hour either side</option><option value="900">15 minutes either side</option><option value="86400">24 hours either side</option><option value="all">Everything collected</option></select></label>${button("caseFindChanges", "Find changes")}</div><div id="caseTimelineRows" aria-live="polite"></div>`,
        actions: [{ label: "Close" }],
        onMount: (root, close) => {
          const q = (s) => root.querySelector(s),
            date = new Date(
              Number.isFinite(Date.parse(report.generated))
                ? report.generated
                : Date.now(),
            );
          date.setMinutes(date.getMinutes() - date.getTimezoneOffset());
          q("#caseOnset").value = date.toISOString().slice(0, 19);
          q("#caseCollectTimeline").onclick = () => {
            close();
            c.collectCase(["system.changes", "net.wifi-auth"]);
          };
          // "12 min before", "3 min after": where an event sits against the onset.
          const from = (iso, onset) => {
            const d = Math.round((Date.parse(iso) - onset) / 1000),
              a = Math.abs(d);
            const size = a < 90 ? a + " s" : a < 5400 ? Math.round(a / 60) + " min" : a < 172800 ? (a / 3600).toFixed(1) + " h" : Math.round(a / 86400) + " d";
            return a < 5 ? "at onset" : `${size} ${d < 0 ? "before" : "after"}`;
          };
          q("#caseFindChanges").onclick = async () => {
            try {
              const at = new Date(q("#caseOnset").value);
              if (!Number.isFinite(at.getTime()))
                throw "Enter the problem's onset time.";
              const everything = q("#caseWindow").value === "all";
              const rows = everything
                ? await api.timelineRows(report)
                : await api.timelineNear(report, at.toISOString(), Number(q("#caseWindow").value));
              q("#caseTimelineRows").innerHTML = rows.length
                ? `<p class="case-legend">${count(rows.length, "row")}, oldest first. Times are this computer's local time.</p>` +
                  table(
                    ["When", "From onset", "Kind", "What happened", "Evidence"],
                    rows.map((e) => [
                      local(e.at) + (e.until ? " until " + clock(Date.parse(e.until)) : ""),
                      from(e.at, at.getTime()),
                      e.kind || "",
                      // The When column already says when a burst ended.
                      e.until ? e.description.replace(/^(\d+ events) until \S+?Z:/, "$1:") : e.description,
                      e.detail,
                    ]),
                    "case-timeline-table",
                  )
                : everything
                  ? "<p>No change or network-authentication events are in this report. Collect history now, or check that the logs are available.</p>"
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
        // A PC isn't its own working example: only other computers' reports.
        const here = String(report.host.hostname).toLowerCase();
        const others = (await api.listHistory()).filter((h) => !h.cancelled && String(h.hostname).toLowerCase() !== here);
        modal({
          title: "Compare with a working PC",
          cls: "wide",
          body: `<p>Current report: <strong>${esc(report.host.hostname)}</strong>. Choose a finished report from a PC that performs the same role and is known to work.</p><p>Compares observed configuration and required app versions. Unique identities, addresses and live performance are excluded. A difference is not automatically a fault.</p>${
            others.length
              ? `<label>Working PC's report<select id="caseBaselinePick">${others
                  .map((h) => `<option value="${esc(h.path)}">${esc(`${h.hostname} · ${local(h.evidence_updated || h.generated)}${h.modules == null ? "" : " · " + count(h.modules, "check")}`)}</option>`)
                  .join("")}</select></label><div class="case-actions">${button("caseCompareBaseline", "Compare configuration")}</div>`
              : `<p class="case-empty"><strong>No report from another PC is here yet.</strong> On the working PC, run the same checks and export its JSON report; then bring it in with <strong>Open</strong> and come back to this dialog.</p>`
          }<div id="caseBaselineResult" aria-live="polite"></div>`,
          actions: [{ label: "Close" }],
          onMount: (root) => {
            const go = root.querySelector("#caseCompareBaseline");
            if (!go) return;
            go.onclick = async () => {
              try {
                const path = root.querySelector("select").value;
                if (!path) throw "Import a finished working-PC report first.";
                const good = await api.loadReport(path);
                const diff = await api.compareBaseline(good, report);
                report.baseline = diff;
                c.attach(report);
                root.querySelector("#caseBaselineResult").innerHTML =
                  `<p><strong>Working baseline: ${esc(diff.baseline_host)} → Current: ${esc(diff.current_host)}</strong></p><p>${count(diff.differences.length, "configuration difference")}. Comparison attached to this report for export.</p>${
                    diff.differences.length
                      ? table(
                          ["Check", "Setting", "Working PC", "Current PC"],
                          diff.differences.map((d) => [
                            titleOf(d.module),
                            d.label,
                            d.baseline == null ? "not observed" : d.baseline,
                            d.current == null ? "not observed" : d.current,
                          ]),
                        )
                      : ""
                  }<ul>${diff.gaps.map((g) => `<li>${esc(g)}</li>`).join("")}</ul>`;
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
                ["File", "Size", "SHA-256"],
                preview.files.map((f) => [f.name, rate(f.bytes).replace("/s", ""), f.sha256]),
              );
              q("#caseBundleStatus").textContent =
                `${count(preview.files.length, "file")}, ${rate(preview.bytes).replace("/s", "")} before zipping. ${preview.note}`;
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
        box.innerHTML = `<strong>Guided troubleshooting · ${esc(report.runbook.id)}</strong><p>${esc(report.runbook.conclusion)}</p><details><summary>Why these checks ran</summary><ol>${report.runbook.steps.map((s) => `<li>${esc(s.reason)}<br><small>${esc(s.modules.map(titleOf).join(", "))}</small></li>`).join("")}</ol></details>`;
        container.prepend(box);
      }
      if (report.baseline) {
        const b = report.baseline,
          box = document.createElement("div");
        box.className = "case-note";
        box.innerHTML = `<strong>Working-PC comparison · ${esc(b.baseline_host)} → ${esc(b.current_host)}</strong><p>${count(b.differences.length, "configuration difference")}. A difference is not automatically a fault.</p>${
          b.differences.length
            ? `<details><summary>What differs</summary>${table(
                ["Check", "Setting", "Working PC", "Current PC"],
                b.differences.map((d) => [titleOf(d.module), d.label, d.baseline == null ? "not observed" : d.baseline, d.current == null ? "not observed" : d.current]),
              )}</details>`
            : ""
        }`;
        container.prepend(box);
      }
      if (report.recording) {
        const rec = report.recording,
          fails = rec.samples.filter((s) => s.tcp_error).length,
          box = document.createElement("div");
        box.className = "case-note";
        box.innerHTML = `<strong>Intermittent issue · ${count(rec.samples.length, "sample")} · ${count(rec.markers.length, "marker")}${fails ? " · " + count(fails, "failed connection") : ""}</strong><p>CPU, RAM, disk/network rates, connection probes and available Wi-Fi state.</p>`;
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
          "Separate resource pressure from application connectivity and recent changes.",
      },
      {
        id: "slow-pc",
        title: "The whole PC is slow",
        symptom:
          "Check load, memory, disk space and startup, then the drive's health and what changed.",
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
      "slow-pc": ["proc.top", "system.memory", "system.disk", "system.startup"],
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
      "slow-pc": ["system.storage", "system.reliability", "system.changes"],
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
            .map((f) => {
              const [at, kind] = f.label.split(" · ");
              const burst = /^\d+ events until (\S+Z):/.exec(f.value);
              return Object.assign(
                {
                  at,
                  source: m.title,
                  kind: kind || "Recorded event",
                  description: f.value,
                  detail: f.detail || "",
                },
                burst ? { until: burst[1] } : {},
              );
            }),
        )
        .sort((a, b) => a.at.localeCompare(b.at));
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
        if (!h.runbook) {
          const outcome = await base.run(ids, h);
          if (h.baseReport) {
            const r = clone(h.baseReport),
              newer = outcome.report;
            r.results = r.results
              .filter(
                (old) =>
                  !newer.results.some((n) => n.module_id === old.module_id),
              )
              .concat(newer.results);
            r.cancelled = !!r.cancelled || !!newer.cancelled;
            r.evidence_updated = new Date().toISOString();
            outcome.report = r;
            outcome.saved = keep(r);
          }
          return outcome;
        }
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
          if (["vpn", "slow-app", "slow-pc"].includes(h.runbook) || bad) {
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
            // A sample story: the PC moves to a weaker access point a few
            // samples in, and one connection attempt fails just after.
            const n = capture.samples.length,
              moved = n >= 3,
              signal = Math.round((moved ? 44 : 71) + Math.random() * 4),
              ap = moved ? "7c:10:c9:2b:6e:a1" : "7c:10:c9:2b:41:d0",
              failed = !!target && n === 4;
            const t = sample(),
              s = {
                at_ms: Date.now(),
                cpu_pct: t.cpu,
                memory_pct: t.mem_pct,
                disk_read: Math.round(t.disk_read),
                disk_write: Math.round(t.disk_write),
                net_rx: Math.round(t.net_rx),
                net_tx: Math.round(t.net_tx),
                tcp_ms: target && !failed ? 14 + Math.random() * 8 : null,
                tcp_error: failed ? "timed out" : null,
                dns_ms: n % 5 === 0 ? 3 : null,
                dns_error: null,
                wifi: `CORP · signal ${signal}% · AP ${ap}`,
                wifi_signal: signal,
                wifi_bssid: ap,
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
                tool_version: "0.10.0",
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
      timelineRows: async (r) => rows(r),
      timelineNear: async (r, at, window) =>
        rows(r).filter(
          (e) =>
            Date.parse(e.at) <= Date.parse(at) + window * 1000 &&
            Date.parse(e.until || e.at) >= Date.parse(at) - window * 1000,
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
