let currentScanId = null;
let currentExposure = null;
let currentServices = [];
let statusIntervalId = null;

document.addEventListener("DOMContentLoaded", async () => {
  const form = document.getElementById("scan-form");
  const statusDiv = document.getElementById("scan-status");
  const startBtn = document.getElementById("start-scan-btn");

  const modal = document.getElementById("service-details-modal");
  const modalCloseBtn = document.getElementById("modal-close-btn");
  modalCloseBtn.addEventListener("click", () => (modal.style.display = "none"));
  modal.addEventListener("click", (e) => {
    if (e.target === modal) modal.style.display = "none";
  });

  loadScanHistory();
  const refreshHistoryBtn = document.getElementById("refresh-history-btn");
  if (refreshHistoryBtn) refreshHistoryBtn.addEventListener("click", loadScanHistory);
  const historyBody = document.querySelector("#history-table tbody");
  if (historyBody) {
    historyBody.addEventListener("click", (event) => {
      const button = event.target.closest("[data-history-scan-id]");
      if (button && !startBtn.disabled) restoreHistoricalScan(button.dataset.historyScanId);
    });
  }
  document.getElementById("download-report-btn").addEventListener("click", () => {
    if (currentScanId && !startBtn.disabled) window.location.href = `/scan/${currentScanId}/report.pdf`;
  });

  document.getElementById("service-search").addEventListener("input", (event) => {
    const query = event.target.value.trim().toLowerCase();
    for (const row of document.querySelectorAll("#services-table tbody tr")) {
      row.hidden = Boolean(query) && !row.textContent.toLowerCase().includes(query);
    }
  });

  const findingsDownload = document.getElementById("download-findings-btn");
  if (findingsDownload) {
    findingsDownload.addEventListener("click", () => {
      if (currentScanId && !startBtn.disabled) window.location.href = `/scan/${currentScanId}/findings.csv`;
    });
  }
  form.addEventListener("submit", async (e) => {
    e.preventDefault();

    const target = document.getElementById("target").value.trim();
    const exposure = document.getElementById("exposure").value;
    const profile = document.getElementById("profile").value;

    if (!target) {
      statusDiv.textContent = "Please enter a target.";
      return;
    }

    if (statusIntervalId !== null) {
      clearInterval(statusIntervalId);
      statusIntervalId = null;
    }

    currentScanId = null;
    resetOverview();
    setTableLoadingStates();


    startBtn.disabled = true;
    statusDiv.textContent = "Starting scan...";

    try {
      const resp = await fetch("/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target, exposure, profile }),
      });

      if (!resp.ok) {
        statusDiv.textContent = resp.status === 400
          ? "Enter one IPv4 address or hostname, with an optional port."
          : "Scan failed. Try again.";
        startBtn.disabled = false;
        return;
      }

      const data = await resp.json();
      currentScanId = data.scan_id;
      currentExposure = data.exposure || exposure;
      statusDiv.textContent = `Scan started (ID: ${currentScanId}). Waiting for completion...`;
      pollScanStatus(currentScanId);
      await loadScanHistory();
    } catch (err) {
      console.error(err);
      statusDiv.textContent = "Error starting scan (check console/logs).";
      startBtn.disabled = false;
    }
  });
});

function resetOverview() {
  document.getElementById("stat-hosts").textContent = "0";
  document.getElementById("stat-services").textContent = "0";
  document.getElementById("stat-critical").textContent = "0 / 0";
  document.getElementById("stat-weak-creds").textContent = "0";
  const findingsSummary = document.getElementById("finding-summary");
  const findingsBody = document.querySelector("#findings-table tbody");
  if (findingsSummary) findingsSummary.textContent = "";
  if (findingsBody) findingsBody.innerHTML = `<tr><td colspan="5">Waiting for scan to complete...</td></tr>`;
}

async function loadScanHistory() {
  const body = document.querySelector("#history-table tbody");
  if (!body) return;
  try {
    const response = await fetch("/scans/history");
    if (!response.ok) throw new Error(`History request failed: ${response.status}`);
    const scans = await response.json();
    if (!scans.length) {
      body.innerHTML = `<tr><td colspan="6" class="px-3 py-2">No scans recorded yet.</td></tr>`;
      return;
    }
    body.innerHTML = scans.map((scan) => `
      <tr>
        <td class="px-3 py-2">${escapeHtml(formatHistoryDate(scan.created_at))}</td>
        <td class="px-3 py-2 font-medium">${escapeHtml(scan.target || "")}</td>
        <td class="px-3 py-2">${escapeHtml(scan.profile || "standard")}</td>
        <td class="px-3 py-2">${escapeHtml(scan.exposure_effective || scan.exposure || "auto")}</td>
        <td class="px-3 py-2">${escapeHtml(scan.status || "unknown")}</td>
        <td class="px-3 py-2"><button type="button" data-history-scan-id="${escapeHtml(scan.scan_id)}" class="btn-link">View results</button></td>
      </tr>
    `).join("");
  } catch (error) {
    console.error("[HISTORY] Failed to load scan history:", error);
    body.innerHTML = `<tr><td colspan="6" class="px-3 py-2">Unable to load scan history.</td></tr>`;
  }
}

async function loadFindings(scanId) {
  const body = document.querySelector("#findings-table tbody");
  const summary = document.getElementById("finding-summary");
  body.innerHTML = `<tr><td colspan="5">Loading findings...</td></tr>`;
  const resp = await fetch(`/scan/${scanId}/findings`);
  if (!resp.ok) {
    body.innerHTML = `<tr><td colspan="5">Findings are not available yet.</td></tr>`;
    return;
  }
  const data = await resp.json();
  const counts = data.summary || {};
  summary.textContent = `Critical: ${counts.critical || 0} · High: ${counts.high || 0} · Medium: ${counts.medium || 0} · Low: ${counts.low || 0}`;
  const findings = data.findings || [];
  if (!findings.length) {
    body.innerHTML = `<tr><td colspan="5">No findings were generated.</td></tr>`;
    return;
  }
  body.innerHTML = "";
  for (const finding of findings) {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td class="px-3 py-2"><span class="badge badge-${escapeHtml(finding.severity || "info")}">${escapeHtml(finding.severity || "info")}</span></td>
      <td class="px-3 py-2">${escapeHtml(finding.title || "")}</td>
      <td class="px-3 py-2">${escapeHtml(finding.asset || "")}</td>
      <td class="px-3 py-2 max-w-xl">${escapeHtml(finding.evidence || "")}</td>
      <td class="px-3 py-2">${escapeHtml(finding.source || "")}</td>
    `;
    body.appendChild(tr);
  }
}

function formatHistoryDate(value) {
  if (!value) return "Unknown";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

async function restoreHistoricalScan(scanId) {
  if (!scanId) return;
  if (statusIntervalId !== null) {
    clearInterval(statusIntervalId);
    statusIntervalId = null;
  }
  const response = await fetch(`/scan/${encodeURIComponent(scanId)}`);
  if (!response.ok) {
    alert("This scan is no longer available.");
    await loadScanHistory();
    return;
  }
  const scan = await response.json();
  currentScanId = scan.scan_id;
  currentExposure = scan.exposure || scan.exposure_effective || "auto";
  document.getElementById("scan-status").textContent = `Viewing scan ${scan.scan_id}`;

  resetOverview();
  setTableLoadingStates();
  if (scan.status === "failed") {
    document.getElementById("scan-status").textContent = scan.message || "Scan failed.";
  } else if (scan.status === "completed") {
    await Promise.all([
      loadScanResults(scan.scan_id),
      loadFindings(scan.scan_id),
      loadAliveHosts(scan.scan_id),
      loadGobusterResults(scan.scan_id),
      loadWebAssessment(scan.scan_id),
      loadAttackGraph(scan.scan_id),
    ]);
  } else {
    pollScanStatus(scan.scan_id);
  }
}

function setTableLoadingStates() {
  const servicesBody = document.querySelector("#services-table tbody");
  const gobBody = document.querySelector("#gobuster-table tbody");
  const agDiv = document.getElementById("attack-graph-content");
  const agNet = document.getElementById("attack-graph-network");
  servicesBody.innerHTML = `<tr><td colspan="9">Waiting for scan to complete...</td></tr>`;
  gobBody.innerHTML = `<tr><td colspan="3">Waiting for scan to complete...</td></tr>`;
  agDiv.textContent = "Waiting for scan to complete...";
  agNet.innerHTML = "";
}

function pollScanStatus(scanId) {
  const statusDiv = document.getElementById("scan-status");
  const startBtn = document.getElementById("start-scan-btn");

  const doPoll = async () => {
    try {
      const resp = await fetch(`/scan/${scanId}`);
      if (!resp.ok) {
        statusDiv.textContent = `Error checking status: ${resp.status}`;
        clearInterval(statusIntervalId);
        statusIntervalId = null;
        startBtn.disabled = false;
        return;
      }

      const data = await resp.json();
      currentExposure = data.exposure || currentExposure;

      if (data.status === "completed") {
        // ✅ Fully done — stop polling and load everything
        clearInterval(statusIntervalId);
        statusIntervalId = null;
        startBtn.disabled = false;

        statusDiv.textContent = `Loading results...`;

        try {
          await Promise.all([
            loadScanResults(scanId).catch(e => {
              console.error("[LOADING] loadScanResults failed:", e);
              throw e;
            }),
            loadFindings(scanId).catch(e => {
              console.error("[LOADING] loadFindings failed:", e);
              throw e;
            }),
            loadAliveHosts(scanId).catch(e => {
              console.error("[LOADING] loadAliveHosts failed:", e);
              throw e;
            }),
            loadGobusterResults(scanId).catch(e => {
              console.error("[LOADING] loadGobusterResults failed:", e);
              throw e;
            }),
            loadWebAssessment(scanId).catch(e => {
              console.error("[LOADING] loadWebAssessment failed:", e);
              throw e;
            }),
            loadAttackGraph(scanId).catch(e => {
              console.error("[LOADING] loadAttackGraph failed:", e);
              throw e;
            }),
          ]);
          statusDiv.textContent = `Scan complete.`;
          await loadScanHistory();
        } catch (loadErr) {
          console.error("[LOADING] Error loading results:", loadErr);
          statusDiv.textContent = `Scan completed but error loading results. Check console.`;
        }

      } else if (data.status === "failed") {
        clearInterval(statusIntervalId);
        statusIntervalId = null;
        startBtn.disabled = false;
        statusDiv.textContent = `Scan failed: ${data.message || "unknown error"}`;

      } else if (data.status === "nmap_done") {
        // ✅ Nmap done but gobuster still running
        if (data.gobuster_status === "completed") {
          statusDiv.textContent = `Gobuster completed. Finalizing...`;
        } else {
          statusDiv.textContent = `Nmap completed. Waiting for Gobuster to finish...`;
        }

      } else if (data.status === "running") {
        statusDiv.textContent = `Scan running... ${data.message || ""}`;

      } else {
        statusDiv.textContent = `Scan status: ${data.status} — ${data.message || ""}`;
      }

    } catch (err) {
      console.error("[POLL] Error in poll callback:", err);
      statusDiv.textContent = "Error checking status (see console).";
      clearInterval(statusIntervalId);
      statusIntervalId = null;
      startBtn.disabled = false;
    }
  };

  // Start polling
  statusIntervalId = setInterval(doPoll, 3000);
  // Also poll immediately
  doPoll();
}

async function loadScanResults(scanId) {
  const servicesBody = document.querySelector("#services-table tbody");
  servicesBody.innerHTML = `<tr><td colspan="9">Loading NVD/RiskLens data...</td></tr>`;
  currentServices = [];

  try {
    const url = `/scan/${scanId}/nvd`;
    const resp = await fetch(url);
    
    if (!resp.ok) {
      const errorText = await resp.text().catch(() => "Unknown error");
      console.error("[loadScanResults] Server error:", resp.status, errorText);
      servicesBody.innerHTML = `<tr><td colspan="9">Server error: ${resp.status}</td></tr>`;
      return;
    }

    const data = await resp.json();
    const hosts = data.data.hosts || [];
    
    const rows = [];
    for (const host of hosts) {
      const ip = host.ip;
      for (const svc of host.services || []) {
        rows.push({ ip, ...svc });
      }
    }

    currentServices = rows;
    rows.sort((a, b) => (b.pcvp_score || 0) - (a.pcvp_score || 0));

    const hostCount = hosts.length;
    const serviceCount = rows.length;
    let criticalCount = 0, highCount = 0, weakCount = 0;
    for (const s of rows) {
      if (s.pcvp_level === "critical") criticalCount++;
      if (s.pcvp_level === "high") highCount++;
      if (s.weak_creds && s.weak_creds.found) weakCount++;
    }

    document.getElementById("stat-hosts").textContent = hostCount;
    document.getElementById("stat-services").textContent = serviceCount;
    document.getElementById("stat-critical").textContent = `${criticalCount} / ${highCount}`;
    document.getElementById("stat-weak-creds").textContent = weakCount;


if (!rows.length) {
  servicesBody.innerHTML = `<tr><td colspan="9">No services detected for this scan.</td></tr>`;
  return;
}

servicesBody.innerHTML = "";
for (const svc of rows) {
  const tr = document.createElement("tr");
  const level = svc.pcvp_level || "informational";
  const badgeClass =
    level === "critical" ? "badge-critical" :
    level === "high" ? "badge-high" :
    level === "medium" ? "badge-medium" :
    level === "low" ? "badge-low" : "badge-info";
  const weakCredsText = svc.weak_creds && svc.weak_creds.found
    ? `${svc.weak_creds.protocol || ""} ${svc.weak_creds.username}:${svc.weak_creds.password}`
    : "None";
  const weakPillClass = svc.weak_creds && svc.weak_creds.found ? "pill pill-weak" : "pill";
  const nseCount = Array.isArray(svc.nse_findings) ? svc.nse_findings.length : 0;
  tr.innerHTML = `
    <td>${escapeHtml(svc.ip || "")}</td>
    <td>${escapeHtml(svc.port)}/${escapeHtml(svc.protocol)} (${escapeHtml(svc.state)})</td>
    <td>${escapeHtml(svc.service || "")}</td>
    <td>${escapeHtml((svc.product || "") + " " + (svc.version || ""))}</td>
    <td><span class="badge ${badgeClass}">${escapeHtml(level)}</span></td>
    <td>${escapeHtml(svc.pcvp_score ?? "")}</td>
    <td><span class="${weakPillClass}">${escapeHtml(weakCredsText)}</span></td>
    <td>${nseCount ? `<span class="pill pill-weak">${nseCount} finding(s)</span>` : "None"}</td>
    <td><button class="btn-link" data-ip="${escapeHtml(svc.ip)}" data-port="${escapeHtml(svc.port)}" data-proto="${escapeHtml(svc.protocol)}">Details</button></td>
  `;
  servicesBody.appendChild(tr);
}
servicesBody.querySelectorAll(".btn-link").forEach((btn) =>
  btn.addEventListener("click", onDetailsClick)
);

} catch (err) {
  console.error("[loadScanResults] CATCH ERROR:", err.name, err.message);
  console.error("[loadScanResults] Full error:", err);
  servicesBody.innerHTML = `<tr><td colspan="9">Error loading NVD/RiskLens data: ${escapeHtml(err.message)}</td></tr>`;
}
}

async function loadAliveHosts(scanId) {
  const body = document.querySelector("#alive-hosts-table tbody");
  body.innerHTML = `<tr><td colspan="6">Loading alive hosts...</td></tr>`;

  try {
    const resp = await fetch(`/scan/${scanId}/alive-hosts`);
    if (!resp.ok) {
      body.innerHTML = `<tr><td colspan="6">Alive hosts are not available yet.</td></tr>`;
      return;
    }

    const data = await resp.json();
    const hosts = data.hosts || [];
    if (!hosts.length) {
      body.innerHTML = `<tr><td colspan="6">No alive hosts detected.</td></tr>`;
      return;
    }

    body.innerHTML = "";
    for (const host of hosts) {
      const tr = document.createElement("tr");
      const os = Array.isArray(host.os) && host.os.length
        ? host.os.map(item => `${item.name || ""} (${item.accuracy || "?"}%)`).join(", ")
        : "Unknown";
      tr.innerHTML = `
        <td class="px-3 py-2">${escapeHtml(host.ip || "")}</td>
        <td class="px-3 py-2">${escapeHtml((host.hostnames || []).join(", ") || "—")}</td>
        <td class="px-3 py-2">${escapeHtml([host.mac, host.mac_vendor].filter(Boolean).join(" / ") || "—")}</td>
        <td class="px-3 py-2">${escapeHtml(os)}</td>
        <td class="px-3 py-2">${host.services ?? "—"}</td>
        <td class="px-3 py-2">${escapeHtml((host.ports || []).join(", ") || "—")}</td>
      `;
      body.appendChild(tr);
    }
  } catch (err) {
    console.error("[loadAliveHosts] Error:", err);
    body.innerHTML = `<tr><td colspan="6">Error loading alive hosts.</td></tr>`;
  }
}

async function loadWebAssessment(scanId) {
  const container = document.getElementById("web-assessment");
  if (!container) return;
  container.textContent = "Loading HTTP/TLS assessment...";
  try {
    const resp = await fetch(`/webscan/${scanId}/assessment`);
    if (!resp.ok) {
      container.textContent = "Web assessment is not available for this scan.";
      return;
    }
    const data = await resp.json();
    const checks = data.checks || [];
    const technologies = data.technologies || [];
    const tls = data.tls || {};
    if (data.error && !data.http?.status && !tls.protocol) {
      const message = data.error.includes("WinError 10013")
        ? "Windows blocked the connection to this address and port."
        : "The web server did not return an HTTP response.";
      container.innerHTML = `
        <p><strong>Target:</strong> ${escapeHtml(data.url || "")}</p>
        <p>${message}</p>
        <details><summary>Technical details</summary><p>${escapeHtml(data.error)}</p></details>
      `;
      return;
    }
    const checkRows = checks.length
      ? checks.map(check => `<li><strong>${escapeHtml(check.name)}</strong>: ${escapeHtml(check.status)} — ${escapeHtml(check.detail)}</li>`).join("")
      : "<li>No HTTP checks returned.</li>";
    const technologyText = technologies.length
      ? technologies.map(item => `${item.name}: ${item.evidence}`).join(", ")
      : "No technology signatures detected";
    container.innerHTML = `
      <div><strong>Final URL:</strong> ${escapeHtml(data.http?.final_url || data.url || "")}</div>
      <div><strong>HTTP status:</strong> ${escapeHtml(data.http?.status ?? "Unavailable")}</div>
      <div><strong>Technologies:</strong> ${escapeHtml(technologyText)}</div>
      <div><strong>TLS:</strong> ${escapeHtml(tls.protocol || "Not HTTPS")} ${tls.cipher ? `(${escapeHtml(tls.cipher)})` : ""}</div>
      <div class="section-title">Security checks</div>
      <ul>${checkRows}</ul>
      ${data.error ? `<div style="color:#fca5a5;">${escapeHtml(data.error)}</div>` : ""}
    `;
  } catch (err) {
    console.error("[loadWebAssessment] Error:", err);
    container.textContent = "Error loading web assessment.";
  }
}

async function loadGobusterResults(scanId) {
  const gobBody = document.querySelector("#gobuster-table tbody");
  gobBody.innerHTML = `<tr><td colspan="3">Loading Gobuster results...</td></tr>`;

  try {
    const resp = await fetch(`/webscan/${scanId}/results`);
    if (!resp.ok) {
      gobBody.innerHTML = `<tr><td colspan="3">No Gobuster results yet or error: ${resp.status}</td></tr>`;
      return;
    }

    const data = await resp.json();
    const results = data.results || [];
    const error = data.error || null;
    const errorDetail = data.error_detail || null;

    if (error && !results.length) {
      gobBody.innerHTML = `
        <tr><td colspan="3">
          <div style="color:#fbbf24;">${escapeHtml(error)}</div>
          ${errorDetail ? `<details style="margin-top:6px;"><summary>Technical details</summary><pre style="white-space:pre-wrap; margin-top:4px;">${escapeHtml(errorDetail)}</pre></details>` : ""}
        </td></tr>`;
      return;
    }

    if (!results.length) {
      gobBody.innerHTML = `
        <tr><td colspan="3">
          <div>No directories found.</div>
          ${error ? `<div style="color:#fbbf24; margin-top:4px;">${escapeHtml(error)}</div>` : ""}
          ${errorDetail ? `<details style="margin-top:6px;"><summary>Technical details</summary><pre style="white-space:pre-wrap; margin-top:4px;">${escapeHtml(errorDetail)}</pre></details>` : ""}
        </td></tr>`;
      return;
    }

    gobBody.innerHTML = "";
    if (error) {
      const notice = document.createElement("tr");
      notice.innerHTML = `<td colspan="3" style="color:#fbbf24;">${escapeHtml(error)} <details style="display:inline;"><summary style="display:inline; cursor:pointer;">details</summary><pre style="white-space:pre-wrap; margin-top:4px;">${escapeHtml(errorDetail || "")}</pre></details></td>`;
      gobBody.appendChild(notice);
    }
    for (const r of results) {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td>${escapeHtml(r.path)}</td>
        <td>${escapeHtml(r.status)}</td>
        <td>${escapeHtml(r.size ?? "")}</td>
      `;
      gobBody.appendChild(tr);
    }
  } catch (err) {
    console.error(err);
    gobBody.innerHTML = `<tr><td colspan="3">Error loading Gobuster results (see console).</td></tr>`;
  }
}

async function loadAttackGraph(scanId) {
  const textContainer = document.getElementById("attack-graph-content");
  const graphContainer = document.getElementById("attack-graph-network");
  textContainer.textContent = "Loading attack graph...";
  graphContainer.innerHTML = "";

  try {
    const resp = await fetch(`/scan/${scanId}/attack-graph`);
    if (!resp.ok) {
      const errorText = await resp.text().catch(() => "Unknown error");
      console.error("[loadAttackGraph] Error response:", errorText);
      textContainer.textContent = `Error loading attack graph: ${resp.status}`;
      return;
    }

    const data = await resp.json();
    const graph = data.graph || {};
    const nodes = graph.nodes || [];
    const edges = graph.edges || [];

    if (!nodes.length || !edges.length) {
      textContainer.textContent = "No attack paths identified for this scan.";
      return;
    }

    const nodeById = {};
    nodes.forEach((n) => (nodeById[n.id] = n));

    if (typeof vis === "undefined") graphContainer.hidden = true;
    else {
      graphContainer.hidden = false;
      const visNodes = new vis.DataSet(
      nodes.map((n) => {
        let label = n.id, color = "#6b7280", shape = "ellipse";
        if (n.type === "host") { label = n.ip || n.id; color = "#1d4ed8"; shape = "box"; }
        else if (n.type === "service") {
          const level = (n.pcvp_level || "").toLowerCase();
          label = `${n.service || "svc"}\n${n.port || ""}/${n.protocol || ""}`;
          if (level === "critical") color = "#dc2626";
          else if (level === "high") color = "#f97316";
          else if (level === "medium") color = "#eab308";
          else if (level === "low") color = "#22c55e";
          else color = "#6b7280";
        } else if (n.type === "cve") { label = n.cve_id || "CVE"; color = "#0ea5e9"; shape = "diamond"; }
        return { id: n.id, label, color, shape, font: { color: "#e5e7eb", size: 12 } };
      })
    );

    const visEdges = new vis.DataSet(
      edges.map((e) => {
        let color = "#4b5563", dashes = false, label = "";
        if (e.relation === "runs") { label = "runs"; color = "#6b7280"; }
        else if (e.relation === "has_vulnerability") { label = "has CVE"; color = "#0ea5e9"; }
        else if (e.relation === "possible_chain") { label = "pivot"; color = "#f97316"; dashes = true; }
        return { from: e.from, to: e.to, color, dashes, arrows: "to", label, font: { align: "middle", color: "#9ca3af", size: 10 } };
      })
    );

    new vis.Network(graphContainer, { nodes: visNodes, edges: visEdges }, {
      autoResize: true,
      physics: { stabilization: true, barnesHut: { springLength: 120, springConstant: 0.01 } },
      interaction: { tooltipDelay: 200, hover: true },
      nodes: { borderWidth: 1 },
      layout: { improvedLayout: true },
    });

    }

    const hostServices = {};
    edges.forEach((e) => {
      if (e.relation === "runs") {
        if (!hostServices[e.from]) hostServices[e.from] = [];
        hostServices[e.from].push(e.to);
      }
    });

    const chains = [];
    for (const [hostId, serviceIds] of Object.entries(hostServices)) {
      const hostNode = nodeById[hostId];
      const hostIp = hostNode && hostNode.ip ? hostNode.ip : hostId;
      for (const sid of serviceIds) {
        const svc = nodeById[sid];
        if (!svc) continue;
        const level = (svc.pcvp_level || "").toLowerCase();
        const score = svc.pcvp_score || 0;
        if (!(level === "critical" || level === "high")) continue;
        const cveEdges = edges.filter((e) => e.from === sid && e.relation === "has_vulnerability");
        const cveIds = cveEdges.map((e) => nodeById[e.to]).filter(Boolean).map((c) => c.cve_id || c.id || c.name).filter(Boolean);
        const chainEdges = edges.filter((e) => e.from === sid && e.relation === "possible_chain");
        const nextServices = chainEdges.map((e) => nodeById[e.to]).filter(Boolean).map((ns) => `${ns.service || "service"} on ${ns.ip || hostIp}:${ns.port}`);
        chains.push({ hostIp, service: svc.service || "service", port: svc.port, level, score, cves: cveIds, nextServices });
      }
    }
if (!chains.length) {
  textContainer.textContent = "No high/critical attack paths identified. Lower-risk services may exist but no strong chains.";
} else {
  let html = "<ul>";
  for (const ch of chains) {
    html += "<li style='margin-bottom:6px;'>";
    html += `<strong>${escapeHtml(ch.service)}</strong> on <strong>${escapeHtml(ch.hostIp)}:${escapeHtml(ch.port)}</strong> `;
    html += `(RiskLens: ${escapeHtml(ch.level.toUpperCase())} score ${escapeHtml(ch.score)})`;
    if (ch.cves.length) { html += "<br><span style='color:#9ca3af;'>Exploitable via:</span> " + ch.cves.map((id) => `<code>${escapeHtml(id)}</code>`).join(", "); }
    if (ch.nextServices.length) { html += "<br><span style='color:#9ca3af;'>Potential pivot to:</span> " + ch.nextServices.map(escapeHtml).join(", "); }
    html += "</li>";
  }
  html += "</ul>";
  textContainer.innerHTML = html;
}

// ✅ Always save cache regardless of chains length
  } catch (err) {
    console.error(err);
    textContainer.textContent = "Error building attack graph (see console).";
  }
}

function onDetailsClick(e) {
  const ip = e.target.getAttribute("data-ip");
  const port = parseInt(e.target.getAttribute("data-port"), 10);
  const proto = e.target.getAttribute("data-proto") || "tcp";
  const svc = currentServices.find((s) => s.ip === ip && s.port === port && (s.protocol || "tcp") === proto);
  if (!svc) return;

  const modal = document.getElementById("service-details-modal");
  const title = document.getElementById("modal-title");
  const body = document.getElementById("modal-body");
  title.textContent = `${escapeHtml(svc.service || "")} on ${escapeHtml(svc.ip)}:${escapeHtml(svc.port)}/${escapeHtml(svc.protocol)}`;

  const reasons = svc.pcvp_reasons || [];
  const nvd = svc.nvd || {};
  const cves = nvd.cves || nvd.CVEs || [];

  let html = "";
  html += `<div><strong>Product:</strong> ${escapeHtml(svc.product || "")} ${escapeHtml(svc.version || "")}</div>`;
  html += `<div><strong>Exposure:</strong> ${escapeHtml(currentExposure || "auto")}</div>`;
  html += `<div><strong>RiskLens:</strong> ${escapeHtml(svc.pcvp_level || "")} (score ${escapeHtml(svc.pcvp_score ?? "")})</div>`;
  if (svc.weak_creds && svc.weak_creds.found) {
    html += `<div style="margin-top:4px;"><strong>Weak Credentials:</strong> ${escapeHtml(`${svc.weak_creds.protocol || ""} ${svc.weak_creds.username}:${svc.weak_creds.password}`)}</div>`;
  }
  html += `<div class="section-title">Why this is prioritized</div>`;
  if (reasons.length) { html += "<ul>"; for (const r of reasons) html += `<li>${escapeHtml(r)}</li>`; html += "</ul>"; }
  else { html += "<div>No reasons available.</div>"; }
  html += `<div class="section-title">Mapped CVEs</div>`;
  if (cves.length) {
    html += "<ul>";
    for (const c of cves) {
      const id = c.cve_id || c.id || "Unknown";
      const sev = c.severity || c.SEVERITY || "Unknown";
      const score = c.score || c.cvss || c.CVSS || "";
      html += `<li>${escapeHtml(id)} (severity: ${escapeHtml(sev)}, score: ${escapeHtml(score)})</li>`;
    }
    html += "</ul>";
  } else { html += "<div>No CVEs mapped for this service.</div>"; }
  const nseFindings = Array.isArray(svc.nse_findings) ? svc.nse_findings : [];
  html += `<div class="section-title">Nmap NSE vulnerability evidence</div>`;
  if (nseFindings.length) {
    html += "<ul>";
    for (const finding of nseFindings) {
      html += `<li><strong>${escapeHtml(finding.id || "NSE script")}</strong><pre style="white-space:pre-wrap; margin-top:4px;">${escapeHtml(finding.output || "")}</pre></li>`;
    }
    html += "</ul>";
  } else {
    html += "<div>No NSE vulnerability evidence reported for this service.</div>";
  }
  body.innerHTML = html;
  modal.style.display = "flex";
}

function escapeHtml(str) {
  return String(str).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}
