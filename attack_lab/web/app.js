"use strict";

const state = {
  report: null,
  activeTarget: null,
  observations: new Map(),
  filters: { search: "", mandate: "all", category: "all", outcome: "all" },
};

const escapeHtml = (value) => String(value ?? "")
  .replaceAll("&", "&amp;")
  .replaceAll("<", "&lt;")
  .replaceAll(">", "&gt;")
  .replaceAll('"', "&quot;")
  .replaceAll("'", "&#039;");

const pretty = (value) => JSON.stringify(value, null, 2);
const score = (value) => Number(value || 0).toLocaleString();

function badge(label, kind = "") {
  return `<span class="badge ${escapeHtml(kind)}">${escapeHtml(label)}</span>`;
}

function responseOutcome(observation) {
  const response = observation.response;
  if (response.planned) return { label: "PLANNED", kind: "warn" };
  if (response.network_error) return { label: "NETWORK", kind: "error" };
  if (observation.analysis?.allowed) return { label: "ALLOW", kind: "allow" };
  if (observation.analysis?.decision === "DENY") return { label: "DENY", kind: "deny" };
  if (response.status >= 500) return { label: `HTTP ${response.status}`, kind: "error" };
  return { label: response.status ? `HTTP ${response.status}` : "NO RESPONSE", kind: "warn" };
}

function renderSummary(report) {
  const summary = report.summary;
  const findings = report.targets.flatMap((target) => target.findings);
  const dataHits = findings.filter((finding) => finding.kind === "data").length;
  const breaks = findings.filter((finding) => finding.kind === "break").length;
  document.querySelector("#summary").innerHTML = `
    <div class="stat-grid">
      <article class="stat"><span class="stat-label">Potential score</span><strong class="stat-value">${score(summary.potential_score)}</strong><span class="stat-note">before organiser review</span></article>
      <article class="stat"><span class="stat-label">Targets</span><strong class="stat-value">${score(summary.targets)}</strong><span class="stat-note">posted gateways</span></article>
      <article class="stat"><span class="stat-label">Data flags</span><strong class="stat-value">${score(dataHits)}</strong><span class="stat-note">highest per mandate is scored</span></article>
      <article class="stat"><span class="stat-label">Gateway breaks</span><strong class="stat-value">${score(breaks)}</strong><span class="stat-note">deduplicated per target</span></article>
    </div>`;
}

function renderScoreboard(report) {
  document.querySelector("#scoreboard").innerHTML = report.targets.map((target) => {
    const summary = target.summary;
    return `<tr>
      <td><strong>${escapeHtml(target.name)}</strong></td>
      <td class="score">${score(summary.data_scores.default)}</td>
      <td class="score">${score(summary.data_scores.feature)}</td>
      <td class="score">${score(summary.break_score)}</td>
      <td class="score total">${score(summary.potential_score)}</td>
      <td>${score(summary.counts.requests)}</td>
    </tr>`;
  }).join("");
}

function renderTargetNav(report) {
  document.querySelector("#target-nav").innerHTML = report.targets.map((target) => `
    <button class="target-tab ${target.id === state.activeTarget ? "active" : ""}" data-target="${escapeHtml(target.id)}" type="button">
      <span>${escapeHtml(target.name)}</span>
      <span class="tab-score">${score(target.summary.potential_score)}</span>
      <small>${score(target.summary.counts.allowed)} allowed / ${score(target.summary.counts.requests)} requests</small>
    </button>`).join("");
}

function formatExpiry(claims) {
  if (!Number.isFinite(claims?.exp)) return "No readable expiry";
  return `Expires ${new Date(claims.exp * 1000).toLocaleString()}`;
}

function renderMandates(target) {
  return Object.entries(target.mandates).map(([kind, mandate]) => {
    const scopeCount = Array.isArray(mandate.claims?.scope) ? mandate.claims.scope.length : 0;
    const note = mandate.note || "No defender note captured. Review feature findings before claiming points.";
    return `<article class="mandate-card">
      <h3>${escapeHtml(kind)} mandate</h3>
      <p>${escapeHtml(note)}</p>
      <div class="mandate-meta">
        ${badge(`${scopeCount} scope ${scopeCount === 1 ? "entry" : "entries"}`)}
        ${badge(formatExpiry(mandate.claims), mandate.known_revoked ? "deny" : "")}
        ${mandate.known_revoked ? badge("known revoked", "deny") : ""}
      </div>
    </article>`;
  }).join("");
}

function shortEvidence(id) {
  const parts = id.split(":");
  return parts.slice(-2).join(":");
}

function renderFindings(target) {
  if (!target.findings.length) {
    return `<div class="empty-state">No scoring flags or unexpected ALLOW decisions were detected in this run.</div>`;
  }
  return `<div class="finding-list">${target.findings.map((finding) => `
    <article class="finding ${escapeHtml(finding.kind)}">
      <div class="finding-points">${score(finding.points)}<small>points</small></div>
      <div>
        <h4>${escapeHtml(finding.title)}</h4>
        <p>${escapeHtml(finding.detail)}</p>
        ${finding.mandate_kind ? `<div class="mandate-meta">${badge(`${finding.mandate_kind} mandate`)}</div>` : ""}
      </div>
      <div class="evidence-links">
        ${finding.evidence.map((id) => `<button type="button" class="evidence-link" data-evidence="${escapeHtml(id)}">${escapeHtml(shortEvidence(id))}</button>`).join("")}
      </div>
    </article>`).join("")}</div>`;
}

function observationMatches(observation) {
  const outcome = responseOutcome(observation).label.toLowerCase();
  const searchable = `${observation.probe.id} ${observation.probe.title} ${observation.probe.category} ${observation.analysis?.reason_code || ""}`.toLowerCase();
  return (state.filters.mandate === "all" || observation.mandate_kind === state.filters.mandate)
    && (state.filters.category === "all" || observation.probe.category === state.filters.category)
    && (state.filters.outcome === "all" || outcome === state.filters.outcome)
    && searchable.includes(state.filters.search.toLowerCase());
}

function clippedJson(value) {
  const text = pretty(value);
  const limit = 24000;
  return text.length > limit ? `${text.slice(0, limit)}\n\n… clipped in dashboard; download the JSON report for full evidence …` : text;
}

function renderObservation(observation) {
  const outcome = responseOutcome(observation);
  const expectation = observation.expectation.outcome.toUpperCase();
  const responseForDisplay = observation.response.json ?? observation.response.text ?? observation.response.network_error;
  return `<details class="observation" id="obs-${escapeHtml(observation.id)}">
    <summary>
      <span>${badge(`${observation.mandate_kind} / ${observation.attempt}`)}</span>
      <span><span class="probe-name">${escapeHtml(observation.probe.title)}</span><br><span class="probe-id">${escapeHtml(observation.probe.id)}</span></span>
      <span class="category">${badge(observation.probe.category)}</span>
      <span class="expectation">${badge(`expected ${expectation}`, expectation === "DENY" ? "deny" : expectation === "ALLOW" ? "allow" : "warn")}</span>
      <span class="latency">${badge(outcome.label, outcome.kind)}<br>${score(observation.response.elapsed_ms)} ms</span>
    </summary>
    <div class="observation-body">
      <section class="evidence-block">
        <div class="evidence-header"><h5>Signed request</h5><button type="button" class="button small" data-copy="request" data-observation="${escapeHtml(observation.id)}">Copy</button></div>
        <pre>${escapeHtml(clippedJson(observation.request))}</pre>
      </section>
      <section class="evidence-block">
        <div class="evidence-header"><h5>HTTP ${escapeHtml(observation.response.status ?? "—")} response</h5><button type="button" class="button small" data-copy="response" data-observation="${escapeHtml(observation.id)}">Copy</button></div>
        <pre>${escapeHtml(clippedJson(responseForDisplay))}</pre>
      </section>
    </div>
  </details>`;
}

function renderObservationList(target) {
  const observations = target.observations.filter(observationMatches);
  const container = document.querySelector("#observation-list");
  container.innerHTML = observations.length
    ? observations.map(renderObservation).join("")
    : `<div class="empty-state">No probes match these filters.</div>`;
}

function renderTarget() {
  const target = state.report.targets.find((item) => item.id === state.activeTarget);
  if (!target) return;
  const categories = [...new Set(target.observations.map((item) => item.probe.category))].sort();
  document.querySelector("#target-content").innerHTML = `
    <article class="panel">
      <header class="target-header">
        <div><p class="eyebrow">Selected target</p><h2 id="target-title">${escapeHtml(target.name)}</h2><span class="target-url">${escapeHtml(target.gateway_url)}</span></div>
        <div class="target-total"><strong>${score(target.summary.potential_score)}</strong><span>potential points</span></div>
      </header>
      <div class="mandate-grid">${renderMandates(target)}</div>
      <section class="subsection">
        <div class="subsection-title"><h3>Findings</h3><p>Evidence links jump to the exact exchange.</p></div>
        ${renderFindings(target)}
      </section>
      <section class="subsection">
        <div class="subsection-title"><h3>Probe evidence</h3><p>${score(target.summary.counts.requests)} signed HTTP exchanges</p></div>
        <div class="filters">
          <input id="filter-search" type="search" placeholder="Search probes or reason codes" aria-label="Search probes">
          <select id="filter-mandate" aria-label="Filter by mandate"><option value="all">All mandates</option>${Object.keys(target.mandates).map((kind) => `<option value="${escapeHtml(kind)}">${escapeHtml(kind)}</option>`).join("")}</select>
          <select id="filter-category" aria-label="Filter by category"><option value="all">All categories</option>${categories.map((category) => `<option value="${escapeHtml(category)}">${escapeHtml(category)}</option>`).join("")}</select>
          <select id="filter-outcome" aria-label="Filter by outcome"><option value="all">All outcomes</option><option value="allow">ALLOW</option><option value="deny">DENY</option><option value="network">Network errors</option><option value="planned">Planned</option></select>
        </div>
        <div id="observation-list" class="observation-list"></div>
      </section>
    </article>`;
  document.querySelector("#filter-search").value = state.filters.search;
  document.querySelector("#filter-mandate").value = state.filters.mandate;
  document.querySelector("#filter-category").value = state.filters.category;
  document.querySelector("#filter-outcome").value = state.filters.outcome;
  renderObservationList(target);
}

function render(report) {
  state.report = report;
  state.activeTarget = report.targets[0]?.id || null;
  state.observations = new Map(report.targets.flatMap((target) => target.observations).map((item) => [item.id, item]));
  const finished = report.run?.finished_at ? new Date(report.run.finished_at).toLocaleString() : "unfinished";
  document.querySelector("#run-meta").textContent = `${String(report.run?.profile || "unknown").toUpperCase()} · ${finished}`;
  renderSummary(report);
  renderScoreboard(report);
  renderTargetNav(report);
  renderTarget();
  document.querySelector("#dashboard").classList.remove("hidden");
}

function copyEvidence(button) {
  const observation = state.observations.get(button.dataset.observation);
  if (!observation) return;
  const value = button.dataset.copy === "request" ? observation.request : observation.response;
  navigator.clipboard.writeText(pretty(value)).then(() => {
    const original = button.textContent;
    button.textContent = "Copied";
    window.setTimeout(() => { button.textContent = original; }, 1200);
  });
}

document.addEventListener("click", (event) => {
  const targetTab = event.target.closest("[data-target]");
  if (targetTab) {
    state.activeTarget = targetTab.dataset.target;
    state.filters = { search: "", mandate: "all", category: "all", outcome: "all" };
    renderTargetNav(state.report);
    renderTarget();
    return;
  }
  const evidence = event.target.closest("[data-evidence]");
  if (evidence) {
    state.filters = { search: "", mandate: "all", category: "all", outcome: "all" };
    renderTarget();
    const details = document.getElementById(`obs-${evidence.dataset.evidence}`);
    if (details) {
      details.open = true;
      details.classList.add("highlight");
      details.scrollIntoView({ block: "center" });
      window.setTimeout(() => details.classList.remove("highlight"), 1800);
    }
    return;
  }
  const copy = event.target.closest("[data-copy]");
  if (copy) copyEvidence(copy);
});

document.addEventListener("input", (event) => {
  if (event.target.id !== "filter-search") return;
  state.filters.search = event.target.value;
  const target = state.report.targets.find((item) => item.id === state.activeTarget);
  renderObservationList(target);
});

document.addEventListener("change", (event) => {
  const mapping = { "filter-mandate": "mandate", "filter-category": "category", "filter-outcome": "outcome" };
  const key = mapping[event.target.id];
  if (!key) return;
  state.filters[key] = event.target.value;
  const target = state.report.targets.find((item) => item.id === state.activeTarget);
  renderObservationList(target);
});

fetch("/report.json", { cache: "no-store" })
  .then((response) => {
    if (!response.ok) throw new Error(`Report request failed with HTTP ${response.status}`);
    return response.json();
  })
  .then(render)
  .catch((error) => {
    const panel = document.querySelector("#error");
    panel.textContent = `Could not load the attack report: ${error.message}`;
    panel.classList.remove("hidden");
    document.querySelector("#run-meta").textContent = "REPORT UNAVAILABLE";
  });
