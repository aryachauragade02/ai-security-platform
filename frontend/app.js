// Dashboard logic. All text from the server is inserted with textContent (never innerHTML),
// so a malicious prompt stored in the logs can't inject HTML or scripts into this page.
const API = (window.API_BASE || "").replace(/\/$/, "");
const $ = (id) => document.getElementById(id);

function el(tag, attrs = {}, ...kids) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") node.className = v;
    else if (k === "text") node.textContent = v;
    else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v);
  }
  for (const kid of kids) if (kid != null) node.append(kid);
  return node;
}

function badge(value) {
  return el("span", { class: "badge b-" + value, text: String(value).replace("_", " ") });
}

function card(label, value) {
  return el("div", { class: "card" }, el("div", { class: "muted", text: label }), el("div", { class: "big", text: String(value) }));
}

function table(target, headers, rows) {
  target.replaceChildren(
    el("thead", {}, el("tr", {}, ...headers.map((h) => el("th", { text: h })))),
    el("tbody", {}, ...rows.map((cells) => el("tr", {}, ...cells.map((c) => (c instanceof Node ? c : el("td", { text: String(c ?? "") })))))),
  );
}

function cell(content, cls) {
  const td = el("td", cls ? { class: cls } : {});
  td.append(content instanceof Node ? content : document.createTextNode(String(content ?? "")));
  return td;
}

async function api(path, options = {}) {
  const headers = { "Content-Type": "application/json" };
  const admin = $("adminKey").value.trim();
  if (admin) headers["x-admin-key"] = admin;
  const res = await fetch(API + path, { headers, ...options });
  let body = null;
  try { body = await res.json(); } catch (_) { /* not json */ }
  if (!res.ok) throw new Error((body && body.detail) || "Request failed (" + res.status + ")");
  return body;
}

// ---------- tabs ----------
document.querySelectorAll("nav button").forEach((b) =>
  b.addEventListener("click", () => {
    document.querySelectorAll("nav button, .tab").forEach((x) => x.classList.remove("active"));
    b.classList.add("active");
    $(b.dataset.tab).classList.add("active");
    if (b.dataset.tab === "logs") loadLogs();
    if (b.dataset.tab === "agents") { loadPolicies(); loadCalls(); }
  }),
);

// ---------- status ----------
async function loadStatus() {
  const pill = $("status");
  try {
    const h = await api("/health");
    pill.textContent = "online · model: " + h.llm + " · store: " + h.store;
    pill.className = "pill ok";
  } catch (e) {
    pill.textContent = "backend offline (it may be waking up, retry in 30s)";
    pill.className = "pill bad";
  }
}

// ---------- playground ----------
$("protect").addEventListener("change", () => ($("protectLabel").textContent = $("protect").checked ? "ON" : "OFF"));
document.querySelectorAll(".ex").forEach((b) => b.addEventListener("click", () => ($("prompt").value = b.dataset.text)));

function findings(obj) {
  const parts = Object.entries(obj || {}).map(([k, v]) => k + " ×" + v);
  return parts.length ? parts.join(", ") : "none";
}

$("send").addEventListener("click", async () => {
  const message = $("prompt").value.trim();
  if (!message) return;
  const btn = $("send");
  btn.disabled = true;
  const out = $("playResult");
  out.replaceChildren(el("div", { class: "card muted", text: "Thinking..." }));
  try {
    const r = await api("/v1/demo/chat", { method: "POST", body: JSON.stringify({ message, protect: $("protect").checked }) });
    out.replaceChildren(
      el("div", { class: "card" },
        el("div", { class: "row" }, badge(r.blocked ? "blocked" : "allowed"), el("span", { class: "muted", text: "risk score " + r.risk_score + "/100 · " + r.latency_ms + " ms · protection " + (r.protected ? "on" : "off") })),
        r.blocked ? el("div", { class: "reply", text: r.reason }) : el("div", { class: "reply", text: r.reply }),
        el("p", { class: "muted", text: "Rules matched: " + (r.matched_rules.length ? r.matched_rules.join(", ") : "none") }),
        el("p", { class: "muted", text: "Sensitive data hidden in your message: " + findings(r.pii_input) + " · in the answer: " + findings(r.pii_output) }),
      ),
    );
  } catch (e) {
    out.replaceChildren(el("div", { class: "card b-blocked", text: e.message }));
  } finally {
    btn.disabled = false;
  }
});

// ---------- logs ----------
async function loadLogs() {
  try {
    const [s, logs] = await Promise.all([api("/v1/stats"), api("/v1/logs?limit=50")]);
    $("stats").replaceChildren(
      card("Requests", s.total_requests), card("Blocked", s.blocked), card("Block rate", s.block_rate + "%"),
      card("Data redactions", s.pii_redactions), card("Avg latency", s.avg_latency_ms + " ms"),
    );
    $("rules").textContent = s.top_rules.length ? "Top rules: " + s.top_rules.map((r) => r.rule + " (" + r.count + ")").join(", ") : "";
    table($("logTable"), ["Time", "Source", "Action", "Risk", "Prompt (sensitive data hidden)"],
      logs.map((l) => [
        new Date(l.created_at).toLocaleTimeString(), l.source, cell(badge(l.action)), l.risk_score,
        cell(l.prompt_redacted, "prompt"),
      ]));
  } catch (e) {
    $("rules").textContent = e.message;
  }
}
$("refreshLogs").addEventListener("click", loadLogs);

// ---------- scanner ----------
async function runScan(protect) {
  const buttons = [$("scanOff"), $("scanOn")];
  buttons.forEach((b) => (b.disabled = true));
  $("scanMsg").textContent = "Running 20 attacks, this can take up to a minute...";
  try {
    const run = await api("/v1/scans", { method: "POST", body: JSON.stringify({ protect }) });
    $("scanMsg").textContent = "";
    $("scanScores").replaceChildren(
      card("Security score", run.score + "/100"),
      card("Attacks that got through", run.leaked + " of " + (run.total - (run.summary.errors || 0))),
      card("Protection", protect ? "ON" : "OFF"),
    );
    table($("scanTable"), ["ID", "Category", "Attack", "Result", "Answer / reason"],
      run.results.map((r) => [r.attack_id, r.category, cell(r.name + ": " + r.prompt, "prompt"), cell(badge(r.verdict)), cell(r.response_excerpt, "prompt")]));
  } catch (e) {
    $("scanMsg").textContent = e.message;
  } finally {
    buttons.forEach((b) => (b.disabled = false));
  }
}
$("scanOff").addEventListener("click", () => runScan(false));
$("scanOn").addEventListener("click", () => runScan(true));

// ---------- agent guard ----------
async function loadPolicies() {
  try {
    const rows = await api("/v1/agents/policies");
    table($("policyTable"), ["Agent", "Tool", "Decision"], rows.map((p) => [p.agent_id, p.tool, cell(badge(p.decision))]));
  } catch (e) {
    $("policyTable").replaceChildren(el("caption", { text: e.message }));
  }
}

async function decide(id, verb) {
  try { await api("/v1/agents/tool-calls/" + id + "/" + verb, { method: "POST" }); } catch (e) { alert(e.message); }
  loadCalls();
}

async function loadCalls() {
  try {
    const rows = await api("/v1/agents/tool-calls?limit=30");
    table($("callTable"), ["Time", "Agent", "Tool", "Arguments", "Status", "Why", ""],
      rows.map((c) => [
        new Date(c.created_at).toLocaleTimeString(), c.agent_id, c.tool, cell(JSON.stringify(c.arguments), "prompt"), cell(badge(c.status)), cell(c.reason, "prompt"),
        c.status === "pending"
          ? cell(el("span", {}, el("button", { class: "ghost", text: "Approve", onclick: () => decide(c.id, "approve") }), " ", el("button", { class: "ghost", text: "Reject", onclick: () => decide(c.id, "reject") })))
          : cell(""),
      ]));
  } catch (e) {
    $("callTable").replaceChildren(el("caption", { text: e.message }));
  }
}
$("refreshCalls").addEventListener("click", loadCalls);

$("checkTool").addEventListener("click", async () => {
  let args = {};
  try { args = JSON.parse($("toolArgs").value || "{}"); } catch (_) { $("toolResult").replaceChildren(el("div", { class: "card", text: "Arguments must be valid JSON" })); return; }
  try {
    const r = await api("/v1/agents/check", { method: "POST", body: JSON.stringify({ agent_id: $("agentId").value.trim(), tool: $("toolName").value.trim(), arguments: args }) });
    $("toolResult").replaceChildren(el("div", { class: "card" }, el("div", { class: "row" }, badge(r.decision), el("span", { text: r.reason }))));
    loadCalls();
  } catch (e) {
    $("toolResult").replaceChildren(el("div", { class: "card", text: e.message }));
  }
});

// ---------- live updates ----------
// Poll the backend every 2s for whichever tab is open, so requests from any client
// (this page, curl, other apps using /v1/chat) appear without clicking Refresh.
let liveTimer = null;
function startLive() {
  clearInterval(liveTimer);
  liveTimer = setInterval(() => {
    if (document.hidden) return;
    const active = document.querySelector(".tabs button.active, nav button.active");
    const tab = active && active.dataset.tab;
    if (tab === "logs") loadLogs();
    if (tab === "agents") loadCalls();
    if (tab === "playground") loadStatus();
  }, 2000);
}
startLive();

loadStatus();
