// AgentWall console. Data shown here can be attacker-written (tool arguments), so every value is
// inserted with textContent / createTextNode; never innerHTML.
"use strict";

const SEVERITY = { allow: 0, redact: 1, ask: 2, block: 3 };
const LABEL = { allow: "allowed", redact: "masked", ask: "held", block: "blocked", hidden: "hidden" };
const state = { lastSeq: 0, events: [], tab: "overview", expanded: new Set() };

function el(tag, attrs, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k === "class") node.className = v;
    else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v);
  }
  for (const child of children.flat()) {
    if (child === null || child === undefined || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

function svg(tag, attrs, ...children) {
  const node = document.createElementNS("http://www.w3.org/2000/svg", tag);
  for (const [k, v] of Object.entries(attrs || {})) node.setAttribute(k, v);
  for (const child of children) node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  return node;
}

const badge = (action) => el("span", { class: `badge ${action}` }, LABEL[action] || action);
const time = (ts) => (ts ? new Date(ts * 1000).toLocaleTimeString() : "");

async function api(path, options) {
  const res = await fetch(path, options);
  if (!res.ok) throw new Error(`${path}: ${res.status}`);
  return res.json();
}

// -- overview -------------------------------------------------------------------------------------
function renderSummary(s) {
  const chain = document.getElementById("chain");
  chain.textContent = s.chain_ok ? "audit chain intact" : `audit chain broken at entry ${s.chain_broken_at}`;
  chain.className = `pill ${s.chain_ok ? "ok" : "bad"}`;

  const tiles = [
    ["Tool calls", s.calls, ""],
    ["Blocked", s.actions.block, "block"],
    ["Held for approval", s.actions.ask, "ask"],
    ["Masked", s.redacted, "redact"],
    ["Quarantined outputs", s.quarantined, ""],
    ["Sessions", s.sessions, ""],
  ];
  document.getElementById("tiles").replaceChildren(
    ...tiles.map(([label, value, cls]) =>
      el("div", { class: `tile ${cls}` }, el("div", { class: "label" }, label), el("div", { class: "value" }, value))
    )
  );

  const body = document.querySelector("#by-tool tbody");
  body.replaceChildren(
    ...(s.tools.length
      ? s.tools.map((t) =>
          el("tr", {}, el("td", { class: "mono" }, t.tool), ...["allow", "redact", "ask", "block"].map((a) => el("td", { class: "num" }, t[a])))
        )
      : [el("tr", {}, el("td", { colspan: "5", class: "empty" }, "No tool calls recorded yet."))])
  );
  document.getElementById("top-rules").replaceChildren(
    ...(s.top_rules.length ? s.top_rules.map(([rule, n]) => el("li", {}, el("span", { class: "mono" }, rule), ` × ${n}`)) : [el("li", { class: "muted" }, "none")])
  );
  document.getElementById("hidden").replaceChildren(
    ...(s.hidden_tools.length ? s.hidden_tools.map((t) => el("li", { class: "mono" }, t)) : [el("li", { class: "muted" }, "none")])
  );
  document.getElementById("audit-path").textContent = `Reading ${s.audit_path}`;
}

// -- activity -------------------------------------------------------------------------------------
function detailRow(e) {
  if (e.event === "tool_hidden") return el("tr", { class: "detail" }, el("td", { colspan: "6" }, e.reason));
  const rows = e.args.map((a) =>
    el(
      "tr",
      {},
      el("td", { class: "mono" }, a.path),
      el("td", { class: "mono" }, a.value),
      el("td", {}, el("span", { class: a.label.startsWith("untrusted") ? "tag untrusted" : "tag" }, a.label)),
      el("td", {}, el("span", { class: "tag" }, a.method), a.flagged ? el("span", { class: "tag untrusted" }, "from flagged text") : null)
    )
  );
  const extras = [];
  if (e.redactions.length) extras.push(el("div", {}, "Masked: ", e.redactions.join(", ")));
  if (e.quarantined) extras.push(el("div", {}, `Output quarantined as ${e.quarantined}`));
  if (e.approval) extras.push(el("div", {}, `Approval: ${e.approval}`));
  return el(
    "tr",
    { class: "detail" },
    el("td", { colspan: "6" }, rows.length ? el("table", { class: "args" }, el("tbody", {}, rows)) : el("span", { class: "muted" }, "no arguments"), extras)
  );
}

function renderActivity() {
  const filter = document.getElementById("filter").value;
  const body = document.querySelector("#activity tbody");
  const shown = state.events.filter((e) => !filter || e.action === filter).slice(-500).reverse();
  const rows = [];
  for (const e of shown) {
    rows.push(
      el(
        "tr",
        {
          class: "row",
          onclick: () => {
            state.expanded.has(e.seq) ? state.expanded.delete(e.seq) : state.expanded.add(e.seq);
            renderActivity();
          },
        },
        el("td", { class: "num" }, e.seq),
        el("td", {}, time(e.ts)),
        el("td", { class: "mono" }, e.tool),
        el("td", {}, badge(e.action)),
        el("td", {}, ...(e.rules || []).map((r) => el("span", { class: "tag" }, r))),
        el("td", { class: "mono muted" }, e.session || "")
      )
    );
    if (state.expanded.has(e.seq)) rows.push(detailRow(e));
  }
  body.replaceChildren(...(rows.length ? rows : [el("tr", {}, el("td", { colspan: "6", class: "empty" }, "Nothing to show yet."))]));
}

// -- flows ----------------------------------------------------------------------------------------
async function renderFlows() {
  const data = await api("/api/flows");
  const box = document.getElementById("flow-graph");
  if (!data.edges.length) {
    box.replaceChildren(el("div", { class: "empty" }, "No traced arguments yet."));
    return;
  }
  const rowH = 34, top = 20, width = 820, leftX = 10, nodeW = 230, rightX = width - nodeW - 10;
  const height = top * 2 + rowH * Math.max(data.sources.length, data.tools.length);
  const y = (list, name) => top + list.indexOf(name) * rowH + rowH / 2;
  const maxTotal = Math.max(...data.edges.map((e) => e.total));
  const root = svg("svg", { viewBox: `0 0 ${width} ${height}`, width: "100%", role: "img", "aria-label": "Data flow graph" });

  for (const e of data.edges) {
    const worst = Object.keys(e.counts).sort((a, b) => (SEVERITY[b] ?? 0) - (SEVERITY[a] ?? 0))[0];
    const y1 = y(data.sources, e.source), y2 = y(data.tools, e.tool);
    const x1 = leftX + nodeW, x2 = rightX, mid = (x1 + x2) / 2;
    const path = svg("path", {
      d: `M${x1},${y1} C${mid},${y1} ${mid},${y2} ${x2},${y2}`,
      class: `edge ${worst}`,
      "stroke-width": String(1.5 + 5 * (e.total / maxTotal)),
    });
    const counts = Object.entries(e.counts).map(([a, n]) => `${LABEL[a] || a} ${n}`).join(", ");
    path.append(svg("title", {}, `${e.source} → ${e.tool}: ${counts}`));
    root.append(path);
  }
  const node = (x, yy, label, sub) => {
    const g = svg("g", {});
    g.append(svg("rect", { class: "node", x, y: yy - 13, width: nodeW, height: 26, rx: 6 }));
    const text = svg("text", { x: x + 10, y: yy + 4 }, label.length > 30 ? label.slice(0, 29) + "…" : label);
    if (sub) text.append(svg("title", {}, `${label} (${sub})`));
    g.append(text);
    root.append(g);
  };
  data.sources.forEach((s) => node(leftX, y(data.sources, s), s, data.labels[s]));
  data.tools.forEach((t) => node(rightX, y(data.tools, t), t));
  box.replaceChildren(root);
}

// -- approvals ------------------------------------------------------------------------------------
async function decide(id, decision, remember, buttons) {
  buttons.forEach((b) => (b.disabled = true));
  try {
    await api(`/api/approvals/${encodeURIComponent(id)}`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-AgentWall-Console": "1" },
      body: JSON.stringify({ decision, remember }),
    });
  } finally {
    await refreshApprovals();
  }
}

async function refreshApprovals() {
  const data = await api("/api/approvals");
  document.getElementById("approvals-off").hidden = data.enabled;
  const pending = data.requests.filter((r) => r.status === "pending");
  const count = document.getElementById("pending-count");
  count.hidden = pending.length === 0;
  count.textContent = pending.length;
  const cards = data.requests.map((r) => {
    const buttons = [];
    if (r.status === "pending") {
      const mk = (label, cls, decision, remember) => {
        const b = el("button", { class: `action ${cls}`, type: "button" }, label);
        b.addEventListener("click", () => decide(r.id, decision, remember, buttons));
        buttons.push(b);
        return b;
      };
      mk("Approve once", "primary", "approve", false);
      mk("Always approve", "", "approve", true);
      mk("Deny", "danger", "deny", false);
      mk("Always deny", "danger", "deny", true);
    }
    const control = Object.entries(r.control).map(([k, v]) => el("div", { class: "mono" }, `${k} = ${v}`));
    return el(
      "div",
      { class: "card approval" },
      el("div", { class: "head" }, el("strong", { class: "mono" }, r.tool), el("span", { class: "muted small" }, `${r.id} · ${r.status} · ${r.created} · seen ${r.calls_seen}×`)),
      control.length ? control : el("div", { class: "muted" }, "no control arguments"),
      ...r.reasons.map((reason) => el("div", { class: "muted small" }, `Why: ${reason}`)),
      buttons.length ? el("div", { class: "buttons" }, buttons) : null
    );
  });
  document.getElementById("approvals").replaceChildren(
    ...(cards.length ? cards : data.enabled ? [el("div", { class: "empty" }, "No approval requests.")] : [])
  );
}

// -- policy ---------------------------------------------------------------------------------------
async function renderPolicy() {
  const data = await api("/api/policy");
  document.getElementById("policy-name").textContent = data.name ? `Policy: ${data.name}` : "Policy";
  document.getElementById("policy-text").textContent = data.text || "Start the console with --policy or --config to show the active policy.";
}

// -- loop -----------------------------------------------------------------------------------------
async function poll() {
  const live = document.getElementById("live");
  try {
    renderSummary(await api("/api/summary"));
    const fresh = await api(`/api/events?after=${state.lastSeq}&limit=1000`);
    if (fresh.events.length) {
      state.events.push(...fresh.events);
      state.events = state.events.slice(-2000);
      state.lastSeq = fresh.events[fresh.events.length - 1].seq;
      if (state.tab === "activity") renderActivity();
      if (state.tab === "flows") renderFlows();
    }
    await refreshApprovals();
    live.textContent = "live";
    live.className = "pill ok";
  } catch (err) {
    live.textContent = "disconnected";
    live.className = "pill bad";
  }
}

function showTab(name) {
  state.tab = name;
  for (const b of document.querySelectorAll(".tabs button")) b.setAttribute("aria-selected", String(b.dataset.tab === name));
  for (const s of document.querySelectorAll(".tab")) s.hidden = s.id !== `tab-${name}`;
  if (name === "activity") renderActivity();
  if (name === "flows") renderFlows();
  if (name === "policy") renderPolicy();
  if (name === "approvals") refreshApprovals();
}

for (const b of document.querySelectorAll(".tabs button")) b.addEventListener("click", () => showTab(b.dataset.tab));
document.getElementById("filter").addEventListener("change", renderActivity);
poll();
setInterval(poll, 2000);
