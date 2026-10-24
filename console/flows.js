"use strict";

// The Flow log tab: every connection from accept to close, including ones
// refused or failed before they became pipes. Its WebSocket is open only
// while the tab is showing, so the server builds no events otherwise.
//
// The server sends a full snapshot first, then batches of open/close events
// and a fresh snapshot every few seconds. Each connection keeps the view with
// the highest seq, so a late snapshot never undoes a newer event. Memory is
// bounded: at most FLOW_KEEP ended connections, and FLOW_ROWS rows in the DOM.

const FLOW_KEEP = 2000;
const FLOW_ROWS = 500;

const fl = {
  ws: null,
  want: false, // the tab is showing
  retry: 0,
  timer: 0,
  flows: new Map(), // id -> view
  rows: new Map(), // id -> row refs
  shown: [],
  paused: false,
  dirty: true,
  filter: "",
  result: "",
  clearedAt: 0, // ended connections that ended before this are hidden
  armed: new Map(), // id -> disarm timer
  resetting: new Set(),
};

function flowsStart() {
  fl.want = true;
  flowConnect();
  fl.dirty = true;
  flowPaint();
}

function flowsStop() {
  fl.want = false;
  clearTimeout(fl.timer);
  if (fl.ws) { const ws = fl.ws; fl.ws = null; ws.close(); }
}

function flowStatus(state, text) {
  $("flow-status").dataset.state = state;
  setText($("flow-status-text"), text);
}

function flowConnect() {
  if (fl.ws || !fl.want) return;
  clearTimeout(fl.timer);
  flowStatus("connecting", "Connecting");
  const base = location.pathname.replace(/[^/]*$/, "");
  const ws = new WebSocket(`${location.protocol === "https:" ? "wss" : "ws"}://${location.host}${base}api/flows`);
  fl.ws = ws;
  ws.onopen = () => { fl.retry = 0; flowStatus("live", "Live"); };
  ws.onmessage = (ev) => flowApply(JSON.parse(ev.data));
  ws.onclose = (ev) => {
    if (fl.ws !== ws) return;
    fl.ws = null;
    flowStatus("down", "Reconnecting");
    if (!fl.want) return;
    const delay = Math.min(10000, 500 * 2 ** fl.retry);
    fl.retry = Math.min(fl.retry + 1, 5);
    // A refused upgrade (signed out) looks the same as a dropped one; let
    // the session check decide whether to show the sign-in form.
    fl.timer = setTimeout(() => checkSession().then((ok) => { if (ok !== false) flowConnect(); }), delay);
  };
}

function flowKeep(v) {
  const old = fl.flows.get(v.id);
  if (!old || v.seq > old.seq) fl.flows.set(v.id, v);
}

function flowApply(m) {
  if (m.type === "snapshot") {
    ui.skew = Date.now() - m.now;
    if (m.full) fl.flows.clear();
    const active = new Set();
    for (const v of m.active) { active.add(v.id); flowKeep(v); }
    for (const v of m.closed) flowKeep(v);
    // An open connection missing from the list has ended; its close event
    // was dropped. Views newer than the list are left alone.
    for (const [id, v] of fl.flows) {
      if (!v.ended && !active.has(id) && v.seq <= m.seq && !m.truncated) fl.flows.delete(id);
    }
  } else if (m.type === "events") {
    for (const ev of m.events) flowKeep(ev.flow);
  }
  flowTrim();
  fl.dirty = true;
  flowSchedule();
}

let flowFrame = 0;
function flowSchedule() {
  if (!flowFrame) flowFrame = requestAnimationFrame(() => { flowFrame = 0; flowPaint(); });
}

// flowTrim drops the oldest ended connections beyond FLOW_KEEP.
function flowTrim() {
  const ended = [];
  for (const v of fl.flows.values()) if (v.ended) ended.push(v);
  if (ended.length <= FLOW_KEEP) return;
  ended.sort((a, b) => a.ended - b.ended || a.seq - b.seq);
  for (let i = 0; i < ended.length - FLOW_KEEP; i++) fl.flows.delete(ended[i].id);
}

const RESULTS = {
  closed: ["CLOSED", "state done", "Both sides finished"],
  reset: ["RESET", "state reset", ""],
  idle: ["IDLE TIMEOUT", "state half", ""],
  failed: ["FAILED", "state reset", "The target could not be reached"],
  refused: ["REFUSED", "state reset", ""],
};

function flowMatches(v) {
  if (fl.result === "open" && v.ended) return false;
  if (fl.result === "ended" && !v.ended) return false;
  if (fl.result && fl.result !== "open" && fl.result !== "ended" && v.result !== fl.result) return false;
  if (v.ended && v.ended < fl.clearedAt) return false;
  if (!fl.filter) return true;
  const hay = `#${v.id} ${v.listener} ${v.target} ${v.client} ${v.local} ${v.upstreamLocal || ""} ${v.upstreamRemote || ""} ${v.result || "open"} ${v.reason || ""}`.toLowerCase();
  return hay.includes(fl.filter);
}

function buildFlowRow(v) {
  const row = el("div", "f-row f-cols");
  const id = el("span", "p-id", "#" + v.id);
  const listener = el("span", "f-listener");
  const client = el("span", "f-addr");
  const upstream = el("span", "f-addr");
  const started = el("span", "f-time");
  const duration = el("span", "f-time r");
  const [total, up, down] = updown("p-total r");
  const resultCell = el("span", "p-statecell");
  const result = el("span", "state");
  resultCell.appendChild(result);
  const action = el("span", "p-action");
  const stop = el("button", "stop");
  stop.type = "button";
  stop.appendChild(el("span", "sq"));
  const stopLabel = el("span", "", "Reset");
  stop.appendChild(stopLabel);
  stop.title = "Reset both legs of this connection (TCP RST)";
  stop.addEventListener("click", () => flowReset(v.id));
  action.appendChild(stop);
  row.append(id, listener, client, upstream, started, duration, total, resultCell, action);
  return { row, listener, client, upstream, started, duration, up, down, result, stop, stopLabel };
}

function paintFlowRow(r, v, now) {
  setText(r.listener, v.listener);
  r.listener.title = `${v.listener} → ${v.target}`;
  setText(r.client, v.client);
  r.client.title = `client ${v.client}, accepted on ${v.local}`;
  setText(r.upstream, v.upstreamRemote || v.target);
  r.upstream.title = v.upstreamRemote ? `from ${v.upstreamLocal} to ${v.upstreamRemote}` : `target ${v.target}, not connected`;
  r.upstream.classList.toggle("dim", !v.upstreamRemote);
  setText(r.started, fmtClock(v.started));
  setText(r.duration, fmtAge((v.ended || now) - v.started));
  setText(r.up, fmtBytes(v.bytesUp));
  setText(r.down, fmtBytes(v.bytesDown));
  const [label, cls, title] = v.ended ? RESULTS[v.result] || [v.result.toUpperCase(), "state", ""]
    : fl.resetting.has(v.id) ? ["RESETTING", "state reset", ""] : ["OPEN", "state", "Relaying"];
  setText(r.result, label);
  if (r.result.className !== cls) r.result.className = cls;
  r.result.title = v.reason || title;
  r.row.classList.toggle("ended", !!v.ended);
  r.stop.hidden = !!v.ended;
  r.stop.disabled = fl.resetting.has(v.id);
}

function flowPaint() {
  if (!fl.want || fl.paused) return;
  const now = serverNow();
  let open = 0, ended = 0;
  const visible = [];
  for (const v of fl.flows.values()) {
    if (v.ended) ended++; else open++;
    if (flowMatches(v)) visible.push(v);
  }
  if (fl.dirty) {
    // Newest first: open connections by when they started, ended ones by
    // when they ended, interleaved by the later of the two.
    visible.sort((a, b) => (b.ended || b.started) - (a.ended || a.started) || b.id - a.id);
    const want = visible.slice(0, FLOW_ROWS);
    const wantIds = new Set(want.map((v) => v.id));
    for (const [id, r] of fl.rows) {
      if (!wantIds.has(id)) { r.row.remove(); fl.rows.delete(id); }
    }
    const box = $("flow-rows");
    let anchor = null;
    for (const v of want) {
      let r = fl.rows.get(v.id);
      if (!r) { r = buildFlowRow(v); fl.rows.set(v.id, r); }
      const next = anchor ? anchor.nextSibling : box.firstChild;
      if (next !== r.row) box.insertBefore(r.row, next);
      anchor = r.row;
    }
    fl.shown = want.map((v) => v.id);
    fl.dirty = false;
    $("flow-empty").hidden = want.length > 0;
    setText($("flow-empty-text"), fl.flows.size === 0
      ? "No connections yet. They show up here as soon as they are accepted."
      : "No connections match the filter.");
    $("flow-more").hidden = visible.length <= FLOW_ROWS;
    setText($("flow-more"), `Showing the newest ${FLOW_ROWS} of ${visible.length}. Filter to find the rest.`);
  }
  for (const id of fl.shown) {
    const v = fl.flows.get(id);
    if (v) paintFlowRow(fl.rows.get(id), v, now);
  }
  setText($("flow-note"), `${open} open · ${ended} ended` + (fl.filter || fl.result ? ` · ${visible.length} match` : ""));
}

function flowReset(id) {
  const r = fl.rows.get(id);
  if (!r || fl.resetting.has(id)) return;
  if (!fl.armed.has(id)) {
    r.stop.classList.add("armed");
    setText(r.stopLabel, "Confirm");
    fl.armed.set(id, setTimeout(() => flowDisarm(id), ARM_MS));
    return;
  }
  flowDisarm(id);
  fl.resetting.add(id);
  flowPaint();
  fetch(`api/connections/${id}`, { method: "DELETE", headers: CSRF, credentials: "same-origin" })
    .then((res) => {
      if (res.status === 401) { showLogin(); return; }
      if (!res.ok && res.status !== 404) throw new Error(res.statusText);
    })
    .catch((e) => toast(`Could not reset #${id}: ${e.message}`, true))
    .finally(() => { fl.resetting.delete(id); flowPaint(); });
}

function flowDisarm(id) {
  clearTimeout(fl.armed.get(id));
  fl.armed.delete(id);
  const r = fl.rows.get(id);
  if (r) { r.stop.classList.remove("armed"); setText(r.stopLabel, "Reset"); }
}

$("flow-filter").addEventListener("input", (ev) => { fl.filter = ev.target.value.trim().toLowerCase(); fl.dirty = true; flowPaint(); });
$("flow-result").addEventListener("change", (ev) => { fl.result = ev.target.value; fl.dirty = true; flowPaint(); });
$("flow-pause").addEventListener("click", (ev) => {
  fl.paused = !fl.paused;
  ev.currentTarget.setAttribute("aria-pressed", String(fl.paused));
  setText(ev.currentTarget, fl.paused ? "Resume" : "Pause");
  fl.dirty = true;
  flowPaint();
});
$("flow-clear").addEventListener("click", () => { fl.clearedAt = serverNow(); fl.dirty = true; flowPaint(); });

// Re-sort at most once a second; durations of open rows tick with it.
setInterval(() => { fl.dirty = fl.dirty || fl.flows.size > 0; flowPaint(); }, 1000);
