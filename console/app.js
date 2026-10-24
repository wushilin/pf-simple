"use strict";

// The server pushes state over a WebSocket only when something changed, at
// most once per 400ms. Local timers only repaint (ages, decaying rates, the
// charts); they never talk to the server.
//
// Memory stays bounded for a page left open indefinitely: chart history lives
// in fixed-size rings, rate samples are capped by count and age, everything
// kept per pipe is deleted when the pipe leaves the pushed state, and at most
// MAX_ROWS rows are in the DOM per listener.

const $ = (id) => document.getElementById(id);
const CSRF = { "X-PF-Console": "1" };
const RATE_WINDOW_MS = 1500;
const RATE_MAX_SAMPLES = 64;
const HISTORY_POINTS = 120; // two minutes at one sample per second
const MAX_ROWS = 200;
const ARM_MS = 3000;

const ui = {
  state: null,
  skew: 0, // local clock minus server clock
  filter: "",
  firstFrame: true,
  expanded: new Set(), // listener ids
  openPipes: new Set(),
  armed: new Map(), // pipe id -> disarm timer
  resetting: new Set(),
  L: new Map(), // listener id -> refs
  P: new Map(), // pipe id -> refs
  meters: new Map(),
  history: new Map(), // listener id -> Ring
  total: null,
  ws: null,
  reconnectTimer: 0,
  retry: 0,
  passwordRequired: false,
};

// ---------- formatting ----------

function fmtBytes(n) {
  const u = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return (i === 0 ? n.toFixed(0) : n.toFixed(n < 10 ? 2 : n < 100 ? 1 : 0)) + " " + u[i];
}

function fmtRate(bytesPerSec) {
  let v = bytesPerSec * 8;
  const u = ["b/s", "Kb/s", "Mb/s", "Gb/s", "Tb/s"];
  let i = 0;
  while (v >= 1000 && i < u.length - 1) { v /= 1000; i++; }
  if (v < 0.5 && i === 0) return "0 b/s";
  return (i === 0 ? v.toFixed(0) : v.toFixed(v < 10 ? 2 : v < 100 ? 1 : 0)) + " " + u[i];
}

function fmtAge(ms) {
  let s = Math.max(0, Math.floor(ms / 1000));
  const d = Math.floor(s / 86400); s -= d * 86400;
  const h = Math.floor(s / 3600); s -= h * 3600;
  const m = Math.floor(s / 60); s -= m * 60;
  if (d) return `${d}d ${h}h`;
  if (h) return `${h}h ${m}m`;
  if (m) return `${m}m ${s}s`;
  return `${s}s`;
}

function fmtClock(ms) {
  const d = new Date(ms);
  const time = d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  return d.toDateString() === new Date().toDateString() ? time : `${d.toLocaleDateString()} ${time}`;
}

const serverNow = () => Date.now() - ui.skew;

// ---------- bounded data structures ----------

class RateMeter {
  constructor() { this.s = []; }
  add(t, v) {
    const s = this.s;
    if (s.length && v < s[s.length - 1][1]) s.length = 0; // counter restarted
    s.push([t, v]);
    while (s.length > RATE_MAX_SAMPLES || (s.length > 2 && t - s[0][0] > RATE_WINDOW_MS)) s.shift();
  }
  rate(now) {
    const s = this.s;
    while (s.length > 1 && now - s[0][0] > RATE_WINDOW_MS) s.shift();
    if (s.length < 2) return 0;
    const [t0, v0] = s[0];
    const [t1, v1] = s[s.length - 1];
    const dt = Math.max(now, t1) - t0; // keeps growing once pushes stop
    return dt > 0 ? ((v1 - v0) * 1000) / dt : 0;
  }
}

class Ring {
  constructor(n) { this.n = n; this.tx = new Float64Array(n); this.rx = new Float64Array(n); this.len = 0; this.head = 0; }
  push(tx, rx) {
    this.tx[this.head] = tx; this.rx[this.head] = rx;
    this.head = (this.head + 1) % this.n;
    if (this.len < this.n) this.len++;
  }
  at(i) { // 0 = oldest
    const k = (this.head - this.len + i + this.n) % this.n;
    return [this.tx[k], this.rx[k]];
  }
  max() {
    let m = 0;
    for (let i = 0; i < this.len; i++) { const [a, b] = this.at(i); if (a > m) m = a; if (b > m) m = b; }
    return m;
  }
}

function meter(key) {
  let m = ui.meters.get(key);
  if (!m) { m = new RateMeter(); ui.meters.set(key, m); }
  return m;
}

// ---------- DOM helpers ----------

function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined) e.textContent = text;
  return e;
}

function setText(node, text) {
  if (node.textContent !== text) node.textContent = text;
}

const SVG = "http://www.w3.org/2000/svg";
function chevron() {
  const svg = document.createElementNS(SVG, "svg");
  svg.setAttribute("viewBox", "0 0 16 16");
  svg.setAttribute("class", "chev");
  svg.setAttribute("aria-hidden", "true");
  const p = document.createElementNS(SVG, "path");
  p.setAttribute("d", "M6 3.5 10.5 8 6 12.5");
  p.setAttribute("fill", "none");
  p.setAttribute("stroke", "currentColor");
  p.setAttribute("stroke-width", "1.8");
  p.setAttribute("stroke-linecap", "round");
  p.setAttribute("stroke-linejoin", "round");
  svg.appendChild(p);
  return svg;
}

function arrowIcon(dir) {
  const svg = document.createElementNS(SVG, "svg");
  svg.setAttribute("viewBox", "0 0 16 16");
  svg.setAttribute("class", "arrow-icon");
  svg.setAttribute("aria-hidden", "true");
  const p = document.createElementNS(SVG, "path");
  p.setAttribute("d", dir === "up" ? "M8 13V3M3.5 7.5 8 3l4.5 4.5" : "M8 3v10M3.5 8.5 8 13l4.5-4.5");
  p.setAttribute("fill", "none");
  p.setAttribute("stroke", "currentColor");
  p.setAttribute("stroke-width", "1.9");
  p.setAttribute("stroke-linecap", "round");
  p.setAttribute("stroke-linejoin", "round");
  svg.appendChild(p);
  return svg;
}

// metric builds a label/value pair; dir adds an up or down arrow icon.
function metric(label, cls, dir) {
  const box = el("div", "metric " + cls);
  const k = el("span", "k");
  if (dir) k.appendChild(arrowIcon(dir));
  k.appendChild(document.createTextNode(label));
  box.appendChild(k);
  const v = el("span", "v " + cls, "—");
  box.appendChild(v);
  return [box, v];
}

// updown builds the stacked "↑ bytes / ↓ bytes" cell.
function updown(cls) {
  const box = el("span", cls);
  const up = el("span", "up");
  const down = el("span", "down");
  const upV = el("span");
  const downV = el("span");
  up.append(arrowIcon("up"), upV);
  down.append(arrowIcon("down"), downV);
  box.append(up, down);
  return [box, upV, downV];
}

function actionButton(label, cls, icon) {
  const b = el("button", "act " + cls);
  b.type = "button";
  if (icon) b.appendChild(el("span", "ico"));
  const t = el("span", "", label);
  b.appendChild(t);
  return [b, t];
}

// ---------- charts ----------

function tokens() {
  const cs = getComputedStyle(document.documentElement);
  const get = (n) => cs.getPropertyValue(n).trim();
  return { tx: get("--tx"), rx: get("--rx"), line: get("--line"), fg3: get("--fg-3"), font: get("--font-ui") };
}

function fitCanvas(c) {
  const dpr = window.devicePixelRatio || 1;
  const w = Math.max(1, Math.round(c.clientWidth * dpr));
  const h = Math.max(1, Math.round(c.clientHeight * dpr));
  if (c.width !== w || c.height !== h) { c.width = w; c.height = h; }
  const ctx = c.getContext("2d");
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  return [ctx, c.clientWidth, c.clientHeight];
}

function niceCeil(v) {
  if (v <= 0) return 1;
  const p = Math.pow(10, Math.floor(Math.log10(v)));
  for (const m of [1, 2, 2.5, 5, 10]) if (m * p >= v) return m * p;
  return 10 * p;
}

function plot(ctx, ring, key, color, x0, y0, w, h, max, fill) {
  if (ring.len < 2) return;
  const step = w / (ring.n - 1);
  const start = ring.n - ring.len; // right-align: newest point at the right edge
  ctx.beginPath();
  for (let i = 0; i < ring.len; i++) {
    const v = ring.at(i)[key === "tx" ? 0 : 1];
    const x = x0 + (start + i) * step;
    const y = y0 + h - (v / max) * h;
    if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
  }
  ctx.strokeStyle = color;
  ctx.lineWidth = 1.6;
  ctx.lineJoin = "round";
  ctx.stroke();
  if (fill) {
    ctx.lineTo(x0 + w, y0 + h);
    ctx.lineTo(x0 + start * step, y0 + h);
    ctx.closePath();
    ctx.globalAlpha = 0.12;
    ctx.fillStyle = color;
    ctx.fill();
    ctx.globalAlpha = 1;
  }
  const [lt, lr] = ring.at(ring.len - 1);
  const last = key === "tx" ? lt : lr;
  ctx.beginPath();
  ctx.arc(x0 + w, y0 + h - (last / max) * h, 2.6, 0, Math.PI * 2);
  ctx.fillStyle = color;
  ctx.fill();
}

function drawTrace() {
  const c = $("trace");
  if (!c || !ui.total || c.clientWidth === 0) return;
  const [ctx, W, H] = fitCanvas(c);
  const t = tokens();
  ctx.clearRect(0, 0, W, H);
  const max = niceCeil(ui.total.max() * 1.1);
  const left = 64, right = 8, top = 6, bottom = 18;
  const w = W - left - right, h = H - top - bottom;
  ctx.font = `11px ${t.font}`;
  ctx.textBaseline = "middle";
  ctx.textAlign = "right";
  for (let i = 0; i <= 2; i++) {
    const y = top + (h * i) / 2;
    ctx.strokeStyle = t.line;
    ctx.lineWidth = 1;
    ctx.beginPath(); ctx.moveTo(left, Math.round(y) + 0.5); ctx.lineTo(left + w, Math.round(y) + 0.5); ctx.stroke();
    ctx.fillStyle = t.fg3;
    ctx.fillText(fmtRate((max * (2 - i)) / 2), left - 8, y);
  }
  ctx.textAlign = "left";
  ctx.textBaseline = "alphabetic";
  ctx.fillText("2 min ago", left, H - 3);
  ctx.textAlign = "right";
  ctx.fillText("now", left + w, H - 3);
  plot(ctx, ui.total, "rx", t.rx, left, top, w, h, max, true);
  plot(ctx, ui.total, "tx", t.tx, left, top, w, h, max, true);
}

function drawSpark(c, ring) {
  if (!c || c.clientWidth === 0) return;
  const [ctx, W, H] = fitCanvas(c);
  const t = tokens();
  ctx.clearRect(0, 0, W, H);
  ctx.strokeStyle = t.line;
  ctx.lineWidth = 1;
  ctx.beginPath(); ctx.moveTo(0, H - 0.5); ctx.lineTo(W, H - 0.5); ctx.stroke();
  const max = Math.max(ring.max() * 1.15, 1);
  plot(ctx, ring, "rx", t.rx, 2, 3, W - 5, H - 5, max, false);
  plot(ctx, ring, "tx", t.tx, 2, 3, W - 5, H - 5, max, false);
}

// ---------- listener cards ----------

function buildListener(l) {
  const card = el("article", "listener");
  const head = el("div", "l-head");
  head.tabIndex = 0;
  head.setAttribute("role", "button");
  head.setAttribute("aria-expanded", "false");
  head.appendChild(chevron());

  const route = el("div", "route");
  const lname = el("span", "lname");
  const listen = el("span", "listen");
  const target = el("span", "target");
  const chips = el("span", "chips");
  const status = el("span", "chip warn");
  const active = el("span", "chip");
  const accepted = el("span", "chip");
  const failed = el("span", "chip bad");
  const refused = el("span", "chip bad");
  const limTotal = el("span", "chip limit");
  const limConn = el("span", "chip limit");
  chips.append(status, active, accepted, failed, refused, limTotal, limConn);
  const line = el("div", "route-line");
  line.append(lname, listen, el("span", "arrow", "→"), target);
  route.append(line, chips);
  head.appendChild(route);

  const spark = el("canvas", "spark");
  spark.setAttribute("aria-hidden", "true");
  head.appendChild(spark);
  const [txBox, tx] = metric("Rate", "tx", "up");
  const [rxBox, rx] = metric("Rate", "rx", "down");
  const [upBox, totalUp] = metric("Sent", "tx", "up");
  const [downBox, totalDown] = metric("Sent", "rx", "down");
  head.append(txBox, rxBox, upBox, downBox);

  const actions = el("div", "l-actions");
  const [toggleBtn, toggleLabel] = actionButton("Stop", "", true);
  const [editBtn] = actionButton("Edit", "");
  const [delBtn, delLabel] = actionButton("Delete", "danger");
  actions.append(toggleBtn, editBtn, delBtn);
  head.appendChild(actions);

  const body = el("div", "l-body");
  body.hidden = true;
  const thead = el("div", "t-head cols");
  ["", "ID", "Client", "Age", "State", "To upstream", "To clients", "Transferred", ""].forEach((label, i) => {
    thead.appendChild(el("span", i >= 5 && i <= 7 ? "r" : "", label));
  });
  const empty = el("div", "empty");
  const sleepy = el("img");
  sleepy.src = "logo-sleep.svg";
  sleepy.alt = "";
  const emptyText = el("span");
  empty.append(sleepy, emptyText);
  const more = el("div", "more");
  body.append(thead, empty, more);

  const toggle = () => {
    if (ui.expanded.has(l.id)) ui.expanded.delete(l.id); else ui.expanded.add(l.id);
    renderRows(ui.L.get(l.id));
    paint();
  };
  head.addEventListener("click", (ev) => { if (!actions.contains(ev.target)) toggle(); });
  head.addEventListener("keydown", (ev) => {
    if (ev.target !== head) return;
    if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); toggle(); }
  });
  toggleBtn.addEventListener("click", () => onStartStop(l.id));
  editBtn.addEventListener("click", () => openEditor(ui.L.get(l.id).data));
  delBtn.addEventListener("click", () => onDeleteListener(l.id));

  card.append(head, body);
  return {
    id: l.id, data: l, card, head, lname, listen, target, status, active, accepted, failed, refused, limTotal, limConn,
    spark, tx, rx, totalUp, totalDown, toggleBtn, toggleLabel, editBtn, delBtn, delLabel,
    body, thead, empty, sleepy, emptyText, more, shown: [],
  };
}

// ---------- pipe rows ----------

function endpoint(role, cls, sides) {
  const n = el("div", "node " + cls);
  n.appendChild(el("div", "role", role));
  const values = sides.map((side) => {
    const ep = el("div", "ep");
    if (side) ep.appendChild(el("span", "side", side));
    const v = el("span");
    ep.appendChild(v);
    n.appendChild(ep);
    return v;
  });
  return [n, values];
}

function lane(cls, label) {
  const d = el("div", "lane " + cls);
  const bytes = el("span", "bytes", "0 B");
  const wire = el("span", "wire");
  const fin = el("span", "fin-tag");
  if (cls === "tx") d.append(wire, bytes, fin); else d.append(fin, bytes, wire);
  d.title = label;
  return { d, bytes, fin };
}

function fact(dl, label) {
  const row = el("div");
  row.appendChild(el("dt", "", label));
  const dd = el("dd");
  row.appendChild(dd);
  dl.appendChild(row);
  return dd;
}

function buildPipe(p) {
  const wrap = el("div", "pipe");
  const row = el("div", "p-row cols");
  row.tabIndex = 0;
  row.setAttribute("role", "button");
  row.setAttribute("aria-expanded", "false");
  row.appendChild(chevron());
  const id = el("span", "p-id", "#" + p.id);
  const client = el("span", "p-client");
  const age = el("span", "p-age");
  const stateCell = el("span", "p-statecell");
  const state = el("span", "state");
  stateCell.appendChild(state);
  const tx = el("span", "p-rate tx r");
  const rx = el("span", "p-rate rx r");
  const [total, totalUp, totalDown] = updown("p-total r");
  const action = el("span", "p-action");
  const stop = el("button", "stop");
  stop.type = "button";
  stop.appendChild(el("span", "sq"));
  const stopLabel = el("span", "", "Stop");
  stop.appendChild(stopLabel);
  stop.title = "Reset both legs of this pipe (TCP RST)";
  action.appendChild(stop);
  row.append(id, client, age, stateCell, tx, rx, total, action);

  const detail = el("div", "detail");
  detail.hidden = true;
  const legs = el("div", "legs");
  const [cNode, [cRemote]] = endpoint("Client", "client", [""]);
  const [pfNode, [pfIn, pfOut]] = endpoint("pf-simple", "pf", ["in", "out"]);
  const [uNode, [uRemote]] = endpoint("Upstream", "upstream", [""]);
  const legA = el("div", "link");
  const c2p = lane("tx", "Client to pf-simple");
  const p2c = lane("rx", "pf-simple to client");
  legA.append(c2p.d, p2c.d);
  const legB = el("div", "link");
  const p2u = lane("tx", "pf-simple to upstream");
  const u2p = lane("rx", "Upstream to pf-simple");
  legB.append(p2u.d, u2p.d);
  legs.append(cNode, legA, pfNode, legB, uNode);
  const facts = el("dl", "facts");
  const opened = fact(facts, "Opened");
  const duration = fact(facts, "Duration");
  const inflight = fact(facts, "In flight");
  const delivered = fact(facts, "Delivered");
  detail.append(legs, facts);
  wrap.append(row, detail);

  const toggle = () => {
    if (ui.resetting.has(p.id)) return;
    if (ui.openPipes.has(p.id)) ui.openPipes.delete(p.id); else ui.openPipes.add(p.id);
    syncPipeOpen(ui.P.get(p.id));
    paint();
  };
  row.addEventListener("click", toggle);
  row.addEventListener("keydown", (ev) => {
    if (ev.target !== row) return;
    if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); toggle(); }
  });
  stop.addEventListener("click", (ev) => { ev.stopPropagation(); onStop(p.id); });

  return {
    id: p.id, data: p, wrap, row, client, age, state, tx, rx, totalUp, totalDown, stop, stopLabel, detail,
    cRemote, pfIn, pfOut, uRemote, c2p, p2c, p2u, u2p, opened, duration, inflight, delivered,
  };
}

function syncPipeOpen(pr) {
  const open = ui.openPipes.has(pr.id);
  pr.row.setAttribute("aria-expanded", String(open));
  pr.wrap.classList.toggle("open", open);
  pr.detail.hidden = !open;
}

function pipeState(p) {
  if (p.interrupted || ui.resetting.has(p.id)) return ["RESET", "state reset", "Reset sent to both peers"];
  if (p.upDone && p.downDone) return ["CLOSING", "state half", "Both directions finished"];
  if (p.upDone) return ["CLIENT FIN", "state half", "Client half-closed; upstream may still send"];
  if (p.downDone) return ["UPSTREAM FIN", "state half", "Upstream half-closed; client may still send"];
  return ["ESTABLISHED", "state", "Both directions open"];
}

function matches(p, l) {
  const f = ui.filter;
  if (!f) return true;
  const hay = `#${p.id} ${p.clientRemote} ${p.clientLocal} ${p.upstreamLocal} ${p.upstreamRemote} ${l.name} ${l.listen} ${l.target}`.toLowerCase();
  return hay.includes(f);
}

// ---------- stop ----------

function onStop(id) {
  const pr = ui.P.get(id);
  if (!pr || ui.resetting.has(id)) return;
  if (!ui.armed.has(id)) {
    pr.stop.classList.add("armed");
    setText(pr.stopLabel, "Confirm");
    ui.armed.set(id, setTimeout(() => disarm(id), ARM_MS));
    return;
  }
  disarm(id);
  ui.resetting.add(id);
  pr.wrap.classList.add("resetting");
  pr.stop.disabled = true;
  setText(pr.stopLabel, "Resetting");
  paint();
  fetch(`api/pipes/${id}/stop`, { method: "POST", headers: CSRF, credentials: "same-origin" })
    .then((r) => {
      if (r.status === 401) { showLogin(); return; }
      if (!r.ok && r.status !== 404) throw new Error(r.statusText);
    })
    .catch(() => {
      ui.resetting.delete(id);
      const again = ui.P.get(id);
      if (!again) return;
      again.wrap.classList.remove("resetting");
      again.stop.disabled = false;
      setText(again.stopLabel, "Stop");
      paint();
    });
}

function disarm(id) {
  clearTimeout(ui.armed.get(id));
  ui.armed.delete(id);
  const pr = ui.P.get(id);
  if (pr && !ui.resetting.has(id)) {
    pr.stop.classList.remove("armed");
    setText(pr.stopLabel, "Stop");
  }
}

document.addEventListener("keydown", (ev) => {
  if (ev.key === "Escape") {
    for (const id of [...ui.armed.keys()]) disarm(id);
    for (const id of [...armedDeletes.keys()]) disarmDelete(id);
  }
});

// ---------- applying pushed state ----------

function forgetPipe(id) {
  const pr = ui.P.get(id);
  if (pr) pr.wrap.remove();
  ui.P.delete(id);
  ui.openPipes.delete(id);
  ui.resetting.delete(id);
  clearTimeout(ui.armed.get(id));
  ui.armed.delete(id);
  ui.meters.delete("pt" + id);
  ui.meters.delete("pr" + id);
}

// showVersion labels the brand with the server's build version; the sign-in
// page shows it too, since api/session needs no session.
function showVersion(v) {
  if (!v) return;
  $("version").hidden = false;
  setText($("version"), "v" + v);
  $("version").title = `pf-simple ${v}`;
}

function applyState(s) {
  ui.skew = Date.now() - s.now;
  showVersion(s.version);
  ui.state = s;
  if (s.host) { $("host").hidden = false; setText($("host"), s.host); document.title = `${s.host} · pf-simple`; }
  if (!ui.total) ui.total = new Ring(HISTORY_POINTS);

  const container = $("listeners");
  const seenL = new Set();
  const seenP = new Set();
  s.listeners.forEach((l, index) => {
    seenL.add(l.id);
    let lr = ui.L.get(l.id);
    if (!lr) {
      lr = buildListener(l);
      ui.L.set(l.id, lr);
      ui.history.set(l.id, new Ring(HISTORY_POINTS));
      if (s.listeners.length <= 3) ui.expanded.add(l.id);
    }
    if (container.children[index] !== lr.card) container.insertBefore(lr.card, container.children[index] || null);
    lr.data = l;
    meter("lt" + l.id).add(s.now, l.bytesUp);
    meter("lr" + l.id).add(s.now, l.bytesDown);
    for (const p of l.pipes) {
      seenP.add(p.id);
      let pr = ui.P.get(p.id);
      if (!pr) {
        pr = buildPipe(p);
        ui.P.set(p.id, pr);
        if (!ui.firstFrame) {
          pr.wrap.classList.add("fresh");
          setTimeout(() => pr.wrap.classList.remove("fresh"), 1700);
        }
      }
      pr.data = p;
      meter("pt" + p.id).add(s.now, p.pfToUpstream);
      meter("pr" + p.id).add(s.now, p.pfToClient);
    }
  });

  for (const id of [...ui.P.keys()]) if (!seenP.has(id)) forgetPipe(id);
  for (const [id, lr] of [...ui.L]) {
    if (seenL.has(id)) continue;
    lr.card.remove();
    ui.L.delete(id);
    clearTimeout(armedDeletes.get(id));
    armedDeletes.delete(id);
    pendingListeners.delete(id);
    ui.history.delete(id);
    ui.expanded.delete(id);
    ui.meters.delete("lt" + id);
    ui.meters.delete("lr" + id);
  }

  for (const lr of ui.L.values()) renderRows(lr);
  if (ui.firstFrame) { ui.firstFrame = false; sample(); }
  paint();
}

// renderRows puts the visible, filtered rows of one listener into the DOM,
// newest first, capped at MAX_ROWS.
function renderRows(lr) {
  const l = lr.data;
  const visible = l.pipes.filter((p) => matches(p, l));
  const open = ui.expanded.has(l.id) || (ui.filter !== "" && visible.length > 0);
  lr.head.setAttribute("aria-expanded", String(open));
  lr.body.hidden = !open;

  const want = open ? visible.slice(-MAX_ROWS).reverse() : [];
  const wantIds = new Set(want.map((p) => p.id));
  for (const id of lr.shown) {
    if (!wantIds.has(id)) { const pr = ui.P.get(id); if (pr) pr.wrap.remove(); }
  }
  let anchor = lr.thead;
  for (const p of want) {
    const pr = ui.P.get(p.id);
    if (anchor.nextSibling !== pr.wrap) lr.body.insertBefore(pr.wrap, anchor.nextSibling);
    syncPipeOpen(pr);
    anchor = pr.wrap;
  }
  lr.shown = want.map((p) => p.id);

  lr.thead.hidden = want.length === 0;
  lr.empty.hidden = want.length > 0;
  if (want.length === 0) {
    const none = l.pipeCount === 0;
    lr.sleepy.hidden = !none;
    const label = l.name ? `${l.name} [${l.listen}]` : l.listen;
    const idle = l.running ? `No active pipes. Connections to ${label} show up here.` : `${label} is stopped. Start it to accept connections.`;
    setText(lr.emptyText, none ? idle : `No pipes match “${ui.filter}”.`);
  }
  const hidden = visible.length - want.length;
  const capped = l.pipeCount - l.pipes.length;
  const notes = [];
  if (open && hidden > 0) notes.push(`Showing the newest ${want.length} of ${visible.length} pipes. Filter to find the rest.`);
  if (open && capped > 0) notes.push(`${capped} older pipes are not sent to the console.`);
  lr.more.hidden = notes.length === 0;
  setText(lr.more, notes.join(" "));
}

// ---------- paint (local clock only) ----------

function paint() {
  const s = ui.state;
  if (!s) return;
  const now = serverNow();
  let active = 0, accepted = 0, txAll = 0, rxAll = 0, totalUp = 0, totalDown = 0, matched = 0, all = 0, running = 0;

  for (const lr of ui.L.values()) {
    const l = lr.data;
    const tx = meter("lt" + l.id).rate(now);
    const rx = meter("lr" + l.id).rate(now);
    active += l.pipeCount; accepted += l.accepted; txAll += tx; rxAll += rx;
    totalUp += l.bytesUp; totalDown += l.bytesDown;
    if (l.running) running++;
    all += l.pipes.length;
    if (ui.filter) matched += l.pipes.filter((p) => matches(p, l)).length;
    lr.lname.hidden = !l.name;
    setText(lr.lname, l.name || "");
    setText(lr.listen, l.name ? `[${l.listen}]` : l.listen);
    lr.listen.classList.toggle("bracketed", !!l.name);
    setText(lr.target, l.target);
    lr.card.classList.toggle("stopped", !l.running);
    lr.status.hidden = l.running;
    setText(lr.status, l.error ? "failed to start" : "stopped");
    lr.status.className = l.error ? "chip bad" : "chip warn";
    lr.status.title = l.error || "Not accepting connections";
    lr.active.hidden = !l.running && l.pipeCount === 0;
    setText(lr.active, l.maxConns > 0 ? `${l.pipeCount} / ${l.maxConns} active` : `${l.pipeCount} active`);
    const full = l.maxConns > 0 && l.pipeCount >= l.maxConns;
    lr.active.className = full ? "chip bad" : l.pipeCount > 0 ? "chip live" : "chip";
    lr.active.title = l.maxConns > 0 ? `max_connections is ${l.maxConns}` : "";
    setText(lr.refused, `${l.rejected} refused`);
    lr.refused.hidden = !l.rejected;
    lr.refused.title = "Connections reset because max_connections was reached";
    setText(lr.limTotal, `max ${fmtBytes(l.totalSpeed)}/s total`);
    lr.limTotal.hidden = !l.totalSpeed;
    lr.limTotal.title = "total_speed: shared by all pipes on this listener, in each direction";
    setText(lr.limConn, `max ${fmtBytes(l.perConnSpeed)}/s per pipe`);
    lr.limConn.hidden = !l.perConnSpeed;
    lr.limConn.title = "per_connection_max_speed: the cap for each pipe, in each direction";
    setText(lr.accepted, `${l.accepted} accepted`);
    setText(lr.failed, `${l.failed} failed`);
    lr.failed.hidden = l.failed === 0;
    lr.failed.title = "Upstream connection attempts that failed";
    setText(lr.tx, fmtRate(tx));
    setText(lr.rx, fmtRate(rx));
    setText(lr.totalUp, fmtBytes(l.bytesUp));
    setText(lr.totalDown, fmtBytes(l.bytesDown));
    paintListenerActions(lr, l, s.manage);

    for (const id of lr.shown) {
      const pr = ui.P.get(id);
      if (pr) paintPipe(pr, now);
    }
  }

  setText($("k-active"), String(active));
  setText($("k-accepted"), String(accepted));
  setText($("k-tx"), fmtRate(txAll));
  setText($("k-rx"), fmtRate(rxAll));
  setText($("k-total-up"), fmtBytes(totalUp));
  setText($("k-total-down"), fmtBytes(totalDown));
  setText($("k-listeners"), ui.L.size === running ? String(running) : `${running} / ${ui.L.size} running`);
  $("add-listener").hidden = !(s.manage && s.manage.enabled);
  setText($("k-uptime"), fmtAge(now - s.started));
  setText($("filter-note"), ui.filter ? `${matched} of ${all} pipes match` : "");
}

function paintPipe(pr, now) {
  const p = pr.data;
  setText(pr.client, p.clientRemote);
  pr.client.title = p.clientRemote;
  setText(pr.age, fmtAge(now - p.started));
  const [label, cls, title] = pipeState(p);
  setText(pr.state, label);
  if (pr.state.className !== cls) pr.state.className = cls;
  pr.state.title = title;
  setText(pr.tx, fmtRate(meter("pt" + p.id).rate(now)));
  setText(pr.rx, fmtRate(meter("pr" + p.id).rate(now)));
  setText(pr.totalUp, fmtBytes(p.pfToUpstream));
  setText(pr.totalDown, fmtBytes(p.pfToClient));
  if (pr.detail.hidden) return;
  setText(pr.cRemote, p.clientRemote);
  setText(pr.pfIn, p.clientLocal);
  setText(pr.pfOut, p.upstreamLocal);
  setText(pr.uRemote, p.upstreamRemote);
  setLane(pr.c2p, p.clientToPf, p.upDone);
  setLane(pr.p2u, p.pfToUpstream, p.upDone);
  setLane(pr.u2p, p.upstreamToPf, p.downDone);
  setLane(pr.p2c, p.pfToClient, p.downDone);
  setText(pr.opened, fmtClock(p.started));
  setText(pr.duration, fmtAge(now - p.started));
  const queued = (p.clientToPf - p.pfToUpstream) + (p.upstreamToPf - p.pfToClient);
  setText(pr.inflight, queued > 0 ? fmtBytes(queued) : "nothing buffered");
  setText(pr.delivered, `${fmtBytes(p.pfToUpstream)} up, ${fmtBytes(p.pfToClient)} down`);
}

function setLane(ln, bytes, fin) {
  setText(ln.bytes, fmtBytes(bytes));
  setText(ln.fin, fin ? "FIN" : "");
  ln.d.classList.toggle("fin", fin);
}

// sample appends one point per second to every chart ring and redraws.
function sample() {
  if (!ui.state || !ui.total) return;
  const now = serverNow();
  let txAll = 0, rxAll = 0;
  for (const lr of ui.L.values()) {
    const tx = meter("lt" + lr.id).rate(now);
    const rx = meter("lr" + lr.id).rate(now);
    txAll += tx; rxAll += rx;
    const ring = ui.history.get(lr.id);
    ring.push(tx, rx);
    drawSpark(lr.spark, ring);
  }
  ui.total.push(txAll, rxAll);
  drawTrace();
}

function redrawCharts() {
  for (const lr of ui.L.values()) drawSpark(lr.spark, ui.history.get(lr.id));
  drawTrace();
}

// ---------- listener actions ----------

const pendingListeners = new Set(); // ids with a start/stop/delete in flight
const armedDeletes = new Map(); // listener id -> disarm timer

function paintListenerActions(lr, l, manage) {
  const editable = !!(manage && manage.enabled && l.source === "config");
  const busy = pendingListeners.has(l.id);
  lr.toggleBtn.disabled = busy;
  if (!busy) setText(lr.toggleLabel, l.running ? "Stop" : "Start");
  lr.toggleBtn.className = l.running ? "act" : "act start";
  lr.toggleBtn.title = l.running ? "Stop accepting and reset this listener's pipes" : "Start accepting connections";
  lr.editBtn.hidden = !editable;
  lr.delBtn.hidden = !editable;
  lr.editBtn.disabled = busy || l.running;
  lr.delBtn.disabled = busy || l.running;
  lr.editBtn.title = l.running ? "Stop the listener before editing it" : "Edit this listener";
  lr.delBtn.title = l.running ? "Stop the listener before deleting it" : "Delete this listener from the config file";
  if (l.running && armedDeletes.has(l.id)) disarmDelete(l.id);
}

function api(path, body) {
  return fetch(path, {
    method: "POST",
    headers: body ? { ...CSRF, "Content-Type": "application/json" } : CSRF,
    credentials: "same-origin",
    body: body ? JSON.stringify(body) : undefined,
  }).then(async (r) => {
    if (r.status === 401) { showLogin(); throw new Error("Your session ended. Sign in again."); }
    if (!r.ok) {
      let msg = r.statusText;
      try { msg = (await r.json()).error || msg; } catch (_) { /* not JSON */ }
      throw new Error(msg);
    }
    return r;
  });
}

function listenerLabel(l) {
  return l.name ? `${l.name} [${l.listen}]` : l.listen;
}

function onStartStop(id) {
  const lr = ui.L.get(id);
  if (!lr || pendingListeners.has(id)) return;
  const l = lr.data;
  const action = l.running ? "stop" : "start";
  pendingListeners.add(id);
  setText(lr.toggleLabel, l.running ? "Stopping" : "Starting");
  paint();
  api(`api/listeners/${id}/${action}`)
    .then(() => toast(`${action === "stop" ? "Stopped" : "Started"} ${listenerLabel(l)}`))
    .catch((e) => toast(`Could not ${action} ${listenerLabel(l)}: ${e.message}`, true))
    .finally(() => { pendingListeners.delete(id); paint(); });
}

function onDeleteListener(id) {
  const lr = ui.L.get(id);
  if (!lr || pendingListeners.has(id)) return;
  if (!armedDeletes.has(id)) {
    lr.delBtn.classList.add("armed");
    setText(lr.delLabel, "Confirm delete");
    armedDeletes.set(id, setTimeout(() => disarmDelete(id), ARM_MS));
    return;
  }
  disarmDelete(id);
  const label = listenerLabel(lr.data);
  pendingListeners.add(id);
  paint();
  api(`api/listeners/${id}/delete`)
    .then(() => toast(`Deleted ${label}`))
    .catch((e) => toast(`Could not delete ${label}: ${e.message}`, true))
    .finally(() => { pendingListeners.delete(id); paint(); });
}

function disarmDelete(id) {
  clearTimeout(armedDeletes.get(id));
  armedDeletes.delete(id);
  const lr = ui.L.get(id);
  if (lr) { lr.delBtn.classList.remove("armed"); setText(lr.delLabel, "Delete"); }
}

// ---------- add / edit dialog ----------

let editing = null; // listener being edited, or null when adding

const fields = {
  name: "f-name", listen: "f-listen", target: "f-target",
  maxConnections: "f-max", totalSpeed: "f-total", perConnSpeed: "f-perconn",
};

function openEditor(l) {
  const s = ui.state;
  if (!s || !s.manage || !s.manage.enabled) return;
  editing = l || null;
  const spec = (l && l.spec) || {};
  setText($("editor-title"), l ? `Edit ${listenerLabel(l)}` : "Add listener");
  setText($("editor-save"), l ? "Save" : "Add and start");
  const fences = [["listen hosts", s.manage.allowBindHosts], ["listen ports", s.manage.allowBindPorts],
    ["target hosts", s.manage.allowTargetHosts], ["target ports", s.manage.allowTargetPorts]]
    .filter(([, v]) => v).map(([k, v]) => `${k}: ${v}`);
  setText($("editor-hint"), (fences.length ? `Allowed ${fences.join("; ")}.` : "No restrictions on hosts or ports.") +
    (l ? " The listener stays stopped until you start it." : " Saved to the config file and started right away."));
  $("f-name").value = spec.name || "";
  $("f-listen").value = spec.listen || "";
  $("f-target").value = spec.target || "";
  $("f-max").value = spec.maxConnections ? String(spec.maxConnections) : "";
  $("f-total").value = spec.totalSpeed || "";
  $("f-perconn").value = spec.perConnSpeed || "";
  setText($("editor-error"), "");
  $("editor").showModal();
  (l ? $("f-name") : $("f-listen")).focus();
}

$("add-listener").addEventListener("click", () => openEditor(null));
$("editor-cancel").addEventListener("click", () => $("editor").close());
$("editor-form").addEventListener("submit", (ev) => {
  ev.preventDefault();
  const max = $("f-max").value.trim();
  if (max !== "" && !/^\d+$/.test(max)) { setText($("editor-error"), "Max connections must be a whole number, or empty for unlimited."); return; }
  const spec = {
    name: $("f-name").value.trim(),
    listen: $("f-listen").value.trim(),
    target: $("f-target").value.trim(),
    maxConnections: max === "" ? 0 : Number(max),
    totalSpeed: $("f-total").value.trim(),
    perConnSpeed: $("f-perconn").value.trim(),
  };
  if (!spec.listen || !spec.target) { setText($("editor-error"), "Listen and target are required."); return; }
  const btn = $("editor-save");
  btn.disabled = true;
  setText($("editor-error"), "");
  const was = editing;
  const req = was ? api(`api/listeners/${was.id}/edit`, spec) : api("api/listeners", spec);
  req
    .then(() => {
      $("editor").close();
      toast(was ? `Saved ${spec.name || spec.listen}` : `Added and started ${spec.name || spec.listen}`);
    })
    .catch((e) => setText($("editor-error"), e.message))
    .finally(() => { btn.disabled = false; });
});

// ---------- toasts ----------

function toast(msg, bad) {
  const box = $("toasts");
  const t = el("div", bad ? "toast bad" : "toast", msg);
  t.setAttribute("role", bad ? "alert" : "status");
  box.appendChild(t);
  while (box.children.length > 3) box.firstChild.remove();
  setTimeout(() => t.remove(), bad ? 7000 : 3500);
}

// ---------- toolbar ----------

$("filter").addEventListener("input", (ev) => {
  ui.filter = ev.target.value.trim().toLowerCase();
  for (const lr of ui.L.values()) renderRows(lr);
  paint();
});
$("expand-all").addEventListener("click", () => {
  for (const id of ui.L.keys()) ui.expanded.add(id);
  for (const lr of ui.L.values()) renderRows(lr);
  paint();
});
$("collapse-all").addEventListener("click", () => {
  ui.expanded.clear();
  ui.openPipes.clear();
  for (const lr of ui.L.values()) renderRows(lr);
  paint();
});

// ---------- connection & sign-in ----------

function setStatus(state, text) {
  $("status").dataset.state = state;
  setText($("status-text"), text);
}

function scheduleReconnect() {
  clearTimeout(ui.reconnectTimer);
  const delay = Math.min(10000, 500 * 2 ** ui.retry);
  ui.retry = Math.min(ui.retry + 1, 5);
  ui.reconnectTimer = setTimeout(() => {
    checkSession().then((ok) => {
      if (ok) connect();
      else if (ok === null) scheduleReconnect();
    });
  }, delay);
}

function connect() {
  if (ui.ws) return;
  clearTimeout(ui.reconnectTimer);
  setStatus("connecting", "Connecting");
  const base = location.pathname.replace(/[^/]*$/, "");
  const ws = new WebSocket(`${location.protocol === "https:" ? "wss" : "ws"}://${location.host}${base}api/ws`);
  ui.ws = ws;
  ws.onopen = () => { ui.retry = 0; setStatus("live", "Live"); };
  ws.onmessage = (ev) => applyState(JSON.parse(ev.data));
  ws.onclose = () => {
    if (ui.ws !== ws) return;
    ui.ws = null;
    setStatus("down", "Reconnecting");
    scheduleReconnect();
  };
}

// checkSession resolves true when the console should connect, false when
// the sign-in form is showing, and null when the server is unreachable.
function checkSession() {
  return fetch("api/session", { credentials: "same-origin" })
    .then((r) => r.json())
    .then((s) => {
      ui.passwordRequired = s.passwordRequired;
      showVersion(s.version);
      if (!s.authorized) { showLogin(); return false; }
      showApp();
      return true;
    })
    .catch(() => null);
}

function showLogin() {
  if (ui.ws) { const ws = ui.ws; ui.ws = null; ws.close(); }
  flowsStop();
  clearTimeout(ui.reconnectTimer);
  $("app").hidden = true;
  $("logout").hidden = true;
  $("login").hidden = false;
  setStatus("down", "Signed out");
  $("password").focus();
}

function showApp() {
  $("login").hidden = true;
  $("app").hidden = false;
  $("logout").hidden = !ui.passwordRequired;
  showTab(currentTab());
}

// ---------- tabs ----------

const TABS = ["listeners", "flows", "api"];

function currentTab() {
  const t = location.hash.slice(1);
  return TABS.includes(t) ? t : "listeners";
}

function showTab(name) {
  for (const t of TABS) {
    $("tab-" + t).hidden = t !== name;
    $("tab-btn-" + t).setAttribute("aria-selected", String(t === name));
  }
  if (name === "flows") flowsStart(); else flowsStop();
  if (name === "api" && !$("api-frame").getAttribute("src")) $("api-frame").src = "swagger/";
  if (name === "listeners") redrawCharts(); // canvases have no size while hidden
}

for (const b of document.querySelectorAll(".tab")) {
  b.addEventListener("click", () => {
    history.replaceState(null, "", b.dataset.tab === "listeners" ? location.pathname : "#" + b.dataset.tab);
    showTab(b.dataset.tab);
  });
}
window.addEventListener("hashchange", () => { if (!$("app").hidden) showTab(currentTab()); });

$("login-form").addEventListener("submit", (ev) => {
  ev.preventDefault();
  const btn = $("login-submit");
  btn.disabled = true;
  setText($("login-error"), "");
  fetch("api/login", {
    method: "POST",
    headers: { ...CSRF, "Content-Type": "application/json" },
    credentials: "same-origin",
    body: JSON.stringify({ password: $("password").value }),
  })
    .then((r) => {
      if (r.status === 401) throw new Error("That password is not correct. Try again.");
      if (!r.ok) throw new Error("Sign-in failed. Check that the forwarder is running.");
      $("password").value = "";
      showApp();
      connect();
    })
    .catch((e) => { setText($("login-error"), e.message); $("password").select(); })
    .finally(() => { btn.disabled = false; });
});

$("logout").addEventListener("click", () => {
  fetch("api/logout", { method: "POST", headers: CSRF, credentials: "same-origin" }).finally(showLogin);
});

// ---------- start ----------

setInterval(paint, 500);
setInterval(sample, 1000);
window.addEventListener("resize", redrawCharts);
window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", redrawCharts);
checkSession().then((ok) => {
  if (ok) connect();
  else if (ok === null) { showApp(); setStatus("down", "Reconnecting"); scheduleReconnect(); }
});
