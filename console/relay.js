"use strict";

// The Relay hub tab. Each serve token is a group that opens to show the
// words registered with it and, for the ones being served right now, their
// tunnel and its open connections with live speeds. The data arrives with
// each console push as state.relay, which is absent when the hub is off;
// the tab's button is hidden then.
//
// The server calls a token's holder a tenant (state.relay.tenants, and
// "tenant" in the API paths); the page calls it a token.

const RELAY_ROWS = 200; // most connections drawn per word
const RELAY_ORPHANS = "\u0000orphans"; // group for words whose token is gone

const rl = {
  groups: new Map(), // token name -> group refs
  words: new Map(), // word id -> card refs
  open: new Set(), // names of the groups that are expanded
  meters: new Map(), // "wu1", "wd1", "su7", "sd7" -> RateMeter
  armed: new Map(), // "action:id" -> disarm timer
  busy: new Set(),
};

function relayMeter(key) {
  let m = rl.meters.get(key);
  if (!m) { m = new RateMeter(); rl.meters.set(key, m); }
  return m;
}

// relayFeed records the byte counters of one push, whether or not the tab
// is showing, so the speeds are right the moment it opens.
function relayFeed(relay, now) {
  const seen = new Set();
  for (const w of relay ? relay.words : []) {
    if (!w.live) continue;
    seen.add("wu" + w.id).add("wd" + w.id);
    relayMeter("wu" + w.id).add(now, w.bytesUp);
    relayMeter("wd" + w.id).add(now, w.bytesDown);
    for (const p of w.sessions) {
      seen.add("su" + p.id).add("sd" + p.id);
      relayMeter("su" + p.id).add(now, p.pfToUpstream);
      relayMeter("sd" + p.id).add(now, p.pfToClient);
    }
  }
  for (const key of rl.meters.keys()) if (!seen.has(key)) rl.meters.delete(key);
}

function relayArmed(key, btn, label, run) {
  if (rl.busy.has(key)) return;
  if (!rl.armed.has(key)) {
    btn.classList.add("armed");
    setText(btn, "Confirm");
    rl.armed.set(key, setTimeout(() => {
      rl.armed.delete(key);
      btn.classList.remove("armed");
      setText(btn, label);
    }, ARM_MS));
    return;
  }
  clearTimeout(rl.armed.get(key));
  rl.armed.delete(key);
  btn.classList.remove("armed");
  setText(btn, label);
  rl.busy.add(key);
  btn.disabled = true;
  run().finally(() => { rl.busy.delete(key); btn.disabled = false; });
}

function relayButton(label, title, danger) {
  const b = el("button", danger ? "act danger" : "act", label);
  b.type = "button";
  b.title = title;
  return b;
}

function relayFact(parent, label, cls) {
  const wrap = el("span", "", label + " ");
  const value = el("b", "num" + (cls ? " " + cls : ""));
  wrap.append(value);
  parent.append(wrap);
  return { wrap, value };
}

// ---------- token groups ----------

function relayGroup(name) {
  const orphans = name === RELAY_ORPHANS;
  const card = el("div", "relay-group");
  const head = el("div", "relay-group-head");
  const toggle = el("button", "relay-toggle");
  toggle.type = "button";
  toggle.append(chevron(), el("span", "relay-group-name", orphans ? "Deleted tokens" : name));
  const facts = el("span", "relay-group-facts");
  toggle.append(facts);
  const refs = {
    card, toggle,
    summary: el("span", ""),
    tx: el("span", "relay-rate tx num"), rx: el("span", "relay-rate rx num"),
    body: el("div", "relay-group-body"),
    note: el("div", "relay-none"),
    words: el("div"),
  };
  facts.append(refs.summary, refs.tx, refs.rx);
  const actions = el("div", "relay-actions");
  if (!orphans) {
    refs.rotate = relayButton("New token", "Replace this serve token; the old one stops working and its tunnels end");
    refs.del = relayButton("Delete", "Delete this token, end its tunnels and free its words", true);
    actions.append(refs.rotate, refs.del);
    refs.rotate.addEventListener("click", () => relayArmed("rotate:" + name, refs.rotate, "New token", () =>
      api(`api/relay/tenants/${encodeURIComponent(name)}/rotate`).then((r) => r.json())
        .then((t) => showRelayToken(t, "has a new serve token. The old one no longer works."))
        .catch((e) => toast(`Could not replace token ${name}: ${e.message}`, true))));
    refs.del.addEventListener("click", () => relayArmed("del:" + name, refs.del, "Delete", () =>
      api(`api/relay/tenants/${encodeURIComponent(name)}/delete`).then(() => toast(`Deleted token ${name}`))
        .catch((e) => toast(`Could not delete ${name}: ${e.message}`, true))));
  }
  head.append(toggle, actions);
  refs.body.append(refs.words, refs.note);
  card.append(head, refs.body);
  toggle.addEventListener("click", () => {
    if (rl.open.has(name)) rl.open.delete(name); else rl.open.add(name);
    if (ui.state) relayPaint(ui.state.relay);
  });
  return refs;
}

// ---------- words and their connections ----------

function relayCard(w) {
  const card = el("div", "relay-word");
  const head = el("div", "relay-head");
  const chip = el("span", "relay-chip");
  const title = el("span", "relay-word-title");
  const name = el("span", "relay-name", w.word);
  name.title = "The secret word both sides type";
  const actions = el("div", "relay-actions");
  const reset = relayButton("Reset", "End this tunnel and its connections; the serving side registers again on its own");
  const clear = relayButton("Clear binding", "Remove the binding of this word to its token, and end its tunnel", true);
  actions.append(reset, clear);
  head.append(chip, title, name, actions);

  const meta = el("div", "relay-meta");
  const refs = {
    card, chip, title, reset, clear, group: null, sessions: new Map(),
    owner: relayFact(meta, "Token"),
    route: relayFact(meta, "Serving"),
    since: relayFact(meta, ""),
    conns: relayFact(meta, "Connections"),
    tx: relayFact(meta, "To serving side", "tx"),
    rx: relayFact(meta, "To connecting side", "rx"),
    up: relayFact(meta, "Sent"),
    down: relayFact(meta, "Received"),
    failed: relayFact(meta, "Failed"),
  };
  const rows = el("div", "relay-rows");
  const cols = el("div", "r-cols r-head");
  for (const [text, cls] of [["Connection", ""], ["Connecting side", ""], ["Serving side", ""], ["Age", "r"], ["To serving", "r"], ["To connecting", "r"], ["", ""]]) {
    cols.append(el("span", cls, text));
  }
  refs.rows = rows;
  refs.body = el("div");
  refs.note = el("div", "relay-none");
  rows.append(cols, refs.body);
  card.append(head, meta, rows, refs.note);

  reset.addEventListener("click", () => relayArmed("reset:" + w.id, reset, "Reset", () =>
    api(`api/relay/${w.id}/reset`).then(() => toast(`Reset the tunnel ${w.name || w.word}`))
      .catch((e) => toast(`Could not reset: ${e.message}`, true))));
  clear.addEventListener("click", () => relayArmed("clear:" + w.id, clear, "Clear binding", () =>
    api(`api/relay/${w.id}/clear`).then(() => toast(`Cleared the binding of ${w.name || w.word}`))
      .catch((e) => toast(`Could not clear: ${e.message}`, true))));
  return refs;
}

function relaySpeed(rate, total) {
  const cell = el("span", "r r-speed");
  const refs = { cell, rate: el("span", "num " + rate), total: el("span", "num r-total") };
  cell.append(refs.rate, refs.total);
  return refs;
}

function relaySessionRow(p) {
  const row = el("div", "r-cols");
  const refs = {
    row,
    id: el("span", "mono"), client: el("span", "mono"), serve: el("span", "mono"),
    age: el("span", "r num"), up: relaySpeed("tx"), down: relaySpeed("rx"),
    stop: relayButton("Stop", "Reset this connection", true),
  };
  const last = el("span", "r");
  last.append(refs.stop);
  row.append(refs.id, refs.client, refs.serve, refs.age, refs.up.cell, refs.down.cell, last);
  refs.stop.addEventListener("click", () => relayArmed("stop:" + p.id, refs.stop, "Stop", () =>
    api(`api/pipes/${p.id}/stop`).catch((e) => toast(`Could not stop #${p.id}: ${e.message}`, true))));
  return refs;
}

function paintRelayWord(c, w, now) {
  setText(c.chip, w.live ? "Live" : "Offline");
  c.chip.className = w.live ? "relay-chip live" : "relay-chip";
  setText(c.title, w.name || "(unnamed)");
  c.reset.hidden = !w.live;
  c.owner.wrap.hidden = !w.orphan; // inside its token's group otherwise
  setText(c.owner.value, `${w.owner} (deleted)`);
  c.route.wrap.hidden = !w.live;
  setText(c.route.value, w.live ? `${w.target} from ${w.serveAddr}` : "");
  setText(c.since.wrap.firstChild, w.live ? "Up " : "Last served ");
  setText(c.since.value, w.live ? fmtAge(now - w.since) : fmtClock(w.lastServed));
  for (const f of [c.conns, c.tx, c.rx, c.up, c.down]) f.wrap.hidden = !w.live;
  setText(c.conns.value, String(w.conns));
  setText(c.tx.value, fmtRate(w.live ? relayMeter("wu" + w.id).rate(now) : 0));
  setText(c.rx.value, fmtRate(w.live ? relayMeter("wd" + w.id).rate(now) : 0));
  setText(c.up.value, fmtBytes(w.bytesUp));
  setText(c.down.value, fmtBytes(w.bytesDown));
  c.failed.wrap.hidden = !w.live || !w.failed;
  setText(c.failed.value, String(w.failed));

  const sessions = w.sessions.slice(-RELAY_ROWS).reverse(); // newest first
  const keep = new Set();
  let anchor = null;
  for (const p of sessions) {
    keep.add(p.id);
    let r = c.sessions.get(p.id);
    if (!r) { r = relaySessionRow(p); c.sessions.set(p.id, r); }
    const next = anchor ? anchor.nextSibling : c.body.firstChild;
    if (next !== r.row) c.body.insertBefore(r.row, next);
    anchor = r.row;
    setText(r.id, p.connId || "#" + p.id);
    r.id.title = `Connection ${p.connId}, #${p.id} in the flow log`;
    setText(r.client, p.clientRemote);
    setText(r.serve, p.upstreamRemote);
    setText(r.age, fmtAge(now - p.started));
    setText(r.up.rate, fmtRate(relayMeter("su" + p.id).rate(now)));
    setText(r.up.total, fmtBytes(p.pfToUpstream));
    setText(r.down.rate, fmtRate(relayMeter("sd" + p.id).rate(now)));
    setText(r.down.total, fmtBytes(p.pfToClient));
  }
  for (const [id, r] of c.sessions) {
    if (!keep.has(id)) { r.row.remove(); c.sessions.delete(id); }
  }
  c.rows.hidden = sessions.length === 0;
  c.note.hidden = sessions.length > 0 && w.conns <= sessions.length;
  setText(c.note, !w.live ? "Nobody is serving this word. Only its token may serve it again."
    : sessions.length === 0 ? "No open connections. They show up here when someone connects with this word."
      : `Showing the newest ${sessions.length} of ${w.conns} connections.`);
}

// ---------- the new-token panel ----------

// The server keeps only a hash of the token, so this is the one time it can
// be shown.
function showRelayToken(t, what) {
  setText($("tenant-token-text"), `Token ${t.name} ${what} Copy it now: it is not stored and cannot be shown again.`);
  setText($("tenant-token-value"), t.token);
  $("tenant-token").hidden = false;
}

$("tenant-add").addEventListener("click", () => {
  $("tenant-form").hidden = false;
  setText($("tenant-error"), "");
  $("tenant-name").focus();
});
$("tenant-cancel").addEventListener("click", () => { $("tenant-form").hidden = true; $("tenant-form").reset(); });
$("tenant-form").addEventListener("submit", (ev) => {
  ev.preventDefault();
  const btn = $("tenant-create");
  btn.disabled = true;
  api("api/relay/tenants", { name: $("tenant-name").value.trim() }).then((r) => r.json())
    .then((t) => {
      $("tenant-form").hidden = true;
      $("tenant-form").reset();
      showRelayToken(t, "was created. This is its serve token.");
    })
    .catch((e) => setText($("tenant-error"), e.message))
    .finally(() => { btn.disabled = false; });
});
$("tenant-token-done").addEventListener("click", () => { $("tenant-token").hidden = true; setText($("tenant-token-value"), ""); });
$("tenant-token-copy").addEventListener("click", () => {
  const value = $("tenant-token-value").textContent;
  // The clipboard API needs https or localhost; otherwise select the text.
  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(value).then(() => toast("Copied the serve token"), () => {});
  } else {
    getSelection().selectAllChildren($("tenant-token-value"));
    toast("Selected the token; copy it with your keyboard");
  }
});

// ---------- paint ----------

function relayPaint(relay) {
  $("tab-btn-relay").hidden = !relay;
  if (!relay) {
    if (!$("tab-relay").hidden) showTab("listeners");
    return;
  }
  if ($("tab-relay").hidden) return;
  const now = serverNow();

  // Group the words by token; words whose token is gone get their own group.
  const names = relay.tenants.map((t) => t.name);
  const byGroup = new Map(names.map((n) => [n, []]));
  for (const w of relay.words) {
    const key = w.orphan ? RELAY_ORPHANS : w.owner;
    if (!byGroup.has(key)) { byGroup.set(key, []); names.push(key); }
    byGroup.get(key).push(w);
  }

  const box = $("relay-groups");
  const seenWords = new Set();
  let anchor = null, liveAll = 0, connsAll = 0;
  for (const name of names) {
    let g = rl.groups.get(name);
    if (!g) { g = relayGroup(name); rl.groups.set(name, g); }
    const next = anchor ? anchor.nextSibling : box.firstChild;
    if (next !== g.card) box.insertBefore(g.card, next);
    anchor = g.card;

    const words = byGroup.get(name);
    let live = 0, conns = 0, tx = 0, rx = 0;
    for (const w of words) {
      seenWords.add(w.id);
      if (w.live) {
        live++; conns += w.conns;
        tx += relayMeter("wu" + w.id).rate(now);
        rx += relayMeter("wd" + w.id).rate(now);
      }
      let c = rl.words.get(w.id);
      if (!c) { c = relayCard(w); rl.words.set(w.id, c); }
      if (c.group !== name) { g.words.append(c.card); c.group = name; }
    }
    liveAll += live; connsAll += conns;
    const open = rl.open.has(name);
    g.toggle.setAttribute("aria-expanded", String(open));
    g.body.hidden = !open;
    setText(g.summary, `${words.length} word${words.length === 1 ? "" : "s"} · ${live} live · ${conns} connection${conns === 1 ? "" : "s"}`);
    g.tx.hidden = g.rx.hidden = live === 0;
    setText(g.tx, "↑ " + fmtRate(tx));
    setText(g.rx, "↓ " + fmtRate(rx));
    if (g.rotate) g.rotate.hidden = g.del.hidden = !relay.manage;
    g.note.hidden = words.length > 0;
    setText(g.note, "No words yet. One appears when pf-client serve registers it with this token.");
    if (open) for (const w of words) paintRelayWord(rl.words.get(w.id), w, now);
  }
  for (const [id, c] of rl.words) {
    if (!seenWords.has(id)) { c.card.remove(); rl.words.delete(id); }
  }
  for (const [name, g] of rl.groups) {
    if (!byGroup.has(name)) { g.card.remove(); rl.groups.delete(name); rl.open.delete(name); }
  }

  $("tenant-add").hidden = !relay.manage;
  if (!relay.manage) $("tenant-form").hidden = true;
  setText($("tenant-note"), relay.manage ? "Each token lets one holder run pf-client serve. Open a token to see its words and connections."
    : "Set with --tunnel. Start pf-simple from a config file to manage tokens here.");
  $("relay-empty").hidden = names.length > 0;
  const count = relay.tenants.length;
  setText($("relay-note"), `${count} token${count === 1 ? "" : "s"} · ${relay.words.length} word${relay.words.length === 1 ? "" : "s"} bound · ${liveAll} live · ${connsAll} open connection${connsAll === 1 ? "" : "s"}`);
}

// Ages and speeds tick between pushes.
setInterval(() => { if (ui.state) relayPaint(ui.state.relay); }, 1000);
