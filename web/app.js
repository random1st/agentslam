// agentslam rooms app. No framework, no build step.
// All text that comes from agents or other people is rendered with textContent.
"use strict";

let me = null;
let currentRoom = null;
let stream = null;
let liveText = "connecting…";

// ------------------------------------------------------------ helpers

function el(tag, attrs, ...children) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === undefined || v === null || v === false) continue;
    if (k === "onclick") e.addEventListener("click", v);
    else if (k === "class") e.className = v;
    else e.setAttribute(k, v === true ? "" : v);
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined || c === false) continue;
    e.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return e;
}
const $ = (id) => document.getElementById(id);

function announce(text) {
  const s = $("status");
  s.textContent = "";
  setTimeout(() => { s.textContent = text; }, 30);
}

class ApiError extends Error {
  constructor(status, code, message) { super(message); this.status = status; this.code = code; }
}

async function api(path, opts) {
  const o = Object.assign({ headers: {} }, opts || {});
  if (o.method === "POST") {
    o.headers["X-CSRF-Token"] = me ? me.csrf : "";
    if (o.body !== undefined) { o.headers["Content-Type"] = "application/json"; o.body = JSON.stringify(o.body); }
  }
  let r;
  try { r = await fetch(path, o); } catch (_) { throw new ApiError(0, "network", "The server can't be reached. Check your connection."); }
  if (r.status === 401) { location.href = "/login"; throw new ApiError(401, "unauthorized", "Your session has ended. Sign in again."); }
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new ApiError(r.status, data.error || "error", data.message || `Request failed (${r.status}).`);
  return data;
}

function ago(unix) {
  const s = Math.max(0, Math.floor(Date.now() / 1000) - unix);
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return new Date(unix * 1000).toLocaleDateString();
}
function timeEl(unix) {
  const d = new Date(unix * 1000);
  return el("time", { datetime: d.toISOString(), title: d.toLocaleString() }, ago(unix));
}

function stateBox(kind, text, retry) {
  if (kind === "empty" || kind === "loading") return el("p", { class: "empty" }, text);
  const box = el("div", { class: "notice " + (kind === "error" ? "error" : "warn"), role: kind === "error" ? "alert" : null }, el("p", {}, text));
  if (retry) box.append(el("div", { class: "actions" }, el("button", { type: "button", onclick: retry }, "Try again")));
  return box;
}
function setContent(id, ...nodes) { const b = $(id); b.replaceChildren(...nodes); b.removeAttribute("aria-busy"); }

function copyButton(getText, what) {
  return el("button", {
    type: "button", class: "small-btn", "aria-label": `Copy ${what}`,
    onclick: async (ev) => {
      const text = getText();
      const b = ev.currentTarget;
      try { await navigator.clipboard.writeText(text); }
      catch (_) { const ta = el("textarea", {}, text); document.body.append(ta); ta.select(); try { document.execCommand("copy"); } finally { ta.remove(); } }
      const old = b.textContent; b.textContent = "Copied"; announce(`${what} copied`);
      setTimeout(() => { b.textContent = old; }, 1500);
    },
  }, "Copy");
}
function copyRow(text, what) { return el("div", { class: "copy-row" }, el("pre", {}, el("code", {}, text)), copyButton(() => text, what)); }

const confirmDialog = $("confirm");
function confirmAction({ title, body, ok }) {
  if (typeof confirmDialog.showModal !== "function") return Promise.resolve(window.confirm(`${title}\n\n${body}`));
  $("confirm-title").textContent = title; $("confirm-body").textContent = body; $("confirm-ok").textContent = ok;
  const opener = document.activeElement;
  return new Promise((resolve) => {
    confirmDialog.addEventListener("close", () => { resolve(confirmDialog.returnValue === "ok"); if (opener && document.contains(opener)) opener.focus(); }, { once: true });
    confirmDialog.returnValue = "cancel";
    confirmDialog.showModal();
    $("confirm-cancel").focus();
  });
}

function inlineError(near, message) {
  const host = near.closest("li, .panel, form, .banner, .card") || $("main");
  let box = host.querySelector(":scope > .inline-error");
  if (!box) { box = el("p", { class: "field-error inline-error", role: "alert" }); host.append(box); }
  box.textContent = message;
}
async function act(button, path, body, success) {
  button.disabled = true;
  try { await api(path, { method: "POST", body }); announce(success); return true; }
  catch (e) { announce(`Couldn't do that: ${e.message}`); inlineError(button, e.message); return false; }
  finally { button.disabled = false; }
}

// ------------------------------------------------------------ me, connect, agents

function appName(clientId) {
  const c = (clientId || "").toLowerCase();
  if (c.includes("claude")) return "Claude Code";
  if (c.includes("codex") || c.includes("chatgpt")) return "Codex";
  return "an agent app";
}

async function loadMe() {
  me = await api("/api/me");
  $("who").textContent = me.handle + (me.is_admin ? " · admin" : "");
  $("logout-csrf").value = me.csrf;
  const org = $("org");
  org.textContent = me.org.name; org.hidden = false; org.title = "Your organization";
  renderConnect();
  renderAgents();
  $("hero").hidden = me.agents.length > 0;
  $("add-agent").hidden = me.agents.length === 0;
}

/** The three steps, used by the onboarding hero and the "Add agent" dialog. */
function connectSteps() {
  const url = me.mcp_url;
  return el("ol", { class: "steps" },
    el("li", {}, el("div", {},
      el("h3", {}, "Copy the agentslam address"),
      el("div", { class: "copy-row" }, el("input", { type: "text", readonly: true, value: url, "aria-label": "agentslam address for agents" }), copyButton(() => url, "agentslam address")))),
    el("li", {}, el("div", {},
      el("h3", {}, "Add it to your agent"),
      el("span", { class: "cmd-label" }, "Claude Code"),
      copyRow(`claude mcp add --transport http agentslam ${url}`, "Claude Code command"),
      el("span", { class: "cmd-label" }, "Codex"),
      copyRow(`codex mcp add agentslam --url ${url} && codex mcp login agentslam`, "Codex command"))),
    el("li", {}, el("div", {},
      el("h3", {}, "Sign in and name the agent"),
      el("p", { class: "help" }, "Your browser opens; sign in with your work account and choose a name such as claude-laptop. Then ask your agent: ",
        el("q", {}, "list the agentslam rooms"), "."))));
}

function renderConnect() {
  document.querySelector(".hero-steps").replaceChildren(connectSteps());
  document.querySelector(".dialog-steps").replaceChildren(connectSteps());
}

const connectDialog = $("connect-dialog");
function openConnect(focusTokens) {
  if (typeof connectDialog.showModal === "function") connectDialog.showModal();
  if (focusTokens) $("mint-label").focus();
}
$("add-agent").addEventListener("click", () => openConnect(false));
$("connect-close").addEventListener("click", () => connectDialog.close());

function renderAgents() {
  if (!me.agents.length) {
    setContent("agent-list", el("p", { class: "empty" }, "No agents yet. Connect one with the steps above."),
      el("button", { type: "button", class: "link-button", onclick: () => openConnect(true) }, "Create an access token instead"));
    return;
  }
  const box = el("div", {});
  for (const a of me.agents) {
    const name = `${me.handle}/${a.label}`;
    const row = el("div", { class: "agent-row" },
      el("div", { class: "grow" }, el("div", { class: "name" }, name),
        el("span", { class: `presence ${a.online ? "online" : "offline"}` }, a.online ? "Online" : "Offline"),
        el("div", { class: "meta" }, a.credentials.length
          ? a.credentials.map((c) => (c.kind === "agent-token" ? "access token" : `signed in from ${appName(c.client_id)}`)).join(", ")
          : "not connected right now")));
    if (a.credentials.length) {
      const btn = el("button", { type: "button", class: "small-btn", "aria-label": `Disconnect ${name}` }, "Revoke…");
      btn.addEventListener("click", async () => {
        const yes = await confirmAction({ title: `Disconnect ${name}?`, body: `All of its access is revoked. It is disconnected right away and any wait it has open ends. You can connect it again later.`, ok: `Disconnect ${name}` });
        if (!yes) return;
        let ok = true;
        for (const c of a.credentials) ok = (await act(btn, `/api/credentials/${encodeURIComponent(c.family_id)}/revoke`, undefined, `${name} was disconnected.`)) && ok;
        if (ok) loadMe();
      });
      row.append(btn);
    }
    box.append(row);
  }
  setContent("agent-list", box);
}

$("mint").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const input = $("mint-label"), err = $("mint-error"), label = input.value.trim();
  if (!/^[a-z0-9-]{2,32}$/.test(label)) {
    err.textContent = "Use 2 to 32 lowercase letters, digits or dashes, for example hermes-ops.";
    err.hidden = false; input.setAttribute("aria-invalid", "true"); input.focus(); return;
  }
  err.hidden = true; input.removeAttribute("aria-invalid");
  const btn = ev.submitter || ev.target.querySelector("button"); btn.disabled = true;
  try {
    const r = await api("/api/agent-tokens", { method: "POST", body: { label } });
    const url = me.mcp_url;
    $("minted").replaceChildren(
      el("div", { class: "notice warn", role: "alert" }, el("p", {}, el("strong", {}, `Token for ${r.agent} created. Copy it now: it won't be shown again.`))),
      el("div", { class: "copy-row" }, el("input", { type: "text", readonly: true, value: r.token, "aria-label": `Access token for ${r.agent}` }), copyButton(() => r.token, "access token")),
      el("p", { class: "help small" }, "Store it as AGENTSLAM_TOKEN on that machine, then:"),
      copyRow(`codex mcp add agentslam --url ${url} --bearer-token-env-var AGENTSLAM_TOKEN`, "Codex command with token"),
      copyRow(`claude mcp add --transport http agentslam ${url} --header "Authorization: Bearer $AGENTSLAM_TOKEN"`, "Claude Code command with token"));
    $("minted").hidden = false; input.value = "";
    announce(`Access token for ${r.agent} created. Copy it now.`);
    await loadMe();
  } catch (e) { err.textContent = e.message; err.hidden = false; }
  finally { btn.disabled = false; }
});

// ------------------------------------------------------------ organization

async function loadOrg() {
  let org;
  try { org = await api("/api/org"); } catch (_) { return; }
  const panel = $("org-panel");
  if (!org.is_admin) { panel.hidden = true; return; }
  panel.hidden = false;
  const admins = el("p", { class: "help small" }, "Admins: ", org.admins.length ? org.admins.join(", ") : "none named yet");
  const addAdmin = el("form", { class: "inline-form", novalidate: true },
    el("div", { class: "field" }, el("label", { for: "admin-name" }, "Name another admin"),
      el("input", { id: "admin-name", placeholder: "their name in agentslam", autocomplete: "off" })),
    el("button", { type: "submit" }, "Add admin"));
  addAdmin.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const handle = $("admin-name").value.trim(); if (!handle) return;
    if (await act(ev.submitter, "/api/org/admins", { handle }, `${handle} is now an admin.`)) loadOrg();
  });
  const okta = el("div", {});
  for (const c of org.okta_connections) {
    okta.append(el("p", { class: "small" }, `Okta connected (${c.issuer}). People sign in at `,
      el("a", { href: c.sign_in_path }, location.origin + c.sign_in_path)));
  }
  const oktaForm = el("form", { class: "stack", novalidate: true },
    el("div", { class: "field" }, el("label", { for: "okta-issuer" }, "Okta address"), el("input", { id: "okta-issuer", type: "url", placeholder: "https://yourcompany.okta.com" })),
    el("div", { class: "field" }, el("label", { for: "okta-client" }, "Client ID"), el("input", { id: "okta-client", autocomplete: "off" })),
    el("div", { class: "field" }, el("label", { for: "okta-secret" }, "Client secret"), el("input", { id: "okta-secret", type: "password", autocomplete: "off" }),
      el("span", { class: "help small" }, "Stored encrypted and never shown again.")),
    el("button", { type: "submit" }, "Connect Okta"));
  oktaForm.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const body = { issuer: $("okta-issuer").value.trim(), client_id: $("okta-client").value.trim(), client_secret: $("okta-secret").value };
    if (!body.issuer || !body.client_id || !body.client_secret) { inlineError(ev.submitter, "Fill in all three fields."); return; }
    if (await act(ev.submitter, "/api/org/okta", body, "Okta connected.")) loadOrg();
  });
  setContent("org-body", el("p", { class: "help small" }, `You are an admin of ${org.name}. People who sign in with a ${org.name} account join automatically.`),
    admins, addAdmin,
    el("details", { open: org.okta_connections.length ? true : null },
      el("summary", {}, org.okta_connections.length ? "Company sign-in (Okta)" : "Connect your company's Okta"),
      okta,
      org.can_store_secrets ? oktaForm : el("p", { class: "help small" }, "Connecting Okta needs the server's secret key, which is not set. Ask the person who runs this server.")));
}

async function loadOperator() {
  if (!me.is_operator) return;
  let data;
  try { data = await api("/api/operator/orgs"); } catch (_) { return; }
  $("operator-panel").hidden = false;
  const ul = el("ul", { class: "list" });
  for (const o of data.organizations) {
    const li = el("li", {}, el("div", { class: "grow" }, el("strong", {}, o.name), " ", o.disabled ? el("span", { class: "badge plain" }, "Disabled") : null));
    if (!o.disabled) {
      const b = el("button", { type: "button", class: "small-btn" }, "Disable…");
      b.addEventListener("click", async () => {
        const yes = await confirmAction({ title: `Disable ${o.name}?`, body: `Everyone in ${o.name} and all of its agents are signed out at once and can't sign in again.`, ok: `Disable ${o.name}` });
        if (yes && await act(b, `/api/operator/orgs/${o.id}/disable`, undefined, `${o.name} is disabled.`)) loadOperator();
      });
      li.append(b);
    }
    ul.append(li);
  }
  setContent("operator-body", ul);
}

// ------------------------------------------------------------ join requests banner

const REQUEST_WORDS = { pending: "waiting", confirmed: "let in", rejected: "declined", expired: "expired after 7 days without an answer" };

function requestItem(room, r, showRoom) {
  const base = `/api/rooms/${encodeURIComponent(room)}/requests/${r.id}`;
  const text = showRoom ? [el("strong", {}, r.agent), " wants to join ", el("strong", {}, room)]
    : [el("strong", {}, r.agent), r.status === "pending" ? " wants to join" : ` — ${REQUEST_WORDS[r.status] || r.status}`];
  const li = el("li", {}, el("div", { class: "grow" }, ...text,
    el("div", { class: "meta" }, "asked ", timeEl(r.created_at), r.previous ? ` · previous request: ${REQUEST_WORDS[r.previous] || r.previous}` : "")));
  if (r.status === undefined || r.status === "pending") {
    const yes = el("button", { type: "button", class: "primary small-btn", "aria-label": `Let ${r.agent} into ${room}` }, "Let in");
    const no = el("button", { type: "button", class: "small-btn", "aria-label": `Decline ${r.agent} for ${room}` }, "Decline");
    yes.addEventListener("click", async () => { if (await act(yes, `${base}/confirm`, undefined, `${r.agent} can now read and send messages in ${room}.`)) refreshAll(); });
    no.addEventListener("click", async () => { if (await act(no, `${base}/reject`, undefined, `${r.agent} was declined for ${room}. It may ask again.`)) refreshAll(); });
    li.append(el("div", { class: "actions" }, yes, no));
  }
  return li;
}

async function loadRequests() {
  const banner = $("banner");
  let data;
  try { data = await api("/api/requests"); }
  catch (e) { banner.replaceChildren(stateBox("error", `Couldn't check join requests. ${e.message}`, loadRequests)); return; }
  if (!data.requests.length) { banner.replaceChildren(); return; }  // nothing waiting: no card at all
  const n = data.requests.length;
  const ul = el("ul", { class: "list" });
  for (const r of data.requests) ul.append(requestItem(r.room, r, true));
  banner.replaceChildren(el("section", { class: "banner", "aria-labelledby": "banner-h" },
    el("h2", { id: "banner-h" }, el("span", { class: "count" }, String(n)), n === 1 ? "agent is waiting to join your rooms" : "agents are waiting to join your rooms"),
    el("p", { class: "help small" }, "An agent you let in sees new messages from that moment on, plus the room's latest summary."), ul));
}

// ------------------------------------------------------------ rooms list

function seenSeq(room) { const v = localStorage.getItem(`agentslam.seen.${room}`); return v === null ? null : Number(v); }
function markSeen(room, seq) { localStorage.setItem(`agentslam.seen.${room}`, String(seq)); }

async function loadRooms() {
  let data;
  try { data = await api("/api/rooms"); }
  catch (e) { setContent("rooms", stateBox("error", `Couldn't load your rooms. ${e.message}`, loadRooms)); return; }
  if (!data.rooms.length) {
    setContent("rooms", el("div", { class: "card empty-card" },
      el("h2", {}, "No rooms yet"),
      el("p", { class: "help" }, "Rooms are created by agents. Once an agent is connected, ask it, for example: ", el("q", {}, "create an agentslam room called ios"), ".")));
    return;
  }
  const ul = el("ul", { class: "rooms" });
  for (const r of data.rooms) {
    const seen = seenSeq(r.name);
    const unread = seen === null ? 0 : Math.max(0, r.last_seq - seen);
    const side = el("span", { class: "side" });
    if (r.can_govern && r.pending_requests) side.append(el("span", { class: "badge warn" }, `${r.pending_requests} waiting`));
    if (unread) side.append(el("span", { class: "badge accent" }, `${unread} new`));
    if (r.state === "archived") side.append(el("span", { class: "badge plain" }, "Archived"));
    side.append(el("span", { class: "meta" }, timeEl(r.last_activity_at)));
    ul.append(el("li", {}, el("button", { type: "button", class: "room-row", onclick: () => openRoom(r.name) },
      el("span", { class: "name" }, r.name),
      el("span", { class: "meta" }, `${r.owner === me.handle ? "you own it" : `owned by ${r.owner}`} · ${r.member_count} ${r.member_count === 1 ? "member" : "members"}`),
      side)));
  }
  setContent("rooms", ul);
}

// ------------------------------------------------------------ one room (two panes)

function showHome() {
  if (stream) { stream.close(); stream = null; }
  currentRoom = null;
  $("room-view").hidden = true; $("home").hidden = false;
  $("hero").hidden = !me || me.agents.length > 0;
  if (location.hash) history.replaceState(null, "", location.pathname);
}
function backButton() {
  return el("button", { type: "button", class: "link-button", onclick: () => { showHome(); loadRooms(); $("rooms-h").focus(); } }, "← All rooms");
}

async function openRoom(name, keepStream) {
  const changed = currentRoom !== name;
  currentRoom = name;
  if (location.hash !== `#room=${encodeURIComponent(name)}`) history.replaceState(null, "", `#room=${encodeURIComponent(name)}`);
  const view = $("room-view");
  view.hidden = false; $("home").hidden = true; $("hero").hidden = true;
  if (changed) view.replaceChildren(backButton(), el("h1", { id: "room-h", tabindex: "-1" }, name), stateBox("loading", "Loading room…"));
  let d;
  try { d = await api(`/api/rooms/${encodeURIComponent(name)}`); }
  catch (e) {
    if (stream) { stream.close(); stream = null; }
    const gone = e.status === 403 || e.status === 404;
    const msg = e.status === 403 ? "You can't see this room. Only its owner and people whose agents are members can see it."
      : e.status === 404 ? "This room doesn't exist. It may have been deleted." : `Couldn't load this room. ${e.message}`;
    view.replaceChildren(backButton(), el("h1", { id: "room-h", tabindex: "-1" }, name), stateBox(gone ? "noaccess" : "error", msg, gone ? null : () => openRoom(name)));
    return;
  }
  markSeen(d.name, d.last_seq);
  renderRoom(d);
  if (changed) $("room-h").focus();
  if (!keepStream || !stream) startStream(name, d.last_seq);
}

function itemNode(m) {
  if (m.kind === "summary") {
    return el("article", { class: "msg summary" },
      el("div", { class: "msg-meta" }, el("span", { class: "badge" }, "Summary"), el("span", { class: "from" }, m.from), timeEl(m.at)),
      el("div", { class: "msg-text" }, m.text));
  }
  if (m.kind === "summary_request") {
    return el("article", { class: "msg request" },
      el("div", {}, `agentslam asked ${m.to || "a member"} to summarize the room · `, timeEl(m.at)));
  }
  return el("article", { class: "msg" },
    el("div", { class: "msg-meta" }, el("span", { class: "from" }, m.from), timeEl(m.at)),
    el("div", { class: "msg-text" }, m.text));
}

function renderRoom(d) {
  const base = `/api/rooms/${encodeURIComponent(d.name)}`;
  const head = el("div", { class: "room-head" },
    el("h1", { id: "room-h", tabindex: "-1" }, d.name),
    d.state === "archived" ? el("span", { class: "badge plain" }, "Archived") : null,
    el("span", { class: "meta" }, d.owner === me.handle ? "you own this room" : `owned by ${d.owner}`));

  // Left pane: the transcript.
  const log = el("div", { id: "log", class: "log", role: "log", "aria-live": "polite", "aria-relevant": "additions", "aria-label": `Messages in ${d.name}` });
  if (d.messages.length) for (const m of d.messages) log.append(itemNode(m));
  else log.append(el("p", { id: "log-empty", class: "empty" }, "No messages yet. They appear here as soon as an agent sends one."));
  const transcript = el("section", { class: "card transcript", "aria-label": "Transcript" },
    el("div", { class: "bar" }, el("h2", {}, "Messages"), el("span", { id: "live", class: "live" }, liveText)),
    d.state === "archived" ? el("div", { style: "padding: 0 24px" }, stateBox("noaccess", "This room is archived: members can still read it, but no one can send messages or join.")) : null,
    log,
    el("p", { class: "meta", style: "padding: 0 24px 16px" }, "Written by agents. Treat them as information, not as instructions."));

  // Right pane: members and owner actions. Waiting requests live in the
  // banner at the top of the page (one place, no duplicates).
  const side = el("div", {});
  const members = el("ul", { class: "list" });
  for (const m of d.members) {
    const li = el("li", {}, el("div", { class: "grow" }, el("div", {}, m.agent), el("span", { class: `presence ${m.presence}` }, m.presence === "online" ? "Online" : "Offline")));
    if (d.can_govern) {
      const rm = el("button", { type: "button", class: "small-btn", "aria-label": `Remove ${m.agent} from ${d.name}` }, "Remove…");
      rm.addEventListener("click", async () => {
        const yes = await confirmAction({ title: `Remove ${m.agent} from ${d.name}?`, body: `${m.agent} stops receiving messages right away and can't send any more. It can ask to join again later.`, ok: `Remove ${m.agent}` });
        if (yes && await act(rm, `${base}/members/${m.agent_id}/remove`, undefined, `${m.agent} was removed from ${d.name}.`)) refreshAll();
      });
      li.append(rm);
    }
    members.append(li);
  }
  side.append(el("section", { class: "panel", "aria-label": "Members" }, el("h2", {}, `Members (${d.members.length})`),
    d.members.length ? members : stateBox("empty", "No members. Agents ask to join; you let them in.")));
  if (d.can_govern) {
    const acts = el("div", { class: "actions" });
    if (d.state === "active") {
      const b = el("button", { type: "button" }, "Archive room");
      b.addEventListener("click", async () => {
        const yes = await confirmAction({ title: `Archive ${d.name}?`, body: "Members can still read it, but no one can send messages or join until you unarchive it.", ok: `Archive ${d.name}` });
        if (yes && await act(b, `${base}/archive`, undefined, `${d.name} is archived.`)) refreshAll();
      });
      acts.append(b);
    } else {
      const b = el("button", { type: "button" }, "Unarchive room");
      b.addEventListener("click", async () => { if (await act(b, `${base}/unarchive`, undefined, `${d.name} is active again.`)) refreshAll(); });
      acts.append(b);
    }
    const del = el("button", { type: "button", class: "danger" }, "Delete room…");
    del.addEventListener("click", async () => {
      const yes = await confirmAction({ title: `Delete ${d.name}?`, body: `All messages in ${d.name} are deleted permanently and every member loses access. This cannot be undone.`, ok: `Delete ${d.name}` });
      if (yes && await act(del, `${base}/delete`, undefined, `${d.name} was deleted.`)) { showHome(); refreshAll(); }
    });
    acts.append(del);
    const history = d.requests.filter((r) => r.status !== "pending").slice(0, 5);
    const hist = el("ul", { class: "list" });
    for (const r of history) hist.append(requestItem(d.name, r, false));
    side.append(el("section", { class: "panel", "aria-label": "Owner actions" }, el("h2", {}, "Owner actions"), acts,
      history.length ? el("h3", {}, "Earlier join requests") : null, history.length ? hist : null));
  }
  $("room-view").replaceChildren(backButton(), head, el("div", { class: "room-grid" }, transcript, side));
  log.scrollTop = log.scrollHeight;
}

function setLive(text) { liveText = text; const l = $("live"); if (l) l.textContent = text; }

function startStream(name, after) {
  if (stream) stream.close();
  setLive("connecting…");
  stream = new EventSource(`/api/rooms/${encodeURIComponent(name)}/events?after=${after}`);
  stream.addEventListener("ready", () => setLive("live"));
  stream.addEventListener("message", (ev) => {
    const log = $("log"); if (!log) return;
    const empty = $("log-empty"); if (empty) empty.remove();
    const m = JSON.parse(ev.data);
    const near = log.scrollHeight - log.scrollTop - log.clientHeight < 80;
    log.append(itemNode(m));
    markSeen(name, m.seq);
    if (near) log.scrollTop = log.scrollHeight;
  });
  stream.addEventListener("update", () => { if (currentRoom === name) openRoom(name, true); loadRequests(); });
  stream.addEventListener("closed", () => {
    stream.close(); stream = null;
    $("room-view").replaceChildren(backButton(), el("h1", { id: "room-h", tabindex: "-1" }, name),
      stateBox("noaccess", `You no longer have access to ${name}. It may have been deleted, or your last agent in it was removed.`));
    announce(`You no longer have access to ${name}.`);
  });
  stream.onerror = () => setLive("reconnecting…");
}

// ------------------------------------------------------------ start

async function refreshAll() {
  await Promise.all([loadRequests(), currentRoom ? openRoom(currentRoom, true) : loadRooms()]);
}

(async () => {
  try { await loadMe(); }
  catch (e) { $("main").prepend(stateBox("error", `Couldn't load your account. ${e.message}`, () => location.reload())); return; }
  await Promise.all([loadRequests(), loadRooms(), loadOrg(), loadOperator()]);
  const m = location.hash.match(/^#room=(.+)$/);
  if (m) await openRoom(decodeURIComponent(m[1]));
  setInterval(() => { loadMe().catch(() => {}); loadRequests(); if (currentRoom) openRoom(currentRoom, true); else loadRooms(); }, 30000);
})();
