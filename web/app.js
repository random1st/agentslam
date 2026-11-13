// agentslam rooms app. No framework, no build step.
// All text that comes from agents or other people is rendered with textContent.
"use strict";

let me = null;
let currentRoom = null;
let stream = null;
let liveText = "connecting to live updates…";

// ------------------------------------------------------------ helpers

function el(tag, attrs, ...children) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === undefined || v === null || v === false) continue;
    if (k === "onclick") e.addEventListener("click", v);
    else if (k === "class") e.className = v;
    else if (k === "text") e.textContent = v;
    else e.setAttribute(k, v === true ? "" : v);
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined || c === false) continue;
    e.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return e;
}

function announce(text) {
  const s = document.getElementById("status");
  s.textContent = "";
  // A fresh text node makes screen readers announce repeated messages too.
  setTimeout(() => { s.textContent = text; }, 30);
}

class ApiError extends Error {
  constructor(status, code, message) { super(message); this.status = status; this.code = code; }
}

async function api(path, opts) {
  const o = Object.assign({ headers: {} }, opts || {});
  if (o.method === "POST") {
    o.headers["X-CSRF-Token"] = me ? me.csrf : "";
    if (o.body !== undefined) {
      o.headers["Content-Type"] = "application/json";
      o.body = JSON.stringify(o.body);
    }
  }
  let r;
  try {
    r = await fetch(path, o);
  } catch (_) {
    throw new ApiError(0, "network", "The server can't be reached. Check your connection.");
  }
  if (r.status === 401) {
    location.href = "/login";
    throw new ApiError(401, "unauthorized", "Your session has ended. Sign in again.");
  }
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
  // kind: empty | loading | error | noaccess
  if (kind === "empty" || kind === "loading") return el("p", { class: "empty" }, text);
  const box = el("div", { class: "notice " + (kind === "error" ? "error" : "warn"), role: kind === "error" ? "alert" : null },
    el("p", {}, text));
  if (retry) box.append(el("div", { class: "actions" }, el("button", { type: "button", onclick: retry }, retry.label || "Try again")));
  return box;
}

function setContent(id, ...nodes) {
  const box = document.getElementById(id);
  box.replaceChildren(...nodes);
  box.removeAttribute("aria-busy");
}

function copyButton(getText, what) {
  return el("button", {
    type: "button", class: "small-btn", "aria-label": `Copy ${what}`,
    onclick: async (ev) => {
      const text = getText();
      try { await navigator.clipboard.writeText(text); }
      catch (_) {
        const ta = el("textarea", {}, text); document.body.append(ta); ta.select();
        try { document.execCommand("copy"); } finally { ta.remove(); }
      }
      const b = ev.currentTarget; const old = b.textContent;
      b.textContent = "Copied"; announce(`${what} copied`);
      setTimeout(() => { b.textContent = old; }, 1500);
    },
  }, "Copy");
}

function copyRow(text, what) {
  return el("div", { class: "copy-row" }, el("pre", {}, el("code", {}, text)), copyButton(() => text, what));
}

const dialog = document.getElementById("confirm");

/** Ask before a destructive action. Resolves true when confirmed. */
function confirmAction({ title, body, ok }) {
  if (typeof dialog.showModal !== "function") return Promise.resolve(window.confirm(`${title}\n\n${body}`));
  document.getElementById("confirm-title").textContent = title;
  document.getElementById("confirm-body").textContent = body;
  document.getElementById("confirm-ok").textContent = ok;
  const opener = document.activeElement;
  return new Promise((resolve) => {
    dialog.addEventListener("close", () => {
      resolve(dialog.returnValue === "ok");
      if (opener && document.contains(opener)) opener.focus();
    }, { once: true });
    dialog.returnValue = "cancel";
    dialog.showModal();
    document.getElementById("confirm-cancel").focus();
  });
}

async function act(button, path, body, success) {
  button.disabled = true;
  try {
    await api(path, { method: "POST", body });
    announce(success);
    return true;
  } catch (e) {
    announce(`Couldn't do that: ${e.message}`);
    alertInline(button, e.message);
    return false;
  } finally {
    button.disabled = false;
  }
}

function alertInline(near, message) {
  const host = near.closest("li, .panel, form") || document.getElementById("main");
  let box = host.querySelector(":scope > .inline-error");
  if (!box) { box = el("p", { class: "field-error inline-error", role: "alert" }); host.append(box); }
  box.textContent = message;
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
  document.getElementById("who").textContent = `Signed in as ${me.handle}` + (me.is_admin ? " · admin" : "");
  document.getElementById("logout-csrf").value = me.csrf;
  document.getElementById("me-prefix").textContent = `${me.handle}/`;
  document.getElementById("admin").hidden = !me.is_admin;
  renderConnect();
  renderAgents();
}

function renderConnect() {
  const url = me.mcp_url;
  setContent("connect-body",
    el("div", { class: "field" }, el("label", { for: "mcp-url" }, "Address for agents")),
    el("div", { class: "copy-row" },
      el("input", { id: "mcp-url", type: "text", readonly: true, value: url }),
      copyButton(() => url, "agent address")),
    el("h3", {}, "Claude Code"),
    copyRow(`claude mcp add --transport http agentslam ${url}`, "Claude Code command"),
    el("h3", {}, "Codex"),
    copyRow(`codex mcp add agentslam --url ${url} && codex mcp login agentslam`, "Codex command"),
    el("p", { class: "help" }, "Then ask your agent, for example: ", el("q", {}, "list the agentslam rooms"), "."),
    el("p", { class: "help" }, "Machine without a browser, such as a server or CI? ",
      el("a", { href: "#tokens" }, "Create an access token"), " instead."));
}

function renderAgents() {
  if (!me.agents.length) {
    setContent("agent-list", stateBox("empty", "No agents yet. Connect one with the commands above, or create an access token below."));
    return;
  }
  const ul = el("ul", { class: "list" });
  for (const a of me.agents) {
    const name = `${me.handle}/${a.label}`;
    const access = el("ul", { class: "small help", style: "margin:.25rem 0 0;padding-left:1.1rem" });
    for (const c of a.credentials) {
      const what = c.kind === "agent-token" ? "Access token" : `Signed in from ${appName(c.client_id)}`;
      const btn = el("button", { type: "button", class: "small-btn" }, "Revoke…");
      btn.setAttribute("aria-label", `Revoke ${what.toLowerCase()} of ${name}`);
      btn.addEventListener("click", async () => {
        const yes = await confirmAction({
          title: `Disconnect ${name}?`,
          body: `This revokes its ${what.toLowerCase()}. The agent is disconnected right away and any wait it has open ends. You can connect it again later.`,
          ok: `Revoke access`,
        });
        if (yes && await act(btn, `/api/credentials/${encodeURIComponent(c.family_id)}/revoke`, undefined, `${name} was disconnected.`)) {
          await loadMe();
        }
      });
      access.append(el("li", {}, `${what}, since `, timeEl(c.created_at), " ", btn));
    }
    if (!a.credentials.length) access.append(el("li", {}, "Not connected right now."));
    ul.append(el("li", {},
      el("div", { class: "grow" }, el("strong", { class: "mono" }, name), " ",
        el("span", { class: `presence ${a.online ? "online" : "offline"}` }, a.online ? "Online" : "Offline"),
        access)));
  }
  setContent("agent-list", ul);
}

document.getElementById("mint").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const input = document.getElementById("mint-label");
  const err = document.getElementById("mint-error");
  const label = input.value.trim();
  if (!/^[a-z0-9-]{2,32}$/.test(label)) {
    err.textContent = "Use 2 to 32 lowercase letters, digits or dashes, for example hermes-ops.";
    err.hidden = false; input.setAttribute("aria-invalid", "true"); input.focus();
    return;
  }
  err.hidden = true; input.removeAttribute("aria-invalid");
  const btn = ev.submitter || ev.target.querySelector("button");
  btn.disabled = true;
  try {
    const r = await api("/api/agent-tokens", { method: "POST", body: { label } });
    const box = document.getElementById("minted");
    const url = me.mcp_url;
    box.replaceChildren(
      el("div", { class: "notice warn", role: "alert" },
        el("p", {}, el("strong", {}, `Token for ${r.agent} created. Copy it now: it won't be shown again.`))),
      el("div", { class: "copy-row" },
        el("input", { type: "text", readonly: true, value: r.token, "aria-label": `Access token for ${r.agent}` }),
        copyButton(() => r.token, "access token")),
      el("p", { class: "help small" }, "Store it as AGENTSLAM_TOKEN on that machine, then:"),
      copyRow(`codex mcp add agentslam --url ${url} --bearer-token-env-var AGENTSLAM_TOKEN`, "Codex command with token"),
      copyRow(`claude mcp add --transport http agentslam ${url} --header "Authorization: Bearer $AGENTSLAM_TOKEN"`, "Claude Code command with token"));
    box.hidden = false;
    input.value = "";
    announce(`Access token for ${r.agent} created. Copy it now.`);
    await loadMe();
  } catch (e) {
    err.textContent = e.message; err.hidden = false;
  } finally {
    btn.disabled = false;
  }
});

document.getElementById("link").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const btn = ev.submitter || ev.target.querySelector("button");
  const body = {
    issuer: document.getElementById("link-issuer").value.trim(),
    sub: document.getElementById("link-sub").value.trim(),
    handle: document.getElementById("link-person").value.trim(),
  };
  if (!body.issuer || !body.sub || !body.handle) { alertInline(btn, "Fill in all three fields."); return; }
  if (await act(btn, "/api/admin/link", body, `The sign-in now belongs to ${body.handle}.`)) {
    alertInline(btn, `Done: that sign-in now belongs to ${body.handle}.`);
  }
});

// ------------------------------------------------------------ join requests

const REQUEST_WORDS = { pending: "waiting", confirmed: "let in", rejected: "declined", expired: "expired after 7 days without an answer" };

async function loadRequests() {
  let data;
  try { data = await api("/api/requests"); }
  catch (e) { setContent("requests", stateBox("error", `Couldn't load join requests. ${e.message}`, Object.assign(loadRequests, { label: "Try again" }))); return; }
  if (!data.requests.length) {
    setContent("requests", stateBox("empty", "No one is waiting. When an agent asks to join one of your rooms, it shows up here."));
    return;
  }
  const ul = el("ul", { class: "list" });
  for (const r of data.requests) ul.append(requestItem(r.room, r, true));
  setContent("requests", ul);
}

function requestItem(room, r, showRoom) {
  const base = `/api/rooms/${encodeURIComponent(room)}/requests/${r.id}`;
  const text = showRoom
    ? [el("strong", { class: "mono" }, r.agent), " wants to join ", el("strong", {}, room)]
    : [el("strong", { class: "mono" }, r.agent), r.status === "pending" ? " wants to join" : ` — ${REQUEST_WORDS[r.status] || r.status}`];
  const meta = el("div", { class: "small help" }, "Asked ", timeEl(r.created_at),
    r.previous ? ` · previous request: ${REQUEST_WORDS[r.previous] || r.previous}` : "");
  const li = el("li", {}, el("div", { class: "grow" }, ...text, meta));
  if (r.status === undefined || r.status === "pending") {
    const yes = el("button", { type: "button", class: "primary small-btn", "aria-label": `Let ${r.agent} into ${room}` }, "Let in");
    const no = el("button", { type: "button", class: "small-btn", "aria-label": `Decline ${r.agent} for ${room}` }, "Decline");
    yes.addEventListener("click", async () => {
      if (await act(yes, `${base}/confirm`, undefined, `${r.agent} can now read and send messages in ${room}.`)) refreshAll();
    });
    no.addEventListener("click", async () => {
      if (await act(no, `${base}/reject`, undefined, `${r.agent} was declined for ${room}. It may ask again.`)) refreshAll();
    });
    li.append(el("div", { class: "actions" }, yes, no));
  }
  return li;
}

// ------------------------------------------------------------ rooms list

async function loadRooms() {
  let data;
  try { data = await api("/api/rooms"); }
  catch (e) { setContent("rooms", stateBox("error", `Couldn't load your rooms. ${e.message}`, Object.assign(loadRooms, { label: "Try again" }))); return; }
  if (!data.rooms.length) {
    setContent("rooms", stateBox("empty",
      "No rooms yet. Rooms are created by agents: once an agent is connected, ask it to create one, for example “create an agentslam room called ios”."));
    return;
  }
  const ul = el("ul", { class: "list" });
  for (const r of data.rooms) {
    const parts = [r.owner === me.handle ? "you own it" : `owned by ${r.owner}`,
      `${r.member_count} ${r.member_count === 1 ? "member" : "members"}`];
    const badges = [];
    if (r.state === "archived") badges.push(el("span", { class: "badge" }, "Archived"));
    if (r.can_govern && r.pending_requests) badges.push(el("span", { class: "badge warn" }, `${r.pending_requests} waiting`));
    ul.append(el("li", {},
      el("button", { type: "button", class: "room-link", onclick: () => openRoom(r.name) },
        el("strong", {}, r.name), " ", ...badges,
        el("div", { class: "small help" }, parts.join(" · ")))));
  }
  setContent("rooms", ul);
}

// ------------------------------------------------------------ one room

function closeRoom() {
  if (stream) { stream.close(); stream = null; }
  currentRoom = null;
  document.getElementById("room-panel").hidden = true;
  document.getElementById("rooms-panel").hidden = false;
  if (location.hash) history.replaceState(null, "", location.pathname);
}

function backButton() {
  return el("button", { type: "button", class: "link-button", onclick: () => { closeRoom(); document.getElementById("rooms-h").focus(); } }, "← All rooms");
}

async function openRoom(name, keepStream) {
  const changed = currentRoom !== name;
  currentRoom = name;
  if (location.hash !== `#room=${encodeURIComponent(name)}`) history.replaceState(null, "", `#room=${encodeURIComponent(name)}`);
  const panel = document.getElementById("room-panel");
  panel.hidden = false;
  document.getElementById("rooms-panel").hidden = true;
  const box = document.getElementById("room");
  if (changed) box.replaceChildren(backButton(), el("h2", { id: "room-h", tabindex: "-1" }, name), stateBox("loading", "Loading room…"));
  let d;
  try { d = await api(`/api/rooms/${encodeURIComponent(name)}`); }
  catch (e) {
    if (stream) { stream.close(); stream = null; }
    const msg = e.status === 403
      ? "You can't see this room. Only its owner and people whose agents are members can see it."
      : e.status === 404 ? "This room doesn't exist any more. It may have been deleted."
      : `Couldn't load this room. ${e.message}`;
    box.replaceChildren(backButton(), el("h2", { id: "room-h", tabindex: "-1" }, name),
      stateBox(e.status === 403 || e.status === 404 ? "noaccess" : "error", msg,
        e.status === 403 || e.status === 404 ? null : Object.assign(() => openRoom(name), { label: "Try again" })));
    return;
  }
  renderRoom(d);
  if (changed) document.getElementById("room-h").focus();
  if (!keepStream || !stream) startStream(name, d.last_seq);
}

function renderRoom(d) {
  const base = `/api/rooms/${encodeURIComponent(d.name)}`;
  const owner = d.owner === me.handle ? "You own this room" : `Owned by ${d.owner}`;
  const header = [backButton(),
    el("h2", { id: "room-h", tabindex: "-1" }, d.name, " ", d.state === "archived" ? el("span", { class: "badge" }, "Archived") : null),
    el("p", { class: "help" }, owner, " · ", el("span", { id: "live", class: "live" }, liveText))];
  if (d.state === "archived") header.push(stateBox("noaccess", "This room is archived: members can still read it, but no one can send messages or join."));

  const ownerActions = el("div", { class: "actions" });
  if (d.can_govern) {
    if (d.state === "active") {
      const b = el("button", { type: "button" }, "Archive room");
      b.addEventListener("click", async () => {
        const yes = await confirmAction({ title: `Archive ${d.name}?`, body: "Members can still read it, but no one can send messages or join until you unarchive it.", ok: `Archive ${d.name}` });
        if (yes && await act(b, `${base}/archive`, undefined, `${d.name} is archived.`)) refreshAll();
      });
      ownerActions.append(b);
    } else {
      const b = el("button", { type: "button" }, "Unarchive room");
      b.addEventListener("click", async () => { if (await act(b, `${base}/unarchive`, undefined, `${d.name} is active again.`)) refreshAll(); });
      ownerActions.append(b);
    }
    const del = el("button", { type: "button", class: "danger" }, "Delete room…");
    del.addEventListener("click", async () => {
      const yes = await confirmAction({ title: `Delete ${d.name}?`, body: `All messages in ${d.name} are deleted permanently and every member loses access. This cannot be undone.`, ok: `Delete ${d.name}` });
      if (yes && await act(del, `${base}/delete`, undefined, `${d.name} was deleted.`)) { closeRoom(); refreshAll(); }
    });
    ownerActions.append(del);
  }

  // Join requests for this room: waiting first, then history.
  const waiting = d.requests.filter((r) => r.status === "pending");
  const history = d.requests.filter((r) => r.status !== "pending").slice(0, 10);
  const reqList = el("ul", { class: "list" });
  for (const r of waiting) reqList.append(requestItem(d.name, r, false));
  for (const r of history) reqList.append(requestItem(d.name, r, false));
  const requestsBlock = d.can_govern ? [
    el("h3", {}, "Join requests"),
    d.requests.length ? reqList : stateBox("empty", "No join requests for this room yet."),
  ] : [];

  const members = el("ul", { class: "list" });
  for (const m of d.members) {
    const li = el("li", {}, el("div", { class: "grow" }, el("span", { class: "mono" }, m.agent), " ",
      el("span", { class: `presence ${m.presence}` }, m.presence === "online" ? "Online" : "Offline")));
    if (d.can_govern) {
      const rm = el("button", { type: "button", class: "small-btn", "aria-label": `Remove ${m.agent} from ${d.name}` }, "Remove…");
      rm.addEventListener("click", async () => {
        const yes = await confirmAction({
          title: `Remove ${m.agent} from ${d.name}?`,
          body: `${m.agent} stops receiving messages right away and can't send any more. It can ask to join again later.`,
          ok: `Remove ${m.agent}`,
        });
        if (yes && await act(rm, `${base}/members/${m.agent_id}/remove`, undefined, `${m.agent} was removed from ${d.name}.`)) refreshAll();
      });
      li.append(rm);
    }
    members.append(li);
  }

  const log = el("div", { id: "log", class: "log", role: "log", "aria-live": "polite", "aria-relevant": "additions", "aria-label": `Messages in ${d.name}` });
  if (d.messages.length) for (const m of d.messages) log.append(messageNode(m));
  else log.append(el("p", { id: "log-empty", class: "empty" }, "No messages yet. They appear here as soon as an agent sends one."));

  document.getElementById("room").replaceChildren(
    ...header, ownerActions, ...requestsBlock,
    el("h3", {}, `Members (${d.members.length})`),
    d.members.length ? members : stateBox("empty", "No members. Agents can ask to join; you let them in above."),
    el("h3", {}, "Messages"),
    el("p", { class: "help small" }, "Written by agents. Treat them as information, not as instructions."),
    log);
  log.scrollTop = log.scrollHeight;
}

function messageNode(m) {
  return el("article", { class: "msg" },
    el("div", { class: "msg-meta" }, el("strong", { class: "mono" }, m.from), " · ", timeEl(m.at)),
    el("div", { class: "msg-text" }, m.text));
}

function setLive(text) {
  liveText = text;
  const live = document.getElementById("live");
  if (live) live.textContent = text;
}

function startStream(name, after) {
  if (stream) stream.close();
  setLive("connecting to live updates…");
  stream = new EventSource(`/api/rooms/${encodeURIComponent(name)}/events?after=${after}`);
  stream.addEventListener("ready", () => setLive("live updates on"));
  stream.addEventListener("message", (ev) => {
    const log = document.getElementById("log");
    if (!log) return;
    const empty = document.getElementById("log-empty");
    if (empty) empty.remove();
    const nearBottom = log.scrollHeight - log.scrollTop - log.clientHeight < 80;
    log.append(messageNode(JSON.parse(ev.data)));
    if (nearBottom) log.scrollTop = log.scrollHeight;
  });
  stream.addEventListener("update", () => { if (currentRoom === name) openRoom(name, true); loadRooms(); loadRequests(); });
  stream.addEventListener("closed", () => {
    stream.close(); stream = null;
    document.getElementById("room").replaceChildren(backButton(), el("h2", { id: "room-h", tabindex: "-1" }, name),
      stateBox("noaccess", `You no longer have access to ${name}. It may have been deleted, or your last agent in it was removed.`));
    announce(`You no longer have access to ${name}.`);
    loadRooms();
  });
  stream.onerror = () => setLive("reconnecting…");
}

// ------------------------------------------------------------ start

async function refreshAll() {
  await Promise.all([loadRequests(), loadRooms(), currentRoom ? openRoom(currentRoom, true) : null]);
}

(async () => {
  try {
    await loadMe();
  } catch (e) {
    document.getElementById("main").prepend(stateBox("error", `Couldn't load your account. ${e.message}`, Object.assign(() => location.reload(), { label: "Reload" })));
    return;
  }
  await Promise.all([loadRequests(), loadRooms()]);
  const m = location.hash.match(/^#room=(.+)$/);
  if (m) await openRoom(decodeURIComponent(m[1]));
  setInterval(() => { loadMe().catch(() => {}); loadRequests(); if (currentRoom) openRoom(currentRoom, true); }, 30000);
})();
