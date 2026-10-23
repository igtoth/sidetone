// Sidetone UI: softphone panel + workspace (calls, SIP trace, analysis,
// diagnostics, settings). One frontend for three hosts:
//  - desktop app / `sidetone serve`: native engine over the local HTTP API
//  - GitHub Pages: WASM analysis and a WebRTC phone (SIP over WebSocket)

import { NativeController, WebController, webAccountDefaults } from "./controllers.js";
import { initI18n, currentLang, setLang, LANGS, t } from "./i18n.js";
import { renderHelp } from "./help.js";
import { renderExplain, sdpTable, headerHelp, statusHelp } from "./explain.js";
import { compileFilter } from "./filter.js";
import { attachSuggest } from "./filter-suggest.js";
import { trFinding } from "./findings-i18n.js";

const $ = (s, el = document) => el.querySelector(s);
const $$ = (s, el = document) => [...el.querySelectorAll(s)];
const esc = (s) => String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

const store = {
  get(k, d) {
    try { const v = localStorage.getItem(k); return v === null ? d : JSON.parse(v); } catch { return d; }
  },
  set(k, v) {
    try { localStorage.setItem(k, JSON.stringify(v)); } catch { /* storage unavailable */ }
  },
};

const token = new URLSearchParams(location.search).get("token");
/// Ladder option: RTP streams after the SIP instead of in time order.
const rtpAtEnd = () => store.get("sidetone.ladder.rtp_end", false);
const ladTime = () => store.get("sidetone.ladder.time", "rel");
const ladRetx = () => store.get("sidetone.ladder.fold_retx", false);
// Bit flags for the WASM ladder: 1 RTP at end, 2 fold retransmissions, 4 delta time, 8 clock time.
const ladFlags = () => (rtpAtEnd() ? 1 : 0) | (ladRetx() ? 2 : 0) | (ladTime() === "delta" ? 4 : ladTime() === "abs" ? 8 : 0);

// ---------- analysis backends ----------

async function wasmBackend() {
  const w = await import("./pkg/sidetone_wasm.js");
  await w.default();
  return {
    kind: "wasm",
    features: [],
    analyze: async (b) => JSON.parse(w.analyze(b)),
    ladder: async (b, call) => (w.ladder_svg_flags ? w.ladder_svg_flags(b, call ?? -1, "", ladFlags()) : w.ladder_svg_opts ? w.ladder_svg_opts(b, call ?? -1, "", rtpAtEnd()) : w.ladder_svg(b, call ?? -1)),
    ladderCalls: async (b, calls) => (w.ladder_svg_flags ? w.ladder_svg_flags(b, -1, calls.join(","), ladFlags()) : w.ladder_svg_opts ? w.ladder_svg_opts(b, -1, calls.join(","), rtpAtEnd()) : w.ladder_svg_calls(b, calls.join(","))),
    rtpAudio: async (b, id) => {
      try {
        return { wav: w.rtp_audio(b, id) };
      } catch (e) {
        let j = null;
        try { j = JSON.parse(e.message); } catch { throw e; }
        return { frames: j };
      }
    },
    exportPcap: async (b, opts) => w.export_capture(b, JSON.stringify(opts)),
    prompt: async (b, call, redact, lang, q) => JSON.parse(w.ai_prompt(b, call ?? -1, redact, lang, q || "")),
    ai: async (cfg, system, prompt) => {
      const req = JSON.parse(w.ai_request(JSON.stringify(cfg), system, prompt));
      let res;
      try {
        res = await fetch(req.url, { method: "POST", headers: Object.fromEntries(req.headers), body: req.body });
      } catch {
        throw new Error(`Could not reach ${req.url}. ${cfg.provider === "ollama" ? "Start Ollama with OLLAMA_ORIGINS set to this page's origin." : "The provider may block browser requests (CORS); use the desktop app or `sidetone serve`."}`);
      }
      return w.ai_parse(cfg.provider, await res.text());
    },
    samples: async () => JSON.parse(w.samples()),
    sample: async (n) => w.sample(n),
    captureFromLog: async (log) => w.capture_from_sip_log(JSON.stringify(log)),
    parseProvision: async (xml, kind) => {
      try {
        return JSON.parse(w.parse_provision(xml, kind));
      } catch (e) {
        throw new Error(e.message || String(e));
      }
    },
  };
}

async function httpBackend() {
  const headers = token ? { "x-sidetone-token": token } : {};
  const info = await (await fetch("api/info", { headers })).json();
  const check = async (r) => {
    if (!r.ok) {
      let msg = `${r.status}`;
      try { msg = (await r.json()).error || msg; } catch { /* not JSON */ }
      throw new Error(msg);
    }
    return r;
  };
  const post = async (path, body, type = "application/octet-stream") => check(await fetch(path, { method: "POST", headers: { ...headers, "content-type": type }, body }));
  const get = async (path) => check(await fetch(path, { headers }));
  const q = (o) => new URLSearchParams(Object.entries(o).filter(([, v]) => v !== null && v !== undefined && v !== false).map(([k, v]) => [k, v === true ? "1" : String(v)])).toString();
  return {
    kind: "http",
    features: info.features || [],
    get,
    post,
    analyze: async (b) => (await post("api/analyze", b)).json(),
    ladder: async (b, call) => (await post(`api/ladder?${q({ call, rtp: rtpAtEnd() ? "end" : null, retx: ladRetx() ? "fold" : null, time: ladTime() })}`, b)).text(),
    ladderCalls: async (b, calls) => (await post(`api/ladder?${q({ calls: calls.join(","), rtp: rtpAtEnd() ? "end" : null, retx: ladRetx() ? "fold" : null, time: ladTime() })}`, b)).text(),
    rtpAudio: async (b, id) => ({ wav: new Uint8Array(await (await post(`api/rtp_audio?${q({ stream: id })}`, b)).arrayBuffer()) }),
    exportPcap: async (b, o) => new Uint8Array(await (await post(`api/export?${q({ call: o.call, redact: o.redact, sip_only: o.sip_only, no_annotate: o.annotate === false })}`, b)).arrayBuffer()),
    prompt: async (b, call, redact, lang, question) => (await post(`api/prompt?${q({ call, redact, lang, question })}`, b)).json(),
    ai: async (cfg, _system, prompt) => (await (await post("api/ai", JSON.stringify({ config: cfg, prompt }), "application/json")).json()).text,
    samples: async () => [
      ["good-call", "Registration with digest auth and a clean call with RFC 4733 DTMF"],
      ["nat-one-way", "Remote phone behind NAT: private SDP, missing ACK, one-way audio, drop at 32 s"],
      ["codec-488", "Carrier rejects a G.729-only offer with 488"],
      ["bad-quality", "Answered call with packet loss, jitter and a dropout"],
      ["register-timeout", "REGISTER retransmitted to a registrar that never answers"],
      ["srtp-mismatch", "SRTP offered, plain RTP answered"],
      ["demo", "All scenarios in one capture"],
    ].map(([name, description]) => ({ name, description })),
    sample: async (n) => new Uint8Array(await (await get(`api/sample?${q({ name: n })}`)).arrayBuffer()),
    captureFromLog: async (log) => new Uint8Array(await (await post("api/sip-log-capture", JSON.stringify(log), "application/json")).arrayBuffer()),
    setWindow: (mode) => post(`api/window?${q({ mode })}`, new Uint8Array()),
    save: (info.features || []).includes("native-save") ? async (data, name) => (await post(`api/save?${q({ name })}`, data)).json() : null,
  };
}

async function pickBackend() {
  try {
    return await httpBackend();
  } catch {
    return await wasmBackend();
  }
}

// ---------- state ----------

const S = {
  scroll: {}, // scrollTop per workspace
  tab: "explain", // analysis detail tab
  hiddenEnded: new Set(),
  picked: new Set(), // dialogs ticked for a combined ladder
  be: null,
  ctl: null,
  st: null, // latest PhoneState
  sel: null, // selected line
  events: [],
  trace: [],
  trSel: null,
  trPaused: false,
  history: [],
  recordings: [],
  xfer: null, // { from, consult }
  errors: 0,
  // analysis
  bytes: null, name: "", report: null, call: null, msg: null, webrtc: null,
};
window.__sidetone = S;

function toast(text, ms = 2800) {
  const t = $("#toast");
  t.textContent = text;
  // A long timeout is how callers mark a problem: red edge instead of green.
  t.classList.toggle("bad", ms >= 4000);
  t.classList.add("show");
  clearTimeout(toast.h);
  toast.h = setTimeout(() => t.classList.remove("show"), ms);
}

async function download(data, name, type) {
  if (S.be && S.be.save) {
    const r = await S.be.save(data, name);
    if (r.saved) toast(`Saved ${r.saved}`);
    return;
  }
  const url = URL.createObjectURL(new Blob([data], { type }));
  const a = Object.assign(document.createElement("a"), { href: url, download: name });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

const pad = (n, w = 2) => String(n).padStart(w, "0");
function dur(ms) {
  if (ms == null || ms < 0) return "";
  const s = Math.floor(ms / 1000);
  const h = Math.floor(s / 3600);
  return h ? `${h}:${pad(Math.floor((s % 3600) / 60))}:${pad(s % 60)}` : `${Math.floor(s / 60)}:${pad(s % 60)}`;
}
function clock(ms, withMs = false) {
  const d = new Date(ms);
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}${withMs ? "." + pad(d.getMilliseconds(), 3) : ""}`;
}
function when(ms) {
  const d = new Date(ms);
  const today = new Date();
  const same = d.toDateString() === today.toDateString();
  return same ? clock(ms) : `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}
const setMeter = (el, pct) => {
  if (el) el.style.width = `${100 - pct}%`;
};
const levelPct = (v) => {
  if (!v) return 0;
  const db = 20 * Math.log10(v / 32767);
  return Math.max(0, Math.min(100, ((db + 60) / 60) * 100));
};

// ---------- workspace ----------

// Only touches the DOM when the HTML changed, so focus, selection and the
// text the user is copying survive the state polling.
function setHtml(el, html) {
  if (!el) return;
  if (el.dataset.sig === html) return;
  el.dataset.sig = html;
  el.innerHTML = html;
}

// Live durations are rendered as <span data-since="ms"> and ticked in place.
const durSpan = (since, cls = "") => `<span class="${cls}" data-since="${since}">${dur(Date.now() - since)}</span>`;
function tickDurations() {
  const now = Date.now();
  $$("[data-since]").forEach((el) => {
    const v = dur(now - +el.dataset.since);
    if (el.textContent !== v) el.textContent = v;
  });
}

// Work that a page reload would lose.
const unsavedWork = () => Boolean((S.bytes && !LIVE.on) || SET.dirty || DOCK.turns.length);
const langGuard = () => !unsavedWork() || confirm(t("Changing the language reloads the page: the open capture and unsaved settings are lost. Continue?"));

const PAGES = ["calls", "trace", "analysis", "diag", "settings", "help"];

// The URL mirrors where the user is (?page=, &set= for a settings section or
// account, &tab= in Analysis), so reload, Back and links land on the same view.
function syncUrl(push = false) {
  const q = new URLSearchParams();
  q.set("page", S.page);
  if (S.page === "settings") {
    if (SET.section) q.set("set", SET.section);
    else if (SET.accId) q.set("set", `acc:${SET.accId}`);
  }
  if (S.page === "analysis" && S.tab && S.tab !== "explain") q.set("tab", S.tab);
  const url = `?${q}`;
  if (url === location.search) return;
  try {
    if (push) history.pushState({ page: S.page }, "", url);
    else history.replaceState({ page: S.page }, "", url);
  } catch {
    /* file:// or sandboxed */
  }
}

// Arrow keys, Home and End move between the tabs of a tablist.
function tablistKeys(list) {
  list.addEventListener("keydown", (e) => {
    const tabs = $$('[role="tab"]:not([hidden])', list);
    const i = tabs.indexOf(document.activeElement);
    if (i < 0) return;
    const j = { ArrowRight: i + 1, ArrowLeft: i - 1, Home: 0, End: tabs.length - 1 }[e.key];
    if (j == null) return;
    e.preventDefault();
    const tgt = tabs[(j + tabs.length) % tabs.length];
    tgt.focus();
    tgt.click();
  });
}

// A wide ladder (many columns) scrolls sideways; the edge fade says so.
function ladderScrollHint() {
  const el = $("#ladder");
  if (!el) return;
  const wrap = el.closest(".ladder-wrap");
  const check = () => wrap && wrap.classList.toggle("scroll-x", el.scrollWidth > el.clientWidth + 2 && el.scrollLeft + el.clientWidth < el.scrollWidth - 2);
  check();
  if (!el.dataset.scrollHint) {
    el.dataset.scrollHint = "1";
    el.addEventListener("scroll", check, { passive: true });
    window.addEventListener("resize", check);
  }
}

function showWs(name, push = true) {
  if (!PAGES.includes(name)) name = "calls";
  // Phone-only mode has no trace, analysis or diagnostics: leaving it is explicit.
  if (document.body.classList.contains("phone-mode") && ["trace", "analysis", "diag"].includes(name)) {
    if (!document.body.classList.contains("compact")) {
      store.set("sidetone.mode", "troubleshoot");
      S.applyMode && S.applyMode("troubleshoot");
      toast(t("Switched to troubleshooting mode"));
    } else {
      name = "calls";
    }
  }
  // Scroll position is kept per page.
  if (S.page && S.page !== name) S.scroll[S.page] = $("#ws") ? $("#ws").scrollTop : 0;
  $$(".ws-tabs [data-ws]").forEach((b) => b.setAttribute("aria-selected", String(b.dataset.ws === name)));
  $$(".ws-page").forEach((p) => (p.hidden = p.dataset.page !== name));
  const changed = S.page !== name;
  S.page = name;
  store.set("sidetone.page", name);
  if (changed && push) syncUrl(true);
  else syncUrl(false);
  if ($("#ws")) $("#ws").scrollTop = S.scroll[name] || 0;
  if (name === "trace") renderTrace(true);
  if (name === "diag") diagOpen();
  if (name === "settings") settingsOpen();
  if (name === "calls") {
    renderHistory();
    renderActive();
  }
  if (name === "help") {
    renderHelp($("#help-page"), {
      lang: currentLang(),
      version: S.version,
      mode: t(engineModeLabel()),
      langs: LANGS,
      onLang: (c) => setLang(c, langGuard),
    });
  }
}

// ============================================================================
// Phone panel

const STATE_TEXT = { calling: "Calling", ringing: "Ringing", early: "Early media", incoming: "Incoming", connected: "Connected", ending: "Ending", ended: "Ended" };

function lines() {
  return S.st ? S.st.calls : [];
}
function line(id) {
  return lines().find((l) => l.line === id) || null;
}
function selLine() {
  return line(S.sel);
}
function liveLines() {
  return lines().filter((l) => l.state !== "ended");
}

function pickSelection() {
  const cur = selLine();
  const live = liveLines();
  if (cur && cur.state !== "ended") return;
  const incoming = live.find((l) => l.state === "incoming");
  const talking = live.find((l) => l.state === "connected" && !l.held);
  const next = incoming || talking || live[live.length - 1] || (cur ? cur : null);
  S.sel = next ? next.line : null;
}

function accLabel(a) {
  return a.label || `${a.user}@${a.domain}`;
}

function currentAccount() {
  const st = S.st;
  if (!st || !st.accounts.length) return null;
  const id = $("#acct").value;
  return st.accounts.find((a) => a.id === id) || st.accounts[0];
}

function engineModeLabel() {
  if (S.ctl.kind === "web") return "Browser phone (WebRTC)";
  const tr = (currentAccount()?.transport || "UDP").toUpperCase();
  return `Desktop engine (${tr === "TCP" || tr === "TLS" ? tr : "UDP"})`;
}

const REG_TEXT = {
  registered: "Registered",
  registering: "Registering",
  unregistering: "Unregistering",
  failed: "Registration failed",
  unreachable: "Server not answering",
  error: "Not ready",
  off: "Not registered",
};

function regClass(a) {
  if (!a || !a.enabled) return "off";
  return { registered: "ok", registering: "busy", unregistering: "busy", failed: "bad", unreachable: "bad", error: "bad" }[a.state] || (a.register ? "off" : "idle");
}

function accountStateText(a) {
  if (!a) return S.ctl && S.ctl.kind === "web" ? "Add a WebSocket SIP account in Settings to start." : "No account yet. Add one in Settings.";
  if (!a.enabled) return "Account disabled";
  if (a.state === "registered") return `Registered as ${a.user} at ${a.server || a.domain}${a.expires_in != null ? `, renews in ${a.expires_in > 90 ? Math.round(a.expires_in / 60) + " min" : a.expires_in + " s"}` : ""}`;
  if (a.state === "failed") return `Registration failed: ${a.code ?? ""} ${a.reason ?? ""}`.trim();
  if (a.state === "unreachable") return `${a.server || a.domain} is not answering. Check address, port and firewall.`;
  if (a.state === "error") return a.error || "Not ready";
  if (!a.register && !a.domain) return `Direct calls, no registrar: dial user@host or a SIP URI (port ${(a.local || "").split(":").pop()})`;
  if (a.state === "off" && !a.register) return `Ready to call from ${a.local || "here"} (registration off)`;
  return REG_TEXT[a.state] || a.state;
}

function renderAccounts() {
  const st = S.st;
  const sel = $("#acct");
  const want = sel.value || store.get("sidetone.acct", "");
  const opts = st.accounts.map((a) => `<option value="${esc(a.id)}">${esc(accLabel(a))}</option>`).join("");
  if (sel.dataset.sig !== opts) {
    sel.innerHTML = opts || `<option value="">No account</option>`;
    sel.dataset.sig = opts;
    if (st.accounts.some((a) => a.id === want)) sel.value = want;
  }
  const a = currentAccount();
  $("#acct-dot").className = `dot ${regClass(a)}`;
  const bad = !!a && regClass(a) === "bad";
  // A problem with the account: a real button opens it in Settings.
  setHtml($("#acct-state"), `${esc(t(accountStateText(a)))}${bad ? ` <button type="button" class="linklike" data-open-acc="${esc(a.id)}">${esc(t("Open the account"))}</button>` : ""}`);
  $("#acct-state").classList.toggle("bad", bad);
}

const BLF_TEXT = { idle: "Free", ringing: "Ringing", busy: "Busy", error: "Error", unknown: "Unknown" };
const PRES_TEXT = { available: "Available", away: "Away", busy: "Busy", dnd: "Do not disturb", offline: "Offline", unknown: "Unknown" };

function renderBlf() {
  const a = currentAccount();
  const items = a && a.blf ? a.blf : [];
  $("#blf-box").hidden = !items.length;
  setHtml($("#blf"), items
    .map((b) => {
      // A watched phone that is not registered reads as Offline, not Free.
      const lamp = b.presence === "offline" && b.state === "idle" ? "" : t(BLF_TEXT[b.state] || b.state);
      // Presence adds to the lamp only when it says something the lamp does not.
      const pres = b.presence && !(b.presence === "available" && b.state === "idle") && !(b.presence === "busy" && b.state !== "idle") ? t(PRES_TEXT[b.presence] || b.presence) : "";
      const note = b.note && !/^(ready|on the phone|ringing|unavailable)$/i.test(b.note) ? b.note : "";
      const sub = [lamp, pres, note].filter(Boolean).join(" · ");
      const title = [b.detail, b.presence ? `${t("Presence")}: ${t(PRES_TEXT[b.presence] || b.presence)}${b.note ? ` (${b.note})` : ""}` : ""].filter(Boolean).join("\n");
      return `<button type="button" class="blf-item blf-${esc(b.state)}${b.presence ? ` pres-${esc(b.presence)}` : ""}" data-dial="${esc(b.target)}" title="${esc(title)}"><span class="dot"></span><span class="blf-t">${esc(b.target)}</span><span class="blf-s">${esc(sub)}</span></button>`;
    })
    .join(""));
  // Call forwarding in force.
  const fs = S.st ? S.st.settings : {};
  const fwd = [
    fs.forward_always && `${t("All calls forwarded to")} ${fs.forward_always}`,
    !fs.forward_always && fs.forward_busy && `${t("Busy: forwarded to")} ${fs.forward_busy}`,
    !fs.forward_always && fs.forward_no_answer && `${t("No answer")} (${fs.forward_no_answer_s} s): ${fs.forward_no_answer}`,
  ].filter(Boolean);
  $("#fwd-note").hidden = !fwd.length;
  $("#fwd-note").textContent = fwd.join(" · ");
  // Voicemail lamp (message-summary NOTIFY).
  const vm = a && a.mwi;
  $("#vm-btn").hidden = !vm;
  if (vm) {
    $("#vm-btn").classList.toggle("on", !!vm.waiting);
    $("#vm-text").textContent = vm.waiting ? `${t("Voicemail")}: ${vm.new} ${t("new")}${vm.old ? `, ${vm.old} ${t("old")}` : ""}` : `${t("Voicemail")}: ${t("no new messages")}`;
  }
  const native = S.ctl.kind === "native";
  $("#pres-row").hidden = !native || !a || a.register === false;
  if (native && a) {
    const sel = $("#my-pres");
    if (document.activeElement !== sel) sel.value = a.presence || "";
    const note = $("#my-pres-note");
    if (document.activeElement !== note && !note.dataset.dirty) note.value = a.presence_note || "";
    note.hidden = !a.presence;
    $("#pres-dot").className = `dot pres-${a.presence || "none"}`;
    $("#pres-err").hidden = !a.presence_error;
    $("#pres-err").textContent = a.presence_error ? `${t("The server did not take the presence")}: ${a.presence_error}` : "";
  }
}

function publishPresence() {
  const a = currentAccount();
  if (!a) return;
  const note = $("#my-pres-note");
  note.dataset.dirty = "";
  cmd({ cmd: "presence", account: a.id, status: $("#my-pres").value || "available", note: note.value.trim() });
}

function renderLines() {
  const ls = lines();
  $("#lines-empty").hidden = ls.length > 0;
  const live = liveLines().length;
  const max = S.st ? S.st.settings.max_lines : 1;
  $("#lines-count").textContent = ls.length ? `${live} of ${S.ctl.features.multiLine ? max : 1}` : "";
  const now = Date.now();
  setHtml($("#lines"), ls
    .map((l) => {
      const tm = l.state === "connected" && l.answered_ms ? durSpan(l.answered_ms) : l.state === "ended" ? (l.answered_ms ? dur((l.ended_ms || now) - l.answered_ms) : "") : durSpan(l.started_ms);
      const stTxt = l.state === "connected" && l.held ? "On hold" : l.state === "connected" && l.remote_held ? "Held by remote" : STATE_TEXT[l.state] || l.state;
      const multi = S.st && S.st.accounts.length > 1;
      const meta = [
        multi ? accName(l.account) : "",
        l.srtp ? "SRTP" : "",
        l.conference ? `${t("Conference")} L${l.conference}` : "",
        l.codec,
        l.state !== "incoming" && (l.rtp_sent || l.rtp_received) ? `↑${l.rtp_sent} ↓${l.rtp_received}` : "",
        l.muted ? "muted" : "",
        l.recording ? "recording" : "",
        l.state === "ended" ? resultText(l.final_code, l.reason) : "",
        l.transfer || "",
      ].filter(Boolean).map(esc).join(" · ");
      const actions =
        l.state === "incoming"
          ? `<div class="ln-act"><button type="button" class="btn small ok" data-act="answer">Answer</button><button type="button" class="btn small" data-act="reject">Reject</button>${S.ctl.kind === "native" ? `<button type="button" class="btn small" data-act="forward" title="${esc(t("Redirect the call (302) to the number typed in the dial field"))}">${esc(t("Forward"))}</button>` : ""}</div>`
          : l.state === "connected" && l.held
          ? `<div class="ln-act"><button type="button" class="btn small" data-act="resume">Resume</button><button type="button" class="btn small" data-act="hangup">Hang up</button></div>`
          : "";
      const cls = `line st-${l.state}${l.held ? " held" : ""}${l.line === S.sel ? " sel" : ""}`;
      return `<li class="${cls}" data-line="${l.line}" tabindex="0">
        <div class="ln-top"><span class="ln-dir"><svg><use href="#i-${l.direction === "in" ? "in" : "out"}"/></svg></span><span class="ln-state">${esc(stTxt)}</span><span class="ln-dur">${tm}</span></div>
        <div class="ln-remote">${l.remote_name ? `<b>${esc(l.remote_name)}</b> ` : ""}<span>${esc(l.remote)}</span></div>
        ${meta ? `<div class="ln-meta">${meta}</div>` : ""}${actions}
      </li>`;
    })
    .join(""));
}

function renderControls() {
  const l = selLine();
  const live = l && l.state !== "ended";
  const connected = l && l.state === "connected";
  const incoming = l && l.state === "incoming";
  if (incoming) document.body.classList.remove("compact-open");
  const callBtn = $("#btn-call");
  callBtn.querySelector("span").textContent = incoming ? "Answer" : "Call";
  callBtn.classList.toggle("pulse", !!incoming);
  $("#btn-hangup").disabled = !live;
  $("#btn-hangup").querySelector("span").textContent = incoming ? "Reject" : l && ["calling", "ringing", "early"].includes(l.state) ? "Cancel" : "Hang up";
  const tool = (n) => $(`.tool[data-tool="${n}"]`);
  tool("hold").disabled = !connected;
  tool("hold").setAttribute("aria-pressed", String(!!(connected && l.held)));
  tool("hold").querySelector("span").textContent = connected && l.held ? "Resume" : "Hold";
  tool("mute").disabled = !(connected || (l && l.state === "early"));
  tool("mute").setAttribute("aria-pressed", String(!!(l && l.muted)));
  tool("transfer").disabled = !connected;
  tool("record").disabled = !(connected && S.ctl.features.record);
  const others = liveLines().filter((x) => x.state === "connected" && (!l || x.line !== l.line));
  tool("conf").hidden = !(S.ctl.kind === "native" || S.ctl.features.conference);
  tool("conf").disabled = !(connected && (l.conference || others.length));
  tool("conf").setAttribute("aria-pressed", String(!!(l && l.conference)));
  tool("record").setAttribute("aria-pressed", String(!!(l && l.recording)));
  const st = S.st ? S.st.settings : {};
  tool("dnd").setAttribute("aria-pressed", String(!!st.dnd));
  tool("aa").setAttribute("aria-pressed", String(!!st.auto_answer));
  // Complete-transfer button appears once the consult call is up.
  if (S.xfer && S.xfer.consult) {
    const c = line(S.xfer.consult);
    const f = line(S.xfer.from);
    const ready = c && c.state === "connected" && f && f.state === "connected";
    $("#xfer-complete").hidden = !ready;
    $("#xfer-note").textContent = ready ? "Talk to the new party, then complete the transfer." : c && c.state !== "ended" ? `Consult call: ${STATE_TEXT[c.state] || c.state}` : "Consult call ended.";
  }
}

function renderMeters() {
  let l = selLine() || liveLines().find((x) => x.state === "connected");
  if (l && l.state === "ended") l = null;
  setMeter($("#m-tx"), l ? levelPct(l.tx_level) : 0);
  setMeter($("#m-rx"), l ? levelPct(l.rx_level) : 0);
  const st = S.st;
  let src = "";
  if (S.ctl.kind === "web") src = "Browser microphone and speaker";
  else if (st) {
    const s = st.settings.audio_source;
    src = s === "device" ? (st.audio_device ? "Sound card" : "No sound card: sending a test tone") : s === "tone" ? `Test tone ${st.settings.tone_hz} Hz` : s === "echo" ? "Echoing received audio" : "Sending silence";
  }
  $("#audio-src").textContent = src;
}

function renderStatus() {
  const st = S.st;
  const a = currentAccount();
  $("#st-acct").innerHTML = `<span class="dot ${regClass(a)}"></span><span>${a ? `${esc(accLabel(a))}: ${esc(REG_TEXT[a.state] || a.state)}` : "No account"}</span>`;
  $("#st-net").textContent = a && a.local ? (S.ctl.kind === "web" ? `WSS ${a.server || ""}` : `${a.transport || "UDP"} ${a.local} → ${a.server || "direct"}`) : "";
  $("#st-nat").textContent = !a || !a.public ? "" : S.ctl.kind === "web" ? `Server sees ${a.public}` : a.public !== a.local ? `Seen as ${a.public} (NAT)` : "No NAT on the signaling path";
  const live = liveLines().length;
  $("#st-lines").textContent = live ? `${live} call${live > 1 ? "s" : ""}` : "Idle";
  $("#st-cap").textContent = st ? `${st.capture_packets.toLocaleString()} packets captured` : "";
  $("#st-mode").textContent = t(engineModeLabel());
  const dec = $("#tr-save-dec");
  if (dec) dec.hidden = !(st && st.capture_srtp);
  $("#trace-count").textContent = S.trace.length ? S.trace.length.toLocaleString() : "";
  const e = $("#st-err");
  e.hidden = !S.errors;
  e.textContent = `${S.errors} problem${S.errors === 1 ? "" : "s"}`;
}

let lastIncoming = new Set();
function onState(st) {
  const prev = S.st;
  S.st = st;
  // New incoming calls take the selection and the user's attention.
  const inc = st.calls.filter((c) => c.state === "incoming").map((c) => c.line);
  for (const id of inc) {
    if (!lastIncoming.has(id)) {
      S.sel = id;
      const c = line(id);
      toast(`Incoming call from ${c.remote_name || c.remote}`);
      flashTitle(`Incoming: ${c.remote_name || c.remote}`);
      followCall(id);
    }
  }
  lastIncoming = new Set(inc);
  // Lines that just ended with a recording become downloadable.
  if (prev) {
    for (const c of st.calls) {
      const was = prev.calls.find((p) => p.line === c.line);
      if (was && was.state !== "ended" && c.state === "ended") {
        if (c.recording && S.ctl.features.record) S.recordings.unshift({ line: c.line, remote: c.remote, ended: c.ended_ms });
        if (S.page === "calls") setTimeout(renderHistory, 400);
      }
    }
  }
  pickSelection();
  announceActions();
  liveTick();
  renderAccounts();
  renderBlf();
  renderLines();
  renderControls();
  renderMeters();
  renderStatus();
  if (S.page === "calls") renderCallDetail();
  if (S.page === "calls") renderActive();
  if (S.page === "calls" && !prev) renderHistory();
  if (S.page === "settings" && SET.cfg) {
    renderSetNav();
    renderAccReg();
  }
}

function flashTitle(text) {
  clearInterval(flashTitle.t);
  let on = false;
  flashTitle.t = setInterval(() => {
    const ringing = liveLines().some((l) => l.state === "incoming");
    if (!ringing) {
      document.title = "Sidetone";
      clearInterval(flashTitle.t);
      return;
    }
    on = !on;
    document.title = on ? text : "Sidetone";
  }, 900);
}

async function cmd(o, quiet = false) {
  try {
    return await S.ctl.cmd(o);
  } catch (e) {
    if (!quiet) toast(e.message || String(e), 4500);
    return null;
  }
}

function parseHeaders(text) {
  return text
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean)
    .map((l) => {
      const i = l.indexOf(":");
      return i > 0 ? [l.slice(0, i).trim(), l.slice(i + 1).trim()] : null;
    })
    .filter(Boolean);
}

function rememberDialed(t) {
  const h = store.get("sidetone.dialed", []).filter((x) => x !== t);
  h.unshift(t);
  store.set("sidetone.dialed", h.slice(0, 30));
  renderDialHistory();
}
function renderDialHistory() {
  $("#dial-history").innerHTML = store.get("sidetone.dialed", []).map((t) => `<option value="${esc(t)}">`).join("");
}

async function dial(target) {
  target = (target ?? $("#dial").value).trim();
  if (!target) {
    $("#dial").focus();
    return;
  }
  const a = currentAccount();
  const req = { cmd: "call", target, account: a ? a.id : null };
  const hdr = parseHeaders($("#opt-headers").value);
  if (hdr.length) req.headers = hdr;
  const ov = $("#opt-overrides").value.trim();
  if (ov && S.ctl.features.overrides) {
    try {
      req.overrides = JSON.parse(ov);
    } catch (e) {
      dialError(`${t("Profile overrides are not valid JSON")}: ${e.message}`);
      return;
    }
  }
  // Codecs chosen for this call only.
  const cc = S.ctl.features.overrides ? readCodecPicker($("#opt-codecs"), null) : null;
  if (cc && cc.length) req.overrides = { ...(req.overrides || {}), codecs: cc };
  rememberDialed(target);
  dialError("");
  let r;
  try {
    r = await S.ctl.cmd(req);
  } catch (e) {
    // The reason stays under the dial field until the next attempt.
    dialError(e.message || String(e));
    return null;
  }
  if (r && r.line) S.sel = r.line;
  return r;
}

function dialError(text) {
  const el = $("#dial-err");
  if (!el) return;
  el.hidden = !text;
  el.textContent = text;
}

async function callOrAnswer() {
  const l = selLine();
  if (l && l.state === "incoming") return cmd({ cmd: "answer", line: l.line });
  const r = await dial();
  if (r && r.line) followCall(r.line);
  return r;
}

function hangupSel() {
  const l = selLine();
  if (!l || l.state === "ended") return;
  if (l.state === "incoming") return cmd({ cmd: "reject", line: l.line, code: 486 });
  return cmd({ cmd: "hangup", line: l.line });
}

// DTMF frequencies (ITU-T Q.23) for the keypad's local feedback tone.
const DTMF_HZ = { 1: [697, 1209], 2: [697, 1336], 3: [697, 1477], A: [697, 1633], 4: [770, 1209], 5: [770, 1336], 6: [770, 1477], B: [770, 1633], 7: [852, 1209], 8: [852, 1336], 9: [852, 1477], C: [852, 1633], "*": [941, 1209], 0: [941, 1336], "#": [941, 1477], D: [941, 1633] };
let keyCtx = null;
function keyTone(k) {
  if (!store.get("sidetone.key_tones", true)) return;
  const f = DTMF_HZ[k];
  if (!f) return;
  try {
    keyCtx ||= new (window.AudioContext || window.webkitAudioContext)();
    if (keyCtx.state === "suspended") keyCtx.resume();
    const t0 = keyCtx.currentTime;
    const g = keyCtx.createGain();
    g.gain.setValueAtTime(0, t0);
    g.gain.linearRampToValueAtTime(0.12, t0 + 0.005);
    g.gain.setValueAtTime(0.12, t0 + 0.13);
    g.gain.linearRampToValueAtTime(0, t0 + 0.15);
    g.connect(keyCtx.destination);
    for (const hz of f) {
      const o = keyCtx.createOscillator();
      o.frequency.value = hz;
      o.connect(g);
      o.start(t0);
      o.stop(t0 + 0.16);
    }
  } catch {
    /* no audio output available */
  }
}

function keyPress(k) {
  keyTone(k);
  const b = $(`#keypad [data-key="${CSS.escape(k)}"]`);
  if (b) {
    b.classList.add("hit");
    setTimeout(() => b.classList.remove("hit"), 140);
  }
  const l = selLine();
  if (l && (l.state === "connected" || l.state === "early")) cmd({ cmd: "dtmf", line: l.line, digits: k });
  else {
    const d = $("#dial");
    d.value += k;
  }
}

// ---- Live analysis: the ladder, log and findings follow the call as it happens

const LIVE = { on: false, line: null, busy: false, last: 0, size: -1, endedAt: 0 };

/// Opens the call being placed or received: Analysis (live) when troubleshooting,
/// the Calls page in phone-only mode.
function followCall(lineId) {
  if (!store.get("sidetone.follow_calls", true)) return;
  // Never pull the user away from a form they are editing or from Help.
  if ((S.page === "settings" && SET.dirty) || S.page === "help") return;
  if (document.body.classList.contains("phone-mode")) {
    if (!document.body.classList.contains("compact")) showWs("calls");
    return;
  }
  Object.assign(LIVE, { on: true, line: lineId, size: -1, last: 0, endedAt: 0, keep: null });
  showWs("analysis");
  liveTick(true);
}

function stopLive() {
  LIVE.on = false;
  renderLiveTag();
}

function renderLiveTag() {
  const el = $("#an-live");
  if (!el) return;
  const l = LIVE.on && line(LIVE.line);
  el.hidden = !LIVE.on;
  if (LIVE.on) {
    $("#an-live-text").textContent = `${t("Live")}: L${LIVE.line}${l ? ` ${l.remote_name || l.remote}` : ""}${l && l.state === "ended" ? ` (${t("ended")})` : ""}`;
  }
}

async function liveTick(force = false) {
  if (!LIVE.on || LIVE.busy) return;
  const l = line(LIVE.line);
  const now = Date.now();
  // Keep refreshing a few seconds after the call ends to catch BYE/200 and the last RTP.
  if (!l || l.state === "ended") {
    if (!LIVE.endedAt) LIVE.endedAt = now;
    if (now - LIVE.endedAt > 4000) {
      LIVE.on = false;
      renderLiveTag();
      return;
    }
  }
  // Signaling settles once the call is up: refresh every 4 s then, 1.5 s otherwise.
  const settled = l && l.state === "connected" && LIVE.sipCount === (S.report ? S.report.summary.sip_messages : -1);
  if (!force && (S.page !== "analysis" || now - LIVE.last < (settled ? 4000 : 1500))) return;
  if (PL.src) return; // do not cut the RTP player
  LIVE.busy = true;
  LIVE.last = now;
  try {
    const bytes = await S.ctl.capture(S.be);
    if (!force && bytes.length === LIVE.size) return;
    LIVE.size = bytes.length;
    await liveLoad(bytes, l ? l.call_id : "");
    LIVE.sipCount = S.report ? S.report.summary.sip_messages : -1;
  } catch {
    /* nothing captured yet */
  } finally {
    LIVE.busy = false;
    renderLiveTag();
  }
}

/// Reloads the capture keeping what the user is looking at: the dialog, the
/// selected message, the tab and the ladder scroll (or its end when it was there).
async function liveLoad(bytes, callId) {
  const prevCall = S.report && S.call != null && S.report.calls[S.call] ? S.report.calls[S.call].call_id : null;
  // The call being followed, unless the user clicked another dialog meanwhile.
  const keepCall = LIVE.keep || callId || prevCall;
  const prevMsg = S.msg;
  const lad = $("#ladder");
  const atEnd = !lad || lad.scrollTop + lad.clientHeight >= lad.scrollHeight - 30;
  const scroll = lad ? [lad.scrollTop, lad.scrollLeft] : [0, 0];
  let report;
  try {
    report = await S.be.analyze(bytes);
  } catch {
    return;
  }
  const picked = S.picked || new Set();
  Object.assign(S, { bytes, name: `live-L${LIVE.line}.pcapng`, report, webrtc: S.ctl.kind === "web" ? S.ctl.lastSummary : null, picked });
  $("#an-empty").hidden = true;
  $("#an").hidden = false;
  const sm = report.summary;
  $("#capinfo").textContent = `${sm.calls} dialogs, ${sm.sip_messages} SIP messages, ${sm.rtp_streams} RTP streams, ${sm.duration_s.toFixed(1)} s, ${sm.errors} errors, ${sm.warnings} warnings`;
  renderCalls();
  let idx = report.calls.findIndex((c) => c.call_id === keepCall);
  if (idx < 0 && callId) idx = report.calls.findIndex((c) => c.call_id === callId);
  if (idx < 0) idx = report.calls.length ? report.calls.length - 1 : null;
  await selectCall(idx);
  const sameCall = idx != null && report.calls[idx] && report.calls[idx].call_id === prevCall;
  if (prevMsg != null && report.messages[prevMsg] && sameCall) selectMessage(prevMsg, false);
  const lad2 = $("#ladder");
  if (lad2) {
    if (atEnd) lad2.scrollTop = lad2.scrollHeight;
    else [lad2.scrollTop, lad2.scrollLeft] = scroll;
  }
}

async function analyzeLine(callId) {
  try {
    const bytes = await S.ctl.capture(S.be);
    await load(bytes, `sidetone-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, "")}.pcapng`, S.ctl.kind === "web" ? S.ctl.lastSummary : null);
    showWs("analysis");
    if (callId && S.report) {
      const i = S.report.calls.findIndex((c) => c.call_id === callId);
      if (i >= 0) selectCall(i);
    }
  } catch (e) {
    toast(t("Nothing to analyze yet: no SIP was sent or received. Check the account in Settings."), 5000);
  }
}

function openXfer() {
  const l = selLine();
  if (!l || l.state !== "connected") return;
  S.xfer = { from: l.line, consult: null };
  $("#xfer").hidden = false;
  $("#xfer-who").textContent = l.remote_name || l.remote;
  $("#xfer-complete").hidden = true;
  $("#xfer-consult").hidden = !S.ctl.features.attended;
  $("#xfer-note").textContent = S.ctl.features.attended ? "Blind sends the call away now. Consult calls the target first, then you complete the transfer." : "Blind transfer only on this account.";
  $("#xfer-to").value = "";
  $("#xfer-to").focus();
}
function closeXfer() {
  S.xfer = null;
  $("#xfer").hidden = true;
}

function bindPhone() {
  $("#acct").addEventListener("change", () => {
    store.set("sidetone.acct", $("#acct").value);
    if (S.ctl.kind === "web") S.ctl.activate($("#acct").value);
    renderAccounts();
    renderStatus();
  });
  $("#acct-state").addEventListener("click", (e) => {
    const b = e.target.closest("[data-open-acc]");
    if (!b) return;
    SET.accId = b.dataset.openAcc;
    SET.section = null;
    showWs("settings");
  });
  $("#acct-reg").addEventListener("click", () => {
    const a = currentAccount();
    if (a) cmd({ cmd: "register", account: a.id });
  });
  $("#opts-toggle").addEventListener("click", () => {
    const o = $("#opts");
    o.hidden = !o.hidden;
    $("#opts-toggle").setAttribute("aria-expanded", String(!o.hidden));
    if (!o.hidden && S.ctl.features.overrides && !$("#opt-codecs")) {
      S.ctl.getConfig().then((cfg) => {
        const a = currentAccount();
        const acc = a && cfg.accounts ? cfg.accounts.find((x) => x.id === a.id) : null;
        const own = acc && acc.profile && acc.profile.behavior && acc.profile.behavior.codecs;
        const fallback = own && own.length ? own : (cfg.settings && cfg.settings.codecs) || CODEC_DEFAULTS;
        $("#opt-codecs-box").innerHTML = codecPicker("opt-codecs", null, { label: "Use the account's codecs", fallback });
      }).catch(() => {});
    }
  });
  $("#btn-call").addEventListener("click", callOrAnswer);
  $("#btn-hangup").addEventListener("click", hangupSel);
  $("#dial").addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      e.preventDefault();
      callOrAnswer();
    }
  });
  $$("#keypad button").forEach((b) => b.addEventListener("click", () => keyPress(b.dataset.key)));

  $(".tools").addEventListener("click", async (e) => {
    const b = e.target.closest(".tool");
    if (!b || b.disabled) return;
    const l = selLine();
    const st = S.st ? S.st.settings : {};
    switch (b.dataset.tool) {
      case "hold":
        if (l) cmd({ cmd: "hold", line: l.line, on: !l.held });
        break;
      case "mute":
        if (l) cmd({ cmd: "mute", line: l.line, on: !l.muted });
        break;
      case "record":
        if (l) cmd({ cmd: "record", line: l.line, on: !l.recording });
        break;
      case "conf": {
        if (!l) break;
        if (l.conference) {
          cmd({ cmd: "conference", line: l.line, to_line: l.conference, on: false });
          break;
        }
        const other = liveLines()
          .filter((x) => x.state === "connected" && x.line !== l.line)
          .sort((a, b) => (b.answered_ms || 0) - (a.answered_ms || 0))[0];
        if (other) cmd({ cmd: "conference", line: l.line, to_line: other.line, on: true });
        break;
      }
      case "transfer":
        if ($("#xfer").hidden) openXfer();
        else closeXfer();
        break;
      case "keypad": {
        const on = $("#keypad").hidden;
        $("#keypad").hidden = !on;
        b.setAttribute("aria-pressed", String(on));
        store.set("sidetone.keypad", on);
        break;
      }
      case "dnd":
        await cmd({ cmd: "dnd", on: !st.dnd });
        toast(!st.dnd ? "Do not disturb: incoming calls are rejected" : "Do not disturb off");
        break;
      case "aa":
        await cmd({ cmd: "auto_answer", on: !st.auto_answer });
        toast(!st.auto_answer ? "Auto answer on" : "Auto answer off");
        break;
      case "analyze": {
        const target = l || lines()[lines().length - 1];
        analyzeLine(target ? target.call_id : null);
        break;
      }
    }
  });

  $("#my-pres").addEventListener("change", publishPresence);
  $("#my-pres-note").addEventListener("input", (e) => (e.target.dataset.dirty = "1"));
  $("#my-pres-note").addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      e.preventDefault();
      publishPresence();
      e.target.blur();
    }
  });
  $("#my-pres-note").addEventListener("change", publishPresence);
  const sendMsg = async () => {
    const target = $("#dial").value.trim();
    const text = $("#msg-text").value;
    if (!target || !text.trim()) {
      toast(t("Type the number above and the text"), 3000);
      return;
    }
    const a = currentAccount();
    if (await cmd({ cmd: "message", account: a ? a.id : "", target, text })) {
      $("#msg-text").value = "";
      toast(t("Message sent; the result shows in Phone events"));
    }
  };
  $("#msg-send").addEventListener("click", sendMsg);
  $("#msg-text").addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      e.preventDefault();
      sendMsg();
    }
  });
  $("#vm-btn").addEventListener("click", () => {
    const a = currentAccount();
    if (!a) return;
    const target = (a.voicemail || "").trim() || (a.mwi && a.mwi.account) || "";
    if (!target) {
      toast(t("Set the voicemail number in the account (Settings, account, Voicemail)"), 4000);
      return;
    }
    $("#dial").value = target;
    dial(target);
  });
  $("#blf").addEventListener("click", (e) => {
    const b = e.target.closest("[data-dial]");
    if (b) {
      $("#dial").value = b.dataset.dial;
      dial(b.dataset.dial);
    }
  });
  $("#lines").addEventListener("keydown", (e) => {
    const li = e.target.closest && e.target.closest("li[data-line]");
    if (!li || e.target !== li) return;
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      const l = line(+li.dataset.line);
      if (l && l.state === "incoming") cmd({ cmd: "answer", line: l.line });
      else li.click();
    }
  });
  $("#lines").addEventListener("click", (e) => {
    const li = e.target.closest("li[data-line]");
    if (!li) return;
    const id = +li.dataset.line;
    const act = e.target.closest("[data-act]");
    S.sel = id;
    if (act) {
      const a = act.dataset.act;
      if (a === "answer") cmd({ cmd: "answer", line: id });
      if (a === "reject") cmd({ cmd: "reject", line: id, code: 486 });
      if (a === "forward") {
        const target = $("#dial").value.trim();
        if (!target) toast(t("Type the destination in the number field, then press Forward"), 4000);
        else cmd({ cmd: "forward", line: id, target });
      }
      if (a === "resume") cmd({ cmd: "hold", line: id, on: false });
      if (a === "hangup") cmd({ cmd: "hangup", line: id });
    }
    renderLines();
    renderControls();
    renderMeters();
    if (S.page === "calls") renderCallDetail();
    if (S.page === "calls") renderActive();
  });

  $("#xfer-blind").addEventListener("click", async () => {
    const t = $("#xfer-to").value.trim();
    if (!t || !S.xfer) return;
    await cmd({ cmd: "transfer", line: S.xfer.from, target: t });
    closeXfer();
  });
  $("#xfer-consult").addEventListener("click", async () => {
    const t = $("#xfer-to").value.trim();
    if (!t || !S.xfer) return;
    const from = line(S.xfer.from);
    if (from && !from.held) await cmd({ cmd: "hold", line: from.line, on: true });
    const r = await dial(t);
    if (r && r.line) S.xfer.consult = r.line;
    renderControls();
  });
  $("#xfer-complete").addEventListener("click", async () => {
    if (!S.xfer || !S.xfer.consult) return;
    await cmd({ cmd: "attended_transfer", line: S.xfer.from, to_line: S.xfer.consult });
    toast("Transfer requested");
    closeXfer();
  });
  $("#xfer-cancel").addEventListener("click", closeXfer);
  $("#xfer-to").addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      e.preventDefault();
      $("#xfer-blind").click();
    }
    if (e.key === "Escape") closeXfer();
  });

  // Hotkeys: Enter call/answer, Esc hang up, F2 transfer, F3 hold, F4 mute, digits send DTMF.
  document.addEventListener("keydown", (e) => {
    const tag = (e.target.tagName || "").toLowerCase();
    const typing = ["input", "textarea", "select"].includes(tag) && e.target.id !== "dial";
    if (e.key === "F2") { e.preventDefault(); $('.tool[data-tool="transfer"]').click(); return; }
    if (e.key === "F3") { e.preventDefault(); $('.tool[data-tool="hold"]').click(); return; }
    if (e.key === "F4") { e.preventDefault(); $('.tool[data-tool="mute"]').click(); return; }
    if (typing) return;
    const l = selLine();
    if (e.key === "Escape") {
      if ($$(".menu.open").length) return;
      if (!$("#xfer").hidden) return closeXfer();
      // Esc ends a call only from the phone panel or with nothing focused;
      // anywhere else it is for closing menus, dialogs and suggestion boxes.
      const inPhone = e.target === document.body || (e.target.closest && e.target.closest(".phone"));
      if ($("#prov-dialog").open || !inPhone) return;
      if (l && l.state !== "ended") {
        e.preventDefault();
        hangupSel();
      }
      return;
    }
    if (e.target.id === "dial") return;
    if (e.key === "Enter" && l && l.state === "incoming") {
      e.preventDefault();
      cmd({ cmd: "answer", line: l.line });
      return;
    }
    if (/^[0-9*#]$/.test(e.key) && !e.ctrlKey && !e.metaKey && !e.altKey) {
      if (l && (l.state === "connected" || l.state === "early")) {
        e.preventDefault();
        keyPress(e.key);
      } else {
        e.preventDefault();
        $("#dial").value += e.key;
        $("#dial").focus();
      }
    }
  });

  if (store.get("sidetone.keypad", true) === false) {
    $("#keypad").hidden = true;
    $('.tool[data-tool="keypad"]').setAttribute("aria-pressed", "false");
  }
  renderDialHistory();
  setInterval(() => {
    if (liveLines().length) tickDurations();
  }, 1000);
  $("#active-body").addEventListener("click", (e) => {
    const tr = e.target.closest("tr[data-line]");
    if (!tr) return;
    S.sel = +tr.dataset.line;
    renderLines();
    renderControls();
    renderCallDetail();
    renderActive();
  });
}

// ============================================================================
// Calls page

function kv(rows) {
  return `<dl class="kv">${rows
    .filter(([, v]) => v !== null && v !== undefined && v !== "")
    .map(([k, v]) => `<dt>${esc(k)}</dt><dd>${v}</dd>`)
    .join("")}</dl>`;
}

/// Tells the user right away when the PBX refuses a feature they used.
const seenActions = new Map();
function announceActions() {
  for (const l of lines()) {
    if (!l.action || seenActions.get(l.line) === l.action) continue;
    seenActions.set(l.line, l.action);
    if (l.action_ok === false) toast(`L${l.line}: ${t(l.action)}`, 6000);
  }
}

/// Live table of the calls on the phone: number, state, duration, codec.
/// Live quality of a line: what we receive, what the far end reports, round trip.
function liveQuality(l) {
  const parts = [];
  const cls = (v, w, b) => (v >= b ? "bad" : v >= w ? "warn" : "");
  if (l.rx_loss_pct != null) parts.push(`<span class="${cls(l.rx_loss_pct, 1, 5)}">↓ ${l.rx_loss_pct.toFixed(1)}% · ${l.rx_jitter_ms.toFixed(0)} ms</span>`);
  if (l.remote_loss_pct != null) parts.push(`<span class="${cls(l.remote_loss_pct, 1, 5)}" title="${esc(t("Reported by the far end in RTCP"))}">↑ ${l.remote_loss_pct.toFixed(1)}% · ${(l.remote_jitter_ms || 0).toFixed(0)} ms</span>`);
  if (l.rtt_ms != null) parts.push(`<span class="${cls(l.rtt_ms, 200, 300)}">RTT ${l.rtt_ms.toFixed(0)} ms</span>`);
  if (!parts.length && l.state === "connected") return `<span class="muted">${esc(t(l.rtcp_sent ? "waiting for RTCP" : "no RTCP"))}</span>`;
  return parts.join("<br>");
}

function renderActive() {
  const box = $("#active-body");
  if (!box) return;
  const ls = lines().filter((l) => !(l.state === "ended" && S.hiddenEnded.has(l.line + ":" + l.call_id)));
  $("#active-count").textContent = ls.filter((l) => l.state !== "ended").length || "";
  $("#active-clear").hidden = !ls.some((l) => l.state === "ended");
  // Every account: registered or not, over which transport, where.
  const accRows = (S.st ? S.st.accounts : []).map((a) => {
    const cls = regClass(a);
    const tp = S.ctl.kind === "web" ? "WSS" : a.transport || "UDP";
    const where = a.server || a.domain || "";
    return `<div class="reg-row"><span class="dot ${cls}"></span><b>${esc(accLabel(a))}</b> <span class="mono">sip:${esc(a.user)}@${esc(a.domain || "")}${tp !== "UDP" && tp !== "WSS" ? `;transport=${tp.toLowerCase()}` : ""}</span> <span class="${cls === "bad" ? "bad" : "muted"}">${esc(t(accountStateText(a)))}</span> <span class="tag">${esc(tp)}</span>${where ? ` <span class="muted mono">${esc(where)}</span>` : ""}</div>`;
  }).join("");
  setHtml($("#active-regs"), accRows);
  $(".active-card").classList.toggle("quiet", !ls.length);
  if (!ls.length) {
    setHtml(box, `<p class="empty-note">${esc(t(S.st && S.st.accounts.length ? "No calls right now: dial a number or wait for one." : "No calls right now."))}</p>`);
    return;
  }
  const now = Date.now();
  const accs = S.st ? S.st.accounts : [];
  const tr = (acc) => (S.ctl.kind === "web" ? "WSS" : acc ? acc.transport || "UDP" : "");
  setHtml(box, `<div class="table-wrap"><table class="hist active"><thead><tr><th>${esc(t("Line"))}</th><th></th><th>${esc(t("Number"))}</th><th>${esc(t("State"))}</th><th>${esc(t("Duration"))}</th><th>${esc(t("Codec"))}</th><th>${esc(t("Transport"))}</th><th>${esc(t("Media"))}</th><th>RTP ↑ / ↓</th><th title="${esc(t("Received: our loss and jitter. Far end: what it reports in RTCP about what we send. RTT from RTCP."))}">${esc(t("Quality"))}</th><th>${esc(t("Account"))}</th><th>${esc(t("Last action"))}</th></tr></thead><tbody>${ls
    .map((l) => {
      const d = l.answered_ms ? (l.ended_ms ? dur(l.ended_ms - l.answered_ms) : durSpan(l.answered_ms)) : "";
      const acc = accs.find((a) => a.id === l.account);
      const media = l.srtp ? (l.security || "SRTP").replace(/, fingerprint verified$/, " ✓") : l.state === "connected" ? "RTP" : "";
      const flags = [l.held ? t("on hold") : "", l.remote_held ? t("held by far end") : "", l.muted ? t("muted") : "", l.conference ? `${t("Conference")} L${l.conference}` : ""].filter(Boolean).join(", ");
      return `<tr data-line="${l.line}" class="${l.line === S.sel ? "sel" : ""} ${l.state === "ended" ? "ended" : ""}">
        <td class="num">L${l.line}</td>
        <td><svg class="hi"><use href="#i-${l.direction === "in" ? "in" : "out"}"/></svg></td>
        <td><b>${esc(l.remote_name || "")}</b> <span class="mono">${esc(l.remote)}</span></td>
        <td><span class="badge st-${l.state}">${esc(t(STATE_TEXT[l.state] || l.state))}</span>${flags ? ` <span class="muted">${esc(flags)}</span>` : ""}</td>
        <td class="num">${d}</td>
        <td class="num">${esc(l.codec || "")}</td>
        <td class="num">${esc(tr(acc))}</td>
        <td>${esc(media)}</td>
        <td class="num">${l.rtp_sent || 0} / ${l.rtp_received || 0}</td>
        <td class="small">${liveQuality(l)}</td>
        <td>${esc(acc ? accLabel(acc) : l.account || "")}</td>
        <td class="${l.action_ok === false ? "bad" : l.action_ok ? "ok" : ""}">${esc(l.action ? t(l.action) : "")}</td></tr>`;
    })
    .join("")}</tbody></table></div>`);
}

function renderCallDetail() {
  const l = selLine() || lines()[lines().length - 1];
  const body = $("#call-detail-body");
  if (!l) {
    // No call: the same fields, empty, so the card keeps its shape.
    const keys = ["Direction", "Account", "Call-ID", "Talk time", "Codec", "Media encryption", "Local media", "Remote media", "RTP sent / received", "Result"];
    setHtml(body, `<div class="cd-head"><span class="badge">${esc(t("No call"))}</span></div><dl class="kv empty">${keys.map((k) => `<dt>${esc(t(k))}</dt><dd>-</dd>`).join("")}</dl>`);
    renderRecordings();
    return;
  }
  const m = (s) => `<span class="mono">${esc(s)}</span>`;
  const html = `
    <div class="cd-head"><span class="badge st-${l.state}">${esc(STATE_TEXT[l.state] || l.state)}</span><b>${esc(l.remote_name || "")}</b> ${m(l.remote)}</div>
    ${kv([
      ["Direction", l.direction === "in" ? "Incoming" : "Outgoing"],
      ["Account", esc(accName(l.account))],
      ["Call-ID", m(l.call_id)],
      ["Talk time", l.answered_ms ? (l.ended_ms ? dur(l.ended_ms - l.answered_ms) : durSpan(l.answered_ms)) : ""],
      ["Codec", esc(l.codec || "")],
      ["Media encryption", S.ctl.kind !== "native" && l.state === "connected" ? "DTLS-SRTP (WebRTC)" : l.srtp ? `${esc(l.security || "SRTP")}${l.srtp_failed ? ` <span class="bad">${l.srtp_failed} packets failed authentication</span>` : ""}` : l.state === "connected" ? "none (RTP)" : ""],
      ["Local media", l.local_media ? m(l.local_media) : ""],
      ["Remote media", l.remote_media ? m(l.remote_media) : ""],
      ["RTP sent / received", l.rtp_sent || l.rtp_received ? `${l.rtp_sent.toLocaleString()} / ${l.rtp_received.toLocaleString()}${l.state === "connected" && !l.held && l.rtp_sent > 100 && l.rtp_received === 0 ? ` <span class="bad">no audio from the far end</span>` : ""}` : ""],
      ["Hold", l.held ? "held by you" : l.remote_held ? "held by the remote side" : ""],
      ["DTMF received", l.dtmf_rx ? m(l.dtmf_rx) : ""],
      ["Transfer", esc(l.transfer || "")],
      ["Result", l.final_code || l.reason ? esc(resultText(l.final_code, l.reason)) : ""],
      ["Ended by", esc(l.ended_by || "")],
    ])}
    <div class="row">
      <button type="button" class="btn small primary" id="cd-analyze">${esc(t("Analyze"))}</button>
      <button type="button" class="btn small" id="cd-trace">${esc(t("Show in SIP trace"))}</button>
      ${l.recording && S.ctl.features.record ? `<button type="button" class="btn small" id="cd-rec">Download recording</button>` : ""}
    </div>`;
  if (body.dataset.sig === html) {
    renderRecordings();
    return;
  }
  body.dataset.sig = html;
  body.innerHTML = html;
  $("#cd-analyze").addEventListener("click", () => analyzeLine(l.call_id));
  $("#cd-trace").addEventListener("click", () => {
    showWs("trace");
    const sel = $("#tr-call");
    if ([...sel.options].some((o) => o.value === l.call_id)) sel.value = l.call_id;
    renderTrace(true);
  });
  const rb = $("#cd-rec");
  if (rb) rb.addEventListener("click", () => downloadRecording(l.line, l.remote));
  renderRecordings();
}

async function downloadRecording(lineId, remote) {
  try {
    const w = await S.ctl.recording(lineId);
    await download(w, `sidetone-${String(remote).replace(/[^\w@.-]+/g, "_")}-line${lineId}.wav`, "audio/wav");
  } catch (e) {
    toast(e.message || String(e), 4000);
  }
}

function renderRecordings() {
  let el = $("#recs");
  if (!S.recordings.length) {
    if (el) el.remove();
    return;
  }
  if (!el) {
    $("#call-detail").insertAdjacentHTML("beforeend", `<div id="recs" class="recs"></div>`);
    el = $("#recs");
  }
  el.innerHTML = `<h3>Recordings this session</h3><ul>${S.recordings
    .map((r) => `<li><button type="button" class="linklike" data-rec="${r.line}">${esc(r.remote)}, ${clock(r.ended)}</button></li>`)
    .join("")}</ul><p class="hint">Stereo WAV: left is what Sidetone sent, right is what it received.</p>`;
  el.querySelectorAll("[data-rec]").forEach((b) => b.addEventListener("click", () => downloadRecording(+b.dataset.rec, S.recordings.find((r) => r.line === +b.dataset.rec).remote)));
}

const EV_KIND = { reg: "Registration", call: "Call", incoming: "Incoming", media: "Media", dtmf: "DTMF", transfer: "Transfer", error: "Problem", account: "Account", diag: "Diagnostics", message: "Message", info: "Info", voicemail: "Voicemail" };

function onEvents(evs) {
  for (const e of evs) {
    S.events.push(e);
    if (e.kind === "error") S.errors++;
    if (e.kind === "provisioned" && S.page === "settings" && SET.cfg) {
      if (SET.dirty) toast(t("Provisioning updated the saved account. Your unsaved edits are still here."));
      else {
        S.ctl.getConfig().then((c) => {
          SET.cfg = c;
          renderSetNav();
          renderSetBody();
        }).catch(() => {});
      }
    }
  }
  if (S.events.length > 1000) S.events.splice(0, S.events.length - 1000);
  renderEvents(evs);
}

function renderEvents(newOnes) {
  const ol = $("#events");
  const fmt = (e) => `<li class="ev-${esc(e.kind)}"><span class="ev-t">${clock(e.ts_ms)}</span><span class="ev-k">${esc(EV_KIND[e.kind] || e.kind)}${e.line ? ` L${e.line}` : ""}</span><span class="ev-x">${esc(e.text)}</span></li>`;
  if (!newOnes) {
    ol.innerHTML = S.events.slice(-300).reverse().map(fmt).join("");
    $("#events-empty").hidden = S.events.length > 0;
    return;
  }
  $("#events-empty").hidden = true;
  ol.insertAdjacentHTML("afterbegin", newOnes.slice().reverse().map(fmt).join(""));
  while (ol.children.length > 300) ol.lastElementChild.remove();
}

/// "404 Not Found" from a code and a reason that may already start with it.
function resultText(code, reason) {
  if (reason && code && String(reason).startsWith(String(code))) return reason;
  return [code, reason].filter(Boolean).join(" ");
}

function accName(id) {
  const a = S.st && S.st.accounts.find((x) => x.id === id);
  return a ? accLabel(a) : id;
}

const HSEL = new Set();

/// History rows that pass the text, date, direction and result filters.
function historyRows() {
  const f = $("#hist-filter").value.trim().toLowerCase();
  const from = $("#hist-from").value ? new Date(`${$("#hist-from").value}T00:00:00`).getTime() : null;
  const to = $("#hist-to").value ? new Date(`${$("#hist-to").value}T23:59:59.999`).getTime() : null;
  const dir = $("#hist-dir").value;
  const res = $("#hist-res").value;
  return S.history.filter((h) => {
    if (f && !`${h.remote} ${h.remote_name || ""} ${h.final_code || ""} ${h.reason || ""} ${h.call_id} ${h.codec || ""}`.toLowerCase().includes(f)) return false;
    if (from != null && h.started_ms < from) return false;
    if (to != null && h.started_ms > to) return false;
    const missed = h.direction === "in" && !h.answered;
    if (dir === "missed" ? !missed : dir && h.direction !== dir) return false;
    if (res === "answered" && !h.answered) return false;
    if (res === "failed" && h.answered) return false;
    return true;
  });
}

/// Fetches the history, then draws it. Filters only redraw (renderHistoryRows).
async function renderHistory() {
  try {
    S.history = await S.ctl.history();
  } catch {
    S.history = [];
  }
  renderHistoryRows();
}

function renderHistoryRows() {
  const rows = historyRows();
  const byId = (id) => rows.find((h) => h.call_id === id);
  for (const id of [...HSEL]) if (!S.history.some((h) => h.call_id === id)) HSEL.delete(id);
  $("#hist-count").textContent = S.history.length ? (rows.length === S.history.length ? `${rows.length}` : `${rows.length} / ${S.history.length}`) : "";
  $("#hist-empty").hidden = rows.length > 0;
  $("#hist-empty").textContent = t(S.history.length ? "No call matches the filters." : S.st && S.st.accounts.length ? "No calls yet: calls you make or receive are listed here with their capture." : "No calls yet: add an account in Settings first.");
  $(".hist-tools").hidden = !S.history.length;
  $(".hist-wrap").classList.toggle("quiet", !S.history.length);
  $("#hist").innerHTML = rows
    .slice(0, 500)
    .map((h) => {
      const missed = h.direction === "in" && !h.answered;
      const icon = missed ? "missed" : h.direction === "in" ? "in" : "out";
      const result = h.answered ? "Answered" : resultText(h.final_code, h.reason) || "Not answered";
      return `<tr class="${missed ? "missed" : ""}${S.histSel === h.call_id ? " sel" : ""}" data-hrow="${esc(h.call_id)}" tabindex="0">
        <td><input type="checkbox" data-hsel="${esc(h.call_id)}" ${HSEL.has(h.call_id) ? "checked" : ""} aria-label="${esc(t("Select"))}"></td>
        <td><svg class="hi" aria-label="${icon}"><use href="#i-${icon}"/></svg></td>
        <td>${h.remote_name ? `<b>${esc(h.remote_name)}</b> ` : ""}<span class="mono">${esc(h.remote)}</span></td>
        <td>${when(h.started_ms)}</td>
        <td class="num">${h.answered ? dur(h.duration_s * 1000) : ""}</td>
        <td class="${h.answered ? "" : "muted"}">${esc(result)}</td>
        <td>${codecCell(h)}</td>
        <td class="num ${h.mos == null ? "" : h.mos < 3.1 ? "bad" : h.mos < 3.6 ? "warn" : ""}" title="${h.loss_pct != null ? esc(`${t("loss")} ${h.loss_pct.toFixed(1)}%`) : ""}">${h.mos == null ? "" : h.mos.toFixed(1)}</td>
        <td class="muted">${esc(accName(h.account))}</td>
        <td class="acts"><button type="button" class="linklike" data-redial="${esc(h.call_id)}">Call</button> <button type="button" class="linklike" data-han="${esc(h.call_id)}">Analyze</button> <button type="button" class="linklike del" data-hdel="${esc(h.call_id)}" title="${esc(t("Delete from history"))}">✕</button></td>
      </tr>`;
    })
    .join("");
  $("#hist-all").checked = rows.length > 0 && rows.every((h) => HSEL.has(h.call_id));
  $("#hist-del").disabled = !HSEL.size;
  $("#hist-del").textContent = HSEL.size ? `${t("Delete selected")} (${HSEL.size})` : t("Delete selected");
  $("#hist").onclick = async (e) => {
    const r = e.target.closest("[data-redial]");
    if (r) {
      const h = byId(r.dataset.redial);
      if (!h) return;
      $("#dial").value = h.remote;
      dial(h.remote);
      return;
    }
    const a = e.target.closest("[data-han]");
    if (a) return openHistoryCall(byId(a.dataset.han), true);
    const d = e.target.closest("[data-hdel]");
    if (d) {
      const h = byId(d.dataset.hdel);
      if (!h || !confirm(`${t("Delete from history")}: ${h.remote}?`)) return;
      HSEL.delete(h.call_id);
      await S.ctl.deleteHistory([h.call_id]);
      renderHistory();
      return;
    }
    const row = e.target.closest("[data-hrow]");
    if (row && !e.target.closest("button, input, a")) openHistoryCall(byId(row.dataset.hrow), false);
  };
  $("#hist").onkeydown = (e) => {
    const row = e.target.closest && e.target.closest("tr[data-hrow]");
    if (!row || e.target !== row) return;
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      openHistoryCall(byId(row.dataset.hrow), e.key === "Enter" && e.shiftKey);
    } else if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      e.preventDefault();
      const n = e.key === "ArrowDown" ? row.nextElementSibling : row.previousElementSibling;
      if (n) n.focus();
    }
  };
  $("#hist").onchange = (e) => {
    const c = e.target.closest("[data-hsel]");
    if (!c) return;
    if (c.checked) HSEL.add(c.dataset.hsel);
    else HSEL.delete(c.dataset.hsel);
    $("#hist-all").checked = rows.length > 0 && rows.every((h) => HSEL.has(h.call_id));
    $("#hist-del").disabled = !HSEL.size;
    $("#hist-del").textContent = HSEL.size ? `${t("Delete selected")} (${HSEL.size})` : t("Delete selected");
  };
  renderCallDetail();
}

/// The codec used, then what was offered and answered.
function codecCell(h) {
  const audio = (l) => (l || []).filter((c) => !/telephone-event|^CN$/i.test(c));
  const used = h.codec || audio(h.answer_codecs)[0] || "";
  const dtmf = (h.answer_codecs || []).some((c) => /telephone-event/i.test(c));
  const parts = [];
  if (h.offer_codecs && h.offer_codecs.length) parts.push(`${t("offer")} ${h.offer_codecs.join(", ")}`);
  if (h.answer_codecs && h.answer_codecs.length) parts.push(`${t("answer")} ${h.answer_codecs.join(", ")}`);
  return `<div class="codec-cell">${used ? `<b class="mono">${esc(used)}</b>` : ""}${dtmf ? ` <span class="tag">DTMF 4733</span>` : ""}${parts.length ? `<div class="muted small mono" title="${esc(parts.join(" · "))}">${esc(parts.join(" · "))}</div>` : ""}</div>`;
}

/// Loads one call from the history into Analysis (its saved capture, or the
/// session capture) and shows it here; `go` switches to Analysis.
async function openHistoryCall(h, go) {
  if (!h) return;
  S.histSel = h.call_id;
  $$("#hist tr").forEach((r) => r.classList.toggle("sel", r.dataset.hrow === h.call_id));
  const box = $("#hist-detail");
  box.hidden = false;
  box.innerHTML = `<p class="muted">${esc(t("Loading the call"))}…</p>`;
  let bytes = null;
  try {
    bytes = S.ctl.historyCapture ? await S.ctl.historyCapture(h.call_id, S.be) : null;
  } catch {
    bytes = null;
  }
  let fromSession = false;
  if (!bytes) {
    try {
      bytes = await S.ctl.capture(S.be);
      fromSession = true;
    } catch {
      bytes = null;
    }
  }
  if (bytes) {
    await load(bytes, `${(h.remote || "call").replace(/[^\w.@-]+/g, "_")}-${new Date(h.started_ms).toISOString().slice(0, 19).replace(/[:T]/g, "")}.pcapng`);
  }
  const ci = S.report ? S.report.calls.findIndex((c) => c.call_id === h.call_id) : -1;
  if (ci >= 0) await selectCall(ci);
  renderHistoryDetail(h, ci, fromSession);
  if (go && ci >= 0) showWs("analysis");
  else if (go) toast(t("This call's SIP is no longer available: it ended before captures were kept, or the trace was cleared."), 5000);
}

function renderHistoryDetail(h, ci, fromSession) {
  const box = $("#hist-detail");
  const result = h.answered ? t("Answered") : resultText(h.final_code, h.reason) || t("Not answered");
  const c = ci >= 0 ? S.report.calls[ci] : null;
  const d = new Date(h.started_ms);
  box.innerHTML = `<div class="sect-head"><h2>${esc(t("Selected call"))}: ${h.remote_name ? `${esc(h.remote_name)} ` : ""}<span class="mono">${esc(h.remote)}</span></h2>
      <span class="row">${c ? `<button type="button" class="btn small primary" id="hd-open">${esc(t("Open in Analysis"))}</button> <button type="button" class="btn small" id="hd-save">${esc(t("Save pcapng"))}</button>` : ""}</span></div>
    ${kv([
      [t("Direction"), esc(t(h.direction === "in" ? "Incoming" : "Outgoing"))],
      [t("Started"), esc(`${d.toLocaleDateString()} ${d.toLocaleTimeString()}`)],
      [t("Duration"), h.answered ? esc(dur(h.duration_s * 1000)) : ""],
      [t("Result"), `${esc(result)}${h.final_code ? ` <span class="mono">${h.final_code}</span>` : ""}${h.ended_by ? ` <span class="muted">(${esc(t("ended by"))} ${esc(t(/remote|callee|far/i.test(h.ended_by) ? "the other side" : "this phone"))})</span>` : ""}`],
      [t("Codecs"), codecCell(h)],
      ...(h.mos != null ? [["MOS", `${h.mos.toFixed(2)}${h.loss_pct != null ? ` <span class="muted">(${esc(t("loss"))} ${h.loss_pct.toFixed(1)}%)</span>` : ""}`]] : []),
      [t("Account"), esc(accName(h.account))],
      ["Call-ID", `<span class="mono">${esc(h.call_id)}</span>`],
      [t("Capture"), c ? esc(t(fromSession ? "from this session's trace" : "saved with the history")) + `, ${c.messages.length} SIP, ${c.streams.length} RTP` : `<span class="muted">${esc(t("not available"))}</span>`],
    ])}
    ${c ? `<div class="hd-ladder" id="hd-ladder"></div>${renderExplain(S.report, ci, S.report.findings)}` : `<p class="muted">${esc(t("This call's SIP is no longer available: it ended before captures were kept, or the trace was cleared."))}</p>`}`;
  if (c) {
    const lad = $("#ladder");
    $("#hd-ladder").innerHTML = lad ? lad.innerHTML : "";
    $("#hd-ladder").addEventListener("click", (e) => {
      const g = e.target.closest(".msg");
      if (g) {
        showWs("analysis");
        selectMessage(+g.dataset.msg);
      }
    });
    $("#hd-open").addEventListener("click", () => showWs("analysis"));
    $("#hd-save").addEventListener("click", async () => {
      const out = await S.be.exportPcap(S.bytes, { call: ci, annotate: true });
      download(out, S.name, "application/vnd.tcpdump.pcap");
    });
  }
}

function historyCsv() {
  const q = (v) => `"${String(v ?? "").replace(/"/g, '""')}"`;
  const head = ["started", "direction", "remote", "remote_name", "answered", "duration_s", "final_code", "reason", "ended_by", "codec", "offer_codecs", "answer_codecs", "mos", "loss_pct", "account", "call_id"];
  const lines = historyRows().map((h) => [new Date(h.started_ms).toISOString(), h.direction, h.remote, h.remote_name, h.answered, h.duration_s.toFixed(1), h.final_code, h.reason, h.ended_by, h.codec, (h.offer_codecs || []).join(" "), (h.answer_codecs || []).join(" "), h.mos, h.loss_pct, accName(h.account), h.call_id].map(q).join(","));
  return [head.join(","), ...lines].join("\r\n");
}

// ============================================================================
// SIP trace

// ---- calls in the trace: one entry per Call-ID that carries an INVITE

const uriUser = (h) => ((h || "").match(/<?sips?:([^@;>]+)/i) || [])[1] || "";
const hdr = (raw, name) => ((raw.match(new RegExp(`^(?:${name}):[ \\t]*(.*)$`, "mi")) || [])[1] || "").trim();

function traceCalls() {
  const calls = new Map();
  for (const t of S.trace) {
    if (!t.call_id) continue;
    let c = calls.get(t.call_id);
    if (!c && t.method === "INVITE" && !t.status) {
      const ruri = (t.first_line.split(" ")[1] || "");
      c = {
        id: t.call_id, ts: t.ts_ms, out: t.dir === "out",
        dialed: uriUser(ruri) || uriUser(hdr(t.raw, "To|t")),
        from: uriUser(hdr(t.raw, "From|f")), to: uriUser(hdr(t.raw, "To|t")),
        status: null, links: new Set(),
      };
      calls.set(t.call_id, c);
    }
    if (!c) continue;
    // The last final answer counts: a 401 challenge is followed by the real result.
    if (t.method === "INVITE" && t.status >= 200) c.status = t.status;
    // Transfers name the other leg: Replaces in an INVITE, Refer-To ...?Replaces= in a REFER.
    for (const v of [hdr(t.raw, "Replaces"), decodeURIComponent(((hdr(t.raw, "Refer-To|r").match(/Replaces=([^;>&]+)/i) || [])[1]) || "")]) {
      const other = (v || "").split(";")[0].trim();
      if (other) c.links.add(other);
    }
  }
  // Links work both ways.
  for (const c of calls.values()) for (const o of c.links) calls.get(o)?.links.add(c.id);
  return calls;
}

function traceCallOptions() {
  const sel = $("#tr-call");
  const calls = traceCalls();
  const sig = [...calls.values()].map((c) => `${c.id}:${c.status}`).join("|");
  if (sel.dataset.sig === sig) return;
  // Rebuilding the options closes an open dropdown: wait until it is not in use.
  if (document.activeElement === sel) return;
  sel.dataset.sig = sig;
  const keep = sel.value;
  const res = (c) => (c.status == null ? t("in progress") : c.status < 300 ? t("answered") : String(c.status));
  sel.innerHTML = [`<option value="">${esc(t("All messages"))}</option>`, `<option value="*calls">${esc(t("Calls only"))}</option>`,
    ...[...calls.values()].reverse().map((c) => `<option value="${esc(c.id)}">${clock(c.ts)} ${c.out ? "→" : "←"} ${esc(c.out ? c.dialed : c.from || c.dialed)} (${esc(res(c))})</option>`)].join("");
  sel.value = [...sel.options].some((o) => o.value === keep) ? keep : "";
}

/// Call-IDs the trace shows for the chosen call (and its related legs).
function traceCallSet() {
  const v = $("#tr-call").value;
  if (!v) return null;
  const calls = traceCalls();
  if (v === "*calls") return new Set(calls.keys());
  const set = new Set([v]);
  if ($("#tr-legs").checked) {
    // Follow links transitively: A replaced by B, B transferred to C...
    const todo = [v];
    while (todo.length) for (const o of calls.get(todo.pop())?.links || []) if (!set.has(o)) { set.add(o); todo.push(o); }
  }
  return set;
}

/// Compiled display filter of an input, with the error shown on the input.
function inputFilter(el) {
  const src = el.value;
  if (el._src === src) return el._fn;
  const c = compileFilter(src);
  el._src = src;
  el._fn = c.error ? null : c.fn;
  el.classList.toggle("bad-filter", !!c.error);
  el.title = c.error ? `${t("Filter error")}: ${c.error}` : t("Like Wireshark: ip.addr, ip.src, port, transport, sip.method, sip.status, sip.from, sip.to, sip.call_id, sip.ua, sdp.ip, sdp.codec; ==, !=, >, contains, ~ (regex); and, or, not, ( ). A word or \"text\" searches the whole message.");
  return el._fn;
}

function traceVisible(t) {
  if (S.trCalls && !S.trCalls.has(t.call_id)) return false;
  if ($("#tr-hide-reg").checked && t.method === "REGISTER") return false;
  if ($("#tr-hide-opt").checked && ["OPTIONS", "NOTIFY", "SUBSCRIBE", "PUBLISH"].includes(t.method)) return false;
  const fn = inputFilter($("#tr-filter"));
  return fn ? fn(t) : true;
}

function traceRow(t) {
  const cls = t.status ? (t.status >= 400 ? "r-err" : t.status >= 300 ? "r-warn" : t.status >= 200 ? "r-ok" : "r-prov") : "r-req";
  return `<div class="tr-row ${t.dir} ${cls}${t.seq === S.trSel ? " sel" : ""}" data-seq="${t.seq}">
    <span class="tr-t">${clock(t.ts_ms, true)}</span>
    <span class="tr-d">${t.dir === "out" ? "→" : "←"}</span>
    <span class="tr-a">${esc(t.dir === "out" ? t.dst : t.src)}</span>
    <span class="tr-f">${esc(t.first_line)}</span>
    <span class="tr-c" title="${esc(t.call_id)}">${esc(t.call_id.length > 14 ? `${t.call_id.slice(0, 12)}…` : t.call_id)}</span>
  </div>`;
}

function onTrace(items) {
  if (!items.length) return;
  for (const t of items) S.trace.push(t);
  if (S.trace.length > 5000) S.trace.splice(0, S.trace.length - 5000);
  if (S.page === "trace" && !S.trPaused) {
    traceCallOptions();
    if ($("#tr-call").value) S.trCalls = traceCallSet();
    const list = $("#tr-list");
    const atEnd = list.scrollTop + list.clientHeight >= list.scrollHeight - 30;
    list.insertAdjacentHTML("beforeend", items.filter(traceVisible).map(traceRow).join(""));
    while (list.children.length > 3000) list.firstElementChild.remove();
    if (atEnd) list.scrollTop = list.scrollHeight;
  }
  if (S.page === "settings" && items.some((x) => /REGISTER/.test(x.cseq))) renderAccReg();
  renderStatus();
}

function renderTrace(scroll) {
  traceCallOptions();
  S.trCalls = traceCallSet();
  const list = $("#tr-list");
  const rows = S.trace.filter(traceVisible).slice(-3000);
  const emptyText = S.trace.length ? t("No messages match the filter.") : !currentAccount() ? t("No account yet: add one in Settings and its REGISTER shows here.") : t("SIP messages sent and received by the phone appear here live. Make a call to see one.");
  const head = `<div class="tr-row tr-head" aria-hidden="true"><span class="tr-t">${esc(t("Time"))}</span><span class="tr-d"></span><span class="tr-a">${esc(t("Peer"))}</span><span class="tr-f">${esc(t("Message"))}</span><span class="tr-c">Call-ID</span></div>`;
  list.innerHTML = rows.length ? head + rows.map(traceRow).join("") : `<p class="empty-note pad">${esc(emptyText)}</p>`;
  if (scroll) list.scrollTop = list.scrollHeight;
}

function bindTrace() {
  ["tr-filter", "tr-hide-reg", "tr-hide-opt", "tr-legs"].forEach((id) => $("#" + id).addEventListener("input", () => renderTrace(false)));
  $("#tr-call").addEventListener("change", () => renderTrace(true));
  $("#tr-list").addEventListener("click", (e) => {
    const r = e.target.closest(".tr-row");
    if (!r) return;
    S.trSel = +r.dataset.seq;
    $$(".tr-row.sel").forEach((x) => x.classList.remove("sel"));
    r.classList.add("sel");
    const t = S.trace.find((x) => x.seq === S.trSel);
    if (t) $("#tr-view").innerHTML = `<span class="muted">${esc(t.dir === "out" ? "Sent" : "Received")} ${clock(t.ts_ms, true)}, ${esc(t.transport)} ${esc(t.src)} → ${esc(t.dst)}, ${t.size} bytes</span>\n\n${highlightSip(t.raw)}`;
  });
  $("#tr-list").addEventListener("keydown", (e) => {
    if (e.key !== "ArrowDown" && e.key !== "ArrowUp") return;
    e.preventDefault();
    const cur = $(".tr-row.sel");
    const next = cur ? (e.key === "ArrowDown" ? cur.nextElementSibling : cur.previousElementSibling) : $(".tr-row");
    if (next) {
      next.click();
      next.scrollIntoView({ block: "nearest" });
    }
  });
  $("#tr-pause").addEventListener("click", (e) => {
    S.trPaused = !S.trPaused;
    e.target.setAttribute("aria-pressed", String(S.trPaused));
    e.target.textContent = S.trPaused ? "Resume" : "Pause";
    if (!S.trPaused) renderTrace(true);
  });
  $("#tr-clear").addEventListener("click", async () => {
    if (S.trace.length && !confirm(t("Clear the trace and the packets captured so far? Calls in the history keep their own capture."))) return;
    S.trace = [];
    S.trSel = null;
    $("#tr-view").innerHTML = "";
    await S.ctl.clearCapture().catch(() => {});
    renderTrace(false);
    renderStatus();
  });
  $("#tr-save").addEventListener("click", async () => {
    try {
      const b = await S.ctl.capture(S.be, { wire: true });
      await download(b, `sidetone-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, "")}.pcapng`, "application/vnd.tcpdump.pcap");
    } catch (e) {
      toast(e.message || String(e), 4000);
    }
  });
  $("#tr-save-dec").addEventListener("click", async () => {
    try {
      const b = await S.ctl.capture(S.be);
      await download(b, `sidetone-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, "")}-decrypted.pcapng`, "application/vnd.tcpdump.pcap");
    } catch (e) {
      toast(e.message || String(e), 4000);
    }
  });
  $("#tr-analyze").addEventListener("click", () => {
    const t = S.trace.find((x) => x.seq === S.trSel);
    analyzeLine(t ? t.call_id : null);
  });
}

// ============================================================================
// Analysis (captures)

async function load(bytes, name, webrtc = null) {
  stopLive();
  try {
    const report = await S.be.analyze(bytes);
    Object.assign(S, { bytes, name, report, call: null, msg: null, webrtc, picked: new Set() });
  } catch (e) {
    // The reason stays on the empty page, where the file was dropped.
    const err = $("#an-load-err");
    err.hidden = false;
    err.textContent = `${t("Could not read")} ${name}: ${e.message || e}`;
    if (S.page !== "analysis") showWs("analysis");
    return;
  }
  $("#an-load-err").hidden = true;
  $("#an-empty").hidden = true;
  $("#an").hidden = false;
  const s = S.report.summary;
  $("#capinfo").textContent = `${name}: ${s.calls} dialogs, ${s.sip_messages} SIP messages, ${s.rtp_streams} RTP streams, ${s.duration_s.toFixed(1)} s, ${s.errors} errors, ${s.warnings} warnings`;
  renderCalls();
  const r = S.report;
  const first = r.calls.findIndex((c) => c.errors > 0);
  const inv = r.calls.findIndex((c) => c.kind === "INVITE");
  await selectCall(first >= 0 ? first : inv >= 0 ? inv : r.calls.length ? 0 : null);
}

async function loadFile(f) {
  await load(new Uint8Array(await f.arrayBuffer()), f.name);
  showWs("analysis");
}

const AN_STATE = { answered: "Answered", failed: "Failed", cancelled: "Cancelled", in_progress: "No answer", non_invite: "" };

/// Dialogs ticked in the list: with two or more, one ladder shows them together.
function pickedCalls() {
  return [...S.picked].filter((i) => S.report && i < S.report.calls.length).sort((a, b) => a - b);
}
function inView(call) {
  const p = pickedCalls();
  if (p.length > 1) return p.includes(call);
  return S.call == null || call === S.call;
}

/// Messages matching the Analysis filter (null when there is no filter).
function anMatches() {
  const fn = inputFilter($("#an-filter"));
  if (!fn || !S.report) return null;
  return new Set(S.report.messages.filter((m) => fn(m)).map((m) => m.index));
}

function renderCalls() {
  const r = S.report;
  const hits = anMatches();
  $("#an-filter-info").textContent = hits ? `${hits.size} ${t("messages match")}` : "";
  $("#calls-count").textContent = S.picked.size > 1 ? `${S.picked.size} / ${r.calls.length}` : r.calls.length;
  $("#calls-clear").hidden = !S.picked.size;
  $("#calls").innerHTML = r.calls
    .filter((c) => !hits || c.messages.some((i) => hits.has(i)))
    .map((c) => {
      const st = c.state;
      const label = st === "non_invite" ? (c.final_status ? `${c.final_status}` : "no answer") : `${AN_STATE[st]}${c.final_status ? " " + c.final_status : ""}`;
      const moss = c.streams.map((i) => r.streams[i].mos).filter((m) => m != null);
      const mos = moss.length ? Math.min(...moss) : null;
      const silent = c.streams.some((i) => r.streams[i].silence_pct >= 95);
      const quality = `${mos != null ? `<span class="q-chip ${mos < 3.1 ? "bad" : mos < 3.6 ? "warn" : "ok"}" title="${esc(t("Lowest estimated MOS of the call's streams"))}">MOS ${mos.toFixed(1)}</span>` : ""}${silent ? `<span class="q-chip bad" title="${esc(t("RTP flows but carries silence"))}">${esc(t("silent"))}</span>` : ""}`;
      const legs = c.related && c.related.length ? `<span class="c-legs" role="button" tabindex="0" data-legs="${c.index}" title="${esc(t("Legs of the same call") + ": " + c.related_by.join(", "))}">⛓ ${c.related.length + 1} ${esc(t("legs"))}</span>` : "";
      const counts = `${quality}${legs}${c.errors ? `<span class="cnt-e">${c.errors} error${c.errors > 1 ? "s" : ""}</span>` : ""}${c.warnings ? `<span class="cnt-w">${c.warnings} warning${c.warnings > 1 ? "s" : ""}</span>` : ""}`;
      return `<li class="${S.picked.has(c.index) ? "picked" : ""}"><label class="c-pick" title="${esc(t("Add to the ladder"))}"><input type="checkbox" data-pick="${c.index}" ${S.picked.has(c.index) ? "checked" : ""}></label><button type="button" data-call="${c.index}">
        <span class="c-top"><span>${esc(c.kind)}</span><span class="state ${st}">${esc(label)}</span></span>
        <span class="c-parties">${esc(c.from)} → ${esc(c.to)}</span>
        <span class="c-meta"><span>+${c.start_rel_s.toFixed(1)} s</span>${c.talk_s != null ? `<span>${c.talk_s.toFixed(1)} s talk</span>` : ""}${counts}</span>
      </button></li>`;
    })
    .join("");
}

async function selectCall(i, user = false) {
  if (user && LIVE.on && S.report && S.report.calls[i]) LIVE.keep = S.report.calls[i].call_id;
  S.call = i;
  S.msg = null;
  const picked = pickedCalls();
  const multi = picked.length > 1;
  $$("#calls button").forEach((b) => b.setAttribute("aria-current", String(multi ? picked.includes(+b.dataset.call) : +b.dataset.call === i)));
  const r = S.report;
  const c = i == null || multi ? null : r.calls[i];
  $("#call-head").innerHTML = multi
    ? `<h2>${picked.length} ${esc(t("dialogs together"))}</h2><dl>${picked.map((k) => `<div><dt>${esc(r.calls[k].kind)}</dt><dd class="mono">${esc(r.calls[k].call_id)}</dd></div>`).join("")}</dl>`
    : c
    ? `<h2>${esc(c.call_id)}</h2><dl>
        ${c.final_status ? `<div><dt>Final</dt><dd>${c.final_status} ${esc(c.final_reason || "")}</dd></div>` : ""}
        ${c.pdd_ms != null ? `<div><dt>Post-dial delay</dt><dd>${(c.pdd_ms / 1000).toFixed(2)} s</dd></div>` : ""}
        ${c.talk_s != null ? `<div><dt>Talk</dt><dd>${c.talk_s.toFixed(1)} s</dd></div>` : ""}
        ${c.ended_by ? `<div><dt>Ended by</dt><dd>${esc(c.ended_by)}</dd></div>` : ""}
        ${c.offer_codecs.length ? `<div><dt>Offer</dt><dd>${esc([...new Set(c.offer_codecs)].join(", "))}</dd></div>` : ""}
        ${c.answer_codecs.length ? `<div><dt>Answer</dt><dd>${esc([...new Set(c.answer_codecs)].join(", "))}</dd></div>` : ""}
        ${c.user_agents.length ? `<div><dt>Agents</dt><dd>${esc(c.user_agents.join(" / "))}</dd></div>` : ""}
      </dl>`
    : `<h2>All messages</h2>`;
  $("#ladder").innerHTML = multi && S.be.ladderCalls ? await S.be.ladderCalls(S.bytes, picked) : await S.be.ladder(S.bytes, i);
  ladderScrollHint();
  markLadderMatches();
  renderFindings();
  renderMedia();
  renderLog();
  renderExplainTab();
  $("#tab-message").innerHTML = `<p class="empty-note">Click an arrow in the ladder to see the full message.</p>`;
}

/// Empty ladder and details, waiting for a dialog to be picked.
function clearLadder() {
  S.msg = null;
  $$("#calls button").forEach((b) => b.setAttribute("aria-current", "false"));
  $("#call-head").innerHTML = "";
  $("#ladder").innerHTML = `<p class="empty-note pad">${esc(t("No dialog selected. Click one on the left, or tick several to see them together."))}</p>`;
  $("#tab-message").innerHTML = "";
  $("#tab-explain").innerHTML = renderExplain(S.report, null, []);
}

/// Highlights the ladder arrows that match the Analysis filter.
function markLadderMatches() {
  const hits = anMatches();
  $$("#ladder .msg").forEach((g) => g.classList.toggle("match", !!hits && hits.has(+g.dataset.msg)));
}

function renderExplainTab() {
  const p = pickedCalls();
  const box = $("#tab-explain");
  if (p.length > 1) {
    box.innerHTML = p.map((k) => `<h2 class="x-leg">${esc(S.report.calls[k].kind)} <span class="mono">${esc(S.report.calls[k].call_id)}</span></h2>${renderExplain(S.report, k, S.report.findings)}`).join("");
    return;
  }
  box.innerHTML = renderExplain(S.report, S.call, S.report.findings);
}

function callFindings() {
  return S.report.findings.filter((f) => f.call == null || inView(f.call));
}

function renderFindings() {
  const fs = callFindings();
  $("#n-findings").textContent = fs.length || "";
  if (!fs.length) {
    $("#tab-findings").innerHTML = `<p class="empty-note">No findings for this dialog. Signaling and media look as expected.</p>`;
    return;
  }
  const sevName = { error: "Error", warning: "Warning", info: "Note" };
  $("#tab-findings").innerHTML = `<ul class="findings">${fs
    .map((f) => {
      const idx = S.report.findings.indexOf(f);
      return `<li class="${f.severity}" data-finding="${idx}" tabindex="0">
        <div><span class="f-sev">${esc(t(sevName[f.severity]))}</span><span class="f-title">${esc(trFinding(f.title))}</span></div>
        <div class="f-detail">${esc(trFinding(f.detail))}</div>
        <div class="f-rule">${esc(f.rule)}${f.messages.length ? `, messages ${f.messages.map((m) => "#" + m).join(" ")}` : ""}</div>
      </li>`;
    })
    .join("")}</ul>`;
}

function highlightSip(raw) {
  const sep = raw.search(/\r?\n\r?\n/);
  const head = sep >= 0 ? raw.slice(0, sep) : raw;
  const body = sep >= 0 ? raw.slice(sep).replace(/^\r?\n\r?\n/, "") : "";
  const ls = head.split(/\r?\n/);
  const code = +((ls[0].match(/^SIP\/2\.0 (\d{3})/) || [])[1] || 0);
  const out = [`<span class="sl"${code && explainOn() ? ` title="${esc(statusHelp(code))}"` : ""}>${esc(ls[0])}</span>`];
  for (const l of ls.slice(1)) {
    const i = l.indexOf(":");
    const help = i > 0 && explainOn() ? headerHelp(l.slice(0, i)) : "";
    out.push(i > 0 ? `<span class="hn${help ? " has-help" : ""}"${help ? ` title="${esc(help)}"` : ""}>${esc(l.slice(0, i))}</span>${esc(l.slice(i))}` : esc(l));
  }
  return out.join("\n") + (body ? `\n\n<span class="sdp">${esc(body)}</span>` : "");
}

/// Plain-language summary of one SIP message in its call: who called whom,
/// what was dialed, what this message is, how long the answer took.
function messageSummary(m) {
  const r = S.report;
  const c = m.call != null ? r.calls[m.call] : null;
  const H = (n) => hdr(m.raw, n);
  const user = (h) => uriUser(h);
  const name = (h) => ((h || "").match(/^\s*"([^"]*)"/) || (h || "").match(/^\s*([^<"]+?)\s*</) || [])[1] || "";
  const party = (h) => (h ? `${name(h) ? `<b>${esc(name(h))}</b> ` : ""}<span class="mono">${esc(user(h) || h)}</span>` : "");
  const mono = (v) => (v ? `<span class="mono">${esc(v)}</span>` : "");
  const cseq = m.cseq || H("CSeq");
  const method = m.method || (cseq.split(" ")[1] || "");
  let what;
  let timing = "";
  if (m.status) {
    what = `${t("Response")} <b>${esc(m.raw.split(/\r?\n/)[0])}</b> ${t("to")} ${esc(method)}`;
    // The request this response answers: same branch and CSeq, sent the other way.
    const req = (c ? c.messages : r.messages.map((x) => x.index))
      .map((i) => r.messages[i])
      .find((x) => !x.status && x.branch === m.branch && x.cseq === m.cseq && x.index < m.index);
    if (req) timing = `${((m.ts_ns - req.ts_ns) / 1e6).toFixed(0)} ms ${t("after the request")} (#${req.index})`;
  } else {
    what = `${t("Request")} <b>${esc(method)}</b>${m.retransmission ? ` <span class="warn">${t("retransmission")}</span>` : ""}`;
    const resp = r.messages.filter((x) => x.status && x.branch === m.branch && x.cseq === m.cseq && x.index > m.index);
    const fin = resp.find((x) => x.status >= 200);
    if (fin) timing = `${t("answered")} ${fin.status} ${t("in")} ${((fin.ts_ns - m.ts_ns) / 1e6).toFixed(0)} ms (#${fin.index})`;
    else if (resp.length) timing = `${resp.length} ${t("provisional responses, no final answer")}`;
    else timing = t("no response in the capture");
  }
  const ruriUser = c ? user(c.request_uri) : "";
  const sdp = m.sdp && m.sdp.media && m.sdp.media.length ? m.sdp : null;
  const media = sdp
    ? sdp.media
        .map((md) => {
          const ip = md.connection || sdp.connection || "";
          const sec = md.fingerprint ? " DTLS-SRTP" : md.crypto && md.crypto.length ? " SRTP (SDES)" : "";
          return `${esc(md.kind)} ${mono(`${ip}:${md.port}`)} ${esc(md.proto)} ${esc((md.codecs || []).map((x) => x.name).join(", "))}, ${esc(md.direction)}${sec}`;
        })
        .join("<br>")
    : "";
  const rows = [
    [t("Message"), what],
    [t("Timing"), esc(timing)],
    [t("Dialed"), ruriUser ? `<b class="mono">${esc(ruriUser)}</b> <span class="muted mono">${esc(c.request_uri)}</span>` : ""],
    [t("Caller"), party(H("From|f"))],
    [t("Called"), party(H("To|t"))],
    [t("Identity"), party(H("P-Asserted-Identity")) || party(H("Remote-Party-ID"))],
    [t("Diverted by"), party(H("Diversion")) || party(H("History-Info"))],
    [t("Agent"), esc(H("User-Agent") || H("Server"))],
    [t("Contact"), mono(H("Contact|m"))],
    [t("Reason"), esc(H("Reason") || H("Warning"))],
    [t("Media"), media],
    ["Call-ID", mono(m.call_id || H("Call-ID|i"))],
    ["CSeq", mono(cseq)],
    [t("Call result"), c ? esc([c.final_status ? `${c.final_status} ${c.final_reason || ""}`.trim() : t("no final response"), c.pdd_ms != null ? `${t("post-dial delay")} ${(c.pdd_ms / 1000).toFixed(2)} s` : "", c.talk_s != null ? `${t("talk")} ${c.talk_s.toFixed(1)} s` : "", c.ended_by ? `${t("ended by")} ${c.ended_by}` : ""].filter(Boolean).join(" · ")) : ""],
  ];
  return `<section class="msg-sum">${kv(rows)}</section>`;
}

const explainOn = () => store.get("sidetone.explain", true);

/// The SDP body of a message, if it has one.
function sdpOf(m) {
  const i = m.raw.search(/\r?\n\r?\n/);
  const body = i >= 0 ? m.raw.slice(i).trim() : "";
  return /^v=0/m.test(body) ? body : "";
}

function selectMessage(idx, switchTab = true) {
  S.msg = idx;
  $$("#ladder .msg").forEach((g) => g.classList.toggle("sel", +g.dataset.msg === idx));
  $$("#ladder .stream").forEach((g) => g.classList.remove("sel"));
  const g = $(`#ladder .msg[data-msg="${idx}"]`);
  if (g) g.scrollIntoView({ block: "nearest", inline: "nearest" });
  const m = S.report.messages[idx];
  const related = S.report.findings.filter((f) => f.messages.includes(idx));
  $("#tab-message").innerHTML = `
    <div class="msg-meta"><span>#${m.index}</span><span>frame ${m.frame}</span><span>+${m.rel_s.toFixed(3)} s</span><span>${esc(m.src)} → ${esc(m.dst)}</span><span>${m.transport}</span>${m.retransmission ? "<span>retransmission</span>" : ""}</div>
    ${m.parse_notes.length ? `<p class="msg-notes">${esc(m.parse_notes.join("; "))}</p>` : ""}
    ${messageSummary(m)}
    ${m.status ? `<p class="status-help"><b>${m.status}</b> ${esc(statusHelp(m.status))}</p>` : ""}
    ${sdpOf(m) ? `<details class="sdp-explained" open><summary>${esc(t("SDP explained line by line"))}</summary>${sdpTable(sdpOf(m))}</details>` : ""}
    ${related.length ? `<ul class="findings" style="margin-bottom:10px">${related.map((f) => `<li class="${f.severity}"><span class="f-title">${esc(trFinding(f.title))}</span><div class="f-detail">${esc(trFinding(f.detail))}</div></li>`).join("")}</ul>` : ""}
    <pre class="sipmsg">${highlightSip(m.raw)}</pre>`;
  if (switchTab) showTab("message");
}

function webrtcBlock() {
  const w = S.webrtc;
  if (!w) return "";
  const rows = [
    ["Codec", w.codec], ["Packets received", w.packets_received], ["Packets sent", w.packets_sent], ["Packets lost", w.packets_lost],
    ["Loss", `${w.loss_pct}%`], ["Max jitter", `${w.max_jitter_ms} ms`], ["Max round trip", `${w.max_rtt_ms} ms`], ["ICE path", w.ice_path], ["Seconds measured", w.seconds],
  ].filter(([, v]) => v !== undefined && v !== null);
  return `<section class="webrtc"><h3>Browser WebRTC statistics</h3><dl>${rows.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join("")}</dl>
    <p class="muted">Media was DTLS-SRTP inside the browser, so it is not part of the capture; these numbers come from getStats().</p></section>`;
}

function renderMedia() {
  stopPlayer();
  PL.buf = null;
  const r = S.report;
  const streams = r.streams.filter((s) => inView(s.call));
  $("#n-media").textContent = streams.length || (S.webrtc ? "1" : "");
  if (S.webrtc && !streams.length) {
    $("#tab-media").innerHTML = webrtcBlock();
    return;
  }
  if (!streams.length) {
    $("#tab-media").innerHTML = `<p class="empty-note">${r.streams.length ? "No RTP linked to this dialog." : "The capture has no RTP. Capture media too (not only port 5060) to analyze audio."}</p>`;
    return;
  }
  const cls = (v, w, b) => (v >= b ? "bad" : v >= w ? "warn" : "");
  $("#tab-media").innerHTML = `<div class="table-wrap"><table class="media"><thead><tr>
      <th></th><th>Stream</th><th>Codec</th><th>Packets</th><th>Lost</th><th>Loss</th><th>Jitter</th><th>Max jitter</th><th>Max gap</th><th>ptime</th><th>MOS est.</th><th title="${esc(t("What the receiver reports in RTCP: loss, jitter, round trip; MOS from RTCP XR"))}">RTCP</th><th title="${esc(t("Share of the decoded audio that is silent (G.711)"))}">${esc(t("Silent"))}</th><th>DTMF</th></tr></thead><tbody>
    ${streams
      .map(
        (s) => `<tr data-stream="${s.id}"><td><button type="button" class="icon-btn play-btn" data-play="${s.id}" title="${esc(t("Listen and see the waveform"))}">▶</button></td><td>${esc(s.src)} → ${esc(s.dst)}<br><span class="muted">SSRC ${esc(s.ssrc)}</span></td>
        <td>${esc(s.codec)}</td><td>${s.packets}</td><td>${Math.max(0, s.lost)}</td>
        <td class="${cls(s.loss_pct, 1, 5)}">${s.loss_pct.toFixed(2)}%</td>
        <td class="${cls(s.jitter_ms, 30, 60)}">${s.jitter_ms.toFixed(1)} ms</td>
        <td class="${cls(s.max_jitter_ms, 50, 80)}">${s.max_jitter_ms.toFixed(1)} ms</td>
        <td class="${cls(s.max_gap_ms, 500, 1000)}">${s.max_gap_ms.toFixed(0)} ms</td>
        <td>${s.mean_ptime_ms ? s.mean_ptime_ms.toFixed(0) + " ms" : ""}</td>
        <td class="${s.mos == null ? "" : s.mos < 3.1 ? "bad" : s.mos < 3.6 ? "warn" : ""}">${s.mos == null ? "n/a" : s.mos.toFixed(2)}</td>
        <td class="rtcp-cell">${rtcpCell(s)}</td>
        <td class="${s.silence_pct >= 95 ? "bad" : ""}">${s.silence_pct == null ? "" : `${s.silence_pct.toFixed(0)}%`}${s.clipping_pct >= 1 ? `<br><span class="warn">${esc(t("clipped"))} ${s.clipping_pct.toFixed(1)}%</span>` : ""}</td>
        <td>${esc(s.dtmf_events.join(""))}</td></tr>`
      )
      .join("")}</tbody></table></div>
    <div class="rtp-player" id="rtp-player" hidden></div>
    ${streams.filter((s) => s.series && s.series.length > 1).map(qualityChart).join("")}
    ${jitterBufferTable(streams)}
    ${rtcpTables(streams)}
    <p class="muted">MOS is an E-model (ITU-T G.107) estimate from loss and jitter at this capture point; network delay is approximated.</p>${webrtcBlock()}`;
}

// ---- Quality over time: three thin charts per stream (jitter, loss, MOS)
// sharing one time axis, each with its own scale, with the SIP events of the
// call marked and a crosshair that reads all three at the same second.

function rtcpCell(s) {
  const parts = [];
  if (s.remote_loss_pct != null) parts.push(`${t("loss")} ${s.remote_loss_pct.toFixed(1)}%`);
  if (s.remote_jitter_ms != null) parts.push(`jitter ${s.remote_jitter_ms.toFixed(0)} ms`);
  if (s.rtt_ms != null) parts.push(`RTT ${s.rtt_ms.toFixed(0)} ms`);
  if (s.xr_mos != null) parts.push(`MOS ${s.xr_mos.toFixed(1)} (XR)`);
  return parts.length ? esc(parts.join(" · ")) : `<span class="muted">${s.rtcp && s.rtcp.length ? "SR" : "-"}</span>`;
}

// MOS through simulated jitter buffers: a late packet is as lost as a missing one.
function jitterBufferTable(streams) {
  const withJ = streams.filter((s) => s.jitter_buffers && s.jitter_buffers.length);
  if (!withJ.length) return "";
  const names = ["fixed 50 ms", "fixed 200 ms", "adaptive"];
  const cell = (j) => {
    if (!j) return "<td></td>";
    const m = j.mos == null ? "n/a" : j.mos.toFixed(2);
    const c = j.mos == null ? "" : j.mos < 3.1 ? "bad" : j.mos < 3.6 ? "warn" : "";
    return `<td class="${c}"><b>${m}</b><br><span class="muted">${j.discarded} ${esc(t("late"))} · ${esc(t("loss"))} ${j.loss_pct.toFixed(1)}% · ${j.delay_ms.toFixed(0)} ms</span></td>`;
  };
  return `<details class="rtcp-reports jb-table"><summary>${esc(t("MOS through a jitter buffer"))}</summary>
    <p class="muted">${esc(t("Packets that arrive after their playout time are dropped by the receiver's jitter buffer and count as lost; a bigger buffer drops fewer but adds delay."))}</p>
    <table class="media"><thead><tr><th>Stream</th>${names.map((n) => `<th>${esc(t(n === "adaptive" ? "Adaptive (up to 500 ms)" : n === "fixed 50 ms" ? "Fixed 50 ms" : "Fixed 200 ms"))}</th>`).join("")}</tr></thead><tbody>${withJ
      .map((s) => `<tr data-stream="${s.id}"><td>${esc(s.src)} → ${esc(s.dst)}<br><span class="muted">${esc(s.codec)}</span></td>${names.map((n) => cell(s.jitter_buffers.find((j) => j.name === n))).join("")}</tr>`)
      .join("")}</tbody></table></details>`;
}

function rtcpTables(streams) {
  const withR = streams.filter((s) => s.rtcp && s.rtcp.some((v) => v.kind !== "SR"));
  if (!withR.length) return "";
  return `<details class="rtcp-reports"><summary>${esc(t("RTCP reports"))} (${withR.reduce((n, s) => n + s.rtcp.length, 0)})</summary>${withR
    .map(
      (s) => `<h4 class="mono">${esc(s.src)} → ${esc(s.dst)} <span class="muted">SSRC ${esc(s.ssrc)}</span></h4>
      <table class="media"><thead><tr><th>${esc(t("Time"))}</th><th>${esc(t("Kind"))}</th><th>${esc(t("From"))}</th><th>${esc(t("Loss"))}</th><th>${esc(t("Cumulative"))}</th><th>Jitter</th><th>RTT</th><th>MOS-LQ</th><th>R</th></tr></thead><tbody>${s.rtcp
        .map(
          (v) => `<tr data-frame="${v.frame}"><td class="mono">+${v.t.toFixed(3)}s</td><td>${esc(v.kind)}</td><td class="mono">${esc(v.from)}</td><td>${v.fraction_lost_pct == null ? "" : v.fraction_lost_pct.toFixed(1) + "%"}</td><td>${v.cumulative_lost ?? ""}</td><td>${v.jitter_ms == null ? "" : v.jitter_ms.toFixed(1) + " ms"}</td><td>${v.rtt_ms == null ? "" : v.rtt_ms.toFixed(0) + " ms"}</td><td>${v.mos_lq ?? ""}</td><td>${v.r_factor ?? ""}</td></tr>`
        )
        .join("")}</tbody></table>`
    )
    .join("")}</details>`;
}

function qualityChart(s) {
  const se = s.series;
  const W = 900, H = 46, padL = 64, padR = 12, gap = 8;
  const t0 = (s.start_ns - S.report.summary.start_ns) / 1e9;
  const n = se.length;
  const x = (i) => padL + (i / Math.max(1, n - 1)) * (W - padL - padR);
  const rows = [
    { key: 3, label: "Jitter", unit: "ms", max: Math.max(40, ...se.map((r) => r[3])), warn: 30 },
    { key: 2, label: t("Lost"), unit: t("pkts"), max: Math.max(5, ...se.map((r) => r[2])), warn: null },
    { key: 4, label: "MOS", unit: "", max: 5, min: 1, warn: 3.6 },
  ];
  // SIP events of this call inside the stream's time span.
  const msgs = s.call != null ? S.report.calls[s.call].messages.map((i) => S.report.messages[i]) : [];
  const evs = msgs
    .filter((m) => (m.method && m.method !== "ACK") || (m.status && m.status >= 200 && /INVITE|BYE|UPDATE/.test(m.cseq || "")))
    .map((m) => ({ at: m.rel_s - t0, label: m.label.replace(/ \(SDP\)/, "") }))
    .filter((e) => e.at >= -0.5 && e.at <= n);
  const totalH = rows.length * (H + gap) + 18;
  let svg = `<svg class="qchart" viewBox="0 0 ${W} ${totalH}" data-stream="${s.id}" role="img" aria-label="${esc(t("Quality over time"))}">`;
  rows.forEach((r, k) => {
    const top = k * (H + gap);
    const lo = r.min ?? 0;
    const y = (v) => top + H - ((Math.min(r.max, Math.max(lo, v)) - lo) / (r.max - lo)) * H;
    svg += `<text class="ql" x="0" y="${top + 13}">${esc(r.label)}</text><text class="qv" x="0" y="${top + 27}">${r.key === 4 ? "" : `max ${Math.round(r.max)} ${esc(r.unit)}`}</text>`;
    svg += `<line class="qbase" x1="${padL}" x2="${W - padR}" y1="${top + H}" y2="${top + H}"/>`;
    if (r.warn != null) svg += `<line class="qwarn" x1="${padL}" x2="${W - padR}" y1="${y(r.warn)}" y2="${y(r.warn)}"/>`;
    if (r.key === 2) {
      // Loss as bars: missing packets are counts, not a trend.
      const bw = Math.max(1.5, (W - padL - padR) / n - 2);
      se.forEach((row, i) => {
        if (row[2] > 0) svg += `<rect class="qbar" x="${x(i) - bw / 2}" y="${y(row[2])}" width="${bw}" height="${top + H - y(row[2])}" rx="1"/>`;
      });
    } else {
      const pts = se.map((row, i) => (r.key === 4 && !row[4] ? null : `${x(i).toFixed(1)},${y(row[r.key]).toFixed(1)}`));
      let d = "";
      pts.forEach((p, i) => {
        if (!p) return;
        d += `${!pts[i - 1] ? "M" : "L"}${p}`;
      });
      svg += `<path class="qline" d="${d}"/>`;
    }
  });
  // Events at the same second share one marker; labels near the right edge
  // are anchored to the end so they stay inside the chart.
  const marks = [];
  for (const e of evs) {
    const ex = x(Math.max(0, Math.min(n - 1, e.at)));
    const prev = marks[marks.length - 1];
    if (prev && Math.abs(prev.x - ex) < 1) prev.labels.push(e.label);
    else marks.push({ x: ex, labels: [e.label] });
  }
  let lastEnd = -Infinity;
  for (const m of marks) {
    const label = m.labels.join(" / ");
    const wide = label.length * 6.2;
    const atEnd = m.x + 3 + wide > W;
    const start = atEnd ? m.x - 3 - wide : m.x + 3;
    svg += `<line class="qev" x1="${m.x}" x2="${m.x}" y1="0" y2="${rows.length * (H + gap) - gap}"/>`;
    if (start > lastEnd + 6) {
      svg += `<text class="qevl" x="${atEnd ? m.x - 3 : m.x + 3}" y="${totalH - 4}"${atEnd ? ' text-anchor="end"' : ""}>${esc(label)}</text>`;
      lastEnd = start + wide;
    }
  }
  svg += `<line class="qcross" x1="0" x2="0" y1="0" y2="${rows.length * (H + gap) - gap}" visibility="hidden"/></svg>`;
  return `<figure class="qfig"><figcaption><b class="mono">${esc(s.src)} → ${esc(s.dst)}</b> <span class="muted">${esc(s.codec)}, ${esc(t("per second"))}, +${t0.toFixed(1)} s</span></figcaption>${svg}<div class="qtip" hidden></div></figure>`;
}

/// Crosshair and tooltip for the quality charts.
function bindQualityCharts() {
  $("#tab-media").addEventListener("mousemove", (e) => {
    const svg = e.target.closest && e.target.closest("svg.qchart");
    $$("#tab-media .qcross").forEach((l) => l.setAttribute("visibility", "hidden"));
    $$("#tab-media .qtip").forEach((d) => (d.hidden = true));
    if (!svg || !S.report) return;
    const s = S.report.streams[+svg.dataset.stream];
    const r = svg.getBoundingClientRect();
    const vx = ((e.clientX - r.left) / r.width) * 900;
    const n = s.series.length;
    const i = Math.round(((vx - 64) / (900 - 64 - 12)) * (n - 1));
    if (i < 0 || i >= n) return;
    const row = s.series[i];
    const xx = 64 + (i / Math.max(1, n - 1)) * (900 - 64 - 12);
    const cross = svg.querySelector(".qcross");
    cross.setAttribute("x1", xx);
    cross.setAttribute("x2", xx);
    cross.setAttribute("visibility", "visible");
    const tip = svg.parentElement.querySelector(".qtip");
    tip.hidden = false;
    tip.innerHTML = `<b>+${(i).toFixed(0)} s</b><br>${row[1]} ${esc(t("packets"))}, ${row[2]} ${esc(t("lost"))}<br>jitter ${row[3].toFixed(1)} ms<br>MOS ${row[4] ? row[4].toFixed(2) : "n/a"}`;
    const fx = e.clientX - svg.parentElement.getBoundingClientRect().left;
    tip.style.left = `${Math.min(fx + 12, svg.parentElement.clientWidth - 170)}px`;
  });
}

// ---- RTP player: listen to a stream and see its waveform

const PL = { ctx: null, src: null, buf: null, id: null, start: 0, offset: 0, raf: 0 };

/// Opus frames decoded in the page with WebCodecs (browser version).
async function decodeOpusFrames(j) {
  if (!("AudioDecoder" in window)) throw new Error(t("This browser cannot decode Opus (no WebCodecs); the desktop app can."));
  const rate = 48000;
  const chunks = [];
  const dec = new AudioDecoder({
    output: (d) => {
      const n = d.numberOfFrames;
      const f = new Float32Array(n);
      d.copyTo(f, { planeIndex: 0, format: "f32-planar" });
      chunks.push([Number(d.timestamp), f]);
      d.close();
    },
    error: () => {},
  });
  dec.configure({ codec: "opus", sampleRate: rate, numberOfChannels: 1 });
  for (const [ts, b64] of j.frames) {
    const data = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
    dec.decode(new EncodedAudioChunk({ type: "key", timestamp: Math.round((ts / 48000) * 1e6), data }));
  }
  await dec.flush();
  const end = chunks.length ? Math.round((chunks[chunks.length - 1][0] / 1e6) * rate) + chunks[chunks.length - 1][1].length : 0;
  const out = new Float32Array(end);
  for (const [us, f] of chunks) out.set(f, Math.round((us / 1e6) * rate));
  return { rate, data: out };
}

async function openPlayer(id) {
  const box = $("#rtp-player");
  if (!box) return;
  stopPlayer();
  const st = S.report.streams[id];
  markStream(id);
  box.hidden = false;
  box.innerHTML = `<p class="muted">${esc(t("Decoding"))} ${esc(st.codec)}…</p>`;
  try {
    PL.ctx ||= new (window.AudioContext || window.webkitAudioContext)();
    const r = await S.be.rtpAudio(S.bytes, id);
    let buf;
    let wav = r.wav;
    if (wav) {
      buf = await PL.ctx.decodeAudioData(wav.buffer.slice(wav.byteOffset, wav.byteOffset + wav.byteLength));
    } else if (r.frames && /opus/i.test(r.frames.codec)) {
      const d = await decodeOpusFrames(r.frames);
      buf = PL.ctx.createBuffer(1, Math.max(1, d.data.length), d.rate);
      buf.copyToChannel(d.data, 0);
    } else {
      throw new Error((r.frames && r.frames.note) || t("This codec cannot be played"));
    }
    PL.buf = buf;
    PL.id = id;
    PL.offset = 0;
    PL.wav = wav;
    box.innerHTML = `<div class="pl-head"><b>${esc(st.src)} → ${esc(st.dst)}</b> <span class="muted">${esc(st.codec)}, ${buf.duration.toFixed(1)} s, SSRC ${esc(st.ssrc)}</span></div>
      <canvas id="pl-wave" height="110"></canvas>
      <div class="row pl-ctl"><button type="button" class="btn small primary" id="pl-play">▶ ${esc(t("Play"))}</button><span class="mono" id="pl-time">0:00.0 / ${buf.duration.toFixed(1)} s</span><span class="grow"></span>${wav ? `<button type="button" class="btn small" id="pl-save">${esc(t("Save WAV"))}</button>` : ""}</div>
      <p class="hint">${esc(t("Click the waveform to jump there. Silence in the middle is a gap: lost packets, hold or silence suppression."))}</p>`;
    drawWave();
    $("#pl-play").addEventListener("click", () => (PL.src ? pausePlayer() : playPlayer()));
    $("#pl-wave").addEventListener("click", (e) => {
      const c = e.currentTarget;
      PL.offset = ((e.clientX - c.getBoundingClientRect().left) / c.clientWidth) * PL.buf.duration;
      if (PL.src) {
        stopPlayer(true);
        playPlayer();
      } else drawWave();
    });
    const sv = $("#pl-save");
    if (sv) sv.addEventListener("click", () => download(PL.wav, `${(S.name || "capture").replace(/\.[^.]+$/, "")}-stream${id}.wav`, "audio/wav"));
  } catch (e) {
    box.innerHTML = `<p class="bad">${esc(e.message || String(e))}</p>`;
  }
}

/// Highlights the selected RTP stream in the ladder and in the Media table.
function markStream(id) {
  S.stream = id;
  $$("#ladder .stream, #hd-ladder .stream").forEach((g) => g.classList.toggle("sel", +g.dataset.stream === id));
  $$("#tab-media tr[data-stream]").forEach((r) => r.classList.toggle("sel", +r.dataset.stream === id));
  $$("#ladder .msg").forEach((g) => g.classList.remove("sel"));
}

function drawWave() {
  const c = $("#pl-wave");
  if (!c || !PL.buf) return;
  const w = (c.width = c.clientWidth * devicePixelRatio);
  const h = (c.height = 110 * devicePixelRatio);
  const g = c.getContext("2d");
  const css = getComputedStyle(document.body);
  const d = PL.buf.getChannelData(0);
  const step = Math.max(1, Math.floor(d.length / w));
  // Scale to the loudest sample so quiet streams are still readable.
  if (PL.peak == null || PL.peakOf !== PL.buf) {
    let pk = 0;
    for (let i = 0; i < d.length; i++) pk = Math.max(pk, Math.abs(d[i]));
    PL.peak = pk;
    PL.peakOf = PL.buf;
  }
  const gain = PL.peak > 0.001 ? 0.95 / PL.peak : 1;
  g.clearRect(0, 0, w, h);
  g.fillStyle = css.getPropertyValue("--sunk") || "#eee";
  g.fillRect(0, 0, w, h);
  g.fillStyle = css.getPropertyValue("--req").trim() || "#2563eb";
  for (let x = 0; x < w; x++) {
    let lo = 1, hi = -1;
    for (let i = x * step, e = Math.min(d.length, i + step); i < e; i++) {
      const v = d[i];
      if (v < lo) lo = v;
      if (v > hi) hi = v;
    }
    if (hi < lo) continue;
    const y1 = ((1 - hi * gain) / 2) * h, y2 = ((1 - lo * gain) / 2) * h;
    g.fillRect(x, y1, 1, Math.max(1, y2 - y1));
  }
  const pos = curTime() / PL.buf.duration;
  g.fillStyle = css.getPropertyValue("--bad").trim() || "#dc2626";
  g.fillRect(Math.round(pos * w), 0, 2 * devicePixelRatio, h);
}

const curTime = () => (PL.src ? Math.min(PL.buf.duration, PL.offset + PL.ctx.currentTime - PL.start) : PL.offset);

function playPlayer() {
  if (!PL.buf) return;
  if (PL.ctx.state === "suspended") PL.ctx.resume();
  if (PL.offset >= PL.buf.duration) PL.offset = 0;
  const src = PL.ctx.createBufferSource();
  src.buffer = PL.buf;
  src.connect(PL.ctx.destination);
  src.onended = () => {
    if (PL.src !== src) return;
    PL.offset = curTime();
    PL.src = null;
    if (PL.offset >= PL.buf.duration - 0.05) PL.offset = 0;
    tickPlayer();
    const b = $("#pl-play");
    if (b) b.textContent = `▶ ${t("Play")}`;
  };
  PL.start = PL.ctx.currentTime;
  src.start(0, PL.offset);
  PL.src = src;
  $("#pl-play").textContent = `❚❚ ${t("Pause")}`;
  const loop = () => {
    tickPlayer();
    if (PL.src) PL.raf = requestAnimationFrame(loop);
  };
  loop();
}

function tickPlayer() {
  const el = $("#pl-time");
  if (el && PL.buf) {
    const tm = curTime();
    el.textContent = `${Math.floor(tm / 60)}:${(tm % 60).toFixed(1).padStart(4, "0")} / ${PL.buf.duration.toFixed(1)} s`;
  }
  drawWave();
}

function pausePlayer() {
  PL.offset = curTime();
  stopPlayer(true);
  const b = $("#pl-play");
  if (b) b.textContent = `▶ ${t("Play")}`;
  tickPlayer();
}

function stopPlayer(keepOffset = false) {
  cancelAnimationFrame(PL.raf);
  if (PL.src) {
    const s = PL.src;
    PL.src = null;
    try { s.stop(); } catch { /* already stopped */ }
  }
  if (!keepOffset) PL.offset = 0;
}

function renderLog() {
  const r = S.report;
  const p = pickedCalls();
  const idxs = p.length > 1
    ? [...new Set(p.flatMap((k) => r.calls[k].messages))].sort((a, b) => a - b)
    : S.call == null ? r.messages.map((m) => m.index) : r.calls[S.call].messages;
  $("#tab-log").innerHTML = `<div class="trace">${idxs
    .map((i) => {
      const m = r.messages[i];
      const t = new Date(m.ts_ns / 1e6);
      const ts = `${t.toISOString().slice(0, 10)} ${t.toISOString().slice(11, 23)}`;
      return `<article><header><b>${esc(m.transport.toLowerCase())}:${esc(m.src)}</b> to <b>${esc(m.dst)}</b> at ${ts} (${new TextEncoder().encode(m.raw).length} bytes)${m.retransmission ? ", retransmission" : ""}</header><pre class="sipmsg">${highlightSip(m.raw)}</pre></article>`;
    })
    .join("")}</div>`;
}

function showTab(name) {
  $$(".tabs [role=tab]").forEach((b) => b.setAttribute("aria-selected", String(b.dataset.tab === name)));
  $$(".tab-body").forEach((p) => (p.hidden = p.id !== `tab-${name}`));
  S.tab = name;
  if (S.page === "analysis") syncUrl(false);
}

// ---------- AI ----------

const AI_DEFAULT_MODEL = { anthropic: "claude-sonnet-5-5", openai: "", ollama: "" };
// OpenAI-compatible services: [label, base URL, example model]
const AI_PRESETS = [
  ["OpenAI", "https://api.openai.com", "gpt-4o-mini"],
  ["OpenRouter", "https://openrouter.ai/api", "anthropic/claude-sonnet-5-5"],
  ["Google Gemini", "https://generativelanguage.googleapis.com/v1beta/openai", "gemini-2.5-flash"],
  ["Groq", "https://api.groq.com/openai", "llama-3.3-70b-versatile"],
  ["Mistral", "https://api.mistral.ai", "mistral-large-latest"],
  ["DeepSeek", "https://api.deepseek.com", "deepseek-chat"],
  ["LM Studio (local)", "http://localhost:1234", "local-model"],
  ["vLLM (local)", "http://localhost:8000", ""],
];
let aiSessionKey = null; // key typed but not remembered: lives until the page closes

function aiSettings() {
  const s = store.get("sidetone.ai", {});
  return {
    provider: s.provider || "anthropic",
    model: s.model || AI_DEFAULT_MODEL[s.provider || "anthropic"],
    base_url: s.base_url || null,
    language: s.language || { pt: "Portuguese (Brazil)", es: "Spanish", de: "German", fr: "French", zh: "Chinese (Simplified)", hi: "Hindi" }[currentLang()] || "English",
    redact: s.redact !== false,
    key: s.key || aiSessionKey || null,
    remember: !!s.key,
  };
}

function saveAiSettings(v) {
  aiSessionKey = v.key || null;
  store.set("sidetone.ai", {
    provider: v.provider,
    model: v.model,
    base_url: v.base_url || null,
    language: v.language,
    redact: v.redact,
    key: v.remember && v.key ? v.key : undefined,
  });
  renderAiUsing();
}

function aiConfig() {
  const s = aiSettings();
  return { provider: s.provider, model: s.model || AI_DEFAULT_MODEL[s.provider], base_url: s.base_url, api_key: s.key, language: s.language, max_tokens: 2000 };
}

const PROVIDER_NAME = { anthropic: "Anthropic", openai: "OpenAI-compatible", ollama: "Ollama" };

/// Problem with the AI settings, or null when ready.
function aiNotReady() {
  const c = aiConfig();
  if (!c.model) return t("Choose a model in Settings, AI.");
  if (c.provider !== "ollama" && !c.api_key && S.be.kind === "wasm") return t("Enter an API key in Settings, AI. It stays on this device and goes only to the provider.");
  return null;
}

function renderAiUsing() {
  const c = aiConfig();
  const host = c.base_url ? ` · ${c.base_url.replace(/^https?:\/\//, "").split("/")[0]}` : "";
  const txt = `${PROVIDER_NAME[c.provider]} · ${c.model || "?"}${host}`;
  const u = $("#ai-using");
  if (u) u.textContent = txt;
  const d = $("#dock-using");
  if (d) d.textContent = txt;
  const r = $("#ai-redact");
  if (r) r.checked = aiSettings().redact;
}

function renderAnswer(text) {
  const ls = esc(text).split("\n").map((l) => {
    const h = l.match(/^#{1,4}\s+(.*)$/);
    if (h) return `<h3>${h[1]}</h3>`;
    return l.replace(/\*\*(.+?)\*\*/g, "<b>$1</b>").replace(/`([^`]+)`/g, "<code>$1</code>");
  });
  return `<div class="answer">${ls.join("\n")}</div>`;
}

async function askAI(preview) {
  if (!S.bytes) return;
  const cfg = aiConfig();
  const out = $("#ai-out");
  let question = $("#ai-question").value;
  if (S.webrtc) question = `${question}\n\nBrowser WebRTC getStats() summary for this call (media is not in the capture): ${JSON.stringify(S.webrtc)}`.trim();
  const { system, prompt } = await S.be.prompt(S.bytes, S.call, $("#ai-redact").checked, cfg.language, question);
  if (preview) {
    out.innerHTML = `<p class="muted">${$("#ai-redact").checked ? "Masked" : "Unmasked"} prompt, ${prompt.length.toLocaleString()} characters:</p><pre>${esc(system)}\n\n${esc(prompt)}</pre>`;
    return;
  }
  const bad = aiNotReady();
  if (bad) {
    out.innerHTML = `<p class="err">${esc(bad)} <button type="button" class="linklike" data-goto-ai>${esc(t("Open Settings, AI"))}</button></p>`;
    return;
  }
  const btn = $("#ai-go");
  btn.disabled = true;
  out.innerHTML = `<p class="muted">Asking ${esc(PROVIDER_NAME[cfg.provider])} (${esc(cfg.model)})…</p>`;
  try {
    out.innerHTML = renderAnswer(await S.be.ai(cfg, system, prompt));
  } catch (e) {
    out.innerHTML = `<p class="err">${esc(e.message || e)}</p>`;
  } finally {
    btn.disabled = false;
  }
}

// ---------- AI panel (conversation) ----------

const DOCK = { turns: [], busy: false, ctx: null };

/// What the AI can look at right now: [id, label, call-id or null].
function dockContexts() {
  const out = [];
  if (S.report) {
    const c = S.call != null ? S.report.calls[S.call] : null;
    out.push(["an", c ? `${t("Analysis")}: ${c.kind} ${c.from} → ${c.to}` : `${t("Analysis")}: ${S.name}`, null]);
  }
  const l = selLine() || lines()[lines().length - 1];
  if (l && l.call_id) out.push(["line", `${t("Phone")}: ${l.remote}`, l.call_id]);
  const tr = S.trace.find((x) => x.seq === S.trSel);
  if (tr && tr.call_id && (!l || tr.call_id !== l.call_id)) out.push(["trace", `${t("SIP trace")}: ${tr.first_line.slice(0, 40)}`, tr.call_id]);
  out.push(["live", t("Everything the phone captured"), null]);
  return out;
}

function renderDockContexts() {
  const ctxs = dockContexts();
  const sel = $("#dock-ctx");
  const want = DOCK.ctx && ctxs.some(([id]) => id === DOCK.ctx) ? DOCK.ctx : S.page === "analysis" && S.report ? "an" : ctxs[0][0];
  sel.innerHTML = ctxs.map(([id, label]) => `<option value="${id}">${esc(label)}</option>`).join("");
  sel.value = want;
  DOCK.ctx = want;
}

function openDock(open = true) {
  $("#ai-dock").hidden = !open;
  document.body.classList.toggle("dock-open", open);
  $("#ai-toggle").setAttribute("aria-expanded", String(open));
  if (open) {
    renderDockContexts();
    renderAiUsing();
    renderDockChat();
    $("#dock-q").focus();
  }
}

function renderDockChat() {
  const el = $("#dock-chat");
  if (!DOCK.turns.length) {
    el.innerHTML = `<div class="ai-empty"><p>${esc(t("Ask anything about the selected call or the capture. The AI gets the findings, the ladder, RTP statistics and the relevant SIP messages, masked by default."))}</p>
      <div class="ai-suggest">${[
        "Why did this call fail?",
        "Is there a NAT problem here?",
        "Why is there one-way audio?",
        "What should I change on the SBC or PBX?",
      ].map((q) => `<button type="button" class="chip" data-q="${esc(t(q))}">${esc(t(q))}</button>`).join("")}</div></div>`;
    return;
  }
  el.innerHTML = DOCK.turns
    .map((x) => (x.role === "user" ? `<div class="msg-u">${esc(x.text)}</div>` : x.role === "error" ? `<div class="msg-e">${esc(x.text)}</div>` : x.role === "pre" ? `<pre class="msg-p">${esc(x.text)}</pre>` : `<div class="msg-a">${renderAnswer(x.text)}</div>`))
    .join("") + (DOCK.busy ? `<div class="msg-a muted">${esc(t("Thinking…"))}</div>` : "");
  el.scrollTop = el.scrollHeight;
}

/// Capture bytes and dialog index for the chosen context.
async function dockSource() {
  const ctx = dockContexts().find(([id]) => id === DOCK.ctx) || ["live", "", null];
  if (ctx[0] === "an") return { bytes: S.bytes, call: S.call, webrtc: S.webrtc };
  const bytes = await S.ctl.capture(S.be);
  let call = null;
  if (ctx[2]) {
    const rep = await S.be.analyze(bytes);
    const i = rep.calls.findIndex((c) => c.call_id === ctx[2]);
    call = i >= 0 ? i : null;
  }
  return { bytes, call, webrtc: S.ctl.kind === "web" ? S.ctl.lastSummary : null };
}

async function dockAsk(question, preview = false) {
  question = question.trim();
  if (!question && !preview) return;
  const cfg = aiConfig();
  const redact = aiSettings().redact;
  // Earlier turns ride along so follow-up questions make sense.
  const history = DOCK.turns
    .filter((x) => x.role === "user" || x.role === "ai")
    .slice(-8)
    .map((x) => `${x.role === "user" ? "Question" : "Your answer"}: ${x.text.slice(0, 3000)}`)
    .join("\n\n");
  let q = history ? `Earlier in this conversation:\n\n${history}\n\nNew question: ${question}` : question;
  try {
    const src = await dockSource();
    if (src.webrtc) q += `\n\nBrowser WebRTC getStats() summary for this call (media is not in the capture): ${JSON.stringify(src.webrtc)}`;
    const { system, prompt } = await S.be.prompt(src.bytes, src.call, redact, cfg.language, q);
    if (preview) {
      DOCK.turns.push({ role: "pre", text: `${system}\n\n${prompt}` });
      renderDockChat();
      return;
    }
    const bad = aiNotReady();
    if (bad) {
      DOCK.turns.push({ role: "error", text: bad });
      renderDockChat();
      return;
    }
    DOCK.turns.push({ role: "user", text: question });
    DOCK.busy = true;
    renderDockChat();
    const answer = await S.be.ai(cfg, system, prompt);
    DOCK.turns.push({ role: "ai", text: answer });
  } catch (e) {
    DOCK.turns.push({ role: "error", text: e.message || String(e) });
  } finally {
    DOCK.busy = false;
    renderDockChat();
  }
}

function bindDock() {
  $("#ai-toggle").addEventListener("click", () => openDock($("#ai-dock").hidden));
  $("#dock-close").addEventListener("click", () => openDock(false));
  $("#dock-new").addEventListener("click", () => {
    DOCK.turns = [];
    renderDockChat();
  });
  $("#dock-ctx").addEventListener("change", (e) => {
    DOCK.ctx = e.target.value;
  });
  $("#dock-ctx").addEventListener("mousedown", () => {
    const keep = DOCK.ctx;
    renderDockContexts();
    if (keep) $("#dock-ctx").value = keep;
  });
  $("#dock-form").addEventListener("submit", (e) => {
    e.preventDefault();
    const q = $("#dock-q").value;
    $("#dock-q").value = "";
    dockAsk(q);
  });
  $("#dock-q").addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      $("#dock-form").requestSubmit();
    }
  });
  $("#dock-preview").addEventListener("click", () => dockAsk($("#dock-q").value || "(no question yet)", true));
  $("#dock-chat").addEventListener("click", (e) => {
    const c = e.target.closest("[data-q]");
    if (c) dockAsk(c.dataset.q);
  });
  $("#ai-to-dock").addEventListener("click", () => {
    DOCK.ctx = "an";
    openDock(true);
    const q = $("#ai-question").value.trim();
    if (q) {
      $("#ai-question").value = "";
      dockAsk(q);
    }
  });
  document.addEventListener("click", (e) => {
    if (e.target.closest("[data-goto-ai]")) {
      SET.section = "ai";
      showWs("settings");
    }
  });
  $("#ai-redact").addEventListener("change", (e) => saveAiSettings({ ...aiSettings(), redact: e.target.checked, key: aiSettings().key, remember: aiSettings().remember }));
}

// ---- draggable dividers

/// A divider that sets a CSS length on `box`: "col" moves a vertical line
/// (size from the left), "row" a horizontal one (size from the bottom).
function splitter(box, { name, axis, min, max, start, place }) {
  const g = document.createElement("div");
  g.className = `gutter ${axis === "col" ? "v" : "h"}`;
  g.setAttribute("role", "separator");
  g.setAttribute("aria-orientation", axis === "col" ? "vertical" : "horizontal");
  g.title = t("Drag to resize, double-click to reset");
  box.appendChild(g);
  const key = `sidetone.split.${name}`;
  // Every divider of the box moves when any of them does.
  (box._gutters ||= []).push(() => place(g, box));
  const replace = () => box._gutters.forEach((f) => f());
  const apply = (px) => {
    if (px == null) box.style.removeProperty(`--${name}`);
    else box.style.setProperty(`--${name}`, `${Math.round(px)}px`);
    replace();
  };
  const clamp = (px) => {
    const r = box.getBoundingClientRect();
    const total = axis === "col" ? r.width : r.height;
    return Math.max(min, Math.min(px, total - max));
  };
  const saved = store.get(key, null);
  apply(saved);
  g.addEventListener("pointerdown", (e) => {
    e.preventDefault();
    g.setPointerCapture(e.pointerId);
    g.classList.add("drag");
    document.body.classList.add("resizing", axis);
    const move = (ev) => {
      const r = box.getBoundingClientRect();
      const px = axis === "col" ? ev.clientX - r.left : r.bottom - ev.clientY;
      apply(clamp(px));
    };
    const up = () => {
      g.classList.remove("drag");
      document.body.classList.remove("resizing", axis);
      g.removeEventListener("pointermove", move);
      g.removeEventListener("pointerup", up);
      const v = parseFloat(box.style.getPropertyValue(`--${name}`));
      if (!Number.isNaN(v)) store.set(key, v);
    };
    g.addEventListener("pointermove", move);
    g.addEventListener("pointerup", up);
  });
  g.addEventListener("dblclick", () => {
    store.set(key, null);
    apply(start);
  });
  // Keyboard: arrows move the divider by 24 px.
  g.tabIndex = 0;
  g.addEventListener("keydown", (e) => {
    const step = { ArrowLeft: -24, ArrowRight: 24, ArrowUp: 24, ArrowDown: -24 }[e.key];
    if (step == null) return;
    e.preventDefault();
    const cur = parseFloat(box.style.getPropertyValue(`--${name}`)) || (axis === "col" ? g.offsetLeft : box.clientHeight - g.offsetTop);
    const v = clamp(cur + step);
    apply(v);
    store.set(key, v);
  });
  new ResizeObserver(replace).observe(box);
  return g;
}

function bindSplitters() {
  const an = $(".an-grid");
  const calls = $(".an-grid .calls");
  const detail = $(".an-grid .detail");
  // Dialog list | ladder and details.
  splitter(an, {
    name: "an-left", axis: "col", min: 160, max: 360, start: null,
    place: (g) => { g.style.left = `${calls.offsetWidth}px`; },
  });
  // Ladder above, details below.
  splitter(an, {
    name: "an-bottom", axis: "row", min: 90, max: 80, start: null,
    place: (g) => { g.style.left = `${calls.offsetWidth}px`; g.style.right = "0"; g.style.top = `${detail.offsetTop}px`; },
  });
  // SIP trace: message list above, message below.
  const tr = $(".trace-split");
  const view = $(".trace-split .trace-view");
  if (tr && view) {
    splitter(tr, {
      name: "tr-bottom", axis: "row", min: 80, max: 60, start: null,
      place: (g) => { g.style.left = "0"; g.style.right = "0"; g.style.top = `${view.offsetTop}px`; },
    });
  }
}

function bindAnalysis() {
  $("#file-btn").addEventListener("click", () => $("#file").click());
  $("#file").addEventListener("change", (e) => {
    if (e.target.files[0]) loadFile(e.target.files[0]);
    e.target.value = ""; // the same file can be opened again
  });
  // Drops of files anywhere open a capture; text dropped into a field is left alone.
  const fileDrop = (e) => e.dataTransfer && [...e.dataTransfer.types].includes("Files") && !e.target.closest("input, textarea");
  document.addEventListener("dragover", (e) => {
    if (!fileDrop(e)) return;
    e.preventDefault();
    document.body.classList.add("dragging");
  });
  document.addEventListener("dragleave", (e) => {
    if (e.target === document.documentElement || !e.relatedTarget) document.body.classList.remove("dragging");
  });
  document.addEventListener("drop", (e) => {
    document.body.classList.remove("dragging");
    if (!fileDrop(e)) return;
    e.preventDefault();
    const f = e.dataTransfer.files[0];
    if (f) loadFile(f);
  });
  const closeMenus = () => $$(".menu").forEach((x) => {
    x.classList.remove("open");
    const b = x.querySelector(":scope > button");
    if (b) b.setAttribute("aria-expanded", "false");
  });
  $$(".menu > button").forEach((b) =>
    b.addEventListener("click", (e) => {
      e.stopPropagation();
      const m = b.parentElement;
      const open = !m.classList.contains("open");
      closeMenus();
      m.classList.toggle("open", open);
      b.setAttribute("aria-expanded", String(open));
      // Focus moves into the menu so the keyboard can use it.
      if (open) {
        const first = m.querySelector(".menu-list button, .menu-list input");
        if (first) first.focus();
      }
    })
  );
  // The view menu holds controls, not one-shot items: clicks inside keep it open.
  $$(".view-menu").forEach((m) => m.addEventListener("click", (e) => e.stopPropagation()));
  document.addEventListener("click", closeMenus);
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") $$(".menu").forEach((x) => x.classList.remove("open"));
  });
  $("#calls").addEventListener("click", (e) => {
    const b = e.target.closest("button[data-call]");
    const lg = e.target.closest("[data-legs]");
    if (lg) {
      e.stopPropagation();
      const c = S.report.calls[+lg.dataset.legs];
      S.picked = new Set([c.index, ...c.related]);
      renderCalls();
      selectCall(null);
      return;
    }
    if (b) selectCall(+b.dataset.call, true);
  });
  $("#calls").addEventListener("change", (e) => {
    const cb = e.target.closest("input[data-pick]");
    if (!cb) return;
    const i = +cb.dataset.pick;
    if (cb.checked) S.picked.add(i);
    else S.picked.delete(i);
    if (!S.picked.size) {
      // Nothing ticked any more: nothing on the ladder until a dialog is picked.
      S.call = null;
      renderCalls();
      clearLadder();
      return;
    }
    renderCalls();
    selectCall(S.picked.size === 1 ? [...S.picked][0] : null);
  });
  attachSuggest($("#an-filter"), () => (S.report ? S.report.messages : []));
  attachSuggest($("#tr-filter"), () => S.trace);
  let anT = null;
  $("#lad-time").value = ladTime();
  $("#lad-retx").checked = ladRetx();
  const redrawLadder = () => {
    if (S.report) selectCall(S.call);
  };
  $("#lad-time").addEventListener("change", (e) => {
    store.set("sidetone.ladder.time", e.target.value);
    redrawLadder();
  });
  $("#lad-retx").addEventListener("change", (e) => {
    store.set("sidetone.ladder.fold_retx", e.target.checked);
    redrawLadder();
  });
  $("#an-filter").addEventListener("input", () => {
    clearTimeout(anT);
    anT = setTimeout(() => {
      if (!S.report) return;
      renderCalls();
      markLadderMatches();
    }, 200);
  });
  // Enter jumps to the first dialog that matches; typing alone never moves the ladder.
  $("#an-filter").addEventListener("keydown", (e) => {
    if (e.key !== "Enter" || !S.report) return;
    const hits = anMatches();
    if (!hits) return;
    const first = S.report.calls.find((c) => c.messages.some((i) => hits.has(i)));
    if (first) selectCall(first.index, true);
  });
  $("#an-live-stop").addEventListener("click", stopLive);
  $("#calls-clear").addEventListener("click", () => {
    S.picked.clear();
    S.call = null;
    renderCalls();
    clearLadder();
  });
  $("#ladder").addEventListener("click", (e) => {
    const g = e.target.closest(".msg");
    if (g) selectMessage(+g.dataset.msg);
    const sg = e.target.closest(".stream");
    if (sg) {
      showTab("media");
      if (sg.dataset.stream != null) openPlayer(+sg.dataset.stream);
    }
  });
  bindQualityCharts();
  $("#tab-media").addEventListener("click", (e) => {
    const b = e.target.closest("[data-play]") || (!e.target.closest("button, a, input, .rtp-player") && e.target.closest("tr[data-stream]"));
    if (b) openPlayer(+(b.dataset.play ?? b.dataset.stream));
  });
  const openFinding = (li) => {
    const f = S.report.findings[+li.dataset.finding];
    if (f.messages.length) selectMessage(f.messages[0]);
    else if (f.stream != null) showTab("media");
  };
  $("#tab-findings").addEventListener("click", (e) => {
    const li = e.target.closest("li[data-finding]");
    if (li) openFinding(li);
  });
  $("#tab-findings").addEventListener("keydown", (e) => {
    const li = e.target.closest("li[data-finding]");
    if (li && (e.key === "Enter" || e.key === " ")) {
      e.preventDefault();
      openFinding(li);
    }
  });
  $$(".tabs [role=tab]").forEach((b) => b.addEventListener("click", () => showTab(b.dataset.tab)));
  tablistKeys($(".tabs"));
  $$("[data-export]").forEach((b) =>
    b.addEventListener("click", async () => {
      const kind = b.dataset.export;
      const base = S.name.replace(/\.(pcapng|pcap|cap)$/i, "");
      try {
        if (kind === "json") return download(JSON.stringify(S.report, null, 2), `${base}-report.json`, "application/json");
        if (kind === "svg") {
          const p = pickedCalls();
          const svg = p.length > 1 && S.be.ladderCalls ? await S.be.ladderCalls(S.bytes, p) : await S.be.ladder(S.bytes, S.call);
          return download(svg, `${base}-${p.length > 1 ? "calls" + p.join("-") : "call" + (S.call ?? "s")}.svg`, "image/svg+xml");
        }
        const opts = { annotate: true, redact: kind === "redacted", call: kind === "all" ? null : S.call, sip_only: false };
        const data = await S.be.exportPcap(S.bytes, opts);
        const suffix = kind === "all" ? "annotated" : kind === "redacted" ? `call${S.call}-redacted` : `call${S.call}`;
        await download(data, `${base}-${suffix}.pcapng`, "application/vnd.tcpdump.pcap");
        if (!S.be.save) toast(kind === "redacted" ? "Exported with numbers, names, credentials and public IPs masked" : "Exported with findings as packet comments");
      } catch (e) {
        toast(`Export failed: ${e.message || e}`, 5000);
      }
    })
  );
  $("#ai-form").addEventListener("submit", (e) => {
    e.preventDefault();
    askAI(false);
  });
  $("#ai-preview").addEventListener("click", () => askAI(true));
}

// Sound card self-test in Settings, Audio.
let audioTestPoll = null;
function bindAudioTest() {
  const busy = (on) => ["#at-rec", "#at-tone"].forEach((s) => ($(s).disabled = on));
  const db = (v) => (v > 0 ? `${(20 * Math.log10(v / 32767)).toFixed(0)} dBFS` : "");
  $("#at-rec").addEventListener("click", async () => {
    try {
      await S.ctl.audioRecordTest(4);
    } catch (e) {
      toast(e.message || String(e), 4000);
    }
  });
  $("#at-tone").addEventListener("click", async () => {
    try {
      await S.ctl.audioTone(Number($("#au-hz").value) || 440, 1500);
    } catch (e) {
      toast(e.message || String(e), 4000);
    }
  });
  $("#at-loop").addEventListener("change", async (e) => {
    try {
      await S.ctl.loopback(e.target.checked);
    } catch (err) {
      toast(err.message || String(err), 4000);
      e.target.checked = false;
    }
  });
  const label = { recording: "Recording… speak now", playing: "Playing back what was recorded", tone: "Playing the test tone" };
  clearInterval(audioTestPoll);
  audioTestPoll = setInterval(async () => {
    if (!$("#at-in")) {
      clearInterval(audioTestPoll);
      S.ctl.loopback(false).catch(() => {});
      return;
    }
    try {
      const s = await S.ctl.audioStatus();
      if (s.status) {
        setMeter($("#at-in"), levelPct(s.status.mic_level));
        setMeter($("#at-out"), levelPct(s.status.speaker_level));
        $("#at-in-db").textContent = db(s.status.mic_level);
        $("#at-out-db").textContent = db(s.status.speaker_level);
      }
      busy(!!s.test);
      $("#at-state").textContent = s.test ? t(label[s.test] || s.test) : s.error ? s.error : "";
    } catch {
      /* server busy; next tick */
    }
  }, 150);
}

// ============================================================================
// Diagnostics

function diagAccounts() {
  const opts = (S.st ? S.st.accounts : []).map((a) => `<option value="${esc(a.id)}">${esc(accLabel(a))}</option>`).join("");
  const sel = $("#dg-opt-acct");
  const keep = sel.value || $("#acct").value;
  sel.innerHTML = opts;
  if (keep) sel.value = keep;
}

function table(head, rows) {
  return `<table class="mini"><thead><tr>${head.map((h) => `<th>${esc(h)}</th>`).join("")}</tr></thead><tbody>${rows.map((r) => `<tr>${r.map((c) => `<td>${c}</td>`).join("")}</tr>`).join("")}</tbody></table>`;
}

let audioPoll = null;
async function diagOpen() {
  diagAccounts();
  if (S.ctl.kind === "native") (SN.loaded ? sniffPoll() : sniffLoad());
  const a = currentAccount();
  if (a && !$("#dg-dns-host").value) $("#dg-dns-host").value = (a.domain || "").replace(/:\d+$/, "");
  const nat = (S.st ? S.st.accounts : []).filter((x) => x.public);
  $("#dg-reg-nat").innerHTML = nat.length
    ? `<h3>What the SIP server sees</h3>${table(["Account", "Local", "Seen as", ""], nat.map((x) => [esc(accLabel(x)), `<span class="mono">${esc(x.local)}</span>`, `<span class="mono">${esc(x.public)}</span>`, x.public !== x.local ? `<span class="warn">NAT between you and the server</span>` : "same address, no NAT"]))}<p class="hint">From the received and rport parameters of the server's response to REGISTER.</p>`
    : "";
  if (S.ctl.kind === "native") {
    try {
      const d = await S.ctl.audio();
      const dev = d.devices;
      const st = d.audio;
      const prefs = st.prefs || {};
      const opt = (list, cur) => [`<option value="">System default</option>`, ...list.map((n) => `<option ${n === cur ? "selected" : ""}>${esc(n)}</option>`)].join("");
      $("#dg-audio").innerHTML = `
        <p class="muted">${st.status ? `Open: microphone <b>${esc(st.status.input || "none")}</b>${st.status.input_rate ? ` at ${st.status.input_rate} Hz` : ""}, speaker <b>${esc(st.status.output || "none")}</b>${st.status.output_rate ? ` at ${st.status.output_rate} Hz` : ""}.` : esc(st.error || dev.error || "No sound card is open. Calls send a test tone instead.")}</p>
        <div class="row">
          <label class="grow">Microphone <select id="dg-in">${opt(dev.inputs || [], prefs.input)}</select></label>
          <label class="grow">Speaker <select id="dg-out">${opt(dev.outputs || [], prefs.output)}</select></label>
          <button type="button" class="btn" id="dg-audio-apply">Use these</button>
        </div>
        <div class="meters">
          <div class="meter-row"><svg><use href="#i-mic"/></svg><div class="meter"><i id="dg-m-in"></i></div></div>
          <div class="meter-row"><svg><use href="#i-spk"/></svg><div class="meter"><i id="dg-m-out"></i></div></div>
        </div>
        <label class="check"><input type="checkbox" id="dg-loop"> Play the microphone on the speaker (use headphones)</label>
        <p class="hint">Audio host: ${esc(dev.host || "")}. Calls use the sound card when Settings, Audio, Send is set to Sound card.</p>`;
      $("#dg-audio-apply").addEventListener("click", async () => {
        const c = await S.ctl.getConfig();
        c.audio = { ...(c.audio || {}), enabled: true, input: $("#dg-in").value || null, output: $("#dg-out").value || null };
        await S.ctl.setConfig({ audio: c.audio });
        toast("Audio devices changed");
        diagOpen();
      });
      $("#dg-loop").addEventListener("change", async (e) => {
        try {
          await S.ctl.loopback(e.target.checked);
        } catch (err) {
          toast(err.message || String(err), 4000);
          e.target.checked = false;
        }
      });
      clearInterval(audioPoll);
      audioPoll = setInterval(async () => {
        if (S.page !== "diag") {
          clearInterval(audioPoll);
          S.ctl.loopback(false).catch(() => {});
          return;
        }
        try {
          const s = await S.ctl.audioStatus();
          if (s.status) {
            setMeter($("#dg-m-in"), levelPct(s.status.mic_level));
            setMeter($("#dg-m-out"), levelPct(s.status.speaker_level));
          }
        } catch { /* ignore */ }
      }, 200);
    } catch (e) {
      $("#dg-audio").innerHTML = `<p class="err">${esc(e.message || e)}</p>`;
    }
  } else {
    $("#dg-audio").innerHTML = `<p class="muted">The browser phone uses the microphone and speaker chosen in the browser. Test the microphone level here:</p>
      <div class="meters"><div class="meter-row"><svg><use href="#i-mic"/></svg><div class="meter"><i id="dg-m-in"></i></div></div></div>
      <button type="button" class="btn" id="dg-mic">Test microphone</button>`;
    $("#dg-mic").addEventListener("click", async () => {
      try {
        const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
        const ac = new AudioContext();
        const an = ac.createAnalyser();
        ac.createMediaStreamSource(stream).connect(an);
        const buf = new Float32Array(an.fftSize);
        const t = setInterval(() => {
          an.getFloatTimeDomainData(buf);
          const peak = Math.max(...buf.map(Math.abs));
          setMeter($("#dg-m-in"), levelPct(peak * 32767));
        }, 100);
        setTimeout(() => {
          clearInterval(t);
          stream.getTracks().forEach((x) => x.stop());
          ac.close();
          setMeter($("#dg-m-in"), 0);
        }, 10000);
      } catch (e) {
        toast(`Microphone: ${e.message || e}`, 4000);
      }
    });
  }
}

// ---- passive capture on an interface (native only)

const SN = { seen: 0, rows: [], timer: null, loaded: false, running: false };

async function sniffLoad() {
  if (S.ctl.kind !== "native" || !S.ctl.sniffInterfaces) return;
  const sel = $("#sn-if");
  try {
    const r = await S.ctl.sniffInterfaces();
    if (r.error) {
      sel.innerHTML = "";
      $("#sn-err").innerHTML = `<p class="bad">${esc(r.error)}</p>`;
      $("#sn-go").disabled = true;
      return;
    }
    const cur = sel.value || store.get("sidetone.sniff.if", "");
    const list = r.interfaces.filter((i) => i.up || i.addresses.length);
    sel.innerHTML = list
      .map((i) => `<option value="${esc(i.name)}" ${i.name === cur ? "selected" : ""}>${esc(i.description && !/^\\Device/.test(i.description) ? `${i.description} (${i.name})` : i.name)}${i.addresses.length ? ` · ${esc(i.addresses.join(", "))}` : ""}</option>`)
      .join("");
    $("#sn-go").disabled = false;
    $("#sn-err").innerHTML = "";
    SN.loaded = true;
    $("#sn-status").textContent = r.library || "";
  } catch (e) {
    $("#sn-err").innerHTML = `<p class="bad">${esc(e.message || e)}</p>`;
  }
  sniffPoll();
}

function sniffRender(st) {
  SN.running = !!st.running;
  $("#sn-go").textContent = t(SN.running ? "Stop" : "Start");
  $("#sn-go").classList.toggle("danger", SN.running);
  $("#sn-analyze").disabled = !st.kept;
  $("#sn-save").disabled = !st.kept;
  if (st.iface) {
    const parts = [`${SN.running ? t("Capturing on") : t("Captured on")} ${st.iface}`, `${st.packets.toLocaleString()} ${t("packets")}`, `${st.sip.toLocaleString()} SIP`, `${st.rtp.toLocaleString()} RTP`];
    $("#sn-status").textContent = parts.join(" · ");
  }
  if (st.error) $("#sn-err").innerHTML = `<p class="warn">${esc(st.error)}</p>`;
  $("#sn-list").innerHTML = SN.rows.length
    ? table(
        [t("Time"), t("From"), t("To"), t("Message")],
        SN.rows
          .slice(-200)
          .reverse()
          .map((m) => [`<span class="mono">${clock(m.ts_ms, true)}</span>`, `<span class="mono">${esc(m.transport.toLowerCase())}:${esc(m.src)}</span>`, `<span class="mono">${esc(m.dst)}</span>`, `<span class="mono ${m.status >= 400 ? "bad" : m.status >= 200 ? "ok" : ""}">${esc(m.first_line)}</span>`])
      )
    : "";
}

async function sniffPoll() {
  clearTimeout(SN.timer);
  if (S.ctl.kind !== "native" || !S.ctl.sniffStatus) return;
  try {
    const r = await S.ctl.sniffStatus(SN.seen);
    for (const m of r.sip) SN.seen = Math.max(SN.seen, m.seq);
    SN.rows.push(...r.sip);
    if (SN.rows.length > 1000) SN.rows.splice(0, SN.rows.length - 1000);
    sniffRender(r.status);
    if (r.status.running && S.page === "diag") SN.timer = setTimeout(sniffPoll, 1000);
  } catch {
    /* server gone; the next page open retries */
  }
}

async function sniffToggle() {
  $("#sn-err").innerHTML = "";
  try {
    if (SN.running) {
      await S.ctl.sniffStop();
    } else {
      const iface = $("#sn-if").value;
      store.set("sidetone.sniff.if", iface);
      SN.rows = [];
      SN.seen = 0;
      await S.ctl.sniffStart(iface, $("#sn-filter").value);
    }
  } catch (e) {
    $("#sn-err").innerHTML = `<p class="bad">${esc(e.message || e)}</p>`;
  }
  sniffPoll();
}

function bindDiag() {
  $("#sn-go").addEventListener("click", sniffToggle);
  $("#sn-analyze").addEventListener("click", async () => {
    const b = await S.ctl.sniffPcap();
    await load(b, `sidetone-interface-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, "")}.pcapng`);
    showWs("analysis");
  });
  $("#sn-save").addEventListener("click", async () => {
    const b = await S.ctl.sniffPcap();
    download(b, `sidetone-interface-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, "")}.pcapng`, "application/vnd.tcpdump.pcap");
  });
  $("#dg-opt-go").addEventListener("click", async () => {
    const out = $("#dg-opt-out");
    out.innerHTML = `<p class="muted">Waiting for a response (up to 32 s)…</p>`;
    try {
      const r = await S.ctl.options($("#dg-opt-acct").value || null, $("#dg-opt-target").value.trim());
      out.innerHTML = r && r.code ? `<p class="${r.code < 300 || r.code === 404 || r.code === 405 ? "ok" : "warn"}"><b>${esc(r.summary)}</b></p>` : `<p class="bad"><b>No response.</b> ${esc((r && r.summary) || "")}</p>`;
    } catch (e) {
      out.innerHTML = `<p class="bad">${esc(e.message || e)}</p>`;
    }
  });
  $("#dg-dns-go").addEventListener("click", async () => {
    const host = $("#dg-dns-host").value.trim();
    if (!host) return;
    const out = $("#dg-dns-out");
    out.innerHTML = `<p class="muted">Looking up ${esc(host)}…</p>`;
    try {
      const r = await S.ctl.dns(host);
      out.innerHTML = `
        ${r.chosen ? `<p class="ok"><b>UDP requests go to ${esc(r.chosen)}</b></p>` : `<p class="bad"><b>No usable address.</b></p>`}
        ${r.naptr.length ? `<h3>NAPTR</h3>${table(["Order", "Pref", "Flags", "Service", "Replacement"], r.naptr.map((n) => [n.order, n.preference, esc(n.flags), esc(n.service), `<span class="mono">${esc(n.replacement)}</span>`]))}` : ""}
        ${r.srv.length ? `<h3>SRV</h3>${table(["Name", "Prio", "Weight", "Port", "Target", "Addresses"], r.srv.map((s) => [`<span class="mono">${esc(s.name)}</span>`, s.priority, s.weight, s.port, `<span class="mono">${esc(s.target)}</span>`, `<span class="mono">${esc(s.addresses.join(", "))}</span>`]))}` : ""}
        <h3>Steps</h3><ol class="steps">${r.steps.map((s) => `<li>${esc(s)}</li>`).join("")}</ol>
        <p class="hint">${r.elapsed_ms} ms</p>`;
    } catch (e) {
      out.innerHTML = `<p class="bad">${esc(e.message || e)}</p>`;
    }
  });
  $("#dg-dns-host").addEventListener("keydown", (e) => e.key === "Enter" && $("#dg-dns-go").click());
  $("#dg-prov-go").addEventListener("click", async () => {
    const url = $("#dg-prov-url").value.trim();
    if (!url) return;
    const out = $("#dg-prov-out");
    out.innerHTML = `<p class="muted">${esc(t("Fetching…"))}</p>`;
    try {
      const r = await S.ctl.diagProvision(url, $("#dg-prov-mac").value.trim(), true);
      const acc = r.account && r.account.profile ? r.account.profile.account : null;
      const beh = r.account && r.account.profile ? r.account.profile.behavior : null;
      out.innerHTML = `
        <p class="mono">${esc(r.url)} <span class="muted">(MAC ${esc((r.mac || "").match(/../g)?.join(":") || "")}, ${r.ms} ms)</span></p>
        ${r.bytes == null ? `<p class="bad"><b>${esc(r.error || "")}</b></p>` : r.ok ? `<p class="ok"><b>${esc(t("Format"))}: ${esc(r.format)}, ${r.bytes} bytes</b></p>` : `<p class="warn"><b>${esc(t("Format"))}: ${esc(r.format)}, ${r.bytes} bytes. ${esc(r.error || "")}</b></p>`}
        ${acc ? table([t("User"), t("Display name"), t("Server"), t("Transport"), t("Codecs"), t("Voicemail")], [[esc(acc.user), esc(acc.display_name || ""), `<span class="mono">${esc(acc.domain)}</span>`, esc(beh.transport), esc((beh.codecs || []).join(", ") || t("global list")), esc(r.account.voicemail || "")]]) : ""}
        ${r.excerpt ? `<details><summary>${esc(t("Content (passwords hidden)"))}</summary><pre class="mono dg-pre">${esc(r.excerpt)}</pre></details>` : ""}`;
    } catch (e) {
      out.innerHTML = `<p class="bad">${esc(e.message || e)}</p>`;
    }
  });
  $("#dg-prov-url").addEventListener("keydown", (e) => e.key === "Enter" && $("#dg-prov-go").click());
  $("#dg-prov-dhcp").addEventListener("click", async () => {
    const out = $("#dg-prov-out");
    out.innerHTML = `<p class="muted">${esc(t("Asking the DHCP server…"))}</p>`;
    try {
      const r = await S.ctl.provisionDiscover($("#dg-prov-mac").value.trim());
      const rows = [["66", esc(r.option66 || "-")], ["150", esc(r.option150.join(", ") || "-")], ["160", esc(r.option160 || "-")]];
      out.innerHTML = `<p class="${r.servers.length ? "ok" : "warn"}"><b>${esc(t("DHCP server"))} ${esc(r.dhcp_server || "?")}</b></p>${table([t("Option"), t("Value")], rows)}
        ${r.servers.map((u) => `<button type="button" class="linklike mono" data-dg-prov="${esc(u)}">${esc(u)}</button>`).join(" · ")}`;
    } catch (e) {
      out.innerHTML = `<p class="bad">${esc(e.message || e)}</p>`;
    }
  });
  $("#dg-prov-out").addEventListener("click", (e) => {
    const b = e.target.closest("[data-dg-prov]");
    if (b) $("#dg-prov-url").value = /^tftp:\/\/[^/]+$/.test(b.dataset.dgProv) ? `${b.dataset.dgProv}/SEP{MAC}.cnf.xml` : b.dataset.dgProv;
  });
  $("#dg-stun-go").addEventListener("click", async () => {
    const servers = $("#dg-stun-servers").value.split(/[,\s]+/).filter(Boolean);
    const out = $("#dg-stun-out");
    out.innerHTML = `<p class="muted">Asking ${servers.length} server${servers.length > 1 ? "s" : ""}…</p>`;
    try {
      const r = await S.ctl.stun(servers);
      out.innerHTML = `<p><b>${esc(r.nat)}</b></p>${table(["Server", "Seen as", "Round trip", ""], r.probes.map((p) => [`<span class="mono">${esc(p.server)}</span>`, `<span class="mono">${esc(p.mapped || "")}</span>`, p.rtt_ms != null ? `${p.rtt_ms} ms` : "", esc(p.error || "")]))}${r.local ? `<p class="hint">Local socket ${esc(r.local)}</p>` : ""}`;
    } catch (e) {
      out.innerHTML = `<p class="bad">${esc(e.message || e)}</p>`;
    }
  });
}

// ============================================================================
// Settings

const get = (o, path) => path.split(".").reduce((x, k) => (x == null ? x : x[k]), o);
function set(o, path, v) {
  const ks = path.split(".");
  let x = o;
  for (const k of ks.slice(0, -1)) x = x[k] ??= {};
  x[ks[ks.length - 1]] = v;
}

// Field: [path, label, type, hint, extra]
const NATIVE_ACC_TABS = [
  ["Account", [
    ["label", "Name in the phone", "text", "e.g. Genesys lab 2001"],
    ["enabled", "Enabled", "bool"],
    ["profile.account.user", "User (extension or number)", "text"],
    ["profile.account.display_name", "Display name", "opt"],
    ["profile.account.auth_user", "Authentication user", "opt", "only when it differs from the user"],
    ["profile.account.password", "Password", "password"],
    ["profile.account.domain", "Domain or registrar", "text", "host or host:port. Without a port, DNS SRV (_sip._udp) is tried first. Leave it empty with Register off for an anonymous client that dials SIP URIs directly."],
  ]],
  ["Server and registration", [
    ["register", "Register", "bool", "turn off for trunks, peer-to-peer tests, call-only use or direct SIP URI dialing"],
    ["profile.account.outbound_proxy", "Outbound proxy", "opt", "host:port. Every request goes here, whatever the destination."],
    ["profile.account.expires", "Registration expiry (s)", "number"],
    ["retry_s", "Retry a failed registration after (s)", "number"],
    ["profile.account.q_value", "Contact q-value", "opt"],
    ["profile.behavior.keepalive_interval", "CRLF keepalive every (s)", "number", "0 = off. Keeps NAT bindings open."],
    ["profile.behavior.filter_registrar", "Accept requests only from the registrar", "bool"],
  ]],
  ["Network", [
    ["profile.behavior.transport", "SIP transport", "select", "TCP and TLS keep one connection to the server; with TLS and no port, 5061 and DNS _sips._tcp are used", [["udp", "UDP"], ["tcp", "TCP"], ["tls", "TLS"]]],
    ["profile.behavior.tls_verify", "Check the server's TLS certificate", "bool", "turn off for labs and PBXs with self-signed certificates"],
    ["profile.behavior.tls_ca_file", "Server CA bundle (private PKI)", "file", "PEM file of the CA(s) that signed the server certificate. Empty = public roots. Used only when the check above is on.", "ca-bundle"],
    ["profile.behavior.tls_client_cert", "Client certificate (mutual TLS)", "file", "For servers that require a client certificate. A PKCS#12 bundle (.p12/.pfx) carries the certificate and key together; a PEM file carries the certificate chain.", "client-cert"],
    ["profile.behavior.tls_client_key", "Client private key (PEM)", "file", "Only for a PEM certificate whose key is a separate file. Leave empty for a .p12/.pfx bundle, or a PEM that already contains the key.", "client-cert"],
    ["profile.behavior.tls_client_pass", "Client bundle password", "password", "Password for the .p12/.pfx bundle, if it has one."],
    ["profile.behavior.local_ip", "Local IP", "opt", "empty = the interface the OS routes to the server"],
    ["profile.behavior.local_port", "Local SIP port", "number", "0 = random. Use 5060 to look like a desk phone."],
    ["profile.behavior.rport", "Request rport (RFC 3581)", "bool"],
    ["profile.behavior.symmetric_rtp", "Symmetric RTP (send audio back where it comes from)", "bool"],
    ["profile.behavior.rtp_port_start", "RTP ports from", "number"],
    ["profile.behavior.rtp_port_end", "RTP ports to", "number"],
    ["profile.behavior.dscp_sip", "DSCP for SIP", "number", "24 = CS3, 26 = AF31"],
    ["profile.behavior.dscp_rtp", "DSCP for RTP", "number", "46 = EF"],
    ["profile.behavior.sdp_ip_override", "Address in SDP", "opt", "advertise another address, e.g. to reproduce one-way audio behind NAT"],
    ["profile.behavior.t1_ms", "Timer T1 (ms)", "number", "RFC 3261 retransmission base, 500 by default"],
  ]],
  ["Media", [
    ["profile.behavior.codecs", "Codecs, in order of preference", "codecs"],
    ["profile.behavior.g726_aal2", "G.726 with the AAL2 bit order (AAL2-G726-xx)", "bool"],
    ["profile.behavior.srtp", "Media encryption (SRTP)", "select", "Optional offers SRTP and accepts plain RTP; Required hangs up or rejects calls without it.", [["off", "Off (RTP)"], ["optional", "Optional"], ["mandatory", "Required"]]],
    ["profile.behavior.srtp_keys", "SRTP keys", "select", "SDES puts the keys in the SDP (a=crypto): use it with TLS. DTLS-SRTP negotiates them on the media path and checks the far end's certificate against a=fingerprint.", [["sdes", "SDES (a=crypto)"], ["dtls", "DTLS-SRTP (a=fingerprint)"]]],
    ["profile.behavior.ptime_ms", "Packet time (ms)", "select", "", [["10", "10"], ["20", "20"], ["30", "30"], ["40", "40"], ["60", "60"]]],
    ["profile.behavior.sdp_direction", "Direction offered", "select", "", [["sendrecv", "sendrecv"], ["sendonly", "sendonly"], ["recvonly", "recvonly"], ["inactive", "inactive"]]],
  ]],
  ["DTMF", [
    ["profile.behavior.dtmf_mode", "Send DTMF as", "select", "", [["rfc4733", "RTP events (RFC 4733)"], ["info", "SIP INFO (dtmf-relay)"], ["inband", "Tones in the audio"]]],
    ["profile.behavior.dtmf_payload_type", "telephone-event payload type", "number"],
  ]],
  ["Advanced SIP", [
    ["profile.behavior.user_agent", "User-Agent", "text"],
    ["profile.behavior.max_forwards", "Max-Forwards", "number"],
    ["profile.behavior.session_timer", "Session timer (s)", "number", "0 = off; otherwise Session-Expires is requested and refreshed with UPDATE"],
    ["profile.behavior.user_phone", "Add user=phone to numeric destinations", "bool"],
    ["profile.behavior.compact_headers", "Compact header names (v, f, t, i, m, l)", "bool"],
    ["profile.behavior.require_prack", "Require reliable provisional responses (100rel)", "bool"],
    ["profile.behavior.offer_gruu", "Advertise GRUU", "bool"],
    ["profile.behavior.long_contact", "Long Contact (+sip.instance, feature tags)", "bool"],
    ["profile.behavior.proxy_require", "Proxy-Require", "opt"],
    ["profile.behavior.skip_ack", "Do not send ACK for 2xx (reproduces the 32 s drop)", "bool", "testing only"],
  ]],
  ["Headers", [["profile.behavior.extra_headers", "Headers added to every request", "headers"]]],
  ["Voicemail", [
    ["mwi", "Show the voicemail lamp (SUBSCRIBE message-summary, RFC 3842)", "bool"],
    ["voicemail", "Voicemail number", "text", "dialed by the voicemail button, e.g. *97; empty = the mailbox address the server announces"],
  ]],
  ["BLF", [["blf", "Extensions to watch (busy lamp field)", "lines", "one per line: an extension, user@host or SIP URI. Sidetone subscribes to the dialog event package (RFC 4235) for the lamp and to presence (RFC 3856, PIDF) when the server offers it, once the account is registered; the PBX needs hints for them."]]],
];

const WEB_ACC_TABS = [
  ["Account", [
    ["label", "Name in the phone", "text"],
    ["enabled", "Enabled", "bool"],
    ["user", "User (extension or number)", "text"],
    ["displayName", "Display name", "text"],
    ["authUser", "Authentication user", "text", "only when it differs from the user"],
    ["password", "Password", "password"],
    ["rememberPassword", "Remember the password in this browser", "bool"],
    ["domain", "SIP domain", "text"],
  ]],
  ["Server and registration", [
    ["ws", "WebSocket URL", "text", "wss://pbx.example.com:8089/ws. Pages served over https need wss with a trusted certificate."],
    ["register", "Register", "bool"],
    ["expires", "Registration expiry (s)", "number"],
  ]],
  ["Network", [["ice", "STUN or TURN servers", "text", "comma separated, e.g. stun:stun.l.google.com:19302"]]],
];

// Codecs the desktop engine can use: [settings name, on by default, kbit/s, description, payload type, rtpmap, fmtp].
const CODEC_LIST = [
  ["PCMU", true, 64, "G.711 μ-law", 0, "PCMU/8000"],
  ["PCMA", true, 64, "G.711 A-law", 8, "PCMA/8000"],
  ["G722", true, 64, "G.722 wideband, 16 kHz", 9, "G722/8000"],
  ["opus", true, 32, "Opus wideband, 16 kHz audio, FEC", 111, "opus/48000/2", "useinbandfec=1"],
  ["G729", false, 8, "G.729 Annex A", 18, "G729/8000", "annexb=no"],
  ["iLBC", false, 13, "iLBC, 30 ms frames", 102, "iLBC/8000", "mode=30"],
  ["speex/16000", false, 28, "Speex wideband", 98, "speex/16000"],
  ["speex/8000", false, 15, "Speex narrowband", 97, "speex/8000"],
  ["GSM", false, 13, "GSM 06.10 full rate", 3, "GSM/8000"],
  ["G726-32", false, 32, "G.726 ADPCM", 112, "G726-32/8000"],
  ["G726-40", false, 40, "G.726 ADPCM", 106, "G726-40/8000"],
  ["G726-24", false, 24, "G.726 ADPCM", 105, "G726-24/8000"],
  ["G726-16", false, 16, "G.726 ADPCM", 104, "G726-16/8000"],
  ["L16/16000", false, 256, "Linear PCM 16 kHz", 115, "L16/16000"],
  ["L16/44100", false, 706, "Linear PCM 44.1 kHz", 116, "L16/44100"],
  ["L16/8000", false, 128, "Linear PCM 8 kHz", 114, "L16/8000"],
];
const CODEC_DEFAULTS = CODEC_LIST.filter((c) => c[1]).map((c) => c[0]);
const codecInfo = (k) => CODEC_LIST.find((c) => c[0].toLowerCase() === String(k).toLowerCase());

/// Ordered checklist of codecs. `inherit` adds a "use the …" switch: when on, the
/// value saved is [] (account: global list) or null (one call: the account's).
function codecPicker(id, value, inherit) {
  const inh = inherit && (value == null || (Array.isArray(value) && !value.length));
  const cur = (inh ? (inherit.fallback || CODEC_DEFAULTS) : value || []).map((k) => (codecInfo(k) || [k])[0]).filter((k) => codecInfo(k));
  const order = [...cur, ...CODEC_LIST.map((c) => c[0]).filter((k) => !cur.includes(k))];
  return `<div class="codec-pick${inh ? " inherit" : ""}" id="${id}">
    ${inherit ? `<label class="check"><input type="checkbox" data-inherit ${inh ? "checked" : ""}> ${esc(t(inherit.label))}</label>` : ""}
    <ol class="codecs">${order
      .map((k) => {
        const c = codecInfo(k);
        return `<li data-codec="${esc(k)}"><label class="check"><input type="checkbox" ${cur.includes(k) ? "checked" : ""}> <b class="mono">${esc(k)}</b></label><span class="muted small">${esc(t(c[3]))}</span><span class="kbps mono">${c[2]} kbit/s</span><span class="cbtns"><button type="button" class="icon-btn" data-cup title="${esc(t("Move up"))}">↑</button><button type="button" class="icon-btn" data-cdown title="${esc(t("Move down"))}">↓</button></span></li>`;
      })
      .join("")}</ol></div>`;
}

/// Reads a codec checklist: null/[] when inheriting, else the ticked codecs in order.
function readCodecPicker(el, inheritValue) {
  if (!el) return inheritValue;
  const inh = el.querySelector("[data-inherit]");
  if (inh && inh.checked) return inheritValue;
  return [...el.querySelectorAll("li")].filter((li) => li.querySelector("input").checked).map((li) => li.dataset.codec);
}

// Up/down and the inherit switch work the same in every codec list.
document.addEventListener("click", (e) => {
  const b = e.target.closest("[data-cup], [data-cdown]");
  if (!b) return;
  const li = b.closest("li");
  if (b.hasAttribute("data-cup") && li.previousElementSibling) li.parentElement.insertBefore(li, li.previousElementSibling);
  if (b.hasAttribute("data-cdown") && li.nextElementSibling) li.parentElement.insertBefore(li.nextElementSibling, li);
  li.closest("form")?.dispatchEvent(new Event("input", { bubbles: true }));
});
document.addEventListener("change", (e) => {
  const i = e.target.closest("[data-inherit]");
  if (i) i.closest(".codec-pick").classList.toggle("inherit", i.checked);
});

const CALL_SETTINGS = [
  ["codecs", "Codecs offered by default (accounts can use their own list)", "codecs-global", "", null, "native"],
  ["dnd", "Do not disturb", "bool"],
  ["dnd_code", "Reject calls in DND with", "select", "", [["486", "486 Busy Here"], ["480", "480 Temporarily Unavailable"], ["603", "603 Decline"]], "native"],
  ["auto_answer", "Auto answer", "bool"],
  ["auto_answer_delay_ms", "Auto answer after (ms)", "number"],
  ["intercom", "Answer intercom calls at once (Call-Info answer-after, Alert-Info)", "bool", "", null, "native"],
  ["max_lines", "Lines", "number"],
  ["auto_hold", "Put the other calls on hold when you answer or resume one", "bool"],
  ["busy_code", "When all lines are busy, reject with", "select", "", [["486", "486 Busy Here"], ["480", "480 Temporarily Unavailable"], ["503", "503 Service Unavailable"]], "native"],
  ["ring_timeout_s", "Cancel unanswered outgoing calls after (s)", "number", "", null, "native"],
  ["forward_always", "Forward all calls to", "text", "number or SIP URI, answered with 302 Moved Temporarily; empty = off", null, "native"],
  ["forward_busy", "Forward when busy or in DND to", "text", "", null, "native"],
  ["forward_no_answer", "Forward unanswered calls to", "text", "", null, "native"],
  ["forward_no_answer_s", "after (s)", "number", "", null, "native"],
];

function fieldHtml(f, value, id) {
  const [, label, type, hint = "", opts] = f;
  const h = hint ? `<span class="hint">${esc(hint)}</span>` : "";
  switch (type) {
    case "bool":
      return `<label class="check fld"><input type="checkbox" id="${id}" ${value ? "checked" : ""}> ${esc(label)} ${h}</label>`;
    case "number":
      return `<label class="fld">${esc(label)} ${h}<input type="number" id="${id}" value="${esc(value ?? "")}"></label>`;
    case "password":
      return `<label class="fld">${esc(label)} ${h}<input type="password" id="${id}" value="${esc(value ?? "")}" autocomplete="new-password"></label>`;
    case "select":
      return `<label class="fld">${esc(label)} ${h}<select id="${id}">${opts.map(([v, t]) => `<option value="${esc(v)}" ${String(value) === v ? "selected" : ""}>${esc(t)}</option>`).join("")}</select></label>`;
    case "codecs-global":
      return `<div class="fld wide"><span>${esc(label)}</span>${codecPicker(id, value && value.length ? value : CODEC_DEFAULTS, null)}<span class="hint">${esc(t("Tick the codecs to offer and put them in order of preference. The first one the other side also has is used."))}</span></div>`;
    case "codecs":
      return `<div class="fld wide"><span>${esc(label)}</span>${codecPicker(id, value, { label: "Use the global codec list (Settings, Call handling)", fallback: SET.cfg && SET.cfg.settings && SET.cfg.settings.codecs })}<span class="hint">${esc(t("Opus and G.722 carry wideband audio (16 kHz). G.726 uses the RFC 3551 bit order unless AAL2 is ticked below."))}</span></div>`;
    case "codecs-old": {
      const all = ["PCMU", "PCMA", "opus"];
      const CODEC_NAMES = { PCMU: "PCMU (G.711 μ-law)", PCMA: "PCMA (G.711 A-law)", opus: "Opus" };
      const cur = (value || []).filter((c) => all.includes(c));
      const order = [...cur, ...all.filter((c) => !cur.includes(c))];
      return `<div class="fld"><span>${esc(label)}</span><ol class="codecs" id="${id}">${order
        .map((c) => `<li data-codec="${c}"><label class="check"><input type="checkbox" ${cur.includes(c) ? "checked" : ""}> ${CODEC_NAMES[c]}</label><button type="button" class="linklike" data-up>Up</button></li>`)
        .join("")}</ol><span class="hint">Opus carries wideband audio (16 kHz, up to 7 kHz of voice) on a 48 kHz RTP clock, with in-band FEC. G.711 is converted to and from 8 kHz.</span></div>`;
    }
    case "lines":
      return `<label class="fld">${esc(label)} ${h}<textarea id="${id}" rows="6" spellcheck="false">${esc((value || []).join("\n"))}</textarea></label>`;
    case "headers": {
      const rows = (value || []).map(([k, v]) => `<div class="hdr-row"><input placeholder="Name" value="${esc(k)}"><input placeholder="Value" value="${esc(v)}"><button type="button" class="linklike" data-del>Remove</button></div>`).join("");
      return `<div class="fld"><span>${esc(label)}</span><div class="hdrs" id="${id}">${rows}</div><button type="button" class="btn small" data-addhdr="${id}">Add header</button></div>`;
    }
    case "file":
      return `<label class="fld">${esc(label)} ${h}<span class="file-row"><input type="text" id="${id}" value="${esc(value ?? "")}" placeholder="${esc(t("No file selected"))}" spellcheck="false"><button type="button" class="btn small" data-pickfile="${id}" data-pickkind="${esc(opts || "client-cert")}">${esc(t("Browse…"))}</button></span></label>`;
    case "opt":
    default:
      return `<label class="fld">${esc(label)} ${h}<input id="${id}" value="${esc(value ?? "")}" spellcheck="false"></label>`;
  }
}

function readField(f, id, obj) {
  const [path, , type] = f;
  const el = document.getElementById(id);
  if (!el) return;
  let v;
  switch (type) {
    case "bool": v = el.checked; break;
    case "number": v = el.value === "" ? 0 : Number(el.value); break;
    case "select": v = /^\d+$/.test(el.value) && typeof get(obj, path) === "number" ? Number(el.value) : el.value; break;
    case "lines": v = el.value.split("\n").map((x) => x.trim()).filter(Boolean); break;
    case "codecs": v = readCodecPicker(el, []); break;
    case "codecs-global": v = readCodecPicker(el, CODEC_DEFAULTS); break;
    case "headers": v = [...el.querySelectorAll(".hdr-row")].map((r) => [r.children[0].value.trim(), r.children[1].value.trim()]).filter(([k]) => k); break;
    case "opt": case "file": v = el.value.trim() || null; break;
    default: v = el.value;
  }
  set(obj, path, v);
}

const SET = { cfg: null, accId: null, accTab: 0, section: null, dirty: false };

function provisionUrlDisplay(url) {
  if (!url) return "";
  try {
    const u = new URL(url);
    u.username = "";
    u.password = "";
    return u.toString();
  } catch {
    return String(url).replace(/^(?<sch>[\w+.-]+:\/\/)(?<auth>[^@/]+@)/u, "$1");
  }
}

function applyNativeProvision(acc, p, url, tlsVerify) {
  const keepName = acc.profile?.name ?? "";
  const prevUa = acc.profile?.behavior?.user_agent;
  acc.label = p.label;
  acc.enabled = p.enabled;
  acc.register = p.register;
  if (p.retry_s != null) acc.retry_s = p.retry_s;
  if (p.blf) acc.blf = p.blf;
  if (p.mwi != null) acc.mwi = p.mwi;
  if (p.voicemail != null) acc.voicemail = p.voicemail;
  if (!acc.profile) acc.profile = { name: keepName, account: {}, behavior: {} };
  acc.profile.name = keepName;
  Object.assign(acc.profile.account, p.profile.account);
  const beh = p.profile?.behavior || {};
  acc.profile.behavior = { ...(acc.profile.behavior || {}), ...beh };
  if (Object.prototype.hasOwnProperty.call(beh, "user_agent") && beh.user_agent === null) {
    acc.profile.behavior.user_agent = prevUa;
  }
  acc.provision_url = url;
  acc.provision_tls_verify = tlsVerify !== false;
}

function applyWebProvision(acc, p, url) {
  acc.label = p.label;
  acc.enabled = p.enabled;
  acc.register = p.register;
  acc.user = p.user;
  acc.authUser = p.authUser || "";
  acc.password = p.password || "";
  acc.displayName = p.displayName;
  acc.domain = p.domain;
  acc.ws = p.ws;
  acc.ice = p.ice || "";
  acc.expires = p.expires;
  acc.rememberPassword = !!p.rememberPassword;
  acc.provisionUrl = url;
}

// DHCPINFORM: offers the servers the network gives phones as URLs to pick.
async function discoverProvisioning() {
  const box = $("#prov-found");
  box.textContent = t("Asking the DHCP server…");
  try {
    const r = await S.ctl.provisionDiscover($("#prov-mac").value.trim());
    if (!r.servers.length) {
      box.textContent = t("The DHCP server answered without provisioning options (66, 150 or 160).");
      return;
    }
    const files = ["SEP{MAC}.cnf.xml", "{mac}.cfg", "y000000000000.cfg", "{mac}-phone.cfg"];
    box.innerHTML = `${esc(t("From DHCP"))}${r.dhcp_server ? ` (${esc(r.dhcp_server)})` : ""}: ` + r.servers
      .flatMap((sv) => (/^tftp:\/\/[^/]+$/.test(sv) ? files.map((f) => `${sv}/${f}`) : [sv]))
      .map((u) => `<button type="button" class="linklike" data-prov-url="${esc(u)}">${esc(u)}</button>`)
      .join(" · ");
  } catch (e) {
    box.textContent = e.message || String(e);
  }
}

function openProvisionDialog() {
  const dlg = $("#prov-dialog");
  const native = S.ctl.kind === "native";
  const acc = SET.cfg?.accounts.find((a) => a.id === SET.accId);
  $("#prov-title").textContent = t("Fetch provisioning");
  $("#prov-url-label").textContent = t("Provisioning URL");
  $("#prov-tls-label").textContent = t("Check the server's TLS certificate");
  $("#prov-hint").textContent = t(native ? "http, https or tftp. Sidetone XML, a Yealink .cfg, a Polycom XML or a Cisco SEP<MAC>.cnf.xml; from a phone file, the first configured line is used. {mac} in the URL becomes the device MAC, as a phone would ask (tftp://10.0.0.5/SEP{MAC}.cnf.xml)." : "Sidetone XML with a WebSocket address (ws or wss). Yealink, Polycom and Cisco files need the desktop app.");
  $("#prov-mac-label").textContent = t("Device MAC (for {mac} in the URL; empty: this computer's)");
  $("#prov-discover").textContent = t("Find the server on the network (DHCP)");
  $("#prov-mac-wrap").hidden = !native;
  $("#prov-discover-wrap").hidden = !native;
  $("#prov-found").innerHTML = "";
  $("#prov-mac").value = (native && acc && acc.provision_mac) || "";
  if (native && S.ctl.provisionMac) S.ctl.provisionMac().then((m) => ($("#prov-mac").placeholder = m.match(/../g).join(":"))).catch(() => {});
  $("#prov-fetch").textContent = t("Fetch");
  $("#prov-cancel").textContent = t("Cancel");
  $("#prov-err").hidden = true;
  $("#prov-err").textContent = "";
  $("#prov-tls-wrap").hidden = S.ctl.kind === "web";
  $("#prov-url").value = acc ? (native ? acc.provision_url || "" : acc.provisionUrl || "") : "";
  $("#prov-tls").checked = acc?.provision_tls_verify !== false;
  dlg.showModal();
}

async function runProvisionFetch() {
  const url = $("#prov-url").value.trim();
  if (!url) return;
  const errEl = $("#prov-err");
  errEl.hidden = true;
  const native = S.ctl.kind === "native";
  try {
    const mac = $("#prov-mac").value.trim();
    const parsed = await S.ctl.provision(url, $("#prov-tls").checked, mac);
    const acc = SET.cfg.accounts.find((a) => a.id === SET.accId);
    if (!acc) return;
    if (native) {
      applyNativeProvision(acc, parsed, url, $("#prov-tls").checked);
      acc.provision_mac = mac || null;
    }
    else applyWebProvision(acc, parsed, url);
    if (!native && parsed.password) S.ctl.passwords[acc.id] = parsed.password;
    $("#prov-dialog").close();
    renderSetNav();
    const saved = await saveAccounts();
    if (!saved) {
      SET.dirty = true;
      await renderSetBody();
    }
  } catch (e) {
    errEl.textContent = e.message || String(e);
    errEl.hidden = false;
  }
}

async function settingsOpen() {
  // Unsaved edits survive leaving and coming back; a fresh copy is only
  // fetched when there is nothing pending.
  if (SET.dirty && SET.cfg) {
    renderSetNav();
    renderSetBody();
    return;
  }
  SET.dirty = false;
  try {
    SET.cfg = await S.ctl.getConfig();
  } catch (e) {
    $("#set-body").innerHTML = `<p class="err">${esc(e.message || e)}</p>`;
    return;
  }
  if (!SET.accId && !SET.section) SET.accId = SET.cfg.accounts.length ? SET.cfg.accounts[0].id : null;
  if (!SET.accId && !SET.section) SET.section = SET.cfg.accounts.length ? null : "new";
  renderSetNav();
  renderSetBody();
}

function renderSetNav() {
  $("#acc-list").innerHTML = SET.cfg.accounts
    .map((a) => {
      const live = S.st && S.st.accounts.find((x) => x.id === a.id);
      const name = a.label || (S.ctl.kind === "web" ? a.user : a.profile.account.user) || "Unnamed";
      return `<li><button type="button" data-acc="${esc(a.id)}" aria-current="${a.id === SET.accId && !SET.section}"><span class="dot ${regClass(live)}"></span>${esc(name)}</button></li>`;
    })
    .join("") || `<li class="muted small pad">No accounts</li>`;
  $$(".set-nav [data-set]").forEach((b) => b.setAttribute("aria-current", String(b.dataset.set === SET.section)));
}

function newNativeAccount() {
  const n = SET.cfg.accounts.length + 1;
  let id = String(n);
  while (SET.cfg.accounts.some((a) => a.id === id)) id = String(+id + 1);
  return { id, label: "", enabled: true, register: true, retry_s: 30, provision_url: null, provision_tls_verify: true, profile: { name: "", account: { user: "", auth_user: null, password: null, domain: "", display_name: null, outbound_proxy: null, expires: 300, q_value: null }, behavior: null } };
}

function markSetDirty() {
  SET.dirty = true;
  const d = $("#acc-dirty");
  if (d) d.textContent = t("Unsaved changes");
}

async function renderSetBody() {
  const body = $("#set-body");
  const native = S.ctl.kind === "native";
  if (SET.section === "new" || (!SET.section && !SET.accId)) {
    body.innerHTML = `<div class="set-empty"><h1>${esc(t("Add your first account"))}</h1><p class="muted">${esc(native ? t("Sidetone registers over UDP from this computer, like a desk phone. You need the server address, the extension and its password.") : t("In the browser Sidetone talks SIP over WebSocket (RFC 7118) with WebRTC audio. Your PBX needs a WSS listener, for example Asterisk on port 8089 or a Genesys/Ribbon SBC with WebRTC enabled."))}</p><div class="row"><button type="button" class="btn primary" id="acc-first">${esc(t("Add account"))}</button><button type="button" class="btn" id="acc-first-prov">${esc(t("Provision"))}</button></div></div>`;
    $("#acc-first").addEventListener("click", addAccount);
    $("#acc-first-prov").addEventListener("click", async () => {
      await addAccount();
      openProvisionDialog();
    });
    return;
  }
  if (SET.section) return renderGlobal(SET.section);
  const acc = SET.cfg.accounts.find((a) => a.id === SET.accId);
  if (!acc) {
    SET.accId = null;
    return renderSetBody();
  }
  // Fill behavior defaults so every field shows a value.
  if (native && !acc.profile.behavior) acc.profile.behavior = (await defaultBehavior()) || {};
  const tabs = native ? NATIVE_ACC_TABS : WEB_ACC_TABS;
  const tabIdx = Math.min(SET.accTab, tabs.length - 1);
  const [, fields] = tabs[tabIdx];
  body.innerHTML = `
    <div class="set-head">
      <h1>${esc(acc.label || (native ? acc.profile.account.user : acc.user) || "New account")}</h1>
      <div class="row"><button type="button" class="btn small" id="acc-prov">${esc(t("Provision"))}</button><button type="button" class="btn small" id="acc-dup">${esc(t("Duplicate"))}</button><button type="button" class="btn small danger" id="acc-del">${esc(t("Delete"))}</button></div>
    </div>
    ${native ? "" : `<div class="notice">${esc(t("The browser can only talk SIP over WebSocket (wss://, or ws:// on a local network): your PBX or SBC needs a WebSocket listener, such as Asterisk's transport-wss, FreeSWITCH's wss-binding or an SBC with WebRTC. For plain SIP over UDP, TCP or TLS, use the desktop app."))} <a href="https://github.com/igtoth/sidetone#downloads" target="_blank" rel="noopener">${esc(t("Download the desktop app"))}</a></div>`}
    <div class="seg nav" role="tablist" id="acc-tabs">${tabs.map(([n], i) => `<button type="button" role="tab" data-acctab="${i}" aria-selected="${i === tabIdx}">${esc(n)}</button>`).join("")}</div>
    <form class="set-form" id="acc-form" autocomplete="off">
      <div class="fields">${tabIdx === 0 ? `<div class="fld"><span>${esc(t("Provisioning URL"))}</span><input readonly class="readonly" value="${esc(provisionUrlDisplay(native ? acc.provision_url : acc.provisionUrl))}"></div>` : ""}${fields.map((f, i) => fieldHtml(f, get(acc, f[0]), `af-${i}`)).join("")}</div>
      ${native && tabs[tabIdx][0] === "Advanced SIP" ? `<h3>What an INVITE from this account looks like</h3><pre class="sipmsg preview" id="inv-preview"></pre>` : ""}
      <div class="set-actions"><span class="hint" id="acc-dirty"></span><button type="submit" class="btn primary">Save account</button></div>
    </form>
    <section class="set-form acc-reg" id="acc-reg"></section>`;
  renderAccReg();
  const form = $("#acc-form");
  const collect = () => fields.forEach((f, i) => readField(f, `af-${i}`, acc));
  const preview = () => {
    const p = $("#inv-preview");
    if (p) {
      collect();
      p.innerHTML = highlightSip(invitePreview(acc));
    }
  };
  preview();
  if (SET.dirty) markSetDirty();
  form.addEventListener("input", () => {
    markSetDirty();
    preview();
  });
  form.addEventListener("click", async (e) => {
    const pick = e.target.closest("[data-pickfile]");
    if (pick) {
      try {
        const r = S.ctl.pickFile ? await S.ctl.pickFile(pick.dataset.pickkind) : null;
        if (r && r.path) {
          $("#" + pick.dataset.pickfile).value = r.path;
          markSetDirty();
        } else if (!r) {
          toast(t("The file picker needs the desktop app. Paste the file path instead."), 5000);
        }
      } catch {
        toast(t("The file picker needs the desktop app. Paste the file path instead."), 5000);
      }
      return;
    }
    const up = e.target.closest("[data-up]");
    if (up) {
      const li = up.closest("li");
      if (li.previousElementSibling) li.parentElement.insertBefore(li, li.previousElementSibling);
      markSetDirty();
      preview();
    }
    const del = e.target.closest("[data-del]");
    if (del) {
      del.closest(".hdr-row").remove();
      markSetDirty();
    }
    const add = e.target.closest("[data-addhdr]");
    if (add) {
      $("#" + add.dataset.addhdr).insertAdjacentHTML("beforeend", `<div class="hdr-row"><input placeholder="Name"><input placeholder="Value"><button type="button" class="linklike" data-del>Remove</button></div>`);
      markSetDirty();
    }
  });
  if ($("#acc-tabs")) tablistKeys($("#acc-tabs"));
  $$("[data-acctab]").forEach((b) =>
    b.addEventListener("click", async () => {
      collect();
      SET.accTab = +b.dataset.acctab;
      await renderSetBody();
      const again = $(`[data-acctab="${SET.accTab}"]`);
      if (again) again.focus();
    })
  );
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    collect();
    const miss = missingField(acc, native);
    if (miss) {
      // Open the tab that has the field and point at it.
      const [tab, key, why] = miss;
      SET.accTab = tab;
      renderSetBody();
      const i = tabs[tab][1].findIndex((f) => f[0] === key);
      const el = $(`#af-${i}`);
      if (el) {
        const fld = el.closest(".fld") || el.parentElement;
        fld.classList.add("invalid");
        fld.insertAdjacentHTML("beforeend", `<span class="fld-err">${esc(t(why))}</span>`);
        el.focus();
      }
      toast(t(why), 5000);
      return;
    }
    await saveAccounts();
  });
  $("#acc-del").addEventListener("click", async () => {
    if (!confirm(`${t("Delete this account?")} ${accLabel(acc) || acc.id}`)) return;
    SET.cfg.accounts = SET.cfg.accounts.filter((a) => a.id !== acc.id);
    SET.accId = SET.cfg.accounts.length ? SET.cfg.accounts[0].id : null;
    await saveAccounts();
  });
  $("#acc-prov").addEventListener("click", () => openProvisionDialog());
  $("#acc-dup").addEventListener("click", () => {
    collect();
    const copy = JSON.parse(JSON.stringify(acc));
    copy.id = native ? newNativeAccount().id : webAccountDefaults().id;
    copy.label = `${acc.label || "Account"} copy`;
    SET.cfg.accounts.push(copy);
    SET.accId = copy.id;
    renderSetNav();
    renderSetBody();
    toast("Copied. Save to keep it.");
  });
}

let behaviorDefaults = null;
async function defaultBehavior() {
  if (behaviorDefaults) return JSON.parse(JSON.stringify(behaviorDefaults));
  // The engine fills defaults for a missing behavior; save then read back gives them.
  behaviorDefaults = {
    transport: "udp", tls_verify: true, local_port: 0, local_ip: null, t1_ms: 500, max_forwards: 70, session_timer: 0, user_phone: false, compact_headers: false, require_prack: false,
    offer_gruu: false, long_contact: false, rport: true, codecs: [], g726_aal2: false, ptime_ms: 20, dtmf_mode: "rfc4733", dtmf_payload_type: 101, srtp: "off", srtp_keys: "sdes",
    symmetric_rtp: true, rtcp: false, rtp_port_start: 40000, rtp_port_end: 49999, dscp_sip: 0, dscp_rtp: 0, keepalive_interval: 0, user_agent: `Sidetone/${S.version || ""}`,
    proxy_require: null, filter_registrar: false, extra_headers: [], sdp_direction: "sendrecv", skip_ack: false, sdp_ip_override: null,
  };
  return JSON.parse(JSON.stringify(behaviorDefaults));
}

async function addAccount() {
  const native = S.ctl.kind === "native";
  const a = native ? newNativeAccount() : webAccountDefaults();
  if (native) a.profile.behavior = await defaultBehavior();
  SET.cfg.accounts.push(a);
  SET.accId = a.id;
  SET.section = null;
  SET.accTab = 0;
  renderSetNav();
  renderSetBody();
}

/// The first required field an account lacks: [tab index, field key, message].
function missingField(acc, native) {
  const tabs = native ? NATIVE_ACC_TABS : WEB_ACC_TABS;
  const where = (key) => tabs.findIndex(([, fs]) => fs.some((f) => f[0] === key));
  if (!acc.enabled) return null;
  if (native) {
    const a = acc.profile.account;
    if (acc.register !== false && !(a.domain || "").trim()) return [where("profile.account.domain"), "profile.account.domain", "Fill in the SIP domain or registrar (host or host:port)."];
    if (acc.register !== false && !(a.user || "").trim()) return [where("profile.account.user"), "profile.account.user", "Fill in the user (extension or number)."];
    return null;
  }
  if (!(acc.user || "").trim()) return [where("user"), "user", "Fill in the user (extension or number)."];
  if (!(acc.domain || "").trim()) return [where("domain"), "domain", "Fill in the SIP domain."];
  const ws = (acc.ws || "").trim();
  if (!ws) return [where("ws"), "ws", "The browser phone needs the WebSocket URL of your PBX or SBC, e.g. wss://pbx.example.com:8089/ws. The desktop app talks UDP, TCP or TLS and needs no WebSocket."];
  if (!/^wss?:\/\//i.test(ws)) return [where("ws"), "ws", "The WebSocket URL starts with wss:// (or ws:// on a local network)."];
  return null;
}

/// Live registration status of the account being edited: state, the REGISTER
/// exchange as it happens, and shortcuts to the trace and the analysis.
function renderAccReg() {
  const box = $("#acc-reg");
  if (!box || !SET.cfg) return;
  const native = S.ctl.kind === "native";
  const acc = SET.cfg.accounts.find((a) => a.id === SET.accId);
  if (!acc) return;
  const live = S.st && S.st.accounts.find((x) => x.id === acc.id);
  const user = native ? acc.profile.account.user : acc.user;
  const regs = S.trace
    .filter((x) => (x.method === "REGISTER" || (x.status && /REGISTER/.test(x.cseq))) && (!user || x.raw.includes(`sip:${user}@`)))
    .slice(-12);
  const open = new Set([...box.querySelectorAll("details[open]")].map((d) => d.dataset.seq));
  const cls = live ? regClass(live) : "";
  box.innerHTML = `
    <div class="sect-head"><h2>${esc(t("Registration"))}</h2>
      <div class="row">
        <button type="button" class="btn small" id="ar-reg" ${live ? "" : "disabled"}>${esc(t("Register now"))}</button>
        <button type="button" class="btn small" id="ar-trace">${esc(t("Show in SIP trace"))}</button>
        <button type="button" class="btn small" id="ar-an" ${regs.length ? "" : "disabled"}>${esc(t("Analyze"))}</button>
      </div></div>
    <p class="ar-state ${cls}"><span class="dot ${cls}"></span> ${esc(live ? t(accountStateText(live)) : t("Not saved yet: save the account to register."))}</p>
    ${live && live.error ? `<p class="bad">${esc(t(live.error))}</p>` : ""}
    ${regs.length
      ? `<div class="ar-list">${regs
          .map((x) => `<details data-seq="${x.seq}" ${open.has(String(x.seq)) ? "open" : ""}><summary><span class="mono muted">${clock(x.ts_ms, true)}</span> <span class="tr-d ${x.dir}">${x.dir === "out" ? "→" : "←"}</span> <span class="mono ${x.status >= 400 ? "bad" : x.status >= 200 ? "ok" : ""}">${esc(x.first_line)}</span></summary><pre class="sipmsg">${highlightSip(x.raw)}</pre></details>`)
          .join("")}</div>`
      : `<p class="hint">${esc(t(live ? "No REGISTER sent yet." : "The REGISTER and the server's answers will show here as they happen."))}</p>`}`;
  $("#ar-reg").addEventListener("click", () => cmd({ cmd: "register", account: acc.id }));
  $("#ar-trace").addEventListener("click", () => {
    showWs("trace");
    $("#tr-hide-reg").checked = false;
    $("#tr-call").value = "";
    $("#tr-filter").value = user || "";
    renderTrace(true);
  });
  $("#ar-an").addEventListener("click", () => analyzeLine(regs.length ? regs[regs.length - 1].call_id : null));
}

async function saveAccounts() {
  try {
    await S.ctl.setConfig({ accounts: SET.cfg.accounts });
    toast("Saved. Registering…");
    const d = $("#acc-dirty");
    if (d) d.textContent = "";
    SET.dirty = false;
    SET.cfg = await S.ctl.getConfig();
    renderSetNav();
    renderSetBody();
    return true;
  } catch (e) {
    const d = $("#acc-dirty");
    if (d) {
      d.textContent = `${t("Not saved")}: ${e.message || e}`;
      d.classList.add("err");
    } else toast(`Not saved: ${e.message || e}`, 5000);
    return false;
  }
}

function invitePreview(acc) {
  const b = acc.profile.behavior;
  const a = acc.profile.account;
  const hn = (n) => (b.compact_headers ? { Via: "v", From: "f", To: "t", "Call-ID": "i", Contact: "m", "Content-Length": "l", "Content-Type": "c", Supported: "k" }[n] || n : n);
  const host = (a.domain || "pbx.example.com").replace(/:\d+$/, "");
  const target = `sip:600@${a.domain || "pbx.example.com"}${b.user_phone ? ";user=phone" : ""}`;
  const local = `${b.local_ip || "192.0.2.10"}:${b.local_port || 50600}`;
  const sup = ["replaces", "100rel", "norefersub", ...(b.session_timer > 0 ? ["timer"] : []), ...(b.offer_gruu ? ["gruu"] : [])];
  const lines = [
    `INVITE ${target} SIP/2.0`,
    `${hn("Via")}: SIP/2.0/UDP ${local};branch=z9hG4bK3f1c9a${b.rport ? ";rport" : ""}`,
    `Max-Forwards: ${b.max_forwards}`,
    `${hn("From")}: ${a.display_name ? `"${a.display_name}" ` : ""}<sip:${a.user || "2001"}@${host}>;tag=8d2e`,
    `${hn("To")}: <${target}>`,
    `${hn("Call-ID")}: 5b0c7e@${local.split(":")[0]}`,
    "CSeq: 1 INVITE",
    ...(b.proxy_require ? [`Proxy-Require: ${b.proxy_require}`] : []),
    `User-Agent: ${b.user_agent}`,
    `${hn("Contact")}: <sip:${a.user || "2001"}@${local}>${b.long_contact ? ';+sip.instance="<urn:uuid:…>";reg-id=1;audio;…' : ""}`,
    "Allow: INVITE, ACK, CANCEL, BYE, OPTIONS, INFO, UPDATE, PRACK, REFER, NOTIFY, MESSAGE",
    `${hn("Supported")}: ${sup.join(", ")}`,
    ...(b.require_prack ? ["Require: 100rel"] : []),
    ...(b.session_timer > 0 ? [`Session-Expires: ${b.session_timer};refresher=uac`, "Min-SE: 90"] : []),
    ...(b.extra_headers || []).map(([k, v]) => `${k}: ${v}`),
    `${hn("Content-Type")}: application/sdp`,
  ];
  const ip = b.sdp_ip_override || local.split(":")[0];
  const offered = (b.codecs && b.codecs.length ? b.codecs : (SET.cfg && SET.cfg.settings && SET.cfg.settings.codecs) || CODEC_DEFAULTS).map(codecInfo).filter(Boolean);
  const pts = offered.map((c) => c[4]);
  const dt = b.dtmf_mode === "rfc4733" ? [b.dtmf_payload_type] : [];
  const sdp = [
    "v=0", `o=sidetone 1 1 IN IP4 ${ip}`, "s=Sidetone", `c=IN IP4 ${ip}`, "t=0 0",
    `m=audio ${b.rtp_port_start} RTP/AVP ${[...pts, ...dt].join(" ")}`,
    ...offered.flatMap((c) => [`a=rtpmap:${c[4]} ${b.g726_aal2 ? c[5].replace(/^G726/, "AAL2-G726") : c[5]}`, ...(c[6] ? [`a=fmtp:${c[4]} ${c[6]}`] : [])]),
    ...(dt.length ? [`a=rtpmap:${dt[0]} telephone-event/8000`, `a=fmtp:${dt[0]} 0-16`] : []),
    `a=ptime:${b.ptime_ms}`, `a=${b.sdp_direction}`,
  ];
  return `${lines.join("\r\n")}\r\n\r\n${sdp.join("\r\n")}`;
}

async function renderGlobal(section) {
  const body = $("#set-body");
  const native = S.ctl.kind === "native";
  const st = SET.cfg.settings || {};
  if (section === "calls") {
    const fields = CALL_SETTINGS.filter((f) => native || f[5] !== "native");
    body.innerHTML = `<div class="set-head"><h1>Call handling</h1></div>
      <form class="set-form" id="g-form"><div class="fields">${fields.map((f, i) => fieldHtml(f, get(st, f[0]), `gf-${i}`)).join("")}
        <label class="check fld"><input type="checkbox" id="lp-follow" ${store.get("sidetone.follow_calls", true) ? "checked" : ""}> ${esc(t("Follow calls: when you call or a call rings, open Analysis and update the ladder and log live"))}</label>
        <label class="check fld"><input type="checkbox" id="lp-keys" ${store.get("sidetone.key_tones", true) ? "checked" : ""}> ${esc(t("Play keypad tones"))}</label>
        <label class="check fld"><input type="checkbox" id="lp-rtpend" ${rtpAtEnd() ? "checked" : ""}> ${esc(t("Ladder: put RTP streams after the SIP (off: each stream where it starts, between the answer and the BYE)"))}</label>
      </div>
      <div class="set-actions"><button type="submit" class="btn primary">Save</button></div></form>`;
    $("#g-form").addEventListener("submit", async (e) => {
      e.preventDefault();
      store.set("sidetone.follow_calls", $("#lp-follow").checked);
      store.set("sidetone.key_tones", $("#lp-keys").checked);
      store.set("sidetone.ladder.rtp_end", $("#lp-rtpend").checked);
      fields.forEach((f, i) => readField(f, `gf-${i}`, st));
      await S.ctl.setConfig({ settings: st });
      toast("Saved");
    });
  } else if (section === "audio") {
    if (!native) {
      body.innerHTML = `<div class="set-head"><h1>Audio</h1></div><p class="muted">The browser phone uses the browser's microphone and speaker. Choose devices in the browser's site settings. Echo cancellation and noise suppression are on.</p>`;
      return;
    }
    let dev = { devices: { inputs: [], outputs: [] }, audio: {} };
    try { dev = await S.ctl.audio(); } catch { /* keep empty */ }
    const ap = SET.cfg.audio || {};
    const opt = (list, cur) => [`<option value="">System default</option>`, ...list.map((n) => `<option ${n === cur ? "selected" : ""}>${esc(n)}</option>`)].join("");
    body.innerHTML = `<div class="set-head"><h1>Audio</h1></div>
      <form class="set-form" id="g-form"><div class="fields">
        <label class="check fld"><input type="checkbox" id="au-en" ${ap.enabled !== false ? "checked" : ""}> Use the sound card</label>
        <label class="fld">Microphone<select id="au-in">${opt(dev.devices.inputs || [], ap.input)}</select></label>
        <label class="fld">Speaker or headset<select id="au-out">${opt(dev.devices.outputs || [], ap.output)}</select></label>
        ${fieldHtml(["audio_source", "Send during calls", "select", "test tone and echo help when nobody is at the other end", [["device", "Sound card (microphone)"], ["tone", "Test tone"], ["echo", "Echo what is received"], ["silence", "Silence"]]], st.audio_source, "au-src")}
        ${fieldHtml(["tone_hz", "Test tone frequency (Hz)", "number"], st.tone_hz, "au-hz")}
      </div>
      <p class="hint">${esc(dev.audio && dev.audio.error ? `Sound card: ${dev.audio.error}` : dev.audio && dev.audio.status ? `Open: ${dev.audio.status.input || "no microphone"} / ${dev.audio.status.output || "no speaker"}` : "")}</p>
      <div class="set-actions"><button type="submit" class="btn primary">Save</button></div></form>
      <section class="set-form audio-test">
        <h2>${esc(t("Test the microphone and speaker"))}</h2>
        <p class="muted">${esc(t("Speak and watch the microphone meter. Record plays back what the far end would hear; use headphones for the live check to avoid feedback."))}</p>
        <div class="meters">
          <div class="meter-row"><svg><use href="#i-mic"/></svg><div class="meter"><i id="at-in"></i></div><span class="hint" id="at-in-db"></span></div>
          <div class="meter-row"><svg><use href="#i-spk"/></svg><div class="meter"><i id="at-out"></i></div><span class="hint" id="at-out-db"></span></div>
        </div>
        <div class="row">
          <button type="button" class="btn" id="at-rec">${esc(t("Record 4 s and play back"))}</button>
          <button type="button" class="btn" id="at-tone">${esc(t("Play a test tone"))}</button>
          <label class="check"><input type="checkbox" id="at-loop"> ${esc(t("Hear the microphone live"))}</label>
        </div>
        <p class="hint" id="at-state"></p>
      </section>`;
    $("#g-form").addEventListener("submit", async (e) => {
      e.preventDefault();
      st.audio_source = $("#au-src").value;
      st.tone_hz = Number($("#au-hz").value) || 440;
      const audio = { enabled: $("#au-en").checked, input: $("#au-in").value || null, output: $("#au-out").value || null };
      await S.ctl.setConfig({ settings: st, audio });
      SET.cfg = await S.ctl.getConfig();
      toast("Saved");
      renderGlobal("audio");
    });
    bindAudioTest();
  } else if (section === "capture") {
    if (!native) {
      body.innerHTML = `<div class="set-head"><h1>Capture and recording</h1></div><p class="muted">The browser phone logs every SIP message and rebuilds a pcapng from it for analysis. Media is DTLS-SRTP inside the browser, so quality comes from WebRTC statistics instead of RTP packets.</p>`;
      return;
    }
    const fields = [
      ["capture", "Capture every SIP packet in memory for analysis and pcapng export", "bool"],
      ["capture_rtp", "Include RTP (needed for jitter, loss and MOS)", "bool"],
      ["record_calls", "Record the audio of every call (WAV)", "bool", "you can also press Record during a call"],
      ["hep_collector", "HEP collector (Homer)", "text", "host:port, UDP; every SIP message is also sent there as HEPv3. Empty = off"],
      ["hep_agent_id", "HEP capture agent ID", "number"],
    ];
    body.innerHTML = `<div class="set-head"><h1>Capture and recording</h1></div>
      <form class="set-form" id="g-form"><div class="fields">${fields.map((f, i) => fieldHtml(f, get(st, f[0]), `gf-${i}`)).join("")}</div>
      <p class="hint">${S.st ? `${S.st.capture_packets.toLocaleString()} packets in memory now.` : ""} Accounts, settings and call history are saved in your user configuration folder.</p>
      <div class="set-actions"><button type="button" class="btn" id="cap-clear">Clear capture now</button><button type="submit" class="btn primary">Save</button></div></form>`;
    $("#g-form").addEventListener("submit", async (e) => {
      e.preventDefault();
      fields.forEach((f, i) => readField(f, `gf-${i}`, st));
      await S.ctl.setConfig({ settings: st });
      toast("Saved");
    });
    $("#cap-clear").addEventListener("click", async () => {
      await S.ctl.clearCapture();
      S.trace = [];
      toast("Capture cleared");
    });
  } else if (section === "ai") {
    const a = aiSettings();
    const presetOpts = [`<option value="">${esc(t("Choose a service…"))}</option>`, ...AI_PRESETS.map(([n], i) => `<option value="${i}">${esc(n)}</option>`)].join("");
    body.innerHTML = `<div class="set-head"><h1>AI</h1></div>
      <form class="set-form" id="ai-set">
        <p class="muted">${esc(t("Sidetone has no AI of its own. Use the provider you prefer: your key goes only to that provider, and nothing is sent until you ask."))}</p>
        <div class="fields">
          <label class="fld">${esc(t("Provider"))}<select id="as-provider">
            <option value="anthropic">Anthropic (Claude)</option>
            <option value="openai">${esc(t("OpenAI-compatible (OpenAI, Gemini, OpenRouter, Groq, Mistral, LM Studio...)"))}</option>
            <option value="ollama">${esc(t("Ollama (local, nothing leaves this machine)"))}</option>
          </select></label>
          <label class="fld" id="as-preset-wrap">${esc(t("Service"))}<select id="as-preset">${presetOpts}</select></label>
          <label class="fld">${esc(t("Model"))}<input id="as-model" value="${esc(a.model || "")}" spellcheck="false"></label>
          <label class="fld">${esc(t("Base URL"))} <span class="hint">${esc(t("empty = the provider's default; a full .../chat/completions URL also works"))}</span><input id="as-base" value="${esc(a.base_url || "")}" spellcheck="false"></label>
          <label class="fld" id="as-key-wrap">${esc(t("API key"))}<input id="as-key" type="password" value="${esc(a.key || "")}" autocomplete="off"></label>
          <label class="check fld"><input type="checkbox" id="as-remember" ${a.remember ? "checked" : ""}> ${esc(t("Remember the key on this device"))}</label>
          <label class="fld">${esc(t("Answer in"))}<select id="as-lang">${["English", "Portuguese (Brazil)", "Spanish", "German", "French", "Chinese (Simplified)", "Hindi"].map((l) => `<option value="${l}" ${l === a.language ? "selected" : ""}>${esc(t(l))}</option>`).join("")}</select></label>
          <label class="check fld"><input type="checkbox" id="as-redact" ${a.redact ? "checked" : ""}> ${esc(t("Mask numbers, names, credentials and public IPs before sending"))}</label>
        </div>
        <p class="hint">${esc(S.be.kind === "wasm" ? t("In the browser the request goes straight from this page to the provider; some providers block that (CORS). Anthropic, OpenRouter and a local Ollama with OLLAMA_ORIGINS work.") : t("Requests go from this computer to the provider."))}</p>
        <div class="set-actions"><span class="hint" id="as-status"></span><button type="button" class="btn" id="as-test">${esc(t("Test connection"))}</button><button type="submit" class="btn primary">${esc(t("Save"))}</button></div>
      </form>`;
    const prov = $("#as-provider");
    prov.value = a.provider;
    const sync = () => {
      const p = prov.value;
      $("#as-preset-wrap").hidden = p !== "openai";
      $("#as-key-wrap").hidden = p === "ollama";
      $("#as-model").placeholder = p === "ollama" ? "llama3.1" : p === "openai" ? "gpt-4o-mini" : "claude-sonnet-5-5";
      $("#as-base").placeholder = p === "ollama" ? "http://localhost:11434" : p === "openai" ? "https://api.openai.com" : "https://api.anthropic.com";
    };
    sync();
    prov.addEventListener("change", () => {
      $("#as-model").value = AI_DEFAULT_MODEL[prov.value] || "";
      $("#as-base").value = "";
      sync();
    });
    $("#as-preset").addEventListener("change", (e) => {
      const p = AI_PRESETS[+e.target.value];
      if (!p) return;
      $("#as-base").value = p[1];
      if (p[2]) $("#as-model").value = p[2];
    });
    const read = () => ({
      provider: prov.value,
      model: $("#as-model").value.trim(),
      base_url: $("#as-base").value.trim() || null,
      key: $("#as-key").value.trim() || null,
      remember: $("#as-remember").checked,
      language: $("#as-lang").value,
      redact: $("#as-redact").checked,
    });
    $("#ai-set").addEventListener("submit", (e) => {
      e.preventDefault();
      saveAiSettings(read());
      toast(t("Saved"));
    });
    $("#as-test").addEventListener("click", async () => {
      saveAiSettings(read());
      const st = $("#as-status");
      const bad = aiNotReady();
      if (bad) return (st.textContent = bad);
      st.textContent = t("Testing…");
      try {
        const r = await S.be.ai(aiConfig(), "You are a connectivity check.", "Reply with the single word OK.");
        st.textContent = `${t("Works")}: ${String(r).trim().slice(0, 60)}`;
        st.className = "hint ok";
      } catch (err) {
        st.textContent = err.message || String(err);
        st.className = "hint bad";
      }
    });
  } else if (section === "backup") {
    renderBackup(body);
  } else if (section === "lang") {
    body.innerHTML = `<div class="set-head"><h1>Language</h1></div>
      <div class="set-form"><div class="fields">
        <label class="fld">Language<select id="lang-sel">${LANGS.map(([c, n]) => `<option value="${c}" ${c === currentLang() ? "selected" : ""}>${esc(n)}</option>`).join("")}</select></label>
      </div>
      <p class="hint">SIP messages, traces and analyzer findings stay in English, as they appear on the wire and in RFCs.</p></div>`;
    $("#lang-sel").addEventListener("change", (e) => {
      if (!setLang(e.target.value, langGuard)) e.target.value = currentLang();
    });
  } else if (section === "keys") {
    const rows = [
      ["Enter", "Call the number in the dial field, or answer the selected incoming call"],
      ["Esc", "Hang up, cancel or reject the selected line"],
      ["0 to 9, *, #", "Send DTMF on the selected call (outside text fields)"],
      ["F2", "Transfer"],
      ["F3", "Hold or resume"],
      ["F4", "Mute or unmute"],
      ["Up and down arrows", "Move through the SIP trace"],
    ];
    body.innerHTML = `<div class="set-head"><h1>Keyboard</h1></div>${table(["Key", "Action"], rows.map(([k, v]) => [`<kbd>${esc(k)}</kbd>`, esc(v)]))}`;
  }
}

// ---- Configuration backup: one JSON file with accounts, phone settings and
// the interface preferences, so a setup moves between computers or is shared.

const BACKUP_FORMAT = "sidetone-config";
const UI_SKIP = /^sidetone\.(web\.history|web\.cap\.|web\.config$)/;

async function exportConfig(withSecrets) {
  const cfg = await S.ctl.getConfig();
  const phone = JSON.parse(JSON.stringify(cfg));
  for (const a of phone.accounts || []) {
    if (withSecrets) continue;
    if (a.profile && a.profile.account) a.profile.account.password = null;
    if ("password" in a) a.password = "";
  }
  const ui = {};
  try {
    for (let i = 0; i < localStorage.length; i++) {
      const k = localStorage.key(i);
      if (!k || !k.startsWith("sidetone.") || UI_SKIP.test(k)) continue;
      const raw = localStorage.getItem(k);
      let v;
      try {
        v = JSON.parse(raw);
      } catch {
        v = raw;
      }
      if (k === "sidetone.ai" && v && !withSecrets) v = { ...v, key: "" };
      ui[k] = v;
    }
  } catch { /* storage unavailable */ }
  return {
    format: BACKUP_FORMAT,
    version: 1,
    exported_at: new Date().toISOString(),
    app_version: S.version || "",
    engine: S.ctl.kind,
    secrets: !!withSecrets,
    phone,
    ui,
  };
}

/// Accounts written by the other engine (desktop <-> browser) keep user, domain, password and name.
function convertAccounts(list, from, to) {
  if (from === to || !Array.isArray(list)) return list || [];
  return list.map((a, i) => {
    if (to === "web") {
      const acc = (a.profile && a.profile.account) || {};
      return { id: `w${Date.now().toString(36)}${i}`, label: a.label || "", enabled: a.enabled !== false, register: a.register !== false, user: acc.user || "", authUser: acc.auth_user || "", password: acc.password || "", displayName: acc.display_name || "", domain: acc.domain || "", ws: "", ice: "stun:stun.l.google.com:19302", expires: acc.expires || 300, rememberPassword: !!acc.password };
    }
    return { id: String(i + 1), label: a.label || "", enabled: a.enabled !== false, register: a.register !== false, retry_s: 30, blf: [], profile: { name: "", account: { user: a.user || "", auth_user: a.authUser || null, password: a.password || null, domain: a.domain || "", display_name: a.displayName || null, outbound_proxy: null, expires: a.expires || 300, q_value: null }, behavior: null } };
  });
}

function renderBackup(body) {
  body.innerHTML = `<div class="set-head"><h1>${esc(t("Import and export"))}</h1></div>
    <div class="set-form">
      <section class="card"><h2>${esc(t("Export"))}</h2>
        <p class="muted">${esc(t("Saves accounts, phone settings, codecs and the interface preferences in one JSON file (format sidetone-config, version 1)."))}</p>
        <label class="check"><input type="checkbox" id="bk-secrets"> ${esc(t("Include passwords and AI API keys (keep the file private)"))}</label>
        <div class="row" style="margin-top:10px"><button type="button" class="btn primary" id="bk-export">${esc(t("Export configuration"))}</button></div>
      </section>
      <section class="card" style="margin-top:14px"><h2>${esc(t("Import"))}</h2>
        <p class="muted">${esc(t("Opens a file exported by Sidetone. Accounts from the desktop app and from the browser are converted to this version."))}</p>
        <button type="button" class="btn small" id="bk-file-btn">${esc(t("Choose file"))}</button><input type="file" id="bk-file" accept=".json,application/json" class="sr-only" tabindex="-1" aria-hidden="true">
        <div class="row bk-url"><input id="bk-url" placeholder="https://provisioning.example.com/sidetone/2001.json" spellcheck="false" aria-label="${esc(t("Provisioning URL"))}"><button type="button" class="btn small" id="bk-fetch">${esc(t("Load from URL"))}</button></div>
        <p class="hint">${esc(t("Provisioning: a sidetone-config file served over HTTP(S), e.g. one per user from your provisioning server. The command line takes the same URL: sidetone config import https://..."))}</p>
        <div id="bk-preview"></div>
      </section>
    </div>`;
  $("#bk-export").addEventListener("click", async () => {
    try {
      const data = await exportConfig($("#bk-secrets").checked);
      const name = `sidetone-config-${new Date().toISOString().slice(0, 10)}.json`;
      await download(new TextEncoder().encode(JSON.stringify(data, null, 2)), name, "application/json");
    } catch (e) {
      toast(e.message || String(e), 5000);
    }
  });
  $("#bk-fetch").addEventListener("click", async () => {
    const url = $("#bk-url").value.trim();
    if (!url) return;
    try {
      const data = S.ctl.fetchConfig ? await S.ctl.fetchConfig(url) : await (await fetch(url)).json();
      if (data && data.error && !data.format) throw new Error(data.error);
      showImport(url.split("/").pop() || url, data);
    } catch (err) {
      $("#bk-preview").innerHTML = `<p class="bad">${esc(err.message || String(err))}</p>`;
    }
  });
  $("#bk-file-btn").addEventListener("click", () => $("#bk-file").click());
  $("#bk-file").addEventListener("change", async (e) => {
    const f = e.target.files[0];
    if (!f) return;
    try {
      showImport(f.name, JSON.parse(await f.text()));
    } catch (err) {
      $("#bk-preview").innerHTML = `<p class="bad">${esc(err.message || String(err))}</p>`;
    }
  });
  function showImport(fname, data) {
    try {
      if (data.format !== BACKUP_FORMAT || !data.phone) throw new Error(t("This is not a Sidetone configuration file."));
      if (data.version > 1) throw new Error(t("This file was made by a newer Sidetone; update to import it."));
    } catch (err) {
      $("#bk-preview").innerHTML = `<p class="bad">${esc(err.message || String(err))}</p>`;
      return;
    }
    const f = { name: fname };
    const accs = data.phone.accounts || [];
    $("#bk-preview").innerHTML = `<div class="notice" style="margin-top:10px">
      <b>${esc(f.name)}</b>: ${accs.length} ${esc(t("accounts"))}, ${Object.keys(data.ui || {}).length} ${esc(t("interface preferences"))}, ${esc(t("exported"))} ${esc((data.exported_at || "").replace("T", " ").slice(0, 16))}${data.app_version ? `, Sidetone ${esc(data.app_version)}` : ""}${data.secrets ? "" : `<br><span class="muted">${esc(t("The file has no passwords: enter them again after importing."))}</span>`}
      </div>
      <div class="row" style="margin-top:10px">
        <button type="button" class="btn primary" id="bk-replace">${esc(t("Replace my configuration"))}</button>
        <button type="button" class="btn" id="bk-merge">${esc(t("Add the accounts to mine"))}</button>
      </div>`;
    const apply = async (merge) => {
      const cur = await S.ctl.getConfig();
      let accounts = convertAccounts(accs, data.engine, S.ctl.kind);
      if (merge) {
        const used = new Set((cur.accounts || []).map((a) => a.id));
        accounts = [
          ...(cur.accounts || []),
          ...accounts.map((a, i) => {
            let id = a.id;
            while (used.has(id)) id = `${a.id}-${i + 2}`;
            used.add(id);
            return { ...a, id };
          }),
        ];
      }
      const next = { accounts };
      if (!merge && data.phone.settings && data.engine === S.ctl.kind) next.settings = data.phone.settings;
      if (!merge && data.phone.audio && data.engine === S.ctl.kind) next.audio = data.phone.audio;
      await S.ctl.setConfig(next);
      if (!merge) {
        for (const [k, v] of Object.entries(data.ui || {})) {
          if (k === "sidetone.ai" && v && !v.key) {
            const old = store.get("sidetone.ai", {});
            store.set(k, { ...v, key: old.key || "" });
          } else if (k === "sidetone.lang" && typeof v === "string") {
            try { localStorage.setItem(k, v); } catch { /* storage unavailable */ }
          } else store.set(k, v);
        }
      }
      toast(t("Configuration imported"));
      setTimeout(() => location.reload(), 600);
    };
    $("#bk-replace").addEventListener("click", () => apply(false));
    $("#bk-merge").addEventListener("click", () => apply(true));
  }
}

function bindSettings() {
  const leaveEdits = () => !SET.dirty || confirm(t("Discard the unsaved changes?"));
  $("#acc-list").addEventListener("click", (e) => {
    const b = e.target.closest("[data-acc]");
    if (!b || b.dataset.acc === SET.accId) return;
    if (!leaveEdits()) return;
    SET.accId = b.dataset.acc;
    SET.section = null;
    SET.dirty = false;
    renderSetNav();
    renderSetBody();
    syncUrl(true);
  });
  $$(".set-nav [data-set]").forEach((b) =>
    b.addEventListener("click", () => {
      if (b.dataset.set === SET.section) return;
      if (!leaveEdits()) return;
      SET.section = b.dataset.set;
      SET.dirty = false;
      renderSetNav();
      renderSetBody();
      syncUrl(true);
    })
  );
  $("#acc-add").addEventListener("click", addAccount);
  $("#prov-form").addEventListener("submit", (e) => {
    e.preventDefault();
    runProvisionFetch();
  });
  $("#prov-cancel").addEventListener("click", () => $("#prov-dialog").close());
  $("#prov-discover").addEventListener("click", discoverProvisioning);
  $("#prov-found").addEventListener("click", (e) => {
    const b = e.target.closest("[data-prov-url]");
    if (b) $("#prov-url").value = b.dataset.provUrl;
  });
}

// ============================================================================
// Boot

function bindChrome() {
  $$(".ws-tabs [data-ws]").forEach((b) => b.addEventListener("click", () => showWs(b.dataset.ws)));
  tablistKeys($(".ws-tabs"));
  const applyTheme = (m) => {
    if (m === "system") document.documentElement.removeAttribute("data-theme");
    else document.documentElement.dataset.theme = m;
    $$("[data-theme]", $(".view-menu")).forEach((b) => b.setAttribute("aria-selected", String(b.dataset.theme === m)));
  };
  applyTheme(store.get("sidetone.theme", "system"));
  $$("[data-theme]", $(".view-menu")).forEach((b) =>
    b.addEventListener("click", () => {
      store.set("sidetone.theme", b.dataset.theme);
      applyTheme(b.dataset.theme);
    })
  );
  // Explanations everywhere, or just the evidence for people who know it by heart.
  const applyExplain = (on) => {
    document.body.classList.toggle("no-explain", !on);
    $("#explain-toggle").checked = on;
    if (!on && $('.tabs [data-tab="explain"]').getAttribute("aria-selected") === "true") showTab("findings");
  };
  applyExplain(explainOn());
  $("#explain-toggle").addEventListener("change", (e) => {
    const on = e.target.checked;
    store.set("sidetone.explain", on);
    applyExplain(on);
    if (S.report && S.msg != null) selectMessage(S.msg, false);
  });
  // Troubleshooting (everything) or Phone only (calls, history, settings, help).
  // In the desktop app, phone only also shrinks the window to the phone panel.
  const winCtl = S.be.kind === "http" && (S.be.features || []).includes("window");
  const applyMode = (m) => {
    S.applyMode = applyMode;
    document.body.classList.toggle("phone-mode", m === "phone");
    document.body.classList.toggle("compact", winCtl && m === "phone");
    document.body.classList.remove("compact-open");
    if (winCtl) S.be.setWindow(m === "phone" ? "phone" : "full").catch(() => {});
    $$("[data-mode]").forEach((b) => b.setAttribute("aria-selected", String(b.dataset.mode === m)));
    if (m === "phone" && ["trace", "analysis", "diag"].includes(S.page)) showWs("calls");
  };
  applyMode(store.get("sidetone.mode", "troubleshoot"));
  const openCompact = (page) => {
    showWs(page);
    document.body.classList.add("compact-open");
  };
  $("#c-calls").addEventListener("click", () => openCompact("calls"));
  $("#c-settings").addEventListener("click", () => openCompact("settings"));
  $("#c-back").addEventListener("click", () => document.body.classList.remove("compact-open"));
  $("#c-full").addEventListener("click", () => {
    store.set("sidetone.mode", "troubleshoot");
    applyMode("troubleshoot");
  });
  $$("[data-mode]").forEach((b) =>
    b.addEventListener("click", () => {
      const m = b.dataset.mode;
      if (m === store.get("sidetone.mode", "troubleshoot")) return;
      store.set("sidetone.mode", m);
      applyMode(m);
      toast(t(m === "phone" ? "Phone only: the trace, analysis and diagnostics are hidden." : "Troubleshooting: trace, analysis and diagnostics are back."), 4000);
    })
  );
  $("#st-err").addEventListener("click", () => {
    S.errors = 0;
    renderStatus();
    showWs("calls");
  });
  $("#events-clear").addEventListener("click", () => {
    S.events = [];
    renderEvents();
  });
  let histT = 0;
  $("#hist-filter").addEventListener("input", () => {
    clearTimeout(histT);
    histT = setTimeout(renderHistoryRows, 150);
  });
  for (const id of ["#hist-from", "#hist-to", "#hist-dir", "#hist-res"]) $(id).addEventListener("change", renderHistoryRows);
  $("#hist-reset").addEventListener("click", () => {
    for (const id of ["#hist-filter", "#hist-from", "#hist-to", "#hist-dir", "#hist-res"]) $(id).value = "";
    renderHistoryRows();
  });
  $("#hist-all").addEventListener("change", (e) => {
    for (const h of historyRows()) e.target.checked ? HSEL.add(h.call_id) : HSEL.delete(h.call_id);
    renderHistoryRows();
  });
  $("#hist-del").addEventListener("click", async () => {
    if (!HSEL.size) return;
    const n = HSEL.size;
    if (!confirm(`${t("Delete selected")} (${n})?`)) return;
    await S.ctl.deleteHistory([...HSEL]);
    HSEL.clear();
    toast(`${n} ${t("calls deleted from the history")}`);
    renderHistory();
  });
  $("#hist-csv").addEventListener("click", () => download(new TextEncoder().encode(historyCsv()), `sidetone-history-${new Date().toISOString().slice(0, 10)}.csv`, "text/csv"));
  $("#active-clear").addEventListener("click", () => {
    for (const l of lines()) if (l.state === "ended") S.hiddenEnded.add(l.line + ":" + l.call_id);
    renderActive();
  });
  $("#hist-clear").addEventListener("click", async () => {
    if (!confirm(t("Clear the whole call history? Saved captures of these calls are deleted too."))) return;
    await S.ctl.clearHistory();
    renderHistory();
  });
}

// First time the browser phone is used, explain what it can and cannot do and
// point at the desktop app. Shown once per browser.
function maybeShowWebLimits() {
  if (!S.ctl || S.ctl.kind !== "web") return;
  if (store.get("sidetone.webLimitsSeen")) return;
  const dlg = $("#web-limits");
  if (!dlg || dlg.open) return;
  const can = [
    "Place SIP calls over WebSocket (wss://) with WebRTC audio",
    "Analyze pcap / pcapng captures and read the diagnosis",
    "Decrypt TLS from a key log embedded in a pcapng",
  ];
  const need = [
    "SIP over UDP, TCP or TLS (not only WebSocket)",
    "Mutual TLS: a client certificate and a private CA bundle",
    "Live packet capture off the wire",
    "Reading certificates and captures from disk",
  ];
  $("#wl-title").textContent = t("You're using the browser version");
  $("#wl-intro").textContent = t("The browser version is handy for a quick test, but it can only do part of what Sidetone does. For the full toolkit, use the desktop app.");
  $("#wl-can-h").textContent = t("In the browser");
  $("#wl-need-h").textContent = t("Desktop only");
  $("#wl-can").innerHTML = can.map((s) => `<li>${esc(t(s))}</li>`).join("");
  $("#wl-need").innerHTML = need.map((s) => `<li>${esc(t(s))}</li>`).join("");
  $("#wl-download").textContent = t("Download the desktop app");
  $("#wl-close").textContent = t("Continue in the browser");
  dlg.addEventListener("close", () => store.set("sidetone.webLimitsSeen", true), { once: true });
  dlg.showModal();
}

async function main() {
  initI18n();
  S.be = await pickBackend();
  if (S.be.kind === "http") {
    try { S.version = (await (await S.be.get("api/info")).json()).version; } catch { /* ignore */ }
  }
  $("#where").textContent = S.be.kind === "wasm" ? "in this browser" : "on this computer";
  // ?phone=web uses the browser phone (WebRTC) even when the native engine is available.
  const forceWeb = new URLSearchParams(location.search).get("phone") === "web";
  S.ctl = !forceWeb && S.be.kind === "http" && S.be.features.includes("phone") ? new NativeController(S.be) : new WebController();
  if (S.ctl.kind === "web" && S.be.parseProvision) {
    S.ctl.setProvisionParser((xml, kind) => S.be.parseProvision(xml, kind));
  }
  document.body.classList.toggle("web-mode", S.ctl.kind === "web");
  $("#st-mode").textContent = t(engineModeLabel());
  bindChrome();
  bindPhone();
  bindTrace();
  bindAnalysis();
  bindDiag();
  bindSplitters();
  bindSettings();
  bindDock();
  renderAiUsing();

  S.ctl.on((u) => {
    if (u.error) toast(u.error, 6000);
    if (u.events && u.events.length) onEvents(u.events);
    if (u.trace && u.trace.length) onTrace(u.trace);
    if (u.state) onState(u.state);
  });
  await S.ctl.start();

  const samples = await S.be.samples();
  const open = async (n) => {
    await load(await S.be.sample(n), `${n}.pcapng`);
    showWs("analysis");
  };
  $("#samples-list").innerHTML = samples.map((s) => `<button type="button" role="menuitem" data-sample="${esc(s.name)}">${esc(s.name)}<small>${esc(s.description)}</small></button>`).join("");
  $("#sample-grid").innerHTML = samples.map((s) => `<button type="button" data-sample="${esc(s.name)}"><b>${esc(s.name)}</b><span>${esc(s.description)}</span></button>`).join("");
  $$("[data-sample]").forEach((b) => b.addEventListener("click", () => open(b.dataset.sample)));

  const params = new URLSearchParams(location.search);
  const want = params.get("sample");
  const noAccounts = S.st && !S.st.accounts.length;
  const set = params.get("set");
  if (set) {
    if (set.startsWith("acc:")) SET.accId = set.slice(4);
    else SET.section = set;
  }
  if (params.get("tab")) S.tab = params.get("tab");
  if (want) {
    // A sample link opens once; the URL then describes the page, not the sample.
    await open(want);
    if (S.tab) showTab(S.tab);
  } else showWs(params.get("page") || (noAccounts ? "settings" : store.get("sidetone.page", "calls")), false);
  maybeShowWebLimits();
  window.addEventListener("popstate", () => {
    const q = new URLSearchParams(location.search);
    const set = q.get("set");
    if (set && set.startsWith("acc:")) {
      SET.accId = set.slice(4);
      SET.section = null;
    } else if (set) SET.section = set;
    else if (q.get("page") === "settings") {
      SET.section = null;
      SET.accId = null;
    }
    if (q.get("tab") && S.report) showTab(q.get("tab"));
    showWs(q.get("page") || "calls", false);
  });
  window.addEventListener("beforeunload", (e) => {
    if (SET.dirty) {
      e.preventDefault();
      e.returnValue = "";
    }
  });
}

main().catch((e) => {
  console.error(e);
  document.body.insertAdjacentHTML("beforeend", `<p style="padding:16px;color:#b91c1c">Sidetone could not start: ${esc(e.message || e)}</p>`);
});
