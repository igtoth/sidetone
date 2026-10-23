// Phone controllers with one interface for the UI:
//  - NativeController: the Rust engine behind `sidetone serve` or the desktop app
//    (UDP, several lines, sound card, transfers, DNS/STUN diagnostics).
//  - WebController: SIP over WebSocket + WebRTC inside the browser (GitHub Pages),
//    one line at a time.
// Both publish snapshots shaped like the engine's PhoneState, plus events and trace items.

import { WebPhone, parse } from "./webphone.js";

const store = {
  get(k, d) {
    try { const v = localStorage.getItem(k); return v === null ? d : JSON.parse(v); } catch { return d; }
  },
  set(k, v) {
    try { localStorage.setItem(k, JSON.stringify(v)); } catch { /* storage unavailable */ }
  },
  del(k) {
    try { localStorage.removeItem(k); } catch { /* storage unavailable */ }
  },
};

class Emitter {
  constructor() { this.fns = new Set(); }
  on(fn) { this.fns.add(fn); return () => this.fns.delete(fn); }
  emit(x) { for (const f of this.fns) { try { f(x); } catch (e) { console.error(e); } } }
}

// ---------------------------------------------------------------------------

export class NativeController extends Emitter {
  constructor(http) {
    super();
    this.kind = "native";
    this.http = http; // { get(path), post(path, body, type) }
    this.features = { multiLine: true, attended: true, record: true, dns: true, stun: true, audioDevices: true, overrides: true, intercom: true };
    this.evSeq = 0;
    this.trSeq = 0;
    this.state = null;
    this.failures = 0;
  }

  async start() {
    await this.poll();
    const loop = async () => {
      await this.poll();
      const busy = this.state && this.state.calls.some((c) => c.state !== "ended");
      setTimeout(loop, busy ? 200 : 600);
    };
    setTimeout(loop, 300);
  }

  async poll() {
    // One request at a time, so the same events are never delivered twice.
    if (this.polling) {
      this.again = true;
      return;
    }
    this.polling = true;
    try {
      const r = await this.http.get(`api/phone/state?since=${this.evSeq}&trace_since=${this.trSeq}`);
      const d = await r.json();
      this.failures = 0;
      this.state = d.state;
      const events = (d.events || []).filter((e) => e.seq > this.evSeq);
      const trace = (d.trace || []).filter((t) => t.seq > this.trSeq);
      if (events.length) this.evSeq = events[events.length - 1].seq;
      if (trace.length) this.trSeq = trace[trace.length - 1].seq;
      this.emit({ state: d.state, events, trace });
    } catch (e) {
      // A render error is not a lost engine: say which it was.
      console.error("state update failed", e);
      if (++this.failures === 3) this.emit({ error: `Lost contact with the Sidetone engine: ${e.message || e}` });
    } finally {
      this.polling = false;
      if (this.again) {
        this.again = false;
        setTimeout(() => this.poll(), 0);
      }
    }
  }

  async cmd(o) {
    const r = await this.http.post("api/phone/cmd", JSON.stringify(o), "application/json");
    const j = await r.json();
    setTimeout(() => this.poll(), 60);
    return j;
  }

  async getConfig() { return (await this.http.get("api/phone/config")).json(); }
  async setConfig(c) {
    const r = await (await this.http.post("api/phone/config", JSON.stringify(c), "application/json")).json();
    setTimeout(() => this.poll(), 300);
    return r;
  }
  async history() { return (await this.http.get("api/phone/history")).json(); }
  async clearHistory() { await this.http.post("api/phone/history/clear", "", "application/json"); }
  async historyCapture(callId) {
    try {
      return new Uint8Array(await (await this.http.get(`api/phone/history/capture?call_id=${encodeURIComponent(callId)}`)).arrayBuffer());
    } catch {
      return null;
    }
  }
  async deleteHistory(ids) { await this.http.post("api/phone/history/delete", JSON.stringify({ call_ids: ids }), "application/json"); }
  // SRTP is decrypted for analysis and playback unless the wire form is asked for.
  async fetchConfig(url) { return (await this.http.get(`api/config/fetch?url=${encodeURIComponent(url)}`)).json(); }
  async pickFile(kind) { return (await this.http.post(`api/pick-file?kind=${encodeURIComponent(kind || "")}`, "", "application/json")).json(); }
  async capture(be, { wire = false } = {}) { return new Uint8Array(await (await this.http.get(`api/phone/capture${wire ? "" : "?decrypted=1"}`)).arrayBuffer()); }
  async clearCapture() { return this.cmd({ cmd: "clear_capture" }); }
  async recording(line) { return new Uint8Array(await (await this.http.get(`api/phone/recording?line=${line}`)).arrayBuffer()); }
  async dns(host) { return (await this.http.get(`api/diag/dns?host=${encodeURIComponent(host)}`)).json(); }
  async stun(servers) { return (await this.http.post("api/diag/stun", JSON.stringify({ servers }), "application/json")).json(); }
  async options(account, target) { return (await this.http.post("api/diag/options", JSON.stringify({ account, target }), "application/json")).json(); }
  async audio() { return (await this.http.get("api/audio/devices")).json(); }
  async sniffInterfaces() { return (await this.http.get("api/sniff/interfaces")).json(); }
  async sniffStart(iface, filter) {
    const j = await (await this.http.post("api/sniff/start", JSON.stringify({ iface, filter }), "application/json")).json();
    if (j.error) throw new Error(j.error);
    return j;
  }
  async sniffStop() { return (await this.http.post("api/sniff/stop", "{}", "application/json")).json(); }
  async sniffStatus(since) { return (await this.http.get(`api/sniff/status?since=${since}`)).json(); }
  async sniffPcap() { return new Uint8Array(await (await this.http.get("api/sniff/pcap")).arrayBuffer()); }
  async audioStatus() { return (await this.http.get("api/audio/status")).json(); }
  async loopback(on) { return (await this.http.post("api/audio/loopback", JSON.stringify({ on }), "application/json")).json(); }
  async provisionMac() { return (await (await this.http.get("api/phone/provision/mac")).json()).mac; }
  async provisionDiscover(mac) {
    const j = await (await this.http.post("api/phone/provision/discover", JSON.stringify({ mac }), "application/json")).json();
    if (j.error) throw new Error(j.error);
    return j.result;
  }
  async diagProvision(url, mac, tlsVerify) { return (await this.http.post("api/diag/provision", JSON.stringify({ url, mac, tls_verify: tlsVerify !== false }), "application/json")).json(); }
  async provision(url, tlsVerify, mac) {
    const r = await this.http.post("api/phone/provision", JSON.stringify({ url, tls_verify: tlsVerify !== false, mac: mac || null }), "application/json");
    const j = await r.json();
    if (j.error) throw new Error(j.error);
    if (!j.ok) throw new Error(j.error || "Provisioning failed");
    return j.account;
  }
  async audioTone(hz, ms) {
    const j = await (await this.http.post("api/audio/tone", JSON.stringify({ hz, ms }), "application/json")).json();
    if (j.error) throw new Error(j.error);
    return j;
  }
  async audioRecordTest(seconds) {
    const j = await (await this.http.post("api/audio/record_test", JSON.stringify({ seconds }), "application/json")).json();
    if (j.error) throw new Error(j.error);
    return j;
  }
}

// ---------------------------------------------------------------------------

const WEB_DEFAULT_SETTINGS = { dnd: false, dnd_code: 486, auto_answer: false, auto_answer_delay_ms: 1000, max_lines: 4, auto_hold: true, ring_timeout_s: 120 };

export function webAccountDefaults() {
  return { id: `w${Date.now().toString(36)}`, label: "", enabled: true, register: true, user: "", authUser: "", password: "", displayName: "", domain: "", ws: "", ice: "stun:stun.l.google.com:19302", expires: 300, rememberPassword: false, provisionUrl: "" };
}

const PROVISION_MIN_MS = 10_000;

function webProvisionSnapshot(a, passwords) {
  return JSON.stringify({
    label: a.label || "",
    enabled: !!a.enabled,
    register: !!a.register,
    user: a.user || "",
    authUser: a.authUser || "",
    password: a.password || passwords[a.id] || "",
    displayName: a.displayName || "",
    domain: a.domain || "",
    ws: a.ws || "",
    ice: a.ice || "",
    expires: Number(a.expires) || 300,
    rememberPassword: !!a.rememberPassword,
  });
}

/// Why the far end refused a call feature, in plain words (as the native engine says it).
function refusal(what, method, code) {
  const why = { 405: `the PBX does not support ${method}`, 501: `the PBX does not support ${method}`, 403: "the PBX does not allow it for this account", 488: "the PBX refused the new media description (SDP)", 491: "both sides changed the call at the same moment (glare); try again", 420: "it needs a SIP extension the PBX does not have", 481: "the PBX no longer knows this call" }[code];
  if (code == null) return `${what} failed: the PBX did not answer`;
  return why ? `${what} failed: ${why} (${code})` : `${what} failed: ${code}`;
}

export class WebController extends Emitter {
  constructor() {
    super();
    this.kind = "web";
    this.features = { multiLine: true, attended: true, conference: true, record: false, dns: false, stun: true, audioDevices: false, overrides: false, intercom: false };
    this.cfg = this.loadConfig();
    this.seq = 0;
    this.phone = null;
    this.acc = null; // AccountView of the active account
    this.lines = []; // CallView-like objects
    this.lineSeq = 1;
    this.traceAll = [];
    this.levels = { tx: 0, rx: 0 };
    this.histList = store.get("sidetone.web.history", []);
    this.passwords = {}; // session-only passwords
    this.parseProvision = null;
    this.resyncPending = false;
    this.pendingProvision = null;
    this.lastProvisionAttempt = {};
    this.resyncTimer = null;
    this.provisionInFlight = false;
    this.provisionRerun = null;
  }

  setProvisionParser(fn) {
    this.parseProvision = fn;
  }

  static setParser(fn) {
    WebController._parseProvision = fn;
  }

  loadConfig() {
    const c = store.get("sidetone.web.phone", null) || {};
    // Migrate the single-account form of earlier versions.
    if (!c.accounts) {
      const old = store.get("sidetone.phone", null);
      c.accounts = [];
      if (old && old.ws && old.domain) c.accounts.push({ ...webAccountDefaults(), id: "w1", label: old.user, user: old.user || "", authUser: old.authUser || "", domain: old.domain, ws: old.ws, ice: old.stun || "" });
    }
    c.settings = { ...WEB_DEFAULT_SETTINGS, ...(c.settings || {}) };
    // Versions before multi-line kept max_lines at 1.
    if (!c.settings.multiline_migrated) {
      c.settings.max_lines = Math.max(c.settings.max_lines || 1, 4);
      c.settings.multiline_migrated = true;
    }
    c.active = c.active || (c.accounts[0] && c.accounts[0].id) || null;
    return c;
  }

  saveConfig() {
    const c = JSON.parse(JSON.stringify(this.cfg));
    c.accounts.forEach((a) => { if (!a.rememberPassword) delete a.password; });
    store.set("sidetone.web.phone", c);
  }

  next() { return ++this.seq; }

  event(kind, text, line = null) {
    this.emit({ events: [{ seq: this.next(), ts_ms: Date.now(), kind, line, account: this.acc && this.acc.id, text }] });
  }

  snapshot() {
    const now = Date.now();
    this.lines = this.lines.filter((l) => l.state !== "ended" || now - l.ended_ms < 8000);
    return {
      seq: this.next(),
      accounts: this.cfg.accounts.map((a) => (this.acc && this.acc.id === a.id ? this.acc : this.accView(a, a.enabled ? "off" : "off"))),
      calls: this.lines.map((l) => ({ ...l })),
      settings: this.cfg.settings,
      capture_packets: this.traceAll.length,
      audio_device: true,
    };
  }

  accView(a, state, extra = {}) {
    return { id: a.id, label: a.label || a.user, user: a.user, domain: a.domain, enabled: a.enabled, register: a.register, state, code: null, reason: null, expires_in: null, local: "WebSocket", server: a.ws, public: null, error: null, ...extra };
  }

  publish(extra = {}) { this.emit({ state: this.snapshot(), events: [], trace: [], ...extra }); }

  async start() {
    this.publish();
    setInterval(() => {
      if (this.acc && this.acc.expires_at) this.acc.expires_in = Math.max(0, Math.round((this.acc.expires_at - Date.now()) / 1000));
      if (this.lines.length || this.acc) this.publish();
    }, 500);
    if (this.cfg.active) this.activate(this.cfg.active).catch(() => {});
  }

  async activate(id) {
    const a = this.cfg.accounts.find((x) => x.id === id);
    if (!a) return;
    this.cfg.active = id;
    this.saveConfig();
    if (this.phone) this.phone.close();
    clearTimeout(this.regTimer);
    this.phone = null;
    this.acc = this.accView(a, "registering");
    this.publish();
    if (!a.enabled) { this.acc.state = "off"; return this.publish(); }
    if (!a.ws || !a.domain || !a.user) {
      this.acc = this.accView(a, "error", { error: !a.ws ? "Fill in the WebSocket URL in Settings, Server and registration" : "Fill in the domain and user in Settings" });
      return this.publish();
    }
    const pw = a.password || this.passwords[a.id] || "";
    const ice = (a.ice || "").split(/[,\s]+/).filter(Boolean).map((u) => ({ urls: u.startsWith("stun:") || u.startsWith("turn:") || u.startsWith("turns:") ? u : `stun:${u}` }));
    const phone = new WebPhone({ ws: a.ws, domain: a.domain, user: a.user, authUser: a.authUser || null, password: pw, iceServers: ice }, this.hooks());
    this.phone = phone;
    window.__phone = phone;
    try {
      await phone.connect();
      this.event("account", `WebSocket ${a.ws} open`);
      await this.register(a);
    } catch (e) {
      this.acc = this.accView(a, "unreachable", { error: e.message || String(e) });
      this.event("error", e.message || String(e));
      this.publish();
      this.regTimer = setTimeout(() => this.activate(id), 30000);
    }
  }

  async register(a, expires) {
    if (!this.phone) return;
    if (!a.register) {
      this.acc = this.accView(a, "off");
      return this.publish();
    }
    const st = await this.phone.register(expires ?? a.expires ?? 300);
    if (st >= 200 && st < 300 && expires !== 0) {
      const g = this.phone.granted || a.expires || 300;
      this.acc = this.accView(a, "registered", { code: st, reason: "OK", expires_at: Date.now() + g * 1000, expires_in: g, public: this.phone.publicAddr });
      this.event("reg", `registered for ${g} s`);
      clearTimeout(this.regTimer);
      this.regTimer = setTimeout(() => this.register(a), Math.max(5, Math.min(g * 0.9, g - 5)) * 1000);
    } else if (expires === 0) {
      this.acc = this.accView(a, "off");
    } else {
      const lr = this.phone.lastReg || {};
      this.acc = this.accView(a, st ? "failed" : "unreachable", { code: st, reason: lr.reason || (st ? "" : "no response") });
      this.event("reg", st ? `REGISTER failed: ${st} ${lr.reason || ""}` : "REGISTER got no response");
      this.regTimer = setTimeout(() => this.register(a), 30000);
    }
    this.publish();
  }

  /// The line that belongs to a WebPhone call.
  lineOf(c) {
    return c && this.lines.find((l) => l.call_id === c.callId && l.state !== "ended");
  }

  /// The WebPhone call behind a line number.
  callOf(lineNo) {
    const p = this.phone;
    const l = this.lines.find((x) => x.line === lineNo);
    return p && l ? p.calls.get(l.call_id) || null : null;
  }

  hooks() {
    return {
      trace: (e) => {
        const m = parse(e.text);
        const host = (() => { try { return new URL(this.phone.cfg.ws).host; } catch { return "server"; } })();
        const item = {
          seq: this.next(), ts_ms: Math.round(e.t_ms), dir: e.out ? "out" : "in", transport: "WSS",
          src: e.out ? "browser" : host, dst: e.out ? host : "browser", first_line: m.first,
          method: (m.cseq.split(" ")[1] || ""), status: m.status ?? null, call_id: m.h("call-id") || "", cseq: m.cseq, size: e.text.length, raw: e.text,
        };
        this.traceAll.push(item);
        this.emit({ trace: [item] });
      },
      closed: (code) => {
        if (!this.acc) return;
        this.acc.state = "unreachable";
        this.acc.error = `WebSocket closed (${code})`;
        this.event("error", `WebSocket closed (${code}); reconnecting in 10 s`);
        clearTimeout(this.regTimer);
        const id = this.cfg.active;
        this.regTimer = setTimeout(() => this.activate(id), 10000);
        this.publish();
      },
      progress: (c, r) => {
        const l = this.lineOf(c);
        if (!l) return;
        if (r.remoteHold !== undefined) {
          if (l.remote_held !== r.remoteHold) this.event("call", r.remoteHold ? "put on hold by the far end" : "resumed by the far end", l.line);
          l.remote_held = r.remoteHold;
        } else if (r.status >= 200 && r.status < 300) {
          l.state = "connected";
          l.answered_ms = Date.now();
          l.final_code = r.status;
          this.event("call", "connected", l.line);
        } else if (r.status > 100) {
          l.state = "ringing";
          this.event("call", `${r.status} ${r.reason}`, l.line);
        }
        this.publish();
      },
      ice: (c, s) => {
        const l = this.lineOf(c);
        if (l) this.event("media", `ICE ${s}`, l.line);
      },
      stats: (c, s) => {
        const l = this.lineOf(c);
        if (!l) return;
        Object.assign(l, {
          codec: (s.codec || "").replace(/^audio\//, "") || l.codec,
          rtp_sent: s.sent ?? l.rtp_sent,
          rtp_received: s.recv ?? l.rtp_received,
          remote_media: s.path || l.remote_media,
          rx_level: s.rx_level != null && !l.held ? Math.round(s.rx_level * 32767) : 0,
          tx_level: s.tx_level != null && !l.muted && !l.held ? Math.round(s.tx_level * 32767) : 0,
        });
      },
      onIncoming: (c, from, m) => {
        const uri = (from.match(/<([^>]+)>/) || [, from])[1];
        const name = (from.match(/^\s*"?([^"<]+?)"?\s*</) || [])[1] || null;
        const l = this.newLine("in", uri.replace(/^sips?:/, "").replace(/;.*$/, ""), name, m.h("call-id"));
        l.state = "incoming";
        const st = this.cfg.settings;
        if (st.dnd) {
          this.event("incoming", `call from ${l.remote} rejected (DND)`, l.line);
          this.phone.reject(c, st.dnd_code || 486, st.dnd_code === 603 ? "Decline" : "Busy Here");
          return;
        }
        const busy = this.lines.some((x) => x !== l && x.state !== "ended");
        this.event("incoming", `incoming call from ${name ? name + " " : ""}<${l.remote}>${busy ? " (call waiting)" : ""}${st.auto_answer && !busy ? " (auto answer)" : ""}`, l.line);
        if (st.auto_answer && !busy) setTimeout(() => this.cmd({ cmd: "answer", line: l.line }), st.auto_answer_delay_ms || 0);
        this.publish();
      },
      onResync: () => this.handleProvisionResync(),
      onNotify: (c, frag) => {
        const l = this.lineOf(c);
        if (!l) return;
        l.transfer = /^SIP\/2\.0 2\d\d/.test(frag) ? "transfer completed" : `transfer progress: ${frag}`;
        this.event("transfer", `transfer progress: ${frag}`, l.line);
        if (/^SIP\/2\.0 2\d\d/.test(frag)) this.phone.hangup(c);
      },
      onDtmf: (c, d) => {
        const l = this.lineOf(c);
        if (l) l.dtmf_rx += d;
        this.event("dtmf", `received ${d} via SIP INFO`, l && l.line);
      },
      onCallEnded: (_p, why, c) => {
        const l = this.lineOf(c);
        if (!l) return;
        l.state = "ended";
        l.ended_ms = Date.now();
        l.reason = why;
        l.final_code = c && c.final ? c.final : l.final_code;
        l.ended_by = /remote/.test(why) ? "remote" : "local";
        l.rx_level = 0;
        l.tx_level = 0;
        for (const o of this.lines) if (o.conference === l.line) o.conference = null;
        l.conference = null;
        this.lastSummary = this.phone && this.phone.summary(c);
        this.event("call", `call ended: ${why}`, l.line);
        this.histList.unshift({
          call_id: l.call_id, account: l.account, direction: l.direction, remote: l.remote, remote_name: l.remote_name,
          started_ms: l.started_ms, answered: !!l.answered_ms, duration_s: l.answered_ms ? (l.ended_ms - l.answered_ms) / 1000 : 0,
          final_code: l.final_code, reason: why, ended_by: l.ended_by, codec: l.codec,
        });
        this.histList = this.histList.slice(0, 300);
        store.set("sidetone.web.history", this.histList);
        // Keep this call's SIP (with its SDP codecs) for the history, once the BYE/200 is in.
        const cid = l.call_id;
        setTimeout(() => this.saveCallLog(cid), 3000);
        this.publish();
        this.afterCallsIdleProvision();
      },
    };
  }

  handleProvisionResync() {
    const id = this.cfg.active;
    const a = id && this.cfg.accounts.find((x) => x.id === id);
    if (!a || !a.provisionUrl) {
      this.event("info", "provisioning resync ignored: no provisioning URL");
      return;
    }
    if (this.liveLines().length) {
      if (!this.resyncPending) this.event("info", "provisioning will wait until the call ends");
      this.resyncPending = true;
      return;
    }
    this.resyncPending = true;
    this.scheduleProvisionFetch(a);
  }

  scheduleProvisionFetch(a) {
    if (!a || !a.provisionUrl) return;
    clearTimeout(this.resyncTimer);
    const id = a.id;
    const started = this.lastProvisionAttempt[id] || 0;
    const wait = started && Date.now() - started < PROVISION_MIN_MS ? PROVISION_MIN_MS - (Date.now() - started) : 0;
    this.resyncTimer = setTimeout(() => this.runProvisionFetch(a), wait);
  }

  async runProvisionFetch(a) {
    if (this.provisionInFlight) {
      this.provisionRerun = a.id;
      return;
    }
    const id = a.id;
    const url = a.provisionUrl;
    if (!url) {
      this.resyncPending = false;
      return;
    }
    this.provisionInFlight = true;
    this.lastProvisionAttempt[id] = Date.now();
    try {
      const parsed = await this.provision(url, true);
      const cur = this.cfg.accounts.find((x) => x.id === id);
      if (!cur) return;
      if (this.liveLines().length) {
        this.pendingProvision = { id, parsed };
        return;
      }
      this.applyProvisionIfChanged(cur, parsed);
    } catch (e) {
      this.event("error", e.message || String(e));
    } finally {
      this.provisionInFlight = false;
      this.resyncPending = false;
      const rerun = this.provisionRerun;
      this.provisionRerun = null;
      if (rerun) {
        const again = this.cfg.accounts.find((x) => x.id === rerun);
        if (again && again.provisionUrl) this.scheduleProvisionFetch(again);
      }
    }
  }

  afterCallsIdleProvision() {
    if (this.liveLines().length) return;
    if (this.pendingProvision) {
      const { id, parsed } = this.pendingProvision;
      this.pendingProvision = null;
      const cur = this.cfg.accounts.find((x) => x.id === id);
      if (cur) this.applyProvisionIfChanged(cur, parsed);
      return;
    }
    if (this.resyncPending) {
      const a = this.cfg.accounts.find((x) => x.id === this.cfg.active);
      if (a && a.provisionUrl) this.scheduleProvisionFetch(a);
    }
  }

  mergeWebProvisionFields(target, src) {
    target.label = src.label;
    target.enabled = src.enabled;
    target.register = src.register;
    target.user = src.user;
    target.authUser = src.authUser || "";
    target.password = src.password || "";
    target.displayName = src.displayName;
    target.domain = src.domain;
    target.ws = src.ws;
    target.ice = src.ice || "";
    target.expires = src.expires;
    target.rememberPassword = !!src.rememberPassword;
  }

  applyProvisionIfChanged(cur, parsed) {
    const pw = { ...this.passwords };
    if (parsed.password) pw[cur.id] = parsed.password;
    const probe = { ...cur };
    this.mergeWebProvisionFields(probe, parsed);
    if (webProvisionSnapshot(cur, this.passwords) === webProvisionSnapshot(probe, pw)) return;
    this.mergeWebProvisionFields(cur, parsed);
    if (parsed.password) this.passwords[cur.id] = parsed.password;
    this.saveConfig();
    this.event("provisioned", "provisioning applied");
    if (this.cfg.active === cur.id) this.activate(cur.id).catch(() => {});
    else this.publish();
  }

  async provision(url, tlsVerify) {
    if (location.protocol === "https:" && url.toLowerCase().startsWith("http://")) {
      throw new Error("This page is HTTPS, so it cannot download an http:// provisioning URL. Use the desktop app for a LAN server.");
    }
    const parse = this.parseProvision || WebController._parseProvision;
    if (!parse) {
      throw new Error("Browser provisioning needs this page's WASM build (open the GitHub Pages site, or use the desktop app to provision).");
    }
    let res;
    try {
      res = await fetch(url);
    } catch (e) {
      throw new Error(`Could not download the provisioning URL (${e.message || e}). CORS is a likely cause if the server does not allow this origin.`);
    }
    if (!res.ok) throw new Error(`Provisioning URL returned HTTP ${res.status}`);
    const xml = await res.text();
    let parsed;
    try {
      parsed = await parse(xml, "browser");
    } catch (e) {
      throw new Error(e.message || String(e));
    }
    return parsed;
  }

  newLine(direction, remote, name, callId) {
    const l = {
      line: this.lineSeq++, account: this.acc ? this.acc.id : "", call_id: callId || "", direction, remote, remote_name: name,
      state: "calling", started_ms: Date.now(), answered_ms: null, ended_ms: null, codec: null, local_media: "WebRTC", remote_media: null,
      muted: false, held: false, remote_held: false, recording: false, rtp_sent: 0, rtp_received: 0, tx_level: 0, rx_level: 0,
      final_code: null, reason: null, ended_by: null, dtmf_rx: "", transfer: null, conference: null,
    };
    this.lines.push(l);
    return l;
  }

  liveLines() {
    return this.lines.filter((l) => l.state !== "ended");
  }

  /// Puts every other connected call on hold, except a conference partner.
  async holdOthers(keep) {
    if (!this.cfg.settings.auto_hold) return;
    const k = this.lines.find((x) => x.line === keep);
    for (const o of this.liveLines()) {
      if (o.line === keep || o.held || o.state !== "connected" || (k && k.conference === o.line)) continue;
      await this.cmd({ cmd: "hold", line: o.line, on: true });
    }
  }

  async cmd(o) {
    const p = this.phone;
    const l = o.line != null ? this.lines.find((x) => x.line === o.line) : [...this.lines].reverse().find((x) => x.state !== "ended");
    const c = l ? this.callOf(l.line) : null;
    switch (o.cmd) {
      case "call": {
        if (!p) throw new Error("No connected account. Check Settings.");
        const max = this.cfg.settings.max_lines || 4;
        if (this.liveLines().length >= max) throw new Error(`All ${max} lines are in use; hang up one first.`);
        const t = o.target.split(/[?,]/)[0].trim();
        const nl = this.newLine("out", t, null, "");
        this.event("call", `calling ${t}`, nl.line);
        this.publish();
        await this.holdOthers(nl.line);
        p.maxLines = max;
        p.dial(t, (call) => { nl.call_id = call.callId; }).catch((e) => {
          this.event("error", `call failed: ${e.message || e}`, nl.line);
          if (nl.state !== "ended") {
            nl.state = "ended";
            nl.ended_ms = Date.now();
            nl.reason = e.message || String(e);
          }
          this.publish();
        });
        return { ok: true, line: nl.line };
      }
      case "answer":
        if (p && c && l.state === "incoming") {
          await this.holdOthers(l.line);
          await p.answer(c);
        }
        break;
      case "reject":
        if (p && c) p.reject(c, o.code || 486, o.code === 603 ? "Decline" : o.code === 480 ? "Temporarily Unavailable" : "Busy Here");
        break;
      case "hangup":
        if (p && c) await p.hangup(c);
        break;
      case "hangup_all":
        if (p) await Promise.all([...p.calls.values()].map((x) => p.hangup(x)));
        break;
      case "hold":
        if (p && c) {
          if (!o.on) await this.holdOthers(l.line);
          if (o.on && l.conference) await this.cmd({ cmd: "conference", line: l.line, to_line: l.conference, on: false });
          const st = await p.hold(c, !!o.on);
          const what = o.on ? "Hold" : "Resume";
          if (st >= 200 && st < 300) {
            l.held = !!o.on;
            l.action = `${what} accepted by the PBX (${st})`;
            l.action_ok = true;
            this.event("call", o.on ? "hold confirmed" : "resume confirmed", l.line);
          } else {
            l.action = refusal(what, "re-INVITE", st);
            l.action_ok = false;
            this.event("error", l.action, l.line);
          }
        }
        break;
      case "mute":
        if (p && c) {
          p.mute(c, !!o.on);
          l.muted = !!o.on;
        }
        break;
      case "dtmf":
        if (p && c) {
          p.dtmf(c, o.digits);
          this.event("dtmf", `sent ${o.digits} as RFC 4733 (WebRTC)`, l.line);
        }
        break;
      case "transfer":
        if (p && c) {
          l.transfer = `blind transfer to ${o.target}: REFER sent`;
          const st = await p.refer(c, o.target);
          l.transfer = st >= 200 && st < 300 ? `REFER accepted (${st}), waiting for NOTIFY` : refusal("Transfer", "REFER", st);
          l.action = st >= 200 && st < 300 ? `Transfer accepted by the PBX (${st}), waiting for the result` : l.transfer;
          l.action_ok = st >= 200 && st < 300;
          this.event("transfer", l.transfer, l.line);
        }
        break;
      case "attended_transfer": {
        const l2 = this.lines.find((x) => x.line === o.to_line);
        const c2 = l2 ? this.callOf(l2.line) : null;
        if (p && c && c2) {
          l.transfer = `attended transfer to ${l2.remote}: REFER with Replaces sent`;
          const st = await p.refer(c, l2.remote, c2);
          l.transfer = st >= 200 && st < 300 ? `REFER accepted (${st}), waiting for NOTIFY` : `transfer failed: REFER answered ${st ?? "nothing"}`;
          this.event("transfer", l.transfer, l.line);
        }
        break;
      }
      case "conference": {
        const l2 = this.lines.find((x) => x.line === o.to_line);
        const c2 = l2 ? this.callOf(l2.line) : null;
        if (p && c && c2) {
          if (o.on) {
            l.conference = l2.line;
            l2.conference = l.line;
            for (const x of [l, l2]) if (x.held) await this.cmd({ cmd: "hold", line: x.line, on: false });
          }
          const ok = p.conference(c, c2, !!o.on);
          if (o.on && !ok) {
            l.conference = null;
            l2.conference = null;
            throw new Error("Both calls need audio before they can be joined");
          }
          l.conference = o.on ? l2.line : null;
          l2.conference = o.on ? l.line : null;
          this.event("call", o.on ? `conference: lines ${l.line} and ${l2.line} joined` : "conference split", l.line);
        }
        break;
      }
      case "register": {
        const a = this.cfg.accounts.find((x) => x.id === (o.account || this.cfg.active));
        if (a && a.id !== this.cfg.active) await this.activate(a.id);
        else if (a && this.phone) await this.register(a);
        else if (a) await this.activate(a.id);
        break;
      }
      case "unregister": {
        const a = this.cfg.accounts.find((x) => x.id === this.cfg.active);
        if (a && this.phone) await this.register(a, 0);
        break;
      }
      case "dnd":
        this.cfg.settings.dnd = !!o.on;
        this.saveConfig();
        break;
      case "auto_answer":
        this.cfg.settings.auto_answer = !!o.on;
        this.saveConfig();
        break;
      case "clear_capture":
        this.traceAll = [];
        if (p) p.log = [];
        break;
      default:
        throw new Error(`not available in the browser: ${o.cmd}`);
    }
    this.publish();
    return { ok: true };
  }

  async getConfig() {
    return { accounts: this.cfg.accounts.map((a) => ({ ...a, password: a.password || this.passwords[a.id] || "" })), settings: this.cfg.settings, active: this.cfg.active };
  }

  async setConfig(c) {
    if (c.accounts) {
      for (const a of c.accounts) if (a.password) this.passwords[a.id] = a.password;
      this.cfg.accounts = c.accounts;
    }
    if (c.settings) this.cfg.settings = { ...this.cfg.settings, ...c.settings };
    const keep = this.cfg.accounts.find((a) => a.id === this.cfg.active) ? this.cfg.active : this.cfg.accounts[0] && this.cfg.accounts[0].id;
    this.saveConfig();
    if (c.accounts) await this.activate(keep || null);
    this.publish();
    return { ok: true };
  }

  async history() { return this.histList; }
  async clearHistory() {
    const ids = this.histList.map((h) => h.call_id);
    this.histList = [];
    store.set("sidetone.web.history", []);
    for (const id of ids) store.del(`sidetone.web.cap.${id}`);
  }
  async deleteHistory(ids) {
    this.histList = this.histList.filter((h) => !ids.includes(h.call_id));
    store.set("sidetone.web.history", this.histList);
    for (const id of ids) store.del(`sidetone.web.cap.${id}`);
  }

  /// Saves the SIP of one call (browser storage) and its offered/answered codecs.
  saveCallLog(callId) {
    if (!this.phone || !callId) return;
    const re = new RegExp(`^(Call-ID|i)\\s*:\\s*${callId.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\s*$`, "mi");
    const log = this.phone.captureLog();
    const entries = log.entries.filter((e) => re.test(e.text));
    if (!entries.length) return;
    store.set(`sidetone.web.cap.${callId}`, { ...log, entries });
    const sdpCodecs = (t) => [...t.matchAll(/^a=rtpmap:\d+ ([^/\s]+)/gm)].map((m) => m[1]);
    const withSdp = entries.filter((e) => /\r?\n\r?\nv=0/.test(e.text));
    const offer = withSdp[0];
    const answer = offer && withSdp.find((e) => e !== offer && e.out !== offer.out);
    const h = this.histList.find((x) => x.call_id === callId);
    if (h) {
      h.offer_codecs = offer ? sdpCodecs(offer.text) : [];
      h.answer_codecs = answer ? sdpCodecs(answer.text) : [];
      h.capture = true;
      store.set("sidetone.web.history", this.histList);
    }
    // Keep the saved logs to the calls still in the history.
    const keep = new Set(this.histList.map((x) => `sidetone.web.cap.${x.call_id}`));
    try {
      for (let i = localStorage.length - 1; i >= 0; i--) {
        const k = localStorage.key(i);
        if (k && k.startsWith("sidetone.web.cap.") && !keep.has(k)) localStorage.removeItem(k);
      }
    } catch { /* storage unavailable */ }
  }

  async historyCapture(callId, be) {
    const log = store.get(`sidetone.web.cap.${callId}`, null);
    if (!log) return null;
    return be.captureFromLog(log);
  }

  /// The capture of a browser call is rebuilt from the SIP log (media is DTLS-SRTP).
  async capture(be) {
    if (!this.phone || !this.phone.log.length) throw new Error("Nothing captured yet: no SIP was sent or received");
    return be.captureFromLog(this.phone.captureLog());
  }
  async clearCapture() { return this.cmd({ cmd: "clear_capture" }); }

  async options(_account, target) {
    if (!this.phone) throw new Error("No connected account");
    return (await this.phone.options(target)) || { code: null, summary: "no response" };
  }

  /// STUN through WebRTC ICE gathering: server-reflexive candidates show the public address.
  async stun(servers) {
    const probes = [];
    for (const s of servers) {
      const url = s.startsWith("stun:") ? s : `stun:${s}`;
      const pc = new RTCPeerConnection({ iceServers: [{ urls: url }] });
      pc.createDataChannel("probe");
      const t = performance.now();
      const found = await new Promise(async (resolve) => {
        const timer = setTimeout(() => resolve(null), 4000);
        pc.onicecandidate = (e) => {
          if (e.candidate && / typ srflx /.test(e.candidate.candidate)) {
            clearTimeout(timer);
            const parts = e.candidate.candidate.split(" ");
            resolve(`${parts[4]}:${parts[5]}`);
          }
          if (!e.candidate) { clearTimeout(timer); resolve(null); }
        };
        await pc.setLocalDescription(await pc.createOffer());
      });
      pc.close();
      probes.push({ server: s, mapped: found, rtt_ms: found ? Math.round(performance.now() - t) : null, error: found ? null : "no answer (UDP blocked or wrong server)" });
    }
    const mapped = probes.map((p) => p.mapped).filter(Boolean);
    const ports = new Set(mapped);
    const nat = !mapped.length ? "no STUN server answered; UDP may be blocked" : ports.size > 1 ? "symmetric NAT (endpoint-dependent mapping): the public port changes per destination; WebRTC needs a TURN server here" : `public address ${mapped[0]}${mapped.length > 1 ? " with a stable mapping" : ""}`;
    return { local: "browser", probes, nat, public: mapped[0] || null };
  }
}
