//! Interactive SIP phone engine: several accounts with automatic
//! re-registration, several lines, hold, mute, three DTMF modes, blind and
//! attended transfer, DND and auto answer. One thread runs the signaling;
//! callers talk to it through commands and read snapshots, events and a
//! live SIP trace.

use crate::media::{AudioSource, Codec, Ring, RtpSession, AUDIO_RATE, SPMS};
use crate::profile::{DtmfMode, Profile};
use crate::sipmsg::{self, build_request, build_response};
use crate::tap::Tap;
use crate::transport::{Kind, Sock};
use crate::ua::{digest_authorization, local_ip_for, rand_hex, resolve};
use serde::{Deserialize, Serialize};
use sidetone_core::sdp::{self, Sdp};
use sidetone_core::sip::{self, SipMessage, StartLine, Uri};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Configuration

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AccountCfg {
    pub id: String,
    pub label: String,
    pub enabled: bool,
    /// Send REGISTER (off = call only, e.g. peer-to-peer or IP trunks).
    pub register: bool,
    /// Seconds to wait before retrying a failed registration.
    pub retry_s: u32,
    /// Extensions or URIs watched with SUBSCRIBE Event: dialog (busy lamp field).
    pub blf: Vec<String>,
    /// Subscribe to message-summary (RFC 3842) for the voicemail lamp.
    pub mwi: bool,
    /// Number dialed to reach voicemail (e.g. *97); empty = the mailbox
    /// address the server announces, if any.
    pub voicemail: String,
    pub profile: Profile,
    /// HTTP(S) URL for NOTIFY-driven provisioning resync.
    pub provision_url: Option<String>,
    #[serde(default = "default_provision_tls_verify")]
    pub provision_tls_verify: bool,
    /// MAC the provisioning URL is fetched for (`{mac}`); empty: this computer's.
    #[serde(default)]
    pub provision_mac: Option<String>,
}

fn default_provision_tls_verify() -> bool {
    true
}

impl Default for AccountCfg {
    fn default() -> Self {
        AccountCfg {
            id: "1".into(),
            label: String::new(),
            enabled: true,
            register: true,
            retry_s: 30,
            blf: Vec::new(),
            mwi: true,
            voicemail: String::new(),
            profile: Profile::default(),
            provision_url: None,
            provision_tls_verify: true,
            provision_mac: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResyncGate {
    Ignore,
    Wait,
    Emit,
}

/// `acc` is `usize::MAX` when set_accounts has detached the line.
/// `live_other` is the number of other lines with the same acc whose state is not Ended.
/// `this_active` is whether this line itself is still active (not Ended).
pub fn resync_gate(
    has_provision_url: bool,
    already_pending: bool,
    acc: usize,
    this_active: bool,
    live_other: usize,
) -> ResyncGate {
    if acc == usize::MAX {
        return ResyncGate::Ignore;
    }
    if !has_provision_url {
        let _ = already_pending;
        return ResyncGate::Ignore;
    }
    if this_active || live_other > 0 {
        return ResyncGate::Wait;
    }
    ResyncGate::Emit
}

pub fn is_provision_resync(event: &str) -> bool {
    let lower = event.to_ascii_lowercase();
    let token = lower
        .split([';', ' ', '\t', '\r', '\n'])
        .next()
        .unwrap_or("");
    token == "check-sync" || token == "resync"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PhoneSettings {
    pub dnd: bool,
    /// Response code for calls rejected by DND.
    pub dnd_code: u16,
    pub auto_answer: bool,
    pub auto_answer_delay_ms: u64,
    /// Auto answer calls that ask for it (Call-Info answer-after, Alert-Info intercom).
    pub intercom: bool,
    pub max_lines: u32,
    /// Put the other calls on hold when a call is answered or resumed.
    pub auto_hold: bool,
    /// Response code when all lines are busy.
    pub busy_code: u16,
    /// Seconds before an unanswered outgoing call is cancelled.
    pub ring_timeout_s: u64,
    /// "device", "tone", "echo" or "silence".
    pub audio_source: String,
    pub tone_hz: f32,
    /// Record every packet in memory for pcapng export and analysis.
    pub capture: bool,
    /// Include RTP in the capture (needed for media quality analysis).
    pub capture_rtp: bool,
    /// Keep the audio of every call for WAV download.
    pub record_calls: bool,
    /// Global codec list in preference order, for accounts without their own.
    pub codecs: Vec<String>,
    /// Forward every incoming call here (302 Moved Temporarily); empty = off.
    pub forward_always: String,
    /// Forward when busy (DND or every line in use).
    pub forward_busy: String,
    /// Forward calls not answered within `forward_no_answer_s`.
    pub forward_no_answer: String,
    pub forward_no_answer_s: u64,
    /// Homer/HEP collector ("host:port", UDP) that gets a copy of every SIP
    /// message; empty for none.
    pub hep_collector: String,
    /// Capture agent ID sent in HEP.
    pub hep_agent_id: u32,
}

impl Default for PhoneSettings {
    fn default() -> Self {
        PhoneSettings {
            dnd: false,
            dnd_code: 486,
            auto_answer: false,
            auto_answer_delay_ms: 1000,
            intercom: true,
            max_lines: 4,
            auto_hold: true,
            busy_code: 486,
            ring_timeout_s: 120,
            audio_source: "device".into(),
            tone_hz: 440.0,
            capture: true,
            capture_rtp: true,
            record_calls: false,
            codecs: crate::media::default_codecs(),
            forward_always: String::new(),
            forward_busy: String::new(),
            forward_no_answer: String::new(),
            forward_no_answer_s: 20,
            hep_collector: String::new(),
            hep_agent_id: 2001,
        }
    }
}

/// Microphone and speaker queues at AUDIO_RATE, filled and drained by the audio layer.
#[derive(Clone)]
pub struct AudioIo {
    pub mic: Arc<Ring>,
    pub speaker: Arc<Ring>,
}

// ---------------------------------------------------------------------------
// Snapshots

#[derive(Debug, Clone, Serialize, Default)]
pub struct AccountView {
    pub id: String,
    pub label: String,
    pub user: String,
    pub domain: String,
    pub enabled: bool,
    pub register: bool,
    /// Number dialed for voicemail (account setting).
    pub voicemail: String,
    /// off, registering, registered, failed, unreachable, error, unregistering
    pub state: String,
    pub code: Option<u16>,
    pub reason: Option<String>,
    pub expires_in: Option<u64>,
    pub local: Option<String>,
    pub server: Option<String>,
    /// Address the server saw us from (Via received/rport).
    pub public: Option<String>,
    pub error: Option<String>,
    /// "UDP", "TCP" or "TLS".
    pub transport: String,
    pub blf: Vec<BlfView>,
    /// Own presence published with PUBLISH (available, away, busy, dnd, offline).
    pub presence: Option<String>,
    pub presence_note: Option<String>,
    /// Why the last PUBLISH failed, if it did.
    pub presence_error: Option<String>,
    /// Voicemail from message-summary NOTIFY (RFC 3842).
    pub mwi: Option<MwiView>,
}

#[derive(Debug, Clone, Serialize, Default, PartialEq)]
pub struct MwiView {
    pub waiting: bool,
    pub new: u32,
    pub old: u32,
    /// Message-Account: the mailbox address, when the server gives one.
    pub account: Option<String>,
}

/// Parses an application/simple-message-summary body.
pub fn parse_mwi(body: &str) -> Option<MwiView> {
    let mut v = MwiView::default();
    let mut seen = false;
    for line in body.lines() {
        let Some((k, val)) = line.split_once(':') else {
            continue;
        };
        let (k, val) = (k.trim().to_ascii_lowercase(), val.trim());
        match k.as_str() {
            "messages-waiting" => {
                seen = true;
                v.waiting = val.eq_ignore_ascii_case("yes");
            }
            "message-account" => v.account = Some(val.to_string()),
            "voice-message" => {
                // "2/8 (0/2)": new/old (urgent new/urgent old).
                let counts = val.split_whitespace().next().unwrap_or("");
                if let Some((n, o)) = counts.split_once('/') {
                    v.new = n.trim().parse().unwrap_or(0);
                    v.old = o.trim().parse().unwrap_or(0);
                }
            }
            _ => {}
        }
    }
    seen.then_some(v)
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct BlfView {
    pub target: String,
    /// unknown, idle, ringing, busy, error
    pub state: String,
    pub detail: Option<String>,
    /// Presence from SUBSCRIBE Event: presence (PIDF): available, away, busy,
    /// dnd, offline; None when the server does not offer presence.
    pub presence: Option<String>,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct CallView {
    pub line: u32,
    pub account: String,
    pub call_id: String,
    pub direction: String,
    pub remote: String,
    pub remote_name: Option<String>,
    /// calling, ringing, early, incoming, connected, ending, ended
    pub state: String,
    pub started_ms: u64,
    pub answered_ms: Option<u64>,
    pub ended_ms: Option<u64>,
    pub codec: Option<String>,
    pub local_media: Option<String>,
    pub remote_media: Option<String>,
    pub muted: bool,
    pub held: bool,
    pub remote_held: bool,
    pub recording: bool,
    pub rtp_sent: u64,
    pub rtp_received: u64,
    /// Our view of the received stream (RFC 3550 counters).
    pub rx_loss_pct: Option<f64>,
    pub rx_jitter_ms: Option<f64>,
    /// What the far end reports about our stream in RTCP, and the round trip.
    pub remote_loss_pct: Option<f64>,
    pub remote_jitter_ms: Option<f64>,
    pub rtt_ms: Option<f64>,
    pub rtcp_sent: u32,
    pub rtcp_received: u32,
    pub tx_level: u32,
    pub rx_level: u32,
    pub final_code: Option<u16>,
    pub reason: Option<String>,
    pub ended_by: Option<String>,
    pub dtmf_rx: String,
    pub transfer: Option<String>,
    /// Outcome of the last call feature used (hold, transfer, DTMF by INFO...),
    /// with the reason in plain words when the PBX refused it.
    pub action: Option<String>,
    pub action_ok: Option<bool>,
    /// Media encrypted with SRTP.
    pub srtp: bool,
    /// How the media is protected, e.g. "SDES AES_CM_128_HMAC_SHA1_80" or
    /// "DTLS-SRTP SRTP_AES128_CM_SHA1_80, fingerprint verified".
    pub security: Option<String>,
    /// Line number of the other party when in a three-way conference.
    pub conference: Option<u32>,
    pub srtp_failed: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HistoryEntry {
    pub call_id: String,
    pub account: String,
    pub direction: String,
    pub remote: String,
    pub remote_name: Option<String>,
    pub started_ms: u64,
    pub answered: bool,
    pub duration_s: f64,
    pub final_code: Option<u16>,
    pub reason: Option<String>,
    pub ended_by: Option<String>,
    pub codec: Option<String>,
    /// Codecs in the SDP offer and answer, filled from the call's capture.
    #[serde(default)]
    pub offer_codecs: Vec<String>,
    #[serde(default)]
    pub answer_codecs: Vec<String>,
    /// Worst MOS estimate and worst loss of the call's RTP streams.
    #[serde(default)]
    pub mos: Option<f64>,
    #[serde(default)]
    pub loss_pct: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct PhoneState {
    pub seq: u64,
    pub accounts: Vec<AccountView>,
    pub calls: Vec<CallView>,
    pub settings: PhoneSettings,
    pub capture_packets: usize,
    /// The capture holds SRTP that Sidetone decrypted (a decrypted export exists).
    pub capture_srtp: bool,
    pub audio_device: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct PhoneEvent {
    pub seq: u64,
    pub ts_ms: u64,
    pub kind: String,
    pub line: Option<u32>,
    pub account: Option<String>,
    pub text: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct TraceItem {
    pub seq: u64,
    pub ts_ms: u64,
    /// "out" or "in"
    pub dir: String,
    pub transport: String,
    pub src: String,
    pub dst: String,
    pub first_line: String,
    pub method: String,
    pub status: Option<u16>,
    pub call_id: String,
    pub cseq: String,
    pub size: usize,
    pub raw: String,
}

// ---------------------------------------------------------------------------
// Commands

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct CallRequest {
    pub account: Option<String>,
    /// Number, user@host, SIP URI; "?Hdr=v" adds headers and ",123" sends DTMF after answer.
    pub target: String,
    pub headers: Vec<(String, String)>,
    /// Behavior fields that override the account profile for this call only.
    pub overrides: Option<serde_json::Value>,
}

pub enum Cmd {
    SetAccounts(Vec<AccountCfg>),
    SetSettings(PhoneSettings),
    SetAudio(Option<AudioIo>),
    Register(String),
    Unregister(String),
    Call(u32, CallRequest),
    Answer(u32),
    Reject(u32, u16),
    Hangup(u32),
    HangupAll,
    Hold(u32, bool),
    Mute(u32, bool),
    Record(u32, bool),
    Dtmf(u32, String),
    BlindTransfer(u32, String),
    AttendedTransfer(u32, u32),
    /// Join two lines into a three-way conference (true) or split it (false).
    Conference(u32, u32, bool),
    /// Publish own presence for an account: status and note.
    SetPresence(String, String, String),
    Options(Option<String>, String, Sender<Option<(u16, u64, String)>>),
    /// SIP MESSAGE (RFC 3428): account, target, text.
    Message(Option<String>, String, String),
    /// Redirect a ringing incoming call (302) to a number or URI.
    Forward(u32, String),
    ClearCapture,
    Shutdown,
}

// ---------------------------------------------------------------------------
// Shared state

struct Shared {
    seq: u64,
    events: VecDeque<PhoneEvent>,
    trace: VecDeque<TraceItem>,
    state: PhoneState,
    history: VecDeque<HistoryEntry>,
    recordings: VecDeque<(u32, Vec<u8>)>,
    history_dirty: bool,
    stopped: bool,
}

const MAX_EVENTS: usize = 2000;
const MAX_TRACE: usize = 5000;
const MAX_HISTORY: usize = 500;

impl Shared {
    fn next(&mut self) -> u64 {
        self.seq += 1;
        self.seq
    }
}

/// Handle to the running engine.
pub struct Engine {
    tx: Sender<Cmd>,
    shared: Arc<Mutex<Shared>>,
    next_line: Arc<AtomicU32>,
    tap: Tap,
    join: Option<thread::JoinHandle<()>>,
}

impl Engine {
    pub fn start(
        settings: PhoneSettings,
        accounts: Vec<AccountCfg>,
        audio: Option<AudioIo>,
    ) -> Engine {
        crate::sipmsg::set_global_codecs(settings.codecs.clone());
        let (tx, rx) = channel();
        let shared = Arc::new(Mutex::new(Shared {
            seq: 0,
            events: VecDeque::new(),
            trace: VecDeque::new(),
            state: PhoneState::default(),
            history: VecDeque::new(),
            recordings: VecDeque::new(),
            history_dirty: false,
            stopped: false,
        }));
        let tap = Tap::new();
        tap.set_enabled(settings.capture);
        let _ = tap.set_hep(&settings.hep_collector, settings.hep_agent_id);
        let next_line = Arc::new(AtomicU32::new(1));
        let mut core = Core {
            next_line: next_line.clone(),
            rx,
            shared: shared.clone(),
            tap: tap.clone(),
            settings,
            audio,
            accs: Vec::new(),
            lines: BTreeMap::new(),
            txs: HashMap::new(),
            dirty: true,
            last_publish: Instant::now(),
            stop: false,
            tone_t: 0,
            conf: None,
            subs: Vec::new(),
        };
        core.set_accounts(accounts);
        let join = thread::Builder::new()
            .name("sidetone-engine".into())
            .spawn(move || core.run())
            .expect("spawn engine");
        Engine {
            tx,
            shared,
            next_line,
            tap,
            join: Some(join),
        }
    }

    pub fn cmd(&self, c: Cmd) {
        let _ = self.tx.send(c);
    }

    /// Starts a call and returns its line number.
    pub fn call(&self, req: CallRequest) -> u32 {
        let id = self.next_line.fetch_add(1, Ordering::Relaxed);
        self.cmd(Cmd::Call(id, req));
        id
    }

    /// OPTIONS ping: (status, round trip ms, summary).
    pub fn options(&self, account: Option<String>, target: String) -> Option<(u16, u64, String)> {
        let (tx, rx) = channel();
        self.cmd(Cmd::Options(account, target, tx));
        rx.recv_timeout(Duration::from_secs(40)).ok().flatten()
    }

    pub fn state(&self) -> PhoneState {
        self.shared.lock().unwrap().state.clone()
    }

    pub fn seq(&self) -> u64 {
        self.shared.lock().unwrap().seq
    }

    pub fn events_since(&self, since: u64) -> Vec<PhoneEvent> {
        let s = self.shared.lock().unwrap();
        s.events.iter().filter(|e| e.seq > since).cloned().collect()
    }

    pub fn emit(&self, kind: &str, account: Option<String>, text: impl Into<String>) {
        let mut s = self.shared.lock().unwrap();
        let seq = s.next();
        s.events.push_back(PhoneEvent {
            seq,
            ts_ms: now_ms(),
            kind: kind.into(),
            line: None,
            account,
            text: text.into(),
        });
        while s.events.len() > MAX_EVENTS {
            s.events.pop_front();
        }
    }

    pub fn trace_since(&self, since: u64, limit: usize) -> Vec<TraceItem> {
        let s = self.shared.lock().unwrap();
        let v: Vec<TraceItem> = s.trace.iter().filter(|e| e.seq > since).cloned().collect();
        let skip = v.len().saturating_sub(limit);
        v.into_iter().skip(skip).collect()
    }

    pub fn history(&self) -> Vec<HistoryEntry> {
        self.shared
            .lock()
            .unwrap()
            .history
            .iter()
            .cloned()
            .collect()
    }

    pub fn set_history(&self, h: Vec<HistoryEntry>) {
        let mut s = self.shared.lock().unwrap();
        s.history = h.into_iter().take(MAX_HISTORY).collect();
    }

    /// Fills the offered and answered codecs of a call in the history.
    pub fn set_history_codecs(&self, call_id: &str, offer: Vec<String>, answer: Vec<String>) {
        let mut s = self.shared.lock().unwrap();
        if let Some(h) = s.history.iter_mut().find(|h| h.call_id == call_id) {
            h.offer_codecs = offer;
            h.answer_codecs = answer;
            s.history_dirty = true;
        }
    }

    pub fn set_history_quality(&self, call_id: &str, mos: Option<f64>, loss_pct: Option<f64>) {
        let mut s = self.shared.lock().unwrap();
        if let Some(h) = s.history.iter_mut().find(|h| h.call_id == call_id) {
            h.mos = mos;
            h.loss_pct = loss_pct;
            s.history_dirty = true;
        }
    }

    /// Removes the calls with these Call-IDs from the history.
    pub fn delete_history(&self, call_ids: &[String]) {
        let mut s = self.shared.lock().unwrap();
        s.history.retain(|h| !call_ids.contains(&h.call_id));
        s.history_dirty = true;
    }

    pub fn clear_history(&self) {
        let mut s = self.shared.lock().unwrap();
        s.history.clear();
        s.history_dirty = true;
    }

    /// True once after the history changed (for persisting it).
    pub fn take_history_dirty(&self) -> bool {
        let mut s = self.shared.lock().unwrap();
        std::mem::take(&mut s.history_dirty)
    }

    /// Everything captured so far as pcapng.
    pub fn capture(&self) -> Vec<u8> {
        self.tap.to_pcapng()
    }

    /// The capture with SRTP media replaced by the decrypted RTP.
    pub fn capture_decrypted(&self) -> Vec<u8> {
        self.tap.to_pcapng_decrypted()
    }

    /// Stereo WAV (left sent, right received) of a recorded line.
    pub fn recording(&self, line: u32) -> Option<Vec<u8>> {
        let s = self.shared.lock().unwrap();
        s.recordings
            .iter()
            .find(|(l, _)| *l == line)
            .map(|(_, w)| w.clone())
    }
}

impl Engine {
    /// Hangs up, unregisters and stops the engine, waiting up to `wait`.
    /// For handles that are never dropped (statics, processes ending on a signal).
    pub fn shutdown(&self, wait: Duration) {
        let _ = self.tx.send(Cmd::Shutdown);
        let end = Instant::now() + wait;
        while Instant::now() < end {
            if self.shared.lock().unwrap().stopped {
                return;
            }
            thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        let _ = self.tx.send(Cmd::Shutdown);
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

// ---------------------------------------------------------------------------
// Engine internals

struct Acc {
    cfg: AccountCfg,
    sock: Option<Sock>,
    local: SocketAddr,
    server: Option<SocketAddr>,
    instance: String,
    state: &'static str,
    code: Option<u16>,
    reason: Option<String>,
    error: Option<String>,
    public: Option<String>,
    expires_at: Option<Instant>,
    /// Next REGISTER (refresh or retry) or next socket setup attempt.
    next_reg: Option<Instant>,
    reg_call_id: String,
    reg_tag: String,
    reg_cseq: u32,
    /// Expiry asked in the REGISTER in flight.
    reg_expires: u32,
    nc: u32,
    last_keepalive: Instant,
    /// Direct client: no registrar, socket bound to every interface.
    direct: bool,
    publication: Option<Publication>,
    resync_pending: bool,
    mwi: Option<MwiView>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LState {
    Calling,
    Ringing,
    Early,
    Incoming,
    Connected,
    Ending,
    Ended,
}

impl LState {
    fn name(self) -> &'static str {
        match self {
            LState::Calling => "calling",
            LState::Ringing => "ringing",
            LState::Early => "early",
            LState::Incoming => "incoming",
            LState::Connected => "connected",
            LState::Ending => "ending",
            LState::Ended => "ended",
        }
    }
    fn active(self) -> bool {
        !matches!(self, LState::Ended)
    }
}

struct Line {
    id: u32,
    acc: usize,
    profile: Profile,
    outgoing: bool,
    state: LState,
    call_id: String,
    local_tag: String,
    remote_tag: String,
    local_uri: String,
    remote_uri: String,
    remote_name: Option<String>,
    remote_target: String,
    route_set: Vec<String>,
    dest: SocketAddr,
    cseq: u32,
    remote_cseq: u32,
    // Initial INVITE (outgoing)
    ruri: String,
    from_hdr: String,
    invite_cseq: u32,
    invite_branch: String,
    invite_dest: SocketAddr,
    extra_headers: Vec<(String, String)>,
    cancel_wanted: bool,
    cancel_sent: Option<Instant>,
    ack_text: Option<String>,
    // Incoming
    invite_req: Option<SipMessage>,
    invite_from: Option<SocketAddr>,
    invite_req_branch: Option<String>,
    last_resp: Option<String>,
    offer: Option<Sdp>,
    auto_answer_at: Option<Instant>,
    replaces_line: Option<u32>,
    // Pending 2xx retransmission until ACK
    uas_2xx: Option<(String, SocketAddr)>,
    uas_next: Instant,
    uas_interval: Duration,
    uas_start: Instant,
    // Media
    rtp: Option<RtpSession>,
    codec: Option<Codec>,
    remote_dtmf: Option<u8>,
    remote_media: Option<SocketAddr>,
    sess_id: u64,
    sdp_ver: u64,
    local_hold: bool,
    remote_hold: bool,
    muted: bool,
    recording: bool,
    reinvite_pending: bool,
    focus: u64,
    // Timing and result
    created: Instant,
    started_ms: u64,
    answered_ms: Option<u64>,
    ended_ms: Option<u64>,
    ended_at: Option<Instant>,
    final_code: Option<u16>,
    reason: Option<String>,
    ended_by: Option<String>,
    // DTMF after answer (",123"): (digits, next send time)
    post_dtmf: Option<(String, Instant)>,
    dtmf_rx: String,
    // Transfer
    transfer: Option<String>,
    transfer_kind: Option<&'static str>,
    /// When this call was created by an incoming REFER: line to NOTIFY.
    notify_line: Option<u32>,
    last_refresh: Instant,
    rtp_final: (u64, u64),
    /// SRTP: our key with its crypto tag, and whether the m= line says RTP/SAVP.
    srtp_local: Option<(u32, crate::srtp::KeyMaterial)>,
    srtp_savp: bool,
    /// SRTP is running (both keys known).
    srtp_on: bool,
    /// We offered DTLS-SRTP (UDP/TLS/RTP/SAVP with a=fingerprint).
    dtls_offer: bool,
    /// DTLS-SRTP agreed: true when we are the DTLS client (a=setup:active).
    dtls_client: Option<bool>,
    /// The DTLS outcome was already reported.
    dtls_reported: bool,
    /// Last feature outcome: text and success.
    action: Option<(String, bool)>,
}

#[derive(Debug, Clone)]
enum Purpose {
    Register(usize),
    Invite(u32),
    Cancel,
    Bye(u32),
    ReInvite(u32, bool),
    Info(u32),
    Refer(u32),
    Notify,
    Prack,
    Update,
    Options(u64),
    Message(String),
    Subscribe(String),
    Publish(usize),
}

/// One subscription for a watched extension: busy lamp (RFC 4235 dialog
/// event package) or presence (RFC 3856, PIDF bodies).
struct Sub {
    acc_id: String,
    label: String,
    /// "dialog" or "presence"
    event: &'static str,
    presence: Option<String>,
    note: Option<String>,
    /// The server refused this event package: do not ask again.
    unsupported: bool,
    uri: String,
    call_id: String,
    local_tag: String,
    remote_tag: String,
    remote_target: String,
    route_set: Vec<String>,
    cseq: u32,
    state: &'static str,
    detail: Option<String>,
    next: Option<Instant>,
}

/// Event package of message waiting (RFC 3842).
const MWI_EVENT: &str = "message-summary";

/// Busy-lamp state from a dialog-info+xml body.
fn blf_state(body: &str) -> &'static str {
    let b = body.to_ascii_lowercase();
    let mut states = Vec::new();
    let mut rest = b.as_str();
    while let Some(i) = rest.find("<state") {
        let after = &rest[i..];
        let Some(gt) = after.find('>') else { break };
        let Some(end) = after.find("</state>") else {
            break;
        };
        if end > gt {
            states.push(after[gt + 1..end].trim().to_string());
        }
        rest = &after[gt..];
    }
    if states.iter().any(|s| s == "confirmed") {
        "busy"
    } else if states
        .iter()
        .any(|s| s == "early" || s == "proceeding" || s == "trying")
    {
        "ringing"
    } else {
        "idle"
    }
}

/// Presence and note from a PIDF body (RFC 3863, RPID activities RFC 4480).
fn pidf_state(body: &str) -> (String, Option<String>) {
    let b = body.to_ascii_lowercase();
    let text_of = |tag: &str| -> Option<String> {
        // Matches <note>, <dm:note>, <pp:note> ...
        let mut rest = body;
        loop {
            let i = rest.find('<')?;
            rest = &rest[i + 1..];
            let name_end = rest.find(|c: char| c == '>' || c.is_whitespace())?;
            let name = &rest[..name_end];
            if name.rsplit(':').next() == Some(tag) && !name.starts_with('/') {
                let gt = rest.find('>')?;
                if rest[..gt].ends_with('/') {
                    continue;
                }
                let after = &rest[gt + 1..];
                let end = after.find("</")?;
                let t = after[..end].trim();
                if !t.is_empty() {
                    return Some(
                        t.replace("&lt;", "<")
                            .replace("&gt;", ">")
                            .replace("&quot;", "\"")
                            .replace("&apos;", "'")
                            .replace("&amp;", "&"),
                    );
                }
            }
        }
    };
    let basic = text_of("basic").map(|x| x.to_ascii_lowercase());
    // An RPID activity element such as <rpid:away/>, <rpid:on-the-phone />.
    let has = |a: &str| {
        [format!(":{a}"), format!("<{a}")].iter().any(|pat| {
            b.match_indices(pat.as_str()).any(|(i, _)| {
                let next = b[i + pat.len()..].chars().next().unwrap_or(' ');
                (next == '/' || next == '>' || next.is_whitespace())
                    && (pat.starts_with('<')
                        || b[..i]
                            .rfind('<')
                            .map(|lt| !b[lt..i].contains('>'))
                            .unwrap_or(false))
            })
        })
    };
    let status = if basic.as_deref() == Some("closed") {
        "offline"
    } else if has("busy") || has("on-the-phone") || has("meeting") || has("appointment") {
        "busy"
    } else if has("away") || has("vacation") || has("lunch") || has("steering") || has("sleeping") {
        "away"
    } else if b.contains("do-not-disturb") {
        "dnd"
    } else if basic.as_deref() == Some("open") {
        "available"
    } else {
        "unknown"
    };
    (status.to_string(), text_of("note"))
}

/// PIDF body for our own presence.
fn pidf_body(entity: &str, status: &str, note: &str) -> String {
    let basic = if status == "offline" {
        "closed"
    } else {
        "open"
    };
    let activity = match status {
        "away" => "<rpid:activities><rpid:away/></rpid:activities>",
        "busy" => "<rpid:activities><rpid:busy/></rpid:activities>",
        "dnd" => "<rpid:activities><rpid:busy/></rpid:activities>",
        _ => "",
    };
    let esc = |t: &str| {
        t.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
    };
    let note = if note.trim().is_empty() {
        String::new()
    } else {
        format!("<dm:note>{}</dm:note>", esc(note.trim()))
    };
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n<presence xmlns=\"urn:ietf:params:xml:ns:pidf\" xmlns:dm=\"urn:ietf:params:xml:ns:pidf:data-model\" xmlns:rpid=\"urn:ietf:params:xml:ns:pidf:rpid\" entity=\"{entity}\">\r\n<tuple id=\"sidetone\"><status><basic>{basic}</basic></status></tuple>\r\n<dm:person id=\"p1\">{activity}{note}</dm:person>\r\n</presence>\r\n"
    )
}

/// Our own presence publication (RFC 3903).
struct Publication {
    status: String,
    note: String,
    etag: Option<String>,
    next: Option<Instant>,
    error: Option<String>,
}

struct ClientTx {
    acc: usize,
    method: String,
    text: String,
    dest: SocketAddr,
    invite: bool,
    start: Instant,
    next: Instant,
    interval: Duration,
    provisional: bool,
    purpose: Purpose,
    auth_tries: u32,
    /// Completed INVITE transaction keeps the ACK to re-send on retransmitted finals.
    completed: Option<(Instant, String)>,
}

/// Three-way conference: two lines mixed together with the local user.
/// Line `a` owns the microphone and the speaker; `b` gets copies.
struct Conf {
    a: u32,
    b: u32,
    mic_share: Arc<Ring>,
    a_to_b: Arc<Ring>,
    b_to_a: Arc<Ring>,
    b_to_spk: Arc<Ring>,
}

struct Core {
    /// Line numbers shared with the handle, so incoming and outgoing calls count together.
    next_line: Arc<AtomicU32>,
    rx: Receiver<Cmd>,
    shared: Arc<Mutex<Shared>>,
    tap: Tap,
    settings: PhoneSettings,
    audio: Option<AudioIo>,
    accs: Vec<Acc>,
    lines: BTreeMap<u32, Line>,
    /// Client transactions keyed by (branch, method).
    txs: HashMap<(String, String), ClientTx>,
    dirty: bool,
    last_publish: Instant,
    stop: bool,
    /// Sample clock of the local ring/ringback tones.
    tone_t: u64,
    conf: Option<Conf>,
    subs: Vec<Sub>,
}

/// Pending OPTIONS requests waiting for a reply channel.
type OptionsWaiters = Mutex<HashMap<u64, (Instant, Sender<Option<(u16, u64, String)>>)>>;

static OPTIONS_WAITERS: std::sync::OnceLock<OptionsWaiters> = std::sync::OnceLock::new();

fn options_waiters() -> &'static OptionsWaiters {
    OPTIONS_WAITERS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn new_branch() -> String {
    format!("z9hG4bK{}", rand_hex(16))
}

fn rand_u64() -> u64 {
    u64::from_str_radix(&rand_hex(12), 16).unwrap_or(1) % 1_000_000_000_000
}

fn reason_of(m: &SipMessage) -> String {
    match &m.start {
        StartLine::Response { reason, .. } => reason.clone(),
        _ => String::new(),
    }
}

/// Parses a Reason header "Q.850;cause=16;text=..." into readable text.
fn reason_header(m: &SipMessage) -> Option<String> {
    let r = m.header("Reason")?;
    let cause = sip::param(r, "cause");
    let text = sip::param(r, "text").map(|t| t.trim_matches('"').to_string());
    match (cause, text) {
        (Some(c), Some(t)) => Some(format!("{t} (Q.850 {c})")),
        (Some(c), None) => Some(format!("Q.850 cause {c}")),
        (None, Some(t)) => Some(t),
        _ => Some(r.to_string()),
    }
}

fn hostport_of(uri: &str) -> Option<String> {
    let u = Uri::parse(uri)?;
    if u.host.is_empty() {
        return None;
    }
    let host = if u.host.contains(':') {
        format!("[{}]", u.host)
    } else {
        u.host.clone()
    };
    Some(match u.port {
        Some(p) => format!("{host}:{p}"),
        None => host,
    })
}

fn media_direction(sdp: &Sdp) -> (Option<String>, bool) {
    let m = sdp.media.iter().find(|m| m.kind == "audio");
    match m {
        Some(m) => {
            let zero = m.address(sdp).map(|a| a.is_unspecified()).unwrap_or(false);
            let held = zero || m.direction == "sendonly" || m.direction == "inactive";
            (Some(m.direction.clone()), held)
        }
        None => (None, false),
    }
}

/// Adds SRTP to an SDP body: RTP/SAVP when asked and an a=crypto line.
/// The telephone-event payload type of a media line, preferring the one at
/// the clock rate of the audio codec in use.
fn telephone_event(m: &sdp::Media, clock: u32) -> Option<u8> {
    let ev = |c: &&sidetone_core::sdp::Codec| c.name.eq_ignore_ascii_case("telephone-event");
    m.codecs
        .iter()
        .filter(ev)
        .find(|c| c.rate == clock)
        .or_else(|| m.codecs.iter().find(ev))
        .map(|c| c.pt)
}

fn with_srtp(sdp: String, crypto: &str, savp: bool) -> String {
    let sdp = if savp {
        sdp.replacen(" RTP/AVP ", " RTP/SAVP ", 1)
    } else {
        sdp
    };
    format!("{sdp}a=crypto:{crypto}\r\n")
}

/// Why the far end refused a call feature, in plain words.
fn refusal(what: &str, method: &str, code: u16, reason: &str) -> String {
    let why = match code {
        405 | 501 => format!("the PBX does not support {method}"),
        403 => "the PBX does not allow it for this account".into(),
        488 | 606 => "the PBX refused the new media description (SDP)".into(),
        491 => "both sides changed the call at the same moment (glare); try again".into(),
        420 => "it needs a SIP extension the PBX does not have".into(),
        481 => "the PBX no longer knows this call".into(),
        408 => "the PBX did not answer".into(),
        404 => "the target does not exist".into(),
        486 | 600 => "the target is busy".into(),
        480 => "the target is not available".into(),
        603 => "the target declined".into(),
        500..=599 => "the PBX failed while handling it".into(),
        _ => String::new(),
    };
    if why.is_empty() {
        format!("{what} failed: {code} {reason}")
    } else {
        format!("{what} failed: {why} ({code} {reason})")
    }
}

/// DTLS-SRTP media line: UDP/TLS/RTP/SAVP, our certificate fingerprint and
/// the DTLS role (RFC 5763).
fn with_dtls(sdp: String, setup: &str) -> String {
    let sdp = sdp.replacen(" RTP/AVP ", " UDP/TLS/RTP/SAVP ", 1);
    format!(
        "{sdp}a=fingerprint:{}\r\na=setup:{setup}\r\n",
        crate::dtls::local_fingerprint()
    )
}

/// The offer or answer asks for DTLS-SRTP.
fn wants_dtls(m: &sdp::Media) -> bool {
    m.fingerprint.is_some() && m.proto.to_ascii_uppercase().contains("TLS")
}

/// First a=crypto of an audio stream with a suite Sidetone supports.
fn offered_crypto(m: &sdp::Media) -> Option<(u32, crate::srtp::KeyMaterial)> {
    m.crypto
        .iter()
        .find_map(|c| crate::srtp::KeyMaterial::parse_sdp(c))
}

/// Inserts a header right after the start line.
fn insert_header(text: &str, name: &str, value: &str) -> String {
    match text.find("\r\n") {
        Some(i) => format!("{}\r\n{name}: {value}{}", &text[..i], &text[i..]),
        None => text.to_string(),
    }
}

impl Core {
    fn run(&mut self) {
        let mut buf = vec![0u8; 65535];
        while !self.stop {
            while let Ok(c) = self.rx.try_recv() {
                self.handle_cmd(c);
                if self.stop {
                    break;
                }
            }
            let mut got = false;
            for ai in 0..self.accs.len() {
                for _ in 0..64 {
                    let r = match &self.accs[ai].sock {
                        Some(s) => s.try_recv(&mut buf),
                        None => break,
                    };
                    match r {
                        Some((data, from)) => {
                            got = true;
                            self.on_datagram(ai, &data, from);
                        }
                        None => break,
                    }
                }
            }
            self.timers();
            if self.dirty || self.last_publish.elapsed() > Duration::from_millis(250) {
                self.publish();
            }
            if !got {
                thread::sleep(Duration::from_millis(4));
            }
        }
        // Shutdown: hang up and unregister politely.
        let ids: Vec<u32> = self.lines.keys().copied().collect();
        for id in ids {
            self.hangup(id);
        }
        for ai in 0..self.accs.len() {
            if self.accs[ai].state == "registered" {
                self.send_register(ai, 0, None);
            }
        }
        let end = Instant::now() + Duration::from_millis(600);
        while Instant::now() < end {
            for ai in 0..self.accs.len() {
                let r = self.accs[ai]
                    .sock
                    .as_ref()
                    .and_then(|s| s.try_recv(&mut buf));
                if let Some((data, from)) = r {
                    self.on_datagram(ai, &data, from);
                }
            }
            thread::sleep(Duration::from_millis(10));
        }
        for l in self.lines.values_mut() {
            if let Some(mut r) = l.rtp.take() {
                r.stop();
            }
        }
        self.publish();
        self.shared.lock().unwrap().stopped = true;
    }

    // ----- events, trace, publish

    fn event(
        &mut self,
        kind: &str,
        line: Option<u32>,
        acc: Option<usize>,
        text: impl Into<String>,
    ) {
        let account = acc.and_then(|a| self.accs.get(a)).map(|a| a.cfg.id.clone());
        let mut s = self.shared.lock().unwrap();
        let seq = s.next();
        s.events.push_back(PhoneEvent {
            seq,
            ts_ms: now_ms(),
            kind: kind.into(),
            line,
            account,
            text: text.into(),
        });
        while s.events.len() > MAX_EVENTS {
            s.events.pop_front();
        }
        self.dirty = true;
    }

    #[allow(clippy::too_many_arguments)]
    fn trace(
        &mut self,
        kind: Kind,
        out: bool,
        src: SocketAddr,
        dst: SocketAddr,
        data: &[u8],
        m: Option<&SipMessage>,
    ) {
        let parsed;
        let m = match m {
            Some(m) => Some(m),
            None => {
                parsed = sip::parse_datagram(data);
                parsed.as_ref()
            }
        };
        let raw = String::from_utf8_lossy(data).into_owned();
        let item_first = raw.lines().next().unwrap_or("").to_string();
        let mut s = self.shared.lock().unwrap();
        let seq = s.next();
        s.trace.push_back(TraceItem {
            seq,
            ts_ms: now_ms(),
            dir: if out { "out" } else { "in" }.into(),
            transport: kind.via().into(),
            src: src.to_string(),
            dst: dst.to_string(),
            first_line: item_first,
            method: m.and_then(|m| m.cseq().map(|c| c.1)).unwrap_or_default(),
            status: m.and_then(|m| m.status()),
            call_id: m
                .and_then(|m| m.call_id().map(|c| c.to_string()))
                .unwrap_or_default(),
            cseq: m
                .and_then(|m| m.header("CSeq").map(|c| c.to_string()))
                .unwrap_or_default(),
            size: data.len(),
            raw,
        });
        while s.trace.len() > MAX_TRACE {
            s.trace.pop_front();
        }
    }

    fn publish(&mut self) {
        self.last_publish = Instant::now();
        self.dirty = false;
        let accounts: Vec<AccountView> = self
            .accs
            .iter()
            .map(|a| AccountView {
                id: a.cfg.id.clone(),
                label: a.cfg.label.clone(),
                user: a.cfg.profile.account.user.clone(),
                domain: a.cfg.profile.account.domain.clone(),
                enabled: a.cfg.enabled,
                register: a.cfg.register,
                voicemail: a.cfg.voicemail.clone(),
                state: a.state.into(),
                code: a.code,
                reason: a.reason.clone(),
                expires_in: a
                    .expires_at
                    .map(|t| t.saturating_duration_since(Instant::now()).as_secs()),
                local: a.sock.as_ref().map(|_| a.local.to_string()),
                server: a.server.map(|s| s.to_string()),
                public: a.public.clone(),
                error: a.error.clone(),
                transport: Kind::parse(&a.cfg.profile.behavior.transport)
                    .via()
                    .to_string(),
                blf: self
                    .subs
                    .iter()
                    .filter(|x| x.acc_id == a.cfg.id && x.event == "dialog")
                    .map(|x| {
                        let p = self.subs.iter().find(|y| {
                            y.acc_id == x.acc_id && y.label == x.label && y.event == "presence"
                        });
                        BlfView {
                            target: x.label.clone(),
                            state: x.state.into(),
                            detail: x.detail.clone(),
                            presence: p.and_then(|p| p.presence.clone()),
                            note: p.and_then(|p| p.note.clone()),
                        }
                    })
                    .collect(),
                presence: a.publication.as_ref().map(|p| p.status.clone()),
                presence_note: a
                    .publication
                    .as_ref()
                    .map(|p| p.note.clone())
                    .filter(|n| !n.is_empty()),
                presence_error: a.publication.as_ref().and_then(|p| p.error.clone()),
                mwi: a.mwi.clone(),
            })
            .collect();
        let calls: Vec<CallView> = self
            .lines
            .values()
            .filter(|l| {
                l.state != LState::Ended
                    || l.ended_at
                        .map(|t| t.elapsed() < Duration::from_secs(8))
                        .unwrap_or(false)
            })
            .map(|l| self.call_view(l))
            .collect();
        let mut s = self.shared.lock().unwrap();
        let seq = s.next();
        s.state = PhoneState {
            seq,
            accounts,
            calls,
            settings: self.settings.clone(),
            capture_packets: self.tap.len(),
            capture_srtp: self.tap.has_srtp(),
            audio_device: self.audio.is_some(),
        };
    }

    fn call_view(&self, l: &Line) -> CallView {
        let (sent, recv, tx_level, rx_level, local_media) = match &l.rtp {
            Some(r) => {
                let st = r.stats.lock().unwrap();
                (
                    st.sent_packets,
                    st.received_packets,
                    r.ctl.tx_level.load(Ordering::Relaxed),
                    r.ctl.rx_level.load(Ordering::Relaxed),
                    Some(r.local.to_string()),
                )
            }
            None => (l.rtp_final.0, l.rtp_final.1, 0, 0, None),
        };
        let rtcp = l.rtp.as_ref().map(|r| r.stats.lock().unwrap().rtcp.clone());
        let round = |v: f64| (v * 10.0).round() / 10.0;
        let remote = Uri::parse(&l.remote_uri)
            .map(|u| u.short())
            .unwrap_or_else(|| l.remote_uri.clone());
        CallView {
            line: l.id,
            account: self
                .accs
                .get(l.acc)
                .map(|a| a.cfg.id.clone())
                .unwrap_or_default(),
            call_id: l.call_id.clone(),
            direction: if l.outgoing { "out" } else { "in" }.into(),
            remote,
            remote_name: l.remote_name.clone(),
            state: l.state.name().into(),
            started_ms: l.started_ms,
            answered_ms: l.answered_ms,
            ended_ms: l.ended_ms,
            codec: l.codec.map(|c| c.name().to_string()),
            local_media,
            remote_media: l.remote_media.map(|r| r.to_string()),
            muted: l.muted,
            held: l.local_hold,
            remote_held: l.remote_hold,
            recording: l.recording,
            rtp_sent: sent,
            rtp_received: recv,
            rx_loss_pct: rtcp
                .as_ref()
                .filter(|r| r.received > 0)
                .map(|r| round(r.rx_loss_pct)),
            rx_jitter_ms: rtcp
                .as_ref()
                .filter(|r| r.received > 0)
                .map(|r| round(r.rx_jitter_ms)),
            remote_loss_pct: rtcp.as_ref().and_then(|r| r.remote_loss_pct).map(round),
            remote_jitter_ms: rtcp.as_ref().and_then(|r| r.remote_jitter_ms).map(round),
            rtt_ms: rtcp.as_ref().and_then(|r| r.rtt_ms).map(round),
            rtcp_sent: rtcp.as_ref().map(|r| r.reports_sent).unwrap_or(0),
            rtcp_received: rtcp.as_ref().map(|r| r.reports_received).unwrap_or(0),
            tx_level,
            rx_level,
            final_code: l.final_code,
            reason: l.reason.clone(),
            ended_by: l.ended_by.clone(),
            dtmf_rx: l.dtmf_rx.clone(),
            transfer: l.transfer.clone(),
            action: l.action.as_ref().map(|a| a.0.clone()),
            action_ok: l.action.as_ref().map(|a| a.1),
            srtp: l.srtp_on,
            security: if l.dtls_client.is_some() {
                l.rtp
                    .as_ref()
                    .and_then(|r| r.stats.lock().unwrap().dtls.clone())
                    .or_else(|| Some("DTLS-SRTP".into()))
            } else if l.srtp_on {
                l.srtp_local
                    .as_ref()
                    .map(|(_, k)| format!("SDES {}", k.suite.name()))
            } else {
                None
            },
            conference: self.conf.as_ref().and_then(|c| {
                if c.a == l.id {
                    Some(c.b)
                } else if c.b == l.id {
                    Some(c.a)
                } else {
                    None
                }
            }),
            srtp_failed: l
                .rtp
                .as_ref()
                .map(|r| r.stats.lock().unwrap().srtp_failed)
                .unwrap_or(0),
        }
    }

    // ----- accounts

    fn set_accounts(&mut self, cfgs: Vec<AccountCfg>) {
        // Keep accounts whose config did not change; rebuild the others.
        let prev_ids: Vec<String> = self.accs.iter().map(|a| a.cfg.id.clone()).collect();
        let mut old: Vec<Option<Acc>> = std::mem::take(&mut self.accs)
            .into_iter()
            .map(Some)
            .collect();
        let mut kept_from: HashMap<usize, usize> = HashMap::new();
        let mut new_accs = Vec::new();
        for cfg in cfgs {
            let same = old.iter().position(|a| {
                a.as_ref()
                    .map(|a| serde_json::to_string(&a.cfg).ok() == serde_json::to_string(&cfg).ok())
                    .unwrap_or(false)
            });
            match same {
                Some(i) => {
                    kept_from.insert(i, new_accs.len());
                    new_accs.push(old[i].take().unwrap());
                }
                None => new_accs.push(Self::new_acc(cfg)),
            }
        }
        // Unregister accounts that changed or went away.
        for a in old.iter().flatten() {
            if a.state == "registered" {
                if let (Some(sock), Some(server)) = (&a.sock, a.server) {
                    let text = Self::register_text(
                        a,
                        &a.cfg.profile,
                        0,
                        None,
                        &new_branch(),
                        a.reg_cseq + 1,
                    );
                    let _ = sock.send_to(text.as_bytes(), server);
                    self.tap
                        .record_sip(sock.kind, a.local, server, text.as_bytes());
                }
            }
        }
        // Lines follow their account; lines of changed accounts end now.
        let ids: Vec<u32> = self.lines.keys().copied().collect();
        let mut orphans = Vec::new();
        for id in ids {
            let l = self.lines.get_mut(&id).unwrap();
            match kept_from.get(&l.acc) {
                Some(&ni) => l.acc = ni,
                None => {
                    if l.state.active() {
                        orphans.push((id, prev_ids.get(l.acc).cloned().unwrap_or_default()));
                    }
                    l.acc = usize::MAX;
                }
            }
        }
        self.accs = new_accs;
        for (id, acc) in orphans {
            if let Some(l) = self.lines.get_mut(&id) {
                if let Some(mut r) = l.rtp.take() {
                    r.stop();
                }
            }
            self.end_line(
                id,
                None,
                Some(format!("account {acc} was reconfigured")),
                "local",
            );
        }
        self.lines
            .retain(|_, l| l.acc != usize::MAX || l.state == LState::Ended);
        for ai in 0..self.accs.len() {
            if self.accs[ai].sock.is_none() && self.accs[ai].cfg.enabled {
                self.setup_acc(ai);
            }
        }
        self.dirty = true;
    }

    fn new_acc(cfg: AccountCfg) -> Acc {
        Acc {
            cfg,
            sock: None,
            local: "0.0.0.0:0".parse().unwrap(),
            server: None,
            instance: format!(
                "{}-{}-4{}-a{}-{}",
                rand_hex(8),
                rand_hex(4),
                rand_hex(3),
                rand_hex(3),
                rand_hex(12)
            ),
            state: "off",
            code: None,
            reason: None,
            error: None,
            public: None,
            expires_at: None,
            next_reg: None,
            reg_call_id: String::new(),
            reg_tag: rand_hex(10),
            reg_cseq: 0,
            reg_expires: 0,
            nc: 0,
            last_keepalive: Instant::now(),
            direct: false,
            publication: None,
            resync_pending: false,
            mwi: None,
        }
    }

    /// Resolves the server and binds the account socket.
    fn setup_acc(&mut self, ai: usize) {
        let a = &self.accs[ai];
        if !a.cfg.enabled {
            return;
        }
        let p = a.cfg.profile.clone();
        let server_str = p
            .account
            .outbound_proxy
            .clone()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| p.account.domain.clone());
        // No domain, no proxy and no registration: a direct (anonymous) SIP client
        // that calls SIP URIs straight to their host.
        let direct = server_str.trim().is_empty() && !a.cfg.register;
        let kind = Kind::parse(&p.behavior.transport);
        let direct = direct && kind == Kind::Udp;
        let res = (|| -> Result<(Sock, SocketAddr, Option<SocketAddr>), String> {
            if direct {
                let fixed: Option<std::net::IpAddr> = match &p.behavior.local_ip {
                    Some(s) if !s.is_empty() => {
                        Some(s.parse().map_err(|_| format!("bad local IP {s}"))?)
                    }
                    _ => None,
                };
                let bind_ip =
                    fixed.unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
                let sock = crate::media::bind_udp(
                    SocketAddr::new(bind_ip, p.behavior.local_port),
                    p.behavior.dscp_sip,
                )
                .map_err(|e| format!("cannot bind {bind_ip}:{}: {e}", p.behavior.local_port))?;
                sock.set_nonblocking(true).map_err(|e| e.to_string())?;
                let port = sock.local_addr().map_err(|e| e.to_string())?.port();
                // Advertised address until a call picks the interface towards its target.
                let ip = fixed.unwrap_or_else(|| {
                    local_ip_for("192.0.2.1:5060".parse().unwrap())
                        .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST))
                });
                let sock = Sock::udp(sock).map_err(|e| e.to_string())?;
                return Ok((sock, SocketAddr::new(ip, port), None));
            }
            if server_str.trim().is_empty() {
                return Err("no server or domain configured (leave Register off and the domain empty for direct calls)".into());
            }
            let server =
                crate::dns::resolve_sip_for(&server_str, kind).map_err(|e| e.to_string())?;
            if kind.reliable() {
                let sni = sip::split_host_port(
                    server_str
                        .trim()
                        .trim_start_matches("sips:")
                        .trim_start_matches("sip:")
                        .split(';')
                        .next()
                        .unwrap_or(""),
                )
                .0;
                let tls = crate::transport::TlsOptions {
                    verify: p.behavior.tls_verify,
                    ca_file: p.behavior.tls_ca_file.clone(),
                    client_cert_file: p.behavior.tls_client_cert.clone(),
                    client_key_file: p.behavior.tls_client_key.clone(),
                    client_pass: p.behavior.tls_client_pass.clone(),
                };
                let sock = Sock::connect(kind, server, &sni, &tls)?;
                let local = sock.local;
                return Ok((sock, local, Some(server)));
            }
            let ip = match &p.behavior.local_ip {
                Some(s) if !s.is_empty() => s.parse().map_err(|_| format!("bad local IP {s}"))?,
                _ => local_ip_for(server).map_err(|e| e.to_string())?,
            };
            let sock = crate::media::bind_udp(
                SocketAddr::new(ip, p.behavior.local_port),
                p.behavior.dscp_sip,
            )
            .map_err(|e| format!("cannot bind {ip}:{}: {e}", p.behavior.local_port))?;
            let sock = Sock::udp(sock).map_err(|e| e.to_string())?;
            let local = sock.local;
            Ok((sock, local, Some(server)))
        })();
        let retry = Duration::from_secs(self.accs[ai].cfg.retry_s.max(5) as u64);
        match res {
            Ok((sock, local, server)) => {
                let a = &mut self.accs[ai];
                a.sock = Some(sock);
                a.local = local;
                a.server = server;
                a.direct = direct;
                a.error = None;
                a.reg_call_id = format!("{}@{}", rand_hex(20), local.ip());
                a.state = if a.cfg.register { "registering" } else { "off" };
                a.next_reg = if a.cfg.register {
                    Some(Instant::now())
                } else {
                    None
                };
                let tls = a.sock.as_ref().and_then(|s| s.tls_info.clone());
                let text = match server {
                    Some(server) if kind.reliable() => format!(
                        "connected over {} from {local} to {server}{}",
                        kind.via(),
                        tls.map(|t| format!(" ({t})")).unwrap_or_default()
                    ),
                    Some(server) => format!("ready on {local}, server {server}"),
                    None => format!("ready for direct calls on port {} (no registrar): dial user@host or a SIP URI", local.port()),
                };
                self.event("account", None, Some(ai), text);
            }
            Err(e) => {
                let a = &mut self.accs[ai];
                a.state = "error";
                a.error = Some(e.clone());
                a.next_reg = Some(Instant::now() + retry);
                self.event("error", None, Some(ai), e);
            }
        }
        self.dirty = true;
    }

    fn acc_index(&self, id: Option<&str>) -> Option<usize> {
        match id {
            Some(id) if !id.is_empty() => self.accs.iter().position(|a| a.cfg.id == id),
            _ => self
                .accs
                .iter()
                .position(|a| a.cfg.enabled && a.state == "registered")
                .or_else(|| {
                    self.accs
                        .iter()
                        .position(|a| a.cfg.enabled && a.sock.is_some())
                }),
        }
    }

    fn register_text(
        a: &Acc,
        p: &Profile,
        expires: u32,
        auth: Option<(&str, &str)>,
        branch: &str,
        cseq: u32,
    ) -> String {
        let ruri = format!("sip:{}", sip::split_host_port(&p.account.domain).0);
        let ruri = match sip::split_host_port(&p.account.domain).1 {
            Some(port) => format!("{ruri}:{port}"),
            None => ruri,
        };
        let aor = sipmsg::aor(p);
        let mut extra = vec![
            (
                "Contact".to_string(),
                sipmsg::contact(p, a.local, &a.instance, true),
            ),
            ("Expires".to_string(), expires.to_string()),
            (
                "Allow".to_string(),
                "INVITE, ACK, CANCEL, BYE, OPTIONS, INFO, UPDATE, PRACK, REFER, NOTIFY, MESSAGE"
                    .to_string(),
            ),
        ];
        let mut sup = vec!["path", "replaces"];
        if p.behavior.offer_gruu {
            sup.push("gruu");
        }
        if p.behavior.long_contact {
            sup.push("outbound");
        }
        extra.push((
            sipmsg::hn(&p.behavior, "Supported").to_string(),
            sup.join(", "),
        ));
        if let Some((h, v)) = auth {
            extra.push((h.to_string(), v.to_string()));
        }
        build_request(
            &p.behavior,
            a.local,
            "REGISTER",
            &ruri,
            branch,
            &sipmsg::from_header(p, &a.reg_tag),
            &format!("<{aor}>"),
            &a.reg_call_id,
            cseq,
            "REGISTER",
            &[],
            &extra,
            None,
        )
    }

    fn send_register(&mut self, ai: usize, expires: u32, auth: Option<(&str, &str)>) {
        let Some(server) = self.accs[ai].server else {
            return;
        };
        self.accs[ai].reg_cseq += 1;
        self.accs[ai].reg_expires = expires;
        let branch = new_branch();
        let a = &self.accs[ai];
        let text = Self::register_text(a, &a.cfg.profile, expires, auth, &branch, a.reg_cseq);
        self.accs[ai].state = if expires == 0 {
            "unregistering"
        } else {
            "registering"
        };
        self.accs[ai].next_reg = None;
        self.start_tx(ai, "REGISTER", &branch, text, server, Purpose::Register(ai));
        self.dirty = true;
    }

    // ----- transport

    fn send_raw(&mut self, ai: usize, text: &str, dest: SocketAddr) {
        let Some(a) = self.accs.get(ai) else { return };
        let Some(sock) = &a.sock else { return };
        let local = a.local;
        let kind = sock.kind;
        match sock.send_to(text.as_bytes(), dest) {
            Ok(dest) => {
                self.tap.record_sip(kind, local, dest, text.as_bytes());
                self.trace(kind, true, local, dest, text.as_bytes(), None);
            }
            Err(e) => {
                let msg = format!("send to {dest} failed: {e}");
                self.event("error", None, Some(ai), msg);
            }
        }
    }

    fn start_tx(
        &mut self,
        ai: usize,
        method: &str,
        branch: &str,
        text: String,
        dest: SocketAddr,
        purpose: Purpose,
    ) {
        let t1 = Duration::from_millis(self.accs[ai].cfg.profile.behavior.t1_ms.max(50));
        self.send_raw(ai, &text, dest);
        let now = Instant::now();
        self.txs.insert(
            (branch.to_string(), method.to_string()),
            ClientTx {
                acc: ai,
                method: method.into(),
                text,
                dest,
                invite: method == "INVITE",
                start: now,
                next: now + t1,
                interval: t1,
                provisional: false,
                purpose,
                auth_tries: 0,
                completed: None,
            },
        );
    }

    fn respond(
        &mut self,
        ai: usize,
        req: &SipMessage,
        from: SocketAddr,
        code: u16,
        reason: &str,
        to_tag: Option<&str>,
        extra: &[(String, String)],
        body: Option<(&str, &str)>,
    ) -> String {
        let a = &self.accs[ai];
        let text = build_response(
            &a.cfg.profile,
            a.local,
            &a.instance,
            req,
            from,
            code,
            reason,
            to_tag,
            extra,
            body,
        );
        self.send_raw(ai, &text, from);
        text
    }

    fn on_datagram(&mut self, ai: usize, data: &[u8], from: SocketAddr) {
        let local = self.accs[ai].local;
        // Keepalive (CRLF) and STUN on the SIP port are ignored.
        if data.iter().all(|b| *b == b'\r' || *b == b'\n') {
            return;
        }
        let kind = self.accs[ai]
            .sock
            .as_ref()
            .map(|s| s.kind)
            .unwrap_or(Kind::Udp);
        self.tap.record_sip(kind, from, local, data);
        let Some(m) = sip::parse_datagram(data) else {
            return;
        };
        self.trace(kind, false, from, local, data, Some(&m));
        let a = &self.accs[ai];
        if a.cfg.profile.behavior.filter_registrar && m.is_request() {
            if let Some(server) = a.server {
                if from.ip() != server.ip() {
                    self.event(
                        "info",
                        None,
                        Some(ai),
                        format!("ignored {} from {from} (not the registrar)", m.summary()),
                    );
                    return;
                }
            }
        }
        if m.is_request() {
            self.on_request(ai, m, from);
        } else {
            self.on_response(ai, m, from);
        }
    }

    // ----- timers

    fn timers(&mut self) {
        let now = Instant::now();
        // Client transaction retransmissions and timeouts.
        let keys: Vec<(String, String)> = self.txs.keys().cloned().collect();
        let mut timeouts = Vec::new();
        let mut resend = Vec::new();
        for k in keys {
            let tx = self.txs.get_mut(&k).unwrap();
            let t1 = tx.interval.min(Duration::from_secs(4));
            let _ = t1;
            if let Some((at, _)) = &tx.completed {
                if now.duration_since(*at) > Duration::from_secs(32) {
                    self.txs.remove(&k);
                }
                continue;
            }
            let b = &self.accs[tx.acc].cfg.profile.behavior;
            let timer_b = Duration::from_millis(b.t1_ms.max(50) * 64);
            if tx.invite && tx.provisional {
                continue; // the line's ring timeout takes over
            }
            if now.duration_since(tx.start) >= timer_b {
                timeouts.push(k.clone());
                continue;
            }
            let reliable = self.accs[tx.acc]
                .sock
                .as_ref()
                .map(|s| s.kind.reliable())
                .unwrap_or(false);
            if now >= tx.next && !reliable {
                resend.push((tx.acc, tx.text.clone(), tx.dest));
                tx.interval = if tx.invite {
                    tx.interval * 2
                } else {
                    (tx.interval * 2).min(Duration::from_secs(4))
                };
                if !tx.invite && tx.provisional {
                    tx.interval = Duration::from_secs(4);
                }
                tx.next = now + tx.interval;
            }
        }
        for (ai, text, dest) in resend {
            self.send_raw(ai, &text, dest);
        }
        for k in timeouts {
            if let Some(tx) = self.txs.remove(&k) {
                self.on_timeout(tx);
            }
        }

        // Registration refresh, retries and keepalives.
        for ai in 0..self.accs.len() {
            if self.accs[ai]
                .sock
                .as_ref()
                .map(|s| !s.alive())
                .unwrap_or(false)
            {
                let a = &mut self.accs[ai];
                a.sock = None;
                a.state = "unreachable";
                a.expires_at = None;
                a.error = Some("the connection to the server closed".into());
                a.next_reg = Some(Instant::now() + Duration::from_secs(5));
                self.event(
                    "error",
                    None,
                    Some(ai),
                    "connection to the server closed; reconnecting in 5 s",
                );
                continue;
            }
            let a = &self.accs[ai];
            if !a.cfg.enabled {
                continue;
            }
            if let Some(t) = a.next_reg {
                if now >= t {
                    if a.sock.is_none() {
                        self.setup_acc(ai);
                    } else if a.cfg.register {
                        let exp = a.cfg.profile.account.expires.max(30);
                        self.send_register(ai, exp, None);
                    } else {
                        self.accs[ai].next_reg = None;
                    }
                }
            }
            let a = &self.accs[ai];
            let reliable = a.sock.as_ref().map(|s| s.kind.reliable()).unwrap_or(false);
            // Streams get a CRLF keepalive every 30 s even when not configured.
            let ka = match (a.cfg.profile.behavior.keepalive_interval, reliable) {
                (0, true) => 30,
                (k, _) => k,
            };
            if ka > 0
                && a.state == "registered"
                && a.last_keepalive.elapsed() >= Duration::from_secs(ka as u64)
            {
                if let (Some(sock), Some(server)) = (&a.sock, a.server) {
                    let _ = sock.send_to(b"\r\n\r\n", server);
                    if sock.kind != Kind::Tls {
                        self.tap.record_sip(sock.kind, a.local, server, b"\r\n\r\n");
                    }
                }
                self.accs[ai].last_keepalive = Instant::now();
            }
            if let Some(exp) = self.accs[ai].expires_at {
                if now >= exp && self.accs[ai].state == "registered" {
                    self.accs[ai].state = "registering";
                    self.accs[ai].expires_at = None;
                    self.event("reg", None, Some(ai), "registration expired");
                }
            }
        }

        // Lines.
        let acc_reliable: Vec<bool> = self
            .accs
            .iter()
            .map(|a| a.sock.as_ref().map(|s| s.kind.reliable()).unwrap_or(false))
            .collect();
        let acc_reliable = if acc_reliable.is_empty() {
            vec![false]
        } else {
            acc_reliable
        };
        let ids: Vec<u32> = self.lines.keys().copied().collect();
        for id in ids {
            let Some(l) = self.lines.get(&id) else {
                continue;
            };
            let ring_to = Duration::from_secs(self.settings.ring_timeout_s.max(5));
            match l.state {
                LState::Calling | LState::Ringing | LState::Early if l.outgoing => {
                    if l.cancel_sent.is_none() && l.created.elapsed() > ring_to {
                        self.event("call", Some(id), Some(l.acc), "no answer, cancelling");
                        self.cancel(id);
                    } else if let Some(t) = l.cancel_sent {
                        if t.elapsed() > Duration::from_secs(32) {
                            self.end_line(
                                id,
                                None,
                                Some("no final response to CANCEL".into()),
                                "local",
                            );
                        }
                    }
                }
                LState::Incoming => {
                    let fwd = self.settings.forward_no_answer.trim().to_string();
                    if !fwd.is_empty()
                        && l.auto_answer_at.is_none()
                        && l.created.elapsed()
                            > Duration::from_secs(self.settings.forward_no_answer_s.max(1))
                    {
                        self.forward(id, &fwd, "no answer");
                        continue;
                    }
                    if let Some(t) = l.auto_answer_at {
                        if now >= t {
                            self.answer(id);
                        }
                    } else if l.created.elapsed() > Duration::from_secs(300) {
                        self.reject(id, 480);
                    }
                }
                LState::Connected => {
                    if let Some((digits, at)) = l.post_dtmf.clone() {
                        if now >= at {
                            // ',' pauses one second between groups.
                            let mut rest = digits.as_str();
                            let mut group = String::new();
                            while let Some(c) = rest.chars().next() {
                                if c == ',' {
                                    if !group.is_empty() {
                                        break;
                                    }
                                    rest = &rest[1..];
                                    continue;
                                }
                                group.push(c);
                                rest = &rest[c.len_utf8()..];
                            }
                            let rest = rest.to_string();
                            if let Some(l) = self.lines.get_mut(&id) {
                                l.post_dtmf = if rest.is_empty() {
                                    None
                                } else {
                                    Some((rest, now + Duration::from_secs(1)))
                                };
                            }
                            if !group.is_empty() {
                                self.dtmf(id, &group);
                            }
                        }
                    }
                    let l = &self.lines[&id];
                    let se = l.profile.behavior.session_timer;
                    if se > 0
                        && l.outgoing
                        && l.last_refresh.elapsed() > Duration::from_secs((se / 2).max(30) as u64)
                    {
                        self.session_refresh(id);
                    }
                }
                LState::Ended => {
                    if l.ended_at
                        .map(|t| t.elapsed() > Duration::from_secs(40))
                        .unwrap_or(true)
                    {
                        self.lines.remove(&id);
                        self.dirty = true;
                    }
                    continue;
                }
                _ => {}
            }
            // 2xx retransmission until ACK (Timer G/H).
            let Some(l) = self.lines.get_mut(&id) else {
                continue;
            };
            if let Some((text, dest)) = l.uas_2xx.clone() {
                let t1 = l.profile.behavior.t1_ms.max(50);
                if l.uas_start.elapsed() > Duration::from_millis(t1 * 64) {
                    l.uas_2xx = None;
                    let acc = l.acc;
                    self.event(
                        "error",
                        Some(id),
                        Some(acc),
                        "ACK never arrived (Timer H); hanging up",
                    );
                    self.send_bye(id, Some("no ACK".into()));
                } else if now >= l.uas_next
                    && !acc_reliable[l.acc.min(acc_reliable.len().saturating_sub(1))]
                {
                    l.uas_interval = (l.uas_interval * 2).min(Duration::from_secs(4));
                    l.uas_next = now + l.uas_interval;
                    let acc = l.acc;
                    self.send_raw(acc, &text, dest);
                }
            }
        }

        let due: Vec<usize> = (0..self.subs.len())
            .filter(|&i| self.subs[i].next.map(|t| now >= t).unwrap_or(false))
            .collect();
        for i in due {
            self.send_subscribe(i);
        }
        let pubs: Vec<usize> = (0..self.accs.len())
            .filter(|&i| {
                self.accs[i]
                    .publication
                    .as_ref()
                    .and_then(|p| p.next)
                    .map(|t| now >= t)
                    .unwrap_or(false)
            })
            .collect();
        for ai in pubs {
            self.send_publish(ai);
        }

        self.local_tones();
        self.dtls_outcomes();

        // OPTIONS waiters that timed out are answered by on_timeout; clean stale ones.
        let mut w = options_waiters().lock().unwrap();
        w.retain(|_, (t, _)| t.elapsed() < Duration::from_secs(60));
    }

    /// Ring for incoming calls and ringback while the far end rings, on the speaker.
    fn local_tones(&mut self) {
        let Some(io) = &self.audio else { return };
        let talking = self.lines.values().any(|l| {
            (l.state == LState::Connected && !l.local_hold)
                || (l.state == LState::Early && l.remote_media.is_some())
        });
        if talking {
            self.tone_t = 0;
            return;
        }
        let ringing_in = self.lines.values().any(|l| l.state == LState::Incoming);
        let ringback = self
            .lines
            .values()
            .any(|l| l.outgoing && l.state == LState::Ringing);
        if !ringing_in && !ringback {
            self.tone_t = 0;
            return;
        }
        let w = 2.0 * std::f32::consts::PI / AUDIO_RATE as f32;
        while io.speaker.len() < SPMS * 200 {
            let mut buf = [0i16; SPMS * 20];
            for b in buf.iter_mut() {
                let t = self.tone_t;
                self.tone_t += 1;
                let ts = t as f32;
                *b = if ringing_in {
                    // Two short bursts every 3 s, warbling between 1300 and 1600 Hz.
                    let ph = t % (SPMS as u64 * 3000);
                    let ms = SPMS as u64;
                    let on = ph < ms * 400 || (ms * 600..ms * 1000).contains(&ph);
                    if on {
                        let f = if (t / (SPMS as u64 * 50)) % 2 == 0 {
                            1300.0
                        } else {
                            1600.0
                        };
                        ((w * f * ts).sin() * 7000.0) as i16
                    } else {
                        0
                    }
                } else {
                    // Ringback: 440 + 480 Hz, 2 s on, 4 s off.
                    if t % (SPMS as u64 * 6000) < SPMS as u64 * 2000 {
                        (((w * 440.0 * ts).sin() + (w * 480.0 * ts).sin()) * 3500.0) as i16
                    } else {
                        0
                    }
                };
            }
            io.speaker.push(&buf);
        }
    }

    fn on_timeout(&mut self, tx: ClientTx) {
        match tx.purpose {
            Purpose::Register(ai) => {
                let retry = Duration::from_secs(self.accs[ai].cfg.retry_s.max(5) as u64);
                let a = &mut self.accs[ai];
                let unreg = a.reg_expires == 0;
                a.state = if unreg { "off" } else { "unreachable" };
                a.code = None;
                a.reason = Some("no response".into());
                a.expires_at = None;
                a.next_reg = if unreg {
                    None
                } else {
                    Some(Instant::now() + retry)
                };
                let server = a.server;
                self.event(
                    "reg",
                    None,
                    Some(ai),
                    format!(
                        "REGISTER to {} got no response; check the server address, port, firewall and the network interface",
                        server.map(|s| s.to_string()).unwrap_or_default()
                    ),
                );
            }
            Purpose::Invite(id) => {
                self.end_line(
                    id,
                    Some(408),
                    Some("no response to INVITE (Timer B)".into()),
                    "timeout",
                );
            }
            Purpose::Bye(id) => {
                self.end_line(id, None, Some("no response to BYE".into()), "local");
            }
            Purpose::ReInvite(id, _) => {
                if let Some(l) = self.lines.get_mut(&id) {
                    l.reinvite_pending = false;
                }
                if let Some(l) = self.lines.get_mut(&id) {
                    l.action = Some((
                        "Hold or resume failed: the PBX did not answer the re-INVITE".into(),
                        false,
                    ));
                }
                self.event("error", Some(id), None, "re-INVITE timed out");
            }
            Purpose::Refer(id) => {
                if let Some(l) = self.lines.get_mut(&id) {
                    l.transfer = Some("transfer failed: no response to REFER".into());
                    l.action = Some((
                        "Transfer failed: the PBX did not answer the REFER".into(),
                        false,
                    ));
                }
                self.event("transfer", Some(id), None, "REFER timed out");
            }
            Purpose::Options(k) => {
                if let Some((_, s)) = options_waiters().lock().unwrap().remove(&k) {
                    let _ = s.send(None);
                }
                self.event("diag", None, Some(tx.acc), "OPTIONS: no response");
            }
            Purpose::Info(id) => self.event("dtmf", Some(id), None, "INFO timed out"),
            Purpose::Message(t) => self.event(
                "message",
                None,
                Some(tx.acc),
                format!("MESSAGE to {t}: no response"),
            ),
            Purpose::Subscribe(cid) => {
                if let Some(x) = self.subs.iter_mut().find(|x| x.call_id == cid) {
                    if x.event == "dialog" {
                        x.state = "error";
                        x.detail = Some("no response to SUBSCRIBE".into());
                    }
                    x.call_id.clear();
                    x.next = Some(Instant::now() + Duration::from_secs(60));
                }
            }
            Purpose::Publish(ai) => {
                if let Some(p) = self.accs.get_mut(ai).and_then(|a| a.publication.as_mut()) {
                    p.error = Some("no response to PUBLISH".into());
                    p.next = Some(Instant::now() + Duration::from_secs(60));
                }
            }
            Purpose::Cancel | Purpose::Notify | Purpose::Prack | Purpose::Update => {}
        }
        self.dirty = true;
    }

    // ----- commands

    fn handle_cmd(&mut self, c: Cmd) {
        match c {
            Cmd::SetAccounts(v) => self.set_accounts(v),
            Cmd::SetSettings(s) => {
                crate::sipmsg::set_global_codecs(s.codecs.clone());
                self.tap.set_enabled(s.capture);
                if s.hep_collector != self.settings.hep_collector
                    || s.hep_agent_id != self.settings.hep_agent_id
                {
                    match self.tap.set_hep(&s.hep_collector, s.hep_agent_id) {
                        Ok(Some(to)) => {
                            self.event("info", None, None, format!("HEP copies of SIP go to {to}"))
                        }
                        Ok(None) => {}
                        Err(e) => self.event("error", None, None, format!("HEP collector: {e}")),
                    }
                }
                self.settings = s;
                self.route_audio();
                self.dirty = true;
            }
            Cmd::SetAudio(a) => {
                self.audio = a;
                self.route_audio();
                self.dirty = true;
            }
            Cmd::Register(id) => {
                if let Some(ai) = self.acc_index(Some(&id)) {
                    if self.accs[ai].sock.is_none() {
                        self.setup_acc(ai);
                    }
                    let exp = self.accs[ai].cfg.profile.account.expires.max(30);
                    self.send_register(ai, exp, None);
                }
            }
            Cmd::Unregister(id) => {
                if let Some(ai) = self.acc_index(Some(&id)) {
                    self.send_register(ai, 0, None);
                }
            }
            Cmd::Call(id, req) => self.place_call(id, req, None),
            Cmd::Answer(id) => self.answer(id),
            Cmd::Reject(id, code) => self.reject(id, code),
            Cmd::Hangup(id) => self.hangup(id),
            Cmd::HangupAll => {
                let ids: Vec<u32> = self.lines.keys().copied().collect();
                for id in ids {
                    self.hangup(id);
                }
            }
            Cmd::Hold(id, on) => self.set_hold(id, on),
            Cmd::Mute(id, on) => {
                if let Some(l) = self.lines.get_mut(&id) {
                    l.muted = on;
                    if let Some(r) = &l.rtp {
                        r.ctl.mute.store(on, Ordering::Relaxed);
                    }
                    self.dirty = true;
                }
            }
            Cmd::Record(id, on) => {
                if let Some(l) = self.lines.get_mut(&id) {
                    l.recording = on;
                    if let Some(r) = &l.rtp {
                        r.ctl.record.store(on, Ordering::Relaxed);
                    }
                    self.dirty = true;
                }
            }
            Cmd::Dtmf(id, digits) => self.dtmf(id, &digits),
            Cmd::BlindTransfer(id, target) => self.blind_transfer(id, &target),
            Cmd::AttendedTransfer(a, b) => self.attended_transfer(a, b),
            Cmd::Conference(a, b, on) => self.conference(a, b, on),
            Cmd::SetPresence(acc, status, note) => {
                if let Some(ai) = self.accs.iter().position(|a| a.cfg.id == acc) {
                    let etag = self.accs[ai].publication.take().and_then(|p| p.etag);
                    self.accs[ai].publication = Some(Publication {
                        status,
                        note,
                        etag,
                        next: Some(Instant::now()),
                        error: None,
                    });
                    self.send_publish(ai);
                }
            }
            Cmd::Options(acc, target, reply) => self.send_options(acc, target, reply),
            Cmd::Message(acc, target, text) => self.send_message(acc, target, text),
            Cmd::Forward(id, target) => self.forward(id, &target, "by hand"),
            Cmd::ClearCapture => {
                self.tap.clear();
                self.shared.lock().unwrap().trace.clear();
                self.dirty = true;
            }
            Cmd::Shutdown => self.stop = true,
        }
    }

    fn active_lines(&self) -> usize {
        self.lines.values().filter(|l| l.state.active()).count()
    }

    fn send_options(
        &mut self,
        acc: Option<String>,
        target: String,
        reply: Sender<Option<(u16, u64, String)>>,
    ) {
        let Some(ai) = self.acc_index(acc.as_deref()) else {
            let _ = reply.send(None);
            return;
        };
        let p = self.accs[ai].cfg.profile.clone();
        let target = if target.trim().is_empty() {
            p.account.domain.clone()
        } else {
            target
        };
        let ruri = if target.contains('@') || target.starts_with("sip:") {
            sipmsg::target_uri(&p, &target)
        } else {
            format!("sip:{}", target.trim())
        };
        let dest = match self.dest_for(ai, &ruri) {
            Ok(d) => d,
            Err(e) => {
                self.event("diag", None, Some(ai), format!("OPTIONS: {e}"));
                let _ = reply.send(None);
                return;
            }
        };
        self.direct_local(ai, dest);
        let branch = new_branch();
        let a = &self.accs[ai];
        let text = build_request(
            &p.behavior,
            a.local,
            "OPTIONS",
            &ruri,
            &branch,
            &sipmsg::from_header(&p, &rand_hex(10)),
            &format!("<{ruri}>"),
            &format!("{}@{}", rand_hex(16), a.local.ip()),
            1,
            "OPTIONS",
            &[],
            &[("Accept".into(), "application/sdp".into())],
            None,
        );
        let k = rand_u64();
        options_waiters()
            .lock()
            .unwrap()
            .insert(k, (Instant::now(), reply));
        self.start_tx(ai, "OPTIONS", &branch, text, dest, Purpose::Options(k));
    }

    fn send_message(&mut self, acc: Option<String>, target: String, text: String) {
        let Some(ai) = self.acc_index(acc.as_deref()) else {
            self.event("error", None, None, "MESSAGE: no account");
            return;
        };
        let p = self.accs[ai].cfg.profile.clone();
        let ruri = sipmsg::target_uri(&p, &target);
        let dest = match self.dest_for(ai, &ruri) {
            Ok(d) => d,
            Err(e) => {
                self.event(
                    "message",
                    None,
                    Some(ai),
                    format!("MESSAGE to {target}: {e}"),
                );
                return;
            }
        };
        self.direct_local(ai, dest);
        let branch = new_branch();
        let a = &self.accs[ai];
        let req = build_request(
            &p.behavior,
            a.local,
            "MESSAGE",
            &ruri,
            &branch,
            &sipmsg::from_header(&p, &rand_hex(10)),
            &format!("<{ruri}>"),
            &format!("{}@{}", rand_hex(16), a.local.ip()),
            1,
            "MESSAGE",
            &[],
            &[],
            Some(("text/plain;charset=UTF-8", &text)),
        );
        self.start_tx(ai, "MESSAGE", &branch, req, dest, Purpose::Message(target));
    }

    /// Direct accounts advertise the interface the OS uses towards `dest`.
    fn direct_local(&mut self, ai: usize, dest: SocketAddr) {
        let a = &self.accs[ai];
        let fixed = a
            .cfg
            .profile
            .behavior
            .local_ip
            .as_ref()
            .map(|s| !s.is_empty())
            .unwrap_or(false);
        if a.direct && !fixed {
            if let Ok(ip) = local_ip_for(dest) {
                let port = a.local.port();
                self.accs[ai].local = SocketAddr::new(ip, port);
            }
        }
    }

    /// Where to send an out-of-dialog request for `ruri`.
    fn dest_for(&self, ai: usize, ruri: &str) -> Result<SocketAddr, String> {
        let a = &self.accs[ai];
        let p = &a.cfg.profile;
        let has_proxy = p
            .account
            .outbound_proxy
            .as_ref()
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false);
        let reliable = a.sock.as_ref().map(|s| s.kind.reliable()).unwrap_or(false);
        if has_proxy || reliable {
            // Streams carry everything over the one connection to the server.
            return a.server.ok_or_else(|| "server not resolved".to_string());
        }
        let hp = hostport_of(ruri).ok_or_else(|| format!("bad URI {ruri}"))?;
        let (h, port) = sip::split_host_port(&hp);
        let (dh, dport) = sip::split_host_port(&p.account.domain);
        if h.eq_ignore_ascii_case(&dh) && port == dport {
            if let Some(s) = a.server {
                return Ok(s);
            }
        }
        crate::dns::resolve_sip(&hp).map_err(|e| e.to_string())
    }

    fn dialog_dest(
        &self,
        ai: usize,
        route_set: &[String],
        remote_target: &str,
        fallback: SocketAddr,
    ) -> SocketAddr {
        let p = &self.accs[ai].cfg.profile;
        if self.accs[ai]
            .sock
            .as_ref()
            .map(|s| s.kind.reliable())
            .unwrap_or(false)
        {
            if let Some(s) = self.accs[ai].server {
                return s;
            }
        }
        if p.account
            .outbound_proxy
            .as_ref()
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false)
        {
            if let Some(s) = self.accs[ai].server {
                return s;
            }
        }
        let target = route_set
            .first()
            .and_then(|r| sipmsg::uri_from_contact(r))
            .unwrap_or_else(|| remote_target.to_string());
        hostport_of(&target)
            .and_then(|hp| resolve(&hp, 5060).ok())
            .unwrap_or(fallback)
    }

    fn effective_profile(&self, ai: usize, overrides: Option<&serde_json::Value>) -> Profile {
        let mut p = self.accs[ai].cfg.profile.clone();
        if let Some(serde_json::Value::Object(o)) = overrides {
            if let Ok(mut bj) = serde_json::to_value(&p.behavior) {
                if let Some(bo) = bj.as_object_mut() {
                    for (k, v) in o {
                        bo.insert(k.clone(), v.clone());
                    }
                }
                if let Ok(b) = serde_json::from_value(bj) {
                    p.behavior = b;
                }
            }
        }
        p
    }

    fn audio_source(&self) -> AudioSource {
        match self.settings.audio_source.as_str() {
            "device" if self.audio.is_some() => AudioSource::Device,
            "echo" => AudioSource::Echo,
            "silence" => AudioSource::Silence,
            _ => AudioSource::Tone(self.settings.tone_hz.max(50.0)),
        }
    }

    fn rtp_tap(&self) -> Tap {
        if self.settings.capture && self.settings.capture_rtp {
            self.tap.clone()
        } else {
            let t = Tap::new();
            t.set_enabled(false);
            t
        }
    }

    /// Connects microphone and speaker to the focused line only.
    fn route_audio(&mut self) {
        let focus = self
            .lines
            .values()
            .filter(|l| {
                matches!(l.state, LState::Connected | LState::Early)
                    && !l.local_hold
                    && l.rtp.is_some()
            })
            .max_by_key(|l| l.focus)
            .map(|l| l.id);
        let use_mic = self.settings.audio_source == "device";
        for l in self.lines.values() {
            if let Some(r) = &l.rtp {
                let on = Some(l.id) == focus;
                *r.ctl.mic.lock().unwrap() = match (&self.audio, on && use_mic) {
                    (Some(a), true) => Some(a.mic.clone()),
                    _ => None,
                };
                *r.ctl.speaker.lock().unwrap() = match (&self.audio, on) {
                    (Some(a), true) => Some(a.speaker.clone()),
                    _ => None,
                };
                r.ctl.clear_mix();
            }
        }
        // A conference stays only while both lines are up and not held.
        let ok = self.conf.as_ref().map(|c| {
            [c.a, c.b].iter().all(|id| {
                self.lines
                    .get(id)
                    .map(|l| l.state == LState::Connected && !l.local_hold && l.rtp.is_some())
                    .unwrap_or(false)
            })
        });
        if ok == Some(false) {
            let c = self.conf.take().unwrap();
            self.event(
                "call",
                Some(c.a),
                None,
                format!("conference with line {} ended", c.b),
            );
            return;
        }
        let Some(c) = &self.conf else { return };
        let (Some(la), Some(lb)) = (self.lines.get(&c.a), self.lines.get(&c.b)) else {
            return;
        };
        let (Some(ra), Some(rb)) = (&la.rtp, &lb.rtp) else {
            return;
        };
        *ra.ctl.mic.lock().unwrap() = match (&self.audio, use_mic) {
            (Some(a), true) => Some(a.mic.clone()),
            _ => None,
        };
        *ra.ctl.speaker.lock().unwrap() = self.audio.as_ref().map(|a| a.speaker.clone());
        *ra.ctl.mic_copy.lock().unwrap() = Some(c.mic_share.clone());
        *ra.ctl.tx_adds.lock().unwrap() = vec![c.b_to_a.clone()];
        *ra.ctl.rx_copies.lock().unwrap() = vec![c.a_to_b.clone()];
        *ra.ctl.spk_adds.lock().unwrap() = vec![c.b_to_spk.clone()];
        *rb.ctl.mic.lock().unwrap() = None;
        *rb.ctl.speaker.lock().unwrap() = None;
        *rb.ctl.tx_adds.lock().unwrap() = vec![c.a_to_b.clone(), c.mic_share.clone()];
        *rb.ctl.rx_copies.lock().unwrap() = vec![c.b_to_a.clone(), c.b_to_spk.clone()];
    }

    /// Joins two connected lines into a three-way conference, or splits it.
    fn conference(&mut self, a: u32, b: u32, on: bool) {
        if !on {
            if let Some(c) = self.conf.take() {
                let other = if c.a == a { c.b } else { c.a };
                self.event("call", Some(a), None, "conference split");
                self.route_audio();
                if self.settings.auto_hold {
                    self.set_hold(other, true);
                }
            }
            return;
        }
        let ready = [a, b].iter().all(|id| {
            self.lines
                .get(id)
                .map(|l| l.state == LState::Connected)
                .unwrap_or(false)
        });
        if a == b || !ready {
            self.event(
                "error",
                Some(a),
                None,
                "a conference needs two connected calls",
            );
            return;
        }
        let ring = || Ring::new(SPMS * 200);
        self.conf = Some(Conf {
            a,
            b,
            mic_share: ring(),
            a_to_b: ring(),
            b_to_a: ring(),
            b_to_spk: ring(),
        });
        for id in [a, b] {
            if self.lines.get(&id).map(|l| l.local_hold).unwrap_or(false) {
                self.set_hold(id, false);
            }
        }
        self.event(
            "call",
            Some(a),
            None,
            format!("conference: lines {a} and {b} joined"),
        );
        self.route_audio();
    }

    fn new_line(&self, id: u32, ai: usize, profile: Profile, outgoing: bool) -> Line {
        let now = Instant::now();
        let fallback: SocketAddr = "0.0.0.0:0".parse().unwrap();
        Line {
            id,
            acc: ai,
            profile,
            outgoing,
            state: if outgoing {
                LState::Calling
            } else {
                LState::Incoming
            },
            call_id: String::new(),
            local_tag: rand_hex(10),
            remote_tag: String::new(),
            local_uri: String::new(),
            remote_uri: String::new(),
            remote_name: None,
            remote_target: String::new(),
            route_set: Vec::new(),
            dest: fallback,
            cseq: 1,
            remote_cseq: 0,
            ruri: String::new(),
            from_hdr: String::new(),
            invite_cseq: 1,
            invite_branch: String::new(),
            invite_dest: fallback,
            extra_headers: Vec::new(),
            cancel_wanted: false,
            cancel_sent: None,
            ack_text: None,
            invite_req: None,
            invite_from: None,
            invite_req_branch: None,
            last_resp: None,
            offer: None,
            auto_answer_at: None,
            replaces_line: None,
            uas_2xx: None,
            uas_next: now,
            uas_interval: Duration::from_millis(500),
            uas_start: now,
            rtp: None,
            codec: None,
            remote_dtmf: None,
            remote_media: None,
            sess_id: rand_u64(),
            sdp_ver: 1,
            local_hold: false,
            remote_hold: false,
            muted: false,
            recording: self.settings.record_calls,
            reinvite_pending: false,
            focus: now_ms(),
            created: now,
            started_ms: now_ms(),
            answered_ms: None,
            ended_ms: None,
            ended_at: None,
            final_code: None,
            reason: None,
            ended_by: None,
            post_dtmf: None,
            dtmf_rx: String::new(),
            transfer: None,
            transfer_kind: None,
            notify_line: None,
            last_refresh: now,
            rtp_final: (0, 0),
            srtp_local: None,
            srtp_savp: false,
            srtp_on: false,
            dtls_offer: false,
            dtls_client: None,
            dtls_reported: false,
            action: None,
        }
    }

    fn failed_line(&mut self, id: u32, ai: usize, target: &str, why: String) {
        let mut l = self.new_line(id, ai, Profile::default(), true);
        l.remote_uri = target.to_string();
        l.call_id = format!("{}@failed", rand_hex(12));
        self.lines.insert(id, l);
        self.event("error", Some(id), Some(ai), why.clone());
        self.end_line(id, None, Some(why), "local");
    }

    fn place_call(&mut self, id: u32, req: CallRequest, replaces: Option<String>) {
        let Some(ai) = self.acc_index(req.account.as_deref()) else {
            self.failed_line(
                id,
                0,
                &req.target,
                "no usable account; configure and enable one first".into(),
            );
            return;
        };
        if self.accs[ai].sock.is_none() {
            let why = self.accs[ai]
                .error
                .clone()
                .unwrap_or_else(|| "account is not ready".into());
            self.failed_line(id, ai, &req.target, why);
            return;
        }
        if self.active_lines() >= self.settings.max_lines.max(1) as usize {
            self.failed_line(
                id,
                ai,
                &req.target,
                format!("all {} lines are busy", self.settings.max_lines),
            );
            return;
        }
        let (target, uri_headers, post) = sipmsg::parse_dial_string(&req.target);
        if target.is_empty() {
            self.failed_line(id, ai, &req.target, "nothing to call".into());
            return;
        }
        let p = self.effective_profile(ai, req.overrides.as_ref());
        if self.accs[ai].direct && !target.contains('@') {
            self.failed_line(
                id,
                ai,
                &target,
                "this account has no domain: dial user@host or a full SIP URI".into(),
            );
            return;
        }
        let ruri = sipmsg::target_uri(&p, &target);
        let dest = match self.dest_for(ai, &ruri) {
            Ok(d) => d,
            Err(e) => {
                self.failed_line(id, ai, &ruri, e);
                return;
            }
        };
        self.direct_local(ai, dest);
        let local = self.accs[ai].local;
        let b = &p.behavior;
        let rtp = match RtpSession::bind(local.ip(), b.rtp_port_start, b.rtp_port_end, b.dscp_rtp) {
            Ok(r) => r,
            Err(e) => {
                self.failed_line(id, ai, &ruri, format!("RTP port: {e}"));
                return;
            }
        };
        let mut l = self.new_line(id, ai, p.clone(), true);
        l.call_id = format!("{}@{}", rand_hex(20), local.ip());
        l.ruri = ruri.clone();
        l.local_uri = sipmsg::aor(&p);
        l.remote_uri = ruri.clone();
        l.remote_target = ruri.clone();
        l.from_hdr = sipmsg::from_header(&p, &l.local_tag);
        l.invite_dest = dest;
        l.dest = dest;
        let mut extra = req.headers.clone();
        extra.extend(uri_headers);
        if let Some(r) = replaces {
            extra.push(("Replaces".into(), r));
        }
        l.extra_headers = extra;
        l.post_dtmf = post.map(|d| (d, Instant::now()));
        if p.behavior.srtp != crate::profile::SrtpMode::Off
            && p.behavior.srtp_keys.eq_ignore_ascii_case("dtls")
        {
            l.dtls_offer = true;
        } else if p.behavior.srtp != crate::profile::SrtpMode::Off {
            l.srtp_local = Some((
                1,
                crate::srtp::KeyMaterial::random(crate::srtp::Suite::Sha80),
            ));
            l.srtp_savp = p.behavior.srtp == crate::profile::SrtpMode::Mandatory;
        }
        rtp.ctl.record.store(l.recording, Ordering::Relaxed);
        l.rtp = Some(rtp);
        self.lines.insert(id, l);
        self.event(
            "call",
            Some(id),
            Some(ai),
            format!("calling {ruri} via {dest}"),
        );
        self.send_invite(id, None);
    }

    fn line_offer(&mut self, id: u32, direction: Option<&str>) -> String {
        let l = self.lines.get_mut(&id).unwrap();
        let b = &l.profile.behavior;
        let codecs = match l.codec {
            Some(c) if l.state == LState::Connected => vec![c],
            _ => sipmsg::profile_codecs(b),
        };
        let dtmf = if b.dtmf_mode == DtmfMode::Rfc4733 {
            Some(l.remote_dtmf.unwrap_or(b.dtmf_payload_type))
        } else {
            None
        };
        let dir = direction
            .map(|d| d.to_string())
            .unwrap_or_else(|| b.sdp_direction.clone());
        let rtp_local = l.rtp.as_ref().map(|r| r.local).unwrap_or(l.dest);
        let body = sipmsg::sdp_body(b, rtp_local, &codecs, dtmf, &dir, l.sess_id, l.sdp_ver);
        if l.dtls_offer || l.dtls_client.is_some() {
            let setup = match l.dtls_client {
                None => "actpass",
                Some(true) => "active",
                Some(false) => "passive",
            };
            return with_dtls(body, setup);
        }
        match &l.srtp_local {
            Some((tag, km)) => with_srtp(body, &km.sdp(*tag), l.srtp_savp),
            None => body,
        }
    }

    fn send_invite(&mut self, id: u32, auth: Option<(String, String)>) {
        let offer = self.line_offer(id, None);
        let l = self.lines.get_mut(&id).unwrap();
        let ai = l.acc;
        let b = l.profile.behavior.clone();
        let local = self.accs[ai].local;
        let mut supported = vec!["replaces", "100rel", "norefersub"];
        if b.session_timer > 0 {
            supported.push("timer");
        }
        if b.offer_gruu {
            supported.push("gruu");
        }
        let mut extra = vec![
            (
                "Contact".to_string(),
                sipmsg::contact(&l.profile, local, &self.accs[ai].instance, false),
            ),
            (
                "Allow".to_string(),
                "INVITE, ACK, CANCEL, BYE, OPTIONS, INFO, UPDATE, PRACK, REFER, NOTIFY, MESSAGE"
                    .to_string(),
            ),
            (
                sipmsg::hn(&b, "Supported").to_string(),
                supported.join(", "),
            ),
        ];
        if b.require_prack {
            extra.push(("Require".into(), "100rel".into()));
        }
        if b.session_timer > 0 {
            extra.push((
                "Session-Expires".into(),
                format!("{};refresher=uac", b.session_timer),
            ));
            extra.push(("Min-SE".into(), "90".into()));
        }
        if let Some((h, v)) = auth {
            extra.push((h, v));
        }
        extra.extend(l.extra_headers.iter().cloned());
        let branch = new_branch();
        l.invite_branch = branch.clone();
        let text = build_request(
            &b,
            local,
            "INVITE",
            &l.ruri,
            &branch,
            &l.from_hdr,
            &format!("<{}>", l.ruri),
            &l.call_id,
            l.invite_cseq,
            "INVITE",
            &[],
            &extra,
            Some(("application/sdp", &offer)),
        );
        l.cseq = l.invite_cseq;
        let dest = l.invite_dest;
        self.start_tx(ai, "INVITE", &branch, text, dest, Purpose::Invite(id));
        self.dirty = true;
    }

    fn send_ack_non2xx(&mut self, id: u32, resp: &SipMessage) -> Option<String> {
        let l = self.lines.get(&id)?;
        let to = resp.header("To").unwrap_or("").to_string();
        let text = build_request(
            &l.profile.behavior,
            self.accs[l.acc].local,
            "ACK",
            &l.ruri,
            &l.invite_branch,
            &l.from_hdr,
            &to,
            &l.call_id,
            l.invite_cseq,
            "ACK",
            &[],
            &[],
            None,
        );
        let (ai, dest) = (l.acc, l.invite_dest);
        self.send_raw(ai, &text, dest);
        Some(text)
    }

    /// Builds an in-dialog request. `cseq` None takes the next local CSeq.
    fn dialog_request(
        &mut self,
        id: u32,
        method: &str,
        extra: &[(String, String)],
        body: Option<(&str, &str)>,
        cseq: Option<u32>,
    ) -> Option<(String, String, SocketAddr, usize)> {
        let l = self.lines.get_mut(&id)?;
        let n = match cseq {
            Some(n) => n,
            None => {
                l.cseq += 1;
                l.cseq
            }
        };
        let branch = new_branch();
        let from = format!("<{}>;tag={}", l.local_uri, l.local_tag);
        let to = if l.remote_tag.is_empty() {
            format!("<{}>", l.remote_uri)
        } else {
            format!("<{}>;tag={}", l.remote_uri, l.remote_tag)
        };
        let ai = l.acc;
        let local = self.accs[ai].local;
        let mut ex: Vec<(String, String)> = Vec::new();
        if method != "ACK" && method != "CANCEL" {
            ex.push((
                "Contact".into(),
                sipmsg::contact(&l.profile, local, &self.accs[ai].instance, false),
            ));
        }
        ex.extend(extra.iter().cloned());
        let text = build_request(
            &l.profile.behavior,
            local,
            method,
            &l.remote_target,
            &branch,
            &from,
            &to,
            &l.call_id,
            n,
            method,
            &l.route_set,
            &ex,
            body,
        );
        Some((text, branch, l.dest, ai))
    }

    fn send_in_dialog(
        &mut self,
        id: u32,
        method: &str,
        extra: &[(String, String)],
        body: Option<(&str, &str)>,
        purpose: Purpose,
    ) -> bool {
        match self.dialog_request(id, method, extra, body, None) {
            Some((text, branch, dest, ai)) => {
                self.start_tx(ai, method, &branch, text, dest, purpose);
                true
            }
            None => false,
        }
    }

    fn cancel(&mut self, id: u32) {
        let Some(l) = self.lines.get_mut(&id) else {
            return;
        };
        // RFC 3261 9.1: CANCEL only after a provisional response.
        let has_prov = self
            .txs
            .get(&(l.invite_branch.clone(), "INVITE".into()))
            .map(|t| t.provisional)
            .unwrap_or(false);
        if !has_prov {
            l.cancel_wanted = true;
            l.state = LState::Ending;
            if l.created.elapsed() > Duration::from_secs(32) {
                self.end_line(id, None, Some("cancelled".into()), "local");
            }
            return;
        }
        l.cancel_sent = Some(Instant::now());
        l.state = LState::Ending;
        let text = build_request(
            &l.profile.behavior,
            self.accs[l.acc].local,
            "CANCEL",
            &l.ruri,
            &l.invite_branch,
            &l.from_hdr,
            &format!("<{}>", l.ruri),
            &l.call_id,
            l.invite_cseq,
            "CANCEL",
            &[],
            &[],
            None,
        );
        let (ai, dest, br) = (l.acc, l.invite_dest, l.invite_branch.clone());
        self.start_tx(ai, "CANCEL", &br, text, dest, Purpose::Cancel);
        self.event("call", Some(id), Some(ai), "CANCEL sent");
    }

    fn hangup(&mut self, id: u32) {
        let Some(l) = self.lines.get(&id) else { return };
        match l.state {
            LState::Calling | LState::Ringing | LState::Early => self.cancel(id),
            LState::Incoming => self.reject(id, 603),
            LState::Connected => self.send_bye(id, None),
            LState::Ending => {
                if l.outgoing && l.cancel_sent.is_none() && !l.cancel_wanted {
                    self.send_bye(id, None);
                }
            }
            LState::Ended => {}
        }
    }

    /// Reports DTLS-SRTP results and hangs up calls whose handshake failed.
    fn dtls_outcomes(&mut self) {
        let mut done = Vec::new();
        for l in self.lines.values() {
            if l.dtls_client.is_none() || l.dtls_reported || l.state == LState::Ended {
                continue;
            }
            let Some(r) = &l.rtp else { continue };
            let st = r.stats.lock().unwrap();
            if st.dtls_ready || st.dtls_failed {
                done.push((
                    l.id,
                    l.acc,
                    st.dtls_failed,
                    st.dtls.clone().unwrap_or_default(),
                ));
            }
        }
        for (id, acc, failed, text) in done {
            if let Some(l) = self.lines.get_mut(&id) {
                l.dtls_reported = true;
            }
            if failed {
                self.event("error", Some(id), Some(acc), format!("{text}; hanging up"));
                self.send_bye(id, Some(text));
            } else {
                self.event("media", Some(id), Some(acc), text);
            }
            self.dirty = true;
        }
    }

    fn send_bye(&mut self, id: u32, why: Option<String>) {
        let reason = (
            "Reason".to_string(),
            "Q.850;cause=16;text=\"Normal call clearing\"".to_string(),
        );
        if let Some(l) = self.lines.get_mut(&id) {
            l.state = LState::Ending;
            l.uas_2xx = None;
            if l.ended_by.is_none() {
                l.ended_by = Some("local".into());
            }
            if why.is_some() {
                l.reason = why;
            }
            if let Some(r) = &l.rtp {
                r.ctl.hold.store(true, Ordering::Relaxed);
            }
        }
        if !self.send_in_dialog(id, "BYE", &[reason], None, Purpose::Bye(id)) {
            return;
        }
        let acc = self.lines.get(&id).map(|l| l.acc);
        self.event("call", Some(id), acc, "BYE sent");
        self.route_audio();
    }

    fn reject(&mut self, id: u32, code: u16) {
        let Some(l) = self.lines.get(&id) else { return };
        if l.state != LState::Incoming {
            return;
        }
        let (Some(req), Some(from)) = (l.invite_req.clone(), l.invite_from) else {
            return;
        };
        let ai = l.acc;
        let tag = l.local_tag.clone();
        let reason = match code {
            486 => "Busy Here",
            480 => "Temporarily Unavailable",
            603 => "Decline",
            404 => "Not Found",
            488 => "Not Acceptable Here",
            487 => "Request Terminated",
            403 => "Forbidden",
            503 => "Service Unavailable",
            _ => "Rejected",
        };
        let text = self.respond(ai, &req, from, code, reason, Some(&tag), &[], None);
        if let Some(l) = self.lines.get_mut(&id) {
            l.last_resp = Some(text);
        }
        self.end_line(
            id,
            Some(code),
            Some(format!("rejected with {code} {reason}")),
            "local",
        );
    }

    /// Redirects a ringing incoming call with 302 Moved Temporarily.
    fn forward(&mut self, id: u32, target: &str, why: &str) {
        let Some(l) = self.lines.get(&id) else { return };
        if l.state != LState::Incoming {
            return;
        }
        let (Some(req), Some(from)) = (l.invite_req.clone(), l.invite_from) else {
            return;
        };
        let ai = l.acc;
        let tag = l.local_tag.clone();
        let uri = sipmsg::target_uri(&l.profile, target);
        let extra = vec![("Contact".to_string(), format!("<{uri}>"))];
        let text = self.respond(
            ai,
            &req,
            from,
            302,
            "Moved Temporarily",
            Some(&tag),
            &extra,
            None,
        );
        if let Some(l) = self.lines.get_mut(&id) {
            l.last_resp = Some(text);
        }
        self.event(
            "incoming",
            Some(id),
            Some(ai),
            format!("forwarded to {target} ({why})"),
        );
        self.end_line(
            id,
            Some(302),
            Some(format!("forwarded to {uri} ({why})")),
            "local",
        );
    }

    fn end_line(&mut self, id: u32, code: Option<u16>, reason: Option<String>, by: &str) {
        let Some(l) = self.lines.get_mut(&id) else {
            return;
        };
        if l.state == LState::Ended {
            return;
        }
        l.state = LState::Ended;
        l.ended_ms = Some(now_ms());
        l.ended_at = Some(Instant::now());
        l.uas_2xx = None;
        if code.is_some() {
            l.final_code = code;
        }
        if reason.is_some() && l.reason.is_none() {
            l.reason = reason;
        }
        if l.ended_by.is_none() {
            l.ended_by = Some(by.into());
        }
        let mut wav = None;
        if let Some(mut r) = l.rtp.take() {
            r.stop();
            let st = r.stats.lock().unwrap();
            l.rtp_final = (st.sent_packets, st.received_packets);
            drop(st);
            if l.recording && l.answered_ms.is_some() {
                wav = Some(r.wav());
            }
        }
        let duration_s = l
            .answered_ms
            .map(|a| (l.ended_ms.unwrap_or(a).saturating_sub(a)) as f64 / 1000.0)
            .unwrap_or(0.0);
        let h = HistoryEntry {
            call_id: l.call_id.clone(),
            account: self
                .accs
                .get(l.acc)
                .map(|a| a.cfg.id.clone())
                .unwrap_or_default(),
            direction: if l.outgoing { "out" } else { "in" }.into(),
            remote: Uri::parse(&l.remote_uri)
                .map(|u| u.short())
                .unwrap_or_else(|| l.remote_uri.clone()),
            remote_name: l.remote_name.clone(),
            started_ms: l.started_ms,
            answered: l.answered_ms.is_some(),
            duration_s,
            final_code: l.final_code,
            reason: l.reason.clone(),
            ended_by: l.ended_by.clone(),
            codec: l.codec.map(|c| c.name().to_string()),
            ..Default::default()
        };
        let text = format!(
            "call ended{}{}",
            l.final_code.map(|c| format!(" ({c})")).unwrap_or_default(),
            l.reason
                .as_ref()
                .map(|r| format!(": {r}"))
                .unwrap_or_default()
        );
        let acc = l.acc;
        let notify_line = l.notify_line;
        let final_code = l
            .final_code
            .unwrap_or(if l.answered_ms.is_some() { 200 } else { 487 });
        {
            let mut s = self.shared.lock().unwrap();
            s.history.push_front(h);
            while s.history.len() > MAX_HISTORY {
                s.history.pop_back();
            }
            s.history_dirty = true;
            if let Some(w) = wav {
                s.recordings.push_back((id, w));
                while s.recordings.len() > 10 {
                    s.recordings.pop_front();
                }
            }
        }
        self.event("call", Some(id), Some(acc), text);
        // Only a resync that arrived during this call is released here. An
        // ordinary hangup must not download just because a URL is stored.
        if acc != usize::MAX {
            let has_url = self
                .accs
                .get(acc)
                .and_then(|a| a.cfg.provision_url.as_ref())
                .is_some_and(|s| !s.is_empty());
            let pending = self
                .accs
                .get(acc)
                .map(|a| a.resync_pending)
                .unwrap_or(false);
            if pending {
                let live_other = self
                    .lines
                    .values()
                    .filter(|l| l.acc == acc && l.state.active())
                    .count();
                match resync_gate(has_url, true, acc, false, live_other) {
                    ResyncGate::Emit => {
                        if let Some(a) = self.accs.get_mut(acc) {
                            a.resync_pending = false;
                        }
                        self.event("resync", None, Some(acc), "provisioning resync");
                    }
                    ResyncGate::Ignore => {
                        if let Some(a) = self.accs.get_mut(acc) {
                            a.resync_pending = false;
                        }
                    }
                    ResyncGate::Wait => {}
                }
            }
        }
        if let Some(parent) = notify_line {
            if self
                .lines
                .get(&id)
                .map(|l| l.answered_ms.is_none())
                .unwrap_or(false)
            {
                self.notify_refer(parent, final_code, "Failed", true);
            }
        }
        self.route_audio();
    }

    fn answer(&mut self, id: u32) {
        let Some(l) = self.lines.get(&id) else { return };
        if l.state != LState::Incoming {
            return;
        }
        let (Some(req), Some(from)) = (l.invite_req.clone(), l.invite_from) else {
            return;
        };
        let ai = l.acc;
        let b = l.profile.behavior.clone();
        let local = self.accs[ai].local;
        let rtp = match RtpSession::bind(local.ip(), b.rtp_port_start, b.rtp_port_end, b.dscp_rtp) {
            Ok(r) => r,
            Err(e) => {
                self.event("error", Some(id), Some(ai), format!("RTP port: {e}"));
                self.reject(id, 500);
                return;
            }
        };
        let offer = l.offer.clone();
        let mine = sipmsg::profile_codecs(&b);
        let (codec, remote_dtmf, remote, remote_held) = match &offer {
            Some(o) => {
                let m = o.media.iter().find(|m| m.kind == "audio" && m.port != 0);
                let codec = m.and_then(|m| {
                    m.formats
                        .iter()
                        .filter_map(|p| Codec::from_media(m, *p))
                        .find(|c| mine.contains(c))
                });
                let clock = codec.map(|c| c.clock()).unwrap_or(8000);
                let dt = m.and_then(|m| telephone_event(m, clock));
                let remote = m.map(|m| SocketAddr::new(m.address(o).unwrap_or(from.ip()), m.port));
                (codec, dt, remote, media_direction(o).1)
            }
            None => (Some(mine[0]), None, None, false),
        };
        let Some(codec) = codec else {
            self.reject(id, 488);
            return;
        };
        let dtmf_pt = if b.dtmf_mode == DtmfMode::Rfc4733 {
            remote_dtmf.or(if offer.is_none() {
                Some(b.dtmf_payload_type)
            } else {
                None
            })
        } else {
            None
        };
        let dir = if remote_held {
            "recvonly"
        } else {
            b.sdp_direction.as_str()
        };
        // SRTP (SDES): answer a=crypto with our own key for the same suite.
        let offer_m = offer.as_ref().and_then(|o| {
            o.media
                .iter()
                .find(|m| m.kind == "audio" && m.port != 0)
                .cloned()
        });
        let offer_savp = offer_m.as_ref().map(|m| m.is_secure()).unwrap_or(false);
        let offer_crypto = offer_m.as_ref().and_then(offered_crypto);
        let mode = b.srtp;
        // DTLS-SRTP offer: we take the role the offer leaves us.
        let offer_dtls = offer_m.as_ref().filter(|m| wants_dtls(m)).map(|m| {
            let remote_setup = m.setup.clone().unwrap_or_default().to_ascii_lowercase();
            crate::dtls::DtlsParams {
                client: remote_setup != "active",
                remote_fingerprint: m.fingerprint.clone().unwrap_or_default(),
            }
        });
        if offer_dtls.is_some() {
            if mode == crate::profile::SrtpMode::Off {
                self.event(
                    "error",
                    Some(id),
                    Some(ai),
                    "the call requires DTLS-SRTP; enable SRTP in the account's Media settings",
                );
                self.reject(id, 488);
                return;
            }
        }
        let use_srtp = match (offer_crypto.is_some() && offer_dtls.is_none(), mode) {
            (false, crate::profile::SrtpMode::Mandatory) if offer_dtls.is_some() => false,
            (true, crate::profile::SrtpMode::Off) => {
                if offer_savp {
                    self.event("error", Some(id), Some(ai), "the call requires SRTP (RTP/SAVP); enable SRTP in the account's Media settings");
                    self.reject(id, 488);
                    return;
                }
                false
            }
            (true, _) => true,
            (false, crate::profile::SrtpMode::Mandatory) => {
                self.event(
                    "error",
                    Some(id),
                    Some(ai),
                    "SRTP is mandatory on this account but the offer has no a=crypto",
                );
                self.reject(id, 488);
                return;
            }
            (false, _) => false,
        };
        let mut rtp = rtp;
        let l = self.lines.get_mut(&id).unwrap();
        let codecs = if offer.is_some() {
            vec![codec]
        } else {
            mine.clone()
        };
        let mut body = sipmsg::sdp_body(&b, rtp.local, &codecs, dtmf_pt, dir, l.sess_id, l.sdp_ver);
        if let Some(dp) = &offer_dtls {
            body = with_dtls(body, if dp.client { "active" } else { "passive" });
            rtp.dtls = Some(dp.clone());
            l.dtls_client = Some(dp.client);
            l.srtp_on = true;
        } else if use_srtp {
            let (tag, remote_km) = offer_crypto.clone().unwrap();
            let mine_km = crate::srtp::KeyMaterial::random(remote_km.suite);
            body = with_srtp(body, &mine_km.sdp(tag), offer_savp);
            rtp.srtp = Some((mine_km.clone(), remote_km));
            l.srtp_local = Some((tag, mine_km));
            l.srtp_savp = offer_savp;
            l.srtp_on = true;
        }
        rtp.ctl.record.store(l.recording, Ordering::Relaxed);
        l.rtp = Some(rtp);
        l.codec = Some(codec);
        l.remote_dtmf = remote_dtmf;
        l.remote_hold = remote_held;
        let tag = l.local_tag.clone();
        let mut extra = Vec::new();
        if b.session_timer > 0 {
            if let Some(se) = req.header("Session-Expires") {
                extra.push(("Session-Expires".to_string(), se.to_string()));
                extra.push(("Require".to_string(), "timer".to_string()));
            }
        }
        extra.push((
            "Allow".into(),
            "INVITE, ACK, CANCEL, BYE, OPTIONS, INFO, UPDATE, PRACK, REFER, NOTIFY, MESSAGE".into(),
        ));
        let text = self.respond(
            ai,
            &req,
            from,
            200,
            "OK",
            Some(&tag),
            &extra,
            Some(("application/sdp", &body)),
        );
        let t1 = Duration::from_millis(b.t1_ms.max(50));
        let source = self.audio_source();
        let tap = self.rtp_tap();
        let l = self.lines.get_mut(&id).unwrap();
        l.last_resp = Some(text.clone());
        l.uas_2xx = Some((text, from));
        l.uas_start = Instant::now();
        l.uas_interval = t1;
        l.uas_next = Instant::now() + t1;
        l.state = LState::Connected;
        l.answered_ms = Some(now_ms());
        l.focus = now_ms();
        l.auto_answer_at = None;
        if let Some(remote) = remote {
            l.remote_media = Some(remote);
            let rtp = l.rtp.as_mut().unwrap();
            rtp.start(
                remote,
                codec,
                b.ptime_ms,
                source,
                dtmf_pt,
                b.symmetric_rtp,
                tap,
            );
        }
        let replaces = l.replaces_line.take();
        self.event(
            "call",
            Some(id),
            Some(ai),
            format!("answered, {}", codec.name()),
        );
        if let Some(old) = replaces {
            self.event(
                "transfer",
                Some(old),
                Some(ai),
                format!("replaced by line {id}"),
            );
            self.send_bye(old, Some("replaced".into()));
        }
        // Other connected lines go on hold, like a desk phone.
        self.hold_others(id);
        self.route_audio();
    }

    fn set_hold(&mut self, id: u32, on: bool) {
        let Some(l) = self.lines.get_mut(&id) else {
            return;
        };
        if l.state != LState::Connected || l.local_hold == on {
            return;
        }
        if l.reinvite_pending {
            let acc = l.acc;
            self.event(
                "error",
                Some(id),
                Some(acc),
                "a re-INVITE is already in progress",
            );
            return;
        }
        l.sdp_ver += 1;
        l.reinvite_pending = true;
        let dir = match (on, l.remote_hold) {
            (true, false) => "sendonly",
            (true, true) => "inactive",
            (false, false) => "sendrecv",
            (false, true) => "recvonly",
        };
        if let Some(r) = &l.rtp {
            r.ctl.hold.store(on, Ordering::Relaxed);
        }
        l.local_hold = on;
        if !on {
            l.focus = now_ms();
        }
        let body = self.line_offer(id, Some(dir));
        self.send_in_dialog(
            id,
            "INVITE",
            &[],
            Some(("application/sdp", &body)),
            Purpose::ReInvite(id, on),
        );
        let acc = self.lines[&id].acc;
        self.event(
            "call",
            Some(id),
            Some(acc),
            if on { "hold" } else { "resume" },
        );
        if !on {
            // Resuming one line holds the others.
            self.hold_others(id);
        }
        self.route_audio();
    }

    /// A phone talks on one line at a time: the others go on hold.
    fn hold_others(&mut self, id: u32) {
        if !self.settings.auto_hold {
            return;
        }
        let others: Vec<u32> = self
            .lines
            .values()
            .filter(|o| o.id != id && o.state == LState::Connected && !o.local_hold)
            .map(|o| o.id)
            .filter(|o| {
                !self
                    .conf
                    .as_ref()
                    .map(|c| (c.a == id || c.b == id) && (c.a == *o || c.b == *o))
                    .unwrap_or(false)
            })
            .collect();
        for o in others {
            self.set_hold(o, true);
        }
    }

    // ----- busy lamp field

    /// Starts subscriptions for the account's BLF list and drops stale ones.
    fn ensure_subs(&mut self, ai: usize) {
        let a = &self.accs[ai];
        let id = a.cfg.id.clone();
        let want: Vec<String> = a
            .cfg
            .blf
            .iter()
            .map(|x| x.trim().to_string())
            .filter(|x| !x.is_empty())
            .collect();
        let mwi = a.cfg.mwi && a.cfg.register;
        self.subs.retain(|x| {
            x.acc_id != id
                || if x.event == MWI_EVENT {
                    mwi
                } else {
                    want.contains(&x.label)
                }
        });
        let own = a.cfg.profile.account.user.clone();
        let mut pairs: Vec<(String, &'static str)> = want
            .iter()
            .flat_map(|t| [(t.clone(), "dialog"), (t.clone(), "presence")])
            .collect();
        if mwi && !own.is_empty() {
            pairs.push((own, MWI_EVENT));
        }
        for (t, event) in pairs {
            if self
                .subs
                .iter()
                .any(|x| x.acc_id == id && x.label == t && x.event == event)
            {
                continue;
            }
            let uri = sipmsg::target_uri(&self.accs[ai].cfg.profile, &t);
            self.subs.push(Sub {
                acc_id: id.clone(),
                label: t,
                event,
                presence: None,
                note: None,
                unsupported: false,
                uri: uri.clone(),
                call_id: String::new(),
                local_tag: String::new(),
                remote_tag: String::new(),
                remote_target: uri,
                route_set: Vec::new(),
                cseq: 0,
                state: "unknown",
                detail: None,
                next: Some(Instant::now()),
            });
        }
        self.dirty = true;
    }

    fn send_subscribe(&mut self, i: usize) {
        let Some(ai) = self
            .accs
            .iter()
            .position(|a| a.cfg.id == self.subs[i].acc_id)
        else {
            return;
        };
        if self.accs[ai].sock.is_none() || self.accs[ai].state != "registered" {
            self.subs[i].next = Some(Instant::now() + Duration::from_secs(10));
            return;
        }
        let x = &mut self.subs[i];
        if x.call_id.is_empty() {
            x.call_id = format!(
                "{}@{}",
                rand_hex(16),
                match x.event {
                    "dialog" => "blf",
                    MWI_EVENT => "mwi",
                    _ => "pres",
                }
            );
            x.local_tag = rand_hex(10);
            x.remote_tag.clear();
            x.remote_target = x.uri.clone();
            x.route_set.clear();
        }
        x.cseq += 1;
        x.next = None;
        let p = self.accs[ai].cfg.profile.clone();
        let local = self.accs[ai].local;
        let to = if x.remote_tag.is_empty() {
            format!("<{}>", x.uri)
        } else {
            format!("<{}>;tag={}", x.uri, x.remote_tag)
        };
        let extra = vec![
            (
                "Contact".to_string(),
                sipmsg::contact(&p, local, &self.accs[ai].instance, false),
            ),
            ("Event".to_string(), x.event.to_string()),
            (
                "Accept".to_string(),
                match x.event {
                    "dialog" => "application/dialog-info+xml",
                    MWI_EVENT => "application/simple-message-summary",
                    _ => "application/pidf+xml",
                }
                .to_string(),
            ),
            ("Expires".to_string(), "600".to_string()),
        ];
        let branch = new_branch();
        let text = build_request(
            &p.behavior,
            local,
            "SUBSCRIBE",
            &x.remote_target,
            &branch,
            &sipmsg::from_header(&p, &x.local_tag),
            &to,
            &x.call_id,
            x.cseq,
            "SUBSCRIBE",
            &x.route_set,
            &extra,
            None,
        );
        let cid = x.call_id.clone();
        let uri = x.uri.clone();
        let dest = match self.dest_for(ai, &uri) {
            Ok(d) => d,
            Err(e) => {
                self.subs[i].state = "error";
                self.subs[i].detail = Some(e);
                return;
            }
        };
        self.start_tx(
            ai,
            "SUBSCRIBE",
            &branch,
            text,
            dest,
            Purpose::Subscribe(cid),
        );
    }

    fn subscribe_result(&mut self, cid: &str, m: &SipMessage) {
        let code = m.status().unwrap_or(0);
        let Some(x) = self.subs.iter_mut().find(|x| x.call_id == cid) else {
            return;
        };
        if (200..300).contains(&code) {
            if let Some(t) = m.to_tag() {
                x.remote_tag = t;
            }
            if let Some(c) = m.header("Contact").and_then(sipmsg::uri_from_contact) {
                x.remote_target = c;
            }
            x.route_set = m.header_values("Record-Route").into_iter().rev().collect();
            let exp = m
                .header("Expires")
                .and_then(|e| e.trim().parse::<u64>().ok())
                .unwrap_or(600)
                .max(30);
            x.next = Some(Instant::now() + Duration::from_secs(exp * 9 / 10));
            x.detail = None;
        } else if x.event == "presence" || x.event == MWI_EVENT {
            // Many PBXs offer only the dialog package; presence just stays off.
            // Voicemail may still arrive unsolicited (Asterisk mailbox= on the peer).
            x.call_id.clear();
            x.presence = None;
            if matches!(code, 403 | 404 | 405 | 489 | 501) {
                x.unsupported = true;
                x.next = None;
            } else {
                x.next = Some(Instant::now() + Duration::from_secs(60));
            }
        } else {
            x.state = "error";
            x.detail = Some(format!("{code} {}", reason_of(m)));
            // Start a new subscription later.
            x.call_id.clear();
            x.next = Some(Instant::now() + Duration::from_secs(60));
        }
        self.dirty = true;
    }

    fn blf_notify(&mut self, m: &SipMessage) {
        let cid = m.call_id().unwrap_or("");
        let Some(x) = self.subs.iter_mut().find(|x| x.call_id == cid) else {
            return;
        };
        if x.remote_tag.is_empty() {
            if let Some(t) = m.from_tag() {
                x.remote_tag = t;
            }
        }
        let terminated = m
            .header("Subscription-State")
            .map(|v| v.trim().to_ascii_lowercase().starts_with("terminated"))
            .unwrap_or(false);
        if !m.body.trim().is_empty() {
            if x.event == "dialog" {
                x.state = blf_state(&m.body);
            } else if x.event == MWI_EVENT {
                // Kept on the account (handled where the NOTIFY arrives).
            } else {
                let (p, n) = pidf_state(&m.body);
                x.presence = Some(p);
                x.note = n;
            }
        }
        if terminated {
            x.call_id.clear();
            x.next = Some(Instant::now() + Duration::from_secs(5));
        }
        self.dirty = true;
    }

    // ----- presence publication (RFC 3903)

    fn send_publish(&mut self, ai: usize) {
        let a = &self.accs[ai];
        if a.sock.is_none() || (a.cfg.register && a.state != "registered") {
            if let Some(p) = self.accs[ai].publication.as_mut() {
                p.next = Some(Instant::now() + Duration::from_secs(5));
            }
            return;
        }
        let Some(pb) = a.publication.as_ref() else {
            return;
        };
        let p = a.cfg.profile.clone();
        let local = a.local;
        let aor = sipmsg::aor(&p);
        let body = pidf_body(&aor, &pb.status, &pb.note);
        let mut extra = vec![
            ("Event".to_string(), "presence".to_string()),
            ("Expires".to_string(), "3600".to_string()),
        ];
        if let Some(e) = &pb.etag {
            extra.push(("SIP-If-Match".to_string(), e.clone()));
        }
        let branch = new_branch();
        let text = build_request(
            &p.behavior,
            local,
            "PUBLISH",
            &aor,
            &branch,
            &sipmsg::from_header(&p, &rand_hex(10)),
            &format!("<{aor}>"),
            &format!("{}@pub", rand_hex(16)),
            1,
            "PUBLISH",
            &[],
            &extra,
            Some(("application/pidf+xml", &body)),
        );
        if let Some(pb) = self.accs[ai].publication.as_mut() {
            pb.next = None;
        }
        // Like REGISTER: to the registrar or outbound proxy, not to the AOR's host.
        let dest = match self.accs[ai].server {
            Some(d) => d,
            None => match self.dest_for(ai, &aor) {
                Ok(d) => d,
                Err(e) => {
                    if let Some(pb) = self.accs[ai].publication.as_mut() {
                        pb.error = Some(e);
                    }
                    return;
                }
            },
        };
        self.start_tx(ai, "PUBLISH", &branch, text, dest, Purpose::Publish(ai));
    }

    fn publish_result(&mut self, ai: usize, m: &SipMessage) {
        let code = m.status().unwrap_or(0);
        let reason = reason_of(m);
        let Some(p) = self.accs.get_mut(ai).and_then(|a| a.publication.as_mut()) else {
            return;
        };
        if (200..300).contains(&code) {
            p.etag = m.header("SIP-ETag").map(|e| e.trim().to_string());
            let exp = m
                .header("Expires")
                .and_then(|e| e.trim().parse::<u64>().ok())
                .unwrap_or(3600)
                .max(60);
            p.next = Some(Instant::now() + Duration::from_secs(exp * 9 / 10));
            p.error = None;
            let text = format!("presence published: {}", p.status);
            self.event("reg", None, Some(ai), text);
        } else if code == 412 && p.etag.is_some() {
            // The server forgot our publication: start a new one.
            p.etag = None;
            p.next = Some(Instant::now());
        } else {
            p.error = Some(format!("{code} {reason}"));
            p.next = None;
            let text = format!("PUBLISH refused: {code} {reason}");
            self.event("error", None, Some(ai), text);
        }
    }

    fn session_refresh(&mut self, id: u32) {
        let se = self.lines[&id].profile.behavior.session_timer;
        if let Some(l) = self.lines.get_mut(&id) {
            l.last_refresh = Instant::now();
        }
        self.send_in_dialog(
            id,
            "UPDATE",
            &[("Session-Expires".into(), format!("{se};refresher=uac"))],
            None,
            Purpose::Update,
        );
    }

    fn dtmf(&mut self, id: u32, digits: &str) {
        let Some(l) = self.lines.get(&id) else { return };
        if !matches!(l.state, LState::Connected | LState::Early) {
            return;
        }
        let digits: String = digits
            .chars()
            .filter(|c| c.is_ascii_digit() || "*#ABCDabcd".contains(*c))
            .collect();
        if digits.is_empty() {
            return;
        }
        let mode = l.profile.behavior.dtmf_mode;
        let ai = l.acc;
        match mode {
            DtmfMode::Rfc4733 => {
                if l.remote_dtmf.is_some() {
                    if let Some(r) = &l.rtp {
                        r.queue_dtmf(&digits);
                    }
                    self.event(
                        "dtmf",
                        Some(id),
                        Some(ai),
                        format!("sent {digits} as RFC 4733 events"),
                    );
                } else {
                    if let Some(r) = &l.rtp {
                        r.ctl.inband.lock().unwrap().extend(digits.chars());
                    }
                    self.event(
                        "dtmf",
                        Some(id),
                        Some(ai),
                        format!("sent {digits} inband (the far end did not offer telephone-event)"),
                    );
                }
            }
            DtmfMode::Inband => {
                if let Some(r) = &l.rtp {
                    r.ctl.inband.lock().unwrap().extend(digits.chars());
                }
                self.event("dtmf", Some(id), Some(ai), format!("sent {digits} inband"));
            }
            DtmfMode::Info => {
                if l.state != LState::Connected {
                    return;
                }
                for d in digits.chars() {
                    let body = format!("Signal={d}\r\nDuration=160\r\n");
                    self.send_in_dialog(
                        id,
                        "INFO",
                        &[],
                        Some(("application/dtmf-relay", &body)),
                        Purpose::Info(id),
                    );
                }
                self.event(
                    "dtmf",
                    Some(id),
                    Some(ai),
                    format!("sent {digits} as SIP INFO"),
                );
            }
        }
    }

    fn blind_transfer(&mut self, id: u32, target: &str) {
        let Some(l) = self.lines.get(&id) else { return };
        if l.state != LState::Connected {
            return;
        }
        let uri = sipmsg::target_uri(&l.profile, sipmsg::parse_dial_string(target).0.as_str());
        let aor = sipmsg::aor(&l.profile);
        let ai = l.acc;
        let extra = vec![
            (
                sipmsg::hn(&l.profile.behavior, "Refer-To").to_string(),
                format!("<{uri}>"),
            ),
            (
                sipmsg::hn(&l.profile.behavior, "Referred-By").to_string(),
                format!("<{aor}>"),
            ),
        ];
        if let Some(l) = self.lines.get_mut(&id) {
            l.transfer = Some(format!("blind transfer to {uri}: REFER sent"));
            l.transfer_kind = Some("blind");
        }
        self.send_in_dialog(id, "REFER", &extra, None, Purpose::Refer(id));
        self.event(
            "transfer",
            Some(id),
            Some(ai),
            format!("blind transfer to {uri}"),
        );
    }

    fn attended_transfer(&mut self, a: u32, b: u32) {
        let (Some(la), Some(lb)) = (self.lines.get(&a), self.lines.get(&b)) else {
            return;
        };
        if la.state != LState::Connected || lb.state != LState::Connected {
            self.event(
                "error",
                Some(a),
                None,
                "attended transfer needs two connected calls",
            );
            return;
        }
        let replaces = format!(
            "{};to-tag={};from-tag={}",
            lb.call_id, lb.remote_tag, lb.local_tag
        );
        let target = lb.remote_uri.clone();
        let refer_to = format!("<{}?Replaces={}>", target, sipmsg::pct_encode(&replaces));
        let aor = sipmsg::aor(&la.profile);
        let ai = la.acc;
        let hb = la.profile.behavior.clone();
        let extra = vec![
            (sipmsg::hn(&hb, "Refer-To").to_string(), refer_to),
            (
                sipmsg::hn(&hb, "Referred-By").to_string(),
                format!("<{aor}>"),
            ),
        ];
        if let Some(l) = self.lines.get_mut(&a) {
            l.transfer = Some(format!("attended transfer to line {b}: REFER sent"));
            l.transfer_kind = Some("attended");
        }
        self.send_in_dialog(a, "REFER", &extra, None, Purpose::Refer(a));
        self.event(
            "transfer",
            Some(a),
            Some(ai),
            format!("attended transfer: line {a} to line {b} ({target})"),
        );
    }

    /// NOTIFY with the progress of a call made because of an incoming REFER.
    fn notify_refer(&mut self, id: u32, code: u16, reason: &str, terminated: bool) {
        let Some(l) = self.lines.get(&id) else { return };
        if !matches!(l.state, LState::Connected | LState::Ending) {
            return;
        }
        let body = format!("SIP/2.0 {code} {reason}\r\n");
        let state = if terminated {
            "terminated;reason=noresource".to_string()
        } else {
            "active;expires=60".to_string()
        };
        let extra = vec![
            ("Event".to_string(), "refer".to_string()),
            ("Subscription-State".to_string(), state),
        ];
        self.send_in_dialog(
            id,
            "NOTIFY",
            &extra,
            Some(("message/sipfrag;version=2.0", &body)),
            Purpose::Notify,
        );
    }

    // ----- responses

    fn on_response(&mut self, ai: usize, m: SipMessage, from: SocketAddr) {
        let _ = from;
        let Some(branch) = m.top_via().and_then(|v| v.branch) else {
            return;
        };
        let method = m.cseq().map(|c| c.1).unwrap_or_default();
        let code = m.status().unwrap_or(0);
        let key = (branch.clone(), method.clone());
        let Some(tx) = self.txs.get_mut(&key) else {
            // Retransmitted 2xx for an INVITE: re-send our ACK.
            if method == "INVITE" && (200..300).contains(&code) {
                let cid = m.call_id().unwrap_or("").to_string();
                if let Some(l) = self.lines.values().find(|l| l.call_id == cid) {
                    if let Some(ack) = l.ack_text.clone() {
                        let (a, d) = (l.acc, l.dest);
                        self.send_raw(a, &ack, d);
                    }
                }
            }
            return;
        };
        if let Some((_, ack)) = &tx.completed {
            // Retransmitted final response of a completed INVITE transaction.
            if code >= 300 {
                let (a, ack, d) = (tx.acc, ack.clone(), tx.dest);
                self.send_raw(a, &ack, d);
            }
            return;
        }
        if code < 200 {
            tx.provisional = true;
            if !tx.invite {
                tx.interval = Duration::from_secs(4);
            }
            let purpose = tx.purpose.clone();
            if let Purpose::Invite(id) = purpose {
                self.invite_provisional(id, &m);
            }
            return;
        }
        // Authentication challenge: repeat with credentials (twice at most).
        if code == 401 || code == 407 {
            let challenge = if code == 401 {
                m.header("WWW-Authenticate")
            } else {
                m.header("Proxy-Authenticate")
            }
            .map(|s| s.to_string());
            let tx = self.txs.remove(&key).unwrap();
            if let (true, Purpose::Invite(id)) = (tx.invite, &tx.purpose) {
                if let Some(text) = self.send_ack_non2xx(*id, &m) {
                    let done = ClientTx {
                        completed: Some((Instant::now(), text)),
                        ..tx_clone_shallow(&tx)
                    };
                    self.txs.insert(key.clone(), done);
                }
            }
            if let Some(ch) = challenge {
                if tx.auth_tries < 2 && self.retry_with_auth(tx, &ch, code, &m) {
                    return;
                }
            }
            self.fail_purpose_auth(ai, &m);
            self.dirty = true;
            return;
        }
        let tx = self.txs.remove(&key).unwrap();
        match tx.purpose.clone() {
            Purpose::Register(ai) => self.register_result(ai, &m),
            Purpose::Invite(id) => {
                if code >= 300 {
                    let ack = self.send_ack_non2xx(id, &m).unwrap_or_default();
                    self.txs.insert(
                        key,
                        ClientTx {
                            completed: Some((Instant::now(), ack)),
                            ..tx
                        },
                    );
                }
                self.invite_final(id, &m);
            }
            Purpose::Cancel => {}
            Purpose::Bye(id) => {
                let rs = reason_of(&m);
                if code >= 300 {
                    self.event(
                        "call",
                        Some(id),
                        Some(ai),
                        format!("BYE answered {code} {rs}"),
                    );
                }
                self.end_line(id, None, None, "local");
            }
            Purpose::ReInvite(id, hold) => {
                if (200..300).contains(&code) {
                    // ACK for the re-INVITE 2xx.
                    let cseq = m.cseq().map(|c| c.0);
                    if let Some((text, _, dest, a)) =
                        self.dialog_request(id, "ACK", &[], None, cseq)
                    {
                        self.send_raw(a, &text, dest);
                    }
                    if m.has_sdp() {
                        if let Some(sd) = sdp::parse(&m.body) {
                            self.apply_remote_sdp(id, &sd, from.ip());
                        }
                    }
                    let text = format!("{} confirmed", if hold { "hold" } else { "resume" });
                    if let Some(l) = self.lines.get_mut(&id) {
                        l.action = Some((
                            format!(
                                "{} accepted by the PBX ({code})",
                                if hold { "Hold" } else { "Resume" }
                            ),
                            true,
                        ));
                    }
                    self.event("call", Some(id), Some(ai), text);
                } else {
                    // Revert the local state.
                    if let Some(l) = self.lines.get_mut(&id) {
                        l.local_hold = !hold;
                        if let Some(r) = &l.rtp {
                            r.ctl.hold.store(!hold, Ordering::Relaxed);
                        }
                    }
                    let rs = reason_of(&m);
                    let what = if hold { "Hold" } else { "Resume" };
                    let text = refusal(what, "re-INVITE", code, &rs);
                    if let Some(l) = self.lines.get_mut(&id) {
                        l.action = Some((text.clone(), false));
                    }
                    self.event("error", Some(id), Some(ai), text);
                    if code == 481 || code == 408 {
                        self.end_line(id, Some(code), Some("dialog lost".into()), "remote");
                    }
                }
                if let Some(l) = self.lines.get_mut(&id) {
                    l.reinvite_pending = false;
                }
                self.route_audio();
            }
            Purpose::Info(id) => {
                if code >= 300 {
                    let rs = reason_of(&m);
                    if let Some(l) = self.lines.get_mut(&id) {
                        l.action = Some((refusal("DTMF by SIP INFO", "INFO", code, &rs), false));
                    }
                    self.event(
                        "dtmf",
                        Some(id),
                        Some(ai),
                        format!("INFO answered {code} {rs}"),
                    );
                }
            }
            Purpose::Refer(id) => {
                let rs = reason_of(&m);
                let ok = (200..300).contains(&code);
                let text = if ok {
                    format!("REFER accepted ({code}), waiting for NOTIFY")
                } else {
                    refusal("Transfer", "REFER", code, &rs)
                };
                if let Some(l) = self.lines.get_mut(&id) {
                    l.transfer = Some(text.clone());
                    l.action = Some((
                        if ok {
                            format!("Transfer accepted by the PBX ({code}), waiting for the result")
                        } else {
                            text.clone()
                        },
                        ok,
                    ));
                }
                self.event("transfer", Some(id), Some(ai), text);
            }
            Purpose::Options(k) => {
                let rtt = tx.start.elapsed().as_millis() as u64;
                let summary = format!(
                    "{} {} in {rtt} ms{}",
                    code,
                    reason_of(&m),
                    m.header("User-Agent")
                        .or(m.header("Server"))
                        .map(|s| format!(", {s}"))
                        .unwrap_or_default()
                );
                self.event("diag", None, Some(ai), format!("OPTIONS: {summary}"));
                if let Some((_, s)) = options_waiters().lock().unwrap().remove(&k) {
                    let _ = s.send(Some((code, rtt, summary)));
                }
            }
            Purpose::Subscribe(cid) => self.subscribe_result(&cid, &m),
            Purpose::Message(t) => {
                let text = if (200..300).contains(&code) {
                    format!("message to {t} delivered ({code} {})", reason_of(&m))
                } else {
                    format!("MESSAGE to {t} refused: {code} {}", reason_of(&m))
                };
                self.event("message", None, Some(ai), text);
            }
            Purpose::Publish(ai) => self.publish_result(ai, &m),
            Purpose::Notify | Purpose::Prack | Purpose::Update => {}
        }
        self.dirty = true;
    }

    fn fail_purpose_auth(&mut self, ai: usize, m: &SipMessage) {
        let code = m.status().unwrap_or(0);
        let method = m.cseq().map(|c| c.1).unwrap_or_default();
        if method == "REGISTER" {
            self.register_result(ai, m);
        } else if method == "INVITE" {
            let cid = m.call_id().unwrap_or("").to_string();
            if let Some(id) = self.lines.values().find(|l| l.call_id == cid).map(|l| l.id) {
                self.end_line(
                    id,
                    Some(code),
                    Some("authentication failed: check the user, auth user and password".into()),
                    "remote",
                );
            }
        } else {
            if method == "PUBLISH" {
                if let Some(p) = self.accs.get_mut(ai).and_then(|a| a.publication.as_mut()) {
                    p.error = Some(format!("authentication failed ({code})"));
                    p.next = None;
                }
            }
            self.event(
                "error",
                None,
                Some(ai),
                format!("{method} needs authentication that failed ({code})"),
            );
            if method == "BYE" {
                let cid = m.call_id().unwrap_or("").to_string();
                if let Some(id) = self.lines.values().find(|l| l.call_id == cid).map(|l| l.id) {
                    self.end_line(id, None, None, "local");
                }
            }
        }
    }

    /// Re-sends a request with credentials. Returns false if no password is set.
    fn retry_with_auth(
        &mut self,
        tx: ClientTx,
        challenge: &str,
        code: u16,
        m: &SipMessage,
    ) -> bool {
        let ai = tx.acc;
        let a = &mut self.accs[ai];
        let Some(pass) = a
            .cfg
            .profile
            .account
            .password
            .clone()
            .filter(|p| !p.is_empty())
        else {
            return false;
        };
        let user = a
            .cfg
            .profile
            .account
            .auth_user
            .clone()
            .filter(|u| !u.is_empty())
            .unwrap_or_else(|| a.cfg.profile.account.user.clone());
        a.nc += 1;
        let nc = a.nc;
        let hdr = if code == 401 {
            "Authorization"
        } else {
            "Proxy-Authorization"
        };
        let ruri = tx.text.split_whitespace().nth(1).unwrap_or("").to_string();
        let auth = digest_authorization(challenge, &tx.method, &ruri, &user, &pass, nc);
        let old_branch = m.top_via().and_then(|v| v.branch).unwrap_or_default();
        let new_b = new_branch();
        let (n, meth) = m.cseq().unwrap_or((1, tx.method.clone()));
        let mut text = tx.text.replacen(&old_branch, &new_b, 1);
        // Drop an older credential of the same kind before adding the new one.
        let lines: Vec<&str> = text.split("\r\n").collect();
        let mut kept = Vec::new();
        for (i, l) in lines.iter().enumerate() {
            let lower = l.to_ascii_lowercase();
            if i > 0
                && (lower.starts_with("authorization:")
                    || lower.starts_with("proxy-authorization:"))
                && lower.starts_with(&hdr.to_ascii_lowercase())
            {
                continue;
            }
            kept.push(*l);
        }
        text = kept.join("\r\n");
        text = text.replacen(
            &format!("CSeq: {n} {meth}"),
            &format!("CSeq: {} {meth}", n + 1),
            1,
        );
        text = insert_header(&text, hdr, &auth);
        // Keep CSeq counters in step.
        match &tx.purpose {
            Purpose::Register(ai) => self.accs[*ai].reg_cseq = n + 1,
            Purpose::Invite(id) => {
                if let Some(l) = self.lines.get_mut(id) {
                    l.invite_cseq = n + 1;
                    l.cseq = n + 1;
                    l.invite_branch = new_b.clone();
                }
            }
            Purpose::Bye(id)
            | Purpose::ReInvite(id, _)
            | Purpose::Info(id)
            | Purpose::Refer(id) => {
                if let Some(l) = self.lines.get_mut(id) {
                    l.cseq = l.cseq.max(n + 1);
                }
            }
            _ => {}
        }
        let tries = tx.auth_tries + 1;
        let purpose = tx.purpose.clone();
        let method = tx.method.clone();
        self.start_tx(ai, &method, &new_b, text, tx.dest, purpose);
        if let Some(t) = self.txs.get_mut(&(new_b, method)) {
            t.auth_tries = tries;
        }
        true
    }

    fn register_result(&mut self, ai: usize, m: &SipMessage) {
        let code = m.status().unwrap_or(0);
        let retry = Duration::from_secs(self.accs[ai].cfg.retry_s.max(5) as u64);
        let reason = reason_of(m);
        let a = &mut self.accs[ai];
        a.code = Some(code);
        a.reason = Some(reason.clone());
        if let Some(v) = m.top_via() {
            if let Some(rcv) = v.received.clone() {
                let port = v
                    .rport
                    .clone()
                    .filter(|p| !p.is_empty())
                    .unwrap_or_else(|| a.local.port().to_string());
                a.public = Some(format!("{rcv}:{port}"));
            } else if let Some(rp) = v.rport.clone().filter(|p| !p.is_empty()) {
                a.public = Some(format!("{}:{rp}", a.local.ip()));
            }
        }
        if (200..300).contains(&code) {
            if a.reg_expires == 0 {
                a.state = "off";
                a.expires_at = None;
                a.next_reg = None;
                self.event("reg", None, Some(ai), "unregistered");
                return;
            }
            // Expiry granted: our Contact's expires param, else Expires header.
            let mine = format!("{}", a.local);
            let granted = m
                .header_values("Contact")
                .iter()
                .find(|c| c.contains(&mine))
                .and_then(|c| sip::param(c, "expires"))
                .and_then(|e| e.parse::<u64>().ok())
                .or_else(|| m.header("Expires").and_then(|e| e.trim().parse().ok()))
                .unwrap_or(a.reg_expires as u64)
                .max(1);
            a.state = "registered";
            a.error = None;
            a.expires_at = Some(Instant::now() + Duration::from_secs(granted));
            // Refresh at about 90% of the interval, at least 5 s before expiry.
            let refresh = (granted * 9 / 10).min(granted.saturating_sub(5)).max(1);
            a.next_reg = Some(Instant::now() + Duration::from_secs(refresh));
            let nat = match &a.public {
                Some(p) if *p != a.local.to_string() => format!("; server sees us as {p} (NAT)"),
                _ => String::new(),
            };
            self.event(
                "reg",
                None,
                Some(ai),
                format!("registered for {granted} s{nat}"),
            );
            self.ensure_subs(ai);
        } else if code == 423 {
            let min = m
                .header("Min-Expires")
                .and_then(|v| v.trim().parse::<u32>().ok())
                .unwrap_or(3600);
            self.event(
                "reg",
                None,
                Some(ai),
                format!("423 Interval Too Brief, retrying with {min} s"),
            );
            self.send_register(ai, min, None);
        } else {
            let unreg = a.reg_expires == 0;
            a.state = if unreg { "off" } else { "failed" };
            a.expires_at = None;
            a.next_reg = if unreg {
                None
            } else {
                Some(Instant::now() + retry)
            };
            let hint = sip::status_hint(code);
            self.event(
                "reg",
                None,
                Some(ai),
                format!("REGISTER failed: {code} {reason}. {hint}"),
            );
        }
    }

    fn invite_provisional(&mut self, id: u32, m: &SipMessage) {
        let code = m.status().unwrap_or(0);
        let Some(l) = self.lines.get_mut(&id) else {
            return;
        };
        let ai = l.acc;
        if l.cancel_wanted && l.cancel_sent.is_none() {
            l.cancel_wanted = false;
            self.cancel(id);
            return;
        }
        if code > 100 {
            if let Some(t) = m.to_tag() {
                if l.remote_tag.is_empty() {
                    l.remote_tag = t;
                }
            }
            if let Some(c) = m.header("Contact").and_then(sipmsg::uri_from_contact) {
                l.remote_target = c;
            }
            if l.state == LState::Calling {
                l.state = if m.has_sdp() {
                    LState::Early
                } else {
                    LState::Ringing
                };
            }
            if m.has_sdp() && l.state != LState::Ending {
                l.state = LState::Early;
                if let Some(sd) = sdp::parse(&m.body) {
                    self.apply_remote_sdp(id, &sd, l_dest_ip(&self.lines[&id]));
                }
            }
            let rs = reason_of(m);
            self.event("call", Some(id), Some(ai), format!("{code} {rs}"));
        }
        // PRACK for reliable provisionals (RFC 3262).
        let reliable = m
            .header("Require")
            .map(|r| r.contains("100rel"))
            .unwrap_or(false);
        if let (true, Some(rseq)) = (reliable, m.header("RSeq")) {
            let l = self.lines.get_mut(&id).unwrap();
            let route_set: Vec<String> =
                m.header_values("Record-Route").into_iter().rev().collect();
            l.route_set = route_set.clone();
            let rack = format!("{} {} INVITE", rseq.trim(), l.invite_cseq);
            let rt = l.remote_target.clone();
            let fallback = l.invite_dest;
            let dest = self.dialog_dest(ai, &route_set, &rt, fallback);
            if let Some(l) = self.lines.get_mut(&id) {
                l.dest = dest;
            }
            self.send_in_dialog(id, "PRACK", &[("RAck".into(), rack)], None, Purpose::Prack);
        }
        self.dirty = true;
    }

    fn invite_final(&mut self, id: u32, m: &SipMessage) {
        let code = m.status().unwrap_or(0);
        let Some(l) = self.lines.get_mut(&id) else {
            return;
        };
        let ai = l.acc;
        if (200..300).contains(&code) {
            if l.state == LState::Connected {
                return;
            }
            l.remote_tag = m.to_tag().unwrap_or_default();
            if let Some(c) = m.header("Contact").and_then(sipmsg::uri_from_contact) {
                l.remote_target = c;
            }
            l.route_set = m.header_values("Record-Route").into_iter().rev().collect();
            let (rs, rt, fb) = (l.route_set.clone(), l.remote_target.clone(), l.invite_dest);
            let dest = self.dialog_dest(ai, &rs, &rt, fb);
            let l = self.lines.get_mut(&id).unwrap();
            l.dest = dest;
            let invite_cseq = l.invite_cseq;
            let cancelled = l.cancel_sent.is_some() || l.cancel_wanted;
            let skip_ack = l.profile.behavior.skip_ack;
            if let Some((ack, _, dest, a)) =
                self.dialog_request(id, "ACK", &[], None, Some(invite_cseq))
            {
                if skip_ack {
                    self.event(
                        "call",
                        Some(id),
                        Some(a),
                        "ACK deliberately skipped (skip_ack)",
                    );
                } else {
                    self.send_raw(a, &ack, dest);
                }
                if let Some(l) = self.lines.get_mut(&id) {
                    l.ack_text = if skip_ack { None } else { Some(ack) };
                }
            }
            let l = self.lines.get_mut(&id).unwrap();
            l.state = LState::Connected;
            l.answered_ms = Some(now_ms());
            l.focus = now_ms();
            l.final_code = Some(code);
            l.last_refresh = Instant::now();
            if let Some(p) = &mut l.post_dtmf {
                p.1 = Instant::now() + Duration::from_millis(1500);
            }
            let fallback = l.invite_dest.ip();
            if cancelled {
                self.event(
                    "call",
                    Some(id),
                    Some(ai),
                    "answered after CANCEL; hanging up",
                );
                self.send_bye(id, Some("cancelled".into()));
                return;
            }
            match sdp::parse(&m.body).filter(|_| m.has_sdp()) {
                Some(sd) => self.apply_remote_sdp(id, &sd, fallback),
                None => {
                    let has_early = self.lines[&id].remote_media.is_some();
                    if !has_early {
                        self.event(
                            "error",
                            Some(id),
                            Some(ai),
                            "2xx without SDP answer; no media",
                        );
                    }
                }
            }
            self.event("call", Some(id), Some(ai), "connected");
            // Notify the transferor when this call came from a REFER.
            if let Some(parent) = self.lines[&id].notify_line {
                self.notify_refer(parent, 200, "OK", true);
            }
            self.hold_others(id);
            self.route_audio();
        } else {
            let phrase = reason_of(m);
            let reason = match reason_header(m) {
                Some(r) => format!("{phrase} ({r})"),
                None => phrase,
            };
            let by = if code == 487 && (l.cancel_sent.is_some()) {
                "local"
            } else {
                "remote"
            };
            let hint = sip::status_hint(code);
            let text = if code == 487 && by == "local" {
                "cancelled".to_string()
            } else {
                format!("{code} {reason}")
            };
            if code != 487 || by != "local" {
                self.event(
                    "call",
                    Some(id),
                    Some(ai),
                    format!("{code} {reason}. {hint}"),
                );
            }
            self.end_line(id, Some(code), Some(text), by);
        }
    }

    /// Starts or updates media from a remote SDP.
    fn apply_remote_sdp(&mut self, id: u32, sd: &Sdp, fallback: std::net::IpAddr) {
        let source = self.audio_source();
        let tap = self.rtp_tap();
        let Some(l) = self.lines.get_mut(&id) else {
            return;
        };
        let Some(m) = sd.media.iter().find(|m| m.kind == "audio") else {
            return;
        };
        let (_, held) = media_direction(sd);
        l.remote_hold = held;
        if m.port == 0 {
            return;
        }
        let mine = sipmsg::profile_codecs(&l.profile.behavior);
        let codec = m
            .formats
            .iter()
            .filter_map(|p| Codec::from_media(m, *p))
            .find(|c| mine.contains(c))
            .or_else(|| m.formats.iter().find_map(|p| Codec::from_media(m, *p)));
        let Some(codec) = codec else {
            let names = m.codec_names().join(", ");
            let acc = l.acc;
            self.event(
                "error",
                Some(id),
                Some(acc),
                format!("no common audio codec in the answer ({names})"),
            );
            return;
        };
        let remote_dtmf = telephone_event(m, codec.clock());
        let ip = m.address(sd).filter(|a| !a.is_unspecified());
        let remote = SocketAddr::new(ip.unwrap_or(fallback), m.port);
        let b = l.profile.behavior.clone();
        l.codec = Some(codec);
        l.remote_dtmf = remote_dtmf;
        let started = l.remote_media.is_some();
        let changed = l.remote_media != Some(remote) && ip.is_some();
        if ip.is_some() {
            l.remote_media = Some(remote);
        }
        // SRTP: the answer to our offer carries the far end's key.
        let mut srtp_missing = false;
        if !started && l.dtls_offer && l.dtls_client.is_none() {
            if wants_dtls(m) {
                // An answer must pick a role; actpass there is read as passive.
                let client = !m
                    .setup
                    .clone()
                    .unwrap_or_default()
                    .eq_ignore_ascii_case("active");
                if let Some(rtp) = l.rtp.as_mut() {
                    rtp.dtls = Some(crate::dtls::DtlsParams {
                        client,
                        remote_fingerprint: m.fingerprint.clone().unwrap_or_default(),
                    });
                }
                l.dtls_client = Some(client);
                l.srtp_on = true;
            } else {
                // The far end answered plain RTP: only acceptable when SRTP is optional.
                l.dtls_offer = false;
                srtp_missing = b.srtp == crate::profile::SrtpMode::Mandatory;
            }
        }
        if !started && !l.srtp_on && l.dtls_client.is_none() {
            if let Some((_, mine_km)) = l.srtp_local.clone() {
                match offered_crypto(m) {
                    Some((_, remote_km)) => {
                        if let Some(rtp) = l.rtp.as_mut() {
                            rtp.srtp = Some((mine_km, remote_km));
                        }
                        l.srtp_on = true;
                    }
                    None => srtp_missing = b.srtp == crate::profile::SrtpMode::Mandatory,
                }
            }
        }
        let srtp_on = l.srtp_on;
        let dtls_on = l.dtls_client.is_some();
        if let Some(rtp) = l.rtp.as_mut() {
            if !started && ip.is_some() {
                let dtmf_pt = if b.dtmf_mode == DtmfMode::Rfc4733 {
                    remote_dtmf
                } else {
                    None
                };
                rtp.start(
                    remote,
                    codec,
                    b.ptime_ms,
                    source,
                    dtmf_pt,
                    b.symmetric_rtp,
                    tap,
                );
                let acc = l.acc;
                let local = rtp.local;
                self.event(
                    "media",
                    Some(id),
                    Some(acc),
                    format!(
                        "{} {local} <-> {remote} {}",
                        if dtls_on {
                            "DTLS-SRTP"
                        } else if srtp_on {
                            "SRTP"
                        } else {
                            "RTP"
                        },
                        codec.name()
                    ),
                );
            } else if changed {
                *rtp.ctl.remote.lock().unwrap() = Some(remote);
                let acc = l.acc;
                self.event(
                    "media",
                    Some(id),
                    Some(acc),
                    format!("media moved to {remote}"),
                );
            }
        }
        if srtp_missing {
            self.event(
                "error",
                Some(id),
                None,
                "SRTP is mandatory on this account but the answer has no SRTP keys (a=crypto or a=fingerprint); hanging up",
            );
            self.send_bye(id, Some("SRTP not accepted by the far end".into()));
        }
        self.route_audio();
    }

    // ----- requests

    fn on_request(&mut self, ai: usize, m: SipMessage, from: SocketAddr) {
        let method = m.method().unwrap_or("").to_string();
        let call_id = m.call_id().unwrap_or("").to_string();
        let line_id = self
            .lines
            .values()
            .find(|l| l.call_id == call_id && l.call_id_matches(&m))
            .map(|l| l.id);
        match method.as_str() {
            "INVITE" if m.to_tag().is_none() => self.incoming_invite(ai, m, from),
            "INVITE" | "UPDATE" => match line_id {
                Some(id) => self.incoming_reinvite(ai, id, &m, from),
                None => {
                    self.respond(
                        ai,
                        &m,
                        from,
                        481,
                        "Call/Transaction Does Not Exist",
                        None,
                        &[],
                        None,
                    );
                }
            },
            "ACK" => {
                if let Some(id) = line_id {
                    let l = self.lines.get_mut(&id).unwrap();
                    l.uas_2xx = None;
                    // Late offer: the SDP answer comes in the ACK.
                    if m.has_sdp() && l.remote_media.is_none() {
                        if let Some(sd) = sdp::parse(&m.body) {
                            self.apply_remote_sdp(id, &sd, from.ip());
                        }
                    }
                }
            }
            "CANCEL" => {
                let branch = m.top_via().and_then(|v| v.branch);
                let target = self
                    .lines
                    .values()
                    .find(|l| {
                        l.call_id == call_id
                            && l.state == LState::Incoming
                            && l.invite_req_branch == branch
                    })
                    .map(|l| l.id);
                match target {
                    Some(id) => {
                        self.respond(ai, &m, from, 200, "OK", None, &[], None);
                        let l = &self.lines[&id];
                        let (req, ifrom, tag) = (
                            l.invite_req.clone().unwrap(),
                            l.invite_from.unwrap(),
                            l.local_tag.clone(),
                        );
                        let text = self.respond(
                            ai,
                            &req,
                            ifrom,
                            487,
                            "Request Terminated",
                            Some(&tag),
                            &[],
                            None,
                        );
                        if let Some(l) = self.lines.get_mut(&id) {
                            l.last_resp = Some(text);
                        }
                        self.end_line(
                            id,
                            Some(487),
                            Some("caller hung up (missed)".into()),
                            "remote",
                        );
                    }
                    None => {
                        self.respond(
                            ai,
                            &m,
                            from,
                            481,
                            "Call/Transaction Does Not Exist",
                            None,
                            &[],
                            None,
                        );
                    }
                }
            }
            "BYE" => match line_id {
                Some(id) => {
                    self.respond(ai, &m, from, 200, "OK", None, &[], None);
                    let reason = reason_header(&m);
                    if let Some(l) = self.lines.get_mut(&id) {
                        l.reason = reason.or(Some("remote hung up".into()));
                    }
                    self.end_line(id, None, None, "remote");
                }
                None => {
                    self.respond(
                        ai,
                        &m,
                        from,
                        481,
                        "Call/Transaction Does Not Exist",
                        None,
                        &[],
                        None,
                    );
                }
            },
            "INFO" => {
                self.respond(ai, &m, from, 200, "OK", None, &[], None);
                if let Some(id) = line_id {
                    let body = m.body.clone();
                    let digit = body
                        .lines()
                        .find_map(|l| {
                            l.trim()
                                .strip_prefix("Signal=")
                                .or_else(|| l.trim().strip_prefix("Signal ="))
                        })
                        .map(|s| s.trim().to_string())
                        .or_else(|| {
                            // application/dtmf: the body is the digit.
                            if m.content_type().as_deref() == Some("application/dtmf") {
                                Some(body.trim().to_string())
                            } else {
                                None
                            }
                        });
                    if let Some(d) = digit {
                        if let Some(l) = self.lines.get_mut(&id) {
                            l.dtmf_rx.push_str(&d);
                        }
                        self.event(
                            "dtmf",
                            Some(id),
                            Some(ai),
                            format!("received {d} via SIP INFO"),
                        );
                    }
                }
            }
            "NOTIFY" => {
                self.respond(ai, &m, from, 200, "OK", None, &[], None);
                let event_hdr = m.header("Event").unwrap_or("");
                let event = event_hdr.to_ascii_lowercase();
                if event.starts_with("dialog")
                    || event.starts_with("presence")
                    || event.starts_with(MWI_EVENT)
                {
                    self.blf_notify(&m);
                }
                if event.starts_with(MWI_EVENT) {
                    if let Some(v) = parse_mwi(&m.body) {
                        if self.accs[ai].mwi.as_ref() != Some(&v) {
                            let text = if v.waiting {
                                format!("voicemail: {} new, {} old", v.new, v.old)
                            } else {
                                "voicemail: no new messages".to_string()
                            };
                            self.accs[ai].mwi = Some(v);
                            self.event("voicemail", None, Some(ai), text);
                        }
                    }
                }
                if let (Some(id), true) = (line_id, event.starts_with("refer")) {
                    let frag = m.body.lines().next().unwrap_or("").trim().to_string();
                    let code: u16 = frag
                        .split_whitespace()
                        .nth(1)
                        .and_then(|c| c.parse().ok())
                        .unwrap_or(0);
                    let text = format!("transfer progress: {frag}");
                    if let Some(l) = self.lines.get_mut(&id) {
                        l.transfer = Some(if (200..300).contains(&code) {
                            "transfer completed".into()
                        } else if code >= 300 {
                            format!("transfer failed: {frag}")
                        } else {
                            text.clone()
                        });
                        if code >= 200 {
                            let reason = frag
                                .split_whitespace()
                                .skip(2)
                                .collect::<Vec<_>>()
                                .join(" ");
                            l.action = Some(if code < 300 {
                                ("Transfer completed".into(), true)
                            } else {
                                (
                                    refusal("Transfer", "the transfer target", code, &reason),
                                    false,
                                )
                            });
                        }
                    }
                    self.event("transfer", Some(id), Some(ai), text);
                    if (200..300).contains(&code) {
                        let st = self.lines.get(&id).map(|l| l.state);
                        if st == Some(LState::Connected) {
                            self.send_bye(id, Some("transferred".into()));
                        }
                    }
                }
                if is_provision_resync(event_hdr) {
                    let has_url = self.accs[ai]
                        .cfg
                        .provision_url
                        .as_ref()
                        .is_some_and(|s| !s.is_empty());
                    let pending = self.accs[ai].resync_pending;
                    let live_other = self
                        .lines
                        .values()
                        .filter(|l| l.acc == ai && l.state.active())
                        .count();
                    match resync_gate(has_url, pending, ai, false, live_other) {
                        ResyncGate::Ignore => {
                            self.event(
                                "info",
                                None,
                                Some(ai),
                                "provisioning resync ignored: no provisioning URL",
                            );
                        }
                        ResyncGate::Wait => {
                            self.accs[ai].resync_pending = true;
                            if !pending {
                                self.event(
                                    "info",
                                    None,
                                    Some(ai),
                                    "provisioning will wait until the call ends",
                                );
                            }
                        }
                        ResyncGate::Emit => {
                            self.accs[ai].resync_pending = false;
                            self.event("resync", None, Some(ai), "provisioning resync");
                        }
                    }
                }
            }
            "REFER" => match line_id {
                Some(id) => self.incoming_refer(ai, id, &m, from),
                None => {
                    self.respond(
                        ai,
                        &m,
                        from,
                        481,
                        "Call/Transaction Does Not Exist",
                        None,
                        &[],
                        None,
                    );
                }
            },
            "OPTIONS" => {
                let extra = vec![
                    ("Allow".to_string(), "INVITE, ACK, CANCEL, BYE, OPTIONS, INFO, UPDATE, PRACK, REFER, NOTIFY, MESSAGE".to_string()),
                    ("Accept".to_string(), "application/sdp".to_string()),
                ];
                let busy = self.settings.dnd;
                if busy {
                    self.respond(ai, &m, from, 486, "Busy Here", None, &extra, None);
                } else {
                    self.respond(ai, &m, from, 200, "OK", None, &extra, None);
                }
            }
            "MESSAGE" => {
                self.respond(ai, &m, from, 200, "OK", None, &[], None);
                let who = m
                    .header("From")
                    .and_then(Uri::from_header)
                    .map(|u| u.short())
                    .unwrap_or_default();
                let body = m.body.chars().take(500).collect::<String>();
                self.event("message", None, Some(ai), format!("{who}: {body}"));
            }
            "PRACK" => {
                self.respond(ai, &m, from, 200, "OK", None, &[], None);
            }
            "SUBSCRIBE" | "PUBLISH" => {
                self.respond(ai, &m, from, 489, "Bad Event", None, &[], None);
            }
            "REGISTER" => {
                self.respond(ai, &m, from, 405, "Method Not Allowed", None, &[], None);
            }
            _ => {
                self.respond(ai, &m, from, 501, "Not Implemented", None, &[], None);
            }
        }
        self.dirty = true;
    }

    fn incoming_invite(&mut self, ai: usize, m: SipMessage, from: SocketAddr) {
        let call_id = m.call_id().unwrap_or("").to_string();
        let branch = m.top_via().and_then(|v| v.branch);
        // Retransmission: repeat the last response.
        if let Some(l) = self
            .lines
            .values()
            .find(|l| l.call_id == call_id && !l.outgoing && l.invite_req_branch == branch)
        {
            if let Some(r) = l.last_resp.clone() {
                let (a, f) = (l.acc, l.invite_from.unwrap_or(from));
                self.send_raw(a, &r, f);
            }
            return;
        }
        // Loop or a forked copy of our own call.
        if self
            .lines
            .values()
            .any(|l| l.call_id == call_id && l.outgoing)
        {
            self.respond(
                ai,
                &m,
                from,
                482,
                "Loop Detected",
                Some(&rand_hex(8)),
                &[],
                None,
            );
            return;
        }
        let id = self.next_line.fetch_add(1, Ordering::Relaxed);
        let p = self.accs[ai].cfg.profile.clone();
        let mut l = self.new_line(id, ai, p, false);
        l.call_id = call_id;
        l.remote_tag = m.from_tag().unwrap_or_default();
        l.remote_uri = m
            .header("From")
            .and_then(sipmsg::uri_from_contact)
            .unwrap_or_default();
        l.remote_name = m.header("From").and_then(sipmsg::display_name);
        l.local_uri = m
            .header("To")
            .and_then(sipmsg::uri_from_contact)
            .unwrap_or_else(|| sipmsg::aor(&l.profile));
        l.remote_target = m
            .header("Contact")
            .and_then(sipmsg::uri_from_contact)
            .unwrap_or_else(|| l.remote_uri.clone());
        l.route_set = m.header_values("Record-Route");
        l.remote_cseq = m.cseq().map(|c| c.0).unwrap_or(0);
        l.invite_from = Some(from);
        l.invite_req_branch = branch;
        l.offer = if m.has_sdp() {
            sdp::parse(&m.body)
        } else {
            None
        };
        l.cseq = 1;
        let (rs, rt) = (l.route_set.clone(), l.remote_target.clone());
        l.dest = self.dialog_dest(ai, &rs, &rt, from);
        l.invite_req = Some(m.clone());
        let tag = l.local_tag.clone();
        let who = format!(
            "{}{}",
            l.remote_name
                .clone()
                .map(|n| format!("{n} "))
                .unwrap_or_default(),
            Uri::parse(&l.remote_uri)
                .map(|u| format!("<{}>", u.short()))
                .unwrap_or_default()
        );
        self.lines.insert(id, l);
        self.respond(ai, &m, from, 100, "Trying", None, &[], None);

        // Replaces (attended transfer target side).
        if let Some(rep) = m.header("Replaces") {
            let rcid = rep.split(';').next().unwrap_or("").trim().to_string();
            let to_tag = sip::param(rep, "to-tag").unwrap_or_default();
            let target = self
                .lines
                .values()
                .find(|o| {
                    o.call_id == rcid && o.local_tag == to_tag && o.state == LState::Connected
                })
                .map(|o| o.id);
            match target {
                Some(old) => {
                    if let Some(l) = self.lines.get_mut(&id) {
                        l.replaces_line = Some(old);
                    }
                    self.event(
                        "transfer",
                        Some(id),
                        Some(ai),
                        format!("INVITE with Replaces for line {old}; answering"),
                    );
                    self.answer(id);
                }
                None => {
                    self.event(
                        "transfer",
                        Some(id),
                        Some(ai),
                        "INVITE with Replaces for an unknown dialog",
                    );
                    self.reject(id, 481);
                }
            }
            return;
        }
        let fwd = self.settings.forward_always.trim().to_string();
        if !fwd.is_empty() {
            self.forward(id, &fwd, "always");
            return;
        }
        let fwd_busy = self.settings.forward_busy.trim().to_string();
        let busy =
            self.settings.dnd || self.active_lines() > self.settings.max_lines.max(1) as usize;
        if busy && !fwd_busy.is_empty() {
            self.forward(
                id,
                &fwd_busy,
                if self.settings.dnd { "DND" } else { "busy" },
            );
            return;
        }
        if self.settings.dnd {
            self.event(
                "incoming",
                Some(id),
                Some(ai),
                format!("call from {who} rejected (DND)"),
            );
            let c = self.settings.dnd_code;
            self.reject(id, c);
            return;
        }
        if self.active_lines() > self.settings.max_lines.max(1) as usize {
            self.event(
                "incoming",
                Some(id),
                Some(ai),
                format!("call from {who} rejected: all lines busy"),
            );
            let c = self.settings.busy_code;
            self.reject(id, c);
            return;
        }
        let mine = sipmsg::profile_codecs(&self.lines[&id].profile.behavior);
        if let Some(o) = &self.lines[&id].offer {
            let ok = o.media.iter().any(|md| {
                md.kind == "audio"
                    && md.port != 0
                    && md
                        .formats
                        .iter()
                        .filter_map(|p| Codec::from_media(md, *p))
                        .any(|c| mine.contains(&c))
            });
            if !ok {
                let names: Vec<String> = o.media.iter().flat_map(|md| md.codec_names()).collect();
                self.event(
                    "incoming",
                    Some(id),
                    Some(ai),
                    format!(
                        "call from {who} rejected: no common codec ({})",
                        names.join(", ")
                    ),
                );
                self.reject(id, 488);
                return;
            }
        }
        let text = self.respond(ai, &m, from, 180, "Ringing", Some(&tag), &[], None);
        let intercom = self.settings.intercom
            && (m
                .header("Call-Info")
                .map(|c| c.to_ascii_lowercase().contains("answer-after"))
                .unwrap_or(false)
                || m.header("Alert-Info")
                    .map(|c| {
                        let c = c.to_ascii_lowercase();
                        c.contains("auto answer")
                            || c.contains("intercom")
                            || c.contains("autoanswer")
                    })
                    .unwrap_or(false));
        let delay = if intercom {
            Some(0)
        } else if self.settings.auto_answer {
            Some(self.settings.auto_answer_delay_ms)
        } else {
            None
        };
        if let Some(l) = self.lines.get_mut(&id) {
            l.last_resp = Some(text);
            l.auto_answer_at = delay.map(|d| Instant::now() + Duration::from_millis(d));
        }
        let note = match delay {
            Some(_) if intercom => " (intercom, answering)",
            Some(_) => " (auto answer)",
            None => "",
        };
        self.event(
            "incoming",
            Some(id),
            Some(ai),
            format!("incoming call from {who}{note}"),
        );
    }

    fn incoming_reinvite(&mut self, ai: usize, id: u32, m: &SipMessage, from: SocketAddr) {
        let is_update = m.method() == Some("UPDATE");
        let st = self.lines[&id].state;
        if !is_update && st != LState::Connected {
            self.respond(ai, m, from, 491, "Request Pending", None, &[], None);
            return;
        }
        if self.lines[&id].reinvite_pending && !is_update {
            self.respond(ai, m, from, 491, "Request Pending", None, &[], None);
            return;
        }
        let offer = if m.has_sdp() {
            sdp::parse(&m.body)
        } else {
            None
        };
        if let Some(c) = m.header("Contact").and_then(sipmsg::uri_from_contact) {
            if let Some(l) = self.lines.get_mut(&id) {
                l.remote_target = c;
            }
        }
        let body = match &offer {
            Some(sd) => {
                self.apply_remote_sdp(id, sd, from.ip());
                let l = self.lines.get_mut(&id).unwrap();
                l.sdp_ver += 1;
                let dir = match (l.local_hold, l.remote_hold) {
                    (false, false) => "sendrecv",
                    (true, false) => "sendonly",
                    (false, true) => "recvonly",
                    (true, true) => "inactive",
                };
                let text = format!(
                    "remote {}",
                    if l.remote_hold {
                        "put the call on hold"
                    } else {
                        "media update"
                    }
                );
                let b = self.line_offer(id, Some(dir));
                self.event("call", Some(id), Some(ai), text);
                Some(b)
            }
            None if !is_update => {
                // Offerless re-INVITE: we offer in the 200, answer arrives in ACK.
                let l = self.lines.get_mut(&id).unwrap();
                l.sdp_ver += 1;
                let dir = if l.local_hold { "sendonly" } else { "sendrecv" };
                Some(self.line_offer(id, Some(dir)))
            }
            None => None,
        };
        let mut extra = Vec::new();
        if let Some(se) = m.header("Session-Expires") {
            extra.push(("Session-Expires".to_string(), se.to_string()));
            extra.push(("Require".to_string(), "timer".to_string()));
        }
        let tag = self.lines[&id].local_tag.clone();
        let text = self.respond(
            ai,
            m,
            from,
            200,
            "OK",
            Some(&tag),
            &extra,
            body.as_deref().map(|b| ("application/sdp", b)),
        );
        if !is_update {
            let t1 = Duration::from_millis(self.lines[&id].profile.behavior.t1_ms.max(50));
            let l = self.lines.get_mut(&id).unwrap();
            l.uas_2xx = Some((text, from));
            l.uas_start = Instant::now();
            l.uas_interval = t1;
            l.uas_next = Instant::now() + t1;
        }
        self.route_audio();
    }

    fn incoming_refer(&mut self, ai: usize, id: u32, m: &SipMessage, from: SocketAddr) {
        let Some(refer_to) = m.header("Refer-To").map(|s| s.to_string()) else {
            self.respond(ai, m, from, 400, "Missing Refer-To", None, &[], None);
            return;
        };
        let tag = self.lines[&id].local_tag.clone();
        self.respond(ai, m, from, 202, "Accepted", Some(&tag), &[], None);
        let inner = match (refer_to.find('<'), refer_to.find('>')) {
            (Some(a), Some(b)) if b > a => refer_to[a + 1..b].to_string(),
            _ => refer_to.trim().to_string(),
        };
        let (target, headers) = match inner.find('?') {
            Some(i) => {
                let (_, h, _) = sipmsg::parse_dial_string(&inner);
                (inner[..i].to_string(), h)
            }
            None => (inner.clone(), Vec::new()),
        };
        let replaces = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("Replaces"))
            .map(|(_, v)| v.clone());
        self.event(
            "transfer",
            Some(id),
            Some(ai),
            format!("asked to transfer to {target}"),
        );
        self.notify_refer(id, 100, "Trying", false);
        let acc_id = self.accs[ai].cfg.id.clone();
        let nid = self.next_line.fetch_add(1, Ordering::Relaxed);
        self.set_hold(id, true);
        self.place_call(
            nid,
            CallRequest {
                account: Some(acc_id),
                target,
                headers: vec![(
                    "Referred-By".into(),
                    m.header("Referred-By").unwrap_or("").to_string(),
                )]
                .into_iter()
                .filter(|(_, v)| !v.is_empty())
                .collect(),
                overrides: None,
            },
            replaces,
        );
        if let Some(l) = self.lines.get_mut(&nid) {
            l.notify_line = Some(id);
        }
    }
}

impl Line {
    /// In-dialog requests match by Call-ID and, when known, the remote tag.
    fn call_id_matches(&self, m: &SipMessage) -> bool {
        if self.remote_tag.is_empty() {
            return true;
        }
        match m.from_tag() {
            Some(t) => {
                t == self.remote_tag || m.method() == Some("CANCEL") || m.method() == Some("ACK")
            }
            None => true,
        }
    }
}

fn l_dest_ip(l: &Line) -> std::net::IpAddr {
    l.invite_dest.ip()
}

fn tx_clone_shallow(tx: &ClientTx) -> ClientTx {
    ClientTx {
        acc: tx.acc,
        method: tx.method.clone(),
        text: tx.text.clone(),
        dest: tx.dest,
        invite: tx.invite,
        start: tx.start,
        next: tx.next,
        interval: tx.interval,
        provisional: tx.provisional,
        purpose: tx.purpose.clone(),
        auth_tries: tx.auth_tries,
        completed: None,
    }
}

#[cfg(test)]
mod provision_resync_tests {
    use super::{is_provision_resync, resync_gate, ResyncGate};

    #[test]
    fn is_provision_resync_cases() {
        assert!(!is_provision_resync("dialog"));
        assert!(!is_provision_resync("presence"));
        assert!(!is_provision_resync("refer"));
        assert!(!is_provision_resync("check-sync-extra"));
        assert!(is_provision_resync("check-sync;reboot=true"));
        assert!(is_provision_resync("resync"));
        assert!(is_provision_resync("ReSync"));
        assert!(is_provision_resync("CHECK-SYNC"));
    }

    #[test]
    fn resync_gate_cases() {
        assert_eq!(resync_gate(true, false, 0, true, 0), ResyncGate::Wait);
        assert_eq!(resync_gate(true, true, 0, false, 1), ResyncGate::Wait);
        assert_eq!(resync_gate(true, true, 0, false, 0), ResyncGate::Emit);
        assert_eq!(
            resync_gate(true, false, usize::MAX, false, 0),
            ResyncGate::Ignore
        );
        assert_eq!(resync_gate(false, false, 0, false, 0), ResyncGate::Ignore);
        assert_eq!(resync_gate(false, true, 0, false, 0), ResyncGate::Ignore);
    }
}

#[cfg(test)]
mod presence_tests {
    use super::{pidf_body, pidf_state};

    #[test]
    fn pidf_states() {
        // Asterisk, device state only.
        let ast = r#"<presence entity="sip:3001@pbx" xmlns="urn:ietf:params:xml:ns:pidf" xmlns:dm="urn:ietf:params:xml:ns:pidf:data-model" xmlns:rpid="urn:ietf:params:xml:ns:pidf:rpid">
 <note>Ready</note><tuple id="3001"><status><basic>open</basic></status></tuple><dm:person /></presence>"#;
        assert_eq!(pidf_state(ast), ("available".into(), Some("Ready".into())));
        let busy = r#"<presence xmlns="urn:ietf:params:xml:ns:pidf" xmlns:rpid="urn:ietf:params:xml:ns:pidf:rpid" xmlns:dm="urn:ietf:params:xml:ns:pidf:data-model">
 <note>On the phone</note><tuple id="x"><status><basic>open</basic></status></tuple>
 <dm:person><rpid:activities><rpid:on-the-phone/></rpid:activities></dm:person></presence>"#;
        assert_eq!(pidf_state(busy).0, "busy");
        assert_eq!(
            pidf_state(&busy.replace("on-the-phone/", "on-the-phone /")).0,
            "busy"
        );
        assert_eq!(pidf_state("<presence><tuple><status><basic>open</basic></status></tuple><activities><away/></activities></presence>").0, "away");
        // A note that merely mentions a word is not an activity.
        assert_eq!(pidf_state("<presence><note>away from desk soon</note><tuple><status><basic>open</basic></status></tuple></presence>").0, "available");
        // RFC 4480 style person element with a namespaced note.
        let away = r#"<presence xmlns="urn:ietf:params:xml:ns:pidf"><tuple id="t"><status><basic>open</basic></status></tuple>
 <dm:person id="p"><rpid:activities><rpid:away/></rpid:activities><dm:note>At lunch</dm:note></dm:person></presence>"#;
        assert_eq!(pidf_state(away), ("away".into(), Some("At lunch".into())));
        let closed =
            r#"<presence><tuple id="t"><status><basic>closed</basic></status></tuple></presence>"#;
        assert_eq!(pidf_state(closed).0, "offline");
        // What we publish reads back the same.
        let mine = pidf_body("sip:2001@pbx", "away", "Back at 3 <pm>");
        assert_eq!(
            pidf_state(&mine),
            ("away".into(), Some("Back at 3 <pm>".into()))
        );
        assert_eq!(
            pidf_state(&pidf_body("sip:a@b", "offline", "")).0,
            "offline"
        );
    }
}

#[cfg(test)]
mod mwi_tests {
    use super::parse_mwi;

    #[test]
    fn message_summary_bodies() {
        let v = parse_mwi(
            "Messages-Waiting: yes\r\nMessage-Account: sip:*97@pbx\r\nVoice-Message: 2/8 (0/2)\r\n",
        )
        .unwrap();
        assert!(v.waiting);
        assert_eq!((v.new, v.old), (2, 8));
        assert_eq!(v.account.as_deref(), Some("sip:*97@pbx"));
        let v = parse_mwi("Messages-Waiting: no\r\n").unwrap();
        assert!(!v.waiting && v.new == 0);
        assert!(parse_mwi("").is_none());
    }
}
