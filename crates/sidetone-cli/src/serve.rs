//! Local web UI + HTTP API. Same frontend as the WASM build, but analysis,
//! AI requests and test calls run natively on this machine.

use crate::aihttp;
use crate::phone;
use crate::provision;
use anyhow::{anyhow, Result};
use serde_json::{json, Value};
use sidetone_core::ai::AiConfig;
use sidetone_core::export::{export_pcapng, ExportOptions};
use sidetone_core::ladder::{render_svg, LadderOptions};
use sidetone_core::redact::RedactOptions;
use sidetone_core::{analyze_bytes, Report};
use sidetone_ua::{AudioSource, CallOptions, Profile, Tap, Ua};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;
use tiny_http::{Header, Method, Request, Response, Server};

const INDEX: &str = include_str!("../../../web/index.html");
const APP_JS: &str = include_str!("../../../web/app.js");
const STYLE: &str = include_str!("../../../web/style.css");
const WEBPHONE_JS: &str = include_str!("../../../web/webphone.js");
const CONTROLLERS_JS: &str = include_str!("../../../web/controllers.js");
const I18N_JS: &str = include_str!("../../../web/i18n.js");
const HELP_JS: &str = include_str!("../../../web/help.js");
const EXPLAIN_JS: &str = include_str!("../../../web/explain.js");
const FILTER_JS: &str = include_str!("../../../web/filter.js");
const FINDINGS_I18N_JS: &str = include_str!("../../../web/findings-i18n.js");
const FILTER_SUGGEST_JS: &str = include_str!("../../../web/filter-suggest.js");
const LANG_FR_JS: &str = include_str!("../../../web/lang-fr.js");
const LANG_ZH_JS: &str = include_str!("../../../web/lang-zh.js");
const LANG_HI_JS: &str = include_str!("../../../web/lang-hi.js");

fn header(k: &str, v: &str) -> Header {
    Header::from_bytes(k.as_bytes(), v.as_bytes()).expect("valid header")
}

fn query(url: &str) -> HashMap<String, String> {
    let mut m = HashMap::new();
    if let Some((_, q)) = url.split_once('?') {
        for kv in q.split('&') {
            let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
            m.insert(k.to_string(), urldecode(v));
        }
    }
    m
}

fn urldecode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < b.len() => {
                if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                    out.push(v);
                    i += 2;
                }
            }
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub fn b64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::with_capacity(data.len().div_ceil(3) * 4);
    for c in data.chunks(3) {
        let n = (c[0] as u32) << 16
            | (*c.get(1).unwrap_or(&0) as u32) << 8
            | *c.get(2).unwrap_or(&0) as u32;
        s.push(T[(n >> 18) as usize & 63] as char);
        s.push(T[(n >> 12) as usize & 63] as char);
        s.push(if c.len() > 1 {
            T[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        s.push(if c.len() > 2 {
            T[n as usize & 63] as char
        } else {
            '='
        });
    }
    s
}

fn call_param(r: &Report, q: &HashMap<String, String>) -> Option<usize> {
    q.get("call")
        .filter(|c| !c.is_empty())
        .and_then(|c| r.find_call(c))
}

fn flag(q: &HashMap<String, String>, k: &str) -> bool {
    matches!(q.get(k).map(|s| s.as_str()), Some("1") | Some("true"))
}

type Resp = Response<std::io::Cursor<Vec<u8>>>;

fn ok_bytes(data: Vec<u8>, ctype: &str) -> Resp {
    Response::from_data(data).with_header(header("Content-Type", ctype))
}

fn err(code: u16, msg: impl std::fmt::Display) -> Resp {
    Response::from_data(json!({"error": msg.to_string()}).to_string().into_bytes())
        .with_status_code(code)
        .with_header(header("Content-Type", "application/json"))
}

fn ua_from(v: &Value) -> Result<Ua> {
    let mut p: Profile = match v.get("profile") {
        Some(p) if !p.is_null() => {
            serde_json::from_value(p.clone()).map_err(|e| anyhow!("profile: {e}"))?
        }
        _ => Profile::default(),
    };
    if let Some(d) = v
        .get("domain")
        .and_then(|x| x.as_str())
        .filter(|x| !x.is_empty())
    {
        p.account.domain = d.into();
    }
    if let Some(u) = v
        .get("user")
        .and_then(|x| x.as_str())
        .filter(|x| !x.is_empty())
    {
        p.account.user = u.into();
    }
    if let Some(pw) = v
        .get("password")
        .and_then(|x| x.as_str())
        .filter(|x| !x.is_empty())
    {
        p.account.password = Some(pw.into());
    }
    Ua::new(p, Tap::new()).map_err(|e| anyhow!("{e}"))
}

/// Native "save as" hook supplied by the desktop app: (suggested name, bytes) -> saved path.
pub type SaveHook = std::sync::Arc<dyn Fn(&str, &[u8]) -> Result<Option<PathBuf>> + Send + Sync>;

/// Window hook supplied by the desktop app: "phone" makes the window compact,
/// "full" restores the troubleshooting layout.
pub type WindowHook = Box<dyn Fn(&str) + Send + Sync>;
pub static WINDOW_HOOK: std::sync::OnceLock<WindowHook> = std::sync::OnceLock::new();

/// File-open hook supplied by the desktop app: shows a native picker for the
/// given purpose ("client-cert", "ca-bundle", …) and returns the chosen path.
pub type OpenHook = Box<dyn Fn(&str) -> Option<PathBuf> + Send + Sync>;
pub static OPEN_HOOK: std::sync::OnceLock<OpenHook> = std::sync::OnceLock::new();

fn handle(
    req: &mut Request,
    web: &Option<PathBuf>,
    token: &Option<String>,
    save: &Option<SaveHook>,
) -> Resp {
    let url = req.url().to_string();
    let path = url.split('?').next().unwrap_or("/").to_string();
    let q = query(&url);
    if let (Some(t), true) = (token, path.starts_with("/api/")) {
        let hdr = req
            .headers()
            .iter()
            .find(|h| h.field.equiv("x-sidetone-token"))
            .map(|h| h.value.as_str().to_string());
        if hdr.as_deref() != Some(t.as_str()) && q.get("token") != Some(t) {
            return err(
                403,
                "missing or wrong token (open the URL printed at startup)",
            );
        }
    }
    let method = req.method().clone();
    let mut body = Vec::new();
    if method == Method::Post {
        if let Err(e) = req.as_reader().read_to_end(&mut body) {
            return err(400, e);
        }
    }
    let analyze = |b: &[u8]| analyze_bytes(b).map_err(|e| e.to_string());
    match (method, path.as_str()) {
        (Method::Get, "/api/info") => {
            let mut features = vec!["analyze", "export", "ai-proxy", "ua", "phone", "sniff"];
            if save.is_some() {
                features.push("native-save");
            }
            if WINDOW_HOOK.get().is_some() {
                features.push("window");
            }
            if OPEN_HOOK.get().is_some() {
                features.push("native-open");
            }
            ok_bytes(json!({"mode": "server", "version": env!("CARGO_PKG_VERSION"), "features": features}).to_string().into_bytes(), "application/json")
        }
        (Method::Post, "/api/window") => match WINDOW_HOOK.get() {
            Some(f) => {
                f(q.get("mode").map(|s| s.as_str()).unwrap_or("full"));
                json_resp(json!({"ok": true}))
            }
            None => err(404, "no window to resize"),
        },
        (Method::Post, "/api/save") => match save {
            Some(f) => match f(
                q.get("name").map(|s| s.as_str()).unwrap_or("sidetone.bin"),
                &body,
            ) {
                Ok(Some(p)) => ok_bytes(
                    json!({"saved": p.display().to_string()})
                        .to_string()
                        .into_bytes(),
                    "application/json",
                ),
                Ok(None) => ok_bytes(
                    json!({"saved": null}).to_string().into_bytes(),
                    "application/json",
                ),
                Err(e) => err(500, e),
            },
            None => err(404, "native save not available"),
        },
        (Method::Post, "/api/pick-file") => match OPEN_HOOK.get() {
            Some(f) => {
                let kind = q.get("kind").map(|s| s.as_str()).unwrap_or("");
                match f(kind) {
                    Some(p) => ok_bytes(
                        json!({ "path": p.display().to_string() })
                            .to_string()
                            .into_bytes(),
                        "application/json",
                    ),
                    None => ok_bytes(
                        json!({ "path": null }).to_string().into_bytes(),
                        "application/json",
                    ),
                }
            }
            None => err(404, "native file picker not available"),
        },
        (Method::Get, "/api/sample") => match sidetone_core::synth::generate(
            q.get("name").map(|s| s.as_str()).unwrap_or("demo"),
        ) {
            Some(b) => ok_bytes(b, "application/octet-stream"),
            None => err(404, "unknown sample"),
        },
        (Method::Post, "/api/sip-log-capture") => {
            let log: sidetone_core::synth::SipLog = match serde_json::from_slice(&body) {
                Ok(l) => l,
                Err(e) => return err(400, e),
            };
            match sidetone_core::synth::capture_from_log(&log) {
                Ok(b) => ok_bytes(b, "application/octet-stream"),
                Err(e) => err(400, e),
            }
        }
        (Method::Post, "/api/analyze") => match analyze(&body) {
            Ok(r) => ok_bytes(r.to_json().into_bytes(), "application/json"),
            Err(e) => err(422, e),
        },
        (Method::Post, "/api/rtp_audio") => {
            let id = q
                .get("stream")
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(0);
            match rtp_wav(&body, id) {
                Ok((wav, info)) => Response::from_data(wav)
                    .with_header(header("Content-Type", "audio/wav"))
                    .with_header(header("X-Sidetone-Audio", &info)),
                Err(e) => err(422, e),
            }
        }
        (Method::Post, "/api/ladder") => match analyze(&body) {
            Ok(r) => {
                let c = call_param(&r, &q);
                ok_bytes(
                    render_svg(
                        &r,
                        &LadderOptions {
                            call: c,
                            // calls=0,2,5: several dialogs (call legs) in one ladder.
                            calls: q
                                .get("calls")
                                .map(|v| {
                                    v.split(',').filter_map(|x| x.trim().parse().ok()).collect()
                                })
                                .unwrap_or_default(),
                            rtp_at_end: q.get("rtp").map(|v| v == "end").unwrap_or(false),
                            collapse_retransmissions: q.get("retx").is_some_and(|v| v == "fold"),
                            time: sidetone_core::ladder::TimeMode::parse(
                                q.get("time").map(String::as_str).unwrap_or(""),
                            ),
                            ..Default::default()
                        },
                    )
                    .into_bytes(),
                    "image/svg+xml",
                )
            }
            Err(e) => err(422, e),
        },
        (Method::Post, "/api/export") => match analyze(&body) {
            Ok(r) => {
                let opts = ExportOptions {
                    annotate: !flag(&q, "no_annotate"),
                    redact: if flag(&q, "redact") {
                        Some(RedactOptions::default())
                    } else {
                        None
                    },
                    call: call_param(&r, &q),
                    sip_only: flag(&q, "sip_only"),
                };
                ok_bytes(export_pcapng(&r, &opts), "application/octet-stream")
            }
            Err(e) => err(422, e),
        },
        (Method::Post, "/api/prompt") => {
            match analyze(&body) {
                Ok(r) => {
                    let red = if flag(&q, "redact") {
                        Some(RedactOptions::default())
                    } else {
                        None
                    };
                    let lang = q.get("lang").cloned().unwrap_or_else(|| "English".into());
                    let prompt = sidetone_core::ai::build_prompt(
                        &r,
                        call_param(&r, &q),
                        red.as_ref(),
                        q.get("question").map(|s| s.as_str()),
                    );
                    ok_bytes(json!({"system": sidetone_core::ai::system_prompt(&lang), "prompt": prompt}).to_string().into_bytes(), "application/json")
                }
                Err(e) => err(422, e),
            }
        }
        (Method::Post, "/api/ai") => {
            let v: Value = match serde_json::from_slice(&body) {
                Ok(v) => v,
                Err(e) => return err(400, e),
            };
            let cfg: AiConfig =
                match serde_json::from_value(v.get("config").cloned().unwrap_or(Value::Null)) {
                    Ok(c) => c,
                    Err(e) => return err(400, format!("config: {e}")),
                };
            let prompt = v.get("prompt").and_then(|p| p.as_str()).unwrap_or("");
            match aihttp::ask(&cfg, prompt) {
                Ok(text) => ok_bytes(
                    json!({"text": text}).to_string().into_bytes(),
                    "application/json",
                ),
                Err(e) => err(502, e),
            }
        }
        (Method::Post, "/api/options")
        | (Method::Post, "/api/call")
        | (Method::Post, "/api/register") => {
            let v: Value = match serde_json::from_slice(&body) {
                Ok(v) => v,
                Err(e) => return err(400, e),
            };
            let mut ua = match ua_from(&v) {
                Ok(u) => u,
                Err(e) => return err(400, e),
            };
            let target = v
                .get("target")
                .and_then(|t| t.as_str())
                .unwrap_or("")
                .to_string();
            if path != "/api/register"
                && v.get("register").and_then(|x| x.as_bool()).unwrap_or(false)
            {
                let _ = ua.register(None);
            }
            let result: Result<Value> = if path == "/api/register" {
                ua.register(None)
                    .map(|st| json!({"status": st}))
                    .map_err(|e| anyhow!("{e}"))
            } else if path == "/api/options" {
                ua.options(&target)
                    .map(|r| json!({"status": r.map(|x| x.0), "rtt_ms": r.map(|x| x.1)}))
                    .map_err(|e| anyhow!("{e}"))
            } else {
                let dur = v
                    .get("duration")
                    .and_then(|d| d.as_u64())
                    .unwrap_or(10)
                    .min(600);
                let audio = match v.get("audio").and_then(|a| a.as_str()) {
                    Some("echo") => AudioSource::Echo,
                    Some("silence") => AudioSource::Silence,
                    _ => AudioSource::Tone(440.0),
                };
                ua.call(&CallOptions {
                    target,
                    duration: Duration::from_secs(dur),
                    ring_timeout: Duration::from_secs(60),
                    audio,
                    dtmf: v
                        .get("dtmf")
                        .and_then(|d| d.as_str())
                        .map(|s| s.to_string()),
                })
                .map(|o| {
                    let wav = o.wav.as_ref().map(|w| b64(w));
                    json!({"outcome": o, "wav_b64": wav})
                })
                .map_err(|e| anyhow!("{e}"))
            };
            match result {
                Ok(mut r) => {
                    r["events"] = serde_json::to_value(&ua.events).unwrap_or(Value::Null);
                    r["local"] = json!(ua.local.to_string());
                    r["pcap_b64"] = json!(b64(&ua.tap.to_pcapng()));
                    ok_bytes(r.to_string().into_bytes(), "application/json")
                }
                Err(e) => err(500, e),
            }
        }
        (m, p) if p.starts_with("/api/sniff/") => sniff_api(&m, p, &q, &body),
        (m, p)
            if p.starts_with("/api/phone/")
                || p.starts_with("/api/audio/")
                || p.starts_with("/api/diag/")
                || p.starts_with("/api/config/") =>
        {
            phone_api(&m, p, &q, &body)
        }
        (Method::Get, p) => {
            let file = if p == "/" {
                "index.html"
            } else {
                p.trim_start_matches('/')
            };
            if file.contains("..") {
                return err(400, "bad path");
            }
            if let Some(dir) = web {
                if let Ok(data) = std::fs::read(dir.join(file)) {
                    return ok_bytes(data, mime(file));
                }
            }
            match file {
                "index.html" => ok_bytes(INDEX.as_bytes().to_vec(), "text/html; charset=utf-8"),
                "app.js" => ok_bytes(APP_JS.as_bytes().to_vec(), "text/javascript"),
                "style.css" => ok_bytes(STYLE.as_bytes().to_vec(), "text/css"),
                "webphone.js" => ok_bytes(WEBPHONE_JS.as_bytes().to_vec(), "text/javascript"),
                "controllers.js" => ok_bytes(CONTROLLERS_JS.as_bytes().to_vec(), "text/javascript"),
                "i18n.js" => ok_bytes(I18N_JS.as_bytes().to_vec(), "text/javascript"),
                "help.js" => ok_bytes(HELP_JS.as_bytes().to_vec(), "text/javascript"),
                "explain.js" => ok_bytes(EXPLAIN_JS.as_bytes().to_vec(), "text/javascript"),
                "filter.js" => ok_bytes(FILTER_JS.as_bytes().to_vec(), "text/javascript"),
                "findings-i18n.js" => {
                    ok_bytes(FINDINGS_I18N_JS.as_bytes().to_vec(), "text/javascript")
                }
                "filter-suggest.js" => {
                    ok_bytes(FILTER_SUGGEST_JS.as_bytes().to_vec(), "text/javascript")
                }
                "lang-fr.js" => ok_bytes(LANG_FR_JS.as_bytes().to_vec(), "text/javascript"),
                "lang-zh.js" => ok_bytes(LANG_ZH_JS.as_bytes().to_vec(), "text/javascript"),
                "lang-hi.js" => ok_bytes(LANG_HI_JS.as_bytes().to_vec(), "text/javascript"),
                _ => err(404, "not found"),
            }
        }
        _ => err(405, "method not allowed"),
    }
}

fn json_resp(v: Value) -> Resp {
    ok_bytes(v.to_string().into_bytes(), "application/json")
}

fn body_json(body: &[u8]) -> std::result::Result<Value, Resp> {
    if body.is_empty() {
        return Ok(json!({}));
    }
    serde_json::from_slice(body).map_err(|e| err(400, format!("bad JSON: {e}")))
}

/// Softphone, sound card and diagnostics endpoints.
fn phone_api(m: &Method, path: &str, q: &HashMap<String, String>, body: &[u8]) -> Resp {
    use sidetone_ua::{audio, dns, stun};
    let num = |k: &str| q.get(k).and_then(|v| v.parse::<u64>().ok());
    match (m, path) {
        (Method::Get, "/api/phone/state") => {
            let p = phone::get();
            let since = num("since").unwrap_or(0);
            let tsince = num("trace_since");
            let mut v = json!({
                "state": p.engine.state(),
                "events": p.engine.events_since(since),
            });
            if let Some(t) = tsince {
                v["trace"] = json!(p.engine.trace_since(t, 500));
            }
            json_resp(v)
        }
        (Method::Get, "/api/phone/trace") => {
            let p = phone::get();
            let since = num("since").unwrap_or(0);
            let limit = num("limit").unwrap_or(2000) as usize;
            json_resp(json!(p.engine.trace_since(since, limit)))
        }
        (Method::Post, "/api/phone/cmd") => {
            let v = match body_json(body) {
                Ok(v) => v,
                Err(r) => return r,
            };
            match phone::get().command(&v) {
                Ok(r) => json_resp(r),
                Err(e) => err(400, e),
            }
        }
        (Method::Get, "/api/phone/config") => json_resp(json!(phone::get().config())),
        (Method::Post, "/api/phone/config") => {
            let v = match body_json(body) {
                Ok(v) => v,
                Err(r) => return r,
            };
            match phone::get().set_config(&v) {
                Ok(()) => json_resp(json!({"ok": true, "config": phone::get().config()})),
                Err(e) => err(400, e),
            }
        }
        (Method::Post, "/api/phone/provision") => {
            let v = match body_json(body) {
                Ok(v) => v,
                Err(r) => return r,
            };
            let url = match v.get("url").and_then(|x| x.as_str()) {
                Some(u) if !u.is_empty() => u,
                _ => return err(400, "missing url"),
            };
            let tls_verify = v
                .get("tls_verify")
                .and_then(|x| x.as_bool())
                .unwrap_or(true);
            let mac = v
                .get("mac")
                .and_then(|x| x.as_str())
                .filter(|m| !m.trim().is_empty());
            match provision::fetch_provision(url, tls_verify, mac) {
                Ok(account) => json_resp(json!({"ok": true, "account": account})),
                Err(e) => err(400, e),
            }
        }
        // This computer's MAC, the default device MAC for {mac} in URLs.
        (Method::Get, "/api/phone/provision/mac") => {
            json_resp(json!({"mac": provision::device_mac(None)}))
        }
        // DHCPINFORM for options 66/150/160 (the servers phones are given).
        (Method::Post, "/api/phone/provision/discover") => {
            let v: Value = serde_json::from_slice(body).unwrap_or_default();
            let mac = provision::device_mac(v.get("mac").and_then(|x| x.as_str()));
            match crate::dhcp::discover(
                provision::mac_bytes(&mac),
                std::time::Duration::from_secs(4),
            ) {
                Ok(r) => json_resp(json!({"ok": true, "result": r})),
                Err(e) => err(400, e),
            }
        }
        // Diagnostics: fetch what a phone with this MAC would get, and say
        // what it is, without touching any account.
        (Method::Post, "/api/diag/provision") => {
            let v: Value = serde_json::from_slice(body).unwrap_or_default();
            let raw_url = v
                .get("url")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .trim()
                .to_string();
            if raw_url.is_empty() {
                return err(400, "missing url");
            }
            let mac = provision::device_mac(v.get("mac").and_then(|x| x.as_str()));
            let url = provision::expand_url(&raw_url, &mac);
            let tls = v
                .get("tls_verify")
                .and_then(|x| x.as_bool())
                .unwrap_or(true);
            let t0 = std::time::Instant::now();
            let res = provision::fetch_raw(&url, tls);
            let ms = t0.elapsed().as_millis() as u64;
            match res {
                Err(e) => json_resp(
                    json!({"ok": false, "url": provision::redact_url(&url), "mac": mac, "ms": ms, "error": e.to_string()}),
                ),
                Ok(body) => {
                    let text = String::from_utf8_lossy(&body).into_owned();
                    let format = sidetone_core::provision::detect_name(&text);
                    let parsed = sidetone_core::provision::parse(&text, "native");
                    let mut excerpt: String = text.chars().take(4000).collect();
                    // Passwords stay out of the preview.
                    excerpt = sidetone_core::provision::mask_secrets(&excerpt);
                    json_resp(json!({
                        "ok": parsed.is_ok(),
                        "url": provision::redact_url(&url),
                        "mac": mac,
                        "ms": ms,
                        "bytes": body.len(),
                        "format": format,
                        "excerpt": excerpt,
                        "account": parsed.as_ref().ok().map(|a| {
                            let mut a = a.clone();
                            if a.pointer("/profile/account/password").is_some_and(|p| !p.is_null()) {
                                a["profile"]["account"]["password"] = json!("•••");
                            }
                            a
                        }),
                        "error": parsed.err(),
                    }))
                }
            }
        }
        (Method::Get, "/api/phone/history") => json_resp(json!(phone::get().history_view())),
        (Method::Get, "/api/phone/history/capture") => {
            match phone::get().call_capture(q.get("call_id").map(|s| s.as_str()).unwrap_or("")) {
                Some(b) => ok_bytes(b, "application/vnd.tcpdump.pcap"),
                None => err(404, "no saved capture for this call"),
            }
        }
        (Method::Post, "/api/phone/history/delete") => {
            let ids: Vec<String> = serde_json::from_slice::<Value>(&body)
                .ok()
                .and_then(|v| v.get("call_ids").cloned())
                .and_then(|v| serde_json::from_value(v).ok())
                .unwrap_or_default();
            phone::get().delete_history(&ids);
            json_resp(json!({"ok": true, "deleted": ids.len()}))
        }
        (Method::Post, "/api/phone/history/clear") => {
            phone::get().clear_history();
            json_resp(json!({"ok": true}))
        }
        // Provisioning: fetch a sidetone-config file from a URL for the
        // Import screen (from here, so the page has no CORS limits).
        (Method::Get, "/api/config/fetch") => {
            match crate::aihttp::fetch_config(q.get("url").map(String::as_str).unwrap_or("")) {
                Ok(v) => json_resp(v),
                Err(e) => err(502, e.to_string()),
            }
        }
        (Method::Get, "/api/phone/capture") => {
            let e = &phone::get().engine;
            let b = if q.get("decrypted").is_some_and(|v| v == "1") {
                e.capture_decrypted()
            } else {
                e.capture()
            };
            ok_bytes(b, "application/octet-stream")
        }
        (Method::Get, "/api/phone/recording") => {
            match num("line").and_then(|l| phone::get().engine.recording(l as u32)) {
                Some(w) => ok_bytes(w, "audio/wav"),
                None => err(
                    404,
                    "no recording for this line (turn Record on during the call)",
                ),
            }
        }
        (Method::Get, "/api/audio/devices") => {
            let d = audio::list();
            let st = phone::get().audio_status();
            json_resp(json!({"devices": d, "audio": st}))
        }
        (Method::Get, "/api/audio/status") => json_resp(phone::get().audio_status()),
        (Method::Post, "/api/audio/tone") => {
            let v = match body_json(body) {
                Ok(v) => v,
                Err(r) => return r,
            };
            let hz = v.get("hz").and_then(|x| x.as_f64()).unwrap_or(440.0) as f32;
            let ms = v
                .get("ms")
                .and_then(|x| x.as_u64())
                .unwrap_or(1500)
                .min(10_000);
            match phone::get().audio_tone(hz.clamp(50.0, 7000.0), ms) {
                Ok(()) => json_resp(json!({"ok": true})),
                Err(e) => err(409, e),
            }
        }
        (Method::Post, "/api/audio/record_test") => {
            let v = match body_json(body) {
                Ok(v) => v,
                Err(r) => return r,
            };
            let secs = v.get("seconds").and_then(|x| x.as_u64()).unwrap_or(4);
            match phone::get().audio_record_test(secs) {
                Ok(()) => json_resp(json!({"ok": true})),
                Err(e) => err(409, e),
            }
        }
        (Method::Post, "/api/audio/loopback") => {
            let v = match body_json(body) {
                Ok(v) => v,
                Err(r) => return r,
            };
            let on = v.get("on").and_then(|x| x.as_bool()).unwrap_or(false);
            match phone::get().audio_loopback(on) {
                Ok(()) => json_resp(json!({"ok": true})),
                Err(e) => err(409, e),
            }
        }
        (Method::Get, "/api/diag/dns") => {
            let host = q.get("host").cloned().unwrap_or_default();
            if host.trim().is_empty() {
                return err(400, "missing host");
            }
            json_resp(json!(dns::report(&host)))
        }
        (Method::Post, "/api/diag/stun") => {
            let v = match body_json(body) {
                Ok(v) => v,
                Err(r) => return r,
            };
            let servers: Vec<String> = v
                .get("servers")
                .and_then(|s| serde_json::from_value(s.clone()).ok())
                .unwrap_or_else(|| {
                    vec![
                        "stun.l.google.com:19302".into(),
                        "stun.cloudflare.com:3478".into(),
                    ]
                });
            json_resp(json!(stun::test(&servers, None)))
        }
        (Method::Post, "/api/diag/options") => {
            let v = match body_json(body) {
                Ok(v) => v,
                Err(r) => return r,
            };
            let acc = v
                .get("account")
                .and_then(|x| x.as_str())
                .map(|s| s.to_string());
            let target = v
                .get("target")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            match phone::get().engine.options(acc, target) {
                Some((code, rtt, summary)) => {
                    json_resp(json!({"code": code, "rtt_ms": rtt, "summary": summary}))
                }
                None => json_resp(
                    json!({"code": null, "summary": "no response (check the account is ready, the server address and the firewall)"}),
                ),
            }
        }
        _ => err(404, "unknown phone endpoint"),
    }
}

/// One RTP stream of a capture as a WAV: G.711 decoded by the core, Opus by
/// libopus. The second value is a short JSON with codec, packets and gaps.
fn rtp_wav(bytes: &[u8], id: usize) -> std::result::Result<(Vec<u8>, String), String> {
    use sidetone_core::audio::{stream_audio, wav_mono};
    let a = stream_audio(bytes, id)?;
    let info = |a: &sidetone_core::audio::StreamAudio| serde_json::to_string(a).unwrap_or_default();
    if !a.pcm.is_empty() {
        return Ok((wav_mono(&a.pcm, a.rate), info(&a)));
    }
    // Every codec the phone speaks: decode with the engine's decoders to 16 kHz.
    if let Some(codec) = codec_for(&a.codec, a.clock_rate) {
        if !a.frames.is_empty() {
            use sidetone_ua::media::{Decoder, AUDIO_RATE};
            let mut dec = Decoder::new(codec);
            let mut pcm: Vec<i16> = Vec::new();
            for (pos, f) in &a.frames {
                // Place each payload where its RTP timestamp says.
                let at = (*pos as u64 * AUDIO_RATE as u64 / codec.clock().max(1) as u64) as usize;
                if pcm.len() < at {
                    pcm.resize(at, 0);
                }
                if let Some(d) = dec.decode(codec.pt(), f) {
                    pcm.extend_from_slice(&d);
                }
            }
            return Ok((wav_mono(&pcm, AUDIO_RATE), info(&a)));
        }
    }
    Err(a
        .note
        .unwrap_or_else(|| format!("{} cannot be played", a.codec)))
}

/// The engine codec for an RTP stream's codec name and clock rate.
fn codec_for(name: &str, clock: u32) -> Option<sidetone_ua::media::Codec> {
    use sidetone_ua::media::Codec;
    let n = name.to_ascii_uppercase();
    let key = match n.as_str() {
        "SPEEX" => format!("speex/{clock}"),
        "L16" => format!("L16/{clock}"),
        _ => name.to_string(),
    };
    Codec::from_name(&key).or_else(|| {
        n.strip_prefix("AAL2-")
            .and_then(Codec::from_name)
            .map(|c| c.with_aal2(true))
    })
}

/// Passive capture on a network interface (libpcap / Npcap loaded at run time).
fn sniff_api(m: &Method, path: &str, q: &HashMap<String, String>, body: &[u8]) -> Resp {
    use sidetone_ua::sniff;
    match (m, path) {
        (Method::Get, "/api/sniff/interfaces") => match sniff::interfaces() {
            Ok((list, version)) => json_resp(json!({"interfaces": list, "library": version})),
            Err(e) => json_resp(json!({"interfaces": [], "error": e})),
        },
        (Method::Post, "/api/sniff/start") => {
            let v = match body_json(body) {
                Ok(v) => v,
                Err(r) => return r,
            };
            let iface = v
                .get("iface")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            let filter = v
                .get("filter")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            if iface.is_empty() {
                return err(400, "choose an interface");
            }
            match sniff::global().lock().unwrap().start(&iface, &filter) {
                Ok(()) => json_resp(json!({"ok": true})),
                Err(e) => err(400, e),
            }
        }
        (Method::Post, "/api/sniff/stop") => {
            sniff::global().lock().unwrap().stop_capture();
            json_resp(json!({"ok": true}))
        }
        (Method::Get, "/api/sniff/status") => {
            let since = q
                .get("since")
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(0);
            let s = sniff::global().lock().unwrap();
            json_resp(json!({"status": s.status(), "sip": s.sip_since(since, 300)}))
        }
        (Method::Get, "/api/sniff/pcap") => ok_bytes(
            sniff::global().lock().unwrap().to_pcapng(),
            "application/octet-stream",
        ),
        _ => err(404, "unknown capture endpoint"),
    }
}

fn mime(f: &str) -> &'static str {
    match f.rsplit('.').next().unwrap_or("") {
        "html" => "text/html; charset=utf-8",
        "js" | "mjs" => "text/javascript",
        "css" => "text/css",
        "wasm" => "application/wasm",
        "svg" => "image/svg+xml",
        "json" => "application/json",
        "png" => "image/png",
        _ => "application/octet-stream",
    }
}

fn new_token() -> String {
    let mut x = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(7)
        ^ (std::process::id() as u64).rotate_left(32);
    let mut s = String::new();
    for _ in 0..4 {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        s.push_str(&format!("{x:016x}"));
    }
    s
}

/// Starts the server on a background thread. Returns the URL to open (with the access token).
pub fn spawn(
    listen: &str,
    web: Option<PathBuf>,
    use_token: bool,
    save: Option<SaveHook>,
) -> Result<(String, std::thread::JoinHandle<()>)> {
    let server = Server::http(listen).map_err(|e| anyhow!("cannot listen on {listen}: {e}"))?;
    let addr = server
        .server_addr()
        .to_ip()
        .ok_or_else(|| anyhow!("no IP address"))?;
    let token = if use_token { Some(new_token()) } else { None };
    let url = match &token {
        Some(t) => format!("http://{addr}/?token={t}"),
        None => format!("http://{addr}/"),
    };
    let h = std::thread::spawn(move || {
        // One thread per request: diagnostics can take seconds while the UI keeps polling.
        let ctx = std::sync::Arc::new((web, token, save));
        for mut req in server.incoming_requests() {
            let ctx = ctx.clone();
            std::thread::spawn(move || {
                let resp = handle(&mut req, &ctx.0, &ctx.1, &ctx.2);
                let _ = req.respond(resp);
            });
        }
    });
    Ok((url, h))
}

pub fn run(listen: &str, web: Option<PathBuf>, use_token: bool, open: bool) -> Result<()> {
    let (url, h) = spawn(listen, web, use_token, None)?;
    if open {
        open_browser(&url);
    }
    // Ctrl+C or SIGTERM: hang up and unregister before leaving.
    let _ = ctrlc::set_handler(|| {
        phone::shutdown();
        std::process::exit(0);
    });
    eprintln!(
        "Sidetone UI: {url}\n(the token protects the API from other local pages; Ctrl+C or closing this window stops Sidetone)"
    );
    let _ = h.join();
    Ok(())
}

/// Opens `url` in the default browser; failure only leaves the printed URL.
fn open_browser(url: &str) {
    let r = if cfg!(target_os = "windows") {
        std::process::Command::new("rundll32")
            .args(["url.dll,FileProtocolHandler", url])
            .spawn()
    } else if cfg!(target_os = "macos") {
        std::process::Command::new("open").arg(url).spawn()
    } else {
        std::process::Command::new("xdg-open").arg(url).spawn()
    };
    if let Err(e) = r {
        eprintln!("could not open a browser ({e}); open the address above by hand");
    }
}
