//! Provisioning files → account JSON (native desktop or browser web phone).
//!
//! The native app reads three formats, recognized from the content: Sidetone's
//! own `sidetone-provision` XML (strict: unknown keys fail), a Yealink `.cfg`
//! and a Polycom (Poly UC Software) XML. Vendor files are full phone
//! configurations, so keys Sidetone has no use for are skipped; line 1 (the
//! first account with a user) becomes the Sidetone account.

mod vendor;

use quick_xml::events::{attributes::Attribute, BytesStart, Event};
use quick_xml::{Reader, XmlVersion};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};

const ACCOUNT_PREFIX: &str = "account.1.";

pub fn parse(xml: &str, kind: &str) -> Result<Value, String> {
    match kind {
        "native" => parse_native(xml),
        "browser" => parse_browser(xml),
        _ => Err(format!("unknown kind: {kind}")),
    }
}

/// The format name of a provisioning file ("Sidetone", "Yealink", "Polycom", "Cisco").
pub fn detect_name(text: &str) -> &'static str {
    vendor::detect(text).name()
}

/// Replaces password values in a provisioning file for display.
pub fn mask_secrets(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for line in text.split_inclusive('\n') {
        out.push_str(&mask_line(line));
    }
    out
}

fn mask_line(line: &str) -> String {
    let lower = line.to_ascii_lowercase();
    // key = value / key: value (Yealink, Cisco text)
    if !lower.trim_start().starts_with('<') {
        if lower.contains("password") || lower.contains("passwd") {
            if let Some(i) = line.find(['=', ':']) {
                let end = if line.ends_with('\n') { "\n" } else { "" };
                return format!("{} ***{end}", &line[..=i]);
            }
        }
        return line.to_string();
    }
    // XML: element text (<authPassword>x</authPassword>) and attributes (x.password="y").
    let mut s = line.to_string();
    for tag in ["authpassword", "password", "account.1.password"] {
        if let Some(a) = s.to_ascii_lowercase().find(&format!("<{tag}>")) {
            let start = a + tag.len() + 2;
            if let Some(e) = s[start..].find('<') {
                s.replace_range(start..start + e, "***");
            }
        }
    }
    let mut res = String::new();
    let mut rest = s.as_str();
    while let Some(i) = rest.to_ascii_lowercase().find("password=\"") {
        let vstart = i + "password=\"".len();
        res.push_str(&rest[..vstart]);
        let after = &rest[vstart..];
        let vend = after.find('"').unwrap_or(after.len());
        res.push_str("***");
        rest = &after[vend..];
    }
    res.push_str(rest);
    res
}

fn reject_doctype_entity(xml: &str) -> Result<(), String> {
    let lower = xml.to_ascii_lowercase();
    if lower.contains("<!doctype") || lower.contains("<!entity") {
        return Err("DOCTYPE or ENTITY declarations are not allowed".into());
    }
    Ok(())
}

fn parse_flat(xml: &str) -> Result<HashMap<String, String>, String> {
    reject_doctype_entity(xml)?;

    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut buf = Vec::new();
    let mut map = HashMap::new();
    let mut saw_root = false;
    let mut root_done = false;

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::DocType(_)) => return Err("DOCTYPE is not allowed".into()),
            Ok(Event::Decl(_)) => {}
            Ok(Event::Start(e)) => {
                if !saw_root {
                    let name = local_name(&e);
                    if name != "sidetone-provision" {
                        return Err(format!("unexpected root element: {name}"));
                    }
                    let version = attr(&e, "version")?;
                    if version != "1" {
                        return Err(format!("unsupported provision version: {version}"));
                    }
                    saw_root = true;
                } else if root_done {
                    return Err("unexpected element after root".into());
                } else {
                    if e.attributes().count() > 0 {
                        return Err(format!(
                            "attributes are not allowed on <{}>",
                            local_name(&e)
                        ));
                    }
                    let key = local_name(&e);
                    if !key.starts_with(ACCOUNT_PREFIX) {
                        return Err(format!("invalid key: {key}"));
                    }
                    if key.starts_with("account.2.")
                        || key.starts_with("account.0.")
                        || key.starts_with("account.3.")
                    {
                        return Err(format!("only account index 1 is supported: {key}"));
                    }
                    if map.contains_key(&key) {
                        return Err(format!("duplicate key: {key}"));
                    }
                    let mut inner = Vec::new();
                    let value = read_element_text(&mut reader, &e, &mut inner)?;
                    map.insert(key, value);
                }
            }
            Ok(Event::End(e)) => {
                if saw_root && local_name_bytes(e.name().as_ref()) == "sidetone-provision" {
                    root_done = true;
                }
            }
            Ok(Event::Eof) => {
                if !saw_root {
                    return Err("missing root element sidetone-provision".into());
                }
                break;
            }
            Ok(Event::Comment(_)) | Ok(Event::PI(_)) => {}
            Ok(_) => {}
            Err(e) => return Err(format!("malformed XML: {e}")),
        }
        buf.clear();
    }

    Ok(map)
}

fn read_element_text(
    reader: &mut Reader<&[u8]>,
    start: &BytesStart,
    buf: &mut Vec<u8>,
) -> Result<String, String> {
    let mut text = String::new();
    loop {
        match reader.read_event_into(buf) {
            Ok(Event::Text(t)) => {
                text.push_str(&t.decode().map_err(|e| format!("malformed XML: {e}"))?);
            }
            Ok(Event::End(e)) if e.name() == start.name() => break,
            Ok(Event::Start(_)) => return Err("nested elements are not allowed".into()),
            Ok(Event::Eof) => return Err("malformed XML: unexpected EOF".into()),
            Ok(Event::CData(_)) => return Err("CDATA is not allowed".into()),
            Err(e) => return Err(format!("malformed XML: {e}")),
            Ok(_) => {}
        }
        buf.clear();
    }
    Ok(text)
}

fn local_name(e: &BytesStart) -> String {
    local_name_bytes(e.name().as_ref())
}

fn local_name_bytes(name: &[u8]) -> String {
    String::from_utf8_lossy(name).into_owned()
}

fn attr(e: &BytesStart, key: &str) -> Result<String, String> {
    let mut found = None;
    for a in e.attributes().flatten() {
        let name = local_name_attr(&a);
        if name == key {
            found = Some(attr_value(&a)?);
        } else {
            return Err(format!(
                "unexpected attribute on sidetone-provision: {name}"
            ));
        }
    }
    found.ok_or_else(|| format!("missing attribute {key} on sidetone-provision"))
}

fn attr_value(a: &Attribute<'_>) -> Result<String, String> {
    a.normalized_value(XmlVersion::Explicit1_0)
        .map(|v| v.into_owned())
        .map_err(|e| format!("malformed XML: {e}"))
}

fn local_name_attr(a: &Attribute<'_>) -> String {
    let name = a.key.as_ref();
    if let Some(i) = name.iter().position(|&b| b == b':') {
        String::from_utf8_lossy(&name[i + 1..]).into_owned()
    } else {
        String::from_utf8_lossy(name).into_owned()
    }
}

fn suffix(full: &str) -> Result<&str, String> {
    full.strip_prefix(ACCOUNT_PREFIX)
        .ok_or_else(|| format!("invalid key: {full}"))
}

fn parse_bool(s: &str, key: &str) -> Result<bool, String> {
    match s.to_ascii_lowercase().as_str() {
        "0" | "false" => Ok(false),
        "1" | "true" => Ok(true),
        _ => Err(format!("invalid boolean for {key}: {s}")),
    }
}

fn parse_u32(s: &str, key: &str) -> Result<u32, String> {
    s.parse::<u32>()
        .map_err(|_| format!("invalid unsigned integer for {key}: {s}"))
}

fn parse_u64(s: &str, key: &str) -> Result<u64, String> {
    s.parse::<u64>()
        .map_err(|_| format!("invalid unsigned integer for {key}: {s}"))
}

fn parse_u16(s: &str, key: &str) -> Result<u16, String> {
    s.parse::<u16>()
        .map_err(|_| format!("invalid unsigned integer for {key}: {s}"))
}

fn parse_u8(s: &str, key: &str) -> Result<u8, String> {
    s.parse::<u8>()
        .map_err(|_| format!("invalid unsigned integer for {key}: {s}"))
}

fn opt_null_str(v: &str) -> Value {
    if v.is_empty() {
        Value::Null
    } else {
        Value::String(v.to_string())
    }
}

fn contiguous_indices(
    prefix: &str,
    keys: &HashMap<String, String>,
) -> Result<Vec<(u32, String)>, String> {
    let mut items: BTreeMap<u32, String> = BTreeMap::new();
    let needle = format!("{ACCOUNT_PREFIX}{prefix}.");
    for (k, v) in keys {
        if let Some(rest) = k.strip_prefix(&needle) {
            let idx: u32 = rest
                .parse()
                .map_err(|_| format!("invalid index in key: {k}"))?;
            if idx == 0 {
                return Err(format!("indexes must start at 1: {k}"));
            }
            if items.insert(idx, v.clone()).is_some() {
                return Err(format!("duplicate key: {k}"));
            }
        }
    }
    if items.is_empty() {
        return Ok(Vec::new());
    }
    let max = *items.keys().max().unwrap();
    let mut out = Vec::new();
    for i in 1..=max {
        match items.get(&i) {
            Some(v) => out.push((i, v.clone())),
            None => {
                return Err(format!(
                    "non-contiguous {prefix} index: missing {prefix}.{i}"
                ))
            }
        }
    }
    Ok(out)
}

fn parse_headers(keys: &HashMap<String, String>) -> Result<Vec<(String, String)>, String> {
    let mut by_idx: BTreeMap<u32, (Option<String>, Option<String>)> = BTreeMap::new();
    let name_p = format!("{ACCOUNT_PREFIX}header.");
    for (k, v) in keys {
        if let Some(rest) = k.strip_prefix(&name_p) {
            let (idx_s, field) = rest
                .split_once('.')
                .ok_or_else(|| format!("invalid header key: {k}"))?;
            let idx: u32 = idx_s
                .parse()
                .map_err(|_| format!("invalid header index: {k}"))?;
            if idx == 0 {
                return Err(format!("indexes must start at 1: {k}"));
            }
            let slot = by_idx.entry(idx).or_default();
            match field {
                "name" => {
                    if slot.0.is_some() {
                        return Err(format!("duplicate key: {k}"));
                    }
                    slot.0 = Some(v.clone());
                }
                "value" => {
                    if slot.1.is_some() {
                        return Err(format!("duplicate key: {k}"));
                    }
                    slot.1 = Some(v.clone());
                }
                _ => return Err(format!("unknown key: {k}")),
            }
        }
    }
    if by_idx.is_empty() {
        return Ok(Vec::new());
    }
    let max = *by_idx.keys().max().unwrap();
    let mut out = Vec::new();
    for i in 1..=max {
        match by_idx.get(&i) {
            Some((Some(n), Some(val))) => out.push((n.clone(), val.clone())),
            Some((Some(_), None)) => {
                return Err(format!("missing value for header.{i}"));
            }
            Some((None, Some(_))) => {
                return Err(format!("missing name for header.{i}"));
            }
            Some((None, None)) => unreachable!(),
            None => return Err(format!("non-contiguous header index: missing header.{i}")),
        }
    }
    Ok(out)
}

fn is_native_only_suffix(suf: &str) -> bool {
    matches!(suf, "ws" | "ice" | "remember_password")
        || suf.starts_with("codec.")
        || suf.starts_with("blf.")
        || suf.starts_with("header.")
        || matches!(
            suf,
            "transport"
                | "tls_verify"
                | "tls_ca_file"
                | "tls_client_cert"
                | "tls_client_key"
                | "tls_client_pass"
                | "local_ip"
                | "local_port"
                | "rport"
                | "symmetric_rtp"
                | "rtp_port_start"
                | "rtp_port_end"
                | "dscp_sip"
                | "dscp_rtp"
                | "sdp_ip_override"
                | "t1_ms"
                | "srtp"
                | "srtp_keys"
                | "ptime_ms"
                | "sdp_direction"
                | "dtmf_mode"
                | "dtmf_payload_type"
                | "user_agent"
                | "max_forwards"
                | "session_timer"
                | "user_phone"
                | "compact_headers"
                | "require_prack"
                | "offer_gruu"
                | "long_contact"
                | "proxy_require"
                | "skip_ack"
                | "keepalive_interval"
                | "filter_registrar"
                | "rtcp"
                | "retry_s"
                | "outbound_proxy"
                | "q_value"
                | "auth_user"
                | "mwi"
                | "voicemail"
        )
}

fn is_browser_only_suffix(suf: &str) -> bool {
    matches!(suf, "ws" | "ice" | "remember_password")
}

/// Codec names a provisioning file may list, in Sidetone's spelling.
const CODEC_NAMES: &[&str] = &[
    "PCMU",
    "PCMA",
    "G722",
    "opus",
    "G729",
    "GSM",
    "iLBC",
    "speex/8000",
    "speex/16000",
    "G726-16",
    "G726-24",
    "G726-32",
    "G726-40",
    "AAL2-G726-32",
    "L16/8000",
    "L16/16000",
    "L16/44100",
];

/// Sidetone's name for a codec, accepting any case and the short aliases.
pub fn codec_name(c: &str) -> Option<&'static str> {
    let c = c.trim();
    let alias = match c.to_ascii_lowercase().as_str() {
        "speex" => "speex/8000",
        "l16" => "L16/8000",
        "g726" => "G726-32",
        _ => c,
    };
    CODEC_NAMES
        .iter()
        .find(|n| n.eq_ignore_ascii_case(alias))
        .copied()
}

fn is_shared_suffix(suf: &str) -> bool {
    matches!(
        suf,
        "label"
            | "enabled"
            | "register"
            | "user"
            | "password"
            | "domain"
            | "display_name"
            | "expires"
    )
}

fn classify_unknown(suf: &str) -> bool {
    if is_shared_suffix(suf) {
        return true;
    }
    if suf.starts_with("blf.") {
        return suf[4..].chars().all(|c| c.is_ascii_digit());
    }
    if suf.starts_with("codec.") {
        return suf[6..].chars().all(|c| c.is_ascii_digit());
    }
    if suf.starts_with("header.") {
        let rest = &suf[7..];
        if let Some((idx, field)) = rest.split_once('.') {
            return idx.chars().all(|c| c.is_ascii_digit()) && matches!(field, "name" | "value");
        }
        return false;
    }
    is_native_only_suffix(suf) && !is_browser_only_suffix(suf)
}

fn validate_keys_native(keys: &HashMap<String, String>) -> Result<(), String> {
    for k in keys.keys() {
        let suf = suffix(k)?;
        if is_browser_only_suffix(suf) {
            return Err(format!("key not allowed for native account: {suf}"));
        }
        if !classify_unknown(suf) {
            return Err(format!("unknown key: {suf}"));
        }
    }
    Ok(())
}

fn validate_keys_browser(keys: &HashMap<String, String>) -> Result<(), String> {
    for k in keys.keys() {
        let suf = suffix(k)?;
        if !is_shared_suffix(suf) && !is_browser_only_suffix(suf) {
            return Err(format!("unknown key: {suf}"));
        }
    }
    Ok(())
}

fn require_non_empty(keys: &HashMap<String, String>, field: &str) -> Result<String, String> {
    let key = format!("{ACCOUNT_PREFIX}{field}");
    match keys.get(&key) {
        Some(v) if !v.is_empty() => Ok(v.clone()),
        Some(_) => Err(format!("{field} must be non-empty")),
        None => Err(format!("missing required field: {field}")),
    }
}

fn parse_native(text: &str) -> Result<Value, String> {
    match vendor::detect(text) {
        vendor::Format::Yealink => native_from_keys(&vendor::yealink(text)?),
        vendor::Format::Polycom => native_from_keys(&vendor::polycom(text)?),
        vendor::Format::Cisco => native_from_keys(&vendor::cisco(text)?),
        vendor::Format::Sidetone => {
            let keys = parse_flat(text)?;
            validate_keys_native(&keys)?;
            native_from_keys(&keys)
        }
    }
}

fn native_from_keys(keys: &HashMap<String, String>) -> Result<Value, String> {
    let keys = keys.clone();
    let user = require_non_empty(&keys, "user")?;
    let domain = require_non_empty(&keys, "domain")?;
    let display_name = require_non_empty(&keys, "display_name")?;

    let label = keys
        .get(&format!("{ACCOUNT_PREFIX}label"))
        .cloned()
        .unwrap_or_default();
    let enabled = keys
        .get(&format!("{ACCOUNT_PREFIX}enabled"))
        .map(|s| parse_bool(s, "enabled"))
        .transpose()?
        .unwrap_or(true);
    let register = keys
        .get(&format!("{ACCOUNT_PREFIX}register"))
        .map(|s| parse_bool(s, "register"))
        .transpose()?
        .unwrap_or(true);
    let retry_s = keys
        .get(&format!("{ACCOUNT_PREFIX}retry_s"))
        .map(|s| parse_u32(s, "retry_s"))
        .transpose()?
        .unwrap_or(30);

    let blf: Vec<Value> = contiguous_indices("blf", &keys)?
        .into_iter()
        .map(|(_, v)| Value::String(v))
        .collect();

    let auth_user = keys
        .get(&format!("{ACCOUNT_PREFIX}auth_user"))
        .map(|s| opt_null_str(s))
        .unwrap_or(Value::Null);
    let password = keys
        .get(&format!("{ACCOUNT_PREFIX}password"))
        .map(|s| opt_null_str(s))
        .unwrap_or(Value::Null);
    let outbound_proxy = keys
        .get(&format!("{ACCOUNT_PREFIX}outbound_proxy"))
        .map(|s| opt_null_str(s))
        .unwrap_or(Value::Null);
    let expires = keys
        .get(&format!("{ACCOUNT_PREFIX}expires"))
        .map(|s| parse_u32(s, "expires"))
        .transpose()?
        .unwrap_or(300);
    let q_value = keys
        .get(&format!("{ACCOUNT_PREFIX}q_value"))
        .map(|s| opt_null_str(s))
        .unwrap_or(Value::Null);

    // Behavior defaults (mirrors sidetone-ua profile::Behavior::default except user_agent handling).
    let mut transport = "udp".to_string();
    let mut tls_verify = true;
    let mut tls_ca_file = Value::Null;
    let mut tls_client_cert = Value::Null;
    let mut tls_client_key = Value::Null;
    let mut tls_client_pass = Value::Null;
    let mut local_port: u16 = 0;
    let mut local_ip = Value::Null;
    let mut t1_ms: u64 = 500;
    let mut max_forwards: u32 = 70;
    let mut session_timer: u32 = 0;
    let mut user_phone = false;
    let mut compact_headers = false;
    let mut require_prack = false;
    let mut offer_gruu = false;
    let mut long_contact = false;
    let mut rport = true;
    // Empty: the account follows the global codec list.
    let mut codecs: Vec<String> = Vec::new();
    let mut ptime_ms: u32 = 20;
    let mut dtmf_mode = "rfc4733".to_string();
    let mut dtmf_payload_type: u8 = 101;
    let mut srtp = "off".to_string();
    let mut srtp_keys = "sdes".to_string();
    let mut symmetric_rtp = true;
    let mut rtcp = false;
    let mut rtp_port_start: u16 = 40000;
    let mut rtp_port_end: u16 = 49999;
    let mut dscp_sip: u8 = 0;
    let mut dscp_rtp: u8 = 0;
    let mut keepalive_interval: u32 = 0;
    let mut user_agent: Value = Value::Null;
    let mut proxy_require = Value::Null;
    let mut filter_registrar = false;
    let mut sdp_direction = "sendrecv".to_string();
    let mut skip_ack = false;
    let mut sdp_ip_override = Value::Null;

    if let Some(s) = keys.get(&format!("{ACCOUNT_PREFIX}transport")) {
        transport = match s.to_ascii_lowercase().as_str() {
            "udp" | "tcp" | "tls" => s.to_ascii_lowercase(),
            _ => return Err(format!("invalid transport: {s}")),
        };
    }
    if let Some(s) = keys.get(&format!("{ACCOUNT_PREFIX}tls_verify")) {
        tls_verify = parse_bool(s, "tls_verify")?;
    }
    if let Some(s) = keys.get(&format!("{ACCOUNT_PREFIX}tls_ca_file")) {
        tls_ca_file = opt_null_str(s);
    }
    if let Some(s) = keys.get(&format!("{ACCOUNT_PREFIX}tls_client_cert")) {
        tls_client_cert = opt_null_str(s);
    }
    if let Some(s) = keys.get(&format!("{ACCOUNT_PREFIX}tls_client_key")) {
        tls_client_key = opt_null_str(s);
    }
    if let Some(s) = keys.get(&format!("{ACCOUNT_PREFIX}tls_client_pass")) {
        tls_client_pass = opt_null_str(s);
    }
    if let Some(s) = keys.get(&format!("{ACCOUNT_PREFIX}local_port")) {
        local_port = parse_u16(s, "local_port")?;
    }
    if let Some(s) = keys.get(&format!("{ACCOUNT_PREFIX}local_ip")) {
        local_ip = opt_null_str(s);
    }
    if let Some(s) = keys.get(&format!("{ACCOUNT_PREFIX}t1_ms")) {
        t1_ms = parse_u64(s, "t1_ms")?;
        if t1_ms == 0 {
            return Err("t1_ms must be greater than 0".into());
        }
    }
    if let Some(s) = keys.get(&format!("{ACCOUNT_PREFIX}max_forwards")) {
        max_forwards = parse_u32(s, "max_forwards")?;
        if !(1..=255).contains(&max_forwards) {
            return Err(format!("max_forwards out of range: {max_forwards}"));
        }
    }
    if let Some(s) = keys.get(&format!("{ACCOUNT_PREFIX}session_timer")) {
        session_timer = parse_u32(s, "session_timer")?;
    }
    if let Some(s) = keys.get(&format!("{ACCOUNT_PREFIX}user_phone")) {
        user_phone = parse_bool(s, "user_phone")?;
    }
    if let Some(s) = keys.get(&format!("{ACCOUNT_PREFIX}compact_headers")) {
        compact_headers = parse_bool(s, "compact_headers")?;
    }
    if let Some(s) = keys.get(&format!("{ACCOUNT_PREFIX}require_prack")) {
        require_prack = parse_bool(s, "require_prack")?;
    }
    if let Some(s) = keys.get(&format!("{ACCOUNT_PREFIX}offer_gruu")) {
        offer_gruu = parse_bool(s, "offer_gruu")?;
    }
    if let Some(s) = keys.get(&format!("{ACCOUNT_PREFIX}long_contact")) {
        long_contact = parse_bool(s, "long_contact")?;
    }
    if let Some(s) = keys.get(&format!("{ACCOUNT_PREFIX}rport")) {
        rport = parse_bool(s, "rport")?;
    }
    if let Some(s) = keys.get(&format!("{ACCOUNT_PREFIX}ptime_ms")) {
        ptime_ms = parse_u32(s, "ptime_ms")?;
        if ![10, 20, 30, 40, 60].contains(&ptime_ms) {
            return Err(format!("invalid ptime_ms: {ptime_ms}"));
        }
    }
    if let Some(s) = keys.get(&format!("{ACCOUNT_PREFIX}dtmf_mode")) {
        dtmf_mode = match s.to_ascii_lowercase().as_str() {
            "rfc4733" | "info" | "inband" => s.to_ascii_lowercase(),
            _ => return Err(format!("invalid dtmf_mode: {s}")),
        };
    }
    if let Some(s) = keys.get(&format!("{ACCOUNT_PREFIX}dtmf_payload_type")) {
        dtmf_payload_type = parse_u8(s, "dtmf_payload_type")?;
        if dtmf_payload_type > 127 {
            return Err(format!(
                "dtmf_payload_type out of range: {dtmf_payload_type}"
            ));
        }
    }
    if let Some(s) = keys.get(&format!("{ACCOUNT_PREFIX}srtp")) {
        srtp = match s.to_ascii_lowercase().as_str() {
            "off" | "optional" | "mandatory" => s.to_ascii_lowercase(),
            _ => return Err(format!("invalid srtp: {s}")),
        };
    }
    if let Some(s) = keys.get(&format!("{ACCOUNT_PREFIX}srtp_keys")) {
        srtp_keys = match s.to_ascii_lowercase().as_str() {
            "sdes" | "dtls" => s.to_ascii_lowercase(),
            _ => return Err(format!("invalid srtp_keys: {s}")),
        };
    }
    if let Some(s) = keys.get(&format!("{ACCOUNT_PREFIX}symmetric_rtp")) {
        symmetric_rtp = parse_bool(s, "symmetric_rtp")?;
    }
    if let Some(s) = keys.get(&format!("{ACCOUNT_PREFIX}rtcp")) {
        rtcp = parse_bool(s, "rtcp")?;
    }
    let mut rtp_start_present = false;
    let mut rtp_end_present = false;
    if let Some(s) = keys.get(&format!("{ACCOUNT_PREFIX}rtp_port_start")) {
        rtp_port_start = parse_u16(s, "rtp_port_start")?;
        rtp_start_present = true;
    }
    if let Some(s) = keys.get(&format!("{ACCOUNT_PREFIX}rtp_port_end")) {
        rtp_port_end = parse_u16(s, "rtp_port_end")?;
        rtp_end_present = true;
    }
    if rtp_start_present && rtp_end_present && rtp_port_end < rtp_port_start {
        return Err("rtp_port_end must be >= rtp_port_start".into());
    }
    if let Some(s) = keys.get(&format!("{ACCOUNT_PREFIX}dscp_sip")) {
        dscp_sip = parse_u8(s, "dscp_sip")?;
        if dscp_sip > 63 {
            return Err(format!("dscp_sip out of range: {dscp_sip}"));
        }
    }
    if let Some(s) = keys.get(&format!("{ACCOUNT_PREFIX}dscp_rtp")) {
        dscp_rtp = parse_u8(s, "dscp_rtp")?;
        if dscp_rtp > 63 {
            return Err(format!("dscp_rtp out of range: {dscp_rtp}"));
        }
    }
    if let Some(s) = keys.get(&format!("{ACCOUNT_PREFIX}keepalive_interval")) {
        keepalive_interval = parse_u32(s, "keepalive_interval")?;
    }
    if let Some(s) = keys.get(&format!("{ACCOUNT_PREFIX}user_agent")) {
        user_agent = Value::String(s.clone());
    }
    if let Some(s) = keys.get(&format!("{ACCOUNT_PREFIX}proxy_require")) {
        proxy_require = opt_null_str(s);
    }
    if let Some(s) = keys.get(&format!("{ACCOUNT_PREFIX}filter_registrar")) {
        filter_registrar = parse_bool(s, "filter_registrar")?;
    }
    if let Some(s) = keys.get(&format!("{ACCOUNT_PREFIX}sdp_direction")) {
        sdp_direction = match s.to_ascii_lowercase().as_str() {
            "sendrecv" | "sendonly" | "recvonly" | "inactive" => s.to_ascii_lowercase(),
            _ => return Err(format!("invalid sdp_direction: {s}")),
        };
    }
    if let Some(s) = keys.get(&format!("{ACCOUNT_PREFIX}skip_ack")) {
        skip_ack = parse_bool(s, "skip_ack")?;
    }
    if let Some(s) = keys.get(&format!("{ACCOUNT_PREFIX}sdp_ip_override")) {
        sdp_ip_override = opt_null_str(s);
    }

    let codec_entries = contiguous_indices("codec", &keys)?;
    if !codec_entries.is_empty() {
        codecs.clear();
        for (_, c) in codec_entries {
            let norm = codec_name(&c).ok_or_else(|| format!("invalid codec: {c}"))?;
            if !codecs.iter().any(|x| x == norm) {
                codecs.push(norm.to_string());
            }
        }
    }

    let headers = parse_headers(&keys)?;
    let extra_headers: Vec<Value> = headers.into_iter().map(|(n, v)| json!([n, v])).collect();

    let behavior = json!({
        "transport": transport,
        "tls_verify": tls_verify,
        "tls_ca_file": tls_ca_file,
        "tls_client_cert": tls_client_cert,
        "tls_client_key": tls_client_key,
        "tls_client_pass": tls_client_pass,
        "local_port": local_port,
        "local_ip": local_ip,
        "t1_ms": t1_ms,
        "max_forwards": max_forwards,
        "session_timer": session_timer,
        "user_phone": user_phone,
        "compact_headers": compact_headers,
        "require_prack": require_prack,
        "offer_gruu": offer_gruu,
        "long_contact": long_contact,
        "rport": rport,
        "codecs": codecs,
        "ptime_ms": ptime_ms,
        "dtmf_mode": dtmf_mode,
        "dtmf_payload_type": dtmf_payload_type,
        "srtp": srtp,
        "srtp_keys": srtp_keys,
        "symmetric_rtp": symmetric_rtp,
        "rtcp": rtcp,
        "rtp_port_start": rtp_port_start,
        "rtp_port_end": rtp_port_end,
        "dscp_sip": dscp_sip,
        "dscp_rtp": dscp_rtp,
        "keepalive_interval": keepalive_interval,
        "user_agent": user_agent,
        "proxy_require": proxy_require,
        "filter_registrar": filter_registrar,
        "extra_headers": extra_headers,
        "sdp_direction": sdp_direction,
        "skip_ack": skip_ack,
        "sdp_ip_override": sdp_ip_override,
    });
    let account = json!({
        "user": user,
        "auth_user": auth_user,
        "password": password,
        "domain": domain,
        "display_name": display_name,
        "outbound_proxy": outbound_proxy,
        "expires": expires,
        "q_value": q_value,
    });
    let mut out = json!({
        "label": label,
        "enabled": enabled,
        "register": register,
        "retry_s": retry_s,
        "blf": blf,
        "profile": {
            "name": "",
            "account": account,
            "behavior": behavior,
        }
    });
    // Voicemail keys only when the file has them, so an absent key keeps
    // what the account already had.
    if let Some(s) = keys.get(&format!("{ACCOUNT_PREFIX}mwi")) {
        out["mwi"] = json!(parse_bool(s, "mwi")?);
    }
    if let Some(s) = keys.get(&format!("{ACCOUNT_PREFIX}voicemail")) {
        out["voicemail"] = json!(s);
    }
    Ok(out)
}

fn parse_browser(xml: &str) -> Result<Value, String> {
    match vendor::detect(xml) {
        vendor::Format::Sidetone => {}
        f => {
            return Err(format!(
                "{} files have no WebSocket address for the browser phone: provision this account in the desktop app",
                f.name()
            ))
        }
    }
    let keys = parse_flat(xml)?;
    validate_keys_browser(&keys)?;

    let user = require_non_empty(&keys, "user")?;
    let domain = require_non_empty(&keys, "domain")?;
    let display_name = require_non_empty(&keys, "display_name")?;
    let ws = require_non_empty(&keys, "ws")?;
    if !ws.starts_with("ws://") && !ws.starts_with("wss://") {
        return Err("ws must start with ws:// or wss://".into());
    }

    let label = keys
        .get(&format!("{ACCOUNT_PREFIX}label"))
        .cloned()
        .unwrap_or_default();
    let enabled = keys
        .get(&format!("{ACCOUNT_PREFIX}enabled"))
        .map(|s| parse_bool(s, "enabled"))
        .transpose()?
        .unwrap_or(true);
    let register = keys
        .get(&format!("{ACCOUNT_PREFIX}register"))
        .map(|s| parse_bool(s, "register"))
        .transpose()?
        .unwrap_or(true);
    let auth_user = keys
        .get(&format!("{ACCOUNT_PREFIX}auth_user"))
        .cloned()
        .unwrap_or_default();
    let password = keys
        .get(&format!("{ACCOUNT_PREFIX}password"))
        .cloned()
        .unwrap_or_default();
    let ice = keys
        .get(&format!("{ACCOUNT_PREFIX}ice"))
        .cloned()
        .unwrap_or_default();
    let expires = keys
        .get(&format!("{ACCOUNT_PREFIX}expires"))
        .map(|s| parse_u32(s, "expires"))
        .transpose()?
        .unwrap_or(300);
    let remember_password = keys
        .get(&format!("{ACCOUNT_PREFIX}remember_password"))
        .map(|s| parse_bool(s, "remember_password"))
        .transpose()?
        .unwrap_or(false);

    Ok(json!({
        "label": label,
        "enabled": enabled,
        "register": register,
        "user": user,
        "authUser": auth_user,
        "password": password,
        "displayName": display_name,
        "domain": domain,
        "ws": ws,
        "ice": ice,
        "expires": expires,
        "rememberPassword": remember_password,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secrets_masked_for_display() {
        let m = mask_secrets("account.1.password = s3cret\n<authPassword>s3cret</authPassword>\n<reg reg.1.auth.password=\"s3cret\" reg.1.address=\"2001\"/>\nline1_password: s3cret\n");
        assert!(!m.contains("s3cret"), "{m}");
        assert!(m.contains("reg.1.address=\"2001\""));
    }

    fn wrap(body: &str) -> String {
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<sidetone-provision version="1">
{body}
</sidetone-provision>"#
        )
    }

    fn native_minimal(extra: &str) -> String {
        wrap(&format!(
            r#"  <account.1.user>2001</account.1.user>
  <account.1.domain>pbx.example.com</account.1.domain>
  <account.1.display_name>Lab phone</account.1.display_name>
{extra}"#
        ))
    }

    #[test]
    fn valid_native_display_name() {
        let xml = native_minimal(
            r#"  <account.1.label>Lab</account.1.label>
  <account.1.password>secret</account.1.password>"#,
        );
        let v = parse(&xml, "native").unwrap();
        assert_eq!(v["label"], "Lab");
        assert_eq!(v["profile"]["account"]["display_name"], "Lab phone");
        assert_eq!(v["profile"]["account"]["password"], "secret");
    }

    #[test]
    fn valid_browser_display_name() {
        let xml = wrap(
            r#"  <account.1.user>2001</account.1.user>
  <account.1.domain>pbx.example.com</account.1.domain>
  <account.1.display_name>Lab phone</account.1.display_name>
  <account.1.ws>wss://pbx.example.com/ws</account.1.ws>"#,
        );
        let v = parse(&xml, "browser").unwrap();
        assert_eq!(v["displayName"], "Lab phone");
        assert_eq!(v["ws"], "wss://pbx.example.com/ws");
    }

    #[test]
    fn unknown_key() {
        let xml = native_minimal("  <account.1.unknown>x</account.1.unknown>");
        assert!(parse(&xml, "native").unwrap_err().contains("unknown key"));
    }

    #[test]
    fn bad_enum() {
        let xml = native_minimal("  <account.1.transport>sctp</account.1.transport>");
        assert!(parse(&xml, "native").unwrap_err().contains("transport"));
    }

    #[test]
    fn missing_user() {
        let xml = wrap(
            r#"  <account.1.domain>pbx.example.com</account.1.domain>
  <account.1.display_name>Lab phone</account.1.display_name>"#,
        );
        assert!(parse(&xml, "native").unwrap_err().contains("user"));
    }

    #[test]
    fn missing_display_name() {
        let xml = wrap(
            r#"  <account.1.user>2001</account.1.user>
  <account.1.domain>pbx.example.com</account.1.domain>"#,
        );
        assert!(parse(&xml, "native").unwrap_err().contains("display_name"));
    }

    #[test]
    fn empty_display_name() {
        let xml = wrap(
            r#"  <account.1.user>2001</account.1.user>
  <account.1.domain>pbx.example.com</account.1.domain>
  <account.1.display_name></account.1.display_name>"#,
        );
        assert!(parse(&xml, "native").unwrap_err().contains("display_name"));
    }

    #[test]
    fn wrong_version() {
        let xml = r#"<?xml version="1.0"?><sidetone-provision version="2"><account.1.user>a</account.1.user></sidetone-provision>"#;
        assert!(parse(xml, "native").unwrap_err().contains("version"));
    }

    #[test]
    fn doctype_rejected() {
        let xml = r#"<!DOCTYPE foo [<!ENTITY xxe "x">]><sidetone-provision version="1"></sidetone-provision>"#;
        assert!(parse(xml, "native").unwrap_err().contains("DOCTYPE"));
    }

    #[test]
    fn duplicate_key() {
        let xml = wrap(
            r#"  <account.1.user>2001</account.1.user>
  <account.1.user>2002</account.1.user>
  <account.1.domain>pbx.example.com</account.1.domain>
  <account.1.display_name>Lab phone</account.1.display_name>"#,
        );
        assert!(parse(&xml, "native").unwrap_err().contains("duplicate"));
    }

    #[test]
    fn non_contiguous_blf() {
        let xml = native_minimal(
            r#"  <account.1.blf.1>3001</account.1.blf.1>
  <account.1.blf.3>3003</account.1.blf.3>"#,
        );
        assert!(parse(&xml, "native").unwrap_err().contains("blf"));
    }

    #[test]
    fn absent_user_agent_null() {
        let v = parse(&native_minimal(""), "native").unwrap();
        assert!(v["profile"]["behavior"]["user_agent"].is_null());
    }

    #[test]
    fn present_user_agent_string() {
        let xml = native_minimal("  <account.1.user_agent>MyUA/1</account.1.user_agent>");
        let v = parse(&xml, "native").unwrap();
        assert_eq!(v["profile"]["behavior"]["user_agent"], "MyUA/1");
    }

    #[test]
    fn browser_transport_fails() {
        let xml = wrap(
            r#"  <account.1.user>2001</account.1.user>
  <account.1.domain>pbx.example.com</account.1.domain>
  <account.1.display_name>Lab phone</account.1.display_name>
  <account.1.ws>wss://pbx.example.com/ws</account.1.ws>
  <account.1.transport>udp</account.1.transport>"#,
        );
        assert!(parse(&xml, "browser").unwrap_err().contains("transport"));
    }

    #[test]
    fn native_ws_fails() {
        let xml = native_minimal("  <account.1.ws>wss://x/ws</account.1.ws>");
        assert!(parse(&xml, "native").unwrap_err().contains("ws"));
    }
}
