//! Behavior profile of the test user agent. Every knob changes what goes on
//! the wire, so a problematic client can be reproduced on purpose.
//! Many knobs follow the per-line and advanced settings of classic desk
//! phones and softphones (DTMF mode, PRACK, user=phone, long Contact, T1...).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Account {
    /// SIP user (From/Contact user part).
    pub user: String,
    /// Authentication user if different from `user`.
    pub auth_user: Option<String>,
    pub password: Option<String>,
    /// Registrar/domain, "host" or "host:port".
    pub domain: String,
    pub display_name: Option<String>,
    /// Send every request to this proxy ("host:port") instead of resolving the domain.
    pub outbound_proxy: Option<String>,
    /// Registration expiry in seconds.
    pub expires: u32,
    /// Contact q-value.
    pub q_value: Option<String>,
}

impl Default for Account {
    fn default() -> Self {
        Account {
            user: "sidetone".into(),
            auth_user: None,
            password: None,
            domain: "127.0.0.1".into(),
            display_name: Some("Sidetone".into()),
            outbound_proxy: None,
            expires: 300,
            q_value: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DtmfMode {
    /// RFC 4733 telephone-event packets.
    Rfc4733,
    /// SIP INFO with application/dtmf-relay.
    Info,
    /// Tones inside the audio.
    Inband,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SrtpMode {
    Off,
    Optional,
    Mandatory,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Behavior {
    /// SIP transport of the phone engine: "udp", "tcp" or "tls".
    pub transport: String,
    /// Check the TLS server certificate against public roots (off for self-signed labs).
    pub tls_verify: bool,
    /// PEM bundle of CA certificates to trust for the TLS server (private PKI).
    /// Empty uses the public roots. Ignored when `tls_verify` is off.
    #[serde(default)]
    pub tls_ca_file: Option<String>,
    /// Client certificate for mutual TLS: a PEM file (certificate chain) or a
    /// PKCS#12 bundle (.p12/.pfx). Empty = no client certificate.
    #[serde(default)]
    pub tls_client_cert: Option<String>,
    /// PEM private key for the client certificate. Unused when the certificate
    /// is a PKCS#12 bundle or a PEM file that already contains the key.
    #[serde(default)]
    pub tls_client_key: Option<String>,
    /// Password for the PKCS#12 client bundle (used for nothing else).
    #[serde(default)]
    pub tls_client_pass: Option<String>,
    /// Local SIP port (0 = random).
    pub local_port: u16,
    /// Force the local IP advertised in Via/Contact/SDP (empty = route-based autodetect).
    pub local_ip: Option<String>,
    /// SIP retransmission base timer in ms (RFC 3261 T1).
    pub t1_ms: u64,
    pub max_forwards: u32,
    /// Session-Expires to request (0 disables session timers).
    pub session_timer: u32,
    /// Add `;user=phone` to numeric request URIs.
    pub user_phone: bool,
    /// Use compact header names (v, f, t, i, m, l, c).
    pub compact_headers: bool,
    /// Require reliable provisional responses (Require: 100rel) instead of only Supported.
    pub require_prack: bool,
    /// Advertise GRUU support.
    pub offer_gruu: bool,
    /// Long Contact with +sip.instance and feature tags (RFC 3840/5626).
    pub long_contact: bool,
    /// Add `;rport` to Via (RFC 3581).
    pub rport: bool,
    /// Audio codecs in preference order (PCMU, PCMA).
    /// Codecs in preference order; empty uses the global list from Settings.
    pub codecs: Vec<String>,
    /// G.726 with the AAL2 bit order (most significant first) instead of RFC 3551.
    pub g726_aal2: bool,
    pub ptime_ms: u32,
    pub dtmf_mode: DtmfMode,
    pub dtmf_payload_type: u8,
    pub srtp: SrtpMode,
    /// How SRTP keys are exchanged: "sdes" (a=crypto in SDP) or "dtls"
    /// (DTLS-SRTP handshake on the media path, a=fingerprint in SDP).
    pub srtp_keys: String,
    /// Send RTP from the receive port and latch to the source of incoming RTP.
    pub symmetric_rtp: bool,
    pub rtcp: bool,
    pub rtp_port_start: u16,
    pub rtp_port_end: u16,
    /// DSCP for signaling and media (e.g. 26 = AF31, 46 = EF). 0 leaves the default.
    pub dscp_sip: u8,
    pub dscp_rtp: u8,
    /// Send CRLF keepalives every N seconds while registered (0 = off).
    pub keepalive_interval: u32,
    pub user_agent: String,
    /// Proxy-Require header value to add to requests.
    pub proxy_require: Option<String>,
    /// Ignore requests that do not come from the registrar/outbound proxy.
    pub filter_registrar: bool,
    /// Extra headers added to every request.
    pub extra_headers: Vec<(String, String)>,
    /// SDP direction attribute to offer.
    pub sdp_direction: String,
    /// Deliberately omit the ACK for 2xx (reproduces the 32 s drop).
    pub skip_ack: bool,
    /// Advertise this address in SDP c= instead of the real one (reproduces NAT issues).
    pub sdp_ip_override: Option<String>,
}

impl Default for Behavior {
    fn default() -> Self {
        Behavior {
            transport: "udp".into(),
            tls_verify: true,
            tls_ca_file: None,
            tls_client_cert: None,
            tls_client_key: None,
            tls_client_pass: None,
            local_port: 0,
            local_ip: None,
            t1_ms: 500,
            max_forwards: 70,
            session_timer: 0,
            user_phone: false,
            compact_headers: false,
            require_prack: false,
            offer_gruu: false,
            long_contact: false,
            rport: true,
            codecs: Vec::new(),
            g726_aal2: false,
            ptime_ms: 20,
            dtmf_mode: DtmfMode::Rfc4733,
            dtmf_payload_type: 101,
            srtp: SrtpMode::Off,
            srtp_keys: "sdes".into(),
            symmetric_rtp: true,
            rtcp: false,
            rtp_port_start: 40000,
            rtp_port_end: 49999,
            dscp_sip: 0,
            dscp_rtp: 0,
            keepalive_interval: 0,
            user_agent: format!("Sidetone/{}", env!("CARGO_PKG_VERSION")),
            proxy_require: None,
            filter_registrar: false,
            extra_headers: Vec::new(),
            sdp_direction: "sendrecv".into(),
            skip_ack: false,
            sdp_ip_override: None,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Profile {
    pub name: String,
    pub account: Account,
    pub behavior: Behavior,
}

impl Profile {
    pub fn from_json(s: &str) -> Result<Profile, String> {
        serde_json::from_str(s).map_err(|e| e.to_string())
    }

    /// Settings this build accepts but cannot honor yet.
    pub fn unsupported(&self) -> Vec<String> {
        let mut v = Vec::new();
        if self.behavior.srtp != SrtpMode::Off {
            v.push(
                "srtp: SRTP media is not implemented yet in the test UA; the call uses plain RTP"
                    .into(),
            );
        }
        v
    }
}
