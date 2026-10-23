//! SIP transports for the phone engine: UDP datagrams, or one persistent
//! TCP or TLS connection to the server (RFC 3261 section 18, RFC 5626 style
//! reuse: requests from the server come back on the same connection).

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Udp,
    Tcp,
    Tls,
}

impl Kind {
    pub fn parse(s: &str) -> Kind {
        match s.to_ascii_lowercase().as_str() {
            "tcp" => Kind::Tcp,
            "tls" => Kind::Tls,
            _ => Kind::Udp,
        }
    }
    /// Name in the Via header.
    pub fn via(self) -> &'static str {
        match self {
            Kind::Udp => "UDP",
            Kind::Tcp => "TCP",
            Kind::Tls => "TLS",
        }
    }
    pub fn reliable(self) -> bool {
        self != Kind::Udp
    }
    pub fn default_port(self) -> u16 {
        if self == Kind::Tls {
            5061
        } else {
            5060
        }
    }
}

trait Stream: Read + Write + Send {}
impl<T: Read + Write + Send> Stream for T {}

struct Conn {
    io: Arc<Mutex<Box<dyn Stream>>>,
    rx: Receiver<Vec<u8>>,
    alive: Arc<AtomicBool>,
    peer: SocketAddr,
}

/// A SIP socket: UDP, or a TCP/TLS connection to one peer.
pub struct Sock {
    pub kind: Kind,
    udp: Option<UdpSocket>,
    conn: Option<Conn>,
    pub local: SocketAddr,
    /// TLS certificate summary (subject and issuer) for diagnostics.
    pub tls_info: Option<String>,
}

impl Sock {
    pub fn udp(s: UdpSocket) -> std::io::Result<Sock> {
        s.set_nonblocking(true)?;
        let local = s.local_addr()?;
        Ok(Sock {
            kind: Kind::Udp,
            udp: Some(s),
            conn: None,
            local,
            tls_info: None,
        })
    }

    /// Connects to `peer` over TCP or TLS. `sni` is the server name for TLS;
    /// `tls` controls server trust and the optional client certificate (mTLS).
    pub fn connect(kind: Kind, peer: SocketAddr, sni: &str, tls: &TlsOptions) -> Result<Sock, String> {
        let tcp = TcpStream::connect_timeout(&peer, Duration::from_secs(5))
            .map_err(|e| format!("cannot connect to {peer}: {e}"))?;
        tcp.set_nodelay(true).ok();
        let local = tcp.local_addr().map_err(|e| e.to_string())?;
        if kind == Kind::Tcp {
            // The reader polls with a short timeout so writers can take the lock.
            tcp.set_read_timeout(Some(Duration::from_millis(20))).ok();
        }
        let mut tls_info = None;
        let stream: Box<dyn Stream> = match kind {
            Kind::Tls => {
                let (cfg, req_log) = tls_client_config(tls)?;
                let name = ServerName::try_from(sni.to_string())
                    .or_else(|_| ServerName::try_from(peer.ip().to_string()))
                    .map_err(|e| format!("bad TLS server name {sni}: {e}"))?;
                let conn = rustls::ClientConnection::new(Arc::new(cfg), name)
                    .map_err(|e| e.to_string())?;
                let mut s = rustls::StreamOwned::new(conn, tcp);
                tcp_ref(&s)
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .ok();
                // Complete the handshake now so certificate errors show up here.
                // On failure, fold in what the server asked for (its client-cert
                // request, if any) so an mTLS failure explains itself.
                while s.conn.is_handshaking() {
                    s.conn
                        .complete_io(&mut s.sock)
                        .map_err(|e| handshake_error(e, &req_log, peer))?;
                }
                let mut parts: Vec<String> = Vec::new();
                if let Some(certs) = s.conn.peer_certificates() {
                    parts.push(cert_summary(certs.first()));
                }
                if let Some(m) = req_log.summary() {
                    parts.push(m);
                }
                if !parts.is_empty() {
                    tls_info = Some(parts.join(" | "));
                }
                s.sock
                    .set_read_timeout(Some(Duration::from_millis(20)))
                    .ok();
                Box::new(s)
            }
            _ => Box::new(tcp.try_clone().map_err(|e| e.to_string())?),
        };
        let io: Arc<Mutex<Box<dyn Stream>>> = Arc::new(Mutex::new(stream));
        let (tx, rx) = channel();
        let alive = Arc::new(AtomicBool::new(true));
        {
            let io = io.clone();
            let alive = alive.clone();
            thread::Builder::new()
                .name("sidetone-sip-stream".into())
                .spawn(move || {
                    let mut acc: Vec<u8> = Vec::new();
                    let mut buf = [0u8; 16384];
                    while alive.load(Ordering::Relaxed) {
                        let r = {
                            let mut g = io.lock().unwrap();
                            g.read(&mut buf)
                        };
                        match r {
                            Ok(0) => break,
                            Ok(n) => {
                                acc.extend_from_slice(&buf[..n]);
                                let (msgs, used) = sidetone_core::sip::parse_stream(&acc);
                                for m in msgs {
                                    if tx.send(m.raw.into_bytes()).is_err() {
                                        return;
                                    }
                                }
                                acc.drain(..used);
                            }
                            Err(e)
                                if e.kind() == std::io::ErrorKind::WouldBlock
                                    || e.kind() == std::io::ErrorKind::TimedOut =>
                            {
                                thread::sleep(Duration::from_millis(2));
                            }
                            Err(_) => break,
                        }
                    }
                    alive.store(false, Ordering::Relaxed);
                })
                .map_err(|e| e.to_string())?;
        }
        Ok(Sock {
            kind,
            udp: None,
            conn: Some(Conn {
                io,
                rx,
                alive,
                peer,
            }),
            local,
            tls_info,
        })
    }

    /// Sends one message. Streams ignore `dest`: everything goes to the peer.
    pub fn send_to(&self, data: &[u8], dest: SocketAddr) -> std::io::Result<SocketAddr> {
        if let Some(u) = &self.udp {
            u.send_to(data, dest)?;
            return Ok(dest);
        }
        let c = self.conn.as_ref().expect("socket");
        let mut g = c.io.lock().unwrap();
        g.write_all(data)?;
        g.flush()?;
        Ok(c.peer)
    }

    /// Next received message or datagram, without blocking.
    pub fn try_recv(&self, buf: &mut [u8]) -> Option<(Vec<u8>, SocketAddr)> {
        if let Some(u) = &self.udp {
            return u.recv_from(buf).ok().map(|(n, f)| (buf[..n].to_vec(), f));
        }
        let c = self.conn.as_ref()?;
        c.rx.try_recv().ok().map(|m| (m, c.peer))
    }

    /// False once a stream connection has closed.
    pub fn alive(&self) -> bool {
        self.conn
            .as_ref()
            .map(|c| c.alive.load(Ordering::Relaxed))
            .unwrap_or(true)
    }

    pub fn peer(&self) -> Option<SocketAddr> {
        self.conn.as_ref().map(|c| c.peer)
    }
}

impl Drop for Sock {
    fn drop(&mut self) {
        if let Some(c) = &self.conn {
            c.alive.store(false, Ordering::Relaxed);
        }
    }
}

fn tcp_ref(s: &rustls::StreamOwned<rustls::ClientConnection, TcpStream>) -> &TcpStream {
    &s.sock
}

fn cert_summary(c: Option<&CertificateDer<'_>>) -> String {
    match c {
        Some(c) => match parse_x509(c.as_ref()) {
            Some((subject, issuer)) => {
                format!("server certificate: subject {subject}, issuer {issuer}")
            }
            None => format!("server certificate, {} bytes", c.len()),
        },
        None => "no certificate".into(),
    }
}

/// Subject and issuer of a DER certificate, best-effort.
fn parse_x509(der: &[u8]) -> Option<(String, String)> {
    use x509_parser::prelude::FromDer;
    let (_, cert) = x509_parser::certificate::X509Certificate::from_der(der).ok()?;
    Some((cert.subject().to_string(), cert.issuer().to_string()))
}

/// A DER-encoded X.500 distinguished name rendered as text, best-effort.
fn dn_to_string(der: &[u8]) -> String {
    use x509_parser::prelude::FromDer;
    match x509_parser::x509::X509Name::from_der(der) {
        Ok((_, name)) => name.to_string(),
        Err(_) => format!("<{}-byte DN>", der.len()),
    }
}

// ---------------------------------------------------------------------------
// Mutual TLS: server trust against a private CA, a client certificate, and a
// record of the server's CertificateRequest for diagnostics.
// ---------------------------------------------------------------------------

/// TLS client options for the SIP transport.
#[derive(Debug, Clone, Default)]
pub struct TlsOptions {
    /// Verify the server certificate. When `ca_file` is set it is checked
    /// against that bundle; otherwise against the public roots. When false the
    /// server certificate is accepted unchecked (labs, self-signed PBXs).
    pub verify: bool,
    /// PEM bundle of CA certificates to trust for the server (private PKI).
    /// Empty uses the public roots. Ignored when `verify` is false.
    pub ca_file: Option<String>,
    /// Client certificate for mutual TLS: a PEM file (certificate chain) or a
    /// PKCS#12 bundle (`.p12`/`.pfx`). Empty = no client certificate.
    pub client_cert_file: Option<String>,
    /// PEM private key for the client certificate. Unused when the certificate
    /// is a PKCS#12 bundle, or a PEM file that already contains the key.
    pub client_key_file: Option<String>,
    /// Password for the PKCS#12 bundle (used for nothing else).
    pub client_pass: Option<String>,
}

impl TlsOptions {
    /// Server-only TLS (no client certificate), matching the legacy behavior.
    pub fn server_only(verify: bool) -> Self {
        TlsOptions {
            verify,
            ..Default::default()
        }
    }
}

/// What the server asked for during the TLS handshake. Populated only when the
/// server sends a CertificateRequest (i.e. it wants mutual TLS).
#[derive(Debug, Default)]
pub struct CertRequestLog {
    /// The server requested a client certificate.
    pub requested: AtomicBool,
    /// We presented a client certificate in response.
    pub presented: AtomicBool,
    /// DER-encoded distinguished names of CAs the server said it accepts.
    pub issuers: Mutex<Vec<Vec<u8>>>,
}

impl CertRequestLog {
    /// A diagnostic line, or None if the server never asked for a client cert.
    pub fn summary(&self) -> Option<String> {
        if !self.requested.load(Ordering::Relaxed) {
            return None;
        }
        let issuers = self
            .issuers
            .lock()
            .map(|g| g.clone())
            .unwrap_or_default();
        let who = if issuers.is_empty() {
            "any CA".to_string()
        } else {
            issuers
                .iter()
                .map(|d| dn_to_string(d))
                .collect::<Vec<_>>()
                .join("; ")
        };
        let presented = if self.presented.load(Ordering::Relaxed) {
            "presented"
        } else {
            "not configured"
        };
        Some(format!(
            "server requested a client certificate (mTLS); acceptable CAs: {who}; client certificate {presented}"
        ))
    }
}

/// Builds a client config for the SIP transport, with optional private-CA
/// server trust and an optional client certificate. The returned log records
/// the server's CertificateRequest once the handshake has run.
pub fn tls_client_config(
    opts: &TlsOptions,
) -> Result<(rustls::ClientConfig, Arc<CertRequestLog>), String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("TLS versions: {e}"))?;

    // Server trust.
    let builder = if opts.verify {
        let roots = match opts.ca_file.as_deref() {
            Some(p) if !p.is_empty() => {
                let pem = std::fs::read(p).map_err(|e| format!("cannot read CA bundle {p}: {e}"))?;
                root_store_from_ca(&pem, p)?
            }
            _ => {
                let mut roots = rustls::RootCertStore::empty();
                roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
                roots
            }
        };
        builder.with_root_certificates(roots)
    } else {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify(provider.clone())))
    };

    // Client identity, plus always-on logging of the server's request.
    let log = Arc::new(CertRequestLog::default());
    let key = match load_client_identity(opts)? {
        Some((certs, key_der)) => {
            let signing = rustls::crypto::ring::sign::any_supported_type(&key_der)
                .map_err(|e| format!("unsupported client private key: {e}"))?;
            Some(Arc::new(rustls::sign::CertifiedKey::new(certs, signing)))
        }
        None => None,
    };
    let resolver = Arc::new(LoggingResolver {
        key,
        log: log.clone(),
    });
    let cfg = builder.with_client_cert_resolver(resolver);
    Ok((cfg, log))
}

fn handshake_error(e: std::io::Error, log: &CertRequestLog, peer: SocketAddr) -> String {
    let base = format!("TLS handshake with {peer} failed: {e}");
    match log.summary() {
        Some(s) => format!("{base} [{s}]"),
        None => base,
    }
}

fn root_store_from_ca(pem: &[u8], src: &str) -> Result<rustls::RootCertStore, String> {
    let mut rd = std::io::BufReader::new(pem);
    let mut roots = rustls::RootCertStore::empty();
    let mut n = 0usize;
    for c in rustls_pemfile::certs(&mut rd) {
        let c = c.map_err(|e| format!("cannot parse CA bundle {src}: {e}"))?;
        roots
            .add(c)
            .map_err(|e| format!("cannot add CA from {src}: {e}"))?;
        n += 1;
    }
    if n == 0 {
        return Err(format!("no certificates in CA bundle {src}"));
    }
    Ok(roots)
}

/// Loads the client certificate chain and private key, from a PEM file (with a
/// separate or inline key) or a PKCS#12 bundle. None when no cert is set.
fn load_client_identity(
    opts: &TlsOptions,
) -> Result<Option<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>, String> {
    let cert_path = match opts.client_cert_file.as_deref() {
        Some(p) if !p.is_empty() => p,
        _ => return Ok(None),
    };
    let data = std::fs::read(cert_path)
        .map_err(|e| format!("cannot read client certificate {cert_path}: {e}"))?;
    let lower = cert_path.to_ascii_lowercase();
    // A .p12/.pfx extension or a file that is not PEM is treated as PKCS#12.
    let is_p12 = lower.ends_with(".p12") || lower.ends_with(".pfx") || !is_pem(&data);
    if is_p12 {
        load_pkcs12(&data, opts.client_pass.as_deref().unwrap_or("")).map(Some)
    } else {
        load_pem_identity(&data, opts, cert_path).map(Some)
    }
}

fn is_pem(data: &[u8]) -> bool {
    data.windows(11).any(|w| w == b"-----BEGIN ")
}

fn load_pkcs12(
    data: &[u8],
    pass: &str,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), String> {
    let ks = p12_keystore::KeyStore::from_pkcs12(
        data,
        pass,
        p12_keystore::Pkcs12ImportPolicy::Relaxed,
    )
    .map_err(|e| format!("cannot open PKCS#12 bundle: {e}"))?;
    let (_alias, chain) = ks
        .private_key_chain()
        .ok_or("PKCS#12 bundle has no private key")?;
    // p12-keystore returns the key as PKCS#8 DER.
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(chain.key().as_der().to_vec()));
    let certs: Vec<CertificateDer<'static>> = chain
        .certs()
        .iter()
        .map(|c| CertificateDer::from(c.as_der().to_vec()))
        .collect();
    if certs.is_empty() {
        return Err("PKCS#12 bundle has no client certificate".into());
    }
    Ok((certs, key))
}

fn load_pem_identity(
    cert_data: &[u8],
    opts: &TlsOptions,
    cert_path: &str,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), String> {
    let mut rd = std::io::BufReader::new(cert_data);
    let certs = rustls_pemfile::certs(&mut rd)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("cannot parse client certificate PEM {cert_path}: {e}"))?;
    if certs.is_empty() {
        return Err(format!("no certificate found in {cert_path}"));
    }
    // The key comes from a separate key file if set, otherwise from the cert
    // file itself (a combined PEM).
    let key = match opts.client_key_file.as_deref() {
        Some(p) if !p.is_empty() => {
            let kd = std::fs::read(p).map_err(|e| format!("cannot read client key {p}: {e}"))?;
            read_pem_key(&kd).ok_or_else(|| format!("no private key found in {p}"))?
        }
        _ => read_pem_key(cert_data).ok_or_else(|| {
            format!("no private key in {cert_path}; set a key file or use a PKCS#12 bundle")
        })?,
    };
    Ok((certs, key))
}

fn read_pem_key(data: &[u8]) -> Option<PrivateKeyDer<'static>> {
    let mut rd = std::io::BufReader::new(data);
    rustls_pemfile::private_key(&mut rd).ok().flatten()
}

/// Presents the configured client certificate and records the server's
/// CertificateRequest (which CAs it accepts, whether we had a cert to send).
#[derive(Debug)]
struct LoggingResolver {
    key: Option<Arc<rustls::sign::CertifiedKey>>,
    log: Arc<CertRequestLog>,
}

impl rustls::client::ResolvesClientCert for LoggingResolver {
    fn resolve(
        &self,
        root_hint_subjects: &[&[u8]],
        _sigschemes: &[rustls::SignatureScheme],
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        self.log.requested.store(true, Ordering::Relaxed);
        if let Ok(mut g) = self.log.issuers.lock() {
            *g = root_hint_subjects.iter().map(|s| s.to_vec()).collect();
        }
        if self.key.is_some() {
            self.log.presented.store(true, Ordering::Relaxed);
        }
        self.key.clone()
    }

    fn has_certs(&self) -> bool {
        self.key.is_some()
    }
}

pub fn tls_config(verify: bool) -> rustls::ClientConfig {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .expect("TLS versions");
    if verify {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        builder.with_root_certificates(roots).with_no_client_auth()
    } else {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify(provider)))
            .with_no_client_auth()
    }
}

/// Accepts any certificate: for labs and PBXs with self-signed certificates,
/// chosen explicitly per account.
#[derive(Debug)]
struct NoVerify(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod mtls_tests {
    use super::*;

    /// A fresh self-signed certificate and its private key, both PEM. Built
    /// from DER because rcgen is compiled without its `pem` feature here.
    fn self_signed() -> (String, String) {
        use base64::Engine;
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let params = rcgen::CertificateParams::new(vec!["client.test".to_string()]).unwrap();
        let cert = params.self_signed(&key).unwrap();
        let pem = |label: &str, der: &[u8]| {
            let b64 = base64::engine::general_purpose::STANDARD.encode(der);
            let body = b64
                .as_bytes()
                .chunks(64)
                .map(|c| std::str::from_utf8(c).unwrap())
                .collect::<Vec<_>>()
                .join("\n");
            format!("-----BEGIN {label}-----\n{body}\n-----END {label}-----\n")
        };
        (
            pem("CERTIFICATE", cert.der()),
            pem("PRIVATE KEY", &key.serialize_der()),
        )
    }

    fn tmp(tag: &str, ext: &str) -> std::path::PathBuf {
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("sidetone-{tag}-{}-{n}.{ext}", std::process::id()))
    }

    #[test]
    fn pem_cert_and_separate_key_build_config() {
        let (cert_pem, key_pem) = self_signed();
        let cert_path = tmp("mtls", "crt");
        let key_path = tmp("mtls", "key");
        std::fs::write(&cert_path, cert_pem).unwrap();
        std::fs::write(&key_path, key_pem).unwrap();

        let opts = TlsOptions {
            verify: true,
            ca_file: None,
            client_cert_file: Some(cert_path.to_string_lossy().into_owned()),
            client_key_file: Some(key_path.to_string_lossy().into_owned()),
            client_pass: None,
        };
        let (certs, _key) = load_client_identity(&opts).unwrap().expect("identity loads");
        assert_eq!(certs.len(), 1);
        // The full build must accept the signing key (any_supported_type).
        let (_cfg, log) = tls_client_config(&opts).unwrap();
        assert!(log.summary().is_none(), "no handshake has run yet");

        let _ = std::fs::remove_file(&cert_path);
        let _ = std::fs::remove_file(&key_path);
    }

    #[test]
    fn combined_pem_without_separate_key() {
        let (cert_pem, key_pem) = self_signed();
        let path = tmp("mtls-combined", "pem");
        std::fs::write(&path, format!("{cert_pem}{key_pem}")).unwrap();

        let opts = TlsOptions {
            verify: false,
            client_cert_file: Some(path.to_string_lossy().into_owned()),
            ..Default::default()
        };
        assert!(load_client_identity(&opts).unwrap().is_some());
        assert!(tls_client_config(&opts).is_ok());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn missing_key_is_an_error() {
        let (cert_pem, _key_pem) = self_signed();
        let path = tmp("mtls-nokey", "crt");
        std::fs::write(&path, cert_pem).unwrap();
        let opts = TlsOptions {
            verify: false,
            client_cert_file: Some(path.to_string_lossy().into_owned()),
            ..Default::default()
        };
        assert!(load_client_identity(&opts).is_err());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn no_cert_means_no_identity() {
        let opts = TlsOptions::server_only(true);
        assert!(load_client_identity(&opts).unwrap().is_none());
        assert!(tls_client_config(&opts).is_ok());
    }
}
