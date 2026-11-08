//! Talking to stations: trust (certificate / public-key pinning), HTTP
//! clients per trust setting, and one request with the "unreachable"
//! classification that drives fallbacks.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use reqwest::header::{ACCEPT, CONTENT_TYPE, RETRY_AFTER, USER_AGENT as UA};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{CertificateError, DigitallySignedStruct, OtherError, SignatureScheme};
use serde::de::DeserializeOwned;
use serde_json::Value;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::core::{parse_retry_after, USER_AGENT};
use crate::error::{body_code, map_error, ApiError, Error};

/// One URL to try, with how to trust it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Target {
    /// `https://host:port`, no trailing slash.
    pub url: String,
    /// Lower-case hex SHA-256 of the certificate DER, or "".
    pub fingerprint: String,
    /// `public`, `self_signed` or "" (unknown).
    pub tls_mode: String,
    pub station_id: String,
    /// `config`, `cloud` or `mdns`.
    pub source: &'static str,
    /// Hex SHA-256 of the public certificate's SubjectPublicKeyInfo, pinned
    /// on top of normal verification for public hostnames (cloud list only).
    pub spki: String,
    /// The station's local label: a dashed-IP hostname is dialled directly
    /// only under it (`"<a-b-c-d>.<label>.<zone>"`).
    pub label: String,
}

impl Target {
    /// Whether the URL can only be trusted by fingerprint: raw IP addresses,
    /// `.local` names and stations known to be self-signed. Public hostnames
    /// are verified with the web PKI like any website.
    pub fn needs_pin(&self) -> bool {
        let (host, _) = url_host(&self.url);
        host.is_empty()
            || host_ip(&host).is_some()
            || host.ends_with(".local")
            || self.tls_mode == "self_signed"
    }
}

/// Accepts hex with optional colons, spaces or dashes and returns lower-case
/// hex, or "" when it isn't 32 bytes of hex.
pub(crate) fn normalize_fingerprint(fp: &str) -> String {
    let s: String = fp
        .trim()
        .chars()
        .filter(|c| !matches!(c, ':' | ' ' | '-'))
        .collect::<String>()
        .to_ascii_lowercase();
    if s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()) {
        s
    } else {
        String::new()
    }
}

/// Checks a station URL (https only, no credentials, path, query or
/// fragment) and returns `https://host[:port]` in lower case.
pub(crate) fn normalize_station_url(raw: &str) -> Result<String, Error> {
    let bad = |why: &str| Error::Config(format!("station URL {raw:?} {why}"));
    let u = reqwest::Url::parse(raw.trim()).map_err(|_| bad("isn't a valid URL"))?;
    let host = match u.host_str() {
        Some(h) if !h.is_empty() => h.to_ascii_lowercase(),
        _ => return Err(bad("isn't a valid URL")),
    };
    if u.scheme() != "https" {
        return Err(bad("must use https://"));
    }
    if !u.username().is_empty()
        || u.password().is_some()
        || u.query().is_some()
        || u.fragment().is_some()
        || (u.path() != "" && u.path() != "/")
    {
        return Err(bad("must be just https://host:port"));
    }
    Ok(match u.port() {
        Some(p) => format!("https://{host}:{p}"),
        None => format!("https://{host}"),
    })
}

/// The host (lower case, IPv6 in brackets) and port (443 by default) of a URL.
pub(crate) fn url_host(u: &str) -> (String, u16) {
    match reqwest::Url::parse(u) {
        Ok(p) => (
            p.host_str().unwrap_or("").to_ascii_lowercase(),
            p.port_or_known_default().unwrap_or(443),
        ),
        Err(_) => (String::new(), 0),
    }
}

/// The IP a host string names (brackets allowed), if it is one.
pub(crate) fn host_ip(h: &str) -> Option<IpAddr> {
    h.trim_start_matches('[').trim_end_matches(']').parse().ok()
}

/// `https://<ip>:<port>`, with brackets for IPv6.
pub(crate) fn ip_url(ip: &str, port: u16) -> String {
    match ip.parse::<IpAddr>() {
        Ok(IpAddr::V6(v6)) => format!("https://[{v6}]:{port}"),
        _ => format!("https://{ip}:{port}"),
    }
}

/// Whether `h` is an IP a station may use on the LAN: RFC 1918, IPv6 ULA,
/// link-local, or loopback (tests). Anything else from the cloud list or
/// mDNS is ignored.
pub(crate) fn private_ip(h: &str) -> bool {
    match host_ip(h) {
        Some(IpAddr::V4(v4)) => private_v4(v4),
        Some(IpAddr::V6(v6)) => match v6.to_ipv4_mapped() {
            Some(v4) => private_v4(v4),
            None => {
                let s = v6.segments()[0];
                v6.is_loopback() || (s & 0xfe00) == 0xfc00 || (s & 0xffc0) == 0xfe80
            }
        },
        None => false,
    }
}

fn private_v4(v4: Ipv4Addr) -> bool {
    v4.is_private() || v4.is_loopback() || v4.is_link_local()
}

/// Decodes the station hostname scheme `"<a>-<b>-<c>-<d>.<label>.<zone>"` to
/// the private (or loopback) IPv4 it names, so the SDK can connect while
/// public DNS is unreachable. Only names under the given station label (from
/// the cloud endpoint list) are mapped; the certificate is still verified
/// for the hostname and its public key pinned.
pub(crate) fn dashed_ip(host: &str, label: &str) -> Option<Ipv4Addr> {
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() < 3 || label.is_empty() || labels[1] != label {
        return None;
    }
    let parts: Vec<&str> = labels[0].split('-').collect();
    if parts.len() != 4 {
        return None;
    }
    let ip: Ipv4Addr = parts.join(".").parse().ok()?;
    (ip.is_private() || ip.is_loopback()).then_some(ip)
}

// ---- TLS ----

/// Carried inside the rustls error when a pin doesn't match, so the SDK can
/// report [`Error::PinMismatch`].
#[derive(Debug)]
struct PinMismatchDetail {
    expected: String,
    got: String,
    spki: bool,
}

impl std::fmt::Display for PinMismatchDetail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "pinned fingerprint mismatch: got {}", self.got)
    }
}

impl std::error::Error for PinMismatchDetail {}

fn pin_error(expected: &str, got: &[u8], spki: bool) -> rustls::Error {
    rustls::Error::InvalidCertificate(CertificateError::Other(OtherError(Arc::new(
        PinMismatchDetail {
            expected: expected.to_string(),
            got: hex::encode(got),
            spki,
        },
    ))))
}

fn decode_pin(hex_fp: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    if let Ok(b) = hex::decode(hex_fp) {
        if b.len() == 32 {
            out.copy_from_slice(&b);
        }
    }
    out
}

/// Trusts exactly one certificate: the leaf's SHA-256 must be the pinned
/// one (the chain isn't checked against CAs). Runs during the handshake, so
/// a mismatch means nothing is sent.
#[derive(Debug)]
struct CertPinVerifier {
    want: [u8; 32],
    want_hex: String,
    algs: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for CertPinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let got = Sha256::digest(end_entity.as_ref());
        if bool::from(got.as_slice().ct_eq(&self.want)) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(pin_error(&self.want_hex, &got, false))
        }
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algs)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algs)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}

/// Normal web-PKI verification, then the leaf's public key must be the one
/// the cloud endpoint list reports (`public_spki_sha256`).
#[derive(Debug)]
struct SpkiPinVerifier {
    inner: Arc<WebPkiServerVerifier>,
    want: [u8; 32],
    want_hex: String,
}

impl ServerCertVerifier for SpkiPinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        )?;
        let parsed = rustls::server::ParsedCertificate::try_from(end_entity)?;
        let got = Sha256::digest(parsed.subject_public_key_info().as_ref());
        if bool::from(got.as_slice().ct_eq(&self.want)) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(pin_error(&self.want_hex, &got, true))
        }
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// The error for an IP or self-signed URL with no fingerprint: never
/// trusted on first use, and never contacted.
pub(crate) fn no_pin_error() -> Error {
    Error::Config(
        "no pinned certificate fingerprint for this address (IP and self-signed stations are \
         only trusted with the fingerprint from the cloud endpoint list, mDNS of a listed \
         station or LocalConfig::fingerprint)"
            .into(),
    )
}

/// Settings that shape a station HTTP client.
pub(crate) struct ClientSettings<'a> {
    pub connect_timeout: Duration,
    /// DER root certificates for public hostnames; empty: the bundled
    /// Mozilla roots (`webpki-roots`), as the cloud client uses.
    pub roots: &'a [Vec<u8>],
}

/// The cache key of a target's client: everything that changes how it is
/// trusted or dialled.
pub(crate) fn client_key(t: &Target) -> String {
    let (host, port) = url_host(&t.url);
    let pin = if t.needs_pin() {
        t.fingerprint.as_str()
    } else {
        ""
    };
    format!("{host}:{port}|{pin}|{}|{}", t.spki, t.label)
}

/// Builds the HTTP client for a target. Fails (without any network
/// activity) when an address needs a pin and has none.
pub(crate) fn station_client(t: &Target, s: &ClientSettings<'_>) -> Result<reqwest::Client, Error> {
    let provider: Arc<CryptoProvider> = Arc::new(rustls::crypto::ring::default_provider());
    let algs = provider.signature_verification_algorithms;
    let verifier: Arc<dyn ServerCertVerifier> = if t.needs_pin() {
        if t.fingerprint.is_empty() {
            return Err(no_pin_error());
        }
        Arc::new(CertPinVerifier {
            want: decode_pin(&t.fingerprint),
            want_hex: t.fingerprint.clone(),
            algs,
        })
    } else {
        let mut roots = rustls::RootCertStore::empty();
        if s.roots.is_empty() {
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        } else {
            for der in s.roots {
                roots
                    .add(CertificateDer::from(der.clone()))
                    .map_err(|e| Error::Config(format!("invalid root certificate: {e}")))?;
            }
        }
        let web = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
            .build()
            .map_err(|e| Error::Config(format!("couldn't set up TLS verification: {e}")))?;
        if t.spki.is_empty() {
            web
        } else {
            Arc::new(SpkiPinVerifier {
                inner: web,
                want: decode_pin(&t.spki),
                want_hex: t.spki.clone(),
            })
        }
    };
    let tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| Error::Config(format!("couldn't set up TLS: {e}")))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    let mut b = reqwest::Client::builder()
        .use_preconfigured_tls(tls)
        // Stations are on the LAN: never through a proxy.
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(s.connect_timeout)
        .pool_max_idle_per_host(2)
        .pool_idle_timeout(Duration::from_secs(60));
    let (host, port) = url_host(&t.url);
    if host_ip(&host).is_none() && !t.label.is_empty() {
        if let Some(ip) = dashed_ip(&host, &t.label) {
            b = b.resolve(&host, SocketAddr::new(IpAddr::V4(ip), port));
        }
    }
    b.build()
        .map_err(|e| Error::Config(format!("couldn't create the station HTTP client: {e}")))
}

/// Finds a pin mismatch anywhere in an error's source chain (through
/// `io::Error`s, whose `source()` skips their inner error).
fn find_pin_mismatch(e: &(dyn std::error::Error + 'static)) -> Option<Error> {
    let mut cur: Option<&(dyn std::error::Error + 'static)> = Some(e);
    let mut depth = 0;
    while let Some(err) = cur {
        depth += 1;
        if depth > 32 {
            return None;
        }
        if let Some(d) = err.downcast_ref::<PinMismatchDetail>() {
            return Some(Error::PinMismatch {
                expected: d.expected.clone(),
                got: d.got.clone(),
                spki: d.spki,
            });
        }
        if let Some(rustls::Error::InvalidCertificate(CertificateError::Other(o))) =
            err.downcast_ref::<rustls::Error>()
        {
            if let Some(found) = find_pin_mismatch(&*o.0) {
                return Some(found);
            }
        }
        if let Some(io) = err.downcast_ref::<std::io::Error>() {
            if let Some(inner) = io.get_ref() {
                if let Some(found) = find_pin_mismatch(inner) {
                    return Some(found);
                }
            }
        }
        cur = err.source();
    }
    None
}

/// The whole cause chain of a reqwest error as one message.
fn chain_message(e: &reqwest::Error) -> String {
    let mut parts = vec![e.to_string()];
    let mut cur = std::error::Error::source(e);
    while let Some(err) = cur {
        let s = err.to_string();
        if !parts.iter().any(|p| p.contains(&s)) {
            parts.push(s);
        }
        cur = err.source();
    }
    parts.join(": ")
}

/// A failed station request.
#[derive(Debug)]
pub(crate) enum SendError {
    /// This station can't be used now and didn't get the request
    /// (NOT_DELIVERED: connect/DNS/TLS/pin errors or anything before the
    /// whole request was written, 502/504, 503 `local_disabled` or without a
    /// code): try the next one.
    Unreachable(Error),
    /// The station answered: return this to the caller.
    Answer(Error),
    /// DELIVERED_NO_ANSWER (only with tracking): the whole request was
    /// written, then no usable answer came (timeout, reset, body read error,
    /// an answer too large or unreadable, a redirect). The station may have
    /// taken the job.
    NoAnswer(Error),
}

/// A request body that records when the connection has taken it. Until then
/// the request can't have been fully written, so the job was certainly not
/// delivered; afterwards it may have been (hyper may still be flushing, which
/// errs on the safe side: "maybe delivered" is settled by asking the
/// station). Keeps an exact size, so `Content-Length` is still sent.
pub(crate) struct TrackedBody {
    data: Option<bytes::Bytes>,
    len: u64,
    taken: Arc<AtomicBool>,
}

impl TrackedBody {
    pub(crate) fn new(data: bytes::Bytes, taken: Arc<AtomicBool>) -> Self {
        TrackedBody {
            len: data.len() as u64,
            data: Some(data),
            taken,
        }
    }
}

impl http_body::Body for TrackedBody {
    type Data = bytes::Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        let frame = self.data.take().map(|d| {
            self.taken.store(true, Ordering::SeqCst);
            Ok(http_body::Frame::data(d))
        });
        std::task::Poll::Ready(frame)
    }

    fn is_end_stream(&self) -> bool {
        self.data.is_none()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        http_body::SizeHint::with_exact(if self.data.is_some() { self.len } else { 0 })
    }
}

/// A body of these exact bytes for a tracked request, and the flag it sets
/// once taken.
pub(crate) fn tracked_bytes(data: bytes::Bytes) -> (reqwest::Body, Arc<AtomicBool>) {
    let taken = Arc::new(AtomicBool::new(false));
    (
        reqwest::Body::wrap(TrackedBody::new(data, taken.clone())),
        taken,
    )
}

/// A JSON body for a tracked request, and the flag it sets once taken.
pub(crate) fn tracked_json(v: &Value) -> (reqwest::Body, Arc<AtomicBool>) {
    tracked_bytes(bytes::Bytes::from(
        serde_json::to_vec(v).unwrap_or_default(),
    ))
}

const MAX_LOCAL_RESPONSE_BYTES: usize = 4 << 20;

/// Makes one request to a station with an already-built client.
///
/// With `track` (job creation), a failure after the whole body was handed
/// to the connection is [`SendError::NoAnswer`], not `Unreachable`: the
/// station may have taken the job, so the caller must not just try the next
/// one. Without it, timeouts and redirects are `Unreachable` and an
/// oversized or unreadable answer is an `Answer`.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn send<T: DeserializeOwned + Default>(
    hc: &reqwest::Client,
    url: &str,
    method: reqwest::Method,
    query: &[(&str, String)],
    token: &str,
    body: Option<&Value>,
    timeout: Duration,
    track: bool,
) -> Result<T, SendError> {
    let mut rb = hc
        .request(method, url)
        .timeout(timeout)
        .header(ACCEPT, "application/json")
        .header(UA, USER_AGENT);
    if !query.is_empty() {
        rb = rb.query(query);
    }
    if !token.is_empty() {
        rb = rb.bearer_auth(token);
    }
    let mut taken = None;
    if let Some(b) = body {
        let (body, flag) = tracked_json(b);
        rb = rb.header(CONTENT_TYPE, "application/json").body(body);
        taken = Some(flag);
    }
    // Whether a failure now may have left the job at the station.
    let delivered = || {
        track
            && taken
                .as_ref()
                .is_some_and(|t: &Arc<AtomicBool>| t.load(Ordering::SeqCst))
    };
    let net_error = |e: reqwest::Error| {
        find_pin_mismatch(&e).unwrap_or_else(|| Error::Connection {
            message: chain_message(&e),
            timeout: e.is_timeout(),
        })
    };
    let failed = |e: reqwest::Error| {
        let err = net_error(e);
        // A pin mismatch or a connect error happens before anything is sent.
        if delivered() && !matches!(err, Error::PinMismatch { .. }) {
            SendError::NoAnswer(err)
        } else {
            SendError::Unreachable(err)
        }
    };
    let mut resp = rb.send().await.map_err(failed)?;
    let status = resp.status().as_u16();
    let retry_after = parse_retry_after(
        resp.headers()
            .get(RETRY_AFTER)
            .and_then(|v| v.to_str().ok()),
    );
    let mut buf = Vec::new();
    let mut too_large = resp
        .content_length()
        .is_some_and(|n| n > MAX_LOCAL_RESPONSE_BYTES as u64);
    while !too_large {
        // The station answered: a broken body is "no answer" with tracking.
        let chunk = resp.chunk().await.map_err(|e| {
            if track {
                SendError::NoAnswer(net_error(e))
            } else {
                SendError::Unreachable(net_error(e))
            }
        })?;
        match chunk {
            Some(c) if buf.len() + c.len() > MAX_LOCAL_RESPONSE_BYTES => too_large = true,
            Some(c) => buf.extend_from_slice(&c),
            None => break,
        }
    }
    if too_large {
        let e = Error::Api(ApiError {
            status,
            code: "response_too_large".into(),
            message: "The station's answer is too large.".into(),
            fields: BTreeMap::new(),
            retry_after: None,
        });
        return Err(if track {
            SendError::NoAnswer(e)
        } else {
            SendError::Answer(e)
        });
    }
    if status >= 300 {
        let code = body_code(&buf);
        let mut e = map_error(status, retry_after, &buf);
        // A 404 without the station's error body (a proxy, a station without
        // that route) keeps no code: only the station's own `not_found`
        // says a job was never recorded.
        if let (404, None, Error::NotFound(a)) = (status, &code, &mut e) {
            a.code.clear();
        }
        return Err(match status {
            // The station answered and refused: nothing was taken.
            502 | 504 => SendError::Unreachable(e),
            503 if code.is_none() || code.as_deref() == Some("local_disabled") => {
                SendError::Unreachable(e)
            }
            // Not a station: something on the network redirected us (after
            // possibly forwarding the request).
            300..=399 if track => SendError::NoAnswer(e),
            300..=399 => SendError::Unreachable(e),
            _ => SendError::Answer(e),
        });
    }
    if buf.iter().all(u8::is_ascii_whitespace) {
        return Ok(T::default());
    }
    serde_json::from_slice(&buf).map_err(|e| {
        let e = Error::Decode(format!(
            "the station returned a response the SDK couldn't read: {e}"
        ));
        if track {
            SendError::NoAnswer(e)
        } else {
            SendError::Answer(e)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dashed_ip_only_under_the_label() {
        for (host, label, want) in [
            (
                "192-168-1-20.ab3k9x2mqp.local.catzprint.com",
                "ab3k9x2mqp",
                "192.168.1.20",
            ),
            (
                "192-168-1-20.ab3k9x2mqp.local.catzprint.com",
                "otherlabel",
                "",
            ),
            ("192-168-1-20.ab3k9x2mqp.local.catzprint.com", "", ""),
            ("10-0-0-5.x.y", "x", "10.0.0.5"),
            ("8-8-8-8.x.local.catzprint.com", "x", ""),
            ("192-168-1.x.y", "x", ""),
            ("192-168-1-20.com", "com", ""),
            ("printer.example.com", "example", ""),
        ] {
            let got = dashed_ip(host, label)
                .map(|i| i.to_string())
                .unwrap_or_default();
            assert_eq!(got, want, "{host}/{label}");
        }
    }

    #[test]
    fn private_addresses() {
        for ok in [
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.20",
            "169.254.1.1",
            "127.0.0.1",
            "[fd00::1]",
            "fe80::1",
            "::1",
            "::ffff:192.168.1.1",
        ] {
            assert!(private_ip(ok), "{ok}");
        }
        for bad in [
            "203.0.113.9",
            "8.8.8.8",
            "100.64.0.1",
            "2001:db8::1",
            "example.com",
            "",
        ] {
            assert!(!private_ip(bad), "{bad}");
        }
    }

    #[test]
    fn fingerprints_and_urls() {
        let fp = "AB:".repeat(31) + "AB";
        assert_eq!(normalize_fingerprint(&fp), "ab".repeat(32));
        assert_eq!(normalize_fingerprint("abc"), "");
        assert_eq!(normalize_fingerprint(&"zz".repeat(32)), "");
        assert_eq!(
            normalize_station_url(" https://192.168.1.20:7443/ ").unwrap(),
            "https://192.168.1.20:7443"
        );
        assert_eq!(
            normalize_station_url("https://Host.Example:7443").unwrap(),
            "https://host.example:7443"
        );
        for bad in [
            "http://192.168.1.20:7443",
            "https://192.168.1.20:7443/x",
            "https://u:p@192.168.1.20:7443",
            "https://192.168.1.20:7443?x=1",
            "nope",
        ] {
            assert!(normalize_station_url(bad).is_err(), "{bad}");
        }
        let t = Target {
            url: "https://[fd00::1]:7443".into(),
            ..Default::default()
        };
        assert!(t.needs_pin());
        assert_eq!(url_host(&t.url), ("[fd00::1]".into(), 7443));
        let h = Target {
            url: "https://a.example.com:7443".into(),
            ..Default::default()
        };
        assert!(!h.needs_pin());
        assert!(Target {
            tls_mode: "self_signed".into(),
            ..h
        }
        .needs_pin());
    }
}
