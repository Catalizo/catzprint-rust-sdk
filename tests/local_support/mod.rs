//! Fakes for the local-printing tests: a TLS station speaking the local API
//! (SPEC §4.2) with tokio + rustls, a stateful fake cloud, and an mDNS
//! responder. Everything runs on the test's tokio runtime.
#![allow(dead_code)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine as _;
use catzprint::{Client, LocalConfig};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, UdpSocket};
use tokio_rustls::rustls;
use tokio_rustls::TlsAcceptor;

pub const API_KEY: &str = "cz_test_abcdefghijklmnopqrstuvwxyz";

// ---- certificates ----

pub struct TestCert {
    pub der: Vec<u8>,
    pub key_der: Vec<u8>,
    pub fingerprint: String,
}

fn fixtures() -> Value {
    serde_json::from_str(include_str!("../fixtures/local-certs.json")).unwrap()
}

/// The DER inside a PEM block.
pub fn pem_der(pem: &str) -> Vec<u8> {
    let b64: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .concat();
    base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .unwrap()
}

pub fn cert(name: &str) -> TestCert {
    let f = fixtures();
    let c = &f[name];
    TestCert {
        der: pem_der(c["cert"].as_str().unwrap()),
        key_der: c["key"].as_str().map(pem_der).unwrap_or_default(),
        fingerprint: c["fingerprint"].as_str().unwrap().to_string(),
    }
}

pub fn ca_der() -> Vec<u8> {
    pem_der(fixtures()["ca"]["cert"].as_str().unwrap())
}

pub fn public_host() -> String {
    fixtures()["publicLeaf"]["host"]
        .as_str()
        .unwrap()
        .to_string()
}

pub fn public_spki() -> String {
    fixtures()["publicLeaf"]["spki_sha256"]
        .as_str()
        .unwrap()
        .to_string()
}

fn acceptor(c: &TestCert) -> TlsAcceptor {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cfg = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![rustls::pki_types::CertificateDer::from(c.der.clone())],
            rustls::pki_types::PrivateKeyDer::Pkcs8(c.key_der.clone().into()),
        )
        .unwrap();
    TlsAcceptor::from(Arc::new(cfg))
}

// ---- a tiny HTTP/1.1 server ----

#[derive(Clone, Debug)]
pub struct Req {
    pub method: String,
    pub path: String,
    pub query: String,
    pub auth: String,
    pub body: Value,
}

/// Status, body and a delay before answering.
pub type Handler = Arc<dyn Fn(&Req) -> (u16, String, Duration) + Send + Sync>;

async fn handle<S: AsyncRead + AsyncWrite + Unpin>(s: S, h: Handler) {
    let mut r = BufReader::new(s);
    let mut line = String::new();
    if r.read_line(&mut line).await.unwrap_or(0) == 0 {
        return;
    }
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let target = parts.next().unwrap_or("").to_string();
    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (target, String::new()),
    };
    let mut headers = HashMap::new();
    loop {
        let mut h = String::new();
        if r.read_line(&mut h).await.unwrap_or(0) == 0 || h == "\r\n" {
            break;
        }
        if let Some((k, v)) = h.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }
    let len: usize = headers
        .get("content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let mut body = vec![0; len];
    if r.read_exact(&mut body).await.is_err() {
        return;
    }
    let req = Req {
        method,
        path,
        query,
        auth: headers.get("authorization").cloned().unwrap_or_default(),
        body: serde_json::from_slice(&body).unwrap_or(Value::Null),
    };
    let (status, body, delay) = h(&req);
    if !delay.is_zero() {
        tokio::time::sleep(delay).await;
    }
    let resp = format!(
        "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let mut s = r.into_inner();
    let _ = s.write_all(resp.as_bytes()).await;
    let _ = s.flush().await;
    let _ = s.shutdown().await;
}

/// Serves `h` on 127.0.0.1 (over TLS with `tls`). Returns the port and a
/// count of accepted TCP connections.
async fn serve(tls: Option<TlsAcceptor>, h: Handler) -> (u16, Arc<AtomicUsize>) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let conns = Arc::new(AtomicUsize::new(0));
    let c2 = conns.clone();
    tokio::spawn(async move {
        loop {
            let Ok((sock, _)) = l.accept().await else {
                return;
            };
            c2.fetch_add(1, Ordering::SeqCst);
            let (tls, h) = (tls.clone(), h.clone());
            tokio::spawn(async move {
                match tls {
                    // A failed handshake (e.g. the client refused the pin)
                    // never reaches the handler.
                    Some(a) => {
                        if let Ok(s) = a.accept(sock).await {
                            handle(s, h).await
                        }
                    }
                    None => handle(sock, h).await,
                }
            });
        }
    });
    (port, conns)
}

pub fn err_body(code: &str) -> String {
    json!({"error": {"code": code, "message": format!("Station says {code}.")}}).to_string()
}

// ---- fake station ----

type Fail = Box<dyn Fn(&Req) -> Option<(u16, String)> + Send>;
type Accept = Box<dyn Fn(&str) -> bool + Send>;

#[derive(Default)]
pub struct StationState {
    pub reqs: Vec<Req>,
    /// None: any czl1./czd_ token.
    pub accept: Option<Accept>,
    pub fail: Option<Fail>,
    pub delay: Duration,
    pub jobs: HashMap<String, Value>,
    pub by_key: HashMap<String, String>,
    pub next_id: u64,
    /// The 401 code for refused tokens (default token_expired).
    pub reject_code: String,
    /// Reported as LocalJob.live when set.
    pub live: Option<bool>,
    /// Extra delay before answering POST /local/v1/jobs (after recording
    /// the job, unless `forget_jobs`).
    pub post_delay: Duration,
    /// Don't record POSTed jobs (the station never took them).
    pub forget_jobs: bool,
    /// Extra delay before answering GET /local/v1/jobs?idempotency_key=.
    pub find_delay: Duration,
    /// Keys used by jobs this caller can't see: the find answers
    /// `409 duplicate` for them.
    pub foreign_keys: Vec<String>,
    /// When set, POST /local/v1/jobs records the job but answers 201 with
    /// this body.
    pub post_body: Option<String>,
    /// POST /local/v1/jobs records the job but answers 409 in_progress.
    pub post_in_progress: bool,
    /// The find answers 409 in_progress this many times first.
    pub find_in_progress: usize,
}

#[derive(Clone)]
pub struct Station {
    pub url: String,
    pub port: u16,
    pub fp: String,
    pub state: Arc<Mutex<StationState>>,
    pub conns: Arc<AtomicUsize>,
}

impl Station {
    pub async fn start() -> Station {
        Station::start_with(&cert("selfSigned")).await
    }

    pub async fn start_with(c: &TestCert) -> Station {
        let state = Arc::new(Mutex::new(StationState::default()));
        let st = state.clone();
        let fp = c.fingerprint.clone();
        let fp2 = fp.clone();
        let h: Handler = Arc::new(move |r| station_serve(&st, &fp2, r));
        let (port, conns) = serve(Some(acceptor(c)), h).await;
        Station {
            url: format!("https://127.0.0.1:{port}"),
            port,
            fp,
            state,
            conns,
        }
    }

    pub fn requests(&self) -> Vec<Req> {
        self.state.lock().unwrap().reqs.clone()
    }

    /// GET /local/v1/jobs?idempotency_key=… requests.
    pub fn find_requests(&self) -> Vec<Req> {
        self.requests()
            .into_iter()
            .filter(|r| r.method == "GET" && r.path == "/local/v1/jobs")
            .collect()
    }

    pub fn job_requests(&self) -> Vec<Req> {
        self.requests()
            .into_iter()
            .filter(|r| r.method == "POST" && r.path == "/local/v1/jobs")
            .collect()
    }

    pub fn set(&self, f: impl FnOnce(&mut StationState)) {
        f(&mut self.state.lock().unwrap());
    }

    pub fn fail_jobs(&self, status: u16, code: &str) {
        let code = code.to_string();
        self.set(|s| {
            s.fail = Some(Box::new(move |r: &Req| {
                (r.path == "/local/v1/jobs").then(|| (status, code.clone()))
            }))
        });
    }
}

fn now() -> String {
    chrono::Utc::now().to_rfc3339()
}

fn station_serve(st: &Mutex<StationState>, fp: &str, r: &Req) -> (u16, String, Duration) {
    let mut s = st.lock().unwrap();
    s.reqs.push(r.clone());
    let delay = s.delay;
    if let Some(f) = &s.fail {
        if let Some((status, code)) = f(r) {
            // An empty code: a 503 without a code (a proxy, a crash page).
            let body = if code.is_empty() {
                "<html>Service Unavailable</html>".to_string()
            } else {
                err_body(&code)
            };
            return (status, body, delay);
        }
    }
    let ok = |b: Value| (200, b.to_string(), delay);
    match (r.method.as_str(), r.path.as_str()) {
        ("GET", "/local/v1/info") => {
            return ok(
                json!({"station_id": "st1", "name": "Kitchen PC", "org_id": "org1",
                "location_id": "loc1", "version": "3.0.0", "port": 7443, "tls_mode": "self_signed",
                "cert_fingerprint_sha256": fp, "hostnames": [], "addresses": ["127.0.0.1"],
                "pairing_open": true, "time": now()}),
            )
        }
        ("POST", "/local/v1/pair") => {
            if r.body["code"] != "12345678" {
                return (403, err_body("invalid_code"), delay);
            }
            return (
                201,
                json!({"device_id": "d_0123456789abcdef", "token": "czd_paired", "station_id": "st1",
                    "org_id": "org1", "location_id": "loc1"})
                .to_string(),
                delay,
            );
        }
        _ => {}
    }
    let tok = r.auth.strip_prefix("Bearer ").unwrap_or("");
    let accepted = match &s.accept {
        Some(f) => f(tok),
        None => tok.starts_with("czl1.") || tok.starts_with("czd_"),
    };
    if !accepted {
        let code = if s.reject_code.is_empty() {
            "token_expired".to_string()
        } else {
            s.reject_code.clone()
        };
        return (401, err_body(&code), delay);
    }
    match (r.method.as_str(), r.path.as_str()) {
        ("POST", "/local/v1/jobs") => {
            let delay = delay + s.post_delay;
            let key = r.body["idempotency_key"].as_str().unwrap_or("").to_string();
            if let Some(id) = s.by_key.get(&key).filter(|_| !key.is_empty()) {
                return (200, s.jobs[id].to_string(), delay);
            }
            s.next_id += 1;
            let id = format!("lj_{:016x}", s.next_id);
            let waited = r.query.contains("wait=");
            let mut j = json!({"id": id, "idempotency_key": key,
                "status": if waited { "printed" } else { "queued" }, "detail": "",
                "printer_id": "p-kitchen", "printer_name": "Kitchen", "role": r.body["role"],
                "location_id": "loc1", "copies": r.body["copies"].as_u64().unwrap_or(1),
                "title": r.body["title"], "reference": r.body["reference"], "created_at": now(),
                "finished_at": if waited { json!(now()) } else { Value::Null },
                "printed_locally": true, "via": "local", "cloud_job_id": null});
            if let Some(live) = s.live {
                j["live"] = json!(live);
            }
            if !s.forget_jobs {
                s.jobs.insert(id.clone(), j.clone());
                s.by_key.insert(key, id);
            }
            if s.post_in_progress {
                return (409, err_body("in_progress"), delay);
            }
            match &s.post_body {
                Some(b) => (201, b.clone(), delay),
                None => (201, j.to_string(), delay),
            }
        }
        ("GET", "/local/v1/jobs") => {
            let delay = delay + s.find_delay;
            let key = r
                .query
                .split('&')
                .find_map(|kv| kv.strip_prefix("idempotency_key="))
                .unwrap_or("")
                .to_string();
            if s.find_in_progress > 0 {
                s.find_in_progress -= 1;
                return (409, err_body("in_progress"), delay);
            }
            if s.foreign_keys.contains(&key) {
                return (409, err_body("duplicate"), delay);
            }
            match s.by_key.get(&key).filter(|_| !key.is_empty()) {
                Some(id) => (200, s.jobs[id].to_string(), delay),
                None => (404, err_body("not_found"), delay),
            }
        }
        ("GET", p) if p.starts_with("/local/v1/jobs/") => {
            let id = p.trim_start_matches("/local/v1/jobs/");
            match s.jobs.get_mut(id) {
                Some(j) => {
                    j["status"] = json!("printed");
                    j["finished_at"] = json!(now());
                    ok(j.clone())
                }
                None => (404, err_body("not_found"), delay),
            }
        }
        ("GET", "/local/v1/status") => ok(json!({
            "station": {"id": "st1", "name": "Kitchen PC", "cloud_connected": false,
                "last_cloud_contact": "", "version": "3.0.0", "local_enabled": true},
            "printers": [{"id": "p-kitchen", "name": "Kitchen", "role": "kitchen", "status": "ready",
                "paper": "ok", "jobs_waiting": 0}],
            "jobs_waiting": 0, "unsynced": 3,
            "allowance": {"expires_at": "2126-11-14T00:00:00Z", "prints_left": 1997}})),
        _ => (404, err_body("not_found"), delay),
    }
}

// ---- fake cloud ----

pub struct CloudState {
    pub mints: Vec<Value>,
    pub jobs: Vec<Value>,
    pub endpoints: usize,
    pub revoked: Vec<String>,
    /// When set, POST /jobs answers this status and code.
    pub job_error: Option<(u16, String)>,
    /// Per attempt, before `job_error`: (status, code, delay before the
    /// answer); status 0: answer normally after the delay; a 2xx status:
    /// answer `{"job": {}}`.
    pub job_script: std::collections::VecDeque<(u16, String, Duration)>,
    pub stations: Value,
    pub expires_in: chrono::Duration,
    /// The lifetime the minted token's claims state (default `expires_in`).
    pub token_ttl: Option<chrono::Duration>,
    /// Every request: 503.
    pub down: bool,
    pub mint_delay: Duration,
    /// GET /v1/public/server-key requests served.
    pub key_fetches: usize,
}

#[derive(Clone)]
pub struct Cloud {
    pub url: String,
    pub state: Arc<Mutex<CloudState>>,
}

pub fn make_local_token(jti: &str, live: bool) -> String {
    make_local_token_ttl(jti, live, chrono::Duration::days(30))
}

/// A token whose claims say it was issued now and lives `ttl`.
pub fn make_local_token_ttl(jti: &str, live: bool, ttl: chrono::Duration) -> String {
    let iat = chrono::Utc::now().timestamp();
    let exp = iat + ttl.num_seconds();
    let p = json!({"v": 1, "kid": "k1", "jti": jti, "org": "org1", "key": "key1", "loc": null,
        "dev": "hub", "live": live, "iat": iat, "exp": exp});
    format!(
        "czl1.{}.c2ln",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(p.to_string())
    )
}

pub fn token_jti(tok: &str) -> String {
    let parts: Vec<&str> = tok.split('.').collect();
    if parts.len() != 3 {
        return String::new();
    }
    let b = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .unwrap_or_default();
    serde_json::from_slice::<Value>(&b).unwrap_or(Value::Null)["jti"]
        .as_str()
        .unwrap_or("")
        .to_string()
}

impl Cloud {
    pub async fn start() -> Cloud {
        let state = Arc::new(Mutex::new(CloudState {
            mints: vec![],
            jobs: vec![],
            endpoints: 0,
            revoked: vec![],
            job_error: None,
            job_script: Default::default(),
            stations: json!([]),
            expires_in: chrono::Duration::days(30),
            token_ttl: None,
            down: false,
            mint_delay: Duration::ZERO,
            key_fetches: 0,
        }));
        let st = state.clone();
        let h: Handler = Arc::new(move |r| cloud_serve(&st, r));
        let (port, _) = serve(None, h).await;
        Cloud {
            url: format!("http://127.0.0.1:{port}"),
            state,
        }
    }

    /// A cloud nobody listens to (network errors).
    pub fn dead() -> Cloud {
        Cloud {
            url: "http://127.0.0.1:1".into(),
            state: Arc::new(Mutex::new(CloudState {
                mints: vec![],
                jobs: vec![],
                endpoints: 0,
                revoked: vec![],
                job_error: None,
                job_script: Default::default(),
                stations: json!([]),
                expires_in: chrono::Duration::days(30),
                token_ttl: None,
                down: true,
                mint_delay: Duration::ZERO,
                key_fetches: 0,
            })),
        }
    }

    pub fn counts(&self) -> (usize, usize) {
        let s = self.state.lock().unwrap();
        (s.mints.len(), s.jobs.len())
    }

    pub fn last_job(&self) -> Value {
        self.state
            .lock()
            .unwrap()
            .jobs
            .last()
            .cloned()
            .unwrap_or(Value::Null)
    }

    pub fn set(&self, f: impl FnOnce(&mut CloudState)) {
        f(&mut self.state.lock().unwrap());
    }
}

fn cloud_serve(st: &Mutex<CloudState>, r: &Req) -> (u16, String, Duration) {
    let mut s = st.lock().unwrap();
    if s.down {
        return (
            503,
            json!({"error": {"code": "unavailable", "message": "Down."}}).to_string(),
            Duration::ZERO,
        );
    }
    let z = Duration::ZERO;
    match (r.method.as_str(), r.path.as_str()) {
        ("POST", "/v1/orgs/org1/local-tokens") => {
            s.mints.push(r.body.clone());
            let jti = format!("jti-{}", s.mints.len());
            let exp = (chrono::Utc::now() + s.expires_in).to_rfc3339();
            let ttl = s.token_ttl.unwrap_or(s.expires_in);
            let body = json!({"token": make_local_token_ttl(&jti, true, ttl), "token_id": jti,
                "expires_at": exp, "stations": s.stations});
            (201, body.to_string(), s.mint_delay)
        }
        ("DELETE", p) if p.starts_with("/v1/orgs/org1/local-tokens/") => {
            s.revoked
                .push(p.trim_start_matches("/v1/orgs/org1/local-tokens/").into());
            (204, String::new(), z)
        }
        ("GET", "/v1/orgs/org1/local-endpoints") => {
            s.endpoints += 1;
            (200, json!({"stations": s.stations}).to_string(), z)
        }
        // The X25519 base point: a valid key for sealing.
        ("GET", "/v1/public/server-key") => {
            s.key_fetches += 1;
            (
                200,
                json!({"public_key": base64::engine::general_purpose::STANDARD
                    .encode([9u8].iter().chain([0u8; 31].iter()).copied().collect::<Vec<u8>>())})
                .to_string(),
                z,
            )
        }
        ("GET", "/v1/orgs/org1/printers") => (200, json!({"printers": []}).to_string(), z),
        ("POST", "/v1/orgs/org1/jobs") => {
            s.jobs.push(r.body.clone());
            if let Some((status, code, delay)) = s.job_script.pop_front() {
                if (200..300).contains(&status) {
                    // A 2xx without a job.
                    return (status, json!({"job": {}}).to_string(), delay);
                }
                if code == "seal400" {
                    // The server key was rotated: the sealed content can't be decrypted.
                    let b = json!({"error": {"code": "invalid", "message": "Couldn't decrypt.",
                        "fields": {"sealed_content": "Couldn't decrypt."}}});
                    return (400, b.to_string(), delay);
                }
                if (300..400).contains(&status) {
                    return (status, String::new(), delay);
                }
                if status != 0 {
                    let b = json!({"error": {"code": code, "message": "Cloud says no."}});
                    return (status, b.to_string(), delay);
                }
                let b = json!({"job": {"id": "cloud-1", "status": "queued",
                    "idempotency_key": r.body["idempotency_key"]}});
                return (201, b.to_string(), delay);
            }
            if let Some((status, code)) = &s.job_error {
                let b = json!({"error": {"code": code, "message": "Cloud says no."}});
                return (*status, b.to_string(), z);
            }
            let b = json!({"job": {"id": "cloud-1", "status": "queued",
                "idempotency_key": r.body["idempotency_key"]}});
            (201, b.to_string(), z)
        }
        _ => (
            404,
            json!({"error": {"code": "not_found", "message": "Nope."}}).to_string(),
            z,
        ),
    }
}

/// A client against the fake cloud with a fast local configuration:
/// `f` adds the test's settings on top of the defaults.
pub fn local_client(cloud: &Cloud, f: impl FnOnce(LocalConfig) -> LocalConfig) -> Client {
    let cfg = LocalConfig::default()
        .connect_timeout(Duration::from_secs(1))
        .request_timeout(Duration::from_secs(2))
        .cloud_timeout(Duration::from_secs(2))
        .discover_timeout(Duration::from_millis(200))
        .device_name("Hub")
        .all_locations(true);
    Client::builder()
        .api_key(API_KEY)
        .base_url(&cloud.url)
        .org_id("org1")
        .retry_base_delay(Duration::from_millis(1))
        .local(f(cfg))
        .build()
        .unwrap()
}

/// An https URL on a closed local port.
pub async fn dead_url() -> String {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    drop(l);
    format!("https://{addr}")
}

// ---- mDNS ----

pub const SERVICE: &str = "_catzprint._tcp.local.";

fn dns_name(n: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for l in n.trim_end_matches('.').split('.') {
        out.push(l.len() as u8);
        out.extend_from_slice(l.as_bytes());
    }
    out.push(0);
    out
}

fn rr(n: &str, typ: u16, rdata: Vec<u8>) -> Vec<u8> {
    let mut out = dns_name(n);
    out.extend_from_slice(&typ.to_be_bytes());
    out.extend_from_slice(&0x8001u16.to_be_bytes());
    out.extend_from_slice(&120u32.to_be_bytes());
    out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    out.extend(rdata);
    out
}

/// A complete station announcement as SPEC §4.8 describes it.
pub fn mdns_answer(
    name: &str,
    id: &str,
    org: &str,
    loc: &str,
    port: u16,
    fp: &str,
    ip: [u8; 4],
) -> Vec<u8> {
    let inst = format!("{name} (CatzPrint).{SERVICE}");
    let host = format!("catzprint-{id}.local.");
    let mut srv = vec![0, 0, 0, 0];
    srv.extend_from_slice(&port.to_be_bytes());
    srv.extend(dns_name(&host));
    let mut txt = Vec::new();
    for kv in [
        "v=1".to_string(),
        format!("id={id}"),
        format!("org={org}"),
        format!("loc={loc}"),
        format!("port={port}"),
        format!("fp={fp}"),
        "tls=self_signed".into(),
        "host=".into(),
    ] {
        txt.push(kv.len() as u8);
        txt.extend_from_slice(kv.as_bytes());
    }
    let records = [
        rr(SERVICE, 12, dns_name(&inst)),
        rr(&inst, 33, srv),
        rr(&inst, 16, txt),
        rr(&host, 1, ip.to_vec()),
    ];
    let mut m = vec![0u8; 12];
    m[2] = 0x84;
    m[7] = 1; // one answer
    m[11] = 3; // three additionals
    for r in records {
        m.extend(r);
    }
    m
}

/// Answers every CatzPrint query with `reply`, unicast to the sender (what a
/// responder does for a QU / legacy-unicast query). Returns its address.
pub async fn fake_responder(reply: Vec<u8>) -> SocketAddr {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    let want = dns_name(SERVICE);
    tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        loop {
            let Ok((n, from)) = sock.recv_from(&mut buf).await else {
                return;
            };
            let q = &buf[..n];
            if n < 12 + want.len() || q[2] & 0x80 != 0 || q[12..12 + want.len()] != want[..] {
                continue;
            }
            let _ = sock.send_to(&reply, from).await;
        }
    });
    addr
}
