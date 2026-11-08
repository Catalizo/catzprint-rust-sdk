//! Local (offline) printing through CatzPrint stations on the same network
//! (feature `local`, on by default).
//!
//! Enable it with [`crate::ClientBuilder::local`]; see [`LocalConfig`] and the
//! README section "Local printing (offline)".

mod cloud;
mod mdns;
mod models;
mod store;
pub(crate) mod transport;

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use base64::Engine as _;
use chrono::{DateTime, TimeDelta, Utc};
use reqwest::Method;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::task::JoinHandle;

use crate::client::{Client, CloudAttempt};
use crate::core::{is_duplicate, sealed_rejected, seg, DUPLICATE_PAUSE, DUPLICATE_RESENDS};
use crate::error::{ApiError, Error, Result, StationAttempt};
use crate::models::{Job, JobStatus, Via};
use crate::params::{detect_kind, Content, CreateJob};

pub use cloud::{LocalEndpoints, LocalTokens};
pub use models::{
    LocalAllowance, LocalEndpoint, LocalInfo, LocalJob, LocalPairing, LocalPrinterStatus,
    LocalStation, LocalStationState, LocalStatus, LocalToken, LocalTokenParams,
};
pub use store::{FileTokenStore, MemoryTokenStore, StoreFuture, StoredToken, TokenStore};

use cloud::invalid;
use mdns::MdnsStation;
use transport::{
    client_key, host_ip, ip_url, normalize_fingerprint, normalize_station_url, private_ip,
    url_host, ClientSettings, SendError, Target,
};

const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
const DEFAULT_CLOUD_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_DISCOVER_TIMEOUT: Duration = Duration::from_millis(1500);
const MAX_LOCAL_WAIT: Duration = Duration::from_secs(30);
const TOKEN_REFRESH_BEFORE: TimeDelta = TimeDelta::days(7);
const ENDPOINTS_MAX_AGE: TimeDelta = TimeDelta::hours(1);
const MDNS_CACHE_TTL: TimeDelta = TimeDelta::minutes(1);
const REFRESH_RETRY_AFTER: TimeDelta = TimeDelta::minutes(5);
/// Re-minting after a station refused a token: at most once per 10 minutes.
const REMINT_INTERVAL: TimeDelta = TimeDelta::minutes(10);

/// Where [`crate::Jobs::create`] sends jobs.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum LocalMode {
    /// Every job goes to the CatzPrint API (the default; same behaviour as
    /// before 2.2.0).
    #[default]
    Cloud,
    /// Jobs go only to stations on the local network.
    Local,
    /// Stations first; the cloud only when no station can be reached.
    LocalFirst,
    /// The cloud first; the stations on a network error, timeout or 5xx.
    CloudFirst,
}

impl LocalMode {
    /// `"cloud"`, `"local"`, `"local_first"` or `"cloud_first"`.
    pub fn as_str(&self) -> &'static str {
        match self {
            LocalMode::Cloud => "cloud",
            LocalMode::Local => "local",
            LocalMode::LocalFirst => "local_first",
            LocalMode::CloudFirst => "cloud_first",
        }
    }
}

impl std::fmt::Display for LocalMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for LocalMode {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        match s {
            "cloud" => Ok(LocalMode::Cloud),
            "local" => Ok(LocalMode::Local),
            "local_first" => Ok(LocalMode::LocalFirst),
            "cloud_first" => Ok(LocalMode::CloudFirst),
            _ => Err(Error::Config(format!(
                "unknown local mode {s:?} (use cloud, local, local_first or cloud_first)"
            ))),
        }
    }
}

/// Configures local printing ([`crate::ClientBuilder::local`]).
///
/// ```no_run
/// # fn main() -> catzprint::Result<()> {
/// use catzprint::{Client, FileTokenStore, LocalConfig, LocalMode};
/// let client = Client::builder()
///     .api_key("cz_live_...")
///     .local(
///         LocalConfig::new(LocalMode::LocalFirst)
///             .location_id("loc_123")
///             .discover(true)
///             .token_store(FileTokenStore::new("/var/lib/catzserve/catzprint-local.json")),
///     )
///     .build()?;
/// # let _ = client; Ok(()) }
/// ```
#[derive(Clone, Default)]
pub struct LocalConfig {
    mode: LocalMode,
    location_id: Option<String>,
    station_urls: Vec<String>,
    fingerprints: Vec<(String, String)>,
    discover: bool,
    all_locations: bool,
    token_store: Option<Arc<dyn TokenStore>>,
    token: Option<String>,
    device_name: Option<String>,
    token_ttl_days: Option<u32>,
    connect_timeout: Option<Duration>,
    request_timeout: Option<Duration>,
    cloud_timeout: Option<Duration>,
    discover_timeout: Option<Duration>,
    wait: Duration,
    root_certificates: Vec<Vec<u8>>,
}

impl std::fmt::Debug for LocalConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalConfig")
            .field("mode", &self.mode)
            .field("location_id", &self.location_id)
            .field("station_urls", &self.station_urls)
            .field("discover", &self.discover)
            .field("all_locations", &self.all_locations)
            .field("token", &self.token.as_deref().map(models::redacted))
            .field("device_name", &self.device_name)
            .finish_non_exhaustive()
    }
}

impl LocalConfig {
    /// A configuration for this mode.
    pub fn new(mode: LocalMode) -> Self {
        LocalConfig {
            mode,
            ..Default::default()
        }
    }
    /// The mode (default [`LocalMode::Cloud`]).
    pub fn mode(mut self, mode: LocalMode) -> Self {
        self.mode = mode;
        self
    }
    /// The location this device prints at. It narrows minted tokens and the
    /// endpoint list, filters discovered stations, and is used as the job's
    /// location when a job sets neither a printer nor a location. Required
    /// for minted tokens unless [`LocalConfig::all_locations`].
    pub fn location_id(mut self, id: impl Into<String>) -> Self {
        self.location_id = Some(id.into());
        self
    }
    /// Adds a station URL to try first, in order, e.g.
    /// `"https://192-168-1-20.ab3k9x2mqp.local.catzprint.com:7443"` or
    /// `"https://192.168.1.20:7443"`. IP URLs need a fingerprint (from the
    /// endpoint list or [`LocalConfig::fingerprint`]).
    pub fn station_url(mut self, url: impl Into<String>) -> Self {
        self.station_urls.push(url.into());
        self
    }
    /// Adds several station URLs.
    pub fn station_urls<I, S>(mut self, urls: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.station_urls.extend(urls.into_iter().map(Into::into));
        self
    }
    /// Pins a certificate you got out of band (the station app shows its
    /// fingerprint). `key` is a station URL, `"host:port"` or a host (or any
    /// label, for a station found over mDNS); `sha256` is the hex SHA-256 of
    /// the certificate (colons allowed).
    pub fn fingerprint(mut self, key: impl Into<String>, sha256: impl Into<String>) -> Self {
        self.fingerprints.push((key.into(), sha256.into()));
        self
    }
    /// Adds stations from the cloud endpoint list (cached in the token store,
    /// refreshed hourly while online) and maps their station IDs to current
    /// addresses with mDNS. mDNS alone is never trusted.
    pub fn discover(mut self, on: bool) -> Self {
        self.discover = on;
        self
    }
    /// Lets the SDK mint tokens valid at every location the API key may use.
    /// By default minted tokens are bound to [`LocalConfig::location_id`].
    pub fn all_locations(mut self, on: bool) -> Self {
        self.all_locations = on;
        self
    }
    /// Keeps the local token and endpoint list between runs (default: in
    /// memory). Use [`FileTokenStore`] for a hub that must print after a
    /// restart while the internet is down.
    pub fn token_store(mut self, store: impl TokenStore + 'static) -> Self {
        self.token_store = Some(Arc::new(store));
        self
    }
    /// A fixed token to use instead of minting one: a device token from
    /// [`Local::pair`] (`"czd_…"`) or a local token (`"czl1.…"`). With
    /// [`LocalMode::Local`] the client then needs no API key.
    pub fn token(mut self, token: impl Into<String>) -> Self {
        self.token = Some(token.into());
        self
    }
    /// Names this device on stations (default: the host name).
    pub fn device_name(mut self, name: impl Into<String>) -> Self {
        self.device_name = Some(name.into());
        self
    }
    /// Lifetime of minted tokens in days, 1–30 (default 30).
    pub fn token_ttl_days(mut self, days: u32) -> Self {
        self.token_ttl_days = Some(days);
        self
    }
    /// Bounds connecting to a station, TLS included (default 3 s).
    pub fn connect_timeout(mut self, d: Duration) -> Self {
        self.connect_timeout = Some(d);
        self
    }
    /// Bounds one station request (default 15 s).
    pub fn request_timeout(mut self, d: Duration) -> Self {
        self.request_timeout = Some(d);
        self
    }
    /// Bounds the cloud attempt in cloud_first mode and token minting /
    /// endpoint refreshes (default 10 s).
    pub fn cloud_timeout(mut self, d: Duration) -> Self {
        self.cloud_timeout = Some(d);
        self
    }
    /// How long an mDNS browse listens (default 1.5 s).
    pub fn discover_timeout(mut self, d: Duration) -> Self {
        self.discover_timeout = Some(d);
        self
    }
    /// Asks the station to hold its answer until the job printed or failed,
    /// up to 30 s (default 0: answer as soon as it's queued).
    pub fn wait(mut self, d: Duration) -> Self {
        self.wait = d;
        self
    }
    /// Adds a DER root certificate for verifying public-certificate station
    /// hostnames. When any is set, they replace the bundled Mozilla roots.
    pub fn root_certificate(mut self, der: impl Into<Vec<u8>>) -> Self {
        self.root_certificates.push(der.into());
        self
    }

    /// A paired device: local mode with a static token needs no API key.
    pub(crate) fn is_paired_device(&self) -> bool {
        self.mode == LocalMode::Local && self.token.as_deref().is_some_and(|t| !t.is_empty())
    }

    #[cfg(feature = "blocking")]
    pub(crate) fn is_local_mode(&self) -> bool {
        self.mode != LocalMode::Cloud
    }
}

/// The validated configuration.
struct Settings {
    mode: LocalMode,
    location_id: String,
    station_urls: Vec<String>,
    pins: BTreeMap<String, String>,
    discover: bool,
    store: Arc<dyn TokenStore>,
    token: String,
    device_name: String,
    ttl_days: Option<u32>,
    connect_timeout: Duration,
    request_timeout: Duration,
    cloud_timeout: Duration,
    discover_timeout: Duration,
    wait: Duration,
    roots: Vec<Vec<u8>>,
}

fn default_device_name() -> String {
    let from_env = ["HOSTNAME", "COMPUTERNAME"]
        .iter()
        .filter_map(|k| std::env::var(k).ok())
        .map(|s| s.trim().to_string())
        .find(|s| !s.is_empty());
    from_env
        .or_else(|| {
            std::fs::read_to_string("/etc/hostname")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        })
        .unwrap_or_else(|| "CatzPrint Rust SDK".into())
}

/// A `Fingerprints` key: a URL becomes its host (and port), anything else is
/// lower-cased.
fn pin_key(k: &str) -> String {
    let k = k.trim().to_ascii_lowercase();
    if k.contains("://") {
        if let Ok(u) = reqwest::Url::parse(&k) {
            if let Some(h) = u.host_str() {
                return match u.port() {
                    Some(p) => format!("{h}:{p}"),
                    None => h.to_string(),
                };
            }
        }
    }
    k.trim_end_matches('/').to_string()
}

impl Settings {
    fn new(cfg: LocalConfig) -> Result<Settings> {
        let bad = |m: &str| Err(Error::Config(m.to_string()));
        let mut urls: Vec<String> = Vec::new();
        for raw in &cfg.station_urls {
            let u = normalize_station_url(raw)?;
            if !urls.contains(&u) {
                urls.push(u);
            }
        }
        let mut pins = BTreeMap::new();
        for (k, v) in &cfg.fingerprints {
            let fp = normalize_fingerprint(v);
            if fp.is_empty() {
                return Err(Error::Config(format!(
                    "fingerprint for {k:?} must be 64 hex characters (SHA-256)"
                )));
            }
            pins.insert(pin_key(k), fp);
        }
        let token = cfg.token.unwrap_or_default();
        let location_id = cfg.location_id.unwrap_or_default();
        if cfg.mode != LocalMode::Cloud && urls.is_empty() && !cfg.discover {
            return bad("local printing needs station URLs or discover(true)");
        }
        if cfg.mode != LocalMode::Cloud
            && token.is_empty()
            && location_id.is_empty()
            && !cfg.all_locations
        {
            return bad(
                "set LocalConfig::location_id (minted local tokens are bound to it), or \
                 all_locations(true) for a token valid at every location",
            );
        }
        if !token.is_empty() && !token.starts_with("czl1.") && !token.starts_with("czd_") {
            return bad(
                "LocalConfig::token must be a local token (czl1.…) or a device token (czd_…)",
            );
        }
        if cfg.token_ttl_days.is_some_and(|d| !(1..=30).contains(&d)) {
            return bad("token_ttl_days must be between 1 and 30");
        }
        if cfg.wait > MAX_LOCAL_WAIT {
            return bad("LocalConfig::wait must be between 0 and 30 s");
        }
        let positive =
            |d: Option<Duration>, def: Duration| d.filter(|d| !d.is_zero()).unwrap_or(def);
        let device_name = cfg
            .device_name
            .filter(|n| !n.trim().is_empty())
            .unwrap_or_else(default_device_name)
            .chars()
            .take(80)
            .collect();
        Ok(Settings {
            mode: cfg.mode,
            location_id,
            station_urls: urls,
            pins,
            discover: cfg.discover,
            store: cfg
                .token_store
                .unwrap_or_else(|| Arc::new(MemoryTokenStore::new())),
            token,
            device_name,
            ttl_days: cfg.token_ttl_days,
            connect_timeout: positive(cfg.connect_timeout, DEFAULT_CONNECT_TIMEOUT),
            request_timeout: positive(cfg.request_timeout, DEFAULT_REQUEST_TIMEOUT),
            cloud_timeout: positive(cfg.cloud_timeout, DEFAULT_CLOUD_TIMEOUT),
            discover_timeout: positive(cfg.discover_timeout, DEFAULT_DISCOVER_TIMEOUT),
            wait: cfg.wait,
            roots: cfg.root_certificates,
        })
    }
}

/// Holds the local state for a client and its clones; dropping the last
/// clone stops background refreshes.
pub(crate) struct LocalHandle {
    pub(crate) state: Arc<LocalState>,
}

impl LocalHandle {
    pub(crate) fn new(cloud: Client, cfg: LocalConfig) -> Result<Self> {
        Ok(LocalHandle {
            state: Arc::new(LocalState::new(cloud, Settings::new(cfg)?)),
        })
    }
}

impl Drop for LocalHandle {
    fn drop(&mut self) {
        self.state.shutdown();
    }
}

struct Inner {
    loaded: bool,
    state: Option<StoredToken>,
    store_err: Option<Arc<io::Error>>,
    mdns: Vec<MdnsStation>,
    mdns_at: Option<DateTime<Utc>>,
    clients: HashMap<String, reqwest::Client>,
    job_urls: HashMap<String, String>,
    next_try: Option<DateTime<Utc>>,
    refreshing: bool,
    bg: Option<JoinHandle<()>>,
    closed: bool,
    clock_offset: TimeDelta,
    mdns_addr: SocketAddr,
}

pub(crate) struct LocalState {
    /// A cloud-only client (no local state: no reference cycle).
    cloud: Client,
    s: Settings,
    store_key: String,
    inner: Mutex<Inner>,
    load_lock: tokio::sync::Mutex<()>,
    mint_lock: tokio::sync::Mutex<()>,
    remint_lock: tokio::sync::Mutex<()>,
}

/// Token claims read (without verifying) from a `czl1` token.
#[derive(Default)]
struct Claims {
    org: String,
    live: bool,
    /// Issued at / expires (Unix seconds), 0 when absent.
    iat: i64,
    exp: i64,
}

fn token_claims(tok: &str) -> Claims {
    let parts: Vec<&str> = tok.split('.').collect();
    if parts.len() != 3 || parts[0] != "czl1" {
        return Claims::default();
    }
    let Ok(b) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(parts[1]) else {
        return Claims::default();
    };
    let v: Value = serde_json::from_slice(&b).unwrap_or(Value::Null);
    Claims {
        org: v["org"].as_str().unwrap_or("").to_string(),
        live: v["live"].as_bool().unwrap_or(false),
        iat: v["iat"].as_i64().unwrap_or(0),
        exp: v["exp"].as_i64().unwrap_or(0),
    }
}

/// How long before expiry a minted token is renewed: `min(7 days, TTL / 2)`,
/// so short-lived tokens (e.g. 1 day) are renewed half-way rather than right
/// away. The TTL is read from the token (`exp - iat`), else the configured
/// `token_ttl_days`; without either, 7 days.
fn refresh_before(tok: &str, ttl_days: Option<u32>) -> TimeDelta {
    let c = token_claims(tok);
    let ttl = if c.iat > 0 && c.exp > c.iat {
        Some(TimeDelta::seconds(c.exp - c.iat))
    } else {
        ttl_days.map(|d| TimeDelta::days(i64::from(d)))
    };
    match ttl {
        Some(ttl) => TOKEN_REFRESH_BEFORE.min(ttl / 2),
        None => TOKEN_REFRESH_BEFORE,
    }
}

/// The live flag a token implies: paired devices (`czd_`) are live; local
/// tokens carry it in their claims.
fn token_live(tok: &str) -> bool {
    tok.starts_with("czd_") || token_claims(tok).live
}

/// Whether a token is a redaction placeholder rather than a token: `…`, a
/// run of 3+ `*`, `[redacted]`, `redacted` or `hidden` (any case),
/// optionally after `czl1.` or `czd_`. Every CatzPrint SDK recognises the
/// same set.
pub(crate) fn is_redacted(tok: &str) -> bool {
    let t = tok
        .strip_prefix("czl1.")
        .or_else(|| tok.strip_prefix("czd_"))
        .unwrap_or(tok);
    t == "…"
        || (t.len() >= 3 && t.chars().all(|c| c == '*'))
        || t.eq_ignore_ascii_case("[redacted]")
        || t.eq_ignore_ascii_case("redacted")
        || t.eq_ignore_ascii_case("hidden")
}

fn usable(st: &StoredToken, now: DateTime<Utc>) -> bool {
    !st.token.is_empty()
        && st
            .expires_at
            .is_some_and(|e| now + TimeDelta::minutes(1) < e)
}

/// Turns one cloud endpoint into targets. Hostnames come only from here
/// (the authenticated cloud list): verified with the web PKI and pinned to
/// the public key the cloud reports, and reached directly at the IP in the
/// name only under the station's own label. IP URLs must be private and are
/// pinned to the station's self-signed certificate.
fn endpoint_targets(ep: &LocalEndpoint, source: &'static str) -> Vec<Target> {
    let fp = normalize_fingerprint(&ep.cert_fingerprint_sha256);
    let spki = normalize_fingerprint(&ep.public_spki_sha256);
    let mut out = Vec::new();
    for raw in &ep.urls {
        let Ok(u) = normalize_station_url(raw) else {
            continue;
        };
        let (host, _) = url_host(&u);
        let mut t = Target {
            url: u,
            tls_mode: ep.tls_mode.clone(),
            station_id: ep.station_id.clone(),
            source,
            ..Default::default()
        };
        if host_ip(&host).is_some() {
            if !private_ip(&host) {
                continue;
            }
            t.fingerprint = fp.clone();
        } else {
            t.spki = spki.clone();
            let mut label = ep.local_label.to_ascii_lowercase();
            let parts: Vec<&str> = host.split('.').collect();
            if label.is_empty() && parts.len() >= 3 {
                label = parts[1].to_string(); // the hostname itself came from the cloud
            }
            t.label = label;
        }
        out.push(t);
    }
    out
}

/// The pinned IP URLs of an accepted announcement.
fn mdns_targets(d: &MdnsStation) -> Vec<Target> {
    d.addresses
        .iter()
        .map(|a| Target {
            url: ip_url(a, d.port),
            fingerprint: d.fingerprint.clone(),
            tls_mode: "self_signed".into(),
            station_id: d.station_id.clone(),
            source: "mdns",
            ..Default::default()
        })
        .collect()
}

/// Candidate stations in order: configured URLs, the cloud endpoint list,
/// then (with discovery, only when those all failed) mDNS.
struct Candidates {
    list: VecDeque<Target>,
    tried: HashSet<String>,
    mdns_done: bool,
}

impl Candidates {
    async fn next(&mut self, l: &LocalState) -> Option<Target> {
        if let Some(t) = self.list.pop_front() {
            self.tried.insert(t.url.clone());
            return Some(t);
        }
        if !l.s.discover || self.mdns_done {
            return None;
        }
        self.mdns_done = true;
        let (found, _) = l.browse(false).await;
        for d in l.accepted_mdns(&found, l.snapshot().as_ref()) {
            for t in mdns_targets(&d) {
                if self.tried.insert(t.url.clone()) {
                    self.list.push_back(t);
                }
            }
        }
        self.list.pop_front()
    }
}

/// What asking a station for a job by idempotency key found.
enum Probe {
    Found(Box<LocalJob>),
    /// `404 not_found`: never recorded.
    NotFound,
    /// An answer that settles it (`409 duplicate`: the key belongs to a job
    /// this caller can't see): returned as is.
    Answer(Error),
    Unknown,
}

/// Asking a station for a job after a delivered request got no answer: at
/// most this many tries, within this time, pausing between failed tries.
const PROBE_ATTEMPTS: u32 = 3;
const PROBE_BUDGET: Duration = Duration::from_secs(5);
const PROBE_PAUSE: Duration = Duration::from_millis(200);

fn unreachable(attempts: Vec<StationAttempt>) -> Error {
    Error::StationUnreachable {
        attempts,
        cloud_error: None,
    }
}

/// A token that can't be minted because the cloud can't be reached makes
/// local printing impossible ("unreachable"); a 4xx from the cloud (e.g. a
/// missing scope) is returned as is.
fn mint_error_is_unreachable(e: &Error) -> bool {
    matches!(e, Error::Connection { .. } | Error::Server(_))
}

impl LocalState {
    fn new(cloud: Client, s: Settings) -> Self {
        let kh = Sha256::digest(cloud.cfg.api_key.as_bytes());
        let store_key = format!(
            "v1|{}|{}|{}",
            hex::encode(&kh[..8]),
            s.location_id,
            s.device_name
        );
        LocalState {
            cloud,
            s,
            store_key,
            inner: Mutex::new(Inner {
                loaded: false,
                state: None,
                store_err: None,
                mdns: Vec::new(),
                mdns_at: None,
                clients: HashMap::new(),
                job_urls: HashMap::new(),
                next_try: None,
                refreshing: false,
                bg: None,
                closed: false,
                clock_offset: TimeDelta::zero(),
                mdns_addr: mdns::GROUP,
            }),
            load_lock: tokio::sync::Mutex::new(()),
            mint_lock: tokio::sync::Mutex::new(()),
            remint_lock: tokio::sync::Mutex::new(()),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub(crate) fn mode(&self) -> LocalMode {
        self.s.mode
    }

    fn now(&self) -> DateTime<Utc> {
        Utc::now() + self.lock().clock_offset
    }

    fn snapshot(&self) -> Option<StoredToken> {
        self.lock().state.clone()
    }

    fn has_api_key(&self) -> bool {
        !self.cloud.cfg.api_key.is_empty()
    }

    // ---- token and endpoint state ----

    async fn ensure_loaded(&self) {
        if self.lock().loaded {
            return;
        }
        let _g = self.load_lock.lock().await;
        if self.lock().loaded {
            return;
        }
        let r = self.s.store.load(&self.store_key).await;
        let mut i = self.lock();
        i.loaded = true;
        match r {
            Ok(mut st) => {
                // A redaction placeholder (a store fed from Debug or log
                // output) is no token.
                if let Some(t) = st.as_mut().filter(|t| is_redacted(&t.token)) {
                    t.token.clear();
                    t.token_id.clear();
                    t.expires_at = None;
                    i.store_err = Some(Arc::new(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "the stored local token is a redaction placeholder (\"****\"), not a token",
                    )));
                }
                if i.state.is_none() {
                    i.state = st;
                }
            }
            Err(e) => i.store_err = Some(Arc::new(e)),
        }
    }

    async fn save(&self, st: StoredToken) {
        self.lock().state = Some(st.clone());
        if let Err(e) = self.s.store.save(&self.store_key, &st).await {
            self.lock().store_err = Some(Arc::new(e));
        }
    }

    /// Runs a cloud call within the cloud timeout.
    async fn cloud_call<T>(&self, fut: impl Future<Output = Result<T>>) -> Result<T> {
        match tokio::time::timeout(self.s.cloud_timeout, fut).await {
            Ok(r) => r,
            Err(_) => Err(Error::Connection {
                message: format!(
                    "the CatzPrint API didn't answer within {:?}",
                    self.s.cloud_timeout
                ),
                timeout: true,
            }),
        }
    }

    /// Gets a fresh local token from the cloud and stores it (with the
    /// endpoint list that comes with it). Unless `force`, a concurrent mint
    /// that already produced a good token is reused.
    async fn mint(&self, force: bool) -> Result<StoredToken> {
        let _g = self.mint_lock.lock().await;
        if !force {
            if let Some(st) = self.snapshot().filter(|st| usable(st, self.now())) {
                return Ok(st);
            }
        }
        let mut params = LocalTokenParams::new(self.s.device_name.clone());
        params.ttl_days = self.s.ttl_days;
        if !self.s.location_id.is_empty() {
            params.location_ids = vec![self.s.location_id.clone()];
        }
        let lt = self
            .cloud_call(cloud::create_token(
                &self.cloud,
                &params,
                Some(self.s.cloud_timeout),
            ))
            .await?;
        let mut st = self.snapshot().unwrap_or_default();
        st.token = lt.token;
        st.token_id = lt.token_id;
        st.expires_at = lt.expires_at;
        if let Some(stations) = lt.stations {
            st.stations = stations;
            st.stations_updated_at = Some(self.now());
        }
        self.save(st.clone()).await;
        Ok(st)
    }

    /// The token for station requests, minting one when none is usable. A
    /// token with less than `min(7 days, TTL/2)` left is still used while a
    /// background refresh replaces it.
    async fn token(self: &Arc<Self>) -> Result<String> {
        if !self.s.token.is_empty() {
            self.maybe_kick_refresh();
            return Ok(self.s.token.clone());
        }
        self.ensure_loaded().await;
        if let Some(st) = self.snapshot().filter(|st| usable(st, self.now())) {
            self.maybe_kick_refresh();
            return Ok(st.token);
        }
        Ok(self.mint(false).await?.token)
    }

    /// What is stale: the token (< min(7 days, TTL/2) left) and/or the endpoint list
    /// (older than an hour).
    fn needs_refresh(&self) -> (bool, bool) {
        let st = self.snapshot();
        let now = self.now();
        let tok = self.s.token.is_empty()
            && match &st {
                Some(st) if !st.token.is_empty() => st
                    .expires_at
                    .is_none_or(|e| e - now < refresh_before(&st.token, self.s.ttl_days)),
                _ => true,
            };
        let eps = match st.as_ref().and_then(|s| s.stations_updated_at) {
            Some(at) => now - at > ENDPOINTS_MAX_AGE,
            None => true,
        };
        (tok, eps)
    }

    fn maybe_kick_refresh(self: &Arc<Self>) {
        if !self.has_api_key() {
            return; // paired-device mode: no cloud
        }
        let (tok, eps) = self.needs_refresh();
        if !tok && !eps {
            return;
        }
        let Ok(rt) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let now = self.now();
        let mut i = self.lock();
        if i.refreshing || i.closed || i.next_try.is_some_and(|t| now < t) {
            return;
        }
        i.refreshing = true;
        let me = self.clone();
        i.bg = Some(rt.spawn(async move {
            let r = tokio::time::timeout(2 * me.s.cloud_timeout, me.refresh(false)).await;
            let failed = !matches!(r, Ok(Ok(())));
            let now = me.now();
            let mut i = me.lock();
            i.refreshing = false;
            if failed {
                i.next_try = Some(now + REFRESH_RETRY_AFTER);
            }
        }));
    }

    /// Renews the token when it has less than min(7 days, TTL/2) left and the endpoint
    /// list when it is older than an hour (or always, with `force`).
    async fn refresh(&self, force: bool) -> Result<()> {
        self.ensure_loaded().await;
        let (tok, eps) = self.needs_refresh();
        if tok {
            let before = self.snapshot().and_then(|s| s.stations_updated_at);
            let st = self.mint(true).await?;
            if st.stations_updated_at != before {
                return Ok(()); // the mint brought a fresh endpoint list
            }
        }
        if !eps && !force {
            return Ok(());
        }
        let loc = Some(self.s.location_id.as_str()).filter(|l| !l.is_empty());
        let list = self
            .cloud_call(cloud::list_endpoints(
                &self.cloud,
                loc,
                Some(self.s.cloud_timeout),
            ))
            .await?;
        let mut st = self.snapshot().unwrap_or_default();
        st.stations = list;
        st.stations_updated_at = Some(self.now());
        self.save(st).await;
        Ok(())
    }

    /// Stops background refreshes without waiting (on drop).
    fn shutdown(&self) {
        let mut i = self.lock();
        i.closed = true;
        if let Some(h) = i.bg.take() {
            h.abort();
        }
    }

    async fn close(&self) {
        let h = {
            let mut i = self.lock();
            i.closed = true;
            i.bg.take()
        };
        if let Some(h) = h {
            h.abort();
            let _ = h.await;
        }
        self.lock().clients.clear();
    }

    /// The organization this device belongs to, if known without a network
    /// call (the configured/cached org ID, or the token's claims).
    fn org_hint(&self) -> String {
        if let Some(o) = self.cloud.cfg.cached_org() {
            return o;
        }
        let tok = if self.s.token.is_empty() {
            self.snapshot().map(|s| s.token).unwrap_or_default()
        } else {
            self.s.token.clone()
        };
        token_claims(&tok).org
    }

    // ---- candidates ----

    /// Whether `fp` is one of the fingerprints the user configured.
    fn user_pinned(&self, fp: &str) -> bool {
        !fp.is_empty() && self.s.pins.values().any(|v| v == fp)
    }

    /// How to trust a configured URL: a pin from the configuration, else the
    /// cloud endpoint list (by URL, or by address and port for IPs), else an
    /// mDNS answer for a station on that list.
    fn target_for(
        &self,
        u: &str,
        source: &'static str,
        st: Option<&StoredToken>,
        found: &[MdnsStation],
    ) -> Target {
        let mut t = Target {
            url: u.to_string(),
            source,
            ..Default::default()
        };
        let (host, port) = url_host(u);
        for k in [format!("{host}:{port}"), host.clone()] {
            if let Some(fp) = self.s.pins.get(&k) {
                t.fingerprint = fp.clone();
                return t;
            }
        }
        let bare = host.trim_start_matches('[').trim_end_matches(']');
        let is_private_ip = host_ip(&host).is_some() && private_ip(&host);
        if let Some(st) = st {
            for ep in &st.stations {
                if let Some(et) = endpoint_targets(ep, source)
                    .into_iter()
                    .find(|et| et.url == u)
                {
                    return et;
                }
                if is_private_ip && ep.addresses.iter().any(|a| a == bare) && ep.port == port {
                    t.fingerprint = normalize_fingerprint(&ep.cert_fingerprint_sha256);
                    t.tls_mode = ep.tls_mode.clone();
                    t.station_id = ep.station_id.clone();
                    return t;
                }
            }
        }
        for d in self.accepted_mdns(found, st) {
            if d.addresses.iter().any(|a| a == bare) && d.port == port {
                t.fingerprint = d.fingerprint;
                t.tls_mode = d.tls_mode;
                t.station_id = d.station_id;
                return t;
            }
        }
        t
    }

    /// The configured URLs, then (with discovery) the cloud endpoint list's
    /// URLs, public hostnames before raw IPs.
    fn primary_targets(&self) -> Vec<Target> {
        let st = self.snapshot();
        let found = self.lock().mdns.clone();
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        for u in &self.s.station_urls {
            seen.insert(u.clone());
            out.push(self.target_for(u, "config", st.as_ref(), &found));
        }
        if let (true, Some(st)) = (self.s.discover, &st) {
            for ep in &st.stations {
                if !ep.local_enabled
                    || (!self.s.location_id.is_empty()
                        && !ep.location_id.is_empty()
                        && ep.location_id != self.s.location_id)
                {
                    continue;
                }
                for t in endpoint_targets(ep, "cloud") {
                    if seen.insert(t.url.clone()) {
                        out.push(t);
                    }
                }
            }
        }
        out
    }

    /// Filters mDNS announcements. mDNS is unauthenticated, so it only maps a
    /// station ID to its current addresses: an announcement is used for a
    /// station on the cloud endpoint list (pinned with the list's
    /// fingerprint, port from the list) or one whose announced fingerprint
    /// the user configured. The announced hostname is never used, and only
    /// private addresses are kept.
    fn accepted_mdns(&self, found: &[MdnsStation], st: Option<&StoredToken>) -> Vec<MdnsStation> {
        let org = self.org_hint();
        let mut out = Vec::new();
        for d in found {
            if !org.is_empty() && !d.org_id.is_empty() && d.org_id != org {
                continue;
            }
            if !self.s.location_id.is_empty()
                && !d.location_id.is_empty()
                && d.location_id != self.s.location_id
            {
                continue;
            }
            let mut d = d.clone();
            d.addresses.retain(|a| private_ip(a));
            d.hostname.clear();
            let ep = st.and_then(|st| {
                st.stations
                    .iter()
                    .rev()
                    .find(|e| e.station_id == d.station_id)
            });
            match ep {
                Some(ep) => {
                    if !ep.local_enabled {
                        continue;
                    }
                    d.fingerprint = normalize_fingerprint(&ep.cert_fingerprint_sha256);
                    d.tls_mode = "self_signed".into();
                    if ep.port > 0 {
                        d.port = ep.port;
                    }
                }
                None if self.user_pinned(&d.fingerprint) => {}
                None => continue,
            }
            if d.fingerprint.is_empty() || d.addresses.is_empty() {
                continue;
            }
            out.push(d);
        }
        out
    }

    /// Runs (or reuses, for a minute) an mDNS browse.
    async fn browse(&self, fresh: bool) -> (Vec<MdnsStation>, Option<io::Error>) {
        let now = self.now();
        let addr = {
            let i = self.lock();
            if !fresh && i.mdns_at.is_some_and(|at| now - at < MDNS_CACHE_TTL) {
                return (i.mdns.clone(), None);
            }
            i.mdns_addr
        };
        let (found, err) = match mdns::browse(self.s.discover_timeout, addr).await {
            Ok(f) => (f, None),
            Err(e) => (Vec::new(), Some(e)),
        };
        let now = self.now();
        let mut i = self.lock();
        i.mdns = found.clone();
        i.mdns_at = Some(now);
        (found, err)
    }

    fn candidates(&self, preferred: &str) -> Candidates {
        let mut list: VecDeque<Target> = self.primary_targets().into();
        if !preferred.is_empty() {
            if let Some(i) = list.iter().position(|t| t.url == preferred) {
                if let Some(t) = list.remove(i) {
                    list.push_front(t);
                }
            }
        }
        Candidates {
            list,
            tried: HashSet::new(),
            mdns_done: false,
        }
    }

    // ---- requests ----

    fn station_client(&self, t: &Target) -> Result<reqwest::Client> {
        let key = client_key(t);
        if let Some(c) = self.lock().clients.get(&key) {
            return Ok(c.clone());
        }
        let c = transport::station_client(
            t,
            &ClientSettings {
                connect_timeout: self.s.connect_timeout,
                roots: &self.s.roots,
            },
        )?;
        self.lock().clients.insert(key, c.clone());
        Ok(c)
    }

    /// One request to a station (without delivery tracking).
    #[allow(clippy::too_many_arguments)]
    async fn send<T: serde::de::DeserializeOwned + Default>(
        &self,
        t: &Target,
        method: Method,
        path: &str,
        query: &[(&str, String)],
        token: &str,
        body: Option<&Value>,
        extra: Duration,
    ) -> std::result::Result<T, SendError> {
        let hc = self.station_client(t).map_err(SendError::Unreachable)?;
        let url = format!("{}{path}", t.url);
        transport::send(
            &hc,
            &url,
            method,
            query,
            token,
            body,
            self.s.request_timeout + extra,
            false,
        )
        .await
    }

    /// Sends a job to a station, telling "not delivered" (try elsewhere)
    /// from "delivered, no answer" ([`SendError::NoAnswer`]).
    async fn post_job(
        &self,
        t: &Target,
        query: &[(&str, String)],
        token: &str,
        body: &Value,
    ) -> std::result::Result<LocalJob, SendError> {
        let hc = self.station_client(t).map_err(SendError::Unreachable)?;
        let lj: LocalJob = transport::send(
            &hc,
            &format!("{}/local/v1/jobs", t.url),
            Method::POST,
            query,
            token,
            Some(body),
            self.s.request_timeout + self.s.wait,
            true,
        )
        .await
        .map_err(|e| match e {
            // 409 in_progress: the station is still processing this key's
            // POST (an earlier attempt): it may print, so ask by key.
            SendError::Answer(e @ Error::Conflict(_)) if e.code() == Some("in_progress") => {
                SendError::NoAnswer(e)
            }
            e => e,
        })?;
        // A 2xx without a job (empty or invalid body): the station may have
        // taken it, so it is asked by key.
        if lj.id.is_empty() {
            return Err(SendError::NoAnswer(Error::Decode(
                "the station accepted the job but its answer has no job".into(),
            )));
        }
        Ok(lj)
    }

    /// After a job reached `t` without an answer: asks the same station for
    /// the job by idempotency key, up to 3 times within 5 s, each time on a
    /// fresh connection (same pinning). `Found`: it has the job. `NotFound`
    /// (404): it never recorded it, so trying elsewhere is safe. `Unknown`:
    /// still no answer.
    async fn find_by_key(&self, t: &Target, token: &str, key: &str) -> Probe {
        let start = tokio::time::Instant::now();
        let q = [("idempotency_key", key.to_string())];
        let mut saw_in_progress = false;
        for i in 0..PROBE_ATTEMPTS {
            let left = PROBE_BUDGET.saturating_sub(start.elapsed());
            if left.is_zero() {
                break;
            }
            let per = left / (PROBE_ATTEMPTS - i);
            let fresh = transport::station_client(
                t,
                &ClientSettings {
                    connect_timeout: self.s.connect_timeout.min(per),
                    roots: &self.s.roots,
                },
            );
            let Ok(hc) = fresh else {
                return Probe::Unknown;
            };
            let r = transport::send::<LocalJob>(
                &hc,
                &format!("{}/local/v1/jobs", t.url),
                Method::GET,
                &q,
                token,
                None,
                per,
                false,
            )
            .await;
            match r {
                Ok(lj) if !lj.id.is_empty() => return Probe::Found(Box::new(lj)),
                // Only the station's own "never recorded" answer: a bare 404
                // (a proxy, an older station without this route) proves
                // nothing.
                // After an in_progress answer a 404 isn't "never recorded"
                // (addendum 6, T2): the outcome stays unknown.
                Err(SendError::Answer(Error::NotFound(e))) if e.code == "not_found" => {
                    return if saw_in_progress {
                        Probe::Unknown
                    } else {
                        Probe::NotFound
                    };
                }
                Err(SendError::Answer(e @ Error::Conflict(_))) if e.code() == Some("duplicate") => {
                    return Probe::Answer(e)
                }
                // Anything else (409 in_progress: the POST is still being
                // processed; 401, 400, a bare 404, 5xx, no answer): ask
                // again within the budget, then the outcome is unknown.
                other => {
                    if let Err(SendError::Answer(e @ Error::Conflict(_))) = &other {
                        saw_in_progress |= e.code() == Some("in_progress");
                    }
                    let left = PROBE_BUDGET.saturating_sub(start.elapsed());
                    tokio::time::sleep(PROBE_PAUSE.min(left)).await;
                }
            }
        }
        Probe::Unknown
    }

    /// Answers a 401 with a fresh token, but only for `token_expired` (never
    /// `device_revoked`: a device revoked at the station must stay revoked),
    /// only for minted tokens, and at most once per 10 minutes per store key
    /// (persisted, so restarts don't reset it).
    async fn remint(&self, rejected: &Error) -> Result<Option<String>> {
        if !self.s.token.is_empty()
            || !self.has_api_key()
            || rejected.code() != Some("token_expired")
        {
            return Ok(None);
        }
        let _g = self.remint_lock.lock().await;
        let mut st = self.snapshot().unwrap_or_default();
        let now = self.now();
        if st
            .last_remint_at
            .is_some_and(|at| now - at < REMINT_INTERVAL)
        {
            return Ok(None);
        }
        st.last_remint_at = Some(now);
        self.save(st).await;
        Ok(Some(self.mint(true).await?.token))
    }

    async fn token_or_unreachable(self: &Arc<Self>) -> Result<String> {
        match self.token().await {
            Ok(t) => Ok(t),
            Err(e) if mint_error_is_unreachable(&e) => Err(unreachable(vec![StationAttempt {
                url: String::new(),
                error: e,
            }])),
            Err(e) => Err(e),
        }
    }

    fn remember_job(&self, id: &str, url: &str) {
        if id.is_empty() {
            return;
        }
        let mut i = self.lock();
        if i.job_urls.len() >= 1000 {
            i.job_urls.clear();
        }
        i.job_urls.insert(id.to_string(), url.to_string());
    }

    /// Sends a job to the first station that takes it.
    async fn create_local(self: &Arc<Self>, p: &CreateJob) -> Result<Job> {
        let body = local_body(p)?;
        let key = p.idempotency_key.clone().unwrap_or_default();
        let mut tok = self.token_or_unreachable().await?;
        let mut q = Vec::new();
        if !self.s.wait.is_zero() {
            q.push(("wait", self.s.wait.as_secs_f64().ceil().to_string()));
        }
        let mut reminted = false;
        let mut attempts = Vec::new();
        let mut cands = self.candidates("");
        while let Some(t) = cands.next(self).await {
            let post = |tok: String| {
                let (t, q, body) = (&t, &q, &body);
                async move { self.post_job(t, q, &tok, body).await }
            };
            let mut r = post(tok.clone()).await;
            if let Err(SendError::Answer(e @ Error::Authentication(_))) = &r {
                if !reminted {
                    // 401 token_expired: mint a fresh token (rate-limited)
                    // and retry this station once.
                    reminted = true;
                    match self.remint(e).await {
                        Ok(Some(nt)) => {
                            tok = nt;
                            r = post(tok.clone()).await;
                        }
                        Ok(None) => {}
                        Err(merr) => {
                            if let Error::Authentication(a) = e {
                                let mut a = a.clone();
                                a.message = format!(
                                    "{} (and a fresh token couldn't be minted: {merr})",
                                    a.message
                                );
                                r = Err(SendError::Answer(Error::Authentication(a)));
                            }
                        }
                    }
                }
            }
            // The POST itself was answered 409 in_progress: a probe's 404
            // then doesn't mean "never recorded" (S4).
            let post_in_progress = matches!(&r, Err(SendError::NoAnswer(e @ Error::Conflict(_))) if e.code() == Some("in_progress"));
            match r {
                Ok(mut lj) => {
                    lj.station_url = t.url.clone();
                    self.remember_job(&lj.id, &t.url);
                    return Ok(to_job(lj, &t, infer_kind(p), token_live(&tok)));
                }
                Err(SendError::Unreachable(e)) => attempts.push(StationAttempt {
                    url: t.url,
                    error: e,
                }),
                Err(SendError::NoAnswer(e)) => {
                    // The station may have the job: never send it elsewhere
                    // until it says it doesn't.
                    match self.find_by_key(&t, &tok, &key).await {
                        Probe::Found(lj) => {
                            let mut lj = *lj;
                            lj.station_url = t.url.clone();
                            self.remember_job(&lj.id, &t.url);
                            return Ok(to_job(lj, &t, infer_kind(p), token_live(&tok)));
                        }
                        Probe::NotFound if !post_in_progress => attempts.push(StationAttempt {
                            url: t.url,
                            error: e,
                        }),
                        Probe::Answer(e) => return Err(e),
                        Probe::NotFound | Probe::Unknown => {
                            return Err(Error::OutcomeUnknown {
                                url: t.url,
                                idempotency_key: key,
                                cause: Box::new(e),
                            })
                        }
                    }
                }
                Err(SendError::Answer(e @ Error::Authentication(_))) => {
                    // Still refused: in the fallback modes this means "use
                    // the cloud"; in local mode the 401 is the answer.
                    if self.s.mode == LocalMode::Local {
                        return Err(e);
                    }
                    attempts.push(StationAttempt {
                        url: t.url,
                        error: e,
                    });
                    return Err(unreachable(attempts));
                }
                Err(SendError::Answer(e)) => return Err(e),
            }
        }
        Err(unreachable(attempts))
    }

    /// Runs `f` against each candidate station with a token until one
    /// answers.
    async fn authed<T, F, Fut>(
        self: &Arc<Self>,
        preferred: &str,
        f: F,
    ) -> Result<(T, Target, String)>
    where
        F: Fn(Target, String) -> Fut,
        Fut: Future<Output = std::result::Result<T, SendError>>,
    {
        let mut tok = self.token_or_unreachable().await?;
        let mut reminted = false;
        let mut attempts = Vec::new();
        let mut cands = self.candidates(preferred);
        while let Some(t) = cands.next(self).await {
            let mut r = f(t.clone(), tok.clone()).await;
            if let Err(SendError::Answer(e @ Error::Authentication(_))) = &r {
                if !reminted {
                    reminted = true;
                    if let Ok(Some(nt)) = self.remint(e).await {
                        tok = nt;
                        r = f(t.clone(), tok.clone()).await;
                    }
                }
            }
            match r {
                Ok(v) => return Ok((v, t, tok)),
                Err(SendError::Unreachable(e)) => attempts.push(StationAttempt {
                    url: t.url,
                    error: e,
                }),
                Err(SendError::Answer(e) | SendError::NoAnswer(e)) => return Err(e),
            }
        }
        Err(unreachable(attempts))
    }
}

// ---- jobs ----

/// The kind a job has on a station, detecting raw bytes like the station.
fn local_kind(p: &CreateJob) -> Option<String> {
    if let Some(k) = &p.kind {
        return Some(k.clone());
    }
    match &p.content {
        Some(Content::Text(_)) => Some("text".into()),
        Some(Content::Commands(_)) => Some("commands".into()),
        Some(Content::Template { .. }) => Some("template".into()),
        Some(Content::Bytes(b)) => Some(
            detect_kind(b, p.file_name.as_deref())
                .map(String::from)
                .unwrap_or_else(|| {
                    if matches!(b.first(), Some(0x1b | 0x1d)) && p.file_name.is_none() {
                        "escpos".into()
                    } else {
                        "document".into()
                    }
                }),
        ),
        None => None,
    }
}

/// Whether a job can go to a station at all.
fn local_capable(p: &CreateJob) -> std::result::Result<(), &'static str> {
    if p.sealed {
        return Err("sealed jobs go through the cloud");
    }
    if p.scheduled_for.is_some() {
        return Err("scheduled jobs go through the cloud");
    }
    match local_kind(p).as_deref() {
        None | Some("commands" | "template" | "text" | "escpos" | "test") => Ok(()),
        _ => Err("PDFs, images and documents go through the cloud"),
    }
}

fn unsupported_locally(why: &str) -> Error {
    Error::Validation(ApiError {
        status: 422,
        code: "unsupported_locally".into(),
        message: format!(
            "This job can't print locally: {why}. Send PDFs, images and documents through the cloud."
        ),
        fields: BTreeMap::new(),
        retry_after: None,
    })
}

/// The station body: the cloud body (same names), with the detected kind
/// and without `file_name`.
fn local_body(p: &CreateJob) -> Result<Value> {
    let mut body = p.to_body(None)?;
    if let Some(m) = body.as_object_mut() {
        m.remove("file_name");
        if let Some(k) = local_kind(p) {
            m.insert("kind".into(), json!(k));
        }
    }
    Ok(body)
}

fn infer_kind(p: &CreateJob) -> String {
    local_kind(p).unwrap_or_default()
}

fn non_empty(s: &str) -> Option<String> {
    (!s.is_empty()).then(|| s.to_string())
}

fn to_job(lj: LocalJob, t: &Target, kind: String, live: bool) -> Job {
    let mut detail = lj.detail.clone();
    if lj.status == JobStatus::Failed && detail.is_empty() {
        detail = lj.error_code.clone().unwrap_or_default();
    }
    Job {
        id: lj.id.clone(),
        live: lj.live.unwrap_or(live), // the station's answer wins
        source: "local".into(),
        kind,
        status: lj.status,
        status_detail: detail,
        title: lj.title.clone(),
        reference: lj.reference.clone(),
        copies: lj.copies,
        printer_id: non_empty(&lj.printer_id),
        printer_name: non_empty(&lj.printer_name),
        location_id: non_empty(&lj.location_id),
        station_id: non_empty(&t.station_id),
        created_at: lj.created_at,
        finished_at: lj.finished_at,
        printed_at: if lj.status == JobStatus::Printed {
            lj.finished_at
        } else {
            None
        },
        printed_locally: true,
        idempotency_key: non_empty(&lj.idempotency_key),
        via: Some(Via::Local),
        local: Some(lj),
        ..Default::default()
    }
}

/// Routes a job according to the local mode (not `Cloud`).
pub(crate) async fn create(
    client: &Client,
    l: &Arc<LocalState>,
    mut params: CreateJob,
) -> Result<Job> {
    // The same key goes to the station and to the cloud, so a fallback can
    // never print twice.
    crate::core::normalize_idempotency_key(&mut params)?;
    if params.idempotency_key.is_none() {
        params.idempotency_key = Some(format!("sdk-{}", uuid::Uuid::new_v4()));
    }
    if params.printer_id.is_none() && params.location_id.is_none() && !l.s.location_id.is_empty() {
        params.location_id = Some(l.s.location_id.clone());
    }
    let cap = local_capable(&params);
    let jobs = client.jobs();
    match l.s.mode {
        LocalMode::Local => {
            cap.map_err(unsupported_locally)?;
            l.create_local(&params).await
        }
        LocalMode::LocalFirst => {
            if cap.is_err() {
                return jobs.create_cloud(params, None).await;
            }
            match l.create_local(&params).await {
                // No station got the job: the cloud may take it.
                Err(Error::StationUnreachable { attempts, .. }) => {
                    match cloud_leg(client, &params, None).await {
                        CloudLeg::Job(j) => Ok(*j),
                        // The cloud's answer (4xx…) is the answer.
                        CloudLeg::Failed(e) | CloudLeg::Unknown(e) => Err(e),
                        CloudLeg::NotDelivered(ce) => Err(Error::StationUnreachable {
                            attempts,
                            cloud_error: Some(Box::new(ce)),
                        }),
                    }
                }
                other => other,
            }
        }
        LocalMode::CloudFirst => {
            if cap.is_err() {
                // Can't print locally: the same create as cloud mode (client
                // retries, the 409 loop, the re-seal).
                return jobs.create_cloud(params, None).await;
            }
            let err = match cloud_leg(client, &params, Some(l.s.cloud_timeout)).await {
                CloudLeg::Job(j) => return Ok(*j),
                // An answer (4xx…) is the answer; after an ambiguous attempt
                // the cloud may already have queued the job for some station,
                // so it never goes local.
                CloudLeg::Failed(e) | CloudLeg::Unknown(e) => return Err(e),
                // Certainly not delivered (network error, 502/503/504): the
                // stations may take it.
                CloudLeg::NotDelivered(e) => e,
            };
            match l.create_local(&params).await {
                Ok(j) => Ok(j),
                Err(Error::StationUnreachable { attempts, .. }) => Err(Error::StationUnreachable {
                    attempts,
                    cloud_error: Some(Box::new(err)),
                }),
                Err(e) => Err(e),
            }
        }
        LocalMode::Cloud => jobs.create_cloud(params, None).await,
    }
}

/// The outcome of the cloud part of a local mode.
enum CloudLeg {
    Job(Box<Job>),
    /// The cloud answered with an error.
    Failed(Error),
    /// The cloud certainly didn't get the job.
    NotDelivered(Error),
    /// [`Error::OutcomeUnknown`]: the cloud may have the job.
    Unknown(Error),
}

/// Sends a job to the cloud. After an ambiguous attempt (delivered without
/// an answer, or a 5xx other than 502/503/504) it is sent once more with the
/// same idempotency key (the cloud dedupes on it). A `409 duplicate` (the key's
/// job is being created) is re-sent after 1 s, at most
/// [`DUPLICATE_RESENDS`] times. Once the cloud may have the job, a not
/// delivered or ambiguous attempt is [`Error::OutcomeUnknown`]: the job never
/// goes local after that.
async fn cloud_leg(client: &Client, params: &CreateJob, timeout: Option<Duration>) -> CloudLeg {
    let jobs = client.jobs();
    let unknown = |e: Error| {
        CloudLeg::Unknown(Error::OutcomeUnknown {
            url: client.cfg.base_url.clone(),
            idempotency_key: params.idempotency_key.clone().unwrap_or_default(),
            cause: Box::new(e),
        })
    };
    // The body is built (and sealed) once: every attempt sends the same bytes
    // (only a sealed_content 400 makes it sealed again, once).
    let mut body = match jobs.cloud_job_bytes(params).await {
        Ok(b) => b,
        Err(e) => return CloudLeg::NotDelivered(e),
    };
    let mut maybe_there = false; // an earlier attempt may have created it
    let mut retried = false; // the one retry after an ambiguous attempt
    let mut resealed = false; // the one re-seal after a sealed_content 400
    let mut resends = 0;
    let mut attempt = jobs.create_cloud_once(&body, timeout).await;
    loop {
        attempt = match attempt {
            CloudAttempt::Answered(Ok(j)) => return CloudLeg::Job(j),
            CloudAttempt::Answered(Err(e)) if is_duplicate(&e) && resends < DUPLICATE_RESENDS => {
                resends += 1;
                maybe_there = true;
                tokio::time::sleep(DUPLICATE_PAUSE).await;
                jobs.create_cloud_once(&body, timeout).await
            }
            CloudAttempt::Answered(Err(e))
                if params.sealed && sealed_rejected(&e) && !resealed && resends == 0 =>
            {
                // The server key was rotated: fetch it again, seal again and
                // re-send once with the same idempotency key (S1).
                resealed = true;
                client.cfg.drop_server_key();
                match jobs.cloud_job_bytes(params).await {
                    Ok(b) => body = b,
                    Err(fe) if maybe_there => return unknown(fe),
                    Err(_) => return CloudLeg::Failed(e), // nothing more was sent
                }
                jobs.create_cloud_once(&body, timeout).await
            }
            // After an ambiguous attempt only the job (or a 409) settles it.
            CloudAttempt::Answered(Err(e))
                if maybe_there && (resealed || (params.sealed && sealed_rejected(&e))) =>
            {
                return unknown(e)
            }
            CloudAttempt::Answered(Err(e)) => return CloudLeg::Failed(e),
            CloudAttempt::NotDelivered(e) if maybe_there => return unknown(e),
            CloudAttempt::NotDelivered(e) => return CloudLeg::NotDelivered(e),
            CloudAttempt::Ambiguous(e) if retried || resends > 0 => return unknown(e),
            CloudAttempt::Ambiguous(_) => {
                retried = true;
                maybe_there = true;
                tokio::time::sleep(client.cfg.backoff(0, None)).await;
                jobs.create_cloud_once(&body, timeout).await
            }
        };
    }
}

/// Reads a local job (`"lj_…"`) from the station that has it.
pub(crate) async fn get_job(l: &Arc<LocalState>, id: &str) -> Result<Job> {
    let pref = l.lock().job_urls.get(id).cloned().unwrap_or_default();
    let path = format!("/local/v1/jobs/{}", seg(id));
    let r = l
        .authed(&pref, |t, tok| {
            let (l, path, pref) = (l.clone(), path.clone(), pref.clone());
            async move {
                match l
                    .send::<LocalJob>(&t, Method::GET, &path, &[], &tok, None, Duration::ZERO)
                    .await
                {
                    // Another station may have it.
                    Err(SendError::Answer(e @ Error::NotFound(_))) if pref.is_empty() => {
                        Err(SendError::Unreachable(e))
                    }
                    other => other,
                }
            }
        })
        .await;
    match r {
        Ok((mut lj, t, tok)) => {
            lj.station_url = t.url.clone();
            l.remember_job(id, &t.url);
            Ok(to_job(lj, &t, String::new(), token_live(&tok)))
        }
        Err(Error::StationUnreachable {
            attempts,
            cloud_error,
        }) => {
            match attempts
                .iter()
                .position(|a| matches!(a.error, Error::NotFound(_)))
            {
                Some(i) => Err(attempts
                    .into_iter()
                    .nth(i)
                    .map(|a| a.error)
                    .unwrap_or_else(|| unreachable(Vec::new()))),
                None => Err(Error::StationUnreachable {
                    attempts,
                    cloud_error,
                }),
            }
        }
        Err(e) => Err(e),
    }
}

// ---- the public helpers ----

/// Talks to CatzPrint stations on the local network: `client.local()`.
#[derive(Clone, Copy)]
pub struct Local<'a> {
    state: &'a Arc<LocalState>,
}

impl std::fmt::Debug for Local<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Local")
            .field("mode", &self.state.s.mode)
            .finish_non_exhaustive()
    }
}

impl Local<'_> {
    /// The configured mode.
    pub fn mode(&self) -> LocalMode {
        self.state.s.mode
    }

    /// The status of the first station that answers: printers, paper,
    /// unsynced jobs, offline allowance.
    pub async fn status(&self) -> Result<LocalStatus> {
        let l = self.state;
        let (mut st, t, _) = l
            .authed("", |t, tok| {
                let l = l.clone();
                async move {
                    l.send::<LocalStatus>(
                        &t,
                        Method::GET,
                        "/local/v1/status",
                        &[],
                        &tok,
                        None,
                        Duration::ZERO,
                    )
                    .await
                }
            })
            .await?;
        st.station_url = t.url;
        Ok(st)
    }

    /// A local job (`"lj_…"`) from the station that has it.
    /// [`crate::Jobs::get`] and [`crate::Jobs::wait_for`] call it for local
    /// job IDs.
    pub async fn get_job(&self, id: &str) -> Result<Job> {
        get_job(self.state, id).await
    }

    /// A station's public information (`GET /local/v1/info`, no token
    /// needed). The URL must be trusted like any station URL: a public
    /// hostname, or an IP with a fingerprint from the endpoint list, mDNS of
    /// a listed station or [`LocalConfig::fingerprint`].
    pub async fn info(&self, station_url: &str) -> Result<LocalInfo> {
        let l = self.state;
        let u = normalize_station_url(station_url)?;
        l.ensure_loaded().await;
        let st = l.snapshot();
        let found = l.lock().mdns.clone();
        let mut t = l.target_for(&u, "config", st.as_ref(), &found);
        if t.needs_pin() && t.fingerprint.is_empty() && l.s.discover {
            let (found, _) = l.browse(true).await;
            if !found.is_empty() {
                t = l.target_for(&u, "config", st.as_ref(), &found);
            }
        }
        match l
            .send::<LocalInfo>(
                &t,
                Method::GET,
                "/local/v1/info",
                &[],
                "",
                None,
                Duration::ZERO,
            )
            .await
        {
            Ok(i) => Ok(i),
            Err(SendError::Unreachable(e)) => Err(unreachable(vec![StationAttempt {
                url: t.url,
                error: e,
            }])),
            Err(SendError::Answer(e) | SendError::NoAnswer(e)) => Err(e),
        }
    }

    /// Pairs this device with one station using the 8-digit code shown in
    /// the station app ("Pair a device"). The device token (`"czd_…"`) works
    /// only on that station and without any cloud account: pass it to
    /// [`LocalConfig::token`].
    ///
    /// The station must be authenticated before the code is sent, or a
    /// device on the LAN could relay it: pass the certificate `fingerprint`
    /// shown in the station app next to the code (with an IP URL), or pin it
    /// with [`LocalConfig::fingerprint`], or use a station on the cloud
    /// endpoint list. mDNS is never enough. `device_name` empty: the
    /// configured device name.
    pub async fn pair(
        &self,
        station_url: &str,
        code: &str,
        device_name: &str,
        fingerprint: Option<&str>,
    ) -> Result<LocalPairing> {
        let l = self.state;
        if code.len() != 8 || !code.bytes().all(|b| b.is_ascii_digit()) {
            return Err(invalid(
                "code",
                "The pairing code is the 8 digits shown in the station app.",
            ));
        }
        let name: String = if device_name.trim().is_empty() {
            l.s.device_name.clone()
        } else {
            device_name.chars().take(80).collect()
        };
        let t = self.pair_target(station_url, fingerprint).await?;
        let body = json!({"code": code, "device_name": name});
        match l
            .send::<LocalPairing>(
                &t,
                Method::POST,
                "/local/v1/pair",
                &[],
                "",
                Some(&body),
                Duration::ZERO,
            )
            .await
        {
            Ok(p) if p.token.is_empty() => {
                Err(Error::Decode("the station answered without a token".into()))
            }
            Ok(p) => Ok(p),
            Err(SendError::Unreachable(e)) => Err(unreachable(vec![StationAttempt {
                url: t.url,
                error: e,
            }])),
            Err(SendError::Answer(e) | SendError::NoAnswer(e)) => Err(e),
        }
    }

    /// Resolves trust for pairing, without mDNS.
    async fn pair_target(&self, station_url: &str, fingerprint: Option<&str>) -> Result<Target> {
        let l = self.state;
        let u = normalize_station_url(station_url)?;
        let (host, _) = url_host(&u);
        if let Some(fp) = fingerprint.filter(|f| !f.trim().is_empty()) {
            let fp = normalize_fingerprint(fp);
            if fp.is_empty() {
                return Err(invalid(
                    "fingerprint",
                    "The fingerprint is the 64 hex characters (SHA-256) shown in the station app.",
                ));
            }
            if host_ip(&host).is_none() {
                return Err(invalid(
                    "url",
                    "Pair with the station's IP address URL when you pass the fingerprint from the station app.",
                ));
            }
            return Ok(Target {
                url: u,
                fingerprint: fp,
                tls_mode: "self_signed".into(),
                source: "config",
                ..Default::default()
            });
        }
        l.ensure_loaded().await;
        let t = l.target_for(&u, "config", l.snapshot().as_ref(), &[]);
        if (t.needs_pin() && t.fingerprint.is_empty())
            || (!t.needs_pin() && t.station_id.is_empty())
        {
            return Err(invalid(
                "fingerprint",
                "Pairing needs the certificate fingerprint shown in the station app, or a station on the cloud endpoint list.",
            ));
        }
        Ok(t)
    }

    /// Lists stations from the cloud endpoint list (refreshed now when the
    /// cloud answers, otherwise the cached copy) and from an mDNS browse,
    /// merged by station ID. It doesn't need [`LocalConfig::discover`].
    pub async fn discover(&self) -> Result<Vec<LocalStation>> {
        let l = self.state;
        l.ensure_loaded().await;
        let cloud_err = l.refresh(true).await.err();
        let st = l.snapshot();
        let (found, mdns_err) = l.browse(true).await;
        let mut out: Vec<LocalStation> = Vec::new();
        let mut idx: HashMap<String, usize> = HashMap::new();
        if let Some(st) = &st {
            for ep in &st.stations {
                if !l.s.location_id.is_empty()
                    && !ep.location_id.is_empty()
                    && ep.location_id != l.s.location_id
                {
                    continue;
                }
                idx.insert(ep.station_id.clone(), out.len());
                out.push(LocalStation {
                    station_id: ep.station_id.clone(),
                    name: ep.name.clone(),
                    org_id: l.org_hint(),
                    location_id: ep.location_id.clone(),
                    port: ep.port,
                    addresses: ep.addresses.clone(),
                    urls: endpoint_targets(ep, "cloud")
                        .into_iter()
                        .map(|t| t.url)
                        .collect(),
                    tls_mode: ep.tls_mode.clone(),
                    fingerprint: normalize_fingerprint(&ep.cert_fingerprint_sha256),
                    from_cloud: true,
                    from_mdns: false,
                    local_enabled: ep.local_enabled,
                    connected: ep.connected,
                });
            }
        }
        for d in l.accepted_mdns(&found, st.as_ref()) {
            let urls: Vec<String> = mdns_targets(&d).into_iter().map(|t| t.url).collect();
            if let Some(&i) = idx.get(&d.station_id) {
                let ls = &mut out[i];
                ls.from_mdns = true;
                for a in &d.addresses {
                    if !ls.addresses.contains(a) {
                        ls.addresses.push(a.clone());
                    }
                }
                for u in urls {
                    if !ls.urls.contains(&u) {
                        ls.urls.push(u);
                    }
                }
                continue;
            }
            idx.insert(d.station_id.clone(), out.len());
            out.push(LocalStation {
                station_id: d.station_id,
                name: d.instance,
                org_id: d.org_id,
                location_id: d.location_id,
                port: d.port,
                addresses: d.addresses,
                urls,
                tls_mode: d.tls_mode,
                fingerprint: d.fingerprint,
                from_cloud: false,
                from_mdns: true,
                local_enabled: true,
                connected: false,
            });
        }
        if out.is_empty() {
            if let Some(e) = cloud_err {
                return Err(e);
            }
            if let Some(e) = mdns_err {
                return Err(Error::Io(e));
            }
        }
        Ok(out)
    }

    /// Renews the local token (when it has less than 7 days left) and
    /// re-reads the cloud endpoint list now. The SDK also does this by
    /// itself in the background while online; call it at start-up or after
    /// network changes.
    pub async fn refresh(&self) -> Result<()> {
        self.state.refresh(true).await
    }

    /// The token the SDK uses for stations (minting one when needed), e.g.
    /// to hand to a browser POS.
    pub async fn token(&self) -> Result<String> {
        self.state.token().await
    }

    /// The last error from the token store, if any. Store failures never
    /// stop printing; they only mean the token or endpoint list won't
    /// survive a restart.
    pub fn store_error(&self) -> Option<Arc<io::Error>> {
        self.state.lock().store_err.clone()
    }

    #[doc(hidden)]
    /// Test hook, not part of the API: moves the SDK's clock forward.
    pub fn __advance_clock(&self, by: Duration) {
        let d = TimeDelta::from_std(by).unwrap_or(TimeDelta::zero());
        self.state.lock().clock_offset += d;
    }

    #[doc(hidden)]
    /// Test hook, not part of the API: where mDNS queries go.
    pub fn __set_mdns_addr(&self, addr: SocketAddr) {
        self.state.lock().mdns_addr = addr;
    }

    #[doc(hidden)]
    /// Test hook, not part of the API: waits for a background refresh.
    pub async fn __wait_background(&self) {
        let h = self.state.lock().bg.take();
        if let Some(h) = h {
            let _ = h.await;
        }
    }

    #[doc(hidden)]
    /// Test hook, not part of the API: the token store key.
    pub fn __store_key(&self) -> String {
        self.state.store_key.clone()
    }
}

impl Client {
    /// Local printing helpers (feature `local`): station status, discovery,
    /// pairing, local jobs.
    #[cfg_attr(docsrs, doc(cfg(feature = "local")))]
    pub fn local(&self) -> Local<'_> {
        Local {
            state: &self
                .local
                .as_ref()
                .expect("clients built by ClientBuilder have local state")
                .state,
        }
    }

    /// Local tokens (feature `local`).
    #[cfg_attr(docsrs, doc(cfg(feature = "local")))]
    pub fn local_tokens(&self) -> LocalTokens<'_> {
        LocalTokens { client: self }
    }

    /// The stations' local endpoints (feature `local`).
    #[cfg_attr(docsrs, doc(cfg(feature = "local")))]
    pub fn local_endpoints(&self) -> LocalEndpoints<'_> {
        LocalEndpoints { client: self }
    }

    /// Stops background refreshes, waits for them, and drops idle
    /// connections to stations. Dropping the last clone of the client also
    /// stops them (without waiting). Safe to call more than once.
    #[cfg_attr(docsrs, doc(cfg(feature = "local")))]
    pub async fn close(&self) {
        if let Some(h) = &self.local {
            h.state.close().await;
        }
    }

    pub(crate) fn local_state(&self) -> Option<&Arc<LocalState>> {
        self.local.as_ref().map(|h| &h.state)
    }
}

#[cfg(test)]
mod tests;
