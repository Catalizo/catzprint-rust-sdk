//! Transport-independent pieces shared by the async and blocking clients:
//! configuration, request descriptions, retry policy and response decoding.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::error::{map_error, Error, Result};

/// The default API base URL.
pub const DEFAULT_BASE_URL: &str = "https://api-v1.catzprint.com";
/// The User-Agent sent with every request.
pub const USER_AGENT: &str = concat!("catzprint-rust/", env!("CARGO_PKG_VERSION"));

/// Configures a [`crate::Client`] (or `blocking::Client`).
///
/// ```no_run
/// # fn main() -> catzprint::Result<()> {
/// use std::time::Duration;
/// let client = catzprint::Client::builder()
///     .api_key("cz_test_...")
///     .timeout(Duration::from_secs(10))
///     .max_retries(3)
///     .build()?;
/// # let _ = client; Ok(()) }
/// ```
#[derive(Clone)]
pub struct ClientBuilder {
    #[cfg(feature = "local")]
    local: Option<crate::local::LocalConfig>,
    api_key: Option<String>,
    base_url: Option<String>,
    org_id: Option<String>,
    timeout: Duration,
    max_retries: u32,
    retry_base_delay: Duration,
    max_retry_delay: Duration,
}

impl Default for ClientBuilder {
    fn default() -> Self {
        ClientBuilder {
            #[cfg(feature = "local")]
            local: None,
            api_key: None,
            base_url: None,
            org_id: None,
            timeout: Duration::from_secs(30),
            max_retries: 2,
            retry_base_delay: Duration::from_millis(500),
            max_retry_delay: Duration::from_secs(30),
        }
    }
}

impl std::fmt::Debug for ClientBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientBuilder")
            .field("api_key", &self.api_key.as_deref().map(redact))
            .field("base_url", &self.base_url)
            .field("org_id", &self.org_id)
            .field("timeout", &self.timeout)
            .field("max_retries", &self.max_retries)
            .finish_non_exhaustive()
    }
}

impl ClientBuilder {
    /// Enables local printing through CatzPrint stations on the same network
    /// (feature `local`). See [`crate::LocalConfig`] and the README section
    /// "Local printing (offline)".
    #[cfg(feature = "local")]
    #[cfg_attr(docsrs, doc(cfg(feature = "local")))]
    pub fn local(mut self, config: crate::local::LocalConfig) -> Self {
        self.local = Some(config);
        self
    }
    /// The API key (`cz_live_…` or `cz_test_…`). Defaults to `$CATZPRINT_API_KEY`.
    pub fn api_key(mut self, key: impl Into<String>) -> Self {
        self.api_key = Some(key.into());
        self
    }
    /// The API base URL. Defaults to `$CATZPRINT_BASE_URL`, then
    /// `https://api-v1.catzprint.com`.
    pub fn base_url(mut self, url: impl Into<String>) -> Self {
        self.base_url = Some(url.into());
        self
    }
    /// The organization ID. When not set it is looked up once with `GET /v1/key`.
    pub fn org_id(mut self, org_id: impl Into<String>) -> Self {
        self.org_id = Some(org_id.into());
        self
    }
    /// Per-request timeout (default 30 s).
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
    /// Retries after network errors, 429 and 502/503/504 (default 2).
    /// POSTs are only retried when they carry an idempotency key.
    pub fn max_retries(mut self, n: u32) -> Self {
        self.max_retries = n;
        self
    }
    /// First backoff delay; doubles on every retry, with jitter (default 500 ms).
    pub fn retry_base_delay(mut self, d: Duration) -> Self {
        self.retry_base_delay = d;
        self
    }
    /// Longest wait between retries, including `Retry-After` (default 30 s).
    /// A longer `Retry-After` is not waited for: the rate-limit error is returned.
    pub fn max_retry_delay(mut self, d: Duration) -> Self {
        self.max_retry_delay = d;
        self
    }

    /// Builds the async client.
    pub fn build(self) -> Result<crate::Client> {
        #[cfg(feature = "local")]
        let local = self.local.clone();
        #[cfg(feature = "local")]
        let paired = local.as_ref().is_some_and(|l| l.is_paired_device());
        #[cfg(not(feature = "local"))]
        let paired = false;
        let cfg = self.into_config_with(paired)?;
        #[cfg(feature = "local")]
        {
            crate::Client::from_config_local(cfg, local)
        }
        #[cfg(not(feature = "local"))]
        {
            crate::Client::from_config(cfg)
        }
    }

    /// Builds the blocking client. Local printing needs the async client.
    #[cfg(feature = "blocking")]
    pub fn build_blocking(self) -> Result<crate::blocking::Client> {
        #[cfg(feature = "local")]
        if self.local.as_ref().is_some_and(|l| l.is_local_mode()) {
            return Err(Error::Config(
                "local printing is only available on the async client".into(),
            ));
        }
        crate::blocking::Client::from_config(self.into_config()?)
    }

    #[cfg(any(feature = "blocking", test))]
    pub(crate) fn into_config(self) -> Result<Config> {
        self.into_config_with(false)
    }

    /// `allow_no_key`: a paired device in local mode (static device token)
    /// needs no API key; its cloud calls fail with `missing_api_key`.
    fn into_config_with(self, allow_no_key: bool) -> Result<Config> {
        let api_key = self
            .api_key
            .or_else(|| std::env::var("CATZPRINT_API_KEY").ok())
            .map(|k| k.trim().to_string())
            .filter(|k| !k.is_empty());
        let api_key = match api_key {
            Some(k) => k,
            None if allow_no_key => String::new(),
            None => {
                return Err(Error::Config(
                    "no API key: pass one or set CATZPRINT_API_KEY (only a paired device in \
                     local mode, with LocalMode::Local and a token, can work without one)"
                        .into(),
                ))
            }
        };
        let base_url = self
            .base_url
            .or_else(|| {
                std::env::var("CATZPRINT_BASE_URL")
                    .ok()
                    .filter(|u| !u.is_empty())
            })
            .unwrap_or_else(|| DEFAULT_BASE_URL.to_string());
        let base_url = base_url.trim().trim_end_matches('/').to_string();
        check_base_url(&base_url)?;
        Ok(Config {
            api_key,
            base_url,
            org_id: Mutex::new(self.org_id),
            server_key: Mutex::new(ServerKeyCache::default()),
            timeout: self.timeout,
            max_retries: self.max_retries,
            retry_base_delay: self.retry_base_delay,
            max_retry_delay: self.max_retry_delay,
        })
    }
}

/// Largest response body the SDK reads (64 MiB); a bigger answer is an error.
pub(crate) const MAX_RESPONSE_BYTES: usize = 64 << 20;

/// Requires `https://`, allowing plain `http://` only for a local server
/// (tests, development proxies): the API key travels with every request.
pub(crate) fn check_base_url(url: &str) -> Result<()> {
    let parsed = reqwest::Url::parse(url)
        .map_err(|_| Error::Config(format!("the base URL isn't a valid URL: {url:?}")))?;
    let host = match parsed.host_str() {
        Some(h) if !h.is_empty() => h
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_ascii_lowercase(),
        _ => return Err(Error::Config(format!("the base URL has no host: {url:?}"))),
    };
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(Error::Config(
            "the base URL must not contain credentials".into(),
        ));
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(Error::Config(
            "the base URL must not contain a query or fragment".into(),
        ));
    }
    let local =
        matches!(host.as_str(), "localhost" | "127.0.0.1" | "::1") || host.ends_with(".localhost");
    match parsed.scheme() {
        "https" => Ok(()),
        "http" if local => Ok(()),
        _ => Err(Error::Config(
            "the base URL must use https:// (http:// is allowed only for localhost), \
             so the API key isn't sent in clear text"
                .into(),
        )),
    }
}

/// Masks an API key for display: `cz_live_****wxyz`.
pub(crate) fn redact(key: &str) -> String {
    let prefix = if key.starts_with("cz_live_") || key.starts_with("cz_test_") {
        &key[..8]
    } else {
        ""
    };
    // Work on chars, not bytes: slicing a non-ASCII key at a byte offset
    // would panic inside Debug.
    let n = key.chars().count();
    let tail: String = if n >= prefix.len() + 12 {
        key.chars().skip(n - 4).collect()
    } else {
        String::new()
    };
    format!("{prefix}****{tail}")
}

/// The cached server key and a generation counter bumped on every drop.
#[derive(Default)]
pub(crate) struct ServerKeyCache {
    pub key: Option<([u8; 32], Instant)>,
    pub gen: u64,
}

pub(crate) struct Config {
    pub api_key: String,
    pub base_url: String,
    pub org_id: Mutex<Option<String>>,
    /// The server key and when it was fetched (used for [`SERVER_KEY_TTL`]).
    pub server_key: Mutex<ServerKeyCache>,
    pub timeout: Duration,
    pub max_retries: u32,
    pub retry_base_delay: Duration,
    pub max_retry_delay: Duration,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("api_key", &redact(&self.api_key))
            .field("base_url", &self.base_url)
            .field(
                "org_id",
                &*self.org_id.lock().unwrap_or_else(|e| e.into_inner()),
            )
            .field("timeout", &self.timeout)
            .field("max_retries", &self.max_retries)
            .finish()
    }
}

impl Config {
    pub fn cached_org(&self) -> Option<String> {
        self.org_id
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
    pub fn set_org(&self, org: &str) {
        *self.org_id.lock().unwrap_or_else(|e| e.into_inner()) = Some(org.to_string());
    }
    /// The cached server key, while it is younger than [`SERVER_KEY_TTL`].
    pub fn cached_server_key(&self) -> Option<[u8; 32]> {
        self.server_key
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .key
            .filter(|(_, at)| at.elapsed() < SERVER_KEY_TTL)
            .map(|(k, _)| k)
    }
    /// The current generation, to pass to [`Config::set_server_key`] when a
    /// fetch completes.
    pub fn server_key_gen(&self) -> u64 {
        self.server_key
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .gen
    }
    /// Caches a fetched key, unless the key was dropped since the fetch
    /// started (`gen` is the generation read before fetching): an older
    /// in-flight fetch must not bring a dropped (rotated) key back.
    pub fn set_server_key(&self, k: [u8; 32], gen: u64) {
        let mut c = self.server_key.lock().unwrap_or_else(|e| e.into_inner());
        if c.gen == gen {
            c.key = Some((k, Instant::now()));
        }
    }
    /// Forgets the server key (the API couldn't decrypt a sealed job).
    pub fn drop_server_key(&self) {
        let mut c = self.server_key.lock().unwrap_or_else(|e| e.into_inner());
        c.key = None;
        c.gen += 1;
    }
    /// Test hook: pretends the cached server key was fetched `age` ago.
    #[cfg(test)]
    pub fn age_server_key(&self, age: Duration) {
        if let Some((_, at)) = self
            .server_key
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .key
            .as_mut()
        {
            *at = at.checked_sub(age).unwrap_or(*at);
        }
    }

    /// The wait before retry number `attempt` (0-based): exponential backoff
    /// with "equal jitter", or the server's Retry-After when it gave one.
    pub fn backoff(&self, attempt: u32, retry_after: Option<Duration>) -> Duration {
        if let Some(ra) = retry_after {
            return ra;
        }
        let exp = self
            .retry_base_delay
            .saturating_mul(1u32 << attempt.min(16));
        let capped = exp.min(self.max_retry_delay);
        let half = capped / 2;
        half + half.mul_f64(fastrand::f64())
    }
}

/// HTTP method of a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Method {
    Get,
    Post,
    #[cfg_attr(not(feature = "local"), allow(dead_code))]
    Delete,
}

/// A request to make, independent of the transport.
#[derive(Debug, Clone)]
pub(crate) struct Request {
    pub method: Method,
    /// Path, possibly containing `{org}`.
    pub path: String,
    pub query: Vec<(String, String)>,
    pub body: Option<Value>,
    /// Whether the request carries an idempotency key (makes POST retryable).
    pub idempotent: bool,
    /// Whether to send the API key.
    pub auth: bool,
    /// Overrides the client's retry count (local printing: the cloud is
    /// tried once before falling back).
    pub max_retries: Option<u32>,
    /// Overrides the client's per-request timeout.
    pub timeout: Option<Duration>,
    /// Set when an attempt that may have reached the API (sent, then no
    /// usable answer) was retried.
    pub ambiguous: Option<Arc<AtomicBool>>,
}

impl Request {
    pub fn get(path: impl Into<String>) -> Self {
        Request {
            method: Method::Get,
            path: path.into(),
            query: Vec::new(),
            body: None,
            idempotent: false,
            auth: true,
            max_retries: None,
            timeout: None,
            ambiguous: None,
        }
    }
    pub fn post(path: impl Into<String>, body: Value) -> Self {
        Request {
            method: Method::Post,
            path: path.into(),
            query: Vec::new(),
            body: Some(body),
            idempotent: false,
            auth: true,
            max_retries: None,
            timeout: None,
            ambiguous: None,
        }
    }
    #[cfg(feature = "local")]
    pub fn delete(path: impl Into<String>) -> Self {
        Request {
            method: Method::Delete,
            ..Request::get(path)
        }
    }
    /// Tries once, within `timeout` (local printing's cloud calls).
    #[cfg(feature = "local")]
    pub fn once_within(mut self, timeout: Duration) -> Self {
        self.max_retries = Some(0);
        self.timeout = Some(timeout);
        self
    }
    pub fn query(mut self, q: Vec<(String, String)>) -> Self {
        self.query = q;
        self
    }
    pub fn idempotent(mut self) -> Self {
        self.idempotent = true;
        self
    }
    pub fn public(mut self) -> Self {
        self.auth = false;
        self
    }
    /// Records retries after attempts that may have reached the API in `flag`.
    pub fn track_ambiguous(mut self, flag: Arc<AtomicBool>) -> Self {
        self.ambiguous = Some(flag);
        self
    }
    /// Called before a retry: `maybe_sent` says the failed attempt may have
    /// reached the API.
    pub fn note_retry(&self, maybe_sent: bool) {
        if let (true, Some(f)) = (maybe_sent, &self.ambiguous) {
            f.store(true, Ordering::SeqCst);
        }
    }
    pub fn needs_org(&self) -> bool {
        self.path.contains("{org}")
    }
    pub fn retryable(&self) -> bool {
        self.method == Method::Get || self.idempotent
    }
    pub fn max_retries(&self, cfg: &Config) -> u32 {
        self.max_retries.unwrap_or(cfg.max_retries)
    }
    pub fn url(&self, base: &str, org: Option<&str>) -> String {
        match org {
            Some(o) => format!("{base}{}", self.path.replace("{org}", &seg(o))),
            None => format!("{base}{}", self.path),
        }
    }
}

/// Percent-encodes one path segment.
pub(crate) fn seg(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// What to do after one attempt.
pub(crate) enum Step {
    Done(Result<Value>),
    Retry(Duration),
}

/// The outcome of one HTTP attempt, as seen by the retry policy.
pub(crate) enum Attempt {
    /// The server answered.
    Response {
        status: u16,
        retry_after: Option<Duration>,
        body: Vec<u8>,
    },
    /// The request failed before an answer.
    Network { message: String, timeout: bool },
    /// The response body was larger than [`MAX_RESPONSE_BYTES`].
    TooLarge,
}

/// Applies the retry policy to one attempt.
pub(crate) fn decide(cfg: &Config, req: &Request, attempt: u32, outcome: Attempt) -> Step {
    let can_retry = req.retryable() && attempt < req.max_retries(cfg);
    match outcome {
        Attempt::TooLarge => Step::Done(Err(Error::Decode(format!(
            "the API response is larger than {MAX_RESPONSE_BYTES} bytes"
        )))),
        Attempt::Network { message, timeout } => {
            if can_retry {
                Step::Retry(cfg.backoff(attempt, None))
            } else {
                Step::Done(Err(Error::Connection { message, timeout }))
            }
        }
        Attempt::Response {
            status,
            retry_after,
            body,
        } => {
            if (200..300).contains(&status) {
                return Step::Done(parse_success(&body));
            }
            let err = map_error(status, retry_after, &body);
            if can_retry && matches!(status, 429 | 502 | 503 | 504) {
                let wait = cfg.backoff(attempt, err.retry_after());
                if wait <= cfg.max_retry_delay {
                    return Step::Retry(wait);
                }
            }
            Step::Done(Err(err))
        }
    }
}

fn parse_success(body: &[u8]) -> Result<Value> {
    if body.iter().all(|b| b.is_ascii_whitespace()) {
        return Ok(Value::Null);
    }
    serde_json::from_slice(body).map_err(|e| Error::Decode(e.to_string()))
}

/// Parses a `Retry-After` header given in seconds.
pub(crate) fn parse_retry_after(v: Option<&str>) -> Option<Duration> {
    v.and_then(|s| s.trim().parse::<f64>().ok())
        .filter(|s| s.is_finite() && *s >= 0.0)
        .map(Duration::from_secs_f64)
}

/// Takes `key` out of a response object and decodes it.
pub(crate) fn field<T: DeserializeOwned>(mut v: Value, key: &str) -> Result<T> {
    let inner = v
        .get_mut(key)
        .map(Value::take)
        .ok_or_else(|| Error::Decode(format!("the response has no {key:?} field")))?;
    serde_json::from_value(inner).map_err(|e| Error::Decode(format!("{key}: {e}")))
}

/// Takes a list out of a response object; `null` reads as an empty list.
pub(crate) fn list_field<T: DeserializeOwned>(mut v: Value, key: &str) -> Result<Vec<T>> {
    match v.get_mut(key).map(Value::take) {
        None => Err(Error::Decode(format!("the response has no {key:?} field"))),
        Some(Value::Null) => Ok(Vec::new()),
        Some(inner) => {
            serde_json::from_value(inner).map_err(|e| Error::Decode(format!("{key}: {e}")))
        }
    }
}

/// Decodes a whole response.
pub(crate) fn whole<T: DeserializeOwned>(v: Value) -> Result<T> {
    serde_json::from_value(v).map_err(|e| Error::Decode(e.to_string()))
}

/// Decodes `jobs.get` (`{"job": {...}, "events": [...]}`) into a Job with events.
pub(crate) fn job_with_events(mut v: Value) -> Result<crate::Job> {
    let events = v.get_mut("events").map(Value::take).unwrap_or(Value::Null);
    let mut job: crate::Job = field(v, "job")?;
    if !events.is_null() {
        job.events =
            serde_json::from_value(events).map_err(|e| Error::Decode(format!("events: {e}")))?;
    }
    Ok(job)
}

/// The error of a cloud call made by a client without an API key (a paired
/// device in local mode).
pub(crate) fn missing_api_key() -> Error {
    Error::Authentication(crate::ApiError {
        status: 401,
        code: "missing_api_key".into(),
        message: "This client has no API key (a paired device in local mode), so it can't call \
                  the CatzPrint API."
            .into(),
        fields: Default::default(),
        retry_after: None,
    })
}

/// Checks the caller's idempotency key: a key that is empty after trimming
/// whitespace counts as no key (`None`); a key with leading or trailing
/// whitespace or control characters is refused rather than silently changed
/// (a changed key would no longer dedupe against the caller's own retries).
pub(crate) fn normalize_idempotency_key(p: &mut crate::CreateJob) -> Result<()> {
    let Some(k) = p.idempotency_key.as_deref() else {
        return Ok(());
    };
    if k.trim().is_empty() {
        p.idempotency_key = None;
        return Ok(());
    }
    let why = if k.trim() != k {
        "Can't start or end with whitespace."
    } else if k.chars().any(char::is_control) {
        "Can't contain control characters."
    } else {
        return Ok(());
    };
    // 422 like the SDK's other client-side validation errors.
    Err(Error::Validation(crate::ApiError {
        status: 422,
        code: "invalid".into(),
        message: format!("The idempotency key is invalid: {why}"),
        fields: [("idempotency_key".to_string(), why.to_string())]
            .into_iter()
            .collect(),
        retry_after: None,
    }))
}

/// A `409 duplicate` to a job create: the idempotency key's job is being
/// created by a concurrent or earlier request (or belongs to another job).
/// The SDK waits [`DUPLICATE_PAUSE`] and re-sends the identical request, at
/// most [`DUPLICATE_RESENDS`] times, so it gets that job.
pub(crate) fn is_duplicate(e: &Error) -> bool {
    matches!(e, Error::Conflict(a) if a.code == "duplicate")
}

/// How long a fetched server key is used before it is fetched again (the
/// server may rotate it).
pub(crate) const SERVER_KEY_TTL: Duration = Duration::from_secs(3600);

/// A 400/422 saying the API couldn't use `sealed_content` (usually: the
/// server key was rotated after the SDK fetched it).
pub(crate) fn sealed_rejected(e: &Error) -> bool {
    matches!(e, Error::Validation(a) if a.fields.contains_key("sealed_content"))
}

/// An error after which the API may have the job (a network error, a 5xx
/// other than 502/503/504, a redirect, an unreadable answer).
pub(crate) fn maybe_arrived(e: &Error) -> bool {
    match e {
        Error::Connection { .. } | Error::Decode(_) => true,
        Error::Server(a) => !matches!(a.status, 502..=504),
        Error::Api(a) => (300..400).contains(&a.status),
        _ => false,
    }
}

/// What the cloud-mode create does after an error: re-send after a
/// `409 duplicate` (R4), re-seal once after a `sealed_content` 400 (S1), or
/// fail.
pub(crate) enum CloudNext {
    Resend,
    /// Carries the API's `sealed_content` answer (returned when the key
    /// can't be fetched again and nothing was ambiguous).
    Reseal(Error),
    Fail(Error),
}

/// The state of one cloud-mode create (shared by the async and blocking
/// clients).
pub(crate) struct CloudModeCreate {
    pub sealed: bool,
    pub resends: u32,
    pub resealed: bool,
    /// An attempt may have reached the API (set by the HTTP retry loop).
    pub ambiguous: Arc<AtomicBool>,
    pub base_url: String,
    pub key: String,
}

impl CloudModeCreate {
    pub fn new(sealed: bool, base_url: &str, key: &str) -> Self {
        CloudModeCreate {
            sealed,
            resends: 0,
            resealed: false,
            ambiguous: Arc::new(AtomicBool::new(false)),
            base_url: base_url.to_string(),
            key: key.to_string(),
        }
    }
    pub fn ambiguous(&self) -> bool {
        self.ambiguous.load(Ordering::SeqCst)
    }
    pub fn unknown(&self, e: Error) -> Error {
        Error::OutcomeUnknown {
            url: self.base_url.clone(),
            idempotency_key: self.key.clone(),
            cause: Box::new(e),
        }
    }
    pub fn after(&mut self, e: Error) -> CloudNext {
        if is_duplicate(&e) && self.resends < DUPLICATE_RESENDS {
            self.resends += 1;
            return CloudNext::Resend;
        }
        if self.sealed && sealed_rejected(&e) {
            if self.resends > 0 {
                // A job with this key exists or is being created.
                return CloudNext::Fail(self.unknown(e));
            }
            if !self.resealed {
                self.resealed = true;
                return CloudNext::Reseal(e);
            }
            return CloudNext::Fail(if self.ambiguous() { self.unknown(e) } else { e });
        }
        if self.resealed && !is_duplicate(&e) && (self.ambiguous() || maybe_arrived(&e)) {
            // After an ambiguous attempt only the job (or a 409) settles it.
            return CloudNext::Fail(self.unknown(e));
        }
        CloudNext::Fail(e)
    }
    /// The re-seal's key fetch failed: nothing more was sent.
    pub fn key_fetch_failed(&self, first: Error, fetch: Error) -> Error {
        if self.ambiguous() {
            self.unknown(fetch)
        } else {
            first
        }
    }
}

/// `409 duplicate` re-sends: at most this many, this far apart.
pub(crate) const DUPLICATE_RESENDS: u32 = 3;
pub(crate) const DUPLICATE_PAUSE: Duration = Duration::from_secs(1);

/// Checks the idempotency key and fills in a generated one when there is
/// none.
pub(crate) fn with_idempotency(mut p: crate::CreateJob) -> Result<crate::CreateJob> {
    normalize_idempotency_key(&mut p)?;
    if p.idempotency_key.is_none() {
        p.idempotency_key = Some(uuid::Uuid::new_v4().to_string());
    }
    Ok(p)
}

/// The file name of a path, used as the job file name and default title.
pub(crate) fn file_name_of(path: &std::path::Path) -> Option<String> {
    path.file_name().map(|n| n.to_string_lossy().into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_keys() {
        assert_eq!(
            redact("cz_live_abcdefghijklmnopqrstuvwxyz"),
            "cz_live_****wxyz"
        );
        assert_eq!(redact("short"), "****");
        let b = ClientBuilder::default().api_key("cz_test_supersecretvalue1234");
        assert!(!format!("{b:?}").contains("supersecret"));
    }

    #[test]
    fn backoff_grows_and_respects_retry_after() {
        let cfg = ClientBuilder::default()
            .api_key("cz_test_x")
            .into_config()
            .unwrap();
        for attempt in 0..4 {
            let d = cfg.backoff(attempt, None);
            let full = Duration::from_millis(500) * (1 << attempt);
            assert!(d >= full / 2 && d <= full, "attempt {attempt}: {d:?}");
        }
        assert_eq!(
            cfg.backoff(0, Some(Duration::from_secs(7))),
            Duration::from_secs(7)
        );
        assert!(cfg.backoff(20, None) <= Duration::from_secs(30));
    }

    #[test]
    fn only_idempotent_posts_retry() {
        let cfg = ClientBuilder::default()
            .api_key("cz_test_x")
            .into_config()
            .unwrap();
        let net = || Attempt::Network {
            message: "reset".into(),
            timeout: false,
        };
        let post = Request::post("/x", Value::Null);
        assert!(matches!(
            decide(&cfg, &post, 0, net()),
            Step::Done(Err(Error::Connection { .. }))
        ));
        let post = post.idempotent();
        assert!(matches!(decide(&cfg, &post, 0, net()), Step::Retry(_)));
        assert!(matches!(decide(&cfg, &post, 2, net()), Step::Done(_)));
        let get = Request::get("/x");
        let r503 = Attempt::Response {
            status: 503,
            retry_after: None,
            body: vec![],
        };
        assert!(matches!(decide(&cfg, &get, 0, r503), Step::Retry(_)));
        let r500 = Attempt::Response {
            status: 500,
            retry_after: None,
            body: vec![],
        };
        assert!(matches!(
            decide(&cfg, &get, 0, r500),
            Step::Done(Err(Error::Server(_)))
        ));
        let r429 = Attempt::Response {
            status: 429,
            retry_after: Some(Duration::from_secs(600)),
            body: vec![],
        };
        assert!(matches!(
            decide(&cfg, &get, 0, r429),
            Step::Done(Err(Error::RateLimit(_)))
        ));
    }

    #[test]
    fn redact_handles_non_ascii_keys() {
        // Must not panic on a char boundary.
        let r = redact("cz_live_ééééééééééééééé");
        assert!(r.starts_with("cz_live_****"));
    }

    #[test]
    fn base_url_must_be_https_except_localhost() {
        for bad in [
            "http://api-v1.catzprint.com",
            "http://10.0.0.5:8080",
            "ftp://x.test",
            "not a url",
            "https://u:p@x.test",
            "https://x.test/?a=1",
        ] {
            assert!(check_base_url(bad).is_err(), "accepted {bad}");
        }
        for ok in [
            "https://api.example.test",
            "http://localhost:8080",
            "http://127.0.0.1:1",
            "http://[::1]:3000",
        ] {
            assert!(check_base_url(ok).is_ok(), "rejected {ok}");
        }
    }

    #[test]
    fn encodes_segments() {
        assert_eq!(seg("a b/c"), "a%20b%2Fc");
        assert_eq!(
            Request::get("/v1/orgs/{org}/jobs").url("http://h", Some("o1")),
            "http://h/v1/orgs/o1/jobs"
        );
    }

    /// S2 (addendum 5): the server key is used for an hour, then fetched
    /// again; a sealed_content 400 drops it at once.
    #[test]
    fn server_key_cache_expires_after_an_hour() {
        let cfg = ClientBuilder::default()
            .api_key("cz_test_x")
            .into_config()
            .unwrap();
        cfg.set_server_key([9; 32], cfg.server_key_gen());
        assert_eq!(cfg.cached_server_key(), Some([9; 32]));
        cfg.age_server_key(Duration::from_secs(59 * 60));
        assert!(cfg.cached_server_key().is_some());
        cfg.age_server_key(Duration::from_secs(2 * 60));
        assert_eq!(cfg.cached_server_key(), None, "stale after an hour");
        cfg.set_server_key([9; 32], cfg.server_key_gen());
        cfg.drop_server_key();
        assert_eq!(cfg.cached_server_key(), None);
    }

    /// SDK9-2: a fetch that started before a drop doesn't re-install its key.
    #[test]
    fn stale_server_key_fetch_is_not_reinstalled() {
        let cfg = ClientBuilder::default()
            .api_key("cz_test_x")
            .into_config()
            .unwrap();
        let gen = cfg.server_key_gen(); // a fetch starts
        cfg.drop_server_key(); // a sealed_content rejection lands meanwhile
        cfg.set_server_key([9; 32], gen); // the old fetch completes
        assert_eq!(cfg.cached_server_key(), None, "the dropped key came back");
        cfg.set_server_key([7; 32], cfg.server_key_gen());
        assert_eq!(cfg.cached_server_key(), Some([7; 32]));
    }
}
