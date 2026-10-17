//! Transport-independent pieces shared by the async and blocking clients:
//! configuration, request descriptions, retry policy and response decoding.

use std::sync::Mutex;
use std::time::Duration;

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
            .finish()
    }
}

impl ClientBuilder {
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
        crate::Client::from_config(self.into_config()?)
    }

    /// Builds the blocking client.
    #[cfg(feature = "blocking")]
    pub fn build_blocking(self) -> Result<crate::blocking::Client> {
        crate::blocking::Client::from_config(self.into_config()?)
    }

    pub(crate) fn into_config(self) -> Result<Config> {
        let api_key = self
            .api_key
            .or_else(|| std::env::var("CATZPRINT_API_KEY").ok())
            .map(|k| k.trim().to_string())
            .filter(|k| !k.is_empty())
            .ok_or_else(|| Error::Config("no API key: pass one or set CATZPRINT_API_KEY".into()))?;
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
            server_key: Mutex::new(None),
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

pub(crate) struct Config {
    pub api_key: String,
    pub base_url: String,
    pub org_id: Mutex<Option<String>>,
    pub server_key: Mutex<Option<[u8; 32]>>,
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
    pub fn cached_server_key(&self) -> Option<[u8; 32]> {
        *self.server_key.lock().unwrap_or_else(|e| e.into_inner())
    }
    pub fn set_server_key(&self, k: [u8; 32]) {
        *self.server_key.lock().unwrap_or_else(|e| e.into_inner()) = Some(k);
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
        }
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
    pub fn needs_org(&self) -> bool {
        self.path.contains("{org}")
    }
    pub fn retryable(&self) -> bool {
        self.method == Method::Get || self.idempotent
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
    let can_retry = req.retryable() && attempt < cfg.max_retries;
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

/// Fills in a generated idempotency key.
pub(crate) fn with_idempotency(mut p: crate::CreateJob) -> crate::CreateJob {
    if p.idempotency_key
        .as_deref()
        .is_none_or(|k| k.trim().is_empty())
    {
        p.idempotency_key = Some(uuid::Uuid::new_v4().to_string());
    }
    p
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
}
