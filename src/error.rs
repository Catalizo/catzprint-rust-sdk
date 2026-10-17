//! Errors returned by the SDK.

use std::collections::BTreeMap;
use std::time::Duration;

use serde::Deserialize;

/// Shorthand for `Result<T, catzprint::Error>`.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// The details of an error answered by the CatzPrint API.
///
/// Every API failure carries the HTTP status, a stable machine-readable
/// `code`, a plain-English `message`, per-field messages (for validation
/// errors) and, when the API asks for it, how long to wait before retrying.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiError {
    /// HTTP status code, e.g. `403`.
    pub status: u16,
    /// Stable error code, e.g. `"forbidden"`, `"invalid"`, `"out_of_prints"`.
    pub code: String,
    /// Human-readable message, safe to show to people.
    pub message: String,
    /// Per-field messages for validation errors (`{"printer_id": "Unknown printer."}`).
    pub fields: BTreeMap<String, String>,
    /// How long the API asked us to wait before trying again.
    pub retry_after: Option<Duration>,
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}: {}", self.status, self.code, self.message)?;
        if !self.fields.is_empty() {
            let parts: Vec<String> = self
                .fields
                .iter()
                .map(|(k, v)| format!("{k}: {v}"))
                .collect();
            write!(f, " ({})", parts.join("; "))?;
        }
        Ok(())
    }
}

/// Every error the SDK can return.
///
/// API failures are split into kinds by status and code; each kind wraps the
/// same [`ApiError`] details, which [`Error::api_error`] returns regardless of
/// the kind.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// 401: the API key is missing, invalid, revoked or expired.
    #[error("authentication failed: {0}")]
    Authentication(ApiError),
    /// 403: the key lacks the scope or the action isn't allowed.
    #[error("permission denied: {0}")]
    Permission(ApiError),
    /// 404: the resource doesn't exist (or isn't visible to this key).
    #[error("not found: {0}")]
    NotFound(ApiError),
    /// 400 / 422: the request was invalid; see `fields`.
    #[error("invalid request: {0}")]
    Validation(ApiError),
    /// 402 or code `out_of_prints`: the organization has no prints left.
    #[error("out of prints: {0}")]
    OutOfPrints(ApiError),
    /// 409: a conflicting state (e.g. cancelling a printed job).
    #[error("conflict: {0}")]
    Conflict(ApiError),
    /// 429: too many requests; see `retry_after`.
    #[error("rate limited: {0}")]
    RateLimit(ApiError),
    /// 5xx: the API failed.
    #[error("server error: {0}")]
    Server(ApiError),
    /// Any other API error status (e.g. 410 `content_deleted`, 413).
    #[error("API error: {0}")]
    Api(ApiError),
    /// The request never got an answer: network failure or timeout.
    #[error("connection error: {message}")]
    Connection {
        /// What went wrong.
        message: String,
        /// Whether the request timed out.
        timeout: bool,
    },
    /// [`crate::Jobs::wait_for`] gave up before the job finished.
    #[error("timed out waiting for job {job_id} (last status: {last_status})")]
    WaitTimeout {
        /// The job that was being waited for.
        job_id: String,
        /// The status the job had at the last poll.
        last_status: String,
    },
    /// A webhook signature didn't verify.
    #[error("webhook signature verification failed: {0}")]
    SignatureVerification(String),
    /// Content couldn't be sealed (bad server key, or the `sealed` feature is off).
    #[error("sealing failed: {0}")]
    Sealing(String),
    /// The client is misconfigured (no API key, bad base URL…).
    #[error("configuration error: {0}")]
    Config(String),
    /// The API answered with a body the SDK couldn't understand.
    #[error("couldn't decode the API response: {0}")]
    Decode(String),
    /// Reading a local file failed.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

impl Error {
    /// The API error details, when this error came from the API.
    pub fn api_error(&self) -> Option<&ApiError> {
        match self {
            Error::Authentication(e)
            | Error::Permission(e)
            | Error::NotFound(e)
            | Error::Validation(e)
            | Error::OutOfPrints(e)
            | Error::Conflict(e)
            | Error::RateLimit(e)
            | Error::Server(e)
            | Error::Api(e) => Some(e),
            _ => None,
        }
    }

    /// The HTTP status, when this error came from the API.
    pub fn status(&self) -> Option<u16> {
        self.api_error().map(|e| e.status)
    }

    /// The API error code (e.g. `"invalid"`), when this error came from the API.
    pub fn code(&self) -> Option<&str> {
        self.api_error().map(|e| e.code.as_str())
    }

    /// Per-field validation messages (empty when there are none).
    pub fn fields(&self) -> Option<&BTreeMap<String, String>> {
        self.api_error().map(|e| &e.fields)
    }

    /// How long the API asked to wait before retrying, if it did.
    pub fn retry_after(&self) -> Option<Duration> {
        self.api_error().and_then(|e| e.retry_after)
    }

    /// Builds the right error kind from an API status and error body.
    pub(crate) fn from_api(e: ApiError) -> Error {
        if e.code == "out_of_prints" || e.status == 402 {
            return Error::OutOfPrints(e);
        }
        match e.status {
            400 | 422 => Error::Validation(e),
            401 => Error::Authentication(e),
            403 => Error::Permission(e),
            404 => Error::NotFound(e),
            409 => Error::Conflict(e),
            429 => Error::RateLimit(e),
            500..=599 => Error::Server(e),
            _ => Error::Api(e),
        }
    }
}

#[derive(Deserialize)]
struct ErrorEnvelope {
    error: ErrorBody,
}

#[derive(Deserialize)]
struct ErrorBody {
    #[serde(default)]
    code: String,
    #[serde(default)]
    message: String,
    #[serde(default)]
    fields: BTreeMap<String, String>,
    #[serde(default)]
    retry_after_seconds: Option<u64>,
}

/// Maps an HTTP error answer (`{"error":{"code","message","fields","retry_after_seconds"}}`)
/// to an [`Error`]. `retry_after_header` is the parsed `Retry-After` header.
pub(crate) fn map_error(status: u16, retry_after_header: Option<Duration>, body: &[u8]) -> Error {
    let parsed: Option<ErrorBody> = serde_json::from_slice::<ErrorEnvelope>(body)
        .ok()
        .map(|e| e.error);
    let (code, message, fields, body_retry) = match parsed {
        Some(b) => (
            b.code,
            b.message,
            b.fields,
            b.retry_after_seconds.map(Duration::from_secs),
        ),
        None => {
            let text = String::from_utf8_lossy(body)
                .trim()
                .chars()
                .take(300)
                .collect::<String>();
            (String::new(), text, BTreeMap::new(), None)
        }
    };
    let code = if code.is_empty() {
        default_code(status).to_string()
    } else {
        code
    };
    let message = if message.is_empty() {
        format!("The API answered HTTP {status}.")
    } else {
        message
    };
    Error::from_api(ApiError {
        status,
        code,
        message,
        fields,
        retry_after: body_retry.or(retry_after_header),
    })
}

fn default_code(status: u16) -> &'static str {
    match status {
        400 | 422 => "invalid",
        401 => "unauthenticated",
        402 => "out_of_prints",
        403 => "forbidden",
        404 => "not_found",
        409 => "conflict",
        429 => "rate_limited",
        500..=599 => "server_error",
        _ => "error",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_statuses_to_kinds() {
        let body = br#"{"error":{"code":"invalid","message":"Unknown printer.","fields":{"printer_id":"Unknown printer."}}}"#;
        let e = map_error(400, None, body);
        assert!(matches!(e, Error::Validation(_)));
        assert_eq!(e.fields().unwrap()["printer_id"], "Unknown printer.");
        assert!(matches!(
            map_error(401, None, b"{}"),
            Error::Authentication(_)
        ));
        assert!(matches!(map_error(403, None, b""), Error::Permission(_)));
        assert!(matches!(map_error(404, None, b""), Error::NotFound(_)));
        assert!(matches!(map_error(409, None, b""), Error::Conflict(_)));
        assert!(matches!(map_error(422, None, b""), Error::Validation(_)));
        assert!(matches!(map_error(402, None, b""), Error::OutOfPrints(_)));
        assert!(matches!(map_error(503, None, b"oops"), Error::Server(_)));
        assert!(matches!(map_error(410, None, b""), Error::Api(_)));
        let oop = map_error(
            403,
            None,
            br#"{"error":{"code":"out_of_prints","message":"No prints left."}}"#,
        );
        assert!(matches!(oop, Error::OutOfPrints(_)));
    }

    #[test]
    fn reads_retry_after() {
        let e = map_error(
            429,
            Some(Duration::from_secs(9)),
            br#"{"error":{"code":"rate_limited","message":"Slow down.","retry_after_seconds":3}}"#,
        );
        assert!(matches!(e, Error::RateLimit(_)));
        assert_eq!(e.retry_after(), Some(Duration::from_secs(3)));
        let e = map_error(429, Some(Duration::from_secs(9)), b"{}");
        assert_eq!(e.retry_after(), Some(Duration::from_secs(9)));
        assert_eq!(e.code(), Some("rate_limited"));
    }
}
