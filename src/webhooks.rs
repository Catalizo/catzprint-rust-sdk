//! Webhook signature verification.
//!
//! Every delivery carries a `CatzPrint-Signature` header of the form
//! `t=<unix seconds>,v1=<hex HMAC-SHA256(secret, t + "." + body)>`. During a
//! secret rotation there may be several `v1=` entries; any match is accepted.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::error::{Error, Result};
use crate::models::WebhookEvent;

/// The header CatzPrint signs deliveries with.
pub const SIGNATURE_HEADER: &str = "CatzPrint-Signature";

/// The header carrying the delivery ID.
pub const DELIVERY_HEADER: &str = "CatzPrint-Delivery";

/// The default tolerance between the signature time and now (5 minutes).
pub const DEFAULT_TOLERANCE: Duration = Duration::from_secs(300);

/// Verifies a delivery and returns the parsed event.
///
/// `payload` must be the raw request body, byte for byte; `signature_header`
/// is the `CatzPrint-Signature` header value; `secret` is the endpoint's
/// signing secret (`whsec_…`). Signatures older (or newer) than `tolerance`
/// are rejected. That limits the replay window but does not close it: a
/// captured delivery can be replayed within the tolerance, so deduplicate on
/// [`WebhookEvent::id`](crate::WebhookEvent::id).
///
/// ```
/// # use catzprint::webhooks;
/// # let (body, header, secret) = (b"{}".as_slice(), "t=1,v1=00", "whsec_x");
/// match webhooks::verify(body, header, secret, webhooks::DEFAULT_TOLERANCE) {
///     Ok(event) => println!("got {}", event.event_type),
///     Err(e) => eprintln!("rejected: {e}"),
/// }
/// ```
pub fn verify(
    payload: impl AsRef<[u8]>,
    signature_header: &str,
    secret: &str,
    tolerance: Duration,
) -> Result<WebhookEvent> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    verify_at(payload, signature_header, secret, tolerance, now)
}

/// Like Stripe's `constructEvent`: [`verify`] with the default 5-minute tolerance.
pub fn construct_event(
    payload: impl AsRef<[u8]>,
    signature_header: &str,
    secret: &str,
) -> Result<WebhookEvent> {
    verify(payload, signature_header, secret, DEFAULT_TOLERANCE)
}

/// [`verify`] against an explicit current time (unix seconds), for tests.
pub fn verify_at(
    payload: impl AsRef<[u8]>,
    signature_header: &str,
    secret: &str,
    tolerance: Duration,
    now_unix: i64,
) -> Result<WebhookEvent> {
    let payload = payload.as_ref();
    let fail = |m: &str| Error::SignatureVerification(m.to_string());
    if secret.is_empty() {
        return Err(fail("the webhook secret is empty"));
    }
    let mut timestamp: Option<i64> = None;
    let mut signatures: Vec<Vec<u8>> = Vec::new();
    for part in signature_header.split(',') {
        let Some((k, v)) = part.trim().split_once('=') else {
            continue;
        };
        match k.trim() {
            "t" => timestamp = v.trim().parse().ok(),
            "v1" => {
                if let Ok(sig) = hex::decode(v.trim()) {
                    signatures.push(sig);
                }
            }
            _ => {}
        }
    }
    let t = timestamp.ok_or_else(|| fail("the signature header has no valid timestamp"))?;
    if signatures.is_empty() {
        return Err(fail("the signature header has no v1 signature"));
    }
    let age = now_unix.abs_diff(t);
    if tolerance > Duration::ZERO && age > tolerance.as_secs() {
        return Err(fail("the signature timestamp is outside the tolerance"));
    }
    let expected = sign_raw(secret, t, payload);
    let mut ok = subtle::Choice::from(0u8);
    for sig in &signatures {
        if sig.len() == expected.len() {
            ok |= sig.as_slice().ct_eq(expected.as_slice());
        }
    }
    if !bool::from(ok) {
        return Err(fail("no signature matches the payload"));
    }
    serde_json::from_slice(payload).map_err(|e| Error::Decode(format!("webhook payload: {e}")))
}

/// Computes a `CatzPrint-Signature` header value, exactly as the server does.
/// Handy for testing your own endpoint.
pub fn sign(secret: &str, timestamp_unix: i64, payload: impl AsRef<[u8]>) -> String {
    format!(
        "t={timestamp_unix},v1={}",
        hex::encode(sign_raw(secret, timestamp_unix, payload.as_ref()))
    )
}

fn sign_raw(secret: &str, t: i64, payload: &[u8]) -> Vec<u8> {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC takes any key length");
    mac.update(t.to_string().as_bytes());
    mac.update(b".");
    mac.update(payload);
    mac.finalize().into_bytes().to_vec()
}
