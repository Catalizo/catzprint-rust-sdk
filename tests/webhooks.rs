//! Webhook verification against vectors produced by the server's Go
//! `SignWebhook` (server/internal/core/webhooks.go), run with `go run`.

use std::time::Duration;

use catzprint::{webhooks, Error};

const BODY: &str = r#"{"type":"job.printed","created_at":"2026-10-16T08:00:00Z","org_id":"34c4671b-d2ab-4ddf-aaac-615786d5acac","data":{"job":{"id":"0b5f3c3e-8a51-4d55-9b0e-4b8f7a0c1d2e","status":"printed","live":true,"copies":1}}}"#;
const SECRET: &str = "whsec_test_secret_123";
const T: i64 = 1792137600;
// Go: SignWebhook("whsec_test_secret_123", time.Unix(1792137600, 0), BODY)
const HEADER: &str =
    "t=1792137600,v1=d1fbd346b9fa57241f7bd4d6802fc9ee09022488f7992b386b50dd36a982113f";
// Go: SignWebhook("whsec_old_secret", time.Unix(1792137600, 0), BODY)
const OLD_SIG: &str = "df39f95d900f100f0d0a5552a19eeecde2cc1f17c578c95bcbabdfb65bf06342";

const TOL: Duration = Duration::from_secs(300);

#[test]
fn valid_signature() {
    let ev = webhooks::verify_at(BODY, HEADER, SECRET, TOL, T + 10).unwrap();
    assert_eq!(ev.event_type, "job.printed");
    assert_eq!(ev.org_id, "34c4671b-d2ab-4ddf-aaac-615786d5acac");
    let job = ev.job().unwrap();
    assert_eq!(job.id, "0b5f3c3e-8a51-4d55-9b0e-4b8f7a0c1d2e");
    assert_eq!(job.status, catzprint::JobStatus::Printed);
}

#[test]
fn sdk_signer_matches_go() {
    assert_eq!(webhooks::sign(SECRET, T, BODY), HEADER);
}

#[test]
fn tampered_payload() {
    let tampered = BODY.replace("printed\",\"live", "failed\",\"live");
    let err = webhooks::verify_at(tampered, HEADER, SECRET, TOL, T).unwrap_err();
    assert!(matches!(err, Error::SignatureVerification(_)));
}

#[test]
fn expired_and_future_timestamps() {
    let err = webhooks::verify_at(BODY, HEADER, SECRET, TOL, T + 301).unwrap_err();
    assert!(matches!(err, Error::SignatureVerification(_)));
    let err = webhooks::verify_at(BODY, HEADER, SECRET, TOL, T - 301).unwrap_err();
    assert!(matches!(err, Error::SignatureVerification(_)));
    // The real clock is far from T, so plain verify rejects it as well.
    assert!(webhooks::construct_event(BODY, HEADER, SECRET).is_err());
}

#[test]
fn wrong_secret() {
    let err = webhooks::verify_at(BODY, HEADER, "whsec_wrong", TOL, T).unwrap_err();
    assert!(matches!(err, Error::SignatureVerification(_)));
}

#[test]
fn multiple_v1_entries() {
    // Rotation: one stale signature and one current one.
    let header = format!(
        "t={T},v1={OLD_SIG},v1={}",
        HEADER.split("v1=").nth(1).unwrap()
    );
    assert!(webhooks::verify_at(BODY, &header, SECRET, TOL, T).is_ok());
    // Only the old secret's signature: rejected for the new secret, accepted for the old.
    let header = format!("t={T},v1={OLD_SIG}");
    assert!(webhooks::verify_at(BODY, &header, SECRET, TOL, T).is_err());
    assert!(webhooks::verify_at(BODY, &header, "whsec_old_secret", TOL, T).is_ok());
}

#[test]
fn malformed_headers() {
    for h in [
        "",
        "v1=abcd",
        "t=abc,v1=00",
        &format!("t={T}"),
        &format!("t={T},v1=nothex"),
    ] {
        assert!(
            webhooks::verify_at(BODY, h, SECRET, TOL, T).is_err(),
            "{h:?}"
        );
    }
    assert!(webhooks::verify_at(BODY, HEADER, "", TOL, T).is_err());
}

#[test]
fn fresh_signature_with_real_clock() {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let header = webhooks::sign(SECRET, now, BODY);
    assert!(webhooks::construct_event(BODY.as_bytes(), &header, SECRET).is_ok());
}

#[test]
fn event_id_for_deduplication() {
    let body = r#"{"id":"dlv_01HZX","type":"ping","created_at":"2026-10-17T00:00:00Z","org_id":"o","data":{}}"#;
    let header = webhooks::sign(SECRET, T, body);
    let ev = webhooks::verify_at(body, &header, SECRET, Duration::from_secs(300), T).unwrap();
    assert_eq!(ev.id.as_deref(), Some("dlv_01HZX"));
    let ev = webhooks::verify_at(BODY, HEADER, SECRET, Duration::from_secs(300), T).unwrap();
    assert_eq!(ev.id, None);
}
