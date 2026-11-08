//! Audit round 7 (SDK addendum 5): the re-seal after a `sealed_content` 400
//! (S1, the amb400/seal400 matrix scenarios), POST 409 in_progress then a
//! probe 404 (S4, the ip404 scenario), cloud_first non-local jobs through the
//! cloud-mode create (S5) and the shared placeholder set / redirect code (S6).
#![cfg(feature = "local")]

mod local_support;

use std::time::Duration;

use catzprint::{
    Client, CreateJob, Error, LocalConfig, LocalMode, MemoryTokenStore, StoredToken, TokenStore,
    Via,
};
use local_support::*;

const MODES: [LocalMode; 3] = [
    LocalMode::Cloud,
    LocalMode::LocalFirst,
    LocalMode::CloudFirst,
];

/// A client with the client's retries on (2) and a short timeout, so a slow
/// answer is a lost one (sent, no answer).
fn client(cloud: &Cloud, st: &Station, mode: LocalMode) -> Client {
    let (url, fp) = (st.url.clone(), st.fp.clone());
    let cfg = LocalConfig::default()
        .mode(mode)
        .station_url(&url)
        .fingerprint(&url, &fp)
        .connect_timeout(Duration::from_secs(1))
        .request_timeout(Duration::from_secs(2))
        .cloud_timeout(Duration::from_secs(2))
        .device_name("Hub")
        .all_locations(true);
    Client::builder()
        .api_key(API_KEY)
        .base_url(&cloud.url)
        .org_id("org1")
        .timeout(Duration::from_millis(300))
        .max_retries(2)
        .retry_base_delay(Duration::from_millis(1))
        .local(cfg)
        .build()
        .unwrap()
}

fn script(cloud: &Cloud, steps: &[(u16, &str, u64)]) {
    cloud.set(|s| {
        s.job_script = steps
            .iter()
            .map(|(st, code, ms)| (*st, code.to_string(), Duration::from_millis(*ms)))
            .collect()
    });
}

const LOST: (u16, &str, u64) = (0, "", 800); // answered after the client gave up
const SEAL400: (u16, &str, u64) = (400, "seal400", 0);
const OK: (u16, &str, u64) = (0, "", 0);

fn posts(cloud: &Cloud) -> Vec<serde_json::Value> {
    cloud.state.lock().unwrap().jobs.clone()
}

fn key_fetches(cloud: &Cloud) -> usize {
    cloud.state.lock().unwrap().key_fetches
}

// ---- S1 ----

/// amb400: the answer was lost, then a sealed_content 400: the SDK re-seals
/// with a fresh key and re-sends with the same idempotency key. Before:
/// `Error::Validation` (the caller would print again with a new key).
#[tokio::test]
async fn amb400_reseals_and_resends() {
    for mode in MODES {
        let cloud = Cloud::start().await;
        let st = Station::start().await;
        script(&cloud, &[LOST, SEAL400, OK]);
        let job = client(&cloud, &st, mode)
            .jobs()
            .create(
                CreateJob::text("card")
                    .sealed(true)
                    .idempotency_key("amb-1"),
            )
            .await
            .unwrap_or_else(|e| panic!("{mode:?}: {e:?}"));
        assert_eq!(job.via, Some(Via::Cloud));
        let p = posts(&cloud);
        assert_eq!(p.len(), 3, "{mode:?}");
        assert_eq!(p[0]["sealed_content"], p[1]["sealed_content"]);
        assert_ne!(p[1]["sealed_content"], p[2]["sealed_content"], "re-sealed");
        assert_eq!(p[2]["idempotency_key"], "amb-1");
        assert_eq!(key_fetches(&cloud), 2);
        assert!(st.requests().is_empty());
    }
}

/// After an ambiguous attempt, a re-sealed re-send rejected again or lost is
/// OutcomeUnknown: never a validation error, never local.
#[tokio::test]
async fn amb400_repeat_is_outcome_unknown() {
    for mode in MODES {
        for tail in [&[SEAL400, SEAL400][..], &[LOST, LOST, LOST][..]] {
            let cloud = Cloud::start().await;
            let st = Station::start().await;
            let mut steps = vec![LOST, SEAL400];
            steps.extend_from_slice(tail);
            script(&cloud, &steps);
            let err = client(&cloud, &st, mode)
                .jobs()
                .create(
                    CreateJob::text("card")
                        .sealed(true)
                        .idempotency_key("amb-2"),
                )
                .await
                .unwrap_err();
            assert!(err.is_outcome_unknown(), "{mode:?}: {err:?}");
            assert!(st.requests().is_empty());
        }
    }
}

/// seal400 without an earlier ambiguous attempt: re-sealed once; a repeat is
/// the validation error.
#[tokio::test]
async fn seal400_reseals_once() {
    for mode in MODES {
        let cloud = Cloud::start().await;
        let st = Station::start().await;
        script(&cloud, &[SEAL400, OK]);
        let job = client(&cloud, &st, mode)
            .jobs()
            .create(CreateJob::text("card").sealed(true))
            .await
            .unwrap();
        assert_eq!(job.via, Some(Via::Cloud));
        assert_eq!(key_fetches(&cloud), 2);

        let cloud = Cloud::start().await;
        script(&cloud, &[SEAL400, SEAL400, SEAL400]);
        let err = client(&cloud, &st, mode)
            .jobs()
            .create(CreateJob::text("card").sealed(true))
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Validation(_)), "{mode:?}: {err:?}");
        assert_eq!(posts(&cloud).len(), 2);
    }
    // An unsealed job's 400 is never re-sent.
    let cloud = Cloud::start().await;
    let st = Station::start().await;
    script(&cloud, &[SEAL400, SEAL400]);
    let err = client(&cloud, &st, LocalMode::Cloud)
        .jobs()
        .create(CreateJob::bytes(b"%PDF-1.4 x".to_vec()))
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Validation(_)));
    assert_eq!(posts(&cloud).len(), 1);
}

/// A sealed_content 400 to a re-send after a 409 "duplicate" is
/// OutcomeUnknown (a job with this key exists or is being created).
#[tokio::test]
async fn sealed_400_after_409_is_unknown() {
    let cloud = Cloud::start().await;
    let st = Station::start().await;
    script(&cloud, &[(409, "duplicate", 0), SEAL400, SEAL400]);
    let err = client(&cloud, &st, LocalMode::Cloud)
        .jobs()
        .create(CreateJob::text("x").sealed(true))
        .await
        .unwrap_err();
    assert!(err.is_outcome_unknown(), "{err:?}");
}

// ---- S4 ----

/// ip404: the station answered the POST 409 in_progress (without recording
/// it), then the probe says 404 not_found. That isn't "never recorded":
/// OutcomeUnknown, no next station, no cloud. Before: the cloud got it too.
#[tokio::test]
async fn in_progress_then_404_is_unknown() {
    for mode in [
        LocalMode::Local,
        LocalMode::LocalFirst,
        LocalMode::CloudFirst,
    ] {
        let cloud = Cloud::start().await;
        if mode == LocalMode::CloudFirst {
            cloud.set(|s| s.job_error = Some((503, "unavailable".into())));
        }
        let (a, b) = (Station::start().await, Station::start().await);
        a.set(|s| {
            s.post_in_progress = true;
            s.forget_jobs = true;
        });
        let (au, af, bu, bf) = (a.url.clone(), a.fp.clone(), b.url.clone(), b.fp.clone());
        let c = local_client(&cloud, move |c| {
            c.mode(mode)
                .station_url(&au)
                .station_url(&bu)
                .fingerprint(&au, &af)
                .fingerprint(&bu, &bf)
        });
        let err = c
            .jobs()
            .create(CreateJob::text("x").idempotency_key("ip404"))
            .await
            .unwrap_err();
        assert!(err.is_outcome_unknown(), "{mode:?}: {err:?}");
        assert!(
            b.requests().is_empty(),
            "{mode:?}: sent to the next station"
        );
        if mode == LocalMode::LocalFirst {
            assert_eq!(cloud.counts().1, 0, "fell back to the cloud");
        }
    }
}

// ---- S5 ----

/// cloud_first: a PDF / scheduled job uses the cloud-mode create (client
/// retries, the 409 loop). Before: one attempt, and a 503 ended it.
#[tokio::test]
async fn cloud_first_non_local_uses_cloud_mode() {
    let when = chrono::DateTime::parse_from_rfc3339("2030-01-01T00:00:00Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    for job in [
        CreateJob::bytes(b"%PDF-1.4 x".to_vec()),
        CreateJob::text("x").scheduled_for(when),
    ] {
        let cloud = Cloud::start().await;
        let st = Station::start().await;
        script(
            &cloud,
            &[(503, "unavailable", 0), (409, "duplicate", 0), OK],
        );
        let j = client(&cloud, &st, LocalMode::CloudFirst)
            .jobs()
            .create(job)
            .await
            .unwrap();
        assert_eq!(j.via, Some(Via::Cloud));
        assert_eq!(posts(&cloud).len(), 3);
        assert!(st.requests().is_empty());
    }
}

// ---- S6 ----

/// Every placeholder in the shared set is "no token": a fresh one is minted.
#[tokio::test]
async fn placeholder_set_is_no_token() {
    for p in [
        "…",
        "***",
        "czl1.…",
        "czl1.***",
        "[redacted]",
        "REDACTED",
        "hidden",
        "czd_[redacted]",
        "czd_hidden",
    ] {
        let cloud = Cloud::start().await;
        let st = Station::start().await;
        let store = std::sync::Arc::new(MemoryTokenStore::new());
        let (url, fp) = (st.url.clone(), st.fp.clone());
        let s2 = store.clone();
        let c = local_client(&cloud, move |c| {
            c.mode(LocalMode::Local)
                .station_url(&url)
                .fingerprint(&url, &fp)
                .token_store(s2)
        });
        let key = c.local().__store_key();
        let t = StoredToken {
            token: p.to_string(),
            expires_at: Some(chrono::Utc::now() + chrono::Duration::days(10)),
            ..Default::default()
        };
        store.save(&key, &t).await.unwrap();
        c.jobs().create(CreateJob::text("x")).await.unwrap();
        let auth = st.job_requests()[0].auth.clone();
        assert!(!auth.ends_with(p), "{p}: placeholder sent");
        assert_eq!(cloud.counts().0, 1, "{p}: no fresh token minted");
    }
}

/// A cloud 3xx has the code unexpected_redirect.
#[tokio::test]
async fn redirect_code() {
    let cloud = Cloud::start().await;
    let st = Station::start().await;
    script(&cloud, &[(302, "", 0)]);
    let err = client(&cloud, &st, LocalMode::Cloud)
        .jobs()
        .create(CreateJob::text("x"))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Some("unexpected_redirect"), "{err:?}");
}

// ---- addendum 6, T2 ----

/// dip404: the POST reached the station but wasn't recorded and got no
/// answer; the first probe says in_progress, the next 404. That isn't "never
/// recorded": OutcomeUnknown, no next station, no cloud.
#[tokio::test]
async fn probe_in_progress_then_404_is_unknown() {
    for mode in [LocalMode::Local, LocalMode::LocalFirst] {
        let cloud = Cloud::start().await;
        let (a, b) = (Station::start().await, Station::start().await);
        a.set(|s| {
            s.forget_jobs = true;
            s.post_delay = Duration::from_secs(2);
            s.find_in_progress = 1;
        });
        let (au, af, bu, bf) = (a.url.clone(), a.fp.clone(), b.url.clone(), b.fp.clone());
        let c = local_client(&cloud, move |c| {
            c.mode(mode)
                .station_url(&au)
                .station_url(&bu)
                .fingerprint(&au, &af)
                .fingerprint(&bu, &bf)
                .request_timeout(Duration::from_millis(300))
        });
        let err = c
            .jobs()
            .create(CreateJob::text("x").idempotency_key("dip404"))
            .await
            .unwrap_err();
        assert!(err.is_outcome_unknown(), "{mode:?}: {err:?}");
        assert!(a.find_requests().len() >= 2, "{mode:?}");
        assert!(
            b.requests().is_empty(),
            "{mode:?}: sent to the next station"
        );
        assert_eq!(cloud.counts().1, 0, "{mode:?}: fell back to the cloud");
    }
}
