//! Audit round 6 (SDK addendum 4): 409 in_progress (Q1), tokens kept in
//! JSON (Q2), one body per create (Q3), probing on any other 4xx (Q7b).
#![cfg(feature = "local")]

mod local_support;

use std::time::{Duration, Instant};

use catzprint::{
    CreateJob, LocalConfig, LocalMode, LocalPairing, LocalToken, MemoryTokenStore, StoredToken,
    TokenStore, Via,
};
use local_support::*;

fn pinned(st: &Station, mode: LocalMode) -> impl FnOnce(LocalConfig) -> LocalConfig {
    let (url, fp) = (st.url.clone(), st.fp.clone());
    move |c| c.mode(mode).station_url(&url).fingerprint(&url, &fp)
}

fn fast(c: LocalConfig) -> LocalConfig {
    c.request_timeout(Duration::from_millis(300))
}

// ---- Q1: 409 in_progress ----

#[tokio::test]
async fn probe_in_progress_keeps_asking() {
    let cloud = Cloud::start().await;
    let st = Station::start().await;
    st.set(|s| {
        s.post_delay = Duration::from_secs(3);
        s.find_in_progress = 2;
    });
    let c = local_client(&cloud, |c| fast(pinned(&st, LocalMode::LocalFirst)(c)));
    let job = c
        .jobs()
        .create(CreateJob::text("x").idempotency_key("ip-1"))
        .await
        .unwrap();
    assert_eq!(job.via, Some(Via::Local));
    assert_eq!(st.find_requests().len(), 3, "two in_progress, then the job");
    assert_eq!(cloud.counts().1, 0);
}

#[tokio::test]
async fn post_in_progress_is_asked_by_key_and_never_falls_back() {
    let cloud = Cloud::start().await;
    let st = Station::start().await;
    st.set(|s| s.post_in_progress = true);
    let c = local_client(&cloud, pinned(&st, LocalMode::LocalFirst));
    let job = c
        .jobs()
        .create(CreateJob::text("x").idempotency_key("ip-2"))
        .await
        .unwrap();
    assert_eq!(job.via, Some(Via::Local));
    assert_eq!(job.idempotency_key.as_deref(), Some("ip-2"));
    assert_eq!(st.find_requests().len(), 1);

    // Still in progress for the whole budget: unknown, no fallback.
    st.set(|s| s.find_in_progress = 1000);
    let start = Instant::now();
    let e = c
        .jobs()
        .create(CreateJob::text("x").idempotency_key("ip-3"))
        .await
        .unwrap_err();
    assert!(e.is_outcome_unknown(), "{e:?}");
    assert!(start.elapsed() < Duration::from_secs(6));
    assert_eq!(cloud.counts().1, 0, "never the cloud");
}

// ---- Q7(b): any other 4xx is asked again (up to 3 times) ----

#[tokio::test]
async fn probe_keeps_asking_after_other_4xx() {
    for (status, code) in [(400, "invalid"), (401, "unauthenticated"), (404, "")] {
        let cloud = Cloud::start().await;
        let st = Station::start().await;
        let code2 = code.to_string();
        st.set(move |s| {
            s.post_delay = Duration::from_secs(3);
            s.fail = Some(Box::new(move |r: &Req| {
                (r.method == "GET" && r.path == "/local/v1/jobs").then(|| (status, code2.clone()))
            }));
        });
        let c = local_client(&cloud, |c| fast(pinned(&st, LocalMode::LocalFirst)(c)));
        let e = c.jobs().create(CreateJob::text("x")).await.unwrap_err();
        assert!(e.is_outcome_unknown(), "{status}: {e:?}");
        assert_eq!(st.find_requests().len(), 3, "{status}: three probes");
        assert_eq!(cloud.counts().1, 0);
    }
}

// ---- Q3: one body per create ----

#[cfg(feature = "sealed")]
#[tokio::test]
async fn sealed_body_is_built_once_and_resent_identically() {
    // cloud_first: a retried 503, then a 409 re-send, then the job (a sealed
    // job in cloud_first uses the cloud-mode create: S5, addendum 5).
    let cloud = Cloud::start().await;
    cloud.set(|s| {
        s.job_script
            .push_back((503, "unavailable".into(), Duration::ZERO));
        s.job_script
            .push_back((409, "duplicate".into(), Duration::ZERO));
    });
    let st = Station::start().await;
    let c = local_client(&cloud, pinned(&st, LocalMode::CloudFirst));
    let job = c
        .jobs()
        .create(CreateJob::text("payslip").sealed(true))
        .await
        .unwrap();
    assert_eq!(job.via, Some(Via::Cloud));
    let jobs = cloud.state.lock().unwrap().jobs.clone();
    assert_eq!(jobs.len(), 3);
    assert!(jobs[0]["sealed_content"]
        .as_str()
        .is_some_and(|s| !s.is_empty()));
    assert_eq!(jobs[0], jobs[1], "the retry re-sealed");
    assert_eq!(jobs[1], jobs[2], "the 409 re-send re-sealed");

    // Cloud mode's 409 re-send too.
    let cloud = Cloud::start().await;
    cloud.set(|s| {
        s.job_script
            .push_back((409, "duplicate".into(), Duration::ZERO))
    });
    let c = local_client(&cloud, |c| c);
    c.jobs()
        .create(CreateJob::text("payslip").sealed(true))
        .await
        .unwrap();
    let jobs = cloud.state.lock().unwrap().jobs.clone();
    assert_eq!(jobs.len(), 2);
    assert_eq!(jobs[0], jobs[1]);
}

// ---- Q2: tokens are serialized; only Debug redacts ----

#[tokio::test]
async fn tokens_serialize_with_the_token() {
    let st = StoredToken {
        token: "czl1.PAYLOAD.SIG".into(),
        token_id: "jti-1".into(),
        ..Default::default()
    };
    let v = serde_json::to_value(&st).unwrap();
    assert_eq!(v["token"], "czl1.PAYLOAD.SIG");
    let back: StoredToken = serde_json::from_value(v).unwrap();
    assert_eq!(back, st);
    let lt = LocalToken {
        token: "czl1.PAYLOAD.SIG".into(),
        ..Default::default()
    };
    assert_eq!(
        serde_json::to_value(&lt).unwrap()["token"],
        "czl1.PAYLOAD.SIG"
    );
    let lp = LocalPairing {
        token: "czd_DEVICE".into(),
        ..Default::default()
    };
    assert_eq!(serde_json::to_value(&lp).unwrap()["token"], "czd_DEVICE");
    assert!(!format!("{st:?}{lt:?}{lp:?}").contains("PAYLOAD"));
    assert!(!format!("{lp:?}").contains("DEVICE"));

    // A FileTokenStore keeps the real token.
    let dir = std::env::temp_dir().join(format!("catzprint-a6-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let fs = catzprint::FileTokenStore::new(dir.join("t.json"));
    fs.save("k", &st).await.unwrap();
    assert!(std::fs::read_to_string(dir.join("t.json"))
        .unwrap()
        .contains("czl1.PAYLOAD.SIG"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn a_redacted_stored_token_is_no_token() {
    let cloud = Cloud::start().await;
    let station = Station::start().await;
    let store = std::sync::Arc::new(MemoryTokenStore::new());
    let c = local_client(&cloud, |c| {
        pinned(&station, LocalMode::Local)(c.token_store(store.clone()))
    });
    let key = c.local().__store_key();
    store
        .save(
            &key,
            &StoredToken {
                token: "****".into(),
                expires_at: Some(chrono::Utc::now() + chrono::Duration::days(20)),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    c.jobs().create(CreateJob::text("x")).await.unwrap();
    assert_ne!(station.job_requests()[0].auth, "Bearer ****");
    assert_eq!(cloud.counts().0, 1, "a real token was minted");
    let err = c.local().store_error().expect("reported");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
}
