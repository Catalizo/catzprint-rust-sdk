//! Audit round 5 (SDK addendum 3): probe answers (R3), cloud `409 duplicate`
//! re-sends (R4), the cloud's 4xx returned as is in local_first (C1), every
//! 5xx but 502/503/504 is ambiguous (C2), and a 2xx without a job is
//! "delivered, no answer" (C5).
#![cfg(feature = "local")]

mod local_support;

use std::time::{Duration, Instant};

use catzprint::{CreateJob, Error, LocalConfig, LocalMode, Via};
use local_support::*;

fn pinned(st: &Station, mode: LocalMode) -> impl FnOnce(LocalConfig) -> LocalConfig {
    let (url, fp) = (st.url.clone(), st.fp.clone());
    move |c| c.mode(mode).station_url(&url).fingerprint(&url, &fp)
}

fn pinned2(a: &Station, b: &Station, mode: LocalMode) -> impl FnOnce(LocalConfig) -> LocalConfig {
    let (ua, fa, ub, fb) = (a.url.clone(), a.fp.clone(), b.url.clone(), b.fp.clone());
    move |c| {
        c.mode(mode)
            .station_url(&ua)
            .fingerprint(&ua, &fa)
            .station_url(&ub)
            .fingerprint(&ub, &fb)
    }
}

fn fast(c: LocalConfig) -> LocalConfig {
    c.request_timeout(Duration::from_millis(300))
}

fn script(cloud: &Cloud, steps: &[(u16, &str)]) {
    cloud.set(|s| {
        for (status, code) in steps {
            s.job_script
                .push_back((*status, code.to_string(), Duration::ZERO));
        }
    });
}

// ---- R3: what the probe answers ----

#[tokio::test]
async fn probe_409_duplicate_is_the_answer() {
    let cloud = Cloud::start().await;
    let a = Station::start().await;
    let b = Station::start().await;
    // A takes the request without answering; the key belongs to a job this
    // caller can't see.
    a.set(|s| {
        s.post_delay = Duration::from_secs(3);
        s.forget_jobs = true;
        s.foreign_keys = vec!["order-20".into()];
    });
    let c = local_client(&cloud, |c| fast(pinned2(&a, &b, LocalMode::LocalFirst)(c)));
    let e = c
        .jobs()
        .create(CreateJob::text("x").idempotency_key("order-20"))
        .await
        .unwrap_err();
    assert!(matches!(e, Error::Conflict(_)), "{e:?}");
    assert_eq!(e.code(), Some("duplicate"));
    assert!(b.requests().is_empty(), "no next station");
    assert_eq!(cloud.counts().1, 0, "no cloud");
}

#[tokio::test]
async fn probe_404_without_not_found_proves_nothing() {
    let cloud = Cloud::start().await;
    let a = Station::start().await;
    let b = Station::start().await;
    // A bare 404 (a proxy, an older station without the route).
    a.set(|s| {
        s.post_delay = Duration::from_secs(3);
        s.fail = Some(Box::new(|r: &Req| {
            (r.method == "GET" && r.path == "/local/v1/jobs").then(|| (404, String::new()))
        }));
    });
    let c = local_client(&cloud, |c| fast(pinned2(&a, &b, LocalMode::LocalFirst)(c)));
    let e = c
        .jobs()
        .create(CreateJob::text("x").idempotency_key("order-21"))
        .await
        .unwrap_err();
    assert!(e.is_outcome_unknown(), "{e:?}");
    assert!(b.requests().is_empty(), "no next station");
    assert_eq!(cloud.counts().1, 0, "no cloud");
}

// ---- R4: cloud 409 duplicate ----

#[tokio::test]
async fn cloud_409_duplicate_is_resent_after_an_ambiguous_attempt() {
    let cloud = Cloud::start().await;
    script(&cloud, &[(500, "internal"), (409, "duplicate")]);
    let st = Station::start().await;
    let c = local_client(&cloud, pinned(&st, LocalMode::CloudFirst));
    let start = Instant::now();
    let job = c
        .jobs()
        .create(CreateJob::text("x").idempotency_key("order-22"))
        .await
        .unwrap();
    assert_eq!(job.via, Some(Via::Cloud));
    assert!(start.elapsed() >= Duration::from_secs(1), "waits 1 s");
    let jobs = cloud.state.lock().unwrap().jobs.clone();
    assert_eq!(jobs.len(), 3);
    assert!(jobs.iter().all(|j| j["idempotency_key"] == "order-22"));
    assert_eq!(jobs[1], jobs[2], "the identical request");
    assert!(st.requests().is_empty(), "never local");
}

#[tokio::test]
async fn cloud_409_duplicate_limits_and_outcomes() {
    let st = Station::start().await;

    // Still 409 after 3 re-sends: that answer, never local.
    let cloud = Cloud::start().await;
    script(&cloud, &[(409, "duplicate"); 4]);
    let c = local_client(&cloud, pinned(&st, LocalMode::CloudFirst));
    let e = c.jobs().create(CreateJob::text("x")).await.unwrap_err();
    assert!(matches!(e, Error::Conflict(_)), "{e:?}");
    assert_eq!(cloud.counts().1, 4, "first try + 3 re-sends");

    // A re-send that isn't delivered: the cloud may have the job.
    let cloud = Cloud::start().await;
    script(&cloud, &[(409, "duplicate"), (503, "unavailable")]);
    let c = local_client(&cloud, pinned(&st, LocalMode::CloudFirst));
    let e = c.jobs().create(CreateJob::text("x")).await.unwrap_err();
    assert!(e.is_outcome_unknown(), "{e:?}");

    // ... or that is ambiguous.
    let cloud = Cloud::start().await;
    script(&cloud, &[(409, "duplicate"), (500, "internal")]);
    let c = local_client(&cloud, pinned(&st, LocalMode::LocalFirst));
    st.fail_jobs(503, "local_disabled");
    let e = c.jobs().create(CreateJob::text("x")).await.unwrap_err();
    assert!(e.is_outcome_unknown(), "{e:?}");
    assert!(st.job_requests().iter().all(|r| r.method == "POST"));
}

#[tokio::test]
async fn cloud_mode_resends_409_duplicate_too() {
    let cloud = Cloud::start().await;
    script(&cloud, &[(409, "duplicate")]);
    let c = local_client(&cloud, |c| c);
    let job = c
        .jobs()
        .create(CreateJob::text("x").idempotency_key("order-23"))
        .await
        .unwrap();
    assert_eq!(job.id, "cloud-1");
    assert_eq!(cloud.counts().1, 2);

    // No key set: the generated key is fixed before the first send, so the
    // re-send is identical.
    let cloud = Cloud::start().await;
    script(&cloud, &[(409, "duplicate")]);
    let c = local_client(&cloud, |c| c);
    c.jobs().create(CreateJob::text("x")).await.unwrap();
    let jobs = cloud.state.lock().unwrap().jobs.clone();
    assert_eq!(jobs.len(), 2);
    assert!(jobs[0]["idempotency_key"]
        .as_str()
        .is_some_and(|k| !k.is_empty()));
    assert_eq!(jobs[0], jobs[1], "identical re-send");
}

// ---- C1: local_first returns the cloud's answer itself ----

#[tokio::test]
async fn local_first_returns_the_cloud_4xx_itself() {
    let st = Station::start().await;
    st.fail_jobs(503, "local_disabled");
    let cloud = Cloud::start().await;
    cloud.set(|s| s.job_error = Some((402, "out_of_prints".into())));
    let c = local_client(&cloud, pinned(&st, LocalMode::LocalFirst));
    let e = c.jobs().create(CreateJob::text("x")).await.unwrap_err();
    assert!(matches!(e, Error::OutOfPrints(_)), "{e:?}");

    // Not delivered (503): still StationUnreachable with the cloud error.
    cloud.set(|s| s.job_error = Some((503, "unavailable".into())));
    let e = c.jobs().create(CreateJob::text("x")).await.unwrap_err();
    assert!(e.is_station_unreachable(), "{e:?}");
}

// ---- C2: any 5xx but 502/503/504 is ambiguous ----

#[tokio::test]
async fn cloud_5xx_other_than_502_503_504_is_ambiguous() {
    let st = Station::start().await;
    for status in [501, 505, 507, 599] {
        let cloud = Cloud::start().await;
        script(&cloud, &[(status, "x")]);
        let c = local_client(&cloud, pinned(&st, LocalMode::CloudFirst));
        let job = c.jobs().create(CreateJob::text("x")).await.unwrap();
        assert_eq!(job.via, Some(Via::Cloud), "{status}");
        assert_eq!(cloud.counts().1, 2, "{status}: one retry");

        let cloud = Cloud::start().await;
        script(&cloud, &[(status, "x"), (status, "x")]);
        let c = local_client(&cloud, pinned(&st, LocalMode::CloudFirst));
        let e = c.jobs().create(CreateJob::text("x")).await.unwrap_err();
        assert!(e.is_outcome_unknown(), "{status}: {e:?}");
    }
    assert!(st.requests().is_empty(), "never local");
}

// ---- C5: a 2xx without a job ----

#[tokio::test]
async fn station_2xx_without_a_job_is_asked_by_key() {
    let cloud = Cloud::start().await;
    let st = Station::start().await;
    for body in ["{}", "", "not json"] {
        st.set(|s| s.post_body = Some(body.into()));
        let c = local_client(&cloud, pinned(&st, LocalMode::LocalFirst));
        let before = st.find_requests().len();
        let job = c.jobs().create(CreateJob::text("x")).await.unwrap();
        assert_eq!(job.via, Some(Via::Local), "{body:?}");
        assert!(job.id.starts_with("lj_"), "{body:?}: the job found by key");
        assert_eq!(st.find_requests().len(), before + 1, "{body:?}");
    }
    assert_eq!(cloud.counts().1, 0);
}

#[tokio::test]
async fn cloud_2xx_without_a_job_is_ambiguous() {
    let st = Station::start().await;
    let cloud = Cloud::start().await;
    script(&cloud, &[(201, "")]);
    let c = local_client(&cloud, pinned(&st, LocalMode::CloudFirst));
    let job = c.jobs().create(CreateJob::text("x")).await.unwrap();
    assert_eq!(job.id, "cloud-1");
    assert_eq!(cloud.counts().1, 2, "retried with the same key");
    assert!(st.requests().is_empty());
}
