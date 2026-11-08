//! Audit round 4 (SDK addendum 2): never print twice on an ambiguous outcome
//! (SDK-1), idempotency key checks (SDK-2), redacted Debug output (SDK-4),
//! refresh at min(7 days, TTL/2) (SDK-6) and the file token store's owner
//! and mode checks (SDK-8).
#![cfg(feature = "local")]

mod local_support;

use std::time::{Duration, Instant};

use catzprint::{
    CreateJob, Error, FileTokenStore, LocalConfig, LocalMode, LocalPairing, LocalToken,
    MemoryTokenStore, StoredToken, TokenStore, Via,
};
use local_support::*;

fn pinned(st: &Station, mode: LocalMode) -> impl FnOnce(LocalConfig) -> LocalConfig {
    let (url, fp) = (st.url.clone(), st.fp.clone());
    move |c| c.mode(mode).station_url(&url).fingerprint(&url, &fp)
}

/// Two pinned stations, tried in order.
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

// ---- SDK-1: stations ----

#[tokio::test]
async fn not_delivered_tries_the_next_station_without_asking() {
    let cloud = Cloud::start().await;
    let good = Station::start().await;
    // A dead port and a station with another certificate (pin mismatch):
    // neither got the request.
    let dead = dead_url().await;
    let wrong = Station::start().await;
    let c = local_client(&cloud, |c| {
        c.mode(LocalMode::Local)
            .station_url(&dead)
            .fingerprint(&dead, "ab".repeat(32))
            .station_url(&wrong.url)
            .fingerprint(&wrong.url, "cd".repeat(32))
            .station_url(&good.url)
            .fingerprint(&good.url, &good.fp)
    });
    let job = c
        .jobs()
        .create(CreateJob::text("x").idempotency_key("nd-1"))
        .await
        .unwrap();
    assert_eq!(job.via, Some(Via::Local));
    assert_eq!(good.job_requests().len(), 1);
    assert!(wrong.requests().is_empty(), "nothing sent past the pin");
    assert!(good.find_requests().is_empty() && wrong.find_requests().is_empty());
}

#[tokio::test]
async fn station_refusals_are_not_delivered() {
    // 502/504, 503 local_disabled and a 503 without a code: the station
    // answered and refused, so the next station (or the cloud) may print.
    for (status, code) in [(502, ""), (504, ""), (503, "local_disabled"), (503, "")] {
        let cloud = Cloud::start().await;
        let st = Station::start().await;
        st.fail_jobs(status, code);
        let c = local_client(&cloud, pinned(&st, LocalMode::LocalFirst));
        let job = c.jobs().create(CreateJob::text("x")).await.unwrap();
        assert_eq!(job.via, Some(Via::Cloud), "{status} {code}");
        assert!(st.find_requests().is_empty(), "{status} {code}: no probe");
    }
}

#[tokio::test]
async fn delivered_without_answer_returns_the_job_found_by_key() {
    let cloud = Cloud::start().await;
    let st = Station::start().await;
    // The station takes the job but answers too late; it answers the probe.
    st.set(|s| s.post_delay = Duration::from_secs(3));
    let c = local_client(&cloud, |c| fast(pinned(&st, LocalMode::LocalFirst)(c)));
    let job = c
        .jobs()
        .create(CreateJob::text("x").idempotency_key("order-7"))
        .await
        .unwrap();
    assert_eq!(job.via, Some(Via::Local));
    assert!(job.id.starts_with("lj_"));
    assert_eq!(job.idempotency_key.as_deref(), Some("order-7"));
    assert_eq!(st.job_requests().len(), 1, "posted once");
    let finds = st.find_requests();
    assert_eq!(finds.len(), 1);
    assert_eq!(finds[0].query, "idempotency_key=order-7");
    assert!(finds[0].auth.starts_with("Bearer czl1."));
    assert_eq!(cloud.counts().1, 0, "never sent to the cloud");
    // The job is remembered with its station.
    let again = c.jobs().get(&job.id).await.unwrap();
    assert_eq!(again.id, job.id);
}

#[tokio::test]
async fn delivered_but_not_recorded_tries_the_next_station() {
    let cloud = Cloud::start().await;
    let a = Station::start().await;
    let b = Station::start().await;
    // A swallows the request and never records it: its probe says 404.
    a.set(|s| {
        s.post_delay = Duration::from_secs(3);
        s.forget_jobs = true;
    });
    let c = local_client(&cloud, |c| fast(pinned2(&a, &b, LocalMode::Local)(c)));
    let job = c
        .jobs()
        .create(CreateJob::text("x").idempotency_key("order-8"))
        .await
        .unwrap();
    assert_eq!(job.local.unwrap().station_url, b.url);
    assert_eq!(a.find_requests().len(), 1);
    assert_eq!(b.job_requests()[0].body["idempotency_key"], "order-8");

    // Only that station, local_first: the cloud takes it (same key).
    let cloud = Cloud::start().await;
    let c = local_client(&cloud, |c| fast(pinned(&a, LocalMode::LocalFirst)(c)));
    let job = c
        .jobs()
        .create(CreateJob::text("x").idempotency_key("order-9"))
        .await
        .unwrap();
    assert_eq!(job.via, Some(Via::Cloud));
    assert_eq!(cloud.last_job()["idempotency_key"], "order-9");
}

#[tokio::test]
async fn redirect_is_delivered_without_answer() {
    let cloud = Cloud::start().await;
    let st = Station::start().await;
    st.set(|s| {
        s.fail = Some(Box::new(|r: &Req| {
            (r.method == "POST" && r.path == "/local/v1/jobs").then(|| (302, "moved".into()))
        }))
    });
    let c = local_client(&cloud, pinned(&st, LocalMode::LocalFirst));
    let job = c.jobs().create(CreateJob::text("x")).await.unwrap();
    // Asked by key first (404: never recorded), then the cloud.
    assert_eq!(st.find_requests().len(), 1);
    assert_eq!(job.via, Some(Via::Cloud));
}

#[tokio::test]
async fn delivered_and_still_no_answer_is_outcome_unknown() {
    let cloud = Cloud::start().await;
    let a = Station::start().await;
    let b = Station::start().await;
    a.set(|s| s.delay = Duration::from_secs(10)); // POST and probes hang
    let c = local_client(&cloud, |c| fast(pinned2(&a, &b, LocalMode::LocalFirst)(c)));
    let start = Instant::now();
    let e = c
        .jobs()
        .create(CreateJob::text("x").idempotency_key("order-10"))
        .await
        .unwrap_err();
    let elapsed = start.elapsed();
    match &e {
        Error::OutcomeUnknown {
            url,
            idempotency_key,
            cause,
        } => {
            assert_eq!(url, &a.url);
            assert_eq!(idempotency_key, "order-10");
            assert!(matches!(**cause, Error::Connection { timeout: true, .. }));
        }
        other => panic!("want OutcomeUnknown, got {other:?}"),
    }
    assert!(e.is_outcome_unknown());
    assert_eq!(e.code(), Some("outcome_unknown"));
    assert!(e.to_string().starts_with(
        "The station may have printed this job. Retry later with the same idempotency key."
    ));
    assert!(b.requests().is_empty(), "no other station");
    assert_eq!(cloud.counts().1, 0, "no cloud");
    // Up to 3 probes on fresh connections within 5 s.
    let finds = a.find_requests().len();
    assert!((1..=3).contains(&finds), "{finds} probes");
    assert!(
        elapsed >= Duration::from_secs(4) && elapsed < Duration::from_millis(6500),
        "{elapsed:?}"
    );
}

// ---- SDK-1: cloud ----

#[tokio::test]
async fn cloud_500_is_retried_once_with_the_same_key() {
    let cloud = Cloud::start().await;
    cloud.set(|s| {
        s.job_script
            .push_back((500, "internal".into(), Duration::ZERO))
    });
    let st = Station::start().await;
    let c = local_client(&cloud, pinned(&st, LocalMode::CloudFirst));
    let job = c.jobs().create(CreateJob::text("x")).await.unwrap();
    assert_eq!(job.via, Some(Via::Cloud));
    let jobs = cloud.state.lock().unwrap().jobs.clone();
    assert_eq!(jobs.len(), 2);
    assert_eq!(jobs[0]["idempotency_key"], jobs[1]["idempotency_key"]);
    assert!(st.requests().is_empty(), "never local");
}

#[tokio::test]
async fn cloud_ambiguous_twice_is_outcome_unknown_and_never_local() {
    // Timeouts after delivery, twice.
    let cloud = Cloud::start().await;
    cloud.set(|s| {
        for _ in 0..2 {
            s.job_script
                .push_back((0, String::new(), Duration::from_secs(2)));
        }
    });
    let st = Station::start().await;
    let c = local_client(&cloud, |c| {
        pinned(&st, LocalMode::CloudFirst)(c.cloud_timeout(Duration::from_millis(300)))
    });
    let e = c
        .jobs()
        .create(CreateJob::text("x").idempotency_key("order-11"))
        .await
        .unwrap_err();
    match &e {
        Error::OutcomeUnknown {
            url,
            idempotency_key,
            ..
        } => {
            assert_eq!(url, &cloud.url);
            assert_eq!(idempotency_key, "order-11");
        }
        other => panic!("want OutcomeUnknown, got {other:?}"),
    }
    assert_eq!(cloud.counts().1, 2);
    assert!(st.requests().is_empty(), "never local");

    // 500, then not delivered (503): also unknown, still never local.
    let cloud = Cloud::start().await;
    cloud.set(|s| {
        s.job_script
            .push_back((500, "internal".into(), Duration::ZERO));
        s.job_script
            .push_back((503, "unavailable".into(), Duration::ZERO));
    });
    let c = local_client(&cloud, pinned(&st, LocalMode::CloudFirst));
    let e = c.jobs().create(CreateJob::text("x")).await.unwrap_err();
    assert!(e.is_outcome_unknown(), "{e:?}");
    assert!(st.requests().is_empty(), "never local");

    // After an ambiguous attempt an answer is used as is.
    let cloud = Cloud::start().await;
    cloud.set(|s| {
        s.job_script
            .push_back((500, "internal".into(), Duration::ZERO));
        s.job_script
            .push_back((402, "out_of_prints".into(), Duration::ZERO));
    });
    let c = local_client(&cloud, pinned(&st, LocalMode::CloudFirst));
    let e = c.jobs().create(CreateJob::text("x")).await.unwrap_err();
    assert!(matches!(e, Error::OutOfPrints(_)), "{e:?}");
}

#[tokio::test]
async fn local_first_cloud_leg_follows_the_same_rules() {
    let st = Station::start().await;
    st.fail_jobs(503, "local_disabled");

    // Not delivered (503): StationUnreachable with the cloud error.
    let cloud = Cloud::start().await;
    cloud.set(|s| s.job_error = Some((503, "unavailable".into())));
    let c = local_client(&cloud, pinned(&st, LocalMode::LocalFirst));
    let e = c.jobs().create(CreateJob::text("x")).await.unwrap_err();
    assert!(e.is_station_unreachable(), "{e:?}");
    assert_eq!(e.cloud_error().and_then(|c| c.status()), Some(503));
    assert_eq!(cloud.counts().1, 1, "not retried");

    // 500 then OK: one retry, same key.
    let cloud = Cloud::start().await;
    cloud.set(|s| {
        s.job_script
            .push_back((500, "internal".into(), Duration::ZERO))
    });
    let c = local_client(&cloud, pinned(&st, LocalMode::LocalFirst));
    let job = c.jobs().create(CreateJob::text("x")).await.unwrap();
    assert_eq!(job.via, Some(Via::Cloud));
    assert_eq!(cloud.counts().1, 2);

    // Ambiguous twice: OutcomeUnknown, not StationUnreachable.
    let cloud = Cloud::start().await;
    cloud.set(|s| {
        s.job_script
            .push_back((500, "internal".into(), Duration::ZERO));
        s.job_script
            .push_back((500, "internal".into(), Duration::ZERO));
    });
    let c = local_client(&cloud, pinned(&st, LocalMode::LocalFirst));
    let e = c.jobs().create(CreateJob::text("x")).await.unwrap_err();
    assert!(e.is_outcome_unknown(), "{e:?}");
    assert_eq!(cloud.counts().1, 2);
}

// ---- SDK-2: idempotency keys ----

#[tokio::test]
async fn blank_keys_are_no_key_and_bad_keys_are_refused() {
    let cloud = Cloud::start().await;
    let st = Station::start().await;

    // Blank: a generated key (sdk-… in the local modes, a UUID in cloud mode).
    let c = local_client(&cloud, pinned(&st, LocalMode::Local));
    c.jobs()
        .create(CreateJob::text("x").idempotency_key(" \t "))
        .await
        .unwrap();
    let k = st.job_requests()[0].body["idempotency_key"].clone();
    assert!(k.as_str().unwrap().starts_with("sdk-"), "{k}");
    let c = local_client(&cloud, |c| c);
    c.jobs()
        .create(CreateJob::text("x").idempotency_key(""))
        .await
        .unwrap();
    let k = cloud.last_job()["idempotency_key"].clone();
    assert_eq!(k.as_str().unwrap().len(), 36, "{k}");

    // Whitespace around or control characters: refused, nothing sent.
    let before = (st.requests().len(), cloud.counts().1);
    for bad in [" order-1", "order-1\n", "ord\u{7}er", "order-1 "] {
        for mode in [LocalMode::Cloud, LocalMode::Local, LocalMode::LocalFirst] {
            let c = local_client(&cloud, pinned(&st, mode));
            let e = c
                .jobs()
                .create(CreateJob::text("x").idempotency_key(bad))
                .await
                .unwrap_err();
            assert!(matches!(e, Error::Validation(_)), "{bad:?} {mode:?}: {e:?}");
            assert!(e.fields().unwrap().contains_key("idempotency_key"));
        }
    }
    assert_eq!((st.requests().len(), cloud.counts().1), before);
}

// ---- SDK-4: secrets in Debug output ----

#[tokio::test]
async fn debug_output_never_shows_tokens() {
    let secret = "czl1.SECRETPAYLOAD.SIG";
    let st = StoredToken {
        token: secret.into(),
        token_id: "jti-1".into(),
        ..Default::default()
    };
    let lt = LocalToken {
        token: secret.into(),
        token_id: "jti-1".into(),
        ..Default::default()
    };
    let lp = LocalPairing {
        token: "czd_SECRETDEVICE".into(),
        device_id: "d1".into(),
        ..Default::default()
    };
    let mem = MemoryTokenStore::new();
    mem.save("k", &st).await.unwrap();
    let cfg = LocalConfig::new(LocalMode::Local).token("czd_SECRETDEVICE");
    for out in [
        format!("{st:?}"),
        format!("{st:#?}"),
        format!("{lt:?}"),
        format!("{lp:?}"),
        format!("{mem:?}"),
        format!("{cfg:?}"),
    ] {
        assert!(!out.contains("SECRET"), "{out}");
    }
    assert!(format!("{st:?}").contains("jti-1"));
    assert!(format!("{lp:?}").contains("****"));
    // The token is still there for the caller.
    assert_eq!(lt.token, secret);

    // A client holding a minted token.
    let cloud = Cloud::start().await;
    let station = Station::start().await;
    let c = local_client(&cloud, pinned(&station, LocalMode::Local));
    c.jobs().create(CreateJob::text("x")).await.unwrap();
    let tok = c.local().token().await.unwrap();
    let payload = tok.split('.').nth(1).unwrap().to_string();
    assert!(!format!("{c:?}").contains(&payload));
    assert!(!format!("{:?}", c.local()).contains(&payload));
}

// ---- SDK-6: refresh at min(7 days, TTL / 2) ----

#[tokio::test]
async fn short_tokens_are_renewed_half_way() {
    let cloud = Cloud::start().await;
    cloud.set(|s| {
        s.expires_in = chrono::Duration::days(1);
        s.token_ttl = Some(chrono::Duration::days(1));
    });
    let st = Station::start().await;
    let c = local_client(&cloud, |c| {
        pinned(&st, LocalMode::Local)(c.token_ttl_days(1))
    });
    c.jobs().create(CreateJob::text("1")).await.unwrap();
    c.local().__wait_background().await;
    assert_eq!(cloud.counts().0, 1, "a fresh 1-day token isn't renewed");
    // 22 h left (> 12 h): kept. Before the fix (< 7 days) it was renewed on
    // every use.
    c.local().__advance_clock(Duration::from_secs(2 * 3600));
    c.jobs().create(CreateJob::text("2")).await.unwrap();
    c.local().__wait_background().await;
    assert_eq!(cloud.counts().0, 1, "renewed too early");
    // 11 h left (< 12 h): renewed in the background.
    c.local().__advance_clock(Duration::from_secs(11 * 3600));
    c.jobs().create(CreateJob::text("3")).await.unwrap();
    c.local().__wait_background().await;
    assert_eq!(cloud.counts().0, 2, "want a renewal half-way");
}

// ---- SDK-8: the file store's owner and mode ----

#[cfg(unix)]
fn tempdir() -> std::path::PathBuf {
    use std::hash::{BuildHasher, Hasher};
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u32(std::process::id());
    let d = std::env::temp_dir().join(format!(
        "catzprint-a4-{}-{:016x}",
        std::process::id(),
        h.finish()
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[cfg(unix)]
#[tokio::test]
async fn file_store_refuses_unsafe_files_and_directories() {
    use std::os::unix::fs::PermissionsExt as _;
    let set_mode = |p: &std::path::Path, m: u32| {
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(m)).unwrap()
    };
    let planted = StoredToken {
        token: "czl1.PLANTED.SIG".into(),
        expires_at: Some(chrono::Utc::now() + chrono::Duration::days(20)),
        ..Default::default()
    };

    // A group- or world-writable store file.
    for mode in [0o666, 0o620] {
        let dir = tempdir();
        let path = dir.join("tokens.json");
        let store = FileTokenStore::new(&path);
        store.save("k", &planted).await.unwrap();
        set_mode(&path, mode);
        let e = store.load("k").await.unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(e.to_string().contains("writable"), "{e}");
        assert!(store.save("k", &planted).await.is_err(), "no silent use");
        let _ = std::fs::remove_dir_all(dir);
    }

    // A world-writable directory.
    let dir = tempdir();
    let path = dir.join("tokens.json");
    let store = FileTokenStore::new(&path);
    store.save("k", &planted).await.unwrap();
    set_mode(&dir, 0o777);
    assert!(store.load("k").await.is_err());
    set_mode(&dir, 0o700);
    assert_eq!(store.load("k").await.unwrap().unwrap().token, planted.token);

    // A client never uses a planted token from an unsafe file: it reports
    // the store error and mints its own (kept in memory).
    let cloud = Cloud::start().await;
    let st = Station::start().await;
    let c = local_client(&cloud, |c| {
        pinned(&st, LocalMode::Local)(c.token_store(FileTokenStore::new(&path)))
    });
    let key = c.local().__store_key();
    store.save(&key, &planted).await.unwrap();
    set_mode(&path, 0o646);
    c.jobs().create(CreateJob::text("x")).await.unwrap();
    assert_ne!(st.job_requests()[0].auth, "Bearer czl1.PLANTED.SIG");
    assert_eq!(cloud.counts().0, 1);
    let err = c.local().store_error().expect("store error reported");
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
    let _ = std::fs::remove_dir_all(&dir);

    // Owned by another user (needs root to set up).
    let dir = tempdir();
    let path = dir.join("tokens.json");
    let store = FileTokenStore::new(&path);
    store.save("k", &planted).await.unwrap();
    use std::os::unix::fs::MetadataExt as _;
    let me = std::fs::metadata(&dir).unwrap().uid();
    if std::os::unix::fs::chown(&path, Some(54321), None).is_ok() {
        let e = store.load("k").await.unwrap_err();
        assert!(e.to_string().contains("owned by uid 54321"), "{e}");
        std::os::unix::fs::chown(&path, Some(me), None).unwrap();
        assert!(store.load("k").await.is_ok());
        if std::os::unix::fs::chown(&dir, Some(54321), None).is_ok() {
            let e = store.load("k").await.unwrap_err();
            assert!(e.to_string().contains("directory"), "{e}");
        }
    }
    let _ = std::fs::remove_dir_all(dir);
}
