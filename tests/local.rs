//! Local (offline) printing against a fake TLS station and a fake cloud:
//! modes and fallback rules, 401 handling, idempotency keys, TLS pinning,
//! discovery, token store, timeouts and cancellation.
#![cfg(feature = "local")]

mod local_support;

use std::time::{Duration, Instant};

use catzprint::{
    Client, Command, CreateJob, Error, FileTokenStore, JobStatus, LocalConfig, LocalEndpoint,
    LocalMode, LocalTokenParams, StoredToken, TokenStore, Via, WaitOptions,
};
use local_support::*;
use serde_json::{json, Value};

fn kitchen(key: &str) -> CreateJob {
    CreateJob::template("tpl-kitchen", json!({"table": "12"}))
        .role("kitchen")
        .reference("order-1042")
        .idempotency_key(key)
}

fn pinned(st: &Station, mode: LocalMode) -> impl FnOnce(LocalConfig) -> LocalConfig {
    let (url, fp) = (st.url.clone(), st.fp.clone());
    move |c| c.mode(mode).station_url(&url).fingerprint(&url, &fp)
}

fn endpoint(st: &Station) -> Value {
    json!([{"station_id": "st1", "local_enabled": true, "urls": [st.url],
        "tls_mode": "self_signed", "cert_fingerprint_sha256": st.fp}])
}

// ---- modes ----

#[tokio::test]
async fn local_mode_prints_on_station() {
    let cloud = Cloud::start().await;
    let st = Station::start().await;
    let c = local_client(&cloud, |c| {
        pinned(&st, LocalMode::Local)(c.location_id("loc1"))
    });
    let job = c
        .jobs()
        .create(
            CreateJob::commands(vec![Command::text("ALLERGY"), Command::cut()])
                .role("kitchen")
                .copies(2),
        )
        .await
        .unwrap();
    assert_eq!(job.via, Some(Via::Local));
    assert!(job.printed_locally && job.live);
    assert!(job.id.starts_with("lj_"), "{}", job.id);
    assert_eq!(job.status, JobStatus::Queued);
    assert_eq!(job.copies, 2);
    assert_eq!(job.printer_name.as_deref(), Some("Kitchen"));
    assert_eq!(job.local.as_ref().unwrap().station_url, st.url);

    let reqs = st.job_requests();
    assert_eq!(reqs.len(), 1);
    let key = reqs[0].body["idempotency_key"].as_str().unwrap();
    assert!(
        key.starts_with("sdk-") && key.len() == 40,
        "auto key {key:?}"
    );
    assert_eq!(job.idempotency_key.as_deref(), Some(key));
    assert!(reqs[0].auth.starts_with("Bearer czl1."));
    assert_eq!(reqs[0].body["kind"], "commands");
    assert_eq!(reqs[0].body["role"], "kitchen");
    assert_eq!(reqs[0].body["location_id"], "loc1", "config location used");

    assert_eq!(cloud.counts(), (1, 0));
    let mint = cloud.state.lock().unwrap().mints[0].clone();
    assert_eq!(mint["device_name"], "Hub");
    assert_eq!(
        mint["location_ids"],
        json!(["loc1"]),
        "token bound to the location"
    );
    // The second job reuses the cached token.
    c.jobs().print_text("hi", CreateJob::new()).await.unwrap();
    assert_eq!(cloud.counts().0, 1, "token not cached");
}

#[tokio::test]
async fn local_job_body_matches_spec() {
    let cloud = Cloud::start().await;
    let st = Station::start().await;
    let c = local_client(&cloud, |c| {
        pinned(&st, LocalMode::Local)(c.wait(Duration::from_secs(5)))
    });
    let mut opts = serde_json::Map::new();
    opts.insert("cut".into(), json!(true));
    let job = c
        .jobs()
        .create(
            CreateJob::bytes(vec![0x1b, 0x40, b'h', b'i'])
                .title("Raw")
                .options(opts),
        )
        .await
        .unwrap();
    assert_eq!(job.status, JobStatus::Printed, "wait honoured");
    assert!(job.printed_at.is_some());
    let r = &st.job_requests()[0];
    assert_eq!(r.query, "wait=5");
    assert_eq!(r.body["kind"], "escpos");
    assert_eq!(r.body["content"], "G0BoaQ==");
    assert_eq!(r.body["title"], "Raw");
    assert_eq!(r.body["options"]["cut"], true);
    for k in ["file_name", "scheduled_for", "sealed_content"] {
        assert!(r.body.get(k).is_none(), "{k} must not be sent to a station");
    }
}

#[tokio::test]
async fn local_first_falls_back_when_station_unreachable() {
    let cloud = Cloud::start().await;
    let dead = dead_url().await;
    let fp = "ab".repeat(32);
    let c = local_client(&cloud, |c| {
        c.mode(LocalMode::LocalFirst)
            .station_url(&dead)
            .fingerprint(&dead, &fp)
    });
    let job = c
        .jobs()
        .create(kitchen("order-1042-kitchen-r1"))
        .await
        .unwrap();
    assert_eq!(job.via, Some(Via::Cloud));
    assert_eq!(job.id, "cloud-1");
    assert!(!job.printed_locally);
    assert_eq!(cloud.last_job()["idempotency_key"], "order-1042-kitchen-r1");
}

#[tokio::test]
async fn local_first_fallback_rules() {
    type Check = fn(&Error) -> bool;
    let fallback: &[(u16, &str)] = &[
        (502, "bad_gateway"),
        (504, "gateway_timeout"),
        (503, "local_disabled"),
        (503, ""), // a 503 without a code
    ];
    let no_fallback: &[(u16, &str, Check)] = &[
        (503, "printer_offline", |e| {
            matches!(e, Error::Printer(_)) && e.is_printer_offline()
        }),
        (503, "out_of_paper", |e| {
            matches!(e, Error::Printer(_)) && e.is_out_of_paper()
        }),
        (503, "cover_open", |e| {
            matches!(e, Error::Printer(_)) && e.is_cover_open()
        }),
        (503, "printer_error", |e| matches!(e, Error::Printer(_))),
        (422, "no_printer", |e| matches!(e, Error::Validation(_))),
        (400, "invalid", |e| matches!(e, Error::Validation(_))),
        (422, "unsupported_locally", |e| {
            matches!(e, Error::Validation(_))
        }),
        (402, "offline_allowance_exhausted", |e| {
            matches!(e, Error::OutOfPrints(_)) && e.is_offline_allowance_exhausted()
        }),
        (403, "device_not_approved", |e| {
            matches!(e, Error::Permission(_))
        }),
        (403, "forbidden_location", |e| {
            matches!(e, Error::Permission(_))
        }),
        (409, "duplicate", |e| matches!(e, Error::Conflict(_))),
        (429, "rate_limited", |e| matches!(e, Error::RateLimit(_))),
    ];
    for &(status, code) in fallback {
        let cloud = Cloud::start().await;
        let st = Station::start().await;
        st.fail_jobs(status, code);
        let c = local_client(&cloud, pinned(&st, LocalMode::LocalFirst));
        let key = format!("k-{status}-{code}");
        let job = c.jobs().create(kitchen(&key)).await;
        let job = job.unwrap_or_else(|e| panic!("{status} {code}: want cloud fallback, got {e}"));
        assert_eq!(job.via, Some(Via::Cloud), "{status} {code}");
        assert_eq!(cloud.counts().1, 1);
        assert_eq!(
            cloud.last_job()["idempotency_key"],
            key.as_str(),
            "same key"
        );
        assert_eq!(st.job_requests()[0].body["idempotency_key"], key.as_str());
    }
    for &(status, code, check) in no_fallback {
        let cloud = Cloud::start().await;
        let st = Station::start().await;
        st.fail_jobs(status, code);
        let c = local_client(&cloud, pinned(&st, LocalMode::LocalFirst));
        let err = c.jobs().create(kitchen("k")).await.unwrap_err();
        assert_eq!(cloud.counts().1, 0, "{status} {code}: must not fall back");
        assert!(!err.is_station_unreachable(), "{status} {code}: {err}");
        assert_eq!(err.code(), Some(code), "{status} {code}");
        assert_eq!(err.status(), Some(status));
        assert!(check(&err), "{status} {code}: wrong kind {err:?}");
    }
}

// ---- 401 ----

#[tokio::test]
async fn local_401_remints_once_then_succeeds() {
    let cloud = Cloud::start().await;
    let st = Station::start().await;
    // The station only accepts the second minted token.
    st.set(|s| s.accept = Some(Box::new(|t: &str| token_jti(t) == "jti-2")));
    let c = local_client(&cloud, pinned(&st, LocalMode::Local));
    let job = c.jobs().create(kitchen("k1")).await.unwrap();
    assert_eq!(job.via, Some(Via::Local));
    assert_eq!(cloud.counts().0, 2);
    assert_eq!(st.job_requests().len(), 2);
    let keys: Vec<Value> = st
        .job_requests()
        .iter()
        .map(|r| r.body["idempotency_key"].clone())
        .collect();
    assert_eq!(
        keys,
        vec![json!("k1"), json!("k1")],
        "the retry reuses the key"
    );
}

#[tokio::test]
async fn local_401_twice_falls_back_or_fails() {
    for mode in [LocalMode::LocalFirst, LocalMode::Local] {
        let cloud = Cloud::start().await;
        let st = Station::start().await;
        st.set(|s| s.accept = Some(Box::new(|_: &str| false)));
        let c = local_client(&cloud, pinned(&st, mode));
        let r = c.jobs().create(kitchen("k401")).await;
        let (mints, cloud_jobs) = cloud.counts();
        assert_eq!(
            (mints, st.job_requests().len()),
            (2, 2),
            "{mode}: re-mint exactly once"
        );
        if mode == LocalMode::LocalFirst {
            let job = r.unwrap();
            assert_eq!(job.via, Some(Via::Cloud));
            assert_eq!(cloud.last_job()["idempotency_key"], "k401");
        } else {
            let e = r.unwrap_err();
            assert!(matches!(e, Error::Authentication(_)), "{e:?}");
            assert_eq!(e.code(), Some("token_expired"));
            assert_eq!(cloud_jobs, 0);
        }
    }
}

#[tokio::test]
async fn local_401_with_cloud_down_falls_back_to_cloud_error() {
    let cloud = Cloud::start().await;
    let st = Station::start().await;
    st.set(|s| s.accept = Some(Box::new(|_: &str| false)));
    let c = local_client(&cloud, pinned(&st, LocalMode::LocalFirst));
    c.local().token().await.unwrap();
    cloud.set(|s| s.down = true);
    let e = c.jobs().create(kitchen("k")).await.unwrap_err();
    assert!(e.is_station_unreachable(), "{e:?}");
    assert!(matches!(e.cloud_error(), Some(Error::Server(_))), "{e:?}");
    assert!(
        std::error::Error::source(&e).is_some(),
        "the cloud error is the source"
    );
    assert_eq!(st.job_requests().len(), 1);
    let msg = e.to_string();
    assert!(
        msg.contains("token_expired") && msg.contains("couldn't be minted"),
        "{msg}"
    );
}

#[tokio::test]
async fn remint_never_on_device_revoked_or_unauthenticated() {
    for code in ["device_revoked", "unauthenticated"] {
        let cloud = Cloud::start().await;
        let st = Station::start().await;
        st.set(|s| {
            s.accept = Some(Box::new(|_: &str| false));
            s.reject_code = code.into();
        });
        let c = local_client(&cloud, pinned(&st, LocalMode::Local));
        let e = c.jobs().create(CreateJob::text("x")).await.unwrap_err();
        assert_eq!(e.code(), Some(code));
        assert_eq!(cloud.counts().0, 1, "re-minted on {code}");
        assert_eq!(st.job_requests().len(), 1);
    }
}

#[tokio::test]
async fn remint_rate_limit_is_persisted_per_store_key() {
    let cloud = Cloud::start().await;
    let st = Station::start().await;
    st.set(|s| s.accept = Some(Box::new(|_: &str| false)));
    let dir = tempdir();
    let path = dir.join("t.json");
    let cfg =
        |c: LocalConfig| pinned(&st, LocalMode::Local)(c.token_store(FileTokenStore::new(&path)));
    for _ in 0..3 {
        // three clients (restarts) within 10 minutes
        let c = local_client(&cloud, cfg);
        let e = c.jobs().create(CreateJob::text("x")).await.unwrap_err();
        assert_eq!(e.code(), Some("token_expired"));
    }
    assert_eq!(cloud.counts().0, 2, "the first mint + one re-mint");
    // After 10 minutes one more re-mint is allowed.
    let c = local_client(&cloud, cfg);
    c.local().__advance_clock(Duration::from_secs(11 * 60));
    let _ = c.jobs().create(CreateJob::text("x")).await;
    assert_eq!(cloud.counts().0, 3);
}

// ---- cloud_first ----

#[tokio::test]
async fn cloud_first_5xx_goes_local_with_the_same_key() {
    let cloud = Cloud::start().await;
    // 502/503/504: certainly not delivered (a 500 is retried in the cloud
    // instead: tests/local_outcome.rs).
    cloud.set(|s| s.job_error = Some((503, "unavailable".into())));
    let st = Station::start().await;
    let c = local_client(&cloud, pinned(&st, LocalMode::CloudFirst));
    let job = c.jobs().create(CreateJob::text("x")).await.unwrap();
    assert_eq!(job.via, Some(Via::Local));
    let cloud_key = cloud.last_job()["idempotency_key"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(cloud_key.starts_with("sdk-"));
    assert_eq!(
        st.job_requests()[0].body["idempotency_key"],
        cloud_key.as_str()
    );
    assert_eq!(
        cloud.counts().1,
        1,
        "a single cloud attempt before falling back"
    );
}

#[tokio::test]
async fn cloud_first_network_error_goes_local() {
    let st = Station::start().await;
    let c = local_client(&Cloud::dead(), |c| {
        pinned(&st, LocalMode::CloudFirst)(c.token("czd_paired"))
    });
    let job = c
        .jobs()
        .create(CreateJob::text("x").idempotency_key("order-7"))
        .await
        .unwrap();
    assert_eq!(job.via, Some(Via::Local));
    let r = &st.job_requests()[0];
    assert_eq!(r.body["idempotency_key"], "order-7");
    assert_eq!(r.auth, "Bearer czd_paired");
}

#[tokio::test]
async fn cloud_first_4xx_is_the_answer() {
    for (status, code) in [
        (422, "no_printer"),
        (402, "out_of_prints"),
        (429, "rate_limited"),
        (401, "invalid_api_key"),
    ] {
        let cloud = Cloud::start().await;
        cloud.set(|s| s.job_error = Some((status, code.into())));
        let st = Station::start().await;
        let c = local_client(&cloud, pinned(&st, LocalMode::CloudFirst));
        let e = c.jobs().create(CreateJob::text("x")).await.unwrap_err();
        assert_eq!(e.code(), Some(code));
        assert!(st.requests().is_empty(), "{status}: station contacted");
        assert_eq!(cloud.counts().1, 1, "{status}: not retried");
    }
}

#[tokio::test]
async fn cloud_first_both_down() {
    let cloud = Cloud::start().await;
    cloud.set(|s| s.job_error = Some((503, "unavailable".into())));
    let dead = dead_url().await;
    let fp = "0".repeat(64);
    let c = local_client(&cloud, |c| {
        c.mode(LocalMode::CloudFirst)
            .station_url(&dead)
            .fingerprint(&dead, &fp)
    });
    let e = c.jobs().create(CreateJob::text("x")).await.unwrap_err();
    assert!(e.is_station_unreachable());
    assert!(matches!(e.cloud_error(), Some(Error::Server(_))));
    let urls: Vec<&str> = e
        .station_attempts()
        .iter()
        .map(|a| a.url.as_str())
        .collect();
    assert_eq!(urls, vec![dead.as_str()]);
    assert_eq!(cloud.counts().1, 1, "cloud_first tries the cloud once");
}

#[tokio::test]
async fn unsupported_locally() {
    let cloud = Cloud::start().await;
    let st = Station::start().await;
    let pdf = b"%PDF-1.4 fake".to_vec();
    let local = local_client(&cloud, pinned(&st, LocalMode::Local));
    let e = local
        .jobs()
        .print_pdf(pdf.clone(), CreateJob::new())
        .await
        .unwrap_err();
    assert_eq!(e.code(), Some("unsupported_locally"));
    assert!(matches!(e, Error::Validation(_)));
    let lf = local_client(&cloud, pinned(&st, LocalMode::LocalFirst));
    let job = lf.jobs().print_pdf(pdf, CreateJob::new()).await.unwrap();
    assert_eq!(job.via, Some(Via::Cloud));
    assert!(
        st.requests().is_empty(),
        "a PDF must go straight to the cloud"
    );
    // Sealed and scheduled jobs too.
    let e = local
        .jobs()
        .create(CreateJob::text("x").scheduled_for(chrono::Utc::now()))
        .await
        .unwrap_err();
    assert_eq!(e.code(), Some("unsupported_locally"));
}

#[tokio::test]
async fn station_order_tries_next_on_unreachable() {
    let cloud = Cloud::start().await;
    let st = Station::start().await;
    let dead = dead_url().await;
    let c = local_client(&cloud, |c| {
        c.mode(LocalMode::Local)
            .station_urls([&dead, &st.url])
            .fingerprint(&dead, &st.fp)
            .fingerprint(&st.url, &st.fp)
    });
    let job = c.jobs().create(CreateJob::text("x")).await.unwrap();
    assert_eq!(job.local.unwrap().station_url, st.url);
}

#[tokio::test]
async fn cloud_mode_unchanged() {
    let cloud = Cloud::start().await;
    let c = Client::builder()
        .api_key(API_KEY)
        .base_url(&cloud.url)
        .org_id("org1")
        .build()
        .unwrap();
    let job = c.jobs().print_text("x", CreateJob::new()).await.unwrap();
    assert_eq!(job.via, Some(Via::Cloud));
    let key = cloud.last_job()["idempotency_key"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(
        !key.starts_with("sdk-") && key.len() == 36,
        "cloud mode key changed: {key}"
    );
    assert_eq!(c.local().mode(), LocalMode::Cloud);
}

// ---- TLS pinning ----

#[tokio::test]
async fn no_fingerprint_never_contacted() {
    let cloud = Cloud::start().await;
    let st = Station::start().await;
    let url = st.url.clone();
    let c = local_client(&cloud, |c| c.mode(LocalMode::Local).station_url(&url));
    let e = c.jobs().create(CreateJob::text("x")).await.unwrap_err();
    assert!(e.is_station_unreachable());
    let a = &e.station_attempts()[0];
    assert!(
        matches!(&a.error, Error::Config(m) if m.contains("fingerprint")),
        "{:?}",
        a.error
    );
    assert_eq!(
        st.conns.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "dialled without a pin"
    );
}

#[tokio::test]
async fn wrong_fingerprint_rejected_in_the_handshake() {
    let cloud = Cloud::start().await;
    let st = Station::start().await;
    let (url, wrong) = (st.url.clone(), "ab".repeat(32));
    let c = local_client(&cloud, |c| {
        c.mode(LocalMode::Local)
            .station_url(&url)
            .fingerprint(&url, &wrong)
    });
    let e = c.jobs().create(CreateJob::text("x")).await.unwrap_err();
    assert!(e.is_station_unreachable());
    match &e.station_attempts()[0].error {
        Error::PinMismatch {
            expected,
            got,
            spki,
        } => {
            assert_eq!(expected, &wrong);
            assert_eq!(got, &st.fp);
            assert!(!spki);
        }
        other => panic!("want PinMismatch, got {other:?}"),
    }
    assert!(
        st.conns.load(std::sync::atomic::Ordering::SeqCst) >= 1,
        "it did connect"
    );
    assert!(
        st.requests().is_empty(),
        "no request may reach an unpinned station"
    );
}

#[tokio::test]
async fn fingerprint_with_colons_upper_case_and_host_key() {
    let cloud = Cloud::start().await;
    let st = Station::start().await;
    let colons: Vec<String> = st
        .fp
        .as_bytes()
        .chunks(2)
        .map(|c| String::from_utf8_lossy(c).to_uppercase())
        .collect();
    let host = st.url.trim_start_matches("https://").to_string();
    let url = st.url.clone();
    let c = local_client(&cloud, |c| {
        c.mode(LocalMode::Local)
            .station_url(&url)
            .fingerprint(&host, colons.join(":"))
    });
    c.jobs().create(CreateJob::text("x")).await.unwrap();
}

#[tokio::test]
async fn fingerprint_from_the_cloud_endpoint_list() {
    let st = Station::start().await;
    let cloud = Cloud::start().await;
    cloud.set(|s| s.stations = endpoint(&st));
    let url = st.url.clone();
    let c = local_client(&cloud, |c| c.mode(LocalMode::Local).station_url(&url));
    let job = c.jobs().create(CreateJob::text("x")).await.unwrap();
    assert_eq!(job.station_id.as_deref(), Some("st1"));
}

#[tokio::test]
async fn public_hostname_verified_spki_pinned_and_dialled_under_its_label() {
    let st = Station::start_with(&cert("publicLeaf")).await;
    let host_url = format!("https://{}:{}", public_host(), st.port);
    let ep = |spki: &str| {
        json!([{"station_id": "st1", "local_enabled": true, "tls_mode": "public",
            "local_label": "abcdefghij", "urls": [host_url], "public_spki_sha256": spki}])
    };
    // Verified with the (test) CA, SPKI pinned, connected to 127.0.0.1 from
    // the dashed name without DNS.
    let cloud = Cloud::start().await;
    cloud.set(|s| s.stations = ep(&public_spki()));
    let c = local_client(&cloud, |c| {
        c.mode(LocalMode::Local)
            .discover(true)
            .root_certificate(ca_der())
    });
    let job = c.jobs().create(CreateJob::text("x")).await.unwrap();
    assert_eq!(job.local.unwrap().station_url, host_url);
    assert_eq!(st.job_requests().len(), 1);

    // Same certificate chain, but the cloud reports another public key:
    // refused in the handshake even though the web PKI check passes.
    let cloud3 = Cloud::start().await;
    cloud3.set(|s| s.stations = ep(&"ab".repeat(32)));
    let c3 = local_client(&cloud3, |c| {
        c.mode(LocalMode::Local)
            .discover(true)
            .root_certificate(ca_der())
    });
    let e = c3.jobs().create(CreateJob::text("x")).await.unwrap_err();
    assert!(
        matches!(&e.station_attempts()[0].error, Error::PinMismatch { spki: true, got, .. } if *got == public_spki()),
        "{e:?}"
    );
    assert_eq!(
        st.job_requests().len(),
        1,
        "no request after an SPKI mismatch"
    );

    // Without the CA (bundled roots only) the same certificate is refused.
    let c2 = local_client(&cloud, |c| c.mode(LocalMode::Local).discover(true));
    let e = c2.jobs().create(CreateJob::text("x")).await.unwrap_err();
    let a = &e.station_attempts()[0].error;
    assert!(
        matches!(a, Error::Connection { message, .. } if message.to_lowercase().contains("certificate")),
        "{a:?}"
    );

    // A configured hostname the cloud doesn't list isn't dialled at the IP
    // in its name (DNS only; here it doesn't resolve).
    let hu = host_url.clone();
    let c4 = local_client(&Cloud::dead(), |c| {
        c.mode(LocalMode::Local)
            .station_url(&hu)
            .root_certificate(ca_der())
            .token("czd_x")
    });
    let e = c4.jobs().create(CreateJob::text("x")).await.unwrap_err();
    assert!(e.is_station_unreachable());
    assert_eq!(
        st.job_requests().len(),
        1,
        "unknown hostname dialled directly"
    );
}

#[tokio::test]
async fn private_addresses_only_from_the_endpoint_list() {
    let st = Station::start().await;
    let cloud = Cloud::start().await;
    cloud.set(|s| {
        s.stations = json!([{"station_id": "st1", "local_enabled": true, "tls_mode": "self_signed",
            "cert_fingerprint_sha256": st.fp,
            "urls": ["https://203.0.113.9:7443", "https://8.8.8.8:7443", st.url]}])
    });
    let c = local_client(&cloud, |c| c.mode(LocalMode::Local).discover(true));
    let job = c.jobs().create(CreateJob::text("x")).await.unwrap();
    assert_eq!(job.local.unwrap().station_url, st.url);
    // Public IPs were never tried: with the station down, only it is listed.
    let st2 = Station::start().await;
    let cloud2 = Cloud::start().await;
    let dead = dead_url().await;
    cloud2.set(|s| {
        s.stations = json!([{"station_id": "st1", "local_enabled": true, "tls_mode": "self_signed",
            "cert_fingerprint_sha256": st2.fp, "urls": ["https://203.0.113.9:7443", dead]}])
    });
    let c2 = local_client(&cloud2, |c| c.mode(LocalMode::Local).discover(true));
    let e = c2.jobs().create(CreateJob::text("x")).await.unwrap_err();
    let urls: Vec<&str> = e
        .station_attempts()
        .iter()
        .map(|a| a.url.as_str())
        .collect();
    assert_eq!(urls, vec![dead.as_str()]);
}

// ---- pairing, live flag, no API key ----

#[tokio::test]
async fn pair_requires_trust() {
    let st = Station::start().await;
    let c = local_client(&Cloud::dead(), |c| c.mode(LocalMode::Cloud));
    let local = c.local();
    let e = local
        .pair(&st.url, "12345678", "Till", None)
        .await
        .unwrap_err();
    assert_eq!(e.code(), Some("invalid"));
    assert!(e.fields().unwrap().contains_key("fingerprint"));
    assert_eq!(st.conns.load(std::sync::atomic::Ordering::SeqCst), 0);

    // A relay (another certificate) is detected before the code is sent.
    let e = local
        .pair(&st.url, "12345678", "Till", Some(&"ab".repeat(32)))
        .await
        .unwrap_err();
    assert!(
        matches!(&e.station_attempts()[0].error, Error::PinMismatch { .. }),
        "{e:?}"
    );
    assert!(st.requests().is_empty());

    let host = format!(
        "https://127-0-0-1.abcdefghij.local.catzprint.com:{}",
        st.port
    );
    let e = local
        .pair(&host, "12345678", "Till", None)
        .await
        .unwrap_err();
    assert_eq!(e.code(), Some("invalid"), "unknown hostname accepted");
    let e = local
        .pair(&st.url, "1234", "Till", Some(&st.fp))
        .await
        .unwrap_err();
    assert_eq!(e.code(), Some("invalid"));
    assert!(st.requests().is_empty());

    let p = local
        .pair(&st.url, "12345678", "Till", Some(&st.fp.to_uppercase()))
        .await
        .unwrap();
    assert_eq!(p.token, "czd_paired");
    assert_eq!(p.device_id, "d_0123456789abcdef");
    let r = st.requests().pop().unwrap();
    assert_eq!(r.auth, "", "pairing carries no token");
    assert_eq!(r.body["device_name"], "Till");
    let e = local
        .pair(&st.url, "00000000", "Till", Some(&st.fp))
        .await
        .unwrap_err();
    assert_eq!(e.code(), Some("invalid_code"));
}

#[tokio::test]
async fn pair_with_a_station_on_the_cloud_list() {
    let st = Station::start().await;
    let cloud = Cloud::start().await;
    cloud.set(|s| s.stations = endpoint(&st));
    let c = local_client(&cloud, |c| c.mode(LocalMode::Cloud));
    c.local().refresh().await.unwrap();
    let p = c.local().pair(&st.url, "12345678", "", None).await.unwrap();
    assert_eq!(p.token, "czd_paired");
    assert_eq!(st.requests().pop().unwrap().body["device_name"], "Hub");
}

#[tokio::test]
async fn local_job_live_flag() {
    let st = Station::start().await;
    let c = local_client(&Cloud::dead(), |c| {
        pinned(&st, LocalMode::Local)(c.token("czd_paired"))
    });
    let j = c.jobs().create(CreateJob::text("x")).await.unwrap();
    assert!(j.live, "paired device jobs are live");
    st.set(|s| s.live = Some(false));
    let j = c.jobs().create(CreateJob::text("y")).await.unwrap();
    assert!(!j.live, "the station's live=false wins");
    assert_eq!(j.local.unwrap().live, Some(false));
}

#[tokio::test]
async fn paired_device_without_api_key() {
    let st = Station::start().await;
    let base = |cfg: LocalConfig| {
        Client::builder()
            .base_url("http://127.0.0.1:1")
            .local(cfg)
            .build()
    };
    let pin = |c: LocalConfig| c.station_url(&st.url).fingerprint(&st.url, &st.fp);
    if std::env::var("CATZPRINT_API_KEY").is_ok() {
        return; // the environment provides a key: nothing to check
    }
    assert!(matches!(
        base(pin(
            LocalConfig::new(LocalMode::LocalFirst).token("czd_paired")
        )),
        Err(Error::Config(_))
    ));
    assert!(matches!(
        base(pin(LocalConfig::new(LocalMode::Local).location_id("l"))),
        Err(Error::Config(_))
    ));
    let c = base(pin(LocalConfig::new(LocalMode::Local)
        .token("czd_paired")
        .discover(true)
        .discover_timeout(Duration::from_millis(50))))
    .unwrap();
    let j = c
        .jobs()
        .create(CreateJob::text("x").role("kitchen"))
        .await
        .unwrap();
    assert_eq!(j.via, Some(Via::Local));
    c.local().status().await.unwrap();
    let e = c.printers().list().await.unwrap_err();
    assert!(matches!(e, Error::Authentication(_)));
    assert_eq!(e.code(), Some("missing_api_key"));
    c.close().await;
}

// ---- discovery ----

#[tokio::test]
async fn mdns_station_used_only_with_a_trusted_fingerprint() {
    let st = Station::start().await;
    let resp = fake_responder(mdns_answer(
        "Kitchen PC",
        "st1",
        "org1",
        "loc1",
        st.port,
        &st.fp,
        [127, 0, 0, 1],
    ))
    .await;
    let cfg = |c: LocalConfig| {
        c.mode(LocalMode::Local)
            .location_id("loc1")
            .discover(true)
            .token("czd_paired")
    };
    // The cloud is unreachable and the endpoint list was never fetched: an
    // announcement alone is not trusted, even with a fingerprint.
    let c0 = local_client(&Cloud::dead(), cfg);
    c0.local().__set_mdns_addr(resp);
    let e = c0.jobs().create(CreateJob::text("x")).await.unwrap_err();
    assert!(e.is_station_unreachable(), "{e:?}");
    assert_eq!(st.conns.load(std::sync::atomic::Ordering::SeqCst), 0);
    // With the fingerprint from the station app configured, mDNS maps it to
    // the station's current address.
    let fp = st.fp.clone();
    let c = local_client(&Cloud::dead(), |c| cfg(c).fingerprint("kitchen-pc", &fp));
    c.local().__set_mdns_addr(resp);
    let j = c.jobs().create(CreateJob::text("x")).await.unwrap();
    assert_eq!(j.local.unwrap().station_url, st.url);
    assert!(j.live);
    // A wrong org or location is ignored.
    for ann in [
        mdns_answer(
            "Other org",
            "st1",
            "org2",
            "loc1",
            st.port,
            &st.fp,
            [127, 0, 0, 1],
        ),
        mdns_answer(
            "Other loc",
            "st1",
            "org1",
            "loc2",
            st.port,
            &st.fp,
            [127, 0, 0, 1],
        ),
    ] {
        let fp = st.fp.clone();
        let c2 = local_client(&Cloud::dead(), |c| cfg(c).fingerprint("kitchen-pc", &fp));
        c2.local().__set_mdns_addr(fake_responder(ann).await);
        assert!(c2
            .jobs()
            .create(CreateJob::text("x"))
            .await
            .unwrap_err()
            .is_station_unreachable());
    }
}

/// Port of Go's TestRevMDNSHostnameImpostor / TestMDNSUnknownStationIgnored…
/// end to end: an impostor announcing an unlisted station ID with its own
/// (valid) certificate is never contacted; a listed station's announced
/// address is pinned with the list's fingerprint, not the announced one.
#[tokio::test]
async fn mdns_impostor_ignored_once_endpoint_list_known() {
    let cloud = Cloud::start().await;
    let impostor = Station::start_with(&cert("otherSelfSigned")).await;
    let dead = dead_url().await;
    cloud.set(|s| {
        s.stations = json!([{"station_id": "st1", "local_enabled": true, "urls": [dead],
            "cert_fingerprint_sha256": "cd".repeat(32)}])
    });
    let c = local_client(&cloud, |c| c.mode(LocalMode::Local).discover(true));
    c.local().__set_mdns_addr(
        fake_responder(mdns_answer(
            "Impostor",
            "st666",
            "org1",
            "loc1",
            impostor.port,
            &impostor.fp,
            [127, 0, 0, 1],
        ))
        .await,
    );
    let e = c.jobs().create(CreateJob::text("x")).await.unwrap_err();
    assert!(e.is_station_unreachable());
    assert_eq!(
        impostor.conns.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "impostor contacted"
    );

    // The listed station ID announced by the impostor: the address is used,
    // pinned with the list's fingerprint, so the handshake fails.
    let c2 = local_client(&cloud, |c| c.mode(LocalMode::Local).discover(true));
    c2.local().__set_mdns_addr(
        fake_responder(mdns_answer(
            "Kitchen",
            "st1",
            "org1",
            "loc1",
            impostor.port,
            &impostor.fp,
            [127, 0, 0, 1],
        ))
        .await,
    );
    let e = c2.jobs().create(CreateJob::text("x")).await.unwrap_err();
    let attempts = e.station_attempts();
    assert_eq!(attempts.len(), 2, "{e}");
    assert_eq!(
        attempts[1].url,
        format!("https://127.0.0.1:{}", impostor.port)
    );
    assert!(
        matches!(&attempts[1].error, Error::PinMismatch { expected, .. } if *expected == "cd".repeat(32)),
        "{:?}",
        attempts[1].error
    );
    assert!(impostor.requests().is_empty());
}

#[tokio::test]
async fn local_helpers() {
    let st = Station::start().await;
    let cloud = Cloud::start().await;
    cloud.set(|s| {
        s.stations = json!([{"station_id": "st1", "name": "Kitchen PC", "location_id": "loc1",
            "local_enabled": true, "port": 7443, "addresses": ["127.0.0.1"], "urls": [st.url],
            "tls_mode": "self_signed", "cert_fingerprint_sha256": st.fp}])
    });
    let c = local_client(&cloud, |c| {
        c.mode(LocalMode::Local).location_id("loc1").discover(true)
    });
    let local = c.local();

    let status = local.status().await.unwrap();
    assert_eq!(status.unsynced, 3);
    assert_eq!(status.allowance.prints_left, 1997);
    assert!(
        status.station.last_cloud_contact.is_none(),
        "\"\" reads as no time"
    );
    assert_eq!(status.printers[0].role, "kitchen");
    assert_eq!(status.station_url, st.url);

    let info = local.info(&st.url).await.unwrap();
    assert_eq!(info.station_id, "st1");
    assert!(info.pairing_open);

    let job = c.jobs().print_text("x", CreateJob::new()).await.unwrap();
    let done = c
        .jobs()
        .wait_for(
            &job.id,
            WaitOptions {
                timeout: Duration::from_secs(5),
                interval: Duration::from_millis(10),
            },
        )
        .await
        .unwrap();
    assert_eq!(done.status, JobStatus::Printed);
    assert_eq!(done.via, Some(Via::Local));
    assert!(done.printed_at.is_some());
    let e = c.jobs().get("lj_missing").await.unwrap_err();
    assert!(matches!(e, Error::NotFound(_)), "{e:?}");

    let stations = local.discover().await.unwrap();
    assert_eq!(stations.len(), 1);
    assert!(stations[0].from_cloud);
    assert_eq!(stations[0].fingerprint, st.fp);
    assert_eq!(stations[0].urls[0], st.url);

    let lt = c
        .local_tokens()
        .create(LocalTokenParams::new("Till 9").location("loc1").ttl_days(7))
        .await
        .unwrap();
    assert!(lt.token.starts_with("czl1."));
    assert_eq!(lt.stations.as_ref().unwrap().len(), 1);
    let m = cloud.state.lock().unwrap().mints.last().cloned().unwrap();
    assert_eq!(
        (m["ttl_days"].clone(), m["device_name"].clone()),
        (json!(7), json!("Till 9"))
    );
    assert!(c
        .local_tokens()
        .create(LocalTokenParams::new("x").ttl_days(31))
        .await
        .is_err());
    c.local_tokens().revoke(&lt.token_id).await.unwrap();
    assert_eq!(
        cloud.state.lock().unwrap().revoked,
        vec![lt.token_id.clone()]
    );
    let eps: Vec<LocalEndpoint> = c.local_endpoints().list(Some("loc1")).await.unwrap();
    assert_eq!(eps.len(), 1);
    assert_eq!(eps[0].port, 7443);
    assert!(local.store_error().is_none());
}

// ---- token store, refresh ----

fn tempdir() -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!(
        "catzprint-test-{}-{}",
        std::process::id(),
        uuid_like()
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn uuid_like() -> String {
    format!(
        "{:x}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    )
}

#[tokio::test]
async fn file_token_store() {
    let dir = tempdir();
    let path = dir.join("sub").join("tokens.json");
    let s = FileTokenStore::new(&path);
    assert!(s.load("a").await.unwrap().is_none());
    let exp = chrono::Utc::now() + chrono::Duration::hours(1);
    s.save(
        "a",
        &StoredToken {
            token: "czl1.a".into(),
            expires_at: Some(exp),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    s.save(
        "b",
        &StoredToken {
            token: "czl1.b".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let dmode = std::fs::metadata(path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dmode, 0o700);
    }
    let entries: Vec<_> = std::fs::read_dir(path.parent().unwrap()).unwrap().collect();
    assert_eq!(entries.len(), 1, "temporary files left behind");
    let got = FileTokenStore::new(&path).load("a").await.unwrap().unwrap();
    assert_eq!(got.token, "czl1.a");
    assert_eq!(got.expires_at, Some(exp));
    assert!(!std::fs::read_to_string(&path).unwrap().contains(API_KEY));
    // A corrupt file is reported on load and replaced on save.
    std::fs::write(&path, "{nope").unwrap();
    assert!(s.load("a").await.is_err());
    s.save(
        "a",
        &StoredToken {
            token: "czl1.c".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(s.load("a").await.unwrap().unwrap().token, "czl1.c");
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn token_store_survives_restart_and_refreshes() {
    let cloud = Cloud::start().await;
    cloud.set(|s| s.stations = json!([{"station_id": "st1", "local_enabled": true}]));
    let st = Station::start().await;
    let dir = tempdir();
    let store = FileTokenStore::new(dir.join("tokens.json"));
    let cfg = |c: LocalConfig| {
        pinned(&st, LocalMode::Local)(c.location_id("loc1").token_store(store.clone()))
    };

    let c1 = local_client(&cloud, cfg);
    c1.jobs().print_text("1", CreateJob::new()).await.unwrap();
    c1.close().await;
    assert_eq!(cloud.counts().0, 1);

    // Restart: the stored token is used, nothing is minted.
    let c2 = local_client(&cloud, cfg);
    c2.jobs().print_text("2", CreateJob::new()).await.unwrap();
    let key = c2.local().__store_key();
    c2.close().await;
    assert_eq!(cloud.counts().0, 1, "stored token not reused");

    // Less than 7 days left: the old token is used now and a new one is
    // minted in the background.
    let mut old = store.load(&key).await.unwrap().unwrap();
    old.expires_at = Some(chrono::Utc::now() + chrono::Duration::days(3));
    store.save(&key, &old).await.unwrap();
    let c3 = local_client(&cloud, cfg);
    c3.jobs().print_text("3", CreateJob::new()).await.unwrap();
    assert_eq!(
        st.job_requests().last().unwrap().auth,
        format!("Bearer {}", old.token)
    );
    c3.local().__wait_background().await;
    assert_eq!(cloud.counts().0, 2, "want a background re-mint");
    let renewed = store.load(&key).await.unwrap().unwrap();
    assert_ne!(renewed.token, old.token);
    assert!(renewed.expires_at.unwrap() - chrono::Utc::now() > chrono::Duration::days(20));

    // Expired: minted before the job.
    let mut expired = renewed.clone();
    expired.expires_at = Some(chrono::Utc::now() - chrono::Duration::minutes(1));
    store.save(&key, &expired).await.unwrap();
    let c4 = local_client(&cloud, cfg);
    c4.jobs().print_text("4", CreateJob::new()).await.unwrap();
    assert_ne!(
        st.job_requests().last().unwrap().auth,
        format!("Bearer {}", expired.token)
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn endpoint_list_refreshed_when_stale() {
    let cloud = Cloud::start().await;
    let st = Station::start().await;
    cloud.set(|s| s.stations = endpoint(&st));
    let c = local_client(&cloud, |c| c.mode(LocalMode::Local).discover(true));
    // First job: the mint brings the endpoint list, used right away.
    let job = c.jobs().print_text("x", CreateJob::new()).await.unwrap();
    assert_eq!(job.local.unwrap().station_url, st.url);
    assert_eq!(
        cloud.state.lock().unwrap().endpoints,
        0,
        "fresh list refreshed"
    );
    c.local().__advance_clock(Duration::from_secs(2 * 3600));
    c.jobs().print_text("y", CreateJob::new()).await.unwrap();
    c.local().__wait_background().await;
    assert_eq!(cloud.state.lock().unwrap().endpoints, 1);
}

#[tokio::test]
async fn background_refresh_stops_on_close_and_drop() {
    for use_close in [true, false] {
        let cloud = Cloud::start().await;
        let st = Station::start().await;
        let dir = tempdir();
        let store = FileTokenStore::new(dir.join("t.json"));
        let cfg = |c: LocalConfig| pinned(&st, LocalMode::Local)(c.token_store(store.clone()));
        let c = local_client(&cloud, cfg);
        c.jobs().print_text("1", CreateJob::new()).await.unwrap();
        let key = c.local().__store_key();
        c.close().await;
        let mut old = store.load(&key).await.unwrap().unwrap();
        old.expires_at = Some(chrono::Utc::now() + chrono::Duration::days(3));
        store.save(&key, &old).await.unwrap();
        cloud.set(|s| s.mint_delay = Duration::from_millis(400));
        let c = local_client(&cloud, cfg);
        c.jobs().print_text("2", CreateJob::new()).await.unwrap(); // starts a refresh
        if use_close {
            c.close().await;
        } else {
            drop(c);
        }
        tokio::time::sleep(Duration::from_millis(900)).await;
        let now = store.load(&key).await.unwrap().unwrap();
        assert_eq!(
            now.token, old.token,
            "close={use_close}: the refresh kept running"
        );
        let _ = std::fs::remove_dir_all(dir);
    }
}

// ---- timeouts, cancellation ----

#[tokio::test]
async fn station_timeout_after_delivery_never_falls_back() {
    // Before audit round 4 a timeout fell back to the cloud, which could
    // print the job twice: the station may have taken it.
    let cloud = Cloud::start().await;
    let st = Station::start().await;
    st.set(|s| s.delay = Duration::from_secs(10)); // the probes hang too
    let c = local_client(&cloud, |c| {
        pinned(&st, LocalMode::LocalFirst)(c.request_timeout(Duration::from_millis(200)))
    });
    let start = Instant::now();
    let e = c
        .jobs()
        .create(CreateJob::text("x").idempotency_key("slow-1"))
        .await
        .unwrap_err();
    assert!(e.is_outcome_unknown(), "{e:?}");
    assert_eq!(e.code(), Some("outcome_unknown"));
    assert_eq!(cloud.counts().1, 0, "never sent to the cloud");
    assert!(
        start.elapsed() < Duration::from_millis(6500),
        "timeout or probe budget not applied: {:?}",
        start.elapsed()
    );
}

#[tokio::test]
async fn connect_timeout_applies_to_unroutable_stations() {
    let cloud = Cloud::start().await;
    // 10.255.255.1 is private and (normally) unroutable: the connect hangs.
    let url = "https://10.255.255.1:7443".to_string();
    let fp = "ab".repeat(32);
    let c = local_client(&cloud, |c| {
        c.mode(LocalMode::LocalFirst)
            .station_url(&url)
            .fingerprint(&url, &fp)
            .connect_timeout(Duration::from_millis(200))
    });
    let start = Instant::now();
    let job = c.jobs().create(CreateJob::text("x")).await.unwrap();
    assert_eq!(job.via, Some(Via::Cloud));
    assert!(
        start.elapsed() < Duration::from_millis(1800),
        "{:?}",
        start.elapsed()
    );
}

#[tokio::test]
async fn cancellation_stops_without_fallback() {
    let cloud = Cloud::start().await;
    let st = Station::start().await;
    st.set(|s| s.delay = Duration::from_secs(5));
    let c = local_client(&cloud, |c| {
        pinned(&st, LocalMode::LocalFirst)(c.request_timeout(Duration::from_secs(10)))
    });
    c.local().token().await.unwrap();
    let start = Instant::now();
    let r = tokio::time::timeout(
        Duration::from_millis(150),
        c.jobs().create(CreateJob::text("x")),
    )
    .await;
    assert!(r.is_err(), "the create was cancelled");
    assert!(start.elapsed() < Duration::from_secs(1));
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(cloud.counts().1, 0, "a cancelled create must not fall back");
    assert_eq!(st.job_requests().len(), 1);
}

#[test]
fn station_unreachable_message() {
    let e = Error::StationUnreachable {
        attempts: vec![catzprint::StationAttempt {
            url: "https://10.0.0.5:7443".into(),
            error: Error::Connection {
                message: "connection refused".into(),
                timeout: false,
            },
        }],
        cloud_error: Some(Box::new(Error::Server(catzprint::ApiError {
            status: 503,
            code: "unavailable".into(),
            message: "Down.".into(),
            fields: Default::default(),
            retry_after: None,
        }))),
    };
    let s = e.to_string();
    assert!(
        s.contains("10.0.0.5")
            && s.contains("connection refused")
            && s.contains("cloud fallback failed"),
        "{s}"
    );
    assert!(e.is_station_unreachable());
    assert_eq!(e.code(), None);
}
