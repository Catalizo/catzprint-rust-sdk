//! Unit tests of the async client against a local fake HTTP server:
//! headers, org lookup, error mapping, retries/backoff and idempotency.

mod common;

use std::time::{Duration, Instant};

use catzprint::{Client, Command, CreateJob, Error, JobStatus, ListJobs, Reprint, WaitOptions};
use common::{job_json, json, FakeServer, Reply, ORG};

fn client(url: &str) -> Client {
    Client::builder()
        .api_key("cz_test_abcdefghijklmnopqrstuvwxyz")
        .base_url(url)
        .org_id(ORG)
        .retry_base_delay(Duration::from_millis(10))
        .build()
        .unwrap()
}

fn created(id: &str) -> Reply {
    json(201, &format!(r#"{{"job":{}}}"#, job_json(id, "queued")))
}

#[tokio::test]
async fn sends_auth_user_agent_and_looks_up_org_once() {
    let srv = FakeServer::start(vec![
        json(
            200,
            &format!(
                r#"{{"id":"k1","org_id":"{ORG}","org_name":"Cat Café","live":false,"scopes":["*"]}}"#
            ),
        ),
        json(
            200,
            r#"{"printers":[{"id":"p1","name":"Front","capabilities":["escpos"],"unknown":1}]}"#,
        ),
        json(200, r#"{"locations":null}"#),
    ]);
    let c = Client::builder()
        .api_key("cz_test_abcdefghijklmnopqrstuvwxyz")
        .base_url(&srv.url)
        .build()
        .unwrap();
    let printers = c.printers().list().await.unwrap();
    assert_eq!(printers[0].name, "Front");
    assert!(c.locations().list().await.unwrap().is_empty());
    let reqs = srv.requests();
    assert_eq!(reqs.len(), 3, "org is cached after the first lookup");
    assert_eq!(reqs[0].path, "/v1/key");
    assert_eq!(reqs[1].path, format!("/v1/orgs/{ORG}/printers"));
    assert_eq!(
        reqs[1].headers["authorization"],
        "Bearer cz_test_abcdefghijklmnopqrstuvwxyz"
    );
    assert_eq!(reqs[1].headers["user-agent"], "catzprint-rust/2.1.3");
    assert!(
        !format!("{c:?}").contains("abcdefghijkl"),
        "Debug must redact the key"
    );
}

#[tokio::test]
async fn maps_api_errors() {
    let srv = FakeServer::start(vec![
        json(
            400,
            r#"{"error":{"code":"invalid","message":"Unknown printer.","fields":{"printer_id":"Unknown printer."}}}"#,
        ),
        json(
            403,
            r#"{"error":{"code":"forbidden","message":"This API key lacks the jobs:write scope."}}"#,
        ),
        json(
            401,
            r#"{"error":{"code":"invalid_api_key","message":"That API key isn't valid."}}"#,
        ),
        json(
            404,
            r#"{"error":{"code":"not_found","message":"Job not found."}}"#,
        ),
        json(
            402,
            r#"{"error":{"code":"out_of_prints","message":"No prints left."}}"#,
        ),
        json(
            409,
            r#"{"error":{"code":"invalid_state","message":"A printed job can't be changed this way."}}"#,
        ),
    ]);
    let c = client(&srv.url);
    let e = c
        .jobs()
        .print_text("x", CreateJob::new().printer("nope"))
        .await
        .unwrap_err();
    assert!(matches!(e, Error::Validation(_)), "{e:?}");
    assert_eq!(e.fields().unwrap()["printer_id"], "Unknown printer.");
    assert_eq!(e.status(), Some(400));
    let e = c
        .jobs()
        .print_text("x", CreateJob::new())
        .await
        .unwrap_err();
    assert!(matches!(e, Error::Permission(_)));
    let e = c.jobs().get("j").await.unwrap_err();
    assert!(matches!(e, Error::Authentication(_)));
    assert_eq!(e.code(), Some("invalid_api_key"));
    assert!(matches!(
        c.jobs().get("j").await.unwrap_err(),
        Error::NotFound(_)
    ));
    assert!(matches!(
        c.jobs()
            .print_text("x", CreateJob::new())
            .await
            .unwrap_err(),
        Error::OutOfPrints(_)
    ));
    assert!(matches!(
        c.jobs().cancel("j").await.unwrap_err(),
        Error::Conflict(_)
    ));
}

#[tokio::test]
async fn retries_gets_on_503_and_network_errors() {
    let srv = FakeServer::start(vec![
        json(503, r#"{"error":{"code":"unavailable","message":"Down."}}"#),
        Reply::Drop,
        json(
            200,
            &format!(
                r#"{{"job":{},"events":[{{"at":"2026-10-16T08:00:00Z","status":"queued","detail":"","actor":"API key"}}]}}"#,
                job_json("j1", "queued")
            ),
        ),
    ]);
    let c = client(&srv.url);
    let job = c.jobs().get("j1").await.unwrap();
    assert_eq!(job.events.len(), 1);
    assert_eq!(job.status, JobStatus::Queued);
    assert_eq!(srv.requests().len(), 3);
}

#[tokio::test]
async fn gives_up_after_two_retries() {
    let srv = FakeServer::start(vec![
        json(502, ""),
        json(504, ""),
        json(503, ""),
        created("never"),
    ]);
    let c = client(&srv.url);
    let e = c.jobs().get("j1").await.unwrap_err();
    assert!(matches!(e, Error::Server(_)), "{e:?}");
    assert_eq!(e.status(), Some(503));
    assert_eq!(srv.requests().len(), 3);
}

#[tokio::test]
async fn does_not_retry_500() {
    let srv = FakeServer::start(vec![
        json(500, r#"{"error":{"code":"internal","message":"Boom."}}"#),
        created("x"),
    ]);
    let e = client(&srv.url).jobs().get("j1").await.unwrap_err();
    assert!(matches!(e, Error::Server(_)));
    assert_eq!(srv.requests().len(), 1);
}

#[tokio::test]
async fn respects_retry_after_on_429() {
    let srv = FakeServer::start(vec![
        Reply::Json(
            429,
            vec![("Retry-After", "1".into())],
            r#"{"error":{"code":"rate_limited","message":"Slow down.","retry_after_seconds":1}}"#
                .into(),
        ),
        json(200, r#"{"templates":[]}"#),
    ]);
    let start = Instant::now();
    assert!(client(&srv.url)
        .templates()
        .list()
        .await
        .unwrap()
        .is_empty());
    assert!(
        start.elapsed() >= Duration::from_millis(950),
        "waited {:?}",
        start.elapsed()
    );
}

#[tokio::test]
async fn returns_rate_limit_when_retry_after_is_too_long() {
    let srv = FakeServer::start(vec![Reply::Json(
        429,
        vec![("Retry-After", "120".into())],
        r#"{"error":{"code":"rate_limited","message":"Slow down.","retry_after_seconds":120}}"#
            .into(),
    )]);
    let e = client(&srv.url).printers().list().await.unwrap_err();
    assert!(matches!(e, Error::RateLimit(_)));
    assert_eq!(e.retry_after(), Some(Duration::from_secs(120)));
    assert_eq!(srv.requests().len(), 1);
}

#[tokio::test]
async fn create_reuses_its_idempotency_key_across_retries() {
    let srv = FakeServer::start(vec![json(503, ""), Reply::Drop, created("j1")]);
    let job = client(&srv.url)
        .jobs()
        .print_receipt(
            vec![Command::text("Hi").bold(), Command::cut()],
            CreateJob::new().printer("p1"),
        )
        .await
        .unwrap();
    assert_eq!(job.id, "j1");
    let reqs = srv.requests();
    assert_eq!(reqs.len(), 3);
    let keys: Vec<String> = reqs
        .iter()
        .map(|r| r.json()["idempotency_key"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(keys[0].len(), 36, "a UUIDv4 is generated");
    assert!(
        keys.iter().all(|k| k == &keys[0]),
        "same key on every attempt: {keys:?}"
    );
    let body = reqs[0].json();
    assert_eq!(body["kind"], "commands");
    assert_eq!(body["printer_id"], "p1");
    assert_eq!(
        body["commands"][0],
        serde_json::json!({"type":"text","text":"Hi","bold":true})
    );
    assert_eq!(reqs[0].path, format!("/v1/orgs/{ORG}/jobs"));
}

#[tokio::test]
async fn keeps_a_caller_idempotency_key() {
    let srv = FakeServer::start(vec![created("j1")]);
    client(&srv.url)
        .jobs()
        .create(
            CreateJob::text("hi")
                .role("receipt")
                .idempotency_key("order-1042"),
        )
        .await
        .unwrap();
    let body = srv.requests()[0].json();
    assert_eq!(body["idempotency_key"], "order-1042");
    assert_eq!(body["content"], "hi");
    assert_eq!(body["kind"], "text");
}

#[tokio::test]
async fn never_retries_posts_without_idempotency_key() {
    let srv = FakeServer::start(vec![
        json(503, ""),
        json(200, &format!(r#"{{"job":{}}}"#, job_json("j", "cancelled"))),
    ]);
    let c = client(&srv.url);
    assert!(matches!(
        c.jobs().cancel("j").await.unwrap_err(),
        Error::Server(_)
    ));
    assert_eq!(srv.requests().len(), 1);

    let srv = FakeServer::start(vec![Reply::Drop, created("never")]);
    let e = client(&srv.url)
        .jobs()
        .reprint(
            "j",
            Reprint {
                copies: Some(2),
                ..Default::default()
            },
        )
        .await
        .unwrap_err();
    assert!(matches!(e, Error::Connection { .. }), "{e:?}");
    assert_eq!(srv.requests().len(), 1);
    assert_eq!(srv.requests()[0].json(), serde_json::json!({"copies": 2}));
}

#[tokio::test]
async fn connection_refused_is_a_connection_error() {
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let c = Client::builder()
        .api_key("cz_test_x")
        .base_url(format!("http://127.0.0.1:{port}"))
        .max_retries(0)
        .build()
        .unwrap();
    assert!(matches!(
        c.key().await.unwrap_err(),
        Error::Connection { .. }
    ));
}

#[cfg(feature = "sealed")]
#[tokio::test]
async fn sealed_job_fetches_and_caches_the_server_key() {
    let sk = crypto_box::SecretKey::from([9u8; 32]);
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::STANDARD;
    let pk = b64.encode(sk.public_key().as_bytes());
    let srv = FakeServer::start(vec![
        json(
            200,
            &format!(
                r#"{{"public_key":"{pk}","algorithm":"x25519-xsalsa20-poly1305-sealed-box"}}"#
            ),
        ),
        created("j1"),
        created("j2"),
    ]);
    let c = client(&srv.url);
    c.jobs()
        .print_pdf(
            b"%PDF-1.4 secret".to_vec(),
            CreateJob::new().printer("p").sealed(true),
        )
        .await
        .unwrap();
    c.jobs()
        .print_text("secret note", CreateJob::new().printer("p").sealed(true))
        .await
        .unwrap();
    let reqs = srv.requests();
    assert_eq!(reqs.len(), 3, "server key fetched once");
    assert_eq!(reqs[0].path, "/v1/public/server-key");
    assert!(!reqs[0].headers.contains_key("authorization"));
    for (req, plain, kind) in [
        (&reqs[1], &b"%PDF-1.4 secret"[..], "pdf"),
        (&reqs[2], &b"secret note"[..], "text"),
    ] {
        let body = req.json();
        assert_eq!(body["kind"], kind);
        assert!(body.get("content").is_none());
        let sealed = b64
            .decode(body["sealed_content"].as_str().unwrap())
            .unwrap();
        assert_eq!(sk.unseal(&sealed).unwrap(), plain);
    }
}

#[tokio::test]
async fn wait_for_polls_until_final_or_times_out() {
    let srv = FakeServer::start(vec![
        json(
            200,
            &format!(r#"{{"job":{},"events":[]}}"#, job_json("j", "queued")),
        ),
        json(
            200,
            &format!(r#"{{"job":{},"events":[]}}"#, job_json("j", "sent")),
        ),
        json(
            200,
            &format!(r#"{{"job":{},"events":[]}}"#, job_json("j", "printed")),
        ),
    ]);
    let opts = WaitOptions {
        timeout: Duration::from_secs(5),
        interval: Duration::from_millis(20),
    };
    let job = client(&srv.url).jobs().wait_for("j", opts).await.unwrap();
    assert_eq!(job.status, JobStatus::Printed);
    assert_eq!(srv.requests().len(), 3);

    let replies = (0..20)
        .map(|_| {
            json(
                200,
                &format!(r#"{{"job":{},"events":[]}}"#, job_json("j", "queued")),
            )
        })
        .collect();
    let srv = FakeServer::start(replies);
    let opts = WaitOptions {
        timeout: Duration::from_millis(100),
        interval: Duration::from_millis(30),
    };
    let e = client(&srv.url)
        .jobs()
        .wait_for("j", opts)
        .await
        .unwrap_err();
    assert!(
        matches!(e, Error::WaitTimeout { ref last_status, .. } if last_status == "queued"),
        "{e:?}"
    );
}

#[tokio::test]
async fn iterates_over_pages() {
    let page = |ids: &[&str], next: &str| {
        let items: Vec<String> = ids.iter().map(|i| job_json(i, "printed")).collect();
        json(
            200,
            &format!(
                r#"{{"items":[{}],"next_cursor":"{next}","counts":{{}}}}"#,
                items.join(",")
            ),
        )
    };
    let srv = FakeServer::start(vec![page(&["a", "b"], "CUR"), page(&["c"], "")]);
    let c = client(&srv.url);
    let mut it = c
        .jobs()
        .iter(ListJobs::new().limit(2).status(JobStatus::Printed));
    let mut ids = vec![];
    while let Some(j) = it.try_next().await.unwrap() {
        ids.push(j.id);
    }
    assert_eq!(ids, ["a", "b", "c"]);
    let reqs = srv.requests();
    assert_eq!(
        reqs[0].path,
        format!("/v1/orgs/{ORG}/jobs?status=printed&limit=2")
    );
    assert_eq!(
        reqs[1].path,
        format!("/v1/orgs/{ORG}/jobs?status=printed&cursor=CUR&limit=2")
    );
}

#[tokio::test]
async fn missing_api_key_is_a_config_error() {
    std::env::remove_var("CATZPRINT_API_KEY");
    assert!(matches!(
        Client::builder().build().unwrap_err(),
        Error::Config(_)
    ));
}

#[tokio::test]
async fn redirects_are_not_followed() {
    let target = FakeServer::start(vec![json(200, r#"{"printers":[]}"#)]);
    let srv = FakeServer::start(vec![Reply::Json(
        302,
        vec![("Location", format!("{}/steal", target.url))],
        String::new(),
    )]);
    let err = client(&srv.url).printers().list().await.unwrap_err();
    assert!(!matches!(err, Error::Decode(_)), "{err:?}");
    assert!(
        target.seen.lock().unwrap().is_empty(),
        "redirect was followed"
    );
}
