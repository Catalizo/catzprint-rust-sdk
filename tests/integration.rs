//! Integration tests against a live CatzPrint API.
//!
//! Run with `CATZPRINT_TEST_FIXTURE=/path/to/fixture.json cargo test`; they are
//! skipped when the variable isn't set. The fixture holds `base_url`, API keys,
//! printer IDs and a station `device_token` used to "play the station".

use std::time::Duration;

use catzprint::{Client, CreateJob, Error, JobStatus, ListJobs, WaitOptions};
use serde_json::Value;

struct Fixture(Value);

impl Fixture {
    fn load() -> Option<Fixture> {
        let path = std::env::var("CATZPRINT_TEST_FIXTURE")
            .ok()
            .filter(|p| !p.is_empty())?;
        let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
        Some(Fixture(
            serde_json::from_str(&raw).expect("fixture is JSON"),
        ))
    }
    fn s(&self, k: &str) -> String {
        self.0[k]
            .as_str()
            .unwrap_or_else(|| panic!("fixture has no {k}"))
            .to_string()
    }
    fn client(&self, key: &str) -> Client {
        Client::builder()
            .api_key(self.s(key))
            .base_url(self.s("base_url"))
            .build()
            .unwrap()
    }

    /// Plays the station: fetch pending jobs (marks them sent), then report `id` printed.
    async fn play_station(&self, id: &str) {
        let http = reqwest::Client::new();
        let base = self.s("base_url");
        let token = self.s("device_token");
        let res = http
            .get(format!("{base}/v1/device/jobs"))
            .bearer_auth(&token)
            .send()
            .await
            .unwrap();
        assert!(res.status().is_success(), "device jobs: {}", res.status());
        let res = http
            .post(format!("{base}/v1/device/jobs/{id}/status"))
            .bearer_auth(&token)
            .json(&serde_json::json!({"status": "printed"}))
            .send()
            .await
            .unwrap();
        assert!(
            res.status().is_success(),
            "device status: {} {}",
            res.status(),
            res.text().await.unwrap_or_default()
        );
    }
}

macro_rules! fixture {
    () => {
        match Fixture::load() {
            Some(f) => f,
            None => {
                eprintln!("skipping: CATZPRINT_TEST_FIXTURE isn't set");
                return;
            }
        }
    };
}

const WAIT: WaitOptions = WaitOptions {
    timeout: Duration::from_secs(30),
    interval: Duration::from_millis(500),
};

fn tiny_pdf() -> Vec<u8> {
    let objs = [
        "<< /Type /Catalog /Pages 2 0 R >>",
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
        "<< /Length 52 >>\nstream\nBT /F1 24 Tf 72 760 Td (CatzPrint Rust SDK) Tj ET\nendstream",
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ];
    let mut out = String::from("%PDF-1.4\n");
    let mut offsets = vec![];
    for (i, o) in objs.iter().enumerate() {
        offsets.push(out.len());
        out.push_str(&format!("{} 0 obj\n{o}\nendobj\n", i + 1));
    }
    let xref = out.len();
    out.push_str(&format!(
        "xref\n0 {}\n0000000000 65535 f \n",
        objs.len() + 1
    ));
    for off in offsets {
        out.push_str(&format!("{off:010} 00000 n \n"));
    }
    out.push_str(&format!(
        "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n",
        objs.len() + 1
    ));
    out.into_bytes()
}

#[tokio::test]
async fn key_returns_the_org() {
    let f = fixture!();
    let key = f.client("api_key_test").key().await.unwrap();
    assert_eq!(key.org_id, f.s("org_id"));
    assert!(!key.live);
    assert!(!key.org_name.is_empty());
    let live = f.client("api_key_live").whoami().await.unwrap();
    assert_eq!(live.org_id, f.s("org_id"));
    assert!(live.live);
}

#[tokio::test]
async fn test_key_text_job_prints_and_is_listed() {
    let f = fixture!();
    let c = f.client("api_key_test");
    let job = c
        .jobs()
        .print_text(
            "Hello from the CatzPrint Rust SDK",
            CreateJob::new()
                .printer(f.s("receipt_printer_id"))
                .title("Rust SDK test")
                .reference("rust-sdk"),
        )
        .await
        .unwrap();
    assert!(!job.live);
    assert_eq!(job.billed_as, "test");
    assert_eq!(
        job.printer_id.as_deref(),
        Some(f.s("receipt_printer_id").as_str())
    );

    f.play_station(&job.id).await;
    let done = c.jobs().wait_for(&job.id, WAIT).await.unwrap();
    assert_eq!(done.status, JobStatus::Printed);
    assert!(done.printed_at.is_some());
    assert!(!done.events.is_empty());

    // The list includes it (walk pages until found).
    let mut it = c.jobs().iter(ListJobs::new().limit(20));
    let mut found = false;
    for _ in 0..400 {
        match it.try_next().await.unwrap() {
            Some(j) if j.id == job.id => {
                found = true;
                break;
            }
            Some(_) => {}
            None => break,
        }
    }
    assert!(found, "job {} not in the list", job.id);
    let page = c
        .jobs()
        .list(ListJobs::new().q(&job.id).live(false))
        .await
        .unwrap();
    assert!(page.items.iter().any(|j| j.id == job.id));
}

#[tokio::test]
async fn live_key_sealed_pdf_to_office_printer() {
    let f = fixture!();
    let c = f.client("api_key_live");
    let job = c
        .jobs()
        .print_pdf(
            tiny_pdf(),
            CreateJob::new()
                .printer(f.s("office_printer_id"))
                .title("Rust SDK sealed PDF")
                .sealed(true),
        )
        .await
        .unwrap();
    assert!(job.live);
    assert_eq!(job.kind, "pdf");
    assert_ne!(job.billed_as, "test");
    f.play_station(&job.id).await;
    let done = c.jobs().wait_for(&job.id, WAIT).await.unwrap();
    assert_eq!(done.status, JobStatus::Printed);
}

#[tokio::test]
async fn scheduled_job_can_be_cancelled() {
    let f = fixture!();
    let c = f.client("api_key_test");
    let at = chrono::Utc::now() + chrono::Duration::hours(1);
    let job = c
        .jobs()
        .print_text(
            "Later",
            CreateJob::new()
                .printer(f.s("receipt_printer_id"))
                .scheduled_for(at),
        )
        .await
        .unwrap();
    assert_eq!(job.status, JobStatus::Scheduled);
    assert!(job.scheduled_for.is_some());
    let cancelled = c.jobs().cancel(&job.id).await.unwrap();
    assert_eq!(cancelled.status, JobStatus::Cancelled);
    // Cancelling again is a conflict.
    assert!(matches!(
        c.jobs().cancel(&job.id).await.unwrap_err(),
        Error::Conflict(_)
    ));
}

#[tokio::test]
async fn error_kinds_from_the_live_api() {
    let f = fixture!();
    let ro = f.client("api_key_printers_read_only");
    let e = ro
        .jobs()
        .print_text("nope", CreateJob::new().printer(f.s("receipt_printer_id")))
        .await
        .unwrap_err();
    assert!(matches!(e, Error::Permission(_)), "{e:?}");
    assert!(!ro.printers().list().await.unwrap().is_empty());

    let bad = Client::builder()
        .api_key("cz_live_thisKeyDoesNotExist0000000000000000000")
        .base_url(f.s("base_url"))
        .build()
        .unwrap();
    let e = bad.key().await.unwrap_err();
    assert!(matches!(e, Error::Authentication(_)), "{e:?}");

    let c = f.client("api_key_test");
    let e = c
        .jobs()
        .print_text(
            "x",
            CreateJob::new().printer("00000000-0000-4000-8000-000000000000"),
        )
        .await
        .unwrap_err();
    assert!(
        matches!(e, Error::Validation(_) | Error::NotFound(_)),
        "{e:?}"
    );
    assert!(e.fields().unwrap().contains_key("printer_id"));
    assert!(matches!(
        c.jobs()
            .get("00000000-0000-4000-8000-000000000000")
            .await
            .unwrap_err(),
        Error::NotFound(_)
    ));
}

#[tokio::test]
async fn idempotency_key_returns_the_same_job() {
    let f = fixture!();
    let c = f.client("api_key_test");
    let key = format!("rust-sdk-{}", uuid::Uuid::new_v4());
    let params = CreateJob::text("Once only")
        .printer(f.s("receipt_printer_id"))
        .idempotency_key(&key);
    let a = c.jobs().create(params.clone()).await.unwrap();
    let b = c.jobs().create(params).await.unwrap();
    assert_eq!(a.id, b.id);
}

#[tokio::test]
async fn reads_printers_locations_templates() {
    let f = fixture!();
    let c = f.client("api_key_live");
    let printers = c.printers().list().await.unwrap();
    assert!(printers.iter().any(|p| p.id == f.s("receipt_printer_id")));
    let locations = c.locations().list().await.unwrap();
    assert!(locations.iter().any(|l| l.id == f.s("location_id")));
    let loc = c.locations().get(&f.s("location_id")).await.unwrap();
    assert_eq!(loc.id, f.s("location_id"));
    c.templates().list().await.unwrap();
}
