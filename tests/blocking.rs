//! The blocking client against the fake server.
#![cfg(feature = "blocking")]

mod common;

use std::time::Duration;

use catzprint::blocking::Client;
use catzprint::{CreateJob, Error, JobStatus, ListJobs, WaitOptions};
use common::{job_json, json, FakeServer, Reply, ORG};

fn client(url: &str) -> Client {
    Client::builder()
        .api_key("cz_test_abcdefghijklmnopqrstuvwxyz")
        .base_url(url)
        .retry_base_delay(Duration::from_millis(10))
        .build_blocking()
        .unwrap()
}

#[test]
fn blocking_create_retries_with_same_key_and_waits() {
    let srv = FakeServer::start(vec![
        json(
            200,
            &format!(
                r#"{{"id":"k","org_id":"{ORG}","org_name":"Cats","live":false,"scopes":["*"]}}"#
            ),
        ),
        json(503, ""),
        Reply::Drop,
        json(201, &format!(r#"{{"job":{}}}"#, job_json("j1", "queued"))),
        json(
            200,
            &format!(r#"{{"job":{},"events":[]}}"#, job_json("j1", "printed")),
        ),
    ]);
    let c = client(&srv.url);
    let job = c
        .jobs()
        .print_text("hello", CreateJob::new().role("receipt"))
        .unwrap();
    assert_eq!(job.id, "j1");
    let done = c
        .jobs()
        .wait_for(
            "j1",
            WaitOptions {
                timeout: Duration::from_secs(2),
                interval: Duration::from_millis(10),
            },
        )
        .unwrap();
    assert_eq!(done.status, JobStatus::Printed);
    let reqs = srv.requests();
    assert_eq!(reqs[0].path, "/v1/key");
    let keys: Vec<_> = reqs[1..4]
        .iter()
        .map(|r| r.json()["idempotency_key"].clone())
        .collect();
    assert!(keys.iter().all(|k| k == &keys[0] && k.is_string()));
}

#[test]
fn blocking_errors_and_iterator() {
    let srv = FakeServer::start(vec![
        json(
            200,
            &format!(
                r#"{{"id":"k","org_id":"{ORG}","org_name":"Cats","live":false,"scopes":["*"]}}"#
            ),
        ),
        json(403, r#"{"error":{"code":"forbidden","message":"No."}}"#),
        json(
            200,
            &format!(
                r#"{{"items":[{}],"next_cursor":"C"}}"#,
                job_json("a", "printed")
            ),
        ),
        json(500, r#"{"error":{"code":"internal","message":"Boom."}}"#),
    ]);
    let c = client(&srv.url);
    assert!(matches!(
        c.jobs().cancel("x").unwrap_err(),
        Error::Permission(_)
    ));
    let got: Vec<_> = c.jobs().iter(ListJobs::new()).collect();
    assert_eq!(got.len(), 2);
    assert_eq!(got[0].as_ref().unwrap().id, "a");
    assert!(matches!(got[1], Err(Error::Server(_))));
}
