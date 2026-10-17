# CatzPrint for Rust

The official Rust SDK for the [CatzPrint](https://catzprint.com) printing API. Send receipts, PDFs, images and
templates to printers attached to CatzPrint stations, follow jobs until they print, and verify webhooks.

- Async client on `reqwest` with rustls; optional blocking client.
- Typed models, typed errors, automatic retries with safe idempotency.
- Client-side sealed printing (NaCl sealed box), on by default.

## Install

```toml
[dependencies]
catzprint = "1"
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

Features:

| Feature | Default | What it adds |
|---|---|---|
| `sealed` | yes | Encrypt job content on your machine before it is sent (`crypto_box`). |
| `blocking` | no | `catzprint::blocking::Client`, a synchronous client on `reqwest::blocking`. |

## Quickstart

```rust
use catzprint::{Client, CreateJob, WaitOptions};

#[tokio::main]
async fn main() -> catzprint::Result<()> {
    let client = Client::from_env()?; // reads CATZPRINT_API_KEY
    let job = client.jobs().print_text("Hello, printer!", CreateJob::new().role("receipt")).await?;
    let done = client.jobs().wait_for(&job.id, WaitOptions::default()).await?;
    println!("job {} is {}", done.id, done.status);
    Ok(())
}
```

## The client

```rust
use std::time::Duration;
use catzprint::Client;

let client = Client::new("cz_live_...")?;           // explicit key
let client = Client::from_env()?;                    // CATZPRINT_API_KEY (+ CATZPRINT_BASE_URL)
let client = Client::builder()
    .api_key("cz_live_...")
    .base_url("https://api-v1.catzprint.com")        // default; or CATZPRINT_BASE_URL
    .org_id("34c4671b-...")                          // optional: skips the GET /v1/key lookup
    .timeout(Duration::from_secs(30))                // per request (default 30 s)
    .max_retries(2)                                  // default 2
    .build()?;
```

Every key belongs to one organization. The client finds it with `GET /v1/key` the first time it needs it and caches
it. `Client` is cheap to clone and safe to share between tasks. Its `Debug` output never shows the API key.

### `key()` / `whoami()`

```rust
let key = client.key().await?;           // same as client.whoami()
println!("{} ({}) live={} scopes={:?}", key.org_name, key.org_id, key.live, key.scopes);
```

### `org_id()` and `server_key()`

```rust
let org = client.org_id().await?;        // cached after the first lookup
let pk: [u8; 32] = client.server_key().await?; // X25519 key used for sealing, cached
```

## Jobs

### `jobs().create(params)`

`CreateJob` takes a destination (`printer`, `location` and/or `role`), exactly one content source, and optional
fields.

```rust
use catzprint::{CreateJob, Content};
use chrono::{Duration, Utc};

let job = client.jobs().create(
    CreateJob::text("2x tomato soup\n1x bread")
        .role("kitchen")                     // or .printer(id) / .location(id)
        .title("Table 4")
        .reference("order-1042")
        .copies(2)
        .idempotency_key("order-1042-kitchen")   // generated when not set
        .scheduled_for(Utc::now() + Duration::minutes(20)),
).await?;
```

Content sources:

| Builder | Sent as | Kind |
|---|---|---|
| `CreateJob::text(s)` | `content` | `text` |
| `CreateJob::commands(vec![...])` | `commands` | `commands` |
| `CreateJob::template(id, data)` | `template_id` + `data` | `template` |
| `CreateJob::bytes(b)` (+ `.file_name("a.docx")`) | base64 `content` | detected: `pdf`, `image`, or `document` |
| any of text/bytes + `.sealed(true)` | `sealed_content` | as above |

Use `.kind("escpos")` to send raw ESC/POS bytes, or `.kind("test")` with no content for a test page.
`.options(map)` passes station options through.

### Helpers

```rust
use catzprint::{Command, Column, CreateJob};
use serde_json::json;

let to = CreateJob::new().printer("78f44a67-...");

client.jobs().print_text("Hello", to.clone()).await?;
client.jobs().print_pdf(std::fs::read("invoice.pdf")?, to.clone()).await?;
client.jobs().print_pdf_file("invoice.pdf", to.clone()).await?;   // title = file name
client.jobs().print_image(std::fs::read("logo.png")?, to.clone()).await?;
client.jobs().print_image_file("logo.png", to.clone()).await?;
client.jobs().print_receipt(vec![
    Command::text("Cat Café").align("center").bold().size(2),
    Command::line(),
    Command::columns(vec![Column::new("Latte").width(0.7), Column::new("3.20").align("right")]),
    Command::barcode("1042").format("code128"),
    Command::qr("https://example.com/r/1042").size(6),
    Command::cut(),
], to.clone()).await?;
client.jobs().print_template("tpl-id", json!({"order": {"number": 1042}}), to).await?;
```

`Command` has constructors for every command type (`text`, `feed`, `line`, `columns`, `barcode`, `qr`, `image`,
`cut`, `partial_cut`, `drawer`, `beep`, `each`) and setters for styles (`align`, `bold`, `underline`, `invert`,
`size`, `font`, `char`, `format`, `pin`).

### `jobs().get(id)`

```rust
let job = client.jobs().get(&id).await?;
for e in &job.events { println!("{:?} {} {}", e.at, e.status, e.detail); }
```

### `jobs().list(params)` and `jobs().iter(params)`

```rust
use catzprint::{JobStatus, ListJobs};

let page = client.jobs().list(ListJobs::new().status(JobStatus::Failed).limit(50)).await?;
if let Some(cursor) = page.next_cursor { /* ListJobs::new().cursor(cursor) */ }

let mut it = client.jobs().iter(ListJobs::new().printer("78f44a67-...").live(true));
while let Some(job) = it.try_next().await? {
    println!("{} {}", job.id, job.status);
}
```

Filters: `status` (repeatable), `printer`, `location`, `station`, `source`, `live`, `q` (reference, title or ID
prefix), `since`, `limit` (1–200), `cursor`.

### `jobs().cancel(id)`, `retry(id)`, `reprint(id, params)`

```rust
use catzprint::Reprint;

client.jobs().cancel(&id).await?;   // scheduled, held, queued or sent jobs
client.jobs().retry(&id).await?;    // failed or held jobs
client.jobs().reprint(&id, Reprint { printer_id: Some(other.into()), copies: Some(2) }).await?;
```

### `jobs().wait_for(id, opts)`

Polls until the job is `printed`, `failed` or `cancelled` and returns it.

```rust
use std::time::Duration;
use catzprint::{Error, WaitOptions};

let opts = WaitOptions { timeout: Duration::from_secs(60), interval: Duration::from_secs(1) }; // the defaults
match client.jobs().wait_for(&job.id, opts).await {
    Ok(job) => println!("{}", job.status),
    Err(Error::WaitTimeout { last_status, .. }) => println!("still {last_status}"),
    Err(e) => return Err(e),
}
```

Statuses: `Scheduled`, `Held`, `Queued`, `Sent`, `Printing`, `Printed`, `Failed`, `Cancelled`
(`JobStatus::is_final()` is true for the last three).

## Printers, locations, templates

```rust
for p in client.printers().list().await? { println!("{} {} {:?}", p.name, p.status, p.capabilities); }
for l in client.locations().list().await? { println!("{} ({} printers)", l.name, l.printers); }
let location = client.locations().get("aed7e3e8-...").await?;
for t in client.templates().list().await? { println!("{} v{}", t.name, t.version); }
```

## Errors

Every method returns `catzprint::Result<T>`. API failures keep the API's status, `code`, `message`, `fields` and
`retry_after` (`error.api_error()`, `error.status()`, `error.code()`, `error.fields()`, `error.retry_after()`).

| Variant | When |
|---|---|
| `Error::Authentication` | 401: missing, invalid, revoked or expired key |
| `Error::Permission` | 403: scope missing or action not allowed |
| `Error::NotFound` | 404 |
| `Error::Validation` | 400 / 422; `fields` says which field (e.g. `printer_id`) |
| `Error::OutOfPrints` | 402 or code `out_of_prints` |
| `Error::Conflict` | 409, e.g. cancelling a printed job |
| `Error::RateLimit` | 429; see `retry_after()` |
| `Error::Server` | 5xx |
| `Error::Api` | any other status (e.g. 410 `content_deleted`) |
| `Error::Connection` | network failure or timeout |
| `Error::WaitTimeout` | `wait_for` gave up |
| `Error::SignatureVerification` | a webhook didn't verify |

```rust
match client.jobs().print_text("hi", CreateJob::new().printer("nope")).await {
    Err(Error::Validation(e)) => eprintln!("{}: {:?}", e.message, e.fields),
    Err(Error::OutOfPrints(_)) => eprintln!("Top up your prints"),
    Err(e) => eprintln!("{e}"),
    Ok(job) => println!("{}", job.id),
}
```

## Retries and idempotency

The client retries up to 2 times (configurable) on network errors, 429 and 502/503/504, with exponential backoff
(500 ms, 1 s, … with jitter, capped at 30 s). On 429 it waits exactly what `Retry-After` / `retry_after_seconds`
asks for (if that is longer than the cap, the `RateLimit` error is returned instead).

POST requests are never retried unless they carry an idempotency key. `jobs().create` (and every `print_*` helper)
always sends one: yours, or a fresh UUIDv4. The same key is reused on every retry, so a job is never printed twice;
repeating a key later returns the first job. Use your own key (an order number) to make your own retries safe too.
`cancel`, `retry` and `reprint` are not retried.

## Sealed printing

With `.sealed(true)` the SDK fetches the server's public key (`GET /v1/public/server-key`, cached), encrypts the
content on your machine with a NaCl sealed box (X25519 + XSalsa20-Poly1305, libsodium-compatible) and sends only
`sealed_content`. Works for text and file content; commands and templates can't be sealed.

```rust
let job = client.jobs().print_pdf_file("payslip.pdf", CreateJob::new().printer(office).sealed(true)).await?;
```

You can also seal yourself: `catzprint::seal(&public_key, bytes)` or `catzprint::seal_base64_key(b64, bytes)`.

## Webhooks

Deliveries carry `CatzPrint-Signature: t=<unix>,v1=<hex HMAC-SHA256(secret, t + "." + body)>`. Verify the **raw**
body:

```rust
use catzprint::webhooks;

let event = webhooks::verify(body_bytes, signature_header, "whsec_...", webhooks::DEFAULT_TOLERANCE)?;
let event = webhooks::construct_event(body_bytes, signature_header, "whsec_...")?; // 300 s tolerance
if event.event_type == "job.printed" {
    let job = event.job().unwrap();
}
```

Comparison is constant-time, timestamps outside the tolerance are rejected and several `v1=` entries (secret
rotation) are accepted. `webhooks::sign(secret, t, body)` builds a header for your tests.

Every event carries `event.id`, the delivery id, which stays the same across retries. **Deduplicate on
`event.id`**: the timestamp check limits the replay window to 5 minutes, it does not stop a captured delivery
from being replayed within that window (and retries can deliver the same event twice).

### axum

```rust
use axum::{body::Bytes, http::{HeaderMap, StatusCode}, routing::post, Router};
use catzprint::webhooks;

async fn catzprint_webhook(headers: HeaderMap, body: Bytes) -> StatusCode {
    let secret = std::env::var("CATZPRINT_WEBHOOK_SECRET").unwrap_or_default();
    let sig = headers.get(webhooks::SIGNATURE_HEADER).and_then(|v| v.to_str().ok()).unwrap_or("");
    match webhooks::construct_event(&body, sig, &secret) {
        Ok(event) => {
            match event.event_type.as_str() {
                "job.printed" => { /* mark the order printed */ }
                "job.failed" => { /* alert someone */ }
                _ => {}
            }
            StatusCode::OK
        }
        Err(_) => StatusCode::BAD_REQUEST,
    }
}

let app = Router::new().route("/webhooks/catzprint", post(catzprint_webhook));
```

Events: `job.created`, `job.printed`, `job.failed`, `job.cancelled`, `job.retried`, `station.online`,
`station.offline`, `printer.status`.

## Test and live keys

- `cz_test_…` keys create test jobs: `job.live == false`, `billed_as == "test"`. They go to real printers but are
  never billed, and can only cancel, retry or reprint test jobs.
- `cz_live_…` keys create billed jobs. Running out of prints gives `Error::OutOfPrints`.

## Blocking client

```toml
catzprint = { version = "1", features = ["blocking"] }
```

```rust
use catzprint::{blocking::Client, CreateJob, ListJobs};

let client = Client::from_env()?;
let job = client.jobs().print_text("Hello", CreateJob::new().role("receipt"))?;
for job in client.jobs().iter(ListJobs::new().limit(100)) {
    println!("{}", job?.id);
}
```

Same methods as the async client, without `.await`; `jobs().iter()` is a regular `Iterator`. Don't call it from
inside an async runtime.

## Examples

```sh
CATZPRINT_API_KEY=cz_test_... cargo run --example print_receipt [printer_id]
CATZPRINT_API_KEY=cz_live_... cargo run --example print_pdf_and_wait -- invoice.pdf <printer_id>
CATZPRINT_WEBHOOK_SECRET=whsec_... cargo run --example verify_webhook   # add -- --self-test for a demo
```

## Development

```sh
cargo fmt --check
cargo clippy --all-features -- -D warnings
cargo test --all-features                                   # unit tests (fake HTTP server, pynacl check)
CATZPRINT_TEST_FIXTURE=fixture.json cargo test --all-features --test integration   # against a live API
```

The pynacl test proves sealed boxes open with libsodium; it is skipped when `python3` with `pynacl` isn't installed.

## License

MIT © Catalizo
