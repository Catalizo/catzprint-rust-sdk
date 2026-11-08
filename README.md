# CatzPrint for Rust

The official Rust SDK for the [CatzPrint](https://catzprint.com) printing API. Send receipts, PDFs, images and
templates to printers attached to CatzPrint stations, follow jobs until they print, and verify webhooks.

- Async client on `reqwest` with rustls; optional blocking client.
- Typed models, typed errors, automatic retries with safe idempotency.
- Client-side sealed printing (NaCl sealed box), on by default.
- Local (offline) printing through the CatzPrint station on the same network, on by default.

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
| `local` | yes | [Local printing](#local-printing-offline) through stations on the LAN (`rustls` pinning, mDNS). Adds no crate that `reqwest` doesn't already pull in. |
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

Printer names aren't unique (two stations can each have a "Kitchen"), so target printers by ID. `client.printers().list()` returns each printer's `id`, `station_id`, `station_name`, `location_id` and `role`. Optional shortcut: in the CatzPrint console, open **Locations & stations** (**My devices** in a personal account), then a station, and click the ID under a printer's name to copy it.


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
| `Error::Printer` | a station's printer can't print: `printer_offline`, `out_of_paper`, `cover_open`, `printer_error` |
| `Error::StationUnreachable` | no station on the LAN could take the job (`station_attempts()`, `cloud_error()`) |
| `Error::PinMismatch` | a station's certificate isn't the pinned one (refused during the TLS handshake) |
| `Error::OutcomeUnknown` | a job reached a station or the cloud but no answer came: it may have printed; retry later with the same idempotency key (`is_outcome_unknown()`, code `outcome_unknown`) |
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

## Local printing (offline)

A restaurant must print when its internet is down. With `ClientBuilder::local`, the SDK sends jobs straight to the
CatzPrint Station (desktop or Android) on the same network (its local API on port 7443), and the station reports everything it
printed offline to the cloud when it's back: one job per idempotency key, billed, with webhooks
(`job.printed_locally`, `job.offline`, `job.duplicate_of`).

```rust
use catzprint::{Client, Column, Command, CreateJob, FileTokenStore, LocalConfig, LocalMode};
use serde_json::json;

let client = Client::builder() // API key from CATZPRINT_API_KEY, or .api_key(...)
    .local(
        LocalConfig::new(LocalMode::LocalFirst)
            .location_id(location_id)
            .discover(true) // the cloud's endpoint list + mDNS on the LAN
            .token_store(FileTokenStore::new("/var/lib/catzserve/catzprint-local.json"))
            .device_name("CatzServe hub"),
    )
    .build()?;

// A kitchen ticket: an inverted ALLERGY banner, then the order.
let job = client
    .jobs()
    .print_receipt(
        vec![
            Command::text(" ALLERGY: PEANUTS ").align("center").bold().invert().size(2),
            Command::text("Table 12").bold().size(2),
            Command::line(),
            Command::columns(vec![Column::new("2 x").width(0.15), Column::new("Pad thai").bold()]),
            Command::text("   no egg"),
            Command::cut(),
        ],
        CreateJob::new()
            .role("kitchen")
            .reference(format!("order-{order_id}"))
            // One key per ticket and attempt: the station and the cloud both dedupe on it,
            // so a fallback or a retry never prints twice.
            .idempotency_key(format!("order-{order_id}-kitchen-r1")),
    )
    .await?;

// Or a saved template with data (templates are synced to the station):
let job = client
    .jobs()
    .print_template(
        kitchen_template_id,
        json!({"table": "12", "items": items}),
        CreateJob::new().role("kitchen").idempotency_key(format!("order-{order_id}-kitchen-r1")),
    )
    .await?;
println!("{} {} {:?} {}", job.id, job.status, job.via, job.live); // lj_… queued Some(Local) true  (or … Some(Cloud))

client.close().await; // stops background token/endpoint refreshes (dropping the client does too)
```

See [`examples/local_hub.rs`](examples/local_hub.rs) for the complete hub.

### Modes

| Mode | Behaviour |
|---|---|
| `LocalMode::Cloud` (default) | Unchanged: every job goes to the API. |
| `LocalMode::Local` | Stations only. No station: `Error::StationUnreachable`. |
| `LocalMode::LocalFirst` | Stations first; the cloud **only** when no station can be reached. |
| `LocalMode::CloudFirst` | Cloud first (within `cloud_timeout`); stations only when the cloud certainly didn't get the job (connection error, `502`/`503`/`504`). A 4xx (validation, 401, 402, 429…) is returned, not retried locally. |

In `LocalFirst` the SDK falls back to the cloud only when the stations are **unreachable**: connection, DNS, TLS or
pin errors and anything else before the whole request was sent, `502`/`504`, `503 local_disabled` and a `503`
without an error code. A station that answers is never second-guessed: these are returned to you, never sent to the
cloud:

| Station answer | Rust |
|---|---|
| `503 printer_offline` / `out_of_paper` / `cover_open` / `printer_error` (not accepted, not counted) | `Error::Printer`; `is_printer_offline()`, `is_out_of_paper()`, `is_cover_open()` |
| `422 no_printer` / `invalid` / `unsupported_locally`, `400` | `Error::Validation` |
| `402 offline_allowance_exhausted` (offline too long / offline prints used) | `Error::OutOfPrints`; `is_offline_allowance_exhausted()` |
| `403 device_not_approved` / `forbidden_location` | `Error::Permission` |
| `409 duplicate`, `429 rate_limited` | `Error::Conflict`, `Error::RateLimit` |

A `401 token_expired` makes the SDK mint a fresh token once and retry the same station (at most once per 10 minutes).
Any other `401` (`device_revoked`, `unauthenticated`), or a token that can't be renewed because the cloud is down
too: `LocalFirst` uses the cloud and `Local` returns the `Error::Authentication`.

The non-cloud modes always send an idempotency key; when you don't set one the SDK uses `"sdk-<uuid v4>"` and sends
the **same** key to the station and the cloud. If a station printed a job and the cloud later gets the same key,
the cloud merges them instead of printing again. Use your own keys (like `order-1042-kitchen-r1`) so your own
retries are safe too.

### Never twice: when the answer is lost

A job POST answered `409 in_progress` (the station is still processing an earlier request with that key) is
handled the same way. A job request that **reached** a station but got no answer (a timeout or reset after the request was sent, an
unreadable, empty or oversized answer, a redirect) may have printed. The SDK then never sends it anywhere else straight
away. It asks the **same** station for the job by its idempotency key (`GET /local/v1/jobs?idempotency_key=…`, up to
3 times within 5 s, on fresh connections with the same pinning):

| The station says | Result |
|---|---|
| `200` with the job | That job is the result (`via: Local`). |
| `404` with code `not_found` (it never recorded it) | Treated as not delivered: the next station, then (in `LocalFirst`) the cloud. Once any answer for the key (the POST or an earlier probe) said `409 in_progress`, though, a `404` is `Error::OutcomeUnknown` (no next station, no cloud). |
| `409 duplicate` (the key belongs to a job you can't see) | That `Error::Conflict` is returned; no other station, no cloud. |
| `409 in_progress` (still processing the POST), another 4xx, a 5xx or no answer | Asked again (up to 3 times in 5 s). |
| Still no answer | `Error::OutcomeUnknown { url, idempotency_key, cause }`, with no fallback. |

The cloud follows the same rule (in `CloudFirst`, and as the cloud leg of `LocalFirst`). If the cloud certainly
didn't get the job (connection error, `502`/`503`/`504`), `CloudFirst` tries the stations and `LocalFirst` returns
`StationUnreachable` with the cloud error, and any other cloud answer (a 4xx such as `402`) is returned as is. A
timeout after the request was sent, a 2xx without a job, or a 5xx other than `502`/`503`/`504` is retried **once**
with the same key (the cloud dedupes on it). A `409 duplicate` (the key's job is still being created) is re-sent
after 1 s, at most 3 times, here and in cloud mode. The body is built (and sealed) once per create, so every
retry and re-send carries the exact same bytes. If that answers, its answer is the result. If it's ambiguous or not
delivered again, the result is `Error::OutcomeUnknown`. The SDK never falls back to the stations after an ambiguous
cloud attempt, because the cloud may already have queued the job for one of them.

A cloud `400`/`422` naming `sealed_content` (the server key was rotated) drops the cached server key, fetches it
again, re-seals and re-sends **once** with the same idempotency key (in every mode, async and blocking). After an
ambiguous attempt (an answer lost, a client retry, a `409`), a failed key fetch or a re-send that is rejected again,
not delivered or ambiguous is `Error::OutcomeUnknown` (never `Error::Validation`, never a station); without one, a
repeated rejection is returned as the `Error::Validation`.

Retrying with the same idempotency key is always safe: the stations and the cloud dedupe on it, so the job prints
at most once.

```rust
match client.jobs().create(params.clone().idempotency_key("order-1042-kitchen-r1")).await {
    Err(e) if e.is_outcome_unknown() => {
        // It may have printed: retry later with the SAME key (never a new one).
    }
    other => { /* … */ }
}
```

An idempotency key that is empty or only whitespace counts as no key (one is generated). A key with leading or
trailing whitespace or control characters is refused with `Error::Validation` (field `idempotency_key`) rather than
silently changed.

Jobs that can't print locally (PDFs, images, Office documents, sealed or scheduled jobs) go straight to the cloud
in `LocalFirst`/`CloudFirst`, through the same create as cloud mode (the client's retries, the `409` re-sends, the
re-seal), and return `Error::Validation` with code `unsupported_locally` in `Local` mode. When a
job sets neither a printer nor a location, `LocalConfig::location_id` is used.

```rust
use catzprint::Error;

match client.jobs().create(params).await {
    Ok(job) => println!("{} via {:?}", job.id, job.via),
    Err(e) if e.is_printer_offline() || e.is_out_of_paper() => {
        // tell the staff; send it again later with the same key
    }
    Err(e @ Error::StationUnreachable { .. }) => {
        for a in e.station_attempts() {
            eprintln!("tried {}: {}", a.url, a.error);
        }
        eprintln!("cloud: {:?}", e.cloud_error()); // the cloud error of a failed fallback
    }
    Err(e) => eprintln!("{e}"),
}
```

### Finding and trusting stations

Stations are tried in this order: `station_url(...)`s, then (with `discover(true)`) the URLs from the cloud's
endpoint list (public-certificate hostnames before raw IPs), then current addresses found over mDNS
(`_catzprint._tcp`), browsed only when the others failed.

- **Public hostnames** (`https://192-168-1-20.<label>.local.catzprint.com:7443`) come **only** from the cloud
  endpoint list. They carry a publicly trusted certificate, verified like any website (Mozilla roots from
  `webpki-roots`, or your own with `root_certificate(der)`), **and** the certificate's public key must match the
  `public_spki_sha256` the cloud reports. The SDK connects to the IP in the name directly (so they work while public
  DNS is down) only for names under that station's own label.
- **IP URLs** are trusted **only** with a pinned SHA-256 fingerprint of the station's self-signed certificate: from
  the cloud endpoint list or `fingerprint(url_or_host, sha256)` (the station app shows it). The check runs inside
  the TLS handshake, so a station with another certificate never receives a byte of the request
  (`Error::PinMismatch`). Only private addresses (RFC 1918, IPv6 ULA, link-local) are used. Nothing is trusted on
  first use.
- **mDNS is never trusted on its own.** It only maps a station ID to its current address, for a station on the
  cloud endpoint list (pinned with the list's fingerprint) or one whose announced fingerprint you configured with
  `fingerprint(...)`. The announced hostname is ignored. So a device on the LAN can't pose as your station, even
  with its own valid CatzPrint certificate.

The local token (`czl1…`) is minted with your API key (`POST /v1/orgs/{org}/local-tokens`, scope `jobs:write`) and
**bound to `location_id`** (required unless you set `all_locations(true)`). It is cached in the `TokenStore` with the
endpoint list, renewed in the background when it has less than `min(7 days, TTL / 2)` left, and the endpoint list is refreshed
hourly while online. A station's `401 token_expired` causes one fresh mint and a retry, at most once per 10 minutes
per device (remembered in the store); `401 device_revoked` (the device was revoked in the station app) is never
answered with a new token. `FileTokenStore::new(path)` writes the file with mode 0600 through an atomic rename. On
Unix it refuses an existing file or directory that another user owns or that is group- or world-writable: the store
then fails with `PermissionDenied` (`client.local().store_error()`) and tokens are kept in memory only. The default
store is in memory (`MemoryTokenStore`). Implement `TokenStore` to keep tokens elsewhere. Tokens never appear in
`Debug` output (`StoredToken`, `LocalToken`, `LocalPairing`, `LocalConfig`). Their serde serialization keeps the
token (it is what a store persists, and what a backend hands to a browser POS). A stored token that is a
redaction placeholder (`…`, a run of 3+ `*`, `[redacted]`, `redacted` or `hidden`, optionally after `czl1.`/`czd_`)
is treated as no token and reported by `store_error()`.

Timeouts: `connect_timeout` (3 s, TLS included), `request_timeout` (15 s), `cloud_timeout` (10 s: the cloud attempt
in `CloudFirst`, minting, refreshes), `discover_timeout` (1.5 s). `wait(d)` (up to 30 s) asks the station to answer
once the job printed or failed. Cancelling a call (dropping its future, e.g. with `tokio::time::timeout`) stops it
where it is: it never falls back afterwards. A dropped future can't return an error, so the SDK can't hand you an
`Error::OutcomeUnknown` for it. If the call was dropped after the job request may have been sent, treat it as an
unknown outcome yourself: the job may have printed, so retry later with the **same** idempotency key, never a new
one. Dropped before anything was sent, nothing was printed.

### Local helpers

```rust
use catzprint::{LocalConfig, LocalMode, LocalTokenParams};

let local = client.local();
let st = local.status().await?;               // printers, paper, unsynced jobs, offline allowance
let stations = local.discover().await?;       // endpoint list + mDNS, merged
let info = local.info(url).await?;            // GET /local/v1/info
let job = client.jobs().get("lj_…").await?;   // local job IDs are read from the station (wait_for works too)
local.refresh().await?;                       // renew token / endpoint list now
let tok = local.token().await?;               // the czl1 token, e.g. for a browser POS

// Pair a device with one station using the 8-digit code and the certificate fingerprint shown in the station
// app (or a station on the cloud endpoint list); the czd_ token works without any cloud account or API key.
let p = local.pair("https://192.168.1.20:7443", "12345678", "Till 3", Some("3f1a…")).await?;

// A paired till needs no API key: local mode with the device token.
let till = Client::builder()
    .local(
        LocalConfig::new(LocalMode::Local)
            .station_url("https://192.168.1.20:7443")
            .fingerprint("192.168.1.20", "3f1a…")
            .token(p.token),
    )
    .build()?;
// (its cloud calls return Error::Authentication with code missing_api_key)

let lt = client.local_tokens().create(LocalTokenParams::new("Till 3").location(loc).ttl_days(30)).await?;
client.local_tokens().revoke(&lt.token_id).await?;
let eps = client.local_endpoints().list(Some(loc)).await?;
```

Local printing needs the async client; `build_blocking()` refuses a local mode.

## Sealed printing

With `.sealed(true)` the SDK fetches the server's public key (`GET /v1/public/server-key`, cached for an hour), encrypts the
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
CATZPRINT_API_KEY=cz_live_... cargo run --example local_hub -- <location_id> [template_id]
```

## Development

```sh
cargo fmt --check
cargo clippy --all-features -- -D warnings
cargo test --all-features                                   # unit tests (fake HTTP server, pynacl check,
                                                            #   fake TLS station + cloud for local printing)
CATZPRINT_TEST_FIXTURE=fixture.json cargo test --all-features --test integration   # against a live API
```

The pynacl test proves sealed boxes open with libsodium; it is skipped when `python3` with `pynacl` isn't installed.

## License

MIT © Catalizo
