# Changelog

All notable changes to this crate are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the crate uses
[Semantic Versioning](https://semver.org/).

## [2.2.1] - 2026-11-07

Security audit round 7 (no API changes).

### Fixed

- A cloud `400`/`422` naming `sealed_content` (the server key was rotated) is no longer final: the SDK drops the cached server key, fetches it again, re-seals and re-sends **once** with the same idempotency key. After an ambiguous attempt (an answer lost, a retry in flight, a `409 duplicate`), a failed key fetch, or a re-send that is rejected again, not delivered or ambiguous, is `OutcomeUnknown` — never a validation error, never local. Without one, a repeated rejection is returned as the validation error. The async and blocking clients both do this.
- The server key is cached for at most an hour (and dropped at once on a `sealed_content` rejection).
- A station that answered the job request `409 in_progress` and then `404 not_found` to the probe by key is `OutcomeUnknown` (no next station, no cloud): the 404 only means "never recorded" when the request itself wasn't answered `in_progress`.
- `cloud_first`: jobs that can't print locally (sealed, PDF/image/document, scheduled) use the same create as cloud mode (the client's retries, the `409` re-sends, the re-seal), like the other SDKs.
- Stored token placeholders are recognised by the same set in every SDK: `…`, a run of 3+ `*`, `[redacted]`, `redacted`, `hidden` (any case), optionally after `czl1.` or `czd_`.
- A cloud `3xx` has the error code `unexpected_redirect` (was `error`).
- Once any answer for the key said `409 in_progress` (the job request or a probe by key), a later probe `404 not_found` is `OutcomeUnknown` (no next station, no cloud).
- A server-key fetch that was already in flight when a `sealed_content` rejection dropped the key no longer re-installs the dropped key.

## [2.2.0] - 2026-11-07

### Added

Local printing: print through the CatzPrint desktop station on the same network when the internet is down
(feature `local`, on by default; same behaviour as the Go and Node SDKs 2.2.0).

- `ClientBuilder::local(LocalConfig)` with `LocalMode::Cloud` (default, unchanged), `Local`, `LocalFirst` and
  `CloudFirst`. `LocalFirst` falls back to the cloud only when no station can be reached (connect/TLS/timeout,
  502/504, 503 `local_disabled` or a 503 without a code); `CloudFirst` tries the cloud once (within
  `cloud_timeout`) and falls back to the stations on a network error, timeout or 5xx. Printer errors,
  `no_printer`, validation errors, 402 `offline_allowance_exhausted`, 403, 409 and 429 are always returned,
  never retried elsewhere.
- The non-cloud modes always send an idempotency key (`sdk-<uuid v4>` when you don't set one) and use the same key
  for the station and the cloud.
- Local tokens are minted bound to `LocalConfig::location_id` (required unless `all_locations(true)`), cached in
  a `TokenStore` (`FileTokenStore`: mode 0600, atomic rename; `MemoryTokenStore`; or your own), renewed in the
  background when less than 7 days are left. A station's `401 token_expired` causes one re-mint and a retry, at
  most once per 10 minutes per store key (persisted); never on `device_revoked` or `unauthenticated`. The station
  endpoint list is cached with the token and refreshed hourly while online. `Client::close()` (or dropping the
  last clone) stops background refreshes.
- Discovery: configured station URLs, the cloud endpoint list (public hostnames first) and mDNS
  (`_catzprint._tcp`, a small built-in browser on tokio's `UdpSocket`).
- TLS: public-certificate hostnames only from the cloud endpoint list, verified with the web PKI **and** pinned to
  the list's `public_spki_sha256`, reached at the IP in a `a-b-c-d.<label>.<zone>` name only under that station's
  own label; IP and self-signed stations only with a pinned certificate SHA-256 (endpoint list or
  `LocalConfig::fingerprint`). Pins are checked by a rustls verifier during the handshake, so a mismatching
  station never receives the request. Only private addresses are used. mDNS only maps a station ID to an address
  for stations on the cloud list or with a configured fingerprint; the announced hostname is ignored.
- `client.local()`: `status`, `discover`, `info`, `pair(url, code, device_name, fingerprint)` (needs the
  fingerprint from the station app or a station on the cloud list), `get_job`, `refresh`, `token`,
  `store_error`; `client.local_tokens().create/revoke`; `client.local_endpoints().list`. `jobs().get` and
  `wait_for` read local job IDs (`lj_…`) from the station.
- A paired device (`LocalMode::Local` with a static `czd_` token) can be built without an API key; its cloud calls
  return `Error::Authentication` with code `missing_api_key`.
- `Job` gains `printed_locally`, `local_device`, `duplicate_of`, `offline`, `idempotency_key`, `via`
  (`Via::Local` / `Via::Cloud`, set by `jobs().create` and `jobs().get`) and `local` (the station's `LocalJob`).
  `LocalJob::live` maps to `Job::live`; paired-device jobs are live.
- Errors: `Error::Printer` (503 `printer_offline`, `out_of_paper`, `cover_open`, `printer_error`),
  `Error::StationUnreachable { attempts, cloud_error }` with `StationAttempt`, `Error::PinMismatch`; helpers
  `is_station_unreachable`, `is_printer_offline`, `is_out_of_paper`, `is_cover_open`,
  `is_offline_allowance_exhausted`, `station_attempts`, `cloud_error`. An API error's `param` now fills `fields`.
- New example: `examples/local_hub.rs`.

### Security (audit round 4)

- Never print twice when an answer is lost. A job that reached a station without an answer (timeout or reset
  after the request was sent, an unreadable or oversized answer, a redirect) is looked up on the same station by
  idempotency key (`GET /local/v1/jobs?idempotency_key=`, up to 3 times within 5 s, on fresh connections). The
  found job is returned. A `404` counts as not delivered (next station or cloud). Still no answer returns the new
  `Error::OutcomeUnknown { url, idempotency_key, cause }` (`is_outcome_unknown()`, code `outcome_unknown`), with no
  fallback. Only failures before the whole request was written, `502`/`504`, `503 local_disabled` and a `503`
  without a code still move on. In the cloud leg, a not-delivered attempt or `502`/`503`/`504` goes local in
  `CloudFirst` (in `LocalFirst`: `StationUnreachable`). A delivered-without-answer attempt or a `500` is retried
  once with the same key; ambiguous again returns `OutcomeUnknown`, never the stations. `CloudFirst` therefore no
  longer goes local on a `500`.
- Idempotency keys: an empty or whitespace-only key counts as no key. Keys with leading or trailing whitespace or
  control characters are refused with `Error::Validation` (field `idempotency_key`), in every mode and in the
  blocking client.
- `seal` refuses small-order X25519 public keys (all-zero shared secret) with `Error::Sealing`.
- `Debug` output of `StoredToken`, `LocalToken` and `LocalPairing` redacts the token (`LocalConfig` already did).
- Tokens are renewed when less than `min(7 days, TTL / 2)` is left. The TTL is read from the token's claims, so a
  1-day token is no longer renewed on every use.
- `FileTokenStore` (Unix) refuses an existing file or directory that another user owns or that is group- or
  world-writable (`PermissionDenied`, reported by `Local::store_error`; tokens stay in memory).

### Security (audit round 5)

- Probing a station by key: only `404` with code `not_found` counts as "never recorded" (a bare 404 from a proxy
  or an older station proves nothing → `OutcomeUnknown`). A `409 duplicate` (the key belongs to a job this caller
  can't see) is returned as that `Error::Conflict`, with no other station and no cloud.
- A cloud `409 duplicate` to a job create (the key's job is still being created) is re-sent after 1 s, identically,
  at most 3 times, in every mode and in the blocking client. Still `409` after that: the `Conflict` is returned. In
  the local modes a re-send that isn't delivered or is ambiguous returns `OutcomeUnknown`, never the stations.
- `LocalFirst` returns the cloud's own answer (e.g. `402`) when the stations were unreachable, instead of wrapping
  it in `StationUnreachable` (still used when the cloud didn't get the job).
- Every cloud 5xx other than `502`/`503`/`504` (and a 2xx without a job) is ambiguous: one retry with the same key.
- A station's 2xx without a job (empty or invalid body) is "delivered, no answer": the job is asked for by key.
- The token store's owner check uses the effective uid (unchanged; now tested). Dropping a call's future can't
  return `OutcomeUnknown`; the README says to retry with the same key.

### Security (audit round 6)

- A station's `409 in_progress` (it is still processing the key's POST) is treated as no answer yet. On the POST,
  the job is asked for by key; on the lookup, it is asked again within the 5 s budget. Then the result is
  `OutcomeUnknown`, never a fallback.
- Asking a station by key now repeats (up to 3 times) on any 4xx other than `404 not_found` and `409 duplicate`,
  instead of giving up at once.
- In the local modes the cloud job body is built and sealed once per create. The ambiguous retry and the `409`
  re-sends carry the exact same bytes (before, `CloudFirst` re-sealed on a retry). A failed server-key fetch for
  sealing counts as not delivered.
- Serde serialization of `StoredToken`, `LocalToken` and `LocalPairing` keeps the token (only `Debug` redacts). A
  stored token that is a redaction placeholder (`"****"`) is treated as no token and reported by
  `Local::store_error`.

### Dependencies

- `rustls` 0.23 (`ring`, `std`, `tls12`), `webpki-roots` 1, `http-body` 1 and `bytes` 1 become direct optional
  dependencies of the `local` feature, and `curve25519-dalek` 4 of the `sealed` feature. All of them were already in
  the dependency tree (through `reqwest`'s `rustls-tls` and `crypto_box`), at the same versions. The feature also
  enables tokio's `net`, `rt` and `sync`. No new crate is downloaded. Build with
  `default-features = false, features = ["sealed"]` to leave local printing out.

## [2.1.4] - 2026-10-20

### Documentation

- Docs only: the README explains that printer names aren't unique across stations, how to target printers by ID, and the console's copy-ID shortcut.

## [2.1.3] - 2026-10-17

### Security
- The base URL must use `https://`; `http://` is accepted only for `localhost`, `127.0.0.1`, `::1` and
  `*.localhost`, so the API key is never sent in clear text.
- Redirects are never followed, so the API key only reaches the configured host.
- Response bodies are capped at 64 MiB; a larger answer is an error.
- Webhook verification hardened: an empty secret is rejected and signatures are compared in constant time.
- `WebhookEvent::id`: the delivery id the server now includes in every signed event (`None` if absent).
  Deduplicate on `event.id`; the timestamp check limits the replay window to 5 minutes, it does not stop
  replays within it. The `webhooks::verify` docs no longer say the timestamp check stops replays.

## [1.0.0] - 2026-10-16

### Added
- Async `Client` (reqwest + rustls) and an optional `blocking::Client` (feature `blocking`).
- API key from code or `CATZPRINT_API_KEY`; base URL override (`CATZPRINT_BASE_URL`);
  organization looked up once with `GET /v1/key` (`client.key()` / `whoami()`) or set explicitly.
- Jobs: `create`, `get` (with status history), `list` + `iter` auto-pagination, `cancel`,
  `retry`, `reprint`, `wait_for`, and helpers `print_text`, `print_pdf(_file)`,
  `print_image(_file)`, `print_receipt`, `print_template`.
- Printers, locations (`list`, `get`) and templates (`list`).
- Typed models (`Job`, `Printer`, `Location`, `Template`, `Key`, `WebhookEvent`) that tolerate unknown fields.
- Receipt `Command` / `Column` builders.
- Client-side sealing of job content (NaCl sealed box to the server key, feature `sealed`, on by default).
- Retries with exponential backoff and jitter on network errors, 429 (honouring `Retry-After`) and 502/503/504;
  POSTs are retried only with an idempotency key, which `jobs.create` always sends.
- Error kinds: authentication, permission, not found, validation, out of prints, conflict,
  rate limit, server, connection, wait timeout, signature verification.
- Webhook verification (`webhooks::verify`, `construct_event`, `sign`) with constant-time comparison,
  timestamp tolerance and multiple `v1` signatures.
