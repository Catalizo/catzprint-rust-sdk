# Changelog

All notable changes to this crate are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the crate uses
[Semantic Versioning](https://semver.org/).

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
