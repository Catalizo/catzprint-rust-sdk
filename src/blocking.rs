//! A synchronous client built on `reqwest::blocking` (feature `blocking`).
//!
//! It mirrors the async API one-to-one, minus the `.await`s:
//!
//! ```no_run
//! # fn main() -> catzprint::Result<()> {
//! use catzprint::{blocking::Client, CreateJob, WaitOptions};
//! let client = Client::new("cz_test_...")?;
//! let job = client.jobs().print_text("Hello", CreateJob::new().role("receipt"))?;
//! let done = client.jobs().wait_for(&job.id, WaitOptions::default())?;
//! println!("{}", done.status);
//! # Ok(()) }
//! ```
//!
//! Like `reqwest::blocking`, don't use it from inside an async runtime.

use std::collections::VecDeque;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use reqwest::header::{ACCEPT, RETRY_AFTER, USER_AGENT as UA};
use serde_json::{json, Value};

use crate::client::read_file;
use crate::core::{
    decide, field, job_with_events, list_field, parse_retry_after, seg, whole, with_idempotency,
    Attempt, ClientBuilder, Config, Method, Request, Step, MAX_RESPONSE_BYTES, USER_AGENT,
};
use crate::error::{Error, Result};
use crate::models::{Job, JobPage, Key, Location, Printer, Template};
use crate::params::{Command, Content, CreateJob, ListJobs, Reprint, Sealer, WaitOptions};
use crate::seal;

/// The blocking CatzPrint client. Cheap to clone.
#[derive(Clone)]
pub struct Client {
    cfg: Arc<Config>,
    http: reqwest::blocking::Client,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.cfg.fmt(f)
    }
}

impl Client {
    /// A client with this API key and default settings.
    pub fn new(api_key: impl Into<String>) -> Result<Self> {
        ClientBuilder::default().api_key(api_key).build_blocking()
    }

    /// A client configured from `CATZPRINT_API_KEY` (and `CATZPRINT_BASE_URL`).
    pub fn from_env() -> Result<Self> {
        ClientBuilder::default().build_blocking()
    }

    /// A builder for custom settings; finish with [`ClientBuilder::build_blocking`].
    pub fn builder() -> ClientBuilder {
        ClientBuilder::default()
    }

    pub(crate) fn from_config(cfg: Config) -> Result<Self> {
        let http = reqwest::blocking::Client::builder()
            .timeout(cfg.timeout)
            // Never follow redirects: the API key must only reach the configured host.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| Error::Config(format!("couldn't create the HTTP client: {e}")))?;
        Ok(Client {
            cfg: Arc::new(cfg),
            http,
        })
    }

    /// The API key in use (`GET /v1/key`). Also caches the organization ID.
    pub fn key(&self) -> Result<Key> {
        let req = Request::get("/v1/key");
        let url = req.url(&self.cfg.base_url, None);
        let key: Key = whole(self.send_to(&req, &url)?)?;
        if !key.org_id.is_empty() {
            self.cfg.set_org(&key.org_id);
        }
        Ok(key)
    }

    /// Alias of [`Client::key`].
    pub fn whoami(&self) -> Result<Key> {
        self.key()
    }

    /// The organization ID: as configured, or looked up once.
    pub fn org_id(&self) -> Result<String> {
        if let Some(o) = self.cfg.cached_org() {
            return Ok(o);
        }
        Ok(self.key()?.org_id)
    }

    /// The server's X25519 public key for sealed content (cached).
    pub fn server_key(&self) -> Result<[u8; 32]> {
        if let Some(k) = self.cfg.cached_server_key() {
            return Ok(k);
        }
        let v = self.send(Request::get("/v1/public/server-key").public())?;
        let b64: String = field(v, "public_key")?;
        let k = seal::decode_public_key(&b64)?;
        self.cfg.set_server_key(k);
        Ok(k)
    }

    /// Print jobs.
    pub fn jobs(&self) -> Jobs<'_> {
        Jobs { client: self }
    }

    /// Printers.
    pub fn printers(&self) -> Printers<'_> {
        Printers { client: self }
    }

    /// Locations.
    pub fn locations(&self) -> Locations<'_> {
        Locations { client: self }
    }

    /// Receipt templates.
    pub fn templates(&self) -> Templates<'_> {
        Templates { client: self }
    }

    fn send(&self, req: Request) -> Result<Value> {
        let org = if req.needs_org() {
            Some(self.org_id()?)
        } else {
            None
        };
        let url = req.url(&self.cfg.base_url, org.as_deref());
        self.send_to(&req, &url)
    }

    fn send_to(&self, req: &Request, url: &str) -> Result<Value> {
        let mut attempt = 0;
        loop {
            let mut rb = match req.method {
                Method::Get => self.http.get(url),
                Method::Post => self.http.post(url),
            }
            .header(ACCEPT, "application/json")
            .header(UA, USER_AGENT);
            if !req.query.is_empty() {
                rb = rb.query(&req.query);
            }
            if req.auth {
                rb = rb.bearer_auth(&self.cfg.api_key);
            }
            if let Some(b) = &req.body {
                rb = rb.json(b);
            }
            let outcome = match rb.send() {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    let retry_after = parse_retry_after(
                        resp.headers()
                            .get(RETRY_AFTER)
                            .and_then(|v| v.to_str().ok()),
                    );
                    match read_limited(resp) {
                        Ok(Some(body)) => Attempt::Response {
                            status,
                            retry_after,
                            body,
                        },
                        Ok(None) => Attempt::TooLarge,
                        Err(e) => Attempt::Network {
                            timeout: e
                                .get_ref()
                                .and_then(|i| i.downcast_ref::<reqwest::Error>())
                                .is_some_and(|r| r.is_timeout()),
                            message: e.to_string(),
                        },
                    }
                }
                Err(e) => Attempt::Network {
                    message: e.to_string(),
                    timeout: e.is_timeout(),
                },
            };
            match decide(&self.cfg, req, attempt, outcome) {
                Step::Done(r) => return r,
                Step::Retry(wait) => {
                    std::thread::sleep(wait);
                    attempt += 1;
                }
            }
        }
    }
}

/// Reads a response body, giving up (`None`) past [`MAX_RESPONSE_BYTES`].
fn read_limited(resp: reqwest::blocking::Response) -> std::io::Result<Option<Vec<u8>>> {
    use std::io::Read as _;
    if resp
        .content_length()
        .is_some_and(|n| n > MAX_RESPONSE_BYTES as u64)
    {
        return Ok(None);
    }
    let mut buf = Vec::new();
    resp.take(MAX_RESPONSE_BYTES as u64 + 1)
        .read_to_end(&mut buf)?;
    if buf.len() > MAX_RESPONSE_BYTES {
        return Ok(None);
    }
    Ok(Some(buf))
}

/// Print jobs: `client.jobs()`.
#[derive(Debug, Clone, Copy)]
pub struct Jobs<'a> {
    client: &'a Client,
}

impl<'a> Jobs<'a> {
    /// Creates a print job. See [`crate::Jobs::create`].
    pub fn create(&self, params: CreateJob) -> Result<Job> {
        let params = with_idempotency(params);
        let key = if params.sealed {
            Some(self.client.server_key()?)
        } else {
            None
        };
        let sealer = key.map(|k| move |m: &[u8]| seal::seal(&k, m));
        let body = params.to_body(sealer.as_ref().map(|f| f as Sealer<'_>))?;
        field(
            self.client
                .send(Request::post("/v1/orgs/{org}/jobs", body).idempotent())?,
            "job",
        )
    }

    /// Prints plain text.
    pub fn print_text(&self, text: impl Into<String>, opts: CreateJob) -> Result<Job> {
        self.create(opts.content(Content::Text(text.into())))
    }

    /// Prints a PDF from bytes.
    pub fn print_pdf(&self, pdf: impl Into<Vec<u8>>, opts: CreateJob) -> Result<Job> {
        let opts = if opts.kind.is_none() {
            opts.kind("pdf")
        } else {
            opts
        };
        self.create(opts.content(Content::Bytes(pdf.into())))
    }

    /// Prints a PDF file.
    pub fn print_pdf_file(&self, path: impl AsRef<Path>, opts: CreateJob) -> Result<Job> {
        let (bytes, opts) = read_file(path.as_ref(), opts)?;
        self.print_pdf(bytes, opts)
    }

    /// Prints a PNG or JPEG image from bytes.
    pub fn print_image(&self, image: impl Into<Vec<u8>>, opts: CreateJob) -> Result<Job> {
        let opts = if opts.kind.is_none() {
            opts.kind("image")
        } else {
            opts
        };
        self.create(opts.content(Content::Bytes(image.into())))
    }

    /// Prints a PNG or JPEG file.
    pub fn print_image_file(&self, path: impl AsRef<Path>, opts: CreateJob) -> Result<Job> {
        let (bytes, opts) = read_file(path.as_ref(), opts)?;
        self.print_image(bytes, opts)
    }

    /// Prints a receipt described by commands.
    pub fn print_receipt(&self, commands: Vec<Command>, opts: CreateJob) -> Result<Job> {
        self.create(opts.content(Content::Commands(commands)))
    }

    /// Prints a saved template.
    pub fn print_template(
        &self,
        template_id: impl Into<String>,
        data: Value,
        opts: CreateJob,
    ) -> Result<Job> {
        self.create(opts.content(Content::Template {
            id: template_id.into(),
            data,
        }))
    }

    /// Gets a job with its status history.
    pub fn get(&self, id: &str) -> Result<Job> {
        job_with_events(
            self.client
                .send(Request::get(format!("/v1/orgs/{{org}}/jobs/{}", seg(id))))?,
        )
    }

    /// Lists one page of jobs.
    pub fn list(&self, params: ListJobs) -> Result<JobPage> {
        whole(
            self.client
                .send(Request::get("/v1/orgs/{org}/jobs").query(params.to_query()))?,
        )
    }

    /// Iterates over every matching job across pages.
    pub fn iter(&self, params: ListJobs) -> JobIter<'a> {
        JobIter {
            jobs: *self,
            params,
            buf: VecDeque::new(),
            done: false,
        }
    }

    /// Cancels a job.
    pub fn cancel(&self, id: &str) -> Result<Job> {
        self.action(id, "cancel", json!({}))
    }

    /// Retries a failed or held job.
    pub fn retry(&self, id: &str) -> Result<Job> {
        self.action(id, "retry", json!({}))
    }

    /// Prints a job again.
    pub fn reprint(&self, id: &str, params: Reprint) -> Result<Job> {
        let body = serde_json::to_value(params).map_err(|e| Error::Decode(e.to_string()))?;
        self.action(id, "reprint", body)
    }

    fn action(&self, id: &str, action: &str, body: Value) -> Result<Job> {
        let path = format!("/v1/orgs/{{org}}/jobs/{}/{action}", seg(id));
        field(self.client.send(Request::post(path, body))?, "job")
    }

    /// Polls until the job is printed, failed or cancelled.
    pub fn wait_for(&self, id: &str, mut opts: WaitOptions) -> Result<Job> {
        if opts.interval.is_zero() {
            opts.interval = WaitOptions::default().interval; // never poll in a tight loop
        }
        let start = Instant::now();
        loop {
            let job = self.get(id)?;
            if job.status.is_final() {
                return Ok(job);
            }
            let elapsed = start.elapsed();
            if elapsed >= opts.timeout {
                return Err(Error::WaitTimeout {
                    job_id: id.to_string(),
                    last_status: job.status.to_string(),
                });
            }
            std::thread::sleep(opts.interval.min(opts.timeout - elapsed));
        }
    }
}

/// Walks every page of jobs; an [`Iterator`] of `Result<Job>`.
#[derive(Debug)]
pub struct JobIter<'a> {
    jobs: Jobs<'a>,
    params: ListJobs,
    buf: VecDeque<Job>,
    done: bool,
}

impl Iterator for JobIter<'_> {
    type Item = Result<Job>;

    fn next(&mut self) -> Option<Self::Item> {
        while self.buf.is_empty() && !self.done {
            match self.jobs.list(self.params.clone()) {
                Ok(page) => {
                    self.buf.extend(page.items);
                    match page.next_cursor {
                        Some(c) => self.params.cursor = Some(c),
                        None => self.done = true,
                    }
                }
                Err(e) => {
                    self.done = true;
                    return Some(Err(e));
                }
            }
        }
        self.buf.pop_front().map(Ok)
    }
}

/// Printers: `client.printers()`.
#[derive(Debug, Clone, Copy)]
pub struct Printers<'a> {
    client: &'a Client,
}

impl Printers<'_> {
    /// Lists the organization's printers.
    pub fn list(&self) -> Result<Vec<Printer>> {
        list_field(
            self.client.send(Request::get("/v1/orgs/{org}/printers"))?,
            "printers",
        )
    }
}

/// Locations: `client.locations()`.
#[derive(Debug, Clone, Copy)]
pub struct Locations<'a> {
    client: &'a Client,
}

impl Locations<'_> {
    /// Lists the organization's locations.
    pub fn list(&self) -> Result<Vec<Location>> {
        list_field(
            self.client.send(Request::get("/v1/orgs/{org}/locations"))?,
            "locations",
        )
    }

    /// Gets one location.
    pub fn get(&self, id: &str) -> Result<Location> {
        let path = format!("/v1/orgs/{{org}}/locations/{}", seg(id));
        field(self.client.send(Request::get(path))?, "location")
    }
}

/// Receipt templates: `client.templates()`.
#[derive(Debug, Clone, Copy)]
pub struct Templates<'a> {
    client: &'a Client,
}

impl Templates<'_> {
    /// Lists the organization's templates.
    pub fn list(&self) -> Result<Vec<Template>> {
        list_field(
            self.client.send(Request::get("/v1/orgs/{org}/templates"))?,
            "templates",
        )
    }
}
