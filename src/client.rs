//! The async client.

use std::collections::VecDeque;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use reqwest::header::{ACCEPT, RETRY_AFTER, USER_AGENT as UA};
use serde_json::{json, Value};

use crate::core::{
    decide, field, file_name_of, job_with_events, list_field, parse_retry_after, seg, whole,
    with_idempotency, Attempt, ClientBuilder, CloudModeCreate, CloudNext, Config, Method, Request,
    Step, DUPLICATE_PAUSE, MAX_RESPONSE_BYTES, USER_AGENT,
};
use crate::error::{Error, Result};
use crate::models::{Job, JobPage, Key, Location, Printer, Template};
use crate::params::{Command, Content, CreateJob, ListJobs, Reprint, Sealer, WaitOptions};
use crate::seal;

/// One cloud create attempt in the local modes (see
/// `Jobs::create_cloud_once`).
#[cfg(feature = "local")]
pub(crate) enum CloudAttempt {
    /// The cloud answered: the job, or an error answer (4xx, 501…).
    Answered(Result<Box<Job>>),
    /// Certainly not delivered: connect/DNS/TLS errors, the organization
    /// lookup failed, or 502/503/504.
    NotDelivered(Error),
    /// Delivered without a usable answer (timeout, reset, unreadable or
    /// oversized answer, a redirect) or 500: the cloud may have the job.
    Ambiguous(Error),
}

/// The async CatzPrint client. Cheap to clone; clones share the connection
/// pool and the cached organization and server key.
///
/// ```no_run
/// # async fn run() -> catzprint::Result<()> {
/// use catzprint::{Client, CreateJob};
/// let client = Client::new("cz_test_...")?;
/// let job = client.jobs().print_text("Hello from Rust", CreateJob::new().role("receipt")).await?;
/// println!("{} is {}", job.id, job.status);
/// # Ok(()) }
/// ```
#[derive(Clone)]
pub struct Client {
    pub(crate) cfg: Arc<Config>,
    pub(crate) http: reqwest::Client,
    #[cfg(feature = "local")]
    pub(crate) local: Option<Arc<crate::local::LocalHandle>>,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.cfg.fmt(f)
    }
}

impl Client {
    /// A client with this API key and default settings.
    pub fn new(api_key: impl Into<String>) -> Result<Self> {
        Client::builder().api_key(api_key).build()
    }

    /// A client configured from `CATZPRINT_API_KEY` (and `CATZPRINT_BASE_URL`).
    pub fn from_env() -> Result<Self> {
        Client::builder().build()
    }

    /// A builder for custom settings.
    pub fn builder() -> ClientBuilder {
        ClientBuilder::default()
    }

    pub(crate) fn from_config(cfg: Config) -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(cfg.timeout)
            // Never follow redirects: the API key must only reach the configured host.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| Error::Config(format!("couldn't create the HTTP client: {e}")))?;
        Ok(Client {
            cfg: Arc::new(cfg),
            http,
            #[cfg(feature = "local")]
            local: None,
        })
    }

    #[cfg(feature = "local")]
    pub(crate) fn from_config_local(
        cfg: Config,
        local: Option<crate::local::LocalConfig>,
    ) -> Result<Self> {
        let mut c = Client::from_config(cfg)?;
        let handle = crate::local::LocalHandle::new(c.clone(), local.unwrap_or_default())?;
        c.local = Some(Arc::new(handle));
        Ok(c)
    }

    /// The API key in use: its organization, mode and scopes (`GET /v1/key`).
    /// Also caches the organization ID.
    pub async fn key(&self) -> Result<Key> {
        let req = Request::get("/v1/key");
        let url = req.url(&self.cfg.base_url, None);
        let key: Key = whole(self.send_to(&req, &url).await?)?;
        if !key.org_id.is_empty() {
            self.cfg.set_org(&key.org_id);
        }
        Ok(key)
    }

    /// Alias of [`Client::key`].
    pub async fn whoami(&self) -> Result<Key> {
        self.key().await
    }

    /// The organization ID: as configured, or looked up once with [`Client::key`].
    pub async fn org_id(&self) -> Result<String> {
        if let Some(o) = self.cfg.cached_org() {
            return Ok(o);
        }
        Ok(self.key().await?.org_id)
    }

    /// The server's X25519 public key for sealed content. Cached for an hour
    /// (the server may rotate it), and dropped at once when the API can't
    /// decrypt a sealed job.
    pub async fn server_key(&self) -> Result<[u8; 32]> {
        if let Some(k) = self.cfg.cached_server_key() {
            return Ok(k);
        }
        let gen = self.cfg.server_key_gen();
        let v = self
            .send(Request::get("/v1/public/server-key").public())
            .await?;
        let b64: String = field(v, "public_key")?;
        let k = seal::decode_public_key(&b64)?;
        self.cfg.set_server_key(k, gen);
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

    pub(crate) async fn send(&self, req: Request) -> Result<Value> {
        let org = if req.needs_org() {
            Some(self.org_id().await?)
        } else {
            None
        };
        let url = req.url(&self.cfg.base_url, org.as_deref());
        self.send_to(&req, &url).await
    }

    async fn send_to(&self, req: &Request, url: &str) -> Result<Value> {
        if req.auth && self.cfg.api_key.is_empty() {
            return Err(crate::core::missing_api_key());
        }
        let mut attempt = 0;
        loop {
            let mut rb = match req.method {
                Method::Get => self.http.get(url),
                Method::Post => self.http.post(url),
                Method::Delete => self.http.delete(url),
            }
            .header(ACCEPT, "application/json")
            .header(UA, USER_AGENT);
            if let Some(t) = req.timeout {
                rb = rb.timeout(t);
            }
            if !req.query.is_empty() {
                rb = rb.query(&req.query);
            }
            if req.auth {
                rb = rb.bearer_auth(&self.cfg.api_key);
            }
            if let Some(b) = &req.body {
                rb = rb.json(b);
            }
            // Whether a failed attempt may have reached the API.
            let mut maybe_sent = false;
            let outcome = match rb.send().await {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    let retry_after = parse_retry_after(
                        resp.headers()
                            .get(RETRY_AFTER)
                            .and_then(|v| v.to_str().ok()),
                    );
                    match read_limited(resp).await {
                        Ok(Some(body)) => Attempt::Response {
                            status,
                            retry_after,
                            body,
                        },
                        Ok(None) => Attempt::TooLarge,
                        Err(e) => {
                            maybe_sent = true;
                            Attempt::Network {
                                message: e.to_string(),
                                timeout: e.is_timeout(),
                            }
                        }
                    }
                }
                Err(e) => {
                    maybe_sent = !e.is_connect();
                    Attempt::Network {
                        message: e.to_string(),
                        timeout: e.is_timeout(),
                    }
                }
            };
            match decide(&self.cfg, req, attempt, outcome) {
                Step::Done(r) => return r,
                Step::Retry(wait) => {
                    req.note_retry(maybe_sent);
                    tokio::time::sleep(wait).await;
                    attempt += 1;
                }
            }
        }
    }
}

/// Print jobs: `client.jobs()`.
#[derive(Debug, Clone, Copy)]
pub struct Jobs<'a> {
    client: &'a Client,
}

impl<'a> Jobs<'a> {
    /// Creates a print job (`POST /v1/orgs/{org}/jobs`).
    ///
    /// An idempotency key is generated when you don't set one, so the request
    /// is retried safely; repeating a key returns the first job.
    ///
    /// With [`ClientBuilder::local`] in a mode other than
    /// [`LocalMode::Cloud`](crate::LocalMode::Cloud), the job goes to a
    /// station on the local network and/or the cloud as the mode says;
    /// [`Job::via`] tells which one took it. The fallback modes use the same
    /// idempotency key (`"sdk-<uuid v4>"` when you set none) for both, so a
    /// fallback never prints twice.
    pub async fn create(&self, params: CreateJob) -> Result<Job> {
        #[cfg(feature = "local")]
        if let Some(l) = self.client.local_state() {
            if l.mode() != crate::LocalMode::Cloud {
                return crate::local::create(self.client, l, params).await;
            }
        }
        self.create_cloud(with_idempotency(params)?, None).await
    }

    /// The JSON body of a cloud job (sealed when asked).
    async fn cloud_body(&self, params: &CreateJob) -> Result<Value> {
        let key = if params.sealed {
            Some(self.client.server_key().await?)
        } else {
            None
        };
        let sealer = key.map(|k| move |m: &[u8]| seal::seal(&k, m));
        params.to_body(sealer.as_ref().map(|f| f as Sealer<'_>))
    }

    /// Sends a job to the cloud. `once_within`: try once within this
    /// timeout instead of the client's retry policy.
    pub(crate) async fn create_cloud(
        &self,
        params: CreateJob,
        once_within: Option<std::time::Duration>,
    ) -> Result<Job> {
        let mut st = CloudModeCreate::new(
            params.sealed,
            &self.client.cfg.base_url,
            params.idempotency_key.as_deref().unwrap_or_default(),
        );
        let amb = st.ambiguous.clone();
        let request = move |body: Value| {
            #[allow(unused_mut)]
            let mut req = Request::post("/v1/orgs/{org}/jobs", body)
                .idempotent()
                .track_ambiguous(amb.clone());
            #[cfg(feature = "local")]
            if let Some(t) = once_within {
                req = req.once_within(t);
            }
            req
        };
        #[cfg(not(feature = "local"))]
        let _ = once_within;
        // Built (and sealed) once: retries and re-sends send the same bytes.
        let mut req = request(self.cloud_body(&params).await?);
        let v = loop {
            let err = match self.client.send(req.clone()).await {
                Ok(v) => break v,
                Err(e) => e,
            };
            match st.after(err) {
                CloudNext::Resend => tokio::time::sleep(DUPLICATE_PAUSE).await,
                CloudNext::Reseal(first) => {
                    // The API couldn't decrypt the sealed content (key
                    // rotated): fetch the key again, seal again, re-send once
                    // with the same idempotency key (S1).
                    self.client.cfg.drop_server_key();
                    match self.cloud_body(&params).await {
                        Ok(b) => req = request(b),
                        Err(fe) => return Err(st.key_fetch_failed(first, fe)),
                    }
                }
                CloudNext::Fail(e) => return Err(e),
            }
        };
        let mut job: Job = field(v, "job")?;
        job.via = Some(crate::models::Via::Cloud);
        Ok(job)
    }

    /// One cloud create for the local modes, classified like a station
    /// attempt: answered, certainly not delivered, or delivered without an
    /// answer (the cloud may have queued it). `timeout` bounds the whole
    /// attempt, the organization lookup included.
    /// The serialized (and sealed) body of a cloud job, built once per
    /// create so retries and re-sends carry the exact same bytes. Fails
    /// before anything is sent: a server-key fetch that fails is
    /// "not delivered" for the caller.
    #[cfg(feature = "local")]
    pub(crate) async fn cloud_job_bytes(&self, params: &CreateJob) -> Result<bytes::Bytes> {
        let v = self.cloud_body(params).await?;
        serde_json::to_vec(&v)
            .map(bytes::Bytes::from)
            .map_err(|e| Error::Decode(e.to_string()))
    }

    #[cfg(feature = "local")]
    pub(crate) async fn create_cloud_once(
        &self,
        body: &bytes::Bytes,
        timeout: Option<std::time::Duration>,
    ) -> CloudAttempt {
        use crate::local::transport::tracked_bytes;
        use std::sync::atomic::Ordering;
        let c = self.client;
        if c.cfg.api_key.is_empty() {
            return CloudAttempt::Answered(Err(crate::core::missing_api_key()));
        }
        let started = Instant::now();
        let org = match timeout {
            Some(t) => match tokio::time::timeout(t, c.org_id()).await {
                Ok(r) => r,
                Err(_) => Err(Error::Connection {
                    message: format!("the CatzPrint API didn't answer within {t:?}"),
                    timeout: true,
                }),
            },
            None => c.org_id().await,
        };
        let org = match org {
            Ok(o) => o,
            // The job wasn't sent: the organization lookup failed.
            Err(e @ (Error::Connection { .. } | Error::Server(_))) => {
                return CloudAttempt::NotDelivered(e)
            }
            Err(e) => return CloudAttempt::Answered(Err(e)),
        };
        let url = format!("{}/v1/orgs/{}/jobs", c.cfg.base_url, seg(&org));
        let (tracked, taken) = tracked_bytes(body.clone());
        let mut rb = c
            .http
            .post(&url)
            .header(ACCEPT, "application/json")
            .header(UA, USER_AGENT)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .bearer_auth(&c.cfg.api_key)
            .body(tracked);
        if let Some(t) = timeout {
            rb = rb.timeout(
                t.saturating_sub(started.elapsed())
                    .max(std::time::Duration::from_millis(1)),
            );
        }
        let net = |e: reqwest::Error| Error::Connection {
            message: e.to_string(),
            timeout: e.is_timeout(),
        };
        let resp = match rb.send().await {
            Ok(r) => r,
            Err(e) if taken.load(Ordering::SeqCst) => return CloudAttempt::Ambiguous(net(e)),
            Err(e) => return CloudAttempt::NotDelivered(net(e)),
        };
        let status = resp.status().as_u16();
        let retry_after = parse_retry_after(
            resp.headers()
                .get(RETRY_AFTER)
                .and_then(|v| v.to_str().ok()),
        );
        let body = match read_limited(resp).await {
            Ok(Some(b)) => b,
            Ok(None) => {
                return CloudAttempt::Ambiguous(Error::Decode(format!(
                    "the API response is larger than {MAX_RESPONSE_BYTES} bytes"
                )))
            }
            Err(e) => return CloudAttempt::Ambiguous(net(e)),
        };
        if (200..300).contains(&status) {
            let job = serde_json::from_slice::<Value>(&body)
                .map_err(|e| Error::Decode(e.to_string()))
                .and_then(|v| field::<Job>(v, "job"));
            return match job {
                Ok(job) if job.id.is_empty() => CloudAttempt::Ambiguous(Error::Decode(
                    "the API accepted the job but its answer has no job id".into(),
                )),
                Ok(mut job) => {
                    job.via = Some(crate::models::Via::Cloud);
                    CloudAttempt::Answered(Ok(Box::new(job)))
                }
                Err(e) => CloudAttempt::Ambiguous(e),
            };
        }
        let err = crate::error::map_error(status, retry_after, &body);
        match status {
            502..=504 => CloudAttempt::NotDelivered(err),
            // Any other 5xx (and a redirect): the cloud may have the job.
            500..=599 | 300..=399 => CloudAttempt::Ambiguous(err),
            _ => CloudAttempt::Answered(Err(err)),
        }
    }

    /// Prints plain text. `opts` sets the destination and other fields.
    pub async fn print_text(&self, text: impl Into<String>, opts: CreateJob) -> Result<Job> {
        self.create(opts.content(Content::Text(text.into()))).await
    }

    /// Prints a PDF from bytes.
    pub async fn print_pdf(&self, pdf: impl Into<Vec<u8>>, opts: CreateJob) -> Result<Job> {
        let opts = if opts.kind.is_none() {
            opts.kind("pdf")
        } else {
            opts
        };
        self.create(opts.content(Content::Bytes(pdf.into()))).await
    }

    /// Prints a PDF file; its file name becomes the title when none is set.
    pub async fn print_pdf_file(&self, path: impl AsRef<Path>, opts: CreateJob) -> Result<Job> {
        let (bytes, opts) = read_file(path.as_ref(), opts)?;
        self.print_pdf(bytes, opts).await
    }

    /// Prints a PNG or JPEG image from bytes.
    pub async fn print_image(&self, image: impl Into<Vec<u8>>, opts: CreateJob) -> Result<Job> {
        let opts = if opts.kind.is_none() {
            opts.kind("image")
        } else {
            opts
        };
        self.create(opts.content(Content::Bytes(image.into())))
            .await
    }

    /// Prints a PNG or JPEG file.
    pub async fn print_image_file(&self, path: impl AsRef<Path>, opts: CreateJob) -> Result<Job> {
        let (bytes, opts) = read_file(path.as_ref(), opts)?;
        self.print_image(bytes, opts).await
    }

    /// Prints a receipt described by commands.
    pub async fn print_receipt(&self, commands: Vec<Command>, opts: CreateJob) -> Result<Job> {
        self.create(opts.content(Content::Commands(commands))).await
    }

    /// Prints a saved template with data for its placeholders.
    pub async fn print_template(
        &self,
        template_id: impl Into<String>,
        data: Value,
        opts: CreateJob,
    ) -> Result<Job> {
        self.create(opts.content(Content::Template {
            id: template_id.into(),
            data,
        }))
        .await
    }

    /// Gets a job, with its status history in `events`. Local job IDs
    /// (`"lj_…"`, from a job a station took) are read from the station.
    pub async fn get(&self, id: &str) -> Result<Job> {
        #[cfg(feature = "local")]
        if id.starts_with("lj_") {
            if let Some(l) = self.client.local_state() {
                return crate::local::get_job(l, id).await;
            }
        }
        let mut job = job_with_events(
            self.client
                .send(Request::get(format!("/v1/orgs/{{org}}/jobs/{}", seg(id))))
                .await?,
        )?;
        job.via = Some(crate::models::Via::Cloud);
        Ok(job)
    }

    /// Lists one page of jobs, newest first. Use `next_cursor` for the next page,
    /// or [`Jobs::iter`] to walk every page.
    pub async fn list(&self, params: ListJobs) -> Result<JobPage> {
        whole(
            self.client
                .send(Request::get("/v1/orgs/{org}/jobs").query(params.to_query()))
                .await?,
        )
    }

    /// Iterates over every matching job, fetching pages as needed.
    ///
    /// ```no_run
    /// # async fn run(client: catzprint::Client) -> catzprint::Result<()> {
    /// let mut it = client.jobs().iter(catzprint::ListJobs::new().limit(100));
    /// while let Some(job) = it.try_next().await? {
    ///     println!("{} {}", job.id, job.status);
    /// }
    /// # Ok(()) }
    /// ```
    pub fn iter(&self, params: ListJobs) -> JobIter<'a> {
        JobIter {
            jobs: *self,
            params,
            buf: VecDeque::new(),
            done: false,
        }
    }

    /// Cancels a scheduled, held, queued or sent job.
    pub async fn cancel(&self, id: &str) -> Result<Job> {
        self.action(id, "cancel", json!({})).await
    }

    /// Retries a failed or held job.
    pub async fn retry(&self, id: &str) -> Result<Job> {
        self.action(id, "retry", json!({})).await
    }

    /// Prints a job again (as a new job), optionally elsewhere or with other copies.
    pub async fn reprint(&self, id: &str, params: Reprint) -> Result<Job> {
        let body = serde_json::to_value(params).map_err(|e| Error::Decode(e.to_string()))?;
        self.action(id, "reprint", body).await
    }

    async fn action(&self, id: &str, action: &str, body: Value) -> Result<Job> {
        let path = format!("/v1/orgs/{{org}}/jobs/{}/{action}", seg(id));
        field(self.client.send(Request::post(path, body)).await?, "job")
    }

    /// Polls a job until it is printed, failed or cancelled, and returns it.
    /// Returns [`Error::WaitTimeout`] when `opts.timeout` passes first.
    pub async fn wait_for(&self, id: &str, mut opts: WaitOptions) -> Result<Job> {
        if opts.interval.is_zero() {
            opts.interval = WaitOptions::default().interval; // never poll in a tight loop
        }
        let start = Instant::now();
        loop {
            let job = self.get(id).await?;
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
            tokio::time::sleep(opts.interval.min(opts.timeout - elapsed)).await;
        }
    }
}

/// Reads a response body, giving up (`None`) past [`MAX_RESPONSE_BYTES`].
async fn read_limited(mut resp: reqwest::Response) -> reqwest::Result<Option<Vec<u8>>> {
    if resp
        .content_length()
        .is_some_and(|n| n > MAX_RESPONSE_BYTES as u64)
    {
        return Ok(None);
    }
    let mut buf = Vec::new();
    while let Some(chunk) = resp.chunk().await? {
        if buf.len() + chunk.len() > MAX_RESPONSE_BYTES {
            return Ok(None);
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(Some(buf))
}

pub(crate) fn read_file(path: &Path, opts: CreateJob) -> Result<(Vec<u8>, CreateJob)> {
    let bytes = std::fs::read(path)?;
    let mut opts = opts;
    if opts.file_name.is_none() {
        opts.file_name = file_name_of(path);
    }
    if opts.title.is_none() {
        opts.title = file_name_of(path);
    }
    Ok((bytes, opts))
}

/// Walks every page of [`Jobs::list`]. Call [`JobIter::try_next`] until it gives `None`.
#[derive(Debug)]
pub struct JobIter<'a> {
    jobs: Jobs<'a>,
    params: ListJobs,
    buf: VecDeque<Job>,
    done: bool,
}

impl JobIter<'_> {
    /// The next job, fetching the next page when needed.
    pub async fn try_next(&mut self) -> Result<Option<Job>> {
        while self.buf.is_empty() && !self.done {
            let page = self.jobs.list(self.params.clone()).await?;
            self.buf.extend(page.items);
            match page.next_cursor {
                Some(c) => self.params.cursor = Some(c),
                None => self.done = true,
            }
        }
        Ok(self.buf.pop_front())
    }
}

/// Printers: `client.printers()`.
#[derive(Debug, Clone, Copy)]
pub struct Printers<'a> {
    client: &'a Client,
}

impl Printers<'_> {
    /// Lists the organization's printers.
    pub async fn list(&self) -> Result<Vec<Printer>> {
        list_field(
            self.client
                .send(Request::get("/v1/orgs/{org}/printers"))
                .await?,
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
    pub async fn list(&self) -> Result<Vec<Location>> {
        list_field(
            self.client
                .send(Request::get("/v1/orgs/{org}/locations"))
                .await?,
            "locations",
        )
    }

    /// Gets one location.
    pub async fn get(&self, id: &str) -> Result<Location> {
        let path = format!("/v1/orgs/{{org}}/locations/{}", seg(id));
        field(self.client.send(Request::get(path)).await?, "location")
    }
}

/// Receipt templates: `client.templates()`.
#[derive(Debug, Clone, Copy)]
pub struct Templates<'a> {
    client: &'a Client,
}

impl Templates<'_> {
    /// Lists the organization's templates (needs the `jobs:write` scope).
    pub async fn list(&self) -> Result<Vec<Template>> {
        list_field(
            self.client
                .send(Request::get("/v1/orgs/{org}/templates"))
                .await?,
            "templates",
        )
    }
}
