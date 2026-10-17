//! Request parameters: jobs, receipt commands, list filters.

use std::time::Duration;

use base64::Engine as _;
use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use crate::error::{Error, Result};
use crate::models::JobStatus;

/// One receipt command (see the "Receipt commands" docs).
///
/// Build commands with the constructors and chain the style setters:
///
/// ```
/// use catzprint::{Command, Column};
/// let receipt = vec![
///     Command::text("Cat Café").align("center").bold().size(2),
///     Command::line(),
///     Command::columns(vec![Column::new("Latte"), Column::new("3.20").align("right")]),
///     Command::qr("https://example.com/r/1042"),
///     Command::cut(),
/// ];
/// # let _ = receipt;
/// ```
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Command {
    /// Command type: `text`, `feed`, `line`, `columns`, `barcode`, `qr`,
    /// `image`, `cut`, `drawer`, `beep` or `each` (templates).
    #[serde(rename = "type")]
    pub kind: String,
    /// Text to print (`text`).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub text: String,
    /// `left`, `center` or `right`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub align: String,
    /// Bold text.
    #[serde(default, skip_serializing_if = "is_false")]
    pub bold: bool,
    /// Underlined text.
    #[serde(default, skip_serializing_if = "is_false")]
    pub underline: bool,
    /// White on black.
    #[serde(default, skip_serializing_if = "is_false")]
    pub invert: bool,
    /// Text size 1–8, or QR module size 1–16.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub size: u32,
    /// Font `a` (default) or `b`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub font: String,
    /// Blank lines for `feed` (1–20).
    #[serde(default, skip_serializing_if = "is_zero")]
    pub lines: u32,
    /// Rule character for `line`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub char: String,
    /// Cells of a `columns` row.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub columns: Vec<Column>,
    /// Barcode format: `code128`, `ean13` or `code39`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub format: String,
    /// Barcode / QR data, or base64 PNG/JPEG for `image`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub data: String,
    /// Partial cut.
    #[serde(default, skip_serializing_if = "is_false")]
    pub partial: bool,
    /// Cash-drawer pin (2 or 5).
    #[serde(default, skip_serializing_if = "is_zero")]
    pub pin: u32,
    /// List path for `each` (templates), e.g. `"order.items"`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub items: String,
    /// Commands repeated by `each`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub commands: Vec<Command>,
}

/// One cell of a `columns` row.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Column {
    /// Cell text.
    pub text: String,
    /// Fraction of the line (0.5 = half); 0 shares what's left.
    #[serde(default, skip_serializing_if = "is_zero_f")]
    pub width: f64,
    /// `left`, `center` or `right`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub align: String,
    /// Bold cell.
    #[serde(default, skip_serializing_if = "is_false")]
    pub bold: bool,
}

fn is_false(b: &bool) -> bool {
    !*b
}
fn is_zero(n: &u32) -> bool {
    *n == 0
}
fn is_zero_f(n: &f64) -> bool {
    *n == 0.0
}

impl Column {
    /// A cell with text.
    pub fn new(text: impl Into<String>) -> Self {
        Column {
            text: text.into(),
            ..Default::default()
        }
    }
    /// Sets the width as a fraction of the line.
    pub fn width(mut self, width: f64) -> Self {
        self.width = width;
        self
    }
    /// Sets the alignment.
    pub fn align(mut self, align: impl Into<String>) -> Self {
        self.align = align.into();
        self
    }
    /// Makes the cell bold.
    pub fn bold(mut self) -> Self {
        self.bold = true;
        self
    }
}

impl Command {
    fn of(kind: &str) -> Self {
        Command {
            kind: kind.to_string(),
            ..Default::default()
        }
    }
    /// A line of text.
    pub fn text(text: impl Into<String>) -> Self {
        Command {
            text: text.into(),
            ..Command::of("text")
        }
    }
    /// Blank lines.
    pub fn feed(lines: u32) -> Self {
        Command {
            lines,
            ..Command::of("feed")
        }
    }
    /// A full-width rule.
    pub fn line() -> Self {
        Command::of("line")
    }
    /// A row of 1–6 cells.
    pub fn columns(columns: Vec<Column>) -> Self {
        Command {
            columns,
            ..Command::of("columns")
        }
    }
    /// A barcode (`code128` by default; set [`Command::format`]).
    pub fn barcode(data: impl Into<String>) -> Self {
        Command {
            data: data.into(),
            ..Command::of("barcode")
        }
    }
    /// A QR code.
    pub fn qr(data: impl Into<String>) -> Self {
        Command {
            data: data.into(),
            ..Command::of("qr")
        }
    }
    /// A PNG or JPEG image (raw bytes; sent as base64).
    pub fn image(bytes: &[u8]) -> Self {
        Command {
            data: base64::engine::general_purpose::STANDARD.encode(bytes),
            ..Command::of("image")
        }
    }
    /// A full cut (after feeding 3 lines).
    pub fn cut() -> Self {
        Command::of("cut")
    }
    /// A partial cut.
    pub fn partial_cut() -> Self {
        Command {
            partial: true,
            ..Command::of("cut")
        }
    }
    /// Opens the cash drawer.
    pub fn drawer() -> Self {
        Command::of("drawer")
    }
    /// Sounds the buzzer.
    pub fn beep() -> Self {
        Command::of("beep")
    }
    /// Repeats `commands` for every element at `items` (templates only).
    pub fn each(items: impl Into<String>, commands: Vec<Command>) -> Self {
        Command {
            items: items.into(),
            commands,
            ..Command::of("each")
        }
    }
    /// Sets the alignment.
    pub fn align(mut self, align: impl Into<String>) -> Self {
        self.align = align.into();
        self
    }
    /// Bold text.
    pub fn bold(mut self) -> Self {
        self.bold = true;
        self
    }
    /// Underlined text.
    pub fn underline(mut self) -> Self {
        self.underline = true;
        self
    }
    /// White-on-black text.
    pub fn invert(mut self) -> Self {
        self.invert = true;
        self
    }
    /// Text size (1–8) or QR module size (1–16).
    pub fn size(mut self, size: u32) -> Self {
        self.size = size;
        self
    }
    /// Font `a` or `b`.
    pub fn font(mut self, font: impl Into<String>) -> Self {
        self.font = font.into();
        self
    }
    /// Rule character for `line`.
    pub fn char(mut self, c: impl Into<String>) -> Self {
        self.char = c.into();
        self
    }
    /// Barcode format.
    pub fn format(mut self, format: impl Into<String>) -> Self {
        self.format = format.into();
        self
    }
    /// Cash-drawer pin.
    pub fn pin(mut self, pin: u32) -> Self {
        self.pin = pin;
        self
    }
}

/// The content of a job. Exactly one per job.
#[derive(Debug, Clone, PartialEq)]
pub enum Content {
    /// Plain text (kind `text`).
    Text(String),
    /// Receipt commands (kind `commands`).
    Commands(Vec<Command>),
    /// A saved template and the data for its placeholders (kind `template`).
    Template {
        /// Template ID.
        id: String,
        /// Placeholder data.
        data: Value,
    },
    /// File bytes: PDF, PNG/JPEG, raw ESC/POS or an Office document.
    /// The kind is detected from the bytes (or `file_name`) unless set.
    Bytes(Vec<u8>),
}

/// Encrypts content for the server (a sealed box).
pub(crate) type Sealer<'a> = &'a dyn Fn(&[u8]) -> Result<Vec<u8>>;

/// Parameters for [`crate::Jobs::create`].
///
/// ```
/// use catzprint::CreateJob;
/// let job = CreateJob::text("Table 4: 2x soup")
///     .role("kitchen")
///     .title("Order 1042")
///     .reference("1042")
///     .copies(2);
/// # let _ = job;
/// ```
#[derive(Debug, Clone, Default, PartialEq)]
pub struct CreateJob {
    /// Send to this printer.
    pub printer_id: Option<String>,
    /// Route to a printer at this location.
    pub location_id: Option<String>,
    /// Route to a printer with this role (`receipt`, `kitchen`, `office`…).
    pub role: Option<String>,
    /// Force a kind: `text`, `commands`, `template`, `escpos`, `image`, `pdf`, `document` or `test`.
    pub kind: Option<String>,
    /// The content.
    pub content: Option<Content>,
    /// File name, used to detect the document type.
    pub file_name: Option<String>,
    /// Title shown in the console (up to 200 characters).
    pub title: Option<String>,
    /// Your reference, e.g. an order number (up to 120 characters).
    pub reference: Option<String>,
    /// Copies, 1–50.
    pub copies: Option<u32>,
    /// Idempotency key; generated (UUIDv4) when not set so retries are safe.
    pub idempotency_key: Option<String>,
    /// Print later (at most 30 days ahead).
    pub scheduled_for: Option<DateTime<Utc>>,
    /// Extra options passed to the station.
    pub options: Option<Map<String, Value>>,
    /// Encrypt the content on this machine to the server's key (NaCl sealed box).
    pub sealed: bool,
}

impl CreateJob {
    /// Empty parameters; set a content source and a destination.
    pub fn new() -> Self {
        Self::default()
    }
    /// A plain-text job.
    pub fn text(text: impl Into<String>) -> Self {
        Self::new().content(Content::Text(text.into()))
    }
    /// A receipt-commands job.
    pub fn commands(commands: Vec<Command>) -> Self {
        Self::new().content(Content::Commands(commands))
    }
    /// A template job.
    pub fn template(template_id: impl Into<String>, data: Value) -> Self {
        Self::new().content(Content::Template {
            id: template_id.into(),
            data,
        })
    }
    /// A job from file bytes (PDF, image, ESC/POS, document).
    pub fn bytes(bytes: impl Into<Vec<u8>>) -> Self {
        Self::new().content(Content::Bytes(bytes.into()))
    }
    /// Sets the content.
    pub fn content(mut self, content: Content) -> Self {
        self.content = Some(content);
        self
    }
    /// Sends to a printer.
    pub fn printer(mut self, printer_id: impl Into<String>) -> Self {
        self.printer_id = Some(printer_id.into());
        self
    }
    /// Routes within a location.
    pub fn location(mut self, location_id: impl Into<String>) -> Self {
        self.location_id = Some(location_id.into());
        self
    }
    /// Routes by printer role.
    pub fn role(mut self, role: impl Into<String>) -> Self {
        self.role = Some(role.into());
        self
    }
    /// Forces the kind.
    pub fn kind(mut self, kind: impl Into<String>) -> Self {
        self.kind = Some(kind.into());
        self
    }
    /// Sets the file name.
    pub fn file_name(mut self, name: impl Into<String>) -> Self {
        self.file_name = Some(name.into());
        self
    }
    /// Sets the title.
    pub fn title(mut self, title: impl Into<String>) -> Self {
        self.title = Some(title.into());
        self
    }
    /// Sets your reference.
    pub fn reference(mut self, reference: impl Into<String>) -> Self {
        self.reference = Some(reference.into());
        self
    }
    /// Sets the number of copies.
    pub fn copies(mut self, copies: u32) -> Self {
        self.copies = Some(copies);
        self
    }
    /// Sets the idempotency key.
    pub fn idempotency_key(mut self, key: impl Into<String>) -> Self {
        self.idempotency_key = Some(key.into());
        self
    }
    /// Schedules the job.
    pub fn scheduled_for(mut self, at: DateTime<Utc>) -> Self {
        self.scheduled_for = Some(at);
        self
    }
    /// Sets station options.
    pub fn options(mut self, options: Map<String, Value>) -> Self {
        self.options = Some(options);
        self
    }
    /// Seals (encrypts) the content client-side.
    pub fn sealed(mut self, sealed: bool) -> Self {
        self.sealed = sealed;
        self
    }

    /// Builds the JSON body. `seal` encrypts bytes when `self.sealed` is set.
    /// The idempotency key must already be filled in.
    pub(crate) fn to_body(&self, seal: Option<Sealer<'_>>) -> Result<Value> {
        let b64 = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);
        let mut m = Map::new();
        let mut put = |k: &str, v: Value| {
            m.insert(k.to_string(), v);
        };
        if let Some(v) = &self.printer_id {
            put("printer_id", json!(v));
        }
        if let Some(v) = &self.location_id {
            put("location_id", json!(v));
        }
        if let Some(v) = &self.role {
            put("role", json!(v));
        }
        let mut kind = self.kind.clone();
        let sealer = if self.sealed {
            Some(seal.ok_or_else(|| Error::Sealing("no server key".into()))?)
        } else {
            None
        };
        match &self.content {
            Some(Content::Text(t)) => {
                kind.get_or_insert_with(|| "text".into());
                match sealer {
                    Some(s) => put("sealed_content", json!(b64(&s(t.as_bytes())?))),
                    None if kind.as_deref() == Some("text") => put("content", json!(t)),
                    None => put("content", json!(b64(t.as_bytes()))),
                }
            }
            Some(Content::Bytes(bytes)) => {
                if kind.is_none() {
                    kind = detect_kind(bytes, self.file_name.as_deref()).map(String::from);
                }
                match sealer {
                    Some(s) => put("sealed_content", json!(b64(&s(bytes)?))),
                    None if kind.as_deref() == Some("text") => {
                        put("content", json!(String::from_utf8_lossy(bytes)))
                    }
                    None => put("content", json!(b64(bytes))),
                }
            }
            Some(Content::Commands(cmds)) => {
                if self.sealed {
                    return Err(Error::Sealing(
                        "receipt commands can't be sealed; seal text or file content instead"
                            .into(),
                    ));
                }
                kind.get_or_insert_with(|| "commands".into());
                put(
                    "commands",
                    serde_json::to_value(cmds).map_err(|e| Error::Decode(e.to_string()))?,
                );
            }
            Some(Content::Template { id, data }) => {
                if self.sealed {
                    return Err(Error::Sealing("template jobs can't be sealed".into()));
                }
                kind.get_or_insert_with(|| "template".into());
                put("template_id", json!(id));
                if !data.is_null() {
                    put("data", data.clone());
                }
            }
            None => {}
        }
        if let Some(k) = kind {
            put("kind", json!(k));
        }
        if let Some(v) = &self.file_name {
            put("file_name", json!(v));
        }
        if let Some(v) = &self.title {
            put("title", json!(v));
        }
        if let Some(v) = &self.reference {
            put("reference", json!(v));
        }
        if let Some(v) = self.copies {
            put("copies", json!(v));
        }
        if let Some(v) = &self.idempotency_key {
            put("idempotency_key", json!(v));
        }
        if let Some(v) = &self.scheduled_for {
            put(
                "scheduled_for",
                json!(v.to_rfc3339_opts(SecondsFormat::Millis, true)),
            );
        }
        if let Some(v) = &self.options {
            put("options", Value::Object(v.clone()));
        }
        Ok(Value::Object(m))
    }
}

/// Detects a job kind from file bytes: PDF, PNG/JPEG, or (with a file name) a document.
pub(crate) fn detect_kind(bytes: &[u8], file_name: Option<&str>) -> Option<&'static str> {
    if bytes.starts_with(b"%PDF-") {
        Some("pdf")
    } else if bytes.starts_with(&[0x89, b'P', b'N', b'G']) || bytes.starts_with(&[0xff, 0xd8, 0xff])
    {
        Some("image")
    } else if file_name.is_some() {
        Some("document")
    } else {
        None
    }
}

/// Filters for [`crate::Jobs::list`].
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ListJobs {
    /// Only these statuses.
    pub status: Vec<JobStatus>,
    /// Only this printer.
    pub printer_id: Option<String>,
    /// Only this station.
    pub station_id: Option<String>,
    /// Only this location.
    pub location_id: Option<String>,
    /// Only this source (`api`, `console`…).
    pub source: Option<String>,
    /// Only live (`true`) or test (`false`) jobs.
    pub live: Option<bool>,
    /// Search reference, title or ID prefix.
    pub q: Option<String>,
    /// Only jobs created at or after this time.
    pub since: Option<DateTime<Utc>>,
    /// Page size, 1–200 (API default 50).
    pub limit: Option<u32>,
    /// Cursor from a previous page.
    pub cursor: Option<String>,
}

impl ListJobs {
    /// No filters.
    pub fn new() -> Self {
        Self::default()
    }
    /// Filter by status (call again to add more).
    pub fn status(mut self, status: JobStatus) -> Self {
        self.status.push(status);
        self
    }
    /// Filter by printer.
    pub fn printer(mut self, printer_id: impl Into<String>) -> Self {
        self.printer_id = Some(printer_id.into());
        self
    }
    /// Filter by location.
    pub fn location(mut self, location_id: impl Into<String>) -> Self {
        self.location_id = Some(location_id.into());
        self
    }
    /// Filter by station.
    pub fn station(mut self, station_id: impl Into<String>) -> Self {
        self.station_id = Some(station_id.into());
        self
    }
    /// Filter by source (`api`, `console`, `app`…).
    pub fn source(mut self, source: impl Into<String>) -> Self {
        self.source = Some(source.into());
        self
    }
    /// Live or test jobs only.
    pub fn live(mut self, live: bool) -> Self {
        self.live = Some(live);
        self
    }
    /// Search text.
    pub fn q(mut self, q: impl Into<String>) -> Self {
        self.q = Some(q.into());
        self
    }
    /// Created since.
    pub fn since(mut self, since: DateTime<Utc>) -> Self {
        self.since = Some(since);
        self
    }
    /// Page size.
    pub fn limit(mut self, limit: u32) -> Self {
        self.limit = Some(limit);
        self
    }
    /// Start from a cursor.
    pub fn cursor(mut self, cursor: impl Into<String>) -> Self {
        self.cursor = Some(cursor.into());
        self
    }

    pub(crate) fn to_query(&self) -> Vec<(String, String)> {
        let mut q = Vec::new();
        if !self.status.is_empty() {
            let s: Vec<&str> = self.status.iter().map(|s| s.as_str()).collect();
            q.push(("status".into(), s.join(",")));
        }
        let pairs = [
            ("printer_id", &self.printer_id),
            ("station_id", &self.station_id),
            ("location_id", &self.location_id),
            ("source", &self.source),
            ("q", &self.q),
            ("cursor", &self.cursor),
        ];
        for (k, v) in pairs {
            if let Some(v) = v {
                q.push((k.into(), v.clone()));
            }
        }
        if let Some(l) = self.live {
            q.push(("live".into(), l.to_string()));
        }
        if let Some(s) = self.since {
            q.push(("since".into(), s.to_rfc3339_opts(SecondsFormat::Secs, true)));
        }
        if let Some(l) = self.limit {
            q.push(("limit".into(), l.to_string()));
        }
        q
    }
}

/// Parameters for [`crate::Jobs::reprint`].
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct Reprint {
    /// Print on another printer (defaults to the original one).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub printer_id: Option<String>,
    /// Copies (defaults to the original count).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub copies: Option<u32>,
}

/// Options for [`crate::Jobs::wait_for`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WaitOptions {
    /// Give up after this long (default 60 s).
    pub timeout: Duration,
    /// Poll this often (default 1 s).
    pub interval: Duration,
}

impl Default for WaitOptions {
    fn default() -> Self {
        WaitOptions {
            timeout: Duration::from_secs(60),
            interval: Duration::from_secs(1),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_text_body() {
        let b = CreateJob::text("hi")
            .printer("p")
            .idempotency_key("k")
            .to_body(None)
            .unwrap();
        assert_eq!(
            b,
            json!({"printer_id":"p","kind":"text","content":"hi","idempotency_key":"k"})
        );
    }

    #[test]
    fn builds_pdf_and_commands_body() {
        let b = CreateJob::bytes(b"%PDF-1.4 x".to_vec())
            .to_body(None)
            .unwrap();
        assert_eq!(b["kind"], "pdf");
        assert_eq!(b["content"], "JVBERi0xLjQgeA==");
        let b = CreateJob::commands(vec![Command::text("A").bold(), Command::cut()])
            .to_body(None)
            .unwrap();
        assert_eq!(b["kind"], "commands");
        assert_eq!(
            b["commands"],
            json!([{"type":"text","text":"A","bold":true},{"type":"cut"}])
        );
        assert!(CreateJob::commands(vec![])
            .sealed(true)
            .to_body(None)
            .is_err());
    }

    #[test]
    fn list_query() {
        let q = ListJobs::new()
            .status(JobStatus::Queued)
            .status(JobStatus::Sent)
            .limit(5)
            .to_query();
        assert_eq!(
            q,
            vec![
                ("status".into(), "queued,sent".into()),
                ("limit".into(), "5".into())
            ]
        );
    }
}
