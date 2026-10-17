//! Typed API models. Unknown fields are ignored, so newer API versions keep working.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Where a job is in its life.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum JobStatus {
    /// Waiting for its `scheduled_for` time.
    Scheduled,
    /// Held because its printer, station or location is turned off.
    Held,
    /// Waiting for the station to pick it up.
    Queued,
    /// Delivered to the station.
    Sent,
    /// The station is printing it.
    Printing,
    /// Printed (final).
    Printed,
    /// Failed (final); see `status_detail`.
    Failed,
    /// Cancelled (final).
    Cancelled,
    /// A status this SDK version doesn't know yet.
    #[serde(other)]
    #[default]
    Unknown,
}

impl JobStatus {
    /// The status as the API spells it.
    pub fn as_str(&self) -> &'static str {
        match self {
            JobStatus::Scheduled => "scheduled",
            JobStatus::Held => "held",
            JobStatus::Queued => "queued",
            JobStatus::Sent => "sent",
            JobStatus::Printing => "printing",
            JobStatus::Printed => "printed",
            JobStatus::Failed => "failed",
            JobStatus::Cancelled => "cancelled",
            JobStatus::Unknown => "unknown",
        }
    }

    /// Whether the job is finished: printed, failed or cancelled.
    pub fn is_final(&self) -> bool {
        matches!(
            self,
            JobStatus::Printed | JobStatus::Failed | JobStatus::Cancelled
        )
    }
}

impl std::fmt::Display for JobStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A print job.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Job {
    /// Job ID (UUID).
    pub id: String,
    /// `false` for unbilled test jobs (made with a `cz_test_` key).
    pub live: bool,
    /// Where the job came from: `api`, `console`, `app`, `reprint`, `playground`…
    pub source: String,
    /// What the station prints: `escpos`, `pdf`, `image`, `text`…
    pub kind: String,
    /// Current status.
    pub status: JobStatus,
    /// Extra detail about the status (e.g. why it failed or is held).
    pub status_detail: String,
    /// Title shown in the console.
    pub title: String,
    /// Your own reference (order number…).
    pub reference: String,
    /// Number of copies.
    pub copies: u32,
    /// Printer the job was routed to.
    pub printer_id: Option<String>,
    /// That printer's name.
    pub printer_name: Option<String>,
    /// Station (computer or phone) the printer is attached to.
    pub station_id: Option<String>,
    /// That station's name.
    pub station_name: Option<String>,
    /// Location of the station.
    pub location_id: Option<String>,
    /// That location's name.
    pub location_name: Option<String>,
    /// Size of the rendered content in bytes.
    pub size: i64,
    /// Delivery attempts so far.
    pub attempts: u32,
    /// How the job was billed: `"plan"`, `"test"`…
    pub billed_as: String,
    /// Email of the person who created it (none for API keys).
    pub created_by: Option<String>,
    /// The job this one reprints.
    pub reprint_of: Option<String>,
    /// When a scheduled job will be released.
    pub scheduled_for: Option<DateTime<Utc>>,
    /// When the job was created.
    pub created_at: Option<DateTime<Utc>>,
    /// When the station received it.
    pub sent_at: Option<DateTime<Utc>>,
    /// When it printed.
    pub printed_at: Option<DateTime<Utc>>,
    /// When it reached a final status.
    pub finished_at: Option<DateTime<Utc>>,
    /// Status history; only filled by [`crate::Jobs::get`].
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub events: Vec<JobEvent>,
}

/// One entry of a job's status history.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct JobEvent {
    /// When it happened.
    pub at: Option<DateTime<Utc>>,
    /// The status the job moved to.
    pub status: String,
    /// Detail text.
    pub detail: String,
    /// Who did it (`"API key"`, `"Station"`, an email…).
    pub actor: String,
}

/// One page of jobs.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct JobPage {
    /// Jobs, newest first.
    pub items: Vec<Job>,
    /// Cursor for the next page; `None` on the last page.
    #[serde(deserialize_with = "empty_string_as_none")]
    pub next_cursor: Option<String>,
}

fn empty_string_as_none<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Option<String>, D::Error> {
    let s: Option<String> = Option::deserialize(d)?;
    Ok(s.filter(|s| !s.is_empty()))
}

/// A printer attached to a station.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Printer {
    /// Printer ID.
    pub id: String,
    /// Station it is attached to.
    pub station_id: String,
    /// That station's name.
    pub station_name: String,
    /// The station's location.
    pub location_id: Option<String>,
    /// The station's own identifier for the printer.
    pub device_key: String,
    /// Printer name.
    pub name: String,
    /// Role: `receipt`, `kitchen`, `bar`, `label`, `office` or `other`.
    pub role: String,
    /// How it's connected (`usb`, `network`, `bluetooth`, `system`…).
    pub connection: String,
    /// Connection address.
    pub address: String,
    /// Paper: `80mm`, `58mm`, `a4`, `letter` or `label`.
    pub paper: String,
    /// What it can print: `escpos`, `pdf`, `image`…
    pub capabilities: Vec<String>,
    /// Whether the owner turned it on.
    pub enabled: bool,
    /// Status: `ready`, `offline`, `error`…
    pub status: String,
    /// Status detail.
    pub status_detail: String,
    /// Whether individuals may print to it.
    pub shared_with_individuals: bool,
    /// Whether its station (and location) is turned on.
    pub station_enabled: bool,
    /// Whether its station is connected right now.
    pub station_connected: bool,
    /// Last change.
    pub updated_at: Option<DateTime<Utc>>,
}

/// A place with stations (a shop, a kitchen, an office).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Location {
    /// Location ID.
    pub id: String,
    /// Name.
    pub name: String,
    /// Street address.
    pub address: String,
    /// IANA time zone.
    pub time_zone: String,
    /// Whether it's turned on.
    pub enabled: bool,
    /// When it was turned off.
    pub disabled_at: Option<DateTime<Utc>>,
    /// What happens to jobs while it's off: `hold`, `fallback` or `reject`.
    pub disabled_job_policy: String,
    /// Where jobs go under the `fallback` policy.
    pub fallback_location_id: Option<String>,
    /// Number of stations.
    pub stations: u32,
    /// Number of printers.
    pub printers: u32,
    /// When it was created.
    pub created_at: Option<DateTime<Utc>>,
}

/// A saved receipt layout with `{{placeholders}}`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Template {
    /// Template ID.
    pub id: String,
    /// Name.
    pub name: String,
    /// Paper it's designed for.
    pub paper: String,
    /// The command list (JSON array).
    pub body: Value,
    /// Version, bumped on every change.
    pub version: u32,
    /// Last change.
    pub updated_at: Option<DateTime<Utc>>,
}

/// The API key the client uses, from `GET /v1/key`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Key {
    /// Key ID.
    pub id: String,
    /// The organization the key belongs to.
    pub org_id: String,
    /// That organization's name.
    pub org_name: String,
    /// `true` for `cz_live_` keys, `false` for `cz_test_` keys.
    pub live: bool,
    /// Scopes, e.g. `["jobs:write", "printers:read"]`.
    pub scopes: Vec<String>,
}

/// A webhook event, as delivered to your endpoint.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct WebhookEvent {
    /// Delivery id, identical across retries of one delivery. Deduplicate on
    /// it: the timestamp check only limits the replay window to the tolerance
    /// (5 minutes by default). `None` when the server did not send one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Event type, e.g. `"job.printed"`.
    #[serde(rename = "type")]
    pub event_type: String,
    /// When the event happened.
    pub created_at: Option<DateTime<Utc>>,
    /// The organization it belongs to.
    pub org_id: String,
    /// Event data; for `job.*` events, `{"job": {...}}`.
    pub data: Value,
}

impl WebhookEvent {
    /// The job in a `job.*` event.
    pub fn job(&self) -> Option<Job> {
        self.data
            .get("job")
            .and_then(|j| serde_json::from_value(j.clone()).ok())
    }
}
