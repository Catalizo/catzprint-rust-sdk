//! Types of the local (offline) printing API: the cloud's station endpoint
//! list and local tokens, and the station's own local API (`/local/v1`).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize};

use crate::models::JobStatus;

/// Reads `null` as the type's default (stations and the API may send `null`
/// for empty strings and lists).
fn null_default<'de, D, T>(d: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Default + Deserialize<'de>,
{
    Ok(Option::<T>::deserialize(d)?.unwrap_or_default())
}

/// Reads `""` and `null` as no time.
fn opt_time<'de, D: Deserializer<'de>>(d: D) -> Result<Option<DateTime<Utc>>, D::Error> {
    let s: Option<String> = Option::deserialize(d)?;
    match s.as_deref().map(str::trim) {
        None | Some("") => Ok(None),
        Some(t) => DateTime::parse_from_rfc3339(t)
            .map(|t| Some(t.with_timezone(&Utc)))
            .map_err(serde::de::Error::custom),
    }
}

/// One station's local-network address as the cloud knows it
/// (`GET /v1/orgs/{org}/local-endpoints` and the local-tokens response).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct LocalEndpoint {
    /// Station ID.
    #[serde(deserialize_with = "null_default")]
    pub station_id: String,
    /// Station name.
    #[serde(deserialize_with = "null_default")]
    pub name: String,
    /// The station's location.
    #[serde(deserialize_with = "null_default")]
    pub location_id: String,
    /// Whether the station is connected to the cloud right now.
    #[serde(deserialize_with = "null_default")]
    pub connected: bool,
    /// Whether the station's local API is turned on.
    #[serde(deserialize_with = "null_default")]
    pub local_enabled: bool,
    /// The local API port (7443 by default).
    #[serde(deserialize_with = "null_default")]
    pub port: u16,
    /// The station's private IPv4 addresses.
    #[serde(deserialize_with = "null_default")]
    pub addresses: Vec<String>,
    /// URLs: public-certificate hostnames first, then raw IP URLs.
    #[serde(deserialize_with = "null_default")]
    pub urls: Vec<String>,
    /// `"public"` (a publicly trusted certificate for the hostnames) or
    /// `"self_signed"`.
    #[serde(deserialize_with = "null_default")]
    pub tls_mode: String,
    /// Hex SHA-256 of the station's certificate (DER). Pinned for IP and
    /// self-signed URLs.
    #[serde(deserialize_with = "null_default")]
    pub cert_fingerprint_sha256: String,
    /// Hex SHA-256 of the public certificate's SubjectPublicKeyInfo (when the
    /// station has one); pinned for hostnames on top of normal verification.
    #[serde(deserialize_with = "null_default")]
    pub public_spki_sha256: String,
    /// The station's label in `"<a-b-c-d>.<label>.<zone>"` hostnames.
    #[serde(deserialize_with = "null_default")]
    pub local_label: String,
    /// When the cloud last heard about these addresses.
    #[serde(deserialize_with = "opt_time", skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<DateTime<Utc>>,
}

/// Settings for [`crate::LocalTokens::create`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LocalTokenParams {
    /// Identifies the device on the station (up to 80 characters).
    pub device_name: String,
    /// Narrows the token to these locations (default: every location the API
    /// key may use).
    pub location_ids: Vec<String>,
    /// Lifetime in days, 1–30 (default 30).
    pub ttl_days: Option<u32>,
}

impl LocalTokenParams {
    /// A token for this device name.
    pub fn new(device_name: impl Into<String>) -> Self {
        LocalTokenParams {
            device_name: device_name.into(),
            ..Default::default()
        }
    }
    /// Adds a location the token is valid at.
    pub fn location(mut self, location_id: impl Into<String>) -> Self {
        self.location_ids.push(location_id.into());
        self
    }
    /// Sets the lifetime in days (1–30).
    pub fn ttl_days(mut self, days: u32) -> Self {
        self.ttl_days = Some(days);
        self
    }
}

/// A minted local token (`"czl1…"`) that stations verify offline. Its
/// `Debug` output never shows the token.
#[derive(Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct LocalToken {
    /// The token.
    pub token: String,
    /// Its ID (the `jti`), for [`crate::LocalTokens::revoke`].
    pub token_id: String,
    /// When it expires.
    #[serde(deserialize_with = "opt_time")]
    pub expires_at: Option<DateTime<Utc>>,
    /// The organization's station endpoints, when the API included them.
    pub stations: Option<Vec<LocalEndpoint>>,
}

/// How a secret appears in `Debug` output: `"****"`, or `""` when unset.
pub(crate) fn redacted(secret: &str) -> &'static str {
    if secret.is_empty() {
        ""
    } else {
        "****"
    }
}

impl std::fmt::Debug for LocalToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalToken")
            .field("token", &redacted(&self.token))
            .field("token_id", &self.token_id)
            .field("expires_at", &self.expires_at)
            .field("stations", &self.stations)
            .finish()
    }
}

impl std::fmt::Debug for LocalPairing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalPairing")
            .field("device_id", &self.device_id)
            .field("token", &redacted(&self.token))
            .field("station_id", &self.station_id)
            .field("org_id", &self.org_id)
            .field("location_id", &self.location_id)
            .finish()
    }
}

/// A job as a station's local API reports it.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct LocalJob {
    /// Local job ID (`"lj_…"`).
    #[serde(deserialize_with = "null_default")]
    pub id: String,
    /// The job's idempotency key.
    #[serde(deserialize_with = "null_default")]
    pub idempotency_key: String,
    /// `queued`, `printing`, `printed` or `failed`.
    pub status: JobStatus,
    /// Why it failed (e.g. `out_of_paper`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    /// Status detail.
    #[serde(deserialize_with = "null_default")]
    pub detail: String,
    /// The printer the station routed it to.
    #[serde(deserialize_with = "null_default")]
    pub printer_id: String,
    /// That printer's name.
    #[serde(deserialize_with = "null_default")]
    pub printer_name: String,
    /// The role it was routed by.
    #[serde(deserialize_with = "null_default")]
    pub role: String,
    /// The station's location.
    #[serde(deserialize_with = "null_default")]
    pub location_id: String,
    /// Copies.
    #[serde(deserialize_with = "null_default")]
    pub copies: u32,
    /// Title.
    #[serde(deserialize_with = "null_default")]
    pub title: String,
    /// Your reference.
    #[serde(deserialize_with = "null_default")]
    pub reference: String,
    /// When the station accepted it.
    #[serde(deserialize_with = "opt_time")]
    pub created_at: Option<DateTime<Utc>>,
    /// When it printed or failed.
    #[serde(deserialize_with = "opt_time")]
    pub finished_at: Option<DateTime<Utc>>,
    /// Always `true` for local jobs.
    #[serde(deserialize_with = "null_default")]
    pub printed_locally: bool,
    /// `"local"`.
    #[serde(deserialize_with = "null_default")]
    pub via: String,
    /// The cloud job this local job became after reconciliation, if any.
    pub cloud_job_id: Option<String>,
    /// `false` for jobs sent with a test-mode token (`None` when the station
    /// didn't say).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub live: Option<bool>,
    /// The station URL that answered (set by the SDK).
    #[serde(skip)]
    pub station_url: String,
}

/// A station's `GET /local/v1/status` answer.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct LocalStatus {
    /// The station.
    pub station: LocalStationState,
    /// Its printers.
    #[serde(deserialize_with = "null_default")]
    pub printers: Vec<LocalPrinterStatus>,
    /// Jobs waiting on all printers.
    #[serde(deserialize_with = "null_default")]
    pub jobs_waiting: u32,
    /// How many local jobs the station still has to report to the cloud.
    #[serde(deserialize_with = "null_default")]
    pub unsynced: u32,
    /// What the station may still print without the cloud.
    pub allowance: LocalAllowance,
    /// The station URL that answered (set by the SDK).
    #[serde(skip)]
    pub station_url: String,
}

/// The station in [`LocalStatus`].
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct LocalStationState {
    /// Station ID.
    #[serde(deserialize_with = "null_default")]
    pub id: String,
    /// Station name.
    #[serde(deserialize_with = "null_default")]
    pub name: String,
    /// Whether it is connected to the cloud.
    #[serde(deserialize_with = "null_default")]
    pub cloud_connected: bool,
    /// When it last reached the cloud.
    #[serde(deserialize_with = "opt_time")]
    pub last_cloud_contact: Option<DateTime<Utc>>,
    /// Station app version.
    #[serde(deserialize_with = "null_default")]
    pub version: String,
    /// Whether the local API is on.
    #[serde(deserialize_with = "null_default")]
    pub local_enabled: bool,
}

/// One printer in [`LocalStatus`].
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct LocalPrinterStatus {
    /// Printer ID.
    #[serde(deserialize_with = "null_default")]
    pub id: String,
    /// Name.
    #[serde(deserialize_with = "null_default")]
    pub name: String,
    /// Role.
    #[serde(deserialize_with = "null_default")]
    pub role: String,
    /// `ready`, `offline`, `paper_out`, `paper_low`, `cover_open`, `error`,
    /// `busy` or `unknown`.
    #[serde(deserialize_with = "null_default")]
    pub status: String,
    /// `ok`, `low`, `out` or `unknown`.
    #[serde(deserialize_with = "null_default")]
    pub paper: String,
    /// Jobs waiting on this printer.
    #[serde(deserialize_with = "null_default")]
    pub jobs_waiting: u32,
}

/// What a station may still print without the cloud.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct LocalAllowance {
    /// When the offline allowance ends.
    #[serde(deserialize_with = "opt_time")]
    pub expires_at: Option<DateTime<Utc>>,
    /// Prints left.
    #[serde(deserialize_with = "null_default")]
    pub prints_left: i64,
}

/// A station's unauthenticated `GET /local/v1/info` answer.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct LocalInfo {
    /// Station ID.
    #[serde(deserialize_with = "null_default")]
    pub station_id: String,
    /// Station name.
    #[serde(deserialize_with = "null_default")]
    pub name: String,
    /// Organization.
    #[serde(deserialize_with = "null_default")]
    pub org_id: String,
    /// Location.
    #[serde(deserialize_with = "null_default")]
    pub location_id: String,
    /// Station app version.
    #[serde(deserialize_with = "null_default")]
    pub version: String,
    /// Local API port.
    #[serde(deserialize_with = "null_default")]
    pub port: u16,
    /// `public` or `self_signed`.
    #[serde(deserialize_with = "null_default")]
    pub tls_mode: String,
    /// Hex SHA-256 of its certificate.
    #[serde(deserialize_with = "null_default")]
    pub cert_fingerprint_sha256: String,
    /// Public-certificate hostnames.
    #[serde(deserialize_with = "null_default")]
    pub hostnames: Vec<String>,
    /// Private addresses.
    #[serde(deserialize_with = "null_default")]
    pub addresses: Vec<String>,
    /// Whether "Pair a device" is open in the station app.
    #[serde(deserialize_with = "null_default")]
    pub pairing_open: bool,
    /// The station's clock.
    #[serde(deserialize_with = "opt_time")]
    pub time: Option<DateTime<Utc>>,
}

/// The result of [`crate::Local::pair`]: a device token (`"czd_…"`) for
/// that one station. Pass it to [`crate::LocalConfig::token`]. Its `Debug`
/// output never shows the token.
#[derive(Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct LocalPairing {
    /// Device ID on the station.
    #[serde(deserialize_with = "null_default")]
    pub device_id: String,
    /// The device token.
    #[serde(deserialize_with = "null_default")]
    pub token: String,
    /// Station ID.
    #[serde(deserialize_with = "null_default")]
    pub station_id: String,
    /// Organization.
    #[serde(deserialize_with = "null_default")]
    pub org_id: String,
    /// Location.
    #[serde(deserialize_with = "null_default")]
    pub location_id: String,
}

/// A station found by [`crate::Local::discover`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct LocalStation {
    /// Station ID.
    pub station_id: String,
    /// Name.
    pub name: String,
    /// Organization.
    pub org_id: String,
    /// Location.
    pub location_id: String,
    /// Local API port.
    pub port: u16,
    /// Private addresses.
    pub addresses: Vec<String>,
    /// The URLs the SDK would use, in order.
    pub urls: Vec<String>,
    /// `public` or `self_signed`.
    pub tls_mode: String,
    /// The pinned certificate fingerprint.
    pub fingerprint: String,
    /// The station is on the cloud's endpoint list (authenticated).
    pub from_cloud: bool,
    /// The station answered over mDNS on the local network.
    pub from_mdns: bool,
    /// From the cloud endpoint list: the local API is on.
    pub local_enabled: bool,
    /// From the cloud endpoint list: connected to the cloud.
    pub connected: bool,
}
