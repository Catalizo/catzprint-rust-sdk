//! Cloud endpoints for local printing: minting/revoking local tokens and the
//! stations' local endpoint list.

use std::time::Duration;

use serde_json::{json, Map, Value};

use crate::client::Client;
use crate::core::{list_field, seg, whole, Request};
use crate::error::{ApiError, Error, Result};

use super::models::{LocalEndpoint, LocalToken, LocalTokenParams};

/// Mints and revokes local tokens: `client.local_tokens()`.
///
/// A local token (`"czl1…"`) lets a device print through any station of the
/// organization on its local network, verified by the station without the
/// internet. With [`crate::ClientBuilder::local`] the SDK mints, caches and
/// refreshes tokens for you.
#[derive(Debug, Clone, Copy)]
pub struct LocalTokens<'a> {
    pub(crate) client: &'a Client,
}

impl LocalTokens<'_> {
    /// Mints a local token (`POST /v1/orgs/{org}/local-tokens`). Needs an API
    /// key with the `jobs:write` scope.
    pub async fn create(&self, params: LocalTokenParams) -> Result<LocalToken> {
        create_token(self.client, &params, None).await
    }

    /// Revokes a local token by its token ID (the `jti`). Stations refuse it
    /// once they have synced their configuration.
    pub async fn revoke(&self, token_id: &str) -> Result<()> {
        let path = format!("/v1/orgs/{{org}}/local-tokens/{}", seg(token_id));
        self.client.send(Request::delete(path)).await?;
        Ok(())
    }
}

/// The stations' local-network addresses: `client.local_endpoints()`.
#[derive(Debug, Clone, Copy)]
pub struct LocalEndpoints<'a> {
    pub(crate) client: &'a Client,
}

impl LocalEndpoints<'_> {
    /// Lists the stations' local endpoints, optionally only those at one
    /// location (`GET /v1/orgs/{org}/local-endpoints`).
    pub async fn list(&self, location_id: Option<&str>) -> Result<Vec<LocalEndpoint>> {
        list_endpoints(self.client, location_id, None).await
    }
}

pub(crate) fn invalid(field: &str, message: &str) -> Error {
    Error::Validation(ApiError {
        status: 400,
        code: "invalid".into(),
        message: message.into(),
        fields: [(field.to_string(), message.to_string())].into(),
        retry_after: None,
    })
}

/// `once_within`: try once within this timeout (the SDK's own calls).
pub(crate) async fn create_token(
    client: &Client,
    params: &LocalTokenParams,
    once_within: Option<Duration>,
) -> Result<LocalToken> {
    if params.device_name.trim().is_empty() {
        return Err(invalid("device_name", "Set the device name."));
    }
    if params.ttl_days.is_some_and(|d| !(1..=30).contains(&d)) {
        return Err(invalid("ttl_days", "ttl_days must be between 1 and 30."));
    }
    let mut body = Map::new();
    body.insert("device_name".into(), json!(params.device_name));
    if !params.location_ids.is_empty() {
        body.insert("location_ids".into(), json!(params.location_ids));
    }
    if let Some(d) = params.ttl_days {
        body.insert("ttl_days".into(), json!(d));
    }
    let mut req = Request::post("/v1/orgs/{org}/local-tokens", Value::Object(body));
    if let Some(t) = once_within {
        req = req.once_within(t);
    }
    let out: LocalToken = whole(client.send(req).await?)?;
    if out.token.is_empty() {
        return Err(Error::Decode("the API answered without a token".into()));
    }
    Ok(out)
}

pub(crate) async fn list_endpoints(
    client: &Client,
    location_id: Option<&str>,
    once_within: Option<Duration>,
) -> Result<Vec<LocalEndpoint>> {
    let mut req = Request::get("/v1/orgs/{org}/local-endpoints");
    if let Some(l) = location_id.filter(|l| !l.is_empty()) {
        req = req.query(vec![("location_id".into(), l.to_string())]);
    }
    if let Some(t) = once_within {
        req = req.once_within(t);
    }
    list_field(client.send(req).await?, "stations")
}
