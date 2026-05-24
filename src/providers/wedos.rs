/*
 * Copyright Stalwart Labs LLC See the COPYING
 * file at the top-level directory of this distribution.
 *
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
 */

use crate::utils::is_email;
use crate::{DnsRecord, DnsRecordType, Error, IntoFqdn, crypto, http::HttpClientBuilder};
use chrono::{Timelike, Utc};
use chrono_tz::Europe::Prague;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::{self, Display, Formatter};
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum WedosReplyCodes {
    Ok = 1000,

    UnsupportedTld = 2201,
    InvalidOrUnsupportedDomainName = 2202,
    InvalidRecordType = 2309,
    UnableToAddAnotherRecordToTheDomain = 2310,
    InvalidName = 2311,
    InvalidNameForRecordType = 2312,
    InvalidCnameForName = 2313,
    InvalidDataForRecord = 2314,
    RecordAlreadyExists = 2316,
    InvalidTtl = 2317,
    SecondaryDomainTypeNotAllowed = 2318,

    OpeningDomainFailed = 3222,
    AccessDenied = 3223,
    DomainLockedForEditing = 3305,
    DomainDeleted = 3306,
}

impl Display for WedosReplyCodes {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize)]
#[serde(transparent)]
struct RowId(String);

#[derive(Debug, Deserialize)]
#[serde(tag = "command", content = "data", rename_all = "kebab-case")]
enum WedosCommandReply {
    DnsRowsList(HashMap<RowId, DnsRow>),
    DnsRowDetail(HashMap<RowId, DnsRow>),
    DnsRowAdd,
    DnsRowUpdate,
    DnsRowDelete,
}

#[derive(Debug, Deserialize)]
struct DnsRow {
    #[serde(rename = "id")]
    id: String,
    name: String,
    ttl: String,
    rdtype: String,
    rdata: String,
    changed_date: String,
}

#[derive(Debug, Serialize)]
#[serde(tag = "command", content = "data", rename_all = "kebab-case")]
enum WedosCommandRequest {
    DnsRowsList,
    DnsRowDetail(DnsRowDetailData),
    DnsRowAdd(DnsRowAddData),
    DnsRowUpdate(DnsRowUpdateData),
    DnsRowDelete(DnsRowDeleteData),
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Serialize)]
struct DnsRowDetailData {
    name: String,
    row_id: String,
}

#[derive(Debug, Serialize)]
struct DnsRowAddData {
    domain: String,
    name: String,
    ttl: String,
    #[serde(rename = "type")]
    record_type: String, // DnsRecordType,
    rdata: String,
}

#[derive(Debug, Serialize)]
struct DnsRowUpdateData {
    domain: String,
    row_id: String,
    ttl: String,
    rdata: String,
}

#[derive(Debug, Serialize)]
struct DnsRowDeleteData {
    domain: String,
    row_id: String,
}

#[derive(Debug, Deserialize)]
struct WedosApiResponse {
    response: WedosResponseBody,
}

#[derive(Debug, Serialize)]
struct WedosApiRequest {
    request: WedosRequestBody,
}

#[derive(Debug, Deserialize)]
struct WedosResponseBody {
    code: WedosReplyCodes,
    result: String,
    timestamp: String,
    #[serde(rename = "svTRID")]
    sv_trid: String,
    #[serde(flatten)]
    command: WedosCommandReply,
}

#[derive(Debug, Serialize)]
struct WedosRequestBody {
    user: String,
    auth: String,
    #[serde(flatten)]
    command: WedosCommandRequest,
}

#[derive(Debug, Clone)]
pub struct WedosConfig {
    login_email: String,
    wapi_password: String,
    timeout: Option<Duration>,
    max_retries: Option<u32>,
}

#[derive(Clone)]
pub struct WedosProvider {
    client: HttpClientBuilder,
    endpoint: String,
    max_retries: u32,
    username: String,
    password: String,
    token: Arc<Mutex<Option<(String, u32)>>>,
}

impl WedosProvider {
    pub(crate) fn new(config: WedosConfig) -> crate::Result<Self> {
        let username = config.login_email.trim().to_string();
        if !is_email(&username) {
            return Err(Error::Api("Wedos API requires a WEDOS login email".into()));
        }
        if config.wapi_password.is_empty() {
            return Err(Error::Api("Wedos API requires a WAPI password".into()));
        }
        // ?
        // https://github.com/stalwartlabs/dns-update/issues/61
        let client = HttpClientBuilder::default()
            .with_header("Accept", "application/json")
            .with_timeout(config.timeout);

        Ok(Self {
            client,
            max_retries: config.max_retries.unwrap_or(3),
            endpoint: "https://api.wedos.com/wapi/json".to_string(),
            token: Arc::new(Mutex::new(None)),
            username,
            password: config.wapi_password,
        })
    }

    #[cfg(test)]
    pub(crate) fn with_endpoints(mut self, wedos_api_url: impl AsRef<str>) -> Self {
        todo!()
    }

    /// Per: https://kb.wedos.global/wapi-wdns/#dns-row-add
    pub(crate) async fn create(
        &self,
        name: impl IntoFqdn<'_>,
        record: DnsRecord,
        ttl: u32,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        todo!()
    }

    pub(crate) async fn update(
        &self,
        name: impl IntoFqdn<'_>,
        record: DnsRecord,
        ttl: u32,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        todo!()
    }

    pub(crate) async fn delete(
        &self,
        name: impl IntoFqdn<'_>,
        origin: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
    ) -> crate::Result<()> {
        todo!()
    }

    /// Wedos API authentication token specification:
    /// ```text
    /// SHA1( login + SHA1(password) + HH )
    /// ```
    /// where `HH` is the current zero-padded hour in `Europe/Prague` time (00–23).
    ///
    /// Per: https://kb.wedos.global/wapi-manual/#connect
    fn ensure_token(&self) -> crate::Result<String> {
        let current_prague_hour = Utc::now().with_timezone(&Prague).hour();
        let mut guard = self
            .token
            .lock()
            .map_err(|_| Error::Api("Wedos token mutex poisoned".into()))?;

        if let Some((ref token, hour)) = *guard {
            if hour == current_prague_hour {
                return Ok(token.clone());
            }
        }
        let raw = format!(
            "{}{}{:02}",
            self.username,
            hex::encode(crypto::sha1_digest(self.password.as_bytes())),
            current_prague_hour,
        );
        let digest = hex::encode(crypto::sha1_digest(raw.as_bytes()));
        *guard = Some((digest.clone(), current_prague_hour));
        Ok(digest)
    }
}
