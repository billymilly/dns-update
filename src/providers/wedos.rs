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
use crate::{
    DnsRecord, DnsRecordType, Error, IntoFqdn, crypto, http::HttpClient, http::HttpClientBuilder,
};
use chrono::{Timelike, Utc};
use chrono_tz::Europe::Prague;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::{self, Display, Formatter};
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WedosReplyCode {
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

impl Display for WedosReplyCode {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl<'de> Deserialize<'de> for WedosReplyCode {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        match u16::deserialize(d)? {
            1000 => Ok(Self::Ok),
            2201 => Ok(Self::UnsupportedTld),
            2202 => Ok(Self::InvalidOrUnsupportedDomainName),
            2309 => Ok(Self::InvalidRecordType),
            2310 => Ok(Self::UnableToAddAnotherRecordToTheDomain),
            2311 => Ok(Self::InvalidName),
            2312 => Ok(Self::InvalidNameForRecordType),
            2313 => Ok(Self::InvalidCnameForName),
            2314 => Ok(Self::InvalidDataForRecord),
            2316 => Ok(Self::RecordAlreadyExists),
            2317 => Ok(Self::InvalidTtl),
            2318 => Ok(Self::SecondaryDomainTypeNotAllowed),
            3222 => Ok(Self::OpeningDomainFailed),
            3223 => Ok(Self::AccessDenied),
            3305 => Ok(Self::DomainLockedForEditing),
            3306 => Ok(Self::DomainDeleted),
            n => Err(serde::de::Error::custom(format!("unknown reply code: {n}"))),
        }
    }
}

impl Serialize for WedosReplyCode {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u16(*self as u16)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize)]
#[cfg_attr(test, derive(Serialize))]
#[serde(transparent)]
struct RowId(String);

#[derive(Debug, Deserialize)]
#[cfg_attr(test, derive(Serialize))]
#[serde(tag = "command", content = "data", rename_all = "kebab-case")]
enum WedosCommandReply {
    DnsRowsList(HashMap<RowId, DnsRow>),
    DnsRowDetail(HashMap<RowId, DnsRow>),
    DnsRowAdd,
    DnsRowUpdate,
    DnsRowDelete,
}

#[derive(Debug, Deserialize)]
#[cfg_attr(test, derive(Serialize))]
struct DnsRow {
    #[serde(rename = "ID")]
    id: String,
    name: String,
    ttl: String,
    rdtype: String,
    rdata: String,
    changed_date: String,
}

#[derive(Debug, Serialize)]
#[cfg_attr(test, derive(Deserialize))]
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
#[cfg_attr(test, derive(Deserialize))]
struct DnsRowDetailData {
    name: String,
    row_id: String,
}

#[derive(Debug, Serialize)]
#[cfg_attr(test, derive(Deserialize))]
struct DnsRowAddData {
    domain: String,
    name: String,
    ttl: String,
    #[serde(rename = "type")]
    record_type: String, // DnsRecordType,
    rdata: String,
}

#[derive(Debug, Serialize)]
#[cfg_attr(test, derive(Deserialize))]
struct DnsRowUpdateData {
    domain: String,
    row_id: String,
    ttl: String,
    rdata: String,
}

#[derive(Debug, Serialize)]
#[cfg_attr(test, derive(Deserialize))]
struct DnsRowDeleteData {
    domain: String,
    row_id: String,
}

#[derive(Debug, Deserialize)]
#[cfg_attr(test, derive(Serialize))]
struct WedosApiResponse {
    response: WedosResponseBody,
}

#[derive(Debug, Serialize)]
#[cfg_attr(test, derive(Deserialize))]
struct WedosApiRequest {
    request: WedosRequestBody,
}

#[derive(Debug, Deserialize)]
#[cfg_attr(test, derive(Serialize))]
struct WedosResponseBody {
    code: WedosReplyCode,
    result: String,
    timestamp: String,
    #[serde(rename = "svTRID")]
    sv_trid: String,
    #[serde(flatten)]
    command: WedosCommandReply,
}

#[derive(Debug, Serialize)]
#[cfg_attr(test, derive(Deserialize))]
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
    client: HttpClient,
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
        let client = HttpClientBuilder::default()
            .with_header("Accept", "application/json")
            .with_timeout(config.timeout)
            .build();

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
    pub(crate) async fn set_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        ttl: u32,
        records: Vec<DnsRecord>,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        todo!()
    }

    pub(crate) async fn add_to_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        ttl: u32,
        records: Vec<DnsRecord>,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        todo!()
    }

    pub(crate) async fn remove_from_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        records: Vec<DnsRecord>,
        origin: impl IntoFqdn<'_>,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_row_deserialize() {
        let json = r#"
        {
            "response": {
                "code": 1000,
                "result": "OK",
                "timestamp": "UTF timestamp",
                "clTRID": "your ID",
                "svTRID": "server ID",
                "command": "dns-row-detail",
                "data": {
                    "row1": {
                        "ID": "record ID",
                        "name": "record name (may be empty)",
                        "ttl": "TTL",
                        "rdtype": "record type",
                        "rdata": "record data",
                        "changed_date": "date and time of last update",
                        "author_comment": "comment"
                    }
                }
            }
        }
        "#;
        let response: WedosApiResponse =
            serde_json::from_str(json).unwrap_or_else(|e| panic!("deserialization failed: {e:?}"));
        assert_eq!(response.response.code, WedosReplyCode::Ok);
        match response.response.command {
            WedosCommandReply::DnsRowDetail(rows) => {
                let row = rows.get(&RowId("row1".into())).unwrap();
                assert_eq!(row.rdata, "record data");
                assert_eq!(row.rdtype, "record type");
            }
            other => panic!("expected DnsRowsList, got {other:?}"),
        }
    }

    #[test]
    fn test_dns_row_add_request_serializes() {
        let request = WedosApiRequest {
            request: WedosRequestBody {
                user: "your@login.tld".into(),
                auth: "authentication string".into(),
                command: WedosCommandRequest::DnsRowAdd(DnsRowAddData {
                    domain: "domain name".into(),
                    name: "record name (may be empty)".into(),
                    ttl: "TTL".into(),
                    record_type: "record type".into(),
                    rdata: "record data".into(),
                }),
            },
        };
        let json: serde_json::Value = serde_json::to_value(&request).unwrap();
        assert_eq!(json["request"]["user"], "your@login.tld");
        assert_eq!(json["request"]["command"], "dns-row-add");
        assert_eq!(json["request"]["data"]["type"], "record type");
        assert_eq!(json["request"]["data"]["rdata"], "record data");
    }
}
