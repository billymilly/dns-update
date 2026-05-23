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

use crate::{DnsRecord, DnsRecordType, Error, IntoFqdn, crypto, http::HttpClientBuilder};
use chrono::{Timelike, Utc};
use chrono_tz::Europe::Prague;
use std::sync::{Arc, Mutex};
use std::time::Duration;

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
    config: WedosConfig,
    endpoint: String,
    token: Arc<Mutex<Option<(String, u32)>>>,
}

impl WedosProvider {
    pub(crate) fn new(config: WedosConfig) -> crate::Result<Self> {
        if config.login_email.is_empty() {
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
            config,
            endpoint: "https://api.wedos.com/wapi/json".to_string(),
            token: Arc::new(Mutex::new(None)),
        })
    }

    #[cfg(test)]
    pub(crate) fn with_endpoints(mut self, wedos_api_url: impl AsRef<str>) -> Self {
        todo!()
    }

    /// Per https://kb.wedos.global/wapi-wdns/#dns-row-add
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
            self.config.login_email,
            hex::encode(crypto::sha1_digest(self.config.wapi_password.as_bytes())),
            current_prague_hour,
        );
        let digest = hex::encode(crypto::sha1_digest(raw.as_bytes()));
        *guard = Some((digest.clone(), current_prague_hour));
        Ok(digest)
    }
}
