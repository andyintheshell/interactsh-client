use crate::client::crypto::{decrypt_message, encoded_public_key};
use crate::client::http::{
    is_connection_refused, normalized_base_url, server_host, should_retry_status,
    transport_stage_for,
};
use crate::client::poll::{PollResponse, RawInteraction, RegisterRequest};
use crate::config::ClientConfig;
use crate::error::{Error, Result, TransportStage};
use crate::model::{CorrelatedInteraction, GeneratedUrl, InteractionContext, InteractionEvent};

use futures_util::StreamExt;
use guise_choice::random_lower_alphanumeric_with_rng;
use guise_pacing::{capped_exponential_backoff, Jitter};
use rsa::{RsaPrivateKey, RsaPublicKey};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::time::sleep;

/// Async client for registering interactsh URLs and polling correlated callbacks.
///
/// `Debug` is implemented manually so the session `secret_key` and the RSA
/// private key never reach logs: the secret authenticates `/poll` (it travels
/// in the poll URL query string) and the private key decrypts every captured
/// interaction, so a single `{:?}` in a scan log would hand both to anyone
/// with log access.
///
/// # Thread Safety
/// `InteractshClient` is `Send` and `Sync`.
pub struct InteractshClient {
    pub(crate) config: ClientConfig,
    pub(crate) correlation_id: String,
    pub(crate) secret_key: String,
    pub(crate) private_key: RsaPrivateKey,
    pub(crate) public_key: RsaPublicKey,
    pub(crate) mappings: Arc<RwLock<HashMap<String, InteractionContext>>>,
    pub(crate) http_client: reqwest::Client,
}

impl InteractshClient {
    /// Creates a new `InteractshClient` using the default HTTP client builder.
    pub async fn new(config: ClientConfig) -> Result<Self> {
        let mut builder = reqwest::Client::builder();
        if let Some(ms) = config.request_timeout_millis {
            builder = builder.timeout(Duration::from_millis(ms));
        }
        if config.accept_invalid_certs {
            eprintln!("Warning: TLS certificate verification is disabled, do NOT use on untrusted networks");
            builder = builder.danger_accept_invalid_certs(true);
        }
        let http_client = builder.build().map_err(|source| Error::Transport {
            url: normalized_base_url(&config),
            stage: TransportStage::Send,
            source,
        })?;
        Self::with_http_client(config, http_client).await
    }

    /// Creates a new `InteractshClient` using a customized HTTP client.
    pub async fn with_http_client(
        config: ClientConfig,
        http_client: reqwest::Client,
    ) -> Result<Self> {
        config.validate()?;

        // rand::thread_rng() returns `ThreadRng` which holds an
        // `Rc<UnsafeCell<...>>` and is therefore `!Send`. The
        // `register().await` below would otherwise capture the rng's
        // stack slot across an await point, making the returned future
        // non-Send and unusable from `tokio::spawn`. Confining the rng
        // (and the keypair-generation that uses it) to a sync block
        // means it's dropped before any `.await`, so the outer future
        // is fully Send. Downstream consumers `tokio::spawn` this in
        // every scan loop  -  this MUST stay Send.
        let (correlation_id, secret_key, private_key) = {
            let mut rng = rand::thread_rng();
            let correlation_id =
                random_lower_alphanumeric_with_rng(config.correlation_id_length, &mut rng);
            let secret_key = random_lower_alphanumeric_with_rng(20, &mut rng);
            let private_key =
                RsaPrivateKey::new(&mut rng, 2048).map_err(|source| Error::Crypto {
                    url: normalized_base_url(&config),
                    message: format!("failed to generate RSA keypair: {source}"),
                })?;
            (correlation_id, secret_key, private_key)
        };
        let public_key = RsaPublicKey::from(&private_key);

        let client = Self {
            config,
            correlation_id,
            secret_key,
            private_key,
            public_key,
            mappings: Arc::new(RwLock::new(HashMap::new())),
            http_client,
        };

        client.register().await?;
        Ok(client)
    }

    /// Returns the configuration used by this client.
    pub fn config(&self) -> &ClientConfig {
        &self.config
    }

    /// Returns the correlation ID for this client session.
    pub fn correlation_id(&self) -> &str {
        &self.correlation_id
    }

    /// Returns the secret key for this client session.
    pub fn secret_key(&self) -> &str {
        &self.secret_key
    }

    /// Generates a new unique URL for tracking out-of-band interactions.
    pub fn generate_url(&self, context: InteractionContext) -> Result<GeneratedUrl> {
        let nonce =
            random_lower_alphanumeric_with_rng(self.config.nonce_length, &mut rand::thread_rng());
        match self.mappings.write() {
            Ok(mut map) => {
                map.insert(nonce.clone(), context);
            }
            Err(_) => return Err(Error::StatePoisoned),
        }
        Ok(GeneratedUrl {
            url: format!(
                "{}{}.{}",
                self.correlation_id,
                nonce,
                server_host(&self.config)
            ),
            nonce,
        })
    }

    /// Removes the interaction context for the specified nonce from tracking.
    pub fn forget(&self, nonce: &str) -> Result<Option<InteractionContext>> {
        let mut map = self.mappings.write().map_err(|_| Error::StatePoisoned)?;
        Ok(map.remove(nonce))
    }

    /// Returns the number of interaction contexts currently being tracked.
    pub fn tracked_count(&self) -> Result<usize> {
        let map = self.mappings.read().map_err(|_| Error::StatePoisoned)?;
        Ok(map.len())
    }

    /// Polls the interactsh server for any interactions matching the current correlation ID.
    pub async fn poll(&self) -> Result<Vec<CorrelatedInteraction>> {
        let url = self.poll_url();
        // Errors carry a redacted copy of the poll URL: the real one embeds the
        // session secret as a query parameter, and an error bubbled into a scan
        // log would otherwise publish credentials that read every captured
        // interaction.
        let error_url = self.redacted_poll_url();
        let response = self.send_poll_request(&url, &error_url).await?;
        let payload = self.parse_poll_response(response, &error_url).await?;
        self.extract_and_correlate(payload, &error_url)
    }

    async fn register(&self) -> Result<()> {
        let url = format!("{}/register", self.base_url());

        let mut attempt: usize = 0;
        loop {
            let request = self.build_register_request(&url)?;
            match request.send().await {
                Ok(response) => {
                    if response.status().is_success() {
                        return Ok(());
                    }
                    if should_retry_status(response.status()) && attempt < self.config.max_retries {
                        attempt += 1;
                        self.sleep_backoff(attempt).await;
                        continue;
                    }
                    return Err(Error::Registration { url: url.clone() });
                }
                Err(source) => {
                    let stage = transport_stage_for(&source, TransportStage::Send);
                    if (source.is_timeout() || source.is_connect())
                        && attempt < self.config.max_retries
                    {
                        attempt += 1;
                        self.sleep_backoff(attempt).await;
                        continue;
                    }
                    return Err(Error::Transport {
                        url: url.clone(),
                        stage,
                        source,
                    });
                }
            }
        }
    }

    fn build_register_request(&self, url: &str) -> Result<reqwest::RequestBuilder> {
        let mut request = self.http_client.post(url).json(&RegisterRequest {
            public_key: encoded_public_key(&self.public_key, url)?,
            secret_key: self.secret_key.clone(),
            correlation_id: self.correlation_id.clone(),
        });
        if let Some(token) = self.config.token.as_ref() {
            request = request.header(&self.config.authorization_header, token);
        }
        Ok(request)
    }

    fn build_poll_request(&self, url: &str) -> reqwest::RequestBuilder {
        let mut request = self.http_client.get(url);
        if let Some(token) = self.config.token.as_ref() {
            request = request.header(&self.config.authorization_header, token);
        }
        request
    }

    async fn send_poll_request(
        &self,
        url: &str,
        error_url: &str,
    ) -> Result<reqwest::Response> {
        let mut attempt: usize = 0;
        loop {
            let request = self.build_poll_request(url);
            match request.send().await {
                Ok(response) => {
                    if !response.status().is_success() {
                        if response.status().as_u16() == 429 && attempt < self.config.max_retries {
                            attempt += 1;
                            self.sleep_backoff(attempt).await;
                            continue;
                        }
                        return Err(Error::HttpStatus {
                            url: error_url.to_string(),
                            status: response.status(),
                        });
                    }
                    return Ok(response);
                }
                Err(source) => {
                    let stage = transport_stage_for(&source, TransportStage::Send);
                    if (source.is_timeout()
                        || source.is_connect()
                        || is_connection_refused(&source))
                        && attempt < self.config.max_retries
                    {
                        attempt += 1;
                        self.sleep_backoff(attempt).await;
                        continue;
                    }
                    return Err(Error::Transport {
                        url: error_url.to_string(),
                        stage,
                        source,
                    });
                }
            }
        }
    }

    async fn parse_poll_response(
        &self,
        response: reqwest::Response,
        url: &str,
    ) -> Result<PollResponse> {
        if let Some(len) = response.content_length() {
            // Widen the limit to u64 rather than narrowing `len` to usize: on a
            // 32-bit target `len as usize` truncates, so an advertised length
            // above usize::MAX (e.g. 4 GiB + 1) would wrap to a tiny value and
            // slip past the guard, then be read into memory.
            if len > self.config.max_poll_response_bytes as u64 {
                return Err(Error::OversizedResponse {
                    url: url.to_string(),
                    size: usize::try_from(len).unwrap_or(usize::MAX),
                    limit: self.config.max_poll_response_bytes,
                });
            }
            let bytes = response.bytes().await.map_err(|source| Error::Transport {
                url: url.to_string(),
                stage: transport_stage_for(&source, TransportStage::ReadBody),
                source,
            })?;
            if bytes.len() > self.config.max_poll_response_bytes {
                return Err(Error::OversizedResponse {
                    url: url.to_string(),
                    size: bytes.len(),
                    limit: self.config.max_poll_response_bytes,
                });
            }
            return serde_json::from_slice(&bytes).map_err(|source| Error::Parse {
                url: url.to_string(),
                source,
            });
        }

        let mut total: usize = 0;
        let mut buffer: Vec<u8> = Vec::new();
        let mut stream = response.bytes_stream();
        while let Some(item) = stream.next().await {
            let chunk = item.map_err(|source| Error::Transport {
                url: url.to_string(),
                stage: transport_stage_for(&source, TransportStage::ReadBody),
                source,
            })?;
            total = total.saturating_add(chunk.len());
            if total > self.config.max_poll_response_bytes {
                return Err(Error::OversizedResponse {
                    url: url.to_string(),
                    size: total,
                    limit: self.config.max_poll_response_bytes,
                });
            }
            buffer.extend_from_slice(&chunk);
        }

        serde_json::from_slice(&buffer).map_err(|source| Error::Parse {
            url: url.to_string(),
            source,
        })
    }

    fn extract_and_correlate(
        &self,
        payload: PollResponse,
        url: &str,
    ) -> Result<Vec<CorrelatedInteraction>> {
        let mut correlated = Vec::new();

        // Decrypt first, then take the mappings read lock ONCE for the whole
        // correlation loop instead of re-locking per interaction. The loop body
        // only does `.get().cloned()` and `extract_nonce` (which never touches
        // `mappings`), so holding the read guard across it is cheap and cannot
        // deadlock.
        let raws = self.raw_interactions_from_payload(payload, url)?;
        let mappings = self.mappings.read().map_err(|_| Error::StatePoisoned)?;
        for raw in raws {
            if let Some(nonce) = self.extract_nonce(&raw) {
                let context_opt = mappings.get(&nonce).cloned();
                if let Some(context_val) = context_opt {
                    correlated.push(CorrelatedInteraction {
                        context: context_val,
                        event: InteractionEvent {
                            full_id: raw.full_id,
                            protocol: raw.protocol,
                            unique_id: raw.unique_id,
                            timestamp: raw.timestamp,
                            raw_request: raw.raw_request,
                            raw_response: raw.raw_response,
                        },
                    });
                }
            }
        }

        Ok(correlated)
    }

    fn raw_interactions_from_payload(
        &self,
        payload: PollResponse,
        url: &str,
    ) -> Result<Vec<RawInteraction>> {
        let mut interactions = payload.interactions;

        if !payload.data.is_empty() {
            let aes_key = payload.aes_key.ok_or_else(|| Error::Crypto {
                url: url.to_string(),
                message: "missing aes_key for encrypted data".to_string(),
            })?;

            for encrypted in payload.data {
                let decrypted = decrypt_message(&self.private_key, &aes_key, &encrypted, url)?;
                let raw =
                    serde_json::from_slice::<RawInteraction>(&decrypted).map_err(|source| {
                        Error::Parse {
                            url: url.to_string(),
                            source,
                        }
                    })?;
                interactions.push(raw);
            }
        }

        interactions.extend(payload.extra);
        interactions.extend(payload.tld_data);
        Ok(interactions)
    }

    fn extract_nonce(&self, raw: &RawInteraction) -> Option<String> {
        if let Some(nonce) = raw.full_id.strip_prefix(&self.correlation_id) {
            return (!nonce.is_empty()).then(|| nonce.to_string());
        }
        if let Some(nonce) = raw.unique_id.strip_prefix(&self.correlation_id) {
            return (!nonce.is_empty()).then(|| nonce.to_string());
        }
        None
    }

    fn base_url(&self) -> String {
        normalized_base_url(&self.config)
    }

    fn poll_url(&self) -> String {
        format!(
            "{}/poll?id={}&secret={}",
            self.base_url(),
            self.correlation_id,
            self.secret_key
        )
    }

    /// Poll URL with the session secret masked, for embedding in errors.
    fn redacted_poll_url(&self) -> String {
        format!(
            "{}/poll?id={}&secret=[redacted]",
            self.base_url(),
            self.correlation_id
        )
    }

    async fn sleep_backoff(&self, attempt: usize) {
        let base = self.config.retry_backoff_millis;
        let backoff = retry_backoff_delay(base, attempt);
        let jitter = Jitter::up_to(base).sample_thread();
        let backoff_ms = u64::try_from(backoff.as_millis()).unwrap_or(u64::MAX);
        let jitter_ms = u64::try_from(jitter.as_millis()).unwrap_or(u64::MAX);
        let delay_ms = backoff_ms.saturating_add(jitter_ms);
        sleep(Duration::from_millis(delay_ms)).await;
    }
}

fn retry_backoff_delay(base_ms: u64, attempt: usize) -> Duration {
    let exponent = attempt.saturating_sub(1).min(u32::MAX as usize) as u32;
    capped_exponential_backoff(base_ms, 2.0, exponent, u64::MAX)
}

impl std::fmt::Debug for InteractshClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InteractshClient")
            .field("config", &self.config)
            .field("correlation_id", &self.correlation_id)
            .field("secret_key", &"[redacted]")
            .field("private_key", &"[redacted]")
            .field("public_key", &self.public_key)
            .field("tracked", &self.mappings.read().map_or(0, |m| m.len()))
            .finish()
    }
}

impl std::fmt::Display for InteractshClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "InteractshClient(server={}, tracked={})",
            self.config.server,
            self.mappings.read().map_or(0, |m| m.len())
        )
    }
}

#[cfg(test)]
mod tests {
    use super::retry_backoff_delay;
    use std::time::Duration;

    #[test]
    fn retry_backoff_attempt_zero_matches_first_attempt() {
        assert_eq!(retry_backoff_delay(250, 0), Duration::from_millis(250));
    }

    #[test]
    fn retry_backoff_attempts_double_from_base() {
        assert_eq!(retry_backoff_delay(100, 1), Duration::from_millis(100));
        assert_eq!(retry_backoff_delay(100, 2), Duration::from_millis(200));
        assert_eq!(retry_backoff_delay(100, 3), Duration::from_millis(400));
    }

    #[test]
    fn retry_backoff_saturates_at_max_pacing_backoff() {
        assert_eq!(
            retry_backoff_delay(u64::MAX, usize::MAX),
            guise_pacing::MAX_PACING_BACKOFF
        );
    }
}
