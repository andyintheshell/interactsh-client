#![allow(missing_docs)]
use crate::error::{ConfigField, ConfigProblem, Error, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

/// Default correlation ID length for generated interactsh sessions.
pub const DEFAULT_CORRELATION_ID_LENGTH: usize = 14;
/// Default nonce length for generated interactsh URLs.
pub const DEFAULT_NONCE_LENGTH: usize = 16;
/// Default maximum poll response size in bytes.
pub const DEFAULT_MAX_POLL_RESPONSE_BYTES: usize = 10 * 1024 * 1024;
/// Default HTTP header used for bearer-style authorization.
pub const DEFAULT_AUTHORIZATION_HEADER: &str = "Authorization";
/// Default URL scheme applied when the server value omits one.
pub const DEFAULT_SCHEME: &str = "https";
/// Maximum DNS label length for the generated `<correlation><nonce>` host label.
pub const MAX_GENERATED_LABEL_BYTES: usize = 63;

/// Configuration for constructing an [`crate::InteractshClient`].
///
/// `Debug` is implemented manually so a configured `token` never reaches
/// logs: it is a bearer credential for the interaction server, and the
/// derived implementation would print it in plaintext.
///
/// # Thread Safety
/// `ClientConfig` is `Send` and `Sync`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientConfig {
    pub server: String,
    #[serde(default)]
    pub token: Option<String>,
    #[serde(default = "default_authorization_header")]
    pub authorization_header: String,
    #[serde(default = "default_correlation_id_length")]
    pub correlation_id_length: usize,
    #[serde(default = "default_nonce_length")]
    pub nonce_length: usize,
    #[serde(default = "default_max_poll_response_bytes")]
    pub max_poll_response_bytes: usize,
    #[serde(default = "default_scheme_string")]
    pub default_scheme: String,
    /// If true, accept invalid TLS certificates (dangerous). Default: false.
    #[serde(default = "default_accept_invalid_certs")]
    pub accept_invalid_certs: bool,
    /// Number of retry attempts for transient failures (0 = no retries).
    #[serde(default = "default_max_retries")]
    pub max_retries: usize,
    /// Base backoff in milliseconds used for exponential backoff between retries.
    #[serde(default = "default_retry_backoff_millis")]
    pub retry_backoff_millis: u64,
    /// Optional per-request timeout in milliseconds for the underlying HTTP client.
    #[serde(default = "default_request_timeout_millis")]
    pub request_timeout_millis: Option<u64>,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            server: "oast.pro".to_string(),
            token: None,
            authorization_header: default_authorization_header(),
            correlation_id_length: default_correlation_id_length(),
            nonce_length: default_nonce_length(),
            max_poll_response_bytes: default_max_poll_response_bytes(),
            default_scheme: default_scheme_string(),
            accept_invalid_certs: default_accept_invalid_certs(),
            max_retries: default_max_retries(),
            retry_backoff_millis: default_retry_backoff_millis(),
            request_timeout_millis: default_request_timeout_millis(),
        }
    }
}

impl ClientConfig {
    /// Validate the configuration before client construction.
    pub fn validate(&self) -> Result<()> {
        validate_non_empty(&self.server, ConfigField::Server)?;
        validate_positive(self.correlation_id_length, ConfigField::CorrelationIdLength)?;
        validate_positive(self.nonce_length, ConfigField::NonceLength)?;
        validate_generated_label_lengths(self.correlation_id_length, self.nonce_length)?;
        validate_positive(
            self.max_poll_response_bytes,
            ConfigField::MaxPollResponseBytes,
        )?;
        validate_non_empty(&self.authorization_header, ConfigField::AuthorizationHeader)?;
        validate_non_empty(&self.default_scheme, ConfigField::DefaultScheme)?;
        Ok(())
    }

    pub fn from_toml_str(input: &str) -> Result<Self> {
        let config: Self = toml::from_str(input)?;
        config.validate()?;
        Ok(config)
    }

    pub fn to_toml_string(&self) -> Result<String> {
        self.validate()?;
        Ok(toml::to_string_pretty(self)?)
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let contents = fs::read_to_string(path)?;
        Self::from_toml_str(&contents)
    }

    pub fn save(&self, path: impl AsRef<Path>) -> Result<()> {
        fs::write(path, self.to_toml_string()?)?;
        Ok(())
    }
}

impl std::fmt::Debug for ClientConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientConfig")
            .field("server", &self.server)
            .field("token", &self.token.as_ref().map(|_| "[redacted]"))
            .field("authorization_header", &self.authorization_header)
            .field("correlation_id_length", &self.correlation_id_length)
            .field("nonce_length", &self.nonce_length)
            .field("max_poll_response_bytes", &self.max_poll_response_bytes)
            .field("default_scheme", &self.default_scheme)
            .field("accept_invalid_certs", &self.accept_invalid_certs)
            .field("max_retries", &self.max_retries)
            .field("retry_backoff_millis", &self.retry_backoff_millis)
            .field("request_timeout_millis", &self.request_timeout_millis)
            .finish()
    }
}

impl std::fmt::Display for ClientConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ClientConfig(server={}, correlation_id_length={}, nonce_length={})",
            self.server, self.correlation_id_length, self.nonce_length
        )
    }
}

impl TryFrom<&str> for ClientConfig {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self> {
        Self::from_toml_str(value)
    }
}

fn validate_non_empty(value: &str, field: ConfigField) -> Result<()> {
    if value.trim().is_empty() {
        return Err(Error::InvalidConfig {
            field,
            problem: ConfigProblem::Empty,
        });
    }
    Ok(())
}

fn validate_positive(value: usize, field: ConfigField) -> Result<()> {
    if value == 0 {
        return Err(Error::InvalidConfig {
            field,
            problem: ConfigProblem::MustBeGreaterThanZero,
        });
    }
    Ok(())
}

fn validate_generated_label_lengths(
    correlation_id_length: usize,
    nonce_length: usize,
) -> Result<()> {
    if correlation_id_length > MAX_GENERATED_LABEL_BYTES {
        return Err(Error::InvalidConfig {
            field: ConfigField::CorrelationIdLength,
            problem: ConfigProblem::TooLarge,
        });
    }
    if nonce_length > MAX_GENERATED_LABEL_BYTES
        || correlation_id_length.saturating_add(nonce_length) > MAX_GENERATED_LABEL_BYTES
    {
        return Err(Error::InvalidConfig {
            field: ConfigField::NonceLength,
            problem: ConfigProblem::TooLarge,
        });
    }
    Ok(())
}

fn default_authorization_header() -> String {
    DEFAULT_AUTHORIZATION_HEADER.to_string()
}

fn default_correlation_id_length() -> usize {
    DEFAULT_CORRELATION_ID_LENGTH
}

fn default_nonce_length() -> usize {
    DEFAULT_NONCE_LENGTH
}

fn default_max_poll_response_bytes() -> usize {
    DEFAULT_MAX_POLL_RESPONSE_BYTES
}

fn default_scheme_string() -> String {
    DEFAULT_SCHEME.to_string()
}

fn default_accept_invalid_certs() -> bool {
    false
}

fn default_max_retries() -> usize {
    3
}

fn default_retry_backoff_millis() -> u64 {
    100
}

fn default_request_timeout_millis() -> Option<u64> {
    None
}
