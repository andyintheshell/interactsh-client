#![allow(missing_docs)]
use reqwest::StatusCode;

/// Which configuration field failed validation.
///
/// # Thread Safety
/// `ConfigField` is `Send` and `Sync`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConfigField {
    Server,
    CorrelationIdLength,
    NonceLength,
    MaxPollResponseBytes,
    AuthorizationHeader,
    DefaultScheme,
}

/// Why a configuration field failed validation.
///
/// # Thread Safety
/// `ConfigProblem` is `Send` and `Sync`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConfigProblem {
    Empty,
    MustBeGreaterThanZero,
    TooLarge,
}

/// Which transport phase failed while communicating with the interactsh service.
///
/// # Thread Safety
/// `TransportStage` is `Send` and `Sync`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TransportStage {
    Send,
    ReadBody,
    Timeout,
    HttpStatus,
}

/// Public error type for interactsh operations.
///
/// # Thread Safety
/// `Error` is `Send` and `Sync`.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("{message}", message = format_invalid_config(*field, *problem))]
    InvalidConfig {
        field: ConfigField,
        problem: ConfigProblem,
    },
    #[error("transport error during {stage:?} while calling {url}: {source}. Fix: verify the interactsh server URL, network reachability, TLS settings, and any configured authorization token.")]
    Transport {
        url: String,
        stage: TransportStage,
        #[source]
        source: reqwest::Error,
    },
    #[error("unexpected HTTP status {status} while calling {url}. Fix: verify the server endpoint, token, and scheme, or inspect the server response body with a manual request.")]
    HttpStatus { url: String, status: StatusCode },
    #[error("failed to parse the interactsh poll response from {url}: {source}. Fix: verify the server is returning the expected JSON schema for `/poll`.")]
    Parse {
        url: String,
        #[source]
        source: serde_json::Error,
    },
    #[error("poll response from {url} exceeded the configured size limit ({size} > {limit}). Fix: raise `max_poll_response_bytes` only if you trust the interactsh server or poll more frequently.")]
    OversizedResponse {
        url: String,
        size: usize,
        limit: usize,
    },
    #[error("failed to register interactsh session with {url}. Fix: verify `/register` is reachable, the token is valid, and the server accepts RSA client registration.")]
    Registration { url: String },
    #[error("failed to decode an interactsh encrypted payload from {url}: {message}. Fix: verify the server and client are using the same RSA registration session and AES response format.")]
    Crypto { url: String, message: String },
    #[error("failed to access interactsh correlation state. Fix: avoid poisoning the client mutex from panicking callbacks and create a fresh client if necessary.")]
    StatePoisoned,
    #[error(
        "interactsh I/O error: {0}. Fix: verify the config file path is readable and writable."
    )]
    Io(#[from] std::io::Error),
    #[error("failed to parse interactsh TOML configuration: {0}. Fix: use top-level keys such as `server`, `token`, `correlation_id_length`, and `nonce_length`.")]
    TomlDe(#[from] toml::de::Error),
    #[error("failed to serialize interactsh TOML configuration: {0}. Fix: remove unsupported values and retry saving the config.")]
    TomlSer(#[from] toml::ser::Error),
}

impl Error {
    pub fn is_timeout(&self) -> bool {
        matches!(self, Self::Transport { source, .. } if source.is_timeout())
    }
}

/// Convenience result alias for interactsh operations.
pub type Result<T> = std::result::Result<T, Error>;

impl std::fmt::Display for ConfigField {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = match self {
            Self::Server => "server",
            Self::CorrelationIdLength => "correlation_id_length",
            Self::NonceLength => "nonce_length",
            Self::MaxPollResponseBytes => "max_poll_response_bytes",
            Self::AuthorizationHeader => "authorization_header",
            Self::DefaultScheme => "default_scheme",
        };
        f.write_str(value)
    }
}

impl std::fmt::Display for ConfigProblem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = match self {
            Self::Empty => "empty",
            Self::MustBeGreaterThanZero => "must-be-greater-than-zero",
            Self::TooLarge => "too-large",
        };
        f.write_str(value)
    }
}

impl std::fmt::Display for TransportStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = match self {
            Self::Send => "send",
            Self::ReadBody => "read-body",
            Self::Timeout => "timeout",
            Self::HttpStatus => "http-status",
        };
        f.write_str(value)
    }
}

fn format_invalid_config(field: ConfigField, problem: ConfigProblem) -> String {
    let field_name = match field {
        ConfigField::Server => "`server`",
        ConfigField::CorrelationIdLength => "`correlation_id_length`",
        ConfigField::NonceLength => "`nonce_length`",
        ConfigField::MaxPollResponseBytes => "`max_poll_response_bytes`",
        ConfigField::AuthorizationHeader => "`authorization_header`",
        ConfigField::DefaultScheme => "`default_scheme`",
    };
    let requirement = match problem {
        ConfigProblem::Empty => "must not be empty",
        ConfigProblem::MustBeGreaterThanZero => "must be greater than zero",
        ConfigProblem::TooLarge => "must fit in the generated DNS label",
    };
    format!(
        "invalid interactsh config: {field_name} {requirement}. Fix: update the config and rerun client construction."
    )
}
