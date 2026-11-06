use crate::config::ClientConfig;
use crate::error::TransportStage;
use std::error::Error as StdError;

pub fn normalized_base_url(config: &ClientConfig) -> String {
    if config.server.starts_with("http://") || config.server.starts_with("https://") {
        config.server.trim_end_matches('/').to_string()
    } else {
        format!(
            "{}://{}",
            config.default_scheme.trim_end_matches("://"),
            config.server.trim_end_matches('/')
        )
    }
}

/// Bare host authority of `config.server` for use as a DNS callback label
/// suffix. Strips any `http://`/`https://` scheme and any path/trailing slash so
/// a scheme- or path-qualified server (`http://oast.pro`, `oast.pro/x`) never
/// produces a malformed callback host such as `<id><nonce>.http://oast.pro`.
/// ONE-PLACE for turning a configured server into a hostname (a DNS/HTTP
/// out-of-band callback cannot carry a scheme or path in its host label).
pub fn server_host(config: &ClientConfig) -> &str {
    let authority = config
        .server
        .strip_prefix("http://")
        .or_else(|| config.server.strip_prefix("https://"))
        .unwrap_or(config.server.as_str());
    match authority.find('/') {
        Some(idx) => &authority[..idx],
        None => authority,
    }
}

pub fn transport_stage_for(
    error: &reqwest::Error,
    default_stage: TransportStage,
) -> TransportStage {
    if error.is_timeout() {
        return TransportStage::Timeout;
    }

    let mut src = (error as &dyn StdError).source();
    while let Some(s) = src {
        if let Some(ioerr) = s.downcast_ref::<std::io::Error>() {
            match ioerr.kind() {
                std::io::ErrorKind::TimedOut
                | std::io::ErrorKind::WouldBlock
                | std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::ConnectionRefused => {
                    return TransportStage::Timeout;
                }
                _ => {}
            }
        }
        src = s.source();
    }

    default_stage
}

pub fn should_retry_status(status: reqwest::StatusCode) -> bool {
    status.as_u16() == 429 || status.is_server_error()
}

pub fn is_connection_refused(error: &reqwest::Error) -> bool {
    let mut src = (error as &dyn StdError).source();
    while let Some(s) = src {
        if let Some(ioerr) = s.downcast_ref::<std::io::Error>() {
            if ioerr.kind() == std::io::ErrorKind::ConnectionRefused {
                return true;
            }
        }
        src = s.source();
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(server: &str) -> ClientConfig {
        ClientConfig {
            server: server.to_string(),
            ..ClientConfig::default()
        }
    }

    #[test]
    fn server_host_strips_scheme_prefix() {
        // Regression for core.rs:127: a scheme-qualified server must NOT leak the
        // scheme into the DNS callback host label.
        assert_eq!(server_host(&cfg("http://oast.pro")), "oast.pro");
        assert_eq!(server_host(&cfg("https://oast.pro")), "oast.pro");
    }

    #[test]
    fn server_host_strips_trailing_slash_and_path() {
        assert_eq!(server_host(&cfg("https://oast.pro/")), "oast.pro");
        assert_eq!(server_host(&cfg("http://oast.pro/register")), "oast.pro");
        assert_eq!(server_host(&cfg("oast.pro/x")), "oast.pro");
    }

    #[test]
    fn server_host_bare_domain_unchanged() {
        assert_eq!(server_host(&cfg("oast.pro")), "oast.pro");
        assert_eq!(server_host(&cfg("sub.oast.pro")), "sub.oast.pro");
    }
}
