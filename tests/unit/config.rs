use interactsh_client::{ClientConfig, ConfigField, ConfigProblem, Error};
use std::io::Write;
use tempfile::NamedTempFile;

#[test]
fn defaults_match_upstream_public_server_lengths() {
    let config = ClientConfig::default();
    assert_eq!(config.correlation_id_length, 20);
    assert_eq!(config.nonce_length, 13);
}

#[test]
fn omitted_toml_lengths_match_public_server_defaults() {
    let config = ClientConfig::from_toml_str("server = 'oast.pro'").unwrap();
    assert_eq!(config, ClientConfig::default());
    assert_eq!(config.correlation_id_length + config.nonce_length, 33);
}

#[test]
fn custom_server_lengths_are_preserved() {
    let config = ClientConfig::from_toml_str(
        "server = 'self-hosted.example'\ncorrelation_id_length = 14\nnonce_length = 16",
    )
    .unwrap();
    assert_eq!(config.correlation_id_length, 14);
    assert_eq!(config.nonce_length, 16);
    let parsed = ClientConfig::from_toml_str(&config.to_toml_string().unwrap()).unwrap();
    assert_eq!(parsed, config);
}

#[test]
fn default_config_is_valid() {
    let config = ClientConfig::default();
    let result = config.validate();
    assert!(result.is_ok(), "Default config must be valid");
}

#[test]
fn config_round_trip_toml() {
    let config = ClientConfig {
        server: "custom.example".into(),
        token: Some("secret".into()),
        ..ClientConfig::default()
    };
    let rendered = config.to_toml_string().unwrap();
    let parsed = ClientConfig::from_toml_str(&rendered).unwrap();
    assert_eq!(config.server, parsed.server);
    assert_eq!(config.token, parsed.token);
}

#[test]
fn config_save_and_load() {
    let config = ClientConfig {
        server: "persist.example".into(),
        ..ClientConfig::default()
    };
    let mut file = NamedTempFile::new().unwrap();
    file.write_all(config.to_toml_string().unwrap().as_bytes())
        .unwrap();
    let loaded = ClientConfig::load(file.path()).unwrap();
    assert_eq!(loaded.server, "persist.example");
}

#[test]
fn config_save_writes_toml() {
    let config = ClientConfig {
        server: "saved.example".into(),
        ..ClientConfig::default()
    };
    let file = NamedTempFile::new().unwrap();
    config.save(file.path()).unwrap();
    let raw = std::fs::read_to_string(file.path()).unwrap();
    assert!(raw.contains("saved.example"));
}

#[test]
fn config_rejects_empty_server() {
    let result = ClientConfig {
        server: "".into(),
        ..ClientConfig::default()
    }
    .validate();
    assert!(matches!(
        result.unwrap_err(),
        Error::InvalidConfig {
            field: ConfigField::Server,
            problem: ConfigProblem::Empty,
        }
    ));
}

#[test]
fn config_rejects_empty_authorization_header() {
    let result = ClientConfig {
        authorization_header: " ".into(),
        ..ClientConfig::default()
    }
    .validate();
    assert!(matches!(
        result.unwrap_err(),
        Error::InvalidConfig {
            field: ConfigField::AuthorizationHeader,
            problem: ConfigProblem::Empty,
        }
    ));
}

#[test]
fn config_rejects_empty_default_scheme() {
    let result = ClientConfig {
        default_scheme: "".into(),
        ..ClientConfig::default()
    }
    .validate();
    assert!(matches!(
        result.unwrap_err(),
        Error::InvalidConfig {
            field: ConfigField::DefaultScheme,
            problem: ConfigProblem::Empty,
        }
    ));
}

#[test]
fn config_rejects_zero_lengths() {
    let result1 = ClientConfig {
        correlation_id_length: 0,
        ..ClientConfig::default()
    }
    .validate();
    assert!(matches!(
        result1.unwrap_err(),
        Error::InvalidConfig {
            field: ConfigField::CorrelationIdLength,
            problem: ConfigProblem::MustBeGreaterThanZero,
        }
    ));

    let result2 = ClientConfig {
        nonce_length: 0,
        ..ClientConfig::default()
    }
    .validate();
    assert!(matches!(
        result2.unwrap_err(),
        Error::InvalidConfig {
            field: ConfigField::NonceLength,
            problem: ConfigProblem::MustBeGreaterThanZero,
        }
    ));
}

#[test]
fn config_rejects_zero_max_poll_response_bytes() {
    let result = ClientConfig {
        max_poll_response_bytes: 0,
        ..ClientConfig::default()
    }
    .validate();
    assert!(matches!(
        result.unwrap_err(),
        Error::InvalidConfig {
            field: ConfigField::MaxPollResponseBytes,
            problem: ConfigProblem::MustBeGreaterThanZero,
        }
    ));
}

#[test]
fn config_rejects_generated_label_overflow() {
    let correlation_too_large = ClientConfig {
        correlation_id_length: interactsh_client::MAX_GENERATED_LABEL_BYTES + 1,
        ..ClientConfig::default()
    }
    .validate();
    assert!(matches!(
        correlation_too_large.unwrap_err(),
        Error::InvalidConfig {
            field: ConfigField::CorrelationIdLength,
            problem: ConfigProblem::TooLarge,
        }
    ));

    let combined_too_large = ClientConfig {
        correlation_id_length: 32,
        nonce_length: 32,
        ..ClientConfig::default()
    }
    .validate();
    assert!(matches!(
        combined_too_large.unwrap_err(),
        Error::InvalidConfig {
            field: ConfigField::NonceLength,
            problem: ConfigProblem::TooLarge,
        }
    ));
}

#[test]
fn config_from_toml_rejects_invalid_types() {
    let error = ClientConfig::from_toml_str("server = 1").unwrap_err();
    assert!(matches!(error, Error::TomlDe(_)));
}

#[test]
fn config_from_toml_rejects_invalid_values() {
    let error = ClientConfig::from_toml_str("server = ''").unwrap_err();
    assert!(matches!(
        error,
        Error::InvalidConfig {
            field: ConfigField::Server,
            problem: ConfigProblem::Empty,
        }
    ));
}

#[test]
fn config_to_toml_rejects_invalid_values() {
    let error = ClientConfig {
        default_scheme: "".into(),
        ..ClientConfig::default()
    }
    .to_toml_string()
    .unwrap_err();
    assert!(matches!(
        error,
        Error::InvalidConfig {
            field: ConfigField::DefaultScheme,
            problem: ConfigProblem::Empty,
        }
    ));
}
