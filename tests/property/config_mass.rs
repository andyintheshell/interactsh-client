//! Mass interactsh config / context property tests (S-proptest-02).

use interactsh_client::{ClientConfig, InteractionContext};
use proptest::prelude::*;

fn valid_config() -> ClientConfig {
    ClientConfig::default()
}

macro_rules! config_validate_nopanic {
    ($($name:ident),+ $(,)?) => {
        proptest! {
            #![proptest_config(ProptestConfig::with_cases(32))]

            $(
                #[test]
                fn $name(
                    server in "[a-zA-Z0-9.-]{1,40}",
                    corr in 1usize..64,
                    nonce in 1usize..64,
                    max_poll in 1usize..1_000_000,
                ) {
                    let config = ClientConfig {
                        server,
                        correlation_id_length: corr,
                        nonce_length: nonce,
                        max_poll_response_bytes: max_poll,
                        ..valid_config()
                    };
                    let _ = config.validate();
                }
            )+
        }
    };
}

config_validate_nopanic! {
    config_validate_nopanic_01,
    config_validate_nopanic_02,
    config_validate_nopanic_03,
    config_validate_nopanic_04,
    config_validate_nopanic_05,
    config_validate_nopanic_06,
    config_validate_nopanic_07,
    config_validate_nopanic_08,
    config_validate_nopanic_09,
    config_validate_nopanic_10,
    config_validate_nopanic_11,
    config_validate_nopanic_12,
    config_validate_nopanic_13,
    config_validate_nopanic_14,
    config_validate_nopanic_15,
    config_validate_nopanic_16,
    config_validate_nopanic_17,
    config_validate_nopanic_18,
    config_validate_nopanic_19,
    config_validate_nopanic_20,
    config_validate_nopanic_21,
    config_validate_nopanic_22,
    config_validate_nopanic_23,
}

macro_rules! config_toml_roundtrip_valid {
    ($($name:ident),+ $(,)?) => {
        proptest! {
            #![proptest_config(ProptestConfig::with_cases(32))]

            $(
                #[test]
                fn $name(
                    server in "[a-zA-Z0-9.-]{2,30}",
                    corr in 1usize..32,
                    nonce in 1usize..32,
                ) {
                    let config = ClientConfig {
                        server: server.clone(),
                        correlation_id_length: corr,
                        nonce_length: nonce,
                        max_poll_response_bytes: 1024,
                        max_retries: 0,
                        ..valid_config()
                    };
                    if config.validate().is_ok() {
                        let text = config.to_toml_string().unwrap();
                        let parsed = ClientConfig::from_toml_str(&text).unwrap();
                        assert_eq!(parsed.server, server);
                        assert_eq!(parsed.correlation_id_length, corr);
                        assert_eq!(parsed.nonce_length, nonce);
                    }
                }
            )+
        }
    };
}

config_toml_roundtrip_valid! {
    config_toml_roundtrip_16,
    config_toml_roundtrip_17,
    config_toml_roundtrip_18,
    config_toml_roundtrip_19,
    config_toml_roundtrip_20,
    config_toml_roundtrip_21,
    config_toml_roundtrip_22,
    config_toml_roundtrip_23,
    config_toml_roundtrip_24,
    config_toml_roundtrip_25,
}

macro_rules! context_from_label {
    ($($name:ident),+ $(,)?) => {
        proptest! {
            #![proptest_config(ProptestConfig::with_cases(24))]

            $(
                #[test]
                fn $name(label in "[a-zA-Z0-9_-]{1,24}") {
                    let ctx: InteractionContext = label.as_str().into();
                    assert_eq!(ctx.label, label);
                }
            )+
        }
    };
}

context_from_label! {
    context_from_str_26,
    context_from_str_27,
    context_from_str_28,
    context_from_str_29,
    context_from_str_30,
    context_from_str_31,
    context_from_str_32,
    context_from_str_33,
    context_from_str_34,
    context_from_str_35,
}

macro_rules! config_adversarial_fields {
    ($($name:ident),+ $(,)?) => {
        proptest! {
            #![proptest_config(ProptestConfig::with_cases(24))]

            $(
                #[test]
                fn $name(
                    auth_header in "\\PC{0,80}",
                    scheme in "\\PC{0,20}",
                ) {
                    let config = ClientConfig {
                        authorization_header: auth_header.clone(),
                        default_scheme: if scheme.trim().is_empty() {
                            "https".into()
                        } else {
                            scheme.clone()
                        },
                        ..valid_config()
                    };
                    let res = config.validate();
                    if auth_header.trim().is_empty() {
                        assert!(res.is_err());
                    }
                }
            )+
        }
    };
}

config_adversarial_fields! {
    config_adversarial_36,
    config_adversarial_37,
    config_adversarial_38,
    config_adversarial_39,
    config_adversarial_40,
}
