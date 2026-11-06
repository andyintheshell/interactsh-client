use interactsh_client::ClientConfig;

/// Regression: `ClientConfig` used to derive `Debug`, which printed the
/// bearer `token` in plaintext. The token authenticates every request to the
/// interaction server, so one `{:?}` in a scan log would publish it. The
/// manual `Debug` impl must mask the token while keeping every other field
/// visible for troubleshooting.
#[test]
fn client_config_debug_redacts_token() {
    let config = ClientConfig {
        server: "redact.example".into(),
        token: Some("super-secret-token-value".into()),
        ..ClientConfig::default()
    };
    let rendered = format!("{config:?}");
    assert!(
        !rendered.contains("super-secret-token-value"),
        "Debug must not contain the token: {rendered}"
    );
    assert!(
        rendered.contains("[redacted]"),
        "Debug must show that a token is set: {rendered}"
    );
    assert!(
        rendered.contains("redact.example"),
        "Debug must keep non-secret fields: {rendered}"
    );
}

/// Boundary twin of `client_config_debug_redacts_token`: with no token
/// configured the redaction marker must not appear, so operators can tell
/// "no token" apart from "token set but hidden".
#[test]
fn client_config_debug_shows_none_token_without_redaction() {
    let config = ClientConfig {
        server: "redact.example".into(),
        token: None,
        ..ClientConfig::default()
    };
    let rendered = format!("{config:?}");
    assert!(
        rendered.contains("token: None"),
        "Debug must show token: None when unset: {rendered}"
    );
    assert!(
        !rendered.contains("[redacted]"),
        "Debug must not claim a redacted token when none is set: {rendered}"
    );
}
