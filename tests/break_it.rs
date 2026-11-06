use interactsh::{
    ClientConfig, ConfigField, ConfigProblem, Error, InteractionContext, InteractshClient,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::sync::Arc;

// --- Category 1 & 9: Empty input / zero-length slices & off-by-one ---

#[tokio::test]
async fn test_config_empty_server() {
    let mut config = ClientConfig::default();
    config.server = "".to_string();
    let res = config.validate();
    assert!(matches!(
        res,
        Err(Error::InvalidConfig {
            problem: ConfigProblem::Empty,
            field: ConfigField::Server
        })
    ));
}

#[tokio::test]
async fn test_config_whitespace_server() {
    let mut config = ClientConfig::default();
    config.server = "   ".to_string();
    let res = config.validate();
    assert!(matches!(
        res,
        Err(Error::InvalidConfig {
            problem: ConfigProblem::Empty,
            field: ConfigField::Server
        })
    ));
}

#[tokio::test]
async fn test_config_zero_correlation_length() {
    let mut config = ClientConfig::default();
    config.correlation_id_length = 0;
    let res = config.validate();
    assert!(matches!(
        res,
        Err(Error::InvalidConfig {
            problem: ConfigProblem::MustBeGreaterThanZero,
            field: ConfigField::CorrelationIdLength
        })
    ));
}

#[tokio::test]
async fn test_config_zero_nonce_length() {
    let mut config = ClientConfig::default();
    config.nonce_length = 0;
    let res = config.validate();
    assert!(matches!(
        res,
        Err(Error::InvalidConfig {
            problem: ConfigProblem::MustBeGreaterThanZero,
            field: ConfigField::NonceLength
        })
    ));
}

#[tokio::test]
async fn test_config_zero_poll_response_bytes() {
    let mut config = ClientConfig::default();
    config.max_poll_response_bytes = 0;
    let res = config.validate();
    assert!(matches!(
        res,
        Err(Error::InvalidConfig {
            problem: ConfigProblem::MustBeGreaterThanZero,
            field: ConfigField::MaxPollResponseBytes
        })
    ));
}

#[tokio::test]
async fn test_config_empty_auth_header() {
    let mut config = ClientConfig::default();
    config.authorization_header = "".to_string();
    let res = config.validate();
    assert!(matches!(
        res,
        Err(Error::InvalidConfig {
            problem: ConfigProblem::Empty,
            field: ConfigField::AuthorizationHeader
        })
    ));
}

#[tokio::test]
async fn test_config_empty_scheme() {
    let mut config = ClientConfig::default();
    config.default_scheme = "".to_string();
    let res = config.validate();
    assert!(matches!(
        res,
        Err(Error::InvalidConfig {
            problem: ConfigProblem::Empty,
            field: ConfigField::DefaultScheme
        })
    ));
}

#[tokio::test]
async fn test_interaction_context_empty_label() {
    let context = InteractionContext::new("");
    assert_eq!(context.label, "");
}

// --- Category 2: Null bytes in input ---

#[tokio::test]
async fn test_config_server_null_byte() {
    let mut config = ClientConfig::default();
    config.server = "oast.pro\0".to_string();
    assert!(config.validate().is_ok());
    let res_client = InteractshClient::new(config).await;
    assert!(res_client.is_err());
}

#[tokio::test]
async fn test_context_label_null_byte() {
    let context = InteractionContext::new("null\0byte");
    assert_eq!(context.label, "null\0byte");
}

#[tokio::test]
async fn test_context_attr_null_byte() {
    let context = InteractionContext::new("test").with_attribute("key\0", "val\0");
    assert_eq!(context.attributes.get("key\0").unwrap(), "val\0");
}

// --- Category 3: Maximum u32/u64 values ---

#[tokio::test]
async fn test_config_max_correlation_length() {
    let mut config = ClientConfig::default();
    config.correlation_id_length = usize::MAX;
    let result = std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(InteractshClient::new(config)).unwrap_err();
    })
    .join();
    assert!(
        result.is_ok(),
        "Client creation with usize::MAX correlation_id_length should gracefully error"
    );
}

#[tokio::test]
async fn test_config_max_nonce_length() {
    let mut config = ClientConfig::default();
    config.nonce_length = usize::MAX;
    let result = std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(InteractshClient::new(config)).unwrap_err();
    })
    .join();
    assert!(
        result.is_ok(),
        "Client creation with usize::MAX nonce_length should gracefully error"
    );
}

#[tokio::test]
async fn test_config_max_poll_response() {
    let mut config = ClientConfig::default();
    config.max_poll_response_bytes = usize::MAX;
    assert!(config.validate().is_ok());
}

#[tokio::test]
async fn test_config_max_retries() {
    let mut config = ClientConfig::default();
    config.max_retries = usize::MAX;
    assert!(config.validate().is_ok());
}

#[tokio::test]
async fn test_config_max_backoff() {
    let mut config = ClientConfig::default();
    config.retry_backoff_millis = u64::MAX;
    assert!(config.validate().is_ok());
}

// --- Category 4: 1MB+ input ---

async fn mock_poll_server(
    response_body: String,
    chunked: bool,
) -> (u16, tokio::task::JoinHandle<()>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let server_task = tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let mut buf = [0; 1024];
            let _ = socket.read(&mut buf).await;
            let req_str = String::from_utf8_lossy(&buf);

            if req_str.contains("/register") {
                let response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}";
                let _ = socket.write_all(response.as_bytes()).await;
            } else if req_str.contains("/poll") {
                let response = if chunked {
                    format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{}\r\n0\r\n\r\n", response_body.len(), response_body)
                } else {
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
                        response_body.len(),
                        response_body
                    )
                };
                let _ = socket.write_all(response.as_bytes()).await;
            }
        }
    });

    (port, server_task)
}

#[tokio::test]
async fn test_massive_json_response_size_limit() {
    let mut massive_json = String::from("{\"interactions\": [], \"data\": [");
    for _i in 0..50000 {
        massive_json.push_str("\"duplicate_data\",");
    }
    massive_json.push_str("\"end\"]}");

    let (port, server_task) = mock_poll_server(massive_json, false).await;

    let mut config = ClientConfig::default();
    config.server = format!("http://127.0.0.1:{}", port);
    config.max_poll_response_bytes = 1000;
    config.max_retries = 0;

    let client = InteractshClient::new(config).await.unwrap();
    let poll_res = client.poll().await;

    assert!(matches!(poll_res, Err(Error::OversizedResponse { .. })));
    server_task.abort();
}

#[tokio::test]
async fn test_massive_json_response_size_limit_chunked() {
    let mut massive_json = String::from("{\"interactions\": [], \"data\": [");
    for _i in 0..50000 {
        massive_json.push_str("\"duplicate_data\",");
    }
    massive_json.push_str("\"end\"]}");

    let (port, server_task) = mock_poll_server(massive_json, true).await;

    let mut config = ClientConfig::default();
    config.server = format!("http://127.0.0.1:{}", port);
    config.max_poll_response_bytes = 1000;
    config.max_retries = 0;

    let client = InteractshClient::new(config).await.unwrap();
    let poll_res = client.poll().await;

    assert!(matches!(poll_res, Err(Error::OversizedResponse { .. })));
    server_task.abort();
}

// --- Category 5: Concurrent access (8 threads) ---

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn test_concurrency_8_threads_hammer_cache() {
    let (port, server_task) = mock_poll_server("{}".to_string(), false).await;
    let mut config = ClientConfig::default();
    config.server = format!("http://127.0.0.1:{}", port);
    config.max_retries = 0;

    let client = Arc::new(InteractshClient::new(config).await.unwrap());

    let mut tasks = vec![];
    for i in 0..8 {
        let c = Arc::clone(&client);
        tasks.push(tokio::spawn(async move {
            for j in 0..1000 {
                let url = c
                    .generate_url(InteractionContext::new(format!("thread_{}_{}", i, j)))
                    .unwrap();
                if j % 50 == 0 {
                    let _ = c.tracked_count().unwrap();
                }
                if j % 2 == 0 {
                    let forgotten = c.forget(&url.nonce).unwrap();
                    assert!(forgotten.is_some());
                }
            }
        }));
    }

    for task in tasks {
        task.await.unwrap();
    }

    assert_eq!(client.tracked_count().unwrap(), 4000);
    server_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn test_concurrency_tracked_count_under_load() {
    let (port, server_task) = mock_poll_server("{}".to_string(), false).await;
    let mut config = ClientConfig::default();
    config.server = format!("http://127.0.0.1:{}", port);
    config.max_retries = 0;
    let client = Arc::new(InteractshClient::new(config).await.unwrap());

    let mut tasks = vec![];
    for _ in 0..8 {
        let c = Arc::clone(&client);
        tasks.push(tokio::spawn(async move {
            for _ in 0..1000 {
                let _ = c.tracked_count().unwrap();
            }
        }));
    }
    for task in tasks {
        task.await.unwrap();
    }
    server_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn test_concurrency_forget_nonexistent() {
    let (port, server_task) = mock_poll_server("{}".to_string(), false).await;
    let mut config = ClientConfig::default();
    config.server = format!("http://127.0.0.1:{}", port);
    config.max_retries = 0;
    let client = Arc::new(InteractshClient::new(config).await.unwrap());

    let mut tasks = vec![];
    for i in 0..8 {
        let c = Arc::clone(&client);
        tasks.push(tokio::spawn(async move {
            for j in 0..100 {
                let forgotten = c.forget(&format!("fake_{}_{}", i, j)).unwrap();
                assert!(forgotten.is_none());
            }
        }));
    }
    for task in tasks {
        task.await.unwrap();
    }
    server_task.abort();
}

// --- Category 6: Malformed/truncated input ---

#[tokio::test]
async fn test_poll_response_truncated_json() {
    let (port, server_task) =
        mock_poll_server("{\"interactions\": [], \"da".to_string(), false).await;
    let mut config = ClientConfig::default();
    config.server = format!("http://127.0.0.1:{}", port);
    config.max_retries = 0;

    let client = InteractshClient::new(config).await.unwrap();
    let poll_res = client.poll().await;
    assert!(matches!(poll_res, Err(Error::Parse { .. })));
    server_task.abort();
}

#[tokio::test]
async fn test_poll_response_missing_aes_key() {
    let body = "{\"interactions\": [], \"data\": [\"enc_data_here\"]}".to_string();
    let (port, server_task) = mock_poll_server(body, false).await;
    let mut config = ClientConfig::default();
    config.server = format!("http://127.0.0.1:{}", port);
    config.max_retries = 0;

    let client = InteractshClient::new(config).await.unwrap();
    let poll_res = client.poll().await;
    assert!(matches!(poll_res, Err(Error::Crypto { .. })));
    server_task.abort();
}

#[tokio::test]
async fn test_poll_response_invalid_aes_key() {
    let body =
        "{\"interactions\": [], \"data\": [\"enc_data_here\"], \"aes_key\": \"not_base64!!!\"}"
            .to_string();
    let (port, server_task) = mock_poll_server(body, false).await;
    let mut config = ClientConfig::default();
    config.server = format!("http://127.0.0.1:{}", port);
    config.max_retries = 0;

    let client = InteractshClient::new(config).await.unwrap();
    let poll_res = client.poll().await;
    // Will fail during decryption due to bad base64
    assert!(matches!(poll_res, Err(Error::Crypto { .. })));
    server_task.abort();
}

#[tokio::test]
async fn test_poll_response_invalid_encrypted_data() {
    let body = "{\"interactions\": [], \"data\": [\"not_base64!!!\"], \"aes_key\": \"AABBCCDD\"}"
        .to_string();
    let (port, server_task) = mock_poll_server(body, false).await;
    let mut config = ClientConfig::default();
    config.server = format!("http://127.0.0.1:{}", port);
    config.max_retries = 0;

    let client = InteractshClient::new(config).await.unwrap();
    let poll_res = client.poll().await;
    assert!(matches!(poll_res, Err(Error::Crypto { .. })));
    server_task.abort();
}

#[tokio::test]
async fn test_poll_response_malformed_raw_interaction() {
    let body = "{\"interactions\": [{\"full-id\": \"foo\"}]}".to_string(); // missing protocol, timestamp, etc
    let (port, server_task) = mock_poll_server(body, false).await;
    let mut config = ClientConfig::default();
    config.server = format!("http://127.0.0.1:{}", port);
    config.max_retries = 0;

    let client = InteractshClient::new(config).await.unwrap();
    let poll_res = client.poll().await;
    assert!(matches!(poll_res, Err(Error::Parse { .. })));
    server_task.abort();
}
#[tokio::test]
async fn test_poll_response_extra_supports_objects_and_strings() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listener_port = listener.local_addr().unwrap().port();
    let generated_nonce = Arc::new(tokio::sync::Mutex::new(String::new()));
    let nonce_clone = generated_nonce.clone();

    let server_task = tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let mut buf = [0u8; 1024];
            let n = stream.read(&mut buf).await.unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]);

            if req.contains("/register") {
                let resp = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}";
                let _ = stream.write_all(resp.as_bytes()).await;
            } else if req.contains("/poll") {
                let cid = req
                    .split("id=")
                    .nth(1)
                    .and_then(|s| s.split('&').next())
                    .unwrap_or("cid");
                let nonce = nonce_clone.lock().await.clone();
                let full_id = format!("{cid}{nonce}");
                let raw_obj = format!(
                    r#"{{"full-id": "{full_id}", "protocol": "http", "unique-id": "{full_id}", "timestamp": "2026-08-07T00:00:00Z"}}"#
                );
                let body = format!(
                    r#"{{"extra": [{}, "{}"], "tlddata": []}}"#,
                    raw_obj,
                    raw_obj.replace('"', "\\\"")
                );
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes()).await;
            }
        }
    });

    let mut config = ClientConfig::default();
    config.server = format!("http://127.0.0.1:{}", listener_port);
    config.max_retries = 0;

    let client = InteractshClient::new(config).await.unwrap();
    let gen = client
        .generate_url(InteractionContext::new("test-ctx"))
        .unwrap();
    *generated_nonce.lock().await = gen.nonce;

    let poll_res = client.poll().await.unwrap();
    assert_eq!(poll_res.len(), 2, "both object and string extra interactions must be parsed and correlated");
    server_task.abort();
}

// --- Category 7: Unicode edge cases ---

#[tokio::test]
async fn test_context_bom() {
    let context = InteractionContext::new("\u{feff}label_with_bom");
    assert_eq!(context.label, "\u{feff}label_with_bom");
}

#[tokio::test]
async fn test_context_fake_surrogate() {
    let unprintable = String::from_utf8_lossy(&[0xed, 0xa0, 0x80]).to_string();
    let context = InteractionContext::new("test").with_attribute("surrogate_replaced", unprintable);
    let value = context.attributes.get("surrogate_replaced").unwrap();
    assert_eq!(value.chars().count(), 3);
    assert!(value.chars().all(|ch| ch == char::REPLACEMENT_CHARACTER));
}

#[tokio::test]
async fn test_context_emojis() {
    let context = InteractionContext::new("test").with_attribute("weird", "🔥👩‍🚒🧯");
    assert_eq!(context.attributes.get("weird").unwrap(), "🔥👩‍🚒🧯");
}

#[tokio::test]
async fn test_config_unicode_domain() {
    let mut config = ClientConfig::default();
    config.server = "http://öäü.com".to_string();
    config.max_retries = 0;
    let client_res = InteractshClient::new(config).await;
    assert!(client_res.is_err());
}

// --- Category 8: Duplicate entries ---

#[tokio::test]
async fn test_context_duplicate_attribute_keys() {
    let context = InteractionContext::new("test")
        .with_attribute("dup", "val1")
        .with_attribute("dup", "val2");
    assert_eq!(context.attributes.get("dup").unwrap(), "val2");
}

#[tokio::test]
async fn test_context_duplicate_generation_nonces() {
    let (port, server_task) = mock_poll_server("{}".to_string(), false).await;
    let mut config = ClientConfig::default();
    config.server = format!("http://127.0.0.1:{}", port);
    config.max_retries = 0;

    let client = InteractshClient::new(config).await.unwrap();
    // Forcing an internal nonce duplicate isn't possible from public API since it generates it randomly,
    // but we can make sure the tracked count increments properly across multiple generated URLs.
    let url1 = client.generate_url(InteractionContext::new("1")).unwrap();
    let url2 = client.generate_url(InteractionContext::new("2")).unwrap();
    assert_ne!(url1.nonce, url2.nonce);
    server_task.abort();
}

// --- Category 12: Secret redaction (regression) ---

/// Regression: poll-path errors used to embed the full poll URL, including
/// the `?id=...&secret=...` query string. The secret authenticates `/poll`,
/// so any error bubbled into a scan log published read access to every
/// captured interaction. Errors must carry the redacted URL instead.
#[tokio::test]
async fn test_poll_error_url_redacts_secret() {
    let (port, server_task) = mock_poll_server("{}".to_string(), false).await;
    let mut config = ClientConfig::default();
    config.server = format!("http://127.0.0.1:{}", port);
    config.max_poll_response_bytes = 1; // force OversizedResponse on the "{}" body
    config.max_retries = 0;

    let client = InteractshClient::new(config).await.unwrap();
    let secret = client.secret_key().to_string();
    let err = client
        .poll()
        .await
        .expect_err("1-byte limit must reject the 2-byte body");
    let message = err.to_string();
    assert!(
        !message.contains(&secret),
        "error must not contain the session secret: {message}"
    );
    assert!(
        message.contains("secret=[redacted]") ,
        "error must carry the redacted poll URL: {message}"
    );
    server_task.abort();
}

/// Regression: `InteractshClient` used to derive `Debug`, printing the
/// session `secret_key` (and RSA key material) in plaintext. Both guard
/// every captured interaction, so the manual `Debug` impl must mask them
/// while keeping non-secret fields useful for troubleshooting.
#[tokio::test]
async fn test_client_debug_redacts_secret_key() {
    let (port, server_task) = mock_poll_server("{}".to_string(), false).await;
    let mut config = ClientConfig::default();
    config.server = format!("http://127.0.0.1:{}", port);
    config.max_retries = 0;

    let client = InteractshClient::new(config).await.unwrap();
    let secret = client.secret_key().to_string();
    let rendered = format!("{client:?}");
    assert!(
        !rendered.contains(&secret),
        "Debug must not contain the session secret: {rendered}"
    );
    assert!(
        rendered.contains("[redacted]"),
        "Debug must mark redacted fields: {rendered}"
    );
    assert!(
        rendered.contains(client.correlation_id()),
        "Debug must keep the non-secret correlation id: {rendered}"
    );
    server_task.abort();
}

// --- Category 10: Resource exhaustion ---

#[tokio::test]
async fn test_resource_100k_mappings() {
    let (port, server_task) = mock_poll_server("{}".to_string(), false).await;
    let mut config = ClientConfig::default();
    config.server = format!("http://127.0.0.1:{}", port);
    config.max_retries = 0;

    let client = InteractshClient::new(config).await.unwrap();
    for i in 0..100_000 {
        let context = InteractionContext::new(format!("item_{}", i));
        client.generate_url(context).unwrap();
    }
    assert_eq!(client.tracked_count().unwrap(), 100_000);
    server_task.abort();
}

#[tokio::test]
async fn test_resource_deep_attribute_value() {
    let (port, server_task) = mock_poll_server("{}".to_string(), false).await;
    let mut config = ClientConfig::default();
    config.server = format!("http://127.0.0.1:{}", port);
    config.max_retries = 0;

    let client = InteractshClient::new(config).await.unwrap();
    let context = InteractionContext::new("deep").with_attribute("payload", "A".repeat(10_000_000)); // 10MB attribute
    client.generate_url(context).unwrap();
    assert_eq!(client.tracked_count().unwrap(), 1);
    server_task.abort();
}

#[tokio::test]
async fn test_resource_many_attributes() {
    let (port, server_task) = mock_poll_server("{}".to_string(), false).await;
    let mut config = ClientConfig::default();
    config.server = format!("http://127.0.0.1:{}", port);
    config.max_retries = 0;

    let client = InteractshClient::new(config).await.unwrap();
    let mut context = InteractionContext::new("many");
    for i in 0..10_000 {
        context = context.with_attribute(format!("k_{}", i), format!("v_{}", i));
    }
    client.generate_url(context).unwrap();
    assert_eq!(client.tracked_count().unwrap(), 1);
    server_task.abort();
}

// --- Hostile servers: hang, reset, 429 flood ---

/// A server that answers /register but accepts the /poll connection and then
/// never writes a byte. The client's request timeout must fire and surface a
/// Transport error; the poll must NEVER hang forever on a wedged server.
#[tokio::test]
async fn test_poll_server_hang_times_out_loudly() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server_task = tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let mut buf = [0; 1024];
            let _ = socket.read(&mut buf).await;
            let req = String::from_utf8_lossy(&buf);
            if req.contains("/register") {
                let _ = socket
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")
                    .await;
            }
            // /poll: read the request and then go silent forever. The socket
            // stays open (moved into the pending future), so the client is
            // stuck waiting on a response that never comes.
        }
    });

    let mut config = ClientConfig::default();
    config.server = format!("http://127.0.0.1:{port}");
    config.max_retries = 0;
    config.request_timeout_millis = Some(300);

    let client = InteractshClient::new(config).await.unwrap();
    let start = std::time::Instant::now();
    let poll_res = client.poll().await;
    let elapsed = start.elapsed();

    assert!(
        matches!(poll_res, Err(Error::Transport { .. })),
        "a hanging server must surface a Transport error, got: {poll_res:?}"
    );
    assert!(
        elapsed < std::time::Duration::from_secs(10),
        "the timeout did not contain the hang: {elapsed:?}"
    );
    server_task.abort();
}

/// A server that accepts the /poll connection and immediately drops it
/// (connection reset mid-request). The client must surface a Transport
/// error, not panic and not invent an empty interaction set.
#[tokio::test]
async fn test_poll_server_reset_is_transport_error() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server_task = tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let mut buf = [0; 1024];
            let _ = socket.read(&mut buf).await;
            let req = String::from_utf8_lossy(&buf);
            if req.contains("/register") {
                let _ = socket
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")
                    .await;
            }
            // /poll: socket dropped here without a single response byte.
        }
    });

    let mut config = ClientConfig::default();
    config.server = format!("http://127.0.0.1:{port}");
    config.max_retries = 0;
    config.request_timeout_millis = Some(2_000);

    let client = InteractshClient::new(config).await.unwrap();
    let poll_res = client.poll().await;
    assert!(
        matches!(poll_res, Err(Error::Transport { .. })),
        "a resetting server must surface a Transport error, got: {poll_res:?}"
    );
    server_task.abort();
}

/// A server that answers EVERY poll with 429 (rate-limit flood). The client
/// retries with backoff up to max_retries and must then fail loudly with
/// HttpStatus(429), never report a clean empty poll.
#[tokio::test]
async fn test_poll_server_429_flood_fails_after_retries() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server_task = tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let mut buf = [0; 1024];
            let _ = socket.read(&mut buf).await;
            let req = String::from_utf8_lossy(&buf);
            if req.contains("/register") {
                let _ = socket
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")
                    .await;
            } else if req.contains("/poll") {
                let _ = socket
                    .write_all(b"HTTP/1.1 429 Too Many Requests\r\nContent-Length: 0\r\n\r\n")
                    .await;
            }
        }
    });

    let mut config = ClientConfig::default();
    config.server = format!("http://127.0.0.1:{port}");
    config.max_retries = 2;
    config.retry_backoff_millis = 1;

    let client = InteractshClient::new(config).await.unwrap();
    let poll_res = client.poll().await;
    match poll_res {
        Err(Error::HttpStatus { status, .. }) => {
            assert_eq!(status.as_u16(), 429, "the flood status must surface");
        }
        other => panic!("a 429 flood must fail with HttpStatus after retries, got: {other:?}"),
    }
    server_task.abort();
}
