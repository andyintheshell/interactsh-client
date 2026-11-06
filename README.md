# interactsh-client

Async client for polling out-of-band interaction servers. Generate unique URLs, inject them into payloads, and correlate DNS/HTTP interactions back to the original probe. Used for detecting blind XSS, SSRF, SQL injection, and other vulnerabilities where the target makes outbound requests.

## Fork provenance and disclaimer

This is an independent fork of [`interactsh` version 0.2.4](https://crates.io/crates/interactsh/0.2.4), originally authored by Santh. [andyintheshell](https://github.com/andyintheshell) created this fork to continue maintenance after the original crate was no longer maintained and its listed source repository became unavailable (404). This fork is not affiliated with or endorsed by the original maintainers.

The original copyright notices and dual MIT/Apache-2.0 licensing are preserved. See [UPSTREAM.md](UPSTREAM.md) for the exact source archive and checksum.

## Quick start

Requires **Rust 1.95 or newer**. The checked-in `rust-toolchain.toml` pins development tools to Rust 1.95.0; CI also tests the latest stable and nightly compilers.

`interactsh-client` is async. Add `tokio` to your `Cargo.toml` before copy-pasting the example:

```toml
[dependencies]
interactsh-client = "0.3"
tokio = { version = "1", features = ["macros", "rt-multi-thread", "time"] }
```

```rust,no_run
use interactsh_client::{InteractshClient, ClientConfig, InteractionContext};
use std::time::Duration;

#[tokio::main]
async fn main() -> interactsh_client::Result<()> {
    let client = InteractshClient::new(ClientConfig::default()).await?;
    
    // Generate a URL tagged with context
    let url = client.generate_url(
        InteractionContext::new("blind-xss")
            .with_attribute("target", "https://app.example.com")
    )?;
    
    println!("Payload URL: {}", url.url);

    // Inject the URL, then poll for up to 60 seconds.
    for _ in 0..12 {
        tokio::time::sleep(Duration::from_secs(5)).await;

        let interactions = client.poll().await?;
        for interaction in interactions {
            println!(
                "Got {} interaction from {}",
                interaction.event.protocol,
                interaction.context.label
            );
        }
    }
    
    Ok(())
}
```

## Why this exists

Blind vulnerabilities require out-of-band detection. You inject a URL into a payload. If the target is vulnerable, it makes a request back to that URL. Most tools either lack OOB detection entirely or embed hardcoded interactsh logic that cannot be reused.

This crate provides an async client that handles URL generation with cryptographic nonces, correlation ID management, and interaction polling. It works with public interactsh servers or self-hosted instances.

## URL generation

Each generated URL contains:

- A correlation ID (configurable length, default 14 chars)
- A unique nonce (configurable length, default 16 chars)
- The server hostname

The combination ensures global uniqueness while letting you correlate interactions back to specific probes.

```rust
# use interactsh_client::{InteractshClient, InteractionContext};
# fn example(client: &InteractshClient) -> interactsh_client::Result<()> {
let url = client.generate_url(InteractionContext::new("probe-123"))?;
// URL format: {correlation_id}{nonce}.{server}
// Example: abc123def456ghi.oast.pro
# Ok(())
# }
```

## Context tracking

Attach metadata to URLs for later correlation:

```rust
# use interactsh_client::{InteractshClient, InteractionContext};
# fn example(client: &InteractshClient) -> interactsh_client::Result<()> {
let context = InteractionContext::new("ssrf-test")
    .with_attribute("template_id", "CVE-2021-44228")
    .with_attribute("target_host", "api.internal");

let url = client.generate_url(context)?;
# Ok(())
# }
```

When polling returns interactions, the context is restored from the nonce mapping.

## Polling

The `poll()` method retrieves all interactions for your correlation ID:

```rust,no_run
# use interactsh_client::InteractshClient;
# async fn example(client: &InteractshClient) -> interactsh_client::Result<()> {
let interactions = client.poll().await?;
for item in interactions {
    println!("Protocol: {}", item.event.protocol);
    println!("Raw request: {:?}", item.event.raw_request);
    println!("Matched context: {}", item.context.label);
}
# Ok(())
# }
```

Unknown interactions (wrong correlation ID or forgotten nonces) are filtered out automatically. Empty poll responses are treated as `Ok(vec![])`, including servers that return `null` for interaction arrays.

## Configuration

```rust
use interactsh_client::ClientConfig;

let config = ClientConfig {
    server: "oast.fun".to_string(),
    token: Some("api-key".to_string()),
    correlation_id_length: 20,
    nonce_length: 12,
    ..ClientConfig::default()
};
```

Load from TOML:

```rust
use interactsh_client::ClientConfig;

let config = ClientConfig::from_toml_str(r#"
    server = "oast.fun"
    token = "secret-api-key"
    correlation_id_length = 16
"#)?;
```

## Error handling

Errors are typed by stage:

- `ConfigProblem::Empty`: Missing required fields
- `ConfigProblem::MustBeGreaterThanZero`: Invalid length settings
- `TransportStage::Send`: Network failure
- `TransportStage::Timeout`: Request timeout
- `TransportStage::ReadBody`: Response body read failure

## Self-hosted servers

Point at your own interactsh instance:

```rust
use interactsh_client::ClientConfig;

let config = ClientConfig {
    server: "oast.internal.corp".to_string(),
    default_scheme: "https".to_string(),
    ..ClientConfig::default()
};
```

## Contributing

Pull requests are welcome. There is no such thing as a perfect crate. If you find a bug, a better API, or just a rough edge, open a PR. We review quickly.

## License

Licensed under either the [MIT License](LICENSE-MIT) or the [Apache License, Version 2.0](LICENSE-APACHE), at your option (`MIT OR Apache-2.0`). Original copyright and license notices are retained.

[![crates.io](https://img.shields.io/crates/v/interactsh-client.svg)](https://crates.io/crates/interactsh-client)
[![docs.rs](https://docs.rs/interactsh-client/badge.svg)](https://docs.rs/interactsh-client)
