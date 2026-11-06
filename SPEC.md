# interactsh-client — Technical Spec

## Overview

Async Rust client for out-of-band interaction servers. Generate a callback hostname,
inject it into a target, then poll for interactions correlated with probe context.

```rust,no_run
use interactsh_client::{ClientConfig, InteractionContext, InteractshClient};

# async fn example() -> interactsh_client::Result<()> {
let client = InteractshClient::new(ClientConfig::default()).await?;
let url = client.generate_url(InteractionContext::new("my-scan"))?;
// Inject url.url into your target, then allow time for callbacks.
for hit in client.poll().await? {
    println!("callback: {}", hit.event.protocol);
}
# Ok(())
# }
```

## Architecture

- `InteractshClient` registers with the server, generates callback hostnames,
  tracks nonce-to-context mappings, and polls for correlated interactions.
- `ClientConfig` controls server selection, authentication, callback lengths,
  response limits, TLS, retries, and timeouts.
- `InteractionContext`, `GeneratedUrl`, `InteractionEvent`, and
  `CorrelatedInteraction` represent probes and their callbacks.
- The public `payload_helpers` module generates blind-vulnerability payloads.
- Internal client modules separate session management, HTTP transport, polling,
  and RSA/AES response decryption. Public entry points are re-exported at the crate root.

## Configuration and compatibility

The default server is `oast.pro`, with a 20-character correlation ID and
13-character nonce. Custom lengths must match the server's
`-correlation-id-length` and `-correlation-id-nonce-length` settings. Their sum
must not exceed the 63-byte DNS label limit. Configuration can be loaded from TOML.

## Guarantees and limits

- The crate forbids unsafe Rust code in its own source.
- Unknown interactions are filtered using the client's tracked nonce mappings.
- Session secrets and authentication tokens are redacted from client/config debug output.
- Poll response bodies are bounded by `ClientConfig::max_poll_response_bytes`.
- Public servers receive callback traffic; do not send secrets in probes.

## Error handling

Fallible operations return `interactsh_client::Result<T>`. `Error` distinguishes
configuration, transport, HTTP status, response-size, parsing, and cryptographic
failures. `ConfigField`, `ConfigProblem`, and `TransportStage` provide typed detail.

See the [README](README.md) for setup and the
[API documentation](https://docs.rs/interactsh-client) for signatures and defaults.
