# interactsh  -  Technical Spec

## Overview

Async Rust client for out-of-band interaction servers.  Register a unique URL, inject it into scan targets, then poll for callbacks. Detects blind vulnerabilities (SSRF, blind XSS, DNS exfiltration) that produce no visible response but trigger outbound requests to your interaction server.  ```rust,no_run # async fn example() -> Result<(), Box<dyn std::error::Error>> { use interactsh::{InteractshClient, ClientConfig, InteractionContext};  let client = InteractshClient::new(ClientConfig::default()).await?; let url = client.generate_url( InteractionContext::new("my-scan").with_attribute("scanner", "demo") )?; // inject url.url into your target... let interactions = client.poll().await?; for hit in &interactions { println!("callback: {}", hit.event.protocol); } # Ok(()) # } ```

## Architecture

The crate is organized into the following public modules:

- (see source for module layout)

## Guarantees

- `#![forbid(unsafe_code)]` where applicable; see `src/lib.rs` for the exact lint preamble.
- All public types have doc comments.
- Error messages are actionable where applicable.

## Public API Summary

Key entry points are exported from `src/lib.rs` via `pub mod` and `pub use` re-exports.
Consult the module-level documentation in each source file for function signatures and usage examples.

## Error Handling

- `Error`
