#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::todo,
        clippy::unimplemented,
        clippy::panic
    )
)]
#![allow(
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
    clippy::missing_errors_doc
)]
#![allow(clippy::return_self_not_must_use)]
#![allow(clippy::needless_borrows_for_generic_args)]
#![allow(clippy::float_cmp)]
#![allow(clippy::cast_sign_loss)]
//! Async Rust client for out-of-band interaction servers.
//!
//! Register a unique URL, inject it into scan targets, then poll for callbacks.
//! Detects blind vulnerabilities (SSRF, blind XSS, DNS exfiltration) that produce
//! no visible response but trigger outbound requests to your interaction server.
//!
//! Independently maintained fork of `interactsh` 0.2.4 by andyintheshell, retaining
//! the original MIT OR Apache-2.0 licensing. The original source repository was
//! unavailable (404) when this fork was created; see the repository's UPSTREAM.md.
//!
//! ```rust,no_run
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use interactsh_client::{InteractshClient, ClientConfig, InteractionContext};
//!
//! let client = InteractshClient::new(ClientConfig::default()).await?;
//! let url = client.generate_url(
//!     InteractionContext::new("my-scan").with_attribute("scanner", "demo")
//! )?;
//! // inject url.url into your target...
//! let interactions = client.poll().await?;
//! for hit in &interactions {
//!     println!("callback: {}", hit.event.protocol);
//! }
//! # Ok(())
//! # }
//! ```

mod client;
mod config;
mod error;
mod model;
/// Blind-vulnerability payload templates parameterized by an OOB
/// callback URL. OOB-server-agnostic, use with interactsh, Burp
/// Collaborator, or any DNS catcher.
pub mod payload_helpers;

pub use client::InteractshClient;
pub use config::{ClientConfig, MAX_GENERATED_LABEL_BYTES};
pub use error::{ConfigField, ConfigProblem, Error, Result, TransportStage};
pub use model::{CorrelatedInteraction, GeneratedUrl, InteractionContext, InteractionEvent};
pub use payload_helpers::{
    blind_cmdi_payloads, blind_sqli_payloads, blind_ssrf_payloads, blind_xss_payloads,
    blind_xxe_payloads, SqliDialect,
};
