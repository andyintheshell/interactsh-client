# Changelog

## Unreleased — interactsh-client fork

- Raised the minimum supported Rust version to 1.95, matching Perseid, and pinned the development toolchain to 1.95.0.
- Modernized CI runners and pinned actions, moved formatting to stable Rust, and made the MSRV tests and publishing use the checked-in lockfile.
- Refreshed pinned dependencies and the lockfile, including AES 0.9, CTR 0.10, Base64 0.23, Reqwest 0.13, and TOML 1.2. Custom HTTP clients now use Reqwest 0.13; its `rustls` feature uses the platform certificate verifier. Rand stays on the latest 0.8 release and SHA-2 on 0.10 for stable RSA/guise compatibility.
- Forked the published `interactsh` 0.2.4 crate as `interactsh-client`, maintained at <https://github.com/andyintheshell/interactsh-client>.
- Renamed Rust imports to `interactsh_client` and updated examples and documentation.
- Preserved the original MIT/Apache-2.0 licensing and copyright notices; recorded the exact upstream archive in `UPSTREAM.md`.
- Cleaned up inherited formatting, lint, and documentation warnings without changing the public API or library behavior; made CI resolve MSRV-compatible dependencies for its Rust 1.85 check.

The entries below are the original upstream changelog.

## [0.2.4] - 2026-08-07

- Fixed `blind_xss_payloads`, `blind_ssrf_payloads`, and `blind_xxe_payloads` to derive scheme-qualified `full_url` targets via `callback_forms` when passed bare-host callback inputs (such as generated URLs from `InteractshClient::generate_url()`), preventing silent payload failures caused by relative URL resolution. Added proving unit tests.
- Fixed `retry_backoff_saturates_at_max_pacing_backoff` test in `src/client/core.rs` to assert `guise_pacing::MAX_PACING_BACKOFF` (60s) ceiling.

## [0.2.3] - 2026-08-07

- Metadata: updated crate `authors` to `Santh <64453045+santhreal@users.noreply.github.com>` and set `package.metadata.santh.status = "beta"`.
- Robustness: `blind_cmdi_payloads` now uses `callback_forms` to derive bare-host and full-URL parameters, preventing malformed command syntax when callers pass full callback URLs (e.g. `nslookup http://...`).
- Robustness: `PollResponse` deserializer now accepts `extra` and `tlddata` interaction arrays returned as either raw JSON objects or JSON-encoded strings.

## v0.2.2

- Security: `InteractshClient` no longer derives `Debug`. A manual implementation masks the session `secret_key` and RSA private key, so debug logging can no longer publish the credentials that guard captured interactions.
- Security: `ClientConfig` no longer derives `Debug`. A manual implementation masks the bearer `token`.
- Security: poll-path errors (`HttpStatus`, `Transport`, `OversizedResponse`, `Parse`, `Crypto`) now carry the poll URL with `secret=[redacted]` instead of the live session secret.

## v0.2.0

- Added `#[non_exhaustive]` to public enums that may grow, including config and transport error enums.
- Added `Display` implementations for printable public types such as `InteractshClient`, `ClientConfig`, `InteractionContext`, `GeneratedUrl`, `InteractionEvent`, and `CorrelatedInteraction`.
- Added `# Thread Safety` sections documenting `Send`/`Sync` behavior across the public API.
- Added `#[must_use]` to important constructors, parsing helpers, and value-returning client methods.
