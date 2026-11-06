# BACKLOG - interactsh-client

- Track [RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071) in `rsa` 0.9.10 (RSA timing side channels). The dependency refresh still reports this existing advisory; no fixed stable release is available. Revisit RSA and its Rand/SHA-2 trait compatibility when a patched stable release becomes available. Do not suppress the advisory.
