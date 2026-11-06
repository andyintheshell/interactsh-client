# Test-only cryptographic fixtures

`rsa-2048-test-only.pem` is a public, disposable 2048-bit RSA private key used
only by the NIST AES-CTR/RSA-OAEP regression test. It was generated with
`openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048` to avoid repeated
prime generation in debug builds. Never use it for real interactions or secrets.
