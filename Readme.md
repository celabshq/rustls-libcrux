# A libcrux-backed crypto provider for Rustls

This library implements the crypto provider traits from [Rustls](https://github.com/rustls/rustls),
allowing TLS connections to be backed by the verified cryptography in
[libcrux](https://github.com/cryspen/libcrux). The demo server injects a
libcrux-enabled Rustls config into actix-web to provide an example HTTPS server.

## Workspace layout

- **`libcrux-provider/`** — the crypto provider crate (`rustls-libcrux-provider`),
  plus runnable `client` / `server` examples and integration tests.
- **`demo-server/`** — an actix-web HTTPS server that uses the provider and renders
  the negotiated key-exchange group (including the post-quantum hybrid) on its
  landing page.
- **`tests/`** — ready-made ECDSA and RSA certificate/key fixtures and convenience
  scripts for the demo server.

## What's supported

- **Protocols:** TLS 1.3 and TLS 1.2
- **Cipher suite:** ChaCha20-Poly1305
- **Key exchange:** X25519 and X25519MLKEM768 (post-quantum hybrid)
- **Signing (server):** ECDSA-P256, Ed25519, RSA-PSS
- **Signature verification:** ECDSA-P256, Ed25519, RSA-PSS, and RSA-PKCS#1v1.5

## Build & test

```sh
cargo build --workspace
cargo test -p rustls-libcrux-provider
```

The integration tests in
[`libcrux-provider/tests/handshake.rs`](libcrux-provider/tests/handshake.rs) run
full in-memory handshakes (plus an application-data round-trip) with the provider on
both ends, covering the ECDSA/RSA signing paths, TLS 1.2 and TLS 1.3, and each
key-exchange group.

## Examples

A client that fetches a file over TLS (from `raw.githubusercontent.com`) using the
provider for all cryptography:

```sh
cargo run -p rustls-libcrux-provider --example client
```

A minimal TLS server (generates its own self-signed ECDSA cert, listens on
`[::]:4443`):

```sh
cargo run -p rustls-libcrux-provider --example server
```

## Running the demo server

The demo server takes three arguments: the bind address(es), a PEM certificate
chain, and a PEM private key. Ready-made fixtures live in `tests/`. From the repo
root:

```sh
# ECDSA certificate
cargo run -p rustls-libcrux-demo-server -- 127.0.0.1:1024 tests/cert_ecdsa.pem tests/key_ecdsa.pem

# or an RSA certificate
cargo run -p rustls-libcrux-demo-server -- 127.0.0.1:1024 tests/cert_rsa.pem tests/key_rsa.pem
```

Then open <https://127.0.0.1:1024/> in a browser. The certificates are self-signed,
so expect (and accept) a certificate warning. The page reports the negotiated
key-exchange group — modern browsers will show the `X25519MLKEM768` hybrid.

You can pass multiple comma-separated bind addresses, e.g.
`127.0.0.1:1024,[::1]:1024`.

The [`tests/test_ecdsa.sh`](tests/test_ecdsa.sh) and
[`tests/test_rsa.sh`](tests/test_rsa.sh) scripts wrap the commands above; run them
from inside the `tests/` directory (they use paths relative to it).

## Creating a libcrux-enabled Rustls server config

A minimal example for building a Rustls `ServerConfig` backed by this provider:

```rust
    // You have to do these yourself. The demo server has code to load PEM files.
    let certs: Vec<CertificateDer> = load_certs();
    let private_key: PrivateKeyDer = load_key();

    ServerConfig::builder_with_provider(Arc::new(rustls_libcrux_provider::provider()))
        .with_protocol_versions(DEFAULT_VERSIONS)
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certs, private_key)
```
