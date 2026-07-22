//! In-memory TLS handshakes exercising the libcrux provider on BOTH ends.
//!
//! These drive the signing paths (server) and verification paths (client) that the
//! public `client` example (a single RSA server over TLS 1.3) can't cover on its
//! own: the ECDSA signature path, the TLS 1.2 cipher/handshake path, the AEAD
//! encrypt+decrypt of application data, and each key-exchange group.

use std::io::{Read, Write};
use std::sync::Arc;

use rcgen::Issuer;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{
    ClientConfig, ClientConnection, ConnectionCommon, NamedGroup, RootCertStore, ServerConfig,
    ServerConnection, SupportedProtocolVersion,
};

struct Pki {
    ca_cert: CertificateDer<'static>,
    server_cert: CertificateDer<'static>,
    server_key: PrivateKeyDer<'static>,
}

fn make_pki(alg: &'static rcgen::SignatureAlgorithm) -> Pki {
    let mut ca_params = rcgen::CertificateParams::new(Vec::new()).unwrap();
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Test CA");
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::DigitalSignature,
    ];
    let ca_key = rcgen::KeyPair::generate_for(alg).unwrap();
    let ca_cert = ca_params.clone().self_signed(&ca_key).unwrap();

    let mut ee_params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    ee_params.is_ca = rcgen::IsCa::NoCa;
    ee_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    let server_key = rcgen::KeyPair::generate_for(alg).unwrap();
    let server_cert = ee_params
        .signed_by(&server_key, &Issuer::new(ca_params, ca_key))
        .unwrap();

    Pki {
        ca_cert: ca_cert.into(),
        server_cert: server_cert.into(),
        server_key: PrivatePkcs8KeyDer::from(server_key.serialize_der()).into(),
    }
}

struct Opts<'a> {
    /// Protocol versions offered by both peers.
    versions: &'a [&'static SupportedProtocolVersion],
    /// If set, restrict the provider to only this key-exchange group and assert it
    /// was the one negotiated.
    kx: Option<NamedGroup>,
}

/// Build a provider, optionally restricting it to a single key-exchange group. The
/// concrete kx types are private to the crate, so we filter the public list on the
/// `SupportedKxGroup::name()` trait method instead.
fn provider(kx: Option<NamedGroup>) -> rustls::crypto::CryptoProvider {
    let mut provider = rustls_libcrux_provider::provider();
    if let Some(want) = kx {
        provider.kx_groups.retain(|g| g.name() == want);
        assert!(
            !provider.kx_groups.is_empty(),
            "kx group {want:?} not supported"
        );
    }
    provider
}

/// Move all currently-pending TLS records from `from` to `to` and process them.
/// Both connection ends deref to `ConnectionCommon<Data>`, so this is generic over it.
fn transfer<A, B>(from: &mut ConnectionCommon<A>, to: &mut ConnectionCommon<B>) {
    let mut buf = Vec::new();
    from.write_tls(&mut buf).unwrap();
    if !buf.is_empty() {
        to.read_tls(&mut &buf[..]).unwrap();
        to.process_new_packets().expect("peer rejected records");
    }
}

/// Full in-memory handshake with the libcrux provider on both peers, followed by a
/// bidirectional application-data round-trip. Asserts the client accepts the
/// server's signature, the negotiated version/kx match expectations, and that AEAD
/// encrypt/decrypt round-trips in both directions.
fn run_handshake(pki: Pki, opts: Opts<'_>) {
    let server_config = ServerConfig::builder_with_provider(Arc::new(provider(opts.kx)))
        .with_protocol_versions(opts.versions)
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![pki.server_cert.clone()], pki.server_key)
        .unwrap();

    let mut roots = RootCertStore::empty();
    roots.add(pki.ca_cert).unwrap();
    let client_config = ClientConfig::builder_with_provider(Arc::new(provider(opts.kx)))
        .with_protocol_versions(opts.versions)
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();

    let server_name: ServerName = "localhost".try_into().unwrap();
    let mut client = ClientConnection::new(Arc::new(client_config), server_name).unwrap();
    let mut server = ServerConnection::new(Arc::new(server_config)).unwrap();

    // Pump until both have finished handshaking. `&mut *conn` derefs the concrete
    // connection to the `ConnectionCommon` the generic helpers expect.
    let mut done = false;
    for _ in 0..20 {
        transfer(&mut client, &mut server);
        transfer(&mut server, &mut client);
        if !client.is_handshaking() && !server.is_handshaking() {
            done = true;
            break;
        }
    }
    assert!(done, "handshake did not complete");

    // The negotiated parameters document what this test actually exercised.
    if opts.versions.len() == 1 {
        assert_eq!(
            client.protocol_version(),
            Some(opts.versions[0].version),
            "unexpected negotiated protocol version"
        );
    }
    if let Some(want) = opts.kx {
        assert_eq!(
            client.negotiated_key_exchange_group().map(|g| g.name()),
            Some(want),
            "unexpected negotiated key-exchange group"
        );
    }

    // Application-data round-trip in both directions (exercises AEAD encrypt+decrypt).
    round_trip(&mut client, &mut server, b"ping from client");
    round_trip(&mut server, &mut client, b"pong from server");
}

/// Send `msg` from `sender` and assert `receiver` reads back exactly the same bytes.
fn round_trip<A, B>(
    sender: &mut ConnectionCommon<A>,
    receiver: &mut ConnectionCommon<B>,
    msg: &[u8],
) {
    sender.writer().write_all(msg).unwrap();
    sender.writer().flush().unwrap();
    transfer(sender, receiver);

    let mut buf = vec![0u8; msg.len()];
    receiver.reader().read_exact(&mut buf).unwrap();
    assert_eq!(buf, msg, "application data did not round-trip");
}

#[test]
fn tls13_ecdsa() {
    // ECDSA P256 signing (sign.rs) + verification with r/s normalization (verify.rs).
    run_handshake(
        make_pki(&rcgen::PKCS_ECDSA_P256_SHA256),
        Opts {
            versions: &[&rustls::version::TLS13],
            kx: None,
        },
    );
}

#[test]
fn tls13_rsa() {
    // RSA private-key decoding (sign.rs) + RSA-PSS SPKI decoding (verify.rs).
    run_handshake(
        make_pki(&rcgen::PKCS_RSA_SHA256),
        Opts {
            versions: &[&rustls::version::TLS13],
            kx: None,
        },
    );
}

#[test]
fn tls12_rsa() {
    // The TLS 1.2 suite is RSA-only for signing, and drives the separate Tls12Cipher
    // (aead.rs) and PRF handshake path.
    run_handshake(
        make_pki(&rcgen::PKCS_RSA_SHA256),
        Opts {
            versions: &[&rustls::version::TLS12],
            kx: None,
        },
    );
}

#[test]
fn tls13_x25519() {
    // Pure X25519 key exchange (kx.rs).
    run_handshake(
        make_pki(&rcgen::PKCS_ECDSA_P256_SHA256),
        Opts {
            versions: &[&rustls::version::TLS13],
            kx: Some(NamedGroup::X25519),
        },
    );
}

#[test]
fn tls13_x25519mlkem768() {
    // Hybrid post-quantum key exchange (pq.rs), touched by the rand migration.
    run_handshake(
        make_pki(&rcgen::PKCS_ECDSA_P256_SHA256),
        Opts {
            versions: &[&rustls::version::TLS13],
            kx: Some(NamedGroup::X25519MLKEM768),
        },
    );
}
