use core::convert::TryFrom;

use libcrux::algorithms::mlkem;

use alloc::{boxed::Box, vec, vec::Vec};
use rand::TryRng as _;
use rustls::{
    crypto::{ActiveKeyExchange, CompletedKeyExchange, SharedSecret, SupportedKxGroup},
    ffdhe_groups::FfdheGroup,
    Error, NamedGroup, PeerMisbehaved, ProtocolVersion,
};

/// This is the [X25519MLKEM768] key exchange.
///
/// [X25519MLKEM768]: <https://datatracker.ietf.org/doc/draft-kwiatkowski-tls-ecdhe-mlkem/>
#[derive(Debug)]
pub struct X25519MlKem768;

impl SupportedKxGroup for X25519MlKem768 {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let x25519 = crate::kx::X25519.start()?;

        let mut rand = [0u8; mlkem::KEY_GENERATION_SEED_SIZE];
        rand::rngs::SysRng.try_fill_bytes(&mut rand).unwrap();
        let ml_kem = mlkem::mlkem768::generate_key_pair(rand);

        let mut combined_pub_key = Vec::with_capacity(COMBINED_PUBKEY_LEN);
        combined_pub_key.extend_from_slice(ml_kem.public_key().as_slice());
        combined_pub_key.extend_from_slice(x25519.pub_key());

        Ok(Box::new(Active {
            x25519,
            key_pair: Box::new(ml_kem),
            combined_pub_key,
        }))
    }

    fn start_and_complete(&self, client_share: &[u8]) -> Result<CompletedKeyExchange, Error> {
        let Some(share) = ReceivedShare::new(client_share) else {
            return Err(INVALID_KEY_SHARE);
        };

        let x25519 = crate::kx::X25519.start_and_complete(share.x25519)?;

        let mut rand = [0u8; mlkem::ENCAPS_SEED_SIZE];
        rand::rngs::SysRng.try_fill_bytes(&mut rand).unwrap();

        let pk = mlkem::mlkem768::MlKem768PublicKey::try_from(share.ml_kem)
            .map_err(|_| INVALID_KEY_SHARE)?;
        let (ml_kem_share, ml_kem_secret) = mlkem::mlkem768::encapsulate(&pk, rand);

        let combined_secret = CombinedSecret::combine(x25519.secret, ml_kem_secret);
        let combined_share = CombinedShare::combine(&x25519.pub_key, ml_kem_share);

        Ok(CompletedKeyExchange {
            group: self.name(),
            pub_key: combined_share.0,
            secret: SharedSecret::from(&combined_secret.0[..]),
        })
    }

    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        None
    }

    fn name(&self) -> NamedGroup {
        NAMED_GROUP
    }

    fn usable_for_version(&self, version: ProtocolVersion) -> bool {
        version == ProtocolVersion::TLSv1_3
    }
}

struct Active {
    x25519: Box<dyn ActiveKeyExchange>,
    key_pair: Box<mlkem::mlkem768::MlKem768KeyPair>,
    combined_pub_key: Vec<u8>,
}

impl ActiveKeyExchange for Active {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
        let Some(ciphertext) = ReceivedCiphertext::new(peer_pub_key) else {
            return Err(INVALID_KEY_SHARE);
        };

        let combined = CombinedSecret::combine(
            self.x25519.complete(ciphertext.x25519)?,
            mlkem::mlkem768::decapsulate(
                self.key_pair.private_key(),
                &ciphertext
                    .ml_kem
                    .try_into()
                    .map_err(|_| INVALID_KEY_SHARE)?,
            ),
        );
        Ok(SharedSecret::from(&combined.0[..]))
    }

    fn pub_key(&self) -> &[u8] {
        &self.combined_pub_key
    }

    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        None
    }

    fn group(&self) -> NamedGroup {
        NAMED_GROUP
    }
}

struct ReceivedShare<'a> {
    ml_kem: &'a [u8],
    x25519: &'a [u8],
}

impl<'a> ReceivedShare<'a> {
    fn new(buf: &'a [u8]) -> Option<ReceivedShare<'a>> {
        if buf.len() != COMBINED_PUBKEY_LEN {
            return None;
        }

        let (ml_kem, x25519) = buf.split_at(MLKEM768_ENCAP_LEN);
        Some(ReceivedShare { ml_kem, x25519 })
    }
}

struct ReceivedCiphertext<'a> {
    ml_kem: &'a [u8],
    x25519: &'a [u8],
}

impl<'a> ReceivedCiphertext<'a> {
    fn new(buf: &'a [u8]) -> Option<ReceivedCiphertext<'a>> {
        if buf.len() != COMBINED_CIPHERTEXT_LEN {
            return None;
        }

        let (ml_kem, x25519) = buf.split_at(MLKEM768_CIPHERTEXT_LEN);
        Some(ReceivedCiphertext { ml_kem, x25519 })
    }
}

struct CombinedSecret([u8; COMBINED_SHARED_SECRET_LEN]);

impl CombinedSecret {
    fn combine(x25519: SharedSecret, ml_kem: [u8; mlkem::SHARED_SECRET_SIZE]) -> Self {
        let mut out = CombinedSecret([0u8; COMBINED_SHARED_SECRET_LEN]);
        out.0[..MLKEM768_SECRET_LEN].copy_from_slice(ml_kem.as_slice());
        out.0[MLKEM768_SECRET_LEN..].copy_from_slice(x25519.secret_bytes());
        out
    }
}

struct CombinedShare(Vec<u8>);

impl CombinedShare {
    fn combine(x25519: &[u8], ml_kem: mlkem::mlkem768::MlKem768Ciphertext) -> Self {
        let mut out = CombinedShare(vec![0u8; COMBINED_CIPHERTEXT_LEN]);
        out.0[..MLKEM768_CIPHERTEXT_LEN].copy_from_slice(ml_kem.as_ref());
        out.0[MLKEM768_CIPHERTEXT_LEN..].copy_from_slice(x25519);
        out
    }
}

const NAMED_GROUP: NamedGroup = NamedGroup::X25519MLKEM768;

const INVALID_KEY_SHARE: Error = Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare);

const X25519_LEN: usize = 32;
const MLKEM768_CIPHERTEXT_LEN: usize = 1088;
const MLKEM768_ENCAP_LEN: usize = 1184;
const MLKEM768_SECRET_LEN: usize = 32;
const COMBINED_PUBKEY_LEN: usize = MLKEM768_ENCAP_LEN + X25519_LEN;
const COMBINED_CIPHERTEXT_LEN: usize = MLKEM768_CIPHERTEXT_LEN + X25519_LEN;
const COMBINED_SHARED_SECRET_LEN: usize = MLKEM768_SECRET_LEN + X25519_LEN;
