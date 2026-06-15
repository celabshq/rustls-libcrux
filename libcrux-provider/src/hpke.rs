use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Debug;

use libcrux::protocols::hpke;
use libcrux::protocols::hpke::libcrux as HPKEProvider;

use rustls::crypto::hpke::{
    EncapsulatedSecret, Hpke, HpkeOpener, HpkePrivateKey, HpkePublicKey, HpkeSealer, HpkeSuite,
};
use rustls::internal::msgs::enums::{
    HpkeAead as HpkeAeadId, HpkeKdf as HpkeKdfId, HpkeKem as HpkeKemId,
};
use rustls::internal::msgs::handshake::HpkeSymmetricCipherSuite;
use rustls::Error;

/// All supported HPKE suites.
///
/// Note: hpke-rs w/ rust-crypto does not support P-384 and P-521 DH KEMs.
pub static ALL_SUPPORTED_SUITES: &[&dyn Hpke] = &[
    DHKEM_P256_HKDF_SHA256_AES_128,
    DHKEM_P256_HKDF_SHA256_AES_256,
    DHKEM_P256_HKDF_SHA256_CHACHA20_POLY1305,
    DHKEM_X25519_HKDF_SHA256_AES_128,
    DHKEM_X25519_HKDF_SHA256_AES_256,
    DHKEM_X25519_HKDF_SHA256_CHACHA20_POLY1305,
];

pub static DHKEM_P256_HKDF_SHA256_AES_128: &LibcruxHpkeConfig = &LibcruxHpkeConfig {
    mode: hpke::Mode::Base,
    kem: hpke::hpke_types::KemAlgorithm::DhKemP256,
    kdf: hpke::hpke_types::KdfAlgorithm::HkdfSha256,
    aead: hpke::hpke_types::AeadAlgorithm::Aes128Gcm,
};

pub static DHKEM_P256_HKDF_SHA256_AES_256: &LibcruxHpkeConfig = &LibcruxHpkeConfig {
    mode: hpke::Mode::Base,
    kem: hpke::hpke_types::KemAlgorithm::DhKemP256,
    kdf: hpke::hpke_types::KdfAlgorithm::HkdfSha256,
    aead: hpke::hpke_types::AeadAlgorithm::Aes256Gcm,
};
pub static DHKEM_P256_HKDF_SHA256_CHACHA20_POLY1305: &LibcruxHpkeConfig = &LibcruxHpkeConfig {
    mode: hpke::Mode::Base,
    kem: hpke::hpke_types::KemAlgorithm::DhKemP256,
    kdf: hpke::hpke_types::KdfAlgorithm::HkdfSha256,
    aead: hpke::hpke_types::AeadAlgorithm::ChaCha20Poly1305,
};
pub static DHKEM_X25519_HKDF_SHA256_AES_128: &LibcruxHpkeConfig = &LibcruxHpkeConfig {
    mode: hpke::Mode::Base,
    kem: hpke::hpke_types::KemAlgorithm::DhKem25519,
    kdf: hpke::hpke_types::KdfAlgorithm::HkdfSha256,
    aead: hpke::hpke_types::AeadAlgorithm::Aes128Gcm,
};
pub static DHKEM_X25519_HKDF_SHA256_AES_256: &LibcruxHpkeConfig = &LibcruxHpkeConfig {
    mode: hpke::Mode::Base,
    kem: hpke::hpke_types::KemAlgorithm::DhKem25519,
    kdf: hpke::hpke_types::KdfAlgorithm::HkdfSha256,
    aead: hpke::hpke_types::AeadAlgorithm::Aes256Gcm,
};
pub static DHKEM_X25519_HKDF_SHA256_CHACHA20_POLY1305: &LibcruxHpkeConfig = &LibcruxHpkeConfig {
    mode: hpke::Mode::Base,
    kem: hpke::hpke_types::KemAlgorithm::DhKem25519,
    kdf: hpke::hpke_types::KdfAlgorithm::HkdfSha256,
    aead: hpke::hpke_types::AeadAlgorithm::ChaCha20Poly1305,
};

#[derive(Debug)]
struct LibcruxHpkeSealer {
    context: hpke::Context<HPKEProvider::HpkeLibcrux>,
}

impl HpkeSealer for LibcruxHpkeSealer {
    fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        self.context
            .seal(aad, plaintext)
            .map_err(|_| Error::General(String::from("hpke seal error")))
    }
}

#[derive(Debug)]
struct LibcruxHpkeOpener {
    context: hpke::Context<HPKEProvider::HpkeLibcrux>,
}

impl HpkeOpener for LibcruxHpkeOpener {
    fn open(&mut self, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        self.context
            .open(aad, ciphertext)
            .map_err(|_| Error::General(String::from("hpke open error")))
    }
}

#[derive(Debug)]
pub struct LibcruxHpkeConfig {
    mode: hpke::Mode,
    kem: hpke::hpke_types::KemAlgorithm,
    kdf: hpke::hpke_types::KdfAlgorithm,
    aead: hpke::hpke_types::AeadAlgorithm,
}

impl From<&LibcruxHpkeConfig> for hpke::Hpke<HPKEProvider::HpkeLibcrux> {
    fn from(value: &LibcruxHpkeConfig) -> Self {
        Self::new(value.mode, value.kem, value.kdf, value.aead)
    }
}

impl Hpke for LibcruxHpkeConfig {
    fn seal(
        &self,
        info: &[u8],
        aad: &[u8],
        plaintext: &[u8],
        pub_key: &HpkePublicKey,
    ) -> Result<(EncapsulatedSecret, Vec<u8>), Error> {
        let mut config = hpke::Hpke::<HPKEProvider::HpkeLibcrux>::from(self);

        let pk_r = hpke::HpkePublicKey::from(pub_key.0.as_slice());

        config
            .seal(&pk_r, info, aad, plaintext, None, None, None)
            .map_err(|_| Error::General(alloc::string::String::from("hpke seal error")))
            .map(|ctxt| (EncapsulatedSecret(ctxt.0), ctxt.1))
    }

    fn setup_sealer(
        &self,
        info: &[u8],
        pub_key: &HpkePublicKey,
    ) -> Result<(EncapsulatedSecret, Box<dyn HpkeSealer + 'static>), Error> {
        let mut config = hpke::Hpke::<HPKEProvider::HpkeLibcrux>::from(self);

        let pk_r = hpke::HpkePublicKey::from(pub_key.0.as_slice());

        let (kem_ctxt, ctx) = config
            .setup_sender(&pk_r, info, None, None, None)
            .map_err(|_| Error::General(alloc::string::String::from("hpke setup sealer error")))?;

        Ok((
            EncapsulatedSecret(kem_ctxt),
            Box::new(LibcruxHpkeSealer { context: ctx }),
        ))
    }

    fn open(
        &self,
        enc: &EncapsulatedSecret,
        info: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
        secret_key: &HpkePrivateKey,
    ) -> Result<Vec<u8>, Error> {
        let config = hpke::Hpke::<HPKEProvider::HpkeLibcrux>::from(self);

        let sk_r = hpke::HpkePrivateKey::from(secret_key.secret_bytes());

        config
            .open(&enc.0, &sk_r, info, aad, ciphertext, None, None, None)
            .map_err(|_| Error::General(alloc::string::String::from("hpke open error")))
    }

    fn setup_opener(
        &self,
        enc: &EncapsulatedSecret,
        info: &[u8],
        secret_key: &HpkePrivateKey,
    ) -> Result<Box<dyn HpkeOpener + 'static>, Error> {
        let config = hpke::Hpke::<HPKEProvider::HpkeLibcrux>::from(self);

        let sk_r = hpke::HpkePrivateKey::from(secret_key.secret_bytes());

        let ctx = config
            .setup_receiver(&enc.0, &sk_r, info, None, None, None)
            .map_err(|_| Error::General(alloc::string::String::from("hpke setup opener error")))?;

        Ok(Box::new(LibcruxHpkeOpener { context: ctx }))
    }

    fn generate_key_pair(&self) -> Result<(HpkePublicKey, HpkePrivateKey), Error> {
        let mut config = hpke::Hpke::<HPKEProvider::HpkeLibcrux>::from(self);

        config
            .generate_key_pair()
            .map_err(|_| Error::General(String::from("hpke kem keygen error")))
            .map(|pair| pair.into_keys())
            .map(|(sk, pk)| {
                (
                    HpkePublicKey(pk.as_slice().to_vec()),
                    HpkePrivateKey::from(sk.as_slice().to_vec()),
                )
            })
    }

    fn suite(&self) -> HpkeSuite {
        let kem = match self.kem {
            hpke::hpke_types::KemAlgorithm::DhKemP256 => HpkeKemId::DHKEM_P256_HKDF_SHA256,
            hpke::hpke_types::KemAlgorithm::DhKemP384 => HpkeKemId::DHKEM_P384_HKDF_SHA384,
            hpke::hpke_types::KemAlgorithm::DhKemP521 => HpkeKemId::DHKEM_P521_HKDF_SHA512,
            hpke::hpke_types::KemAlgorithm::DhKem25519 => HpkeKemId::DHKEM_X25519_HKDF_SHA256,
            hpke::hpke_types::KemAlgorithm::DhKem448 => HpkeKemId::DHKEM_X448_HKDF_SHA512,
            _ => unimplemented!(),
        };

        let kdf_id = match self.kdf {
            hpke::hpke_types::KdfAlgorithm::HkdfSha256 => HpkeKdfId::HKDF_SHA256,
            hpke::hpke_types::KdfAlgorithm::HkdfSha384 => HpkeKdfId::HKDF_SHA384,
            hpke::hpke_types::KdfAlgorithm::HkdfSha512 => HpkeKdfId::HKDF_SHA512,
        };

        let aead_id = match self.aead {
            hpke::hpke_types::AeadAlgorithm::Aes128Gcm => HpkeAeadId::AES_128_GCM,
            hpke::hpke_types::AeadAlgorithm::Aes256Gcm => HpkeAeadId::AES_256_GCM,
            hpke::hpke_types::AeadAlgorithm::ChaCha20Poly1305 => HpkeAeadId::CHACHA20_POLY_1305,
            hpke::hpke_types::AeadAlgorithm::HpkeExport => HpkeAeadId::EXPORT_ONLY,
        };

        HpkeSuite {
            kem,
            sym: HpkeSymmetricCipherSuite { kdf_id, aead_id },
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::{format, vec};

    use super::*;

    #[test]
    fn smoke_test() {
        for suite in ALL_SUPPORTED_SUITES {
            _ = format!("{suite:?}"); // HpkeRs suites should be Debug.

            // We should be able to generate a random keypair.
            let (pk, sk) = suite.generate_key_pair().unwrap();

            // Info value corresponds to the first RFC 9180 base mode test vector.
            let info = &[
                0x4f, 0x64, 0x65, 0x20, 0x6f, 0x6e, 0x20, 0x61, 0x20, 0x47, 0x72, 0x65, 0x63, 0x69,
                0x61, 0x6e, 0x20, 0x55, 0x72, 0x6e,
            ][..];

            // We should be able to set up a sealer.
            let (enc, mut sealer) = suite.setup_sealer(info, &pk).unwrap();

            _ = format!("{sealer:?}"); // Sealer should be Debug.

            // Setting up a sealer with an invalid public key should fail.
            let bad_setup_res = suite.setup_sealer(info, &HpkePublicKey(vec![]));
            assert!(bad_setup_res.is_err());

            // We should be able to seal some plaintext.
            let aad = &[0xC0, 0xFF, 0xEE];
            let pt = &[0xF0, 0x0D];
            let ct = sealer.seal(aad, pt).unwrap();

            // We should be able to set up an opener.
            let mut opener = suite.setup_opener(&enc, info, &sk).unwrap();
            _ = format!("{opener:?}"); // Opener should be Debug.

            // Setting up an opener with an invalid private key should fail.
            let bad_key_res = suite.setup_opener(&enc, info, &HpkePrivateKey::from(vec![]));
            assert!(bad_key_res.is_err());

            // Opening the plaintext should work with the correct opener and aad.
            let pt_prime = opener.open(aad, &ct).unwrap();
            assert_eq!(pt_prime, pt);

            // Opening the plaintext with the correct opener and wrong aad should fail.
            let open_res = opener.open(&[0x0], &ct);
            assert!(open_res.is_err());

            // Opening the plaintext with the wrong opener should fail.
            let mut sk_rm_prime = sk.secret_bytes().to_vec();
            sk_rm_prime[10] ^= 0xFF; // Corrupt a byte of the private key.
            let mut opener_two = suite
                .setup_opener(&enc, info, &HpkePrivateKey::from(sk_rm_prime))
                .unwrap();
            let open_res = opener_two.open(aad, &ct);
            assert!(open_res.is_err());
        }
    }

    #[test]
    fn test_fips() {
        // None of the rust-crypto backed hpke-rs suites should be considered FIPS approved.
        assert!(ALL_SUPPORTED_SUITES.iter().all(|suite| !suite.fips()));
    }
}
