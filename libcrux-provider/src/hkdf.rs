use alloc::boxed::Box;

use libcrux::algorithms::{hkdf, hmac};
use rustls::crypto;

pub struct Sha256HKDF;

const SHA2_256_LEN: usize = 32;

impl crypto::tls13::Hkdf for Sha256HKDF {
    fn extract_from_zero_ikm(&self, salt: Option<&[u8]>) -> Box<dyn crypto::tls13::HkdfExpander> {
        let mut prk = [0u8; SHA2_256_LEN];
        let ikm = [0u8; SHA2_256_LEN];
        let salt = salt.unwrap_or(&[0u8; SHA2_256_LEN]);

        hkdf::sha2_256::extract(&mut prk, salt, &ikm).unwrap();

        Box::new(Sha256HKDFKey(prk))
    }

    fn extract_from_secret(
        &self,
        salt: Option<&[u8]>,
        secret: &[u8],
    ) -> Box<dyn crypto::tls13::HkdfExpander> {
        let mut prk = [0u8; SHA2_256_LEN];
        let salt = salt.unwrap_or(&[0u8; SHA2_256_LEN]);

        hkdf::sha2_256::extract(&mut prk, salt, secret).unwrap();

        Box::new(Sha256HKDFKey(prk))
    }

    fn expander_for_okm(
        &self,
        okm: &crypto::tls13::OkmBlock,
    ) -> Box<dyn crypto::tls13::HkdfExpander> {
        let key: [u8; 32] = okm.as_ref().try_into().unwrap();
        Box::new(Sha256HKDFKey(key))
    }

    fn hmac_sign(&self, key: &crypto::tls13::OkmBlock, message: &[u8]) -> crypto::hmac::Tag {
        let result = hmac::hmac(hmac::Algorithm::Sha256, key.as_ref(), message, None);
        crypto::hmac::Tag::new(&result[..])
    }
}

struct Sha256HKDFKey([u8; SHA2_256_LEN]);

impl crypto::tls13::HkdfExpander for Sha256HKDFKey {
    fn expand_slice(
        &self,
        info: &[&[u8]],
        output: &mut [u8],
    ) -> Result<(), crypto::tls13::OutputLengthError> {
        hkdf::sha2_256::expand(output, &self.0, &info.concat())
            .map_err(|_| crypto::tls13::OutputLengthError)
    }

    fn expand_block(&self, info: &[&[u8]]) -> crypto::tls13::OkmBlock {
        let mut okm = [0u8; SHA2_256_LEN];
        // In this setting, okm and prk are guaranteed to be in bounds, so only info can fail
        hkdf::sha2_256::expand(&mut okm, &self.0, &info.concat()).expect("info too long");

        crypto::tls13::OkmBlock::new(&okm)
    }

    fn hash_len(&self) -> usize {
        SHA2_256_LEN
    }
}
