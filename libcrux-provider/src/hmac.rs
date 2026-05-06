use alloc::boxed::Box;

use rustls::crypto;
use libcrux::algorithms::sha2 as sha2;
use libcrux::algorithms::hmac as hmac;

pub struct Sha256Hmac;

impl crypto::hmac::Hmac for Sha256Hmac {
    fn with_key(&self, key: &[u8]) -> Box<dyn crypto::hmac::Key> {
        Box::new(Sha256HmacKey(key.to_vec()))
    }

    fn hash_output_len(&self) -> usize {
        sha2::SHA256_LENGTH
    }
}

struct Sha256HmacKey(alloc::vec::Vec<u8>);

impl crypto::hmac::Key for Sha256HmacKey {
    fn sign_concat(&self, first: &[u8], middle: &[&[u8]], last: &[u8]) -> crypto::hmac::Tag {
        let middle_len = middle.iter().fold(0, |acc, v| acc + v.len());
        let mut data = alloc::vec::Vec::with_capacity(first.len() + middle_len + last.len());
        data.extend_from_slice(first);
        for chunk in middle {
            data.extend_from_slice(chunk);
        }
        data.extend_from_slice(last);

        let result = hmac::hmac(hmac::Algorithm::Sha256, &self.0, &data, None);
        crypto::hmac::Tag::new(&result[..])
    }

    fn tag_len(&self) -> usize {
        hmac::tag_size(hmac::Algorithm::Sha256)
    }
}
