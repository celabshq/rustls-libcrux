use std::vec;

use alloc::boxed::Box;

use rustls::{
    crypto::cipher::{
        make_tls12_aad, make_tls13_aad, AeadKey, InboundOpaqueMessage, InboundPlainMessage, Iv,
        KeyBlockShape, MessageDecrypter, MessageEncrypter, Nonce, OutboundOpaqueMessage,
        OutboundPlainMessage, PrefixedPayload, Tls12AeadAlgorithm, Tls13AeadAlgorithm,
        UnsupportedOperationError, NONCE_LEN,
    },
    ConnectionTrafficSecrets, ContentType, ProtocolVersion,
};

use libcrux::{algorithms::aes_gcm::Aead, primitives::aead};
use libcrux::algorithms::chacha20poly1305;



pub enum LibcruxAeadKey {
    Chacha20Poly1305([u8; chacha20poly1305::KEY_LEN]),
}

pub struct Chacha20Poly1305;

impl Tls13AeadAlgorithm for Chacha20Poly1305 {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        let key: [u8; chacha20poly1305::KEY_LEN] = key.as_ref().try_into().unwrap();
        let key = LibcruxAeadKey::Chacha20Poly1305(key);
        Box::new(Tls13Cipher(key, iv))
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        let key: [u8; chacha20poly1305::KEY_LEN] = key.as_ref().try_into().unwrap();
        let key = LibcruxAeadKey::Chacha20Poly1305(key);
        Box::new(Tls13Cipher(key, iv))
    }

    fn key_len(&self) -> usize {
        32
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok(ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv })
    }
}

impl Tls12AeadAlgorithm for Chacha20Poly1305 {
    fn encrypter(&self, key: AeadKey, iv: &[u8], _: &[u8]) -> Box<dyn MessageEncrypter> {
        let key: [u8; chacha20poly1305::KEY_LEN] = key.as_ref().try_into().unwrap();
        let key = LibcruxAeadKey::Chacha20Poly1305(key);
        Box::new(Tls12Cipher(key, Iv::copy(iv)))
    }

    fn decrypter(&self, key: AeadKey, iv: &[u8]) -> Box<dyn MessageDecrypter> {
        let key: [u8; chacha20poly1305::KEY_LEN] = key.as_ref().try_into().unwrap();
        let key = LibcruxAeadKey::Chacha20Poly1305(key);
        Box::new(Tls12Cipher(key, Iv::copy(iv)))
    }

    fn key_block_shape(&self) -> KeyBlockShape {
        KeyBlockShape {
            enc_key_len: 32,
            fixed_iv_len: 12,
            explicit_nonce_len: 0,
        }
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: &[u8],
        _explicit: &[u8],
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        // This should always be true because KeyBlockShape and the Iv nonce len are in agreement.
        debug_assert_eq!(NONCE_LEN, iv.len());
        Ok(ConnectionTrafficSecrets::Chacha20Poly1305 {
            key,
            iv: Iv::new(iv[..].try_into().unwrap()),
        })
    }
}

struct Tls13Cipher(LibcruxAeadKey, Iv);

impl MessageEncrypter for Tls13Cipher {
    fn encrypt(
        &mut self,
        m: OutboundPlainMessage,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, rustls::Error> {
        let total_len = self.encrypted_payload_len(m.payload.len());
        let mut payload = PrefixedPayload::with_capacity(total_len);

        payload.extend_from_chunks(&m.payload);
        payload.extend_from_slice(&m.typ.to_array());
        let plaintext = payload.as_ref().to_vec();

        let nonce = Nonce::new(&self.1, seq);
        let aad = make_tls13_aad(total_len);
        let mut ciphertext = vec![0u8; plaintext.len()];

        let key = match &self.0 {
            LibcruxAeadKey::Chacha20Poly1305(key) => aead::KeyRef::new_for_algo(aead::Aead::ChaCha20Poly1305, key).map_err(|_| rustls::Error::EncryptError)?,
        };

        let mut tag = vec![0u8; key.algo().tag_len()];

        let tag_ref = aead::TagMut::new_for_algo(*key.algo(), &mut tag)
            .map_err(|_| rustls::Error::EncryptError)?;

        let nonce = aead::NonceRef::new_for_algo(*key.algo(), &nonce.0)
            .map_err(|_| rustls::Error::EncryptError)?;

        key.encrypt(&mut ciphertext, tag_ref, nonce, &aad, &plaintext)
            .map_err(|_| rustls::Error::EncryptError)?;

        let mut payload = PrefixedPayload::with_capacity(total_len);
        payload.extend_from_slice(&ciphertext);
        payload.extend_from_slice(tag.as_ref());

        // self.0
        //     .encrypt_in_place(&nonce, &aad, &mut EncryptBufferAdapter(&mut payload))

        Ok(OutboundOpaqueMessage::new(
            ContentType::ApplicationData,
            ProtocolVersion::TLSv1_2,
            payload,
        ))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + 1 + CHACHAPOLY1305_OVERHEAD
    }
}

impl MessageDecrypter for Tls13Cipher {
    fn decrypt<'a>(
        &mut self,
        mut m: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, rustls::Error> {
        let key = match &self.0 {
            LibcruxAeadKey::Chacha20Poly1305(key) => aead::KeyRef::new_for_algo(aead::Aead::ChaCha20Poly1305, key).map_err(|_| rustls::Error::DecryptError)?,
        };

        let payload_and_tag = &mut m.payload;
        let total_len = payload_and_tag.len();
        let tag_len = key.algo().tag_len();
        if total_len < tag_len {
            return Err(rustls::Error::DecryptError);
        }

        let (payload, tag) = payload_and_tag.split_at_mut(total_len - tag_len);

        let nonce = Nonce::new(&self.1, seq);
        let aad = make_tls13_aad(total_len);
        let mut plaintext = vec![0u8; payload.len()];

        let tag = aead::TagRef::new_for_algo(*key.algo(), tag)
            .map_err(|_| rustls::Error::DecryptError)?;

        let nonce = aead::NonceRef::new_for_algo(*key.algo(), &nonce.0)
            .map_err(|_| rustls::Error::DecryptError)?;

        key.decrypt(&mut plaintext, nonce, &aad, payload, tag)
            .map_err(|_| rustls::Error::DecryptError)?;

        m.payload
            .truncate(m.payload.len() - tag_len);

        m.payload.copy_from_slice(&plaintext);

        m.into_tls13_unpadded_message()
    }
}

struct Tls12Cipher(LibcruxAeadKey, Iv);

impl MessageEncrypter for Tls12Cipher {
    fn encrypt(
        &mut self,
        m: OutboundPlainMessage,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, rustls::Error> {
        let total_len = self.encrypted_payload_len(m.payload.len());
        let mut payload = PrefixedPayload::with_capacity(total_len);

        payload.extend_from_chunks(&m.payload);
        let plaintext = payload.as_ref().to_vec();

        let nonce = Nonce::new(&self.1, seq);
        let aad = make_tls12_aad(seq, m.typ, m.version, m.payload.len());
        let mut ciphertext = vec![0u8; plaintext.len()];
        
        let key = match &self.0 {
            LibcruxAeadKey::Chacha20Poly1305(key) => aead::KeyRef::new_for_algo(aead::Aead::ChaCha20Poly1305, key).map_err(|_| rustls::Error::EncryptError)?,
        };

        let mut tag = vec![0u8; key.algo().tag_len()];

        let tag_ref = aead::TagMut::new_for_algo(*key.algo(), &mut tag)
            .map_err(|_| rustls::Error::EncryptError)?;

        let nonce = aead::NonceRef::new_for_algo(*key.algo(), &nonce.0)
            .map_err(|_| rustls::Error::EncryptError)?;

        key.encrypt(&mut ciphertext, tag_ref, nonce, &aad, &plaintext)
            .map_err(|_| rustls::Error::EncryptError)?;

        let mut payload = PrefixedPayload::with_capacity(total_len);
        payload.extend_from_slice(&ciphertext);

        Ok(OutboundOpaqueMessage::new(
            m.typ,
            m.version,
            payload,
        ))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + CHACHAPOLY1305_OVERHEAD
    }
}

impl MessageDecrypter for Tls12Cipher {
    fn decrypt<'a>(
        &mut self,
        mut m: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, rustls::Error> {
        let key = match &self.0 {
            LibcruxAeadKey::Chacha20Poly1305(key) => aead::KeyRef::new_for_algo(aead::Aead::ChaCha20Poly1305, key).map_err(|_| rustls::Error::DecryptError)?,
        };

        let payload_and_tag = &mut m.payload;
        let payload_and_tag_len = payload_and_tag.len();
        let tag_len = key.algo().tag_len();
        if payload_and_tag_len < tag_len {
            return Err(rustls::Error::DecryptError);
        }

        let (payload, tag) = payload_and_tag.split_at_mut(payload_and_tag_len - tag_len);
        let nonce = Nonce::new(&self.1, seq);
        let aad = make_tls12_aad(
            seq,
            m.typ,
            m.version,
            payload.len() - CHACHAPOLY1305_OVERHEAD,
        );
        let mut plaintext = vec![0u8; payload.len()];

        let tag = aead::TagRef::new_for_algo(*key.algo(), tag)
            .map_err(|_| rustls::Error::DecryptError)?;

        let nonce = aead::NonceRef::new_for_algo(*key.algo(), &nonce.0)
            .map_err(|_| rustls::Error::DecryptError)?;

        key.decrypt(&mut plaintext, nonce, &aad, payload, tag)
            .map_err(|_| rustls::Error::DecryptError)?;

        m.payload
            .truncate(m.payload.len() - tag_len);

        m.payload.copy_from_slice(&plaintext);

        Ok(m.into_plain_message())
    }
}

const CHACHAPOLY1305_OVERHEAD: usize = 16;
