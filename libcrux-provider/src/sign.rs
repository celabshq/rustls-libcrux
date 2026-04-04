use std::vec;

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use der::oid::Arc as OidArc;
use der::{Decode, Tag, Tagged};
use pkcs8::ObjectIdentifier;
use rand_core::TryRngCore;
use sec1::EcPrivateKey;
use rustls::pki_types::PrivateKeyDer;
use rustls::sign::{Signer, SigningKey};
use rustls::{SignatureAlgorithm, SignatureScheme};

use der::{asn1::UintRef, Encode};

use libcrux::algorithms::rsapss;
use libcrux::algorithms::ecdsa;
use libcrux::algorithms::ed25519;

#[derive(Clone, Debug, Copy)]
pub enum EcdsaSignatureScheme {
    /// ECDSA backed by the NIST P256 curve. Currently the only NIST curve supported by libcrux
    #[allow(non_camel_case_types)]
    ECDSA_NISTP256_SHA256,
}

pub enum LibcruxSigningKey {
    RsaPss {
        n: Vec<u8>,
        d: Vec<u8>,
        hash_algo: rsapss::DigestAlgorithm,
    },
    Ecdsa(ecdsa::p256::PrivateKey, EcdsaSignatureScheme),
    Ed25519([u8; 32]),
}

impl LibcruxSigningKey {
    pub fn new_ed25519(sk: [u8; 32]) -> Self {
        Self::Ed25519(sk)
    }
}

impl TryFrom<PrivateKeyDer<'_>> for LibcruxSigningKey {
    type Error = pkcs8::Error;

    fn try_from(value: PrivateKeyDer<'_>) -> Result<Self, Self::Error> {
        match value {
            PrivateKeyDer::Pkcs8(der) => {
                let private_key_info = pkcs8::PrivateKeyInfo::try_from(der.secret_pkcs8_der())?;
                let algo_oid_arcs: Vec<OidArc> = private_key_info.algorithm.oid.arcs().collect();

                match algo_oid_arcs.as_slice() {
                    // `id-ecPublicKey' from RFC 3279
                    [1, 2, 840, 10045, 2, 1] => {
                        let parameter = private_key_info
                            .algorithm
                            .parameters
                            .ok_or(pkcs8::Error::KeyMalformed)?;
                        if parameter.tag() != Tag::ObjectIdentifier {
                            return Err(pkcs8::Error::KeyMalformed);
                        }

                        let parameter_oid =
                            ObjectIdentifier::from_bytes(parameter.value()).unwrap();
                        let parameter_oid_arcs: Vec<OidArc> = parameter_oid.arcs().collect();

                        let (key, scheme) = match parameter_oid_arcs.as_slice() {
                            [1, 2, 840, 10045, 3, 1, 7] => {
                                let key = private_key_info.private_key;
                                let key: ecdsa::p256::PrivateKey = EcPrivateKey::try_from(key)
                                    .map_err(|_| pkcs8::Error::KeyMalformed)?
                                    .private_key
                                    .try_into()
                                    .map_err(|_| pkcs8::Error::KeyMalformed)?;

                                (key, EcdsaSignatureScheme::ECDSA_NISTP256_SHA256)
                            }
                            // [1, 3, 132, 0, 34] => EcdsaSignatureScheme::ECDSA_NISTP384_SHA384,
                            // [1, 3, 132, 0, 35] => EcdsaSignatureScheme::ECDSA_NISTP521_SHA512,
                            _ => return Err(pkcs8::Error::KeyMalformed),
                        };

                        Ok(Self::Ecdsa(key, scheme))
                    }
                    // `rsaEncryption` from RFC3279 / PKCS#1
                    [1, 2, 840, 113549, 1, 1, 1] => {
                        let mut decoder = der::SliceReader::new(private_key_info.private_key)?;
                        let rsa_priv_key = pkcs1::RsaPrivateKey::decode(&mut decoder)?;

                        if !matches!(rsa_priv_key.public_exponent.as_bytes(), [1, 0, 1]) {
                            return Err(pkcs8::Error::ParametersMalformed);
                        }

                        let n = rsa_priv_key.modulus.as_bytes();
                        let n = trim_leading_zeroes(n).to_vec();

                        let d = rsa_priv_key.private_exponent.as_bytes();
                        let d = trim_leading_zeroes(d).to_vec();

                        // let pub_key =
                        //     signature::rsa_pss::RsaPssPublicKey::new(key_size, &n).unwrap();
                        // let priv_key = signature::rsa_pss::RsaPssPrivateKey::new(&pub_key, &d);

                        Ok(Self::RsaPss {
                            n,
                            d,
                            hash_algo: rsapss::DigestAlgorithm::Sha2_256,
                        })
                    }
                    _ => Err(pkcs8::Error::KeyMalformed),
                }
            }
            _ => Err(pkcs8::Error::KeyMalformed),
        }
    }
}

fn trim_leading_zeroes(mut buf: &[u8]) -> &[u8] {
    while let Some(leading) = buf.first() {
        if *leading == 0 {
            buf = &buf[481..];
        } else {
            break;
        }
    }
    buf
}

impl core::fmt::Debug for LibcruxSigningKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            LibcruxSigningKey::RsaPss { n, d: _, hash_algo } => {
                f.debug_struct("RsaPss")
                    .field("modulus_len", &n.len())
                    .field("private_exponent", &"<redacted>")
                    .field("hash_algo", hash_algo)
                    .finish()
            }
            LibcruxSigningKey::Ecdsa(_, scheme) => {
                f.debug_struct("Ecdsa")
                    .field("private_key", &"<redacted>")
                    .field("scheme", scheme)
                    .finish()
            }
            LibcruxSigningKey::Ed25519(_) => {
                f.debug_struct("Ed25519")
                    .field("private_key", &"<redacted>")
                    .finish()
            }
        }
    }
}

impl Clone for LibcruxSigningKey {
    fn clone(&self) -> Self {
        match self {
            LibcruxSigningKey::Ecdsa(key, scheme) => {
                let key_slice: &[u8; 32] = key.as_ref();
                let key = ecdsa::p256::PrivateKey::try_from(key_slice).unwrap();
                LibcruxSigningKey::Ecdsa(key, *scheme)
            }
            LibcruxSigningKey::Ed25519(key) => LibcruxSigningKey::Ed25519(*key),
            LibcruxSigningKey::RsaPss { n, d, hash_algo } => LibcruxSigningKey::RsaPss { n: n.clone(), d: d.clone(), hash_algo: *hash_algo },
        }
    }
}
impl SigningKey for LibcruxSigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        if offered.contains(&self.scheme()) {
            Some(Box::new(self.clone()))
        } else {
            None
        }
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        match self {
            LibcruxSigningKey::RsaPss { .. } => SignatureAlgorithm::RSA,
            LibcruxSigningKey::Ecdsa(_, _) => SignatureAlgorithm::ECDSA,
            LibcruxSigningKey::Ed25519(_) => SignatureAlgorithm::ED25519,
        }
    }
}

impl Signer for LibcruxSigningKey {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        match self {
            LibcruxSigningKey::RsaPss {
                n,
                d,
                hash_algo,
            } => {
                let mut sig = vec![0u8; n.len()];
                let mut salt = [0u8; 32];
                rand_core::OsRng.try_fill_bytes(&mut salt).unwrap();
                let n = n.as_slice();
                let d = d.as_slice();

                let priv_key =
                    rsapss::VarLenPrivateKey::from_components(n, d).map_err(|_| {
                        rustls::Error::General(String::from("error building private key"))
                    })?;
                rsapss::sign_varlen(*hash_algo, &priv_key, message, &salt, sig.as_mut_slice())
                    .map_err(|_| rustls::Error::General(String::from("error signing")))?;

                Ok(sig)
            }

            LibcruxSigningKey::Ecdsa(private_key, scheme) => {
                match scheme {
                    EcdsaSignatureScheme::ECDSA_NISTP256_SHA256 => {
                        let alg = ecdsa::DigestAlgorithm::Sha256;
                        let nonce = ecdsa::p256::Nonce::random(&mut rand_core::OsRng.unwrap_mut())
                            .map_err(|_| rustls::Error::General(String::from("signing error")))?;
                        let sig = ecdsa::p256::sign(alg, message, private_key, &nonce)
                            .map_err(|_| rustls::Error::General(String::from("signing error")))?;
                        der_encode_ecdsa_signature(&sig).map_err(|_| {
                            rustls::Error::General(String::from(
                                "error der encoding ecdsa signature",
                            ))
                        })
                    }
                    // EcdsaSignatureScheme::ECDSA_NISTP384_SHA384 => todo!(),
                    // EcdsaSignatureScheme::ECDSA_NISTP521_SHA512 => todo!(),
                }
            }

            LibcruxSigningKey::Ed25519(sk) => ed25519::sign(message, sk)
                .map_err(|_| rustls::Error::General(String::from("signing error")))
                .map(|sig| sig.to_vec()),
        }
    }

    fn scheme(&self) -> SignatureScheme {
        match self {
            LibcruxSigningKey::RsaPss {
                hash_algo: rsapss::DigestAlgorithm::Sha2_256,
                ..
            } => SignatureScheme::RSA_PSS_SHA256,
            LibcruxSigningKey::RsaPss {
                hash_algo: rsapss::DigestAlgorithm::Sha2_384,
                ..
            } => SignatureScheme::RSA_PSS_SHA384,
            LibcruxSigningKey::RsaPss {
                hash_algo: rsapss::DigestAlgorithm::Sha2_512,
                ..
            } => SignatureScheme::RSA_PSS_SHA512,
            LibcruxSigningKey::Ecdsa(_, EcdsaSignatureScheme::ECDSA_NISTP256_SHA256) => {
                SignatureScheme::ECDSA_NISTP256_SHA256
            }
            // LibcruxSigningKey::Ecdsa(_, EcdsaSignatureScheme::ECDSA_NISTP384_SHA384) => {
            //     SignatureScheme::ECDSA_NISTP384_SHA384
            // }
            // LibcruxSigningKey::Ecdsa(_, EcdsaSignatureScheme::ECDSA_NISTP521_SHA512) => {
            //     SignatureScheme::ECDSA_NISTP521_SHA512
            // }
            LibcruxSigningKey::Ed25519(_) => SignatureScheme::ED25519,
        }
    }
}

// copied from ecdsa crate, where it wasn't public
/// Create an ASN.1 DER encoded signature from big endian `r` and `s` scalar
/// components.
fn der_encode_ecdsa_signature(sig: &ecdsa::p256::Signature) -> der::Result<Vec<u8>> {
    let (r, s) = sig.as_bytes();
    let r = UintRef::new(r)?;
    let s = UintRef::new(s)?;

    let mut bytes = [0u8; 73];
    let mut writer = der::SliceWriter::new(&mut bytes);

    writer.sequence((r.encoded_len()? + s.encoded_len()?)?, |seq| {
        seq.encode(&r)?;
        seq.encode(&s)
    })?;

    Ok(writer.finish()?.to_vec())
}
