use der::Reader;
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::pki_types::{
    alg_id, AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm,
};
use rustls::SignatureScheme;
use webpki::aws_lc_rs::RSA_PKCS1_2048_8192_SHA256 as AWS_LC_RSA_PKCS1_SHA256;

use libcrux::algorithms::{ecdsa, ed25519, rsapss};

pub static ALGORITHMS: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[
        RSA_PSS_SHA256,
        RSA_PSS_SHA384,
        RSA_PSS_SHA512,
        ED25519,
        ECDSA_P256_SHA256,
        AWS_LC_RSA_PKCS1_SHA256,
    ],
    mapping: &[
        (SignatureScheme::RSA_PSS_SHA256, &[RSA_PSS_SHA256]),
        (SignatureScheme::RSA_PSS_SHA384, &[RSA_PSS_SHA384]),
        (SignatureScheme::RSA_PSS_SHA512, &[RSA_PSS_SHA512]),
        (SignatureScheme::ED25519, &[ED25519]),
        (SignatureScheme::ECDSA_NISTP256_SHA256, &[ECDSA_P256_SHA256]),
        (
            SignatureScheme::RSA_PKCS1_SHA256,
            &[AWS_LC_RSA_PKCS1_SHA256],
        ),
    ],
};

static RSA_PSS_SHA256: &dyn SignatureVerificationAlgorithm =
    &RsaPssVerify(rsapss::DigestAlgorithm::Sha2_256, 0x20);

static RSA_PSS_SHA384: &dyn SignatureVerificationAlgorithm =
    &RsaPssVerify(rsapss::DigestAlgorithm::Sha2_384, 0x20);

static RSA_PSS_SHA512: &dyn SignatureVerificationAlgorithm =
    &RsaPssVerify(rsapss::DigestAlgorithm::Sha2_512, 0x20);

static ED25519: &dyn SignatureVerificationAlgorithm = &Ed25519Verify;

static ECDSA_P256_SHA256: &dyn SignatureVerificationAlgorithm =
    &EcdsaP256Verify(ecdsa::DigestAlgorithm::Sha256);

#[derive(Debug, Clone, Copy)]
struct EcdsaP256Verify(ecdsa::DigestAlgorithm);

impl SignatureVerificationAlgorithm for EcdsaP256Verify {
    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        let mut decoder = der::SliceReader::new(signature).map_err(|_| InvalidSignature)?;
        let sig: DerEcdsaSignature = decoder.decode().map_err(|_| InvalidSignature)?;
        let r = scalar_to_fixed_32(sig.r.as_bytes())?;
        let s = scalar_to_fixed_32(sig.s.as_bytes())?;
        let signature = ecdsa::p256::Signature::from_raw(r, s);
        let public_key =
            ecdsa::p256::PublicKey::try_from(public_key).map_err(|_| InvalidSignature)?;
        let alg = ecdsa::DigestAlgorithm::Sha256;
        ecdsa::p256::verify(alg, message, &signature, &public_key).map_err(|_| InvalidSignature)
    }

    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ECDSA_P256
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        match self.0 {
            ecdsa::DigestAlgorithm::Sha224 => unreachable!(),
            ecdsa::DigestAlgorithm::Sha256 => alg_id::ECDSA_SHA256,
            ecdsa::DigestAlgorithm::Sha384 => alg_id::ECDSA_SHA384,
            ecdsa::DigestAlgorithm::Sha512 => alg_id::ECDSA_SHA512,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Ed25519Verify;

impl SignatureVerificationAlgorithm for Ed25519Verify {
    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        let public_key: [u8; 32] = public_key.try_into().map_err(|_| InvalidSignature)?;
        let signature: [u8; 64] = signature.try_into().map_err(|_| InvalidSignature)?;
        ed25519::verify(message, &public_key, &signature).map_err(|_| InvalidSignature)
    }

    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ED25519
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ED25519
    }
}

#[derive(Debug, Clone, Copy)]
struct RsaPssVerify(rsapss::DigestAlgorithm, usize);

impl SignatureVerificationAlgorithm for RsaPssVerify {
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::RSA_ENCRYPTION
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        match self.0 {
            rsapss::DigestAlgorithm::Sha2_256 => alg_id::RSA_PSS_SHA256,
            rsapss::DigestAlgorithm::Sha2_384 => alg_id::RSA_PSS_SHA384,
            rsapss::DigestAlgorithm::Sha2_512 => alg_id::RSA_PSS_SHA512,
        }
    }

    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        let Self(digest_algo, salt_len) = *self;
        let salt_len: u32 = salt_len.try_into().map_err(|_| InvalidSignature)?;
        let public_key = decode_spki_spk(public_key)?;

        rsapss::verify(digest_algo, &public_key, message, salt_len, signature)
            .map_err(|_| InvalidSignature)
    }
}

fn decode_spki_spk(spki_spk: &[u8]) -> Result<rsapss::VarLenPublicKey<'_>, InvalidSignature> {
    // public_key: unfortunately this is not a whole SPKI, but just the key material,
    // i.e. an `RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }`.
    // Decode the SEQUENCE and extract the two integers.
    let mut reader = der::SliceReader::new(spki_spk).map_err(|_| InvalidSignature)?;
    let (n, e) = reader
        .sequence(|reader| {
            let n: der::asn1::UintRef = reader.decode()?;
            let e: der::asn1::UintRef = reader.decode()?;
            Ok::<_, der::Error>((n, e))
        })
        .map_err(|_| InvalidSignature)?;

    let n_bytes = n.as_bytes();
    let e_bytes = e.as_bytes();

    if !matches!(e_bytes, [1, 0, 1]) {
        // it's actually a NotSupportedError, but it amounts to the same
        return Err(InvalidSignature);
    }

    rsapss::VarLenPublicKey::try_from(n_bytes).map_err(|_| InvalidSignature)
}

/// Normalize a DER INTEGER's content bytes into a fixed-length 32-byte
/// big-endian scalar, as required by the raw P256 signature representation.
///
/// DER INTEGER encoding may prepend a `0x00` sign byte when the high bit is
/// set (making the content 33 bytes) or omit leading zero bytes for small
/// values (making it shorter). Both cases must be normalized back to exactly
/// 32 bytes, otherwise the signature is spuriously rejected.
fn scalar_to_fixed_32(bytes: &[u8]) -> Result<[u8; 32], InvalidSignature> {
    // Strip a single leading zero sign byte, if present.
    let bytes = match bytes {
        [0x00, rest @ ..] => rest,
        other => other,
    };
    if bytes.len() > 32 {
        return Err(InvalidSignature);
    }
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(bytes);
    Ok(out)
}

struct DerEcdsaSignature {
    r: der::asn1::Int,
    s: der::asn1::Int,
}

impl<'a> der::Decode<'a> for DerEcdsaSignature {
    type Error = der::Error;

    fn decode<R: der::Reader<'a>>(decoder: &mut R) -> der::Result<Self> {
        decoder.sequence(|decoder| {
            Ok(Self {
                r: decoder.decode()?,
                s: decoder.decode()?,
            })
        })
    }
}
