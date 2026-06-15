use alloc::boxed::Box;
use alloc::string::String;

use libcrux::algorithms::curve25519;

use libcrux_traits::ecdh::owned::EcdhOwned;
use rand_core::TryRngCore;
use rustls::crypto::{self, SupportedKxGroup as _};

use crate::pq::X25519MlKem768;

pub struct X25519KeyExchange {
    priv_key: [u8; 32],
    pub_key: [u8; 32],
}

impl crypto::ActiveKeyExchange for X25519KeyExchange {
    fn complete(
        self: Box<X25519KeyExchange>,
        peer: &[u8],
    ) -> Result<crypto::SharedSecret, rustls::Error> {
        let peer: [u8; 32] = peer
            .try_into()
            .map_err(|_| rustls::Error::General(String::from("ecdh derive error")))?;
        let shared_secret = curve25519::X25519::derive_ecdh(&peer, &self.priv_key)
            .map_err(|_| rustls::Error::General(String::from("ecdh derive error")))?;

        Ok(crypto::SharedSecret::from(&shared_secret[..]))
    }

    fn pub_key(&self) -> &[u8] {
        &self.pub_key[..]
    }

    fn group(&self) -> rustls::NamedGroup {
        X25519.name()
    }
}

pub const ALL_KX_GROUPS: &[&dyn crypto::SupportedKxGroup] = &[
    &X25519MlKem768 as &dyn crypto::SupportedKxGroup,
    &X25519 as &dyn crypto::SupportedKxGroup,
];

#[derive(Debug)]
pub struct X25519;

impl crypto::SupportedKxGroup for X25519 {
    fn start(&self) -> Result<Box<dyn crypto::ActiveKeyExchange>, rustls::Error> {
        let mut rand: [u8; 32] = [0u8; 32];
        rand_core::OsRng
            .try_fill_bytes(&mut rand)
            .map_err(|_| rustls::Error::FailedToGetRandomBytes)?;
        let (pub_key, priv_key) = curve25519::X25519::generate_pair(&rand)
            .map_err(|_| rustls::Error::General(String::from("ecdh keygen error")))?;

        Ok(Box::new(X25519KeyExchange { pub_key, priv_key }))
    }

    fn name(&self) -> rustls::NamedGroup {
        rustls::NamedGroup::X25519
    }
}
