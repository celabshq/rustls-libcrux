use alloc::boxed::Box;
use std::sync::Mutex;

use libcrux::algorithms::sha2::{self, Digest};
use rustls::crypto::hash;

pub struct Sha256;

impl hash::Hash for Sha256 {
    fn start(&self) -> Box<dyn hash::Context> {
        Box::new(Sha256Context(Mutex::new(sha2::Sha256::new())))
    }

    fn hash(&self, data: &[u8]) -> hash::Output {
        hash::Output::new(&sha2::sha256(data)[..])
    }

    fn algorithm(&self) -> hash::HashAlgorithm {
        hash::HashAlgorithm::SHA256
    }

    fn output_len(&self) -> usize {
        32
    }
}

struct Sha256Context(Mutex<sha2::Sha256>);

impl hash::Context for Sha256Context {
    fn fork_finish(&self) -> hash::Output {
        let mut out = [0u8; 32];
        self.0
            .lock()
            .expect("couldn't take hasher lock")
            .finish(&mut out);
        hash::Output::new(&out)
    }

    fn fork(&self) -> Box<dyn hash::Context> {
        let hasher: sha2::Sha256 = {
            self.0
                .lock()
                .expect("couldn't take hasher lock during fork_finish")
                .clone()
        };

        Box::new(Self(Mutex::new(hasher)))
    }

    fn finish(self: Box<Self>) -> hash::Output {
        (*self).fork_finish()
    }

    fn update(&mut self, data: &[u8]) {
        self.0
            .lock()
            .expect("couldn't take hasher lock during update")
            .update(data);
    }
}
