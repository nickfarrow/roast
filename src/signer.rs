//! ROAST Signer
//!
//! Manage a FROST key in order to send nonces and signature shares upon request from a ROAST coordinator.
use rand::RngCore;
use secp256kfun::{
    marker::{Public, Zero},
    Scalar,
};

use schnorr_fun::{
    musig::{Nonce, NonceKeyPair},
    Message,
};

use crate::threshold_scheme::ThresholdScheme;

pub struct RoastSigner<'a, S: ThresholdScheme<K>, K: Clone> {
    threshold_scheme: S,
    joint_key: K,
    my_index: usize,
    secret_share: Scalar,
    message: Message<'a, Public>,
    my_nonces: Vec<NonceKeyPair>,
}

impl<'a, S: ThresholdScheme<K> + Clone, K: Clone> RoastSigner<'a, S, K> {
    /// Create a new [`RoastSigner`] session for a particular message
    ///
    /// A new [`RoastSigner`] should be created for each message the group wants to sign.
    /// The frost protocol instance's noncegen (NG) will be used to generate nonces.
    /// This noncegen must be chosen carefully (including between sessions) to ensure
    /// that nonces are never reused. See *[secp256kfun FROST]* for more info.
    ///
    /// [secp256kfun FROST]: <https://docs.rs/schnorr_fun/latest/schnorr_fun/frost/index.html>
    pub fn new(
        nonce_rng: &mut impl RngCore,
        threshold_scheme: S,
        joint_key: K,
        my_index: usize,
        secret_share: Scalar,
        message: Message<'a>,
    ) -> (RoastSigner<'a, S, K>, Nonce) {
        let initial_nonce = threshold_scheme.gen_nonce(nonce_rng);
        let my_nonces = vec![initial_nonce.clone()];

        (
            RoastSigner {
                threshold_scheme,
                joint_key,
                my_index,
                secret_share,
                message,
                my_nonces,
            },
            initial_nonce.public(),
        )
    }

    /// Create a new nonce using the [`Frost`]'s internal noncegen
    pub fn new_nonce(&mut self, nonce_rng: &mut impl RngCore) -> NonceKeyPair {
        let nonce = self.threshold_scheme.gen_nonce(nonce_rng);
        self.my_nonces.push(nonce.clone());
        nonce
    }

    /// Sign the message with a nonce set
    ///
    /// Also generates a new nonce to share and use for the next signing round
    pub fn sign(
        &mut self,
        nonce_rng: &mut impl RngCore,
        nonce_set: Vec<(usize, Nonce)>,
    ) -> (Scalar<Public, Zero>, Nonce) {
        // call server with (sig, self.new_nonce())
        let my_nonce = self
            .my_nonces
            .pop()
            .expect("some nonce available for signing");
        let sig = self.threshold_scheme.sign(
            self.joint_key.clone(),
            nonce_set,
            self.my_index,
            &self.secret_share,
            my_nonce,
            self.message,
        );
        // Must be called **after sign**
        let nonce = self.new_nonce(nonce_rng);
        (sig, nonce.public())
    }
}
