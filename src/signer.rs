//! ROAST Signer
//! 
//! Manage a FROST key in order to send nonces and signature shares upon request from a ROAST coordinator.
use rand::{RngCore};
use secp256kfun::{
    digest::typenum::U32,
    marker::{Public, Zero, EvenY},
    Scalar,
};

use schnorr_fun::{
    frost::{Frost, FrostKey},
    musig::{Nonce, NonceKeyPair},
    nonce::NonceGen,
    Message,
};
use sha2::Digest;

pub struct RoastSigner<'a, H, NG> {
    frost: Frost<H, NG>,
    frost_key: FrostKey<EvenY>,
    my_index: usize,
    secret_share: Scalar,
    message: Message<'a, Public>,
    my_nonces: Vec<NonceKeyPair>,
}

impl<'a, H: Digest + Clone + Digest<OutputSize = U32>, NG: NonceGen> RoastSigner<'a, H, NG> {
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
        frost: Frost<H, NG>,
        frost_key: FrostKey<EvenY>,
        my_index: usize,
        secret_share: Scalar,
        message: Message<'a>,
    ) -> (RoastSigner<'a, H, NG>, Nonce) {
        let initial_nonce = frost.gen_nonce(nonce_rng);
        let my_nonces = vec![initial_nonce.clone()];

        (
            RoastSigner {
                frost,
                frost_key,
                my_index,
                secret_share,
                message,
                my_nonces,
            },
            initial_nonce.public(),
        )
    }

    /// Create a new nonce using the [`Frost`]'s internal noncegen
    pub fn new_nonce(&mut self,
        nonce_rng: &mut impl RngCore,
    ) -> NonceKeyPair {
        let nonce = self.frost.gen_nonce(
            nonce_rng
        );
        self.my_nonces.push(nonce.clone());
        nonce
    }

    /// Sign the message with a nonce set
    /// 
    /// Also generates a new nonce to share and use for the next signing round
    pub fn sign(&mut self, nonce_rng: &mut impl RngCore, nonce_set: Vec<(usize, Nonce)>) -> (Scalar<Public, Zero>, Nonce) {
        let session = self.frost.start_sign_session(
            &self.frost_key,
            nonce_set,
            self.message,
        );
        let my_nonce = self
            .my_nonces
            .pop()
            .expect("some nonce available to use for signing");
        let sig = self.frost.sign(
            &self.frost_key,
            &session,
            self.my_index,
            &self.secret_share,
            my_nonce,
        );
        // call server with (sig, self.new_nonce())
        let nonce = self.new_nonce(nonce_rng);
        (sig, nonce.public())
    }
}
