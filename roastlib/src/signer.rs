use secp256kfun::{
    digest::typenum::U32,
    marker::{Public, Zero},
    Scalar,
};

use schnorr_fun::{
    frost::{Frost, XOnlyFrostKey},
    musig::{Nonce, NonceKeyPair},
    nonce::NonceGen,
    Message,
};
use sha2::Digest;

pub struct RoastSigner<'a, H, NG> {
    frost: Frost<H, NG>,
    frost_key: XOnlyFrostKey,
    my_index: usize,
    secret_share: Scalar,
    message: Message<'a, Public>,
    my_nonces: Vec<NonceKeyPair>,
}

impl<'a, H: Digest + Clone + Digest<OutputSize = U32>, NG: NonceGen> RoastSigner<'a, H, NG> {
    pub fn new(
        frost: Frost<H, NG>,
        frost_key: XOnlyFrostKey,
        my_index: usize,
        secret_share: Scalar,
        initial_nonce_sid: &[u8],
        message: Message<'a>,
    ) -> (RoastSigner<'a, H, NG>, Nonce) {
        let initial_nonce = frost.gen_nonce(
            &secret_share,
            &initial_nonce_sid,
            Some(frost_key.public_key().normalize()),
            Some(message),
        );
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

    pub fn new_nonce(&self, sid: &[u8]) -> NonceKeyPair {
        let nonce = self.frost.gen_nonce(
            &self.secret_share,
            sid,
            Some(self.frost_key.public_key().normalize()),
            Some(self.message),
        );
        nonce
    }

    pub fn sign(&mut self, nonce_set: Vec<(usize, Nonce)>) -> (Scalar<Public, Zero>, Nonce) {
        let session = self.frost.start_sign_session(
            &self.frost_key,
            nonce_set,
            Message::plain("test", b"test"),
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
        self.my_nonces.push(self.new_nonce(&[0]));

        (sig, self.my_nonces.last().expect("some nonce").public())
    }
}
