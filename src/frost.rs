use schnorr_fun::{
    frost::{Frost, FrostKey},
    musig::{Nonce, NonceKeyPair},
    Message, Signature,
};
use secp256kfun::{
    digest::typenum::U32,
    marker::{EvenY, Public, Zero},
    Scalar,
};
use sha2::Digest;

use crate::threshold_scheme::ThresholdScheme;

impl<H: Digest + Clone + Digest<OutputSize = U32>, NG> ThresholdScheme<FrostKey<EvenY>>
    for Frost<H, NG>
{
    fn gen_nonce<R: rand::RngCore>(&self, nonce_rng: &mut R) -> schnorr_fun::musig::NonceKeyPair {
        NonceKeyPair::random(nonce_rng)
    }

    fn sign(
        &self,
        joint_key: FrostKey<EvenY>,
        nonces: Vec<(usize, Nonce)>,
        my_index: usize,
        secret_share: &Scalar,
        secret_nonce: schnorr_fun::musig::NonceKeyPair,
        message: Message,
    ) -> Scalar<Public, Zero> {
        let session = self.start_sign_session(&joint_key, nonces, message);
        self.sign(&joint_key, &session, my_index, &secret_share, secret_nonce)
    }

    fn verify_signature_share(
        &self,
        joint_key: FrostKey<EvenY>,
        nonces: Vec<(usize, Nonce)>,
        index: usize,
        signature_share: Scalar<Public, Zero>,
        message: Message,
    ) -> bool {
        let sign_session = self.start_sign_session(&joint_key, nonces, message);
        self.verify_signature_share(&joint_key, &sign_session, index, signature_share)
    }

    fn combine_signature_shares(
        &self,
        joint_key: FrostKey<EvenY>,
        nonces: Vec<(usize, Nonce)>,
        signature_shares: Vec<Scalar<Public, Zero>>,
        message: Message,
    ) -> Signature {
        let sign_session = self.start_sign_session(&joint_key, nonces, message);
        self.combine_signature_shares(&joint_key, &sign_session, signature_shares)
    }
}
