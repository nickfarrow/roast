use rand::RngCore;
use schnorr_fun::{frost::Nonce, musig::NonceKeyPair, Message, Signature};
use secp256kfun::{
    marker::{Public, Zero},
    Scalar,
};

/// A Threshold Signature Scheme to be used with ROAST
pub trait ThresholdScheme<K> {
    /// The scheme must implement a way for signers to generate nonces
    fn gen_nonce<R: RngCore>(&self, nonce_rng: &mut R) -> NonceKeyPair;

    /// The scheme must implement a way for signers to sign signature shares
    fn sign(
        &self,
        joint_key: K,
        nonces: Vec<(usize, Nonce)>,
        my_index: usize,
        secret_share: &Scalar,
        secret_nonce: NonceKeyPair,
        message: Message,
    ) -> Scalar<Public, Zero>;

    /// The scheme must implement identifiable aborts, if signing session fails then the coordinator
    /// can identify at least one malicious signer responsible for the failure.
    fn verify_signature_share(
        &self,
        joint_key: K,
        nonces: Vec<(usize, Nonce)>,
        index: usize,
        signature_share: Scalar<Public, Zero>,
        message: Message,
    ) -> bool;

    /// The scheme must implement some way for coordinator to combine signature shares.
    fn combine_signature_shares(
        &self,
        joint_key: K,
        nonces: Vec<(usize, Nonce)>,
        signature_shares: Vec<Scalar<Public, Zero>>,
        message: Message,
    ) -> Signature;
}
