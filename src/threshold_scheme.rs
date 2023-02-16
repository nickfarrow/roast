use schnorr_fun::{frost::Nonce, Message, Signature};
use secp256kfun::{
    marker::{Public, Zero},
    Scalar,
};

pub trait ThresholdScheme<K> {
    fn verify_signature_share(
        &self,
        joint_key: K,
        nonces: Vec<(usize, Nonce)>,
        index: usize,
        signature_share: Scalar<Public, Zero>,
        message: Message,
    ) -> bool;

    fn combine_signature_shares(
        &self,
        joint_key: K,
        nonces: Vec<(usize, Nonce)>,
        signature_shares: Vec<Scalar<Public, Zero>>,
        message: Message,
    ) -> Signature;
}
