use schnorr_fun::{
    frost::{Frost, FrostKey},
    musig::Nonce,
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
