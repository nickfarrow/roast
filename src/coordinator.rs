use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
};

use secp256kfun::{
    digest::typenum::U32,
    marker::{Public, Zero},
    Scalar,
};

use schnorr_fun::{
    frost::{Frost, XOnlyFrostKey},
    musig::{Nonce, NonceKeyPair},
    nonce::NonceGen,
    Message, Signature,
};
use sha2::Digest;

pub struct RoastServer<'a, H, NG> {
    pub frost: Frost<H, NG>,
    pub frost_key: Option<XOnlyFrostKey>,
    state: Arc<Mutex<RoastState<'a>>>,
}

pub struct RoastState<'a> {
    message: Message<'a, Public>,
    responsive_signers: HashSet<usize>,
    malicious_signers: HashSet<usize>,
    latest_nonces: HashMap<usize, Nonce>,
    sessions: HashMap<usize, Arc<Mutex<RoastSignSession>>>,
    session_counter: usize,
}

pub struct RoastSignSession {
    signers: HashSet<usize>,
    nonces: Vec<(usize, Nonce)>,
    sig_shares: Vec<Scalar<Public, Zero>>,
}

impl<'a, H: Digest + Clone + Digest<OutputSize = U32>, NG> RoastServer<'a, H, NG> {
    pub fn new(
        frost: Frost<H, NG>,
        frost_key: Option<XOnlyFrostKey>,
        message: Message<'a, Public>,
    ) -> Self {
        return Self {
            frost,
            frost_key,
            state: Arc::new(Mutex::new(RoastState {
                message,
                responsive_signers: HashSet::new(),
                malicious_signers: HashSet::new(),
                latest_nonces: HashMap::new(),
                sessions: HashMap::new(),
                session_counter: 0,
            })),
        };
    }

    pub fn mark_malicious(&self, index: &usize) {
        let mut roast_state = self.state.lock().expect("got lock");
        roast_state.malicious_signers.insert(*index);
        if roast_state.malicious_signers.len()
            >= self.frost_key.clone().expect("initialised").threshold()
        {
            panic!("not enough singers left to continue!");
        }
    }

    // // Running roast as signer
    // pub fn create_signature(
    //     self,
    //     secret_share: &Scalar,
    //     secret_nonce: NonceKeyPair,
    //     my_index: usize,
    //     nonces: Vec<(usize, Nonce)>,
    //     message: Message<'_>,
    // ) -> Scalar<Public, Zero> {
    //     let session = self.frost.start_sign_session(
    //         &self.frost_key.clone().expect("initialised"),
    //         nonces,
    //         message,
    //     );
    //     self.frost.sign(
    //         &self.frost_key.clone().expect("initialised"),
    //         &session,
    //         my_index,
    //         secret_share,
    //         secret_nonce,
    //     )
    // }

    // Main body of the ROAST coordinator algorithm
    pub async fn receive_signature(
        &self,
        index: usize,
        signature_share: Option<Scalar<Public, Zero>>,
        new_nonce: Nonce,
    ) -> (Option<Signature>, Option<Vec<(usize, Nonce)>>) {
        let mut roast_state = self.state.lock().expect("got lock");

        if roast_state.malicious_signers.contains(&index) {
            println!("Malicious signer tried to send signature! {}", index);
            return (None, None);
        }

        if roast_state.responsive_signers.contains(&index) {
            println!(
                "Unsolicited reply from signer {}, marking malicious.",
                index
            );
            self.mark_malicious(&index);
            return (None, None);
        }

        // If this is not the inital message from S_i
        if roast_state.sessions.contains_key(&index) {
            let mut roast_session = roast_state
                .sessions
                .get(&index)
                .unwrap()
                .lock()
                .expect("got lock");

            let session = self.frost.start_sign_session(
                &self.frost_key.clone().expect("initialised"),
                roast_session.nonces.clone(),
                roast_state.message,
            );

            if !self.frost.verify_signature_share(
                &self.frost_key.clone().expect("initialised"),
                &session,
                index,
                signature_share.expect("party provided None signature share"),
            ) {
                println!("Invalid signature, marking {} malicious.", index);
                self.mark_malicious(&index);
                return (None, None);
            }

            // Store valid signature
            roast_session
                .sig_shares
                .push(signature_share.expect("party provided None signature share"));
            println!("New signature from party {}", index);

            // if we have t-of-n, combine!
            if roast_session.sig_shares.len()
                >= self.frost_key.clone().expect("initialised").threshold()
            {
                println!("We have the threshold number of signatures, combining!");
                let combined_sig = self.frost.combine_signature_shares(
                    &self.frost_key.clone().expect("initialised"),
                    &session,
                    roast_session.sig_shares.clone(),
                );
                // return combined signature
                return (Some(combined_sig), None);
            }
        }

        // Store the recieved presignature shares
        roast_state.latest_nonces.insert(index, new_nonce);

        // Mark S_i as responsive
        roast_state.responsive_signers.insert(index);

        // if we now have t responsive signers:
        if roast_state.responsive_signers.len()
            >= self.frost_key.clone().expect("initialised").threshold()
        {
            println!("We now have threshold number of responsive signers!");
            roast_state.session_counter += 1;
            // build the presignature (aggregate the nonces).
            let r_signers = roast_state.responsive_signers.clone();
            // we're not actually aggregating any nonces in this core yet since this will
            // require changes to frost.rs
            let nonces: Vec<_> = r_signers
                .iter()
                .cloned()
                .map(|i| {
                    (
                        i,
                        *roast_state
                            .latest_nonces
                            .get(&i)
                            .expect("has submitted nonce"),
                    )
                })
                .collect();

            for i in r_signers.clone() {
                // send agg nonce to signers (rho, R)
                roast_state.sessions.insert(
                    i,
                    Arc::new(Mutex::new(RoastSignSession {
                        signers: r_signers.clone(),
                        nonces: nonces.clone(),
                        sig_shares: vec![],
                    })),
                );
                let nonces = roast_state
                    .latest_nonces
                    .iter()
                    .map(|(i, nonce)| (*i, *nonce))
                    .collect();
                println!("Responding with nonces:");
                // DO THIS FOR EVERY S_i...>!>!> need async

                // OPEN MANY THREADS AND THEN AWAIT COLLECTION
                return (None, Some(nonces));
            }
        }

        // (None, Some(roast_state.latest_nonces))
        (None, None)
    }
}
