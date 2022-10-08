//! ROAST coordinator
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
    musig::Nonce,
    Message, Signature,
};
use sha2::Digest;

pub struct Coordinator<'a, H, NG> {
    pub frost: Frost<H, NG>,
    pub frost_key: XOnlyFrostKey,
    state: Arc<Mutex<RoastState<'a>>>,
}

#[derive(Debug)]
pub struct RoastState<'a> {
    message: Message<'a, Public>,
    responsive_signers: HashSet<usize>,
    malicious_signers: HashSet<usize>,
    session_counter: usize,
    latest_nonces: HashMap<usize, Nonce>,
    sessions: HashMap<usize, Arc<Mutex<RoastSignSession>>>,
    signer_session_map: HashMap<usize, usize>,
}

#[derive(Debug)]
pub struct RoastSignSession {
    pub signers: HashSet<usize>,
    nonces: Vec<(usize, Nonce)>,
    sig_shares: Vec<Scalar<Public, Zero>>,
}

#[derive(Debug)]
pub struct RoastResponse {
    pub recipients: Vec<usize>,
    pub combined_signature: Option<Signature>,
    pub nonce_set: Option<Vec<(usize, Nonce)>>,
}

impl<'a, H: Digest + Clone + Digest<OutputSize = U32>, NG> Coordinator<'a, H, NG> {
    pub fn new(
        frost: Frost<H, NG>,
        frost_key: XOnlyFrostKey,
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
                signer_session_map: HashMap::new(),
                session_counter: 0,
            })),
        };
    }

    // pub fn mark_malicious(self, roast_state: &mut MutexGuard<RoastState>, index: &usize) {
    //     roast_state.malicious_signers.insert(*index);
    //     if roast_state.malicious_signers.len() >= self.frost_key.clone().threshold() {
    //         panic!("not enough singers left to continue!");
    //     }
    // }

    // Main body of the ROAST coordinator algorithm
    pub fn receive(
        &self,
        index: usize,
        signature_share: Option<Scalar<Public, Zero>>,
        new_nonce: Nonce,
    ) -> RoastResponse {
        let mut roast_state = self.state.lock().expect("got lock");
        // dbg!(&roast_state);

        if roast_state.malicious_signers.contains(&index) {
            println!("Malicious signer tried to send signature! {}", index);
            return RoastResponse {
                recipients: vec![index],
                combined_signature: None,
                nonce_set: None,
            };
        }

        if roast_state.responsive_signers.contains(&index) {
            println!(
                "Unsolicited reply from signer {}, marking malicious.",
                index
            );

            // Mark malicious
            roast_state.malicious_signers.insert(index);
            if roast_state.malicious_signers.len() >= self.frost_key.clone().threshold() {
                panic!("not enough singers left to continue!");
            }

            return RoastResponse {
                recipients: vec![index],
                combined_signature: None,
                nonce_set: None,
            };
        }

        // If this is not the inital message from S_i
        match roast_state.signer_session_map.get(&index) {
            Some(session_id) => {
                println!(
                    "Party {} sent a signature for sign session {}",
                    index, session_id
                );
                // Get session from roast_state
                let session = {
                    let roast_session = roast_state
                        .sessions
                        .get(&session_id)
                        .unwrap()
                        .lock()
                        .expect("got lock");

                    self.frost.start_sign_session(
                        &self.frost_key.clone(),
                        roast_session.nonces.clone(),
                        roast_state.message,
                    )
                };

                if !self.frost.verify_signature_share(
                    &self.frost_key.clone(),
                    &session,
                    index,
                    signature_share.expect(
                        "party unexpectedly provided None signature share for a sign session",
                    ),
                ) {
                    println!("Invalid signature, marking {} malicious.", index);
                    roast_state.malicious_signers.insert(index);
                    if roast_state.malicious_signers.len() >= self.frost_key.clone().threshold() {
                        panic!("not enough singers left to continue!");
                    }

                    return RoastResponse {
                        recipients: vec![index],
                        combined_signature: None,
                        nonce_set: None,
                    };
                }

                // Reopen session within the roast state for writting
                let mut roast_session = roast_state
                    .sessions
                    .get(&session_id)
                    .unwrap()
                    .lock()
                    .expect("got lock");

                // Store valid signature
                roast_session
                    .sig_shares
                    .push(signature_share.expect("party provided None signature share"));
                println!("New signature from party {}", index);

                // if we have t-of-n, combine!
                if roast_session.sig_shares.len() >= self.frost_key.clone().threshold() {
                    println!("We have the threshold number of signatures, combining!");
                    dbg!(&roast_session.sig_shares);
                    let combined_sig = self.frost.combine_signature_shares(
                        &self.frost_key.clone(),
                        &session,
                        roast_session.sig_shares.clone(),
                    );
                    // return combined signature
                    return RoastResponse {
                        recipients: (0..self.frost_key.n_signers()).collect(),
                        combined_signature: Some(combined_sig),
                        nonce_set: None,
                    };
                }
            }
            None => {}
        }

        // Store the recieved presignature shares
        roast_state.latest_nonces.insert(index, new_nonce);

        // Mark S_i as responsive
        println!("Marked {} as responsive", index.clone());
        roast_state.responsive_signers.insert(index);

        // if we now have t responsive signers:
        if roast_state.responsive_signers.len() >= self.frost_key.clone().threshold() {
            println!("We now have threshold number of responsive signers!");
            dbg!(&roast_state.responsive_signers);
            roast_state.session_counter += 1;

            // Look up the nonces
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

            let sid = roast_state.session_counter.clone();
            // Clear responsive signers (otherwise we ban everyone and hang)
            roast_state.responsive_signers = HashSet::new();
            roast_state.sessions.insert(
                sid,
                Arc::new(Mutex::new(RoastSignSession {
                    signers: r_signers.clone(),
                    nonces: nonces.clone(),
                    sig_shares: vec![],
                })),
            );

            // Remember the session for signers S_i
            for i in &r_signers {
                roast_state.signer_session_map.insert(*i, sid);
            }

            // Send nonces to each signer S_i
            return RoastResponse {
                recipients: r_signers.into_iter().collect(),
                combined_signature: None,
                nonce_set: Some(nonces),
            };
        }

        // (None, Some(roast_state.latest_nonces))
        return RoastResponse {
            recipients: vec![index],
            combined_signature: None,
            nonce_set: None,
        };
    }
}
