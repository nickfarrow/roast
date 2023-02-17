//! ROAST Coordinator
//!
//! The core algorithm for managing the state of a ROAST [`Coordinator`].
//!
//! When a coordinator wants a message to be signed, each signer will first send the coordinator a nonce.
//! Upon the coordinator receiving enough nonces, it should request those "responsive signers" to sign,
//! and also to provide a new nonce for following signing rounds.
//!
//! The ROAST coordinator keeps track of responsive and malicious signers in order to work towards a
//! complete and valid signature.
use std::{
    collections::{HashMap, HashSet},
    fmt,
    sync::{Arc, Mutex},
};

use secp256kfun::{
    marker::{Public, Zero},
    Scalar,
};

use schnorr_fun::{musig::Nonce, Message, Signature};

use crate::threshold_scheme::ThresholdScheme;

// TODO: we may want to continue the roast coordinator state to the next message signing session
// such that we keep our list of malicious or responsive signers. fn start_session() & Option<Message>?
pub struct Coordinator<'a, S, K> {
    pub threshold_scheme: S,
    pub joint_key: K,
    n_signers: usize,
    threshold: usize,
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

#[derive(Debug, Clone)]
pub enum RoastError {
    TooFewHonest,
}

impl fmt::Display for RoastError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::TooFewHonest => write!(f, "Too few honest signers"),
        }
    }
}

// impl<'a, H: Digest + Clone + Digest<OutputSize = U32>, NG> Coordinator<'a, H, NG> {
impl<'a, S: ThresholdScheme<K>, K: Clone> Coordinator<'a, S, K> {
    /// Create a new ROAST [`Coordinator`] to receive signatures and nonces from signers
    ///
    /// # Returns
    ///
    /// Returns a Coordinator with a fresh state
    pub fn new(
        threshold_scheme: S,
        joint_key: K,
        message: Message<'a, Public>,
        threshold: usize,
        n_signers: usize,
    ) -> Self {
        return Self {
            threshold_scheme,
            joint_key,
            n_signers,
            threshold,
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

    /// Receive a signature share and new nonce from a signer
    ///
    /// For the first signing session, signers must first send just a nonce with None signature.
    ///
    /// This function contains the core of *[ROAST paper's coordinator algorithm]* (Figure 4).
    /// Hopefully the comments are helpful in comparison.
    ///
    /// [ROAST coordinator algorithm]: <https://eprint.iacr.org/2022/550.pdf>
    ///
    /// # Returns
    ///
    /// Returns a [`RoastResponse`] which contains an optional signature and nonce set.
    /// Check the `recipients` field to determine who this message should be broadcast too.
    pub fn receive(
        &self,
        index: usize,
        signature_share: Option<Scalar<Public, Zero>>,
        new_nonce: Nonce,
    ) -> Result<RoastResponse, RoastError> {
        let mut roast_state = self.state.lock().expect("got lock");
        // dbg!(&roast_state);

        if roast_state.malicious_signers.contains(&index) {
            println!("Malicious signer tried to send signature! {}", index);
            return Ok(RoastResponse {
                recipients: vec![index],
                combined_signature: None,
                nonce_set: None,
            });
        }

        if roast_state.responsive_signers.contains(&index) {
            println!(
                "Unsolicited reply from signer {}, marking malicious.",
                index
            );

            // Mark malicious
            roast_state.malicious_signers.insert(index);
            if roast_state.malicious_signers.len() > self.n_signers - self.threshold {
                return Err(RoastError::TooFewHonest);
            }

            return Ok(RoastResponse {
                recipients: vec![index],
                combined_signature: None,
                nonce_set: None,
            });
        }

        // If this is not the inital message from S_i
        match roast_state.signer_session_map.get(&index) {
            Some(session_id) => {
                println!(
                    "Party {} sent a signature for sign session {}",
                    index, session_id
                );
                let nonces = {
                    let roast_session = roast_state
                        .sessions
                        .get(&session_id)
                        .unwrap()
                        .lock()
                        .expect("got lock");
                    roast_session.nonces.clone()
                };
                if !self.threshold_scheme.verify_signature_share(
                    self.joint_key.clone(),
                    nonces.clone(),
                    index,
                    signature_share.expect(
                        "party unexpectedly provided None signature share for a sign session",
                    ),
                    roast_state.message,
                ) {
                    println!("Invalid signature, marking {} malicious.", index);
                    roast_state.malicious_signers.insert(index);
                    if roast_state.malicious_signers.len() > self.n_signers - self.threshold {
                        return Err(RoastError::TooFewHonest);
                    }

                    return Ok(RoastResponse {
                        recipients: vec![index],
                        combined_signature: None,
                        nonce_set: None,
                    });
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
                if roast_session.sig_shares.len() >= self.threshold {
                    println!("We have the threshold number of signatures, combining!");
                    dbg!(&roast_session.sig_shares);
                    let combined_sig = self.threshold_scheme.combine_signature_shares(
                        self.joint_key.clone(),
                        nonces.clone(),
                        roast_session.sig_shares.clone(),
                        roast_state.message,
                    );
                    // return combined signature
                    return Ok(RoastResponse {
                        recipients: (0..self.n_signers).collect(),
                        combined_signature: Some(combined_sig),
                        nonce_set: None,
                    });
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
        if roast_state.responsive_signers.len() >= self.threshold {
            println!("We now have threshold number of responsive signers!");
            dbg!(&roast_state.responsive_signers);
            roast_state.session_counter += 1;

            // Look up the nonces
            let r_signers = roast_state.responsive_signers.clone();
            // we're not actually aggregating any nonces within the coordinator
            // This is a change that would belong in the schnorr_fun frost code.
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
            // Clear responsive signers for following rounds
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
            return Ok(RoastResponse {
                recipients: r_signers.into_iter().collect(),
                combined_signature: None,
                nonce_set: Some(nonces),
            });
        }

        // (None, Some(roast_state.latest_nonces))
        return Ok(RoastResponse {
            recipients: vec![index],
            combined_signature: None,
            nonce_set: None,
        });
    }
}
