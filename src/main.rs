use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
};

use secp256kfun::{
    digest::typenum::U32,
    marker::{Public, Zero},
    rand_core::RngCore,
    Scalar,
};

use schnorr_fun::{
    frost::{Frost, PointPoly, ScalarPoly, XOnlyFrostKey},
    musig::{Nonce, NonceKeyPair},
    nonce::Deterministic,
    Message, Signature,
};
use sha2::Digest;

use schnorr_fun::Schnorr;
use sha2::Sha256;

struct Roast<'a, H, NG> {
    frost: Frost<H, NG>,
    frost_key: XOnlyFrostKey,
    state: Arc<Mutex<RoastState<'a>>>,
}

struct RoastState<'a> {
    message: Message<'a, Public>,
    responsive_signers: HashSet<usize>,
    malicious_signers: HashSet<usize>,
    latest_nonces: HashMap<usize, Nonce>,
    sessions: HashMap<usize, Arc<Mutex<RoastSession>>>,
    session_counter: usize,
}

struct RoastSession {
    signers: HashSet<usize>,
    nonces: Vec<(usize, Nonce)>,
    sig_shares: Vec<Scalar<Public, Zero>>,
}

impl<'a, H: Digest + Clone + Digest<OutputSize = U32>, NG> Roast<'a, H, NG> {
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
                session_counter: 0,
            })),
        };
    }

    pub async fn mark_malicious(&self, index: &usize) {
        let mut roast_state = self.state.lock().expect("got lock");
        roast_state.malicious_signers.insert(*index);
        if roast_state.malicious_signers.len() >= self.frost_key.threshold() {
            panic!("not enough singers left to continue!");
        }
    }

    /// Running roast as a signer
    // pub fn create_signature(
    //     self,
    //     secret_share: &Scalar,
    //     secret_nonce: NonceKeyPair,
    //     my_index: usize,
    //     nonces: Vec<(usize, Nonce)>,
    //     message: Message<'_>,
    // ) -> Scalar<Public, Zero> {
    //     let session = self
    //         .frost
    //         .start_sign_session(&self.frost_key, nonces, message);
    //     self.frost.sign(
    //         &self.frost_key,
    //         &session,
    //         my_index,
    //         secret_share,
    //         secret_nonce,
    //     )
    // }

    // Main body of the ROAST coordinator algorithm
    pub async fn recieve_signature(
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

        dbg!(roast_state.responsive_signers.clone());
        if roast_state.responsive_signers.contains(&index) {
            println!(
                "Unsolicited reply from signer {}, marking malicious.",
                index
            );
            self.mark_malicious(&index).await;
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
                &self.frost_key,
                roast_session.nonces.clone(),
                roast_state.message,
            );

            if !self.frost.verify_signature_share(
                &self.frost_key,
                &session,
                index,
                signature_share.expect("party provided None signature share"),
            ) {
                println!("Invalid signature, marking {} malicious.", index);
                self.mark_malicious(&index).await;
                return (None, None);
            }

            // Store valid signature
            roast_session
                .sig_shares
                .push(signature_share.expect("party provided None signature share"));
            println!("New signature from party {}", index);

            // if we have t-of-n, combine!
            if roast_session.sig_shares.len() >= self.frost_key.threshold() {
                println!("We have the threshold number of signatures, combining!");
                let combined_sig = self.frost.combine_signature_shares(
                    &self.frost_key,
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
        if roast_state.responsive_signers.len() >= self.frost_key.threshold() {
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
                    Arc::new(Mutex::new(RoastSession {
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

        // Return None if we get to here?
        // Better API would be return the number of remaining signatures or th remaining signature if complete.
        // Non complex RecieveSigResponse Result
        (None, None)
    }
}

// use mini_redis::{client, Result};

#[tokio::main]
async fn main() {
    // Do frost keygen for 9-of-15
    let threshold: usize = 2;
    let n_parties: usize = 3;

    let frost = Frost::new(Schnorr::<Sha256, Deterministic<Sha256>>::new(
        Deterministic::<Sha256>::default(),
    ));
    dbg!(threshold, n_parties);
    assert!(threshold <= n_parties);

    // create some scalar polynomial for each party
    let mut scalar_polys = vec![];
    for i in 1..=n_parties {
        println!("Creating scalar poly {}", i);
        let scalar_poly = (1..=threshold)
            .map(|_| {
                let mut rng: rand::rngs::StdRng = rand::SeedableRng::from_entropy();
                Scalar::from(rng.next_u32())
                    .non_zero()
                    .expect("computationally unreachable")
            })
            .collect();
        scalar_polys.push(ScalarPoly::new(scalar_poly));
    }
    let point_polys: Vec<PointPoly> = scalar_polys.iter().map(|sp| sp.to_point_poly()).collect();

    let keygen = frost.new_keygen(point_polys).unwrap();

    let mut proofs_of_possession = vec![];
    let mut shares_vec = vec![];
    for (i, sp) in scalar_polys.into_iter().enumerate() {
        println!("calculating shares and pop {}", i);
        let (shares, pop) = frost.create_shares(&keygen, sp);
        proofs_of_possession.push(pop);
        shares_vec.push(shares);
    }
    println!("Calculated shares and pops");

    // collect the recieved shares for each party
    let mut recieved_shares: Vec<Vec<_>> = vec![];
    for party_index in 0..n_parties {
        println!("Collecting shares for {}", party_index);
        recieved_shares.push(vec![]);
        for share_index in 0..n_parties {
            recieved_shares[party_index].push(shares_vec[share_index][party_index].clone());
        }
    }

    println!("{:?}", recieved_shares);

    // finish keygen for each party
    let (secret_shares, frost_keys): (Vec<Scalar>, Vec<XOnlyFrostKey>) = (0..n_parties)
        .map(|i| {
            println!("Finishing keygen for participant {}", i);
            std::thread::sleep(std::time::Duration::from_secs(1));
            let (secret_share, frost_key) = frost
                .finish_keygen(
                    keygen.clone(),
                    i,
                    recieved_shares[i].clone(),
                    proofs_of_possession.clone(),
                )
                .expect("collected shares");
            println!("got secret share");
            let xonly_frost_key = frost_key.into_xonly_key();
            (secret_share, xonly_frost_key)
        })
        .unzip();
    println!("Finished keygen!");

    // use a boolean mask for which t participants are signers
    let mut signer_mask = vec![true; threshold];
    signer_mask.append(&mut vec![false; n_parties - threshold]);
    // shuffle the mask for random signers

    let signer_indexes: Vec<_> = signer_mask
        .iter()
        .enumerate()
        .filter(|(_, is_signer)| **is_signer)
        .map(|(i, _)| i)
        .collect();

    println!("Preparing for signing session...");

    let verification_shares_bytes: Vec<_> = frost_keys[signer_indexes[0]]
        .verification_shares()
        .map(|share| share.to_bytes())
        .collect();

    let sid = [
        frost_keys[signer_indexes[0]]
            .public_key()
            .to_xonly_bytes()
            .as_slice(),
        verification_shares_bytes.concat().as_slice(),
        b"frost-prop-test".as_slice(),
    ]
    .concat();

    let mut nonces: Vec<NonceKeyPair> = signer_indexes
        .iter()
        .map(|i| {
            frost.gen_nonce(
                &secret_shares[*i],
                &[sid.as_slice(), [*i as u8].as_slice()].concat(),
                Some(frost_keys[signer_indexes[0]].public_key().normalize()),
                None,
            )
        })
        .collect();

    let mut recieved_nonces: Vec<_> = vec![];
    for (i, nonce) in signer_indexes.iter().zip(nonces.clone()) {
        recieved_nonces.push((*i, nonce.public()));
    }
    println!("Recieved nonces..");

    // Now time for ROAST

    // Test roast being run by 1 external party -> frost_key contains public data
    let message = Message::plain("test", b"test");
    let roast = Roast::new(frost.clone(), frost_keys[0].clone(), message);

    let mut counter = 0;
    loop {
        for i in 0..signer_indexes.len() {
            let current_nonce = nonces[i].clone();
            let next_nonce = frost.gen_nonce(
                &secret_shares[i],
                &[sid.clone(), [counter].to_vec()].concat(),
                Some(frost_keys[i].public_key().normalize()),
                None,
            );
            nonces[i] = next_nonce.clone();

            let (sig, new_nonces) = if counter == 0 {
                // Initial sending empty sig with nonces
                roast.recieve_signature(i, None, next_nonce.public()).await
            } else {
                println!("Signing for participant {}", signer_indexes[i]);
                let signer_index = signer_indexes[i];
                let session = frost.start_sign_session(
                    &frost_keys[signer_index],
                    recieved_nonces.clone(),
                    Message::plain("test", b"test"),
                );
                let sig = frost.sign(
                    &frost_keys[signer_index],
                    &session,
                    signer_index,
                    &secret_shares[signer_index],
                    current_nonce.clone(),
                );
                roast
                    .recieve_signature(i, Some(sig), next_nonce.public())
                    .await
            };

            // Hangs if you always send same index
            match sig {
                Some(combined_sig) => {
                    assert!(frost.schnorr.verify(
                        &frost_keys[signer_indexes[i]].public_key(),
                        Message::<Public>::plain("test", b"test"),
                        &combined_sig
                    ));
                    println!("Signed via roast!");
                    break;
                }
                None => {
                    println!("Sent partial signature {} to roast..", i)
                }
            };
            match new_nonces {
                Some(nonces) => {
                    recieved_nonces = nonces.clone();
                    println!("Got new nonces {:?}", nonces);
                }
                None => println!("No new nonces!?"),
            }
            println!("Current nonces {:?}", recieved_nonces.clone());
        }
        counter += 1;
    }
}
