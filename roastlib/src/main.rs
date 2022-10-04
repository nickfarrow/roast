fn main() {}

#[cfg(test)]
mod test {
    use roast::coordinator;
    use roast::frost;
    use roast::signer;
    use schnorr_fun::frost as secp_frost;
    use schnorr_fun::musig::Nonce;
    use schnorr_fun::nonce::Deterministic;
    use schnorr_fun::Message;
    use sha2::Sha256;

    use secp256kfun::proptest::{
        proptest,
        strategy::{Just, Strategy},
    };

    #[test]
    fn test_2_of_3_sequential() {
        let frost = secp_frost::Frost::<Sha256, Deterministic<Sha256>>::default();
        let (secret_shares, frost_keys) = frost::frost_keygen(2, 3);

        let message = Message::plain("test", b"test");
        let roast = coordinator::Coordinator::new(frost.clone(), frost_keys[0].clone(), message);

        // Create each signer session and create an initial nonce
        let (mut signer1, nonce1) = signer::RoastSigner::new(
            frost.clone(),
            frost_keys[0].clone(),
            0,
            secret_shares[0].clone(),
            [].as_slice(),
            message,
        );
        let (mut signer2, nonce2) = signer::RoastSigner::new(
            frost,
            frost_keys[1].clone(),
            1,
            secret_shares[1].clone(),
            [1].as_slice(),
            message,
        );

        // Begin with each signer sending a nonce to ROAST, marking these signers as responsive.
        let (combined_signature, nonce_set) = roast.receive(0, None, nonce1);
        assert!(nonce_set.is_none());
        assert!(combined_signature.is_none());

        let (_combined_signature, nonce_set) = roast.receive(1, None, nonce2);
        assert!(nonce_set.is_some());

        // Once ROAST receives the threshold number of nonces, it responds with a nonce set
        let sign_session_nonces = nonce_set.expect("roast responded with nonces");

        // The signer signs using this the nonces for this sign session,
        // and responds to ROAST with a signature share.
        let (sig_share2, nonce2) = signer2.sign(sign_session_nonces.clone());
        let (combined_signature, nonce_set) = roast.receive(1, Some(sig_share2), nonce2);
        dbg!(&combined_signature.is_some(), &nonce_set.is_some());
        assert!(combined_signature.is_none());

        // ROAST also sends the nonce set to the other signer, who also signs
        let (sig_share1, nonce1) = signer1.sign(sign_session_nonces);

        let (combined_signature, nonce_set) = roast.receive(0, Some(sig_share1), nonce1);
        dbg!(&combined_signature.is_some(), &nonce_set.is_some());
        assert!(combined_signature.is_some());

        // Once the threshold number of signature shares have been received,
        // ROAST combines the signature shares into the aggregate signature
        dbg!(combined_signature);
    }

    // This test works, but slowly since it goes through a few sets of responsive signers
    // before producing a complete signature. This is because we aren't accurately replicating
    // any asynchronous messages.
    fn t_of_n_sequential(threshold: usize, n_parties: usize) {
        let frost = secp_frost::Frost::<Sha256, Deterministic<Sha256>>::default();
        let (secret_shares, frost_keys) = frost::frost_keygen(threshold, n_parties);

        let message = Message::plain("test", b"test");
        let roast = coordinator::Coordinator::new(frost.clone(), frost_keys[0].clone(), message);

        // Create each signer session and create an initial nonce
        let (mut signers, mut nonces): (Vec<_>, Vec<_>) = frost_keys
            .into_iter()
            .zip(secret_shares)
            .enumerate()
            .map(|(i, (frost_key, secret_share))| {
                signer::RoastSigner::new(
                    frost.clone(),
                    frost_key,
                    i,
                    secret_share,
                    [i as u8].as_slice(),
                    message,
                )
            })
            .unzip();

        let mut sig_shares = vec![];
        let mut nonce_set: Vec<Option<Vec<(usize, Nonce)>>> = vec![None; n_parties + 1];
        let mut finished_signature = None;
        let mut n_rounds = 0;

        while finished_signature.is_none() {
            n_rounds += 1;
            for signer_index in 0..n_parties {
                // Check to see if this signer has recieved any nonces
                let (sig, new_nonce) = match nonce_set[signer_index].clone() {
                    // Sign if we have recieved nonces, and create new nonce
                    Some(signing_nonces) => {
                        // dbg!(&signing_nonces);
                        let (sig, nonce) = signers[signer_index].sign(signing_nonces);
                        (Some(sig), nonce)
                    }
                    // Otherwise, just create a new nonce
                    None => (
                        None,
                        signers[signer_index]
                            .new_nonce([signer_index as u8].as_slice())
                            .public(),
                    ),
                };
                // Send signature and our next nonce to ROAST
                let (combined_sig, updated_nonce_set) = roast.receive(signer_index, sig, new_nonce);

                if combined_sig.is_some() {
                    finished_signature = combined_sig;
                    break;
                }

                // hacky mimic broadcast
                // Store the new nonce_set for this caller,
                // and for peers who are have not recieved any nonces yet.
                // this will probably break when introducing malicious signers
                if updated_nonce_set.is_some() {
                    nonce_set[signer_index] = updated_nonce_set.clone();
                    nonce_set = nonce_set
                        .into_iter()
                        .map(|nonce| {
                            if nonce.is_some() {
                                nonce
                            } else {
                                updated_nonce_set.clone()
                            }
                        })
                        .collect()
                }

                nonces[signer_index] = new_nonce;

                if sig.is_some() {
                    sig_shares.push(sig);
                }
                // dbg!(&sig_shares);
            }
        }
        dbg!(&finished_signature, &n_rounds);
        assert!(finished_signature.is_some())
    }

    proptest! {
            #[test]
            fn roast_proptest_t_of_n(
                (n_parties, threshold) in (2usize..5).prop_flat_map(|n| (Just(n), 2usize..=n))
            ) {
            t_of_n_sequential(threshold, n_parties);
        }
    }
}
