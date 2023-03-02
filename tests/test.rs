#[cfg(feature = "frost")]
mod tests {
    use rand::seq::SliceRandom;

    use schnorr_fun::frost as secp_frost;
    use schnorr_fun::musig::Nonce;
    use schnorr_fun::nonce::Deterministic;
    use schnorr_fun::Message;
    use secp256kfun::proptest::test_runner::RngAlgorithm;
    use secp256kfun::proptest::test_runner::TestRng;
    use secp256kfun::Scalar;
    use sha2::Sha256;

    use secp256kfun::proptest::{
        proptest,
        strategy::{Just, Strategy},
    };

    use roast::coordinator;
    use roast::signer;

    #[test]
    fn test_2_of_3_basic() {
        let frost = secp_frost::Frost::<Sha256, Deterministic<Sha256>>::default();
        let mut rng = rand::thread_rng();

        let (frost_key, secret_shares) = frost.simulate_keygen(2, 3, &mut rng);
        let xonly_frost_key = frost_key.into_xonly_key();

        let message = Message::plain("test", b"test");
        let roast =
            coordinator::Coordinator::new(frost.clone(), xonly_frost_key.clone(), message, 2, 3);

        // Create each signer session and create an initial nonce
        let (mut signer1, nonce1) = signer::RoastSigner::new(
            &mut rng,
            frost.clone(),
            xonly_frost_key.clone(),
            0,
            secret_shares[0].clone(),
            message,
        );
        let (mut signer2, nonce2) = signer::RoastSigner::new(
            &mut rng,
            frost,
            xonly_frost_key.clone(),
            1,
            secret_shares[1].clone(),
            message,
        );

        // Begin with each signer sending a nonce to ROAST, marking these signers as responsive.
        let response = roast.receive(0, None, nonce1).unwrap();
        assert!(response.nonce_set.is_none());
        assert!(response.combined_signature.is_none());

        let response2 = roast.receive(1, None, nonce2).unwrap();
        assert!(response2.nonce_set.is_some());

        // Once ROAST receives the threshold number of nonces, it responds to the group of
        // responsive signers with a nonce set to the group of responsive signers.
        assert!(response2.recipients.contains(&0) && response2.recipients.contains(&1));
        let sign_session_nonces = response2.nonce_set.expect("roast responded with nonces");

        // The signer signs using this the nonces for this sign session,
        // and responds to ROAST with a signature share.
        let (sig_share2, nonce2) = signer2.sign(&mut rng, sign_session_nonces.clone());
        let response = roast.receive(1, Some(sig_share2), nonce2).unwrap();
        dbg!(
            &response.combined_signature.is_some(),
            &response.nonce_set.is_some()
        );
        assert!(response.combined_signature.is_none());

        // ROAST also sends the nonce set to the other signer, who also signs
        let (sig_share1, nonce1) = signer1.sign(&mut rng, sign_session_nonces);

        let response = roast.receive(0, Some(sig_share1), nonce1).unwrap();
        dbg!(
            &response.combined_signature.is_some(),
            &response.nonce_set.is_some()
        );
        assert!(response.combined_signature.is_some());

        // Once the threshold number of signature shares have been received,
        // ROAST combines the signature shares into the aggregate signature
        dbg!(response.combined_signature);
    }

    // This test works, but slowly since it goes through a few sets of responsive signers
    // before producing a complete signature. This is because we aren't accurately replicating
    // any asynchronous messages.
    fn t_of_n_sequential(
        threshold: usize,
        n_parties: usize,
        n_malicious: usize,
        rng: &mut TestRng,
    ) {
        println!(
            "Testing {}-of-{} with {} malicious:",
            threshold, n_parties, n_malicious
        );
        let frost = secp_frost::Frost::<Sha256, Deterministic<Sha256>>::default();
        let (frost_key, secret_shares) =
            frost.simulate_keygen(threshold, n_parties, &mut rand::thread_rng());
        let xonly_frost_key = frost_key.into_xonly_key();

        let message = Message::plain("test", b"test");
        let roast = coordinator::Coordinator::new(
            frost.clone(),
            xonly_frost_key.clone(),
            message,
            threshold,
            n_parties,
        );

        // use a boolean mask for which participants are malicious
        let mut malicious_mask = vec![true; n_malicious];
        malicious_mask.append(&mut vec![false; n_parties - n_malicious]);
        // shuffle the mask for random signers
        malicious_mask.shuffle(rng);

        let malicious_indexes: Vec<_> = malicious_mask
            .iter()
            .enumerate()
            .filter(|(_, is_signer)| **is_signer)
            .map(|(i, _)| i)
            .collect();

        // Create each signer session and create an initial nonce
        let (mut signers, mut nonces): (Vec<_>, Vec<_>) = secret_shares
            .into_iter()
            .enumerate()
            .map(|(i, secret_share)| {
                signer::RoastSigner::new(
                    rng,
                    frost.clone(),
                    xonly_frost_key.clone(),
                    i,
                    secret_share,
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
                    // If the signer has a nonce shared, sign and send sig as well as a new nonce
                    Some(signing_nonces) => {
                        let (mut sig, nonce) = signers[signer_index].sign(rng, signing_nonces);
                        // If we are malcious, send a bogus signature to disrupt signing process
                        if malicious_indexes.contains(&signer_index) {
                            sig = Scalar::random(rng).mark_zero().public();
                        }
                        (Some(sig), nonce)
                    }
                    // Otherwise, just create a new nonce
                    None => (None, signers[signer_index].new_nonce(rng).public()),
                };
                // Send signature and our next nonce to ROAST
                let response = roast.receive(signer_index, sig, new_nonce).unwrap();
                nonces[signer_index] = new_nonce;

                if response.combined_signature.is_some() {
                    finished_signature = response.combined_signature;
                    break;
                }

                for index in response.recipients {
                    nonce_set[index] = response.nonce_set.clone();
                }

                if sig.is_some() {
                    sig_shares.push(sig);
                }
                // dbg!(&sig_shares);
            }
        }
        dbg!(&finished_signature, &n_rounds);
        assert!(finished_signature.is_some())
    }

    #[test]
    fn roast_5_of_10_5_malicious() {
        let mut rng = TestRng::deterministic_rng(RngAlgorithm::ChaCha);
        t_of_n_sequential(5, 10, 5, &mut rng);
    }

    proptest! {
            #[test]
            fn proptest_t_of_n_no_malicious(
                (n_parties, threshold) in (2usize..6).prop_flat_map(|n| (Just(n), 2usize..=n))
            ) {
                let mut rng = TestRng::deterministic_rng(RngAlgorithm::ChaCha);

                t_of_n_sequential(threshold, n_parties, 0, &mut rng);
            }

            #[test]
            fn proptest_t_of_n_with_malicious(
                (n_parties, threshold, n_malicious) in (2usize..6).prop_flat_map(|n| (Just(n), 2usize..=n)).prop_flat_map(|(n, t)| (Just(n), Just(t), 0..=(n-t)))
            ) {
                let mut rng = TestRng::deterministic_rng(RngAlgorithm::ChaCha);

                t_of_n_sequential(threshold, n_parties, n_malicious, &mut rng);
            }
    }
}
