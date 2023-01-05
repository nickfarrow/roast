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
        let mut rng1 = rand::thread_rng();
        let mut rng2 = rand::thread_rng();

        // Create each signer session and create an initial nonce
        let (mut signer1, nonce1) = signer::RoastSigner::new(
            &mut rng1,
            frost.clone(),
            frost_keys[0].clone(),
            0,
            secret_shares[0].clone(),
            message,
        );
        let (mut signer2, nonce2) = signer::RoastSigner::new(
            &mut rng2,
            frost,
            frost_keys[1].clone(),
            1,
            secret_shares[1].clone(),
            message,
        );

        // Begin with each signer sending a nonce to ROAST, marking these signers as responsive.
        let response = roast.receive(0, None, nonce1);
        assert!(response.nonce_set.is_none());
        assert!(response.combined_signature.is_none());

        let response2 = roast.receive(1, None, nonce2);
        assert!(response2.nonce_set.is_some());

        // Once ROAST receives the threshold number of nonces, it responds to the group of
        // responsive signers with a nonce set to the group of responsive signers.
        assert!(response2.recipients.contains(&0) && response2.recipients.contains(&1));
        let sign_session_nonces = response2.nonce_set.expect("roast responded with nonces");

        // The signer signs using this the nonces for this sign session,
        // and responds to ROAST with a signature share.
        let (sig_share2, nonce2) = signer2.sign(&mut rng2, sign_session_nonces.clone());
        let response = roast.receive(1, Some(sig_share2), nonce2);
        dbg!(
            &response.combined_signature.is_some(),
            &response.nonce_set.is_some()
        );
        assert!(response.combined_signature.is_none());

        // ROAST also sends the nonce set to the other signer, who also signs
        let (sig_share1, nonce1) = signer1.sign(&mut rng1, sign_session_nonces);

        let response = roast.receive(0, Some(sig_share1), nonce1);
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
    fn t_of_n_sequential(threshold: usize, n_parties: usize) {
        let frost = secp_frost::Frost::<Sha256, Deterministic<Sha256>>::default();
        let (secret_shares, frost_keys) = frost::frost_keygen(threshold, n_parties);

        let message = Message::plain("test", b"test");
        let roast = coordinator::Coordinator::new(frost.clone(), frost_keys[0].clone(), message);

        let mut rng = rand::thread_rng();
        // Create each signer session and create an initial nonce
        let (mut signers, mut nonces): (Vec<_>, Vec<_>) = frost_keys
            .into_iter()
            .zip(secret_shares)
            .enumerate()
            .map(|(i, (frost_key, secret_share))| {
                signer::RoastSigner::new(
                    &mut rng,
                    frost.clone(),
                    frost_key,
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
                    // If we have nonces, sign and send sig and a new nonce
                    Some(signing_nonces) => {
                        let (sig, nonce) = signers[signer_index].sign(&mut rng, signing_nonces);
                        (Some(sig), nonce)
                    }
                    // Otherwise, just create a new nonce
                    None => (
                        None,
                        signers[signer_index]
                            .new_nonce(&mut rng)
                            .public(),
                    ),
                };
                // Send signature and our next nonce to ROAST
                let response = roast.receive(signer_index, sig, new_nonce);
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

    proptest! {
            #[test]
            fn roast_proptest_t_of_n(
                (n_parties, threshold) in (2usize..5).prop_flat_map(|n| (Just(n), 2usize..=n))
            ) {
            t_of_n_sequential(threshold, n_parties);
        }
    }
}
