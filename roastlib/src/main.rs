use roast::coordinator;
use roast::frost;
use roast::signer;
use schnorr_fun::frost as secp_frost;
use schnorr_fun::nonce::Deterministic;
use schnorr_fun::Message;
use sha2::Sha256;

fn main() {
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

    // Begin with each signer sending a nonce to ROAST
    let (combined_signature, nonce_set) = roast.process(0, None, nonce1);
    assert!(nonce_set.is_none());
    assert!(combined_signature.is_none());

    let (_combined_signature, nonce_set) = roast.process(1, None, nonce2);
    assert!(nonce_set.is_some());

    // Once ROAST receives the threshold number of nonces, it responds with a nonce set
    let sign_session_nonces = nonce_set.expect("roast responded with nonces");

    // The signer signs using this nonce set and response with a signature share
    let (sig_share2, nonce2) = signer2.sign(sign_session_nonces.clone());
    let (combined_signature, nonce_set) = roast.process(1, Some(sig_share2), nonce2);
    dbg!(&combined_signature.is_some(), &nonce_set.is_some());
    assert!(combined_signature.is_none());

    // ROAST also sends the nonce set to the other signer, who also signs
    let (sig_share1, nonce1) = signer1.sign(sign_session_nonces);

    let (combined_signature, nonce_set) = roast.process(0, Some(sig_share1), nonce1);
    dbg!(&combined_signature.is_some(), &nonce_set.is_some());
    assert!(combined_signature.is_some());

    // Once the threshold number of signature shares have been received,
    // ROAST combines the signature shares into the aggregate signature
    dbg!(combined_signature);
}
