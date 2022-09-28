use roast::client;
use roast::coordinator;
use roast::frost;
use schnorr_fun::frost as secp_frost;
use schnorr_fun::nonce::Deterministic;
use schnorr_fun::Message;
use sha2::Sha256;

fn main() {
    let frost = secp_frost::Frost::<Sha256, Deterministic<Sha256>>::default();
    let (secret_shares, frost_keys) = frost::frost_keygen(5, 10);

    let message = Message::plain("test", b"test");
    let roast = coordinator::Coordinator::new(frost.clone(), frost_keys[0].clone(), message);

    let client1 = client::RoastClient::new(
        frost,
        frost_keys[0].clone(),
        0,
        secret_shares[0].clone(),
        [0].as_slice(),
        message,
    );

    let (sig, nonce) = client1.start();
    roast.receive_signature(0, sig, nonce);
}
