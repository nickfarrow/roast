use roast::frost;
use roast::roast_coordinator;
use roast::roast_signer;
use schnorr_fun::frost::Frost;
use schnorr_fun::nonce::Deterministic;
use schnorr_fun::Message;
use schnorr_fun::Schnorr;
use sha2::Sha256;

pub fn main() {
    // Do a frost keygen
    let (secret_shares, frost_keys) = frost::frost_keygen(3, 5);

    let frost = Frost::<Sha256, Deterministic<Sha256>>::default();

    let message = Message::plain("10 000 emails", b"");
    // Create a roast server
    roast_coordinator::RoastServer::new(frost, frost_keys[0].clone(), message);
}
