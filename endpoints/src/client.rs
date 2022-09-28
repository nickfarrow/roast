#![feature(decl_macro)]

#[macro_use]
extern crate rocket;
use roast_signer::client::RoastClient;
use roast_signer::frost;

use rocket::State;
use schnorr_fun::{
    frost::{Frost, XOnlyFrostKey},
    nonce::Deterministic,
    Message, Schnorr,
};
use secp256kfun::Scalar;
use sha2::Sha256;
use std::{error::Error, sync::Mutex};

#[get("/sign?<nonce_set>")]
pub fn sign<'a>(
    signer_db: &State<Mutex<RoastClient<'a, Sha256, Deterministic<Sha256>>>>,
    nonce_set: String,
) -> () {
}

#[rocket::main]
// Here we need to spawn n_parties of rockets under different ports and launch?
async fn main() -> Result<(), Box<dyn Error>> {
    let message = Message::plain("test", b"test");
    let (secret_shares, frost_keys) = frost::frost_keygen(3, 5);
    frost_keys
        .iter()
        .zip(secret_shares)
        .enumerate()
        .map(|(i, (frost_key, secret_share))| {
            create_roast_client(frost_key.clone(), i, secret_share, [0].as_slice(), message)
        });
    Ok(())
}

fn create_roast_client<'a>(
    frost_key: XOnlyFrostKey,
    my_index: usize,
    secret_share: Scalar,
    initial_nonce_sid: &[u8],
    message: Message<'a>,
) -> Result<(), Box<dyn Error>> {
    rocket::build()
        .manage(Mutex::new(RoastClient::start(
            "127.0.0.1:510".to_string(),
            Frost::new(Schnorr::<Sha256, Deterministic<Sha256>>::new(
                Deterministic::<Sha256>::default(),
            )),
            frost_key,
            my_index,
            secret_share,
            initial_nonce_sid,
            message,
        )))
        .mount(
            "/",
            routes![
            sign,   //post
        ],
        )
        .launch();
    Ok(())
}
