#![feature(decl_macro)]

#[macro_use]
extern crate rocket;

use roast::coordinator::RoastServer;
use rocket::{Rocket, State};
use schnorr_fun::musig::Nonce;
use std::{error::Error, sync::Mutex};

use schnorr_fun::frost::Frost;
use schnorr_fun::nonce::Deterministic;
use schnorr_fun::{Message, Schnorr};
use sha2::Sha256;

// Also have optional message here
#[get("/init?<frost_key>")]
pub fn init(roast_db: &State<Mutex<RoastServer<Sha256, Sha256>>>, frost_key: String) {
    let mut roast_state = roast_db.lock().expect("got lock");
    roast_state.frost_key = serde_json::from_str(&frost_key).expect("read frost key ok");
}

#[get("/receive_signature?<sig>&<nonce>&<index>")]
pub async fn receive_signature(
    roast_db: &State<RoastServer<'_, Sha256, Sha256>>,
    sig: Option<String>,
    nonce: String,
    index: usize,
) -> String {
    let roast_state = roast_db; //.lock().expect("got lock");
    let submitted_sig = match sig {
        Some(str) => Some(serde_json::from_str(&str).expect("valid sig str")),
        None => None,
    };
    let submitted_nonce = serde_json::from_str(&nonce).expect("valid nonce str");
    // let submitted_nonce = match nonce {
    //     Some(str) => Some(serde_json::from_str(&str).expect("valid nonce str")),
    //     None => None,
    // };
    roast_state
        .receive_signature(index, submitted_sig, submitted_nonce)
        .await;

    format!("done")
}

#[rocket::main]
pub async fn main() -> () {
    let res = rocket::build()
        .manage(Mutex::new(RoastServer::new(
            Frost::new(Schnorr::<Sha256, Deterministic<Sha256>>::new(
                Deterministic::<Sha256>::default(),
            )),
            None,
            Message::plain("test", b"test"),
        )))
        .mount("/", routes![receive_signature])
        .launch()
        .await;
    ()
}

//     let frost = Frost::<Sha256, Deterministic<Sha256>>::default();

//     let message = Message::plain("10 000 emails", b"");
//     // Create a roast server
//     let roast_coordinator =
//         roast_coordinator::RoastServer::new(frost.clone(), frost_keys[0].clone(), message);

// let roast_signer1 = roast_signer::RoastClient::start(
//     roast_coordinator,
//     frost.clone(),
//     frost_keys[0].clone(),
//     0,
//     secret_shares[0].clone(),
//     [0].as_slice(),
//     message,
// )
// .await;

// let roast_signer1.

// We need to somehow set some general methods of communication for roast signers and clients
// Rocket API probably not the most basic? Would be cool...
//

// let roast_signer2 = roast_signer::RoastClient::start(
//     roast_coordinator,
//     frost.clone(),
//     frost_keys[0].clone(),
//     0,
//     secret_shares[0].clone(),
//     [0].as_slice(),
//     message,
// );



// OLD HTTP TRASH
//
//
// HTTP call roast_server receive
// let (combined_sig, nonce_set) =
// let request_url = roast_server.clone()
//     + "/init?"
//     + &serde_json::to_string(&frost_key).expect("valid serialization");
// let response = reqwest::get(&request_url).await.expect("valid request");
// dbg!(response);

// roast_server
//     .receive_signature(my_index, None, initial_nonce.public)
//     .await;

// match combined_sig {
//     Some(_) => {
//         println!("got combined sig!");
//     }
//     None => {
//         // println!("Sent partial signature {} to roast..", i)
//     }
// };
// match nonce_set {
//     Some(nonces) => {
//         println!("Got nonces {:?}", nonces);
//     }
//     None => println!("No new nonces!?"),
// };

// let mut my_nonces = HashMap::new();
// my_nonces.insert(0 as usize, initial_nonce);

// pub async fn sign
