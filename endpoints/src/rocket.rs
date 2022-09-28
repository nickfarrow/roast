#![feature(decl_macro)]

#[macro_use]
extern crate rocket;

use rocket::State;
use rocket_contrib::json::Json;
use std::collections::BTreeMap;
use std::{error::Error, sync::Mutex};

use schnorr_fun::frost::Nonce;
use schnorr_fun::{frost::PointPoly, fun::Scalar, Signature};

#[derive(Debug)]
pub struct RoastDatabase {}

// #[derive(Serialize, Deserialize, Clone)]
// pub struct Response<'a, T> {
//     data: T,
//     message: &'a str,
// }

#[post("/submit_signature", data = "<signature>")]
pub fn send_signature(roast_db: State<'_, Mutex<RoastDatabase>>, signature: String) -> () {}

fn main() -> Result<(), Box<dyn Error>> {
    rocket::ignite()
        .manage(Mutex::new(RoastDatabase {}))
        .mount(
            "/",
            routes![
                send_signature,   //post
            ],
        )
        .launch();
    Ok(())
}
