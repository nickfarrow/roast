#![feature(decl_macro)]

#[macro_use]
extern crate rocket;

use rocket::State;
use std::{error::Error, sync::Mutex};

#[post("/sign", data = "<nonce_set>")]
pub fn sign(signer_db: State<'_, Mutex<rocket::client::RoastClient>>, nonce_set: String) -> () {}

#[rocket::main]
async fn main() -> Result<(), Box<dyn Error>> {
    rocket::ignite()
        .manage(Mutex::new(rocket::client::RoastClient {}))
        .mount(
            "/",
            routes![
                sign,   //post
            ],
        )
        .launch();
    Ok(())
}
