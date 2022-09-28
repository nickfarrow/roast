use std::{collections::HashMap, hash::Hash};

use secp256kfun::{digest::typenum::U32, marker::Public, Scalar};

use schnorr_fun::{
    frost::{Frost, XOnlyFrostKey},
    musig::{Nonce, NonceKeyPair},
    nonce::NonceGen,
    Message,
};
use sha2::Digest;

use roast_coordinator;

pub struct RoastClient<'a, H, NG> {
    roast_server: RoastServer<'a, H, NG>,
    frost: Frost<H, NG>,
    frost_key: XOnlyFrostKey,
    my_index: usize,
    secret_share: Scalar,
    message: Message<'a, Public>,
    my_nonces: Vec<NonceKeyPair>,
}

impl<'a, H: Digest + Clone + Digest<OutputSize = U32>, NG: NonceGen> RoastClient<'a, H, NG> {
    pub async fn start(
        roast_server: RoastServer<'a, H, NG>,
        frost: Frost<H, NG>,
        frost_key: XOnlyFrostKey,
        my_index: usize,
        secret_share: Scalar,
        initial_nonce_sid: &[u8],
        message: Message<'a>,
    ) -> RoastClient<'a, H, NG> {
        let initial_nonce = frost.gen_nonce(
            &secret_share,
            &initial_nonce_sid,
            Some(frost_key.public_key().normalize()),
            Some(message),
        );

        let (combined_sig, nonce_set) = roast_server
            .receive_signature(my_index, None, initial_nonce.public)
            .await;

        match combined_sig {
            Some(_) => {
                println!("got combined sig!");
            }
            None => {
                // println!("Sent partial signature {} to roast..", i)
            }
        };
        match nonce_set {
            Some(nonces) => {
                println!("Got nonces {:?}", nonces);
            }
            None => println!("No new nonces!?"),
        };

        // let mut my_nonces = HashMap::new();
        // my_nonces.insert(0 as usize, initial_nonce);
        let my_nonces = vec![initial_nonce];

        RoastClient {
            roast_server,
            frost,
            frost_key,
            my_index,
            secret_share,
            message,
            my_nonces,
        }
    }

    fn new_nonce(&self, sid: &[u8]) -> NonceKeyPair {
        self.frost.gen_nonce(
            &self.secret_share,
            sid,
            Some(self.frost_key.public_key().normalize()),
            Some(self.message),
        )
    }

    pub async fn sign(&mut self, nonce_set: Vec<(usize, Nonce)>) {
        let session = self.frost.start_sign_session(
            &self.frost_key,
            nonce_set,
            Message::plain("test", b"test"),
        );
        let my_nonce = self
            .my_nonces
            .pop()
            .expect("some nonce available to use for signing");
        let sig = self.frost.sign(
            &self.frost_key,
            &session,
            self.my_index,
            &self.secret_share,
            my_nonce,
        );
        // call server with (sig, self.new_nonce())

        self.my_nonces.push(self.new_nonce(&[0]));

        let (combined_sig, nonce_set) = self
            .roast_server
            .receive_signature(
                self.my_index,
                Some(sig),
                self.my_nonces.last().expect("some nonce").public(),
            )
            .await;

        match combined_sig {
            Some(_) => {
                println!("got combined sig!");
            }
            None => {
                // println!("Sent partial signature {} to roast..", i)
            }
        };
        match nonce_set {
            Some(nonces) => {
                println!("Got nonces {:?}", nonces);
            }
            None => println!("No new nonces!?"),
        };
    }
}
