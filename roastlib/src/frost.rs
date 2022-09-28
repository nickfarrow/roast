use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
};

use secp256kfun::{rand_core::RngCore, Scalar};

use schnorr_fun::{
    frost::{Frost, PointPoly, ScalarPoly, XOnlyFrostKey},
    nonce::Deterministic,
};

use schnorr_fun::Schnorr;
use sha2::Sha256;

pub fn frost_keygen(threshold: usize, n_parties: usize) -> (Vec<Scalar>, Vec<XOnlyFrostKey>) {
    let frost = Frost::new(Schnorr::<Sha256, Deterministic<Sha256>>::new(
        Deterministic::<Sha256>::default(),
    ));
    dbg!(threshold, n_parties);
    assert!(threshold <= n_parties);

    // create some scalar polynomial for each party
    let mut scalar_polys = vec![];
    for i in 1..=n_parties {
        println!("Creating scalar poly {}", i);
        let scalar_poly = (1..=threshold)
            .map(|_| {
                let mut rng: rand::rngs::StdRng = rand::SeedableRng::from_entropy();
                Scalar::from(rng.next_u32())
                    .non_zero()
                    .expect("computationally unreachable")
            })
            .collect();
        scalar_polys.push(ScalarPoly::new(scalar_poly));
    }
    let point_polys: Vec<PointPoly> = scalar_polys.iter().map(|sp| sp.to_point_poly()).collect();

    let keygen = frost.new_keygen(point_polys).unwrap();

    let mut proofs_of_possession = vec![];
    let mut shares_vec = vec![];
    for (i, sp) in scalar_polys.into_iter().enumerate() {
        println!("calculating shares and pop {}", i);
        let (shares, pop) = frost.create_shares(&keygen, sp);
        proofs_of_possession.push(pop);
        shares_vec.push(shares);
    }
    println!("Calculated shares and pops");

    // collect the recieved shares for each party
    let mut recieved_shares: Vec<Vec<_>> = vec![];
    for party_index in 0..n_parties {
        println!("Collecting shares for {}", party_index);
        recieved_shares.push(vec![]);
        for share_index in 0..n_parties {
            recieved_shares[party_index].push(shares_vec[share_index][party_index].clone());
        }
    }

    println!("{:?}", recieved_shares);

    // finish keygen for each party
    let (secret_shares, frost_keys): (Vec<Scalar>, Vec<XOnlyFrostKey>) = (0..n_parties)
        .map(|i| {
            println!("Finishing keygen for participant {}", i);
            std::thread::sleep(std::time::Duration::from_secs(1));
            let (secret_share, frost_key) = frost
                .finish_keygen(
                    keygen.clone(),
                    i,
                    recieved_shares[i].clone(),
                    proofs_of_possession.clone(),
                )
                .expect("collected shares");
            println!("got secret share");
            let xonly_frost_key = frost_key.into_xonly_key();
            (secret_share, xonly_frost_key)
        })
        .unzip();
    println!("Finished keygen!");

    (secret_shares, frost_keys)
}
