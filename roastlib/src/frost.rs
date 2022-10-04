use secp256kfun::Scalar;

use schnorr_fun::{
    frost::{Frost, ScalarPoly, XOnlyFrostKey},
    nonce::Deterministic,
};

use schnorr_fun::Schnorr;
use sha2::Sha256;

pub fn frost_keygen(threshold: usize, n_parties: usize) -> (Vec<Scalar>, Vec<XOnlyFrostKey>) {
    let frost = Frost::new(Schnorr::<Sha256, Deterministic<Sha256>>::new(
        Deterministic::<Sha256>::default(),
    ));
    assert!(threshold <= n_parties);

    // create some scalar polynomial for each party
    let mut rng = rand::rngs::ThreadRng::default();
    let scalar_polys = (0..n_parties)
        .map(|_| ScalarPoly::random(threshold, &mut rng))
        .collect::<Vec<_>>();
    let point_polys = scalar_polys
        .iter()
        .map(ScalarPoly::to_point_poly)
        .collect::<Vec<_>>();
    let keygen = frost.new_keygen(point_polys).unwrap();
    let (shares, proofs_of_possesion): (Vec<_>, Vec<_>) = scalar_polys
        .into_iter()
        .map(|sp| frost.create_shares(&keygen, sp))
        .unzip();
    // collect the received shares for each party
    let received_shares = (0..n_parties)
        .map(|party_index| {
            (0..n_parties)
                .map(|share_index| shares[share_index][party_index].clone())
                .collect()
        })
        .collect::<Vec<Vec<_>>>();

    // finish keygen for each party
    let (secret_shares, frost_keys): (Vec<_>, Vec<_>) = (0..n_parties)
        .map(|party_index| {
            let (secret_share, frost_key) = frost
                .finish_keygen(
                    keygen.clone(),
                    party_index,
                    received_shares[party_index].clone(),
                    proofs_of_possesion.clone(),
                )
                .unwrap();

            let xonly_frost_key = frost_key.into_xonly_key();
            (secret_share, xonly_frost_key)
        })
        .unzip();

    (secret_shares, frost_keys)
}
