## ROAST: Robust Asychronous Schnorr Threshold Signatures

**Run FROST multisignatures in asynchronous environments and always arrive at a signature provided a threshold number of honest signers.**

This implementation was primarily built for [secp256kfun frost](https://github.com/LLFourn/secp256kfun/blob/master/schnorr_fun/src/frost.rs), however it has been designed to be agnostic as to the choice of threshold signature scheme used within the ROAST wrapper.

## Unfishished and not ready for use

Click [here to get an idea for how this roast wrapper can be used](https://github.com/nickfarrow/roast/blob/master/src/main.rs)

[roast paper](https://eprint.iacr.org/2022/550.pdf)

## To Do

- [ ] Create asycnronous tests involving coordinators and signers using new architecture, then use them to communicate a test session and perhaps a proptest.

## excerpt

```
let frost = secp_frost::Frost::<Sha256, Deterministic<Sha256>>::default();
let mut rng = rand::thread_rng();

let (frost_key, secret_shares) = frost.simulate_keygen(2, 3, &mut rng);
let xonly_frost_key = frost_key.into_xonly_key();

let message = Message::plain("test", b"test");
let roast =
coordinator::Coordinator::new(frost.clone(), xonly_frost_key.clone(), message, 2, 3);

// Create each signer session and create an initial nonce
let (mut signer1, nonce1) = signer::RoastSigner::new(
&mut rng,
frost.clone(),
xonly_frost_key.clone(),
0,
secret_shares[0].clone(),
message,
);
let (mut signer2, nonce2) = signer::RoastSigner::new(
&mut rng,
frost,
xonly_frost_key.clone(),
1,
secret_shares[1].clone(),
message,
);

// Begin with each signer sending a nonce to ROAST, marking these signers as responsive.
let response = roast.receive(0, None, nonce1).unwrap();
assert!(response.nonce_set.is_none());
assert!(response.combined_signature.is_none());

let response2 = roast.receive(1, None, nonce2).unwrap();
assert!(response2.nonce_set.is_some());

// Once ROAST receives the threshold number of nonces, it responds to the group of
// responsive signers with a nonce set to the group of responsive signers.
assert!(response2.recipients.contains(&0) && response2.recipients.contains(&1));
let sign_session_nonces = response2.nonce_set.expect("roast responded with nonces");

// The signer signs using this the nonces for this sign session,
// and responds to ROAST with a signature share.
let (sig_share2, nonce2) = signer2.sign(&mut rng, sign_session_nonces.clone());
let response = roast.receive(1, Some(sig_share2), nonce2).unwrap();
dbg!(
&response.combined_signature.is_some(),
&response.nonce_set.is_some()
);
assert!(response.combined_signature.is_none());

// ROAST also sends the nonce set to the other signer, who also signs
let (sig_share1, nonce1) = signer1.sign(&mut rng, sign_session_nonces);

let response = roast.receive(0, Some(sig_share1), nonce1).unwrap();
dbg!(
&response.combined_signature.is_some(),
&response.nonce_set.is_some()
);
assert!(response.combined_signature.is_some());

// Once the threshold number of signature shares have been received,
// ROAST combines the signature shares into the aggregate signature
dbg!(response.combined_signature);
```

## ROAST Paper Notes

[roast paper](https://eprint.iacr.org/2022/550.pdf)

Roast is a simple wrapper that turns a given threshold signature scheme into a scheme with a robust and asynchronous signing protocol, as long as the underlying signing protocol is semi-interactive (i.e. has one preprocessing round and one actual signing round), proviceds identifiable aborts, and is unforgable under concurrent signing sessions.

Robustness is the guarentee that t honest signers are able to obtain a valid signature even in the presence of other malicious signers who try to disrupt the protocol.

FROST provides identifiable aborts (IA): if signing session fails, then honest signers can identify at least one malicious signer responsible for the failure.

We cant run every combination of signers n choose t, too computationally expensive -> ROAST tackles this problem.

> an algorithmic approach to choosing signer sets based on past behaviour?

### Security of Threshold Signatures

Identifiable aborts:

- Ensures that ShareVal reliably identifies disruptive signers who send wrong shares. The IA-CMA (identifiable abort, chosen message attack) game: A controls all but one signer and can ask the remaining honest signer to take part in arbitrary number of concurrent sign sessions. Wins if the malicious signers all submit presignature or signature shares that somehow pass validation but lead to an output of an invalid signature (break of accountability). Or A wins if the honest signer outputs a presignatures and signature shares that will not pass validation.

Unforgability: a threshold signature scheme is existentially unforgable under CMA and concurrent sessions if no adversary A which controls t-1 signers during keygen and signing and can ask the remaining n-t+1 honest signers to take part in arbitrarily many concurrent signing sessions on messages of its choice,

-> ie.e for every honest signer, A has oracles simulating PreRound(PK) and SignRound(sk_i, PK, State_i_sid) on an already preprocessed but unfinished session sid of its choice.can

can produce a valid signature on a message that was never used in a signing session and A never asked in any query round.

#### Nonce aggregation

A semi-interactive threshold signature scheme is aggregatable if |p| and |sigma| are constant in parameters n and t, for p <- PreAgg(PK, {t_i}\_i_in_T), sigma <- SignAgg(PK, p, {sigma_i}\_i_in_T) and all inputs PK and m.

The aggregation of these elements is important for practical purposes as it reduces the size of the final signature as well as the amount of data that needs to be breadcast during signing.

In each of the signing rounds, a coordinator node will be one of the ssigners and can collect the contributions from all signers, aggregate them, and broadcast only the aggregate output back to signers.

> Doesn't seem super important

FROST3 -> PreAgg (nonce agg) -> Aggregate two presignature products D=prod(d_i), and E=prod(e_i) for i in T. Whereas FROST2 the aggregated presignature is not really aggregated, just the set {(D_i, E_i) for i in T}. The SignRound algorightm takes care of computing the products, as before. Other FROST versions include 2-BTZ and 2-CKM.

### FROSTLAND

A majority of t of 15 council members is needed to sign a bill for it to pass.

Each counci member has its own twatermark and a bill is only vaild if it carries the watermarks of all signers (and no others).

Find a majority of council members, use thier watermarks to create the paper, then collect their signatures. However if one of them fail to sign at the final step, then the process talls. It is not possible to ask anyone else since the watermark on the page corresponds to the disruptive signer. So we must start the signing process from scratch.

From time to time, members try to disrupt the signing process in an attempt to prevent other members from passing the bill and refuse to sign even though they indicated support.

The solution process is the following procedure:
In the beginning, all the council members that signal support for the bill are asked to gather. The secretary maintains a slist of all these members and whenever there are at least 9 members on the list, they call a group of 9 members to their office and strikes out their names on the list.

He then obtains paper with the watermarks of those 9 members, writes a copy of the bill and askes them each to sign. Whenever a council member has completed signing the copy they leave the office and the secretary adds their name back to the list.

If at least 9 council members behave honestly then they will eventually sign their assigned copy and be readded to the list. WIll this procedure we know that these 9 members will be on the list at some point in the future and so the signing procedure will not get stuck. Since members are assigned a new copy each time, a member can at most hold up the singing of at most one copy at a time. The naximum n-t 1= 15-9 = 6 disruptive council members can hold up 6 copies at most.

### Robust Asychronous Threshold Signatures

The coordinators task is to maintain a set of responsive signers who have responded to all previous signing requests. As soon as R contains t, C initiates a new signing session.

Along with each signature share, each signer is also required to provide a fresh presignature share (nonce) in preparation for a poosible next signing session. "A pipeline of signing sessions"

### Eliminating the Trusted Coordinator

A simple method to eliminate the need for semi-strusted coordinator is to let the signers run enough instances of the coordinator process: the n signers choose among themselves any set n-t+1 coordinators and start s-t+1 concurrent runs of roast. Note that one of these sessions will have t honest signers.

The concurrent runs of ROAST do not need to be started simultaneously - e.g. honest signers can resend their reply in the run with coorinator_2 only after d seconds and only if they have not obtained a valid signature from any other run (is that a concern? Yes excessive computation and communication.)

![image](https://user-images.githubusercontent.com/24557779/192925900-3c15cddf-a467-47be-80a5-3b04b0acbd47.png)
