//! ROAST: Robust Asynchronous Schnorr Threshold Signatures
//! 
//! ## Description
//! 
//! This crate contains the core ROAST algorithm, used as a wrapper around a threshold signature
//! scheme in order to guarentee that t honest signers in a t-of-n multisignature can obtain a 
//! valid signature, regardless of the presence of absent or malicious signers.
//! 
//! > ⚠ At this stage this implementation is for API exploration purposes only. It has not been 
//! reviewed or vetted, and should be considered insecure for practical purposes.
//! 
//! Much of the communication and interaction between the signer and coordinator is missing,
//! including any asynchronicity (hopefully can be built around the existing core functions).
//! 
//! ## ROAST Summary
//! 
//! In order to sign a message, a ROAST coordinator will first request that each signer provide
//! a nonce. Upon receiving a threshold number of nonces, the coordinator will ask these t signers
//! to sign under that nonce set. Each responsive signer will send their signature share along with
//! a new nonce that will be used for future signing sessions.
//! 
//! Special care is taken to track responsive signers and malicious signers, ensuring we will 
//! eventually arrive upon a signature.
//! 
//! ## Usage Notes
//! 
//! In theory, each signer can also be a coordinator, allowing for symmetric design accross
//! participants of the multisignature - though this library has not yet been tested in this way.
//! 
//! Currently this ROAST implementation only works with *[secp256kfun FROST]*, but it should later
//! be made agnostic to which threshold signature scheme is used.
//! 
//! [secp256kfun FROST]: <https://docs.rs/schnorr_fun/latest/schnorr_fun/frost/index.html>


pub mod coordinator;
pub mod signer;

pub mod test_keygen;