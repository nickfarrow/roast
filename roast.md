Roast is a simple wrapper that turns a given threshold signature scheme into a scheme with a robust and asynchronous signing protocol, as long as the underlying signing protocol is semi-interactive (i.e. has one preprocessing round and one actual signing round), proviceds identifiable aborts, and is unforgable under concurrent signing sessions.


Robustness is the guarentee that t honest signers are able to obtain a valid signature even in the presence of other malicious signers who try to disrupt the protocol. 


FROST provides identifiable aborts (IA): if signing session fails, then honest signers can identify at least one malicious signer responsible for the failure.

We cant run every combination of signers n choose t, too computationally expensive -> ROAST tackles this problem. 
>an algorithmic approach to choosing signer sets based on past behaviour?




Security of Threshold Signatures

Identifiable aborts:
 - Ensures that ShareVal reliably identifies disruptive signers who send wrong shares. The IA-CMA (identifiable abort, chosen message attack) game: A controls all but one signer and can ask the remaining honest signer to take part in arbitrary number of concurrent sign sessions. Wins if the malicious signers all submit presignature or signature shares that somehow pass validation but lead to an output of an invalid signature (break of accountability). Or A wins if the honest signer outputs a presignatures and signature shares that will not pass validation.


Unforgability: a threshold signature scheme is existentially unforgable under CMA and concurrent sessions if no adversary A which controls t-1 signers during keygen and signing and can ask the remaining n-t+1 honest signers to take part in arbitrarily many concurrent signing sessions on messages of its choice,

-> ie.e for every honest signer, A has oracles simulating PreRound(PK) and SignRound(sk_i, PK, State_i_sid) on an already preprocessed but unfinished session sid of its choice.can 

can produce a valid signature on a message that was never used in a signing session and A never asked in any query round.

FROST3 -> PreAgg (nonce agg) -> Aggregate two presignature products D=prod(d_i), and E=prod(e_i) for i in T. Whereas FROST2 the aggregated presignature is not really aggregated, just the set {(D_i, E_i) for i in T}. The SignRound algorightm takes care of computing the products, as before. Other FROST versions include 2-BTZ and 2-CKM.

FROSTLAND
A majority of t of 15 council members is needed to sign a bill for it to pass.

Each counci member has its own twatermark and a bill is only vaild if it carries the watermarks of all signers (and no others).

Find a majority of council members, use thier watermarks to create the paper, then collect their signatures. However if one of them fail to sign at the final step, then the process talls. It is not possible to ask anyone else since the watermark on the page corresponds to the disruptive signer. So we must start the signing process from scratch.



The signing process is 