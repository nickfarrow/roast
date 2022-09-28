Experimental
-> unfishished and not ready for use

## todo
Make agnostic to the threshold signature scheme that is used


## ROAST Paper Notes
[paper](https://eprint.iacr.org/2022/550.pdf)

Roast is a simple wrapper that turns a given threshold signature scheme into a scheme with a robust and asynchronous signing protocol, as long as the underlying signing protocol is semi-interactive (i.e. has one preprocessing round and one actual signing round), proviceds identifiable aborts, and is unforgable under concurrent signing sessions.


Robustness is the guarentee that t honest signers are able to obtain a valid signature even in the presence of other malicious signers who try to disrupt the protocol. 


FROST provides identifiable aborts (IA): if signing session fails, then honest signers can identify at least one malicious signer responsible for the failure.

We cant run every combination of signers n choose t, too computationally expensive -> ROAST tackles this problem. 
>an algorithmic approach to choosing signer sets based on past behaviour?




### Security of Threshold Signatures

Identifiable aborts:
 - Ensures that ShareVal reliably identifies disruptive signers who send wrong shares. The IA-CMA (identifiable abort, chosen message attack) game: A controls all but one signer and can ask the remaining honest signer to take part in arbitrary number of concurrent sign sessions. Wins if the malicious signers all submit presignature or signature shares that somehow pass validation but lead to an output of an invalid signature (break of accountability). Or A wins if the honest signer outputs a presignatures and signature shares that will not pass validation.


Unforgability: a threshold signature scheme is existentially unforgable under CMA and concurrent sessions if no adversary A which controls t-1 signers during keygen and signing and can ask the remaining n-t+1 honest signers to take part in arbitrarily many concurrent signing sessions on messages of its choice,

-> ie.e for every honest signer, A has oracles simulating PreRound(PK) and SignRound(sk_i, PK, State_i_sid) on an already preprocessed but unfinished session sid of its choice.can 

can produce a valid signature on a message that was never used in a signing session and A never asked in any query round.

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

The coordinators task is to maintain a set of responsive signers who have responded to all previous signing requests. As soon as R contains  t, C initiates a new signing session.

Along with each signature share, each signer is also required to provide a fresh presignature share (nonce) in preparation for a poosible next signing session. "A pipeline of signing sessions"


### Eliminating the Trusted Coordinator
A simple method to eliminate the need for semi-strusted coordinator is to let the signers run enough instances of the coordinator process: the n signers choose among themselves any set n-t+1 coordinators and start s-t+1 concurrent runs of roast. Note that one of these sessions will have t honest signers.

The concurrent runs of ROAST do not need to be started simultaneously - e.g. honest signers can resend their reply in the run with coorinator_2 only after d seconds and only if they have not obtained a valid signature from any other run (is that a concern?)

