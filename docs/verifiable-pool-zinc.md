# Making Pool's server verifiable

## The problem

Pool is an OPRF: the client sends a blinded request, the server replies, and the client
unblinds to get `y = F(sk, x)`. The server never learns `x`, the client never learns `sk` —
and the client has **no way to check the answer**.

A dishonest server can return nonsense and the client cannot tell, because an OPRF output
looks random either way. Worse, it can use a **different key for each client**. Everyone
then lives on their own private function: clients who should agree on `F(sk, x)` do not, and
the server can tell which output came from which client. That is how a key server
deanonymises its users.

The fix is a *verifiable* OPRF, where each response comes with a proof saying *"I used the
one key I publicly committed to, and I followed the protocol."* Every deployed VOPRF is
Diffie-Hellman based, so none of them are post-quantum. This document describes how to get
one for Pool.

Pool's own messages and arithmetic do not change. We add commitments around them, a proof
on the response, and a check on the client.

## Two things we need first

**Commitments.** A commitment pins down a secret without revealing it. *Binding* means you
cannot later claim you committed to a different value; *hiding* means it leaks nothing. To
*open* a commitment is to reveal the value together with the random blinder used to build
it.

Ours is one line of arithmetic:

```
commit(value, blinder) = A * value + B * blinder  (mod q)
```

`A` and `B` are fixed public matrices, generated from a seed — one mixes in the value, the
other mixes in the blinder. Its modulus `q` is the commitment's own, chosen for SIS
security; it is not Pool's `Q`. Binding rests on a lattice problem (SIS), so it stays
post-quantum. The reason we pick it over a hash is that it is *linear*: only additions and
multiplications by public constants, which are the cheap operations. `BLAKE3(sk)` would cost
more to prove than everything else combined.

**A prover.** We describe the server's computation as an arithmetic circuit and prove it was
run correctly. Adding values is free; multiplying two secret values is what costs.
[Zinc](https://github.com/NethermindEth/zinc) ([eprint
2025/316](https://eprint.iacr.org/2025/316)) fits for two reasons: it is hash-based, so the
result stays post-quantum, and it works natively modulo any integer. Pool mixes `Q = 2^12`,
`P = 2^8` and `DELTA = 16` in a single expression, which other proof systems have to
simulate bit by bit.

Zinc is a research prototype: unaudited, with no published end-to-end performance numbers.
Anything built on it should sit behind a feature flag and stay off the default build path
until that changes.

## The design

Three commitments and one proof.

### The key

The server commits to `sk` once and publishes it. Every client checks against that same
value, which is what makes "one key for everyone" verifiable.

### The masks

During preprocessing the two sides run oblivious transfers. For each of the `N` = 482 key
bits the
**client** holds two masks, `r0[i]` and `r1[i]` — these are `r_seeds[i][0]` and
`r_seeds[i][1]` in `preprocessing.rs`. The **server** picks a secret bit `b[i]` and receives
exactly one of them, learning nothing about the other. It then returns

```
bhat[i] = b[i] ^ sk[i]
```

which is safe to send because `b[i]` is secret.

Those masks feed straight into the response, so the proof has to pin them down. The obvious
move — let the server commit to the mask it holds — **fails**: nothing stops it committing
to a value it invented. The proof would still verify, but the answer would be `F(sk, x)` plus
a constant of the server's choosing, different for each client. Key inconsistency again,
wearing a different hat.

So the **client** commits instead. Before the transfer it publishes two commitments per
index, and the transfer hands over the blinder along with the mask:

```
D0[i] = commit(r0[i], blinder0[i])
D1[i] = commit(r1[i], blinder1[i])
```

Both sides now know both commitments — they are hiding, so the server learns nothing from
them — and the server holds exactly one blinder. The proof then shows its mask opens the
right one. Since `b[i]` is a bit, picking between them is a branchless select:

```
expected[i] = D0[i] + b[i] * (D1[i] - D0[i])
```

`D0` and `D1` are public, so that is one multiplication per bit. The server cannot invent a
mask, because it has to open a commitment the *client* made.

### The pads

A second round of transfers gives the client one pad per evaluation, from a set the server
generates. Same trick in reverse: the server commits to all the pads up front and the
transfer carries the opening, so the client checks its own pad itself. This one needs no
proof at all.

## What the proof shows

Public: the three commitments, the masked key bits `bhat`, the request and the response.
Secret: `sk`, the server's bits `b`, the masks and pads with their blinders, and the
intermediate values of the evaluation.

The server proves:

1. `sk` is a vector of bits, and it opens the key commitment;
2. `bhat[i] == b[i] ^ sk[i]` for every `i`;
3. each mask opens `expected[i]`, and the pads open their commitment;
4. the blinded inner product was computed as in `blind_eval_evaluation`
   (`pool-oprf/src/online.rs:352`);
5. the response is that value rounded and padded, as in `round_zq_to_zp`
   (`pool-prf/src/round.rs:8`).

Claim 5 dominates the cost. The rounding is round-to-nearest with ties down, not truncation,
so each of the `OUTPUT_ELEMENTS` = 16 output elements needs a comparison and a wrap.

## Why it holds

Two attacks matter, and each is blocked by a different part of the design.

**Swapping the key.** The server picks a second key `sk2` and sends `bhat = b ^ sk2`, hoping
the client will unblind under `sk2` without noticing.

Why it cannot: the client's request carries *both* masks, `e = a + r0 + r1`
(`pool-oprf/src/online.rs:261`), and the correction the client subtracts at the end is
`sum of r[bhat[i]]` (`:262`), which depends only on the public `bhat`. So the server's
contribution comes out right for exactly one branch per index — the one at
`bhat[i] ^ sk[i]`.

That is the branch the proof pins. `sk` is fixed by its commitment and `bhat` is public, so
claim 2 leaves the server no choice of `b`, and claim 3 makes it open that branch's
commitment. Both outcomes are safe: either it holds that branch, and the answer is
`F(sk, x)` under the committed key, or it does not, and the proof fails and the client
aborts.

Note this needs nothing from the OT beyond what Pool already assumes. The binding comes from
the key commitment, not from the server's ignorance of the other mask.

**Faking masks or pads.** Blocked by binding: the masks open commitments the client made,
and the client checks its own pad directly.

## What this does not fix

**The client is still untrusted.** A malicious client can recover the server's key by
choosing its requests carefully. Nothing here changes that — this work covers the server
only.

**Input privacy still rests on semi-honest OT.** Since the request is `e = a + r0 + r1`, a
server that learned *both* masks could recover `a` and go after the client's input. Pool
already assumes it does not; this work neither strengthens nor weakens that.

## Open questions

| question | why it matters |
|---|---|
| Cost of committing to masks | Today one 16-byte seed per index expands into masks for many slots. Committing to the expanded masks loses that compression; committing to the seed instead would put BLAKE3 in the circuit, which is worse. |
| Rounding constraint count | If the range checks need full bit decomposition, the circuit roughly doubles. |
