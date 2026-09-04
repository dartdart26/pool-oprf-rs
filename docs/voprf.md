# Making Pool verifiable: what the server has to prove

Status: design note for review. Nothing here is implemented.

Scope: turn the Pool OPRF (Figures 3 and 4 of `docs/paper.txt`, code in
`pool-oprf`) into a *verifiable* OPRF by having the server prove to the client
that its response is the correct one for a committed key. Everything else stays
as it is: privacy of the client's input is still only against a semi-honest
server, pseudorandomness is still only against a semi-honest client, and the OT
from CryProt stays semi-honest. This is the "server zero-knowledge proofs" the
paper calls "much simpler" than the client-side ones (Section 4, "Achieving
malicious security").

Contents:

1. What "verifiable" buys us, and the exact threat model.
2. The protocol in the notation used below, matched to the code.
3. What has to be proven: the relation, why each part is there, what is *not*
   proven.
4. Do we need zero-knowledge, or just a proof? (Zero-knowledge. Argument in 4.)
5. Zinc and Zinc+: not zero-knowledge, unusable as-is.
6. Other proof systems that fit, and a recommendation.
7. Protocol changes, message sizes, cost estimates.
8. Open questions for review.

---

## 1. Goal and threat model

A VOPRF adds a public key `pk` that commits the server to its key `sk`, and a
guarantee for the client: **if `Finalize` outputs `z ≠ ⊥`, then
`z = F_sk(t, x)` for the `sk` committed in `pk`.** That is the verifiability
experiment of Albrecht–Gür (ASIACRYPT'24, Def. 11, Fig. 1b, adopted from
ADDG24), and the "uniqueness" notion POUNIQ of Tyagi et al. (EUROCRYPT'22): a
server cannot make a client accept two different outputs for the same
`(pk, t, x)`, and cannot make it accept an output under a key other than the
committed one.

Verifiability is, by definition, a property against a server that *deviates*:
a server that follows the protocol always returns the right thing, so there is
nothing to verify. The model I propose is the usual VOPRF split:

| property                    | adversary                                     | change |
| --------------------------- | --------------------------------------------- | ------ |
| verifiability (new)         | server may deviate arbitrarily, in preprocessing and online | new |
| client input privacy        | semi-honest server (POPRIV1, Thm 5.3)         | none   |
| pseudorandomness            | semi-honest client (SH-PPOPRF, Thm 5.2)       | none, but the proof must now be simulated (Section 4) |
| key privacy vs. client      | semi-honest client                            | none   |

Concretely this rules out: a server answering with garbage, answering with a
different key than `pk` (per-client keys, the Privacy Pass linkability attack),
using the wrong preprocessing state, or mixing up slots. It does not try to
protect the client's `x` against a server that cheats in the OT (a malicious
IKNP receiver can learn both OT messages, hence `a = RO(t, x)`), and it does
not protect `sk` against a malicious client. Both would need malicious OT,
extractable commitments and client-side proofs of `a = RO(t, x)`, which the
paper leaves as future work and which the user asked to leave out.

One consequence worth stating: verifiability holds **without relying on the OT
being maliciously secure**. The proof binds the server to values the client
knows from its own side of the OT (see Section 3.3), so the OT is only trusted
for privacy, as today.

## 2. The protocol as implemented

Per row (the paper's single-row protocol; one evaluation is `H_ROWS = 16` rows,
each spending one preprocessing slot `ctr`). Parameters: `n = 482`,
`q = 2^12`, `p = 2^8`, `Δ = q/p = 16`, `sk ∈ {0,1}^n`.

Preprocessing (Figure 3, `pool-oprf/src/preprocessing.rs`):

- `n` binary random OTs, client as sender. Client gets seed pairs
  `(s_{0,i}, s_{1,i})`, server gets `(b_i, s_{b_i,i})` for a random choice bit
  `b_i`. The paper's per-slot masks are derived from the seed:
  `r^ctr_{c,i} = derive_r(s_{c,i}, ctr)` (BLAKE3 XOF, `preprocessing.rs:90`).
- `τ` (Δ-choose-1) random OTs, server as sender. For slot `ctr` the server
  gets Δ blocks and derives pads `ρ_{j,ctr} = r_prime_from_block(block_j)`
  (`preprocessing.rs:113`); the client gets `(b'_ctr, block_{b'_ctr})`, hence
  `ρ_{b'_ctr,ctr}`. The Δ-OT itself is built from `log Δ` binary OTs plus a
  BLAKE3 derivation (`delta_ot.rs:62`).
- Server sends `b̄_i = b_i ⊕ sk_i` (`preprocessing.rs:560`).

Online (Figure 4, `pool-oprf/src/online.rs`), for a row on slot `ctr`:

- Request (`online.rs:242`): `a = RO(t, x)` row; client uses
  `u_i = r^ctr_{b̄_i,i}` as the mask and `v_i = r^ctr_{1−b̄_i,i}` as the other
  message, sends `e_i = a_i + u_i + v_i mod q` and
  `b̄' = (r_Σ mod Δ) − b'_ctr mod Δ` where `r_Σ = Σ_i u_i mod q`. Keeps
  `(ctr, r_Σ, ρ_{b'_ctr,ctr})`.
- BlindEval (`online.rs:343`): the server's mask is `m_i = r^ctr_{b_i,i}`.
  `ã_i = m_i` if `sk_i = 0`, else `e_i − m_i`. `ã_Σ = Σ_i ã_i mod q`.
  `y_j = ⌈ã_Σ − j⌋_{q,p} + ρ_{(j − b̄') mod Δ, ctr} mod p` for `j ∈ [0, Δ)`.
- Finalize (`online.rs:439`): `j* = r_Σ mod Δ`,
  `z = y_{j*} − ρ_{b'_ctr,ctr} − ⌊r_Σ/Δ⌋ mod p`.

Correctness hinges on `b_i = b̄_i ⊕ sk_i`, which makes `m_i = u_i` when
`sk_i = 0` and `m_i = v_i` when `sk_i = 1`, so `ã_i = sk_i·a_i + u_i` and
`ã_Σ = a^T sk + r_Σ`. Written with the server's own quantities, which is how the
proof will see it:

```
ã_Σ = Σ_i [ sk_i · e_i + (1 − 2·sk_i) · m_i ]   mod q        (★)
```

## 3. What has to be proven

### 3.1 The obstacle that shapes the statement

In algebraic VOPRFs (2HashDH, Albrecht–Gür) the server's response is an
arithmetic function of the *public* request and the key, so "the response is
correct for `pk`" is a statement over values both parties know. In Pool the key
enters through **OT choice bits**: the server's response depends on `m_i`, its
OT output, and the client cannot tell which of `(u_i, v_i)` the server holds
without learning `sk_i`. The prover, in turn, does not know the other message.
So neither party knows the whole "natural" public input `(e, u, v)`, and the
relation cannot be stated as `ã_Σ = a^T sk + r_Σ` with `a` public, because the
server never sees `a`.

The statement therefore has to be about the server's actual computation (★)
with `m_i` and `sk_i` as witnesses, **plus a binding of `m_i` to the OT
message the client sent at index `b̄_i ⊕ sk_i`**. Without that binding the
server can pick `m` freely, (★) then says nothing, and the proof is worthless.
Any information the client could send to let the server learn its "other"
message would reveal `a_i = e_i − u_i − v_i`, so the binding has to go through
one-way commitments that are opened *inside* the proof. That is the one
unavoidable cost of verifying an OT-based OPRF; everything else is cheap
modular arithmetic.

The same issue appears on the pad side: the client knows only one of the Δ
pads, and it must not learn any other (Section 4). The server therefore
commits to all Δ pads of a slot; the client checks the one it knows; the proof
covers all Δ.

### 3.2 New public values

Set up once per key:

- `pk = Com_key(sk; ω_pk)`, a hiding, binding commitment. Distributed like any
  VOPRF public key, i.e. authenticated out of band (RFC 9497 style). If the
  client just takes `pk` from the server's hello, a server can still use a
  per-client key; verifiability then only says "consistent with *this* `pk`".

Once per preprocessing run (session `uid`):

- From the client, after the binary OTs: `c_{0,i} = Com_seed(s_{0,i})`,
  `c_{1,i} = Com_seed(s_{1,i})` for `i ∈ [n]`. `Com_seed` can be a plain
  one-way hash (seeds are 128-bit random OT outputs), it need not be hiding.
- From the server, after the Δ-OTs: for every slot `ctr` and every
  `j ∈ [0, Δ)`, `d_{j,ctr} = Com_pad(ρ_{j,ctr}; ω_{j,ctr})`. `Com_pad` **must**
  be hiding (pads are 8-bit values). Both the pad and `ω_{j,ctr}` are derived
  from the server's Δ-OT block `j`, so the client can recompute
  `d_{b'_ctr,ctr}` from its own block and check it. It cannot check, and must
  not be able to check, the other `Δ − 1`.
- `b̄ ∈ {0,1}^n`, already sent today.

Per response: a proof `π` covering every row of the request (a batch of `k`
evaluations is `16·k` rows and one proof).

### 3.3 The relation `R_row`, one instance per row / slot

Public input (known to both, all already on the wire or above):

```
e ∈ Z_q^n, b̄' ∈ Z_Δ, y ∈ Z_p^Δ, ctr            (this row's request / response)
b̄ ∈ {0,1}^n, c_{0,·}, c_{1,·}, d_{·,ctr}, pk     (session values)
```

Witness:

```
sk ∈ {0,1}^n, ω_pk                (key and its commitment randomness)
s_i, i ∈ [n]                      (the seed the server holds for coordinate i)
m_i ∈ Z_q, i ∈ [n]                (masks, derived from s_i)
ρ_j ∈ Z_p, ω_j, j ∈ [0, Δ)        (pads and their commitment randomness)
```

Constraints:

```
(K)  pk = Com_key(sk; ω_pk)                    and sk_i ∈ {0,1} for all i
(S)  Com_seed(s_i) = c_{b̄_i ⊕ sk_i, i}         for all i
       i.e. (1 − sk_i)·c_{b̄_i,i} + sk_i·c_{1−b̄_i,i} = Com_seed(s_i)
(M)  m_i = Expand(s_i, ctr)                    for all i
(A)  ã_Σ = Σ_i [ sk_i·e_i + (1 − 2·sk_i)·m_i ]   mod q
(R)  y_j = ⌈(ã_Σ − j) mod q⌋_{q,p} + ρ_{(j − b̄') mod Δ}   mod p,   j ∈ [0, Δ)
(P)  d_{j,ctr} = Com_pad(ρ_j; ω_j)             for all j
```

Client-side checks outside the proof, per row: verify `π`; check
`d_{b'_ctr,ctr}` opens to the pad and randomness derived from its own Δ-OT
block; check `ctr` matches (already done). Then run `Finalize` as today.

Why this is sufficient (soundness sketch). `pk` binding fixes `sk`. The server
holds one seed per `i` and `c_{·,i}` is binding, so (S) forces
`s_i = s_{b̄_i ⊕ sk_i, i}`; note `b̄` is a server-chosen value, but whatever it
chose, `sk` is pinned by `pk`. (M) then forces `m_i` to equal the client's mask
`u_i` if `sk_i = 0` and `v_i` if `sk_i = 1`, so (A) gives
`ã_Σ = a^T sk + r_Σ` with the client's own `a`, `r_Σ`. (R) and (P) with the
client's own check of `d_{b'_ctr,ctr}` at `j* = r_Σ mod Δ` (note
`j* − b̄' = b'_ctr mod Δ`) give `y_{j*} = ⌈a^T sk + r_Σ − j*⌋ + ρ_{b'_ctr}`,
and `Finalize` outputs `⌈a^T sk⌋_{q,p} = F_sk(t, x)` exactly as in the
correctness proof (Appendix D.1).

Nothing here depends on the OT protocol being honest: the client compares
against messages *it* sent (the seeds) and the value *it* received (its pad).

### 3.4 What is deliberately not proven

- Anything the client computes itself: `a = RO(t, x)`, `e`, `b̄'`, `r_Σ`,
  `Finalize`. The client trusts itself.
- That the server's `b̄_i` is "honest" with respect to its OT choice bit. Not
  needed, argued above.
- That the server's Δ-OT sender blocks are the "right" ones. Not needed: the
  client only relies on the block it received.
- Well-formedness of the client's request (malicious client). Out of scope.
- The `d_{j,ctr}` for `j ≠ b'_ctr` can be commitments to anything; the client
  only uses its own index, and the server does not know which one that is.

### 3.5 Variants considered and rejected

- *Trust preprocessing, verify only the online phase.* One would have the
  server commit to its state at the end of preprocessing and open it inside
  the online proof. The opening costs the same `n + Δ` commitment checks per
  row as (S) and (P), so it saves nothing and gives a weaker guarantee.
- *Commit to per-slot masks instead of seeds.* Removes (M) but costs the
  client `2n` commitments per slot, about 500 kB per evaluation. No.
- *Consistency instead of correctness* (evaluate `x` twice, compare). Detects
  a randomly misbehaving server, not one using a wrong key. Not verifiability.
- *Let the client prove/verify with its private `(u, v)` in a 2PC* (both
  parties commit into authenticated shares, SPDZ-style, and check (★)). Avoids
  all hashing and is the cheapest in constraints, but it is an interactive
  2PC, not a proof, adds rounds, and is a bigger redesign. Kept as a fallback
  idea only.

## 4. Do we need zero-knowledge?

Yes. Concretely, the witness of `R_row` contains two things that must stay
hidden from the client:

1. **`sk`** (and equivalently the seed selection in (S)). Any leak of key bits
   degrades pseudorandomness directly; a full leak lets the client evaluate
   the PRF itself.
2. **The pads `ρ_j`, `j ≠ b'_ctr`.** With a pad the client computes
   `y_j − ρ_j = ⌈ã_Σ − j⌋_{q,p}`. Two such values at adjacent `j` reveal
   whether a rounding boundary lies between them, i.e. bits of
   `(a^T sk + r_Σ) mod Δ`; the client knows `r_Σ`, so it learns low bits of
   `a^T sk mod q`, an *unrounded* LWE-style sample. With about `n` of those it
   recovers `sk` by linear algebra. The paper's proof of Theorem 5.2 depends
   exactly on the `y_j`, `j ≠ j*`, being uniform to the client
   (Appendix D.2, game `G_3`).

A proof system that is sound but not zero-knowledge leaks arbitrary functions
of the witness. In hash-based systems without ZK (plain FRI/STARK without
randomisers, Brakedown, Zinc, Binius as published) the verifier sees, for
example, random linear combinations of witness rows and evaluations of witness
polynomials at queried points, which leak bits of `sk` and of the pads outright.
So "just a proof" is not an option; the proof must be zero-knowledge, or at
minimum witness-hiding for `sk` and the pads. For the paper's game-based
proof the cleaner requirement is simulatable ZK: the semi-honest-client
simulator of Theorem 5.2 additionally sets `pk = Com_key(0)`, the `d_{j,ctr}`
to commitments of random values, and replaces `π` by the ZK simulator's output.
That requires `Com_key` and `Com_pad` to be hiding.

On the soundness side, what verifiability needs is soundness relative to the
binding of `pk`, `c`, `d`. Knowledge soundness (an argument of knowledge) makes
the reduction to commitment binding standard and is what the lattice and
hash-based systems below provide anyway.

## 5. Zinc and Zinc+

Both are hash-based, plausibly post-quantum, and their arithmetization is a
very good match for Pool: they prove statements over `ℤ` and `ℤ/nℤ` for
arbitrary `n`, including several moduli in one statement, so the
`mod 2^12` / `mod 2^8` / rounding arithmetic of (A) and (R) would cost almost
nothing. But:

- **Zinc** (Garreta, Hristova, Waldner, Dall'Ava; CRYPTO 2025,
  [ePrint 2025/316](https://eprint.iacr.org/2025/316)) never claims
  zero-knowledge. The word does not occur in the paper outside the reference
  list, and the PCS ("Zip", Brakedown-type) is not hiding. The
  [reference implementation](https://github.com/NethermindEth/zinc) (Rust, MIT,
  research prototype, CCS/R1CS over integers) does not mention ZK either.
- **Zinc+** (Abdugafarov, Garreta, Kumar, Osadnik, Vesely, Vlasov, Zheng; May
  2026, [ePrint 2026/855](https://eprint.iacr.org/2026/855)) is explicit:
  "Note that our schemes are not zero-knowledge in any case. We leave
  zero-knowledgeness as future work", and its benchmark is labelled "without
  zero-knowledge" (198 KB proof, 40.6 ms prover for 7 SHA-256 compressions +
  an ECDSA MSM on an M4).

So neither can be used for the server proof as they stand. Making a Brakedown
family system zero-knowledge is known in principle (Ligero-style masking of
the encoded rows plus a ZK sumcheck) but is research and engineering nobody
has done for Zinc. If the colleague's suggestion was motivated by the
mixed-modulus arithmetization, that advantage is real but secondary: (A) and
(R) are a few thousand constraints per evaluation in any system; the
commitment openings (S), (M), (P) dominate.

## 6. Proof systems that fit

Requirements: zero-knowledge, post-quantum, able to open the commitments in
(S), (M), (P) at reasonable cost, and preferably a usable implementation. The
statement is small (Section 7 puts it around `2^19` to `2^20` constraints per
evaluation, dominated by ~1.2k hash permutations), and it is proven by a
server per request, so prover time and proof size both matter; the verifier is
a client.

### 6.1 Lattice-based (LNP22, LaBRADOR + LNP-Lite)

- **LNP22** (Lyubashevsky, Nguyen, Plançon, CRYPTO'22,
  [ePrint 2022/284](https://eprint.iacr.org/2022/284)): linear-size ZK
  proofs of linear relations over `Z_q'[X]/(X^d+1)` with exact norm bounds and
  native "this vector is binary" proofs. ~14 KB for a basic statement, grows
  linearly with the witness. This is what Albrecht–Gür use for the server-side
  proof of their lattice VOPRF (their `P_2`, response `= c_x·k + e_S`; ~39 kB
  per query, Table 2 of [ePrint 2024/1459](https://eprint.iacr.org/2024/1459)).
- **LaBRADOR** (Beullens–Seiler, CRYPTO'23) is succinct (<100 KB for any
  statement size) but **not zero-knowledge**; the prover messages leak the
  witness. The June 2026 **"Toolkit for Succinct Lattice-Based Zero Knowledge
  Proofs"** (Biasioli, Bolboceanu, Lyubashevsky, Merino-Gallardo, Osadnik,
  Seiler, Steuer, [ePrint 2026/1289](https://eprint.iacr.org/2026/1289))
  combines LaBRADOR with a compressed LNP ("LNP-Lite") and reports ~110 KB
  proofs with ZK (100 KB without) and seconds-range provers; e.g. proving the
  expansion of a seed into `2^8` binary polynomials of degree 512 takes about
  1 s on one core, `2^12` about 3 s (their Table 1). Implemented as an
  extension of the **LaZer** library
  ([ePrint 2024/1846](https://eprint.iacr.org/2024/1846)): C with a Python
  front end, no Rust bindings.
- Fit for Pool: the commitments become Ajtai/BDLOP commitments (linear, hence
  free), `Expand` becomes an LWR/M-SIS style PRG (what their PRG benchmark
  proves), and the `mod 2^12` arithmetic has to be lifted to `Z_q'` with carry
  witnesses and binary decompositions. Doable but the arithmetization is the
  least natural of the options, and there is no Rust implementation.

### 6.2 Hash-based STARK / FRI with zero-knowledge

- Any FRI-based STARK can be made ZK by randomising the witness polynomials
  and the quotient decomposition, but it is easy to get wrong: Haböck and Al
  Kindi ([ePrint 2024/1037](https://eprint.iacr.org/2024/1037)) found ZK gaps
  in Plonky2, RISC Zero and Triton (since patched) and give the correct
  construction; the arithmetic overhead is roughly `1 + 4/(3·log|H|)`, i.e. a
  few percent.
- **Plonky3** (Rust; Mersenne31, BabyBear, KoalaBear, Goldilocks; Poseidon2,
  Rescue, Monolith, BLAKE3 hashes): the README says nothing about ZK; a search
  turns up claims of "full ZK support" but I could not confirm a ZK flag in the
  code from here. **Must be checked before relying on it.**
- **Winterfell** (Rust, Meta): documented as *not* zero-knowledge.
- **RISC Zero**: zkVM, ZK STARK receipts; simplest engineering (write the
  checker in Rust) but a general zkVM is 10–100x slower than a hand-written
  AIR for this statement.
- **Binius / Binius64**: Brakedown-based, no ZK claim in the README, original
  repo archived Sept 2025. Treat like Zinc.
- Fit for Pool: good. Use Poseidon2 (or another arithmetization-friendly
  permutation) for `Com_key`, `Com_seed`, `Com_pad` and for `Expand`; the
  `mod 2^12` / `mod 2^8` arithmetic is done with bit decompositions
  (Section 7.2). Proof sizes ~100–200 KB at 128 bits with ZK; prover in the
  100 ms–1 s range for one evaluation is a reasonable expectation for
  `~2^19` constraints; verifier a few ms. Batching all evaluations of a PSI
  request into one proof amortises well.

### 6.3 Ligero-family (Ligero, Ligero++, Ligetron)

ZK, hash-based, `O(√|C|)` proof size, very fast provers. Proofs for our size
would be several hundred KB to a few MB. Fewer maintained implementations.
A fallback if a STARK with proper ZK is not available.

### 6.4 VOLE-based, designated verifier (QuickSilver, Mac'n'Cheese, Mozzarella)

Interactive ZK from VOLE correlations, post-quantum (built on OT), 1 field
element of communication per multiplication gate, extremely fast, and the
verifier is *designated*, which is exactly the OPRF situation (only the client
needs to be convinced). Mozzarella / "Appenzeller to Brie" even work natively
over `Z_{2^k}`, so (A) and (R) need no lifting. Rust implementation:
Diet Mac'n'Cheese in GaloisInc/swanky. Two problems: it adds online rounds
(Pool is built for two messages), and the hash-based bindings (S), (M), (P)
cost ~`4·10^5` multiplications per evaluation, i.e. ~3 MB of communication.
Only attractive if the binding can be made hash-free (the 2PC idea in 3.5).

### 6.5 MPC-in-the-head / VOLE-in-the-head (FAEST-style)

ZK, hash-based, publicly verifiable, but linear proof size: ~3 field elements
per multiplication over a 64-bit field at 128-bit soundness
([ePrint 2023/996](https://eprint.iacr.org/2023/996), Table 1), so ~10 MB per
evaluation for our statement. Not suitable.

### 6.6 Recommendation

1. **Primary: a hash-based STARK with zero-knowledge** (Plonky3 if its ZK mode
   checks out, otherwise RISC Zero for a first prototype), Poseidon2 for all
   commitments and for `Expand`. Reasons: Rust, fits the workspace, native
   support for the hash we need in-circuit, no new assumptions beyond hashes
   (the PRF itself is LWR, but the *proof* adding no lattice-parameter
   choices is a plus), batching is natural, and there is a documented recipe
   for doing ZK right.
2. **Secondary: LaBRADOR + LNP-Lite via LaZer**, for smaller proofs
   (~110 KB regardless of statement size) if proof size turns out to matter
   more than prover time and the C/Python dependency is acceptable.
3. Not Zinc / Zinc+ / Binius / Winterfell until they have zero-knowledge.

## 7. Protocol changes and cost

### 7.1 Message changes

Preprocessing (Figure 3), added:

| who → who        | what                                    | size (per session, `τ = 16·k` slots) |
| ---------------- | --------------------------------------- | ------------------------------------ |
| server → client  | `pk` (or out of band)                   | 32 B once                            |
| client → server  | `c_{0,i}, c_{1,i}`, `i ∈ [n]`           | `2·482·32 B ≈ 31 KB`                 |
| server → client  | `d_{j,ctr}`, `j < Δ`, `ctr < τ`         | `16·32 B = 512 B` per slot, 8 KB per evaluation |

Against ~750 KB (IKNP) or ~800 KB (silent OT) of preprocessing per evaluation
today (paper, Table 2), this is noise.

Online (Figure 4), added: `π` in `ResponseMessage`, one per request, order of
100–200 KB for a hash-based system, ~110 KB for the lattice toolkit, largely
independent of the number of evaluations in the batch. Compared with 11.9 kB
per evaluation today this dominates single evaluations and is amortised in
PSI batches. No extra round.

### 7.2 Code changes implied

- `derive_r` (`preprocessing.rs:90`) becomes an arithmetization-friendly PRF:
  one Poseidon2 permutation on `(s_i, evaluation index)` squeezing the 16
  masks (16 × 12 bits) of one evaluation for coordinate `i`. Both sides
  compute it natively; only the server also proves it. The paper only needs
  the OT output to be pseudorandomly expanded, so this is a legitimate
  implementation choice.
- `r_prime_from_block` (`preprocessing.rs:113`) additionally derives
  `ω_{j,ctr}`; the server publishes `d_{j,ctr}`; `ClientState` keeps its
  `(ρ, ω)` per slot and checks `d_{b'_ctr,ctr}` in `finalize_row`.
- `preproc_client` sends `c_{0,i}, c_{1,i}` after `sender.send`; `ClientState`
  keeps them; `ServerState` keeps them for the public input.
- `OprfServer::new` computes `pk`; `blind_eval` produces `π` over all rows;
  `finalize_batch` verifies `π` before unblinding.
- The circuit for one row: (K) once per proof; (S) `n` permutations, once per
  proof (amortised over the batch); (M) `n` permutations per evaluation (one
  per `i`, covering 16 rows); (A) `2n` multiplications plus one 24-bit
  decomposition per row; (R) 16 × (12-bit decomposition, 4-bit rounding
  gadget with the tie-rounds-down rule of `round_zq_to_zp`, 9-bit
  decomposition for `mod p`) per row; (P) 16 permutations per row. Per
  evaluation roughly 1.2k permutations, 20k multiplications, 5k bit
  constraints; with Poseidon2 at a few hundred constraints per permutation,
  about `2^19` constraints.

## 8. Questions for review

1. Threat model: agree that verifiability is stated against an arbitrarily
   deviating server while privacy stays semi-honest? (Section 1.)
2. Is the mask binding (S)+(M) acceptable, given it forces replacing BLAKE3 in
   `derive_r` with a ZK-friendly PRF? The alternative (commit per-slot masks)
   is much more communication; the 2PC alternative changes the protocol shape.
3. Pad binding (P) uses per-entry commitments (8 KB per evaluation in
   preprocessing). A Merkle root per slot with the path delivered through the
   OT costs more and needs a chosen-message OT; is per-entry fine?
4. `pk` distribution: out of band, or in the hello with the caveat in 3.2?
5. Batch proofs: one `π` per request, covering all evaluations, or one per
   evaluation? The former is what the cost estimates assume.
6. Proof system choice: STARK-with-ZK first, lattice toolkit second. Anyone
   with LaZer experience?

## References

- Pool: Davidson, Deo, Tremblay Thibault, ePrint 2025/1816 (`docs/paper.txt`),
  Figures 3–4, Section 4 "Achieving malicious security", Appendix D.
- Verifiability definitions: Albrecht, Gür, "Verifiable OPRFs from Lattices:
  Practical-ish and Thresholdisable", ASIACRYPT'24,
  https://eprint.iacr.org/2024/1459 (Def. 11, Fig. 1b, Sect. 5 on proofs
  P0/P2 with LNP22). Tyagi et al., "A Fast and Simple Partially Oblivious
  PRF", EUROCRYPT'22, https://eprint.iacr.org/2021/864 (POPRIV2, POUNIQ).
- Zinc: https://eprint.iacr.org/2025/316, code
  https://github.com/NethermindEth/zinc. Zinc+: https://eprint.iacr.org/2026/855.
- LNP22: https://eprint.iacr.org/2022/284. LaZer: https://eprint.iacr.org/2024/1846.
  LaBRADOR+LNP-Lite toolkit: https://eprint.iacr.org/2026/1289.
- ZK for FRI/STARK: Haböck, Al Kindi, https://eprint.iacr.org/2024/1037.
- VOLE-in-the-head: https://eprint.iacr.org/2023/996.
- Plonky3: https://github.com/Plonky3/Plonky3. Binius:
  https://github.com/IrreducibleOSS/binius (archived).
