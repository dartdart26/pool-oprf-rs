# Pool VOPRF: the server's proofs

- [1. Introduction](#1-introduction)
- [2. High level design](#2-high-level-design)
- [3. Server proofs](#3-server-proofs)
  - [Response equation](#response-equation)
  - [Statements](#statements)
  - [Proving the response](#proving-the-response)
  - [Constraints](#constraints)
- [4. Why zero-knowledge](#4-why-zero-knowledge)
- [5. Proof system](#5-proof-system)
- [6. The OT underneath](#6-the-ot-underneath)
- [7. Known issues](#7-known-issues)
- [References](#references)

## 1. Introduction

This note explains what a server needs to prove for Figures 3 and 4
of the paper to make it a verifiable and post-quantum VOPRF.

Pool's PRF is based on LWR. The secret key `sk in {0, 1}^n` has `n` bits.
Each output element is `⌈a^⊤·sk mod q⌋` in `ℤ_p`, for `a ∈ ℤ_q^n` being a
hash of the tag `t` and the input `x`. `⌈w⌋` is the nearest integer to
`w / Δ`, rounding down on a tie, with `Δ = q/p`.

A **run** of the protocol gives one output element of `ℤ_p`, i.e. 8 bits. An
**evaluation** is `RUNS_PER_EVALUATION = 16` runs and that gives 128 bits of
output. Each evaluation has its own and separate online proof.

One preprocessing can be made for more than one evaluation, i.e. a preprocessing
serves `τ` runs and `τ / RUNS_PER_EVALUATION` evaluations. In a superscript,
`v` marks the evaluation and `k = 0 .. RUNS_PER_EVALUATION-1` the run within
the evaluation, e.g. as in response `y^{v, k}_j`. In a subscript,
`j = 0 .. Δ-1` marks a **position** within a run.

We introduce `pk`, a commitment to the secret key `sk`, that the server
publishes once. If the client is convinced the server response is correct,
it accepts it as `F_sk(t, x)` - the PRF's output on tag `t` and input `x`,
under the `sk` committed to by `pk`.

Pool runs two kinds of random OTs (1-out-of-2 and 1-out-of-Δ) and this note
treats them as ideal: a box that hands each party its outputs and reveals
nothing else. Here, we assume maliciously secure OT, which behaves like that
box even when either party cheats. [Section 6](#6-the-ot-underneath) talks
more about the underlying OTs. The preprocessing runs `n` binary OTs (one per
key bit) and `τ` 1-out-of-Δ OTs (one per run).

Binary OT `i = 0 .. n-1` gives the client two OT blocks, `ot_block_{0, i}` and
`ot_block_{1, i}` and the server `ot_block_{b_i, i}` for its choice bit `b_i`.
These blocks serve the whole preprocessing. The client expands both of its OT
blocks and the server its one OT block, each into a stream of **masks** with one
mask for each of the `τ` runs of the preprocessing. Evaluation 0 uses the first
`RUNS_PER_EVALUATION` masks of a stream, evaluation 1 the next
`RUNS_PER_EVALUATION` and so on. For example, `r^{v, k}_{b, i}` is mask
`v·RUNS_PER_EVALUATION + k` of the stream from `ot_block_{b, i}`. In run `k` of
evaluation `v`, the client therefore holds the pair `r^{v, k}_{0, i}` and
`r^{v, k}_{1, i}` and the server holds `r^{v, k}_{b_i, i}`.

The 1-out-of-Δ OT of run `k` of evaluation `v` gives the server (as sender) all
**pads** `r′^{v, k}_0 .. r′^{v, k}_{Δ-1}` of that run, and the client (as
receiver) only `r′^{v, k}_{b′^{v, k}}`, for its choice `b′^{v, k}`. Each pad
`r′^{v, k}_j` is derived from an 1-out-of-Δ OT block `ot_block′^{v, k}_j`.

## 2. High level design

In the paper's protocol, the server sends only two non-OT messages:
 - `b̄` in preprocessing step 4
 - `y^{v, k}_0 .. y^{v, k}_{Δ-1}` as a response in the online phase

With ideal OTs ([section 6](#6-the-ot-underneath)), these are the only
messages a server can fake (as the OTs are considered correct). Without
verifiability, a fake goes undetected and the OPRF output still looks random.

To prove these non-OT messages, we add the following new messages to the
protocol:

| message                                                    | description                                               | direction        | when                            |
| ---------------------------------------------------------- | --------------------------------------------------------- | ---------------- | ------------------------------- |
| `pk`                                                       | commitment to the server's `sk`                           | server -> client | setup                           |
| `π_setup`                                                  | proof of the setup statement                              | server -> client | setup                           |
| `c^v_{0, 0} .. c^v_{0, n-1}`, `c^v_{1, 0} .. c^v_{1, n-1}` | commitments to the client's masks for each evaluation `v` | client -> server | after preprocessing step 2      |
| `d^{v, k}_0 .. d^{v, k}_{Δ-1}`                             | commitments to the server's pads for each run `k`         | server -> client | after preprocessing step 3      |
| `m^v`                                                      | commitment to all `r̃^{v, k}_Σ` of each evaluation `v`     | server -> client | end of preprocessing            |
| `π_preproc`                                                | proof of the preprocessing statement                      | server -> client | end of preprocessing            |
| `π_online`                                                 | proof of the online statement                             | server -> client | with each evaluation's response |

## 3. Server proofs

### Response equation

The client's request in run `k` of evaluation `v` is
`e^{v, k}_0 .. e^{v, k}_{n-1}` and `b̄′^{v, k}`. The server's response in that
run is `y^{v, k}_0 .. y^{v, k}_{Δ-1}`.

```
// the server's online response, one entry per position j of run k for evaluation v
y^{v, k}_j = ⌈(ã^{v, k}_Σ - j) mod q⌋ + r′^{v, k}_{(j - b̄′^{v, k}) mod Δ}                          mod p,   j = 0 .. Δ-1

// the sum
// ã^{v, k}_i = r^{v, k}_{b_i, i} if sk_i = 0 or ã^{v, k}_i = e^{v, k}_i - r^{v, k}_{b_i, i} if sk_i = 1
ã^{v, k}_i = (1 - sk_i)·r^{v, k}_{b_i, i} + sk_i·(e^{v, k}_i - r^{v, k}_{b_i, i})                  mod q
           = sk_i·e^{v, k}_i + (1 - 2·sk_i)·r^{v, k}_{b_i, i}                                      mod q
ã^{v, k}_Σ = Σ_i ã^{v, k}_i  =  Σ_i sk_i·e^{v, k}_i + r̃^{v, k}_Σ                                   mod q
r̃^{v, k}_Σ = Σ_i (1 - 2·sk_i)·r^{v, k}_{b_i, i}                                                    mod q

// b̄_i sent by the server at the end of preprocessing
b̄_i        = b_i ⊕ sk_i

// the server's OT choice, derived from b̄_i
b_i        = b̄_i ⊕ sk_i

// b̄′^{v, k} sent by the client in the request
b̄′^{v, k}  = (j*^{v, k} - b′^{v, k}) mod Δ

// the entry of the response the client reads
j*^{v, k}  = r^{v, k}_Σ mod Δ
r^{v, k}_Σ = Σ_i r^{v, k}_{b̄_i, i}                                                                 mod q

// therefore, another way to write y^{v, k}_j is
y^{v, k}_j = ⌈(Σ_i sk_i·e^{v, k}_i + r̃^{v, k}_Σ - j) mod q⌋ + r′^{v, k}_{(j - b̄′^{v, k}) mod Δ}    mod p
```

One way to look at `y^{v, k}_j` is as a sum of two OT-derived parts on the server side.
The rounded part comes from the binary OTs' masks in `r̃^{v, k}_Σ`. The other part is the pad
`r′` from run `k`'s 1-out-of-Δ OT.

Furthermore, the point of rewriting `ã^{v, k}_Σ` as above is to separate it into
two terms - one that depends on the online request and one that only depends on
preprocessing. This way, we can do more work in preprocessing and less during
the online phase, making the online proof smaller and faster.

Note that the server does not know `j*^{v, k}` and, therefore, it has to prove
the equation for `y^{v, k}_j` at every `j`, not just at `j*^{v, k}`.

A summary of symbols used:

| symbol       | domain       | in the proof |
| ------------ | ------------ | ------------ |
| `j`          | `ℤ_Δ`        | public       |
| `b̄`          | `{0, 1}`     | public       |
| `e`          | `ℤ_q`        | public       |
| `b̄′`         | `ℤ_Δ`        | public       |
| `y`          | `ℤ_p`        | public       |
| `sk`         | `{0, 1}`     | witness      |
| `ot_block`   | `{0, 1}^128` | witness      |
| `r`          | `ℤ_q`        | witness      |
| `r̃_Σ`        | `ℤ_q`        | witness      |
| `randomness` | `{0, 1}^128` | witness      |
| `r′`         | `ℤ_p`        | witness      |
| `ot_block′`  | `{0, 1}^128` | witness      |
| `ã_Σ`        | `ℤ_q`        | computed     |
| `r_Σ`        | `ℤ_q`        | not in it    |
| `j*`         | `ℤ_Δ`        | not in it    |
| `b′`         | `ℤ_Δ`        | not in it    |

### Statements

The server proves three statements, with one proof for each. See [Constraints](#constraints)
for details.

| statement     | proof       | when the server proves it       | server messages it covers | constraints         |
| ------------- | ----------- | ------------------------------- | ------------------------- | ------------------- |
| setup         | `π_setup`   | at setup                        | `pk`                      | (K)                 |
| preprocessing | `π_preproc` | at the end of preprocessing     | `b̄`, `m^v`                | (K) (S) (T) (M)     |
| online        | `π_online`  | with each evaluation's response | `y^{v, k}`, `d^{v, k}`    | (K) (M) (P) (A) (R) |

### Proving the response

`y^{v, k}_{j*^{v, k}}` is correct only if the server used the right public
values, its secret key `sk`, its own masks, and the pad the client holds. The
secret values each come from something the client trusts, through a chain of
constraints. Read `->` as "pins down":

```
key       pk -(K)-> sk
masks     c^v_{0, i}, c^v_{1, i} -(S)-> all r^{v, k}_{b_i, i} -(T)-> all r̃^{v, k}_Σ -(M)-> m^v
pads      d^{v, k}_0 .. d^{v, k}_{Δ-1} -(P)-> r′^{v, k}_0 .. r′^{v, k}_{Δ-1}
sum       sk, masks -(A)-> ã^{v, k}_Σ
response  ã^{v, k}_Σ, pads -(R)-> y^{v, k}_0 .. y^{v, k}_{Δ-1}
```

**Key.** `pk` is the server's commitment to `sk`, published at setup.

**Masks.** `c^v_{0, i}` and `c^v_{1, i}` commit to the client's masks for
evaluation `v`. (S) opens `c^v_{b̄_i ⊕ sk_i, i}` with the server's masks, (T)
sums the server's masks into `r̃^{v, k}_Σ` and (M) opens `m^v`, the server's
commitment to these sums. The online proof opens the same `m^v` and, therefore,
uses the same sums.

**Pads.** `d^{v, k}_0 .. d^{v, k}_{Δ-1}` are the server's commitments to its
pads of run `k`. The client checks its own pad `r′^{v, k}_{b′^{v, k}}` against
`d^{v, k}`. The online proof opens the same `d^{v, k}` and, therefore, the pad
on `y^{v, k}_{j*^{v, k}}` is the client's.

**Response.** (A) sums `sk` and `r̃^{v, k}_Σ` with the request `e^{v, k}` into
`ã^{v, k}_Σ`. (R) computes `y^{v, k}` from `ã^{v, k}_Σ` and the pads.

With that, every value behind `y^{v, k}_{j*^{v, k}}` is pinned down such that
the server can only send the honest one.

### Constraints

A commitment is a hash and hides its value only if the input value is too big to
guess. For example, `sk` is big enough at `n` bits and so is an OT block at 128
bits. However, masks and pads, for example, are not as each is one number of
`ℤ_q` or `ℤ_p`. Therefore, in such cases, we hash a random value in with the
committed one and the constraint that opens them has the random value in the
witness. The random value comes from the OT blocks.

We write a commitment as `Commit(domain, values, random value)`. Every kind
of commitment or hash has its own domain, such that no two kinds hash to the
same output.

#### (K) The key

```
pk = Commit(Domain::Key, sk),   each sk_i in {0, 1}
```

`pk` is the commitment to the binary secret key `sk`. Opening `pk` pins down
`sk` and the bit check ensures `sk` is binary.

#### (S) The server's masks

```
c^v_{b̄_i ⊕ sk_i, i} = Commit(Domain::Masks, r^{v, 0}_{b_i, i} .. r^{v, RUNS_PER_EVALUATION-1}_{b_i, i}, ot_block_{b_i, i})      i = 0 .. n-1
```

Both parties expand the binary OT blocks into masks outside the proof. The
server's response is right only if the server's masks are expanded correctly
from the correct OT block.

The client sends `c^v_{0, i}` and `c^v_{1, i}`: commitments to both OT blocks
and respective masks of each `i`, for evaluation `v`. The OT block itself is the
random value used when hashing.

Before sending `b̄`, the server checks `c^v_{b_i, i}` against its own masks and
`ot_block_{b_i, i}` and aborts on a mismatch. Otherwise, a client that knows
`b̄_i` can send a bad `c^v_{0, i}`. The proof then fails only when `b_i = 0`,
and the client learns `sk_i = b̄_i ⊕ b_i`. Before the server sends `b̄`, `b_i`
alone says nothing about `sk_i`.

Opening `c^v_{b_i, i}` with the server's own `b_i` proves nothing as the server
can open the commitment to the OT block it holds. Therefore, the proof opens
`c^v_{b̄_i ⊕ sk_i, i}` instead. `b̄_i` is public, `sk_i` is pinned down by `pk` and
the server holds only `ot_block_{b_i, i}`. Opening it, therefore, shows
`b̄_i ⊕ sk_i = b_i`: the `b̄_i` the server sent matches its OT choice and the
correct secret key, and the server's masks are the committed ones.

#### (T) The mask sum `r̃^{v, k}_Σ`

```
r̃^{v, k}_Σ = Σ_i (1 - 2·sk_i)·r^{v, k}_{b_i, i}      mod q
```

(T) checks that `r̃^{v, k}_Σ`, the sum for run `k` of evaluation `v`, is
correct as per [Response equation](#response-equation).

#### (M) The commitment `m^v`

```
m^v = Commit(Domain::MaskSum, r̃^{v, 0}_Σ .. r̃^{v, RUNS_PER_EVALUATION-1}_Σ, randomness^v)
```

`m^v` commits to all sums of evaluation `v`, one for each run `k` as above.
(M) is in both the preprocessing and the online proof. Therefore, the sums that
(T) checks from the masks are the ones the online proof uses in (A).

The random value is `randomness^v`:

```
randomness^v = Hash(Domain::MaskSumRandomness, ot_block′^{v, 0}_0 .. ot_block′^{v, 0}_{Δ-1})
```

`ot_block′^{v, 0}_0 .. ot_block′^{v, 0}_{Δ-1}` are the 1-out-of-Δ OT blocks of
run 0 for evaluation `v`. The server holds all Δ of them, but the client holds
only `ot_block′^{v, 0}_{b′^{v, 0}}` and lacks the other Δ - 1 blocks. The Δ - 1
blocks it lacks from run 0 are enough randomness for evaluation `v` as each OT
block is 128 bits.

#### (P) The pads

```
d^{v, k}_0     = Commit(Domain::Pad, r′^{v, k}_0, ot_block′^{v, k}_0)
..
d^{v, k}_{Δ-1} = Commit(Domain::Pad, r′^{v, k}_{Δ-1}, ot_block′^{v, k}_{Δ-1})
```

The server does not know which pad the client holds, so the server commits to
all Δ ones and the proof opens them all. The random values
`ot_block′^{v, k}_0 .. ot_block′^{v, k}_{Δ-1}` are the 1-out-of-Δ OT blocks the
pads come from.

#### (A) The sum `ã^{v, k}_Σ`

```
ã^{v, k}_Σ = Σ_i sk_i·e^{v, k}_i + r̃^{v, k}_Σ      mod q
```

(A) checks that `ã^{v, k}_Σ` is computed correctly as in [Response equation](#response-equation).

#### (R) The response

```
y^{v, k}_j = ⌈(ã^{v, k}_Σ - j) mod q⌋ + r′^{v, k}_{(j - b̄′^{v, k}) mod Δ}      mod p,   j = 0 .. Δ-1
```

(R) checks that every `y^{v, k}_j` is computed correctly. It checks the
arithmetic only - the constraints before it pin the values down.

## 4. Why zero-knowledge

Every part of the witness gives away the key:

- `sk`, directly.
- `ot_block_{b_i, i}`, and the masks expanded from it: the client holds both
  OT blocks, so seeing which one the server has gives it `b_i`, and
  `sk_i = b̄_i ⊕ b_i`.
- `r̃^{v, k}_Σ`: the client holds every `r^{v, k}_{0, i}` and `r^{v, k}_{1, i}`,
  so `r̃^{v, k}_Σ` is one linear equation mod `q` in the bits of `sk`. Every run
  adds one, and about `n` of them solve for `sk`.
- `r′^{v, k}_0 .. r′^{v, k}_{Δ-1}` and
  `ot_block′^{v, k}_0 .. ot_block′^{v, k}_{Δ-1}`: the client holds
  `r′^{v, k}_{b′^{v, k}}` and `ot_block′^{v, k}_{b′^{v, k}}` only and having
  the other Δ - 1 pads exposes `sk`.

Therefore, the proofs must be zero-knowledge.

## 5. Proof system

We can use any proof system that is zero-knowledge and post-quantum. The
choice is left to the implementation.

## 6. The OT underneath

This note treats both kinds of random OT as ideal and maliciously secure.
CryProt's OTs are such in their malicious variants:

- Base OT: [MR19] with ML-KEM, endemic secure in the random oracle model.
- IKNP extension, the default build: [KOS15]. [MR19] shows it is
  maliciously secure over endemic base OTs.
- Silent OT extension, the `silent-ot` feature: [BCG+19] with the [RRT23]
  code and the check of [YWL+20], on top of [KOS15] base OTs.
- 1-out-of-Δ OT, built on top of CryProt: [NP99], from `log Δ` binary
  random OTs of the extension above and a hash.

Pool uses the malicious variants in both of its builds: [KOS15] for IKNP in
the default build and silent OT with the `silent-ot` feature.

**Maliciously secure OT extension reasoning needs to be double checked.**

Without malicious OT there is no OPRF, verifiable or not - a server that
cheats the OT learns the client's input and a client that cheats learns
the key.

## 7. Known issues

**Selective failure.** The client checks only commitment `d^{v, k}_{b′^{v, k}}`
against the pad it itself holds. A server that commits wrong pads at some positions is
caught only when `b′^{v, k}` is one of them. When the client moves on with the protocol,
the server learns that `b′^{v, k}` is none of them as the client's check must have succeeded.
With that information, the server has a hint about the client's input.

Currently, the client is designed to stop at the first bad `d^{v, k}_{b′^{v, k}}` it
encounters.

**TODO:** define how many bits can leak and with what probability.

## References

- [Pool] A. Davidson, A. Deo, L. Tremblay Thibault. Pool: A Practical OT-based
  OPRF from Learning with Rounding. CCS 2025.
  https://eprint.iacr.org/2025/1816
- [MR19] D. Masny, P. Rindal. Endemic Oblivious Transfer. CCS 2019.
  https://eprint.iacr.org/2019/706
- [KOS15] M. Keller, E. Orsini, P. Scholl. Actively Secure OT Extension with
  Optimal Overhead. CRYPTO 2015. https://eprint.iacr.org/2015/546
- [BCG+19] E. Boyle, G. Couteau, N. Gilboa, Y. Ishai, L. Kohl, P. Rindal,
  P. Scholl. Efficient Two-Round OT Extension and Silent Non-Interactive
  Secure Computation. CCS 2019. https://eprint.iacr.org/2019/1159
- [RRT23] S. Raghuraman, P. Rindal, T. Tanguy. Expand-Convolute Codes for
  Pseudorandom Correlation Generators from LPN. CRYPTO 2023.
  https://eprint.iacr.org/2023/882
- [YWL+20] K. Yang, C. Weng, X. Lan, J. Zhang, X. Wang. Ferret: Fast Extension
  for Correlated OT with Small Communication. CCS 2020.
  https://eprint.iacr.org/2020/924
- [NP99] M. Naor, B. Pinkas. Oblivious Transfer and Polynomial Evaluation.
  STOC 1999. https://doi.org/10.1145/301250.301312
- CryProt, https://github.com/robinhundt/CryProt
- Plonky3, https://github.com/Plonky3/Plonky3
