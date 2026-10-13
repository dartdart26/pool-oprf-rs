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

## 1. Introduction

This note explains what a server needs to prove for Figures 3 and 4
of the paper to make it a verifiable and post-quantum OPRF.

A **run** of the protocol gives one output element of `ℤ_p`, i.e. 8 bits. An
**evaluation** is `RUNS_PER_EVALUATION = 16` runs and that gives 128 bits of
output. A superscript `k` marks the run with
`k = 0 .. RUNS_PER_EVALUATION-1`, as in response `y^k_j`. The online proof
we aim at covers one evaluation.

One preprocessing can be made for more than one evaluation, i.e. a preprocessing
serves `τ` runs and `τ / RUNS_PER_EVALUATION` evaluations.

We introduce `pk`, a commitment to secret key `sk`, that the server
publishes once. If the client is convinced the server response is correct,
it accepts it as `F_sk(t, x)` - the PRF's output on its tag `t` and input
`x`, under the `sk` committed to by `pk`.

Pool runs two kinds of random OT (1-out-of-2 and 1-out-of-Δ) and this note
treats them as ideal: a box that hands each party its outputs and reveals
nothing else. This note uses maliciously secure OT, which behaves like that
box even when either party cheats. [Section 6](#6-the-ot-underneath) talks
more about the underlying OTs.

We call the results expanded from the binary OT blocks **masks**, e.g.
`r^k_{b_i, i}`, and the outputs of the 1-out-of-Δ OTs **pads**, e.g. `r′^k_j`.

## 2. High level design

In the paper's protocol, the server sends only two non-OT messages:
 - `b̄` in preprocessing step 4
 - `y_0 .. y_{Δ-1}` as a response in the online phase

Since the OTs are ideal ([section 6](#6-the-ot-underneath)) and without
verifiability, above are the server's only messages it can fake undetected,
with the OPRF output still looking random.

To prove these non-OT messages, we add the following new messages to the
protocol:

| message                                            | description                                       | direction        | when                            |
| -------------------------------------------------- | ------------------------------------------------- | ---------------- | ------------------------------- |
| `pk`                                               | commitment to the server's `sk`                   | server -> client | setup                           |
| `π_setup`                                          | proof of the setup statement                      | server -> client | setup                           |
| `c_{0, 0} .. c_{0, n-1}`, `c_{1, 0} .. c_{1, n-1}` | commitments to the client's OT blocks             | client -> server | after preprocessing step 2      |
| `d^k_0 .. d^k_{Δ-1}`                               | commitments to the server's pads for each run `k` | server -> client | after preprocessing step 3      |
| `m`                                                | one commitment per evaluation to `r̃^k_Σ`          | server -> client | end of preprocessing            |
| `π_preproc`                                        | proof of the preprocessing statement              | server -> client | end of preprocessing            |
| `π_online`                                         | proof of the online statement                     | server -> client | with each evaluation's response |

## 3. Server proofs

### Response equation

The client's request in run `k` is `e^k_0 .. e^k_{n-1}` and `b̄′^k`.
The response of the server in run `k` is `y^k_0 .. y^k_{Δ-1}`.

```
// the server's online response, one entry per position j of run k
y^k_j  = ⌈(ã^k_Σ - j) mod q⌋ + r′^k_{(j - b̄′^k) mod Δ}                     mod p,   j = 0 .. Δ-1

// the server's sum
// ã^k_i = r^k_{b_i, i} if sk_i = 0 or ã^k_i = e^k_i - r^k_{b_i, i} if sk_i = 1
ã^k_i  = (1 - sk_i)·r^k_{b_i, i} + sk_i·(e^k_i - r^k_{b_i, i})             mod q
ã^k_Σ  = Σ_i ã^k_i  =  Σ_i sk_i·e^k_i + r̃^k_Σ                              mod q
r̃^k_Σ  = Σ_i (1 - 2·sk_i)·r^k_{b_i, i}                                     mod q

// b̄_i sent by the server at the end of preprocessing
b̄_i    = b_i ⊕ sk_i

// the server's OT choice, derived from b̄_i
b_i    = b̄_i ⊕ sk_i

// b̄′^k sent by the client in the request
b̄′^k   = (j*^k - b′^k) mod Δ

// the entry of the response the client reads
j*^k   = r^k_Σ mod Δ
r^k_Σ  = Σ_i r^k_{b̄_i, i}                                                  mod q

// therefore, another way to write y^k_j is
y^k_j  = ⌈(Σ_i sk_i·e^k_i + r̃^k_Σ - j) mod q⌋ + r′^k_{(j - b̄′^k) mod Δ}    mod p
```

One way to look at `y^k_j` is as a sum of two parts. The rounded part comes
from the binary OTs' masks in `r̃^k_Σ`. The other part is the pad
`r′^k_{(j - b̄′^k) mod Δ}` from run `k`'s 1-out-of-Δ OT.

Furthermore, the point of writing `ã_Σ` as above is to separate it into two
terms - one that depends on the online request and one that only depends on
preprocessing. This way, we can do more work in preprocessing and less
during the online phase, making the online proof smaller and faster.

Note that the server does not know `j*` and, therefore, it has to prove the
equation for `y_j` at every `j`, not just at `j*`.

A summary of symbols used:

| symbol                 | domain       | in the proof | constraint |
| ---------------------- | ------------ | ------------ | ---------- |
| `j`                    | `ℤ_Δ`        | public       |            |
| `b̄_i`                  | `{0, 1}`     | public       |            |
| `e^k_i`                | `ℤ_q`        | public       |            |
| `b̄′^k`                 | `ℤ_Δ`        | public       |            |
| `sk_i`                 | `{0, 1}`     | witness      | (K)        |
| `ot_block_{b_i, i}`    | `{0, 1}^128` | witness      | (S)        |
| `r^k_{b_i, i}`         | `ℤ_q`        | witness      | (X)        |
| `r̃^k_Σ`                | `ℤ_q`        | witness      | (T) (M)    |
| `r′^k_0 .. r′^k_{Δ-1}` | `ℤ^Δ_p`      | witness      | (P)        |
| `r^k_Σ`                | `ℤ_q`        | not in it    |            |
| `j*^k`                 | `ℤ_Δ`        | not in it    |            |
| `b′^k`                 | `ℤ_Δ`        | not in it    |            |

### Statements

The server proves three statements, with one proof for each. The
constraints are in [Constraints](#constraints).

| statement     | proof       | when the server proves it       | server messages it covers | constraints         |
| ------------- | ----------- | ------------------------------- | ------------------------- | ------------------- |
| setup         | `π_setup`   | at setup                        | `pk`                      | (K)                 |
| preprocessing | `π_preproc` | at the end of preprocessing     | `b̄`, `m`                  | (K) (S) (X) (T) (M) |
| online        | `π_online`  | with each evaluation's response | `y`, `d`                  | (K) (M) (P) (A) (R) |

### Proving the response

`y_{j*}` is correct only if the server used the right public values, its
secret key `sk`, its own masks, through `r̃_Σ`, and the pad `r′^k_{b′^k}` the
client holds. The secret values each come from something the client trusts,
through a chain of constraints. Read `->` as "pins down":

```
key     pk -(K)-> sk
masks   c_{0, i}, c_{1, i} -(S)-> the server's OT block -(X)-> the server's masks -(T)-> r̃_Σ -(M)-> m
pads    d^k_0 .. d^k_{Δ-1} -(P)-> the server's pads
```

**Key.** `pk` is the server's commitment to `sk`, published at setup.

**Masks.** `c_{0, i}`, `c_{1, i}` (`c` for short) are the client's
commitments to its two OT blocks of each `i`, and `m` is the server's
commitment to `r̃_Σ`. The preprocessing proof pins down `m` all the way from
`c`. The online proof opens the same `m` and, therefore, it uses the same
`r̃_Σ`.

**Pads.** `d^k_0 .. d^k_{Δ-1}` are the server's commitments to its pads of
run `k`. The client checks its own pad `r′^k_{b′^k}` against `d`. The online
proof opens the same `d` and, therefore, the pad on `y_{j*}` is the client's.

With that, every value behind `y_{j*}` is pinned down such that the server
can only send the honest one.

### Constraints

A commitment is a hash and hides its value only if the input value is too big
to guess. For example, `sk` is big enough at `n` bits and so is an OT block
at 128 bits. However, a pad or `r̃_Σ` is not, as each is one number of `ℤ_p`
or `ℤ_q`. Therefore, in such cases, we hash a random value in with the committed
one and the constraint that opens them has the random value in the witness.

#### (K) The key

```
sk opens pk,   each sk_i in {0, 1}
```

`pk` is the commitment to the binary secret key `sk`. Opening `pk` pins down
`sk` and the bit check ensures `sk` is binary.

#### (S) The server's OT block

```
ot_block_{b_i, i} opens c_{b̄_i ⊕ sk_i, i}      i = 0 .. n-1
```

The binary OT of preprocessing step 2 hands out 128-bit OT blocks, not
masks: the client gets two for each `i` (`ot_block_{0, i}` and
`ot_block_{1, i}`) and the server one (`ot_block_{b_i, i}`). Server's
response is right only if the server's mask comes from the correct OT block.
The client cannot reveal its OT blocks to the server, so after step 2 it
sends commitments to both, `c_{0, i}` and `c_{1, i}`. Opening `c_{b_i, i}`
with the server's own `b_i` proves nothing as the server can open the
commitment to the OT block it holds. Therefore, the proof opens
`c_{b̄_i ⊕ sk_i, i}` instead. `b̄_i` is public, `sk_i` is pinned down by `pk`,
and the server holds only `ot_block_{b_i, i}`. Opening it therefore shows
`b̄_i ⊕ sk_i = b_i`: the `b̄_i` the server sent matches its OT choice and the
committed key.

#### (X) The masks

```
r^k_{b_i, i} = Expand(ot_block_{b_i, i}, v·RUNS_PER_EVALUATION + k)      i = 0 .. n-1
```

Both parties expand an OT block into one mask per run. `v` is the
evaluation's number in the preprocessing, and `v·RUNS_PER_EVALUATION + k`
numbers run `k` among all `τ` runs. Every evaluation thereby gets different
masks from the same OT blocks.

#### (T) The mask sum `r̃_Σ`

```
r̃^k_Σ = Σ_i (1 - 2·sk_i)·r^k_{b_i, i}      mod q
```

(T) checks that `r̃_Σ` adds the masks where `sk_i = 0` and subtracts those
where `sk_i = 1`, as [Response equation](#response-equation)
derives it.

#### (M) The commitment `m`

```
r̃^0_Σ .. r̃^{RUNS_PER_EVALUATION-1}_Σ open m
```

`m` is the server's commitment to `r̃_Σ`, for all runs of the evaluation.
(M) is in both the preprocessing and the online proof. Therefore, the `r̃_Σ`
that (T) sums from the masks is the `r̃_Σ` the online proof uses in (A).

#### (P) The pads

```
r′^k_0 .. r′^k_{Δ-1} open d^k_0 .. d^k_{Δ-1}
```

The server does not know which pad the client holds, so the server commits
to all Δ ones and the proof opens them all.

#### (A) The sum `ã_Σ`

```
ã^k_Σ = Σ_i sk_i·e^k_i + r̃^k_Σ      mod q
```

(A) checks that `ã_Σ` is computed correctly as in [Response
equation](#response-equation).

#### (R) The response

```
y^k_j = ⌈(ã^k_Σ - j) mod q⌋ + r′^k_{(j - b̄′^k) mod Δ}      mod p,   j = 0 .. Δ-1
```

(R) checks that every `y_j` is computed correctly. It checks the arithmetic
only - the constraints before it pin the values down.

## 4. Why zero-knowledge

Every part of the witness gives away the key:

- `sk`, directly.
- `ot_block_{b_i, i}`, and the masks expanded from it: the client holds both
  OT blocks, so seeing which one the server has gives it `b_i`, and
  `sk_i = b̄_i ⊕ b_i`.
- `r̃_Σ`: the client holds every `r_{0, i}` and `r_{1, i}`, so `r̃_Σ` is one
  linear equation mod `q` in the bits of `sk`. Every run adds one, and
  about `n` of them solve for `sk`.
- `r′_0 .. r′_{Δ-1}`: the client holds `r′_{b′}` only, and having the
  other Δ - 1 pads exposes `sk`.

Therefore, the proofs must be zero-knowledge.

## 5. Proof system

We can use any proof system that is zero-knowledge and post-quantum - the
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

**References.**

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
