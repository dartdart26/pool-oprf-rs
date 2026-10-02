# Pool VOPRF: the server's proofs

- [1. Introduction](#1-introduction)
- [2. How to read symbols](#2-how-to-read-symbols)
- [3. What the server can fake](#3-what-the-server-can-fake)
- [4. What the server proves](#4-what-the-server-proves)
  - [Response equation](#response-equation)
  - [Statements](#statements)
  - [Constraints](#constraints)
- [5. Why zero-knowledge](#5-why-zero-knowledge)
- [6. Proof system](#6-proof-system)
- [7. The OT underneath](#7-the-ot-underneath)

## 1. Introduction

This note explains what a server needs to prove for Figures 3 and 4
of the paper to make it a verifiable OPRF.

A run of the protocol gives one output element of `ℤ_p`, i.e 8 bits. An
evaluation is `RUNS_PER_EVALUATION = 16` runs and that gives for 128 bits
of output. The online proof covers one evaluation.

We introduce `pk`, a commitment to `sk`, that the server publishes once. If the
client accepts the response from the server, its output is `F_sk(t, x)` for the
`sk` committed to by `pk`.

Pool runs on two random OTs, and the paper treats them as ideal: a box that
hands each party its outputs and reveals nothing else. This note uses
maliciously secure OT, which behaves like that box even when one party
cheats. [Section 7](#7-the-ot-underneath) says which OT gives that. That
leaves only the server's own messages: `pk` once, `b̄` in preprocessing, `y`
in every evaluation, and the commitments the proofs add. Those are all it
can fake, and the proofs cover them.

## 2. How to read symbols

A *coordinate* is an index `i` into `aᵀsk = Σ_i a_i·sk_i`, i.e. into `a` and
`sk`.

1. No prime versus prime. Unprimed `r`, `b` belong to the binary OTs.
   Primed `r′`, `b′` belong to the 1-out-of-Δ OT.
2. `b` is always an OT choice, handed out at random. A bar, as in `b̄` and
   `b̄′`, marks a correction sent over the wire.
3. Suffixes. `_i` is per coordinate. `_Σ` is summed over all `n` coordinates,
   as in `ã_Σ`, `r_Σ` and `r̃_Σ`.

## 3. What the server can fake

In the paper's protocol the server sends `pk` once, `b̄` in preprocessing
step 4, and `y_0 .. y_{Δ-1}` in the online phase. Since the OTs are ideal
([section 7](#7-the-ot-underneath)), those are its only other messages in
the protocol. Without verifiability, the server can fake any of them undetected,
with the OPRF output still looking random.

These are the messages we focus on in this note.

## 4. What the server proves

### Response equation

The response of the server is `y_0 .. y_{Δ-1}`. Write it out with every
input it depends on:

```
y_j  = ⌈(ã_Σ - j) mod q⌋ + r′_{(j - b̄′) mod Δ}              mod p,   j = 0 .. Δ-1
ã_Σ  = Σ_i ã_i  =  Σ_i sk_i·e_i + r̃_Σ                       mod q
ã_i  = (1 - sk_i)·r_{b_i, i} + sk_i·(e_i - r_{b_i, i})      mod q
     = sk_i·e_i + (1 - sk_i)·r_{b_i, i} - sk_i·r_{b_i, i}   mod q
r̃_Σ  = Σ_i (1 - sk_i)·r_{b_i, i} - Σ_i sk_i·r_{b_i, i}      mod q
b_i  = b̄_i ⊕ sk_i                                           from b̄_i = b_i ⊕ sk_i, preprocessing step 4
```

The first sum of `ã_Σ` needs `e`, which only comes online. `r̃_Σ` needs
`sk` and the masks, so the server computes it at the end of preprocessing
and commits to it as `m`.

The server computes with its own `b_i`, which the client never sees. The
last line writes it through `b̄_i` (which the server sent to the client)
and `sk_i` (which `pk` fixes), so the proof can tie `b_i` to `b̄_i`.

The inputs to the equation, and where the server gets each:

| symbol             | domain        | where the server gets it                                       | in the proof | constraint |
| ------------------ | ------------- | -------------------------------------------------------------- | ------------ | ---------- |
| `j`                | `ℤ_Δ`         | the position in the response, `0 .. Δ-1`                       | public       |            |
| `e_i`              | `ℤ_q`         | from the client, in Request                                    | public       |            |
| `b̄′`               | `ℤ_Δ`         | from the client, in Request                                    | public       |            |
| `b̄_i`              | `{0, 1}`      | its own, sent to the client in preprocessing step 4            | public       |            |
| `sk_i`             | `{0, 1}`      | its own key, from setup                                        | witness      | (K)        |
| `seed_{b_i, i}`    | `{0, 1}^128`  | its block as receiver of the random OT of preprocessing step 2 | witness      | (S)        |
| `r_{b_i, i}`       | `ℤ_q`         | derived from its block `seed_{b_i, i}`, one mask per run       | witness      | (D)        |
| `r′_0 .. r′_{Δ-1}` | each in `ℤ_p` | all Δ pads, as sender of the random OT of preprocessing step 3 | witness      | (P)        |
| `r̃_Σ`              | `ℤ_q`         | its masks, added where `sk_i = 0`, subtracted where `sk_i = 1` | witness      | (T)        |

The client reads one entry of the response, `y_{j*}`, at the index
`j* = r_Σ mod Δ`, where `r_Σ = Σ_i r_{b̄_i, i} mod q` is the sum of the
client's masks. The server does not know `j*`, so it has to prove the
equation for `y_j` at every `j`, not just at `j*`.

The 1-out-of-Δ OT of preprocessing step 3 picks a random index `b′`. It
gives the client `b′` and one pad, `r′_{b′}`. It gives the server all Δ
pads, `r′_0 .. r′_{Δ-1}`, and the server cannot see `b′`.

The client sends `b̄′ = (j* - b′) mod Δ`. The server adds one pad to each
entry `y_j` of the response: `r′_{(j - b̄′) mod Δ}` to `y_j`. For `y_{j*}`
that pad is `r′_{(j* - b̄′) mod Δ} = r′_{b′}` (the client's).

### Statements

The server proves three statements, with one proof for each. The
constraints are in [Constraints](#constraints).

| statement     | when the server proves it   | server messages it covers | constraints         |
| ------------- | --------------------------- | ------------------------- | ------------------- |
| setup         | at setup                    | `pk`                      | (K)                 |
| preprocessing | at the end of preprocessing | `b̄`, `m`                  | (K) (S) (D) (T) (M) |
| online        | with every response         | `y`, `d`                  | (K) (M) (P) (A) (R) |

(S) and (D) could be checked online as well, since `b̄` is public in both
proofs. They are not, because of cost: (S) is `n` commitment openings and
(D) `n` derivations. They need nothing from the request, so they are proved
once, at the end of preprocessing.

The preprocessing proof and the online proof both use `sk` and `r̃_Σ`. To
tie them together, (K) and (M) are in both: (K) opens `pk`, and (M) opens
`m`. Without (M) the server could pass (S), (D) and (T) with the right
masks and then use any `r̃_Σ` in (A).

### Constraints

Eight constraints. What the client holds is public and what only the server
holds is the witness.

A commitment is a hash, and hides its value only if the value is too big
to guess. `sk` is big enough at `n` bits, and so is a block at 128. A pad
or `r̃_Σ` is not, as each is one number in `ℤ_p` or `ℤ_q`. So `d` and `m`
hash a random value in with the committed one and the constraint that opens
them has the random value in the witness. For a pad the random value comes
from the OT. For `m` the server draws it.

```
(K)  sk opens pk,   each sk_i in {0, 1}
```

`pk` is the commitment to the secret key `sk` from setup. Opening it fixes
`sk`, and the bit check makes sure `sk` is binary.

```
(S)  seed_{b_i, i} opens c_{b̄_i ⊕ sk_i, i}      i = 1 .. n
```

The binary OT of preprocessing step 2 hands out 128-bit blocks, not masks:
the client gets two per coordinate, `seed_{0, i}` and `seed_{1, i}`, and
the server one, `seed_{b_i, i}`. `ã_i` is right only if the server's mask
comes from the correct block. The client cannot reveal its blocks to the
server, since it derives the blinding of `e_i` from both, so after step 2 it
sends commitments to both, `c_{0, i}` and `c_{1, i}`. Opening `c_{b_i, i}`
with the server's own `b_i` proves nothing as any server can open the
commitment to the block it holds. So the proof opens `c_{b̄_i ⊕ sk_i, i}`
instead: `b̄_i` is public and `sk_i` is fixed by `pk`, so this is the block
that goes with the committed key and with the `b̄_i` the server sent in
preprocessing, not one the server picks. The OT handed the server one block
only, `seed_{b_i, i}`, so it can open `c_{b_i, i}` and not the other one.
Opening `c_{b̄_i ⊕ sk_i, i}` then means `b̄_i ⊕ sk_i = b_i`.

```
(D)  r_{b_i, i} = Derive(seed_{b_i, i}, run)      i = 1 .. n
```

Both parties derive one mask per run from a block, with the run's index as
input (`derive_r` in the code), and the proof derives it the same way. So
the client commits to its `2n` blocks once per preprocessing, (S) stays `n`
openings however many runs the preprocessing serves, and the masks of every
run come out of (D). `Derive` has to be a hash the proof system computes
cheaply, so it replaces the BLAKE3 derivation the code uses today.

```
(T)  r̃_Σ = Σ_i (1 - 2·sk_i)·r_{b_i, i}      mod q
```

(T) checks that `r̃_Σ` adds the masks where `sk_i = 0` and subtracts those
where `sk_i = 1`, as [Response equation](#response-equation)
derives it.

```
(M)  r̃_Σ opens m
```

`m` is the server's commitment to `r̃_Σ`, sent at the end of preprocessing.
(M) is in the preprocessing proof and in the online proof, so the `r̃_Σ`
that (T) sums from the masks is the `r̃_Σ` the online proof uses in (A).
(T) computes `r̃_Σ` mod `q`, therefore (M) has no range to check.
With `RUNS_PER_EVALUATION` runs, `m` commits to the `r̃_Σ` of all of them.

```
(P)  r′_0 .. r′_{Δ-1} open d_0 .. d_{Δ-1}
```

The server does not know which pad the client holds, so it commits to all Δ
and the proof opens all Δ:

1. After preprocessing step 3 the server sends commitments `d_0 .. d_{Δ-1}`
   to its Δ pads.
2. The client checks `d_{b′}` against its own pad `r′_{b′}`.
3. The proof shows that the pad added to `y_j` opens `d_{(j - b̄′) mod Δ}`.

For `y_{j*}` that is `d_{b′}`, since `(j* - b̄′) mod Δ = b′`. So the pad on
`y_{j*}` is the client's own.

```
(A)  ã_Σ = Σ_i sk_i·e_i + r̃_Σ      mod q
```

(A) checks that `ã_Σ` is computed correctly, in the form of
[Response equation](#response-equation).

```
(R)  y_j = ⌈(ã_Σ - j) mod q⌋ + r′_{(j - b̄′) mod Δ}      mod p,   j = 0 .. Δ-1
```

(R) checks that every `y_j` is computed correctly. The proof has no `mod`
or rounding of its own, but `q`, `p` and `Δ` are powers of two, so each is a
matter of bit arithmetic. (R) checks the arithmetic only. It takes `ã_Σ` and
`r′` as given, without checking that they are in `ℤ_q` and `ℤ_p` - (A) and
(P) fix them.

## 5. Why zero-knowledge

Every part of the witness gives away the key:

- `sk`, directly.
- `seed_{b_i, i}`, and the masks derived from it: the client holds both
  blocks, so seeing which one the server has gives it `b_i`, and
  `sk_i = b̄_i ⊕ b_i`.
- `r̃_Σ`: the client holds every `r_{0, i}` and `r_{1, i}`, so `r̃_Σ` is one
  linear equation mod `q` in the bits of `sk`. Every run adds one, and
  about `n` of them solve for `sk`.
- `r′_0 .. r′_{Δ-1}`: the client holds `r′_{b′}` only, and having the
  other Δ - 1 pads gives it the key too.

Therefore, the proofs must be zero-knowledge.

## 6. Proof system

Any that is zero-knowledge and post-quantum - the choice is left to the
implementation.

## 7. The OT underneath

Everything above treats the two random OTs as ideal and maliciously secure.
CryProt's OTs are, in their malicious variants:

- Base OT: [MR19] with ML-KEM, endemic secure in the random oracle model.
- IKNP extension, the default build: [KOS15]. [MR19] shows it is
  maliciously secure over endemic base OTs.
- Silent OT extension, the `silent-ot` feature: [BCG+19] with the check of
  [YWL+20], on top of [KOS15] base OTs.

Pool uses the malicious variants in both of its builds: [KOS15] for IKNP in
the default build, and silent OT with the `silent-ot` feature.

**Maliciously secure OT extension reasonings needs to be double checked.**

Without malicious OT there is no OPRF, verifiable or not: a server that
cheats the OT learns the client's input, and a client that cheats it learns
the key.

**References.**

- [Pool] A. Davidson, A. Deo, L. Tremblay Thibault. Pool: A Practical OT-based
  OPRF from Learning with Rounding. https://eprint.iacr.org/2025/1816
- [MR19] D. Masny, P. Rindal. Endemic Oblivious Transfer. CCS 2019.
  https://eprint.iacr.org/2019/706
- [KOS15] M. Keller, E. Orsini, P. Scholl. Actively Secure OT Extension with
  Optimal Overhead. CRYPTO 2015. https://eprint.iacr.org/2015/546
- [BCG+19] E. Boyle, G. Couteau, N. Gilboa, Y. Ishai, L. Kohl, P. Scholl.
  Efficient Pseudorandom Correlation Generators: Silent OT Extension and
  More. CRYPTO 2019. https://eprint.iacr.org/2019/448
- [YWL+20] K. Yang, C. Weng, X. Lan, J. Zhang, X. Wang. Ferret: Fast Extension
  for Correlated OT with Small Communication. CCS 2020.
  https://eprint.iacr.org/2020/924
- CryProt, https://github.com/robinhundt/CryProt
- Plonky3, https://github.com/Plonky3/Plonky3
