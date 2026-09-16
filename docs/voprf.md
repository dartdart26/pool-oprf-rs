# Pool VOPRF: the server's proof

- [1. What this is](#1-what-this-is)
- [2. Symbols, and how to read them](#2-symbols-and-how-to-read-them)
- [3. What the server can fake](#3-what-the-server-can-fake)
- [4. What the server proves](#4-what-the-server-proves)
  - [The equation](#the-equation)
  - [The statement](#the-statement)
- [5. Why zero-knowledge](#5-why-zero-knowledge)
- [6. To the full protocol](#6-to-the-full-protocol)
- [7. Which proof system](#7-which-proof-system)
- [8. The OT underneath](#8-the-ot-underneath)

## 1. What this is

This note works out what a server has to prove for Figures 3 and 4
of the paper to make it a verifiable OPRF.

Simplifications: `τ = 1`, so one preprocessing run pays for one evaluation,
and the paper's session id `uid` and counter `ctr` are dropped, since they
only match a message to its preprocessing run. Here we focus on one output
element of `ℤ_p`, i.e. 8 bits. For 128 bits it means it needs to run 16
times.

```
F_sk(t, x) = ⌈aᵀsk⌋_{q, p}      a = RO(t, x) in ℤ_q^n,   sk in {0,1}^n,   output in ℤ_p
n = 482,  q = 4096,  p = 256,  Δ = q / p = 16
⌈v⌋ = ⌈v⌋_{q, p} = nearest integer to v / Δ, ties down
```

We introduce `pk`, a commitment to `sk`, that the server publishes once. If the
client accepts the response from the server, its output is `F_sk(t, x)` for the
`sk` committed to by `pk`.

Pool runs on two random OTs, and the paper treats them as ideal: a box that
hands each party its outputs and reveals nothing else. This note uses
maliciously secure OT, which behaves like that box even when one party
cheats. [Section 8](#8-the-ot-underneath) says which OT gives that. That
leaves the server with three messages in the whole protocol: `pk` once, `b̄`
in preprocessing and `y` in every evaluation. Those are all it can fake, and
the proof covers exactly those.

## 2. Symbols, and how to read them

A *coordinate* is an index `i` into `aᵀsk = Σ_i a_i*sk_i`, i.e. into `a` and
`sk`.

1. No prime versus prime. Unprimed `r`, `b` belong to the binary OTs.
   Primed `r′`, `b′` belong to the 1-out-of-Δ OT.
2. `b` is always an OT choice, handed out at random. A bar, as in `b̄` and
   `b̄′`, marks a correction sent over the wire.
3. Suffixes. `_i` is per coordinate. `_Σ` is summed over all `n` coordinates,
   as in `r_Σ` and `ã_Σ`.

## 3. What the server can fake

The server sends three things in the whole protocol: `pk` once, `b̄` in
preprocessing step 4, and `y_0 .. y_{Δ-1}` in BlindEval. The OTs are ideal
([section 8](#8-the-ot-underneath)), so those are its only messages, and
whatever it does wrong shows up in one of them or not at all. It can fake
any of them undetected, since an OPRF output looks random either way.

## 4. What the server proves

### The equation

The response of the server is `y_0 .. y_{Δ-1}`. Write it out with every
input it depends on:

```
y_j  = ⌈(ã_Σ - j) mod q⌋ + r′_{(j - b̄′) mod Δ}      mod p,   j = 0 .. Δ-1
ã_Σ  = Σ_i ã_i                                      mod q
ã_i  = r_{b_i, i}          if sk_i = 0
ã_i  = e_i - r_{b_i, i}    if sk_i = 1              mod q
b_i  = b̄_i ⊕ sk_i                                   from b̄_i = b_i ⊕ sk_i, preprocessing step 4
```

The server computes with its own `b_i`, which the client never sees. The
last line writes it through `b̄_i` (which the server sent to the client)
and `sk_i` (which `pk` fixes), so the proof can tie `b_i` to `b̄_i`.

The inputs to the equation, and where the server gets each:

| symbol             | where the server gets it                                       | in the proof | constraint |
| ------------------ | -------------------------------------------------------------- | ------------ | ---------- |
| `j`                | the position in the response, `0 .. Δ-1`                       | public       |            |
| `e_i`              | from the client, in Request                                    | public       |            |
| `b̄′`               | from the client, in Request                                    | public       |            |
| `b̄_i`              | its own, sent to the client in preprocessing step 4            | public       |            |
| `sk_i`             | its own key, from setup                                        | witness      | (K)        |
| `r_{b_i, i}`       | one mask, as receiver of the random OT of preprocessing step 2 | witness      | (S)        |
| `r′_0 .. r′_{Δ-1}` | all Δ pads, as sender of the random OT of preprocessing step 3 | witness      | (P)        |

Plus the operations, the sum, `mod q`, the rounding and `mod p`, which the
server could do wrong too - those are constraints (A) and (R).

The client reads one entry of the response, `y_{j*}`, at an index `j*` that
only it knows. The server does not know `j*`, so it has to prove the
equation for `y_j` at every `j`, not just at `j*`.

### The statement

Five constraints. What the client holds is public and what only the server
holds is the witness.

```
(K)  sk opens pk,   each sk_i in {0, 1}
```

`pk` is the commitment to the secret key `sk` from setup. Opening it fixes
`sk`, and the bit check makes sure `sk` is binary.

```
(S)  r_{b_i, i} opens c_{b̄_i ⊕ sk_i, i}      i = 1 .. n
```

`ã_i` is right only if the server used the correct OT mask `r_{b_i, i}`.
That mask is one of the client's two, `r_{0, i}` and `r_{1, i}`, from
preprocessing step 2. The client cannot reveal them to the server, since it
uses both to blind its input in `e_i`, so after step 2 it sends commitments
to both, `c_{0, i}` and `c_{1, i}`. Opening `c_{b_i, i}` with the server's
own `b_i` proves nothing as any server can open the commitment to the mask
it holds. So the proof opens `c_{b̄_i ⊕ sk_i, i}` instead: `b̄_i` is public
and `sk_i` is fixed by `pk`, so this is the mask that goes with the
committed key and with the `b̄_i` the server sent in preprocessing, not one
the server picks.

```
(P)  r′_0 .. r′_{Δ-1} open d_0 .. d_{Δ-1}
```

The client holds one pad, `r′_{b′}`, and must not tell the server which, so
after preprocessing step 3 the server sends commitments `d_0 .. d_{Δ-1}` to
all its Δ pads. It does not know which one the client will check, so it is
forced to commit to the right value for all of them. The client checks
`d_{b′}` against its own pad, so the pad at index `b′` is the client's.

```
(A)  ã_Σ = Σ_i ã_i,   ã_i = r_{b_i, i} if sk_i = 0,   e_i - r_{b_i, i} if sk_i = 1   mod q
```

(A) checks that `ã_Σ` is computed correctly. A circuit has no `if`, so
`ã_i` is written `sk_i*(e_i - r_{b_i, i}) + (1 - sk_i)*r_{b_i, i}`.

```
(R)  y_j = ⌈(ã_Σ - j) mod q⌋ + r′_{(j - b̄′) mod Δ}      mod p,   j = 0 .. Δ-1
```

(R) checks that every `y_j` is computed correctly. The proof has no `mod`
or rounding of its own, but `q`, `p` and `Δ` are powers of two, so each is a
matter of bit arithmetic.

Every value in the equation is fixed, by (K), (S) and (P), and the
equation itself is checked, by (A) and (R). All Δ entries are then what an
honest server would send.

## 5. Why zero-knowledge

Every part of the witness gives away the key:

- `sk`, directly.
- `r_{b_i, i}`: the client holds `r_{0, i}` and `r_{1, i}`, so seeing which
  one the server has gives it `b_i`, and `sk_i = b̄_i ⊕ b_i`.
- `r′_0 .. r′_{Δ-1}`: the client holds `r′_{b′}` only, and having the
  other Δ - 1 pads gives it the key too.

Therefore, the proof must be zero-knowledge.

## 6. To the full protocol

Section 1 simplified to one output element and `τ = 1`. In full, one
evaluation is 16 runs of the protocol, for a 128-bit output, and one
preprocessing serves `τ` evaluations, each with its own masks from the same
OT, so `16·τ` runs. (A), (R) and (P) are proven per run: 16 times per
evaluation, `16·τ` times per preprocessing. (K) and (S) do not depend on the
evaluation and are proven once per preprocessing.

## 7. Which proof system

Any that is zero-knowledge and post-quantum - the choice is left to the
implementation.

## 8. The OT underneath

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
