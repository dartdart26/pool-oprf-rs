# Verifiable Pool

Simplifications: `tau = 1`, so one preprocessing run pays for one evaluation and
an OT message is the mask itself; and one output element of `Z_p`, 8 bits, as
the paper writes it. The paper repeats the protocol 16 times for 128 bits.

```
F_sk(t, x) = round(a^T sk)        a = RO(t, x) in Z_q^n,   sk in {0,1}^n,   output in Z_p
n = 482,  q = 4096,  p = 256,  delta = q / p = 16
round(v) = nearest integer to v / delta, ties down    (round_zq_to_zp in pool-prf)
```

Verifiable means: the server publishes `pk`, a commitment to `sk`, once. If the
client's Finalize does not abort, its output is `F_sk(t, x)` for the `sk` in
`pk`. No garbage answers, no per-client keys.

A *coordinate* is an index `i` into `a^T sk = sum_i a_i*sk_i`. The `n` binary
OTs are one per coordinate and are the only place the key acts. The single
1-out-of-delta OT delivers the rounded answer and has nothing to do with the key.

## Symbols, and how to read them

1. No prime versus prime. Unprimed `r`, `b` belong to the binary OTs: masks,
   the input side, values in `Z_q`. Primed `r'`, `b'` belong to the
   1-out-of-delta OT.
2. `b` is always an OT choice, handed out at random. A bar marks a correction
   sent over the wire: the difference between that random choice and the
   choice the protocol needs, so the other side can compensate.
3. Suffixes. `_i` is per coordinate. `_sum` is added over all `n`
   coordinates.
4. The three messages, in order: `e` is the request, `y` the response, `z`
   the output.
5. Commitments, added for the VOPRF in Section 3: `pk` to the key, `c` to the
   masks, `d` to the pads. `w` is always a commitment's blinder.

## 1. Figure 3, preprocessing

The paper's order is 1, 2, 3, 4. Step 4 completes step 2, and step 3 is
independent of both, so it is described last.

**Step 1.** Sample a session id.

**Step 2.** `n` binary random OTs, client as sender, server as receiver.
Random OT hands out uniformly random values; nobody chooses anything. The
values are elements of `Z_q`, called *masks* because the client will later add
them to its input entries `a_i` to hide them, one-time-pad style. For OT
number `i`:

|               | client                  | server                |
| ------------- | ----------------------- | --------------------- |
| holds         | `r_{0,i}` and `r_{1,i}` | `b_i` and `r_{b_i,i}` |
| does not know | `b_i`                   | `r_{1-b_i,i}`         |

**Step 4.** Server sends `b_bar_i = b_i xor sk_i` for every `i`. Afterwards:

|               | client                          | server                     |
| ------------- | ------------------------------- | -------------------------- |
| holds         | `r_{0,i}`, `r_{1,i}`, `b_bar_i` | `b_i`, `r_{b_i,i}`, `sk_i` |
| does not know | `b_i`, `sk_i`                   | `r_{1-b_i,i}`              |

`b_bar_i` is a one-time-pad encryption of `sk_i` under the uniform, hidden `b_i`,
so the client learns nothing from it. It does select one of the client's two
masks, `r_{b_bar_i, i}`, which the client, following the paper, calls `r_i`.

**Step 3.** One 1-out-of-delta random OT, server as sender, client as receiver.
The values are elements of `Z_p`, called *pads*. At the end of the online
phase the server will have delta candidate answers and add one pad to each,
so the client can read exactly the candidate whose pad it holds. The client's
choice `b'` is an index in `{0, .., delta-1}`; only the pads are in `Z_p`.
Afterwards:

|               | client                   | server                 |
| ------------- | ------------------------ | ---------------------- |
| holds         | `b'` and `r'_{b'}`       | `r'_0 .. r'_{delta-1}` |
| does not know | the other delta - 1 pads | `b'`                   |

Naming: `b'` is this choice index; `b_bar_i` is the masked key bit of step 4.
The two are unrelated.

**State at the end of preprocessing:**

|               | client                                             | server                                  |
| ------------- | -------------------------------------------------- | --------------------------------------- |
| holds         | `(r_{0,i}, r_{1,i})` for `i = 1..n`, all `b_bar_i` | `sk`, `(b_i, r_{b_i,i})` for `i = 1..n` |
|               | `b'`, `r'_{b'}`                                    | `r'_0 .. r'_{delta-1}`                  |
| does not know | any `b_i`, any `sk_i`, the other delta - 1 pads    | any `r_{1-b_i,i}`, `b'`                 |

Nothing is verifiable yet, but the client now holds three kinds of values it
can hold the server to later: the masks, because it sent them; the pad
`r'_{b'}`, because it received it; and the bits `b_bar_i`, because the server
sent them and they are fixed.

**Where the server could deviate.** Call a value the server *chooses* and
feeds into a step its input, as opposed to values the step hands to it. In a
random OT nobody inputs anything: the functionality generates the choice bit
and the messages itself. So with the OT an ideal random OT, the server's only
input in all of preprocessing is `b_bar`. The paper writes the phase as
`PreProc(sk)`, but `sk` is used only to compute `b_bar`.

| step | server's role         | server input                                 | can deviate?          |
| ---- | --------------------- | -------------------------------------------- | --------------------- |
| 1    | picks session id      | a label                                      | no effect on anything |
| 2    | receiver of random OT | none, `b_i` and `r_{b_i,i}` are handed to it | no                    |
| 3    | sender of random OT   | none, the pads are handed to it              | no                    |
| 4    | sends `b_bar_i`       | `n` bits, its choice                         | yes, the only place   |

Since `b_i` is fixed, choosing `b_bar_i` *is* choosing a key bit,
`sk_i = b_bar_i xor b_i`. So the only question preprocessing raises is whether
that key is the one in `pk`. `b_bar` is never checked on its own: it enters the
proof as a public input to constraint (S) below, proven with the online
response. A wrong `b_bar_i` points the server at a mask it does not hold, and the
proof fails. The real freedom is in the online phase, where the server sends
delta numbers and can put anything in them.

## 2. Figure 4, online

A complete numeric instance, in the same order as the blocks below, is at the
end of this section. Reading each block next to its part of the instance is
the easiest way through.

**Request**, client side. The client does:

1. Hides its input under both masks. The server knows only one, so it sees
   nothing.
2. Adds up the selected masks `r_i` into `r_sum`. That is the blinding it will
   have to strip from the answer later.
3. Defines `b_bar'`, a hint the server will use to arrange its response
   around the one pad the client got in step 3. Explained after BlindEval.

```
a      = RO(t, x)                              in Z_q^n
r_i    = r_{b_bar_i, i}                        the mask b_bar_i selected, in step 4 of preprocessing
e_i    = a_i + r_{0,i} + r_{1,i}   mod q       a_i hidden: the server knows only one mask
r_sum  = sum_i r_i                 mod q       sum of the selected masks over all i
b_bar' = (r_sum mod delta) - b'    mod delta   see point 3; explained after BlindEval
send (t, e, b_bar');   keep (r_sum, r'_{b'})   r'_{b'}: the client's one pad from step 3 in preprecessing, both needed in Finalize
```

**BlindEval**, server side:

```
a_tilde_i   = r_{b_i,i}            if sk_i = 0
a_tilde_i   = e_i - r_{b_i,i}      if sk_i = 1                              mod q
a_tilde_sum = sum_i a_tilde_i                                               mod q
y_j         = round((a_tilde_sum - j) mod q) + r'_{(j - b_bar') mod delta}  mod p,   j = 0 .. delta-1
send (y_0 .. y_{delta-1})
```

Why `a_tilde_sum = a^T sk + r_sum`, one coordinate, using `b_bar_i = b_i xor sk_i`:

```
client sent   e_i = a_i + r_{0,i} + r_{1,i}
selected      r_i = r_{b_bar_i, i}

server, sk_i = 0:  a_tilde_i = r_{b_i,i}        = r_{b_bar_i,i}                              = r_i         since b_i = b_bar_i
server, sk_i = 1:  a_tilde_i = e_i - r_{b_i,i}  = a_i + r_{1-b_i,i}  = a_i + r_{b_bar_i,i}  = a_i + r_i   since 1 - b_i = b_bar_i
```

Either way `a_tilde_i = sk_i*a_i + r_i`: the selected mask always ends up in
the server's sum, and the client never learns whether `a_i` did. Branch-free,
which is how the proof will state it, as constraint (A):

```
a_tilde_sum = sum_i [ sk_i*e_i + (1 - 2*sk_i)*r_{b_i,i} ]     mod q         (A)
```

**From `a_tilde_sum` to the answer**, which is what the `y_j` line and `b_bar'` are
about. Take it in steps.

1. The server holds `a_tilde_sum = a^T sk + r_sum`. The client wants
   `round(a^T sk) = round(a_tilde_sum - r_sum)`. Only the client knows `r_sum`.
2. The server cannot be told `r_sum`: with it, the server would learn
   `a^T sk mod q`, twelve exact bits about the client's input. So instead the
   server offers every candidate `round(a_tilde_sum - j)` and the client must pick one
   without saying which. That is a 1-out-of-something OT.
3. Not all `q` candidates are needed. `round(a_tilde_sum - j)` as `j` runs over `Z_q` is
   a cyclic shift of `0,..,0,1,..,1,..,p-1,..,p-1` with runs of length delta,
   so candidates delta apart differ by exactly one. Write
   `r_sum = k*delta + j*` with `j* = r_sum mod delta`. Then
   `round(a_tilde_sum - j*) = round(a^T sk) + k`, and the client can subtract `k` itself. So
   the server offers only `j = 0 .. delta-1`, and the client wants entry `j*`.
4. The 1-out-of-delta OT for that pick was already run in step 3, as a
   *random* OT: the client got a random index `b'` and the pad `r'_{b'}`, the
   server got all delta pads. To turn the random choice `b'` into the wanted
   choice `j*`, the client sends the difference, `b_bar' = j* - b'`, and the
   server rotates its pads by it: entry `j` gets pad `r'_{(j - b_bar') mod delta}`.
   Entry `j*` then gets pad `r'_{(j* - b_bar')} = r'_{b'}`, the one pad the
   client holds. Every other entry gets a pad the client does not hold.
5. `b'` is uniform and hidden from the server, so `b_bar'` reveals nothing
   about `j*`, and the server does not know which entry the client reads.

This is where the two OT sets meet: `r_sum`, hence `j*`, comes from the step 2
masks selected by step 4, and `b'` comes from step 3.

**Finalize**, client side:

```
j* = r_sum mod delta,    k = (r_sum - j*) / delta
z  = y_{j*} - r'_{b'} - k        mod p
```

Stripping the pad leaves `round(a^T sk + r_sum - j*) = round(a^T sk + k*delta) = round(a^T sk) + k`.

**A complete instance.** Real moduli, `q = 4096`, `p = 256`, `delta = 16`, and
`n = 4` instead of 482 so that every coordinate fits on the page. Values were
drawn at random; `sk = (1, 0, 1, 1)`.

Preprocessing, steps 2, 4, 3:

```
coordinate i              1     2     3     4
step 2  r_{0,i}        1100   516  2089   965    client, mask 0
        r_{1,i}        4058  3682  3868  3109    client, mask 1
        b_i               0     0     1     0    server, random choice
        r_{b_i,i}      1100   516  3868   965    server, the mask it got
step 4  sk_i              1     0     1     1    server's key
        b_bar_i           1     0     0     1    b_i xor sk_i, sent to the client

step 3  pads r'_0 .. r'_15, server:
          199  221    1  228  136  117   52  162   15   11   13    4  195  110  216   14
        client:  b' = 7,  r'_7 = 162
```

Request, client:

```
a_i                    3587  4061  1909  2831    RO(t, x)
r_i = r_{b_bar_i,i}    4058   516  2089  3109    selected mask: mask 1 where b_bar_i = 1, mask 0 where 0
e_i                     553    67  3770  2809    a_i + r_{0,i} + r_{1,i} mod 4096, sent

r_sum  = 4058 + 516 + 2089 + 3109 = 9772 mod 4096 = 1580
j*     = 1580 mod 16 = 12
k      = (1580 - 12) / 16 = 98
b_bar' = (12 - 7) mod 16 = 5                     sent
```

BlindEval, server. Per coordinate, keep the mask if `sk_i = 0`, else
subtract it from `e_i`:

```
i = 1, sk = 1:  a_tilde_1 = e_1 - r_{b_1,1}    = 553 - 1100 mod 4096 = 3549   = a_1 + r_1 = 3587 + 4058 mod 4096
i = 2, sk = 0:  a_tilde_2 = r_{b_2,2}          = 516                      = r_2
i = 3, sk = 1:  a_tilde_3 = e_3 - r_{b_3,3}    = 3770 - 3868 mod 4096 = 3998   = a_3 + r_3 = 1909 + 2089 mod 4096
i = 4, sk = 1:  a_tilde_4 = e_4 - r_{b_4,4}    = 2809 - 965 mod 4096 = 1844   = a_4 + r_4 = 2831 + 3109 mod 4096

a_tilde_sum = 3549 + 516 + 3998 + 1844 = 9907 mod 4096 = 1715
check:  a^T sk = 3587 + 1909 + 2831 = 8327 mod 4096 = 135,
        and 135 + r_sum 1580 = 1715.  ok
```

Then the response, `y_j = round((a_tilde_sum - j) mod 4096) + r'_{(j - b_bar') mod 16} mod 256`:

```
j                        0    1    2    3    4    5    6    7    8    9   10   11   12   13   14   15
1715 - j             1715 1714 1713 1712 1711 1710 1709 1708 1707 1706 1705 1704 1703 1702 1701 1700
round(...)             107  107  107  107  107  107  107  107  107  107  107  106  106  106  106  106
pad index j - 5         11   12   13   14   15    0    1    2    3    4    5    6    7    8    9   10
pad                      4  195  110  216   14  199  221    1  228  136  117   52  162   15   11   13
y_j                    111   46  217   67  121   50   72  108   79  243  224  158   12  121  117  119
```

Finalize, client:

```
y_{j*} = y_12 = 12
z = y_12 - r'_7 - k = 12 - 162 - 98 = -248 mod 256 = 8
check: round(a^T sk) = round(135): 135 / 16 = 8.44, so 8.  ok
```

## 3. What the server proves

For each server-side value: can the server lie, what pins it, and which
constraint says so.

| value         | how the server could lie                   | what pins it                                                            | constraint |
| ------------- | ------------------------------------------ | ----------------------------------------------------------------------- | ---------- |
| `sk`          | any key, or a non-binary "key"             | `pk`, opened in the proof; each `sk_i` shown to be a bit                | (K)        |
| `r_{b_i,i}`   | any value, steering `a_tilde_sum` anywhere | client's commitments to both masks; open the one at `b_bar_i xor sk_i`  | (S)        |
| `a_tilde_sum` | wrong sum                                  | plain arithmetic on public `e` and the witnesses                        | (A)        |
| rounding      | off by one, wrong tie rule                 | high `log p` bits, plus 1 iff the low `log delta` bits exceed `delta/2` | (R)        |
| pads in `y_j` | any pad, on any entry                      | server's commitments to all delta; client checks its own                | (R), (P)   |

The mask row is the crux. If the proof only covered (A), the server would pick
`m` freely and the statement would prove nothing. The client cannot reveal
both masks, since with both the server unblinds `a_i`. So the client commits
to both in preprocessing, the OT carries the blinder along with the mask, and
the proof opens the one the key bit selects:

```
client publishes   c_{0,i} = Com(r_{0,i}; w_{0,i}),   c_{1,i} = Com(r_{1,i}; w_{1,i})
OT message i       (r_{c,i}, w_{c,i})
proof shows        Com(r_{b_i,i}; w_{b_i,i}) = (1 - sk_i)*c_{b_bar_i,i} + sk_i*c_{1-b_bar_i,i}    (S)
```

`b_i` is not in the statement. With `sk` pinned by `pk` and `b_bar` on the wire,
(S) names one commitment per coordinate, and only a server holding that mask
can open it. This holds even if the server cheated the OT and knows both
masks: it is still forced to the one at `b_bar_i xor sk_i`, which is what the
client's `r_sum` accounts for. OT security is a privacy concern, not a
verifiability one.

The pad rows work the same way in reverse. The server must cover all delta
entries, since it does not know `j*`; the client checks the one commitment it
can:

```
server publishes after step 3    d_k = Com_pad(r'_k; w'_k),   k = 0 .. delta-1
client checks by itself          d_{b'} opens to r'_{b'}
proof shows                      y_j = round((a_tilde_sum - j) mod q) + r'_{(j - b_bar') mod delta}    (R)
                                 d_k opens to r'_k                                                     (P)
```

Deriving `w'_k` from the same OT block as `r'_k` lets the client check without
an extra message. Both `Com` and `Com_pad` must be hiding: masks are 12 bits
and pads 8, so a plain hash would be brute-forced.

**The statement**, one instance per evaluation:

```
public:   e, b_bar', y_0..y_{delta-1},  b_bar,  c_{0,i} and c_{1,i} for i in 1..n,  d_0..d_{delta-1},  pk
witness:  sk, w_pk,   r_{b_i,i} and w_{b_i,i} for i in 1..n,   r'_k and w'_k for k in 0..delta-1

(K)  pk = Com_key(sk; w_pk),   sk_i in {0,1}
(S)  Com(r_{b_i,i}; w_{b_i,i}) = (1 - sk_i)*c_{b_bar_i,i} + sk_i*c_{1-b_bar_i,i}
(A)  a_tilde_sum = sum_i [ sk_i*e_i + (1 - 2*sk_i)*r_{b_i,i} ]                   mod q
(R)  y_j         = round((a_tilde_sum - j) mod q) + r'_{(j - b_bar') mod delta}   mod p,   j = 0..delta-1
(P)  d_k         = Com_pad(r'_k; w'_k),                                                    k = 0..delta-1
```

Client, outside the proof: verify it, check `d_{b'}`, run Finalize. Not
proven: anything the client computes; `b_i`; the delta - 1 pads it never uses.
Cost: one key opening, `n` mask openings, `n` multiply-adds, delta rounding
gadgets, delta pad openings. Openings dominate.

Soundness in three steps. `pk` fixes `sk`; (S) then fixes `r_{b_i,i}` to the
client's mask at `b_bar_i xor sk_i`, so (A) gives `a_tilde_sum = a^T sk + r_sum` for the
client's own `a` and `r_sum`. (R), (P) and the client's check of `d_{b'}` give
`y_{j*} = round(a^T sk + r_sum - j*) + r'_{b'}`. Finalize then outputs `round(a^T sk)`,
as in the paper's Appendix D.1.

## 4. Why zero-knowledge

Two witnesses leak the key: `sk` itself, and the delta - 1 pads at `j != j*`.
Continue the instance and suppose the client knew all 16 pads. Stripping
them from the response gives `round(1715 - j)`, the `round(...)` row above:

```
j                0    1    2    3    4    5    6    7    8    9   10   11   12   13   14   15
round(...)     107  107  107  107  107  107  107  107  107  107  107  106  106  106  106  106
```

The value drops by one at `j = 11`, and the drop always sits 8 past
`a_tilde_sum mod 16`: `11 - 8 = 3 = 1715 mod 16`. Together with the
rounded value that pins `a_tilde_sum = 1715` exactly. The client subtracts
`r_sum` and has `a^T sk mod q = 135` with no
rounding: one exact linear equation in the key bits. About `n` of those and
it solves for the key. Theorem 5.2 of the paper relies on these entries being
uniform to the client (game `G_3`, Appendix D.2). A sound but non-ZK proof
exposes random combinations of the witness, which is enough for this attack.

## 5. To the full protocol

- 128-bit output: 16 rows of `a`, so 16 copies of (A), (R), (P) sharing one
  (K) and one set of (S).
- `tau > 1`: the OT message becomes a seed, per-evaluation masks are derived by
  a PRF, and one constraint is added, `r_{b_i,i} = Expand(seed_{b_i,i}, ctr)`. The client
  commits to seeds, not masks, so the PRF sits inside the proof; hence the
  circuit-friendly PRF proposed in `docs/voprf.md`.
- Proof system: unchanged. Zero-knowledge, post-quantum, cheap commitment
  openings. See `docs/voprf.md`, Section 6.
