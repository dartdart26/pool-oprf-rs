# pool-oprf-rs

Rust implementation of [*Pool: A Practical OT-based OPRF from Learning with
Rounding*](https://eprint.iacr.org/2025/1816) (Davidson, Deo, Tremblay
Thibault), plus a private set intersection protocol built on it: the client
learns the intersection, and each side learns the other's set size.

Pool obliviously evaluates the LWR-based PRF `F_sk(x) = round_{q,p}(H(x)^T * sk)`.
It is round-optimal online - one message each way - because the expensive OT is
input-independent preprocessing that can run ahead of time. The stack is
post-quantum throughout: LWR for the PRF, ML-KEM base OTs, and a
symmetric-key OT extension on top of them.

OT and the networked channels come from
[CryProt](https://github.com/robinhundt/CryProt). Network transport is QUIC, via
s2n-quic.

| crate           | what                                                        |
| --------------- | ----------------------------------------------------------- |
| `pool-prf`      | the plaintext PRF, parameters                               |
| `pool-oprf`     | the OPRF: OT preprocessing, blind evaluation, client/server |
| `pool-psi`      | PSI library on top of pool-oprf                             |
| `pool-psi-cli`  | a generic PSI client and server based on pool-psi           |

## Parameters

The paper's Table 3 row for 128-bit semi-honest security, in
[`pool-prf/src/params.rs`](pool-prf/src/params.rs).

## Running

```
cargo test --workspace      # tests
cargo bench --workspace     # benchmarks
./pool-psi-cli/demo.sh      # a demo of the PSI client and server over the network
```

Preprocessing uses IKNP OT extension by default. The `silent-ot` feature swaps
in silent OT.

```
cargo test --workspace --features silent-ot
cargo bench --workspace --features silent-ot
./pool-psi-cli/demo.sh --silent-ot
```

See [`pool-psi-cli`](pool-psi-cli/README.md) to run client and server separately.

## Security

Research code. Not audited, and not safe for production until it is.

## Roadmap

This is still experimental and a lot of things can be improved, optimized and added.
Treat as work in progress.
