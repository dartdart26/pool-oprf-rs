# pool-voprf

The server's proofs that make the [Pool OPRF](../pool-oprf) verifiable.

A plain OPRF allows the server to answer with whatever it likes: A verifiable
one has the server commit to its key once and prove in zero knowledge that every
answer came from that key. [`docs/voprf.md`](../docs/voprf.md) reasons about
how to do that for Pool.

The interface in the `pool-voprf` crate is generic such that any backend can be used.
The one implemented now is Plonky3 with Poseidon2 hashing.

```
cargo test -p pool-voprf --release -- --nocapture
```

## Not audited

**This is research code. Nothing in it has been audited, and it is not safe
for production until it is.**
