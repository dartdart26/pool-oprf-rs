# pool-psi

Private set intersection on top of the [Pool OPRF](../pool-oprf).

Both parties run their elements through one secret function `F_sk`. The server
holds the key, so it applies it to its own set directly. The client cannot, so
its elements go through the OPRF, one oblivious evaluation each. Comparing the
two sets of outputs on the client side gives the intersection and nothing more,
because the outputs are pseudorandom.

`F_sk` behaves like a hash with a key: the same input and key always gives the same
output, and different inputs give unrelated ones. So the comparison of elements is plain
equality on those outputs, like a hash-set lookup.

## Shape of a run

1. The client announces its set size to the server. Both sides size OPRF preprocessing
   from that one number so they cannot disagree.
2. Both run the OPRF's preprocessing — the expensive phase, and the one Pool
   moves off the critical path.
3. The server applies the plaintext PRF to its deduplicated set and sends the
   result. This needs no OTs at all.
4. The client evaluates its own set through the OPRF, in batches of
   `MAX_BATCH_EVALUATIONS`, and looks the results up in what arrived at step 3.

Steps 3 and 4 are the online phase, one round trip per batch.

## What each side learns

The **client** learns the intersection, and how many distinct elements the
server holds.

The **server** learns how many elements the client announced, duplicates
included, since preprocessing is sized to that number. Server doesn't learn
any element or how many matched.

## Cost

One oblivious evaluation per client element, and one masked element sent from
server to client per deduplicated server element.

## Tags

Every run happens under a public tag, a label the server picks. It goes into the
hash, so outputs under one tag mean nothing under another: rotate the tag and an
honest client's old masked set stops matching.
