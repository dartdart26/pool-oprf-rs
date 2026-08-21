# pool-psi-cli

A client and a server for private set intersection, talking over QUIC.

The server holds a set. A client connects with a set of its own and learns which
of its entries the server also has, and how many distinct entries the server
holds in total. The server learns how many entries the client brought, and
nothing else — not one of them, not how many matched.

Entries are opaque UTF-8 strings.

## Usage

Three subcommands, `keygen`, `serve` and `lookup`.

`keygen` writes the PRF key the server masks and evaluates under. It refuses to
overwrite an existing one.

`serve` loads that key, masks its set once at startup, then answers every client
that connects, one session each.

`lookup` prints the entries the client shares with the server's set.

## Set files

UTF-8, one entry per line. Blank lines and lines starting with `#` are ignored,
and surrounding whitespace is trimmed. Entries match on exact bytes.

## Try it

`samples/` has two sets with a 20-entry overlap, plus a certificate, so this
runs with no setup:

```
./pool-psi-cli/demo.sh
```

That runs `keygen` into a temporary directory, starts a server, runs a client
against it, prints both sides and stops the server. The client finds the 20
entries the two sets share; the server reports only how many evaluations it
answered.

## Certificates

QUIC has TLS built in, so the server needs a certificate, for example:

```
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
    -keyout key.pem -out cert.pem -subj /CN=your.host
```

The client is given that certificate as its only trust anchor, so it trusts
exactly that one server, and the name it verifies against has to match.

`samples/demo-cert.pem` and `samples/demo-key.pem` are a self-signed pair for
`localhost`, committed so the samples need no setup. **That private key is in
this repository**, so it authenticates nobody and secures nothing. It exists to
make the demo work.

## Running it in prod

- **Authenticate clients in front of the server.**
- **Keep the key file, and give every replica the same one.** Masked values only
  mean anything under the key that made them.
- **Use one tag per set.** A tag that changes under a set gives an empty
  intersection, not an error.
- **Set `--max-sessions` to what your memory allows.** Each session holds its
  preprocessing, sized to the set its client announced, until it ends.
- **Set `--session-timeout` to fit your sets.** The default might not be suitable for
  your use case.
- **Rate limit outside the server.** `--max-sessions` caps what runs at once and
  nothing else: a client refused for being over it can reconnect immediately, as
  often as it likes.
