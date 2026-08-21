#!/usr/bin/env bash
# Runs both halves against each other: a server holding samples/server-set.txt,
# a client holding samples/client-set.txt.
set -euo pipefail

cd "$(dirname "$0")"
addr="${1:-127.0.0.1:4433}"
work=$(mktemp -d)
log="$work/server.log"
trap 'kill "${server:-}" 2>/dev/null || true; rm -rf "$work"' EXIT

cargo build --release -p pool-psi-cli
bin=../target/release/pool-psi-cli

# A real deployment keeps this: masked sets only mean anything under the key
# that made them. The demo throws it away with the temporary directory.
"$bin" keygen --out "$work/psi.key" >/dev/null

echo "--- server -------------------------------------------------------"
"$bin" serve \
    --listen "$addr" \
    --set samples/server-set.txt \
    --psi-key "$work/psi.key" \
    --cert samples/demo-cert.pem \
    --key samples/demo-key.pem >"$log" 2>&1 &
server=$!

# It prints this once the socket is open. Bail if it died instead.
for _ in $(seq 50); do
    grep -q 'listening on' "$log" && break
    kill -0 "$server" 2>/dev/null || { cat "$log"; exit 1; }
    sleep 0.1
done
cat "$log"

echo
echo "--- client -------------------------------------------------------"
"$bin" lookup \
    --connect "$addr" \
    --set samples/client-set.txt \
    --cert samples/demo-cert.pem

echo
echo "--- server, after ------------------------------------------------"
awk 'f; /listening on/{f=1}' "$log"