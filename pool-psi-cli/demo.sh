#!/usr/bin/env bash
# Runs both halves against each other: a server holding samples/server-set.txt,
# a client holding samples/client-set.txt.
#
# Usage: demo.sh [--silent-ot] [addr]
set -euo pipefail

cd "$(dirname "$0")"

features=()
ot="IKNP OT extension"
addr=127.0.0.1:4433
while (($#)); do
    case "$1" in
        --silent-ot)
            features=(--features silent-ot)
            ot="silent OT"
            ;;
        -h | --help)
            echo "usage: demo.sh [--silent-ot] [addr]"
            exit 0
            ;;
        -*)
            echo "unknown option: $1" >&2
            exit 2
            ;;
        *) addr="$1" ;;
    esac
    shift
done

work=$(mktemp -d)
log="$work/server.log"
trap 'kill "${server:-}" 2>/dev/null || true; rm -rf "$work"' EXIT

cargo build --release -p pool-psi-cli "${features[@]}"
bin=../target/release/pool-psi-cli

echo "preprocessing with $ot"

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

# It prints this once the socket is open, after masking its whole set. Bail if
# it died instead, or if 30s went by without it getting there.
ready=
for _ in $(seq 300); do
    if grep -q 'listening on' "$log"; then
        ready=1
        break
    fi
    kill -0 "$server" 2>/dev/null || { cat "$log"; exit 1; }
    sleep 0.1
done
[ -n "$ready" ] || { echo "server did not come up within 30s" >&2; cat "$log"; exit 1; }
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
