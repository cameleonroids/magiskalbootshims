#!/usr/bin/env bash
# ================================================================
# gen_fixtures.sh - build the crypto test vectors used by the host
# tests. Everything is produced with OpenSSL so the expectations come
# from an independent implementation rather than from our own code.
# ================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/tests/fixtures/rsa4096"
mkdir -p "$OUT"

if [ -f "$OUT/pub.der" ] && [ -f "$OUT/sig.bin" ]; then
    echo "fixtures already present in $OUT"
    exit 0
fi

echo "generating RSA-4096 fixtures in $OUT"
cd "$OUT"

openssl genrsa -out key.pem 4096 2>/dev/null
# Raw RSAPublicKey DER -- the same format avbtool writes to .avbpubkey.
openssl rsa -in key.pem -RSAPublicKey_out -outform DER -out pub.der 2>/dev/null

printf 'bootshims4magisk secondary boot image payload' > msg.bin
openssl dgst -sha256 -sign key.pem -out sig.bin msg.bin 2>/dev/null

# A signature over different content, used to prove we check the digest
# and not merely the structure of the padding.
printf 'tampered payload bytes' > other.bin
openssl dgst -sha256 -sign key.pem -out sig_other.bin other.bin 2>/dev/null

# A second key, to prove the shim pins the key rather than trusting
# whatever key travels with the payload.
openssl genrsa -out key2.pem 4096 2>/dev/null
openssl rsa -in key2.pem -RSAPublicKey_out -outform DER -out pub2.der 2>/dev/null
openssl dgst -sha256 -sign key2.pem -out sig2.bin msg.bin 2>/dev/null

rm -f key.pem key2.pem
echo "done:"
ls -l "$OUT"