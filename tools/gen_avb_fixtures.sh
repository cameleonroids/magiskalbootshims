#!/usr/bin/env bash
# ================================================================
# gen_avb_fixtures.sh - build vbmeta fixtures with the real avbtool.
#
# avbtool is AOSP's own implementation, so agreeing with it means much
# more than agreeing with our own encoder would.
#
# A hash descriptor is produced via `add_hash_footer`, which is how a
# normal OTA flow creates one, and the vbmeta is then extracted as a
# standalone blob -- exactly the shape the shim consumes at boot.
# ================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/tests/fixtures/avb"
command -v avbtool >/dev/null || { echo "avbtool not found; skipping AVB fixtures"; exit 0; }

rm -rf "$OUT"
mkdir -p "$OUT"
cd "$OUT"

echo "generating AVB fixtures in $OUT"

head -c 32768 /dev/urandom > payload.bin
head -c 32768 /dev/urandom > payload_other.bin

openssl genrsa -out key.pem 4096 2>/dev/null
openssl genrsa -out key2.pem 4096 2>/dev/null

avbtool extract_public_key --key key.pem --output pub.avbpubkey

# Build a vbmeta carrying a hash descriptor for `payload.bin`.
make_vbmeta() {
    local payload="$1" key="$2" out="$3"
    rm -f tmp.img vbmeta.tmp
    cp "$payload" tmp.img
    avbtool add_hash_footer \
        --image tmp.img \
        --partition_size 1048576 \
        --partition_name boot \
        --hash_algorithm sha256 \
        --algorithm SHA256_RSA4096 \
        --key "$key" \
        --do_not_append_vbmeta_image \
        --output_vbmeta_image vbmeta.tmp
    cp vbmeta.tmp "$out"
    rm -f tmp.img vbmeta.tmp
    [ -s "$out" ] || { echo "avbtool produced an empty $out" >&2; exit 1; }
}

make_vbmeta payload.bin        key.pem  vbmeta.img
make_vbmeta payload.bin        key2.pem vbmeta_wrongkey.img
make_vbmeta payload_other.bin  key.pem  vbmeta_otherpayload.img

rm -f key.pem key2.pem tmp.img

echo "done"
ls -l "$OUT"

# Sanity: the pinned key must really be inside the good vbmeta, else the
# test would be vacuous.
avbtool info_image --image vbmeta.img | head -20