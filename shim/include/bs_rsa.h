/* ================================================================
 * bs_rsa.h - RSA signature verification (PKCS#1 v1.5 / SHA-256)
 *
 * This is what AVB's SHA256_RSAxxxx algorithms use, and it is the
 * format Samsung's own vbmeta images are signed with. Public keys are
 * supplied as DER-encoded RSAPublicKey, which is exactly what
 * `avbtool extract_public_key` emits as a .avbpubkey file.
 * ================================================================ */
#ifndef BS_RSA_H
#define BS_RSA_H

#include <stddef.h>
#include <stdint.h>

#include "bs_bignum.h"
#include "bs_config.h"
#include "bs_sha256.h"

typedef struct {
    bs_bn    n;
    bs_bn    e;
    uint32_t k;          /* modulus size in bytes */
} bs_rsa_pub;

/* --- minimal DER reader -------------------------------------------
 * Enough of X.690 to walk an RSAPublicKey. Everything is bounds
 * checked; no pointer is ever advanced past `end`.
 * --------------------------------------------------------------- */

typedef struct {
    uint8_t              tag;
    const uint8_t       *val;
    uint32_t             len;
} bs_der_tlv;

/* Reads one TLV at *p, advancing p past it. Returns 0 on success. */
int bs_der_next(const uint8_t **p, const uint8_t *end, bs_der_tlv *out);

/* --- key handling -------------------------------------------------- */

/* Parse a DER RSAPublicKey:
 *   RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
 * Rejects a leading 0x00 sign byte correctly, rejects non-positive
 * exponents, and rejects anything larger than BS_RSA_MAX_BYTES.
 * Returns 0 on success. */
int bs_rsa_pub_from_der(bs_rsa_pub *pub, const uint8_t *der, uint32_t len);

/* Parse a key in AVB's own binary format, which is what
 * `avbtool extract_public_key` writes to a .avbpubkey file:
 *
 *   offset 0 : uint32 key_num_bits          (big-endian)
 *   offset 4 : uint32 n0inv                 (big-endian, unused here)
 *   offset 8 : modulus, key_num_bits/8 bytes (big-endian)
 *   ...      : rr = n^-1 mod 2^key_num_bits (unused here)
 *
 * Note AVB does not store an exponent at all: libavb hard-codes F4
 * (65537), so this does too. Returns 0 on success. */
int bs_rsa_pub_from_avb(bs_rsa_pub *pub, const uint8_t *key, uint32_t len);

/* --- verification --------------------------------------------------- */

/* Verify a PKCS#1 v1.5 signature over SHA-256(msg).
 * Returns 1 on success, 0 on any failure (bad padding, wrong digest,
 * malformed signature, out-of-range signature). */
int bs_rsa_verify_sha256(const bs_rsa_pub *pub,
                         const uint8_t *msg, size_t mlen,
                         const uint8_t *sig, size_t slen);

/* Same, but the caller has already computed SHA-256(msg). AVB signs a
 * header and a trailer region that are not contiguous in memory, so the
 * digest has to be assembled by streaming before the RSA step; passing
 * the digest directly avoids needing a contiguous copy. */
int bs_rsa_verify_sha256_digest(const bs_rsa_pub *pub,
                                const uint8_t digest[BS_SHA256_DIGEST_SIZE],
                                const uint8_t *sig, size_t slen);

/* Constant-time equality of two byte ranges. */
int bs_rsa_ct_eq(const uint8_t *a, const uint8_t *b, size_t n);

#endif /* BS_RSA_H */