/* ================================================================
 * bs_bignum.h - fixed-width big integers for RSA-4096
 *
 * Fixed width, no heap, no dynamic limbs. Every value is zero-padded
 * to BS_BN_LIMBS limbs internally, which keeps the modular arithmetic
 * branch-free and bounded at the cost of some wasted work on smaller
 * keys. At 4096 bits the exponentiation costs a few tens of
 * milliseconds of SoC time, which is fine for a one-shot boot check.
 * ================================================================ */
#ifndef BS_BIGNUM_H
#define BS_BIGNUM_H

#include <stddef.h>
#include <stdint.h>

/* 64 limbs * 64 bits = 4096 bits, the RSA-4096 modulus size. */
#define BS_BN_LIMBS 64
#define BS_BN_BYTES (BS_BN_LIMBS * 8)

typedef struct {
    uint32_t len;                  /* number of significant limbs */
    uint64_t d[BS_BN_LIMBS];
} bs_bn;

void   bs_bn_zero(bs_bn *r);
void   bs_bn_copy(bs_bn *r, const bs_bn *a);
int    bs_bn_is_zero(const bs_bn *a);
int    bs_bn_is_one(const bs_bn *a);
int    bs_bn_cmp(const bs_bn *a, const bs_bn *b);
int    bs_bn_bit(const bs_bn *a, uint32_t i);

/* Big-endian conversions. from_bytes accepts up to BS_BN_BYTES and
 * left-pads with zeros; to_bytes right-pads. */
int    bs_bn_from_bytes(bs_bn *r, const uint8_t *b, size_t n);
void   bs_bn_to_bytes(const bs_bn *a, uint8_t *b, size_t n);
void   bs_bn_from_u64(bs_bn *r, uint64_t v);

/* r = a + b. Returns 1 on overflow out of BS_BN_LIMBS. */
int    bs_bn_add(bs_bn *r, const bs_bn *a, const bs_bn *b);
/* r = a - b. Requires a >= b. */
void   bs_bn_sub(bs_bn *r, const bs_bn *a, const bs_bn *b);
void   bs_bn_dbl(bs_bn *r, const bs_bn *a);

/* Montgomery context for a fixed odd modulus. */
typedef struct {
    bs_bn    n;         /* modulus, must be odd                       */
    uint64_t n0inv;     /* -n^-1 mod 2^64                             */
    uint32_t k;         /* significant limbs of n                     */
} bs_mont;

int  bs_mont_init(bs_mont *m, const bs_bn *n);

/* out = a * b * R^-1 mod n, where R = 2^(64*k). Both a and b must
 * already be < n. */
void bs_mont_mul(bs_bn *out, const bs_bn *a, const bs_bn *b, const bs_mont *m);

/* out = a^e mod n, computed entirely in the Montgomery domain.
 * a and out may alias. */
void bs_mont_exp(bs_bn *out, const bs_bn *a, const bs_bn *e, const bs_mont *m);

#endif /* BS_BIGNUM_H */