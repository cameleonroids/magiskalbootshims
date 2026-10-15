/* ================================================================
 * bignum.c - fixed-width bignum + Montgomery modular arithmetic
 *
 * Deliberately small and constant-width. Correctness and auditability
 * matter far more than speed here: this runs once per boot.
 * ================================================================ */
#include "bs_bignum.h"
#include "bs_util.h"

typedef unsigned __int128 u128;

void bs_bn_zero(bs_bn *r) { bs_memset(r, 0, sizeof(*r)); }

void bs_bn_copy(bs_bn *r, const bs_bn *a) { *r = *a; }

int bs_bn_is_zero(const bs_bn *a) {
    for (uint32_t i = 0; i < a->len; i++) if (a->d[i]) return 0;
    return 1;
}

int bs_bn_is_one(const bs_bn *a) {
    if (a->len == 0) return 0;
    if (a->d[0] != 1) return 0;
    for (uint32_t i = 1; i < a->len; i++) if (a->d[i]) return 0;
    return 1;
}

int bs_bn_cmp(const bs_bn *a, const bs_bn *b) {
    if (a->len != b->len) return a->len > b->len ? 1 : -1;
    for (uint32_t i = a->len; i-- > 0;) {
        if (a->d[i] != b->d[i]) return a->d[i] > b->d[i] ? 1 : -1;
    }
    return 0;
}

int bs_bn_bit(const bs_bn *a, uint32_t i) {
    uint32_t limb = i >> 6;
    if (limb >= a->len) return 0;
    return (int)((a->d[limb] >> (i & 63)) & 1u);
}

int bs_bn_from_bytes(bs_bn *r, const uint8_t *b, size_t n) {
    if (n > BS_BN_BYTES) return -1;
    bs_bn_zero(r);
    /* Drop leading zeros so `len` reflects significance. */
    size_t off = 0;
    while (off < n && b[off] == 0) off++;
    size_t sig = n - off;
    r->len = (uint32_t)((sig + 7) / 8);
    if (r->len > BS_BN_LIMBS) return -1;
    for (size_t i = 0; i < sig; i++) {
        size_t idx = sig - 1 - i;          /* big-endian index */
        r->d[i >> 3] |= (uint64_t)b[off + idx] << ((i & 7) * 8);
    }
    if (r->len == 0) r->len = 0;
    return 0;
}

void bs_bn_to_bytes(const bs_bn *a, uint8_t *b, size_t n) {
    if (n > BS_BN_BYTES) n = BS_BN_BYTES;
    /* Right-pad with zeros if the value is narrower than the output. */
    size_t sig = (size_t)a->len * 8;
    for (size_t i = 0; i < n; i++) {
        size_t from_end = n - 1 - i;       /* big-endian output index */
        b[i] = 0;
        if (from_end < sig)
            b[i] = (uint8_t)(a->d[from_end >> 3] >> ((from_end & 7) * 8));
    }
}

void bs_bn_from_u64(bs_bn *r, uint64_t v) {
    bs_bn_zero(r);
    r->d[0] = v;
    r->len = v ? 1 : 0;
}

int bs_bn_add(bs_bn *r, const bs_bn *a, const bs_bn *b) {
    uint32_t max = a->len > b->len ? a->len : b->len;
    if (max > BS_BN_LIMBS) return 1;
    uint64_t carry = 0;
    for (uint32_t i = 0; i < max; i++) {
        uint64_t x = i < a->len ? a->d[i] : 0;
        uint64_t y = i < b->len ? b->d[i] : 0;
        u128 s = (u128)x + y + carry;
        r->d[i] = (uint64_t)s;
        carry = (uint64_t)(s >> 64);
    }
    if (carry) {
        if (max == BS_BN_LIMBS) return 1;
        r->d[max] = carry;
        max++;
    }
    r->len = max;
    while (r->len > 0 && r->d[r->len - 1] == 0) r->len--;
    return 0;
}

/* r = a - b, requires a >= b. */
void bs_bn_sub(bs_bn *r, const bs_bn *a, const bs_bn *b) {
    uint64_t borrow = 0;
    uint32_t max = a->len;
    for (uint32_t i = 0; i < max; i++) {
        uint64_t x = a->d[i];
        uint64_t y = i < b->len ? b->d[i] : 0;
        u128 t = (u128)x - y - borrow;
        r->d[i] = (uint64_t)t;
        borrow = (uint64_t)((t >> 64) & 1u);
    }
    r->len = max;
    while (r->len > 0 && r->d[r->len - 1] == 0) r->len--;
}

void bs_bn_dbl(bs_bn *r, const bs_bn *a) {
    uint64_t carry = 0;
    r->len = a->len;
    for (uint32_t i = 0; i < a->len; i++) {
        uint64_t v = a->d[i];
        r->d[i] = (v << 1) | carry;
        carry = v >> 63;
    }
    if (carry) {
        if (r->len < BS_BN_LIMBS) r->d[r->len++] = carry;
    }
}

/* r = 2*a mod n, for a < n.
 *
 * Doubling can produce a 4097-bit intermediate, which does not fit in
 * a bs_bn (64 limbs). We therefore carry into an explicit extra limb
 * and subtract n based on a full comparison. Because a < n the result
 * 2*a is always < 2*n, so exactly one conditional subtraction is
 * required -- including when 2*a lands exactly on n. */
static void bn_mod_dbl(bs_bn *r, const bs_bn *a, const bs_bn *n) {
    uint64_t t[BS_BN_LIMBS + 1];
    bs_memset(t, 0, sizeof(t));

    uint64_t carry = 0;
    for (uint32_t i = 0; i < n->len; i++) {
        uint64_t v = (i < a->len) ? a->d[i] : 0;
        t[i] = (v << 1) | carry;
        carry = v >> 63;
    }
    t[n->len] = carry;

    /* Decide whether t >= n. */
    int ge;
    if (t[n->len]) {
        ge = 1;                                   /* t >= 2^(64*n->len) > n */
    } else {
        int gt = 0, equal = 1;
        for (int64_t i = (int64_t)n->len - 1; i >= 0; i--) {
            if (t[i] != n->d[i]) { gt = (t[i] > n->d[i]); equal = 0; break; }
        }
        ge = gt || equal;
    }

    if (ge) {
        uint64_t borrow = 0;
        for (uint32_t i = 0; i < n->len; i++) {
            u128 d = (u128)t[i] - n->d[i] - borrow;
            t[i] = (uint64_t)d;
            borrow = (uint64_t)((d >> 64) & 1u);
        }
        t[n->len] -= borrow;                      /* clears the extra limb */
    }

    uint32_t len = n->len + 1;
    while (len > 0 && t[len - 1] == 0) len--;
    r->len = len;
    for (uint32_t i = 0; i < len; i++) r->d[i] = t[i];
}

/* Newton-Raphson inverse of an odd 64-bit value, modulo 2^64.
 * Starting from x = a gives one correct bit; each iteration doubles
 * the count, so six iterations cover all 64. */
static uint64_t inv64(uint64_t a) {
    uint64_t x = a;
    for (int i = 0; i < 6; i++) x *= 2u - a * x;
    return x;
}

int bs_mont_init(bs_mont *m, const bs_bn *n) {
    if (n->len == 0) return -1;
    if (!(n->d[0] & 1u)) return -1;       /* modulus must be odd */
    if (n->len > BS_BN_LIMBS) return -1;
    bs_bn_copy(&m->n, n);
    m->k = n->len;
    m->n0inv = (uint64_t)0 - inv64(n->d[0]);
    return 0;
}

/* CIOS Montgomery multiplication: out = a*b*R^-1 mod n. */
void bs_mont_mul(bs_bn *out, const bs_bn *a, const bs_bn *b, const bs_mont *m) {
    const uint32_t k = m->k;
    uint64_t t[BS_BN_LIMBS + 2];
    bs_memset(t, 0, sizeof(uint64_t) * (k + 2));

    for (uint32_t i = 0; i < k; i++) {
        uint64_t bi = i < b->len ? b->d[i] : 0;
        uint64_t c = 0;

        for (uint32_t j = 0; j < k; j++) {
            uint64_t aj = j < a->len ? a->d[j] : 0;
            u128 s = (u128)aj * bi + t[j] + c;
            t[j] = (uint64_t)s;
            c = (uint64_t)(s >> 64);
        }
        u128 s = (u128)t[k] + c;
        t[k] = (uint64_t)s;
        t[k + 1] = (uint64_t)(s >> 64);

        uint64_t u = t[0] * m->n0inv;
        c = 0;
        for (uint32_t j = 0; j < k; j++) {
            u128 p = (u128)u * m->n.d[j] + t[j] + c;
            if (j > 0) t[j - 1] = (uint64_t)p;
            c = (uint64_t)(p >> 64);
        }
        u128 s2 = (u128)t[k] + c;
        t[k - 1] = (uint64_t)s2;
        t[k] = t[k + 1] + (uint64_t)(s2 >> 64);
    }

    /* CIOS leaves the product in t[0..k], where t[k] is an extra high
     * limb that may be set. The true value is always < 2n, so exactly
     * one conditional subtraction of n brings it into [0,n) and clears
     * that extra limb.
     *
     * Critically, t[k] must participate in the comparison. Discarding
     * it first would make a value of n + (small) look like just (small),
     * skip the subtraction, and yield a result off by exactly 2^(64*k).
     */
    const uint64_t top = t[k];
    int ge;
    if (top) {
        ge = 1;                                   /* >= W^k > n */
    } else {
        int gt = 0, equal = 1;
        for (int64_t j = (int64_t)k - 1; j >= 0; j--) {
            if (t[j] != m->n.d[j]) { gt = (t[j] > m->n.d[j]); equal = 0; break; }
        }
        ge = gt || equal;
    }

    if (ge) {
        uint64_t borrow = 0;
        for (uint32_t j = 0; j < k; j++) {
            u128 d = (u128)t[j] - m->n.d[j] - borrow;
            t[j] = (uint64_t)d;
            borrow = (uint64_t)((d >> 64) & 1u);
        }
        /* The final borrow absorbs the extra high limb. */
    }

    bs_bn r;
    bs_bn_zero(&r);
    for (uint32_t i = 0; i < k; i++) r.d[i] = t[i];
    r.len = k;
    while (r.len > 0 && r.d[r.len - 1] == 0) r.len--;
    *out = r;
}

/* Compute R^2 mod n where R = 2^(64*k), by repeated doubling.
 * 2*(64*k) doublings total; for k=64 that is 8192 passes over <=64
 * limbs, i.e. well under a millisecond even on a slow phone core. */
static void mont_r2(bs_bn *out, const bs_mont *m) {
    bs_bn r;
    bs_bn_from_u64(&r, 1);
    const uint32_t bits = m->k * 64;
    for (uint32_t i = 0; i < bits; i++) bn_mod_dbl(&r, &r, &m->n);
    for (uint32_t i = 0; i < bits; i++) bn_mod_dbl(&r, &r, &m->n);
    *out = r;
}

void bs_mont_exp(bs_bn *out, const bs_bn *a, const bs_bn *e, const bs_mont *m) {
    bs_bn r2;
    mont_r2(&r2, m);

    /* acc = mont_mul(a, R2) == a*R mod n -- enters the domain. */
    bs_bn acc;
    bs_mont_mul(&acc, a, &r2, m);

    /* acc = 1 in Montgomery form. */
    bs_bn one;
    bs_bn_from_u64(&one, 1);
    bs_bn res;
    bs_mont_mul(&res, &one, &r2, m);

    /* Find the top set bit of the exponent. */
    uint32_t ebits = 0;
    for (uint32_t i = 0; i < e->len * 64; i++) if (bs_bn_bit(e, i)) ebits = i + 1;
    if (ebits == 0) { *out = res; return; }   /* a^0 == 1 */

    for (int64_t i = (int64_t)ebits - 1; i >= 0; i--) {
        /* Square. */
        bs_bn sq;
        bs_mont_mul(&sq, &res, &res, m);
        res = sq;
        /* Multiply in the base if the bit is set. */
        if (bs_bn_bit(e, (uint32_t)i)) {
            bs_bn pr;
            bs_mont_mul(&pr, &acc, &res, m);
            res = pr;
        }
    }
    *out = res;
}