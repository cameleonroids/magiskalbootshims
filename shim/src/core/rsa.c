/* ================================================================
 * rsa.c - RSA PKCS#1 v1.5 signature verification
 * ================================================================ */
#include "bs_rsa.h"
#include "bs_sha256.h"
#include "bs_util.h"

/* --- DER ------------------------------------------------------------ */

int bs_der_next(const uint8_t **p, const uint8_t *end, bs_der_tlv *out) {
    const uint8_t *p0 = *p;
    if (p0 + 2 > end) return -1;

    out->tag = p0[0];
    const uint8_t *lp = p0 + 1;
    uint32_t len;

    if (*lp < 0x80) {
        len = *lp++;
    } else {
        uint8_t nb = (uint8_t)(*lp & 0x7f);
        /* Indefinite length is illegal in DER, and a length field
         * wider than 4 bytes cannot describe anything we accept. */
        if (nb == 0 || nb > 4) return -1;
        lp++;
        if (lp + nb > end) return -1;
        len = 0;
        for (uint8_t i = 0; i < nb; i++) len = (len << 8) | *lp++;
    }
    if ((uint32_t)(end - lp) < len) return -1;

    out->val = lp;
    out->len = len;
    *p = lp + len;
    return 0;
}

int bs_rsa_pub_from_der(bs_rsa_pub *pub, const uint8_t *der, uint32_t len) {
    const uint8_t *p = der, *end = der + len;
    bs_der_tlv seq, mod, exp;

    if (bs_der_next(&p, end, &seq)) return -1;
    if (seq.tag != 0x30) return -1;                 /* SEQUENCE */

    /* The two INTEGERs live inside the SEQUENCE's content, so rewind
     * to the start of that content and parse them from there. */
    const uint8_t *inner = seq.val;
    const uint8_t *inner_end = seq.val + seq.len;

    if (bs_der_next(&inner, inner_end, &mod)) return -1;
    if (mod.tag != 0x02) return -1;                 /* INTEGER */
    if (bs_der_next(&inner, inner_end, &exp)) return -1;
    if (exp.tag != 0x02) return -1;                 /* INTEGER */

    /* DER INTEGERs are signed and minimally encoded. A leading 1-bit
     * marks a negative value, which a modulus or exponent never is.
     * The 0x00 sign byte is present precisely when the first magnitude
     * byte has its high bit set, so it must be tested BEFORE stripping. */
    const uint8_t *nb = mod.val;
    uint32_t nl = mod.len;
    if (nl == 0) return -1;
    if (nb[0] & 0x80) return -1;                    /* negative modulus */
    if (nb[0] == 0x00) {
        if (nl < 2) return -1;                      /* INTEGER 0 */
        nb++; nl--;
        if (!(nb[0] & 0x80)) return -1;             /* non-minimal encoding */
    }
    if (nl == 0 || nl > BS_RSA_MAX_BYTES) return -1;

    const uint8_t *eb = exp.val;
    uint32_t el = exp.len;
    if (el == 0) return -1;
    if (eb[0] & 0x80) return -1;                    /* negative exponent */
    if (eb[0] == 0x00) {
        if (el < 2) return -1;
        eb++; el--;
        if (!(eb[0] & 0x80)) return -1;             /* non-minimal encoding */
    }
    if (el == 0 || el > 4) return -1;               /* we support e < 2^32 */

    /* The exponent must be odd and at least 3; otherwise RSA is broken. */
    if (!(eb[el - 1] & 1)) return -1;

    bs_bn_zero(&pub->n);
    bs_bn_zero(&pub->e);
    if (bs_bn_from_bytes(&pub->n, nb, nl)) return -1;
    if (bs_bn_from_bytes(&pub->e, eb, el)) return -1;
    pub->k = nl;

    /* Reject an even modulus outright -- Montgomery requires odd. */
    if (!(pub->n.d[0] & 1u)) return -1;
    return 0;
}

/* AVB_RSA_F4 -- libavb hard-codes this exponent; the AVB key format
 * has no field for one. */
#define AVB_RSA_F4 65537u

int bs_rsa_pub_from_avb(bs_rsa_pub *pub, const uint8_t *key, uint32_t len) {
    if (!pub || !key || len < 12) return -1;

    const uint32_t bits = ((uint32_t)key[0] << 24) | ((uint32_t)key[1] << 16) |
                          ((uint32_t)key[2] << 8)  |  (uint32_t)key[3];
    /* Only sizes we can actually hold; AVB_RSA_KEY_SIZE_MAX is 8192 but
     * our bignum tops out at 4096. */
    if (bits != 1024 && bits != 2048 && bits != 3072 && bits != 4096) return -1;

    const uint32_t nb = bits / 8;
    if (nb > BS_RSA_MAX_BYTES) return -1;
    if (len < 8u + nb) return -1;

    bs_bn_zero(&pub->n);
    bs_bn_zero(&pub->e);
    if (bs_bn_from_bytes(&pub->n, key + 8, nb)) return -1;
    bs_bn_from_u64(&pub->e, AVB_RSA_F4);
    pub->k = nb;

    /* Montgomery needs an odd modulus; a public modulus always is. */
    if (!(pub->n.d[0] & 1u)) return -1;
    return 0;
}

/* --- PKCS#1 v1.5 --------------------------------------------------- */

/* DER of DigestInfo(SHA-256), RFC 8017 section 9.2 note 1.
 *   SEQUENCE {
 *     SEQUENCE { OID 2.16.840.1.101.3.4.2.1, NULL }
 *     OCTET STRING (32 bytes)
 *   }
 * The final 32 bytes are the digest, filled in at verify time. */
static const uint8_t SHA256_DIGESTINFO_PREFIX[19] = {
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48,
    0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20
};
#define SHA256_DIGESTINFO_LEN (sizeof(SHA256_DIGESTINFO_PREFIX) + 32)

int bs_rsa_ct_eq(const uint8_t *a, const uint8_t *b, size_t n) {
    return bs_memeq_ct(a, b, n);
}

int bs_rsa_verify_sha256_digest(const bs_rsa_pub *pub,
                                const uint8_t digest[BS_SHA256_DIGEST_SIZE],
                                const uint8_t *sig, size_t slen) {
    if (!pub || !pub->k || pub->k > BS_RSA_MAX_BYTES) return 0;

    /* A PKCS#1 v1.5 signature is exactly the modulus size. Reject
     * anything else up front. */
    if (slen != (size_t)pub->k) return 0;

    bs_mont m;
    if (bs_mont_init(&m, &pub->n)) return 0;

    bs_bn s;
    if (bs_bn_from_bytes(&s, sig, slen)) return 0;

    /* RFC 8017 s1: signature representative must satisfy 0 <= s < n. */
    if (bs_bn_cmp(&s, &pub->n) >= 0) return 0;

    /* m = s^e mod n, computed in the Montgomery domain. */
    bs_bn x;
    bs_mont_exp(&x, &s, &pub->e, &m);

    /* Leave the Montgomery domain: multiply by 1 (i.e. by R^-1). */
    bs_bn one;
    bs_bn_from_u64(&one, 1);
    bs_bn em_bn;
    bs_mont_mul(&em_bn, &x, &one, &m);

    uint8_t em[BS_RSA_MAX_BYTES];
    if (pub->k > sizeof(em)) return 0;
    bs_bn_to_bytes(&em_bn, em, pub->k);

    /* EM = 0x00 || 0x01 || PS || 0x00 || T,  len(EM) = k
     *     T = DigestInfo(SHA-256, digest),  len(T) = 51
     * So PS must be exactly k - 3 - 51 bytes of 0xFF. For RSA-4096
     * that is 458 bytes. */
    const size_t tlen = SHA256_DIGESTINFO_LEN;
    if ((size_t)pub->k < tlen + 11) return 0;       /* need PS >= 8 */
    const size_t ps = (size_t)pub->k - tlen - 3;

    if (em[0] != 0x00 || em[1] != 0x01) return 0;

    /* PS must be all 0xFF. Accumulate the OR so the loop is not
     * obviously data-dependent on secret values. */
    uint8_t acc = 0;
    for (size_t i = 0; i < ps; i++) acc |= (uint8_t)(em[2 + i] ^ 0xff);
    if (acc != 0) return 0;

    if (em[2 + ps] != 0x00) return 0;

    const uint8_t *t = em + 3 + ps;
    uint8_t diff = 0;
    for (size_t i = 0; i < sizeof(SHA256_DIGESTINFO_PREFIX); i++)
        diff |= (uint8_t)(t[i] ^ SHA256_DIGESTINFO_PREFIX[i]);
    for (size_t i = 0; i < BS_SHA256_DIGEST_SIZE; i++)
        diff |= (uint8_t)(t[sizeof(SHA256_DIGESTINFO_PREFIX) + i] ^ digest[i]);

    return diff == 0;
}

int bs_rsa_verify_sha256(const bs_rsa_pub *pub,
                         const uint8_t *msg, size_t mlen,
                         const uint8_t *sig, size_t slen) {
    uint8_t digest[BS_SHA256_DIGEST_SIZE];
    bs_sha256(msg, mlen, digest);
    return bs_rsa_verify_sha256_digest(pub, digest, sig, slen);
}