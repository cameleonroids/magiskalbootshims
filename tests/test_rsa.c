/* ================================================================
 * test_rsa.c - RSA-4096 PKCS#1 v1.5 verification against OpenSSL
 *
 * The positive vectors come from `openssl dgst -sha256 -sign`, so a
 * pass means our modular arithmetic, DER parsing and padding check
 * all agree with an independent implementation. The negative cases
 * pin down the failure modes we care about for a boot shim.
 * ================================================================ */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bs_rsa.h"
#include "bs_util.h"

static int fails = 0;
static const char *FIX = "tests/fixtures/rsa4096";

static uint8_t *slurp(const char *name, size_t *n) {
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", FIX, name);
    FILE *f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "  missing fixture %s (run: make fixtures)\n", path); return NULL; }
    fseek(f, 0, SEEK_END); long L = ftell(f); fseek(f, 0, SEEK_SET);
    uint8_t *b = malloc((size_t)L);
    if (!b || fread(b, 1, (size_t)L, f) != (size_t)L) { fclose(f); free(b); return NULL; }
    fclose(f);
    *n = (size_t)L;
    return b;
}

static void expect(const char *what, int got, int want) {
    if (got == want) printf("  ok   %-46s = %d\n", what, got);
    else { printf("  FAIL %-46s = %d (want %d)\n", what, got, want); fails++; }
}

int main(void) {
    size_t dn, sn, mn, on, dn2, sn2;
    uint8_t *der = slurp("pub.der", &dn);
    uint8_t *sig = slurp("sig.bin", &sn);
    uint8_t *msg = slurp("msg.bin", &mn);
    uint8_t *oth = slurp("other.bin", &on);
    uint8_t *sig_other = slurp("sig_other.bin", &on);
    uint8_t *der2 = slurp("pub2.der", &dn2);
    uint8_t *sig2 = slurp("sig2.bin", &sn2);
    if (!der || !sig || !msg || !sig_other || !der2 || !sig2) return 2;

    printf("[rsa] key parsing\n");
    bs_rsa_pub pub;
    if (bs_rsa_pub_from_der(&pub, der, (uint32_t)dn)) { puts("  FAIL DER parse"); return 1; }
    printf("  ok   modulus %u bytes (%u bits)\n", pub.k, pub.k * 8);
    if (pub.k != 512) { puts("  FAIL expected a 4096-bit modulus"); fails++; }

    /* The DER must be consumed exactly -- trailing junk is a bug. */
    {
        bs_der_tlv t; const uint8_t *p = der, *e = der + dn;
        int count = 0;
        while (p < e && bs_der_next(&p, e, &t) == 0) count++;
        if (p != e) { puts("  FAIL trailing bytes in DER"); fails++; }
        else printf("  ok   DER fully consumed (%d TLVs)\n", count);
    }

    printf("[rsa] verification\n");
    expect("verify good sig over good msg",
           bs_rsa_verify_sha256(&pub, msg, mn, sig, sn), 1);

    /* Signature from a different message must not verify against msg. */
    expect("verify sig-over-other-msg against msg",
           bs_rsa_verify_sha256(&pub, msg, mn, sig_other, (size_t)sn), 0);

    /* Signature made with an unpinned key must not verify. */
    expect("verify sig from unpinned key #2",
           bs_rsa_verify_sha256(&pub, msg, mn, sig2, sn2), 0);

    /* Flipped bit inside the signature. */
    {
        uint8_t *t = malloc(sn);
        memcpy(t, sig, sn);
        t[sn / 2] ^= 0x01;
        expect("verify with one bit flipped", bs_rsa_verify_sha256(&pub, msg, mn, t, sn), 0);
        free(t);
    }

    /* Flipped bit inside the message, signature unchanged. Verification
     * must now fail -- that is the whole point of binding the digest
     * to the content. */
    {
        uint8_t *t = malloc(mn);
        memcpy(t, msg, mn);
        t[mn - 1] ^= 0x01;
        expect("verify against a modified message", bs_rsa_verify_sha256(&pub, t, mn, sig, sn), 0);
        expect("  ...and the original still verifies", bs_rsa_verify_sha256(&pub, msg, mn, sig, sn), 1);
        free(t);
    }

    /* Truncated / oversized signatures. */
    expect("verify truncated signature", bs_rsa_verify_sha256(&pub, msg, mn, sig, sn - 1), 0);
    {
        uint8_t *t = calloc(1, sn + 8);
        memcpy(t, sig, sn);
        expect("verify oversized signature", bs_rsa_verify_sha256(&pub, msg, mn, t, sn + 8), 0);
        free(t);
    }

    /* Signature >= modulus must be rejected before exponentiation
     * (RFC 8017 s2.2.2). 0xFF..FF is always > n. */
    {
        uint8_t *t = malloc(sn);
        memset(t, 0xff, sn);
        expect("verify signature >= modulus", bs_rsa_verify_sha256(&pub, msg, mn, t, sn), 0);
        free(t);
    }

    /* All-zero signature. */
    {
        uint8_t *t = calloc(1, sn);
        expect("verify all-zero signature", bs_rsa_verify_sha256(&pub, msg, mn, t, sn), 0);
        free(t);
    }

    printf("[rsa] malformed key rejection\n");
    /* The exponent is the trailing 02 03 01 00 01; flip it to an even
     * value, which must be refused. */
    {
        uint8_t *t = malloc(dn);
        memcpy(t, der, dn);
        t[dn - 1] = 0x02;
        bs_rsa_pub bad;
        expect("reject even public exponent", bs_rsa_pub_from_der(&bad, t, (uint32_t)dn), -1);
        free(t);
    }
    /* Corrupt the outer SEQUENCE length. */
    {
        uint8_t *t = malloc(dn);
        memcpy(t, der, dn);
        t[1] ^= 0xff;
        bs_rsa_pub bad;
        expect("reject corrupt DER length", bs_rsa_pub_from_der(&bad, t, (uint32_t)dn), -1);
        free(t);
    }
    /* Truncate. */
    {
        bs_rsa_pub bad;
        expect("reject truncated DER", bs_rsa_pub_from_der(&bad, der, 8), -1);
    }
    /* Not a DER structure at all. */
    {
        uint8_t junk[16];
        memset(junk, 0xaa, sizeof(junk));
        bs_rsa_pub bad;
        expect("reject non-DER input", bs_rsa_pub_from_der(&bad, junk, sizeof(junk)), -1);
    }

    free(der); free(sig); free(msg); free(sig_other); free(der2); free(sig2);
    (void)oth;

    if (fails) { printf("\n%d FAILURE(S)\n", fails); return 1; }
    printf("\nrsa: all passed\n");
    return 0;
}