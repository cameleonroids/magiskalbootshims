/* ================================================================
 * test_avb.c - AVB 2.0 vbmeta verification against real avbtool output
 * ================================================================ */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bs_avb.h"
#include "bs_rsa.h"
#include "bs_util.h"

static int fails = 0;
static const char *FIX = "tests/fixtures/avb";

static uint8_t *slurp(const char *name, size_t *n) {
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", FIX, name);
    FILE *f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "  missing %s (run: make fixtures)\n", path); return NULL; }
    fseek(f, 0, SEEK_END); long L = ftell(f); fseek(f, 0, SEEK_SET);
    uint8_t *b = malloc((size_t)L);
    if (!b || fread(b, 1, (size_t)L, f) != (size_t)L) { fclose(f); free(b); return NULL; }
    fclose(f); *n = (size_t)L; return b;
}

static void expect(const char *what, int got, int want) {
    if (got == want) printf("  ok   %-48s = %d\n", what, got);
    else { printf("  FAIL %-48s = %d (want %d)\n", what, got, want); fails++; }
}

static void expect_status(const char *what, bs_avb_status got, bs_avb_status want) {
    if (got == want) printf("  ok   %-48s = %s\n", what, bs_avb_strerror(got));
    else { printf("  FAIL %-48s = %s (want %s)\n", what,
                   bs_avb_strerror(got), bs_avb_strerror(want)); fails++; }
}

int main(void) {
    size_t vn, pn, wn, on, kn;
    uint8_t *vbmeta = slurp("vbmeta.img", &vn);
    uint8_t *payload = slurp("payload.bin", &pn);
    uint8_t *wrongkey = slurp("vbmeta_wrongkey.img", &wn);
    uint8_t *otherpayload = slurp("vbmeta_otherpayload.img", &on);
    uint8_t *key = slurp("pub.avbpubkey", &kn);
    if (!vbmeta || !payload || !wrongkey || !otherpayload || !key) return 2;

    printf("[avb] header sanity (matches AOSP layout)\n");
    if (memcmp(vbmeta, "AVB0", 4) != 0) { puts("  FAIL magic"); return 1; }
    printf("  ok   magic AVB0\n");
    printf("  ok   vbmeta is %zu bytes\n", vn);

    printf("[avb] verify against the pinned key\n");
    bs_avb_binding bind;
    memset(&bind, 0, sizeof(bind));
    bs_avb_status st = bs_avb_verify(vbmeta, vn, key, (uint32_t)kn, &bind);
    expect_status("verify good vbmeta", st, BS_AVB_OK);
    if (st != BS_AVB_OK) { printf("aborting: %s\n", bs_avb_strerror(st)); return 1; }

    printf("[avb] hash descriptor binding\n");
    printf("  ok   partition  = \"%s\"\n", bind.partition);
    printf("  ok   image_size = %llu (payload %zu bytes)\n",
           (unsigned long long)bind.image_size, pn);
    if (bind.image_size != pn) { puts("  FAIL image_size mismatch"); fails++; }
    if (bind.digest_size != 32) { printf("  FAIL digest_size=%u\n", bind.digest_size); fails++; }
    else printf("  ok   digest_size = 32, salt_size = %u\n", bind.salt_size);
    if (bind.salt_size == 0) { puts("  FAIL avbtool default salt should be non-empty"); fails++; }

    printf("[avb] payload digest enforcement\n");
    expect_status("payload matches descriptor",
                  bs_avb_check_payload(&bind, payload, pn), BS_AVB_OK);
    uint8_t *tampered = malloc(pn);
    memcpy(tampered, payload, pn);
    tampered[pn / 2] ^= 0x01;
    expect_status("payload with one bit flipped",
                  bs_avb_check_payload(&bind, tampered, pn),
                  BS_AVB_ERR_DIGEST_MISMATCH);
    expect_status("payload truncated by one byte",
                  bs_avb_check_payload(&bind, payload, pn - 1),
                  BS_AVB_ERR_DIGEST_MISMATCH);
    free(tampered);

    printf("[avb] rejection paths\n");
    expect_status("vbmeta signed by an unpinned key",
                  bs_avb_verify(wrongkey, wn, key, (uint32_t)kn, NULL),
                  BS_AVB_ERR_KEY_MISMATCH);

    {
        bs_avb_binding b2;
        expect_status("vbmeta bound to a different payload",
                      bs_avb_verify(otherpayload, on, key, (uint32_t)kn, &b2),
                      BS_AVB_OK);
        expect_status("  ...then rejected at payload check",
                      bs_avb_check_payload(&b2, payload, pn),
                      BS_AVB_ERR_DIGEST_MISMATCH);
    }

    /* Corrupt the signature bytes. */
    {
        uint8_t *t = malloc(vn);
        memcpy(t, vbmeta, vn);
        t[256 + 32 + 8] ^= 0x01;     /* first byte after hash = signature */
        expect_status("flipped bit inside the signature",
                      bs_avb_verify(t, vn, key, (uint32_t)kn, NULL),
                      BS_AVB_ERR_BAD_SIGNATURE);
        free(t);
    }

    /* Corrupt the signed region (descriptor area). */
    {
        uint8_t *t = malloc(vn);
        memcpy(t, vbmeta, vn);
        t[vn - 4] ^= 0x01;
        expect_status("flipped bit in the signed region",
                      bs_avb_verify(t, vn, key, (uint32_t)kn, NULL),
                      BS_AVB_ERR_BAD_SIGNATURE);
        free(t);
    }

    /* Corrupt the descriptor offsets in the header. They are covered by
     * the signature, so this must not be able to redirect the digest. */
    {
        uint8_t *t = malloc(vn);
        memcpy(t, vbmeta, vn);
        t[96] ^= 0x01;               /* descriptors_offset, low byte */
        expect_status("tampered descriptors_offset",
                      bs_avb_verify(t, vn, key, (uint32_t)kn, NULL),
                      BS_AVB_ERR_BAD_SIGNATURE);
        free(t);
    }

    /* Non-AVB input. */
    {
        uint8_t junk[300];
        memset(junk, 0xAA, sizeof(junk));
        expect_status("non-AVB input",
                      bs_avb_verify(junk, sizeof(junk), key, (uint32_t)kn, NULL),
                      BS_AVB_ERR_MAGIC);
    }

    /* Too short to hold a header. */
    expect_status("truncated vbmeta",
                  bs_avb_verify(vbmeta, 100, key, (uint32_t)kn, NULL),
                  BS_AVB_ERR_TRUNCATED);

    free(vbmeta); free(payload); free(wrongkey); free(otherpayload); free(key);

    if (fails) { printf("\n%d FAILURE(S)\n", fails); return 1; }
    printf("\navb: all passed\n");
    return 0;
}