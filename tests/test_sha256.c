/* ================================================================
 * test_sha256.c - NIST CAVP / RFC 6234 vectors
 * ================================================================ */
#include <stdio.h>
#include <string.h>

#include "bs_sha256.h"
#include "bs_bootimg.h"
#include "bs_util.h"

static int fails = 0;

static void check(const char *name, const char *msg,
                  const uint8_t *got, const char *want_hex) {
    char hex[65];
    for (int i = 0; i < 32; i++) sprintf(hex + i * 2, "%02x", got[i]);
    if (strcmp(hex, want_hex) != 0) {
        printf("  FAIL %s\n    msg  : \"%s\"\n    got  : %s\n    want : %s\n",
               name, msg, hex, want_hex);
        fails++;
    } else {
        printf("  ok   %s\n", name);
    }
}

static void t_vectors(void) {
    uint8_t d[32];
    printf("[sha256] known-answer tests\n");

    bs_sha256("", 0, d);
    check("empty", "", d,
          "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

    bs_sha256("abc", 3, d);
    check("abc", "abc", d,
          "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

    bs_sha256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56, d);
    check("448-bit", "abcdbcde...nopq", d,
          "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");

    /* Exercises the multi-block + streaming paths (1,000,000 'a'). */
    {
        bs_sha256_ctx c;
        bs_sha256_init(&c);
        char buf[1000];
        memset(buf, 'a', sizeof(buf));
        for (int i = 0; i < 1000; i++) bs_sha256_update(&c, buf, sizeof(buf));
        bs_sha256_final(&c, d);
        check("1e6 x 'a'", "<1,000,000 a's>", d,
              "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
    }
}

static void t_streaming(void) {
    printf("[sha256] streaming vs one-shot agreement\n");
    const char *msg = "The quick brown fox jumps over the lazy dog, "
                      "repeated to exercise block boundaries.";
    size_t len = strlen(msg);
    uint8_t one[32], inc[32];
    bs_sha256(msg, len, one);

    bs_sha256_ctx c;
    bs_sha256_init(&c);
    for (size_t i = 0; i < len; i++) bs_sha256_update(&c, msg + i, 1);
    bs_sha256_final(&c, inc);

    if (memcmp(one, inc, 32) != 0) {
        printf("  FAIL byte-at-a-time differs from one-shot\n"); fails++;
    } else {
        printf("  ok   byte-at-a-time matches\n");
    }

    /* Odd chunking (7 bytes) to cross block boundaries unevenly. */
    bs_sha256_init(&c);
    size_t off = 0;
    while (off < len) {
        size_t n = (len - off) < 7 ? (len - off) : 7;
        bs_sha256_update(&c, msg + off, n);
        off += n;
    }
    bs_sha256_final(&c, inc);
    if (memcmp(one, inc, 32) != 0) {
        printf("  FAIL 7-byte chunks differ\n"); fails++;
    } else {
        printf("  ok   7-byte chunks match\n");
    }
}

/* ---- boot image parser ------------------------------------------- */

static void put32(uint8_t *p, uint32_t v) { memcpy(p, &v, 4); }

static void t_bootimg(void) {
    printf("[bootimg] legacy v0/v1/v2 header parsing\n");
    uint8_t img[8192];
    memset(img, 0, sizeof(img));

    const uint32_t PAGE = 2048;
    memcpy(img, BOOT_MAGIC, 8);
    put32(img + 8,  1000);        /* kernel_size  */
    put32(img + 12, 0x40008000);  /* kernel_addr  */
    put32(img + 16, 500);         /* ramdisk_size */
    put32(img + 20, 0x41000000);  /* ramdisk_addr */
    put32(img + 24, 128);         /* second_size  */
    put32(img + 28, 0x42000000);  /* second_addr  */
    put32(img + 32, 0x40000100);  /* tags_addr    */
    put32(img + 36, PAGE);
    put32(img + 40, 2);           /* header_version */
    put32(img + 44, 0x2a000000);  /* os_version: 12.0.0 */
    memcpy(img + 48, "my-device", 9);
    memcpy(img + 64, "console=ttyMSM0 androidboot.hardware=qcom", 40);
    put32(img + 1648 + 4, 64);    /* dtb_size (v2) */

    bs_boot_img bi;
    memset(&bi, 0, sizeof(bi));
    bs_boot_status st = bs_boot_parse(img, sizeof(img), &bi);

    if (st != BS_BOOT_OK) {
        printf("  FAIL parse returned %s\n", bs_boot_strerror(st)); fails++; return;
    }
    printf("  ok   parsed header_version=%u page_size=%u\n",
           bi.header_version, bi.page_size);

    struct { const char *n; uint64_t got, want; } t[] = {
        {"kernel_offset",  bi.kernel_offset,  PAGE},
        {"ramdisk_offset", bi.ramdisk_offset, PAGE + 2048},
        {"second_offset",  bi.second_offset,  PAGE + 2048 + 2048},
        {"tail_offset",    bi.tail_offset,    PAGE + 2048*3},
    };
    for (size_t i = 0; i < sizeof(t)/sizeof(t[0]); i++) {
        if (t[i].got != t[i].want) {
            printf("  FAIL %s = %llu want %llu\n", t[i].n,
                   (unsigned long long)t[i].got, (unsigned long long)t[i].want);
            fails++;
        } else printf("  ok   %s = %llu\n", t[i].n, (unsigned long long)t[i].got);
    }

    if (bi.second_size != 128 || bi.second_addr != 0x42000000) {
        printf("  FAIL second slot not captured\n"); fails++;
    } else printf("  ok   second slot size=128 addr=0x%08x\n", bi.second_addr);

    if (strncmp(bi.cmdline, "console=ttyMSM0", 14) != 0) {
        printf("  FAIL cmdline = \"%s\"\n", bi.cmdline); fails++;
    } else printf("  ok   cmdline captured\n");

    if (strncmp((const char *)bi.name, "my-device", 9) != 0) {
        printf("  FAIL name = \"%s\"\n", (char *)bi.name); fails++;
    } else printf("  ok   name captured\n");

    /* Negative cases. */
    uint8_t bad[8192];
    memcpy(bad, img, sizeof(img));

    memcpy(bad, "NOTANDRO", 8);
    if (bs_boot_parse(bad, sizeof(bad), &bi) != BS_BOOT_ERR_MAGIC) {
        printf("  FAIL bad magic not rejected\n"); fails++;
    } else printf("  ok   bad magic rejected\n");

    memcpy(bad, img, sizeof(img));
    put32(bad + 40, 4);  /* v4 has no second slot */
    if (bs_boot_parse(bad, sizeof(bad), &bi) != BS_BOOT_ERR_VERSION) {
        printf("  FAIL v4 not rejected\n"); fails++;
    } else printf("  ok   v4 rejected (no second-stage slot)\n");

    memcpy(bad, img, sizeof(img));
    put32(bad + 36, 3000);  /* not a power of two */
    if (bs_boot_parse(bad, sizeof(bad), &bi) != BS_BOOT_ERR_PAGESIZE) {
        printf("  FAIL non-pow2 page size not rejected\n"); fails++;
    } else printf("  ok   non-power-of-two page size rejected\n");

    memcpy(bad, img, sizeof(img));
    put32(bad + 16, 100000);  /* ramdisk larger than the buffer */
    if (bs_boot_parse(bad, sizeof(bad), &bi) != BS_BOOT_ERR_TRUNCATED) {
        printf("  FAIL truncation not detected\n"); fails++;
    } else printf("  ok   truncation detected\n");
}

int main(void) {
    t_vectors();
    t_streaming();
    t_bootimg();
    if (fails) { printf("\n%d FAILURE(S)\n", fails); return 1; }
    printf("\nsha256+bootimg: all passed\n");
    return 0;
}