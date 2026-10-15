/* ================================================================
 * bs_sha256.h - FIPS 180-4 SHA-256
 * ================================================================ */
#ifndef BS_SHA256_H
#define BS_SHA256_H

#include <stddef.h>
#include <stdint.h>

#define BS_SHA256_DIGEST_SIZE 32
#define BS_SHA256_BLOCK_SIZE  64

typedef struct {
    uint32_t state[8];
    uint64_t bitlen;
    uint8_t  buf[BS_SHA256_BLOCK_SIZE];
    size_t   buflen;
} bs_sha256_ctx;

void bs_sha256_init(bs_sha256_ctx *c);
void bs_sha256_update(bs_sha256_ctx *c, const void *data, size_t len);
void bs_sha256_final(bs_sha256_ctx *c, uint8_t out[BS_SHA256_DIGEST_SIZE]);
void bs_sha256(const void *data, size_t len, uint8_t out[BS_SHA256_DIGEST_SIZE]);

#endif /* BS_SHA256_H */