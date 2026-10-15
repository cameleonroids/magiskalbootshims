/* ================================================================
 * bs_avb.h - Android Verified Boot 2.0 image verification
 *
 * Only the subset the shim needs is implemented: a vbmeta image with
 * an RSA signature over (header || descriptors || aux data), plus an
 * AVB hash descriptor binding a named partition to a SHA-256 digest.
 *
 * Layout of a vbmeta image:
 *
 *   +--------------------------------------------------+
 *   | AvbVBMetaImageHeader                (256 bytes)   |
 *   +--------------------------------------------------+
 *   | hash        (hash_size, usually 32)              |  \
 *   | signature   (signature_size, 256/512/1024)       |  | auth block
 *   | public key  (DER, optional)                      |  /
 *   +--------------------------------------------------+
 *   | descriptors (descriptors_size)                   |
 *   +--------------------------------------------------+
 *   | auxiliary data (auxiliary_data_block_size)       |
 *   +--------------------------------------------------+
 *
 * The signature covers the header and everything AFTER the auth
 * block, which is what libavb does. Note that this means the header
 * is covered too -- the offset fields are authenticated, so an
 * attacker cannot slide the hash or signature windows.
 * ================================================================ */
#ifndef BS_AVB_H
#define BS_AVB_H

#include <stddef.h>
#include <stdint.h>

#define AVB_MAGIC             "AVB0"
#define AVB_VBMETA_HEADER_SIZE 256

/* AvbAlgorithmType */
#define AVB_ALGO_NONE            0
#define AVB_ALGO_SHA256_RSA2048  1
#define AVB_ALGO_SHA256_RSA4096  2
#define AVB_ALGO_SHA256_RSA8192  3
#define AVB_ALGO_SHA512_RSA2048  4
#define AVB_ALGO_SHA512_RSA4096  5
#define AVB_ALGO_SHA512_RSA8192  6

/* AvbDescriptorTag */
#define AVB_DESC_TAG_PROPERTY  0
#define AVB_DESC_TAG_HASH      2
#define AVB_DESC_TAG_KERNEL    4
#define AVB_DESC_TAG_CHAIN     6

typedef struct {
    uint8_t  magic[4];
    uint32_t required_libavb_version_major;
    uint32_t required_libavb_version_minor;
    uint64_t authentication_data_block_size;
    uint64_t auxiliary_data_block_size;
    uint32_t algorithm_type;
    uint64_t hash_offset;
    uint64_t hash_size;
    uint64_t signature_offset;
    uint64_t signature_size;
    uint64_t public_key_offset;
    uint64_t public_key_size;
    uint64_t public_key_metadata_offset;
    uint64_t public_key_metadata_size;
    uint64_t descriptors_offset;
    uint64_t descriptors_size;
    uint64_t rollback_index;
    uint32_t flags;
    uint32_t rollback_index_location;
    uint8_t  release_string[48];
    uint8_t  reserved[80];
} bs_avb_vbmeta;

/* AvbDescriptor -- 16-byte tag-prefixed header. */
typedef struct {
    uint64_t tag;
    uint64_t num_bytes_following;
} bs_avb_descriptor;

/* AvbHashDescriptor body, following the 16-byte prefix. All the
 * integer fields are stored big-endian. */
typedef struct {
    uint64_t image_size;      /* big-endian on disk */
    uint8_t  hash_algorithm[32];   /* "sha256", NUL-padded */
    uint32_t num_partitions;  /* big-endian */
    uint32_t hash_size;       /* big-endian */
    uint8_t  digest[64];
} bs_avb_hash_desc_body;

typedef enum {
    BS_AVB_OK = 0,
    BS_AVB_ERR_TRUNCATED,
    BS_AVB_ERR_MAGIC,
    BS_AVB_ERR_UNSUPPORTED_ALGO,
    BS_AVB_ERR_BAD_SIGNATURE,
    BS_AVB_ERR_KEY_MISMATCH,      /* embedded key != pinned key */
    BS_AVB_ERR_NO_KEY,
    BS_AVB_ERR_NO_HASH_DESC,
    BS_AVB_ERR_DESC_RANGE,
    BS_AVB_ERR_DIGEST_MISMATCH,
} bs_avb_status;

/* A verified digest binding. */
typedef struct {
    uint64_t image_size;
    uint8_t  hash_algorithm[32];  /* NUL-padded, e.g. "sha256" */
    uint8_t  salt[64];            /* AVB hashes salt || image */
    uint32_t salt_size;
    uint8_t  digest[64];
    uint32_t digest_size;
    char     partition[65];
} bs_avb_binding;

const char *bs_avb_strerror(bs_avb_status s);

/* Verify `vbmeta` (of `vbmeta_len` bytes) against a pinned DER public
 * key. Enforces, in order: magic, algorithm supported, key byte-for-
 * byte identical to `pinned`, and RSA signature valid.
 *
 * On success `binding` (may be NULL) receives the first hash
 * descriptor's digest and partition name. */
bs_avb_status bs_avb_verify(const void *vbmeta, size_t vbmeta_len,
                           const uint8_t *pinned_key, uint32_t pinned_key_len,
                           bs_avb_binding *binding);

/* Convenience: compare a payload's digest against a verified binding. */
bs_avb_status bs_avb_check_payload(const bs_avb_binding *b,
                                   const void *payload, size_t len);

#endif /* BS_AVB_H */