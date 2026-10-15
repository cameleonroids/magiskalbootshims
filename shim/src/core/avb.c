/* ================================================================
 * avb.c - AVB 2.0 vbmeta verification (RSA + hash descriptors)
 * ================================================================ */
#include "bs_avb.h"
#include "bs_rsa.h"
#include "bs_sha256.h"
#include "bs_util.h"

/* Field offsets within the 256-byte vbmeta header.
 *
 * AvbVBMetaImageHeader is a packed native C struct, so every field here
 * is LITTLE-endian on the hosts that produce vbmeta images. Only the
 * integers inside AvbHashDescriptor are explicitly big-endian, which is
 * why the two accessors below are both needed. */
enum {
    H_MAGIC        = 0,
    H_MAJOR        = 4,
    H_MINOR        = 8,
    H_AUTH_BLOCK   = 12,
    H_AUX_BLOCK    = 20,
    H_ALGO         = 28,
    H_HASH_OFF     = 32,
    H_HASH_SIZE    = 40,
    H_SIG_OFF      = 48,
    H_SIG_SIZE     = 56,
    H_KEY_OFF      = 64,
    H_KEY_SIZE     = 72,
    H_PKMETA_OFF   = 80,
    H_PKMETA_SIZE  = 88,
    H_DESC_OFF     = 96,
    H_DESC_SIZE    = 104,
};

/* All AvbVBMetaImageHeader fields are serialized BIG-endian by avbtool
 * -- verified against avbtool 1.4.0 output, not assumed. */
static uint64_t rd_be64(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | p[i];
    return v;
}
static uint32_t rd_be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  |  (uint32_t)p[3];
}

/* Offset bases. avbtool does not use one common base for every field:
 *
 *   hash / signature        : relative to the end of the 256-byte header
 *   public key / descriptors: relative to the end of the auth block
 *
 * Both were confirmed by locating the structures in real avbtool
 * output: with auth_block == 576 the descriptors land at 256+576+0
 * and the public key at 256+576+200, exactly where the header says. */
#define HDR_END     ((size_t)AVB_VBMETA_HEADER_SIZE)

const char *bs_avb_strerror(bs_avb_status s) {
    switch (s) {
    case BS_AVB_OK:                  return "ok";
    case BS_AVB_ERR_TRUNCATED:       return "vbmeta truncated";
    case BS_AVB_ERR_MAGIC:           return "not an AVB0 vbmeta";
    case BS_AVB_ERR_UNSUPPORTED_ALGO:return "unsupported signature algorithm";
    case BS_AVB_ERR_BAD_SIGNATURE:   return "vbmeta signature invalid";
    case BS_AVB_ERR_KEY_MISMATCH:    return "vbmeta key is not the pinned key";
    case BS_AVB_ERR_NO_KEY:          return "vbmeta carries no public key";
    case BS_AVB_ERR_NO_HASH_DESC:    return "no hash descriptor present";
    case BS_AVB_ERR_DESC_RANGE:      return "descriptor out of range";
    case BS_AVB_ERR_DIGEST_MISMATCH: return "payload digest mismatch";
    }
    return "unknown";
}

/* SHA-256 over the signed region: header || (everything past the auth
 * block). Hashing in two spans avoids copying the whole image. */
static void avb_hash_signed_region(const uint8_t *img, size_t len,
                                   uint64_t auth_block, uint8_t out[32]) {
    bs_sha256_ctx c;
    bs_sha256_init(&c);
    bs_sha256_update(&c, img, AVB_VBMETA_HEADER_SIZE);
    if (len > AVB_VBMETA_HEADER_SIZE + auth_block)
        bs_sha256_update(&c, img + AVB_VBMETA_HEADER_SIZE + auth_block,
                         len - (size_t)(AVB_VBMETA_HEADER_SIZE + auth_block));
    bs_sha256_final(&c, out);
}

/* Locate the AvbHashDescriptor and extract its binding.
 *
 * The fixed head (image_size, hash_algorithm, and the three u32
 * lengths) is at a stable offset, but the trailing partition record
 * moved between avbtool releases -- in avbtool 1.4.0 it is laid out as
 *
 *     +0   image_size      (8)
 *     +8   hash_algorithm  (32)
 *     +40  name_len        (4, BE)   <- not "num_partitions" in 1.4.0
 *     +44  salt_len        (4, BE)
 *     +48  digest_len      (4, BE)
 *     ...  name, salt, digest, laid out backwards from the end
 *
 * Parsing backwards from the end of the descriptor is stable across
 * those shifts, because `num_bytes_following` bounds it exactly. */
static bs_avb_status avb_find_hash_desc(const uint8_t *img, size_t len,
                                        uint64_t desc_abs, uint64_t desc_size,
                                        bs_avb_binding *out) {
    if (desc_size == 0) return BS_AVB_ERR_NO_HASH_DESC;
    if (desc_abs > len || desc_size > len || desc_abs + desc_size > len)
        return BS_AVB_ERR_DESC_RANGE;

    const uint8_t *body = img + desc_abs + 16;      /* skip AvbDescriptor */
    const size_t   blen = (size_t)desc_size - 16;
    if (blen < 8 + 32 + 12) return BS_AVB_ERR_DESC_RANGE;

    const uint64_t name_len   = rd_be32(body + 40);
    const uint32_t salt_len   = rd_be32(body + 44);
    const uint32_t digest_len = rd_be32(body + 48);

    if (name_len == 0 || name_len > 64) return BS_AVB_ERR_DESC_RANGE;
    if (salt_len > 64 || digest_len > 64 || digest_len == 0)
        return BS_AVB_ERR_DESC_RANGE;
    /* The tail must fit: name + salt + digest, laid out backwards. */
    if ((size_t)name_len + salt_len + digest_len > blen) return BS_AVB_ERR_DESC_RANGE;

    const size_t digest_at = blen - digest_len;
    const size_t salt_at   = digest_at - salt_len;
    const size_t name_at   = salt_at - name_len;

    if (out) {
        out->image_size = rd_be64(body);
        bs_memcpy(out->hash_algorithm, body + 8, 32);
        bs_memcpy(out->digest, body + digest_at, digest_len);
        out->digest_size = digest_len;
        if (salt_len) bs_memcpy(out->salt, body + salt_at, salt_len);
        out->salt_size = salt_len;
        bs_memcpy(out->partition, body + name_at, name_len);
        out->partition[name_len] = '\0';
    }
    return BS_AVB_OK;
}

bs_avb_status bs_avb_verify(const void *vbmeta_v, size_t vbmeta_len,
                            const uint8_t *pinned_key, uint32_t pinned_key_len,
                            bs_avb_binding *binding) {
    const uint8_t *img = (const uint8_t *)vbmeta_v;

    if (!img || vbmeta_len < AVB_VBMETA_HEADER_SIZE) return BS_AVB_ERR_TRUNCATED;
    if (bs_memcmp(img + H_MAGIC, AVB_MAGIC, 4) != 0) return BS_AVB_ERR_MAGIC;

    uint64_t auth_block  = rd_be64(img + H_AUTH_BLOCK);
    uint64_t hash_off    = rd_be64(img + H_HASH_OFF);
    uint64_t hash_size   = rd_be64(img + H_HASH_SIZE);
    uint64_t sig_off     = rd_be64(img + H_SIG_OFF);
    uint64_t sig_size    = rd_be64(img + H_SIG_SIZE);
    uint64_t key_off     = rd_be64(img + H_KEY_OFF);
    uint64_t key_size    = rd_be64(img + H_KEY_SIZE);
    uint64_t desc_off    = rd_be64(img + H_DESC_OFF);
    uint64_t desc_size   = rd_be64(img + H_DESC_SIZE);
    uint32_t algo        = rd_be32(img + H_ALGO);

    /* Resolve the two different offset bases into absolute offsets. */
    size_t auth_end = HDR_END + (size_t)auth_block;
    if (auth_block > vbmeta_len || auth_end > vbmeta_len) return BS_AVB_ERR_TRUNCATED;

    size_t hash_abs = HDR_END + (size_t)hash_off;
    size_t sig_abs  = HDR_END + (size_t)sig_off;
    size_t key_abs  = auth_end + (size_t)key_off;
    size_t desc_abs = auth_end + (size_t)desc_off;

    /* We implement SHA256 with RSA, which is what SHA256_RSA2048/4096/8192
     * all use (the RSA size comes from the key). SHA512 would need a
     * SHA-512 implementation we deliberately do not carry. */
    if (algo != AVB_ALGO_SHA256_RSA2048 &&
        algo != AVB_ALGO_SHA256_RSA4096 &&
        algo != AVB_ALGO_SHA256_RSA8192)
        return BS_AVB_ERR_UNSUPPORTED_ALGO;

    if (hash_size != 32) return BS_AVB_ERR_UNSUPPORTED_ALGO;

    /* Every window must lie inside the image. These offsets are signed
     * over, but we still bounds-check before dereferencing. */
    if (hash_size != 32) return BS_AVB_ERR_UNSUPPORTED_ALGO;
    if (hash_abs > vbmeta_len || hash_size > vbmeta_len - hash_abs)
        return BS_AVB_ERR_TRUNCATED;
    if (sig_abs > vbmeta_len || sig_size == 0 || sig_size > vbmeta_len - sig_abs)
        return BS_AVB_ERR_TRUNCATED;

    /* Trust anchor: the key embedded in the vbmeta must be byte-for-byte
     * the key we pinned at build time. Without this, anyone could
     * re-sign a vbmeta with their own key and it would verify. */
    if (!pinned_key || !pinned_key_len) return BS_AVB_ERR_NO_KEY;
    if (key_size == 0) return BS_AVB_ERR_NO_KEY;
    if (key_abs > vbmeta_len || key_size > vbmeta_len - key_abs)
        return BS_AVB_ERR_TRUNCATED;
    if (key_size != pinned_key_len ||
        bs_memcmp(img + key_abs, pinned_key, key_size) != 0)
        return BS_AVB_ERR_KEY_MISMATCH;

    /* The signature covers header || (everything past the auth block).
     * Re-hash that region and compare against the stored hash first: it
     * is far cheaper than RSA and catches corruption immediately. */
    uint8_t digest[32];
    avb_hash_signed_region(img, vbmeta_len, auth_block, digest);
    if (!bs_memeq_ct(digest, img + hash_abs, 32)) return BS_AVB_ERR_BAD_SIGNATURE;

    /* The key embedded in a vbmeta is in AVB's own binary format, not DER. */
    bs_rsa_pub pub;
    if (bs_rsa_pub_from_avb(&pub, img + key_abs, (uint32_t)key_size))
        return BS_AVB_ERR_BAD_SIGNATURE;
    if (sig_size != pub.k) return BS_AVB_ERR_BAD_SIGNATURE;

    /* The RSA signature is over that same digest (PKCS#1 v1.5 embeds the
     * SHA-256 DigestInfo itself, so we hand the verifier the digest
     * rather than re-hashing a non-contiguous region). */
    if (!bs_rsa_verify_sha256_digest(&pub, digest, img + sig_abs, (size_t)sig_size))
        return BS_AVB_ERR_BAD_SIGNATURE;

    return avb_find_hash_desc(img, vbmeta_len, desc_abs, desc_size, binding);
}

bs_avb_status bs_avb_check_payload(const bs_avb_binding *b,
                                   const void *payload, size_t len) {
    if (!b || b->digest_size == 0 || b->digest_size > 64) return BS_AVB_ERR_NO_HASH_DESC;
    /* Only SHA-256 digests are recomputable here; a descriptor asking
     * for anything else must not be silently accepted. */
    /* Padded to the full on-disk field width so the compare below stays
     * in bounds and also enforces that AVB's trailing NULs are present. */
    static const uint8_t sha256_name[32] = "sha256";
    {
        uint8_t diff = 0;
        for (size_t i = 0; i < 32; i++)
            diff |= (uint8_t)(b->hash_algorithm[i] ^ sha256_name[i]);
        if (diff != 0) return BS_AVB_ERR_UNSUPPORTED_ALGO;
    }
    if (b->image_size != 0 && len != b->image_size) return BS_AVB_ERR_DIGEST_MISMATCH;

    /* AVB hashes salt || image, not the image alone. */
    uint8_t d[32];
    bs_sha256_ctx c;
    bs_sha256_init(&c);
    if (b->salt_size) bs_sha256_update(&c, b->salt, b->salt_size);
    bs_sha256_update(&c, payload, len);
    bs_sha256_final(&c, d);

    /* Constant-time compare of the first digest_size bytes. */
    if (!bs_memeq_ct(d, b->digest, b->digest_size)) return BS_AVB_ERR_DIGEST_MISMATCH;
    return BS_AVB_OK;
}