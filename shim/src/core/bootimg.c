/* ================================================================
 * bootimg.c - legacy Android boot image header parser (v0/v1/v2)
 *
 * All reads go through bs_rd32() which handles unaligned access: the
 * bootloader hands us the image at an arbitrary physical address, so
 * we must never dereference a struct pointer directly.
 * ================================================================ */
#include "bs_bootimg.h"
#include "bs_util.h"
#include "bs_config.h"

/* Field offsets within the header, computed once. These match the
 * AOSP struct layout exactly. */
enum {
    OFF_MAGIC          = 0,
    OFF_KERNEL_SIZE    = 8,
    OFF_KERNEL_ADDR    = 12,
    OFF_RAMDISK_SIZE   = 16,
    OFF_RAMDISK_ADDR   = 20,
    OFF_SECOND_SIZE    = 24,
    OFF_SECOND_ADDR    = 28,
    OFF_TAGS_ADDR      = 32,
    OFF_PAGE_SIZE      = 36,
    OFF_HEADER_VERSION = 40,
    OFF_OS_VERSION     = 44,
    OFF_NAME           = 48,
    OFF_CMDLINE        = 48 + BOOT_NAME_SIZE,
    OFF_ID             = 48 + BOOT_NAME_SIZE + BOOT_ARGS_SIZE,      /* 576 */
    OFF_EXTRA_CMDLINE  = OFF_ID + 32,
    OFF_RECOVERY_DTBO_SIZE   = OFF_EXTRA_CMDLINE + BOOT_EXTRA_ARGS_SIZE,
    OFF_RECOVERY_DTBO_OFFSET = OFF_RECOVERY_DTBO_SIZE + 4,
    OFF_HEADER_SIZE          = OFF_RECOVERY_DTBO_OFFSET + 4,       /* 1648 */
    OFF_DTB_SIZE             = OFF_HEADER_SIZE + 4,                /* 1652 */
    OFF_DTB_ADDR             = OFF_DTB_SIZE + 4,                  /* 1656 */
};

static void copy_cstr(char *dst, size_t dstsz, const void *src, size_t srcsz) {
    size_t n = srcsz < dstsz - 1 ? srcsz : dstsz - 1;
    bs_memcpy(dst, src, n);
    dst[n] = '\0';
    /* Trim at the first NUL so padding bytes do not leak into output. */
    for (size_t i = 0; i < n; i++) {
        if (dst[i] == '\0') { dst[i] = '\0'; return; }
    }
}

bs_boot_status bs_boot_parse(const void *base, size_t avail, bs_boot_img *out) {
    const uint8_t *b = (const uint8_t *)base;

    if (avail < BOOT_HEADER_SIZE_V1)
        return BS_BOOT_ERR_TRUNCATED;

    if (bs_memcmp(b + OFF_MAGIC, BOOT_MAGIC, BOOT_MAGIC_SIZE) != 0)
        return BS_BOOT_ERR_MAGIC;

    uint32_t hdr_ver = bs_rd32(b + OFF_HEADER_VERSION);
    if (hdr_ver > BS_BOOT_MAX_VERSION)
        return BS_BOOT_ERR_VERSION;

    uint32_t page = bs_rd32(b + OFF_PAGE_SIZE);
    /* Android has used 2048 (legacy ARM), 4096 and 16384. Reject
     * anything that is not a power of two or is absurd, because every
     * offset below is derived from it. */
    if (page < 512 || page > 65536 || (page & (page - 1)) != 0)
        return BS_BOOT_ERR_PAGESIZE;

    uint32_t ksz = bs_rd32(b + OFF_KERNEL_SIZE);
    uint32_t rsz = bs_rd32(b + OFF_RAMDISK_SIZE);
    uint32_t ssz = bs_rd32(b + OFF_SECOND_SIZE);
    uint32_t hsz = bs_rd32(b + OFF_HEADER_SIZE);
    if (hsz == 0) hsz = (hdr_ver >= 2) ? BOOT_HEADER_SIZE_V2 : BOOT_HEADER_SIZE_V1;
    if (hsz > BOOT_HEADER_SIZE_MAX) return BS_BOOT_ERR_PAGESIZE;

    /* Tail section: v1 carries a recovery dtbo, v2 carries a dtb. */
    uint32_t tsz;
    if (hdr_ver >= 2) {
        if (avail < BOOT_HEADER_SIZE_V2) return BS_BOOT_ERR_TRUNCATED;
        tsz = bs_rd32(b + OFF_DTB_SIZE);
    } else {
        tsz = bs_rd32(b + OFF_RECOVERY_DTBO_SIZE);
    }

    uint64_t off = page;                                  /* skip header page */
    uint64_t k_off = off; off += bs_align_page(ksz, page);
    uint64_t r_off = off; off += bs_align_page(rsz, page);
    uint64_t s_off = off; off += bs_align_page(ssz, page);
    uint64_t t_off = off; off += bs_align_page(tsz, page);

    /* If the caller gave us a bounded buffer, make sure everything we
     * are about to describe actually fits inside it. */
    if (avail && off > (uint64_t)avail)
        return BS_BOOT_ERR_TRUNCATED;

    out->header_version = hdr_ver;
    out->page_size      = page;
    out->header_size    = hsz;
    out->os_version     = bs_rd32(b + OFF_OS_VERSION);

    out->kernel_addr  = bs_rd32(b + OFF_KERNEL_ADDR);
    out->ramdisk_addr = bs_rd32(b + OFF_RAMDISK_ADDR);
    out->second_addr  = bs_rd32(b + OFF_SECOND_ADDR);
    out->tags_addr    = bs_rd32(b + OFF_TAGS_ADDR);

    out->kernel_offset  = k_off;
    out->ramdisk_offset = r_off;
    out->second_offset  = s_off;
    out->tail_offset    = t_off;

    out->kernel_size  = ksz;
    out->ramdisk_size = rsz;
    out->second_size  = ssz;
    out->tail_size    = tsz;

    copy_cstr((char *)out->name, sizeof(out->name),
              b + OFF_NAME, BOOT_NAME_SIZE);
    copy_cstr(out->cmdline, sizeof(out->cmdline),
              b + OFF_CMDLINE, BOOT_ARGS_SIZE);
    copy_cstr(out->extra_cmdline, sizeof(out->extra_cmdline),
              b + OFF_EXTRA_CMDLINE, BOOT_EXTRA_ARGS_SIZE);

    /* v1+: `id` is a SHA-1 over the image minus kernel and second.
     * v0 leaves it as an opaque timestamp. */
    out->has_id = (hdr_ver >= 1);
    for (int i = 0; i < 8; i++)
        out->tags_id[i] = bs_rd32(b + OFF_ID + i * 4);

    return BS_BOOT_OK;
}

const char *bs_boot_strerror(bs_boot_status s) {
    switch (s) {
    case BS_BOOT_OK:           return "ok";
    case BS_BOOT_ERR_MAGIC:    return "bad ANDROID! magic";
    case BS_BOOT_ERR_VERSION:  return "header version > 2 (no second-stage slot)";
    case BS_BOOT_ERR_PAGESIZE: return "implausible page size";
    case BS_BOOT_ERR_TRUNCATED:return "image truncated";
    case BS_BOOT_ERR_TOO_LARGE:return "image too large";
    case BS_BOOT_ERR_NO_SECOND:return "second-stage slot is empty";
    }
    return "unknown";
}