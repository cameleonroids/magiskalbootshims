/* ================================================================
 * bs_bootimg.h - legacy Android boot image header (v0 / v1 / v2)
 *
 * This is the format that still carries a second-stage bootloader
 * slot (`second_size` / `second_addr`). AOSP removed that slot in
 * header v3, which is precisely why the shim targets v0-v2: it is
 * the last format where a pre-kernel payload slot exists.
 *
 * On-disk layout (all sections start on a page boundary):
 *
 *   +-------------------------------+
 *   | header            (1 page)    |
 *   +-------------------------------+
 *   | kernel            k pages     |
 *   +-------------------------------+
 *   | ramdisk           r pages     |
 *   +-------------------------------+
 *   | second            s pages     |  <-- the shim lives here
 *   +-------------------------------+
 *   | recovery dtbo/dtb (v1/v2)     |
 *   +-------------------------------+
 *   | [ AVB footer / vbmeta ]       |
 *   +-------------------------------+
 * ================================================================ */
#ifndef BS_BOOTIMG_H
#define BS_BOOTIMG_H

#include <stddef.h>
#include <stdint.h>

#define BOOT_MAGIC            "ANDROID!"
#define BOOT_MAGIC_SIZE       8
#define BOOT_NAME_SIZE        16
#define BOOT_ARGS_SIZE        512
#define BOOT_EXTRA_ARGS_SIZE  1024

#define BOOT_NAME_KERNEL      "kernel"
#define BOOT_NAME_RAMDISK     "ramdisk"
#define BOOT_NAME_SECOND      "second"
#define BOOT_NAME_DTB         "dtb"

/* AOSP reference sizes (system/tools/mkbootimg/include/bootimg.h) */
#define BOOT_HEADER_SIZE_V1   1648
#define BOOT_HEADER_SIZE_V2   1660
#define BOOT_HEADER_SIZE_MAX  4096   /* one page, our hard cap        */

/* Maximum header version this parser understands. */
#define BS_BOOT_MAX_VERSION   2

/* A resolved, pointer-free description of one boot image. */
typedef struct {
    uint32_t header_version;
    uint32_t page_size;
    uint32_t os_version;
    uint32_t header_size;

    /* Physical load addresses requested by the header. */
    uint32_t kernel_addr;
    uint32_t ramdisk_addr;
    uint32_t second_addr;
    uint32_t tags_addr;

    /* Byte offsets of each section relative to the image base. */
    uint64_t kernel_offset;
    uint64_t ramdisk_offset;
    uint64_t second_offset;
    uint64_t tail_offset;     /* recovery-dtbo (v1) or dtb (v2) */

    /* Unpadded byte sizes. */
    uint32_t kernel_size;
    uint32_t ramdisk_size;
    uint32_t second_size;
    uint32_t tail_size;       /* recovery_dtbo_size (v1) / dtb_size (v2) */

    uint8_t  name[BOOT_NAME_SIZE + 1];
    char     cmdline[BOOT_ARGS_SIZE + 1];
    char     extra_cmdline[BOOT_EXTRA_ARGS_SIZE + 1];
    uint32_t tags_id[8];

    /* v1 only: SHA-1 over everything except kernel and second. */
    int      has_id;
} bs_boot_img;

typedef enum {
    BS_BOOT_OK = 0,
    BS_BOOT_ERR_MAGIC,
    BS_BOOT_ERR_VERSION,
    BS_BOOT_ERR_PAGESIZE,
    BS_BOOT_ERR_TRUNCATED,
    BS_BOOT_ERR_TOO_LARGE,
    BS_BOOT_ERR_NO_SECOND,
} bs_boot_status;

/* Parse a boot image header. `base` must point at the ANDROID! magic.
 * All out-params are written only on BS_BOOT_OK. */
bs_boot_status bs_boot_parse(const void *base, size_t avail, bs_boot_img *out);

const char *bs_boot_strerror(bs_boot_status s);

/* Round `n` up to the image page size. */
static inline uint64_t bs_align_page(uint64_t n, uint32_t page) {
    return (n + page - 1) / page * page;
}

#endif /* BS_BOOTIMG_H */