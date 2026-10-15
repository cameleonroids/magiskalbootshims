/* ================================================================
 * bs_util.h - freestanding primitives + debug logging
 *
 * The shim runs before the kernel. There is no libc, no syscalls
 * and no stdio. Everything here is self-contained so the same
 * source builds for the target and for host-side unit tests.
 * ================================================================ */
#ifndef BS_UTIL_H
#define BS_UTIL_H

#include <stddef.h>
#include <stdint.h>

void  *bs_memcpy(void *dst, const void *src, size_t n);
void  *bs_memset(void *dst, int c, size_t n);
int    bs_memcmp(const void *a, const void *b, size_t n);
size_t bs_strlen(const char *s);
int    bs_strcmp(const char *a, const char *b);

/* Constant-time compare -- used for digests and MAC-like checks. */
int bs_memeq_ct(const void *a, const void *b, size_t n);

/* Little-endian unaligned loads. The shim reads structures that were
 * written by a host tool, so we must not assume alignment. */
static inline uint16_t bs_rd16(const void *p) {
    const uint8_t *b = (const uint8_t *)p;
    return (uint16_t)(b[0] | ((uint16_t)b[1] << 8));
}
static inline uint32_t bs_rd32(const void *p) {
    const uint8_t *b = (const uint8_t *)p;
    return (uint32_t)b[0] | ((uint32_t)b[1] << 8) |
           ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
}
static inline uint64_t bs_rd64(const void *p) {
    const uint64_t lo = bs_rd32(p);
    const uint64_t hi = bs_rd32((const uint8_t *)p + 4);
    return lo | (hi << 32);
}

/* ---- debug logging ---------------------------------------------------
 * On the target these write to the bootloader-provided UART if the
 * board layer registered one, otherwise they are no-ops. On host
 * builds they go to stderr.
 * --------------------------------------------------------------- */

typedef enum {
    BS_LOG_NONE = 0,
    BS_LOG_ERROR,
    BS_LOG_WARN,
    BS_LOG_INFO,
    BS_LOG_DEBUG
} bs_log_level;

void bs_log_set(bs_log_level lvl);
void bs_log_set_sink(void (*sink)(const char *msg));
void bs_log(bs_log_level lvl, const char *fmt, ...);

#define bs_err(...)   bs_log(BS_LOG_ERROR, __VA_ARGS__)
#define bs_warn(...)  bs_log(BS_LOG_WARN,  __VA_ARGS__)
#define bs_info(...)  bs_log(BS_LOG_INFO,  __VA_ARGS__)
#define bs_dbg(...)   bs_log(BS_LOG_DEBUG, __VA_ARGS__)

/* ---- halt ------------------------------------------------------------ */

void bs_halt(void) __attribute__((noreturn));

/* Provided by the board layer. Writes a NUL-terminated string to the
 * bootloader-provided console if one is wired up. */
void bs_uart_puts(const char *s);

#endif /* BS_UTIL_H */