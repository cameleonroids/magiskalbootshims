/* ================================================================
 * util.c - freestanding primitives
 * ================================================================ */
#include "bs_util.h"

#ifndef BS_HOST_BUILD
#include <stdarg.h>
#endif

void *bs_memcpy(void *dst, const void *src, size_t n) {
    uint8_t *d = (uint8_t *)dst;
    const uint8_t *s = (const uint8_t *)src;
    /* Word-at-a-time when both ends share alignment; the shim copies
     * multi-megabyte payloads so this matters. */
    if ((((uintptr_t)d | (uintptr_t)s) & 7u) == 0) {
        while (n >= 8) {
            uint64_t w;
            __builtin_memcpy(&w, s, 8);
            __builtin_memcpy(d, &w, 8);
            d += 8; s += 8; n -= 8;
        }
    }
    while (n--) *d++ = *s++;
    return dst;
}

void *bs_memset(void *dst, int c, size_t n) {
    uint8_t *d = (uint8_t *)dst;
    uint8_t v = (uint8_t)c;
    while (n--) *d++ = v;
    return dst;
}

int bs_memcmp(const void *a, const void *b, size_t n) {
    const uint8_t *x = (const uint8_t *)a, *y = (const uint8_t *)b;
    for (size_t i = 0; i < n; i++)
        if (x[i] != y[i]) return (int)x[i] - (int)y[i];
    return 0;
}

size_t bs_strlen(const char *s) {
    const char *p = s;
    while (*p) p++;
    return (size_t)(p - s);
}

int bs_strcmp(const char *a, const char *b) {
    while (*a && *a == *b) { a++; b++; }
    return (int)(uint8_t)*a - (int)(uint8_t)*b;
}

int bs_memeq_ct(const void *a, const void *b, size_t n) {
    const uint8_t *x = (const uint8_t *)a, *y = (const uint8_t *)b;
    uint8_t d = 0;
    for (size_t i = 0; i < n; i++) d |= (uint8_t)(x[i] ^ y[i]);
    return d == 0;
}

#ifndef BS_HOST_BUILD
/* ---- logging --------------------------------------------------------- */

static bs_log_level g_level = BS_LOG_INFO;
static void (*g_sink)(const char *msg);

void bs_log_set(bs_log_level lvl) { g_level = lvl; }
void bs_log_set_sink(void (*sink)(const char *msg)) { g_sink = sink; }

/* Minimal formatter. The shim cannot pull in printf, and pulling in
 * newlib/printf would dwarf the whole binary. Supports %s %d %u %x
 * %p %% and zero-padded %08x style widths. */
void bs_log(bs_log_level lvl, const char *fmt, ...) {
    if (lvl > g_level) return;

    char out[256];
    size_t o = 0;
    va_list ap;
    va_start(ap, fmt);

    for (const char *p = fmt; *p && o + 2 < sizeof(out); p++) {
        if (*p != '%') { out[o++] = *p; continue; }
        p++;
        int width = 0, zero = 0;
        if (*p == '0') { zero = 1; p++; }
        while (*p >= '0' && *p <= '9') { width = width * 10 + (*p++ - '0'); }
        if (!*p) break;

        char tmp[24];
        int t = 0;
        switch (*p) {
        case 's': {
            const char *s = va_arg(ap, const char *);
            if (!s) s = "(null)";
            while (*s && o + 2 < sizeof(out)) out[o++] = *s++;
            continue;
        }
        case 'd': case 'i': {
            int v = va_arg(ap, int);
            if (v < 0) { out[o++] = '-'; v = -v; }
            if (!v) tmp[t++] = '0';
            while (v && t < (int)sizeof(tmp)) { tmp[t++] = (char)('0' + v % 10); v /= 10; }
            break;
        }
        case 'u': {
            unsigned v = va_arg(ap, unsigned);
            if (!v) tmp[t++] = '0';
            while (v && t < (int)sizeof(tmp)) { tmp[t++] = (char)('0' + v % 10); v /= 10; }
            break;
        }
        case 'x': case 'X': {
            unsigned v = va_arg(ap, unsigned);
            const char *digs = (*p == 'x') ? "0123456789abcdef"
                                           : "0123456789ABCDEF";
            if (!v) tmp[t++] = '0';
            while (v && t < (int)sizeof(tmp)) { tmp[t++] = digs[v & 0xf]; v >>= 4; }
            break;
        }
        case 'p': {
            void *v = va_arg(ap, void *);
            unsigned long l = (unsigned long)v;
            int sh = (int)(sizeof(l) * 2);
            for (int i = sh - 1; i >= 0 && t < (int)sizeof(tmp); i--)
                tmp[t++] = "0123456789abcdef"[(l >> (i * 4)) & 0xf];
            break;
        }
        case '%': out[o++] = '%'; continue;
        default:  out[o++] = '%'; out[o++] = *p; continue;
        }

        int pad = width - t;
        while (pad-- > 0 && o + 2 < sizeof(out)) out[o++] = zero ? '0' : ' ';
        while (t > 0 && o + 2 < sizeof(out)) out[o++] = tmp[--t];
    }
    va_end(ap);

    out[o] = '\0';
    if (g_sink) g_sink(out);
    else bs_uart_puts(out);
}

void bs_halt(void) {
    for (;;) {
        /* Prefer a WFI-equivalent spin; on the target the board layer
         * may install a real halt. */
        __asm__ volatile("wfi");
    }
}
#endif /* !BS_HOST_BUILD */