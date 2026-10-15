/* ================================================================
 * bs_config.h - compile-time configuration for the boot shim
 *
 * Everything here that describes a specific board lives in the
 * shim/src/board directory instead. This header only holds values
 * that change the shape of the wire format or the shim's own header.
 * ================================================================ */
#ifndef BS_CONFIG_H
#define BS_CONFIG_H

/* ---- shim identity -------------------------------------------------- */

#define BS_SHIM_NAME       "bootshims4magisk"
#define BS_SHIM_VERSION    "0.1.0"

/* ---- shim self-signature header ------------------------------------
 * The shim binary is stored as:
 *
 *   [ bs_shim_hdr ][ shim .text/.data/.bss ][ ed25519-ish sig ]
 *
 * The signature covers the header (minus the signature field) plus
 * the payload. At startup the shim verifies this before touching any
 * other data. A mismatched or truncated shim refuses to run rather
 * than half-initialising and jumping somewhere unpredictable.
 * --------------------------------------------------------------- */

#define BS_SHIM_HDR_MAGIC  0x5348535Bu   /* 'K','S','H','S' LE */

/* Trailer appended to the flat binary by tools/bake_key.py. */
#define BS_SIG_ALGO_ED25519  1
#define BS_SIG_ALGO_RSA4096   2

/* ---- limits ---------------------------------------------------------
 * The shim must fit in the `second` slot of the target boot image
 * alongside whatever else lives there. Keep it small.
 * --------------------------------------------------------------- */

#define BS_MAX_PAYLOAD   (16u * 1024u * 1024u)  /* 16 MiB sanity ceiling */
#define BS_MAX_DTABLES   8                       /* max FDT nodes walked  */

/* ---- AVB / crypto parameters ---------------------------------------- */

#define BS_RSA_KEY_BYTES   512   /* RSA-4096 */
#define BS_RSA_MAX_BYTES   512   /* largest modulus we will parse     */
#define BS_SHA256_LEN      32

/* AVB algorithm id for SHA256_RSA4096 (AvbAlgorithm enum). */
#define BS_AVB_ALGO_SHA256_RSA4096 2

/* Default payload source when none is configured in the shim header.
 * 0 = embedded memory region, 1 = block device, 2 = data partition.
 * See bs_payload.h. */
#define BS_DEFAULT_SOURCE   0

#endif /* BS_CONFIG_H */