# bootshims4magisk

A pre-kernel **second-stage boot shim** for legacy Android boot images.

The shim lives in the `second` slot (`second_size` / `second_addr`) of a
header **v0/v1/v2** boot image. That slot is the last place Android offers
for code that runs *before* the kernel — AOSP removed it in header v3.
On start the shim locates a secondary boot image, verifies it against a
public key pinned at build time, and would chain control into it.

> **Status: the verified core is done and tested. The runtime shim is not
> yet built.** See [Status](#status) for exactly what works and what
> doesn't. Nothing here has been run on real hardware.

---

## The Samsung key question, answered honestly

The original ask was for a shim "signed with a certificate trusted by the
motherboard's firmware (usually a Samsung-signed key)". Two things matter
here, and both are worth being blunt about.

**1. Samsung's private key cannot be manufactured.** From Samsung's own
Knox whitepaper:

> "The public part of the Samsung Secure Boot key is stored in hardware at
> the time of manufacture... For Samsung devices, this public/private key
> pair is Samsung-controlled and goes through a chain of certificates to
> the Samsung Secure Boot Certificate."

This project therefore treats the trust anchor as **a public key you
supply**, baked in at build time. Supply your own, or extract the OEM
*public* key from a firmware image for your own device. Nothing here
generates, extracts, or bundles an OEM signing key.

**2. But the architecture you described is real.** AOSP's verified-boot
spec says the bootloader *"always attempts to verify the boot partition
using the OEM key first and tries other possible keys only if this
verification fails"*, and in the **UNLOCKED** state *"it is possible for
the user to flash software signed with other keys."* That is the YELLOW
boot state. On Samsung Exynos the bootloader is unlockable regardless of
region. So a shim signed by a key you control is a legitimate path on an
unlocked device — it is not a bypass, it is the documented behaviour.

**One dead end, explicitly ruled out:** the header-v4 `boot_signature`
field is *not* part of device verified boot. AOSP states the GKI
`boot.img` *"isn't signed for verified boot"* and that
`boot_signature` *"isn't involved in the device-specific verified boot
process and is only used in VTS."* It is not a Samsung bypass route.

**The `second` slot is a real risk.** AOSP dropped it in v3, and most
modern firmware ignores it. Devices that actually *execute* a second
stage are old. Confirm your target executes it before building on this;
`tools/inspect_bootimg.py` (not yet written) would help.

---

## What's built and verified

Every claim below is backed by an executable test. The crypto was
verified against **independent implementations** — OpenSSL and AOSP's
`avbtool` — not against our own encoder.

| Component | File | Verified against |
|---|---|---|
| SHA-256 | `shim/src/core/sha256.c` | NIST CAVP / RFC 6234 vectors, incl. the 1,000,000-`a` case |
| Bignum + Montgomery | `shim/src/core/bignum.c` | Python `pow()`, k = 1…64 limbs |
| RSA-4096 PKCS#1 v1.5 | `shim/src/core/rsa.c` | `openssl dgst -sha256 -sign` |
| DER / AVB key parsing | `shim/src/core/rsa.c` | `avbtool extract_public_key` |
| AVB 2.0 vbmeta | `shim/src/core/avb.c` | `avbtool make_vbmeta_image` / `add_hash_footer` |
| Boot image v0–v2 header | `shim/src/core/bootimg.c` | hand-built vectors |

```
$ make test
...
avb: all passed
rsa: all passed
sha256+bootimg: all passed
all host tests passed
```

---

## Two bugs worth reading about

**1. CIOS dropped its carry-out limb.** Montgomery multiplication leaves
the product in `t[0..k]`, where `t[k]` is an extra high limb. The first
implementation copied only `t[0..k-1]` and *then* compared against `n` to
decide whether to subtract. Whenever `t[k]` was set, the comparison saw a
value `2^4096` too small, skipped the reduction, and returned a result off
by exactly `2^4096`. It passed a test comparing only the low 32 bytes;
it failed on the full 512. The fix is in `bs_mont_mul`.

**2. AVB's formats are not what they look like.** Three assumptions were
wrong and were each caught by diffing against real `avbtool` output:

- vbmeta header fields are **big-endian** (confirmed by decoding
  `required_libavb_version_major`).
- Offsets use **two different bases**: hash/signature relative to the end
  of the 256-byte header, public key/descriptors relative to the end of
  the auth block.
- A `.avbpubkey` file is **not DER** — it is AVB's own struct
  (8-byte header + big-endian modulus), and it stores **no exponent**;
  libavb hard-codes F4 (65537).
- Hash descriptors hash **`salt || image`**, not the image alone. The salt
  lives in the descriptor, and the trailing partition record moved between
  avbtool releases — so it is parsed *backwards* from the descriptor end,
  which `num_bytes_following` bounds exactly.

---

## Build

Needs a cross-compiler. `ziglang` is used by default because it needs no
sysroot and is a single `pip install`:

```
make bootstrap          # creates .venv with ziglang
make                    # -> build/shim.elf, build/shim.bin
make test               # host unit tests (generates fixtures first)
```

Override the toolchain with `make ZIG="zig"` or
`make CC="aarch64-linux-gnu-gcc"`.

### Key configuration

Board-specific values are set on the command line:

```
make SHIM_BASE=0x42000000        # must equal the image's second_addr
make SHIM_LIMIT=0x08000000       # size of the RAM window
```

`SHIM_BASE` is per-device and is *not* guessed here. See
`shim/link.ld.in`.

---

## Layout

```
shim/include/     headers (boot image, AVB, RSA, bignum, SHA-256)
shim/src/core/    portable, freestanding logic -- unit tested on host
shim/src/board/   per-SoC layer (console, block device, memory discovery)
tools/            fixture generation (OpenSSL + avbtool)
tests/            host tests
```

`shim/src/core` builds both for the target and for the host, so every
crypto path is exercised by `make test` before it ever reaches a device.

---

## Status

**Done and tested**

- Cryptographic core: SHA-256, Montgomery bignum, RSA-4096 PKCS#1 v1.5
- AVB 2.0 vbmeta verification with a build-time-pinned key
- Legacy boot image v0–v2 header parsing and section-offset math
- Build system, cross-compilation to aarch64, fixture generation

**Not built yet** — this is the remaining work, in order:

1. `shim/src/main.c` — `_start`, BSS zeroing, stack setup, self-integrity
   gate. The link target does not exist yet, so `make` (default goal) is
   incomplete.
2. Payload location. You asked for all three sources. Two are viable
   pre-kernel:
   - *embedded / memory region* — portable, implementable now;
   - *block device* — viable only behind a board ops interface; needs a
     SoC-specific eMMC/UFS driver, which is per-device work;
   - *data-partition file* — **not viable pre-kernel.** Reading a file
     requires a filesystem, and there is no kernel or libc at this stage.
     This source would need the shim to run after the kernel instead,
     which contradicts the "pre-kernel" requirement. Flagging it rather
     than quietly building something that cannot work.
3. Chain handoff — relocate the secondary kernel/ramdisk, patch the DTB
   `/chosen/bootargs`, branch to the entry point.
4. `tools/patch.py` — inject the shim into a boot image's `second` slot
   and repack, honouring the header-version rules.
5. The "data partition" source, if you decide the userspace model suits.

The verification logic is complete and exercised end-to-end against real
`avbtool` output, so it can be wired into the runtime as-is.

---

## Legal

Modifying boot images is only meaningful on devices you own, and on most
devices requires unlocking the bootloader. Flashing a modified bootloader
or secure-boot chain voids warranties and may violate your device's terms.
You are responsible for complying with applicable law and licence terms —
including Samsung's, which restrict bootloader modification on Exynos
hardware.