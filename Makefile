# ==============================================================
#  bootshims4magisk
#  Pre-kernel second-stage boot shim for legacy Android boot
#  images (header v0/v1/v2), targeting the `second` slot.
#
#  The shim lives in the second-stage bootloader slot that AOSP
#  removed in header v3. The bootloader loads and runs it BEFORE
#  the kernel. The shim locates a secondary boot image, verifies
#  it with AVB-style SHA256_RSA4096 against a public key pinned
#  at build time, and chains control into it.
# ==============================================================

SHELL := /bin/bash
ROOT  := $(patsubst %/,%,$(dir $(abspath $(lastword $(MAKEFILE_LIST)))))
BUILD := $(ROOT)/build

# ---- cross toolchain -------------------------------------------------
# Prefer a venv'd ziglang (self-contained clang cross-compiler).
# Override with: make ZIG="zig"  or  make CC="aarch64-linux-gnu-gcc"
ZIGPY := $(firstword $(wildcard $(ROOT)/.venv/bin/python) \
                     $(wildcard $(HOME)/.venv/bin/python))
ZIG   ?= $(if $(ZIGPY),$(ZIGPY) -m ziglang,zig)
TARGET ?= aarch64-linux-musl

CC     := $(ZIG) cc
LD     := $(ZIG) cc
HOSTCC ?= cc

# ---- board / image configuration -------------------------------------
# Physical load address of the second stage. This is the `second_addr`
# field of the boot image header. It is BOARD SPECIFIC -- override it
# for your device. See docs/BOARD_PORTING.md.
SHIM_BASE  ?= 0x10000000
SHIM_LIMIT ?= 0x08000000
PAGE_SIZE  ?= 4096

# ---- flags ------------------------------------------------------------
FREESTAND := -ffreestanding -fno-builtin -fno-stack-protector \
             -fno-pie -fno-pic -fno-asynchronous-unwind-tables \
             -fno-unwind-tables -fomit-frame-pointer
WARN       := -Wall -Wextra -Werror -Wno-unused-parameter \
              -Wno-unused-function
CFLAGS_T   := -target $(TARGET) -nostdlib $(FREESTAND) $(WARN) \
              -O2 -g -std=gnu11 -Ishim/include
CFLAGS_H   := -std=gnu11 $(WARN) -O1 -g -Ishim/include -Ishim/src \
              -DBS_HOST_BUILD=1
LDFLAGS_T  := -target $(TARGET) -nostdlib $(FREESTAND) -Wl,-T,$(BUILD)/link.ld \
              -Wl,--build-id=none -Wl,-z,noexecstack -Wl,--gc-sections

# ---- sources ----------------------------------------------------------
CORE_SRC := $(wildcard shim/src/core/*.c)
BOARD_SRC := $(wildcard shim/src/board/*.c)
MAIN_SRC := shim/src/main.c
CORE_OBJ := $(patsubst %.c,$(BUILD)/%.o,$(CORE_SRC))
BOARD_OBJ := $(patsubst %.c,$(BUILD)/%.o,$(BOARD_SRC))
MAIN_OBJ := $(patsubst %.c,$(BUILD)/%.o,$(MAIN_SRC))
TARGET_OBJ := $(CORE_OBJ) $(BOARD_OBJ) $(MAIN_OBJ)

TEST_SRC := $(wildcard tests/test_*.c)
TEST_BIN := $(patsubst tests/%.c,$(BUILD)/%,$(TEST_SRC))

.PHONY: all clean test e2e keys bootstrap fixtures
.DEFAULT_GOAL := all

all: $(BUILD)/shim.bin $(BUILD)/shim.elf

bootstrap:
	@test -x $(ROOT)/.venv/bin/python || \
		(python3 -m venv $(ROOT)/.venv && $(ROOT)/.venv/bin/pip install -q ziglang)
	@$(CC) --version | head -1

$(BUILD)/link.ld: shim/link.ld.in
	@mkdir -p $(BUILD)
	@sed -e 's/@BASE@/$(SHIM_BASE)/g' -e 's/@LIMIT@/$(SHIM_LIMIT)/g' $< > $@

$(BUILD)/shim.elf: $(TARGET_OBJ) $(BUILD)/link.ld
	@mkdir -p $(BUILD)
	$(LD) $(CFLAGS_T) $(LDFLAGS_T) -o $@ $(TARGET_OBJ)

$(BUILD)/shim.bin: $(BUILD)/shim.elf
	$(ZIG) objcopy -O binary --strip-all $< $@
	@echo "built $@ ($$(stat -c%s $@) bytes) base=$(SHIM_BASE)"

$(BUILD)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS_T) -MMD -MP -c -o $@ $<

# ---- host-side unit tests --------------------------------------------
$(BUILD)/test_%: tests/test_%.c $(CORE_SRC) $(wildcard shim/src/host/*.c)
	@mkdir -p $(BUILD)
	$(HOSTCC) $(CFLAGS_H) -o $@ $< $(CORE_SRC) $(wildcard shim/src/host/*.c)

test: fixtures $(TEST_BIN)
	@fail=0; for t in $(TEST_BIN); do \
	  printf '\033[1m==> %s\033[0m\n' "$$t"; \
	  $$t || fail=1; \
	done; \
	if [ $$fail -ne 0 ]; then echo "\nFAILED"; exit 1; fi; \
	echo "\n\033[32mall host tests passed\033[0m"

fixtures:
	@bash tools/gen_fixtures.sh
	@bash tools/gen_avb_fixtures.sh

e2e: all keys
	python3 tests/e2e.py

keys:
	python3 tools/keygen.py --outdir keys

clean:
	rm -rf $(BUILD)

-include $(shell find $(BUILD) -name '*.d' 2>/dev/null)