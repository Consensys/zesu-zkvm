# Makefile for the Zisk zkVM guest build of zesu.
#
# Prerequisites:
#   - cargo-zisk installed: curl -L https://raw.githubusercontent.com/0xPolygonHermez/zisk/main/ziskup/install.sh | bash
#   - Zisk toolchain installed: cargo-zisk toolchain install
#   - Zisk source checkout (default: ../../zisk, override via ZISK_DIR)
#   - Zig (see minimum_zig_version in build.zig.zon)
#
# Usage:
#   make lib/libziskos.a   — build the Zisk OS library
#   make                   — build lib/libziskos.a then the Zig guest ELF
#   make run INPUT=<file>  — build and run under ziskemu
#   make clean             — remove build artifacts (preserves lib/libziskos.a)
#   make clean-lib         — also remove lib/libziskos.a (forces a rebuild)

ZISK_DIR  ?= ../../zisk
ZISK_PKG   = ziskos
ZISK_TARGET = riscv64ima-zisk-zkvm-elf
CARGO     ?= cargo

LIB_OUT   = lib/libziskos.a
CARGO_OUT = $(ZISK_DIR)/target/$(ZISK_TARGET)/release/lib$(ZISK_PKG).a

ZIG       ?= zig
ZISKEMU   ?= ziskemu

.PHONY: all run clean clean-lib check-toolchain

all: $(LIB_OUT)
	$(ZIG) build

$(LIB_OUT): check-toolchain
	@echo "==> Building libziskos.a from $(ZISK_DIR) ..."
	cd $(ZISK_DIR) && $(CARGO) +zisk build -p $(ZISK_PKG) \
	    --target $(ZISK_TARGET) --release --no-default-features
	@mkdir -p lib
	cp $(CARGO_OUT) $(LIB_OUT)
	@echo "==> Copied $(LIB_OUT)  ($$(wc -c < $(LIB_OUT)) bytes)"

run: all
ifndef INPUT
	$(error INPUT is required: make run INPUT=path/to/block.bin)
endif
	$(ZISKEMU) -e zig-out/bin/zesu-zisk -i $(INPUT)

clean:
	rm -rf zig-out .zig-cache

clean-lib: clean
	rm -f $(LIB_OUT)

check-toolchain:
	@command -v $(CARGO) >/dev/null 2>&1 || \
	    { echo "ERROR: cargo not found. Install Rust: https://rustup.rs"; exit 1; }
	@$(CARGO) +zisk --version >/dev/null 2>&1 || \
	    { echo "ERROR: Zisk Rust toolchain not installed."; \
	      echo "       Run: cargo-zisk toolchain install"; exit 1; }
	@test -d $(ZISK_DIR) || \
	    { echo "ERROR: ZISK_DIR=$(ZISK_DIR) not found."; \
	      echo "       Clone zisk 0.17.0: git clone https://github.com/0xPolygonHermez/zisk $(ZISK_DIR)"; \
	      echo "       Or set ZISK_DIR=/path/to/zisk"; exit 1; }
