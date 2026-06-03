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
ZESU_OBJ  ?=

ZIG_FLAGS  = $(if $(ZESU_OBJ),-Dzesu_obj=$(ZESU_OBJ))

.PHONY: all run test bless clean clean-lib

all: $(LIB_OUT)
	$(ZIG) build $(ZIG_FLAGS)

$(LIB_OUT):
	@command -v $(CARGO) >/dev/null 2>&1 || \
	    { echo "ERROR: cargo not found. Install Rust: https://rustup.rs"; exit 1; }
	@$(CARGO) +zisk --version >/dev/null 2>&1 || \
	    { echo "ERROR: Zisk Rust toolchain not installed."; \
	      echo "       Run: cargo-zisk toolchain install"; exit 1; }
	@test -d $(ZISK_DIR) || \
	    { echo "ERROR: ZISK_DIR=$(ZISK_DIR) not found."; \
	      echo "       Clone zisk 0.17.0: git clone https://github.com/0xPolygonHermez/zisk $(ZISK_DIR)"; \
	      echo "       Or set ZISK_DIR=/path/to/zisk"; exit 1; }
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

test: $(LIB_OUT)
	$(ZIG) build -Doptimize=ReleaseFast $(ZIG_FLAGS)
	@fail=0; \
	for bin in ../vectors/*.bin; do \
	    name=$$(basename $$bin .bin); \
	    expected=../vectors/$$name.expected.hex; \
	    out=$$(mktemp); \
	    echo "==> $$name"; \
	    if ! $(ZISKEMU) -e zig-out/bin/zesu-zisk -i $$bin -o $$out; then \
	        echo "  FAIL: ziskemu non-zero exit"; \
	        fail=1; \
	    elif [ -f $$expected ]; then \
	        got=$$(xxd -p -l 105 $$out | tr -d '\n'); \
	        want=$$(tr -d '[:space:]' < $$expected | sed 's/^0x//' | tr 'A-F' 'a-f'); \
	        if [ "$$got" = "$$want" ]; then \
	            echo "  OK"; \
	        else \
	            echo "  FAIL"; \
	            echo "    expected: $$want"; \
	            echo "    got:      $$got"; \
	            fail=1; \
	        fi; \
	    else \
	        echo "  (no expected.hex — informational)"; \
	    fi; \
	    rm -f $$out; \
	done; \
	exit $$fail

bless: $(LIB_OUT)
	$(ZIG) build -Doptimize=ReleaseFast $(ZIG_FLAGS)
	@for bin in ../vectors/*.bin; do \
	    name=$$(basename $$bin .bin); \
	    expected=../vectors/$$name.expected.hex; \
	    out=$$(mktemp); \
	    $(ZISKEMU) -e zig-out/bin/zesu-zisk -i $$bin -o $$out; \
	    xxd -p -l 105 $$out | tr -d '\n' > $$expected; \
	    echo "wrote $$expected"; \
	    rm -f $$out; \
	done

clean:
	rm -rf zig-out .zig-cache

clean-lib: clean
	rm -f $(LIB_OUT)
