ELF      := zig-out/bin/zesu-linea
OPTIMIZE ?= ReleaseFast

.PHONY: all build run clean

all: build

build: $(ELF)

$(ELF):
	zig build -Doptimize=$(OPTIMIZE)

# Run via the Linea zkc emulator.
# Usage: make run INPUT=/path/to/block.bin
run: $(ELF)
	zkc run $(ELF) $(if $(INPUT),--input $(INPUT),)

clean:
	rm -rf zig-out .zig-cache
