# zesu-zkvm / zisk

Zisk zkVM guest for zesu — compiles the Ethereum stateless block executor to a
`riscv64-freestanding-none` ELF that runs inside the
[Zisk zkVM](https://github.com/0xPolygonHermez/zisk).

## Directory layout

```
zisk/
  src/
    main.zig          — Zisk harness: UART, ZiskAllocator, zkExit, sys_read
    zkvm_io.zig       — memory-mapped input/output (Zisk address map)
    deserialize.zig   — wire-format parser for the stateless input
    runtime/          — Zisk CSR circuit bindings and allocator
      main.zig        — public re-exports (the "zisk" module)
      allocator.zig   — ZiskAllocator (shares ZISK_BUMP_HEAP_POS with libziskos.a)
      circuits.zig    — RISC-V CSR wrappers for keccakf, sha256f, secp256k1, BN254, …
      accel_impl.zig  — (legacy) hand-rolled zkvm_* impls, superseded by libziskos.a
      eip196.zig      — BN254 add / mul / pairing
      secp256k1.zig   — full ecrecover via arith256Mod + secp256k1Add CSRs
      secp256r1.zig   — P-256 verify via secp256r1Add CSRs
      blake2f.zig     — BLAKE2f round function
  lib/
    libziskos.a       — NOT committed; build with `make lib/libziskos.a`
  build.zig           — Zig build script
  build.zig.zon       — dependency manifest (path dep: ../../zesu/core)
  zisk.ld             — linker script (Zisk memory map)
  Makefile            — builds libziskos.a then the Zig guest ELF
```

## Dependencies

| Dependency | Version | Notes |
|---|---|---|
| Zig | ≥ 0.16.0 | see `minimum_zig_version` in `build.zig.zon` |
| Rust + cargo-zisk | 0.17.0 | Zisk custom Rust toolchain |
| Zisk source | 0.17.0 | for building `libziskos.a` |
| zesu/core | path dep | sibling at `../../zesu/core` |

## Building `lib/libziskos.a`

`libziskos.a` is the canonical Rust implementation of `zkvm_accelerators.h` from
`zisk/ziskos/entrypoint`. It provides:

- All `zkvm_*` hardware-accelerated cryptographic functions
  (`zkvm_keccak256`, `zkvm_sha256`, `zkvm_secp256k1_ecrecover`,
   `zkvm_bn254_*`, `zkvm_bls12_*`, `zkvm_kzg_point_eval`, …)
- The `_start` → `_zisk_main` entry-point chain
- `init_sys_alloc()` and the shared bump allocator (`ZISK_BUMP_HEAP_POS`)

It is **not committed** because it is a cross-compiled RISC-V binary that must be
reproducibly built from a known Zisk commit.

### One-time toolchain setup

```sh
# 1. Install cargo-zisk
curl -L https://raw.githubusercontent.com/0xPolygonHermez/zisk/main/ziskup/install.sh | bash

# 2. Install the Zisk Rust toolchain (downloads ~1.5 GB)
cargo-zisk toolchain install

# 3. Clone Zisk 0.17.0 alongside this repo (or set ZISK_DIR)
git clone --branch v0.17.0 https://github.com/0xPolygonHermez/zisk ../../zisk
```

### Build the library

```sh
# From this directory (zesu-zkvm/zisk/)
make lib/libziskos.a

# With a custom Zisk checkout location
make lib/libziskos.a ZISK_DIR=/path/to/zisk
```

This runs:

```sh
cd $ZISK_DIR && cargo +zisk build -p ziskos \
    --target riscv64ima-zisk-zkvm-elf --release --no-default-features
cp $ZISK_DIR/target/riscv64ima-zisk-zkvm-elf/release/libziskos.a lib/
```

The output is fully deterministic for a given Zisk commit and is identical on
linux-x86_64 and darwin-arm64 (it cross-compiles to RISC-V either way).

## Building the guest ELF

```sh
make                              # builds lib/libziskos.a then the debug ELF
zig build -Doptimize=ReleaseFast  # release build only (lib/ must already exist)
```

Output: `zig-out/bin/zesu-zisk`

## Running under ziskemu

```sh
make run INPUT=../../block_24758572_new.bin

# or directly
ziskemu -e zig-out/bin/zesu-zisk -i /path/to/block.bin
```

## How the entry-point chain works

```
_start           (libziskos.a, Rust)
  sets gp from _global_pointer linker symbol
  sets sp from _init_stack_top linker symbol
  calls _zisk_main

_zisk_main       (libziskos.a, Rust)
  calls init_sys_alloc()   — sets ZISK_BUMP_HEAP_POS / ZISK_BUMP_HEAP_TOP
  calls main()

main()           (zisk/src/main.zig, Zig, export fn)
  creates ZiskAllocator (reads shared ZISK_BUMP_HEAP_POS)
  calls guestMain()
  calls zkExit(0 or 1)
```

## Memory map (Zisk 0.17.0)

| Region | Address | Size |
|---|---|---|
| ROM (code + rodata) | `0x80000000` | 128 MB |
| SYS / UART | `0xa0000000` | 64 KB |
| OUTPUT | `0xa0010000` | 64 KB |
| gap | `0xa0020000` | 64 KB |
| RAM (heap + stack) | `0xa0030000` | ~512 MB |
| INPUT | `0x40000000` | 1 GB |

## Linking notes

`libziskos.a` is linked with archive semantics (`addLibraryPath` +
`linkSystemLibrary`) so the linker only pulls in object file members that
resolve undefined references. This prevents the duplicate `_start` symbol that
occurs when the archive is passed as an object file directly.

The `sys_read` symbol (referenced by Rust's zkvm `Stdin` impl) is provided as
an EOF stub in `src/main.zig` since the guest reads input from the memory-mapped
INPUT region, not stdin.
