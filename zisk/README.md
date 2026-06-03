# zesu-zkvm / zisk

Zisk zkVM guest for zesu — compiles the Ethereum stateless block executor to a
`riscv64-freestanding-none` ELF that runs inside the
[Zisk zkVM](https://github.com/0xPolygonHermez/zisk).

## Architecture

The guest ELF is assembled from two relocatable objects:

```
zesu.o          — EVM + stateless execution logic (from zesu/core)
                  Compiled for rv64im freestanding; leaves all platform
                  symbols (IO, crypto, heap, runtime) as extern refs.

zisk-wrapped.o  — All platform symbols, merged in a partial-link step:
                    zisk-host.o   (Zig)   IO, runtime, 9 CSR accelerators
                  + libziskos.a   (Rust)  BLS12/kzg/pairing, _start, heap init
```

The partial link step (`zig ld.lld -r --allow-multiple-definition`) merges
`zisk-host.o` and `libziskos.a` into `zisk-wrapped.o`. Because `zisk-host.o`
is listed first, its 9 CSR-backed `zkvm_*` implementations take precedence;
`libziskos.a` contributes the remaining 10 BLS12/kzg/pairing symbols plus the
entry-point chain and heap initializer. The final link is a clean
`zesu.o + zisk-wrapped.o` with each symbol defined exactly once.

### Symbol ownership

| Symbol(s) | Source | Implementation |
|---|---|---|
| `zkvm_keccak256`, `zkvm_sha256` | `zisk_host.zig` | ZisK keccakf / sha256Compress CSRs |
| `zkvm_secp256k1_ecrecover` | `zisk_host.zig` | arith256Mod + secp256k1Add CSRs |
| `zkvm_ripemd160` | `zisk_host.zig` | pure Zig (no ZisK circuit) |
| `zkvm_modexp` | `zisk_host.zig` | arith256ModDirect CSR (≤32 B), big-int fallback |
| `zkvm_bn254_g1_add`, `zkvm_bn254_g1_mul` | `zisk_host.zig` | bn254CurveAdd/Double CSRs |
| `zkvm_blake2f` | `zisk_host.zig` | pure Zig (ZisK circuit is BLAKE2b, not BLAKE2f) |
| `zkvm_secp256r1_verify` | `zisk_host.zig` | secp256r1Add/Double CSRs |
| `zkvm_bn254_pairing`, `zkvm_kzg_point_eval` | `libziskos.a` | Rust (full Miller loop / BLS12 pairing) |
| `zkvm_bls12_g1_*`, `zkvm_bls12_g2_*`, `zkvm_bls12_pairing` | `libziskos.a` | Rust |
| `zkvm_bls12_map_fp*`, `zkvm_secp256k1_verify` | `libziskos.a` | Rust |
| `read_input`, `write_output` | `zisk_host.zig` | memory-mapped IO (0x40000000 / 0xa0010000) |
| `zkvm_log`, `zkvm_exit` | `zisk_host.zig` | UART (0xa0000200) + ecall a7=93 |
| `sys_read` | `zisk_host.zig` | EOF stub (guest uses memory-mapped input) |
| `_start`, `_zisk_main`, `init_sys_alloc` | `libziskos.a` | Rust entry-point chain |
| `ZISK_BUMP_HEAP_POS`, `ZISK_BUMP_HEAP_TOP` | `libziskos.a` | shared bump heap vars |

## Directory layout

```
zisk/
  src/
    zisk_host.zig        — host object root: IO, runtime, 9 CSR-backed zkvm_* exports
    zkvm_io.zig          — memory-mapped input/output (Zisk address map)
    runtime/
      main.zig           — public re-exports (the "zisk" module)
      circuits.zig       — RISC-V CSR wrappers for keccakf, sha256f, secp256k1, BN254, …
      zisk_accel_impl.zig — CSR-backed implementations of the 9 accelerators
      allocator.zig      — ZiskAllocator (shares ZISK_BUMP_HEAP_POS with libziskos.a)
      eip196.zig         — BN254 add / mul (used by zisk_accel_impl)
      secp256k1.zig      — full ecrecover via arith256Mod + secp256k1Add CSRs
      secp256r1.zig      — P-256 verify via secp256r1Add CSRs
      blake2f.zig        — BLAKE2f round function (pure Zig)
      ripemd160.zig      — RIPEMD-160 (pure Zig)
  lib/
    libziskos.a          — NOT committed; build with `make lib/libziskos.a`
  build.zig              — Zig build script
  build.zig.zon          — dependency manifest (path dep: ../../zesu/core)
  zisk.ld                — linker script (Zisk memory map)
  Makefile               — builds libziskos.a then the Zig guest ELF
```

## Dependencies

| Dependency | Version | Notes |
|---|---|---|
| Zig | ≥ 0.16.0 | see `minimum_zig_version` in `build.zig.zon` |
| Rust + cargo-zisk | 0.17.0 | Zisk custom Rust toolchain |
| Zisk source | 0.17.0 | for building `libziskos.a` |
| zesu/core | path dep | sibling at `../../zesu/core` |

## Building `lib/libziskos.a`

`libziskos.a` is the Zisk OS runtime. After the partial link step it contributes
the 10 BLS12/kzg/pairing accelerators that have no complete Zig CSR
implementation, plus the entry-point chain and heap initializer.

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

## Building the guest ELF

```sh
make                              # builds lib/libziskos.a then the debug ELF
zig build -Doptimize=ReleaseFast  # release build only (lib/ must already exist)
```

Output: `zig-out/bin/zesu-zisk`

The build executes three steps:

1. **Compile `zesu.o`** — zesu/core's `zkvm_root` module for rv64im freestanding.
   All `zkvm_*`, IO, and heap symbols are unresolved extern refs.
2. **Partial link** — `zig ld.lld -r --allow-multiple-definition zisk-host.o lib/libziskos.a`
   produces `zisk-wrapped.o` with conflicts resolved (host wins for the 9 CSR
   symbols; libziskos.a wins for BLS12/kzg/pairing and the runtime).
3. **Final link** — `zesu.o + zisk-wrapped.o` under `zisk.ld`.

## Running under ziskemu

```sh
make run INPUT=../../block_24758572_new.bin

# or directly
ziskemu -e zig-out/bin/zesu-zisk -i /path/to/block.bin
```

## Entry-point chain

```
_start           (libziskos.a, Rust)
  sets gp from _global_pointer linker symbol
  sets sp from _init_stack_top linker symbol
  calls _zisk_main

_zisk_main       (libziskos.a, Rust)
  calls init_sys_alloc()   — sets ZISK_BUMP_HEAP_POS / ZISK_BUMP_HEAP_TOP
  calls main()

main()           (zesu.o / zesu/src/zkvm/root.zig, Zig, export fn)
  calls runner.runStateless(bump_allocator)
  writes SSZ output via zkvm_io.write_output
  calls zkvm_exit(0 or 1)
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
