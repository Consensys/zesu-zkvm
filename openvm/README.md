# zesu-openvm

OpenVM guest build of [zesu](https://github.com/Consensys/zesu), the Ethereum
stateless block executor. Executes a single EVM block from an SSZ witness
input and commits the `new_payload_request_root` + success flag as public
values.

## Status

**Early / experimental.** This is an initial port to demonstrate end-to-end
execution under OpenVM's default accelerators (rv64i + rv64m + io). Known
limitations:

- **No ZK proof generation.** The runner calls `sdk.execute()` (emulation
  only). Proof generation would require wiring in STARK aggregation params and
  a real trusted setup.
- **KZG point evaluation is not verified.** The `kzg_point_eval` stub accepts
  all proofs without computing the BLS12-381 pairing. Valid mainnet blocks are
  unaffected (the consensus layer validates blob proofs before inclusion), but
  a guest compiled from this tree must not be used to prove untrusted blocks.
- **BN254, BLS12-381, RIPEMD-160, and modexp are stubs.** Returns
  false/zero. Blocks that call those precompiles will produce wrong state.
- **ecrecover, SHA-256, secp256k1 verify** use `std.crypto` — functional and
  tested against mainnet blocks.

## Prerequisites

- Zig 0.16 (`zvm install 0.16.0` or the version in `build.zig.zon`)
- Rust stable ≥ 1.91 (`rustup update stable`)
- `openvm` source at `../../../../openvm` relative to this directory (the
  runner's `Cargo.toml` points there via a path dependency)

## Build

```sh
# Build the Rust host runner (one-time or after openvm changes)
make runner

# Build the Zig guest ELF
make
```

Or run both in one step:

```sh
make all
```

## Usage

Run a single `.bin` test vector (8-byte LE payload-length header + SSZ body):

```sh
make run INPUT=../vectors/mainnet_24758573.bin
```

Run all vectors and check against `.expected.hex` files:

```sh
make test
```

Regenerate expected outputs after intentional changes:

```sh
make bless
```

## Input format

The `.bin` files carry a fixed header consumed by the OpenVM hint-stream:

```
[0..8]   payload_len  — u64 LE, byte count of the SSZ body
[8..]    SSZ body     — padded to 8-byte boundary
```

The host runner passes the raw file bytes as a single `StdIn::from_bytes`
entry; `zkvm_io.read_input` strips the length prefix and hands the SSZ slice
to the executor.

## Output format

41 bytes written to `public_values[0..41]` via REVEAL instructions:

```
[0..32]  new_payload_request_root  — SSZ hash_tree_root of the execution payload
[32]     success                   — 1 = block executed correctly, 0 = failed
[33..41] chain_id                  — u64 LE
```

## Project layout

```
openvm/
  src/
    main.zig           — guest entry point, panic handler, log → printStr
    startup.S          — _start in .text._start (linker-script anchor)
    zkvm_io.zig        — hint-stream I/O (read_input, write_output, printStr)
    runtime/
      main.zig         — OpenVmAllocator (bump allocator over _end symbol)
      zesu_allocator.zig
      stdlibs_accel.zig — accel_impl: ecrecover/sha256/keccak256 via std.crypto;
                          kzg_point_eval returns success (no pairing); everything
                          else stubbed
  runner/
    src/main.rs        — Rust host: loads ELF, feeds hint stream, reads public values
  openvm.ld            — linker script (TEXT_START=0x00200800, 256 MB heap)
  openvm.toml          — VM config (rv64i + rv64m + io, 64 public value bytes)
  build.zig            — Zig build: riscv64im freestanding target
  Makefile             — build / run / test / bless
```
