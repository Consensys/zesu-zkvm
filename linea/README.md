# zesu-linea

Guest binary for the [Linea zkVM](https://github.com/Consensys/linea-monorepo) arithmetization.

`zesu-linea` is a RISC-V ELF (`riscv64im_zicclsm-unknown-none-elf`) that executes the EVM state transition for a stateless block inside the Linea zkVM. It links `zesu` EVM logic with a Linea-compatible host layer that provides the zkvm-standards I/O interface and cryptographic accelerators, then runs under `zkc` for constraint checking.

## Requirements

- `zig >= 0.16` — to build `zesu-linea`
- `go >= 1.23` — to run the ELF-to-JSON helper from [linea-monorepo](https://github.com/Consensys/linea-monorepo)
- `zkc >= 1.2.12` from [go-corset](https://github.com/Consensys/go-corset) — to execute and prove the trace

### Install zkc

No official releases yet. Clone and install from source:

```bash
git clone https://github.com/Consensys/go-corset
cd go-corset
go install ./cmd/zkc
```

## Build

From this directory:

```bash
zig build                          # debug
zig build -Doptimize=ReleaseFast   # optimized (default for CI)
```

The binary is written to `zig-out/bin/zesu-linea`.

To use a pre-built `zesu.rv64im.o` object rather than building zesu from source:

```bash
zig build -Dzesu_obj=/path/to/zesu.rv64im.o
```

## Running a stateless block

Processing a block through the Linea arithmetization is a two-step pipeline.

### Step 1 — Convert ELF + input to zkc JSON

The ELF-to-JSON helper from [linea-monorepo](https://github.com/Consensys/linea-monorepo/tree/main/arithmetization/src/test/examples) loads the guest ELF and writes the stateless input bytes into the zkVM's memory image at the expected input offset, producing a JSON blob consumed by `zkc`.

```bash
go run /path/to/linea-monorepo/arithmetization/src/test/examples/main.go \
    zig-out/bin/zesu-linea \
    @/path/to/stateless_input.ssz \
    0x08800000 \
    > block.json
```

| Argument | Description |
|---|---|
| `zig-out/bin/zesu-linea` | Guest ELF |
| `@/path/to/stateless_input.ssz` | Stateless input file (`@` prefix reads from file; bare `0x…` for inline hex) |
| `0x08800000` | Input start address — matches the default memory layout |

### Step 2 — Execute the arithmetization

```bash
zkc exec block.json /path/to/linea-monorepo/arithmetization/src/main/riscv/main.zkc
```

`zkc exec` runs the guest against the RISC-V arithmetization constraints defined in [`main.zkc`](https://github.com/Consensys/linea-monorepo/blob/main/arithmetization/src/main/riscv/main.zkc) and reports any constraint violations.

## Memory layout

```
0x00000000  ──  program start
    ↓  grows up (≤ 128 MiB)
0x08000000  ──  stack top
    ↑  grows downward (8 MiB)
0x08800000  ──  stack base / input start  ← IN_BYTES_OFFSET
    ↓  grows up (≤ 1 GiB)
0x48800000  ──  input end at most
```

The default input offset `0x08800000` must match the value passed to `main.go` and the linker script (`linea.ld`).
