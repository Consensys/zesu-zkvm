# zesu-zkvm

zkVM guest builds for [zesu](https://github.com/Consensys/zesu) — the Ethereum
stateless block executor. Each subdirectory is a self-contained build for one
zkVM target.

## Targets

| Directory | zkVM | Status |
|---|---|---|
| [`zisk/`](zisk/) | [Zisk 0.17.0](https://github.com/0xPolygonHermez/zisk) | Working |
| [`openvm/`](openvm/) | [openvm](https://github.com/openvm-org/openvm/pull/2719) | Working (emulation only, no proofs) |

## Repository layout

```
zesu-zkvm/
  zisk/       — Zisk zkVM guest (Zig + libziskos.a)
  openvm/        — openvm guest (Zig ELF + Rust host runner)
```

Each target directory contains its own `build.zig`, `Makefile`, and `README.md`.
See the target-specific README for build instructions.

## Shared sibling layout

All targets expect the following siblings on the filesystem:

```
dev/stateless/
  zesu-zkvm/    ← this repo
  zesu/         ← EVM + stateless executor (zesu/core is the path dependency)
  zisk/         ← Zisk source checkout (needed to build libziskos.a)
```
