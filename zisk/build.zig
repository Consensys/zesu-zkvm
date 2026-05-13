const std = @import("std");

pub fn build(b: *std.Build) void {
    // ── Zisk zkVM target: RISC-V 64-bit freestanding (rv64im baseline) ────────
    const target = b.resolveTargetQuery(.{
        .cpu_arch = .riscv64,
        .cpu_model = .{ .explicit = &std.Target.riscv.cpu.baseline_rv64 },
        .cpu_features_add = std.Target.riscv.featureSet(&.{.m}),
        .cpu_features_sub = std.Target.riscv.featureSet(&.{ .a, .c, .d, .f, .zicsr, .zaamo, .zalrsc }),
        .os_tag = .freestanding,
        .abi = .none,
    });
    const optimize = b.standardOptimizeOption(.{});

    // ── zesu-core: pure module definitions, no C libraries ────────────────────
    // No crypto flags needed — accelerators.zig uses extern fn zkvm_* declarations
    // resolved at link time from the ZisK accel object compiled below.
    const zesu_core_dep = b.dependency("zesu_core", .{
        .target = target,
        .optimize = optimize,
    });

    // ── Zisk zkVM runtime module ──────────────────────────────────────────────
    // Provides: ZiskAllocator (bump allocator), CSR circuit bindings
    // (keccak, sha256, secp256k1, BN254, BLS12-381, arith256, ...)
    const zisk_mod = b.addModule("zisk", .{
        .root_source_file = b.path("src/runtime/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    // ── Override zesu_allocator: Zisk bump allocator ──────────────────────────
    // Replaces zesu-core's default std.heap.c_allocator (unavailable in freestanding).
    // Every EVM module that heap-allocates has this injected.
    const zisk_alloc_mod = b.addModule("zesu_allocator", .{
        .root_source_file = b.path("src/runtime/zesu_allocator.zig"),
        .target = target,
        .optimize = optimize,
    });
    zisk_alloc_mod.addImport("zisk", zisk_mod);

    for ([_]*std.Build.Module{
        zesu_core_dep.module("bytecode"),
        zesu_core_dep.module("state"),
        zesu_core_dep.module("context"),
        zesu_core_dep.module("interpreter"),
        zesu_core_dep.module("precompile"),
        zesu_core_dep.module("handler"),
    }) |evm_mod| {
        evm_mod.addImport("zesu_allocator", zisk_alloc_mod);
    }

    // zesu_allocator: override for executor internals (system_calls, transition) in freestanding.
    zesu_core_dep.module("executor").addImport("zesu_allocator", zisk_alloc_mod);

    // ── ZisK zkvm_io: memory-mapped I/O per zkvm-standards ───────────────────
    const zisk_io_mod = b.createModule(.{
        .root_source_file = b.path("src/zkvm_io.zig"),
        .target = target,
        .optimize = optimize,
    });

    // runner: zesu's SSZ stream execution entry point.
    // Inject the ZisK-specific zkvm_io so runStateless reads from the
    // memory-mapped input region and returns SSZ output bytes.
    const runner_mod = zesu_core_dep.module("runner");
    runner_mod.addImport("zkvm_io", zisk_io_mod);

    // ── Guest executable ──────────────────────────────────────────────────────
    // src/main.zig: ZisK harness only — UART, ZiskAllocator, zkExit, panic,
    // sys_read. Calls runner.runStateless() for all execution logic.
    const exe = b.addExecutable(.{
        .name = "zesu-zisk",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });

    exe.setLinkerScript(b.path("zisk.ld"));
    exe.root_module.code_model = .medium;

    // Link the pre-built Zisk OS library which provides all zkvm_* accelerators
    // (keccak256, sha256, ecrecover, BN254, BLS12-381, KZG, secp256r1, blake2f, ...)
    // built from zisk/ziskos/entrypoint for the riscv64ima-zisk-zkvm-elf target.
    // Use archive semantics (addLibraryPath + linkSystemLibrary) so the linker only
    // pulls in members that resolve undefined references — prevents duplicate _start.
    exe.root_module.addLibraryPath(b.path("lib"));
    exe.root_module.linkSystemLibrary("ziskos", .{ .preferred_link_mode = .static });

    exe.root_module.addImport("zisk", zisk_mod);
    exe.root_module.addImport("runner", runner_mod);
    exe.root_module.addImport("zkvm_io", zisk_io_mod);

    // Override the accel_impl in zesu-core's accelerators module.  Uses ZisK
    // hardware CSRs for everything that has a circuit (keccak256, sha256, ecrecover,
    // secp256r1_verify, modexp, bn254_g1_add, bn254_g1_mul) and pure-Zig for
    // ripemd160 and blake2f (no CSRs exist).  Delegates to libziskos.a only for
    // bn254_pairing, kzg_point_eval, BLS12-381, and secp256k1_verify.
    const zisk_accel_impl_mod = b.createModule(.{
        .root_source_file = b.path("src/runtime/zisk_accel_impl.zig"),
        .target = target,
        .optimize = optimize,
    });
    zisk_accel_impl_mod.addImport("zisk", zisk_mod);
    zesu_core_dep.module("accelerators").addImport("accel_impl", zisk_accel_impl_mod);

    b.installArtifact(exe);

    // Run via ziskemu emulator
    const run_step = b.step("run", "Run via Zisk emulator (ziskemu must be in PATH)");
    const run_cmd = b.addSystemCommand(&.{ "ziskemu", "-e" });
    run_cmd.addArtifactArg(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_cmd.addArgs(args);
    run_step.dependOn(&run_cmd.step);

    // Placeholder test step
    _ = b.step("test", "Run unit tests");
}
