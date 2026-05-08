const std = @import("std");

pub fn build(b: *std.Build) void {
    // ── OpenVM target: RISC-V 64-bit freestanding (rv64im) ───────────────────
    // Matches riscv64im-openvm-none-elf: no atomics, no compressed, no float.
    const target = b.resolveTargetQuery(.{
        .cpu_arch = .riscv64,
        .cpu_model = .{ .explicit = &std.Target.riscv.cpu.baseline_rv64 },
        .cpu_features_add = std.Target.riscv.featureSet(&.{.m}),
        .cpu_features_sub = std.Target.riscv.featureSet(&.{ .a, .c, .zca, .zcb, .d, .f, .zicsr, .zaamo, .zalrsc }),
        .os_tag = .freestanding,
        .abi = .none,
    });
    const optimize = b.standardOptimizeOption(.{});

    // ── zesu-core: pure EVM module definitions ────────────────────────────────
    const zesu_core_dep = b.dependency("zesu_core", .{
        .target = target,
        .optimize = optimize,
    });

    // ── OpenVM runtime module ─────────────────────────────────────────────────
    // Provides: OpenVmAllocator (bump allocator using _end symbol)
    const openvm_mod = b.addModule("openvm", .{
        .root_source_file = b.path("src/runtime/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    // ── Override zesu_allocator: OpenVM bump allocator ────────────────────────
    const openvm_alloc_mod = b.addModule("zesu_allocator", .{
        .root_source_file = b.path("src/runtime/zesu_allocator.zig"),
        .target = target,
        .optimize = optimize,
    });
    openvm_alloc_mod.addImport("openvm", openvm_mod);

    // ── Override accel_impl: pure-Zig stubs (no extern zkvm_* symbols needed) ──
    const nolibs_accel_mod = b.createModule(.{
        .root_source_file = b.path("src/runtime/stdlibs_accel.zig"),
        .target = target,
        .optimize = optimize,
    });
    zesu_core_dep.module("accelerators").addImport("accel_impl", nolibs_accel_mod);

    for ([_]*std.Build.Module{
        zesu_core_dep.module("bytecode"),
        zesu_core_dep.module("state"),
        zesu_core_dep.module("context"),
        zesu_core_dep.module("interpreter"),
        zesu_core_dep.module("precompile"),
        zesu_core_dep.module("handler"),
    }) |evm_mod| {
        evm_mod.addImport("zesu_allocator", openvm_alloc_mod);
    }

    zesu_core_dep.module("executor").addImport("zesu_allocator", openvm_alloc_mod);

    // ── OpenVM zkvm_io: hint-stream I/O ───────────────────────────────────────
    const openvm_io_mod = b.createModule(.{
        .root_source_file = b.path("src/zkvm_io.zig"),
        .target = target,
        .optimize = optimize,
    });

    // runner: zesu's SSZ execution entry point.
    const runner_mod = zesu_core_dep.module("runner");
    runner_mod.addImport("zkvm_io", openvm_io_mod);

    // ── Guest executable ──────────────────────────────────────────────────────
    const exe = b.addExecutable(.{
        .name = "zesu-openvm",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });

    exe.entry = .{ .symbol_name = "_start" };
    exe.setLinkerScript(b.path("openvm.ld"));
    exe.root_module.addAssemblyFile(b.path("src/startup.S"));
    exe.root_module.code_model = .medium;

    exe.root_module.addImport("openvm", openvm_mod);
    exe.root_module.addImport("runner", runner_mod);
    exe.root_module.addImport("zkvm_io", openvm_io_mod);

    b.installArtifact(exe);

    // Run step: build runner, then execute via the Rust runner binary.
    const run_step = b.step("run", "Run via OpenVM runner (cargo build runner first)");
    const run_cmd = b.addSystemCommand(&.{"runner/target/release/zesu-openvm-runner"});
    run_cmd.addArtifactArg(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_cmd.addArgs(args);
    run_step.dependOn(&run_cmd.step);

    _ = b.step("test", "Run unit tests");
}
