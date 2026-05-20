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

    // ── zesu-core dependency ──────────────────────────────────────────────────
    // When built with a freestanding target, core/build.zig:
    //   - Overrides zesu_allocator → bump_alloc.zig (ZISK_BUMP_HEAP_POS/TOP)
    //   - Overrides accel_impl → extern_bridge.zig (extern fn zkvm_* refs)
    //   - Injects extern_io.zig as zkvm_io into runner
    //   - Exposes "zkvm_root" named module (src/zkvm/root.zig) with all wired deps
    const zesu_core_dep = b.dependency("zesu_core", .{
        .target = target,
        .optimize = optimize,
    });

    // ── OpenVM zkvm_io: hint-stream I/O ───────────────────────────────────────
    const openvm_io_mod = b.createModule(.{
        .root_source_file = b.path("src/zkvm_io.zig"),
        .target = target,
        .optimize = optimize,
    });

    // ── accel_impl: pure-Zig implementations (std.crypto + stubs) ────────────
    const accel_impl_mod = b.createModule(.{
        .root_source_file = b.path("src/runtime/stdlibs_accel.zig"),
        .target = target,
        .optimize = optimize,
    });

    // ── zesu rv64im object ────────────────────────────────────────────────────
    // Uses core's "zkvm_root" module (already wired with extern_bridge, bump_alloc,
    // extern_io). Produces an object with main() and all EVM/stateless logic,
    // leaving IO / crypto / heap / runtime as unresolved extern refs.
    const zesu_obj = b.addObject(.{
        .name = "zesu",
        .root_module = zesu_core_dep.module("zkvm_root"),
    });
    zesu_obj.root_module.code_model = .medium;

    // ── OpenVM host object ────────────────────────────────────────────────────
    // Satisfies all extern refs from zesu.o:
    //   - 19 zkvm_* accelerators (pure-Zig / std.crypto stubs)
    //   - read_input / write_output (hint-stream IO)
    //   - zkvm_log / zkvm_exit (print_str phantom / TERMINATE)
    //   - ZISK_BUMP_HEAP_POS / ZISK_BUMP_HEAP_TOP (bump heap vars + init fn)
    const host_mod = b.createModule(.{
        .root_source_file = b.path("src/openvm_host.zig"),
        .target = target,
        .optimize = optimize,
        .code_model = .medium,
    });
    host_mod.addImport("accel_impl", accel_impl_mod);
    host_mod.addImport("zkvm_io", openvm_io_mod);
    const host_obj = b.addObject(.{
        .name = "openvm-host",
        .root_module = host_mod,
    });

    // ── Guest executable ──────────────────────────────────────────────────────
    // zesu.o (main + EVM logic) + openvm-host.o (host + accelerators).
    // startup.S provides _start → openvm_init_heap → main.
    // No partial link needed: no external archive with duplicate symbols.
    const exe = b.addExecutable(.{
        .name = "zesu-openvm",
        .root_module = b.createModule(.{
            .root_source_file = null,
            .target = target,
            .optimize = optimize,
        }),
    });
    exe.entry = .{ .symbol_name = "_start" };
    exe.root_module.code_model = .medium;
    exe.root_module.addObject(zesu_obj);
    exe.root_module.addObject(host_obj);
    exe.root_module.addAssemblyFile(b.path("src/startup.S"));
    exe.setLinkerScript(b.path("openvm.ld"));

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
