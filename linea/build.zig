const std = @import("std");

pub fn build(b: *std.Build) void {
    // ── Linea zkVM target: RISC-V 64-bit freestanding (rv64im + zicclsm) ─────
    // Matches riscv64im_zicclsm-unknown-none-elf per the Linea zkVM Makefile.
    const target = b.resolveTargetQuery(.{
        .cpu_arch = .riscv64,
        .cpu_model = .{ .explicit = &std.Target.riscv.cpu.baseline_rv64 },
        .cpu_features_add = std.Target.riscv.featureSet(&.{ .m, .zicclsm }),
        .cpu_features_sub = std.Target.riscv.featureSet(&.{ .a, .c, .d, .f, .zicsr, .zaamo, .zalrsc }),
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

    // ── Linea zkvm_io: memory-mapped input + write-ecall output ──────────────
    const linea_io_mod = b.createModule(.{
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

    // ── Linea host object ─────────────────────────────────────────────────────
    // Satisfies all extern refs from zesu.o:
    //   - 19 zkvm_* accelerators (pure-Zig / std.crypto stubs)
    //   - read_input (memory-mapped from _input_start)
    //   - write_output / zkvm_log (Linux write ecall a7=64)
    //   - zkvm_exit (Linux exit ecall a7=93)
    //   - ZISK_BUMP_HEAP_POS / ZISK_BUMP_HEAP_TOP + linea_init_heap
    const host_mod = b.createModule(.{
        .root_source_file = b.path("src/linea_host.zig"),
        .target = target,
        .optimize = optimize,
        .code_model = .medium,
    });
    host_mod.addImport("accel_impl", accel_impl_mod);
    host_mod.addImport("zkvm_io", linea_io_mod);
    const host_obj = b.addObject(.{
        .name = "linea-host",
        .root_module = host_mod,
    });

    // ── Guest executable ──────────────────────────────────────────────────────
    // zesu.o (main + EVM logic) + linea-host.o (host + accelerators).
    // startup.S provides _start → linea_init_heap → main.
    // Stripped to minimize binary size per Linea zkVM requirements.
    const exe = b.addExecutable(.{
        .name = "zesu-linea",
        .root_module = b.createModule(.{
            .root_source_file = null,
            .target = target,
            .optimize = optimize,
        }),
    });
    exe.entry = .{ .symbol_name = "_start" };
    exe.root_module.strip = true;
    exe.root_module.code_model = .medium;
    exe.root_module.addObject(zesu_obj);
    exe.root_module.addObject(host_obj);
    exe.root_module.addAssemblyFile(b.path("src/startup.S"));
    exe.setLinkerScript(b.path("linea.ld"));

    b.installArtifact(exe);

    // Run step: invoke zkc emulator with the built ELF and an input file.
    const run_step = b.step("run", "Run via Linea zkc emulator (zkc must be in PATH)");
    const run_cmd = b.addSystemCommand(&.{ "zkc", "run" });
    run_cmd.addArtifactArg(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_cmd.addArgs(args);
    run_step.dependOn(&run_cmd.step);

    _ = b.step("test", "Run unit tests");
}
