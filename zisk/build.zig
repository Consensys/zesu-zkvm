const std = @import("std");

pub fn build(b: *std.Build) void {
    // ── Zisk zkVM target: RISC-V 64-bit freestanding (rv64im + zicclsm) ──────
    const target = b.resolveTargetQuery(.{
        .cpu_arch = .riscv64,
        .cpu_model = .{ .explicit = &std.Target.riscv.cpu.baseline_rv64 },
        .cpu_features_add = std.Target.riscv.featureSet(&.{ .m, .zicclsm }),
        .cpu_features_sub = std.Target.riscv.featureSet(&.{ .a, .c, .d, .f, .zicsr, .zaamo, .zalrsc }),
        .os_tag = .freestanding,
        .abi = .none,
    });
    const optimize = b.standardOptimizeOption(.{});

    // ── zesu object ───────────────────────────────────────────────────────────
    // -Dzesu_obj=/path/to/zesu.rv64im.o  use a pre-built object (CI default)
    // (omit)                             build from source via zesu_core path dep
    const zesu_obj_path = b.option([]const u8, "zesu_obj", "Path to pre-built zesu.rv64im.o (omit to build from source via zesu_core dep)");

    // ── Zisk zkVM runtime module ──────────────────────────────────────────────
    const zisk_mod = b.addModule("zisk", .{
        .root_source_file = b.path("src/runtime/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    // ── ZisK zkvm_io: memory-mapped I/O per zkvm-standards ───────────────────
    const zisk_io_mod = b.createModule(.{
        .root_source_file = b.path("src/zkvm_io.zig"),
        .target = target,
        .optimize = optimize,
    });

    // ── accel_impl: ZisK CSR-backed accelerators ─────────────────────────────
    const accel_impl_mod = b.createModule(.{
        .root_source_file = b.path("src/runtime/zisk_accel_impl.zig"),
        .target = target,
        .optimize = optimize,
    });
    accel_impl_mod.addImport("zisk", zisk_mod);

    // ── zesu rv64im object ────────────────────────────────────────────────────

    // ── zisk-host object ─────────────────────────────────────────────────────
    // Compiled separately so it can be partially linked with libziskos.a before
    // the final link.  Exports: 9 CSR-backed zkvm_* + IO + runtime symbols.
    const host_mod = b.createModule(.{
        .root_source_file = b.path("src/zisk_host.zig"),
        .target = target,
        .optimize = optimize,
        .code_model = .medium,
    });
    host_mod.addImport("accel_impl", accel_impl_mod);
    host_mod.addImport("zkvm_io", zisk_io_mod);
    const host_obj = b.addObject(.{
        .name = "zisk-host",
        .root_module = host_mod,
    });

    // ── Partial link: zisk-host.o + libziskos.a → zisk-wrapped.o ─────────────
    //
    // libziskos.a's cgu.11 defines all 19 zkvm_* symbols in one archive member.
    // zesu.o needs the 10 BLS12/kzg symbols from cgu.11, so the linker must pull
    // it in — bringing the 9 duplicate CSR definitions with it.
    //
    // Resolving this before the final link:
    //   --allow-multiple-definition: host_obj's 9 CSR exports (listed first) win;
    //   libziskos.a contributes the 10 BLS12/kzg symbols + _start/init_sys_alloc.
    // Output is a single relocatable object with every symbol defined exactly once.
    const wrap_cmd = b.addSystemCommand(&.{
        "zig", "ld.lld",
        "-r",  "--allow-multiple-definition",
    });
    wrap_cmd.addFileArg(host_obj.getEmittedBin());
    wrap_cmd.addFileArg(b.path("lib/libziskos.a"));
    wrap_cmd.addArg("-o");
    const zisk_wrapped = wrap_cmd.addOutputFileArg("zisk-wrapped.o");

    // ── Final guest executable ────────────────────────────────────────────────
    // zesu.o (main + EVM logic) + zisk-wrapped.o (host + libziskos merged).
    // The linker script handles memory layout; no Zig root source needed here.
    const exe = b.addExecutable(.{
        .name = "zesu-zisk",
        .root_module = b.createModule(.{
            .root_source_file = null,
            .target = target,
            .optimize = optimize,
        }),
    });
    exe.root_module.code_model = .medium;
    if (zesu_obj_path) |path| {
        exe.root_module.addObjectFile(.{ .cwd_relative = path });
    } else {
        const zesu_core_dep = b.dependency("zesu_core", .{
            .target = target,
            .optimize = optimize,
        });
        const zesu_obj = b.addObject(.{
            .name = "zesu",
            .root_module = zesu_core_dep.module("zkvm_root"),
        });
        zesu_obj.root_module.code_model = .medium;
        exe.root_module.addObject(zesu_obj);
    }
    exe.root_module.addObjectFile(zisk_wrapped);
    exe.setLinkerScript(b.path("zisk.ld"));

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
