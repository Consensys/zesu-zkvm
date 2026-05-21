const std = @import("std");
const openvm = @import("openvm");
const runner = @import("runner");
const zkvm_io = @import("zkvm_io");

/// Route all std.log calls through the OpenVM print_str phantom instruction.
pub const std_options: std.Options = .{ .logFn = logFn };

fn logFn(
    comptime level: std.log.Level,
    comptime scope: @TypeOf(.EnumLiteral),
    comptime format: []const u8,
    args: anytype,
) void {
    _ = scope;
    zkvm_io.printStr(level.asText());
    zkvm_io.printStr(": ");
    var buf: [512]u8 = undefined;
    const msg = std.fmt.bufPrint(&buf, format, args) catch format;
    zkvm_io.printStr(msg);
    zkvm_io.printStr("\n");
}

// ── Entry point ───────────────────────────────────────────────────────────────
//
// _start is defined in src/startup.S (section .text._start) so the linker
// script's KEEP(*(.text._start)) places it first at 0x00200800.
// It sets sp = 0x00200400 and calls main() below.

/// C entry point called by _start.
export fn main() void {
    guestMain() catch |err| {
        std.log.err("fatal: {s}", .{@errorName(err)});
        zkExit(1);
    };
    std.log.info("ok", .{});
    zkExit(0);
}

fn guestMain() !void {
    var alloc = openvm.OpenVmAllocator.init();
    const allocator = alloc.allocator();

    const result = try runner.runStateless(allocator);
    zkvm_io.write_output(&result.out);
}

/// Terminate via OpenVM's TERMINATE custom instruction (funct3=0, imm=exit_code).
fn zkExit(comptime exit_code: u8) noreturn {
    asm volatile (".insn i 0x0b, 0, x0, x0, " ++ std.fmt.comptimePrint("{d}", .{exit_code}) ::: .{ .memory = true });
    unreachable;
}

/// Panic handler for freestanding OpenVM target.
pub fn panic(msg: []const u8, error_return_trace: ?*std.builtin.StackTrace, ret_addr: ?usize) noreturn {
    _ = error_return_trace;
    _ = ret_addr;
    zkvm_io.printStr("PANIC: ");
    zkvm_io.printStr(msg);
    zkvm_io.printStr("\n");
    zkExit(1);
}
