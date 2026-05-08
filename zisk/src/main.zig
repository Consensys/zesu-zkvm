const std = @import("std");
const zisk = @import("zisk");
const runner = @import("runner");
const zkvm_io = @import("zkvm_io");

/// Zisk zkVM UART address for console output
const ZISK_UART: *volatile u8 = @ptrFromInt(0xa0000200);

/// Route all std.log calls through UART.
pub const std_options: std.Options = .{ .logFn = logFn };

fn logFn(
    comptime level: std.log.Level,
    comptime scope: @TypeOf(.EnumLiteral),
    comptime format: []const u8,
    args: anytype,
) void {
    _ = scope;
    uartWrite(level.asText());
    uartWrite(": ");
    var buf: [512]u8 = undefined;
    const msg = std.fmt.bufPrint(&buf, format, args) catch format;
    uartWrite(msg);
    uartWrite("\n");
}

/// Write bytes to the Zisk zkVM UART
pub fn uartWrite(bytes: []const u8) void {
    for (bytes) |byte| {
        ZISK_UART.* = byte;
    }
}

/// Exit via Zisk zkVM ecall (Linux syscall 93 = exit)
fn zkExit(exit_code: u32) noreturn {
    asm volatile (
        \\ ecall
        \\ .align 4
        :
        : [exit_code] "{a0}" (exit_code),
          [syscall] "{a7}" (93),
        : .{ .memory = true });
    while (true) {
        asm volatile ("wfi");
    }
}

// ── Entry point ───────────────────────────────────────────────────────────────
// libziskos.a provides _start which:
//   1. Sets gp from _global_pointer linker symbol
//   2. Sets sp from _init_stack_top linker symbol
//   3. Calls _zisk_main which calls init_sys_alloc() then calls main()
// We export main() as the C entry point that _zisk_main invokes.

/// C entry point: delegate to zesu's runner, write SSZ output.
export fn main() void {
    guestMain() catch |err| {
        std.log.err("fatal: {s}", .{@errorName(err)});
        zkExit(1);
    };
    std.log.info("ok", .{});
    zkExit(0);
}

fn guestMain() !void {
    var zisk_alloc = zisk.ZiskAllocator.init();
    const allocator = zisk_alloc.allocator();

    const result = try runner.runStateless(allocator);
    zkvm_io.write_output(&result.out);
}

/// Rust std's zkvm Stdin calls this — no stdin in zkVM, return EOF.
export fn sys_read(fd: i32, buf: [*]u8, count: usize) isize {
    _ = fd;
    _ = buf;
    _ = count;
    return 0;
}

/// Panic handler for freestanding Zisk zkVM target
pub fn panic(msg: []const u8, error_return_trace: ?*std.builtin.StackTrace, ret_addr: ?usize) noreturn {
    _ = error_return_trace;
    _ = ret_addr;
    uartWrite("PANIC: ");
    uartWrite(msg);
    uartWrite("\n");
    zkExit(1);
}
