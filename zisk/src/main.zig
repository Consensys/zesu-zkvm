const std = @import("std");
const zisk = @import("zisk");
const executor = @import("executor");
const ssz_decode = @import("ssz_decode");
const ssz_output = @import("ssz_output");
const zkvm_io = @import("./zkvm_io.zig");

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

/// C entry point: read SSZ input, execute block, write SSZ output.
///
/// Input: raw SszStatelessInput bytes.
///
/// Output: SszStatelessValidationResult — 41 bytes
///   [0..32] new_payload_request_root (computed here via hash_tree_root)
///   [32]    successful_validation
///   [33..41] chain_config.chain_id (u64 LE)
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

    const input_data = zkvm_io.read_input_slice();
    std.log.info("input_len={d}", .{input_data.len});

    const si = try ssz_decode.decode(allocator, input_data);

    const ep = &si.new_payload_request.execution_payload;
    std.log.info("block={d} txns={d}", .{ ep.block_number, ep.transactions.len });

    const exec_result = executor.executeStatelessInput(allocator, si, si.chain_config.fork_name);
    const success = if (exec_result) |_| true else |err| blk: {
        std.log.err("execution failed: {s}", .{@errorName(err)});
        break :blk false;
    };

    const out = try ssz_output.serialize(allocator, si.new_payload_request, si.chain_config.chain_id, success);
    std.log.info("root: 0x{x} success={d}", .{ out[0..32], @intFromBool(success) });
    zkvm_io.write_output_slice(&out);
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
