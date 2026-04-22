const std = @import("std");
const zisk = @import("zisk");
const executor = @import("executor");
const deserialize = @import("./deserialize.zig");
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

// ── Assembly entry point ──────────────────────────────────────────────────────
// Must be the very first thing in .text._start.  Pure asm: no Zig prologue.
comptime {
    asm (
        \\.section .text._start,"ax",%progbits
        \\.global _start
        \\.type _start, @function
        \\_start:
        \\  li sp, 0xa0120000    // Initialize stack pointer
        \\  li gp, 0xa0020000    // Initialize global pointer
        \\  call _start_main     // Jump to Zig entry
        \\  .align 4
        \\1: wfi
        \\  j 1b
        \\.size _start, . - _start
    );
}

/// First Zig function executed after sp/gp are set by _start
export fn _start_main() noreturn {
    main() catch |err| {
        std.log.err("fatal: {s}", .{@errorName(err)});
        zkExit(1);
    };

    std.log.info("ok", .{});
    zkExit(0);
}

/// Guest entry point: read input, deserialize, execute block, write ProofOutput.
pub fn main() !void {
    var zisk_alloc = zisk.ZiskAllocator.init();
    const allocator = zisk_alloc.allocator();

    const input_data = zkvm_io.read_input_slice();

    std.log.info("input_len={d}", .{input_data.len});
    if (input_data.len == 0) return error.NoInput;

    const si = try deserialize.fromBytes(allocator, input_data);
    const ep = &si.new_payload_request.execution_payload;
    std.log.info("block={d} txns={d}", .{ ep.block_number, ep.transactions.len });

    const output = try executor.executeStatelessInput(allocator, si, null);

    // Write ProofOutput to zkVM output region
    // Format: pre_state_root (32) | post_state_root (32) | receipts_root (32)
    std.log.info("pre-state: 0x{x} ", .{&output.pre_state_root});
    std.log.info("post-state: 0x{x} ", .{&output.post_state_root});
    std.log.info("receipts: 0x{x} ", .{&output.receipts_root});
    zkvm_io.write_output_slice(&output.pre_state_root);
    zkvm_io.write_output_slice(&output.post_state_root);
    zkvm_io.write_output_slice(&output.receipts_root);
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
