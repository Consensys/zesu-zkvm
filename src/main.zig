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

/// SHA-256 over arbitrary-length data via the ZisK SHA-256 CSR accelerator.
/// Resolved at link time from accel_impl.zig (same object linked into the exe).
extern fn zkvm_sha256(data: [*]const u8, len: usize, output: *[32]u8) i32;

/// Guest entry point: read input, deserialize, execute block, write ProofOutput.
///
/// Input layout (ere wire format):
///   [new_payload_request_root: u8; 32]   -- SSZ hash-tree-root, precomputed by host
///   [block_rlp_len: u64 big-endian]      -- zevm-stateless binary format (unchanged)
///   [block_rlp bytes]
///   [state_count u64] [u64 len + node bytes] × N
///   [codes_count u64] [u64 len + code bytes] × N
///   [keys_count u64]  [u64 len + key bytes]  × N  (ignored)
///   [headers_count u64] [u64 len + header RLP] × N
///
/// Output layout (ere wire format, matches StatelessValidatorOutput):
///   sha256([new_payload_request_root (32)] ++ [successful_block_validation (1)])
///   = 32 bytes
pub fn main() !void {
    var zisk_alloc = zisk.ZiskAllocator.init();
    const allocator = zisk_alloc.allocator();

    const input_data = zkvm_io.read_input_slice();

    std.log.info("input_len={d}", .{input_data.len});
    if (input_data.len < 32) return error.NoInput;

    // First 32 bytes: SSZ hash-tree-root of NewPayloadRequest (precomputed by host).
    const new_payload_request_root: [32]u8 = input_data[0..32].*;
    const block_data = input_data[32..];

    const si = try deserialize.fromBytes(allocator, block_data);
    const ep = &si.new_payload_request.execution_payload;
    std.log.info("block={d} txns={d}", .{ ep.block_number, ep.transactions.len });

    const exec_result = executor.executeStatelessInput(allocator, si, null);
    const success: u8 = if (exec_result) |_| 1 else |err| blk: {
        std.log.err("execution failed: {s}", .{@errorName(err)});
        break :blk 0;
    };

    // Encode output as StatelessValidatorOutput: root (32) ++ success (1), then SHA-256.
    // align(8): SHA-256 CSR requires 8-byte-aligned data and output pointers.
    var pre_image: [33]u8 align(8) = undefined;
    pre_image[0..32].* = new_payload_request_root;
    pre_image[32] = success;
    var digest: [32]u8 align(8) = undefined;
    _ = zkvm_sha256(&pre_image, pre_image.len, &digest);

    std.log.info("root: 0x{x} success={d}", .{ &new_payload_request_root, success });
    zkvm_io.write_output_slice(&digest);
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
