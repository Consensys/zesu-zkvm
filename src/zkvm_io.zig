/// zkVM I/O Interface for Zisk
///
/// Implements the Direct Buffer Interface from the zkvm-standards spec.
/// Input and output are memory-mapped regions in the Zisk address space.
const std = @import("std");

/// Zisk zkVM memory regions (zisk 0.16.x)
const ZISK_INPUT_BASE: usize = 0x40000000;
const ZISK_INPUT_SIZE: usize = 0x40000000; // 1GB (0x40000000–0x80000000)
const ZISK_OUTPUT_BASE: usize = 0xa0010000;
const ZISK_OUTPUT_SIZE: usize = 0x00010000; // 64KB

/// Track output position for sequential writes
var output_pos: usize = 0;

/// Read the private input data.
///
/// Memory layout (zisk 0.16.x, INPUT_ADDR = 0x40000000):
///   [0..8]   free_input (u64 = 0) — written by the emulator
///   [8..16]  input_len  (u64 little-endian) — byte count of payload
///   [16..]   data bytes (input_len bytes)
///
/// The input binary passed to ziskemu MUST begin with a u64 LE length
/// field encoding the total size of the remaining data.
pub fn read_input(buf_ptr: *[*]const u8, buf_size: *usize) void {
    const size_ptr: *const u64 = @ptrFromInt(ZISK_INPUT_BASE + 8);
    const input_size = std.mem.littleToNative(u64, size_ptr.*);

    if (input_size == 0 or input_size > ZISK_INPUT_SIZE - 16) {
        buf_ptr.* = @ptrFromInt(ZISK_INPUT_BASE);
        buf_size.* = 0;
        return;
    }

    buf_ptr.* = @ptrFromInt(ZISK_INPUT_BASE + 16);
    buf_size.* = input_size;
}

/// Write public output data. Multiple calls concatenate sequentially.
pub fn write_output(output: [*]const u8, size: usize) void {
    if (output_pos + size > ZISK_OUTPUT_SIZE) {
        @panic("Output exceeds OUTPUT region size (64KB)");
    }
    const output_region: [*]u8 = @ptrFromInt(ZISK_OUTPUT_BASE);
    @memcpy((output_region + output_pos)[0..size], output[0..size]);
    output_pos += size;
}

/// Helper: read input as a slice
pub fn read_input_slice() []const u8 {
    var buf_ptr: [*]const u8 = undefined;
    var buf_size: usize = 0;
    read_input(&buf_ptr, &buf_size);
    return buf_ptr[0..buf_size];
}

/// Helper: write output from a slice
pub fn write_output_slice(output: []const u8) void {
    write_output(output.ptr, output.len);
}
