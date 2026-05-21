/// zkVM I/O Interface for Linea
///
/// Input: memory-mapped at _input_start (0x08800000).
///   [0..8]   payload_len  — u64 LE, byte count of SSZ body
///   [8..]    SSZ body
///
/// Output / logging: Linux write ecall (a7=64, fd=1 stdout).
/// The Linea zkVM captures stdout bytes as the program's observable output.
const std = @import("std");

/// Linker-defined start of the IN memory region (0x08800000).
extern var _input_start: u8;

/// Read the private input data from the memory-mapped IN region.
pub fn read_input(buf_ptr: *[*]const u8, buf_size: *usize) void {
    const base = @intFromPtr(&_input_start);
    const size_ptr: *const u64 = @ptrFromInt(base);
    const payload_len = std.mem.littleToNative(u64, size_ptr.*);

    buf_ptr.* = @ptrFromInt(base + 8);
    buf_size.* = @intCast(payload_len);
}

/// Write bytes via the Linux write ecall (a7=64, fd=1).
fn writeEcall(ptr: [*]const u8, len: usize) void {
    _ = asm volatile ("ecall"
        : [ret] "={a0}" (-> usize),
        : [fd] "{a0}" (@as(usize, 1)),
          [buf] "{a1}" (@intFromPtr(ptr)),
          [count] "{a2}" (len),
          [syscall] "{a7}" (@as(usize, 64)),
        : .{ .memory = true });
}

/// Write public output bytes (SSZ commitment) to stdout.
pub fn write_output(output: []const u8) void {
    writeEcall(output.ptr, output.len);
}

/// Print a UTF-8 string to stdout (debug/log output).
pub fn printStr(s: []const u8) void {
    if (s.len > 0) writeEcall(s.ptr, s.len);
}
