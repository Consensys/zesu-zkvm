/// ZisK host object: satisfies all extern symbol references in zesu.rv64im.o
///
/// Exports:
///   read_input / write_output        — zkvm-standards io-interface
///   zkvm_keccak256 … zkvm_secp256r1_verify — CSR-backed accelerators
///   zkvm_log / zkvm_exit             — runtime (UART + ecall)
///   sys_read                         — Rust std stdin stub
///
/// The following symbols are NOT exported here; they are resolved from
/// libziskos.a at final link time (no CSR-level implementation exists):
///   zkvm_bn254_pairing, zkvm_kzg_point_eval
///   zkvm_bls12_g1_{add,msm}, zkvm_bls12_g2_{add,msm}, zkvm_bls12_pairing
///   zkvm_bls12_map_fp{,2}_to_g{1,2}, zkvm_secp256k1_verify
///
/// NOTE: the BLS12 / pairing field-validation wrappers from zisk_accel_impl
/// are bypassed in this path; libziskos.a provides the raw implementations.
/// Field-validation for malformed inputs is a known follow-up item.
const std = @import("std");
const accel = @import("accel_impl");
const io = @import("zkvm_io");

/// Zisk zkVM UART — byte writes here appear in ziskemu console output
const ZISK_UART: *volatile u8 = @ptrFromInt(0xa0000200);

// ── Runtime ───────────────────────────────────────────────────────────────────

/// Logging sink used by zesu.o's std_options.logFn (src/zkvm/root.zig).
export fn zkvm_log(level: u8, msg_ptr: [*]const u8, msg_len: usize) void {
    _ = level;
    for (msg_ptr[0..msg_len]) |byte| {
        ZISK_UART.* = byte;
    }
    ZISK_UART.* = '\n';
}

/// Halt/exit: Linux syscall 93 (exit) via ecall.
export fn zkvm_exit(code: i32) noreturn {
    asm volatile (
        \\ ecall
        \\ .align 4
        :
        : [code] "{a0}" (code),
          [syscall] "{a7}" (@as(u32, 93)),
        : .{ .memory = true });
    while (true) {
        asm volatile ("wfi");
    }
}

/// Rust std's zkvm Stdin calls this — no stdin in zkVM, return EOF.
export fn sys_read(fd: i32, buf: [*]u8, count: usize) isize {
    _ = fd;
    _ = buf;
    _ = count;
    return 0;
}

// ── IO — zkvm-standards io-interface ─────────────────────────────────────────

export fn read_input(buf_ptr: *[*]const u8, buf_size: *usize) void {
    io.read_input(buf_ptr, buf_size);
}

/// Adapt: zesu.o calls write_output(ptr, len) C ABI; zkvm_io takes []const u8.
export fn write_output(ptr: [*]const u8, len: usize) void {
    io.write_output(ptr[0..len]);
}

// ── Accelerators — CSR-backed implementations ─────────────────────────────────

export fn zkvm_keccak256(data: [*]const u8, len: usize, output: *[32]u8) i32 {
    accel.keccak256(data[0..len], output);
    return 0;
}

export fn zkvm_sha256(data: [*]const u8, len: usize, output: *[32]u8) i32 {
    accel.sha256(data[0..len], output);
    return 0;
}

export fn zkvm_secp256k1_ecrecover(msg: *const [32]u8, sig: *const [64]u8, recid: u8, output: *[64]u8) i32 {
    return if (accel.ecrecover(msg, sig, recid, output)) 0 else -1;
}

export fn zkvm_ripemd160(data: [*]const u8, len: usize, output: *[32]u8) i32 {
    accel.ripemd160(data[0..len], output);
    return 0;
}

export fn zkvm_modexp(
    base: [*]const u8,
    base_len: usize,
    exp: [*]const u8,
    exp_len: usize,
    modulus: [*]const u8,
    mod_len: usize,
    output: [*]u8,
) i32 {
    _ = accel.modexp(base[0..base_len], exp[0..exp_len], modulus[0..mod_len], output[0..mod_len]);
    return 0;
}

export fn zkvm_bn254_g1_add(p1: *const [64]u8, p2: *const [64]u8, result: *[64]u8) i32 {
    return if (accel.bn254_g1_add(p1, p2, result)) 0 else -1;
}

export fn zkvm_bn254_g1_mul(point: *const [64]u8, scalar: *const [32]u8, result: *[64]u8) i32 {
    return if (accel.bn254_g1_mul(point, scalar, result)) 0 else -1;
}

export fn zkvm_blake2f(rounds: u32, h: *[64]u8, m: *const [128]u8, t: *const [16]u8, f: u8) i32 {
    return if (accel.blake2f(rounds, h, m, t, f)) 0 else -1;
}

export fn zkvm_secp256r1_verify(msg: *const [32]u8, sig: *const [64]u8, pubkey: *const [64]u8, verified: *bool) i32 {
    accel.secp256r1_verify(msg, sig, pubkey, verified);
    return 0;
}
