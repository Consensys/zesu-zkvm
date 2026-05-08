/// accel_impl for zesu-zkvm/zisk.
///
/// Uses ZisK hardware circuits (CSRs) for everything that has a circuit, and
/// pure-Zig for ripemd160 (no CSR exists).  Only delegates to libziskos.a via
/// extern fn zkvm_* for operations that lack a complete CSR-level implementation:
///
///   bn254_pairing  — Fp2 CSRs exist but full Miller loop + final-exp requires
///                    substantial software; libziskos.a has a correct implementation
///   kzg_point_eval — no CSR; libziskos.a has a correct implementation
///   BLS12-381      — G1/G2 and Fp2 CSRs exist but protocol software (MSM, pairing,
///                    map-to-curve) is not yet implemented
///   secp256k1_verify — not called in stateless block execution; delegated
///
/// CSR coverage in this module:
///   keccak256      — keccakf CSR (0x800)
///   sha256         — sha256Compress CSR (0x805), BE/LE conversion applied
///   ecrecover      — arith256Mod + secp256k1Add/Double CSRs via secp256k1.zig
///   ripemd160      — pure-Zig (no ZisK circuit)
///   modexp         — arith256ModDirect CSR for ≤32-byte inputs, big-int fallback
///   bn254_g1_add   — bn254CurveAdd CSR (0x806) via eip196.zig
///   bn254_g1_mul   — bn254CurveDouble + bn254CurveAdd CSRs via eip196.zig
///   blake2f        — pure-Zig (blake2bRound CSR is blake2B, not blake2F)
///   secp256r1_verify — secp256r1Add/Double CSRs via secp256r1.zig
const std = @import("std");
const zisk = @import("zisk");
const secp256k1_impl = @import("./secp256k1.zig");
const secp256r1_impl = @import("./secp256r1.zig");
const blake2f_impl = @import("./blake2f.zig");
const eip196 = @import("./eip196.zig");
const ripemd160_impl = @import("./ripemd160.zig");

// Pair types — binary-compatible with accelerators.zig and extern_bridge.zig.
const Bn254PairingPair = extern struct { g1: [64]u8, g2: [128]u8 };
const Bls12G1MsmPair = extern struct { point: [96]u8, scalar: [32]u8 };
const Bls12G2MsmPair = extern struct { point: [192]u8, scalar: [32]u8 };
const Bls12PairingPair = extern struct { g1: [96]u8, g2: [192]u8 };

// ── extern fn declarations — libziskos.a fallbacks ────────────────────────────
// Only for operations without a complete CSR-level implementation.

extern fn zkvm_secp256k1_verify(msg: *const [32]u8, sig: *const [64]u8, pubkey: *const [64]u8, verified: *bool) i32;
extern fn zkvm_bn254_pairing(pairs: [*]const Bn254PairingPair, num_pairs: usize, verified: *bool) i32;
extern fn zkvm_kzg_point_eval(commitment: *const [48]u8, z: *const [32]u8, y: *const [32]u8, proof: *const [48]u8, verified: *bool) i32;
extern fn zkvm_bls12_g1_add(p1: *const [96]u8, p2: *const [96]u8, result: *[96]u8) i32;
extern fn zkvm_bls12_g1_msm(pairs: [*]const Bls12G1MsmPair, num_pairs: usize, result: *[96]u8) i32;
extern fn zkvm_bls12_g2_add(p1: *const [192]u8, p2: *const [192]u8, result: *[192]u8) i32;
extern fn zkvm_bls12_g2_msm(pairs: [*]const Bls12G2MsmPair, num_pairs: usize, result: *[192]u8) i32;
extern fn zkvm_bls12_pairing(pairs: [*]const Bls12PairingPair, num_pairs: usize, verified: *bool) i32;
extern fn zkvm_bls12_map_fp_to_g1(field_element: *const [48]u8, result: *[96]u8) i32;
extern fn zkvm_bls12_map_fp2_to_g2(field_element: *const [96]u8, result: *[192]u8) i32;

// ── Keccak-256 — keccakf CSR (0x800) ─────────────────────────────────────────

const KECCAK_RATE = 136; // 1088-bit rate for Keccak-256

pub fn keccak256(data: []const u8, output: *[32]u8) void {
    var state: [200]u8 align(8) = undefined;
    for (@as(*[25]u64, @ptrCast(&state))) |*w| w.* = 0;
    var offset: usize = 0;

    while (offset + KECCAK_RATE <= data.len) : (offset += KECCAK_RATE) {
        for (0..KECCAK_RATE) |i| state[i] ^= data[offset + i];
        zisk.keccakf(&state);
    }

    const remaining = data.len - offset;
    for (0..remaining) |i| state[i] ^= data[offset + i];
    state[remaining] ^= 0x01;
    state[KECCAK_RATE - 1] ^= 0x80;
    zisk.keccakf(&state);

    output.* = state[0..32].*;
}

// ── SHA-256 — sha256Compress CSR (0x805) with correct BE output ───────────────
// The CSR returns state as 8×u32 in little-endian (native RISC-V order).
// SHA-256 output must be big-endian per spec, so each word is byte-swapped.

const SHA256_IV: [8]u32 = .{
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
};

fn sha256CompressState(state: *[8]u32, block: *const [64]u8) void {
    var buf: [96]u8 align(8) = undefined;
    @memcpy(buf[0..64], block);
    @memcpy(buf[64..96], std.mem.sliceAsBytes(state));
    zisk.sha256Compress(&buf);
    @memcpy(std.mem.sliceAsBytes(state), buf[64..96]);
}

pub fn sha256(data: []const u8, output: *[32]u8) void {
    var state: [8]u32 align(8) = SHA256_IV;
    const bit_len: u64 = @as(u64, data.len) * 8;
    var offset: usize = 0;

    while (offset + 64 <= data.len) : (offset += 64) {
        sha256CompressState(&state, data[offset..][0..64]);
    }

    const remaining = data.len - offset;
    var block1: [64]u8 align(8) = .{0} ** 64;
    @memcpy(block1[0..remaining], data[offset..]);
    block1[remaining] = 0x80;

    if (remaining < 56) {
        std.mem.writeInt(u64, block1[56..64], bit_len, .big);
        sha256CompressState(&state, &block1);
    } else {
        sha256CompressState(&state, &block1);
        var block2: [64]u8 align(8) = .{0} ** 64;
        std.mem.writeInt(u64, block2[56..64], bit_len, .big);
        sha256CompressState(&state, &block2);
    }

    for (state, 0..) |word, i| {
        std.mem.writeInt(u32, output[i * 4 ..][0..4], word, .big);
    }
}

// ── ECRECOVER — secp256k1 CSRs ────────────────────────────────────────────────

pub fn ecrecover(msg: *const [32]u8, sig: *const [64]u8, recid: u8, output: *[64]u8) bool {
    return secp256k1_impl.recoverPubkey(msg, sig, recid, output);
}

// ── secp256k1_verify — delegated (not called in stateless execution) ──────────

pub fn secp256k1_verify(msg: *const [32]u8, sig: *const [64]u8, pubkey: *const [64]u8, verified: *bool) void {
    _ = zkvm_secp256k1_verify(msg, sig, pubkey, verified);
}

// ── RIPEMD-160 — pure Zig (no ZisK circuit) ──────────────────────────────────
// output[0..20] = hash, output[20..32] = 0.

pub fn ripemd160(data: []const u8, output: *[32]u8) void {
    const hash = ripemd160_impl.ripemd160(data);
    output.* = .{0} ** 32;
    @memcpy(output[0..20], &hash);
}

// ── ModExp — arith256ModDirect CSR for ≤32-byte inputs, big-int fallback ──────

fn rev32(b: [32]u8) [32]u8 {
    var r = b;
    std.mem.reverse(u8, &r);
    return r;
}

fn padBE32(src: []const u8) [32]u8 {
    var out: [32]u8 = [_]u8{0} ** 32;
    @memcpy(out[32 - src.len ..], src);
    return out;
}

fn modexp256(base: []const u8, exp: []const u8, modulus: []const u8, output: []u8) void {
    const exp_be = padBE32(exp);
    const mod_le = rev32(padBE32(modulus));
    const zero: [32]u8 = [_]u8{0} ** 32;
    var one_le: [32]u8 = [_]u8{0} ** 32;
    one_le[0] = 1;

    var base_le = rev32(padBE32(base));
    var a_le: [32]u8 = undefined;
    zisk.arith256ModDirect(&base_le, &one_le, &zero, &mod_le, &a_le);

    var result_le = one_le;

    var highest_bit: usize = 0;
    for (0..256) |i| {
        const byte_idx = i / 8;
        const bit_idx: u3 = @intCast(i % 8);
        if ((exp_be[31 - byte_idx] >> bit_idx) & 1 != 0) highest_bit = i;
    }

    for (0..highest_bit + 1) |i| {
        const byte_idx = i / 8;
        const bit_idx: u3 = @intCast(i % 8);
        if ((exp_be[31 - byte_idx] >> bit_idx) & 1 != 0) {
            var tmp: [32]u8 = undefined;
            zisk.arith256ModDirect(&result_le, &a_le, &zero, &mod_le, &tmp);
            result_le = tmp;
        }
        if (i < highest_bit) {
            var tmp: [32]u8 = undefined;
            zisk.arith256ModDirect(&a_le, &a_le, &zero, &mod_le, &tmp);
            a_le = tmp;
        }
    }

    const result_be = rev32(result_le);
    @memset(output, 0);
    const copy_len = @min(result_be.len, output.len);
    @memcpy(output[output.len - copy_len ..], result_be[result_be.len - copy_len ..]);
}

// ── Pure-Zig big-integer helpers for modexp with mod > 32 bytes ───────────────

fn bigCmp(a: []const u8, b: []const u8) std.math.Order {
    var ai: usize = 0;
    var bi: usize = 0;
    while (ai < a.len and a[ai] == 0) ai += 1;
    while (bi < b.len and b[bi] == 0) bi += 1;
    const alen = a.len - ai;
    const blen = b.len - bi;
    if (alen != blen) return if (alen < blen) .lt else .gt;
    return std.mem.order(u8, a[ai..], b[bi..]);
}

fn bigSubInPlace(a: []u8, b: []const u8) void {
    var borrow: u8 = 0;
    var i: usize = a.len;
    while (i > 0) {
        i -= 1;
        const lsb_pos = a.len - 1 - i;
        const bval: u8 = if (lsb_pos < b.len) b[b.len - 1 - lsb_pos] else 0;
        const sub: i16 = @as(i16, a[i]) - @as(i16, bval) - @as(i16, borrow);
        if (sub < 0) {
            a[i] = @intCast(sub + 256);
            borrow = 1;
        } else {
            a[i] = @intCast(sub);
            borrow = 0;
        }
    }
}

fn bigBitLen(a: []const u8) usize {
    for (a, 0..) |byte, i| {
        if (byte != 0) return (a.len - i) * 8 - @as(usize, @clz(byte));
    }
    return 0;
}

fn bigShiftInto(dst: []u8, m: []const u8, shift: usize) void {
    @memset(dst, 0);
    const byte_shift = shift / 8;
    const bit_off: u3 = @intCast(shift % 8);
    var i: usize = dst.len;
    while (i > 0) {
        i -= 1;
        const lsb_pos = dst.len - 1 - i;
        if (lsb_pos < byte_shift) continue;
        const src_lsb = lsb_pos - byte_shift;
        if (src_lsb >= m.len) continue;
        const mb = m[m.len - 1 - src_lsb];
        dst[i] |= mb << bit_off;
        if (bit_off != 0 and i > 0) dst[i - 1] |= mb >> @as(u3, @intCast(8 - @as(u4, bit_off)));
    }
}

fn bigReduce(a: []u8, m: []const u8) void {
    if (bigCmp(a, m) == .lt) return;
    var shifted_buf: [2048]u8 = undefined;
    const shifted_m = shifted_buf[0..a.len];
    while (bigCmp(a, m) != .lt) {
        const a_bl = bigBitLen(a);
        const m_bl = bigBitLen(m);
        var shift = a_bl - m_bl;
        bigShiftInto(shifted_m, m, shift);
        if (bigCmp(shifted_m, a) == .gt) {
            shift -= 1;
            bigShiftInto(shifted_m, m, shift);
        }
        bigSubInPlace(a, shifted_m);
    }
}

fn bigModMulInto(scratch: []u8, a: []const u8, b: []const u8, m: []const u8, out: []u8) void {
    @memset(scratch, 0);
    var ai: usize = 0;
    while (ai < a.len) : (ai += 1) {
        const a_byte = a[a.len - 1 - ai];
        if (a_byte == 0) continue;
        var carry: u32 = 0;
        var bi: usize = 0;
        while (bi < b.len) : (bi += 1) {
            const pidx = scratch.len - 1 - ai - bi;
            const cur = @as(u32, scratch[pidx]) + @as(u32, a_byte) * @as(u32, b[b.len - 1 - bi]) + carry;
            scratch[pidx] = @truncate(cur);
            carry = cur >> 8;
        }
        var ci: usize = scratch.len - 1 - ai - b.len;
        while (carry > 0) {
            const cur = @as(u32, scratch[ci]) + carry;
            scratch[ci] = @truncate(cur);
            carry = cur >> 8;
            if (ci == 0) break;
            ci -= 1;
        }
    }
    bigReduce(scratch, m);
    @memset(out, 0);
    const src_start = scratch.len - @min(scratch.len, out.len);
    const dst_start = out.len - (scratch.len - src_start);
    @memcpy(out[dst_start..], scratch[src_start..]);
}

fn modexpGeneral(alloc: std.mem.Allocator, base: []const u8, exp: []const u8, modulus: []const u8, output: []u8) !void {
    const n = modulus.len;
    const result = try alloc.alloc(u8, n);
    defer alloc.free(result);
    @memset(result, 0);
    if (n > 0) result[n - 1] = 1;

    const a = try alloc.alloc(u8, n);
    defer alloc.free(a);
    @memset(a, 0);
    const base_copy_len = @min(base.len, n);
    @memcpy(a[n - base_copy_len ..], base[base.len - base_copy_len ..]);
    bigReduce(a, modulus);

    const tmp = try alloc.alloc(u8, n);
    defer alloc.free(tmp);
    const scratch = try alloc.alloc(u8, n * 2);
    defer alloc.free(scratch);

    var highest_bit: usize = 0;
    for (0..exp.len * 8) |i| {
        const byte_idx = i / 8;
        const bit_idx: u3 = @intCast(i % 8);
        if ((exp[exp.len - 1 - byte_idx] >> bit_idx) & 1 != 0) highest_bit = i;
    }

    for (0..highest_bit + 1) |i| {
        const byte_idx = i / 8;
        const bit_idx: u3 = @intCast(i % 8);
        if ((exp[exp.len - 1 - byte_idx] >> bit_idx) & 1 != 0) {
            bigModMulInto(scratch, result, a, modulus, tmp);
            @memcpy(result, tmp);
        }
        if (i < highest_bit) {
            bigModMulInto(scratch, a, a, modulus, tmp);
            @memcpy(a, tmp);
        }
    }

    @memset(output, 0);
    const copy_len = @min(result.len, output.len);
    @memcpy(output[output.len - copy_len ..], result[result.len - copy_len ..]);
}

pub fn modexp(base: []const u8, exp: []const u8, modulus: []const u8, output: []u8) bool {
    if (modulus.len == 0 or std.mem.allEqual(u8, modulus, 0)) {
        @memset(output, 0);
        return true;
    }

    const mod_is_one = blk: {
        for (modulus[0 .. modulus.len - 1]) |b| if (b != 0) break :blk false;
        break :blk modulus[modulus.len - 1] == 1;
    };
    if (mod_is_one) {
        @memset(output, 0);
        return true;
    }

    if (exp.len == 0 or std.mem.allEqual(u8, exp, 0)) {
        @memset(output, 0);
        if (output.len > 0) output[output.len - 1] = 1;
        return true;
    }

    if (base.len == 0 or std.mem.allEqual(u8, base, 0)) {
        @memset(output, 0);
        return true;
    }

    if (base.len <= 32 and exp.len <= 32 and modulus.len <= 32 and output.len <= 32) {
        modexp256(base, exp, modulus, output);
        return true;
    }

    var allocator_state = zisk.ZiskAllocator.init();
    const alloc = allocator_state.allocator();
    modexpGeneral(alloc, base, exp, modulus, output) catch @memset(output, 0);
    return true;
}

// ── BN254 G1 add/mul — bn254CurveAdd/Double CSRs via eip196.zig ───────────────

pub fn bn254_g1_add(p1: *const [64]u8, p2: *const [64]u8, result: *[64]u8) bool {
    eip196.ecAdd(p1, p2, result);
    return true;
}

pub fn bn254_g1_mul(point: *const [64]u8, scalar: *const [32]u8, result: *[64]u8) bool {
    eip196.ecMul(point, scalar, result);
    return true;
}

// ── BN254 pairing — delegated to libziskos.a ──────────────────────────────────
// Fp2 CSRs (0x808–0x80A) exist, but the full Miller loop + final exponentiation
// requires substantial software not yet implemented.  libziskos.a is correct.

pub fn bn254_pairing(pairs: anytype, verified: *bool) bool {
    const ptr: [*]const Bn254PairingPair = @ptrCast(pairs.ptr);
    return zkvm_bn254_pairing(ptr, pairs.len, verified) == 0;
}

// ── BLAKE2f — pure Zig (blake2bRound CSR is BLAKE2b, not BLAKE2f) ────────────

pub fn blake2f(rounds: u32, h: *[64]u8, m: *const [128]u8, t: *const [16]u8, f: u8) bool {
    if (f > 1) return false;
    blake2f_impl.compress(rounds, h, m, t, f == 1);
    return true;
}

// ── KZG point evaluation — delegated to libziskos.a (no CSR) ─────────────────

pub fn kzg_point_eval(commitment: *const [48]u8, z: *const [32]u8, y: *const [32]u8, proof: *const [48]u8, verified: *bool) bool {
    return zkvm_kzg_point_eval(commitment, z, y, proof, verified) == 0;
}

// ── BLS12-381 — delegated to libziskos.a ──────────────────────────────────────
// G1/G2 and Fp2 CSRs exist, but MSM, pairing, and map-to-curve software is
// not yet implemented.

pub fn bls12_g1_add(p1: *const [96]u8, p2: *const [96]u8, result: *[96]u8) bool {
    return zkvm_bls12_g1_add(p1, p2, result) == 0;
}

pub fn bls12_g1_msm(pairs: anytype, result: *[96]u8) bool {
    const ptr: [*]const Bls12G1MsmPair = @ptrCast(pairs.ptr);
    return zkvm_bls12_g1_msm(ptr, pairs.len, result) == 0;
}

pub fn bls12_g2_add(p1: *const [192]u8, p2: *const [192]u8, result: *[192]u8) bool {
    return zkvm_bls12_g2_add(p1, p2, result) == 0;
}

pub fn bls12_g2_msm(pairs: anytype, result: *[192]u8) bool {
    const ptr: [*]const Bls12G2MsmPair = @ptrCast(pairs.ptr);
    return zkvm_bls12_g2_msm(ptr, pairs.len, result) == 0;
}

pub fn bls12_pairing(pairs: anytype, verified: *bool) bool {
    const ptr: [*]const Bls12PairingPair = @ptrCast(pairs.ptr);
    return zkvm_bls12_pairing(ptr, pairs.len, verified) == 0;
}

pub fn bls12_map_fp_to_g1(field_element: *const [48]u8, result: *[96]u8) bool {
    return zkvm_bls12_map_fp_to_g1(field_element, result) == 0;
}

pub fn bls12_map_fp2_to_g2(field_element: *const [96]u8, result: *[192]u8) bool {
    return zkvm_bls12_map_fp2_to_g2(field_element, result) == 0;
}

// ── secp256r1 verify — secp256r1Add/Double CSRs ───────────────────────────────

pub fn secp256r1_verify(msg: *const [32]u8, sig: *const [64]u8, pubkey: *const [64]u8, verified: *bool) void {
    verified.* = secp256r1_impl.verifySignature(msg, sig, pubkey);
}
