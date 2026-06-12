/// EIP-196 and EIP-197 implementation for BN254 (alt_bn128) curve operations.
///
/// Provides high-level functions that handle big-endian EIP format conversions
/// and dispatch to the Zisk hardware circuits via the zisk module.
const std = @import("std");
const zisk = @import("./circuits.zig");
const bn254_pairing = @import("./bn254_pairing.zig");

// ── BN254 G1 curve equation: y² ≡ x³ + 3 (mod p) ─────────────────────────────
// All constants are little-endian 32-byte (the format arith256ModDirect expects).
// align(8) ensures word-aligned CSR inputs.

/// BN254 base field prime p, little-endian.
const BN254_P_LE: [32]u8 align(8) = .{
    0x47, 0xfd, 0x7c, 0xd8, 0x16, 0x8c, 0x20, 0x3c,
    0x8d, 0xca, 0x71, 0x68, 0x91, 0x6a, 0x81, 0x97,
    0x5d, 0x58, 0x81, 0x81, 0xb6, 0x45, 0x50, 0xb8,
    0x29, 0xa0, 0x31, 0xe1, 0x72, 0x4e, 0x64, 0x30,
};
const BN254_ZERO_LE: [32]u8 align(8) = .{0} ** 32;
const BN254_THREE_LE: [32]u8 align(8) = .{3} ++ .{0} ** 31;

fn scalarToLimbs(scalar_be: *const [32]u8) [4]u64 {
    var limbs: [4]u64 = undefined;
    for (0..4) |i| {
        const offset = (3 - i) * 8;
        limbs[i] = std.mem.readInt(u64, scalar_be[offset..][0..8], .big);
    }
    return limbs;
}

fn limbsToCoordinate(limbs: [4]u64, coord_be: *[32]u8) void {
    for (0..4) |i| {
        const offset = (3 - i) * 8;
        std.mem.writeInt(u64, coord_be[offset..][0..8], limbs[i], .big);
    }
}

fn isInfinity(point: *const [64]u8) bool {
    for (point) |b| if (b != 0) return false;
    return true;
}

fn pointsEqual(p1: *const [64]u8, p2: *const [64]u8) bool {
    return std.mem.eql(u8, p1, p2);
}

/// Check that an LE-encoded G1 point (x(32) || y(32)) satisfies y² ≡ x³ + 3 (mod p).
/// (0, 0) — point at infinity — is accepted by EIP-196 convention.
/// Without this guard the CSR happily computes on garbage inputs, so off-curve
/// points sneak past `bn254_g1_add` / `bn254_g1_mul` and produce non-spec results.
fn isOnCurveLE(point_le: *const [64]u8) bool {
    if (isInfinity(point_le)) return true;
    const x: *const [32]u8 = point_le[0..32];
    const y: *const [32]u8 = point_le[32..64];
    var x_sq: [32]u8 align(8) = undefined;
    var rhs: [32]u8 align(8) = undefined;
    var lhs: [32]u8 align(8) = undefined;
    // x² mod p
    zisk.arith256ModDirect(x, x, &BN254_ZERO_LE, &BN254_P_LE, &x_sq);
    // x² · x + 3 mod p
    zisk.arith256ModDirect(&x_sq, x, &BN254_THREE_LE, &BN254_P_LE, &rhs);
    // y² mod p
    zisk.arith256ModDirect(y, y, &BN254_ZERO_LE, &BN254_P_LE, &lhs);
    return std.mem.eql(u8, &lhs, &rhs);
}

/// EIP-196 ecAdd: add two BN254 G1 points (big-endian EIP format).
/// Returns `false` when either input is not on-curve; caller is expected to
/// surface `Bn254FieldPointNotAMember` in that case.
pub fn ecAdd(p1_be: *const [64]u8, p2_be: *const [64]u8, result_be: *[64]u8) bool {
    var p1: [64]u8 align(8) = undefined;
    var p2: [64]u8 align(8) = undefined;

    for (0..4) |i| {
        std.mem.writeInt(u64, p1[i * 8 ..][0..8], scalarToLimbs(p1_be[0..32])[i], .little);
        std.mem.writeInt(u64, p1[32 + i * 8 ..][0..8], scalarToLimbs(p1_be[32..64])[i], .little);
        std.mem.writeInt(u64, p2[i * 8 ..][0..8], scalarToLimbs(p2_be[0..32])[i], .little);
        std.mem.writeInt(u64, p2[32 + i * 8 ..][0..8], scalarToLimbs(p2_be[32..64])[i], .little);
    }

    if (!isOnCurveLE(&p1) or !isOnCurveLE(&p2)) return false;

    if (isInfinity(&p1)) {
        @memcpy(&p1, &p2);
    } else if (isInfinity(&p2)) {
        // p1 is already the result
    } else if (pointsEqual(&p1, &p2)) {
        zisk.bn254CurveDouble(&p1);
    } else {
        const x_equal = std.mem.eql(u8, p1[0..32], p2[0..32]);
        const y_equal = std.mem.eql(u8, p1[32..64], p2[32..64]);
        if (x_equal and !y_equal) {
            @memset(&p1, 0);
        } else {
            var points: [128]u8 align(8) = undefined;
            @memcpy(points[0..64], &p1);
            @memcpy(points[64..128], &p2);
            zisk.bn254CurveAdd(&points);
            @memcpy(&p1, points[0..64]);
        }
    }

    var rx: [4]u64 = undefined;
    var ry: [4]u64 = undefined;
    for (0..4) |i| {
        rx[i] = std.mem.readInt(u64, p1[i * 8 ..][0..8], .little);
        ry[i] = std.mem.readInt(u64, p1[32 + i * 8 ..][0..8], .little);
    }
    limbsToCoordinate(rx, result_be[0..32]);
    limbsToCoordinate(ry, result_be[32..64]);
    return true;
}

/// EIP-196 ecMul: scalar multiplication k*P on BN254 (big-endian EIP format).
/// Returns `false` when the input point is not on-curve; caller is expected to
/// surface `Bn254FieldPointNotAMember` in that case.
pub fn ecMul(point_be: *const [64]u8, scalar_be: *const [32]u8, result_be: *[64]u8) bool {
    const k = scalarToLimbs(scalar_be);

    var point: [64]u8 align(8) = undefined;
    for (0..4) |i| {
        std.mem.writeInt(u64, point[i * 8 ..][0..8], scalarToLimbs(point_be[0..32])[i], .little);
        std.mem.writeInt(u64, point[32 + i * 8 ..][0..8], scalarToLimbs(point_be[32..64])[i], .little);
    }

    if (!isOnCurveLE(&point)) return false;

    const is_zero = k[0] == 0 and k[1] == 0 and k[2] == 0 and k[3] == 0;
    if (is_zero or isInfinity(&point)) {
        @memset(result_be, 0);
        return true;
    }
    if (k[0] == 1 and k[1] == 0 and k[2] == 0 and k[3] == 0) {
        @memcpy(result_be, point_be);
        return true;
    }
    if (k[0] == 2 and k[1] == 0 and k[2] == 0 and k[3] == 0) {
        zisk.bn254CurveDouble(&point);
    } else {
        var max_limb: usize = 3;
        while (max_limb > 0 and k[max_limb] == 0) max_limb -= 1;
        var max_bit: u6 = 63;
        const tv = k[max_limb];
        while (max_bit > 0 and (tv >> max_bit) == 0) max_bit -= 1;

        var p_orig: [64]u8 = undefined;
        @memcpy(&p_orig, &point);

        var limb_idx: usize = max_limb;
        var first_iteration: bool = true;
        while (true) {
            const start_bit: usize = if (limb_idx == max_limb) max_bit else 63;
            var bit_idx: usize = start_bit;
            while (true) {
                if (first_iteration and bit_idx == start_bit) {
                    first_iteration = false;
                    if (bit_idx == 0) break;
                    bit_idx -= 1;
                    continue;
                }
                zisk.bn254CurveDouble(&point);
                if (((k[limb_idx] >> @intCast(bit_idx)) & 1) == 1) {
                    var pts: [128]u8 align(8) = undefined;
                    @memcpy(pts[0..64], &point);
                    @memcpy(pts[64..128], &p_orig);
                    zisk.bn254CurveAdd(&pts);
                    @memcpy(&point, pts[0..64]);
                }
                if (bit_idx == 0) break;
                bit_idx -= 1;
            }
            if (limb_idx == 0) break;
            limb_idx -= 1;
        }
    }

    var rx: [4]u64 = undefined;
    var ry: [4]u64 = undefined;
    for (0..4) |i| {
        rx[i] = std.mem.readInt(u64, point[i * 8 ..][0..8], .little);
        ry[i] = std.mem.readInt(u64, point[32 + i * 8 ..][0..8], .little);
    }
    limbsToCoordinate(rx, result_be[0..32]);
    limbsToCoordinate(ry, result_be[32..64]);
    return true;
}

/// EIP-197 ecPairing: pairing check for BN254.
/// `input`: flat array of (G1 x||y, G2 x1||x0||y1||y0) pairs, 192 bytes each.
/// Sets `result[31] = 1` if the pairing equation holds.
pub fn ecPairing(input: []const u8, result: *[32]u8, allocator: std.mem.Allocator) !void {
    if (input.len % 192 != 0) return error.InvalidInputLength;
    const num_pairs = input.len / 192;
    @memset(result, 0);
    if (num_pairs == 0) {
        result[31] = 1;
        return;
    }

    const circuit_input = try allocator.alloc(u8, input.len);
    defer allocator.free(circuit_input);

    for (0..num_pairs) |i| {
        const off = i * 192;
        const g1_xl = scalarToLimbs(input[off..][0..32]);
        const g1_yl = scalarToLimbs(input[off + 32 ..][0..32]);
        for (0..4) |j| {
            std.mem.writeInt(u64, circuit_input[off + j * 8 ..][0..8], g1_xl[j], .little);
            std.mem.writeInt(u64, circuit_input[off + 32 + j * 8 ..][0..8], g1_yl[j], .little);
        }
        for ([_]usize{ 64, 96, 128, 160 }, 0..) |src_off, k| {
            const lx = scalarToLimbs(input[off + src_off ..][0..32]);
            for (0..4) |j| {
                std.mem.writeInt(u64, circuit_input[off + src_off + j * 8 ..][0..8], lx[j], .little);
            }
            _ = k;
        }
    }

    const pairing_valid = try bn254_pairing.pairingCheckBytes(allocator, circuit_input);
    if (pairing_valid) result[31] = 1;
}
