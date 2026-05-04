//! P-256 (secp256r1) ECDSA signature verification for the Zisk zkVM target.
//!
//! Uses Zisk CSR hardware circuits:
//!   - arith256ModDirect (0x802): (a*b + c) mod m
//!   - secp256r1Add (0x817): P-256 point addition    (indirect_params=2)
//!   - secp256r1Double (0x818): P-256 point doubling
//!
//! Point format (CSR): 64 bytes = x(32 LE bytes) || y(32 LE bytes).
//! Field/scalar elements use the same LE 32-byte representation (byte 0 = LSB).

const std = @import("std");
const zisk = @import("zisk");

// ── P-256 constants (little-endian 256-bit integers) ──────────────────────────
// align(8) on constants ensures word-aligned CSR inputs without runtime cost.

/// Field prime p = 2²⁵⁶ − 2²²⁴ + 2¹⁹² + 2⁹⁶ − 1
const P_LE: Fe align(8) = .{
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
};

/// Curve order n
const N_LE: Fe align(8) = .{
    0x51, 0x25, 0x63, 0xFC, 0xC2, 0xCA, 0xB9, 0xF3,
    0x84, 0x9E, 0x17, 0xA7, 0xAD, 0xFA, 0xE6, 0xBC,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
};

/// Generator x-coordinate
const GX_LE: Fe align(8) = .{
    0x96, 0xC2, 0x98, 0xD8, 0x45, 0x39, 0xA1, 0xF4,
    0xA0, 0x33, 0xEB, 0x2D, 0x81, 0x7D, 0x03, 0x77,
    0xF2, 0x40, 0xA4, 0x63, 0xE5, 0xE6, 0xBC, 0xF8,
    0x47, 0x42, 0x2C, 0xE1, 0xF2, 0xD1, 0x17, 0x6B,
};

/// Generator y-coordinate
const GY_LE: Fe align(8) = .{
    0xF5, 0x51, 0xBF, 0x37, 0x68, 0x40, 0xB6, 0xCB,
    0xCE, 0x5E, 0x31, 0x6B, 0x57, 0x33, 0xCE, 0x2B,
    0x16, 0x9E, 0x0F, 0x7C, 0x4A, 0xEB, 0xE7, 0x8E,
    0x9B, 0x7F, 0x1A, 0xFE, 0xE2, 0x42, 0xE3, 0x4F,
};

/// n − 2 (big-endian) — exponent for scalar inverse via Fermat: a^(n−2) mod n
const N_MINUS_2_BE: [32]u8 = .{
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84,
    0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x4F,
};

const ZERO: Fe align(8) = .{0} ** 32;
const ONE: Fe align(8) = .{1} ++ (.{0} ** 31);

// ── Types ──────────────────────────────────────────────────────────────────────

/// 256-bit field element in little-endian byte order (byte 0 = LSB).
const Fe = [32]u8;

/// A P-256 affine point. null = point at infinity.
const Point = struct { x: Fe align(8), y: Fe align(8) };

// ── Byte-order helpers ─────────────────────────────────────────────────────────

fn beToLe(be: *const [32]u8) Fe {
    var le: Fe align(8) = undefined;
    for (0..32) |i| le[i] = be[31 - i];
    return le;
}

// ── Field arithmetic (via arith256ModDirect CSR) ───────────────────────────────

fn feMul(a: *const Fe, b: *const Fe, m: *const Fe) Fe {
    var out: Fe align(8) = undefined;
    zisk.arith256ModDirect(a, b, &ZERO, m, &out);
    return out;
}

fn feIsZero(a: *const Fe) bool {
    return std.mem.eql(u8, a, &ZERO);
}

/// Numeric less-than for LE 256-bit integers (MSB = index 31).
fn feNumericLessThan(a: *const Fe, b: *const Fe) bool {
    var i: usize = 32;
    while (i > 0) {
        i -= 1;
        if (a[i] < b[i]) return true;
        if (a[i] > b[i]) return false;
    }
    return false;
}

/// Left-to-right binary exponentiation: base^exp_be mod m.
fn fePow(base: *const Fe, exp_be: [32]u8, m: *const Fe) Fe {
    var result: Fe align(8) = ONE;
    for (0..256) |i| {
        const byte_idx = i / 8;
        const bit_idx: u3 = @intCast(7 - (i % 8));
        result = feMul(&result, &result, m);
        if ((exp_be[byte_idx] >> bit_idx) & 1 == 1) {
            result = feMul(&result, base, m);
        }
    }
    return result;
}

fn feInvN(a: *const Fe) Fe {
    return fePow(a, N_MINUS_2_BE, &N_LE);
}

// ── Point operations (secp256r1Add / secp256r1Double CSRs) ────────────────────

fn pointIsInfinity(buf: *const [64]u8) bool {
    for (buf) |b| if (b != 0) return false;
    return true;
}

fn pointToBytes(p: *const Point) [64]u8 {
    var buf: [64]u8 align(8) = undefined;
    @memcpy(buf[0..32], &p.x);
    @memcpy(buf[32..64], &p.y);
    return buf;
}

fn bytesToPoint(buf: *const [64]u8) Point {
    return .{ .x = buf[0..32].*, .y = buf[32..64].* };
}

fn optAdd(a: ?Point, b: ?Point) ?Point {
    const pa = a orelse return b;
    const pb = b orelse return a;
    return pointAdd(pa, pb);
}

fn pointAdd(p1: Point, p2: Point) ?Point {
    const b1 = pointToBytes(&p1);
    const b2 = pointToBytes(&p2);
    if (pointIsInfinity(&b1)) return p2;
    if (pointIsInfinity(&b2)) return p1;
    if (std.mem.eql(u8, b1[0..32], b2[0..32])) {
        if (std.mem.eql(u8, b1[32..64], b2[32..64])) return pointDouble(p1);
        return null;
    }
    var buf: [128]u8 align(8) = undefined;
    @memcpy(buf[0..64], b1[0..]);
    @memcpy(buf[64..128], b2[0..]);
    zisk.secp256r1Add(&buf);
    return bytesToPoint(buf[0..64]);
}

fn pointDouble(p: Point) ?Point {
    var buf: [64]u8 align(8) = pointToBytes(&p);
    if (pointIsInfinity(&buf)) return null;
    zisk.secp256r1Double(&buf);
    return bytesToPoint(&buf);
}

fn scalarMul(k: *const Fe, p: Point) ?Point {
    if (feIsZero(k)) return null;
    var result: ?Point = null;
    var cur: ?Point = p;
    for (0..256) |i| {
        const byte_idx = i / 8;
        const bit_idx: u3 = @intCast(i % 8);
        if ((k[byte_idx] >> bit_idx) & 1 == 1) {
            result = optAdd(result, cur);
        }
        cur = if (cur) |c| pointDouble(c) else null;
    }
    return result;
}

// ── ECDSA verify ───────────────────────────────────────────────────────────────

fn doVerify(
    hash_be: *const [32]u8,
    r_be: *const [32]u8,
    s_be: *const [32]u8,
    qx_be: *const [32]u8,
    qy_be: *const [32]u8,
) bool {
    var r_le: Fe align(8) = beToLe(r_be);
    var s_le: Fe align(8) = beToLe(s_be);

    if (feIsZero(&r_le) or !feNumericLessThan(&r_le, &N_LE)) return false;
    if (feIsZero(&s_le) or !feNumericLessThan(&s_le, &N_LE)) return false;

    var hash_le: Fe align(8) = beToLe(hash_be);
    // Reduce hash mod n
    var z_le: Fe align(8) = feMul(&hash_le, &ONE, &N_LE);

    var w: Fe align(8) = feInvN(&s_le);
    var k1: Fe align(8) = feMul(&z_le, &w, &N_LE);
    var k2: Fe align(8) = feMul(&r_le, &w, &N_LE);

    const G = Point{ .x = GX_LE, .y = GY_LE };
    const Q = Point{ .x = beToLe(qx_be), .y = beToLe(qy_be) };

    const R = optAdd(scalarMul(&k1, G), scalarMul(&k2, Q)) orelse return false;

    // R.x mod n == r
    const rx_mod_n = feMul(&R.x, &ONE, &N_LE);
    return std.mem.eql(u8, &rx_mod_n, &r_le);
}

// ── Public interface ───────────────────────────────────────────────────────────

/// Verify a P-256 ECDSA signature.
/// msg: 32-byte big-endian message hash.
/// sig: 64-byte big-endian r(32) || s(32).
/// pubkey: 64-byte big-endian x(32) || y(32).
pub fn verifySignature(
    msg: *const [32]u8,
    sig: *const [64]u8,
    pubkey: *const [64]u8,
) bool {
    return doVerify(msg, sig[0..32], sig[32..64], pubkey[0..32], pubkey[32..64]);
}
