//! secp256k1 ecrecover for the Zisk zkVM target.
//!
//! Uses Zisk CSR hardware circuits:
//!   - arith256Mod (0x802): (a*b + c) mod m  — 128-byte buffer, result in first 32
//!   - secp256k1Add (0x803): point addition   — 128-byte buffer, result in first 64
//!   - secp256k1Double (0x804): point double  — 64-byte buffer, in-place
//!
//! Point format (CSR): 64 bytes = x(32 LE bytes) || y(32 LE bytes).
//! Each coordinate is a 256-bit integer in little-endian byte order.
//! Field/scalar elements (Fe) use the same LE 32-byte representation.
//!
//! Public interface:
//!   recoverPubkey — recover the 64-byte uncompressed secp256k1 public key
//!                   (big-endian x||y, no 0x04 prefix) from a recoverable sig.
//!                   Returns false if recovery fails.

const std = @import("std");
const zisk = @import("zisk");

// ── secp256k1 constants (little-endian 256-bit integers) ──────────────────────

/// Field prime p = 2²⁵⁶ − 2³² − 977
const P_LE: Fe = .{
    0x2f, 0xfc, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
};

/// Curve order n
const N_LE: Fe = .{
    0x41, 0x41, 0x36, 0xd0, 0x8c, 0x5e, 0xd2, 0xbf,
    0x3b, 0xa0, 0x48, 0xaf, 0xe6, 0xdc, 0xae, 0xba,
    0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
};

/// Generator x-coordinate
const GX_LE: Fe = .{
    0x98, 0x17, 0xf8, 0x16, 0x5b, 0x81, 0xf2, 0x59,
    0xd9, 0x28, 0xce, 0x2d, 0xdb, 0xfc, 0x9b, 0x02,
    0x07, 0x0b, 0x87, 0xce, 0x95, 0x62, 0xa0, 0x55,
    0xac, 0xbb, 0xdc, 0xf9, 0x7e, 0x66, 0xbe, 0x79,
};

/// Generator y-coordinate
const GY_LE: Fe = .{
    0xb8, 0xd4, 0x10, 0xfb, 0x8f, 0xd0, 0x47, 0x9c,
    0x19, 0x54, 0x85, 0xa6, 0x48, 0xb4, 0x17, 0xfd,
    0xa8, 0x08, 0x11, 0x0e, 0xfc, 0xfb, 0xa4, 0x5d,
    0x65, 0xc4, 0xa3, 0x26, 0x77, 0xda, 0x3a, 0x48,
};

/// p − 2 (big-endian) — exponent for field inverse via Fermat: a^(p−2) mod p
const P_MINUS_2_BE: [32]u8 = .{
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x2d,
};

/// n − 2 (big-endian) — exponent for scalar inverse via Fermat: a^(n−2) mod n
const N_MINUS_2_BE: [32]u8 = .{
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
    0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x3f,
};

/// (p + 1) / 4 (big-endian) — exponent for field sqrt: a^((p+1)/4) mod p
/// Valid because p ≡ 3 (mod 4).
const P_SQRT_EXP_BE: [32]u8 = .{
    0x3f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xbf, 0xff, 0xff, 0x0c,
};

const ZERO: Fe = .{0} ** 32;
const ONE: Fe = .{1} ++ (.{0} ** 31);

// ── Types ──────────────────────────────────────────────────────────────────────

/// 256-bit field element / scalar in little-endian byte order (byte 0 = LSB).
const Fe = [32]u8;

/// A secp256k1 affine point.
const Point = struct { x: Fe, y: Fe };

// ── Byte-order conversion ──────────────────────────────────────────────────────

fn beToLe(be: *const [32]u8) Fe {
    var le: Fe = undefined;
    for (0..32) |i| le[i] = be[31 - i];
    return le;
}

fn leToBe(le: *const Fe) [32]u8 {
    var be: [32]u8 = undefined;
    for (0..32) |i| be[i] = le[31 - i];
    return be;
}

// ── Field arithmetic (via arith256Mod CSR) ─────────────────────────────────────

fn modMulAdd(a: *const Fe, b: *const Fe, c: *const Fe, m: *const Fe) Fe {
    var buf: [128]u8 align(8) = undefined;
    @memcpy(buf[0..32], a);
    @memcpy(buf[32..64], b);
    @memcpy(buf[64..96], c);
    @memcpy(buf[96..128], m);
    zisk.arith256Mod(&buf);
    var result: Fe = undefined;
    @memcpy(&result, buf[0..32]);
    return result;
}

fn feMul(a: *const Fe, b: *const Fe, m: *const Fe) Fe {
    return modMulAdd(a, b, &ZERO, m);
}

fn feAdd(a: *const Fe, b: *const Fe, m: *const Fe) Fe {
    return modMulAdd(a, &ONE, b, m);
}

fn feIsZero(a: *const Fe) bool {
    return std.mem.eql(u8, a, &ZERO);
}

/// Numeric less-than for LE 256-bit integers (compare from MSB = index 31).
fn feNumericLessThan(a: *const Fe, b: *const Fe) bool {
    var i: usize = 32;
    while (i > 0) {
        i -= 1;
        if (a[i] < b[i]) return true;
        if (a[i] > b[i]) return false;
    }
    return false;
}

fn feNeg(a: *const Fe, m: *const Fe) Fe {
    if (feIsZero(a)) return ZERO;
    var result: Fe = m.*;
    var borrow: u8 = 0;
    for (0..32) |i| {
        const diff: i16 = @as(i16, result[i]) - @as(i16, a[i]) - @as(i16, @intCast(borrow));
        if (diff < 0) {
            result[i] = @intCast(diff + 256);
            borrow = 1;
        } else {
            result[i] = @intCast(diff);
            borrow = 0;
        }
    }
    return result;
}

fn fePow(base: *const Fe, exp_be: [32]u8, m: *const Fe) Fe {
    var result = ONE;
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

fn feSqrtP(a: *const Fe) Fe {
    return fePow(a, P_SQRT_EXP_BE, &P_LE);
}

// ── Point operations (via secp256k1Add / secp256k1Double CSRs) ─────────────────

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
    zisk.secp256k1Add(&buf);
    return bytesToPoint(buf[0..64]);
}

fn pointDouble(p: Point) ?Point {
    var buf: [64]u8 align(8) = pointToBytes(&p);
    if (pointIsInfinity(&buf)) return null;
    zisk.secp256k1Double(&buf);
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

// ── ecrecover ──────────────────────────────────────────────────────────────────

/// Recover the 64-byte uncompressed secp256k1 public key (big-endian x||y)
/// from a recoverable signature.  Returns null on failure.
fn doRecover(msg_hash: [32]u8, sig: [64]u8, recid: u8) ?[64]u8 {
    if (recid > 3) return null;

    const r_le = beToLe(sig[0..32]);
    const s_le = beToLe(sig[32..64]);
    const z_le = feMul(&beToLe(&msg_hash), &ONE, &N_LE);

    if (feIsZero(&r_le) or feIsZero(&s_le)) return null;

    var rx: Fe = r_le;
    if (recid & 2 != 0) {
        rx = feAdd(&r_le, &N_LE, &P_LE);
        if (feNumericLessThan(&rx, &r_le)) return null;
    }

    const x2 = feMul(&rx, &rx, &P_LE);
    const x3 = feMul(&x2, &rx, &P_LE);
    const seven: Fe = .{7} ++ (.{0} ** 31);
    const y2 = feAdd(&x3, &seven, &P_LE);
    var y = feSqrtP(&y2);

    if (!std.mem.eql(u8, &feMul(&y, &y, &P_LE), &y2)) return null;

    if ((y[0] & 1) != (recid & 1)) y = feNeg(&y, &P_LE);

    const R = Point{ .x = rx, .y = y };
    const G = Point{ .x = GX_LE, .y = GY_LE };

    const r_inv = feInvN(&r_le);
    const k1 = feMul(&feNeg(&z_le, &N_LE), &r_inv, &N_LE);
    const k2 = feMul(&s_le, &r_inv, &N_LE);

    const Q = optAdd(scalarMul(&k1, G), scalarMul(&k2, R)) orelse return null;

    // Return uncompressed public key: big-endian x||y (no 0x04 prefix)
    var pubkey: [64]u8 = undefined;
    @memcpy(pubkey[0..32], &leToBe(&Q.x));
    @memcpy(pubkey[32..64], &leToBe(&Q.y));
    return pubkey;
}

// ── Public interface ───────────────────────────────────────────────────────────

/// Recover the 64-byte uncompressed secp256k1 public key from a recoverable
/// signature.  Returns true and writes to `output` on success; false on failure.
///
/// `msg`:   32-byte message hash (big-endian)
/// `sig`:   64-byte signature r||s (big-endian, each 32 bytes)
/// `recid`: recovery ID (0 or 1; 2 and 3 for x >= n, extremely rare)
/// `output`: 64-byte uncompressed public key x||y (big-endian, no 0x04 prefix)
pub fn recoverPubkey(msg: *const [32]u8, sig: *const [64]u8, recid: u8, output: *[64]u8) bool {
    const pubkey = doRecover(msg.*, sig.*, recid) orelse return false;
    output.* = pubkey;
    return true;
}
