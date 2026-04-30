//! secp256k1 ecrecover for the Zisk zkVM target.
//!
//! Uses Zisk CSR hardware circuits:
//!   - arith256ModDirect (0x802): out = (a*b + c) mod m — zero-copy, 5 direct pointers
//!   - secp256k1AddDirect (0x803): p1 += p2 in-place — zero-copy, 2 direct pointers
//!   - secp256k1Double (0x804): point double in-place — 64 bytes
//!
//! Point format (CSR): 64 bytes = x(32 LE bytes) || y(32 LE bytes), align(8).
//! Field/scalar elements (Fe) use the same LE 32-byte representation.
//! All-zero 64-byte buffer represents the point at infinity.
//!
//! Public interface:
//!   recoverPubkey — recover the 64-byte uncompressed secp256k1 public key
//!                   (big-endian x||y, no 0x04 prefix) from a recoverable sig.
//!                   Returns false if recovery fails.

const std = @import("std");
const zisk = @import("zisk");

// ── secp256k1 constants (little-endian 256-bit integers) ──────────────────────
// align(8) on constants ensures word-aligned CSR inputs without runtime cost.

/// Field prime p = 2²⁵⁶ − 2³² − 977
const P_LE: Fe align(8) = .{
    0x2f, 0xfc, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
};

/// Curve order n
const N_LE: Fe align(8) = .{
    0x41, 0x41, 0x36, 0xd0, 0x8c, 0x5e, 0xd2, 0xbf,
    0x3b, 0xa0, 0x48, 0xaf, 0xe6, 0xdc, 0xae, 0xba,
    0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
};

/// Generator x-coordinate
const GX_LE: Fe align(8) = .{
    0x98, 0x17, 0xf8, 0x16, 0x5b, 0x81, 0xf2, 0x59,
    0xd9, 0x28, 0xce, 0x2d, 0xdb, 0xfc, 0x9b, 0x02,
    0x07, 0x0b, 0x87, 0xce, 0x95, 0x62, 0xa0, 0x55,
    0xac, 0xbb, 0xdc, 0xf9, 0x7e, 0x66, 0xbe, 0x79,
};

/// Generator y-coordinate
const GY_LE: Fe align(8) = .{
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

const ZERO: Fe align(8) = .{0} ** 32;
const ONE: Fe align(8) = .{1} ++ (.{0} ** 31);
const SEVEN: Fe align(8) = .{7} ++ (.{0} ** 31);

/// Generator point as a flat 64-byte aligned buffer — avoids copying in doRecover.
const G_BUF: [64]u8 align(8) = GX_LE ++ GY_LE;

// ── Types ──────────────────────────────────────────────────────────────────────

/// 256-bit field element / scalar in little-endian byte order (byte 0 = LSB).
const Fe = [32]u8;

// ── Byte-order conversion ──────────────────────────────────────────────────────

fn beToLe(be: *const [32]u8) Fe {
    var le: Fe align(8) = undefined;
    for (0..32) |i| le[i] = be[31 - i];
    return le;
}

fn leToBe(le: *const [32]u8) [32]u8 {
    var be: [32]u8 = undefined;
    for (0..32) |i| be[i] = le[31 - i];
    return be;
}

// ── Field element helpers ──────────────────────────────────────────────────────

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

/// In-place negation: a = m - a. No-op if a is zero.
fn feNegInPlace(a: *Fe, m: *const Fe) void {
    if (feIsZero(a)) return;
    var borrow: u8 = 0;
    for (0..32) |i| {
        const ai = a[i];
        const diff: i16 = @as(i16, m[i]) - @as(i16, ai) - @as(i16, @intCast(borrow));
        if (diff < 0) {
            a[i] = @intCast(diff + 256);
            borrow = 1;
        } else {
            a[i] = @intCast(diff);
            borrow = 0;
        }
    }
}

/// out = base^exp mod m, using ping-pong buffers to eliminate per-iteration copies.
/// exp is big-endian (MSB first). Callers must declare out/base as align(8).
fn fePow(out: *Fe, base: *const Fe, exp_be: [32]u8, m: *const Fe) void {
    var bufs: [2]Fe align(8) = .{ ONE, undefined };
    var cur: u1 = 0;
    for (0..256) |i| {
        const nxt: u1 = cur ^ 1;
        zisk.arith256ModDirect(&bufs[cur], &bufs[cur], &ZERO, m, &bufs[nxt]);
        cur = nxt;
        const byte_idx = i / 8;
        const bit_idx: u3 = @intCast(7 - (i % 8));
        if ((exp_be[byte_idx] >> bit_idx) & 1 == 1) {
            const nxt2: u1 = cur ^ 1;
            zisk.arith256ModDirect(&bufs[cur], base, &ZERO, m, &bufs[nxt2]);
            cur = nxt2;
        }
    }
    out.* = bufs[cur];
}

// ── Point operations ───────────────────────────────────────────────────────────
// Points are 64-byte aligned buffers: x(32 LE bytes) || y(32 LE bytes).
// All-zero = point at infinity.

fn isInfinity(p: *const [64]u8) bool {
    const words: *const [8]u64 = @ptrCast(@alignCast(p));
    for (words) |w| if (w != 0) return false;
    return true;
}

/// In-place point addition: a += b.
/// Handles identity, doubling, and negation-to-infinity cases.
fn pointAddInPlace(a: *[64]u8, b: *const [64]u8) void {
    if (isInfinity(a)) {
        @memcpy(a, b);
        return;
    }
    if (isInfinity(b)) return;
    if (std.mem.eql(u8, a[0..32], b[0..32])) {
        if (std.mem.eql(u8, a[32..64], b[32..64])) {
            zisk.secp256k1Double(a); // P + P = 2P
        } else {
            @memset(a, 0); // P + (-P) = infinity
        }
        return;
    }
    zisk.secp256k1AddDirect(a, b);
}

/// Scalar multiplication: result = k * p, accumulated LSB-first.
/// result/p must be 8-byte aligned (declared align(8) by caller).
fn scalarMul(result: *[64]u8, k: *const Fe, p: *const [64]u8) void {
    @memset(result, 0);
    if (feIsZero(k)) return;
    var cur: [64]u8 align(8) = p.*;
    for (0..256) |i| {
        const byte_idx = i / 8;
        const bit_idx: u3 = @intCast(i % 8);
        if ((k[byte_idx] >> bit_idx) & 1 == 1) {
            pointAddInPlace(result, &cur);
        }
        if (!isInfinity(&cur)) {
            zisk.secp256k1Double(&cur);
        }
    }
}

// ── ecrecover ──────────────────────────────────────────────────────────────────

fn doRecover(msg_hash: [32]u8, sig: [64]u8, recid: u8) ?[64]u8 {
    if (recid > 3) return null;

    var r_le: Fe align(8) = beToLe(sig[0..32]);
    var s_le: Fe align(8) = beToLe(sig[32..64]);

    // z = beToLe(msg_hash) mod N
    var z_le: Fe align(8) = undefined;
    const mh_le: Fe align(8) = beToLe(&msg_hash);
    zisk.arith256ModDirect(&mh_le, &ONE, &ZERO, &N_LE, &z_le);

    if (feIsZero(&r_le) or feIsZero(&s_le)) return null;

    // rx: x-coordinate of R (r or r+N for recid bit 1)
    var rx: Fe align(8) = r_le;
    if (recid & 2 != 0) {
        zisk.arith256ModDirect(&r_le, &ONE, &N_LE, &P_LE, &rx);
        // If rx < r_le, addition overflowed P — x-coordinate is unreachable.
        if (feNumericLessThan(&rx, &r_le)) return null;
    }

    // Candidate y: y = sqrt(rx^3 + 7) mod P
    var x2: Fe align(8) = undefined;
    var x3: Fe align(8) = undefined;
    var y2: Fe align(8) = undefined;
    var y: Fe align(8) = undefined;
    zisk.arith256ModDirect(&rx, &rx, &ZERO, &P_LE, &x2);
    zisk.arith256ModDirect(&x2, &rx, &ZERO, &P_LE, &x3);
    zisk.arith256ModDirect(&x3, &ONE, &SEVEN, &P_LE, &y2);
    fePow(&y, &y2, P_SQRT_EXP_BE, &P_LE);

    // Verify y^2 == y2
    var y_sq: Fe align(8) = undefined;
    zisk.arith256ModDirect(&y, &y, &ZERO, &P_LE, &y_sq);
    if (!std.mem.eql(u8, &y_sq, &y2)) return null;

    // Choose correct y parity
    if ((y[0] & 1) != (recid & 1)) feNegInPlace(&y, &P_LE);

    // Build R point buffer
    var R_buf: [64]u8 align(8) = undefined;
    @memcpy(R_buf[0..32], &rx);
    @memcpy(R_buf[32..64], &y);

    // r_inv = r^(N-2) mod N
    var r_inv: Fe align(8) = undefined;
    fePow(&r_inv, &r_le, N_MINUS_2_BE, &N_LE);

    // k1 = (-z * r_inv) mod N,  k2 = (s * r_inv) mod N
    var neg_z: Fe align(8) = z_le;
    feNegInPlace(&neg_z, &N_LE);
    var k1: Fe align(8) = undefined;
    var k2: Fe align(8) = undefined;
    zisk.arith256ModDirect(&neg_z, &r_inv, &ZERO, &N_LE, &k1);
    zisk.arith256ModDirect(&s_le, &r_inv, &ZERO, &N_LE, &k2);

    // Q = k1*G + k2*R
    var Q: [64]u8 align(8) = undefined;
    var Q2: [64]u8 align(8) = undefined;
    scalarMul(&Q, &k1, &G_BUF);
    scalarMul(&Q2, &k2, &R_buf);
    pointAddInPlace(&Q, &Q2);

    if (isInfinity(&Q)) return null;

    // Return uncompressed public key: big-endian x||y (no 0x04 prefix)
    var pubkey: [64]u8 = undefined;
    const qx = leToBe(Q[0..32]);
    const qy = leToBe(Q[32..64]);
    @memcpy(pubkey[0..32], &qx);
    @memcpy(pubkey[32..64], &qy);
    return pubkey;
}

// ── Public interface ───────────────────────────────────────────────────────────

/// Recover the 64-byte uncompressed secp256k1 public key from a recoverable
/// signature. Returns true and writes to `output` on success; false on failure.
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
