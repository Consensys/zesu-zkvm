/// BN254 Pairing Implementation using Zisk Hardware Circuits
///
/// Architecture:
///   Fp2 operations   → hardware circuits (CSR 0x808, 0x809, 0x80A)
///   G2 operations    → implemented using Fp2 circuits
///   Fp6/Fp12 ops     → built from Fp2 circuits
///   Miller loop      → uses G2 operations and Fp12 accumulation
///   Final exp        → uses Fp12 operations
///
/// Status:
///   ✓ Fp2 hardware circuits wired (CSR 0x808, 0x809, 0x80A)
///   ✓ Miller loop with 63-bit ate parameter (x = 4965661367192848881)
///   ⚠ Final exponentiation is a placeholder (single square)
///   TODO: implement full final exponentiation for EIP-197 compliance
const std = @import("std");
const circuits = @import("zisk"); // zisk module provides all circuit functions

pub const Fp2 = struct {
    data: [64]u8 align(8), // [c0: 32 bytes | c1: 32 bytes] little-endian limbs

    pub fn zero() Fp2 {
        return .{ .data = [_]u8{0} ** 64 };
    }

    pub fn one() Fp2 {
        var r = Fp2.zero();
        r.data[0] = 1;
        return r;
    }

    pub fn add(self: *const Fp2, other: *const Fp2) Fp2 {
        var input: [128]u8 align(8) = undefined;
        @memcpy(input[0..64], &self.data);
        @memcpy(input[64..128], &other.data);
        circuits.bn254ComplexAdd(&input);
        var r: Fp2 = undefined;
        @memcpy(&r.data, input[0..64]);
        return r;
    }

    pub fn sub(self: *const Fp2, other: *const Fp2) Fp2 {
        var input: [128]u8 align(8) = undefined;
        @memcpy(input[0..64], &self.data);
        @memcpy(input[64..128], &other.data);
        circuits.bn254ComplexSub(&input);
        var r: Fp2 = undefined;
        @memcpy(&r.data, input[0..64]);
        return r;
    }

    pub fn mul(self: *const Fp2, other: *const Fp2) Fp2 {
        var input: [128]u8 align(8) = undefined;
        @memcpy(input[0..64], &self.data);
        @memcpy(input[64..128], &other.data);
        circuits.bn254ComplexMul(&input);
        var r: Fp2 = undefined;
        @memcpy(&r.data, input[0..64]);
        return r;
    }

    pub fn square(self: *const Fp2) Fp2 {
        return self.mul(self);
    }

    pub fn isZero(self: *const Fp2) bool {
        for (self.data) |b| if (b != 0) return false;
        return true;
    }

    pub fn neg(self: *const Fp2) Fp2 {
        return Fp2.zero().sub(self);
    }

    pub fn double(self: *const Fp2) Fp2 {
        return self.add(self);
    }

    pub fn inverse(self: *const Fp2) Fp2 {
        var c0 = Fp2.zero();
        var c1 = Fp2.zero();
        @memcpy(c0.data[0..32], self.data[0..32]);
        @memcpy(c1.data[0..32], self.data[32..64]);

        const a2 = c0.mul(&c0);
        const b2 = c1.mul(&c1);
        const norm = a2.add(&b2);
        const norm_inv = inverseFp(&norm);

        var conj_data = self.data;
        const zero_val = Fp2.zero();
        var c1_only = Fp2.zero();
        @memcpy(c1_only.data[32..64], self.data[32..64]);
        const neg_c1 = zero_val.sub(&c1_only);
        @memcpy(conj_data[32..64], neg_c1.data[32..64]);
        const conj = Fp2{ .data = conj_data };
        return conj.mul(&norm_inv);
    }

    fn inverseFp(a: *const Fp2) Fp2 {
        // p - 2 for BN254 (little-endian u64 limbs)
        const p_minus_2 = [4]u64{
            0x3c208c16d87cfd45,
            0x97816a916871ca8d,
            0xb85045b68181585d,
            0x30644e72e131a029,
        };

        var result = Fp2.one();
        var base = a.*;
        _ = &base;
        var limb_idx: usize = 4;
        while (limb_idx > 0) {
            limb_idx -= 1;
            const limb = p_minus_2[limb_idx];
            const start_bit: usize = if (limb_idx == 3) blk: {
                var bit: usize = 63;
                while (bit > 0) : (bit -= 1) if ((limb >> @intCast(bit)) & 1 == 1) break;
                break :blk bit;
            } else 63;

            var bit_idx: isize = @intCast(start_bit);
            while (bit_idx >= 0) : (bit_idx -= 1) {
                if (limb_idx == 3 and bit_idx == @as(isize, @intCast(start_bit))) continue;
                result = result.square();
                if ((limb >> @intCast(bit_idx)) & 1 == 1) result = result.mul(a);
            }
        }
        return result;
    }

    pub fn div(self: *const Fp2, other: *const Fp2) Fp2 {
        return self.mul(&other.inverse());
    }
};

pub const G2Point = struct {
    x: Fp2,
    y: Fp2,

    pub fn infinity() G2Point {
        return .{ .x = Fp2.zero(), .y = Fp2.zero() };
    }
    pub fn isInfinity(self: *const G2Point) bool {
        return self.x.isZero() and self.y.isZero();
    }

    pub fn double(self: *const G2Point) G2Point {
        if (self.isInfinity()) return G2Point.infinity();
        const x2 = self.x.square();
        var three = Fp2.zero();
        three.data[0] = 3;
        const num = three.mul(&x2);
        const den = self.y.double();
        const lam = num.div(&den);
        const lam2 = lam.square();
        const two_x = self.x.double();
        const x_new = lam2.sub(&two_x);
        const x_diff = self.x.sub(&x_new);
        const y_new = lam.mul(&x_diff).sub(&self.y);
        return .{ .x = x_new, .y = y_new };
    }

    pub fn add(self: *const G2Point, other: *const G2Point) G2Point {
        if (self.isInfinity()) return other.*;
        if (other.isInfinity()) return self.*;
        const xe = std.mem.eql(u8, &self.x.data, &other.x.data);
        const ye = std.mem.eql(u8, &self.y.data, &other.y.data);
        if (xe and ye) return self.double();
        if (xe and !ye) return G2Point.infinity();
        const dy = other.y.sub(&self.y);
        const dx = other.x.sub(&self.x);
        const lam = dy.div(&dx);
        const lam2 = lam.square();
        const x_new = lam2.sub(&self.x).sub(&other.x);
        const x_diff = self.x.sub(&x_new);
        const y_new = lam.mul(&x_diff).sub(&self.y);
        return .{ .x = x_new, .y = y_new };
    }
};

pub const Fp6 = struct {
    c0: Fp2,
    c1: Fp2,
    c2: Fp2,

    pub fn zero() Fp6 {
        return .{ .c0 = Fp2.zero(), .c1 = Fp2.zero(), .c2 = Fp2.zero() };
    }
    pub fn one() Fp6 {
        return .{ .c0 = Fp2.one(), .c1 = Fp2.zero(), .c2 = Fp2.zero() };
    }

    pub fn add(self: *const Fp6, other: *const Fp6) Fp6 {
        return .{ .c0 = self.c0.add(&other.c0), .c1 = self.c1.add(&other.c1), .c2 = self.c2.add(&other.c2) };
    }

    pub fn sub(self: *const Fp6, other: *const Fp6) Fp6 {
        return .{ .c0 = self.c0.sub(&other.c0), .c1 = self.c1.sub(&other.c1), .c2 = self.c2.sub(&other.c2) };
    }

    pub fn mulByNonResidue(a: *const Fp2) Fp2 {
        var nine = Fp2.zero();
        nine.data[0] = 9;
        return a.mul(&nine);
    }

    pub fn mul(self: *const Fp6, other: *const Fp6) Fp6 {
        const v0 = self.c0.mul(&other.c0);
        const v1 = self.c1.mul(&other.c1);
        const v2 = self.c2.mul(&other.c2);

        const t0 = self.c1.add(&self.c2).mul(&other.c1.add(&other.c2)).sub(&v1).sub(&v2);
        const c0 = v0.add(&mulByNonResidue(&t0));
        const c1 = self.c0.add(&self.c1).mul(&other.c0.add(&other.c1)).sub(&v0).sub(&v1).add(&mulByNonResidue(&v2));
        const c2 = self.c0.add(&self.c2).mul(&other.c0.add(&other.c2)).sub(&v0).add(&v1).sub(&v2);
        return .{ .c0 = c0, .c1 = c1, .c2 = c2 };
    }

    pub fn square(self: *const Fp6) Fp6 {
        return self.mul(self);
    }
};

pub const Fp12 = struct {
    c0: Fp6,
    c1: Fp6,

    pub fn zero() Fp12 {
        return .{ .c0 = Fp6.zero(), .c1 = Fp6.zero() };
    }
    pub fn one() Fp12 {
        return .{ .c0 = Fp6.one(), .c1 = Fp6.zero() };
    }

    pub fn mul(self: *const Fp12, other: *const Fp12) Fp12 {
        const v0 = self.c0.mul(&other.c0);
        const v1 = self.c1.mul(&other.c1);
        const c1 = self.c0.add(&self.c1).mul(&other.c0.add(&other.c1)).sub(&v0).sub(&v1);
        const v1_nr = Fp6{
            .c0 = Fp6.mulByNonResidue(&v1.c2),
            .c1 = v1.c0,
            .c2 = v1.c1,
        };
        return .{ .c0 = v0.add(&v1_nr), .c1 = c1 };
    }

    pub fn square(self: *const Fp12) Fp12 {
        return self.mul(self);
    }

    pub fn isOne(self: *const Fp12) bool {
        const one_val = Fp12.one();
        return std.mem.eql(u8, std.mem.asBytes(&self.c0), std.mem.asBytes(&one_val.c0)) and
            std.mem.eql(u8, std.mem.asBytes(&self.c1), std.mem.asBytes(&one_val.c1));
    }
};

pub const G1Point = struct {
    data: [64]u8 align(8),

    pub fn isInfinity(self: *const G1Point) bool {
        for (self.data) |b| if (b != 0) return false;
        return true;
    }
};

fn lineDouble(t: *const G2Point, p: *const G1Point) Fp12 {
    var p_x = Fp2.zero();
    @memcpy(p_x.data[0..32], p.data[0..32]);
    var p_y = Fp2.zero();
    @memcpy(p_y.data[0..32], p.data[32..64]);
    const x2 = t.x.square();
    var three = Fp2.zero();
    three.data[0] = 3;
    const num = three.mul(&x2);
    const den = t.y.double();
    const lam = num.div(&den);
    const r = lam.mul(&t.x.sub(&p_x)).add(&p_y.sub(&t.y));
    return Fp12{ .c0 = Fp6{ .c0 = r, .c1 = Fp2.zero(), .c2 = Fp2.zero() }, .c1 = Fp6.zero() };
}

fn lineAdd(t: *const G2Point, q: *const G2Point, p: *const G1Point) Fp12 {
    var p_x = Fp2.zero();
    @memcpy(p_x.data[0..32], p.data[0..32]);
    var p_y = Fp2.zero();
    @memcpy(p_y.data[0..32], p.data[32..64]);
    const dy = q.y.sub(&t.y);
    const dx = q.x.sub(&t.x);
    const lam = dy.div(&dx);
    const r = lam.mul(&t.x.sub(&p_x)).add(&p_y.sub(&t.y));
    return Fp12{ .c0 = Fp6{ .c0 = r, .c1 = Fp2.zero(), .c2 = Fp2.zero() }, .c1 = Fp6.zero() };
}

pub const Pair = struct {
    p: G1Point,
    q: G2Point,
};

fn millerLoop(p: *const G1Point, q: *const G2Point) Fp12 {
    // BN254 optimal ate loop bits (MSB first, 63 bits)
    const ate_loop_bits = [_]u1{
        0, 1, 0, 0, 0, 1, 0, 0,
        1, 1, 1, 0, 1, 0, 0, 1,
        1, 0, 0, 1, 0, 0, 1, 0,
        1, 0, 1, 1, 0, 1, 0, 0,
        0, 1, 0, 0, 1, 0, 1, 0,
        0, 1, 1, 0, 1, 0, 0, 1,
        0, 0, 0, 0, 1, 0, 0, 1,
        1, 1, 1, 1, 0, 0, 0, 1,
    };

    var f = Fp12.one();
    var t = q.*;

    for (ate_loop_bits[1..]) |bit| {
        f = f.square();
        const ld = lineDouble(&t, p);
        f = f.mul(&ld);
        t = t.double();
        if (bit == 1) {
            const la = lineAdd(&t, q, p);
            f = f.mul(&la);
            t = t.add(q);
        }
    }
    return f;
}

fn finalExponentiation(f: *const Fp12) Fp12 {
    // TODO: implement full final exponentiation
    // (easy part: f^(p^6-1)(p^2+1); hard part: exponentiation by (p^4-p^2+1)/r)
    return f.square();
}

pub fn pairing(p: *const G1Point, q: *const G2Point) Fp12 {
    if (p.isInfinity() or q.isInfinity()) return Fp12.one();
    return finalExponentiation(&millerLoop(p, q));
}

/// Run pairing check on a slice of G1/G2 pairs.
pub fn pairingCheck(pairs: []const Pair) bool {
    var result = Fp12.one();
    for (pairs) |pair| {
        result = result.mul(&pairing(&pair.p, &pair.q));
    }
    return result.isOne();
}

/// Run pairing check on raw circuit-format bytes (little-endian, 192 bytes/pair).
/// Layout per pair: G1(64 LE) | G2.x(64 LE) | G2.y(64 LE)
pub fn pairingCheckBytes(allocator: std.mem.Allocator, data: []const u8) !bool {
    if (data.len % 192 != 0) return error.InvalidInput;
    const num_pairs = data.len / 192;
    if (num_pairs == 0) return true;

    const pairs = try allocator.alloc(Pair, num_pairs);
    defer allocator.free(pairs);

    for (0..num_pairs) |i| {
        const off = i * 192;
        @memcpy(&pairs[i].p.data, data[off..][0..64]);
        @memcpy(&pairs[i].q.x.data, data[off + 64 ..][0..64]);
        @memcpy(&pairs[i].q.y.data, data[off + 128 ..][0..64]);
    }
    return pairingCheck(pairs);
}
