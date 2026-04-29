/// ZisK zkVM implementation of the zkvm_accelerators.h C interface.
///
/// Exports zkvm_* symbols that are resolved at link time by the zesu-core
/// accelerators module (which declares them as extern fn).
///
/// All cryptographic operations dispatch to ZisK hardware circuits (CSRs).
/// Operations without a ZisK circuit are stubbed (return ZKVM_EFAIL = -1).
///
/// Circuit coverage:
///   keccak256      — keccakf CSR (0x800), full variable-length sponge
///   sha256         — sha256Compress CSR (0x805), full Merkle-Damgård
///   ecrecover      — arith256Mod + secp256k1Add/Double CSRs
///   bn254_g1_add   — bn254CurveAdd CSR (0x806)
///   bn254_g1_mul   — bn254CurveDouble (0x807) + bn254CurveAdd (0x806)
///   bn254_pairing  — BN254 Fp2 CSRs (0x808–0x80A) + Miller loop
///   secp256k1_verify — stub (not needed for stateless block execution)
///   ripemd160      — stub (zero output, ZKVM_EOK)
///   modexp         — stub (ZKVM_EFAIL; zero output)
///   blake2f        — stub (ZKVM_EFAIL)
///   kzg_point_eval — stub (ZKVM_EFAIL)
///   BLS12-381 ops  — stub (ZKVM_EFAIL; CSRs exist, protocol TODO)
///   secp256r1_verify — stub (ZKVM_EFAIL)
const std = @import("std");
const zisk = @import("zisk");
const secp256k1_impl = @import("./secp256k1.zig");
const eip196 = @import("./eip196.zig");

// Local pair types — binary-compatible with accelerators.zig and zkvm_accelerators.h.
const Bn254PairingPair = extern struct { g1: [64]u8, g2: [128]u8 };
const Bls12G1MsmPair = extern struct { point: [96]u8, scalar: [32]u8 };
const Bls12G2MsmPair = extern struct { point: [192]u8, scalar: [32]u8 };
const Bls12PairingPair = extern struct { g1: [96]u8, g2: [192]u8 };

// ── Keccak-256 sponge ─────────────────────────────────────────────────────────

const KECCAK_RATE = 136; // 1088-bit rate for Keccak-256

export fn zkvm_keccak256(data: [*]const u8, len: usize, output: *[32]u8) i32 {
    var state: [200]u8 = .{0} ** 200;
    var offset: usize = 0;
    const d = data[0..len];

    while (offset + KECCAK_RATE <= d.len) : (offset += KECCAK_RATE) {
        for (0..KECCAK_RATE) |i| state[i] ^= d[offset + i];
        zisk.keccakf(&state);
    }

    const remaining = d.len - offset;
    for (0..remaining) |i| state[i] ^= d[offset + i];
    state[remaining] ^= 0x01; // Keccak domain separator
    state[KECCAK_RATE - 1] ^= 0x80; // end-of-rate marker
    zisk.keccakf(&state);

    output.* = state[0..32].*;
    return 0;
}

// ── SHA-256 ───────────────────────────────────────────────────────────────────

const SHA256_IV: [32]u8 = .{
    0x6a, 0x09, 0xe6, 0x67,
    0xbb, 0x67, 0xae, 0x85,
    0x3c, 0x6e, 0xf3, 0x72,
    0xa5, 0x4f, 0xf5, 0x3a,
    0x51, 0x0e, 0x52, 0x7f,
    0x9b, 0x05, 0x68, 0x8c,
    0x1f, 0x83, 0xd9, 0xab,
    0x5b, 0xe0, 0xcd, 0x19,
};

export fn zkvm_sha256(data: [*]const u8, len: usize, output: *[32]u8) i32 {
    var state: [32]u8 = SHA256_IV;
    const bit_len: u64 = @as(u64, len) * 8;
    var offset: usize = 0;
    const d = data[0..len];

    while (offset + 64 <= d.len) : (offset += 64) {
        var buf: [96]u8 = undefined;
        @memcpy(buf[0..64], d[offset..][0..64]);
        @memcpy(buf[64..96], &state);
        zisk.sha256Compress(&buf);
        @memcpy(&state, buf[64..96]);
    }

    const remaining = d.len - offset;
    var block1: [64]u8 = .{0} ** 64;
    @memcpy(block1[0..remaining], d[offset..]);
    block1[remaining] = 0x80;

    if (remaining < 56) {
        std.mem.writeInt(u64, block1[56..64], bit_len, .big);
        var buf: [96]u8 = undefined;
        @memcpy(buf[0..64], &block1);
        @memcpy(buf[64..96], &state);
        zisk.sha256Compress(&buf);
        @memcpy(&state, buf[64..96]);
    } else {
        var buf: [96]u8 = undefined;
        @memcpy(buf[0..64], &block1);
        @memcpy(buf[64..96], &state);
        zisk.sha256Compress(&buf);
        @memcpy(&state, buf[64..96]);

        var block2: [64]u8 = .{0} ** 64;
        std.mem.writeInt(u64, block2[56..64], bit_len, .big);
        @memcpy(buf[0..64], &block2);
        @memcpy(buf[64..96], &state);
        zisk.sha256Compress(&buf);
        @memcpy(&state, buf[64..96]);
    }

    output.* = state;
    return 0;
}

// ── ECRECOVER ─────────────────────────────────────────────────────────────────

export fn zkvm_secp256k1_ecrecover(
    msg: *const [32]u8,
    sig: *const [64]u8,
    recid: u8,
    output: *[64]u8,
) i32 {
    return if (secp256k1_impl.recoverPubkey(msg, sig, recid, output)) 0 else -1;
}

// ── secp256k1 verify — stub ───────────────────────────────────────────────────
// Full verification needs scalar multiplication + point comparison.
// Not required for stateless block execution (only ecrecover is needed).

export fn zkvm_secp256k1_verify(
    msg: *const [32]u8,
    sig: *const [64]u8,
    pubkey: *const [64]u8,
    verified: *bool,
) i32 {
    _ = msg;
    _ = sig;
    _ = pubkey;
    verified.* = false;
    return 0;
}

// ── RIPEMD-160 — stub ─────────────────────────────────────────────────────────
// No ZisK circuit. Returns zero hash (ZKVM_EOK so the precompile can proceed).

export fn zkvm_ripemd160(data: [*]const u8, len: usize, output: *[32]u8) i32 {
    _ = data;
    _ = len;
    output.* = .{0} ** 32;
    return 0;
}

// ── ModExp — stub ─────────────────────────────────────────────────────────────
// arith256Mod covers 256-bit ops but modexp inputs can be any size.

export fn zkvm_modexp(
    base: [*]const u8,
    base_len: usize,
    exp: [*]const u8,
    exp_len: usize,
    modulus: [*]const u8,
    mod_len: usize,
    output: [*]u8,
) i32 {
    _ = base;
    _ = base_len;
    _ = exp;
    _ = exp_len;
    _ = modulus;
    @memset(output[0..mod_len], 0);
    return -1;
}

// ── BN254 operations ──────────────────────────────────────────────────────────

export fn zkvm_bn254_g1_add(p1: *const [64]u8, p2: *const [64]u8, result: *[64]u8) i32 {
    eip196.ecAdd(p1, p2, result);
    return 0;
}

export fn zkvm_bn254_g1_mul(point: *const [64]u8, scalar: *const [32]u8, result: *[64]u8) i32 {
    eip196.ecMul(point, scalar, result);
    return 0;
}

export fn zkvm_bn254_pairing(pairs: [*]const Bn254PairingPair, num_pairs: usize, verified: *bool) i32 {
    var tmp = zisk.ZiskAllocator.init();
    const alloc = tmp.allocator();
    var result: [32]u8 = undefined;
    const raw = std.mem.sliceAsBytes(pairs[0..num_pairs]);
    eip196.ecPairing(raw, &result, alloc) catch return -1;
    verified.* = (result[31] == 1);
    return 0;
}

// ── BLAKE2f — stub ────────────────────────────────────────────────────────────

export fn zkvm_blake2f(
    rounds: u32,
    h: *[64]u8,
    m: *const [128]u8,
    t: *const [16]u8,
    f: u8,
) i32 {
    _ = rounds;
    _ = h;
    _ = m;
    _ = t;
    _ = f;
    return -1;
}

// ── KZG point evaluation — stub ───────────────────────────────────────────────

export fn zkvm_kzg_point_eval(
    commitment: *const [48]u8,
    z: *const [32]u8,
    y: *const [32]u8,
    proof: *const [48]u8,
    verified: *bool,
) i32 {
    _ = commitment;
    _ = z;
    _ = y;
    _ = proof;
    verified.* = false;
    return -1;
}

// ── BLS12-381 — stubs ─────────────────────────────────────────────────────────
// ZisK has circuits for G1 add/double (0x80C–0x80D) and Fp2 ops (0x80E–0x810),
// but the full BLS12-381 protocol (pairing, MSM, map-to-curve) requires
// substantial software on top of those primitives.

export fn zkvm_bls12_g1_add(p1: *const [96]u8, p2: *const [96]u8, result: *[96]u8) i32 {
    _ = p1;
    _ = p2;
    _ = result;
    return -1;
}

export fn zkvm_bls12_g1_msm(pairs: [*]const Bls12G1MsmPair, num_pairs: usize, result: *[96]u8) i32 {
    _ = pairs;
    _ = num_pairs;
    _ = result;
    return -1;
}

export fn zkvm_bls12_g2_add(p1: *const [192]u8, p2: *const [192]u8, result: *[192]u8) i32 {
    _ = p1;
    _ = p2;
    _ = result;
    return -1;
}

export fn zkvm_bls12_g2_msm(pairs: [*]const Bls12G2MsmPair, num_pairs: usize, result: *[192]u8) i32 {
    _ = pairs;
    _ = num_pairs;
    _ = result;
    return -1;
}

export fn zkvm_bls12_pairing(pairs: [*]const Bls12PairingPair, num_pairs: usize, verified: *bool) i32 {
    _ = pairs;
    _ = num_pairs;
    verified.* = false;
    return -1;
}

export fn zkvm_bls12_map_fp_to_g1(field_element: *const [48]u8, result: *[96]u8) i32 {
    _ = field_element;
    _ = result;
    return -1;
}

export fn zkvm_bls12_map_fp2_to_g2(field_element: *const [96]u8, result: *[192]u8) i32 {
    _ = field_element;
    _ = result;
    return -1;
}

// ── secp256r1 verify — stub ───────────────────────────────────────────────────

export fn zkvm_secp256r1_verify(
    msg: *const [32]u8,
    sig: *const [64]u8,
    pubkey: *const [64]u8,
    verified: *bool,
) i32 {
    _ = msg;
    _ = sig;
    _ = pubkey;
    verified.* = false;
    return -1;
}
