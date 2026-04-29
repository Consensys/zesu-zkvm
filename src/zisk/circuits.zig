/// Zisk zkVM Hardware-Accelerated Circuits via CSR Instructions
///
/// Each circuit is invoked by writing a pointer to its input buffer into the
/// corresponding CSR address. The circuit executes in-place and overwrites
/// the result into the buffer.
///
/// CSR address map (0x800–0x811):
///   0x800  keccakf         — Keccak-f[1600] (200 bytes)
///   0x801  arith256        — 256-bit multiply-add
///   0x802  arith256_mod    — 256-bit modular multiply-add
///   0x803  secp256k1_add   — Secp256k1 point addition
///   0x804  secp256k1_dbl   — Secp256k1 point doubling
///   0x805  sha256f         — SHA-256 compression
///   0x806  bn254_curve_add — BN254 G1 point addition
///   0x807  bn254_curve_dbl — BN254 G1 point doubling
///   0x808  bn254_cplx_add  — BN254 Fp2 addition
///   0x809  bn254_cplx_sub  — BN254 Fp2 subtraction
///   0x80A  bn254_cplx_mul  — BN254 Fp2 multiplication
///   0x80B  arith384_mod    — 384-bit modular operations
///   0x80C  bls12_381_add   — BLS12-381 G1 point addition
///   0x80D  bls12_381_dbl   — BLS12-381 G1 point doubling
///   0x80E  bls12_381_fadd  — BLS12-381 Fp2 addition
///   0x80F  bls12_381_fsub  — BLS12-381 Fp2 subtraction
///   0x810  bls12_381_fmul  — BLS12-381 Fp2 multiplication
///   0x811  add256          — 256-bit addition
pub const CircuitCSR = enum(u16) {
    keccakf = 0x800,
    arith256 = 0x801,
    arith256_mod = 0x802,
    secp256k1_add = 0x803,
    secp256k1_dbl = 0x804,
    sha256f = 0x805,
    bn254_curve_add = 0x806,
    bn254_curve_dbl = 0x807,
    bn254_complex_add = 0x808,
    bn254_complex_sub = 0x809,
    bn254_complex_mul = 0x80A,
    arith384_mod = 0x80B,
    bls12_381_curve_add = 0x80C,
    bls12_381_curve_dbl = 0x80D,
    bls12_381_complex_add = 0x80E,
    bls12_381_complex_sub = 0x80F,
    bls12_381_complex_mul = 0x810,
    add256 = 0x811,
};

// ── Basic cryptographic operations ───────────────────────────────────────────

/// Keccak-f[1600] permutation — 200-byte state, in-place
pub fn keccakf(state: *[200]u8) void {
    const ptr = @intFromPtr(state);
    asm volatile ("csrs 0x800, %[ptr]"
        :
        : [ptr] "r" (ptr),
        : .{ .memory = true });
}

/// SHA-256 compression — 96 bytes (64-byte block + 32-byte state), in-place.
/// After the call, buf[64..96] contains the new SHA-256 hash state.
pub fn sha256Compress(block_and_state: *[96]u8) void {
    const ptr = @intFromPtr(block_and_state);
    asm volatile ("csrs 0x805, %[ptr]"
        :
        : [ptr] "r" (ptr),
        : .{ .memory = true });
}

// ── Secp256k1 operations ──────────────────────────────────────────────────────

/// Secp256k1 point addition — 128 bytes (P1: 64, P2: 64), result in first 64.
/// CSR 0x803 uses indirect_params=2: expects a pointer to [*P1, *P2] struct.
pub fn secp256k1Add(points: *[128]u8) void {
    const p1: *Point256 = @ptrCast(@alignCast(points[0..64]));
    const p2: *Point256 = @ptrCast(@alignCast(points[64..128]));
    var params = Bn254CurveAddParams{ .p1 = p1, .p2 = p2 };
    const ptr = @intFromPtr(&params);
    asm volatile ("csrs 0x803, %[ptr]"
        :
        : [ptr] "r" (ptr),
        : .{ .memory = true });
}

/// Secp256k1 point doubling — 64-byte point, in-place
pub fn secp256k1Double(point: *[64]u8) void {
    const ptr = @intFromPtr(point);
    asm volatile ("csrs 0x804, %[ptr]"
        :
        : [ptr] "r" (ptr),
        : .{ .memory = true });
}

// ── BN254 operations ──────────────────────────────────────────────────────────

pub const Point256 = extern struct {
    x: [4]u64,
    y: [4]u64,
};

pub const Bn254CurveAddParams = extern struct {
    p1: *Point256,
    p2: *Point256,
};

pub const Fp2Element = extern struct {
    data: [64]u8,
};

pub const Bn254Fp2BinaryOpParams = extern struct {
    e1: *Fp2Element,
    e2: *Fp2Element,
};

/// BN254 G1 point addition — 128 bytes (P1: 64, P2: 64), result in first 64
pub fn bn254CurveAdd(points: *[128]u8) void {
    const p1: *Point256 = @ptrCast(@alignCast(points[0..64]));
    const p2: *Point256 = @ptrCast(@alignCast(points[64..128]));
    var params = Bn254CurveAddParams{ .p1 = p1, .p2 = p2 };
    const ptr = @intFromPtr(&params);
    asm volatile ("csrs 0x806, %[ptr]"
        :
        : [ptr] "r" (ptr),
        : .{ .memory = true });
}

/// BN254 G1 point doubling — 64-byte point, in-place
pub fn bn254CurveDouble(point: *[64]u8) void {
    const p: *Point256 = @ptrCast(@alignCast(point));
    const ptr = @intFromPtr(p);
    asm volatile ("csrs 0x807, %[ptr]"
        :
        : [ptr] "r" (ptr),
        : .{ .memory = true });
}

/// BN254 Fp2 addition — 128 bytes, result in first 64
pub fn bn254ComplexAdd(elements: *[128]u8) void {
    const e1: *Fp2Element = @ptrCast(@alignCast(elements[0..64]));
    const e2: *Fp2Element = @ptrCast(@alignCast(elements[64..128]));
    var params = Bn254Fp2BinaryOpParams{ .e1 = e1, .e2 = e2 };
    const ptr = @intFromPtr(&params);
    asm volatile ("csrs 0x808, %[ptr]"
        :
        : [ptr] "r" (ptr),
        : .{ .memory = true });
}

/// BN254 Fp2 subtraction — 128 bytes, result in first 64
pub fn bn254ComplexSub(elements: *[128]u8) void {
    const e1: *Fp2Element = @ptrCast(@alignCast(elements[0..64]));
    const e2: *Fp2Element = @ptrCast(@alignCast(elements[64..128]));
    var params = Bn254Fp2BinaryOpParams{ .e1 = e1, .e2 = e2 };
    const ptr = @intFromPtr(&params);
    asm volatile ("csrs 0x809, %[ptr]"
        :
        : [ptr] "r" (ptr),
        : .{ .memory = true });
}

/// BN254 Fp2 multiplication — 128 bytes, result in first 64
pub fn bn254ComplexMul(elements: *[128]u8) void {
    const e1: *Fp2Element = @ptrCast(@alignCast(elements[0..64]));
    const e2: *Fp2Element = @ptrCast(@alignCast(elements[64..128]));
    var params = Bn254Fp2BinaryOpParams{ .e1 = e1, .e2 = e2 };
    const ptr = @intFromPtr(&params);
    asm volatile ("csrs 0x80A, %[ptr]"
        :
        : [ptr] "r" (ptr),
        : .{ .memory = true });
}

// ── BLS12-381 operations ──────────────────────────────────────────────────────

/// BLS12-381 G1 point addition — 192 bytes (P1: 96, P2: 96), result in first 96
pub fn bls12_381CurveAdd(points: *[192]u8) void {
    const ptr = @intFromPtr(points);
    asm volatile ("csrs 0x80C, %[ptr]"
        :
        : [ptr] "r" (ptr),
        : .{ .memory = true });
}

/// BLS12-381 G1 point doubling — 96-byte point, in-place
pub fn bls12_381CurveDouble(point: *[96]u8) void {
    const ptr = @intFromPtr(point);
    asm volatile ("csrs 0x80D, %[ptr]"
        :
        : [ptr] "r" (ptr),
        : .{ .memory = true });
}

/// BLS12-381 Fp2 addition — 192 bytes, result in first 96
pub fn bls12_381ComplexAdd(elements: *[192]u8) void {
    const ptr = @intFromPtr(elements);
    asm volatile ("csrs 0x80E, %[ptr]"
        :
        : [ptr] "r" (ptr),
        : .{ .memory = true });
}

/// BLS12-381 Fp2 subtraction — 192 bytes, result in first 96
pub fn bls12_381ComplexSub(elements: *[192]u8) void {
    const ptr = @intFromPtr(elements);
    asm volatile ("csrs 0x80F, %[ptr]"
        :
        : [ptr] "r" (ptr),
        : .{ .memory = true });
}

/// BLS12-381 Fp2 multiplication — 192 bytes, result in first 96
pub fn bls12_381ComplexMul(elements: *[192]u8) void {
    const ptr = @intFromPtr(elements);
    asm volatile ("csrs 0x810, %[ptr]"
        :
        : [ptr] "r" (ptr),
        : .{ .memory = true });
}

// ── Arithmetic operations ─────────────────────────────────────────────────────

/// 256-bit multiply-add: result = (a*b + c) mod 2^256 — 96 bytes, result in first 32
pub fn arith256(input: *[96]u8) void {
    const ptr = @intFromPtr(input);
    asm volatile ("csrs 0x801, %[ptr]"
        :
        : [ptr] "r" (ptr),
        : .{ .memory = true });
}

/// 256-bit modular multiply-add: result = (a*b + c) mod m — 128 bytes, result in first 32.
/// Buffer layout: [a(32)|b(32)|c(32)|m(32)]; result written back to first 32 bytes.
/// CSR 0x802 uses indirect_params=5: pointer to [*a, *b, *c, *m, *out].
pub fn arith256Mod(input: *[128]u8) void {
    var out: [32]u8 align(8) = undefined;
    var ptrs: [5]u64 align(8) = .{
        @intFromPtr(&input[0]),
        @intFromPtr(&input[32]),
        @intFromPtr(&input[64]),
        @intFromPtr(&input[96]),
        @intFromPtr(&out),
    };
    asm volatile ("csrs 0x802, %[ptr]"
        :
        : [ptr] "r" (@intFromPtr(&ptrs)),
        : .{ .memory = true });
    @memcpy(input[0..32], &out);
}

/// 384-bit modular operations — 192 bytes, result in first 48
pub fn arith384Mod(input: *[192]u8) void {
    const ptr = @intFromPtr(input);
    asm volatile ("csrs 0x80B, %[ptr]"
        :
        : [ptr] "r" (ptr),
        : .{ .memory = true });
}

/// 256-bit addition: result = a + b — 64 bytes, result in first 32
pub fn add256(input: *[64]u8) void {
    const ptr = @intFromPtr(input);
    asm volatile ("csrs 0x811, %[ptr]"
        :
        : [ptr] "r" (ptr),
        : .{ .memory = true });
}
