/// Zisk zkVM Hardware-Accelerated Circuits via CSR Instructions
///
/// Each circuit is invoked by writing a pointer to its input buffer into the
/// corresponding CSR address. The circuit executes in-place and overwrites
/// the result into the buffer.
///
/// CSR address map (0x800–0x81A, Zisk 0.17.0):
///   0x800  keccakf           — Keccak-f[1600] (200 bytes)
///   0x801  arith256          — 256-bit multiply-add
///   0x802  arith256_mod      — 256-bit modular multiply-add  (indirect_params=5)
///   0x803  secp256k1_add     — Secp256k1 point addition      (indirect_params=2)
///   0x804  secp256k1_dbl     — Secp256k1 point doubling
///   0x805  sha256f           — SHA-256 compression           (indirect_params=2: {state_ptr, block_ptr})
///   0x806  bn254_curve_add   — BN254 G1 point addition       (indirect_params=2)
///   0x807  bn254_curve_dbl   — BN254 G1 point doubling
///   0x808  bn254_cplx_add    — BN254 Fp2 addition            (indirect_params=2)
///   0x809  bn254_cplx_sub    — BN254 Fp2 subtraction         (indirect_params=2)
///   0x80A  bn254_cplx_mul    — BN254 Fp2 multiplication      (indirect_params=2)
///   0x80B  arith384_mod      — 384-bit modular operations
///   0x80C  bls12_381_add     — BLS12-381 G1 point addition   (indirect_params=2)
///   0x80D  bls12_381_dbl     — BLS12-381 G1 point doubling
///   0x80E  bls12_381_fadd    — BLS12-381 Fp2 addition        (indirect_params=2)
///   0x80F  bls12_381_fsub    — BLS12-381 Fp2 subtraction     (indirect_params=2)
///   0x810  bls12_381_fmul    — BLS12-381 Fp2 multiplication  (indirect_params=2)
///   0x811  add256            — 256-bit addition
///   0x812  poseidon2         — Poseidon2 hash
///   0x813  dma_memcpy        — DMA memory copy
///   0x814  dma_memcmp        — DMA memory compare
///   0x815  dma_inputcpy      — DMA input copy
///   0x816  dma_memset        — DMA memory set
///   0x817  secp256r1_add     — Secp256r1 (P-256) point addition  (indirect_params=2)
///   0x818  secp256r1_dbl     — Secp256r1 (P-256) point doubling
///   0x819  blake2b_round     — BLAKE2b single round
///   0x81A  profile           — Profiling marker
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
    poseidon2 = 0x812,
    dma_memcpy = 0x813,
    dma_memcmp = 0x814,
    dma_inputcpy = 0x815,
    dma_memset = 0x816,
    secp256r1_add = 0x817,
    secp256r1_dbl = 0x818,
    blake2b_round = 0x819,
    profile = 0x81A,
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

/// SHA-256 compression (Zisk 0.17.0 indirect_params=2 convention).
/// Struct layout: {state_ptr, block_ptr} matching SyscallSha256Params{state, input}.
/// State is 32 bytes (8 x u32 in native LE byte order); block is 64 bytes.
/// After the call buf[64..96] contains the updated SHA-256 state (LE u32 format).
pub fn sha256Compress(block_and_state: *[96]u8) void {
    var params: [2]u64 align(8) = .{
        @intFromPtr(block_and_state) + 64, // params[0] = state_ptr (32 bytes at offset 64)
        @intFromPtr(block_and_state), //      params[1] = block_ptr (64 bytes at offset 0)
    };
    asm volatile ("csrs 0x805, %[ptr]"
        :
        : [ptr] "r" (@intFromPtr(&params)),
        : .{ .memory = true });
}

// ── Secp256k1 operations ──────────────────────────────────────────────────────

/// Secp256k1 point addition — 128 bytes (P1: 64, P2: 64), result in first 64.
/// CSR 0x803 uses indirect_params=2: expects a pointer to {*P1, *P2} struct.
pub fn secp256k1Add(points: *[128]u8) void {
    const p1: *Point256 = @ptrCast(@alignCast(points[0..64]));
    const p2: *Point256 = @ptrCast(@alignCast(points[64..128]));
    var params = CurveAddParams256{ .p1 = p1, .p2 = p2 };
    const ptr = @intFromPtr(&params);
    asm volatile ("csrs 0x803, %[ptr]"
        :
        : [ptr] "r" (ptr),
        : .{ .memory = true });
}

/// Secp256k1 point addition with separate point pointers — result written to p1.
pub fn secp256k1AddDirect(p1: *[64]u8, p2: *const [64]u8) void {
    const p1_ptr: *Point256 = @ptrCast(@alignCast(p1));
    const p2_ptr: *Point256 = @ptrCast(@alignCast(@constCast(p2)));
    var params = CurveAddParams256{ .p1 = p1_ptr, .p2 = p2_ptr };
    asm volatile ("csrs 0x803, %[ptr]"
        :
        : [ptr] "r" (@intFromPtr(&params)),
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

pub const CurveAddParams256 = extern struct {
    p1: *Point256,
    p2: *Point256,
};

pub const Fp2Element = extern struct {
    data: [64]u8,
};

pub const Fp2BinaryOpParams256 = extern struct {
    e1: *Fp2Element,
    e2: *Fp2Element,
};

// Keep old names as aliases for callers that use them
pub const Bn254CurveAddParams = CurveAddParams256;
pub const Bn254Fp2BinaryOpParams = Fp2BinaryOpParams256;

/// BN254 G1 point addition — 128 bytes (P1: 64, P2: 64), result in first 64
pub fn bn254CurveAdd(points: *[128]u8) void {
    const p1: *Point256 = @ptrCast(@alignCast(points[0..64]));
    const p2: *Point256 = @ptrCast(@alignCast(points[64..128]));
    var params = CurveAddParams256{ .p1 = p1, .p2 = p2 };
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
    var params = Fp2BinaryOpParams256{ .e1 = e1, .e2 = e2 };
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
    var params = Fp2BinaryOpParams256{ .e1 = e1, .e2 = e2 };
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
    var params = Fp2BinaryOpParams256{ .e1 = e1, .e2 = e2 };
    const ptr = @intFromPtr(&params);
    asm volatile ("csrs 0x80A, %[ptr]"
        :
        : [ptr] "r" (ptr),
        : .{ .memory = true });
}

// ── BLS12-381 operations ──────────────────────────────────────────────────────

/// 384-bit point (96 bytes): x(48 LE) || y(48 LE)
pub const Point384 = extern struct {
    x: [6]u64,
    y: [6]u64,
};

/// indirect_params=2 struct for BLS12-381 curve add
pub const CurveAddParams384 = extern struct {
    p1: *Point384,
    p2: *Point384,
};

pub const Fp2Element384 = extern struct {
    data: [96]u8,
};

/// indirect_params=2 struct for BLS12-381 Fp2 binary ops
pub const Fp2BinaryOpParams384 = extern struct {
    e1: *Fp2Element384,
    e2: *Fp2Element384,
};

/// BLS12-381 G1 point addition — 192 bytes (P1: 96, P2: 96), result in first 96.
/// CSR 0x80C uses indirect_params=2: passes {*P1, *P2}.
pub fn bls12_381CurveAdd(points: *[192]u8) void {
    const p1: *Point384 = @ptrCast(@alignCast(points[0..96]));
    const p2: *Point384 = @ptrCast(@alignCast(points[96..192]));
    var params = CurveAddParams384{ .p1 = p1, .p2 = p2 };
    asm volatile ("csrs 0x80C, %[ptr]"
        :
        : [ptr] "r" (@intFromPtr(&params)),
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

/// BLS12-381 Fp2 addition — 192 bytes, result in first 96.
/// CSR 0x80E uses indirect_params=2.
pub fn bls12_381ComplexAdd(elements: *[192]u8) void {
    const e1: *Fp2Element384 = @ptrCast(@alignCast(elements[0..96]));
    const e2: *Fp2Element384 = @ptrCast(@alignCast(elements[96..192]));
    var params = Fp2BinaryOpParams384{ .e1 = e1, .e2 = e2 };
    asm volatile ("csrs 0x80E, %[ptr]"
        :
        : [ptr] "r" (@intFromPtr(&params)),
        : .{ .memory = true });
}

/// BLS12-381 Fp2 subtraction — 192 bytes, result in first 96.
pub fn bls12_381ComplexSub(elements: *[192]u8) void {
    const e1: *Fp2Element384 = @ptrCast(@alignCast(elements[0..96]));
    const e2: *Fp2Element384 = @ptrCast(@alignCast(elements[96..192]));
    var params = Fp2BinaryOpParams384{ .e1 = e1, .e2 = e2 };
    asm volatile ("csrs 0x80F, %[ptr]"
        :
        : [ptr] "r" (@intFromPtr(&params)),
        : .{ .memory = true });
}

/// BLS12-381 Fp2 multiplication — 192 bytes, result in first 96.
pub fn bls12_381ComplexMul(elements: *[192]u8) void {
    const e1: *Fp2Element384 = @ptrCast(@alignCast(elements[0..96]));
    const e2: *Fp2Element384 = @ptrCast(@alignCast(elements[96..192]));
    var params = Fp2BinaryOpParams384{ .e1 = e1, .e2 = e2 };
    asm volatile ("csrs 0x810, %[ptr]"
        :
        : [ptr] "r" (@intFromPtr(&params)),
        : .{ .memory = true });
}

// ── Secp256r1 (P-256) operations ──────────────────────────────────────────────

/// Secp256r1 point addition — 128 bytes (P1: 64, P2: 64), result in first 64.
/// CSR 0x817 uses indirect_params=2: passes {*P1, *P2}.
pub fn secp256r1Add(points: *[128]u8) void {
    const p1: *Point256 = @ptrCast(@alignCast(points[0..64]));
    const p2: *Point256 = @ptrCast(@alignCast(points[64..128]));
    var params = CurveAddParams256{ .p1 = p1, .p2 = p2 };
    asm volatile ("csrs 0x817, %[ptr]"
        :
        : [ptr] "r" (@intFromPtr(&params)),
        : .{ .memory = true });
}

/// Secp256r1 point addition with separate pointers — result written to p1.
pub fn secp256r1AddDirect(p1: *[64]u8, p2: *const [64]u8) void {
    const p1_ptr: *Point256 = @ptrCast(@alignCast(p1));
    const p2_ptr: *Point256 = @ptrCast(@alignCast(@constCast(p2)));
    var params = CurveAddParams256{ .p1 = p1_ptr, .p2 = p2_ptr };
    asm volatile ("csrs 0x817, %[ptr]"
        :
        : [ptr] "r" (@intFromPtr(&params)),
        : .{ .memory = true });
}

/// Secp256r1 point doubling — 64-byte point, in-place
pub fn secp256r1Double(point: *[64]u8) void {
    const ptr = @intFromPtr(point);
    asm volatile ("csrs 0x818, %[ptr]"
        :
        : [ptr] "r" (ptr),
        : .{ .memory = true });
}

// ── BLAKE2b round ─────────────────────────────────────────────────────────────

/// Params struct for blake2b_round CSR: index (value) + two sub-pointers.
pub const Blake2bRoundParams = extern struct {
    index: u64,
    state: *[16]u64,
    input: *const [16]u64,
};

/// Execute one BLAKE2b compression round.
/// index: sigma permutation index in [0, 10).
/// state: 16×u64 work vector v (modified in place).
/// input: 16×u64 message block m.
pub fn blake2bRound(index: u64, state: *[16]u64, input: *const [16]u64) void {
    var params = Blake2bRoundParams{ .index = index, .state = state, .input = input };
    asm volatile ("csrs 0x819, %[ptr]"
        :
        : [ptr] "r" (@intFromPtr(&params)),
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

/// Direct 256-bit modular multiply-add: out = (a*b + c) mod m.
pub fn arith256ModDirect(
    a: *const [32]u8,
    b: *const [32]u8,
    c: *const [32]u8,
    m: *const [32]u8,
    out: *[32]u8,
) void {
    var ptrs: [5]u64 align(8) = .{
        @intFromPtr(a),
        @intFromPtr(b),
        @intFromPtr(c),
        @intFromPtr(m),
        @intFromPtr(out),
    };
    asm volatile ("csrs 0x802, %[ptr]"
        :
        : [ptr] "r" (@intFromPtr(&ptrs)),
        : .{ .memory = true });
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
