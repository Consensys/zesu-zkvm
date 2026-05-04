/// Zisk zkVM runtime support module
///
/// Provides:
///   - ZiskAllocator: bump allocator using sys_alloc_aligned / _kernel_heap_bottom
///   - BumpAllocator, ArenaAllocator, FixedBufferAllocator: fixed-buffer variants
///   - Hardware-accelerated cryptographic circuits via RISC-V CSR instructions
const allocator_mod = @import("./allocator.zig");
const circuits = @import("./circuits.zig");

// Allocator types
pub const ZiskAllocator = allocator_mod.ZiskAllocator;
pub const BumpAllocator = allocator_mod.BumpAllocator;
pub const ArenaAllocator = allocator_mod.ArenaAllocator;
pub const FixedBufferAllocator = allocator_mod.FixedBufferAllocator;

// Circuit CSR addresses
pub const CircuitCSR = circuits.CircuitCSR;

// Cryptographic circuits
pub const keccakf = circuits.keccakf;
pub const sha256Compress = circuits.sha256Compress;

// Secp256k1 circuits
pub const secp256k1Add = circuits.secp256k1Add;
pub const secp256k1AddDirect = circuits.secp256k1AddDirect;
pub const secp256k1Double = circuits.secp256k1Double;

// Secp256r1 (P-256) circuits
pub const secp256r1Add = circuits.secp256r1Add;
pub const secp256r1AddDirect = circuits.secp256r1AddDirect;
pub const secp256r1Double = circuits.secp256r1Double;

// BLAKE2b
pub const blake2bRound = circuits.blake2bRound;
pub const Blake2bRoundParams = circuits.Blake2bRoundParams;

// BN254 circuits
pub const bn254CurveAdd = circuits.bn254CurveAdd;
pub const bn254CurveDouble = circuits.bn254CurveDouble;
pub const bn254ComplexAdd = circuits.bn254ComplexAdd;
pub const bn254ComplexSub = circuits.bn254ComplexSub;
pub const bn254ComplexMul = circuits.bn254ComplexMul;

// BLS12-381 circuits
pub const bls12_381CurveAdd = circuits.bls12_381CurveAdd;
pub const bls12_381CurveDouble = circuits.bls12_381CurveDouble;
pub const bls12_381ComplexAdd = circuits.bls12_381ComplexAdd;
pub const bls12_381ComplexSub = circuits.bls12_381ComplexSub;
pub const bls12_381ComplexMul = circuits.bls12_381ComplexMul;

// Arithmetic circuits
pub const arith256 = circuits.arith256;
pub const arith256Mod = circuits.arith256Mod;
pub const arith256ModDirect = circuits.arith256ModDirect;
pub const arith384Mod = circuits.arith384Mod;
pub const add256 = circuits.add256;
