//! EIP-152 BLAKE2f compression function for the Zisk zkVM target.
//!
//! Uses Zisk CSR hardware circuit:
//!   - blake2bRound (0x819): one BLAKE2b G-mixing round
//!
//! EIP-152 input format (213 bytes):
//!   [0..4]    rounds (u32 big-endian)
//!   [4..68]   h state (8×u64 little-endian = 64 bytes)
//!   [68..196] m message block (16×u64 little-endian = 128 bytes)
//!   [196..212] t counters (2×u64 little-endian = 16 bytes)
//!   [212]     f finalization flag (0 or 1)
//!
//! Output: 64 bytes — updated h state (8×u64 little-endian).

const std = @import("std");
const zisk = @import("zisk");

/// BLAKE2b initialization vector (constants from the spec).
const IV: [8]u64 = .{
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
};

/// Run the BLAKE2b F compression function.
///
/// rounds: number of rounds (EIP-152 allows 0 to 2^32-1).
/// h:      current 64-byte state (8×u64 LE), updated in place.
/// m:      128-byte message block (16×u64 LE).
/// t:      16-byte counter (2×u64 LE): t[0]=low, t[1]=high.
/// f:      finalization flag (true = last block).
pub fn compress(rounds: u32, h: *[64]u8, m: *const [128]u8, t: *const [16]u8, f: bool) void {
    // Load h and m as u64 arrays (already LE in memory on RISC-V LE target)
    var h_words: [8]u64 align(8) = undefined;
    var m_words: [16]u64 align(8) = undefined;
    for (0..8) |i| h_words[i] = std.mem.readInt(u64, h[i * 8 ..][0..8], .little);
    for (0..16) |i| m_words[i] = std.mem.readInt(u64, m[i * 8 ..][0..8], .little);

    const t0 = std.mem.readInt(u64, t[0..8], .little);
    const t1 = std.mem.readInt(u64, t[8..16], .little);

    // Build the 16-element work vector v
    var v: [16]u64 align(8) = undefined;
    for (0..8) |i| v[i] = h_words[i];
    v[8] = IV[0];
    v[9] = IV[1];
    v[10] = IV[2];
    v[11] = IV[3];
    v[12] = t0 ^ IV[4];
    v[13] = t1 ^ IV[5];
    v[14] = (if (f) ~@as(u64, 0) else @as(u64, 0)) ^ IV[6];
    v[15] = IV[7];

    // Run rounds using the blake2b_round CSR
    // Sigma index cycles through [0, 10) for each round
    for (0..rounds) |r| {
        zisk.blake2bRound(@as(u64, r % 10), &v, &m_words);
    }

    // Finalize: h'[i] = h[i] ^ v[i] ^ v[i+8]
    for (0..8) |i| {
        const result = h_words[i] ^ v[i] ^ v[i + 8];
        std.mem.writeInt(u64, h[i * 8 ..][0..8], result, .little);
    }
}
