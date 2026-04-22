//! Binary deserializer for the StatelessInput format.
//!
//! Parses the zevm-zisk binary format (same as zevm-stateless/src/io.zig):
//!
//!   [u64 BE: block_rlp_len] [raw Ethereum block RLP bytes]
//!   [u64: state_count]   [u64 len + node bytes] × N   (MPT nodes)
//!   [u64: codes_count]   [u64 len + code bytes] × N   (contract bytecodes)
//!   [u64: keys_count]    [u64 len + key bytes]  × N   (witness keys, ignored)
//!   [u64: headers_count] [u64 len + header RLP] × N   (ancestor headers)
//!
//! Block parsing delegates to rlp_decode (decodeBlockHeader, decodeTxList,
//! decodeWithdrawals, findPreStateRoot) rather than re-implementing field-by-field.

const std = @import("std");
const input_mod = @import("input");
const primitives = @import("primitives");
const mpt = @import("mpt");
const rlp_decode = @import("rlp_decode");

/// Deserialize a StatelessInput from a raw byte slice (zevm-zisk binary format).
pub fn fromBytes(allocator: std.mem.Allocator, data: []const u8) !input_mod.StatelessInput {
    var pos: usize = 0;

    // ── Block RLP ─────────────────────────────────────────────────────────────
    if (pos + 8 > data.len) return error.UnexpectedEndOfInput;
    const rlp_len: usize = @intCast(std.mem.readInt(u64, data[pos..][0..8], .big));
    pos += 8;
    if (pos + rlp_len > data.len) return error.UnexpectedEndOfInput;
    const block_rlp = data[pos..][0..rlp_len];
    pos += rlp_len;

    // Block structure: RLP([header_list, txs_list, ommers_list, withdrawals_list?])
    const outer_r = mpt.rlp.decodeItem(block_rlp) catch return error.InvalidBlock;
    const block_payload = switch (outer_r.item) {
        .list => |p| p,
        .bytes => return error.InvalidBlock,
    };

    // Decode header
    const hdr_r = mpt.rlp.decodeItem(block_payload) catch return error.InvalidBlock;
    const hdr_payload = switch (hdr_r.item) {
        .list => |p| p,
        .bytes => return error.InvalidBlock,
    };
    const header = try rlp_decode.decodeBlockHeader(allocator, hdr_payload);

    // Decode transactions
    const after_hdr = block_payload[hdr_r.consumed..];
    const txns_r = mpt.rlp.decodeItem(after_hdr) catch return error.InvalidBlock;
    const txns_payload = switch (txns_r.item) {
        .list => |p| p,
        .bytes => return error.InvalidBlock,
    };
    const transactions = try rlp_decode.decodeTxList(allocator, txns_payload);

    // Skip ommers, decode optional withdrawals
    var withdrawals: []const input_mod.Withdrawal = &.{};
    const after_txns = after_hdr[txns_r.consumed..];
    if (after_txns.len > 0) {
        if (mpt.rlp.decodeItem(after_txns)) |ommers_r| {
            const after_ommers = after_txns[ommers_r.consumed..];
            if (after_ommers.len > 0) {
                if (mpt.rlp.decodeItem(after_ommers)) |wd_r| {
                    const wd_payload = switch (wd_r.item) {
                        .list => |p| p,
                        .bytes => &.{},
                    };
                    withdrawals = rlp_decode.decodeWithdrawals(allocator, wd_payload) catch &.{};
                } else |_| {}
            }
        } else |_| {}
    }

    // ── ExecutionWitness ──────────────────────────────────────────────────────
    const nodes = try readSliceArray(allocator, data, &pos);
    const codes = try readSliceArray(allocator, data, &pos);
    _ = try readSliceArray(allocator, data, &pos); // keys — not in ExecutionWitness
    const headers = try readSliceArray(allocator, data, &pos);

    return input_mod.StatelessInput{
        .new_payload_request = .{
            .execution_payload = input_mod.payloadFromBlock(header, transactions, withdrawals),
            .parent_beacon_block_root = @splat(0),
        },
        .witness = .{
            .nodes = nodes,
            .codes = codes,
            .headers = headers,
        },
    };
}

/// Read a u64-count array of u64-length-prefixed byte slices (zero-copy into `data`).
fn readSliceArray(allocator: std.mem.Allocator, data: []const u8, pos: *usize) ![]const []const u8 {
    if (pos.* + 8 > data.len) return error.UnexpectedEndOfInput;
    const count: usize = @intCast(std.mem.readInt(u64, data[pos.*..][0..8], .big));
    pos.* += 8;
    const result = try allocator.alloc([]const u8, count);
    for (0..count) |i| {
        if (pos.* + 8 > data.len) return error.UnexpectedEndOfInput;
        const len: usize = @intCast(std.mem.readInt(u64, data[pos.*..][0..8], .big));
        pos.* += 8;
        if (pos.* + len > data.len) return error.UnexpectedEndOfInput;
        result[i] = data[pos.*..][0..len];
        pos.* += len;
    }
    return result;
}
