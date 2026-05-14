/// Bump allocator for the OpenVM zkVM guest.
///
/// Uses `_end` (the linker-defined end of all ELF sections) as the heap start.
/// Heap grows upward; allocations are never freed.
const std = @import("std");

/// Upper bound for guest memory (OpenVM MEM_SIZE = 1 << 29 = 512 MB).
const GUEST_MAX_MEM: usize = 0x20000000;

/// Minimum allocation alignment in bytes (matches OpenVM's bump allocator).
const WORD_SIZE: usize = 8;

/// Linker-defined symbol marking the end of all ELF sections (heap start).
extern var _end: u8;

/// Current heap cursor.  Zero means uninitialised (heap starts at `_end`).
var heap_pos: usize = 0;

fn sysAllocAligned(bytes: usize, align_size: usize) ?[*]u8 {
    if (heap_pos == 0) {
        heap_pos = @intFromPtr(&_end);
    }
    const eff_align = @max(align_size, WORD_SIZE);
    const offset = heap_pos & (eff_align - 1);
    if (offset != 0) heap_pos += eff_align - offset;
    const new_pos = heap_pos + bytes;
    if (new_pos > GUEST_MAX_MEM) return null;
    const result: [*]u8 = @ptrFromInt(heap_pos);
    heap_pos = new_pos;
    return result;
}

pub const OpenVmAllocator = struct {
    const Self = @This();

    pub fn init() Self {
        return Self{};
    }

    fn alloc(ctx: *anyopaque, n: usize, ptr_align: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
        _ = ctx;
        _ = ret_addr;
        const alignment = @as(usize, 1) << @intFromEnum(ptr_align);
        return sysAllocAligned(n, alignment);
    }

    fn resize(ctx: *anyopaque, buf: []u8, buf_align: std.mem.Alignment, new_len: usize, ret_addr: usize) bool {
        _ = ctx;
        _ = buf_align;
        _ = ret_addr;
        return new_len <= buf.len;
    }

    fn remap(ctx: *anyopaque, buf: []u8, buf_align: std.mem.Alignment, new_len: usize, ret_addr: usize) ?[*]u8 {
        _ = ctx;
        _ = buf_align;
        _ = ret_addr;
        if (new_len <= buf.len) return buf.ptr;
        return null;
    }

    fn free(ctx: *anyopaque, buf: []u8, buf_align: std.mem.Alignment, ret_addr: usize) void {
        _ = ctx;
        _ = buf;
        _ = buf_align;
        _ = ret_addr;
    }

    pub fn allocator(self: *Self) std.mem.Allocator {
        return .{
            .ptr = self,
            .vtable = &.{
                .alloc = alloc,
                .resize = resize,
                .remap = remap,
                .free = free,
            },
        };
    }
};
