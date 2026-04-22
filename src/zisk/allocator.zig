const std = @import("std");

// Linker-provided symbol: heap starts immediately after the 1MB stack
extern const _kernel_heap_bottom: u8;

/// Bump allocator backed by the _kernel_heap_bottom linker symbol.
fn sys_alloc_aligned(bytes: usize, alignment: usize) [*]u8 {
    const State = struct {
        var heap_pos: usize = 0;
    };

    if (State.heap_pos == 0) {
        State.heap_pos = @intFromPtr(&_kernel_heap_bottom);
    }

    const offset = State.heap_pos & (alignment - 1);
    if (offset != 0) {
        State.heap_pos += alignment - offset;
    }

    const ptr: [*]u8 = @ptrFromInt(State.heap_pos);
    State.heap_pos += bytes;
    return ptr;
}

/// Zig std.mem.Allocator backed by sys_alloc_aligned.
/// This is a pure bump allocator: free/resize/remap are no-ops.
pub const ZiskAllocator = struct {
    const Self = @This();

    pub fn init() Self {
        return Self{};
    }

    fn alloc(ctx: *anyopaque, len: usize, ptr_align: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
        _ = ctx;
        _ = ret_addr;
        const alignment = @as(usize, 1) << @intFromEnum(ptr_align);
        return sys_alloc_aligned(len, alignment);
    }

    fn resize(ctx: *anyopaque, buf: []u8, buf_align: std.mem.Alignment, new_len: usize, ret_addr: usize) bool {
        _ = ctx;
        _ = buf;
        _ = buf_align;
        _ = new_len;
        _ = ret_addr;
        return false;
    }

    fn free(ctx: *anyopaque, buf: []u8, buf_align: std.mem.Alignment, ret_addr: usize) void {
        _ = ctx;
        _ = buf;
        _ = buf_align;
        _ = ret_addr;
    }

    fn remap(ctx: *anyopaque, old_buf: []u8, buf_align: std.mem.Alignment, new_len: usize, ret_addr: usize) ?[*]u8 {
        _ = ctx;
        _ = old_buf;
        _ = buf_align;
        _ = new_len;
        _ = ret_addr;
        return null;
    }

    pub fn allocator(self: *Self) std.mem.Allocator {
        return .{
            .ptr = self,
            .vtable = &.{
                .alloc = alloc,
                .resize = resize,
                .free = free,
                .remap = remap,
            },
        };
    }
};

/// Simple bump allocator for a fixed buffer.
pub const BumpAllocator = struct {
    buffer: []u8,
    offset: usize,

    const Self = @This();

    pub fn init(buffer: []u8) Self {
        return .{ .buffer = buffer, .offset = 0 };
    }

    pub fn reset(self: *Self) void {
        self.offset = 0;
    }

    pub fn getStats(self: *const Self) struct { used: usize, total: usize, free: usize } {
        return .{ .used = self.offset, .total = self.buffer.len, .free = self.buffer.len - self.offset };
    }

    fn alignUp(offset: usize, alignment: usize) usize {
        return (offset + alignment - 1) & ~(alignment - 1);
    }

    fn alloc(ctx: *anyopaque, len: usize, ptr_align: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
        _ = ret_addr;
        const self: *Self = @ptrCast(@alignCast(ctx));
        const alignment = @as(usize, 1) << @intFromEnum(ptr_align);
        const aligned_offset = alignUp(self.offset, alignment);
        const new_offset = aligned_offset + len;
        if (new_offset > self.buffer.len) return null;
        const result = self.buffer[aligned_offset..new_offset];
        self.offset = new_offset;
        return result.ptr;
    }

    fn resize(ctx: *anyopaque, buf: []u8, buf_align: std.mem.Alignment, new_len: usize, ret_addr: usize) bool {
        _ = ctx;
        _ = buf;
        _ = buf_align;
        _ = new_len;
        _ = ret_addr;
        return false;
    }

    fn free(ctx: *anyopaque, buf: []u8, buf_align: std.mem.Alignment, ret_addr: usize) void {
        _ = ctx;
        _ = buf;
        _ = buf_align;
        _ = ret_addr;
    }

    fn remap(ctx: *anyopaque, old_buf: []u8, buf_align: std.mem.Alignment, new_len: usize, ret_addr: usize) ?[*]u8 {
        _ = ctx;
        _ = old_buf;
        _ = buf_align;
        _ = new_len;
        _ = ret_addr;
        return null;
    }

    pub fn allocator(self: *Self) std.mem.Allocator {
        return .{
            .ptr = self,
            .vtable = &.{
                .alloc = alloc,
                .resize = resize,
                .free = free,
                .remap = remap,
            },
        };
    }
};

/// Resettable bump allocator (ergonomic wrapper around BumpAllocator).
pub const ArenaAllocator = struct {
    bump: BumpAllocator,

    const Self = @This();

    pub fn init(buffer: []u8) Self {
        return .{ .bump = BumpAllocator.init(buffer) };
    }

    pub fn reset(self: *Self) void {
        self.bump.reset();
    }

    pub fn allocator(self: *Self) std.mem.Allocator {
        return self.bump.allocator();
    }

    pub fn getStats(self: *const Self) struct { used: usize, total: usize, free: usize } {
        return self.bump.getStats();
    }
};

/// Compile-time fixed-size arena allocator.
pub fn FixedBufferAllocator(comptime size: usize) type {
    return struct {
        buffer: [size]u8,
        bump: BumpAllocator,

        const Self = @This();

        pub fn init() Self {
            var self = Self{ .buffer = undefined, .bump = undefined };
            self.bump = BumpAllocator.init(&self.buffer);
            return self;
        }

        pub fn reset(self: *Self) void {
            self.bump.reset();
        }

        pub fn allocator(self: *Self) std.mem.Allocator {
            return self.bump.allocator();
        }
    };
}
