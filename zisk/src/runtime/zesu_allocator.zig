/// zesu_allocator override for the Zisk zkVM build.
///
/// Replaces zesu's default src/evm/allocator.zig (which returns std.heap.c_allocator)
/// with the Zisk bump allocator. Injected via:
///   module.addImport("zesu_allocator", zisk_alloc_mod)
/// for each EVM module that allocates heap memory.
const std = @import("std");
// Import via the named 'zisk' module so that allocator.zig stays in a single
// module (the 'zisk' module), avoiding the "file exists in multiple modules" error.
const zisk = @import("zisk");

var instance = zisk.ZiskAllocator.init();

pub fn get() std.mem.Allocator {
    return instance.allocator();
}
