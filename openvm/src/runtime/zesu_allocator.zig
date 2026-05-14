/// zesu_allocator override for the OpenVM zkVM build.
///
/// Replaces zesu's default src/evm/allocator.zig (which returns std.heap.c_allocator)
/// with the OpenVM bump allocator. Injected via:
///   module.addImport("zesu_allocator", openvm_alloc_mod)
/// for each EVM module that allocates heap memory.
const std = @import("std");
const openvm = @import("openvm");

var instance = openvm.OpenVmAllocator.init();

pub fn get() std.mem.Allocator {
    return instance.allocator();
}
