/// ZisK host object: satisfies all extern symbol references in zesu.rv64im.o
///
/// Exports:
///   zkvm_log / zkvm_exit             — runtime (UART + ecall)
///   sys_read                         — Rust std stdin stub
///
/// Symbols provided by libziskos_staticlib.a at link time (NOT exported here):
///   read_input / write_output        — zkvm-standards io-interface
///   zkvm_* accelerators              — all 19 circuit-backed implementations (ZisK 0.18)
///   zkvm_init / zkvm_deinit / _start — entrypoint and lifecycle
/// Zisk zkVM UART — byte writes here appear in ziskemu console output
const ZISK_UART: *volatile u8 = @ptrFromInt(0xa0000200);

// ── Runtime ───────────────────────────────────────────────────────────────────

/// Logging sink used by zesu.o's std_options.logFn (src/zkvm/root.zig).
export fn zkvm_log(level: u8, msg_ptr: [*]const u8, msg_len: usize) void {
    _ = level;
    for (msg_ptr[0..msg_len]) |byte| {
        ZISK_UART.* = byte;
    }
    ZISK_UART.* = '\n';
}

/// Halt/exit: Linux syscall 93 (exit) via ecall.
export fn zkvm_exit(code: i32) noreturn {
    asm volatile (
        \\ ecall
        \\ .align 4
        :
        : [code] "{a0}" (code),
          [syscall] "{a7}" (@as(u32, 93)),
        : .{ .memory = true });
    while (true) {
        asm volatile ("wfi");
    }
}

/// Rust std's zkvm Stdin calls this — no stdin in zkVM, return EOF.
export fn sys_read(fd: i32, buf: [*]u8, count: usize) isize {
    _ = fd;
    _ = buf;
    _ = count;
    return 0;
}
