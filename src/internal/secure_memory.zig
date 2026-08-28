const std = @import("std");
const c = @import("../c.zig").raw;

/// Wipes memory through SymCrypt. The caller must have initialized SymCrypt.
pub fn wipe(bytes: []u8) void {
    if (bytes.len == 0) return;
    c.SymCryptWipe(bytes.ptr, bytes.len);
}

/// Wipes memory without calling SymCrypt, including before or after failed initialization.
pub fn wipeIndependent(bytes: []u8) void {
    std.crypto.secureZero(u8, bytes);
}

/// Wipes immediately before releasing a byte allocation. This deliberately
/// bypasses `Allocator.free`, which poisons bytes before invoking `rawFree`.
pub fn wipeAndFree(allocator: std.mem.Allocator, bytes: []u8) void {
    if (bytes.len == 0) return;
    wipeIndependent(bytes);
    allocator.rawFree(bytes, .fromByteUnits(1), @returnAddress());
}

pub fn wipeValue(value: anytype) void {
    wipe(std.mem.asBytes(value));
}
