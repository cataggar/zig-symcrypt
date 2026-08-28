const std = @import("std");
const symcrypt = @import("symcrypt");

comptime {
    if (symcrypt.linkage != .static) @compileError("this example requires -Dlinkage=static");
}

pub fn main() !void {
    const context = try symcrypt.hmac.Sha256.create(std.heap.page_allocator, "example key");
    defer context.deinit();
    try context.update("abc");
    const result = try context.final();
    std.debug.print("static SymCrypt HMAC-SHA-256: {x} (not a FIPS claim)\n", .{result});
}
