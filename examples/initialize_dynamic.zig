const std = @import("std");
const symcrypt = @import("symcrypt");

comptime {
    if (symcrypt.linkage != .dynamic) @compileError("this example requires -Dlinkage=dynamic");
}

pub fn main() !void {
    const digest = try symcrypt.hash.digest(.sha256, "abc");
    std.debug.print("dynamic SymCrypt SHA-256(abc): {x}\n", .{digest});
}
