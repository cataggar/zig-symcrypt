const std = @import("std");
const symcrypt = @import("symcrypt");

comptime {
    if (symcrypt.linkage != .static) @compileError("this example requires -Dlinkage=static");
}

pub fn main() !void {
    try symcrypt.init();
    std.debug.print("statically linked SymCrypt is initialized (not a FIPS claim)\n", .{});
}
