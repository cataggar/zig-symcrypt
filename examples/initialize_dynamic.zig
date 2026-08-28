const std = @import("std");
const symcrypt = @import("symcrypt");

comptime {
    if (symcrypt.linkage != .dynamic) @compileError("this example requires -Dlinkage=dynamic");
}

pub fn main() !void {
    try symcrypt.init();
    std.debug.print("dynamically linked SymCrypt is initialized\n", .{});
}
