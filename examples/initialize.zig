const std = @import("std");
const symcrypt = @import("symcrypt");

pub fn main() !void {
    try symcrypt.init();
    std.debug.print(
        "SymCrypt headers {d}.{d}.{d}, {s} linkage: initialized\n",
        .{
            symcrypt.header_version.api,
            symcrypt.header_version.minor,
            symcrypt.header_version.patch,
            @tagName(symcrypt.linkage),
        },
    );
}
