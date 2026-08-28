const std = @import("std");
const options = @import("symcrypt_options");
const abi = @import("abi.zig");
const initialization = @import("init.zig");

pub const Version = struct {
    api: u32,
    minor: u32,
    patch: u32,
};

pub const header_version: Version = .{ .api = 103, .minor = 13, .patch = 0 };

pub const Linkage = enum { dynamic, static };
pub const linkage: Linkage = if (std.mem.eql(u8, options.linkage, "dynamic")) .dynamic else .static;

pub const InitError = @import("errors.zig").InitError;

pub fn init() InitError!void {
    try initialization.ensureInitialized();
}

pub fn ensureInitialized() InitError!void {
    try initialization.ensureInitialized();
}

comptime {
    abi.validate();
}

test {
    std.testing.refAllDecls(@This());
}
