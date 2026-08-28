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
pub const legacy_enabled = options.legacy;

const error_model = @import("errors.zig");
pub const InitError = error_model.InitError;
pub const SymCryptError = error_model.SymCryptError;
pub const Error = error_model.Error;
pub const KnownError = error_model.KnownError;
pub const Status = error_model.Status;
pub const classifyCode = error_model.classifyCode;
pub const checkCode = error_model.checkCode;

pub const random = @import("random.zig");
pub const hash = if (options.legacy) @import("hash_legacy.zig") else @import("hash.zig");
pub const hmac = if (options.legacy) @import("hmac_legacy.zig") else @import("hmac.zig");
pub const hkdf = @import("hkdf.zig");
pub const testing = if (@import("builtin").is_test) struct {
    pub fn lastWipeLength() usize {
        return @import("internal/secure_memory.zig").testLastWipeLength();
    }
} else struct {};

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
