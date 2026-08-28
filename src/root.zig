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
pub const aead = @import("aead.zig");
pub const cipher = @import("cipher.zig");
pub const testing = if (@import("builtin").is_test) struct {
    pub fn failNextHmacCreateAfterAllocation() void {
        @import("hmac_impl.zig").testFailNextCreateAfterAllocation();
    }

    pub fn failNextAesGcmCreateAfterAllocation() void {
        @import("aead/aes_gcm.zig").testFailNextCreateAfterAllocation();
    }

    pub fn failNextAesCreateAfterAllocation() void {
        @import("cipher/aes.zig").testFailNextCreateAfterAllocation();
    }

    pub fn validateGcmLengths(nonce_len: u64, aad_len: u64, data_len: u64, tag_len: u64) Error!void {
        try @import("aead/aes_gcm.zig").validateLengths(nonce_len, aad_len, data_len, tag_len);
    }

    pub fn validateChaChaLengths(key_len: u64, nonce_len: u64, data_len: u64, tag_len: u64) Error!void {
        try @import("aead/chacha20_poly1305.zig").validateLengths(key_len, nonce_len, data_len, tag_len);
    }

    pub fn symCryptValidateGcmLengths(nonce_len: u64, aad_len: u64, data_len: u64, tag_len: u64) Error!u32 {
        return @import("aead/aes_gcm.zig").testSymCryptValidateLengths(nonce_len, aad_len, data_len, tag_len);
    }

    pub fn checkedBufferLength(a: usize, b: usize) Error!usize {
        return @import("internal/buffers.zig").checkedAdd(a, b);
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
