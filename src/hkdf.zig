const std = @import("std");
const builtin = @import("builtin");
const options = @import("symcrypt_options");
const c = @import("c.zig").raw;
const initialization = @import("init.zig");
const errors = @import("errors.zig");
const secure_memory = @import("internal/secure_memory.zig");
const hmac = if (options.legacy) @import("hmac_legacy.zig") else @import("hmac.zig");

const empty_input: u8 = 0;

/// RFC 5869 HKDF into caller-owned output. On failure, all output bytes are wiped.
pub fn derive(
    algorithm: hmac.Algorithm,
    ikm: []const u8,
    salt: []const u8,
    info: []const u8,
    output: []u8,
) errors.Error!void {
    const limit = std.math.mul(usize, 255, digestLength(algorithm)) catch
        return error.WrongDataSize;
    if (output.len > limit) {
        secure_memory.wipe(output);
        return error.WrongDataSize;
    }

    try initialization.ensureInitialized();
    if (output.len == 0) return;
    errors.check(c.SymCryptHkdf(
        macAlgorithm(algorithm),
        requiredPtr(ikm),
        ikm.len,
        optionalPtr(salt),
        salt.len,
        optionalPtr(info),
        info.len,
        output.ptr,
        output.len,
    )) catch |err| {
        secure_memory.wipe(output);
        return err;
    };
}

pub fn maxOutputLength(algorithm: hmac.Algorithm) usize {
    return std.math.mul(usize, 255, digestLength(algorithm)) catch unreachable;
}

fn digestLength(algorithm: hmac.Algorithm) usize {
    const name = @tagName(algorithm);
    if (std.mem.eql(u8, name, "md5")) return c.SYMCRYPT_MD5_RESULT_SIZE;
    if (std.mem.eql(u8, name, "sha1")) return c.SYMCRYPT_SHA1_RESULT_SIZE;
    if (std.mem.eql(u8, name, "sha256")) return c.SYMCRYPT_SHA256_RESULT_SIZE;
    if (std.mem.eql(u8, name, "sha384")) return c.SYMCRYPT_SHA384_RESULT_SIZE;
    if (std.mem.eql(u8, name, "sha512")) return c.SYMCRYPT_SHA512_RESULT_SIZE;
    if (std.mem.eql(u8, name, "sha3_224")) return c.SYMCRYPT_SHA3_224_RESULT_SIZE;
    if (std.mem.eql(u8, name, "sha3_256")) return c.SYMCRYPT_SHA3_256_RESULT_SIZE;
    if (std.mem.eql(u8, name, "sha3_384")) return c.SYMCRYPT_SHA3_384_RESULT_SIZE;
    if (std.mem.eql(u8, name, "sha3_512")) return c.SYMCRYPT_SHA3_512_RESULT_SIZE;
    unreachable;
}

fn macAlgorithm(algorithm: hmac.Algorithm) c.PCSYMCRYPT_MAC {
    return if (comptime builtin.target.os.tag == .windows and
        std.mem.eql(u8, options.linkage, "dynamic"))
        importedMacAlgorithm(algorithm)
    else
        linkedMacAlgorithm(algorithm);
}

fn linkedMacAlgorithm(algorithm: hmac.Algorithm) c.PCSYMCRYPT_MAC {
    const name = @tagName(algorithm);
    if (std.mem.eql(u8, name, "md5")) return c.SymCryptHmacMd5Algorithm;
    if (std.mem.eql(u8, name, "sha1")) return c.SymCryptHmacSha1Algorithm;
    if (std.mem.eql(u8, name, "sha256")) return c.SymCryptHmacSha256Algorithm;
    if (std.mem.eql(u8, name, "sha384")) return c.SymCryptHmacSha384Algorithm;
    if (std.mem.eql(u8, name, "sha512")) return c.SymCryptHmacSha512Algorithm;
    if (std.mem.eql(u8, name, "sha3_224")) return c.SymCryptHmacSha3_224Algorithm;
    if (std.mem.eql(u8, name, "sha3_256")) return c.SymCryptHmacSha3_256Algorithm;
    if (std.mem.eql(u8, name, "sha3_384")) return c.SymCryptHmacSha3_384Algorithm;
    if (std.mem.eql(u8, name, "sha3_512")) return c.SymCryptHmacSha3_512Algorithm;
    unreachable;
}

extern fn SymCryptZigHmacMd5Algorithm() c.PCSYMCRYPT_MAC;
extern fn SymCryptZigHmacSha1Algorithm() c.PCSYMCRYPT_MAC;
extern fn SymCryptZigHmacSha256Algorithm() c.PCSYMCRYPT_MAC;
extern fn SymCryptZigHmacSha384Algorithm() c.PCSYMCRYPT_MAC;
extern fn SymCryptZigHmacSha512Algorithm() c.PCSYMCRYPT_MAC;
extern fn SymCryptZigHmacSha3_224Algorithm() c.PCSYMCRYPT_MAC;
extern fn SymCryptZigHmacSha3_256Algorithm() c.PCSYMCRYPT_MAC;
extern fn SymCryptZigHmacSha3_384Algorithm() c.PCSYMCRYPT_MAC;
extern fn SymCryptZigHmacSha3_512Algorithm() c.PCSYMCRYPT_MAC;

fn importedMacAlgorithm(algorithm: hmac.Algorithm) c.PCSYMCRYPT_MAC {
    const name = @tagName(algorithm);
    if (std.mem.eql(u8, name, "md5")) return SymCryptZigHmacMd5Algorithm();
    if (std.mem.eql(u8, name, "sha1")) return SymCryptZigHmacSha1Algorithm();
    if (std.mem.eql(u8, name, "sha256")) return SymCryptZigHmacSha256Algorithm();
    if (std.mem.eql(u8, name, "sha384")) return SymCryptZigHmacSha384Algorithm();
    if (std.mem.eql(u8, name, "sha512")) return SymCryptZigHmacSha512Algorithm();
    if (std.mem.eql(u8, name, "sha3_224")) return SymCryptZigHmacSha3_224Algorithm();
    if (std.mem.eql(u8, name, "sha3_256")) return SymCryptZigHmacSha3_256Algorithm();
    if (std.mem.eql(u8, name, "sha3_384")) return SymCryptZigHmacSha3_384Algorithm();
    if (std.mem.eql(u8, name, "sha3_512")) return SymCryptZigHmacSha3_512Algorithm();
    unreachable;
}

fn optionalPtr(data: []const u8) [*c]const u8 {
    return if (data.len == 0) null else @ptrCast(data.ptr);
}

fn requiredPtr(data: []const u8) [*c]const u8 {
    return if (data.len == 0) @ptrCast(&empty_input) else @ptrCast(data.ptr);
}
