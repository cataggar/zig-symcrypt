const std = @import("std");
const builtin = @import("builtin");
const options = @import("symcrypt_options");
const c = @import("../c.zig").raw;
const hash = if (options.legacy) @import("../hash_legacy.zig") else @import("../hash.zig");

pub const Algorithm = hash.Algorithm;

pub fn digestLength(algorithm: Algorithm) usize {
    const name = @tagName(algorithm);
    if (std.mem.eql(u8, name, "md5")) return c.SYMCRYPT_MD5_RESULT_SIZE;
    if (std.mem.eql(u8, name, "sha1")) return c.SYMCRYPT_SHA1_RESULT_SIZE;
    if (std.mem.eql(u8, name, "sha256")) return c.SYMCRYPT_SHA256_RESULT_SIZE;
    if (std.mem.eql(u8, name, "sha384")) return c.SYMCRYPT_SHA384_RESULT_SIZE;
    if (std.mem.eql(u8, name, "sha512")) return c.SYMCRYPT_SHA512_RESULT_SIZE;
    if (std.mem.eql(u8, name, "sha3_256")) return c.SYMCRYPT_SHA3_256_RESULT_SIZE;
    if (std.mem.eql(u8, name, "sha3_384")) return c.SYMCRYPT_SHA3_384_RESULT_SIZE;
    if (std.mem.eql(u8, name, "sha3_512")) return c.SYMCRYPT_SHA3_512_RESULT_SIZE;
    return 0;
}

pub fn allowedEcdsa(algorithm: Algorithm) bool {
    const name = @tagName(algorithm);
    return !std.mem.eql(u8, name, "md5") and !std.mem.eql(u8, name, "sha3_224");
}

pub fn allowedRsa(algorithm: Algorithm) bool {
    const name = @tagName(algorithm);
    return !std.mem.eql(u8, name, "sha3_224");
}

pub fn pointer(algorithm: Algorithm) c.PCSYMCRYPT_HASH {
    if (builtin.target.os.tag == .windows and
        comptime std.mem.eql(u8, options.linkage, "dynamic"))
        return pointerWindows(algorithm);
    const name = @tagName(algorithm);
    if (std.mem.eql(u8, name, "md5")) return c.SymCryptMd5Algorithm;
    if (std.mem.eql(u8, name, "sha1")) return c.SymCryptSha1Algorithm;
    if (std.mem.eql(u8, name, "sha256")) return c.SymCryptSha256Algorithm;
    if (std.mem.eql(u8, name, "sha384")) return c.SymCryptSha384Algorithm;
    if (std.mem.eql(u8, name, "sha512")) return c.SymCryptSha512Algorithm;
    if (std.mem.eql(u8, name, "sha3_256")) return c.SymCryptSha3_256Algorithm;
    if (std.mem.eql(u8, name, "sha3_384")) return c.SymCryptSha3_384Algorithm;
    if (std.mem.eql(u8, name, "sha3_512")) return c.SymCryptSha3_512Algorithm;
    unreachable;
}

extern fn SymCryptZigMd5Algorithm() c.PCSYMCRYPT_HASH;
extern fn SymCryptZigSha1Algorithm() c.PCSYMCRYPT_HASH;
extern fn SymCryptZigSha256Algorithm() c.PCSYMCRYPT_HASH;
extern fn SymCryptZigSha384Algorithm() c.PCSYMCRYPT_HASH;
extern fn SymCryptZigSha512Algorithm() c.PCSYMCRYPT_HASH;
extern fn SymCryptZigSha3_256Algorithm() c.PCSYMCRYPT_HASH;
extern fn SymCryptZigSha3_384Algorithm() c.PCSYMCRYPT_HASH;
extern fn SymCryptZigSha3_512Algorithm() c.PCSYMCRYPT_HASH;

fn pointerWindows(algorithm: Algorithm) c.PCSYMCRYPT_HASH {
    const name = @tagName(algorithm);
    if (std.mem.eql(u8, name, "md5")) return SymCryptZigMd5Algorithm();
    if (std.mem.eql(u8, name, "sha1")) return SymCryptZigSha1Algorithm();
    if (std.mem.eql(u8, name, "sha256")) return SymCryptZigSha256Algorithm();
    if (std.mem.eql(u8, name, "sha384")) return SymCryptZigSha384Algorithm();
    if (std.mem.eql(u8, name, "sha512")) return SymCryptZigSha512Algorithm();
    if (std.mem.eql(u8, name, "sha3_256")) return SymCryptZigSha3_256Algorithm();
    if (std.mem.eql(u8, name, "sha3_384")) return SymCryptZigSha3_384Algorithm();
    if (std.mem.eql(u8, name, "sha3_512")) return SymCryptZigSha3_512Algorithm();
    unreachable;
}
