const std = @import("std");
const c = @import("c.zig").raw;

pub fn validate() void {
    comptime {
        if (@sizeOf(usize) != 8 or @sizeOf(*anyopaque) != 8) {
            @compileError("SymCrypt bootstrap supports only 64-bit targets (SIZE_T and pointers must be 8 bytes)");
        }
        if (c.SYMCRYPT_ALIGN_VALUE != 16) {
            @compileError(std.fmt.comptimePrint(
                "SYMCRYPT_ALIGN_VALUE mismatch: expected 16, found {d}",
                .{c.SYMCRYPT_ALIGN_VALUE},
            ));
        }
        if (c.SYMCRYPT_ASYM_ALIGN_VALUE != 32) {
            @compileError(std.fmt.comptimePrint(
                "SYMCRYPT_ASYM_ALIGN_VALUE mismatch: expected 32, found {d}",
                .{c.SYMCRYPT_ASYM_ALIGN_VALUE},
            ));
        }

        assertLayout("SYMCRYPT_MD5_STATE", c.SYMCRYPT_MD5_STATE, 112, 16);
        assertLayout("SYMCRYPT_SHA1_STATE", c.SYMCRYPT_SHA1_STATE, 128, 16);
        assertLayout("SYMCRYPT_SHA256_STATE", c.SYMCRYPT_SHA256_STATE, 128, 16);
        assertLayout("SYMCRYPT_SHA384_STATE", c.SYMCRYPT_SHA384_STATE, 224, 16);
        assertLayout("SYMCRYPT_SHA512_STATE", c.SYMCRYPT_SHA512_STATE, 224, 16);
        assertLayout("SYMCRYPT_SHA3_224_STATE", c.SYMCRYPT_SHA3_224_STATE, 240, 16);
        assertLayout("SYMCRYPT_SHA3_256_STATE", c.SYMCRYPT_SHA3_256_STATE, 240, 16);
        assertLayout("SYMCRYPT_SHA3_384_STATE", c.SYMCRYPT_SHA3_384_STATE, 240, 16);
        assertLayout("SYMCRYPT_SHA3_512_STATE", c.SYMCRYPT_SHA3_512_STATE, 240, 16);

        assertLayout("SYMCRYPT_HMAC_MD5_EXPANDED_KEY", c.SYMCRYPT_HMAC_MD5_EXPANDED_KEY, 48, 16);
        assertLayout("SYMCRYPT_HMAC_MD5_STATE", c.SYMCRYPT_HMAC_MD5_STATE, 128, 16);
        assertLayout("SYMCRYPT_HMAC_SHA1_EXPANDED_KEY", c.SYMCRYPT_HMAC_SHA1_EXPANDED_KEY, 80, 16);
        assertLayout("SYMCRYPT_HMAC_SHA1_STATE", c.SYMCRYPT_HMAC_SHA1_STATE, 144, 16);
        assertLayout("SYMCRYPT_HMAC_SHA256_EXPANDED_KEY", c.SYMCRYPT_HMAC_SHA256_EXPANDED_KEY, 80, 16);
        assertLayout("SYMCRYPT_HMAC_SHA256_STATE", c.SYMCRYPT_HMAC_SHA256_STATE, 144, 16);
        assertLayout("SYMCRYPT_HMAC_SHA384_EXPANDED_KEY", c.SYMCRYPT_HMAC_SHA384_EXPANDED_KEY, 144, 16);
        assertLayout("SYMCRYPT_HMAC_SHA384_STATE", c.SYMCRYPT_HMAC_SHA384_STATE, 240, 16);
        assertLayout("SYMCRYPT_HMAC_SHA512_EXPANDED_KEY", c.SYMCRYPT_HMAC_SHA512_EXPANDED_KEY, 144, 16);
        assertLayout("SYMCRYPT_HMAC_SHA512_STATE", c.SYMCRYPT_HMAC_SHA512_STATE, 240, 16);
        assertLayout("SYMCRYPT_HMAC_SHA3_224_EXPANDED_KEY", c.SYMCRYPT_HMAC_SHA3_224_EXPANDED_KEY, 512, 16);
        assertLayout("SYMCRYPT_HMAC_SHA3_224_STATE", c.SYMCRYPT_HMAC_SHA3_224_STATE, 272, 16);
        assertLayout("SYMCRYPT_HMAC_SHA3_256_EXPANDED_KEY", c.SYMCRYPT_HMAC_SHA3_256_EXPANDED_KEY, 512, 16);
        assertLayout("SYMCRYPT_HMAC_SHA3_256_STATE", c.SYMCRYPT_HMAC_SHA3_256_STATE, 272, 16);
        assertLayout("SYMCRYPT_HMAC_SHA3_384_EXPANDED_KEY", c.SYMCRYPT_HMAC_SHA3_384_EXPANDED_KEY, 512, 16);
        assertLayout("SYMCRYPT_HMAC_SHA3_384_STATE", c.SYMCRYPT_HMAC_SHA3_384_STATE, 272, 16);
        assertLayout("SYMCRYPT_HMAC_SHA3_512_EXPANDED_KEY", c.SYMCRYPT_HMAC_SHA3_512_EXPANDED_KEY, 512, 16);
        assertLayout("SYMCRYPT_HMAC_SHA3_512_STATE", c.SYMCRYPT_HMAC_SHA3_512_STATE, 272, 16);

        assertLayout("SYMCRYPT_AES_EXPANDED_KEY", c.SYMCRYPT_AES_EXPANDED_KEY, 496, 16);
        assertLayout("SYMCRYPT_GCM_EXPANDED_KEY", c.SYMCRYPT_GCM_EXPANDED_KEY, 2608, 16);
        assertLayout("SYMCRYPT_GCM_STATE", c.SYMCRYPT_GCM_STATE, 112, 16);
        assertLayout("SYMCRYPT_RSA_PARAMS", c.SYMCRYPT_RSA_PARAMS, 16, 4);
        assertOffset("SYMCRYPT_RSA_PARAMS.version", c.SYMCRYPT_RSA_PARAMS, "version", 0);
        assertOffset("SYMCRYPT_RSA_PARAMS.nBitsOfModulus", c.SYMCRYPT_RSA_PARAMS, "nBitsOfModulus", 4);
        assertOffset("SYMCRYPT_RSA_PARAMS.nPrimes", c.SYMCRYPT_RSA_PARAMS, "nPrimes", 8);
        assertOffset("SYMCRYPT_RSA_PARAMS.nPubExp", c.SYMCRYPT_RSA_PARAMS, "nPubExp", 12);
    }
}

fn assertOffset(
    comptime name: []const u8,
    comptime T: type,
    comptime field: []const u8,
    comptime expected: usize,
) void {
    const actual = @offsetOf(T, field);
    if (actual != expected) {
        @compileError(std.fmt.comptimePrint(
            "{s} ABI mismatch: expected offset {d}, found {d}",
            .{ name, expected, actual },
        ));
    }
}

fn assertLayout(comptime name: []const u8, comptime T: type, comptime size: usize, comptime alignment: usize) void {
    if (@sizeOf(T) != size or @alignOf(T) != alignment) {
        @compileError(std.fmt.comptimePrint(
            "{s} ABI mismatch: expected size/alignment {d}/{d}, found {d}/{d}",
            .{ name, size, alignment, @sizeOf(T), @alignOf(T) },
        ));
    }
}
