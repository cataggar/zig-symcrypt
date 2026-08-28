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

        assertLayout("SYMCRYPT_SHA256_STATE", c.SYMCRYPT_SHA256_STATE, 128, 16);
        assertLayout("SYMCRYPT_SHA384_STATE", c.SYMCRYPT_SHA384_STATE, 224, 16);
        assertLayout("SYMCRYPT_SHA512_STATE", c.SYMCRYPT_SHA512_STATE, 224, 16);
        assertLayout("SYMCRYPT_HMAC_SHA256_STATE", c.SYMCRYPT_HMAC_SHA256_STATE, 144, 16);
        assertLayout("SYMCRYPT_AES_EXPANDED_KEY", c.SYMCRYPT_AES_EXPANDED_KEY, 496, 16);
        assertLayout("SYMCRYPT_GCM_EXPANDED_KEY", c.SYMCRYPT_GCM_EXPANDED_KEY, 2608, 16);
        assertLayout("SYMCRYPT_GCM_STATE", c.SYMCRYPT_GCM_STATE, 112, 16);
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
