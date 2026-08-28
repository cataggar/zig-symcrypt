const std = @import("std");
const options = @import("symcrypt_options");

pub const raw = @cImport({
    @cDefine("SYMCRYPT_ZIG_IMPORT", "1");
    @cInclude("stddef.h");
    @cInclude("symcrypt.h");
});

comptime {
    const expected = .{ 103, 13, 0 };
    const actual = .{
        raw.SYMCRYPT_CODE_VERSION_API,
        raw.SYMCRYPT_CODE_VERSION_MINOR,
        raw.SYMCRYPT_CODE_VERSION_PATCH,
    };
    if (actual[0] != expected[0] or actual[1] != expected[1] or actual[2] != expected[2]) {
        @compileError(std.fmt.comptimePrint(
            "SymCrypt header version mismatch in '{s}': expected 103.13.0, found {d}.{d}.{d}",
            .{ options.include_dir, actual[0], actual[1], actual[2] },
        ));
    }
}
