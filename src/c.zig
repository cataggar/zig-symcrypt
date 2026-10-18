const std = @import("std");
const options = @import("symcrypt_options");
const pinned = @import("symcrypt_version.zig");

pub const raw = @import("symcrypt_c_raw");

comptime {
    const expected = .{ pinned.api, pinned.minor, pinned.patch };
    const actual = .{
        raw.SYMCRYPT_CODE_VERSION_API,
        raw.SYMCRYPT_CODE_VERSION_MINOR,
        raw.SYMCRYPT_CODE_VERSION_PATCH,
    };
    if (actual[0] != expected[0] or actual[1] != expected[1] or actual[2] != expected[2]) {
        @compileError(std.fmt.comptimePrint(
            "SymCrypt header version mismatch in '{s}': expected {s}, found {d}.{d}.{d}",
            .{ options.include_dir, pinned.string, actual[0], actual[1], actual[2] },
        ));
    }
}
