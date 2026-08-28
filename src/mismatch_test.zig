const std = @import("std");
const initialization = @import("init.zig");
const hkdf = @import("hkdf.zig");

test "dynamic version mismatch is cached and HKDF wipes without further SymCrypt calls" {
    try std.testing.expectError(
        error.IncompatibleSymCryptVersion,
        initialization.initializeVersion(103, 14),
    );

    var output = [_]u8{0xa5} ** 64;
    try std.testing.expectError(
        error.IncompatibleSymCryptVersion,
        hkdf.derive(.sha256, "ikm", "salt", "info", &output),
    );
    try std.testing.expectEqualSlices(u8, &([_]u8{0} ** output.len), &output);

    try std.testing.expectError(
        error.IncompatibleSymCryptVersion,
        initialization.initializeVersion(103, 13),
    );
}
