const std = @import("std");
const initialization = @import("init.zig");

test "dynamic version mismatch is recoverable and cached" {
    try std.testing.expectError(
        error.IncompatibleSymCryptVersion,
        initialization.initializeVersion(103, 14),
    );
    try std.testing.expectError(
        error.IncompatibleSymCryptVersion,
        initialization.initializeVersion(103, 13),
    );
}
