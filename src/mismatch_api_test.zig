const std = @import("std");
const initialization = @import("init.zig");
const pinned = @import("symcrypt_version.zig");

test "dynamic API version mismatch is recoverable and cached" {
    try std.testing.expectError(
        error.IncompatibleSymCryptVersion,
        initialization.initializeVersion(pinned.api + 1, pinned.minor),
    );
    try std.testing.expectError(
        error.IncompatibleSymCryptVersion,
        initialization.ensureInitialized(),
    );
}
