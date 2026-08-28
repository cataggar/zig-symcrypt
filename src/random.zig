const std = @import("std");
const options = @import("symcrypt_options");
const c = @import("c.zig").raw;
const initialization = @import("init.zig");
const errors = @import("errors.zig");

/// Fills a caller-owned buffer with cryptographically strong random bytes.
/// A zero-length request initializes SymCrypt and then succeeds without FFI.
pub fn fill(output: []u8) errors.Error!void {
    try initialization.ensureInitialized();
    if (output.len == 0) return;
    if (comptime std.mem.eql(u8, options.linkage, "dynamic")) {
        c.SymCryptRandom(output.ptr, output.len);
    } else {
        try errors.check(c.SymCryptCallbackRandom(output.ptr, output.len));
    }
}
