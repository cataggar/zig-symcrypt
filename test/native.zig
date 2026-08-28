const std = @import("std");
const symcrypt = @import("symcrypt");
const c = @cImport({
    @cDefine("SYMCRYPT_ZIG_IMPORT", "1");
    @cInclude("stddef.h");
    @cInclude("symcrypt.h");
});

test "initialization is repeatable and SymCrypt SHA-256 is usable" {
    try symcrypt.init();
    try symcrypt.ensureInitialized();

    var digest: [32]u8 = undefined;
    const message = "abc";
    c.SymCryptSha256(message.ptr, message.len, &digest);
    try std.testing.expectEqualSlices(
        u8,
        &[_]u8{
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
            0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
            0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
            0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
        },
        &digest,
    );
}

test "static callbacks allocate, randomize, and synchronize" {
    if (symcrypt.linkage != .static) return error.SkipZigTest;

    for ([_]usize{ 0, 1, 31, 32, 33 }) |size| {
        const ptr = c.SymCryptCallbackAlloc(size) orelse return error.OutOfMemory;
        try std.testing.expectEqual(@as(usize, 0), @intFromPtr(ptr) % 32);
        c.SymCryptCallbackFree(ptr);
    }

    var first: [32]u8 = undefined;
    var second: [32]u8 = undefined;
    try std.testing.expectEqual(
        @as(c_uint, c.SYMCRYPT_NO_ERROR),
        c.SymCryptCallbackRandom(&first, first.len),
    );
    try std.testing.expectEqual(
        @as(c_uint, c.SYMCRYPT_NO_ERROR),
        c.SymCryptCallbackRandom(&second, second.len),
    );
    try std.testing.expect(!std.mem.eql(u8, &first, &second));
    try std.testing.expectEqual(
        @as(c_uint, c.SYMCRYPT_NO_ERROR),
        c.SymCryptCallbackRandom(null, 0),
    );

    const mutex = c.SymCryptCallbackAllocateMutexFastInproc() orelse return error.OutOfMemory;
    defer c.SymCryptCallbackFreeMutexFastInproc(mutex);
    const Counter = struct {
        fn run(m: ?*anyopaque, value: *usize) void {
            var i: usize = 0;
            while (i < 1000) : (i += 1) {
                c.SymCryptCallbackAcquireMutexFastInproc(m);
                value.* += 1;
                c.SymCryptCallbackReleaseMutexFastInproc(m);
            }
        }
    };
    var value: usize = 0;
    var threads: [8]std.Thread = undefined;
    for (&threads) |*thread| thread.* = try std.Thread.spawn(.{}, Counter.run, .{ mutex, &value });
    for (&threads) |*thread| thread.join();
    try std.testing.expectEqual(@as(usize, 8000), value);
}
