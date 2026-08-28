const std = @import("std");
const builtin = @import("builtin");
const symcrypt = @import("symcrypt");
const common = @import("../common.zig");
const c = @cImport({
    if (builtin.target.os.tag == .windows) {
        @cUndef("_MSC_VER");
        @cDefine("__GNUC__", "4");
    }
    @cDefine("SYMCRYPT_ZIG_IMPORT", "1");
    @cInclude("stddef.h");
    @cInclude("symcrypt.h");
});

fn testVector(key: []const u8, expected_ciphertext: []const u8) !void {
    const iv = common.bytes("000102030405060708090a0b0c0d0e0f");
    const plaintext = common.bytes("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710");
    const aes = try symcrypt.cipher.AesKey.init(std.testing.allocator, key);
    defer aes.deinit();
    var encrypt_iv = iv;
    var ciphertext: [plaintext.len]u8 = undefined;
    try aes.cbcEncrypt(&encrypt_iv, &plaintext, &ciphertext);
    try std.testing.expectEqualSlices(u8, expected_ciphertext, &ciphertext);
    try std.testing.expectEqualSlices(u8, expected_ciphertext[expected_ciphertext.len - 16 ..], &encrypt_iv);
    var decrypt_iv = iv;
    var recovered: [plaintext.len]u8 = undefined;
    try aes.cbcDecrypt(&decrypt_iv, &ciphertext, &recovered);
    try std.testing.expectEqual(plaintext, recovered);
    try std.testing.expectEqualSlices(u8, expected_ciphertext[expected_ciphertext.len - 16 ..], &decrypt_iv);
}

test "AES-CBC NIST vectors for 128/192/256-bit keys" {
    const key128 = common.bytes("2b7e151628aed2a6abf7158809cf4f3c");
    const ciphertext128 = common.bytes("7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b273bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7");
    try testVector(&key128, &ciphertext128);
    const key192 = common.bytes("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b");
    const ciphertext192 = common.bytes("4f021db243bc633d7178183a9fa071e8b4d9ada9ad7dedf4e5e738763f69145a571b242012fb7ae07fa9baac3df102e008b0e27988598881d920a9e64f5615cd");
    try testVector(&key192, &ciphertext192);
    const key256 = common.bytes("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
    const ciphertext256 = common.bytes("f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d39f23369a9d9bacfa530e26304231461b2eb05e2c39be9fcda6c19078c6a9d1b");
    try testVector(&key256, &ciphertext256);
}

test "AES-CBC is raw unpadded, supports in-place, piecewise, empty, and owned APIs" {
    const key = common.bytes("2b7e151628aed2a6abf7158809cf4f3c");
    const original_iv = common.bytes("000102030405060708090a0b0c0d0e0f");
    const aes = try symcrypt.cipher.AesKey.init(std.testing.allocator, &key);
    defer aes.deinit();
    var data = common.bytes("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51");
    const plaintext = data;
    var iv = original_iv;
    try aes.cbcEncryptInPlace(&iv, &data);
    var decrypt_iv = original_iv;
    try aes.cbcDecryptInPlace(&decrypt_iv, &data);
    try std.testing.expectEqual(plaintext, data);

    var all_at_once: [plaintext.len]u8 = undefined;
    iv = original_iv;
    try aes.cbcEncrypt(&iv, &plaintext, &all_at_once);
    var piecewise: [plaintext.len]u8 = undefined;
    var piece_iv = original_iv;
    try aes.cbcEncrypt(&piece_iv, plaintext[0..16], piecewise[0..16]);
    try aes.cbcEncrypt(&piece_iv, plaintext[16..32], piecewise[16..32]);
    try std.testing.expectEqual(all_at_once, piecewise);
    try std.testing.expectEqual(iv, piece_iv);

    var empty_iv = original_iv;
    var empty: [0]u8 = .{};
    try aes.cbcEncryptInPlace(&empty_iv, &empty);
    try std.testing.expectEqual(original_iv, empty_iv);

    var owned_iv = original_iv;
    var encrypted = try aes.cbcEncryptAlloc(std.testing.allocator, &owned_iv, &plaintext);
    defer encrypted.deinit();
    owned_iv = original_iv;
    var decrypted = try aes.cbcDecryptAlloc(std.testing.allocator, &owned_iv, encrypted.bytes);
    defer decrypted.deinit();
    try std.testing.expectEqualSlices(u8, &plaintext, decrypted.bytes);
}

test "AES-CBC rejects invalid keys, blocks, lengths, and overlaps without changing IV/output" {
    try std.testing.expectError(error.WrongKeySize, symcrypt.cipher.AesKey.init(std.testing.allocator, &([_]u8{0} ** 20)));
    const aes = try symcrypt.cipher.AesKey.init(std.testing.allocator, &([_]u8{0} ** 16));
    defer aes.deinit();
    var iv = [_]u8{0x11} ** 16;
    const original_iv = iv;
    var output = [_]u8{0xa5} ** 32;
    try std.testing.expectError(error.WrongBlockSize, aes.cbcEncrypt(&iv, output[0..15], output[16..31]));
    try std.testing.expectEqual(original_iv, iv);
    try std.testing.expectError(error.WrongDataSize, aes.cbcEncrypt(&iv, output[0..16], output[16..31]));
    try std.testing.expectEqual(original_iv, iv);

    var overlap = [_]u8{0x44} ** 64;
    try std.testing.expectError(error.OverlappingBuffers, aes.cbcEncrypt(&iv, overlap[0..32], overlap[1..33]));
    try std.testing.expectError(error.OverlappingBuffers, aes.cbcEncrypt(&iv, overlap[1..33], overlap[0..32]));
    try std.testing.expectError(error.OverlappingBuffers, aes.cbcEncrypt(&iv, overlap[0..32], overlap[0..32]));
    try aes.cbcEncrypt(&iv, overlap[0..16], overlap[16..32]);

    var iv_storage = [_]u8{0} ** 48;
    const overlapping_iv: *[16]u8 = @ptrCast(iv_storage[0..16].ptr);
    try std.testing.expectError(error.OverlappingBuffers, aes.cbcEncryptInPlace(overlapping_iv, iv_storage[8..24]));
}

test "AES-CBC allocation failures and expanded-key/plaintext wiping" {
    const key = [_]u8{0x23} ** 16;
    var failing_key = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    try std.testing.expectError(error.OutOfMemory, symcrypt.cipher.AesKey.init(failing_key.allocator(), &key));
    const KeyImpl = struct {
        allocator: std.mem.Allocator,
        expanded_key: c.SYMCRYPT_AES_EXPANDED_KEY,
    };
    var checking_key = common.WipeCheckingAllocator.init(std.testing.allocator);
    const checked = try symcrypt.cipher.AesKey.init(checking_key.allocator(), &key);
    checked.deinit();
    try checking_key.expectSingleZeroedFree(@sizeOf(KeyImpl));

    var post_allocation = common.WipeCheckingAllocator.init(std.testing.allocator);
    symcrypt.testing.failNextAesCreateAfterAllocation();
    try std.testing.expectError(error.MemoryAllocationFailure, symcrypt.cipher.AesKey.init(post_allocation.allocator(), &key));
    try post_allocation.expectSingleZeroedFree(@sizeOf(KeyImpl));

    const aes = try symcrypt.cipher.AesKey.init(std.testing.allocator, &key);
    defer aes.deinit();
    var iv = [_]u8{0} ** 16;
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    try std.testing.expectError(error.OutOfMemory, aes.cbcEncryptAlloc(failing.allocator(), &iv, &([_]u8{0} ** 16)));
    var checking_ciphertext = common.WipeCheckingAllocator.init(std.testing.allocator);
    var owned_ciphertext = try aes.cbcEncryptAlloc(checking_ciphertext.allocator(), &iv, &([_]u8{0} ** 16));
    owned_ciphertext.deinit();
    try checking_ciphertext.expectSingleZeroedFree(16);
    iv = [_]u8{0} ** 16;
    var ciphertext: [16]u8 = undefined;
    try aes.cbcEncrypt(&iv, &([_]u8{0} ** 16), &ciphertext);
    iv = [_]u8{0} ** 16;
    var checking_plaintext = common.WipeCheckingAllocator.init(std.testing.allocator);
    var plaintext = try aes.cbcDecryptAlloc(checking_plaintext.allocator(), &iv, &ciphertext);
    plaintext.deinit();
    try checking_plaintext.expectSingleZeroedFree(ciphertext.len);
}

const Worker = struct {
    fn run(aes: *const symcrypt.cipher.AesKey, failed: *bool, value: u8) void {
        var iv = [_]u8{value} ** 16;
        var data = [_]u8{value} ** 32;
        const expected = data;
        aes.cbcEncryptInPlace(&iv, &data) catch {
            @atomicStore(bool, failed, true, .release);
            return;
        };
        iv = [_]u8{value} ** 16;
        aes.cbcDecryptInPlace(&iv, &data) catch {
            @atomicStore(bool, failed, true, .release);
            return;
        };
        if (!std.mem.eql(u8, &data, &expected)) @atomicStore(bool, failed, true, .release);
    }
};

test "immutable AES expanded keys are reusable concurrently" {
    const aes = try symcrypt.cipher.AesKey.init(std.testing.allocator, &([_]u8{0x55} ** 32));
    defer aes.deinit();
    var failed = false;
    var threads: [8]std.Thread = undefined;
    for (&threads, 0..) |*thread, index| thread.* = try std.Thread.spawn(.{}, Worker.run, .{ aes, &failed, @as(u8, @intCast(index + 1)) });
    for (&threads) |*thread| thread.join();
    try std.testing.expect(!@atomicLoad(bool, &failed, .acquire));
}
