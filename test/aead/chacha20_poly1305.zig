const std = @import("std");
const symcrypt = @import("symcrypt");
const common = @import("../common.zig");

test "ChaCha20-Poly1305 RFC 8439 known-answer and owned round trip" {
    const key = common.bytes("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
    const nonce = common.bytes("070000004041424344454647");
    const aad = common.bytes("50515253c0c1c2c3c4c5c6c7");
    const plaintext = common.bytes("4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e");
    const expected_ciphertext = common.bytes("d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116");
    const expected_tag = common.bytes("1ae10b594f09e26a7e902ecbd0600691");
    var ciphertext: [plaintext.len]u8 = undefined;
    var tag: [16]u8 = undefined;
    try symcrypt.aead.ChaCha20Poly1305.seal(&key, &nonce, &aad, &plaintext, &ciphertext, &tag);
    try std.testing.expectEqual(expected_ciphertext, ciphertext);
    try std.testing.expectEqual(expected_tag, tag);
    var recovered: [plaintext.len]u8 = undefined;
    try symcrypt.aead.ChaCha20Poly1305.open(&key, &nonce, &aad, &ciphertext, &recovered, &tag);
    try std.testing.expectEqual(plaintext, recovered);

    var sealed = try symcrypt.aead.ChaCha20Poly1305.sealAlloc(std.testing.allocator, &key, &nonce, &aad, &plaintext);
    defer sealed.deinit();
    var opened = try symcrypt.aead.ChaCha20Poly1305.openAlloc(std.testing.allocator, &key, &nonce, &aad, sealed.ciphertext(), sealed.tag());
    defer opened.deinit();
    try std.testing.expectEqualSlices(u8, &plaintext, opened.bytes);
}

test "ChaCha20-Poly1305 empty, multiblock, in-place, and authentication wiping" {
    const key = [_]u8{0x31} ** 32;
    const nonce = [_]u8{0x42} ** 12;
    var empty: [0]u8 = .{};
    var empty_tag: [16]u8 = undefined;
    try symcrypt.aead.ChaCha20Poly1305.sealInPlace(&key, &nonce, "", &empty, &empty_tag);
    try symcrypt.aead.ChaCha20Poly1305.openInPlace(&key, &nonce, "", &empty, &empty_tag);
    empty_tag[0] ^= 1;
    try std.testing.expectError(
        error.AuthenticationFailure,
        symcrypt.aead.ChaCha20Poly1305.openInPlace(&key, &nonce, "", &empty, &empty_tag),
    );

    var message: [160]u8 = undefined;
    for (&message, 0..) |*byte, index| byte.* = @truncate(index *% 29 +% 7);
    const original = message;
    var tag: [16]u8 = undefined;
    try symcrypt.aead.ChaCha20Poly1305.sealInPlace(&key, &nonce, "aad", &message, &tag);
    try symcrypt.aead.ChaCha20Poly1305.openInPlace(&key, &nonce, "aad", &message, &tag);
    try std.testing.expectEqual(original, message);

    var ciphertext: [160]u8 = undefined;
    try symcrypt.aead.ChaCha20Poly1305.seal(&key, &nonce, "aad", &original, &ciphertext, &tag);
    var bad_tag = tag;
    bad_tag[0] ^= 1;
    var output = [_]u8{0xa5} ** ciphertext.len;
    try std.testing.expectError(error.AuthenticationFailure, symcrypt.aead.ChaCha20Poly1305.open(&key, &nonce, "aad", &ciphertext, &output, &bad_tag));
    try std.testing.expectEqual([_]u8{0} ** output.len, output);

    var bad_ciphertext = ciphertext;
    bad_ciphertext[0] ^= 1;
    output = [_]u8{0xa5} ** output.len;
    try std.testing.expectError(error.AuthenticationFailure, symcrypt.aead.ChaCha20Poly1305.open(&key, &nonce, "aad", &bad_ciphertext, &output, &tag));
    try std.testing.expectEqual([_]u8{0} ** output.len, output);

    var bad_nonce = nonce;
    bad_nonce[0] ^= 1;
    output = [_]u8{0xa5} ** output.len;
    try std.testing.expectError(error.AuthenticationFailure, symcrypt.aead.ChaCha20Poly1305.open(&key, &bad_nonce, "aad", &ciphertext, &output, &tag));
    try std.testing.expectEqual([_]u8{0} ** output.len, output);

    output = [_]u8{0xa5} ** output.len;
    try std.testing.expectError(error.AuthenticationFailure, symcrypt.aead.ChaCha20Poly1305.open(&key, &nonce, "bad", &ciphertext, &output, &tag));
    try std.testing.expectEqual([_]u8{0} ** output.len, output);

    var wrong_key = key;
    wrong_key[0] ^= 1;
    output = [_]u8{0xa5} ** output.len;
    try std.testing.expectError(error.AuthenticationFailure, symcrypt.aead.ChaCha20Poly1305.open(&wrong_key, &nonce, "aad", &ciphertext, &output, &tag));
    try std.testing.expectEqual([_]u8{0} ** output.len, output);

    var in_place = ciphertext;
    try std.testing.expectError(error.AuthenticationFailure, symcrypt.aead.ChaCha20Poly1305.openInPlace(&key, &nonce, "aad", &in_place, &bad_tag));
    try std.testing.expectEqual([_]u8{0} ** in_place.len, in_place);
}

test "ChaCha20-Poly1305 validates lengths, overlap, allocation failure, and limits" {
    const key = [_]u8{0x11} ** 32;
    const nonce = [_]u8{0x22} ** 12;
    var output = [_]u8{0xa5} ** 32;
    var tag = [_]u8{0x5a} ** 16;
    try std.testing.expectError(error.WrongKeySize, symcrypt.aead.ChaCha20Poly1305.seal(key[0..31], &nonce, "", &output, &output, &tag));
    try std.testing.expectEqual([_]u8{0xa5} ** output.len, output);
    try std.testing.expectError(error.WrongNonceSize, symcrypt.aead.ChaCha20Poly1305.seal(&key, nonce[0..11], "", &output, &output, &tag));
    try std.testing.expectError(error.WrongTagSize, symcrypt.aead.ChaCha20Poly1305.seal(&key, &nonce, "", &output, &output, tag[0..15]));
    try std.testing.expectError(error.WrongDataSize, symcrypt.aead.ChaCha20Poly1305.seal(&key, &nonce, "", output[0..31], &output, &tag));

    var overlap = [_]u8{0x33} ** 96;
    try std.testing.expectError(error.OverlappingBuffers, symcrypt.aead.ChaCha20Poly1305.seal(&key, &nonce, "", overlap[0..32], overlap[1..33], overlap[64..80]));
    try std.testing.expectError(error.OverlappingBuffers, symcrypt.aead.ChaCha20Poly1305.seal(&key, &nonce, "", overlap[1..33], overlap[0..32], overlap[64..80]));
    try std.testing.expectError(error.OverlappingBuffers, symcrypt.aead.ChaCha20Poly1305.seal(&key, &nonce, "", overlap[0..32], overlap[0..32], overlap[64..80]));
    try std.testing.expectError(error.OverlappingBuffers, symcrypt.aead.ChaCha20Poly1305.seal(&key, &nonce, "", overlap[0..32], overlap[32..64], overlap[16..32]));
    try std.testing.expectError(error.OverlappingBuffers, symcrypt.aead.ChaCha20Poly1305.sealInPlace(overlap[0..32], &nonce, "", overlap[16..48], overlap[64..80]));
    try symcrypt.aead.ChaCha20Poly1305.seal(&key, &nonce, "", overlap[0..32], overlap[32..64], overlap[64..80]);

    try symcrypt.testing.validateChaChaLengths(32, 12, 274_877_906_880, 16);
    try std.testing.expectError(error.WrongDataSize, symcrypt.testing.validateChaChaLengths(32, 12, 274_877_906_881, 16));

    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    try std.testing.expectError(error.OutOfMemory, symcrypt.aead.ChaCha20Poly1305.sealAlloc(failing.allocator(), &key, &nonce, "", "message"));

    var ciphertext: [7]u8 = undefined;
    try symcrypt.aead.ChaCha20Poly1305.seal(&key, &nonce, "", "message", &ciphertext, &tag);
    var failing_open = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    try std.testing.expectError(
        error.OutOfMemory,
        symcrypt.aead.ChaCha20Poly1305.openAlloc(failing_open.allocator(), &key, &nonce, "", &ciphertext, &tag),
    );
    tag[0] ^= 1;
    var checking = common.WipeCheckingAllocator.init(std.testing.allocator);
    try std.testing.expectError(
        error.AuthenticationFailure,
        symcrypt.aead.ChaCha20Poly1305.openAlloc(checking.allocator(), &key, &nonce, "", &ciphertext, &tag),
    );
    try checking.expectSingleZeroedFree(ciphertext.len);
}

const Worker = struct {
    fn run(key: *const [32]u8, failed: *bool, index: usize) void {
        var nonce = [_]u8{0} ** 12;
        std.mem.writeInt(u64, nonce[4..12], index, .little);
        var data = [_]u8{0x6d} ** 64;
        const expected = data;
        var tag: [16]u8 = undefined;
        symcrypt.aead.ChaCha20Poly1305.sealInPlace(key, &nonce, "aad", &data, &tag) catch {
            @atomicStore(bool, failed, true, .release);
            return;
        };
        symcrypt.aead.ChaCha20Poly1305.openInPlace(key, &nonce, "aad", &data, &tag) catch {
            @atomicStore(bool, failed, true, .release);
            return;
        };
        if (!std.mem.eql(u8, &data, &expected)) @atomicStore(bool, failed, true, .release);
    }
};

test "ChaCha20-Poly1305 operations are concurrent" {
    const key = [_]u8{0x77} ** 32;
    var failed = false;
    var threads: [8]std.Thread = undefined;
    for (&threads, 0..) |*thread, index| thread.* = try std.Thread.spawn(.{}, Worker.run, .{ &key, &failed, index });
    for (&threads) |*thread| thread.join();
    try std.testing.expect(!@atomicLoad(bool, &failed, .acquire));
}
