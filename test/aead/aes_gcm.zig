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

fn testVector(
    comptime Gcm: type,
    key: []const u8,
    nonce: []const u8,
    aad: []const u8,
    plaintext: []const u8,
    expected_ciphertext: []const u8,
    expected_tag: []const u8,
) !void {
    const gcm = try Gcm.init(std.testing.allocator, key);
    defer gcm.deinit();
    const ciphertext = try std.testing.allocator.alloc(u8, plaintext.len);
    defer std.testing.allocator.free(ciphertext);
    const tag = try std.testing.allocator.alloc(u8, expected_tag.len);
    defer std.testing.allocator.free(tag);
    try gcm.seal(nonce, aad, plaintext, ciphertext, tag);
    try std.testing.expectEqualSlices(u8, expected_ciphertext, ciphertext);
    try std.testing.expectEqualSlices(u8, expected_tag, tag);

    const recovered = try std.testing.allocator.alloc(u8, plaintext.len);
    defer std.testing.allocator.free(recovered);
    try gcm.open(nonce, aad, ciphertext, recovered, tag);
    try std.testing.expectEqualSlices(u8, plaintext, recovered);
}

test "AES-128/256-GCM upstream known-answer vectors including non-96-bit nonce" {
    const empty_key = common.bytes("00000000000000000000000000000000");
    const empty_nonce = common.bytes("000000000000000000000000");
    const empty_tag = common.bytes("58e2fccefa7e3061367f1d57a4e7455a");
    try testVector(symcrypt.aead.Aes128Gcm, &empty_key, &empty_nonce, "", "", "", &empty_tag);

    const key128 = common.bytes("feffe9928665731c6d6a8f9467308308");
    const nonce = common.bytes("cafebabefacedbaddecaf888");
    const aad = common.bytes("feedfacedeadbeeffeedfacedeadbeefabaddad2");
    const plaintext = common.bytes("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39");
    const ciphertext128 = common.bytes("42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091");
    const tag128 = common.bytes("5bc94fbc3221a5db94fae95ae7121a47");
    try testVector(symcrypt.aead.Aes128Gcm, &key128, &nonce, &aad, &plaintext, &ciphertext128, &tag128);

    const key256 = common.bytes("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
    const ciphertext256 = common.bytes("522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662");
    const tag256 = common.bytes("76fc6ece0f4e1768cddf8853bb2d551b");
    try testVector(symcrypt.aead.Aes256Gcm, &key256, &nonce, &aad, &plaintext, &ciphertext256, &tag256);

    const nonce64 = common.bytes("cafebabefacedbad");
    const ciphertext64 = common.bytes("61353b4c2806934a777ff51fa22a4755699b2a714fcdc6f83766e5f97b6c742373806900e49f24b22b097544d4896b424989b5e1ebac0f07c23f4598");
    const tag64 = common.bytes("3612d2e79e3b0785561be14aaca2fccb");
    try testVector(symcrypt.aead.Aes128Gcm, &key128, &nonce64, &aad, &plaintext, &ciphertext64, &tag64);
}

test "AES-GCM detached, in-place, owned, tag lengths, and repeated use" {
    const key = common.bytes("000102030405060708090a0b0c0d0e0f");
    const nonce = common.bytes("101112131415161718191a1b");
    const gcm = try symcrypt.aead.Aes128Gcm.init(std.testing.allocator, &key);
    defer gcm.deinit();
    const messages = [_][]const u8{ "", "x", "sixteen bytes msg", "a message spanning several AES blocks for round trips" };
    for (messages) |message| {
        for (12..17) |tag_len| {
            const ciphertext = try std.testing.allocator.alloc(u8, message.len);
            defer std.testing.allocator.free(ciphertext);
            const tag = try std.testing.allocator.alloc(u8, tag_len);
            defer std.testing.allocator.free(tag);
            try gcm.seal(&nonce, "aad", message, ciphertext, tag);
            const plaintext = try std.testing.allocator.alloc(u8, message.len);
            defer std.testing.allocator.free(plaintext);
            try gcm.open(&nonce, "aad", ciphertext, plaintext, tag);
            try std.testing.expectEqualSlices(u8, message, plaintext);
        }
    }

    var in_place = [_]u8{0x33} ** 48;
    const original = in_place;
    var tag: [16]u8 = undefined;
    try gcm.sealInPlace(&nonce, "aad", &in_place, &tag);
    try gcm.openInPlace(&nonce, "aad", &in_place, &tag);
    try std.testing.expectEqual(original, in_place);

    var sealed = try gcm.sealAlloc(std.testing.allocator, &nonce, "aad", "owned plaintext", 16);
    defer sealed.deinit();
    var opened = try gcm.openAlloc(std.testing.allocator, &nonce, "aad", sealed.ciphertext(), sealed.tag());
    defer opened.deinit();
    try std.testing.expectEqualStrings("owned plaintext", opened.bytes);
}

test "AES-GCM authentication failures always wipe the complete destination" {
    const key = common.bytes("000102030405060708090a0b0c0d0e0f");
    const wrong_key = common.bytes("010102030405060708090a0b0c0d0e0f");
    const nonce = common.bytes("101112131415161718191a1b");
    const gcm = try symcrypt.aead.Aes128Gcm.init(std.testing.allocator, &key);
    defer gcm.deinit();
    const wrong_gcm = try symcrypt.aead.Aes128Gcm.init(std.testing.allocator, &wrong_key);
    defer wrong_gcm.deinit();
    const plaintext = "plaintext which must never escape!";
    var ciphertext: [plaintext.len]u8 = undefined;
    var tag: [16]u8 = undefined;
    try gcm.seal(&nonce, "authenticated data", plaintext, &ciphertext, &tag);

    var bad_ciphertext = ciphertext;
    bad_ciphertext[0] ^= 1;
    var output = [_]u8{0xa5} ** ciphertext.len;
    try std.testing.expectError(error.AuthenticationFailure, gcm.open(&nonce, "authenticated data", &bad_ciphertext, &output, &tag));
    try std.testing.expectEqual([_]u8{0} ** output.len, output);

    output = [_]u8{0xa5} ** output.len;
    try std.testing.expectError(error.AuthenticationFailure, gcm.open(&nonce, "altered data", &ciphertext, &output, &tag));
    try std.testing.expectEqual([_]u8{0} ** output.len, output);

    var bad_nonce = nonce;
    bad_nonce[0] ^= 1;
    output = [_]u8{0xa5} ** output.len;
    try std.testing.expectError(error.AuthenticationFailure, gcm.open(&bad_nonce, "authenticated data", &ciphertext, &output, &tag));
    try std.testing.expectEqual([_]u8{0} ** output.len, output);

    var bad_tag = tag;
    bad_tag[15] ^= 1;
    output = [_]u8{0xa5} ** output.len;
    try std.testing.expectError(error.AuthenticationFailure, gcm.open(&nonce, "authenticated data", &ciphertext, &output, &bad_tag));
    try std.testing.expectEqual([_]u8{0} ** output.len, output);

    output = [_]u8{0xa5} ** output.len;
    try std.testing.expectError(error.AuthenticationFailure, wrong_gcm.open(&nonce, "authenticated data", &ciphertext, &output, &tag));
    try std.testing.expectEqual([_]u8{0} ** output.len, output);

    var in_place = ciphertext;
    try std.testing.expectError(error.AuthenticationFailure, gcm.openInPlace(&nonce, "authenticated data", &in_place, &bad_tag));
    try std.testing.expectEqual([_]u8{0} ** in_place.len, in_place);

    for (12..17) |tag_len| {
        var short_tag: [16]u8 = undefined;
        try gcm.seal(&nonce, "authenticated data", plaintext, &ciphertext, short_tag[0..tag_len]);
        short_tag[tag_len - 1] ^= 1;
        output = [_]u8{0xa5} ** output.len;
        try std.testing.expectError(
            error.AuthenticationFailure,
            gcm.open(&nonce, "authenticated data", &ciphertext, &output, short_tag[0..tag_len]),
        );
        try std.testing.expectEqual([_]u8{0} ** output.len, output);
    }

    var empty_tag: [16]u8 = undefined;
    var empty_ciphertext: [0]u8 = .{};
    try gcm.seal(&nonce, "", "", &empty_ciphertext, &empty_tag);
    empty_tag[0] ^= 1;
    try std.testing.expectError(error.AuthenticationFailure, gcm.openInPlace(&nonce, "", &empty_ciphertext, &empty_tag));
}

const GcmWorker = struct {
    fn run(gcm: *const symcrypt.aead.Aes128Gcm, failed: *bool, index: usize) void {
        var nonce = [_]u8{0} ** 12;
        std.mem.writeInt(u64, nonce[4..12], index, .little);
        var data = [_]u8{0x6a} ** 64;
        const expected = data;
        var tag: [16]u8 = undefined;
        gcm.sealInPlace(&nonce, "aad", &data, &tag) catch {
            @atomicStore(bool, failed, true, .release);
            return;
        };
        gcm.openInPlace(&nonce, "aad", &data, &tag) catch {
            @atomicStore(bool, failed, true, .release);
            return;
        };
        if (!std.mem.eql(u8, &data, &expected)) @atomicStore(bool, failed, true, .release);
    }
};

test "immutable AES-GCM expanded keys are reusable concurrently" {
    const gcm = try symcrypt.aead.Aes128Gcm.init(std.testing.allocator, &([_]u8{0x55} ** 16));
    defer gcm.deinit();
    var failed = false;
    var threads: [8]std.Thread = undefined;
    for (&threads, 0..) |*thread, index| thread.* = try std.Thread.spawn(.{}, GcmWorker.run, .{ gcm, &failed, index });
    for (&threads) |*thread| thread.join();
    try std.testing.expect(!@atomicLoad(bool, &failed, .acquire));
}

test "AES-GCM rejects invalid lengths and every unsafe overlap before mutation" {
    try std.testing.expectError(error.WrongKeySize, symcrypt.aead.Aes128Gcm.init(std.testing.allocator, &([_]u8{0} ** 24)));
    const key = [_]u8{0} ** 16;
    const nonce = [_]u8{1} ** 12;
    const gcm = try symcrypt.aead.Aes128Gcm.init(std.testing.allocator, &key);
    defer gcm.deinit();
    var dst = [_]u8{0xa5} ** 16;
    var tag = [_]u8{0x5a} ** 16;
    try std.testing.expectError(error.WrongNonceSize, gcm.seal("", "", &dst, &dst, &tag));
    try std.testing.expectEqual([_]u8{0xa5} ** 16, dst);
    try std.testing.expectEqual([_]u8{0x5a} ** 16, tag);
    try std.testing.expectError(error.WrongTagSize, gcm.seal(&nonce, "", &dst, &dst, tag[0..11]));
    try std.testing.expectError(error.WrongDataSize, gcm.seal(&nonce, "", dst[0..15], &dst, &tag));

    var overlap = [_]u8{0x44} ** 80;
    try std.testing.expectError(error.OverlappingBuffers, gcm.seal(&nonce, "", overlap[0..32], overlap[1..33], overlap[48..64]));
    try std.testing.expectError(error.OverlappingBuffers, gcm.seal(&nonce, "", overlap[1..33], overlap[0..32], overlap[48..64]));
    try std.testing.expectError(error.OverlappingBuffers, gcm.seal(&nonce, "", overlap[0..32], overlap[0..32], overlap[48..64]));
    try std.testing.expectError(error.OverlappingBuffers, gcm.seal(&nonce, "", overlap[0..32], overlap[32..64], overlap[16..32]));
    try std.testing.expectError(error.OverlappingBuffers, gcm.sealInPlace(&nonce, overlap[0..16], overlap[8..40], overlap[48..64]));

    var adjacent_tag: [16]u8 = undefined;
    try gcm.seal(&nonce, "", overlap[0..32], overlap[32..64], &adjacent_tag);
}

test "AES-GCM validators match pinned SymCrypt and cover boundaries" {
    const cases = [_]struct { nonce: u64, aad: u64, data: u64, tag: u64 }{
        .{ .nonce = 1, .aad = 0, .data = 0, .tag = 12 },
        .{ .nonce = 12, .aad = (@as(u64, 1) << 61) - 1, .data = (@as(u64, 1) << 36) - 32, .tag = 16 },
        .{ .nonce = 0, .aad = 0, .data = 0, .tag = 16 },
        .{ .nonce = 12, .aad = @as(u64, 1) << 61, .data = 0, .tag = 16 },
        .{ .nonce = 12, .aad = 0, .data = (@as(u64, 1) << 36) - 31, .tag = 16 },
        .{ .nonce = 12, .aad = 0, .data = 0, .tag = 11 },
    };
    for (cases) |case| {
        const wrapper_ok = if (symcrypt.testing.validateGcmLengths(case.nonce, case.aad, case.data, case.tag)) |_| true else |_| false;
        const raw = try symcrypt.testing.symCryptValidateGcmLengths(case.nonce, case.aad, case.data, case.tag);
        try std.testing.expectEqual(raw == @as(u32, @bitCast(c.SYMCRYPT_NO_ERROR)), wrapper_ok);
    }
    try std.testing.expectError(
        error.WrongNonceSize,
        symcrypt.testing.validateGcmLengths(std.math.maxInt(u64), 0, 0, 16),
    );
    try std.testing.expectError(
        error.ValueTooLarge,
        symcrypt.testing.checkedBufferLength(std.math.maxInt(usize), 1),
    );
}

test "AES-GCM allocation failures and exact state/plaintext wiping" {
    const key = [_]u8{0x11} ** 16;
    const nonce = [_]u8{0x22} ** 12;
    var failing_key = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    try std.testing.expectError(error.OutOfMemory, symcrypt.aead.Aes128Gcm.init(failing_key.allocator(), &key));

    const KeyImpl = struct {
        allocator: std.mem.Allocator,
        expanded_key: c.SYMCRYPT_GCM_EXPANDED_KEY,
    };
    var checking_key = common.WipeCheckingAllocator.init(std.testing.allocator);
    const gcm_checked = try symcrypt.aead.Aes128Gcm.init(checking_key.allocator(), &key);
    gcm_checked.deinit();
    try checking_key.expectSingleZeroedFree(@sizeOf(KeyImpl));

    var post_allocation = common.WipeCheckingAllocator.init(std.testing.allocator);
    symcrypt.testing.failNextAesGcmCreateAfterAllocation();
    try std.testing.expectError(error.MemoryAllocationFailure, symcrypt.aead.Aes128Gcm.init(post_allocation.allocator(), &key));
    try post_allocation.expectSingleZeroedFree(@sizeOf(KeyImpl));

    const gcm = try symcrypt.aead.Aes128Gcm.init(std.testing.allocator, &key);
    defer gcm.deinit();
    var failing_seal = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    try std.testing.expectError(error.OutOfMemory, gcm.sealAlloc(failing_seal.allocator(), &nonce, "", "message", 16));
    var ciphertext: [7]u8 = undefined;
    var tag: [16]u8 = undefined;
    try gcm.seal(&nonce, "", "message", &ciphertext, &tag);
    var failing_open = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    try std.testing.expectError(error.OutOfMemory, gcm.openAlloc(failing_open.allocator(), &nonce, "", &ciphertext, &tag));

    var checking_sealed = common.WipeCheckingAllocator.init(std.testing.allocator);
    var sealed = try gcm.sealAlloc(checking_sealed.allocator(), &nonce, "", "message", 16);
    sealed.deinit();
    try checking_sealed.expectSingleZeroedFree("message".len + 16);

    tag[0] ^= 1;
    var checking_plaintext = common.WipeCheckingAllocator.init(std.testing.allocator);
    try std.testing.expectError(
        error.AuthenticationFailure,
        gcm.openAlloc(checking_plaintext.allocator(), &nonce, "", &ciphertext, &tag),
    );
    try checking_plaintext.expectSingleZeroedFree(ciphertext.len);
}
