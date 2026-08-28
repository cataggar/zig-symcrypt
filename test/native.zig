const std = @import("std");
const builtin = @import("builtin");
const symcrypt = @import("symcrypt");
const c = @cImport({
    if (builtin.target.os.tag == .windows) {
        @cUndef("_MSC_VER");
        @cDefine("__GNUC__", "4");
    }
    @cDefine("SYMCRYPT_ZIG_IMPORT", "1");
    @cInclude("stddef.h");
    @cInclude("symcrypt.h");
});

test {
    _ = @import("aead/aes_gcm.zig");
    _ = @import("aead/chacha20_poly1305.zig");
    _ = @import("cipher/aes_cbc.zig");
}

fn expectHex(comptime expected: []const u8, actual: anytype) !void {
    const encoded = std.fmt.bytesToHex(actual, .lower);
    try std.testing.expectEqualStrings(expected, &encoded);
}

const WipeCheckingAllocator = struct {
    backing: std.mem.Allocator,
    allocations: usize = 0,
    frees: usize = 0,
    last_free_len: usize = 0,
    last_free_all_zero: bool = false,

    fn init(backing: std.mem.Allocator) WipeCheckingAllocator {
        return .{ .backing = backing };
    }

    fn allocator(self: *WipeCheckingAllocator) std.mem.Allocator {
        return .{
            .ptr = self,
            .vtable = &.{
                .alloc = alloc,
                .resize = resize,
                .remap = remap,
                .free = free,
            },
        };
    }

    fn alloc(
        context: *anyopaque,
        len: usize,
        alignment: std.mem.Alignment,
        return_address: usize,
    ) ?[*]u8 {
        const self: *WipeCheckingAllocator = @ptrCast(@alignCast(context));
        const result = self.backing.rawAlloc(len, alignment, return_address) orelse return null;
        self.allocations += 1;
        return result;
    }

    fn resize(
        context: *anyopaque,
        memory: []u8,
        alignment: std.mem.Alignment,
        new_len: usize,
        return_address: usize,
    ) bool {
        const self: *WipeCheckingAllocator = @ptrCast(@alignCast(context));
        return self.backing.rawResize(memory, alignment, new_len, return_address);
    }

    fn remap(
        context: *anyopaque,
        memory: []u8,
        alignment: std.mem.Alignment,
        new_len: usize,
        return_address: usize,
    ) ?[*]u8 {
        const self: *WipeCheckingAllocator = @ptrCast(@alignCast(context));
        return self.backing.rawRemap(memory, alignment, new_len, return_address);
    }

    fn free(
        context: *anyopaque,
        memory: []u8,
        alignment: std.mem.Alignment,
        return_address: usize,
    ) void {
        const self: *WipeCheckingAllocator = @ptrCast(@alignCast(context));
        self.last_free_len = memory.len;
        self.last_free_all_zero = true;
        for (memory) |byte| {
            if (byte != 0) {
                self.last_free_all_zero = false;
                break;
            }
        }
        self.frees += 1;
        self.backing.rawFree(memory, alignment, return_address);
    }

    fn expectSingleZeroedFree(self: *const WipeCheckingAllocator, expected_len: usize) !void {
        try std.testing.expectEqual(@as(usize, 1), self.allocations);
        try std.testing.expectEqual(@as(usize, 1), self.frees);
        try std.testing.expectEqual(expected_len, self.last_free_len);
        try std.testing.expect(self.last_free_all_zero);
    }
};

fn hashBlockLength(comptime algorithm: symcrypt.hash.Algorithm) usize {
    return if (symcrypt.legacy_enabled)
        switch (algorithm) {
            .md5 => c.SYMCRYPT_MD5_INPUT_BLOCK_SIZE,
            .sha1 => c.SYMCRYPT_SHA1_INPUT_BLOCK_SIZE,
            .sha256 => c.SYMCRYPT_SHA256_INPUT_BLOCK_SIZE,
            .sha384 => c.SYMCRYPT_SHA384_INPUT_BLOCK_SIZE,
            .sha512 => c.SYMCRYPT_SHA512_INPUT_BLOCK_SIZE,
            .sha3_224 => c.SYMCRYPT_SHA3_224_INPUT_BLOCK_SIZE,
            .sha3_256 => c.SYMCRYPT_SHA3_256_INPUT_BLOCK_SIZE,
            .sha3_384 => c.SYMCRYPT_SHA3_384_INPUT_BLOCK_SIZE,
            .sha3_512 => c.SYMCRYPT_SHA3_512_INPUT_BLOCK_SIZE,
        }
    else switch (algorithm) {
        .sha256 => c.SYMCRYPT_SHA256_INPUT_BLOCK_SIZE,
        .sha384 => c.SYMCRYPT_SHA384_INPUT_BLOCK_SIZE,
        .sha512 => c.SYMCRYPT_SHA512_INPUT_BLOCK_SIZE,
        .sha3_224 => c.SYMCRYPT_SHA3_224_INPUT_BLOCK_SIZE,
        .sha3_256 => c.SYMCRYPT_SHA3_256_INPUT_BLOCK_SIZE,
        .sha3_384 => c.SYMCRYPT_SHA3_384_INPUT_BLOCK_SIZE,
        .sha3_512 => c.SYMCRYPT_SHA3_512_INPUT_BLOCK_SIZE,
    };
}

fn testHash(
    comptime algorithm: symcrypt.hash.Algorithm,
    comptime empty_hex: []const u8,
    comptime abc_hex: []const u8,
) !void {
    try expectHex(empty_hex, try symcrypt.hash.digest(algorithm, ""));
    try expectHex(abc_hex, try symcrypt.hash.digest(algorithm, "abc"));

    var output: symcrypt.hash.Digest(algorithm) = undefined;
    try symcrypt.hash.digestInto(algorithm, "abc", &output);
    try expectHex(abc_hex, output);
    var wrong: [1]u8 = undefined;
    try std.testing.expectError(error.WrongDataSize, symcrypt.hash.digestInto(algorithm, "", &wrong));

    var message: [300]u8 = undefined;
    for (&message, 0..) |*byte, index| byte.* = @truncate(index *% 37 +% 11);
    const expected = try symcrypt.hash.digest(algorithm, &message);
    const block = hashBlockLength(algorithm);
    for ([_]usize{ 0, 1, block - 1, block, block + 1, message.len }) |split| {
        const context = try symcrypt.hash.Context(algorithm).create(std.testing.allocator);
        defer context.deinit();
        try context.update(message[0..split]);
        try context.update(message[split..]);
        try std.testing.expectEqual(expected, try context.final());
    }

    const reusable = try symcrypt.hash.Context(algorithm).create(std.testing.allocator);
    defer reusable.deinit();
    try reusable.update("abc");
    try expectHex(abc_hex, try reusable.final());
    try expectHex(empty_hex, try reusable.final());
    try reusable.update("discarded");
    try reusable.reset();
    try expectHex(empty_hex, try reusable.final());

    const source = try symcrypt.hash.Context(algorithm).create(std.testing.allocator);
    defer source.deinit();
    try source.update("prefix");
    try std.testing.expectEqual(
        try symcrypt.hash.digest(algorithm, "prefix"),
        try source.snapshot(),
    );
    const fork = try source.clone(std.testing.allocator);
    defer fork.deinit();
    try source.update("left");
    try fork.update("right");
    try std.testing.expectEqual(
        try symcrypt.hash.digest(algorithm, "prefixleft"),
        try source.final(),
    );
    try std.testing.expectEqual(
        try symcrypt.hash.digest(algorithm, "prefixright"),
        try fork.final(),
    );
}

fn hmacBlockLength(comptime algorithm: symcrypt.hmac.Algorithm) usize {
    return if (symcrypt.legacy_enabled)
        switch (algorithm) {
            .md5 => c.SYMCRYPT_HMAC_MD5_INPUT_BLOCK_SIZE,
            .sha1 => c.SYMCRYPT_HMAC_SHA1_INPUT_BLOCK_SIZE,
            .sha256 => c.SYMCRYPT_HMAC_SHA256_INPUT_BLOCK_SIZE,
            .sha384 => c.SYMCRYPT_HMAC_SHA384_INPUT_BLOCK_SIZE,
            .sha512 => c.SYMCRYPT_HMAC_SHA512_INPUT_BLOCK_SIZE,
            .sha3_224 => c.SYMCRYPT_HMAC_SHA3_224_INPUT_BLOCK_SIZE,
            .sha3_256 => c.SYMCRYPT_HMAC_SHA3_256_INPUT_BLOCK_SIZE,
            .sha3_384 => c.SYMCRYPT_HMAC_SHA3_384_INPUT_BLOCK_SIZE,
            .sha3_512 => c.SYMCRYPT_HMAC_SHA3_512_INPUT_BLOCK_SIZE,
        }
    else switch (algorithm) {
        .sha256 => c.SYMCRYPT_HMAC_SHA256_INPUT_BLOCK_SIZE,
        .sha384 => c.SYMCRYPT_HMAC_SHA384_INPUT_BLOCK_SIZE,
        .sha512 => c.SYMCRYPT_HMAC_SHA512_INPUT_BLOCK_SIZE,
        .sha3_224 => c.SYMCRYPT_HMAC_SHA3_224_INPUT_BLOCK_SIZE,
        .sha3_256 => c.SYMCRYPT_HMAC_SHA3_256_INPUT_BLOCK_SIZE,
        .sha3_384 => c.SYMCRYPT_HMAC_SHA3_384_INPUT_BLOCK_SIZE,
        .sha3_512 => c.SYMCRYPT_HMAC_SHA3_512_INPUT_BLOCK_SIZE,
    };
}

fn testHmac(
    comptime algorithm: symcrypt.hmac.Algorithm,
    comptime empty_hex: []const u8,
    comptime key_abc_hex: []const u8,
) !void {
    try expectHex(empty_hex, try symcrypt.hmac.mac(algorithm, "", ""));
    try expectHex(key_abc_hex, try symcrypt.hmac.mac(algorithm, "key", "abc"));

    var output: symcrypt.hmac.Digest(algorithm) = undefined;
    try symcrypt.hmac.macInto(algorithm, "key", "abc", &output);
    try expectHex(key_abc_hex, output);
    var wrong: [1]u8 = undefined;
    try std.testing.expectError(error.WrongDataSize, symcrypt.hmac.macInto(algorithm, "", "", &wrong));

    var block_key: [hmacBlockLength(algorithm)]u8 = undefined;
    @memset(&block_key, 0x5a);
    var long_key: [hmacBlockLength(algorithm) + 17]u8 = undefined;
    @memset(&long_key, 0xa5);
    inline for (.{ "", "key", block_key[0..], long_key[0..] }) |key| {
        const expected = try symcrypt.hmac.mac(algorithm, key, "abcdef");
        const context = try symcrypt.hmac.Context(algorithm).create(std.testing.allocator, key);
        defer context.deinit();
        try context.update("");
        try context.update("ab");
        try context.update("cdef");
        try std.testing.expectEqual(expected, try context.snapshot());
        try std.testing.expectEqual(expected, try context.final());
        try std.testing.expectError(error.InvalidState, context.update("x"));
        try std.testing.expectError(error.InvalidState, context.final());
        try std.testing.expectError(error.InvalidState, context.snapshot());
        try std.testing.expectError(error.InvalidState, context.clone(std.testing.allocator));
        try context.reset();
        try context.update("abcdef");
        try std.testing.expectEqual(expected, try context.final());
    }

    const source = try symcrypt.hmac.Context(algorithm).create(std.testing.allocator, "secret key");
    defer source.deinit();
    try source.update("prefix");
    const fork = try source.clone(std.testing.allocator);
    defer fork.deinit();
    try source.update("left");
    try fork.update("right");
    try std.testing.expectEqual(
        try symcrypt.hmac.mac(algorithm, "secret key", "prefixleft"),
        try source.final(),
    );
    try std.testing.expectEqual(
        try symcrypt.hmac.mac(algorithm, "secret key", "prefixright"),
        try fork.final(),
    );
}

fn testHkdf(
    algorithm: symcrypt.hmac.Algorithm,
    comptime expected_hex: []const u8,
) !void {
    const ikm = [_]u8{0x0b} ** 22;
    const salt = [_]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c };
    const info = [_]u8{ 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9 };
    var output: [42]u8 = undefined;
    try symcrypt.hkdf.derive(algorithm, &ikm, &salt, &info, &output);
    try expectHex(expected_hex, output);
    try symcrypt.hkdf.derive(algorithm, "", "", "", output[0..0]);
}

fn testHkdfMaximum(algorithm: symcrypt.hmac.Algorithm) !void {
    const maximum = symcrypt.hkdf.maxOutputLength(algorithm);
    const output = try std.testing.allocator.alloc(u8, maximum);
    defer std.testing.allocator.free(output);
    try symcrypt.hkdf.derive(algorithm, "ikm", "", "", output);
}

test "initialization is repeatable and public legacy surface is gated" {
    try symcrypt.init();
    try symcrypt.ensureInitialized();
    try std.testing.expectEqual(symcrypt.legacy_enabled, @hasDecl(symcrypt.hash, "Md5"));
    try std.testing.expectEqual(symcrypt.legacy_enabled, @hasDecl(symcrypt.hash, "Sha1"));
    try std.testing.expectEqual(symcrypt.legacy_enabled, @hasDecl(symcrypt.hmac, "Md5"));
    try std.testing.expectEqual(symcrypt.legacy_enabled, @hasDecl(symcrypt.hmac, "Sha1"));
    try std.testing.expectEqual(
        symcrypt.legacy_enabled,
        std.meta.stringToEnum(symcrypt.hash.Algorithm, "md5") != null,
    );
}

test "all known SymCrypt errors and unknown raw values are diagnosed" {
    try symcrypt.checkCode(c.SYMCRYPT_NO_ERROR);
    const known = [_]u32{
        c.SYMCRYPT_UNUSED,
        c.SYMCRYPT_WRONG_KEY_SIZE,
        c.SYMCRYPT_WRONG_BLOCK_SIZE,
        c.SYMCRYPT_WRONG_DATA_SIZE,
        c.SYMCRYPT_WRONG_NONCE_SIZE,
        c.SYMCRYPT_WRONG_TAG_SIZE,
        c.SYMCRYPT_WRONG_ITERATION_COUNT,
        c.SYMCRYPT_AUTHENTICATION_FAILURE,
        c.SYMCRYPT_EXTERNAL_FAILURE,
        c.SYMCRYPT_FIPS_FAILURE,
        c.SYMCRYPT_HARDWARE_FAILURE,
        c.SYMCRYPT_NOT_IMPLEMENTED,
        c.SYMCRYPT_INVALID_BLOB,
        c.SYMCRYPT_BUFFER_TOO_SMALL,
        c.SYMCRYPT_INVALID_ARGUMENT,
        c.SYMCRYPT_MEMORY_ALLOCATION_FAILURE,
        c.SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE,
        c.SYMCRYPT_INCOMPATIBLE_FORMAT,
        c.SYMCRYPT_VALUE_TOO_LARGE,
        c.SYMCRYPT_SESSION_REPLAY_FAILURE,
        c.SYMCRYPT_HBS_NO_OTS_KEYS_LEFT,
        c.SYMCRYPT_HBS_PUBLIC_ROOT_MISMATCH,
    };
    for (known) |code| {
        try std.testing.expect(symcrypt.classifyCode(code) == .known);
    }
    const unknown: u32 = @intCast(c.SYMCRYPT_HBS_PUBLIC_ROOT_MISMATCH + 0x1000);
    try std.testing.expectEqual(unknown, symcrypt.classifyCode(unknown).unknown_code);
    try std.testing.expectError(error.UnknownSymCryptError, symcrypt.checkCode(unknown));
}

test "hash known-answer incremental clone snapshot reset and empty vectors" {
    try testHash(.sha256, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    try testHash(.sha384, "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b", "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7");
    try testHash(.sha512, "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e", "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
    try testHash(.sha3_224, "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7", "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf");
    try testHash(.sha3_256, "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a", "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");
    try testHash(.sha3_384, "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004", "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25");
    try testHash(.sha3_512, "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26", "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0");
    if (comptime symcrypt.legacy_enabled) {
        try testHash(.md5, "d41d8cd98f00b204e9800998ecf8427e", "900150983cd24fb0d6963f7d28e17f72");
        try testHash(.sha1, "da39a3ee5e6b4b0d3255bfef95601890afd80709", "a9993e364706816aba3e25717850c26c9cd0d89d");
    }
}

test "HMAC known-answer incremental clone snapshot reset and key lengths" {
    try testHmac(.sha256, "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad", "9c196e32dc0175f86f4b1cb89289d6619de6bee699e4c378e68309ed97a1a6ab");
    try testHmac(.sha384, "6c1f2ee938fad2e24bd91298474382ca218c75db3d83e114b3d4367776d14d3551289e75e8209cd4b792302840234adc", "30ddb9c8f347cffbfb44e519d814f074cf4047a55d6f563324f1c6a33920e5edfb2a34bac60bdc96cd33a95623d7d638");
    try testHmac(.sha512, "b936cee86c9f87aa5d3c6f2e84cb5a4239a5fe50480a6ec66b70ab5b1f4ac6730c6c515421b327ec1d69402e53dfb49ad7381eb067b338fd7b0cb22247225d47", "3926a207c8c42b0c41792cbd3e1a1aaaf5f7a25704f62dfc939c4987dd7ce060009c5bb1c2447355b3216f10b537e9afa7b64a4e5391b0d631172d07939e087a");
    try testHmac(.sha3_224, "1b9044e0d5bb4ef944bc00f1b26c483ac3e222f4640935d089a49083", "09d9d74e7d761c8f27f07d8d35f95b9d160b6b4d8175329db68eea6d");
    try testHmac(.sha3_256, "e841c164e5b4f10c9f3985587962af72fd607a951196fc92fb3a5251941784ea", "09b6dbab8d11795ca7c8d82f1cf91682013c7cb980abbb25473be4ae7f7b5683");
    try testHmac(.sha3_384, "adca89f07bbfbeaf58880c1572379ea2416568fd3b66542bd42599c57c4567e6ae086299ea216c6f3e7aef90b6191d24", "94f2aa7ae7c4b7b8fa4c612fdb422b3343811b13c8888257904f543995cdbcba5e49f10f8ed6f7b9ddc1b30b3828815c");
    try testHmac(.sha3_512, "cbcf45540782d4bc7387fbbf7d30b3681d6d66cc435cafd82546b0fce96b367ea79662918436fba442e81a01d0f9592dfcd30f7a7a8f1475693d30be4150ca84", "085e4e83503f40b82fef38438bc4905a55dbaa8c8878097a899db0b57ce7da57a368251c34474f60b3ebacb39b2edaca4b290456411c76ec7ab61944cfe2288e");
    if (comptime symcrypt.legacy_enabled) {
        try testHmac(.md5, "74e6f7298a9c2d168935f58c001bad88", "d2fe98063f876b03193afb49b4979591");
        try testHmac(.sha1, "fbdb1d1b18aa6c08324b7d64b71fb76370690e1d", "4fd0b215276ef12f2b3e4c8ecac2811498b656fc");
    }
}

test "HKDF vectors limits empty inputs and failure wiping" {
    try testHkdf(.sha256, "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");
    try testHkdf(.sha384, "9b5097a86038b805309076a44b3a9f38063e25b516dcbf369f394cfab43685f748b6457763e4f0204fc5");
    try testHkdf(.sha512, "832390086cda71fb47625bb5ceb168e4c8e26a1a16ed34d9fc7fe92c1481579338da362cb8d9f925d7cb");
    try testHkdf(.sha3_224, "5058867fc7bdb118ce6a703add6edbf8e2ce21f5766cfc2e662e1a36ff6922fa96fc149517cf1e451fe6");
    try testHkdf(.sha3_256, "0c5160501d65021deaf2c14f5abce04c5bd2635abceeba61c2edb6e8ed72674900557728f2c9f2c4c179");
    try testHkdf(.sha3_384, "138d8521e5a346a9cb770f762b9c04d9ca317409fb6a3ef9cb905228385589ae883bbe8b07b009f0e08b");
    try testHkdf(.sha3_512, "40e9f17e9bf2ef99425c2b23ccdf20a018ea5513f9ae68e1ea8c626deb57dfa4d56c27ccf2a2a24488a5");
    if (comptime symcrypt.legacy_enabled) {
        try testHkdf(.md5, "b222c9db38d17b2fea8b3bb511c0d6d86049ef481ba7065ca5c6422618ed9cc9144900e2c72b6a863a31");
        try testHkdf(.sha1, "d6000ffb5b50bd3970b260017798fb9c8df9ce2e2c16b6cd709cca07dc3cf9cf26d6c6d750d0aaf5ac94");
    }

    try testHkdfMaximum(.sha256);
    try testHkdfMaximum(.sha384);
    try testHkdfMaximum(.sha512);
    try testHkdfMaximum(.sha3_224);
    try testHkdfMaximum(.sha3_256);
    try testHkdfMaximum(.sha3_384);
    try testHkdfMaximum(.sha3_512);
    if (comptime symcrypt.legacy_enabled) {
        try testHkdfMaximum(.md5);
        try testHkdfMaximum(.sha1);
    }

    const max = symcrypt.hkdf.maxOutputLength(.sha256);
    const too_long = try std.testing.allocator.alloc(u8, max + 1);
    defer std.testing.allocator.free(too_long);
    @memset(too_long, 0xa5);
    try std.testing.expectError(
        error.OverlappingBuffers,
        symcrypt.hkdf.derive(.sha256, "", "", too_long[0..1], too_long),
    );
    for (too_long) |byte| try std.testing.expectEqual(@as(u8, 0), byte);
    @memset(too_long, 0xa5);
    try std.testing.expectError(error.WrongDataSize, symcrypt.hkdf.derive(.sha256, "", "", "", too_long));
    for (too_long) |byte| try std.testing.expectEqual(@as(u8, 0), byte);

    var full_overlap = [_]u8{0x3c} ** 65;
    try std.testing.expectError(
        error.OverlappingBuffers,
        symcrypt.hkdf.derive(
            .sha256,
            "ikm",
            "salt",
            full_overlap[0..],
            full_overlap[0..],
        ),
    );
    try std.testing.expectEqualSlices(u8, &([_]u8{0} ** full_overlap.len), &full_overlap);

    var partial_storage = [_]u8{0x5a} ** 96;
    try std.testing.expectError(
        error.OverlappingBuffers,
        symcrypt.hkdf.derive(
            .sha256,
            "ikm",
            "salt",
            partial_storage[0..48],
            partial_storage[31..96],
        ),
    );
    try std.testing.expectEqualSlices(
        u8,
        &([_]u8{0} ** 65),
        partial_storage[31..96],
    );

    var reverse_partial_storage = [_]u8{0xc3} ** 96;
    try std.testing.expectError(
        error.OverlappingBuffers,
        symcrypt.hkdf.derive(
            .sha256,
            "ikm",
            "salt",
            reverse_partial_storage[48..96],
            reverse_partial_storage[0..65],
        ),
    );
    try std.testing.expectEqualSlices(
        u8,
        &([_]u8{0} ** 65),
        reverse_partial_storage[0..65],
    );

    const adjacent_info = [_]u8{0x7b} ** 32;
    var expected_adjacent: [65]u8 = undefined;
    try symcrypt.hkdf.derive(.sha256, "ikm", "salt", &adjacent_info, &expected_adjacent);
    var adjacent_storage: [97]u8 = undefined;
    @memcpy(adjacent_storage[0..32], &adjacent_info);
    try symcrypt.hkdf.derive(
        .sha256,
        "ikm",
        "salt",
        adjacent_storage[0..32],
        adjacent_storage[32..97],
    );
    try std.testing.expectEqualSlices(u8, &expected_adjacent, adjacent_storage[32..97]);

    var separate_output: [65]u8 = undefined;
    try symcrypt.hkdf.derive(.sha256, "ikm", "salt", &adjacent_info, &separate_output);
    try std.testing.expectEqualSlices(u8, &expected_adjacent, &separate_output);
}

test "allocation failures and exact full-allocation wiping before free" {
    var failing_hash = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    try std.testing.expectError(error.OutOfMemory, symcrypt.hash.Sha256.create(failing_hash.allocator()));
    var failing_hmac = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    try std.testing.expectError(error.OutOfMemory, symcrypt.hmac.Sha256.create(failing_hmac.allocator(), "key"));

    const HashImpl = struct {
        allocator: std.mem.Allocator,
        state: c.SYMCRYPT_SHA256_STATE,
    };
    const HmacImpl = struct {
        allocator: std.mem.Allocator,
        key: c.SYMCRYPT_HMAC_SHA256_EXPANDED_KEY,
        state: c.SYMCRYPT_HMAC_SHA256_STATE,
        active: bool,
    };

    var hash_create_allocator = WipeCheckingAllocator.init(std.testing.allocator);
    const hash_context = try symcrypt.hash.Sha256.create(hash_create_allocator.allocator());
    hash_context.deinit();
    try hash_create_allocator.expectSingleZeroedFree(@sizeOf(HashImpl));

    const hash_source = try symcrypt.hash.Sha256.create(std.testing.allocator);
    defer hash_source.deinit();
    var hash_clone_allocator = WipeCheckingAllocator.init(std.testing.allocator);
    const hash_clone = try hash_source.clone(hash_clone_allocator.allocator());
    hash_clone.deinit();
    try hash_clone_allocator.expectSingleZeroedFree(@sizeOf(HashImpl));

    var failing_hash_clone = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    try std.testing.expectError(error.OutOfMemory, hash_source.clone(failing_hash_clone.allocator()));

    var hmac_create_allocator = WipeCheckingAllocator.init(std.testing.allocator);
    const hmac_context = try symcrypt.hmac.Sha256.create(hmac_create_allocator.allocator(), "secret");
    hmac_context.deinit();
    try hmac_create_allocator.expectSingleZeroedFree(@sizeOf(HmacImpl));

    const hmac_source = try symcrypt.hmac.Sha256.create(std.testing.allocator, "secret");
    defer hmac_source.deinit();
    var hmac_clone_allocator = WipeCheckingAllocator.init(std.testing.allocator);
    const hmac_clone = try hmac_source.clone(hmac_clone_allocator.allocator());
    hmac_clone.deinit();
    try hmac_clone_allocator.expectSingleZeroedFree(@sizeOf(HmacImpl));

    var failing_clone = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    try std.testing.expectError(error.OutOfMemory, hmac_source.clone(failing_clone.allocator()));

    var post_allocation_failure_allocator = WipeCheckingAllocator.init(std.testing.allocator);
    symcrypt.testing.failNextHmacCreateAfterAllocation();
    try std.testing.expectError(
        error.MemoryAllocationFailure,
        symcrypt.hmac.Sha256.create(post_allocation_failure_allocator.allocator(), "secret"),
    );
    try post_allocation_failure_allocator.expectSingleZeroedFree(@sizeOf(HmacImpl));
}

test "random zero length smoke and static callback routing" {
    var empty: [0]u8 = .{};
    try symcrypt.random.fill(&empty);
    var first: [32]u8 = undefined;
    var second: [32]u8 = undefined;
    try symcrypt.random.fill(&first);
    try symcrypt.random.fill(&second);
    try std.testing.expect(!std.mem.eql(u8, &first, &second));
    if (symcrypt.linkage == .static) {
        try std.testing.expectEqual(
            @as(c.SYMCRYPT_ERROR, c.SYMCRYPT_NO_ERROR),
            c.SymCryptCallbackRandom(null, 0),
        );
    }
}

const ConcurrentWorker = struct {
    fn run(
        source: *const symcrypt.hash.Sha256,
        hmac_source: *const symcrypt.hmac.Sha256,
        failed: *bool,
    ) void {
        const clone = source.clone(std.heap.page_allocator) catch {
            @atomicStore(bool, failed, true, .release);
            return;
        };
        defer clone.deinit();
        const snapshot = source.snapshot() catch {
            @atomicStore(bool, failed, true, .release);
            return;
        };
        const expected = symcrypt.hash.digest(.sha256, "prefix") catch {
            @atomicStore(bool, failed, true, .release);
            return;
        };
        if (!std.mem.eql(u8, &snapshot, &expected)) @atomicStore(bool, failed, true, .release);

        const hmac_clone = hmac_source.clone(std.heap.page_allocator) catch {
            @atomicStore(bool, failed, true, .release);
            return;
        };
        defer hmac_clone.deinit();
        hmac_clone.update("suffix") catch {
            @atomicStore(bool, failed, true, .release);
            return;
        };
        const tag = hmac_clone.final() catch {
            @atomicStore(bool, failed, true, .release);
            return;
        };
        const expected_tag = symcrypt.hmac.mac(.sha256, "key", "prefixsuffix") catch {
            @atomicStore(bool, failed, true, .release);
            return;
        };
        if (!std.mem.eql(u8, &tag, &expected_tag)) @atomicStore(bool, failed, true, .release);

        _ = symcrypt.hmac.mac(.sha3_256, "key", "message") catch {
            @atomicStore(bool, failed, true, .release);
            return;
        };
        var random_bytes: [16]u8 = undefined;
        symcrypt.random.fill(&random_bytes) catch {
            @atomicStore(bool, failed, true, .release);
        };
    }
};

test "independent operations clones snapshots and random are concurrent" {
    const source = try symcrypt.hash.Sha256.create(std.testing.allocator);
    defer source.deinit();
    try source.update("prefix");
    const hmac_source = try symcrypt.hmac.Sha256.create(std.testing.allocator, "key");
    defer hmac_source.deinit();
    try hmac_source.update("prefix");
    var failed = false;
    var threads: [12]std.Thread = undefined;
    for (&threads) |*thread| {
        thread.* = try std.Thread.spawn(.{}, ConcurrentWorker.run, .{ source, hmac_source, &failed });
    }
    for (&threads) |*thread| thread.join();
    try std.testing.expect(!@atomicLoad(bool, &failed, .acquire));
}

test "static callbacks allocate and synchronize" {
    if (symcrypt.linkage != .static) return error.SkipZigTest;
    for ([_]usize{ 0, 1, 31, 32, 33 }) |size| {
        const ptr = c.SymCryptCallbackAlloc(size) orelse return error.OutOfMemory;
        try std.testing.expectEqual(@as(usize, 0), @intFromPtr(ptr) % 32);
        c.SymCryptCallbackFree(ptr);
    }

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

extern fn SymCryptZigTestFailAllocationAfter(allocation_index: usize) void;
extern fn SymCryptZigTestDisableAllocationFailure() void;

test "static callback allocation failures clean up ECC and RSA construction" {
    if (symcrypt.linkage != .static) return error.SkipZigTest;
    defer SymCryptZigTestDisableAllocationFailure();

    const warm_ecc = try symcrypt.asymmetric.ecc.PrivateKey.generate(
        std.testing.allocator,
        .p256,
        .signing,
    );
    warm_ecc.deinit();
    const warm_rsa = try symcrypt.asymmetric.rsa.PrivateKey.generate(
        std.testing.allocator,
        2048,
        null,
        .signing,
    );
    warm_rsa.deinit();

    for (0..2) |failure_index| {
        SymCryptZigTestFailAllocationAfter(failure_index);
        try std.testing.expectError(
            error.MemoryAllocationFailure,
            symcrypt.asymmetric.ecc.PrivateKey.generate(
                std.testing.allocator,
                .p256,
                .signing,
            ),
        );
    }
    SymCryptZigTestDisableAllocationFailure();
    const recovered_ecc = try symcrypt.asymmetric.ecc.PrivateKey.generate(
        std.testing.allocator,
        .p256,
        .signing,
    );
    recovered_ecc.deinit();

    SymCryptZigTestFailAllocationAfter(0);
    try std.testing.expectError(
        error.MemoryAllocationFailure,
        symcrypt.asymmetric.rsa.PrivateKey.generate(
            std.testing.allocator,
            2048,
            null,
            .signing,
        ),
    );
    SymCryptZigTestDisableAllocationFailure();
    const recovered_rsa = try symcrypt.asymmetric.rsa.PrivateKey.generate(
        std.testing.allocator,
        2048,
        null,
        .signing,
    );
    recovered_rsa.deinit();
}
