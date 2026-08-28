const std = @import("std");
const c = @import("../c.zig").raw;
const errors = @import("../errors.zig");
const buffers = @import("../internal/buffers.zig");
const owned = @import("../internal/owned.zig");
const secure_memory = @import("../internal/secure_memory.zig");

pub const block_size = 16;

pub fn encrypt(
    expanded_key: *const c.SYMCRYPT_AES_EXPANDED_KEY,
    iv: *[block_size]u8,
    plaintext: []const u8,
    ciphertext: []u8,
) errors.Error!void {
    try validate(plaintext.len, ciphertext.len);
    try validateOutOfPlace(iv, plaintext, ciphertext);
    if (plaintext.len == 0) return;
    c.SymCryptAesCbcEncrypt(
        expanded_key,
        iv,
        buffers.constPtr(plaintext),
        buffers.mutPtr(ciphertext),
        plaintext.len,
    );
}

pub fn decrypt(
    expanded_key: *const c.SYMCRYPT_AES_EXPANDED_KEY,
    iv: *[block_size]u8,
    ciphertext: []const u8,
    plaintext: []u8,
) errors.Error!void {
    try validate(ciphertext.len, plaintext.len);
    try validateOutOfPlace(iv, ciphertext, plaintext);
    if (ciphertext.len == 0) return;
    c.SymCryptAesCbcDecrypt(
        expanded_key,
        iv,
        buffers.constPtr(ciphertext),
        buffers.mutPtr(plaintext),
        ciphertext.len,
    );
}

pub fn encryptInPlace(
    expanded_key: *const c.SYMCRYPT_AES_EXPANDED_KEY,
    iv: *[block_size]u8,
    data: []u8,
) errors.Error!void {
    try validate(data.len, data.len);
    try buffers.requireDisjoint(iv, data);
    if (data.len == 0) return;
    c.SymCryptAesCbcEncrypt(
        expanded_key,
        iv,
        buffers.constPtr(data),
        buffers.mutPtr(data),
        data.len,
    );
}

pub fn decryptInPlace(
    expanded_key: *const c.SYMCRYPT_AES_EXPANDED_KEY,
    iv: *[block_size]u8,
    data: []u8,
) errors.Error!void {
    try validate(data.len, data.len);
    try buffers.requireDisjoint(iv, data);
    if (data.len == 0) return;
    c.SymCryptAesCbcDecrypt(
        expanded_key,
        iv,
        buffers.constPtr(data),
        buffers.mutPtr(data),
        data.len,
    );
}

pub fn encryptAlloc(
    expanded_key: *const c.SYMCRYPT_AES_EXPANDED_KEY,
    allocator: std.mem.Allocator,
    iv: *[block_size]u8,
    plaintext: []const u8,
) (std.mem.Allocator.Error || errors.Error)!owned.OwnedCiphertext {
    try validate(plaintext.len, plaintext.len);
    const allocation = try allocator.alloc(u8, plaintext.len);
    errdefer secure_memory.wipeAndFree(allocator, allocation);
    try encrypt(expanded_key, iv, plaintext, allocation);
    return .{ .allocator = allocator, .bytes = allocation };
}

pub fn decryptAlloc(
    expanded_key: *const c.SYMCRYPT_AES_EXPANDED_KEY,
    allocator: std.mem.Allocator,
    iv: *[block_size]u8,
    ciphertext: []const u8,
) (std.mem.Allocator.Error || errors.Error)!owned.OwnedPlaintext {
    try validate(ciphertext.len, ciphertext.len);
    const allocation = try allocator.alloc(u8, ciphertext.len);
    errdefer secure_memory.wipeAndFree(allocator, allocation);
    try decrypt(expanded_key, iv, ciphertext, allocation);
    return .{ .allocator = allocator, .bytes = allocation };
}

fn validate(input_len: usize, output_len: usize) errors.Error!void {
    if (input_len != output_len) return error.WrongDataSize;
    if (input_len % block_size != 0) return error.WrongBlockSize;
}

fn validateOutOfPlace(
    iv: *[block_size]u8,
    input: []const u8,
    output: []const u8,
) errors.Error!void {
    try buffers.requireDisjoint(input, output);
    try buffers.requireDisjoint(iv, input);
    try buffers.requireDisjoint(iv, output);
}
