const std = @import("std");
const c = @import("../c.zig").raw;
const errors = @import("../errors.zig");
const initialization = @import("../init.zig");
const buffers = @import("../internal/buffers.zig");
const owned = @import("../internal/owned.zig");
const secure_memory = @import("../internal/secure_memory.zig");

pub const key_length = 32;
pub const nonce_length = 12;
pub const tag_length = 16;
pub const max_data_length: u64 = (std.math.maxInt(u32) * @as(u64, 64));

pub fn validateLengths(key_len: u64, nonce_len: u64, data_len: u64, tag_len: u64) errors.Error!void {
    if (key_len != key_length) return error.WrongKeySize;
    if (nonce_len != nonce_length) return error.WrongNonceSize;
    if (tag_len != tag_length) return error.WrongTagSize;
    if (data_len > max_data_length) return error.WrongDataSize;
}

pub fn seal(
    key: []const u8,
    nonce: []const u8,
    aad: []const u8,
    plaintext: []const u8,
    ciphertext: []u8,
    tag: []u8,
) errors.Error!void {
    try validate(key, nonce, plaintext.len, ciphertext.len, tag.len);
    try validateOutOfPlace(key, nonce, aad, plaintext, ciphertext, tag);
    initialization.ensureInitialized() catch |err| {
        secure_memory.wipeIndependent(ciphertext);
        secure_memory.wipeIndependent(tag);
        return err;
    };
    const result = c.SymCryptChaCha20Poly1305Encrypt(
        buffers.constPtr(key),
        key.len,
        buffers.constPtr(nonce),
        nonce.len,
        buffers.optionalConstPtr(aad),
        aad.len,
        buffers.constPtr(plaintext),
        buffers.mutPtr(ciphertext),
        plaintext.len,
        buffers.mutPtr(tag),
        tag.len,
    );
    errors.check(result) catch |err| {
        secure_memory.wipeIndependent(ciphertext);
        secure_memory.wipeIndependent(tag);
        return err;
    };
}

pub fn open(
    key: []const u8,
    nonce: []const u8,
    aad: []const u8,
    ciphertext: []const u8,
    plaintext: []u8,
    tag: []const u8,
) errors.Error!void {
    try validate(key, nonce, ciphertext.len, plaintext.len, tag.len);
    try validateOutOfPlace(key, nonce, aad, ciphertext, plaintext, tag);
    initialization.ensureInitialized() catch |err| {
        secure_memory.wipeIndependent(plaintext);
        return err;
    };
    const result = c.SymCryptChaCha20Poly1305Decrypt(
        buffers.constPtr(key),
        key.len,
        buffers.constPtr(nonce),
        nonce.len,
        buffers.optionalConstPtr(aad),
        aad.len,
        buffers.constPtr(ciphertext),
        buffers.mutPtr(plaintext),
        ciphertext.len,
        buffers.constPtr(tag),
        tag.len,
    );
    errors.check(result) catch |err| {
        secure_memory.wipeIndependent(plaintext);
        return err;
    };
}

pub fn sealInPlace(
    key: []const u8,
    nonce: []const u8,
    aad: []const u8,
    buffer: []u8,
    tag: []u8,
) errors.Error!void {
    try validate(key, nonce, buffer.len, buffer.len, tag.len);
    try validateInPlace(key, nonce, aad, buffer, tag);
    initialization.ensureInitialized() catch |err| {
        secure_memory.wipeIndependent(buffer);
        secure_memory.wipeIndependent(tag);
        return err;
    };
    const result = c.SymCryptChaCha20Poly1305Encrypt(
        buffers.constPtr(key),
        key.len,
        buffers.constPtr(nonce),
        nonce.len,
        buffers.optionalConstPtr(aad),
        aad.len,
        buffers.constPtr(buffer),
        buffers.mutPtr(buffer),
        buffer.len,
        buffers.mutPtr(tag),
        tag.len,
    );
    errors.check(result) catch |err| {
        secure_memory.wipeIndependent(buffer);
        secure_memory.wipeIndependent(tag);
        return err;
    };
}

/// Authentication failure wipes `buffer`, destroying the ciphertext.
pub fn openInPlace(
    key: []const u8,
    nonce: []const u8,
    aad: []const u8,
    buffer: []u8,
    tag: []const u8,
) errors.Error!void {
    try validate(key, nonce, buffer.len, buffer.len, tag.len);
    try validateInPlace(key, nonce, aad, buffer, tag);
    initialization.ensureInitialized() catch |err| {
        secure_memory.wipeIndependent(buffer);
        return err;
    };
    const result = c.SymCryptChaCha20Poly1305Decrypt(
        buffers.constPtr(key),
        key.len,
        buffers.constPtr(nonce),
        nonce.len,
        buffers.optionalConstPtr(aad),
        aad.len,
        buffers.constPtr(buffer),
        buffers.mutPtr(buffer),
        buffer.len,
        buffers.constPtr(tag),
        tag.len,
    );
    errors.check(result) catch |err| {
        secure_memory.wipeIndependent(buffer);
        return err;
    };
}

pub fn sealAlloc(
    allocator: std.mem.Allocator,
    key: []const u8,
    nonce: []const u8,
    aad: []const u8,
    plaintext: []const u8,
) (std.mem.Allocator.Error || errors.Error)!owned.OwnedSealed {
    try validateLengths(key.len, nonce.len, plaintext.len, tag_length);
    const total = try buffers.checkedAdd(plaintext.len, tag_length);
    const allocation = try allocator.alloc(u8, total);
    errdefer secure_memory.wipeAndFree(allocator, allocation);
    try seal(key, nonce, aad, plaintext, allocation[0..plaintext.len], allocation[plaintext.len..]);
    return .{ .allocator = allocator, .bytes = allocation, .ciphertext_len = plaintext.len };
}

pub fn openAlloc(
    allocator: std.mem.Allocator,
    key: []const u8,
    nonce: []const u8,
    aad: []const u8,
    ciphertext: []const u8,
    tag: []const u8,
) (std.mem.Allocator.Error || errors.Error)!owned.OwnedPlaintext {
    try validateLengths(key.len, nonce.len, ciphertext.len, tag.len);
    const allocation = try allocator.alloc(u8, ciphertext.len);
    errdefer secure_memory.wipeAndFree(allocator, allocation);
    try open(key, nonce, aad, ciphertext, allocation, tag);
    return .{ .allocator = allocator, .bytes = allocation };
}

fn validate(
    key: []const u8,
    nonce: []const u8,
    input_len: usize,
    output_len: usize,
    tag_len: usize,
) errors.Error!void {
    if (input_len != output_len) return error.WrongDataSize;
    try validateLengths(key.len, nonce.len, input_len, tag_len);
}

fn validateOutOfPlace(
    key: []const u8,
    nonce: []const u8,
    aad: []const u8,
    input: []const u8,
    output: []const u8,
    tag: []const u8,
) errors.Error!void {
    try buffers.requireDisjoint(input, output);
    try buffers.requireDisjoint(tag, input);
    try buffers.requireDisjointFromAll(output, .{ tag, key, nonce, aad });
    try buffers.requireDisjointFromAll(tag, .{ key, nonce, aad });
}

fn validateInPlace(
    key: []const u8,
    nonce: []const u8,
    aad: []const u8,
    buffer: []const u8,
    tag: []const u8,
) errors.Error!void {
    try buffers.requireDisjointFromAll(buffer, .{ tag, key, nonce, aad });
    try buffers.requireDisjointFromAll(tag, .{ key, nonce, aad });
}
