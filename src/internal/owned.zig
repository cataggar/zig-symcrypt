const std = @import("std");
const secure_memory = @import("secure_memory.zig");

pub const OwnedPlaintext = struct {
    allocator: std.mem.Allocator,
    bytes: []u8,

    pub fn deinit(self: *OwnedPlaintext) void {
        secure_memory.wipeAndFree(self.allocator, self.bytes);
    }
};

pub const OwnedCiphertext = struct {
    allocator: std.mem.Allocator,
    bytes: []u8,

    pub fn deinit(self: *OwnedCiphertext) void {
        secure_memory.wipeAndFree(self.allocator, self.bytes);
    }
};

pub const OwnedSealed = struct {
    allocator: std.mem.Allocator,
    bytes: []u8,
    ciphertext_len: usize,

    pub fn ciphertext(self: *const OwnedSealed) []const u8 {
        return self.bytes[0..self.ciphertext_len];
    }

    pub fn ciphertextMut(self: *OwnedSealed) []u8 {
        return self.bytes[0..self.ciphertext_len];
    }

    pub fn tag(self: *const OwnedSealed) []const u8 {
        return self.bytes[self.ciphertext_len..];
    }

    pub fn tagMut(self: *OwnedSealed) []u8 {
        return self.bytes[self.ciphertext_len..];
    }

    pub fn deinit(self: *OwnedSealed) void {
        secure_memory.wipeAndFree(self.allocator, self.bytes);
    }
};
