const std = @import("std");
const builtin = @import("builtin");
const options = @import("symcrypt_options");
const c = @import("../c.zig").raw;
const errors = @import("../errors.zig");
const initialization = @import("../init.zig");
const secure_memory = @import("../internal/secure_memory.zig");
const state_memory = @import("../internal/state.zig");
const asymmetric = @import("../asymmetric.zig");

pub const encoded_length = 32;
pub const secret_length = 32;

const Impl = struct {
    allocator: std.mem.Allocator,
    curve_object: c.PSYMCRYPT_ECURVE,
    key_object: c.PSYMCRYPT_ECKEY,
};

pub const PrivateKey = opaque {
    const Self = @This();

    pub fn generate(
        allocator: std.mem.Allocator,
    ) (std.mem.Allocator.Error || errors.Error)!*Self {
        return @ptrCast(try createPrivate(allocator, null));
    }

    pub fn import(
        allocator: std.mem.Allocator,
        scalar_le: []const u8,
    ) (std.mem.Allocator.Error || errors.Error)!*Self {
        if (scalar_le.len != encoded_length) return error.InvalidLength;
        return @ptrCast(try createPrivate(allocator, scalar_le));
    }

    /// Exports the canonical clamped little-endian scalar held by SymCrypt.
    pub fn exportPrivate(
        self: *const Self,
        allocator: std.mem.Allocator,
    ) (std.mem.Allocator.Error || errors.Error)!*asymmetric.SecretBytes {
        const secret = try asymmetric.SecretBytes.create(allocator, encoded_length);
        errdefer secret.deinit();
        try errors.check(c.SymCryptEckeyGetValue(
            privateImplConst(self).key_object,
            secret.mutable().ptr,
            secret.mutable().len,
            null,
            0,
            c.SYMCRYPT_NUMBER_FORMAT_LSB_FIRST,
            c.SYMCRYPT_ECPOINT_FORMAT_X,
            0,
        ));
        return secret;
    }

    pub fn exportPublic(self: *const Self, output: []u8) errors.Error!void {
        return exportPublicImpl(privateImplConst(self), output);
    }

    pub fn publicKey(
        self: *const Self,
        allocator: std.mem.Allocator,
    ) (std.mem.Allocator.Error || errors.Error)!*PublicKey {
        var encoded: [encoded_length]u8 = undefined;
        try exportPublicImpl(privateImplConst(self), &encoded);
        return PublicKey.import(allocator, &encoded);
    }

    pub fn agree(
        self: *const Self,
        allocator: std.mem.Allocator,
        peer: *const PublicKey,
    ) (std.mem.Allocator.Error || errors.Error)!*asymmetric.SecretBytes {
        const secret = try asymmetric.SecretBytes.create(allocator, secret_length);
        errdefer secret.deinit();
        try errors.check(c.SymCryptEcDhSecretAgreement(
            privateImplConst(self).key_object,
            publicImplConst(peer).key_object,
            c.SYMCRYPT_NUMBER_FORMAT_LSB_FIRST,
            0,
            secret.mutable().ptr,
            secret.mutable().len,
        ));
        var any_nonzero = false;
        for (secret.bytes()) |byte| any_nonzero = any_nonzero or byte != 0;
        if (!any_nonzero) return error.InvalidEncoding;
        return secret;
    }

    pub fn deinit(self: *Self) void {
        destroy(privateImpl(self));
    }
};

pub const PublicKey = opaque {
    const Self = @This();

    pub fn import(
        allocator: std.mem.Allocator,
        public_le: []const u8,
    ) (std.mem.Allocator.Error || errors.Error)!*Self {
        if (public_le.len != encoded_length) return error.InvalidLength;
        var normalized: [encoded_length]u8 = undefined;
        defer secure_memory.wipe(&normalized);
        normalizeUCoordinate(public_le, &normalized);
        return @ptrCast(try createPublic(allocator, &normalized));
    }

    pub fn exportPublic(self: *const Self, output: []u8) errors.Error!void {
        return exportPublicImpl(publicImplConst(self), output);
    }

    pub fn deinit(self: *Self) void {
        destroy(publicImpl(self));
    }
};

pub fn normalizeUCoordinate(input: []const u8, output: *[encoded_length]u8) void {
    std.debug.assert(input.len == encoded_length);
    @memcpy(output, input);
    output[31] &= 0x7f;

    const modulus = [_]u8{0xed} ++ ([_]u8{0xff} ** 30) ++ [_]u8{0x7f};
    var greater_or_equal = true;
    var index: usize = encoded_length;
    while (index > 0) {
        index -= 1;
        if (output[index] > modulus[index]) break;
        if (output[index] < modulus[index]) {
            greater_or_equal = false;
            break;
        }
    }
    if (!greater_or_equal) return;

    var borrow: u16 = 0;
    for (output, modulus) |*byte, p| {
        const lhs: u16 = byte.*;
        const rhs: u16 = @as(u16, p) + borrow;
        if (lhs >= rhs) {
            byte.* = @intCast(lhs - rhs);
            borrow = 0;
        } else {
            byte.* = @intCast(256 + lhs - rhs);
            borrow = 1;
        }
    }
}

fn createPrivate(
    allocator: std.mem.Allocator,
    scalar: ?[]const u8,
) (std.mem.Allocator.Error || errors.Error)!*Impl {
    const implementation = try allocate(allocator);
    errdefer destroy(implementation);
    if (scalar) |value| {
        try errors.check(c.SymCryptEckeySetValueIetfPrivateKey(
            value.ptr,
            value.len,
            c.SYMCRYPT_ECKEY_IETF_PRIVATE_KEY_FORMAT_C25519,
            c.SYMCRYPT_FLAG_ECKEY_ECDH,
            implementation.key_object,
        ));
    } else {
        try errors.check(c.SymCryptEckeySetRandom(
            c.SYMCRYPT_FLAG_ECKEY_ECDH,
            implementation.key_object,
        ));
    }
    return implementation;
}

fn createPublic(
    allocator: std.mem.Allocator,
    public: []const u8,
) (std.mem.Allocator.Error || errors.Error)!*Impl {
    const implementation = try allocate(allocator);
    errdefer destroy(implementation);
    try errors.check(c.SymCryptEckeySetValueIetfPublicKey(
        public.ptr,
        public.len,
        c.SYMCRYPT_ECKEY_IETF_PUBLIC_KEY_FORMAT_RAW_X_LE,
        c.SYMCRYPT_FLAG_ECKEY_ECDH,
        implementation.key_object,
    ));
    return implementation;
}

fn allocate(allocator: std.mem.Allocator) (std.mem.Allocator.Error || errors.Error)!*Impl {
    try initialization.ensureInitialized();
    const implementation = try state_memory.allocate(Impl, allocator);
    implementation.* = .{
        .allocator = allocator,
        .curve_object = null,
        .key_object = null,
    };
    errdefer state_memory.destroy(Impl, allocator, implementation);
    implementation.curve_object = c.SymCryptEcurveAllocate(curveParams(), 0);
    if (implementation.curve_object == null) return error.MemoryAllocationFailure;
    errdefer c.SymCryptEcurveFree(implementation.curve_object);
    implementation.key_object = c.SymCryptEckeyAllocate(implementation.curve_object);
    if (implementation.key_object == null) return error.MemoryAllocationFailure;
    return implementation;
}

fn exportPublicImpl(implementation: *const Impl, output: []u8) errors.Error!void {
    if (output.len != encoded_length) return error.InvalidLength;
    try errors.check(c.SymCryptEckeyGetValueIetfPublicKey(
        implementation.key_object,
        c.SYMCRYPT_ECKEY_IETF_PUBLIC_KEY_FORMAT_RAW_X_LE,
        output.ptr,
        output.len,
    ));
}

fn destroy(implementation: *Impl) void {
    const allocator = implementation.allocator;
    const key = implementation.key_object;
    const curve = implementation.curve_object;
    implementation.key_object = null;
    implementation.curve_object = null;
    if (key != null) c.SymCryptEckeyFree(key);
    if (curve != null) c.SymCryptEcurveFree(curve);
    state_memory.destroy(Impl, allocator, implementation);
}

fn privateImpl(self: *PrivateKey) *Impl {
    return @ptrCast(@alignCast(self));
}
fn privateImplConst(self: *const PrivateKey) *const Impl {
    return @ptrCast(@alignCast(self));
}
fn publicImpl(self: *PublicKey) *Impl {
    return @ptrCast(@alignCast(self));
}
fn publicImplConst(self: *const PublicKey) *const Impl {
    return @ptrCast(@alignCast(self));
}

extern fn SymCryptZigEcurveParamsCurve25519() c.PCSYMCRYPT_ECURVE_PARAMS;

fn curveParams() c.PCSYMCRYPT_ECURVE_PARAMS {
    if (builtin.target.os.tag == .windows and
        comptime std.mem.eql(u8, options.linkage, "dynamic"))
        return SymCryptZigEcurveParamsCurve25519();
    return c.SymCryptEcurveParamsCurve25519;
}

test "RFC 7748 u-coordinate normalization" {
    var input = [_]u8{0xff} ** 32;
    var output: [32]u8 = undefined;
    normalizeUCoordinate(&input, &output);
    try std.testing.expectEqual(@as(u8, 18), output[0]);
    try std.testing.expectEqual(@as(u8, 0), output[31]);
    input = [_]u8{0} ** 32;
    input[31] = 0x80;
    normalizeUCoordinate(&input, &output);
    try std.testing.expectEqualSlices(u8, &([_]u8{0} ** 32), &output);
}

test "RFC 7748 X25519 known answer" {
    var alice_private: [32]u8 = undefined;
    var alice_public_expected: [32]u8 = undefined;
    var bob_private: [32]u8 = undefined;
    var bob_public_expected: [32]u8 = undefined;
    var shared_expected: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&alice_private, "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    _ = try std.fmt.hexToBytes(&alice_public_expected, "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    _ = try std.fmt.hexToBytes(&bob_private, "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
    _ = try std.fmt.hexToBytes(&bob_public_expected, "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    _ = try std.fmt.hexToBytes(&shared_expected, "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

    const alice = try PrivateKey.import(std.testing.allocator, &alice_private);
    defer alice.deinit();
    const bob = try PrivateKey.import(std.testing.allocator, &bob_private);
    defer bob.deinit();
    var alice_public: [32]u8 = undefined;
    var bob_public: [32]u8 = undefined;
    try alice.exportPublic(&alice_public);
    try bob.exportPublic(&bob_public);
    try std.testing.expectEqualSlices(u8, &alice_public_expected, &alice_public);
    try std.testing.expectEqualSlices(u8, &bob_public_expected, &bob_public);
    const alice_peer = try PublicKey.import(std.testing.allocator, &bob_public);
    defer alice_peer.deinit();
    const bob_peer = try PublicKey.import(std.testing.allocator, &alice_public);
    defer bob_peer.deinit();
    const alice_secret = try alice.agree(std.testing.allocator, alice_peer);
    defer alice_secret.deinit();
    const bob_secret = try bob.agree(std.testing.allocator, bob_peer);
    defer bob_secret.deinit();
    try std.testing.expectEqualSlices(u8, &shared_expected, alice_secret.bytes());
    try std.testing.expectEqualSlices(u8, alice_secret.bytes(), bob_secret.bytes());
}

test "X25519 rejects low-order peers and allocation failure" {
    const zero = [_]u8{0} ** 32;
    const zero_peer = try PublicKey.import(std.testing.allocator, &zero);
    defer zero_peer.deinit();
    const private = try PrivateKey.generate(std.testing.allocator);
    defer private.deinit();
    if (private.agree(std.testing.allocator, zero_peer)) |secret| {
        secret.deinit();
        return error.TestExpectedError;
    } else |_| {}

    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    try std.testing.expectError(error.OutOfMemory, PrivateKey.generate(failing.allocator()));
}
