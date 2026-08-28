const std = @import("std");
const builtin = @import("builtin");
const options = @import("symcrypt_options");
const c = @import("../c.zig").raw;
const errors = @import("../errors.zig");
const initialization = @import("../init.zig");
const secure_memory = @import("../internal/secure_memory.zig");
const state_memory = @import("../internal/state.zig");
const asymmetric = @import("../asymmetric.zig");
const der = @import("ecdsa_der.zig");
const hashes = @import("hash_support.zig");

pub const Curve = enum {
    p256,
    p384,
    p521,

    pub fn scalarLength(self: Curve) usize {
        return switch (self) {
            .p256 => 32,
            .p384 => 48,
            .p521 => 66,
        };
    }

    pub fn publicLength(self: Curve) usize {
        return 1 + 2 * self.scalarLength();
    }

    pub fn rawSignatureLength(self: Curve) usize {
        return 2 * self.scalarLength();
    }

    pub fn maxDerSignatureLength(self: Curve) usize {
        return switch (self) {
            .p256 => 72,
            .p384 => 104,
            .p521 => 139,
        };
    }
};

pub const Usage = struct {
    sign: bool = false,
    key_agreement: bool = false,

    pub const signing: Usage = .{ .sign = true };
    pub const agreement: Usage = .{ .key_agreement = true };
    pub const signing_and_agreement: Usage = .{ .sign = true, .key_agreement = true };

    fn flags(self: Usage) errors.Error!u32 {
        if (!self.sign and !self.key_agreement) return error.InvalidUsage;
        return @as(u32, @intCast(if (self.sign) c.SYMCRYPT_FLAG_ECKEY_ECDSA else 0)) |
            @as(u32, @intCast(if (self.key_agreement) c.SYMCRYPT_FLAG_ECKEY_ECDH else 0));
    }
};

const Impl = struct {
    allocator: std.mem.Allocator,
    curve_object: c.PSYMCRYPT_ECURVE,
    key_object: c.PSYMCRYPT_ECKEY,
    curve: Curve,
    usage: Usage,
};

pub const PrivateKey = opaque {
    const Self = @This();

    pub fn generate(
        allocator: std.mem.Allocator,
        selected_curve: Curve,
        requested_usage: Usage,
    ) (std.mem.Allocator.Error || errors.Error)!*Self {
        return @ptrCast(try createKey(allocator, selected_curve, requested_usage, null, true));
    }

    pub fn import(
        allocator: std.mem.Allocator,
        selected_curve: Curve,
        scalar_be: []const u8,
        requested_usage: Usage,
    ) (std.mem.Allocator.Error || errors.Error)!*Self {
        if (scalar_be.len != selected_curve.scalarLength()) return error.InvalidLength;
        return @ptrCast(try createKey(allocator, selected_curve, requested_usage, scalar_be, true));
    }

    pub fn curve(self: *const Self) Curve {
        return implConst(self).curve;
    }

    pub fn usage(self: *const Self) Usage {
        return implConst(self).usage;
    }

    pub fn exportPrivate(
        self: *const Self,
        allocator: std.mem.Allocator,
    ) (std.mem.Allocator.Error || errors.Error)!*asymmetric.SecretBytes {
        const implementation = implConst(self);
        const secret = try asymmetric.SecretBytes.create(allocator, implementation.curve.scalarLength());
        errdefer secret.deinit();
        try errors.check(c.SymCryptEckeyGetValue(
            implementation.key_object,
            secret.mutable().ptr,
            secret.mutable().len,
            null,
            0,
            c.SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
            c.SYMCRYPT_ECPOINT_FORMAT_XY,
            0,
        ));
        return secret;
    }

    pub fn exportPublic(self: *const Self, output: []u8) errors.Error!void {
        return exportPublicImpl(implConst(self), output);
    }

    pub fn publicKey(
        self: *const Self,
        allocator: std.mem.Allocator,
    ) (std.mem.Allocator.Error || errors.Error)!*PublicKey {
        var encoded: [133]u8 = undefined;
        const implementation = implConst(self);
        const public = encoded[0..implementation.curve.publicLength()];
        try exportPublicImpl(implementation, public);
        return PublicKey.import(allocator, implementation.curve, public, implementation.usage);
    }

    pub fn agree(
        self: *const Self,
        allocator: std.mem.Allocator,
        peer: *const PublicKey,
    ) (std.mem.Allocator.Error || errors.Error)!*asymmetric.SecretBytes {
        const private = implConst(self);
        const public = publicImplConst(peer);
        if (!private.usage.key_agreement or !public.usage.key_agreement) return error.InvalidUsage;
        if (private.curve != public.curve) return error.KeyMismatch;
        const secret = try asymmetric.SecretBytes.create(allocator, private.curve.scalarLength());
        errdefer secret.deinit();
        try errors.check(c.SymCryptEcDhSecretAgreement(
            private.key_object,
            public.key_object,
            c.SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
            0,
            secret.mutable().ptr,
            secret.mutable().len,
        ));
        return secret;
    }

    pub fn sign(
        self: *const Self,
        algorithm: hashes.Algorithm,
        digest: []const u8,
        output_der: []u8,
    ) errors.Error!usize {
        const implementation = implConst(self);
        if (!implementation.usage.sign) return error.InvalidUsage;
        if (!hashes.allowedEcdsa(algorithm) or digest.len != hashes.digestLength(algorithm))
            return error.InvalidLength;
        var raw: [132]u8 = [_]u8{0} ** 132;
        defer secure_memory.wipe(&raw);
        const raw_signature = raw[0..implementation.curve.rawSignatureLength()];
        try errors.check(c.SymCryptEcDsaSign(
            implementation.key_object,
            requiredPtr(digest),
            digest.len,
            c.SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
            0,
            raw_signature.ptr,
            raw_signature.len,
        ));
        return der.encode(raw_signature, implementation.curve.scalarLength(), output_der) catch
            error.InvalidEncoding;
    }

    pub fn verify(
        self: *const Self,
        algorithm: hashes.Algorithm,
        digest: []const u8,
        signature_der: []const u8,
    ) errors.Error!void {
        return verifyImpl(implConst(self), algorithm, digest, signature_der);
    }

    pub fn deinit(self: *Self) void {
        destroy(impl(self));
    }

    fn impl(self: *Self) *Impl {
        return @ptrCast(@alignCast(self));
    }

    fn implConst(self: *const Self) *const Impl {
        return @ptrCast(@alignCast(self));
    }
};

pub const PublicKey = opaque {
    const Self = @This();

    pub fn import(
        allocator: std.mem.Allocator,
        selected_curve: Curve,
        sec1_uncompressed: []const u8,
        requested_usage: Usage,
    ) (std.mem.Allocator.Error || errors.Error)!*Self {
        if (sec1_uncompressed.len != selected_curve.publicLength() or sec1_uncompressed[0] != 0x04)
            return error.InvalidEncoding;
        return @ptrCast(try createKey(allocator, selected_curve, requested_usage, sec1_uncompressed, false));
    }

    pub fn curve(self: *const Self) Curve {
        return publicImplConst(self).curve;
    }

    pub fn usage(self: *const Self) Usage {
        return publicImplConst(self).usage;
    }

    pub fn exportPublic(self: *const Self, output: []u8) errors.Error!void {
        return exportPublicImpl(publicImplConst(self), output);
    }

    pub fn verify(
        self: *const Self,
        algorithm: hashes.Algorithm,
        digest: []const u8,
        signature_der: []const u8,
    ) errors.Error!void {
        return verifyImpl(publicImplConst(self), algorithm, digest, signature_der);
    }

    pub fn deinit(self: *Self) void {
        destroy(publicImpl(self));
    }
};

fn createKey(
    allocator: std.mem.Allocator,
    curve: Curve,
    usage: Usage,
    encoded: ?[]const u8,
    private: bool,
) (std.mem.Allocator.Error || errors.Error)!*Impl {
    const flags = try usage.flags();
    try initialization.ensureInitialized();
    const implementation = try state_memory.allocate(Impl, allocator);
    implementation.* = .{
        .allocator = allocator,
        .curve_object = null,
        .key_object = null,
        .curve = curve,
        .usage = usage,
    };
    errdefer state_memory.destroy(Impl, allocator, implementation);

    implementation.curve_object = c.SymCryptEcurveAllocate(curveParams(curve), 0);
    if (implementation.curve_object == null) return error.MemoryAllocationFailure;
    errdefer c.SymCryptEcurveFree(implementation.curve_object);
    implementation.key_object = c.SymCryptEckeyAllocate(implementation.curve_object);
    if (implementation.key_object == null) return error.MemoryAllocationFailure;
    errdefer c.SymCryptEckeyFree(implementation.key_object);

    if (encoded) |value| {
        if (private) {
            try errors.check(c.SymCryptEckeySetValueIetfPrivateKey(
                requiredPtr(value),
                value.len,
                c.SYMCRYPT_ECKEY_IETF_PRIVATE_KEY_FORMAT_NIST_SCALAR,
                flags,
                implementation.key_object,
            ));
        } else {
            try errors.check(c.SymCryptEckeySetValueIetfPublicKey(
                requiredPtr(value),
                value.len,
                c.SYMCRYPT_ECKEY_IETF_PUBLIC_KEY_FORMAT_SEC1_UNCOMPRESSED,
                flags,
                implementation.key_object,
            ));
        }
    } else {
        try errors.check(c.SymCryptEckeySetRandom(flags, implementation.key_object));
    }
    return implementation;
}

fn exportPublicImpl(implementation: *const Impl, output: []u8) errors.Error!void {
    if (output.len != implementation.curve.publicLength()) return error.InvalidLength;
    try errors.check(c.SymCryptEckeyGetValueIetfPublicKey(
        implementation.key_object,
        c.SYMCRYPT_ECKEY_IETF_PUBLIC_KEY_FORMAT_SEC1_UNCOMPRESSED,
        output.ptr,
        output.len,
    ));
}

fn verifyImpl(
    implementation: *const Impl,
    algorithm: hashes.Algorithm,
    digest: []const u8,
    signature_der: []const u8,
) errors.Error!void {
    if (!implementation.usage.sign) return error.InvalidUsage;
    if (!hashes.allowedEcdsa(algorithm) or digest.len != hashes.digestLength(algorithm))
        return error.InvalidLength;
    var raw: [132]u8 = [_]u8{0} ** 132;
    defer secure_memory.wipe(&raw);
    const signature = raw[0..implementation.curve.rawSignatureLength()];
    der.decode(signature_der, implementation.curve.scalarLength(), signature) catch
        return error.InvalidEncoding;
    errors.check(c.SymCryptEcDsaVerify(
        implementation.key_object,
        requiredPtr(digest),
        digest.len,
        signature.ptr,
        signature.len,
        c.SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        0,
    )) catch |err| switch (err) {
        error.SignatureVerificationFailure => return error.InvalidSignature,
        else => return err,
    };
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

fn publicImpl(self: *PublicKey) *Impl {
    return @ptrCast(@alignCast(self));
}

fn publicImplConst(self: *const PublicKey) *const Impl {
    return @ptrCast(@alignCast(self));
}

fn requiredPtr(bytes: []const u8) [*c]const u8 {
    return @ptrCast(bytes.ptr);
}

extern fn SymCryptZigEcurveParamsNistP256() c.PCSYMCRYPT_ECURVE_PARAMS;
extern fn SymCryptZigEcurveParamsNistP384() c.PCSYMCRYPT_ECURVE_PARAMS;
extern fn SymCryptZigEcurveParamsNistP521() c.PCSYMCRYPT_ECURVE_PARAMS;

fn curveParams(curve: Curve) c.PCSYMCRYPT_ECURVE_PARAMS {
    if (builtin.target.os.tag == .windows and
        comptime std.mem.eql(u8, options.linkage, "dynamic"))
    {
        return switch (curve) {
            .p256 => SymCryptZigEcurveParamsNistP256(),
            .p384 => SymCryptZigEcurveParamsNistP384(),
            .p521 => SymCryptZigEcurveParamsNistP521(),
        };
    }

    return switch (curve) {
        .p256 => c.SymCryptEcurveParamsNistP256,
        .p384 => c.SymCryptEcurveParamsNistP384,
        .p521 => c.SymCryptEcurveParamsNistP521,
    };
}

test "generated P-curve agreements, signatures, and round trips" {
    const hash = if (options.legacy) @import("../hash_legacy.zig") else @import("../hash.zig");
    const digest = try hash.digest(.sha256, "asymmetric test");
    inline for (.{ Curve.p256, Curve.p384, Curve.p521 }) |selected_curve| {
        const alice = try PrivateKey.generate(std.testing.allocator, selected_curve, .signing_and_agreement);
        defer alice.deinit();
        const bob = try PrivateKey.generate(std.testing.allocator, selected_curve, .agreement);
        defer bob.deinit();
        const alice_public = try alice.publicKey(std.testing.allocator);
        defer alice_public.deinit();
        const bob_public = try bob.publicKey(std.testing.allocator);
        defer bob_public.deinit();
        const alice_secret = try alice.agree(std.testing.allocator, bob_public);
        defer alice_secret.deinit();
        const bob_secret = try bob.agree(std.testing.allocator, alice_public);
        defer bob_secret.deinit();
        try std.testing.expectEqualSlices(u8, alice_secret.bytes(), bob_secret.bytes());

        const private_bytes = try alice.exportPrivate(std.testing.allocator);
        defer private_bytes.deinit();
        const imported = try PrivateKey.import(std.testing.allocator, selected_curve, private_bytes.bytes(), .signing_and_agreement);
        defer imported.deinit();
        var original_public: [133]u8 = undefined;
        var imported_public: [133]u8 = undefined;
        try alice.exportPublic(original_public[0..selected_curve.publicLength()]);
        try imported.exportPublic(imported_public[0..selected_curve.publicLength()]);
        try std.testing.expectEqualSlices(
            u8,
            original_public[0..selected_curve.publicLength()],
            imported_public[0..selected_curve.publicLength()],
        );

        var signature: [141]u8 = undefined;
        const signature_len = try alice.sign(.sha256, &digest, &signature);
        try alice_public.verify(.sha256, &digest, signature[0..signature_len]);
        signature[signature_len - 1] ^= 1;
        try std.testing.expectError(
            error.InvalidSignature,
            alice_public.verify(.sha256, &digest, signature[0..signature_len]),
        );
        try std.testing.expectError(
            error.InvalidUsage,
            bob.sign(.sha256, &digest, &signature),
        );
        if (selected_curve != .p256) {
            const wrong_curve_public = try tryWrongCurvePublic(selected_curve);
            defer wrong_curve_public.deinit();
            try std.testing.expectError(
                error.KeyMismatch,
                alice.agree(std.testing.allocator, wrong_curve_public),
            );
        }
    }
}

fn tryWrongCurvePublic(selected_curve: Curve) (std.mem.Allocator.Error || errors.Error)!*PublicKey {
    const other: Curve = if (selected_curve == .p384) .p256 else .p384;
    const key = try PrivateKey.generate(std.testing.allocator, other, .agreement);
    defer key.deinit();
    return key.publicKey(std.testing.allocator);
}

test "ECC wrapper allocation failures do not return partial owners" {
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    try std.testing.expectError(
        error.OutOfMemory,
        PrivateKey.generate(failing.allocator(), .p256, .signing),
    );
}

test "pinned NIST P-256 ECDH and ECDSA known answers" {
    const hash = if (options.legacy) @import("../hash_legacy.zig") else @import("../hash.zig");

    var private_scalar: [32]u8 = undefined;
    var peer_sec1: [65]u8 = undefined;
    var expected_secret: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&private_scalar, "7d7dc5f71eb29ddaf80d6214632eeae03d9058af1fb6d22ed80badb62bc1a534");
    peer_sec1[0] = 4;
    _ = try std.fmt.hexToBytes(peer_sec1[1..], "700c48f77f56584c5cc632ca65640db91b6bacce3a4df6b42ce7cc838833d287db71e509e3fd9b060ddb20ba5c51dcc5948d46fbf640dfe0441782cab85fa4ac");
    _ = try std.fmt.hexToBytes(&expected_secret, "46fc62106420ff012e54a434fbdd2d25ccc5852060561e68040dd7778997bd7b");
    const ecdh_private = try PrivateKey.import(std.testing.allocator, .p256, &private_scalar, .agreement);
    defer ecdh_private.deinit();
    const ecdh_peer = try PublicKey.import(std.testing.allocator, .p256, &peer_sec1, .agreement);
    defer ecdh_peer.deinit();
    const secret = try ecdh_private.agree(std.testing.allocator, ecdh_peer);
    defer secret.deinit();
    try std.testing.expectEqualSlices(u8, &expected_secret, secret.bytes());

    var message: [128]u8 = undefined;
    var public_sec1: [65]u8 = undefined;
    var raw_signature: [64]u8 = undefined;
    _ = try std.fmt.hexToBytes(&message, "5905238877c77421f73e43ee3da6f2d9e2ccad5fc942dcec0cbd25482935faaf416983fe165b1a045ee2bcd2e6dca3bdf46c4310a7461f9a37960ca672d3feb5473e253605fb1ddfd28065b53cb5858a8ad28175bf9bd386a5e471ea7a65c17cc934a9d791e91491eb3754d03799790fe2d308d16146d5c9b0d0debd97d79ce8");
    public_sec1[0] = 4;
    _ = try std.fmt.hexToBytes(public_sec1[1..], "1ccbe91c075fc7f4f033bfa248db8fccd3565de94bbfb12f3c59ff46c271bf83ce4014c68811f9a21a1fdb2c0e6113e06db7ca93b7404e78dc7ccd5ca89a4ca9");
    _ = try std.fmt.hexToBytes(&raw_signature, "f3ac8061b514795b8843e3d6629527ed2afd6b1f6a555a7acabb5e6f79c8c2ac8bf77819ca05a6b2786c76262bf7371cef97b218e96f175a3ccdda2acc058903");
    const digest = try hash.digest(.sha256, &message);
    var signature_der: [72]u8 = undefined;
    const signature_len = try der.encode(&raw_signature, 32, &signature_der);
    const verifying_key = try PublicKey.import(std.testing.allocator, .p256, &public_sec1, .signing);
    defer verifying_key.deinit();
    try verifying_key.verify(.sha256, &digest, signature_der[0..signature_len]);
}

const ConcurrentVerifyWork = struct {
    key: *const PublicKey,
    digest: [32]u8,
    signature: [72]u8,
    signature_len: usize,
};

fn concurrentVerify(work: *const ConcurrentVerifyWork) void {
    for (0..50) |_| {
        work.key.verify(.sha256, &work.digest, work.signature[0..work.signature_len]) catch
            @panic("concurrent ECDSA verification failed");
    }
}

test "const asymmetric operations are concurrent" {
    const hash = if (options.legacy) @import("../hash_legacy.zig") else @import("../hash.zig");
    const private = try PrivateKey.generate(std.testing.allocator, .p256, .signing);
    defer private.deinit();
    const public = try private.publicKey(std.testing.allocator);
    defer public.deinit();
    var work = ConcurrentVerifyWork{
        .key = public,
        .digest = try hash.digest(.sha256, "concurrent"),
        .signature = undefined,
        .signature_len = 0,
    };
    work.signature_len = try private.sign(.sha256, &work.digest, &work.signature);
    var threads: [4]std.Thread = undefined;
    for (&threads) |*thread| thread.* = try std.Thread.spawn(.{}, concurrentVerify, .{&work});
    for (&threads) |*thread| thread.join();
}
