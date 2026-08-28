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

const TestFailureStage = enum { none, after_curve, after_key };
var test_failure_stage: TestFailureStage = .none;

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
    if (builtin.is_test and test_failure_stage == .after_curve) {
        test_failure_stage = .none;
        return error.MemoryAllocationFailure;
    }
    implementation.key_object = c.SymCryptEckeyAllocate(implementation.curve_object);
    if (implementation.key_object == null) return error.MemoryAllocationFailure;
    errdefer c.SymCryptEckeyFree(implementation.key_object);
    if (builtin.is_test and test_failure_stage == .after_key) {
        test_failure_stage = .none;
        return error.MemoryAllocationFailure;
    }

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
    inline for (.{ Curve.p256, Curve.p384, Curve.p521 }) |selected_curve| {
        const algorithm = switch (selected_curve) {
            .p256 => .sha256,
            .p384 => .sha384,
            .p521 => .sha512,
        };
        const digest = try hash.digest(algorithm, "asymmetric test");
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
        const signature_len = try alice.sign(algorithm, &digest, &signature);
        try alice_public.verify(algorithm, &digest, signature[0..signature_len]);
        const wrong_key = try PrivateKey.generate(std.testing.allocator, selected_curve, .signing);
        defer wrong_key.deinit();
        const wrong_public = try wrong_key.publicKey(std.testing.allocator);
        defer wrong_public.deinit();
        try std.testing.expectError(
            error.InvalidSignature,
            wrong_public.verify(algorithm, &digest, signature[0..signature_len]),
        );
        signature[signature_len - 1] ^= 1;
        try std.testing.expectError(
            error.InvalidSignature,
            alice_public.verify(algorithm, &digest, signature[0..signature_len]),
        );
        try std.testing.expectError(
            error.InvalidUsage,
            bob.sign(algorithm, &digest, &signature),
        );
        inline for (.{
            hashes.Algorithm.sha256,
            hashes.Algorithm.sha384,
            hashes.Algorithm.sha512,
            hashes.Algorithm.sha3_256,
            hashes.Algorithm.sha3_384,
            hashes.Algorithm.sha3_512,
        }) |matrix_algorithm| {
            const matrix_digest = try hash.digest(matrix_algorithm, "ECDSA algorithm matrix");
            const matrix_signature_len = try alice.sign(matrix_algorithm, &matrix_digest, &signature);
            try alice_public.verify(
                matrix_algorithm,
                &matrix_digest,
                signature[0..matrix_signature_len],
            );
        }
        if (comptime options.legacy) {
            const legacy_digest = try hash.digest(.sha1, "ECDSA legacy matrix");
            const legacy_signature_len = try alice.sign(.sha1, &legacy_digest, &signature);
            try alice_public.verify(.sha1, &legacy_digest, signature[0..legacy_signature_len]);
        }
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

    inline for (.{ TestFailureStage.after_curve, TestFailureStage.after_key }) |stage| {
        var checking = asymmetric.testing.WipeAllocator{ .backing = std.testing.allocator };
        test_failure_stage = stage;
        try std.testing.expectError(
            error.MemoryAllocationFailure,
            PrivateKey.generate(checking.allocator(), .p256, .signing),
        );
        try std.testing.expectEqual(@as(usize, 1), checking.frees);
        try std.testing.expectEqual(@as(usize, 0), checking.nonzero_frees);
    }
}

test "invalid SEC1 points are rejected for every advertised curve" {
    inline for (.{ Curve.p256, Curve.p384, Curve.p521 }) |selected_curve| {
        var invalid: [selected_curve.publicLength()]u8 = [_]u8{0} ** selected_curve.publicLength();
        invalid[0] = 4;
        if (PublicKey.import(std.testing.allocator, selected_curve, &invalid, .agreement)) |key| {
            key.deinit();
            return error.TestExpectedError;
        } else |_| {}
    }
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

fn runNistKat(
    comptime selected_curve: Curve,
    comptime algorithm: hashes.Algorithm,
    comptime private_hex: []const u8,
    comptime peer_x_hex: []const u8,
    comptime peer_y_hex: []const u8,
    comptime secret_hex: []const u8,
    comptime message_hex: []const u8,
    comptime public_x_hex: []const u8,
    comptime public_y_hex: []const u8,
    comptime r_hex: []const u8,
    comptime s_hex: []const u8,
) !void {
    const hash = if (options.legacy) @import("../hash_legacy.zig") else @import("../hash.zig");
    const scalar_len = comptime selected_curve.scalarLength();
    var private_scalar: [scalar_len]u8 = undefined;
    var peer_sec1: [1 + 2 * scalar_len]u8 = undefined;
    var expected_secret: [scalar_len]u8 = undefined;
    _ = try std.fmt.hexToBytes(&private_scalar, private_hex);
    peer_sec1[0] = 4;
    _ = try std.fmt.hexToBytes(peer_sec1[1 .. 1 + scalar_len], peer_x_hex);
    _ = try std.fmt.hexToBytes(peer_sec1[1 + scalar_len ..], peer_y_hex);
    _ = try std.fmt.hexToBytes(&expected_secret, secret_hex);
    const private = try PrivateKey.import(std.testing.allocator, selected_curve, &private_scalar, .agreement);
    defer private.deinit();
    const peer = try PublicKey.import(std.testing.allocator, selected_curve, &peer_sec1, .agreement);
    defer peer.deinit();
    const secret = try private.agree(std.testing.allocator, peer);
    defer secret.deinit();
    try std.testing.expectEqualSlices(u8, &expected_secret, secret.bytes());

    var message: [128]u8 = undefined;
    var public_sec1: [1 + 2 * scalar_len]u8 = undefined;
    var raw_signature: [2 * scalar_len]u8 = undefined;
    _ = try std.fmt.hexToBytes(&message, message_hex);
    public_sec1[0] = 4;
    _ = try std.fmt.hexToBytes(public_sec1[1 .. 1 + scalar_len], public_x_hex);
    _ = try std.fmt.hexToBytes(public_sec1[1 + scalar_len ..], public_y_hex);
    _ = try std.fmt.hexToBytes(raw_signature[0..scalar_len], r_hex);
    _ = try std.fmt.hexToBytes(raw_signature[scalar_len..], s_hex);
    const digest = try hash.digest(algorithm, &message);
    var signature_der: [141]u8 = undefined;
    const signature_len = try der.encode(&raw_signature, scalar_len, &signature_der);
    const public = try PublicKey.import(std.testing.allocator, selected_curve, &public_sec1, .signing);
    defer public.deinit();
    try public.verify(algorithm, &digest, signature_der[0..signature_len]);
}

test "pinned NIST P-384 and P-521 ECDH and ECDSA known answers" {
    try runNistKat(
        .p384,
        .sha384,
        "3cc3122a68f0d95027ad38c067916ba0eb8c38894d22e1b15618b6818a661774ad463b205da88cf699ab4d43c9cf98a1",
        "a7c76b970c3b5fe8b05d2838ae04ab47697b9eaf52e764592efda27fe7513272734466b400091adbf2d68c58e0c50066",
        "ac68f19f2e1cb879aed43a9969b91a0839c4c38a49749b661efedf243451915ed0905a32b060992b468c64766fc8437a",
        "5f9d29dc5e31a163060356213669c8ce132e22f57c9a04f40ba7fcead493b457e5621e766c40a2e3d4d6a04b25e533f1",
        "6b45d88037392e1371d9fd1cd174e9c1838d11c3d6133dc17e65fa0c485dcca9f52d41b60161246039e42ec784d49400bffdb51459f5de654091301a09378f93464d52118b48d44b30d781eb1dbed09da11fb4c818dbd442d161aba4b9edc79f05e4b7e401651395b53bd8b5bd3f2aaa6a00877fa9b45cadb8e648550b4c6cbe",
        "c2b47944fb5de342d03285880177ca5f7d0f2fcad7678cce4229d6e1932fcac11bfc3c3e97d942a3c56bf34123013dbf",
        "37257906a8223866eda0743c519616a76a758ae58aee81c5fd35fbf3a855b7754a36d4a0672df95d6c44a81cf7620c2d",
        "50835a9251bad008106177ef004b091a1e4235cd0da84fff54542b0ed755c1d6f251609d14ecf18f9e1ddfe69b946e32",
        "0475f3d30c6463b646e8d3bf2455830314611cbde404be518b14464fdb195fdcc92eb222e61f426a4a592c00a6a89721",
    );
    try runNistKat(
        .p521,
        .sha512,
        "017eecc07ab4b329068fba65e56a1f8890aa935e57134ae0ffcce802735151f4eac6564f6ee9974c5e6887a1fefee5743ae2241bfeb95d5ce31ddcb6f9edb4d6fc47",
        "00685a48e86c79f0f0875f7bc18d25eb5fc8c0b07e5da4f4370f3a9490340854334b1e1b87fa395464c60626124a4e70d0f785601d37c09870ebf176666877a2046d",
        "01ba52c56fc8776d9e8f5db4f0cc27636d0b741bbe05400697942e80b739884a83bde99e0f6716939e632bc8986fa18dccd443a348b6c3e522497955a4f3c302f676",
        "005fc70477c3e63bc3954bd0df3ea0d1f41ee21746ed95fc5e1fdf90930d5e136672d72cc770742d1711c3c3a4c334a0ad9759436a4d3c5bf6e74b9578fac148c831",
        "9ecd500c60e701404922e58ab20cc002651fdee7cbc9336adda33e4c1088fab1964ecb7904dc6856865d6c8e15041ccf2d5ac302e99d346ff2f686531d25521678d4fd3f76bbf2c893d246cb4d7693792fe18172108146853103a51f824acc621cb7311d2463c3361ea707254f2b052bc22cb8012873dcbb95bf1a5cc53ab89f",
        "0061387fd6b95914e885f912edfbb5fb274655027f216c4091ca83e19336740fd81aedfe047f51b42bdf68161121013e0d55b117a14e4303f926c8debb77a7fdaad1",
        "00e7d0c75c38626e895ca21526b9f9fdf84dcecb93f2b233390550d2b1463b7ee3f58df7346435ff0434199583c97c665a97f12f706f2357da4b40288def888e59e6",
        "004de826ea704ad10bc0f7538af8a3843f284f55c8b946af9235af5af74f2b76e099e4bc72fd79d28a380f8d4b4c919ac290d248c37983ba05aea42e2dd79fdd33e8",
        "0087488c859a96fea266ea13bf6d114c429b163be97a57559086edb64aed4a18594b46fb9efc7fd25d8b2de8f09ca0587f54bd287299f47b2ff124aac566e8ee3b43",
    );
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
