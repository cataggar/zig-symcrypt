const std = @import("std");
const builtin = @import("builtin");
const options = @import("symcrypt_options");
const c = @import("../c.zig").raw;
const errors = @import("../errors.zig");
const initialization = @import("../init.zig");
const secure_memory = @import("../internal/secure_memory.zig");
const state_memory = @import("../internal/state.zig");
const asymmetric = @import("../asymmetric.zig");
const hashes = @import("hash_support.zig");

pub const Usage = struct {
    sign: bool = false,
    encrypt: bool = false,

    pub const signing: Usage = .{ .sign = true };
    pub const encryption: Usage = .{ .encrypt = true };
    pub const signing_and_encryption: Usage = .{ .sign = true, .encrypt = true };

    fn flags(self: Usage) errors.Error!u32 {
        if (!self.sign and !self.encrypt) return error.InvalidUsage;
        return @as(u32, @intCast(if (self.sign) c.SYMCRYPT_FLAG_RSAKEY_SIGN else 0)) |
            @as(u32, @intCast(if (self.encrypt) c.SYMCRYPT_FLAG_RSAKEY_ENCRYPT else 0));
    }
};

fn validatePssOaepAlgorithm(algorithm: hashes.Algorithm) errors.Error!usize {
    const name = @tagName(algorithm);
    const length = hashes.digestLength(algorithm);
    if (length == 0 or std.mem.eql(u8, name, "md5") or std.mem.eql(u8, name, "sha3_224"))
        return error.InvalidLength;
    return length;
}

pub const PublicComponents = struct {
    allocator: std.mem.Allocator,
    modulus_be: []u8,
    public_exponent: u64,

    pub fn deinit(self: *PublicComponents) void {
        self.allocator.free(self.modulus_be);
        self.* = undefined;
    }
};

pub const PrivatePrimeComponents = struct {
    modulus_be: []const u8,
    public_exponent: u64,
    p_be: []const u8,
    q_be: []const u8,
};

pub const PrivateExponentComponents = struct {
    modulus_be: []const u8,
    public_exponent: u64,
    d_be: []const u8,
};

pub const PrivateComponents = struct {
    modulus_be: *asymmetric.SecretBytes,
    public_exponent: u64,
    p_be: *asymmetric.SecretBytes,
    q_be: *asymmetric.SecretBytes,
    d_p_be: *asymmetric.SecretBytes,
    d_q_be: *asymmetric.SecretBytes,
    q_inv_be: *asymmetric.SecretBytes,
    d_be: *asymmetric.SecretBytes,

    pub fn deinit(self: *PrivateComponents) void {
        self.d_be.deinit();
        self.q_inv_be.deinit();
        self.d_q_be.deinit();
        self.d_p_be.deinit();
        self.q_be.deinit();
        self.p_be.deinit();
        self.modulus_be.deinit();
        self.* = undefined;
    }
};

pub const PssSalt = union(enum) {
    exact: usize,
    digest_length,
    minimum: usize,
};

const Impl = struct {
    allocator: std.mem.Allocator,
    key_object: c.PSYMCRYPT_RSAKEY,
    usage: Usage,
    has_private: bool,
};

var test_fail_after_key_allocation = false;

pub const PrivateKey = opaque {
    const Self = @This();

    pub fn generate(
        allocator: std.mem.Allocator,
        modulus_bits: u32,
        public_exponent: ?u64,
        requested_usage: Usage,
    ) (std.mem.Allocator.Error || errors.Error)!*Self {
        if (modulus_bits < 2048 or modulus_bits > 16384 or modulus_bits % 8 != 0)
            return error.InvalidLength;
        if (public_exponent) |exponent| try validateExponent(exponent);
        const implementation = try allocateKey(allocator, modulus_bits, true, requested_usage);
        errdefer destroy(implementation);
        var exponent_storage = public_exponent orelse 0;
        try errors.check(c.SymCryptRsakeyGenerate(
            implementation.key_object,
            if (public_exponent != null) &exponent_storage else null,
            if (public_exponent != null) 1 else 0,
            try requested_usage.flags(),
        ));
        return @ptrCast(implementation);
    }

    pub fn importPrimes(
        allocator: std.mem.Allocator,
        components: PrivatePrimeComponents,
        requested_usage: Usage,
    ) (std.mem.Allocator.Error || errors.Error)!*Self {
        const bits = try validateModulus(components.modulus_be);
        try validateExponent(components.public_exponent);
        try validateUnsigned(components.p_be);
        try validateUnsigned(components.q_be);
        const implementation = try allocateKey(allocator, bits, true, requested_usage);
        errdefer destroy(implementation);
        var exponent = components.public_exponent;
        var primes = [_][*c]const u8{ components.p_be.ptr, components.q_be.ptr };
        var sizes = [_]usize{ components.p_be.len, components.q_be.len };
        try errors.check(c.SymCryptRsakeySetValue(
            components.modulus_be.ptr,
            components.modulus_be.len,
            &exponent,
            1,
            @ptrCast(&primes),
            &sizes,
            2,
            c.SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
            try requested_usage.flags(),
            implementation.key_object,
        ));
        return @ptrCast(implementation);
    }

    pub fn importPrivateExponent(
        allocator: std.mem.Allocator,
        components: PrivateExponentComponents,
        requested_usage: Usage,
    ) (std.mem.Allocator.Error || errors.Error)!*Self {
        const bits = try validateModulus(components.modulus_be);
        try validateExponent(components.public_exponent);
        try validateUnsigned(components.d_be);
        const implementation = try allocateKey(allocator, bits, true, requested_usage);
        errdefer destroy(implementation);
        try errors.check(c.SymCryptRsakeySetValueFromPrivateExponent(
            components.modulus_be.ptr,
            components.modulus_be.len,
            components.public_exponent,
            components.d_be.ptr,
            components.d_be.len,
            c.SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
            try requested_usage.flags(),
            implementation.key_object,
        ));
        return @ptrCast(implementation);
    }

    pub fn usage(self: *const Self) Usage {
        return privateImplConst(self).usage;
    }

    pub fn modulusLength(self: *const Self) usize {
        return c.SymCryptRsakeySizeofModulus(privateImplConst(self).key_object);
    }

    pub fn exportPublic(
        self: *const Self,
        allocator: std.mem.Allocator,
    ) (std.mem.Allocator.Error || errors.Error)!PublicComponents {
        return exportPublicImpl(privateImplConst(self), allocator);
    }

    pub fn exportPrivate(
        self: *const Self,
        allocator: std.mem.Allocator,
    ) (std.mem.Allocator.Error || errors.Error)!PrivateComponents {
        return exportPrivateImpl(privateImplConst(self), allocator);
    }

    pub fn publicKey(
        self: *const Self,
        allocator: std.mem.Allocator,
    ) (std.mem.Allocator.Error || errors.Error)!*PublicKey {
        var components = try exportPublicImpl(privateImplConst(self), allocator);
        defer components.deinit();
        return PublicKey.import(allocator, components.modulus_be, components.public_exponent, privateImplConst(self).usage);
    }

    pub fn signPkcs1v15(
        self: *const Self,
        algorithm: hashes.Algorithm,
        digest: []const u8,
        signature: []u8,
    ) errors.Error!void {
        errdefer secure_memory.wipeIndependent(signature);
        return signPkcs1(privateImplConst(self), algorithm, digest, signature);
    }

    pub fn verifyPkcs1v15(
        self: *const Self,
        algorithm: hashes.Algorithm,
        digest: []const u8,
        signature: []const u8,
    ) errors.Error!void {
        return verifyPkcs1(privateImplConst(self), algorithm, digest, signature);
    }

    pub fn signPss(
        self: *const Self,
        algorithm: hashes.Algorithm,
        digest: []const u8,
        salt_length: usize,
        signature: []u8,
    ) errors.Error!void {
        errdefer secure_memory.wipeIndependent(signature);
        return signPssImpl(privateImplConst(self), algorithm, digest, salt_length, signature);
    }

    pub fn verifyPss(
        self: *const Self,
        algorithm: hashes.Algorithm,
        digest: []const u8,
        salt: PssSalt,
        signature: []const u8,
    ) errors.Error!void {
        return verifyPssImpl(privateImplConst(self), algorithm, digest, salt, signature);
    }

    pub fn encryptOaep(
        self: *const Self,
        algorithm: hashes.Algorithm,
        message: []const u8,
        label: []const u8,
        ciphertext: []u8,
    ) errors.Error!void {
        errdefer secure_memory.wipeIndependent(ciphertext);
        return encryptOaepImpl(privateImplConst(self), algorithm, message, label, ciphertext);
    }

    pub fn decryptOaep(
        self: *const Self,
        algorithm: hashes.Algorithm,
        ciphertext: []const u8,
        label: []const u8,
        output: []u8,
    ) errors.Error!usize {
        return decryptOaepImpl(privateImplConst(self), algorithm, ciphertext, label, output);
    }

    pub fn deinit(self: *Self) void {
        destroy(privateImpl(self));
    }
};

pub const PublicKey = opaque {
    const Self = @This();

    pub fn import(
        allocator: std.mem.Allocator,
        modulus_be: []const u8,
        public_exponent: u64,
        requested_usage: Usage,
    ) (std.mem.Allocator.Error || errors.Error)!*Self {
        const bits = try validateModulus(modulus_be);
        try validateExponent(public_exponent);
        const implementation = try allocateKey(allocator, bits, false, requested_usage);
        errdefer destroy(implementation);
        var exponent = public_exponent;
        try errors.check(c.SymCryptRsakeySetValue(
            modulus_be.ptr,
            modulus_be.len,
            &exponent,
            1,
            null,
            null,
            0,
            c.SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
            try requested_usage.flags(),
            implementation.key_object,
        ));
        return @ptrCast(implementation);
    }

    pub fn usage(self: *const Self) Usage {
        return publicImplConst(self).usage;
    }

    pub fn modulusLength(self: *const Self) usize {
        return c.SymCryptRsakeySizeofModulus(publicImplConst(self).key_object);
    }

    pub fn exportPublic(
        self: *const Self,
        allocator: std.mem.Allocator,
    ) (std.mem.Allocator.Error || errors.Error)!PublicComponents {
        return exportPublicImpl(publicImplConst(self), allocator);
    }

    pub fn verifyPkcs1v15(
        self: *const Self,
        algorithm: hashes.Algorithm,
        digest: []const u8,
        signature: []const u8,
    ) errors.Error!void {
        return verifyPkcs1(publicImplConst(self), algorithm, digest, signature);
    }

    pub fn verifyPss(
        self: *const Self,
        algorithm: hashes.Algorithm,
        digest: []const u8,
        salt: PssSalt,
        signature: []const u8,
    ) errors.Error!void {
        return verifyPssImpl(publicImplConst(self), algorithm, digest, salt, signature);
    }

    pub fn encryptOaep(
        self: *const Self,
        algorithm: hashes.Algorithm,
        message: []const u8,
        label: []const u8,
        ciphertext: []u8,
    ) errors.Error!void {
        errdefer secure_memory.wipeIndependent(ciphertext);
        return encryptOaepImpl(publicImplConst(self), algorithm, message, label, ciphertext);
    }

    pub fn deinit(self: *Self) void {
        destroy(publicImpl(self));
    }
};

fn allocateKey(
    allocator: std.mem.Allocator,
    bits: u32,
    private: bool,
    usage: Usage,
) (std.mem.Allocator.Error || errors.Error)!*Impl {
    _ = try usage.flags();
    try initialization.ensureInitialized();
    const implementation = try state_memory.allocate(Impl, allocator);
    implementation.* = .{
        .allocator = allocator,
        .key_object = null,
        .usage = usage,
        .has_private = private,
    };
    errdefer state_memory.destroy(Impl, allocator, implementation);
    var params = c.SYMCRYPT_RSA_PARAMS{
        .version = 1,
        .nBitsOfModulus = bits,
        .nPrimes = if (private) 2 else 0,
        .nPubExp = 1,
    };
    implementation.key_object = c.SymCryptRsakeyAllocate(&params, 0);
    if (implementation.key_object == null) return error.MemoryAllocationFailure;
    if (builtin.is_test and test_fail_after_key_allocation) {
        test_fail_after_key_allocation = false;
        c.SymCryptRsakeyFree(implementation.key_object);
        implementation.key_object = null;
        return error.MemoryAllocationFailure;
    }
    return implementation;
}

fn validateUnsigned(value: []const u8) errors.Error!void {
    if (value.len == 0 or value[0] == 0) return error.InvalidEncoding;
}

fn validateModulus(modulus: []const u8) errors.Error!u32 {
    try validateUnsigned(modulus);
    if (modulus[modulus.len - 1] & 1 == 0) return error.InvalidEncoding;
    if (modulus.len > 2048) return error.InvalidLength;
    const leading = @clz(modulus[0]);
    const bits_usize = std.math.mul(usize, modulus.len - 1, 8) catch return error.InvalidLength;
    const bits = std.math.add(usize, bits_usize, 8 - leading) catch return error.InvalidLength;
    if (bits < 2048 or bits > 16384) return error.InvalidLength;
    return @intCast(bits);
}

fn validateExponent(exponent: u64) errors.Error!void {
    if (exponent < 3 or exponent & 1 == 0) return error.InvalidEncoding;
}

fn exportPublicImpl(
    implementation: *const Impl,
    allocator: std.mem.Allocator,
) (std.mem.Allocator.Error || errors.Error)!PublicComponents {
    const modulus = try allocator.alloc(u8, c.SymCryptRsakeySizeofModulus(implementation.key_object));
    errdefer allocator.free(modulus);
    var exponent: u64 = 0;
    try errors.check(c.SymCryptRsakeyGetValue(
        implementation.key_object,
        modulus.ptr,
        modulus.len,
        &exponent,
        1,
        null,
        null,
        0,
        c.SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        0,
    ));
    return .{ .allocator = allocator, .modulus_be = modulus, .public_exponent = exponent };
}

fn exportPrivateImpl(
    implementation: *const Impl,
    allocator: std.mem.Allocator,
) (std.mem.Allocator.Error || errors.Error)!PrivateComponents {
    if (!implementation.has_private) return error.InvalidUsage;
    const modulus_len = c.SymCryptRsakeySizeofModulus(implementation.key_object);
    const p_len = c.SymCryptRsakeySizeofPrime(implementation.key_object, 0);
    const q_len = c.SymCryptRsakeySizeofPrime(implementation.key_object, 1);
    var result = PrivateComponents{
        .modulus_be = try asymmetric.SecretBytes.create(allocator, modulus_len),
        .public_exponent = 0,
        .p_be = undefined,
        .q_be = undefined,
        .d_p_be = undefined,
        .d_q_be = undefined,
        .q_inv_be = undefined,
        .d_be = undefined,
    };
    errdefer result.modulus_be.deinit();
    result.p_be = try asymmetric.SecretBytes.create(allocator, p_len);
    errdefer result.p_be.deinit();
    result.q_be = try asymmetric.SecretBytes.create(allocator, q_len);
    errdefer result.q_be.deinit();
    result.d_p_be = try asymmetric.SecretBytes.create(allocator, p_len);
    errdefer result.d_p_be.deinit();
    result.d_q_be = try asymmetric.SecretBytes.create(allocator, q_len);
    errdefer result.d_q_be.deinit();
    result.q_inv_be = try asymmetric.SecretBytes.create(allocator, p_len);
    errdefer result.q_inv_be.deinit();
    result.d_be = try asymmetric.SecretBytes.create(allocator, modulus_len);
    errdefer result.d_be.deinit();

    var primes = [_][*c]u8{ result.p_be.mutable().ptr, result.q_be.mutable().ptr };
    var prime_sizes = [_]usize{ p_len, q_len };
    try errors.check(c.SymCryptRsakeyGetValue(
        implementation.key_object,
        result.modulus_be.mutable().ptr,
        modulus_len,
        &result.public_exponent,
        1,
        @ptrCast(&primes),
        &prime_sizes,
        2,
        c.SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        0,
    ));
    var crt = [_][*c]u8{ result.d_p_be.mutable().ptr, result.d_q_be.mutable().ptr };
    var crt_sizes = [_]usize{ p_len, q_len };
    try errors.check(c.SymCryptRsakeyGetCrtValue(
        implementation.key_object,
        @ptrCast(&crt),
        &crt_sizes,
        2,
        result.q_inv_be.mutable().ptr,
        p_len,
        result.d_be.mutable().ptr,
        modulus_len,
        c.SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        0,
    ));
    try tightenSecret(allocator, &result.p_be);
    try tightenSecret(allocator, &result.q_be);
    try tightenSecret(allocator, &result.d_p_be);
    try tightenSecret(allocator, &result.d_q_be);
    try tightenSecret(allocator, &result.q_inv_be);
    try tightenSecret(allocator, &result.d_be);
    return result;
}

fn tightenSecret(
    allocator: std.mem.Allocator,
    secret_ptr: **asymmetric.SecretBytes,
) std.mem.Allocator.Error!void {
    const bytes = secret_ptr.*.bytes();
    var first: usize = 0;
    while (first + 1 < bytes.len and bytes[first] == 0) : (first += 1) {}
    if (first == 0) return;
    const replacement = try asymmetric.SecretBytes.create(allocator, bytes.len - first);
    @memcpy(replacement.mutable(), bytes[first..]);
    secret_ptr.*.deinit();
    secret_ptr.* = replacement;
}

fn validateDigest(algorithm: hashes.Algorithm, digest: []const u8) errors.Error!void {
    if (!hashes.allowedRsa(algorithm) or digest.len != hashes.digestLength(algorithm))
        return error.InvalidLength;
}

fn signPkcs1(
    implementation: *const Impl,
    algorithm: hashes.Algorithm,
    digest: []const u8,
    signature: []u8,
) errors.Error!void {
    if (!implementation.has_private or !implementation.usage.sign) return error.InvalidUsage;
    try validateDigest(algorithm, digest);
    const k = c.SymCryptRsakeySizeofModulus(implementation.key_object);
    if (signature.len != k) return error.InvalidLength;
    var digest_info: [83]u8 = undefined;
    const info = try buildDigestInfo(algorithm, digest, true, &digest_info);
    var written: usize = 0;
    try errors.check(c.SymCryptRsaPkcs1Sign(
        implementation.key_object,
        info.ptr,
        info.len,
        null,
        0,
        c.SYMCRYPT_FLAG_RSA_PKCS1_NO_ASN1,
        c.SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        signature.ptr,
        signature.len,
        &written,
    ));
    if (written != signature.len) {
        secure_memory.wipeIndependent(signature);
        return error.InvalidLength;
    }
}

fn verifyPkcs1(
    implementation: *const Impl,
    algorithm: hashes.Algorithm,
    digest: []const u8,
    signature: []const u8,
) errors.Error!void {
    if (!implementation.usage.sign) return error.InvalidUsage;
    try validateDigest(algorithm, digest);
    if (signature.len != c.SymCryptRsakeySizeofModulus(implementation.key_object))
        return error.InvalidLength;
    var storage: [83]u8 = undefined;
    for ([_]bool{ true, false }) |with_null| {
        const info = try buildDigestInfo(algorithm, digest, with_null, &storage);
        errors.check(c.SymCryptRsaPkcs1Verify(
            implementation.key_object,
            info.ptr,
            info.len,
            signature.ptr,
            signature.len,
            c.SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
            null,
            0,
            0,
        )) catch |err| switch (err) {
            error.SignatureVerificationFailure, error.InvalidArgument => continue,
            else => return err,
        };
        return;
    }
    return error.InvalidSignature;
}

fn signPssImpl(
    implementation: *const Impl,
    algorithm: hashes.Algorithm,
    digest: []const u8,
    salt_length: usize,
    signature: []u8,
) errors.Error!void {
    if (!implementation.has_private or !implementation.usage.sign) return error.InvalidUsage;
    try validateDigest(algorithm, digest);
    _ = try validatePssOaepAlgorithm(algorithm);
    const k = c.SymCryptRsakeySizeofModulus(implementation.key_object);
    if (signature.len != k) return error.InvalidLength;
    const em_len = (c.SymCryptRsakeyModulusBits(implementation.key_object) - 1 + 7) / 8;
    if (salt_length > em_len or hashes.digestLength(algorithm) + salt_length + 2 > em_len)
        return error.MessageTooLong;
    var written: usize = 0;
    try errors.check(c.SymCryptRsaPssSign(
        implementation.key_object,
        digest.ptr,
        digest.len,
        hashes.pointer(algorithm),
        salt_length,
        0,
        c.SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        signature.ptr,
        signature.len,
        &written,
    ));
    if (written != signature.len) {
        secure_memory.wipeIndependent(signature);
        return error.InvalidLength;
    }
}

fn verifyPssImpl(
    implementation: *const Impl,
    algorithm: hashes.Algorithm,
    digest: []const u8,
    salt: PssSalt,
    signature: []const u8,
) errors.Error!void {
    if (!implementation.usage.sign) return error.InvalidUsage;
    try validateDigest(algorithm, digest);
    _ = try validatePssOaepAlgorithm(algorithm);
    if (signature.len != c.SymCryptRsakeySizeofModulus(implementation.key_object))
        return error.InvalidLength;
    const salt_len = switch (salt) {
        .exact => |len| len,
        .digest_length => hashes.digestLength(algorithm),
        .minimum => |len| len,
    };
    const em_len = (c.SymCryptRsakeyModulusBits(implementation.key_object) - 1 + 7) / 8;
    if (salt_len > em_len or hashes.digestLength(algorithm) + salt_len + 2 > em_len)
        return error.MessageTooLong;
    const flags: u32 = switch (salt) {
        .minimum => c.SYMCRYPT_FLAG_RSA_PSS_VERIFY_WITH_MINIMUM_SALT,
        else => 0,
    };
    errors.check(c.SymCryptRsaPssVerify(
        implementation.key_object,
        digest.ptr,
        digest.len,
        signature.ptr,
        signature.len,
        c.SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        hashes.pointer(algorithm),
        salt_len,
        flags,
    )) catch |err| switch (err) {
        error.SignatureVerificationFailure, error.InvalidArgument => return error.InvalidSignature,
        else => return err,
    };
}

fn encryptOaepImpl(
    implementation: *const Impl,
    algorithm: hashes.Algorithm,
    message: []const u8,
    label: []const u8,
    ciphertext: []u8,
) errors.Error!void {
    if (!implementation.usage.encrypt) return error.InvalidUsage;
    const h_len = try validatePssOaepAlgorithm(algorithm);
    const k = c.SymCryptRsakeySizeofModulus(implementation.key_object);
    if (ciphertext.len != k) return error.InvalidLength;
    if (k < 2 * h_len + 2 or message.len > k - 2 * h_len - 2) return error.MessageTooLong;
    var written: usize = 0;
    errors.check(c.SymCryptRsaOaepEncrypt(
        implementation.key_object,
        optionalPtr(message),
        message.len,
        hashes.pointer(algorithm),
        optionalPtr(label),
        label.len,
        0,
        c.SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        ciphertext.ptr,
        ciphertext.len,
        &written,
    )) catch |err| {
        secure_memory.wipeIndependent(ciphertext);
        return err;
    };
    if (written != ciphertext.len) {
        secure_memory.wipeIndependent(ciphertext);
        return error.InvalidLength;
    }
}

fn decryptOaepImpl(
    implementation: *const Impl,
    algorithm: hashes.Algorithm,
    ciphertext: []const u8,
    label: []const u8,
    output: []u8,
) errors.Error!usize {
    errdefer secure_memory.wipeIndependent(output);
    if (!implementation.has_private or !implementation.usage.encrypt) return error.InvalidUsage;
    _ = try validatePssOaepAlgorithm(algorithm);
    const k = c.SymCryptRsakeySizeofModulus(implementation.key_object);
    if (ciphertext.len != k) return error.InvalidLength;
    var written: usize = 0;
    try errors.check(c.SymCryptRsaOaepDecrypt(
        implementation.key_object,
        ciphertext.ptr,
        ciphertext.len,
        c.SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        hashes.pointer(algorithm),
        optionalPtr(label),
        label.len,
        0,
        optionalMutPtr(output),
        output.len,
        &written,
    ));
    if (written > output.len) return error.InvalidLength;
    return written;
}

fn buildDigestInfo(
    algorithm: hashes.Algorithm,
    digest: []const u8,
    with_null: bool,
    output: *[83]u8,
) errors.Error![]const u8 {
    var oid_storage: [13]u8 = undefined;
    const oid = try oidEncoding(algorithm, with_null, &oid_storage);
    const algorithm_identifier_len = oid.len;
    const content_len = 2 + algorithm_identifier_len + 2 + digest.len;
    const total_len = 2 + content_len;
    output[0] = 0x30;
    output[1] = @intCast(content_len);
    output[2] = 0x30;
    output[3] = @intCast(algorithm_identifier_len);
    @memcpy(output[4 .. 4 + oid.len], oid);
    var index: usize = 4 + oid.len;
    output[index] = 0x04;
    output[index + 1] = @intCast(digest.len);
    index += 2;
    @memcpy(output[index .. index + digest.len], digest);
    return output[0..total_len];
}

fn oidEncoding(
    algorithm: hashes.Algorithm,
    with_null: bool,
    output: *[13]u8,
) errors.Error![]const u8 {
    const name = @tagName(algorithm);
    var len: usize = 0;
    if (std.mem.eql(u8, name, "md5")) {
        const value = [_]u8{ 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05 };
        @memcpy(output[0..value.len], &value);
        len = value.len;
    } else if (std.mem.eql(u8, name, "sha1")) {
        const value = [_]u8{ 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a };
        @memcpy(output[0..value.len], &value);
        len = value.len;
    } else {
        const suffix: u8 = if (std.mem.eql(u8, name, "sha256"))
            0x01
        else if (std.mem.eql(u8, name, "sha384"))
            0x02
        else if (std.mem.eql(u8, name, "sha512"))
            0x03
        else if (std.mem.eql(u8, name, "sha3_256"))
            0x08
        else if (std.mem.eql(u8, name, "sha3_384"))
            0x09
        else if (std.mem.eql(u8, name, "sha3_512"))
            0x0a
        else
            return error.InvalidLength;
        const prefix = [_]u8{ 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02 };
        @memcpy(output[0..prefix.len], &prefix);
        output[prefix.len] = suffix;
        len = prefix.len + 1;
    }
    if (with_null) {
        output[len] = 0x05;
        output[len + 1] = 0;
        len += 2;
    }
    return output[0..len];
}

fn destroy(implementation: *Impl) void {
    const allocator = implementation.allocator;
    const key = implementation.key_object;
    implementation.key_object = null;
    if (key != null) c.SymCryptRsakeyFree(key);
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

fn optionalPtr(bytes: []const u8) [*c]const u8 {
    return if (bytes.len == 0) null else bytes.ptr;
}
fn optionalMutPtr(bytes: []u8) [*c]u8 {
    return if (bytes.len == 0) null else bytes.ptr;
}

pub const legacy = if (options.enable_legacy_rsa_pkcs1_encryption) struct {
    /// RSAES-PKCS1-v1_5 decryption is padding-oracle sensitive. Do not expose
    /// distinguishable failures or attacker-controlled retries.
    pub fn encrypt(
        key: anytype,
        message: []const u8,
        ciphertext: []u8,
    ) errors.Error!void {
        errdefer secure_memory.wipeIndependent(ciphertext);
        const implementation = keyImpl(key);
        if (!implementation.usage.encrypt) return error.InvalidUsage;
        const k = c.SymCryptRsakeySizeofModulus(implementation.key_object);
        if (ciphertext.len != k) return error.InvalidLength;
        if (message.len > k - 11) return error.MessageTooLong;
        var written: usize = 0;
        errors.check(c.SymCryptRsaPkcs1Encrypt(
            implementation.key_object,
            optionalPtr(message),
            message.len,
            0,
            c.SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
            ciphertext.ptr,
            ciphertext.len,
            &written,
        )) catch |err| {
            secure_memory.wipeIndependent(ciphertext);
            return err;
        };
        if (written != ciphertext.len) {
            secure_memory.wipeIndependent(ciphertext);
            return error.InvalidLength;
        }
    }

    pub fn decrypt(
        key: *const PrivateKey,
        ciphertext: []const u8,
        output: []u8,
    ) errors.Error!usize {
        errdefer secure_memory.wipeIndependent(output);
        const implementation = privateImplConst(key);
        if (!implementation.usage.encrypt) return error.InvalidUsage;
        if (ciphertext.len != c.SymCryptRsakeySizeofModulus(implementation.key_object))
            return error.InvalidLength;
        var written: usize = 0;
        try errors.check(c.SymCryptRsaPkcs1Decrypt(
            implementation.key_object,
            ciphertext.ptr,
            ciphertext.len,
            c.SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
            0,
            optionalMutPtr(output),
            output.len,
            &written,
        ));
        if (written > output.len) return error.InvalidLength;
        return written;
    }

    fn keyImpl(key: anytype) *const Impl {
        const T = @TypeOf(key);
        if (T == *const PrivateKey or T == *PrivateKey) return privateImplConst(key);
        if (T == *const PublicKey or T == *PublicKey) return publicImplConst(key);
        @compileError("legacy RSA encryption requires an RSA public or private key");
    }
} else struct {};

test "generated RSA signing, OAEP, exports, and restrictions" {
    const hash = if (options.legacy) @import("../hash_legacy.zig") else @import("../hash.zig");
    const key = try PrivateKey.generate(std.testing.allocator, 2048, null, .signing_and_encryption);
    defer key.deinit();
    try std.testing.expectEqual(@as(usize, 256), key.modulusLength());

    var public_components = try key.exportPublic(std.testing.allocator);
    defer public_components.deinit();
    const public = try key.publicKey(std.testing.allocator);
    defer public.deinit();
    var private_components = try key.exportPrivate(std.testing.allocator);
    defer private_components.deinit();
    try std.testing.expectEqualSlices(
        u8,
        public_components.modulus_be,
        private_components.modulus_be.bytes(),
    );
    const imported_public = try PublicKey.import(
        std.testing.allocator,
        public_components.modulus_be,
        public_components.public_exponent,
        .signing_and_encryption,
    );
    defer imported_public.deinit();
    const imported_primes = try PrivateKey.importPrimes(std.testing.allocator, .{
        .modulus_be = private_components.modulus_be.bytes(),
        .public_exponent = private_components.public_exponent,
        .p_be = private_components.p_be.bytes(),
        .q_be = private_components.q_be.bytes(),
    }, .signing_and_encryption);
    defer imported_primes.deinit();
    const imported_d = try PrivateKey.importPrivateExponent(std.testing.allocator, .{
        .modulus_be = private_components.modulus_be.bytes(),
        .public_exponent = private_components.public_exponent,
        .d_be = private_components.d_be.bytes(),
    }, .signing_and_encryption);
    defer imported_d.deinit();

    const digest = try hash.digest(.sha256, "asymmetric test");
    var pkcs1: [256]u8 = undefined;
    try key.signPkcs1v15(.sha256, &digest, &pkcs1);
    try public.verifyPkcs1v15(.sha256, &digest, &pkcs1);
    try imported_public.verifyPkcs1v15(.sha256, &digest, &pkcs1);
    try imported_primes.verifyPkcs1v15(.sha256, &digest, &pkcs1);
    try imported_d.verifyPkcs1v15(.sha256, &digest, &pkcs1);
    pkcs1[0] ^= 1;
    try std.testing.expectError(error.InvalidSignature, public.verifyPkcs1v15(.sha256, &digest, &pkcs1));
    const out_of_range_signature = [_]u8{0xff} ** 256;
    try std.testing.expectError(
        error.InvalidSignature,
        public.verifyPkcs1v15(.sha256, &digest, &out_of_range_signature),
    );

    var pss: [256]u8 = undefined;
    try key.signPss(.sha256, &digest, digest.len, &pss);
    try public.verifyPss(.sha256, &digest, .digest_length, &pss);
    try std.testing.expectError(
        error.InvalidSignature,
        public.verifyPss(.sha256, &digest, .digest_length, &out_of_range_signature),
    );
    try std.testing.expectError(error.InvalidSignature, public.verifyPss(.sha256, &digest, .{ .exact = 0 }, &pss));

    var ciphertext: [256]u8 = undefined;
    try public.encryptOaep(.sha256, "message", "label", &ciphertext);
    var plaintext: [64]u8 = undefined;
    const plaintext_len = try key.decryptOaep(.sha256, &ciphertext, "label", &plaintext);
    try std.testing.expectEqualStrings("message", plaintext[0..plaintext_len]);
    @memset(&plaintext, 0xa5);
    if (key.decryptOaep(.sha256, &ciphertext, "wrong", &plaintext)) |_| {
        return error.TestExpectedError;
    } else |_| {}
    try std.testing.expectEqualSlices(u8, &([_]u8{0} ** 64), &plaintext);
    const wrong_key = try PrivateKey.generate(std.testing.allocator, 2048, null, .signing_and_encryption);
    defer wrong_key.deinit();
    const wrong_public = try wrong_key.publicKey(std.testing.allocator);
    defer wrong_public.deinit();
    try key.signPkcs1v15(.sha256, &digest, &pkcs1);
    try std.testing.expectError(
        error.InvalidSignature,
        wrong_public.verifyPkcs1v15(.sha256, &digest, &pkcs1),
    );
    try std.testing.expectError(
        error.InvalidSignature,
        wrong_public.verifyPss(.sha256, &digest, .digest_length, &pss),
    );
    @memset(&plaintext, 0xa5);
    if (wrong_key.decryptOaep(.sha256, &ciphertext, "label", &plaintext)) |_| {
        return error.TestExpectedError;
    } else |_| {}
    try std.testing.expectEqualSlices(u8, &([_]u8{0} ** 64), &plaintext);
    const out_of_range_ciphertext = [_]u8{0xff} ** 256;
    @memset(&plaintext, 0xa5);
    if (key.decryptOaep(.sha256, &out_of_range_ciphertext, "label", &plaintext)) |_| {
        return error.TestExpectedError;
    } else |_| {}
    try std.testing.expectEqualSlices(u8, &([_]u8{0} ** 64), &plaintext);

    const sign_only = try PrivateKey.generate(std.testing.allocator, 2048, null, .signing);
    defer sign_only.deinit();
    try std.testing.expectError(error.InvalidUsage, sign_only.encryptOaep(.sha256, "", "", &ciphertext));

    if (comptime options.legacy) {
        const sha1 = try hash.digest(.sha1, "legacy test");
        try key.signPkcs1v15(.sha1, &sha1, &pkcs1);
        try public.verifyPkcs1v15(.sha1, &sha1, &pkcs1);
        try key.signPss(.sha1, &sha1, sha1.len, &pss);
        try public.verifyPss(.sha1, &sha1, .digest_length, &pss);
        const md5 = try hash.digest(.md5, "legacy test");
        try key.signPkcs1v15(.md5, &md5, &pkcs1);
        try public.verifyPkcs1v15(.md5, &md5, &pkcs1);
    }

    if (comptime options.enable_legacy_rsa_pkcs1_encryption) {
        try legacy.encrypt(public, "legacy", &ciphertext);
        const len = try legacy.decrypt(key, &ciphertext, &plaintext);
        try std.testing.expectEqualStrings("legacy", plaintext[0..len]);
    }
}

test "RSA validation and allocator failures are fail closed" {
    try std.testing.expectError(
        error.InvalidLength,
        PublicKey.import(std.testing.allocator, &.{1}, 65537, .signing),
    );
    var leading_zero = [_]u8{0} ** 256;
    leading_zero[255] = 1;
    try std.testing.expectError(
        error.InvalidEncoding,
        PublicKey.import(std.testing.allocator, &leading_zero, 65537, .signing),
    );
    var even_modulus = [_]u8{0xff} ** 256;
    even_modulus[255] = 0xfe;
    var no_allocation = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    try std.testing.expectError(
        error.InvalidEncoding,
        PublicKey.import(no_allocation.allocator(), &even_modulus, 65537, .signing),
    );
    try std.testing.expectError(
        error.InvalidEncoding,
        PrivateKey.importPrimes(no_allocation.allocator(), .{
            .modulus_be = &even_modulus,
            .public_exponent = 65537,
            .p_be = &.{3},
            .q_be = &.{5},
        }, .signing),
    );
    try std.testing.expectError(
        error.InvalidEncoding,
        PrivateKey.importPrivateExponent(no_allocation.allocator(), .{
            .modulus_be = &even_modulus,
            .public_exponent = 65537,
            .d_be = &.{3},
        }, .signing),
    );
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    try std.testing.expectError(
        error.OutOfMemory,
        PrivateKey.generate(failing.allocator(), 2048, null, .signing),
    );

    var checking = asymmetric.testing.WipeAllocator{ .backing = std.testing.allocator };
    test_fail_after_key_allocation = true;
    try std.testing.expectError(
        error.MemoryAllocationFailure,
        PrivateKey.generate(checking.allocator(), 2048, null, .signing),
    );
    try std.testing.expectEqual(@as(usize, 1), checking.frees);
    try std.testing.expectEqual(@as(usize, 0), checking.nonzero_frees);
}

test "pinned 2048-bit SHA-256 RSA PKCS1 known answer" {
    var modulus: [256]u8 = undefined;
    var private_exponent: [256]u8 = undefined;
    var digest: [32]u8 = undefined;
    var expected_signature: [256]u8 = undefined;
    var pss_digest: [32]u8 = undefined;
    var pss_signature: [256]u8 = undefined;
    _ = try std.fmt.hexToBytes(&modulus, "d18fb8613ff74ebbcd0d9e3d8c57d7475e2287f11200bc99876e7988775a17fb8524ae13760ebd0274d0547d3fc36675bab4c7131102972eb5dab50bbcc14f96fac3aceb955b8a054cff1712b0338bab5d1c29e6616b6d544c049d7632b86b49b8f288f755d57fdcf6ff280d3ec87b91ba00baa388c738fd3ed05d3574d28e0ce2cd816c05f3cfb18d242c3edef14b7283368ddf7abd75da06eda02b27177c82969aae6e38b2057da93c307e0382740fe0b7f2dfd7490ef8ddf282aa50c885683a886d86b2aa9f3c65599474fdda354eaa790af0c99e964db9021f934c6289dabd9d1608803e57d2aa230fb6587f1dd8e592485fcd9b7effc6a4c48e89922f25");
    _ = try std.fmt.hexToBytes(&private_exponent, "56ae16b99eb56ce1e665b395c9ac7d06ebc12af2abfc23a6c3c36e7a119068ac53e48d3badc011e6f449834dd1661d47d7c379de653321df89b56ce82d39ef5efbbcd6ff71a3498d97619189d511a53bbdd65eab384dd84a41a00aa9e7c9525348fde337b720ee2943f5f691f14cc6a791922a5775eb7f690f9e3169a4b3f650d396eb296bcc8e27c4c65a444ddd15632bba75bdc5da294b58fd724d2f87f2ab73986f840f833dc1ded559b4e801723b5e0d597f06f798af111ccdaf7a6348d7033a07b18537863f34dbd7fd15841d44f3d08cb8c1d779a84787c185bb1d98595504f48318189602930ed058be85b86b20ad28bef756f06bba04ec92520278cd");
    _ = try std.fmt.hexToBytes(&digest, "685663873e404bbc28237cac8920572aa683a0f38fe8ec65e94611a9115acfd1");
    _ = try std.fmt.hexToBytes(&expected_signature, "1ecf305ee05e8eb077d046c5e32267771d612b0e820a8166fee16a11e4e9c3c65342151a1e41cd185a04d2b334658ead4f1f098c1b1512e7fb27554ede15ef971ad90d3c728c872643e1838b39395b105cc173abd06a7b716dbb80d4328f04db5b752103a182e0616fc26eb95d95833c56d70bae0f4c84b99f609077cb56cb86908599384767541b0b69bcfc2b9ed5ffd199e303bddae2055652ebeff6a0c27b3b32f9029a5a962bbcfad290bb2db51ad8437bbdfc0fca843f8481015f8acc729c115196786cf929a35e58761cf6a4782090b3dc1ea26fdf36d2a79ec3b3b223032eb376d63d7e00e5ae45382c6426324a7ee04b57026ec72c9f3045dffe4da0");
    _ = try std.fmt.hexToBytes(&pss_digest, "77749d2cd74a7f195b6aad85824fc0c5b476ed23ec9c584a3befb09d4a095369");
    _ = try std.fmt.hexToBytes(&pss_signature, "6807bfc1c1ec4f260340b35d9ae644e4ccd840a50875b8b53c1ad7baca723d77098c23feee69b03879e44f7407db742242eb57c231ab52dd7f7b7ca8c12f09d17b6b260240521bafba6880e84f8b275e8aa3bbdfab614711e51fba4b40f2cb9b002d2a66b1fbcb174d7fa5f335b7bafd0a49286f1f62212ba8e5660c4e2b9d6eab07dca14be78da9aed6ebdf7833a9b287e2152c828052a6f67e5a5ed9890f0a9819554cc8f88c72aee69b9794fb7a81bb598f7aa946581339b3025cd93f5c85aab2309d48899b5876ff5ed81b6d02bf93835331a39de45d24f7fe4112f1e44dc44457b6e9e0816c4d755d1b699b332d2d125ec13b23df1014d92869a23760aa");
    const exponent: u64 = 0x38ef1586f9;
    const public = try PublicKey.import(std.testing.allocator, &modulus, exponent, .signing);
    defer public.deinit();
    try public.verifyPkcs1v15(.sha256, &digest, &expected_signature);
    try public.verifyPss(.sha256, &pss_digest, .{ .exact = 32 }, &pss_signature);

    const private = try PrivateKey.importPrivateExponent(std.testing.allocator, .{
        .modulus_be = &modulus,
        .public_exponent = exponent,
        .d_be = &private_exponent,
    }, .signing);
    defer private.deinit();
    var actual_signature: [256]u8 = undefined;
    try private.signPkcs1v15(.sha256, &digest, &actual_signature);
    try std.testing.expectEqualSlices(u8, &expected_signature, &actual_signature);
}

fn runRsaAlgorithmMatrix(
    key: *const PrivateKey,
    public: *const PublicKey,
    comptime algorithm: hashes.Algorithm,
) !void {
    const hash = if (options.legacy) @import("../hash_legacy.zig") else @import("../hash.zig");
    const digest = try hash.digest(algorithm, "RSA algorithm matrix");
    const modulus_len = key.modulusLength();
    const signature = try std.testing.allocator.alloc(u8, modulus_len);
    defer std.testing.allocator.free(signature);
    try key.signPkcs1v15(algorithm, &digest, signature);
    try public.verifyPkcs1v15(algorithm, &digest, signature);
    try key.signPss(algorithm, &digest, digest.len, signature);
    try public.verifyPss(algorithm, &digest, .digest_length, signature);

    const ciphertext = try std.testing.allocator.alloc(u8, modulus_len);
    defer std.testing.allocator.free(ciphertext);
    try public.encryptOaep(algorithm, "matrix message", "matrix label", ciphertext);
    var plaintext: [32]u8 = undefined;
    const plaintext_len = try key.decryptOaep(algorithm, ciphertext, "matrix label", &plaintext);
    try std.testing.expectEqualStrings("matrix message", plaintext[0..plaintext_len]);
}

test "RSA 2048 3072 4096 and advertised modern hash matrix" {
    inline for (.{
        .{ 2048, hashes.Algorithm.sha256, hashes.Algorithm.sha3_256 },
        .{ 3072, hashes.Algorithm.sha384, hashes.Algorithm.sha3_384 },
        .{ 4096, hashes.Algorithm.sha512, hashes.Algorithm.sha3_512 },
    }) |case| {
        const key = try PrivateKey.generate(std.testing.allocator, case[0], null, .signing_and_encryption);
        defer key.deinit();
        const public = try key.publicKey(std.testing.allocator);
        defer public.deinit();
        try runRsaAlgorithmMatrix(key, public, case[1]);
        try runRsaAlgorithmMatrix(key, public, case[2]);
    }
}

test "pinned 2048-bit SHA-256 RSA OAEP known answer" {
    var modulus: [256]u8 = undefined;
    var private_exponent: [256]u8 = undefined;
    var message: [85]u8 = undefined;
    var label: [895]u8 = undefined;
    var ciphertext: [256]u8 = undefined;
    _ = try std.fmt.hexToBytes(&modulus, "ad120f90d7ac1bfb6248a99eff0ca41cd95fcafe1df148b2af62387ba5f1fbb41edb2182cddf5fda66a22ffad709b68ac4356b8f2fc350e8e9cd96fbaea441439374f37e870519ce6594ec8677baa9d96a300a9fdf3aecd3587cf85d0f743ce671f30d1ad86a5fe6b69e430c41bcca624e183ddb69f382dfaf7df16f9ee7a3d8924882d921932cc9edb4b63bb15cc493f0bad8c69a3c0916a7c477dca294d39e777e0048feed1b9f1e7e8ac9962b19fcebfa644513c8012ba7ac328a1a7747e88ae61eff95949dec3e11b5635a04fa29de0f3df09b7ff324352083fb125b88e7689ee08dff05a5e9ebf3a820a8a47125646e061273c69ec77bed72bf6b831b3d");
    _ = try std.fmt.hexToBytes(&private_exponent, "28b097c5bfb18ef4fd667973cb42e7ee65fcbc901f6e33d6534f5e33ee14bb179e52d6588cbb19d484278db400c1d79ab17ffe2d579d174f9526b17a7d1b0505ebad852bf69519e5c3e990431ba08880bb1e665c51148211781cd52784b79462bdb3a1dbf853aa4a4e6a5618d6a6a509c00633ad00173f94a5ef711d1060a3bf611f4e486ca70bb579326920c8187c01e00d7b5239c2a225503f5d3b67b67dbd522aa812e96fdc543d523b890174efe4389cbc39dcf8d6718ccd6a2d25d4f2f3f1a2d45b97eb0db2b58a4737af53ad2aedd646476ac29134d68b95f892ba1c96355d77640f58057357462636b6d437180a5b0ac2e725e55c473f8317c8102da1");
    _ = try std.fmt.hexToBytes(&message, "19ec5cd571cd03774cbce0cec6b045eb9c1e550b124bc163efa2a25357e0466d104ddc80f773aa905f59b1fb19853e3d66f428e74ce00911b3373c47e77e58997df72ae7fe678278cee17fb6bf8494a687a4c5a349");
    _ = try std.fmt.hexToBytes(&label, "28d1b43ab00f888176cd1f49ca5ca92ee53475be6edac24ba5144ede9bf5d5f57b96bafe2249b939c81af2c0091f2c00624c21485113827246671fbc31dcb86cb3519062a539bf83c7766d31239c52ec5df0416f18aaf72f0fd5991736f96fc43d55cbe62aeb6cfa9406803290083b7c32a9ecc13abdbf1a269ab87b2e3e922c3d0a3c7ec7dbe759162c9d20ccbece35243ba9ebf64714b9a54449b68e4870f723f6caece4cd4fdab033db3d51ed6a7a2e7b5351528559a88028b8fcd14e8df5d15d1059ba007321c9dc95da79753adb18f8bd7c9b742ad0ff1162584d324ead3f2dc40177d7a143c75254fda3a1fded150eaa0a44d745db96ab38301e22148e1571b88e1836c537c2f29dc526372ccbfb8f0a0e323608e3d08adeba2cc357738fa6953d9962638eb6285e7313f4eb86505a9c6abfca8db0e45fa91c20e3eeb900f218864063e1727aca74f5f9e7c4c5e3e2f0a69fa20ce588049658a3d360fe506d45d819e6f8bb4c69144021aefabac72746f3460e072fd26f37ec74a2a0d92f3ba62005684a0dc77796ccd9a780f0feb050a1ccdf0e9e4b584d121cb3a37502253c7bd879612e3055e9d412f1b0676ff3cf21395243beab20a596942114b6bbc6b7eb224180697ba34f23258a8a54e41ede188ba1853bc1bb75d3d70d033997aa7bb2eb80a7c6617e4e1cdedc2d072393ceddfb031e21b7773ad7b53727cad73a525a677c736f54aac7df6fa42a01670e0e00f322b4d28e90228f3562d34838e8b959e7250023fe7b07f4dbcecc19522e7cf42fd3d4404724fad3df48adae7d067fb5460125d0785ca7cb98dfcd872f9a43195327b063af65fc0b882680c74fb15d2a4e605344ce26e827e8815d6b297230e72b4d99c416544b2a177875a6a00cebff14385ea0de01da5231cde0f68641f4b1a005ade86d8ff63f031c17db78307b5374802692faba476c28a653dad0b07a763ef250925a6fa927dc35e562c90193b120079ceb7106e4d5fc4167814fd78bb1cf959f3b58e36568eaacf26c348a44ab440b7004c2e9864c6ba5b799c4a21310982a219e29248e6ad6a1553dcb517256fb0e7a9a5b1d7d497be6443e201da63915265b4bff6225022517ae48550b2b03470898cb2646af2e9608ed0351c006cfb9bd6c8643f20f47ba6775b35c41d7ec90d882422e79a2e5a9cd5639f2a402e80ea8151b563118eb82c21e57966cf08028cbaffe3144e39a3045f5cd1f4775a2a4432963c3c14919356754");
    _ = try std.fmt.hexToBytes(&ciphertext, "9c3561c79b360421ffe42a84e7f77ecfea5e236ba97ed15f0de548a05253dfe845d804db6e6bdaf86638ff9309784458772f93844ffd58a11616cb110e936852e1007262348f239f9260b7e4ed87fceb393fca2bf57a2e44d8b6c1e6cd6b878905bb3a7f5ceb4042d4946643685c69ad16a3c6298a6f8648ed9f0810c79a755c4c468135c94895870dfbe3a2c6dcdb76454385da37eb234e253cfc57f4725ed66ed69f1b4f2fece8d795ff24c4775f1b3b5f40f1ab1214cada4ed5c78e98d4be0147b8dda4006996d2dcdb03222ac68b3cf8f55651c72f2ab1db4f54256c795f9f45d3e9cba99b45edc844303b698b70704c762aa81b87f125c63fd7d455a1aa");
    const key = try PrivateKey.importPrivateExponent(std.testing.allocator, .{
        .modulus_be = &modulus,
        .public_exponent = 0x0ee52d763c25,
        .d_be = &private_exponent,
    }, .encryption);
    defer key.deinit();
    var output: [128]u8 = undefined;
    const output_len = try key.decryptOaep(.sha256, &ciphertext, &label, &output);
    try std.testing.expectEqualSlices(u8, &message, output[0..output_len]);
}
