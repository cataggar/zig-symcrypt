const c = @import("c.zig").raw;

pub const InitError = error{
    IncompatibleSymCryptVersion,
    SymCryptInitializationFailed,
};

pub const SymCryptError = error{
    Unused,
    WrongKeySize,
    WrongBlockSize,
    WrongDataSize,
    WrongNonceSize,
    WrongTagSize,
    WrongIterationCount,
    AuthenticationFailure,
    ExternalFailure,
    FipsFailure,
    HardwareFailure,
    NotImplemented,
    InvalidBlob,
    BufferTooSmall,
    InvalidArgument,
    MemoryAllocationFailure,
    SignatureVerificationFailure,
    IncompatibleFormat,
    ValueTooLarge,
    SessionReplayFailure,
    HbsNoOtsKeysLeft,
    HbsPublicRootMismatch,
    UnknownSymCryptError,
};

pub const Error = InitError || SymCryptError || error{InvalidState};

pub const KnownError = enum {
    unused,
    wrong_key_size,
    wrong_block_size,
    wrong_data_size,
    wrong_nonce_size,
    wrong_tag_size,
    wrong_iteration_count,
    authentication_failure,
    external_failure,
    fips_failure,
    hardware_failure,
    not_implemented,
    invalid_blob,
    buffer_too_small,
    invalid_argument,
    memory_allocation_failure,
    signature_verification_failure,
    incompatible_format,
    value_too_large,
    session_replay_failure,
    hbs_no_ots_keys_left,
    hbs_public_root_mismatch,
};

/// A diagnostic classification which preserves unknown future SymCrypt codes.
pub const Status = union(enum) {
    success,
    known: KnownError,
    unknown_code: u32,
};

/// Classifies a raw integer without constructing an invalid C enum value.
pub fn classifyCode(code: u32) Status {
    return switch (code) {
        raw(c.SYMCRYPT_NO_ERROR) => .success,
        raw(c.SYMCRYPT_UNUSED) => .{ .known = .unused },
        raw(c.SYMCRYPT_WRONG_KEY_SIZE) => .{ .known = .wrong_key_size },
        raw(c.SYMCRYPT_WRONG_BLOCK_SIZE) => .{ .known = .wrong_block_size },
        raw(c.SYMCRYPT_WRONG_DATA_SIZE) => .{ .known = .wrong_data_size },
        raw(c.SYMCRYPT_WRONG_NONCE_SIZE) => .{ .known = .wrong_nonce_size },
        raw(c.SYMCRYPT_WRONG_TAG_SIZE) => .{ .known = .wrong_tag_size },
        raw(c.SYMCRYPT_WRONG_ITERATION_COUNT) => .{ .known = .wrong_iteration_count },
        raw(c.SYMCRYPT_AUTHENTICATION_FAILURE) => .{ .known = .authentication_failure },
        raw(c.SYMCRYPT_EXTERNAL_FAILURE) => .{ .known = .external_failure },
        raw(c.SYMCRYPT_FIPS_FAILURE) => .{ .known = .fips_failure },
        raw(c.SYMCRYPT_HARDWARE_FAILURE) => .{ .known = .hardware_failure },
        raw(c.SYMCRYPT_NOT_IMPLEMENTED) => .{ .known = .not_implemented },
        raw(c.SYMCRYPT_INVALID_BLOB) => .{ .known = .invalid_blob },
        raw(c.SYMCRYPT_BUFFER_TOO_SMALL) => .{ .known = .buffer_too_small },
        raw(c.SYMCRYPT_INVALID_ARGUMENT) => .{ .known = .invalid_argument },
        raw(c.SYMCRYPT_MEMORY_ALLOCATION_FAILURE) => .{ .known = .memory_allocation_failure },
        raw(c.SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE) => .{ .known = .signature_verification_failure },
        raw(c.SYMCRYPT_INCOMPATIBLE_FORMAT) => .{ .known = .incompatible_format },
        raw(c.SYMCRYPT_VALUE_TOO_LARGE) => .{ .known = .value_too_large },
        raw(c.SYMCRYPT_SESSION_REPLAY_FAILURE) => .{ .known = .session_replay_failure },
        raw(c.SYMCRYPT_HBS_NO_OTS_KEYS_LEFT) => .{ .known = .hbs_no_ots_keys_left },
        raw(c.SYMCRYPT_HBS_PUBLIC_ROOT_MISMATCH) => .{ .known = .hbs_public_root_mismatch },
        else => .{ .unknown_code = code },
    };
}

pub fn check(code: c.SYMCRYPT_ERROR) SymCryptError!void {
    return checkCode(raw(code));
}

pub fn checkCode(code: u32) SymCryptError!void {
    switch (classifyCode(code)) {
        .success => return,
        .unknown_code => return error.UnknownSymCryptError,
        .known => |known| return switch (known) {
            .unused => error.Unused,
            .wrong_key_size => error.WrongKeySize,
            .wrong_block_size => error.WrongBlockSize,
            .wrong_data_size => error.WrongDataSize,
            .wrong_nonce_size => error.WrongNonceSize,
            .wrong_tag_size => error.WrongTagSize,
            .wrong_iteration_count => error.WrongIterationCount,
            .authentication_failure => error.AuthenticationFailure,
            .external_failure => error.ExternalFailure,
            .fips_failure => error.FipsFailure,
            .hardware_failure => error.HardwareFailure,
            .not_implemented => error.NotImplemented,
            .invalid_blob => error.InvalidBlob,
            .buffer_too_small => error.BufferTooSmall,
            .invalid_argument => error.InvalidArgument,
            .memory_allocation_failure => error.MemoryAllocationFailure,
            .signature_verification_failure => error.SignatureVerificationFailure,
            .incompatible_format => error.IncompatibleFormat,
            .value_too_large => error.ValueTooLarge,
            .session_replay_failure => error.SessionReplayFailure,
            .hbs_no_ots_keys_left => error.HbsNoOtsKeysLeft,
            .hbs_public_root_mismatch => error.HbsPublicRootMismatch,
        },
    }
}

fn raw(value: c.SYMCRYPT_ERROR) u32 {
    return @bitCast(value);
}

test "all pinned error values and unknown values classify safely" {
    const std = @import("std");
    try check(c.SYMCRYPT_NO_ERROR);
    const cases = [_]struct { code: c.SYMCRYPT_ERROR, expected: KnownError }{
        .{ .code = c.SYMCRYPT_UNUSED, .expected = .unused },
        .{ .code = c.SYMCRYPT_WRONG_KEY_SIZE, .expected = .wrong_key_size },
        .{ .code = c.SYMCRYPT_WRONG_BLOCK_SIZE, .expected = .wrong_block_size },
        .{ .code = c.SYMCRYPT_WRONG_DATA_SIZE, .expected = .wrong_data_size },
        .{ .code = c.SYMCRYPT_WRONG_NONCE_SIZE, .expected = .wrong_nonce_size },
        .{ .code = c.SYMCRYPT_WRONG_TAG_SIZE, .expected = .wrong_tag_size },
        .{ .code = c.SYMCRYPT_WRONG_ITERATION_COUNT, .expected = .wrong_iteration_count },
        .{ .code = c.SYMCRYPT_AUTHENTICATION_FAILURE, .expected = .authentication_failure },
        .{ .code = c.SYMCRYPT_EXTERNAL_FAILURE, .expected = .external_failure },
        .{ .code = c.SYMCRYPT_FIPS_FAILURE, .expected = .fips_failure },
        .{ .code = c.SYMCRYPT_HARDWARE_FAILURE, .expected = .hardware_failure },
        .{ .code = c.SYMCRYPT_NOT_IMPLEMENTED, .expected = .not_implemented },
        .{ .code = c.SYMCRYPT_INVALID_BLOB, .expected = .invalid_blob },
        .{ .code = c.SYMCRYPT_BUFFER_TOO_SMALL, .expected = .buffer_too_small },
        .{ .code = c.SYMCRYPT_INVALID_ARGUMENT, .expected = .invalid_argument },
        .{ .code = c.SYMCRYPT_MEMORY_ALLOCATION_FAILURE, .expected = .memory_allocation_failure },
        .{ .code = c.SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE, .expected = .signature_verification_failure },
        .{ .code = c.SYMCRYPT_INCOMPATIBLE_FORMAT, .expected = .incompatible_format },
        .{ .code = c.SYMCRYPT_VALUE_TOO_LARGE, .expected = .value_too_large },
        .{ .code = c.SYMCRYPT_SESSION_REPLAY_FAILURE, .expected = .session_replay_failure },
        .{ .code = c.SYMCRYPT_HBS_NO_OTS_KEYS_LEFT, .expected = .hbs_no_ots_keys_left },
        .{ .code = c.SYMCRYPT_HBS_PUBLIC_ROOT_MISMATCH, .expected = .hbs_public_root_mismatch },
    };
    for (cases) |case| {
        try std.testing.expectEqual(case.expected, classifyCode(raw(case.code)).known);
    }
    const synthetic = raw(c.SYMCRYPT_HBS_PUBLIC_ROOT_MISMATCH) + 0x1000;
    try std.testing.expectEqual(synthetic, classifyCode(synthetic).unknown_code);
    try std.testing.expectError(error.UnknownSymCryptError, checkCode(synthetic));
}
