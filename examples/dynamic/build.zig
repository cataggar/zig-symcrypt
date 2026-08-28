const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const libraries = b.option(
        []const std.Build.LazyPath,
        "symcrypt_libraries",
        "Ordered exact SymCrypt library files",
    ) orelse &.{};
    const include_dir = b.option(
        std.Build.LazyPath,
        "symcrypt_include_dir",
        "Complete SymCrypt public header directory",
    ) orelse b.path("../../vendor/symcrypt/include");
    const checked = b.option(bool, "symcrypt_checked", "Use checked SymCrypt ABI") orelse false;
    const legacy = b.option(bool, "legacy", "Enable legacy hash APIs") orelse false;
    const legacy_rsa = b.option(
        bool,
        "enable_legacy_rsa_pkcs1_encryption",
        "Enable legacy RSA encryption",
    ) orelse false;

    const dependency = b.dependency("zig_symcrypt", .{
        .target = target,
        .optimize = optimize,
        .linkage = .dynamic,
        .symcrypt_libraries = libraries,
        .symcrypt_include_dir = include_dir,
        .symcrypt_checked = checked,
        .legacy = legacy,
        .enable_legacy_rsa_pkcs1_encryption = legacy_rsa,
    });
    const module = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    module.addImport("symcrypt", dependency.module("symcrypt"));
    const executable = b.addExecutable(.{ .name = "dynamic-consumer", .root_module = module });
    const run = b.addRunArtifact(executable);
    b.step("run", "Run the dynamic package consumer").dependOn(&run.step);
}
