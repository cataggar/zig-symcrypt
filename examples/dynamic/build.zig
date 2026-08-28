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
    const provenance = b.option(
        std.Build.LazyPath,
        "symcrypt_provenance",
        "Exact fixture provenance used to verify and stage the runtime DLL",
    );

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
    const run_step = b.step("run", "Run the dynamic package consumer");
    if (target.result.os.tag == .windows) {
        if (provenance) |manifest| {
            const run = b.addSystemCommand(&.{"python3"});
            run.addFileArg(b.path("../../tools/run_verified.py"));
            run.addArg("--manifest");
            run.addFileArg(manifest);
            run.addArgs(&.{
                "--target",
                b.fmt(
                    "{s}-{s}-{s}",
                    .{
                        @tagName(target.result.cpu.arch),
                        @tagName(target.result.os.tag),
                        @tagName(target.result.abi),
                    },
                ),
            });
            for (libraries) |library| {
                run.addArg("--library");
                run.addFileArg(library);
            }
            run.addArtifactArg(executable);
            run_step.dependOn(&run.step);
        } else {
            const fail = b.addFail(
                "dynamic Windows consumer execution requires -Dsymcrypt_provenance",
            );
            run_step.dependOn(&fail.step);
        }
    } else {
        run_step.dependOn(&b.addRunArtifact(executable).step);
    }
}
