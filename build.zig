const std = @import("std");

pub const Linkage = enum { dynamic, static };

const supported_targets =
    "x86_64-linux-gnu, aarch64-linux-gnu, x86_64-windows-msvc, aarch64-windows-msvc";

pub fn build(b: *std.Build) void {
    const default_target: std.Target.Query = if (b.graph.host.result.os.tag == .windows)
        .{
            .cpu_arch = b.graph.host.result.cpu.arch,
            .os_tag = .windows,
            .abi = .msvc,
        }
    else
        .{};
    const target = b.standardTargetOptions(.{ .default_target = default_target });
    const optimize = b.standardOptimizeOption(.{});
    const linkage = b.option(Linkage, "linkage", "SymCrypt linkage mode (dynamic or static)") orelse .dynamic;
    const libraries = b.option(
        []const std.Build.LazyPath,
        "symcrypt_libraries",
        "Ordered exact SymCrypt library files; repeat -Dsymcrypt_libraries for each file",
    ) orelse &.{};
    const include_dir = b.option(
        std.Build.LazyPath,
        "symcrypt_include_dir",
        "Directory containing the complete pinned SymCrypt public header set",
    ) orelse b.path("vendor/symcrypt/include");
    const system_include_dirs = b.option(
        []const std.Build.LazyPath,
        "symcrypt_system_include_dirs",
        "Additional target SDK/CRT include directories; repeat for cross-toolchains",
    ) orelse &.{};
    const checked = b.option(bool, "symcrypt_checked", "Match a checked/DBG SymCrypt binary") orelse false;
    const legacy = b.option(
        bool,
        "legacy",
        "Expose legacy MD5 and SHA-1 APIs for compatibility/integrity-only use",
    ) orelse false;
    const legacy_rsa = b.option(
        bool,
        "enable_legacy_rsa_pkcs1_encryption",
        "Expose legacy RSAES-PKCS1-v1_5 encryption/decryption APIs",
    ) orelse false;
    const mlkem = b.option(bool, "enable_mlkem", "Enable ML-KEM-768 (currently unavailable)") orelse false;
    const tls_hybrid = b.option(
        bool,
        "enable_tls_x25519_mlkem768",
        "Enable RFC 10024 X25519MLKEM768 (currently unavailable)",
    ) orelse false;
    const headers_only = b.option(
        bool,
        "headers_only",
        "Compile only header/version/ABI checks; no native library is required",
    ) orelse false;

    const target_ok = validateTarget(b, target, system_include_dirs);
    const libraries_ok = if (headers_only) true else validateLibraries(b, target, linkage, libraries);

    if (mlkem or tls_hybrid) {
        const fail = b.addFail(
            "ML-KEM-768 and RFC 10024 X25519MLKEM768 remain unavailable until independent FIPS 203 and TLS interoperability vectors are included",
        );
        b.getInstallStep().dependOn(&fail.step);
        b.step("test", "Run native initialization, hash, asymmetric, callback, and concurrency tests")
            .dependOn(&fail.step);
        b.step("test-compile", "Compile and link native tests without running them")
            .dependOn(&fail.step);
        b.step("example", "Build initialization and asymmetric examples").dependOn(&fail.step);
        b.step("abi-local", "Compile host-available ABI checks").dependOn(&fail.step);
        b.step("abi", "Compile the full ABI matrix").dependOn(&fail.step);
        return;
    }

    const options = makeOptions(b, linkage, include_dir, checked, false, legacy, legacy_rsa);
    const symcrypt = b.addModule("symcrypt", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    configureHeaders(symcrypt, include_dir, system_include_dirs, checked, options);

    if (target_ok and libraries_ok and !headers_only) {
        configureNative(b, symcrypt, target, linkage, libraries);
    }

    const abi_local_step = b.step(
        "abi-local",
        "Compile pinned header and ABI checks for targets available from this host/toolchain",
    );
    addAbiMatrix(b, abi_local_step, include_dir, system_include_dirs, legacy, legacy_rsa, .local_available);
    const abi_step = b.step(
        "abi",
        "Compile pinned header and ABI checks for all supported targets (Windows SDK required)",
    );
    addAbiMatrix(b, abi_step, include_dir, system_include_dirs, legacy, legacy_rsa, .full);

    if (!headers_only and libraries.len == 0) {
        const fail = b.addFail(
            "no SymCrypt libraries supplied: pass one or more ordered -Dsymcrypt_libraries=/exact/path files, or use -Dheaders_only=true for ABI-only checks",
        );
        b.getInstallStep().dependOn(&fail.step);
        b.step("test", "Run native cryptographic, initialization, callback, and concurrency tests")
            .dependOn(&fail.step);
        b.step("test-compile", "Compile and link native test executables without running them")
            .dependOn(&fail.step);
        b.step("example", "Build the minimal initialization example").dependOn(&fail.step);
        return;
    }

    if (headers_only or !target_ok or !libraries_ok) {
        b.getInstallStep().dependOn(abi_local_step);
        return;
    }

    const test_step = b.step("test", "Run native cryptographic, initialization, callback, and concurrency tests");
    const test_compile_step = b.step(
        "test-compile",
        "Compile and link native test executables without running them",
    );
    addNativeTests(
        b,
        symcrypt,
        target,
        optimize,
        linkage,
        include_dir,
        system_include_dirs,
        checked,
        legacy,
        legacy_rsa,
        test_step,
        test_compile_step,
    );

    const example_mod = b.createModule(.{
        .root_source_file = b.path(if (linkage == .dynamic)
            "examples/initialize_dynamic.zig"
        else
            "examples/initialize_static.zig"),
        .target = target,
        .optimize = optimize,
    });
    example_mod.addImport("symcrypt", symcrypt);
    const example = b.addExecutable(.{ .name = "symcrypt-initialize", .root_module = example_mod });
    const symmetric_example_mod = b.createModule(.{
        .root_source_file = b.path("examples/symmetric.zig"),
        .target = target,
        .optimize = optimize,
    });
    symmetric_example_mod.addImport("symcrypt", symcrypt);
    const symmetric_example = b.addExecutable(.{
        .name = "symcrypt-symmetric",
        .root_module = symmetric_example_mod,
    });
    const asymmetric_example_mod = b.createModule(.{
        .root_source_file = b.path("examples/asymmetric.zig"),
        .target = target,
        .optimize = optimize,
    });
    asymmetric_example_mod.addImport("symcrypt", symcrypt);
    const asymmetric_example = b.addExecutable(.{
        .name = "symcrypt-asymmetric",
        .root_module = asymmetric_example_mod,
    });
    const example_step = b.step("example", "Build initialization, symmetric, and asymmetric examples");
    example_step.dependOn(&example.step);
    example_step.dependOn(&symmetric_example.step);
    example_step.dependOn(&asymmetric_example.step);

    b.getInstallStep().dependOn(abi_local_step);
    b.getInstallStep().dependOn(&example.step);
    b.getInstallStep().dependOn(&symmetric_example.step);
    b.getInstallStep().dependOn(&asymmetric_example.step);
}

fn makeOptions(
    b: *std.Build,
    linkage: Linkage,
    include_dir: std.Build.LazyPath,
    checked: bool,
    init_test_hooks: bool,
    legacy: bool,
    legacy_rsa: bool,
) *std.Build.Step.Options {
    const options = b.addOptions();
    options.addOption([]const u8, "linkage", @tagName(linkage));
    options.addOption([]const u8, "include_dir", include_dir.getDisplayName());
    options.addOption(bool, "checked", checked);
    options.addOption(bool, "init_test_hooks", init_test_hooks);
    options.addOption(bool, "legacy", legacy);
    options.addOption(bool, "enable_legacy_rsa_pkcs1_encryption", legacy_rsa);
    options.addOption(bool, "enable_mlkem", false);
    options.addOption(bool, "enable_tls_x25519_mlkem768", false);
    return options;
}

fn configureHeaders(
    module: *std.Build.Module,
    include_dir: std.Build.LazyPath,
    system_include_dirs: []const std.Build.LazyPath,
    checked: bool,
    options: *std.Build.Step.Options,
) void {
    module.addIncludePath(include_dir);
    for (system_include_dirs) |dir| module.addSystemIncludePath(dir);
    module.addOptions("symcrypt_options", options);
    if (checked) module.addCMacro("DBG", "1");
}

fn configureNative(
    b: *std.Build,
    module: *std.Build.Module,
    target: std.Build.ResolvedTarget,
    linkage: Linkage,
    libraries: []const std.Build.LazyPath,
) void {
    for (libraries) |library| module.addObjectFile(library);

    if (target.result.os.tag == .windows and linkage == .dynamic) {
        module.addCSourceFile(.{
            .file = b.path("src/algorithm_accessors.c"),
            .flags = &.{"-std=c11"},
        });
    }

    if (linkage == .static) {
        module.addCSourceFile(.{ .file = b.path("src/static_environment.c"), .flags = &.{"-std=c11"} });
        module.addCSourceFile(.{ .file = b.path("src/callbacks.c"), .flags = &.{"-std=c11"} });
        if (target.result.os.tag == .linux) {
            module.linkSystemLibrary("atomic", .{});
            module.linkSystemLibrary("pthread", .{});
        } else {
            module.linkSystemLibrary("bcrypt", .{});
        }
    }
}

fn validateTarget(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    system_include_dirs: []const std.Build.LazyPath,
) bool {
    const t = target.result;
    const arch_ok = t.cpu.arch == .x86_64 or t.cpu.arch == .aarch64;
    const linux_ok = t.os.tag == .linux and t.abi == .gnu;
    const windows_ok = t.os.tag == .windows and t.abi == .msvc;
    if (arch_ok and (linux_ok or windows_ok)) {
        if (windows_ok and b.graph.host.result.os.tag != .windows and system_include_dirs.len == 0) {
            std.log.err(
                "target '{s}' requires MSVC/Windows SDK headers: run on Windows or pass ordered -Dsymcrypt_system_include_dirs paths",
                .{t.zigTriple(b.allocator) catch @panic("out of memory")},
            );
            b.invalid_user_input = true;
            return false;
        }
        return true;
    }

    const triple = t.zigTriple(b.allocator) catch @panic("out of memory");
    if (t.os.tag == .linux and t.abi == .musl) {
        std.log.err(
            "unsupported target '{s}': SymCrypt 103.13.0 fixtures are GNU user mode, not musl; supported: {s}",
            .{ triple, supported_targets },
        );
    } else if (t.os.tag == .windows and t.abi != .msvc) {
        std.log.err(
            "unsupported target '{s}': Windows requires the MSVC ABI/SDK; supported: {s}",
            .{ triple, supported_targets },
        );
    } else {
        std.log.err("unsupported target '{s}'; supported: {s}", .{ triple, supported_targets });
    }
    b.invalid_user_input = true;
    return false;
}

fn validateLibraries(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    linkage: Linkage,
    libraries: []const std.Build.LazyPath,
) bool {
    if (libraries.len == 0) {
        return false;
    }

    var ok = true;
    var has_plus = false;
    for (libraries) |library| {
        const path = library.getDisplayName();
        has_plus = has_plus or std.mem.indexOf(u8, std.fs.path.basename(path), "symcrypt_plus") != null;
        const valid = if (target.result.os.tag == .linux)
            if (linkage == .dynamic)
                isSharedObject(path) or std.mem.endsWith(u8, path, "libsymcrypt_plus.a")
            else
                std.mem.endsWith(u8, path, ".a")
        else
            std.mem.endsWith(u8, path, ".lib");
        if (!valid) {
            if (target.result.os.tag == .windows and linkage == .dynamic and
                std.mem.endsWith(u8, path, ".dll"))
            {
                std.log.err(
                    "invalid dynamic Windows link input '{s}': pass the import .lib; the .dll is a runtime artifact",
                    .{path},
                );
            } else {
                const expected = if (target.result.os.tag == .linux)
                    if (linkage == .dynamic) ".so or versioned .so.N" else ".a"
                else if (linkage == .dynamic) "import .lib" else "static .lib (prefer symcrypt_static_NoCIL.lib)";
                std.log.err(
                    "invalid {s} SymCrypt library '{s}' for target {s}-{s}: expected {s}",
                    .{ @tagName(linkage), path, @tagName(target.result.cpu.arch), @tagName(target.result.os.tag), expected },
                );
            }
            ok = false;
        }
    }
    if (!has_plus) {
        std.log.err(
            "missing pinned symcrypt_plus static companion library required for checked SEC1/X25519 IETF encodings",
            .{},
        );
        ok = false;
    }
    if (!ok) b.invalid_user_input = true;
    return ok;
}

fn isSharedObject(path: []const u8) bool {
    return std.mem.endsWith(u8, path, ".so") or std.mem.indexOf(u8, path, ".so.") != null;
}

const AbiMatrix = enum {
    local_available,
    full,
};

fn addAbiMatrix(
    b: *std.Build,
    step: *std.Build.Step,
    include_dir: std.Build.LazyPath,
    system_include_dirs: []const std.Build.LazyPath,
    legacy: bool,
    legacy_rsa: bool,
    matrix: AbiMatrix,
) void {
    const windows_available =
        b.graph.host.result.os.tag == .windows or system_include_dirs.len != 0;
    if (matrix == .full and !windows_available) {
        const fail = b.addFail(
            "full ABI matrix requires MSVC/Windows SDK headers for x86_64-windows-msvc and aarch64-windows-msvc: run 'zig build abi -Dheaders_only=true' on Windows or pass ordered -Dsymcrypt_system_include_dirs paths; use 'zig build abi-local -Dheaders_only=true' for host-available checks",
        );
        step.dependOn(&fail.step);
    }

    const queries = [_]std.Target.Query{
        .{ .cpu_arch = .x86_64, .os_tag = .linux, .abi = .gnu },
        .{ .cpu_arch = .aarch64, .os_tag = .linux, .abi = .gnu },
        .{ .cpu_arch = .x86_64, .os_tag = .windows, .abi = .msvc },
        .{ .cpu_arch = .aarch64, .os_tag = .windows, .abi = .msvc },
    };
    for (queries) |query| {
        if (query.os_tag == .windows and !windows_available) continue;
        inline for (.{ false, true }) |checked| {
            const target = b.resolveTargetQuery(query);
            const options = makeOptions(b, .dynamic, include_dir, checked, false, legacy, legacy_rsa);
            const module = b.createModule(.{
                .root_source_file = b.path("src/root.zig"),
                .target = target,
                .optimize = .Debug,
                .link_libc = true,
            });
            configureHeaders(module, include_dir, system_include_dirs, checked, options);
            const object = b.addObject(.{
                .name = b.fmt("abi-{s}-{s}-{s}", .{
                    @tagName(target.result.cpu.arch),
                    @tagName(target.result.os.tag),
                    if (checked) "checked" else "fre",
                }),
                .root_module = module,
            });
            step.dependOn(&object.step);
        }
    }
}

fn addNativeTests(
    b: *std.Build,
    symcrypt: *std.Build.Module,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    linkage: Linkage,
    include_dir: std.Build.LazyPath,
    system_include_dirs: []const std.Build.LazyPath,
    checked: bool,
    legacy: bool,
    legacy_rsa: bool,
    test_step: *std.Build.Step,
    test_compile_step: *std.Build.Step,
) void {
    const test_mod = b.createModule(.{
        .root_source_file = b.path("test/native.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    test_mod.addImport("symcrypt", symcrypt);
    test_mod.addIncludePath(include_dir);
    for (system_include_dirs) |dir| test_mod.addSystemIncludePath(dir);
    if (checked) test_mod.addCMacro("DBG", "1");
    const tests = b.addTest(.{ .root_module = test_mod });
    const run_tests = b.addRunArtifact(tests);
    test_compile_step.dependOn(&tests.step);
    test_step.dependOn(&run_tests.step);

    const package_test_options = makeOptions(b, linkage, include_dir, checked, false, legacy, legacy_rsa);
    const package_test_mod = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    configureHeaders(
        package_test_mod,
        include_dir,
        system_include_dirs,
        checked,
        package_test_options,
    );
    for (symcrypt.link_objects.items) |object| {
        package_test_mod.link_objects.append(b.allocator, object) catch @panic("OOM");
    }
    const package_tests = b.addTest(.{ .root_module = package_test_mod });
    const run_package_tests = b.addRunArtifact(package_tests);
    test_compile_step.dependOn(&package_tests.step);
    test_step.dependOn(&run_package_tests.step);

    const concurrency_options = makeOptions(b, linkage, include_dir, checked, true, legacy, legacy_rsa);
    const concurrency_mod = b.createModule(.{
        .root_source_file = b.path("src/init_concurrency_test.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    configureHeaders(
        concurrency_mod,
        include_dir,
        system_include_dirs,
        checked,
        concurrency_options,
    );
    for (symcrypt.link_objects.items) |object| {
        concurrency_mod.link_objects.append(b.allocator, object) catch @panic("OOM");
    }
    const concurrency = b.addTest(.{ .root_module = concurrency_mod });
    const run_concurrency = b.addRunArtifact(concurrency);
    test_compile_step.dependOn(&concurrency.step);
    test_step.dependOn(&run_concurrency.step);

    if (linkage == .dynamic) {
        const mismatch_options = makeOptions(b, .dynamic, include_dir, checked, false, legacy, legacy_rsa);
        const mismatch_mod = b.createModule(.{
            .root_source_file = b.path("src/mismatch_test.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        });
        configureHeaders(mismatch_mod, include_dir, system_include_dirs, checked, mismatch_options);
        for (symcrypt.link_objects.items) |object| mismatch_mod.link_objects.append(b.allocator, object) catch @panic("OOM");
        const mismatch = b.addTest(.{ .root_module = mismatch_mod });
        const run_mismatch = b.addRunArtifact(mismatch);
        test_compile_step.dependOn(&mismatch.step);
        test_step.dependOn(&run_mismatch.step);
    }
}
