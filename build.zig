const std = @import("std");
const zig_build_sbom = @import("zig_build_sbom");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const version = b.option([]const u8, "version", "Version string embedded in shim executables") orelse "0.0.0-dev";

    const app = b.option([]const u8, "app", "Shim app to build: node|proxy|reshim") orelse "node";

    const root_source_file = if (std.mem.eql(u8, app, "node"))
        "node/main.zig"
    else if (std.mem.eql(u8, app, "proxy"))
        "proxy/main.zig"
    else if (std.mem.eql(u8, app, "reshim"))
        "reshim/main.zig"
    else
        @panic("Invalid -Dapp value. Expected one of: node, proxy, reshim");

    const registry_path = b.option([]const u8, "registry_path", "Path to registry module") orelse "shared/registry.zig";
    const config_path = b.option([]const u8, "config_path", "Path to config module") orelse "shared/config.zig";
    const eventlog_path = b.option([]const u8, "eventlog_path", "Path to eventlog module") orelse "shared/eventlog.zig";
    const errors_path = b.option([]const u8, "errors_path", "Path to errors module") orelse "shared/errors.zig";
    const resolver_path = b.option([]const u8, "resolver_path", "Path to version resolver module") orelse "shared/resolver.zig";
    const nodeversion_path = b.option([]const u8, "nodeversion_path", "Path to node version module") orelse "shared/nodeversion.zig";
    const shimintegrity_path = b.option([]const u8, "shimintegrity_path", "Path to shim integrity module") orelse "shared/shimintegrity.zig";
    const wintrust_path = b.option([]const u8, "wintrust_path", "Path to wintrust module") orelse "shared/wintrust.zig";
    const verifycache_path = b.option([]const u8, "verifycache_path", "Path to verify cache module") orelse "shared/verifycache.zig";
    const jobobject_path = b.option([]const u8, "jobobject_path", "Path to job object module") orelse "shared/jobobject.zig";

    const config_module = b.createModule(.{
        .root_source_file = b.path(config_path),
        .target = target,
        .optimize = optimize,
    });

    const registry_module = b.createModule(.{
        .root_source_file = b.path(registry_path),
        .target = target,
        .optimize = optimize,
    });
    registry_module.addImport("config", config_module);

    const resolver_module = b.createModule(.{
        .root_source_file = b.path(resolver_path),
        .target = target,
        .optimize = optimize,
    });

    const nodeversion_module = b.createModule(.{
        .root_source_file = b.path(nodeversion_path),
        .target = target,
        .optimize = optimize,
    });
    nodeversion_module.addImport("config", config_module);
    nodeversion_module.addImport("registry", registry_module);
    nodeversion_module.addImport("resolver", resolver_module);

    const shimintegrity_module = b.createModule(.{
        .root_source_file = b.path(shimintegrity_path),
        .target = target,
        .optimize = optimize,
    });
    shimintegrity_module.addImport("nodeversion", nodeversion_module);

    const wintrust_module = b.createModule(.{
        .root_source_file = b.path(wintrust_path),
        .target = target,
        .optimize = optimize,
    });

    const verifycache_module = b.createModule(.{
        .root_source_file = b.path(verifycache_path),
        .target = target,
        .optimize = optimize,
    });
    verifycache_module.addImport("config", config_module);
    verifycache_module.addImport("registry", registry_module);
    verifycache_module.addImport("wintrust", wintrust_module);

    const verifycache_tests = b.addTest(.{
        .root_module = verifycache_module,
    });
    verifycache_tests.root_module.linkSystemLibrary("bcrypt", .{});
    verifycache_tests.root_module.linkSystemLibrary("kernel32", .{});
    verifycache_tests.root_module.linkSystemLibrary("advapi32", .{});
    verifycache_tests.root_module.linkSystemLibrary("crypt32", .{});
    verifycache_tests.root_module.linkSystemLibrary("wintrust", .{});
    const run_verifycache_tests = b.addRunArtifact(verifycache_tests);
    const test_step = b.step("test", "Run verify cache unit tests");
    test_step.dependOn(&run_verifycache_tests.step);

    const exe = b.addExecutable(.{
        .name = app,
        .root_module = b.createModule(.{
            .root_source_file = b.path(root_source_file),
            .target = target,
            .optimize = optimize,
        }),
    });

    const build_options = b.addOptions();
    build_options.addOption([]const u8, "version", version);
    exe.root_module.addOptions("build_options", build_options);

    exe.root_module.addImport("registry", registry_module);

    exe.root_module.addImport("config", config_module);
    exe.root_module.addImport("resolver", resolver_module);
    exe.root_module.addImport("nodeversion", nodeversion_module);
    exe.root_module.addImport("shimintegrity", shimintegrity_module);

    if (std.mem.eql(u8, app, "reshim")) {
        exe.root_module.addImport("jobobject", b.createModule(.{
            .root_source_file = b.path(jobobject_path),
            .target = target,
            .optimize = optimize,
        }));
        exe.root_module.linkSystemLibrary("kernel32", .{});
    }

    if (std.mem.eql(u8, app, "node") or std.mem.eql(u8, app, "proxy")) {
        exe.root_module.addImport("verifycache", verifycache_module);
        exe.root_module.linkSystemLibrary("bcrypt", .{});
        exe.root_module.linkSystemLibrary("kernel32", .{});
        exe.root_module.linkSystemLibrary("advapi32", .{});
        exe.root_module.linkSystemLibrary("crypt32", .{});
        exe.root_module.linkSystemLibrary("wintrust", .{});
    }

    exe.root_module.addImport("errors", b.createModule(.{
        .root_source_file = b.path(errors_path),
        .target = target,
        .optimize = optimize,
    }));

    exe.root_module.addImport("eventlog", b.createModule(.{
        .root_source_file = b.path(eventlog_path),
        .target = target,
        .optimize = optimize,
    }));

    b.installArtifact(exe);

    // CycloneDX 1.6 via zig-build-sbom (compile graph + build.zig.zon).
    // Reachable with `zig build sbom` (does not block default install).
    // Note: zig-build-sbom 0.1.0 can emit invalid UTF-8 in source_url on Windows
    // (https://github.com/OrlovEvgeny/zig-build-sbom/issues/1);
    // shim/scripts/Export-ZigBuildSbom.ps1 sanitizes + finishes export.
    _ = zig_build_sbom.addSbomStep(b, exe, .{
        .format = .cyclonedx_json,
        .output_path = b.fmt("{s}.cdx.json", .{app}),
        .version = version,
        .manufacturer = .{
            .name = "Author Software Inc.",
            .url = "https://author.io",
        },
        .include_c_sources = true,
        .include_transitive = true,
        .infer_licenses = true,
        .strict_purl = true,
    });
}
