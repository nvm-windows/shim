const std = @import("std");

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
}
