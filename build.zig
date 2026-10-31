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
    const install_safety_path = b.option([]const u8, "install_safety_path", "Path to install safety module") orelse "shared/install_safety.zig";
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

    const cmd_spawn_module = b.createModule(.{
        .root_source_file = b.path("shared/cmd_spawn.zig"),
        .target = target,
        .optimize = optimize,
    });

    const errors_module = b.createModule(.{
        .root_source_file = b.path(errors_path),
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
    nodeversion_module.addImport("cmd_spawn", cmd_spawn_module);
    nodeversion_module.addImport("errors", errors_module);

    const shimintegrity_module = b.createModule(.{
        .root_source_file = b.path(shimintegrity_path),
        .target = target,
        .optimize = optimize,
    });
    shimintegrity_module.addImport("nodeversion", nodeversion_module);

    const shim_bun_module = b.createModule(.{
        .root_source_file = b.path("shared/shim_bun.zig"),
        .target = target,
        .optimize = optimize,
    });
    shim_bun_module.addImport("config", config_module);
    shim_bun_module.addImport("registry", registry_module);

    const wintrust_module = b.createModule(.{
        .root_source_file = b.path(wintrust_path),
        .target = target,
        .optimize = optimize,
    });
    wintrust_module.addImport("config", config_module);

    const verifycache_module = b.createModule(.{
        .root_source_file = b.path(verifycache_path),
        .target = target,
        .optimize = optimize,
    });
    const pe_version_module = b.createModule(.{
        .root_source_file = b.path("shared/pe_version.zig"),
        .target = target,
        .optimize = optimize,
    });

    const version_firewall_module = b.createModule(.{
        .root_source_file = b.path("shared/version_firewall.zig"),
        .target = target,
        .optimize = optimize,
    });
    version_firewall_module.addImport("config", config_module);
    version_firewall_module.addImport("registry", registry_module);
    version_firewall_module.addImport("resolver", resolver_module);
    version_firewall_module.addImport("nodeversion", nodeversion_module);

    verifycache_module.addImport("config", config_module);
    verifycache_module.addImport("registry", registry_module);
    verifycache_module.addImport("wintrust", wintrust_module);
    verifycache_module.addImport("pe_version", pe_version_module);

    const verifycache_tests = b.addTest(.{
        .root_module = verifycache_module,
    });
    verifycache_tests.root_module.linkSystemLibrary("bcrypt", .{});
    verifycache_tests.root_module.linkSystemLibrary("kernel32", .{});
    verifycache_tests.root_module.linkSystemLibrary("advapi32", .{});
    verifycache_tests.root_module.linkSystemLibrary("crypt32", .{});
    verifycache_tests.root_module.linkSystemLibrary("wintrust", .{});
    verifycache_tests.root_module.linkSystemLibrary("version", .{});
    const run_verifycache_tests = b.addRunArtifact(verifycache_tests);
    const test_step = b.step("test", "Run shim unit tests");
    test_step.dependOn(&run_verifycache_tests.step);

    const nodeversion_tests = b.addTest(.{
        .root_module = nodeversion_module,
    });
    nodeversion_tests.root_module.linkSystemLibrary("advapi32", .{});
    nodeversion_tests.root_module.linkSystemLibrary("kernel32", .{});
    const run_nodeversion_tests = b.addRunArtifact(nodeversion_tests);
    test_step.dependOn(&run_nodeversion_tests.step);

    const resolver_tests = b.addTest(.{
        .root_module = resolver_module,
    });
    const run_resolver_tests = b.addRunArtifact(resolver_tests);
    test_step.dependOn(&run_resolver_tests.step);

    const pe_version_tests = b.addTest(.{
        .root_module = pe_version_module,
    });
    pe_version_tests.root_module.linkSystemLibrary("version", .{});
    const run_pe_version_tests = b.addRunArtifact(pe_version_tests);
    test_step.dependOn(&run_pe_version_tests.step);

    const version_firewall_tests = b.addTest(.{
        .root_module = version_firewall_module,
    });
    version_firewall_tests.root_module.linkSystemLibrary("advapi32", .{});
    const run_version_firewall_tests = b.addRunArtifact(version_firewall_tests);
    test_step.dependOn(&run_version_firewall_tests.step);

    const permission_grants_module = b.createModule(.{
        .root_source_file = b.path("shared/permission_grants.zig"),
        .target = target,
        .optimize = optimize,
    });
    const permission_grants_tests = b.addTest(.{
        .root_module = permission_grants_module,
    });
    const run_permission_grants_tests = b.addRunArtifact(permission_grants_tests);
    test_step.dependOn(&run_permission_grants_tests.step);

    const script_node_options_module = b.createModule(.{
        .root_source_file = b.path("shared/script_node_options.zig"),
        .target = target,
        .optimize = optimize,
    });
    script_node_options_module.addImport("permission_grants", permission_grants_module);
    const script_node_options_tests = b.addTest(.{
        .root_module = script_node_options_module,
    });
    const run_script_node_options_tests = b.addRunArtifact(script_node_options_tests);
    test_step.dependOn(&run_script_node_options_tests.step);

    const install_safety_module = b.createModule(.{
        .root_source_file = b.path(install_safety_path),
        .target = target,
        .optimize = optimize,
    });
    const install_safety_tests = b.addTest(.{
        .root_module = install_safety_module,
    });
    install_safety_tests.root_module.linkSystemLibrary("advapi32", .{});
    install_safety_tests.root_module.linkSystemLibrary("kernel32", .{});
    const run_install_safety_tests = b.addRunArtifact(install_safety_tests);
    test_step.dependOn(&run_install_safety_tests.step);

    const cmd_spawn_tests = b.addTest(.{
        .root_module = cmd_spawn_module,
    });
    const run_cmd_spawn_tests = b.addRunArtifact(cmd_spawn_tests);
    test_step.dependOn(&run_cmd_spawn_tests.step);

    const exe = b.addExecutable(.{
        .name = app,
        .root_module = b.createModule(.{
            .root_source_file = b.path(root_source_file),
            .target = target,
            .optimize = optimize,
        }),
    });

    const certified = b.option(bool, "certified", "Emit certified package-manager audit events") orelse false;

    const build_options = b.addOptions();
    build_options.addOption([]const u8, "version", version);
    build_options.addOption(bool, "certified", certified);
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
        exe.root_module.addImport("shim_bun", shim_bun_module);
        exe.root_module.linkSystemLibrary("kernel32", .{});
        exe.root_module.linkSystemLibrary("advapi32", .{});
        const reshim_tests = b.addTest(.{
            .root_module = exe.root_module,
        });
        const run_reshim_tests = b.addRunArtifact(reshim_tests);
        test_step.dependOn(&run_reshim_tests.step);
    }

    if (std.mem.eql(u8, app, "node")) {
        exe.root_module.addImport("permission_grants", permission_grants_module);
    }

    if (std.mem.eql(u8, app, "node") or std.mem.eql(u8, app, "proxy")) {
        exe.root_module.addImport("verifycache", verifycache_module);
        exe.root_module.addImport("version_firewall", version_firewall_module);
        exe.root_module.addImport("pe_version", pe_version_module);
        exe.root_module.linkSystemLibrary("bcrypt", .{});
        exe.root_module.linkSystemLibrary("kernel32", .{});
        exe.root_module.linkSystemLibrary("advapi32", .{});
        exe.root_module.linkSystemLibrary("crypt32", .{});
        exe.root_module.linkSystemLibrary("wintrust", .{});
        exe.root_module.linkSystemLibrary("version", .{});
    }

    if (std.mem.eql(u8, app, "proxy")) {
        exe.root_module.addImport("permission_grants", permission_grants_module);
        exe.root_module.addImport("script_node_options", script_node_options_module);
        exe.root_module.addImport("install_safety", install_safety_module);
        exe.root_module.addImport("wintrust", wintrust_module);
        const module_firewall_module = b.createModule(.{
            .root_source_file = b.path("shared/module_firewall.zig"),
            .target = target,
            .optimize = optimize,
        });
        module_firewall_module.addImport("config", config_module);
        module_firewall_module.addImport("registry", registry_module);
        module_firewall_module.addImport("nodeversion", nodeversion_module);
        exe.root_module.addImport("module_firewall", module_firewall_module);
        const malware_module = b.createModule(.{
            .root_source_file = b.path("shared/malware.zig"),
            .target = target,
            .optimize = optimize,
        });
        exe.root_module.addImport("malware", malware_module);
        const malware_tests = b.addTest(.{
            .root_module = malware_module,
        });
        const run_malware_tests = b.addRunArtifact(malware_tests);
        test_step.dependOn(&run_malware_tests.step);
        const cose_sign1_module = b.createModule(.{
            .root_source_file = b.path("shared/cose_sign1.zig"),
            .target = target,
            .optimize = optimize,
        });
        exe.root_module.addImport("cose_sign1", cose_sign1_module);
        const cose_sign1_tests = b.addTest(.{
            .root_module = cose_sign1_module,
        });
        cose_sign1_tests.root_module.linkSystemLibrary("bcrypt", .{});
        cose_sign1_tests.root_module.linkSystemLibrary("crypt32", .{});
        const run_cose_sign1_tests = b.addRunArtifact(cose_sign1_tests);
        test_step.dependOn(&run_cose_sign1_tests.step);
        exe.root_module.addImport("cmd_spawn", cmd_spawn_module);
        exe.root_module.addImport("shim_bun", shim_bun_module);
        const module_firewall_tests = b.addTest(.{
            .root_module = module_firewall_module,
        });
        module_firewall_tests.root_module.linkSystemLibrary("advapi32", .{});
        const run_module_firewall_tests = b.addRunArtifact(module_firewall_tests);
        test_step.dependOn(&run_module_firewall_tests.step);

        const shim_bun_tests = b.addTest(.{
            .root_module = b.createModule(.{
                .root_source_file = b.path("shared/shim_bun.zig"),
                .target = target,
                .optimize = optimize,
            }),
        });
        shim_bun_tests.root_module.addImport("config", config_module);
        shim_bun_tests.root_module.addImport("registry", registry_module);
        shim_bun_tests.root_module.linkSystemLibrary("advapi32", .{});
        const run_shim_bun_tests = b.addRunArtifact(shim_bun_tests);
        test_step.dependOn(&run_shim_bun_tests.step);

        const proxy_tests = b.addTest(.{
            .root_module = exe.root_module,
        });
        const run_proxy_tests = b.addRunArtifact(proxy_tests);
        test_step.dependOn(&run_proxy_tests.step);
    }

    exe.root_module.addImport("errors", errors_module);

    exe.root_module.addImport("eventlog", b.createModule(.{
        .root_source_file = b.path(eventlog_path),
        .target = target,
        .optimize = optimize,
    }));

    if (std.mem.eql(u8, app, "node")) {
        const node_tests = b.addTest(.{
            .root_module = exe.root_module,
        });
        const run_node_tests = b.addRunArtifact(node_tests);
        test_step.dependOn(&run_node_tests.step);
    }

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
