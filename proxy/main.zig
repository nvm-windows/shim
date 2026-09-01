const std = @import("std");
const build_options = @import("build_options");
const nodeversion = @import("nodeversion");
const resolver = @import("resolver");
const eventlog = @import("eventlog");
const errors = @import("errors");
const shimintegrity = @import("shimintegrity");
const verifycache = @import("verifycache");
const install_safety = @import("install_safety");

const ParsedArgs = struct {
    override_version: ?[]const u8,
    nvm_use_debug: bool,
    forwarded: []const []const u8,
};

const nodeNotFound = errors.nodeNotFound;
const noActiveVersionConfigured = errors.noActiveVersionConfigured;
const nodeVerifyFailed = errors.nodeVerifyFailed;
const shim_version = build_options.version;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const argv = std.process.argsAlloc(allocator) catch {
        std.debug.print("proxy.exe\n", .{});
        return;
    };
    defer std.process.argsFree(allocator, argv);

    if (argv.len == 0) {
        std.debug.print("proxy.exe\n", .{});
        return;
    }

    if (argv.len >= 2 and std.mem.eql(u8, argv[1], "--nvm-shim-version")) {
        std.debug.print("{s}\n", .{shim_version});
        return;
    }

    const parsed_args = try parseArgs(allocator, argv[1..]);
    defer allocator.free(parsed_args.forwarded);

    shimintegrity.verifySelfIfInvokedFromShim(allocator) catch {
        std.debug.print("shim integrity check failed\n", .{});
        std.process.exit(1);
    };

    const invoked = std.fs.path.basename(argv[0]);
    const command_name = std.fs.path.stem(invoked);
    // std.debug.print("{s}\n", .{command_name});

    const cfg = try nodeversion.loadConfig(allocator);
    defer nodeversion.deinitConfig(allocator, cfg);

    var resolved = nodeversion.resolveConfiguredNode(allocator, cfg, parsed_args.override_version) catch |err| switch (err) {
        error.NoActiveVersion => noActiveVersionConfigured(),
        error.NoVersionsInstalled => errors.noVersionsInstalled(),
        error.UnsupportedVersionSpec => {
            if (!nodeversion.hasInstalledVersions(cfg.root)) {
                errors.noVersionsInstalled();
            }
            errors.unresolvedVersionSpec(nodeversion.lastResolutionSpec());
        },
        else => return err,
    };
    defer resolved.deinit(allocator);

    nodeversion.ensureInstalledNode(allocator, cfg, parsed_args.override_version, &resolved) catch |err| switch (err) {
        error.NodeNotFound => nodeNotFound(resolved.resolved_version orelse resolved.effective_version),
        error.AutoInstallCancelled => {
            std.debug.print("operation cancelled\n", .{});
            std.process.exit(1);
        },
        error.AutoInstallFailed => return err,
    };

    if (parsed_args.nvm_use_debug) {
        std.debug.print(
            "nvm version resolution: source={s} requested={s} effective={s} resolved={s} node={s}\n",
            .{ resolved.version_source, resolved.requested_version, resolved.effective_version, resolved.resolved_version.?, resolved.node_bin.? },
        );
    }

    const node_install_dir = std.fs.path.dirname(resolved.node_bin.?) orelse ".";
    const node_install_dir_abs = try std.fs.path.resolve(allocator, &.{node_install_dir});
    defer allocator.free(node_install_dir_abs);

    install_safety.checkVersionDirTrust(allocator, node_install_dir_abs) catch |err| {
        const detail = switch (err) {
            error.ReparsePoint => "Directory is a junction, symbolic link, or other reparse point.",
            error.CrossUserWritable => "Directory is writable by other users.",
            error.NotADirectory => "Path is not a directory.",
            error.PathUnavailable => "Directory trust checks failed.",
        };
        const message = try std.fmt.allocPrint(
            allocator,
            "NVM4305 Package-manager launch blocked because the Node.js directory is unsafe: {s} ({s})",
            .{ node_install_dir_abs, detail },
        );
        defer allocator.free(message);
        eventlog.writeLicensedSecurityError(
            allocator,
            cfg.structured_logging,
            "proxy",
            "node.security.activation_blocked",
            .{
                .action = "execution_blocked",
                .command = command_name,
                .detail = detail,
                .failure_kind = @errorName(err),
                .node_path = resolved.node_bin.?,
                .node_version = resolved.resolved_version.?,
                .source = "proxy",
                .version_path = node_install_dir_abs,
            },
            message,
            4305,
        );
        std.debug.print(
            \\NVM blocked package-manager execution because the Node.js directory is unsafe.
            \\
            \\Path: {s}
            \\Reason: {s}
            \\Action: Reinstall this version into a private install root.
            \\If this change was unexpected, contact your administrator and review NVM event logs.
            \\Event code: NVM4305
            \\
        , .{ node_install_dir_abs, detail });
        std.process.exit(1);
    };

    const command_path = try resolveDelegatedCommandPath(allocator, node_install_dir_abs, command_name);
    defer allocator.free(command_path);

    if (!try enforcePackageManagerConstraint(allocator, cfg, resolved.version_source, command_name, resolved.node_bin.?, command_path)) {
        std.process.exit(1);
    }

    const verify_outcome = verifycache.ensureResolvedNodeTrusted(allocator, cfg.root, resolved.node_bin.?);
    switch (verify_outcome.result) {
        .trusted_cache => {},
        .verified_full => {
            if (verify_outcome.cache_status != .none) {
                const cache_message = try std.fmt.allocPrint(
                    allocator,
                    "NVM4303 Node.js verify-cache state changed; full verification required: {s} ({s})",
                    .{ resolved.node_bin.?, @tagName(verify_outcome.cache_status) },
                );
                defer allocator.free(cache_message);
                eventlog.writeLicensedSecurityWarning(
                    allocator,
                    cfg.structured_logging,
                    "proxy",
                    "node.security.cache_state_changed",
                    .{
                        .action = "full_verification_required",
                        .cache_status = @tagName(verify_outcome.cache_status),
                        .command = command_name,
                        .node_path = resolved.node_bin.?,
                        .node_version = resolved.resolved_version.?,
                        .source = "proxy",
                        .verification_result = "cache_invalidated",
                    },
                    cache_message,
                    4303,
                );
                const recovery_message = try std.fmt.allocPrint(
                    allocator,
                    "NVM4304 Full Node.js verification succeeded after verify-cache state changed: {s}",
                    .{resolved.node_bin.?},
                );
                defer allocator.free(recovery_message);
                eventlog.writeLicensedSecurityInfo(
                    allocator,
                    cfg.structured_logging,
                    "proxy",
                    "node.security.full_verification_recovered",
                    .{
                        .action = "execution_allowed",
                        .cache_status = @tagName(verify_outcome.cache_status),
                        .command = command_name,
                        .node_path = resolved.node_bin.?,
                        .node_version = resolved.resolved_version.?,
                        .source = "proxy",
                        .verification_result = "trusted",
                    },
                    recovery_message,
                    4304,
                );
            }
        },
        .failed => {
            const message = try std.fmt.allocPrint(
                allocator,
                "NVM4301 Node.js execution blocked because integrity verification failed: {s} ({s})",
                .{ resolved.node_bin.?, if (verify_outcome.reason.len == 0) "trust verification failed" else verify_outcome.reason },
            );
            defer allocator.free(message);
            eventlog.writeLicensedSecurityError(
                allocator,
                cfg.structured_logging,
                "proxy",
                "node.security.verification_failed",
                .{
                    .action = "execution_blocked",
                    .cache_status = @tagName(verify_outcome.cache_status),
                    .command = command_name,
                    .detail = if (verify_outcome.reason.len == 0) "trust verification failed" else verify_outcome.reason,
                    .failure_kind = "executable_trust_failed",
                    .node_path = resolved.node_bin.?,
                    .node_version = resolved.resolved_version.?,
                    .source = "proxy",
                    .verification_result = "failed",
                },
                message,
                4301,
            );
            nodeVerifyFailed(resolved.node_bin.?, resolved.resolved_version.?, verify_outcome.reason);
        },
    }

    try enforceDelegatedCommandTrust(allocator, cfg, command_name, command_path, resolved.node_bin.?, resolved.resolved_version.?, node_install_dir_abs);

    const needs_reshim = detectReshimNeeded(command_name, parsed_args.forwarded);

    const process_exit_code = runDelegatedCommand(
        allocator,
        node_install_dir_abs,
        resolved.node_bin.?,
        command_name,
        command_path,
        cfg.npm_module_minimum_age,
        cfg.npm_registry_fallback,
        parsed_args.forwarded,
    ) catch |err| blk: {
        std.debug.print("proxy failed to run {s}: {s}\n", .{ command_name, @errorName(err) });
        break :blk 1;
    };

    // std.debug.print("{s}\n", .{node_install_dir});

    if (needs_reshim) {
        eventlog.writeInfo(allocator, "proxy", "reshim scheduled");
        runReshim(allocator, cfg.root, node_install_dir_abs);
    }

    std.process.exit(process_exit_code);
}

fn enforcePackageManagerConstraint(
    allocator: std.mem.Allocator,
    cfg: nodeversion.ShimConfig,
    version_source: []const u8,
    command_name: []const u8,
    node_bin: []const u8,
    command_path: []const u8,
) !bool {
    if (!nodeversion.shouldCheckPackageManagerMismatch(version_source, cfg.package_manager_mismatch_action)) {
        return true;
    }

    if (!isConstrainedPackageManagerHardlink(command_name)) {
        return true;
    }

    const constraint = try nodeversion.detectPackageManagerConstraintFromFile(allocator, version_source);
    if (constraint == null) {
        return true;
    }
    defer constraint.?.deinit(allocator);

    if (!std.ascii.eqlIgnoreCase(constraint.?.name, command_name)) {
        const name_mismatch_message = try std.fmt.allocPrint(
            allocator,
            "invoked package manager {s} does not match required {s} in {s} (devEngines.packageManager)",
            .{ command_name, constraint.?.name, version_source },
        );
        defer allocator.free(name_mismatch_message);

        return handlePackageManagerMismatchAction(allocator, cfg.package_manager_mismatch_action, name_mismatch_message);
    }

    const current_version = try nodeversion.resolvePackageManagerVersion(allocator, node_bin, command_name, command_path);
    if (current_version == null) {
        return true;
    }
    defer allocator.free(current_version.?);

    const is_match = resolver.versionSatisfiesSpec(allocator, constraint.?.version_spec, current_version.?) catch true;
    if (is_match) {
        return true;
    }

    const message = try std.fmt.allocPrint(
        allocator,
        "{s} version {s} does not satisfy required {s} in {s} (devEngines.packageManager)",
        .{ constraint.?.name, current_version.?, constraint.?.version_spec, version_source },
    );
    defer allocator.free(message);

    return handlePackageManagerMismatchAction(allocator, cfg.package_manager_mismatch_action, message);
}

fn handlePackageManagerMismatchAction(
    allocator: std.mem.Allocator,
    action: nodeversion.PackageManagerMismatchAction,
    message: []const u8,
) !bool {
    switch (action) {
        .warn => {
            var stderr_file = std.fs.File.stderr();
            var stderr_buf: [512]u8 = undefined;
            var stderr_writer = stderr_file.writer(&stderr_buf);
            try stderr_writer.interface.print("warning: {s}\n", .{message});
            try stderr_writer.interface.flush();
            eventlog.writeWarning(allocator, "proxy", message);
            return true;
        },
        .@"error" => {
            var stderr_file = std.fs.File.stderr();
            var stderr_buf: [512]u8 = undefined;
            var stderr_writer = stderr_file.writer(&stderr_buf);
            try stderr_writer.interface.print("error: {s}\n", .{message});
            try stderr_writer.interface.flush();
            eventlog.writeError(allocator, "proxy", message);
            return false;
        },
        .ignore => return true,
    }
}

fn isConstrainedPackageManagerHardlink(command_name: []const u8) bool {
    return std.ascii.eqlIgnoreCase(command_name, "npm") or
        std.ascii.eqlIgnoreCase(command_name, "npx") or
        std.ascii.eqlIgnoreCase(command_name, "pnpm") or
        std.ascii.eqlIgnoreCase(command_name, "yarn");
}

fn resolveDelegatedCommandPath(allocator: std.mem.Allocator, node_install_dir: []const u8, command_name: []const u8) ![]u8 {
    const exts = [_][]const u8{ ".exe", ".cmd", ".bat" };

    for (exts) |ext| {
        const filename = try std.fmt.allocPrint(allocator, "{s}{s}", .{ command_name, ext });
        defer allocator.free(filename);

        const full = try std.fs.path.join(allocator, &.{ node_install_dir, filename });
        errdefer allocator.free(full);

        std.fs.cwd().access(full, .{}) catch {
            allocator.free(full);
            continue;
        };

        return full;
    }

    return error.CommandNotFound;
}

fn enforceDelegatedCommandTrust(
    allocator: std.mem.Allocator,
    cfg: nodeversion.ShimConfig,
    command_name: []const u8,
    command_path: []const u8,
    node_bin: []const u8,
    node_version: []const u8,
    node_install_dir: []const u8,
) !void {
    // Fast path entrypoints (npm-cli.js / npx-cli.js) use the same script-cache
    // trust as *.cmd — node.exe trust alone is never enough (SEC-04).
    if (try resolvePackageManagerCliJs(allocator, node_install_dir, command_name)) |cli_js| {
        defer allocator.free(cli_js);
        const outcome = verifycache.ensureDelegatedScriptTrusted(allocator, cfg.root, cli_js);
        if (outcome.result == .failed) {
            reportDelegatedTrustFailure(
                allocator,
                cfg,
                command_name,
                cli_js,
                node_bin,
                node_version,
                if (outcome.reason.len == 0) "delegated package-manager entrypoint trust verification failed" else outcome.reason,
            );
        }
        return;
    }

    const ext = std.fs.path.extension(command_path);
    if (std.ascii.eqlIgnoreCase(ext, ".exe")) {
        // Same TPM verify-cache as node.exe — never full Authenticode on warm path.
        const outcome = verifycache.ensureResolvedNodeTrusted(allocator, cfg.root, command_path);
        if (outcome.result == .failed) {
            reportDelegatedTrustFailure(
                allocator,
                cfg,
                command_name,
                command_path,
                node_bin,
                node_version,
                if (outcome.reason.len == 0) "delegated executable trust verification failed" else outcome.reason,
            );
        }
        return;
    }

    if (std.ascii.eqlIgnoreCase(ext, ".cmd") or std.ascii.eqlIgnoreCase(ext, ".bat")) {
        const outcome = verifycache.ensureDelegatedScriptTrusted(allocator, cfg.root, command_path);
        if (outcome.result == .failed) {
            reportDelegatedTrustFailure(
                allocator,
                cfg,
                command_name,
                command_path,
                node_bin,
                node_version,
                if (outcome.reason.len == 0) "delegated script trust verification failed" else outcome.reason,
            );
        }
        return;
    }

    reportDelegatedTrustFailure(allocator, cfg, command_name, command_path, node_bin, node_version, "unsupported delegated command type");
}

fn reportDelegatedTrustFailure(
    allocator: std.mem.Allocator,
    cfg: nodeversion.ShimConfig,
    command_name: []const u8,
    command_path: []const u8,
    node_bin: []const u8,
    node_version: []const u8,
    detail: []const u8,
) noreturn {
    const message = std.fmt.allocPrint(
        allocator,
        "NVM4306 Package-manager launch blocked because delegated command trust failed: {s} ({s})",
        .{ command_path, detail },
    ) catch {
        std.debug.print("NVM4306 delegated command trust failed\n", .{});
        std.process.exit(1);
    };
    defer allocator.free(message);
    eventlog.writeLicensedSecurityError(
        allocator,
        cfg.structured_logging,
        "proxy",
        "node.security.verification_failed",
        .{
            .action = "execution_blocked",
            .command = command_name,
            .detail = detail,
            .failure_kind = "delegated_command_trust_failed",
            .node_path = node_bin,
            .node_version = node_version,
            .script_path = command_path,
            .source = "proxy",
            .verification_result = "failed",
        },
        message,
        4306,
    );
    std.debug.print(
        \\NVM blocked package-manager execution because a delegated command could not be trusted.
        \\
        \\Command: {s}
        \\File: {s}
        \\Reason: {s}
        \\Action: Reinstall this Node.js version or run `nvm reshim` after a trusted install.
        \\If this change was unexpected, contact your administrator and review NVM event logs.
        \\Event code: NVM4306
        \\
    , .{ command_name, command_path, detail });
    std.process.exit(1);
}

fn runDelegatedCommand(
    allocator: std.mem.Allocator,
    node_install_dir: []const u8,
    node_bin: []const u8,
    command_name: []const u8,
    command_path: []const u8,
    npm_module_minimum_age: ?u64,
    npm_registry_fallback: ?[]const u8,
    forwarded: []const []const u8,
) !u8 {
    var env_map = try std.process.getEnvMap(allocator);
    defer env_map.deinit();

    const forwarded_args = try filterForwardedArgsForAgePolicy(allocator, command_name, npm_module_minimum_age, forwarded);
    defer allocator.free(forwarded_args);

    const old_path = env_map.get("PATH") orelse "";
    const child_path = try std.fmt.allocPrint(allocator, "{s};{s}", .{ node_install_dir, old_path });
    defer allocator.free(child_path);
    try env_map.put("PATH", child_path);
    try applyPackageManagerMinimumAgeGate(allocator, &env_map, command_name, npm_module_minimum_age);
    try applyPackageManagerRegistryFallback(allocator, &env_map, command_name, forwarded_args, npm_registry_fallback);

    // Fast path: skip cmd.exe + *.cmd wrapper (often doubles Node startup).
    // Entrypoint must already be script-cache trusted in enforceDelegatedCommandTrust.
    if (try resolvePackageManagerCliJs(allocator, node_install_dir, command_name)) |cli_js| {
        defer allocator.free(cli_js);
        return spawnArgv(allocator, &env_map, node_bin, cli_js, forwarded_args);
    }

    const ext = std.fs.path.extension(command_path);
    const use_cmd = std.ascii.eqlIgnoreCase(ext, ".cmd") or std.ascii.eqlIgnoreCase(ext, ".bat");

    if (use_cmd) {
        var argv = try allocator.alloc([]const u8, forwarded_args.len + 4);
        defer allocator.free(argv);
        argv[0] = "cmd.exe";
        argv[1] = "/d";
        argv[2] = "/c";
        argv[3] = command_path;
        for (forwarded_args, 0..) |arg, i| {
            argv[i + 4] = arg;
        }
        return spawnArgvSlice(allocator, &env_map, argv);
    }

    var argv = try allocator.alloc([]const u8, forwarded_args.len + 1);
    defer allocator.free(argv);
    argv[0] = command_path;
    for (forwarded_args, 0..) |arg, i| {
        argv[i + 1] = arg;
    }
    return spawnArgvSlice(allocator, &env_map, argv);
}

fn resolvePackageManagerCliJs(allocator: std.mem.Allocator, node_install_dir: []const u8, command_name: []const u8) !?[]u8 {
    const parts: []const []const u8 = blk: {
        if (std.ascii.eqlIgnoreCase(command_name, "npm")) {
            break :blk &.{ "node_modules", "npm", "bin", "npm-cli.js" };
        }
        if (std.ascii.eqlIgnoreCase(command_name, "npx")) {
            break :blk &.{ "node_modules", "npm", "bin", "npx-cli.js" };
        }
        if (std.ascii.eqlIgnoreCase(command_name, "corepack")) {
            break :blk &.{ "node_modules", "corepack", "dist", "corepack.js" };
        }
        return null;
    };

    var segments = try allocator.alloc([]const u8, parts.len + 1);
    defer allocator.free(segments);
    segments[0] = node_install_dir;
    for (parts, 0..) |part, i| {
        segments[i + 1] = part;
    }

    const full = try std.fs.path.join(allocator, segments);
    errdefer allocator.free(full);

    var file = std.fs.openFileAbsolute(full, .{}) catch {
        allocator.free(full);
        return null;
    };
    file.close();
    return full;
}

fn spawnArgv(
    allocator: std.mem.Allocator,
    env_map: *std.process.EnvMap,
    node_bin: []const u8,
    cli_js: []const u8,
    forwarded_args: []const []const u8,
) !u8 {
    var argv = try allocator.alloc([]const u8, forwarded_args.len + 2);
    defer allocator.free(argv);
    argv[0] = node_bin;
    argv[1] = cli_js;
    for (forwarded_args, 0..) |arg, i| {
        argv[i + 2] = arg;
    }
    return spawnArgvSlice(allocator, env_map, argv);
}

fn spawnArgvSlice(allocator: std.mem.Allocator, env_map: *std.process.EnvMap, argv: []const []const u8) !u8 {
    var child = std.process.Child.init(argv, allocator);
    child.stdin_behavior = .Inherit;
    child.stdout_behavior = .Inherit;
    child.stderr_behavior = .Inherit;
    child.env_map = env_map;

    try child.spawn();
    const term = try child.wait();

    return switch (term) {
        .Exited => |code| code,
        else => 1,
    };
}

fn filterForwardedArgsForAgePolicy(
    allocator: std.mem.Allocator,
    command_name: []const u8,
    npm_module_minimum_age: ?u64,
    forwarded: []const []const u8,
) ![]const []const u8 {
    if (!(std.ascii.eqlIgnoreCase(command_name, "yarn") and (npm_module_minimum_age orelse 0) != 0)) {
        return allocator.dupe([]const u8, forwarded);
    }

    var filtered = std.ArrayListUnmanaged([]const u8){};
    defer filtered.deinit(allocator);

    for (forwarded) |arg| {
        if (std.ascii.eqlIgnoreCase(arg, "--bypass-age-policy")) continue;
        try filtered.append(allocator, arg);
    }

    return filtered.toOwnedSlice(allocator);
}

const PackageManagerAgeGateEnv = struct {
    key: []const u8,
    value: []u8,

    fn deinit(self: PackageManagerAgeGateEnv, allocator: std.mem.Allocator) void {
        allocator.free(self.value);
    }
};

fn applyPackageManagerMinimumAgeGate(
    allocator: std.mem.Allocator,
    env_map: *std.process.EnvMap,
    command_name: []const u8,
    npm_module_minimum_age: ?u64,
) !void {
    const minutes = npm_module_minimum_age orelse return;
    if (minutes == 0) return;

    const age_gate = try buildPackageManagerMinimumAgeGate(allocator, command_name, minutes) orelse return;
    defer age_gate.deinit(allocator);

    try env_map.put(age_gate.key, age_gate.value);
}

fn buildPackageManagerMinimumAgeGate(
    allocator: std.mem.Allocator,
    command_name: []const u8,
    minutes: u64,
) !?PackageManagerAgeGateEnv {
    if (std.ascii.eqlIgnoreCase(command_name, "npm")) {
        const days = (minutes + 1439) / 1440;
        return .{
            .key = "npm_config_min_release_age",
            .value = try std.fmt.allocPrint(allocator, "{d}", .{days}),
        };
    }

    if (std.ascii.eqlIgnoreCase(command_name, "pnpm")) {
        return .{
            .key = "pnpm_config_minimum_release_age",
            .value = try std.fmt.allocPrint(allocator, "{d}", .{minutes}),
        };
    }

    if (std.ascii.eqlIgnoreCase(command_name, "yarn")) {
        return .{
            .key = "YARN_NPM_MINIMAL_AGE_GATE",
            .value = try std.fmt.allocPrint(allocator, "{d}", .{minutes}),
        };
    }

    return null;
}

fn applyPackageManagerRegistryFallback(
    allocator: std.mem.Allocator,
    env_map: *std.process.EnvMap,
    command_name: []const u8,
    forwarded: []const []const u8,
    npm_registry_fallback: ?[]const u8,
) !void {
    const registry_url = npm_registry_fallback orelse return;
    if (!supportsPackageManagerRegistryFallback(command_name)) return;
    if (hasExplicitRegistryArgument(forwarded)) return;
    if (hasInheritedRegistryEnvironment(env_map, command_name)) return;
    if (try configFilesSpecifyRegistry(allocator, env_map, command_name, forwarded)) return;

    try env_map.put("npm_config_registry", registry_url);
    if (std.ascii.eqlIgnoreCase(command_name, "yarn")) {
        try env_map.put("YARN_NPM_REGISTRY_SERVER", registry_url);
    }
}

fn supportsPackageManagerRegistryFallback(command_name: []const u8) bool {
    return std.ascii.eqlIgnoreCase(command_name, "npm") or
        std.ascii.eqlIgnoreCase(command_name, "npx") or
        std.ascii.eqlIgnoreCase(command_name, "pnpm") or
        std.ascii.eqlIgnoreCase(command_name, "yarn");
}

fn hasExplicitRegistryArgument(args: []const []const u8) bool {
    var i: usize = 0;
    while (i < args.len) {
        const arg = std.mem.trim(u8, args[i], " \t\r\n");

        if (std.mem.eql(u8, arg, "--registry") or
            std.mem.eql(u8, arg, "--npm-registry-server") or
            std.mem.eql(u8, arg, "--npmRegistryServer"))
        {
            if (i + 1 < args.len and std.mem.trim(u8, args[i + 1], " \t\r\n").len > 0) {
                return true;
            }
        }

        if (flagWithValue(arg, "--registry=") or
            flagWithValue(arg, "--npm-registry-server=") or
            flagWithValue(arg, "--npmRegistryServer="))
        {
            return true;
        }

        i += 1;
    }

    return false;
}

fn flagWithValue(arg: []const u8, prefix: []const u8) bool {
    if (!std.mem.startsWith(u8, arg, prefix)) return false;
    return std.mem.trim(u8, arg[prefix.len..], " \t\r\n").len > 0;
}

fn hasInheritedRegistryEnvironment(env_map: *std.process.EnvMap, command_name: []const u8) bool {
    if (envMapHasValue(env_map, "npm_config_registry") or envMapHasValue(env_map, "NPM_CONFIG_REGISTRY")) {
        return true;
    }

    if (std.ascii.eqlIgnoreCase(command_name, "yarn")) {
        if (envMapHasValue(env_map, "YARN_NPM_REGISTRY_SERVER") or envMapHasValue(env_map, "yarn_npm_registry_server")) {
            return true;
        }
    }

    return false;
}

fn envMapHasValue(env_map: *std.process.EnvMap, key: []const u8) bool {
    const value = env_map.get(key) orelse return false;
    return std.mem.trim(u8, value, " \t\r\n").len > 0;
}

fn configFilesSpecifyRegistry(
    allocator: std.mem.Allocator,
    env_map: *std.process.EnvMap,
    command_name: []const u8,
    forwarded: []const []const u8,
) !bool {
    if (try explicitConfigArgumentsSpecifyRegistry(allocator, command_name, forwarded)) return true;
    if (try explicitConfigEnvironmentSpecifiesRegistry(allocator, env_map, command_name)) return true;

    const cwd = try std.fs.cwd().realpathAlloc(allocator, ".");
    defer allocator.free(cwd);
    if (try directoryTreeSpecifiesRegistry(allocator, cwd, command_name)) return true;

    if (try userHomeConfigSpecifiesRegistry(allocator, env_map, command_name)) return true;

    return false;
}

fn explicitConfigArgumentsSpecifyRegistry(allocator: std.mem.Allocator, command_name: []const u8, args: []const []const u8) !bool {
    var i: usize = 0;
    while (i < args.len) {
        const arg = std.mem.trim(u8, args[i], " \t\r\n");

        if (std.mem.eql(u8, arg, "--userconfig") or std.mem.eql(u8, arg, "--globalconfig")) {
            if (i + 1 < args.len and try npmRcPathSpecifiesRegistry(allocator, args[i + 1])) {
                return true;
            }
        }

        if (std.mem.startsWith(u8, arg, "--userconfig=") and try npmRcPathSpecifiesRegistry(allocator, arg[13..])) {
            return true;
        }

        if (std.mem.startsWith(u8, arg, "--globalconfig=") and try npmRcPathSpecifiesRegistry(allocator, arg[15..])) {
            return true;
        }

        if (std.ascii.eqlIgnoreCase(command_name, "yarn") and
            ((std.mem.eql(u8, arg, "--use-yarnrc") and i + 1 < args.len and try yarnRcPathSpecifiesRegistry(allocator, args[i + 1])) or
                (std.mem.startsWith(u8, arg, "--use-yarnrc=") and try yarnRcPathSpecifiesRegistry(allocator, arg[13..]))))
        {
            return true;
        }

        i += 1;
    }

    return false;
}

fn explicitConfigEnvironmentSpecifiesRegistry(
    allocator: std.mem.Allocator,
    env_map: *std.process.EnvMap,
    command_name: []const u8,
) !bool {
    const npm_config_paths = [_][]const u8{
        "npm_config_userconfig",
        "NPM_CONFIG_USERCONFIG",
        "npm_config_globalconfig",
        "NPM_CONFIG_GLOBALCONFIG",
    };

    for (npm_config_paths) |key| {
        if (env_map.get(key)) |value| {
            if (try npmRcPathSpecifiesRegistry(allocator, value)) {
                return true;
            }
        }
    }

    if (std.ascii.eqlIgnoreCase(command_name, "yarn")) {
        const yarn_config_paths = [_][]const u8{ "YARN_RC_FILENAME", "yarn_rc_filename" };
        for (yarn_config_paths) |key| {
            if (env_map.get(key)) |value| {
                if (try yarnRcPathSpecifiesRegistry(allocator, value)) {
                    return true;
                }
            }
        }
    }

    return false;
}

fn userHomeConfigSpecifiesRegistry(
    allocator: std.mem.Allocator,
    env_map: *std.process.EnvMap,
    command_name: []const u8,
) !bool {
    const home = env_map.get("USERPROFILE") orelse env_map.get("HOME") orelse return false;
    return directorySpecifiesRegistry(allocator, home, command_name);
}

fn directoryTreeSpecifiesRegistry(allocator: std.mem.Allocator, start_dir: []const u8, command_name: []const u8) !bool {
    var current = try allocator.dupe(u8, start_dir);
    defer allocator.free(current);

    while (true) {
        if (try directorySpecifiesRegistry(allocator, current, command_name)) {
            return true;
        }

        const parent = std.fs.path.dirname(current) orelse break;
        if (std.mem.eql(u8, parent, current)) break;

        const next = try allocator.dupe(u8, parent);
        allocator.free(current);
        current = next;
    }

    return false;
}

fn directorySpecifiesRegistry(allocator: std.mem.Allocator, directory: []const u8, command_name: []const u8) !bool {
    const npmrc_path = try std.fs.path.join(allocator, &.{ directory, ".npmrc" });
    defer allocator.free(npmrc_path);
    if (try npmRcPathSpecifiesRegistry(allocator, npmrc_path)) {
        return true;
    }

    if (std.ascii.eqlIgnoreCase(command_name, "yarn")) {
        const yarnrc_path = try std.fs.path.join(allocator, &.{ directory, ".yarnrc.yml" });
        defer allocator.free(yarnrc_path);
        if (try yarnRcPathSpecifiesRegistry(allocator, yarnrc_path)) {
            return true;
        }
    }

    return false;
}

fn npmRcPathSpecifiesRegistry(allocator: std.mem.Allocator, path: []const u8) !bool {
    const trimmed = std.mem.trim(u8, path, " \t\r\n\"");
    if (trimmed.len == 0) return false;
    const content = try readTextFileIfPresent(allocator, trimmed) orelse return false;
    defer allocator.free(content);
    return npmRcSpecifiesRegistry(content);
}

fn yarnRcPathSpecifiesRegistry(allocator: std.mem.Allocator, path: []const u8) !bool {
    const trimmed = std.mem.trim(u8, path, " \t\r\n\"");
    if (trimmed.len == 0) return false;
    const content = try readTextFileIfPresent(allocator, trimmed) orelse return false;
    defer allocator.free(content);
    return yarnRcSpecifiesRegistry(content);
}

fn readTextFileIfPresent(allocator: std.mem.Allocator, path: []const u8) !?[]u8 {
    const max_bytes = 1024 * 1024;

    if (std.fs.path.isAbsolute(path)) {
        const file = std.fs.openFileAbsolute(path, .{}) catch return null;
        defer file.close();
        return try file.readToEndAlloc(allocator, max_bytes);
    }

    const file = std.fs.cwd().openFile(path, .{}) catch return null;
    defer file.close();
    return try file.readToEndAlloc(allocator, max_bytes);
}

fn npmRcSpecifiesRegistry(content: []const u8) bool {
    var lines = std.mem.splitScalar(u8, content, '\n');
    while (lines.next()) |raw_line| {
        const line = std.mem.trim(u8, raw_line, " \t\r\n");
        if (line.len == 0 or line[0] == '#' or line[0] == ';') continue;

        const eq = std.mem.indexOfScalar(u8, line, '=') orelse continue;
        const key = std.mem.trim(u8, line[0..eq], " \t");
        const value = std.mem.trim(u8, line[eq + 1 ..], " \t\"'");
        if (value.len == 0) continue;

        if (std.ascii.eqlIgnoreCase(key, "registry") or asciiEndsWithIgnoreCase(key, ":registry")) {
            return true;
        }
    }

    return false;
}

fn yarnRcSpecifiesRegistry(content: []const u8) bool {
    var lines = std.mem.splitScalar(u8, content, '\n');
    while (lines.next()) |raw_line| {
        const line = std.mem.trim(u8, raw_line, " \t\r\n");
        if (line.len == 0 or line[0] == '#') continue;

        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        const key = std.mem.trim(u8, line[0..colon], " \t");
        const value = std.mem.trim(u8, line[colon + 1 ..], " \t\"'");
        if (value.len == 0) continue;

        if (std.ascii.eqlIgnoreCase(key, "npmRegistryServer")) {
            return true;
        }
    }

    return false;
}

fn asciiEndsWithIgnoreCase(value: []const u8, suffix: []const u8) bool {
    if (value.len < suffix.len) return false;
    return std.ascii.eqlIgnoreCase(value[value.len - suffix.len ..], suffix);
}

fn runReshim(allocator: std.mem.Allocator, install_root: []const u8, node_install_dir: []const u8) void {
    const reshim_path = std.fs.path.resolve(allocator, &.{ install_root, "..", "utils", "reshim.exe" }) catch return;
    defer allocator.free(reshim_path);

    std.fs.cwd().access(reshim_path, .{}) catch return;

    var child = std.process.Child.init(&.{ reshim_path, node_install_dir }, allocator);
    child.stdin_behavior = .Ignore;
    child.stdout_behavior = .Ignore;
    child.stderr_behavior = .Ignore;

    // Detached on purpose: npm/yarn global install already finished; reshim
    // must outlive proxy.exe. reshim.exe binds a kill-on-close job so its
    // own children cannot leak after it exits.
    child.spawn() catch return;
}

fn parseArgs(allocator: std.mem.Allocator, args: []const []const u8) !ParsedArgs {
    var forwarded = std.ArrayListUnmanaged([]const u8){};
    defer forwarded.deinit(allocator);

    var override_version: ?[]const u8 = null;
    var nvm_use_debug = false;

    var i: usize = 0;
    while (i < args.len) {
        const arg = args[i];

        if (std.mem.eql(u8, arg, "--nvm-use")) {
            if (i + 1 >= args.len) return error.InvalidNvmUseFlag;
            const next = std.mem.trim(u8, args[i + 1], " \t\r\n");
            if (next.len == 0) return error.InvalidNvmUseFlag;
            override_version = next;
            i += 2;
            continue;
        }

        if (std.mem.eql(u8, arg, "--nvm-which")) {
            nvm_use_debug = true;
            i += 1;
            continue;
        }

        const eq_prefix = "--nvm-use=";
        if (std.mem.startsWith(u8, arg, eq_prefix)) {
            const raw = std.mem.trim(u8, arg[eq_prefix.len..], " \t\r\n");
            if (raw.len == 0) return error.InvalidNvmUseFlag;
            override_version = raw;
            i += 1;
            continue;
        }

        try forwarded.append(allocator, arg);
        i += 1;
    }

    return .{
        .override_version = override_version,
        .nvm_use_debug = nvm_use_debug,
        .forwarded = try forwarded.toOwnedSlice(allocator),
    };
}

/// Returns true when the invoked package manager command is likely to install
/// or remove a globally-visible executable that reshim needs to reconcile.
fn detectReshimNeeded(command_name: []const u8, args: []const []const u8) bool {
    if (std.ascii.eqlIgnoreCase(command_name, "npm") or
        std.ascii.eqlIgnoreCase(command_name, "pnpm") or
        std.ascii.eqlIgnoreCase(command_name, "vlt"))
    {
        return npmOrPnpmNeedsReshim(args);
    }

    if (std.ascii.eqlIgnoreCase(command_name, "yarn")) {
        return yarnNeedsReshim(args);
    }

    if (std.ascii.eqlIgnoreCase(command_name, "corepack")) {
        return corepackNeedsReshim(args);
    }

    return false;
}

/// npm/pnpm: reshim when -g / --global is present anywhere in the args.
/// Handles concatenated short flags like -ig, -gD, etc.
fn npmOrPnpmNeedsReshim(args: []const []const u8) bool {
    for (args) |arg| {
        if (std.mem.eql(u8, arg, "--global")) return true;

        // short flags: starts with '-' but not '--'
        if (arg.len >= 2 and arg[0] == '-' and arg[1] != '-') {
            for (arg[1..]) |ch| {
                if (ch == 'g') return true;
            }
        }
    }
    return false;
}

/// yarn: reshim on `global`, `dlx`, `plugins import`, `set version` commands.
fn yarnNeedsReshim(args: []const []const u8) bool {
    if (args.len == 0) return false;

    const cmd = args[0];

    if (std.ascii.eqlIgnoreCase(cmd, "global")) return true;
    if (std.ascii.eqlIgnoreCase(cmd, "dlx")) return true;

    if (std.ascii.eqlIgnoreCase(cmd, "plugins") and args.len >= 2 and
        std.ascii.eqlIgnoreCase(args[1], "import")) return true;

    if (std.ascii.eqlIgnoreCase(cmd, "set") and args.len >= 2 and
        std.ascii.eqlIgnoreCase(args[1], "version")) return true;

    return false;
}

/// corepack: reshim on enable, disable, prepare, hydrate, use commands.
fn corepackNeedsReshim(args: []const []const u8) bool {
    if (args.len == 0) return false;

    const cmd = args[0];
    const reshim_cmds = [_][]const u8{ "enable", "disable", "prepare", "hydrate", "use" };
    for (reshim_cmds) |rc| {
        if (std.ascii.eqlIgnoreCase(cmd, rc)) return true;
    }
    return false;
}

test "parseArgs strips nvm which flag" {
    const allocator = std.testing.allocator;
    const parsed = try parseArgs(allocator, &.{ "--nvm-which", "install", "-g", "pnpm" });
    defer allocator.free(parsed.forwarded);

    try std.testing.expect(parsed.override_version == null);
    try std.testing.expect(parsed.nvm_use_debug);
    try std.testing.expectEqual(@as(usize, 3), parsed.forwarded.len);
    try std.testing.expectEqualStrings("install", parsed.forwarded[0]);
    try std.testing.expectEqualStrings("-g", parsed.forwarded[1]);
    try std.testing.expectEqualStrings("pnpm", parsed.forwarded[2]);
}

test "parseArgs supports nvm use override forms" {
    const allocator = std.testing.allocator;

    const parsed_space = try parseArgs(allocator, &.{ "--nvm-use", "20.18.0", "install", "-g", "pnpm" });
    defer allocator.free(parsed_space.forwarded);
    try std.testing.expectEqualStrings("20.18.0", parsed_space.override_version.?);
    try std.testing.expect(!parsed_space.nvm_use_debug);
    try std.testing.expectEqual(@as(usize, 3), parsed_space.forwarded.len);
    try std.testing.expectEqualStrings("install", parsed_space.forwarded[0]);
    try std.testing.expectEqualStrings("-g", parsed_space.forwarded[1]);
    try std.testing.expectEqualStrings("pnpm", parsed_space.forwarded[2]);

    const parsed_eq = try parseArgs(allocator, &.{ "--nvm-use=22.1.0", "--nvm-which", "corepack", "enable" });
    defer allocator.free(parsed_eq.forwarded);
    try std.testing.expectEqualStrings("22.1.0", parsed_eq.override_version.?);
    try std.testing.expect(parsed_eq.nvm_use_debug);
    try std.testing.expectEqual(@as(usize, 2), parsed_eq.forwarded.len);
    try std.testing.expectEqualStrings("corepack", parsed_eq.forwarded[0]);
    try std.testing.expectEqualStrings("enable", parsed_eq.forwarded[1]);
}

test "parseArgs rejects invalid nvm use flag" {
    const allocator = std.testing.allocator;

    try std.testing.expectError(error.InvalidNvmUseFlag, parseArgs(allocator, &.{"--nvm-use"}));
    try std.testing.expectError(error.InvalidNvmUseFlag, parseArgs(allocator, &.{ "--nvm-use", "   " }));
    try std.testing.expectError(error.InvalidNvmUseFlag, parseArgs(allocator, &.{"--nvm-use="}));
}

test "buildPackageManagerMinimumAgeGate emits npm, pnpm, and yarn formats" {
    const allocator = std.testing.allocator;

    // npm: minutes rounded up to days, plain integer
    const npm_gate_exact = (try buildPackageManagerMinimumAgeGate(allocator, "npm", 1440)).?;
    defer npm_gate_exact.deinit(allocator);
    try std.testing.expectEqualStrings("npm_config_min_release_age", npm_gate_exact.key);
    try std.testing.expectEqualStrings("1", npm_gate_exact.value);

    const npm_gate_round = (try buildPackageManagerMinimumAgeGate(allocator, "npm", 10081)).?;
    defer npm_gate_round.deinit(allocator);
    try std.testing.expectEqualStrings("8", npm_gate_round.value);
}

test "buildPackageManagerMinimumAgeGate emits pnpm and yarn formats" {
    const allocator = std.testing.allocator;

    const pnpm_gate = (try buildPackageManagerMinimumAgeGate(allocator, "pnpm", 1440)).?;
    defer pnpm_gate.deinit(allocator);
    try std.testing.expectEqualStrings("pnpm_config_minimum_release_age", pnpm_gate.key);
    try std.testing.expectEqualStrings("1440", pnpm_gate.value);

    const yarn_gate = (try buildPackageManagerMinimumAgeGate(allocator, "yarn", 1440)).?;
    defer yarn_gate.deinit(allocator);
    try std.testing.expectEqualStrings("YARN_NPM_MINIMAL_AGE_GATE", yarn_gate.key);
    try std.testing.expectEqualStrings("1440", yarn_gate.value);
}

test "hasExplicitRegistryArgument detects registry flags" {
    try std.testing.expect(hasExplicitRegistryArgument(&.{ "install", "--registry", "https://registry.example.test" }));
    try std.testing.expect(hasExplicitRegistryArgument(&.{ "add", "--registry=https://registry.example.test" }));
    try std.testing.expect(hasExplicitRegistryArgument(&.{ "add", "--npm-registry-server", "https://registry.example.test" }));
    try std.testing.expect(hasExplicitRegistryArgument(&.{ "add", "--npmRegistryServer=https://registry.example.test" }));
    try std.testing.expect(!hasExplicitRegistryArgument(&.{ "install", "left-pad" }));
}

test "npmRcSpecifiesRegistry recognizes registry entries" {
    try std.testing.expect(npmRcSpecifiesRegistry("registry=https://registry.example.test\n"));
    try std.testing.expect(npmRcSpecifiesRegistry("@author:registry=https://registry.example.test\n"));
    try std.testing.expect(!npmRcSpecifiesRegistry("# registry=https://registry.example.test\n"));
    try std.testing.expect(!npmRcSpecifiesRegistry("strict-ssl=true\n"));
}

test "yarnRcSpecifiesRegistry recognizes npm registry server" {
    try std.testing.expect(yarnRcSpecifiesRegistry("npmRegistryServer: \"https://registry.example.test\"\n"));
    try std.testing.expect(yarnRcSpecifiesRegistry("npmScopes:\n  author:\n    npmRegistryServer: https://registry.example.test\n"));
    try std.testing.expect(!yarnRcSpecifiesRegistry("enableGlobalCache: true\n"));
}

test "directoryTreeSpecifiesRegistry finds project npmrc in parent" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("workspace\\project\\child");
    try tmp.dir.writeFile(.{ .sub_path = "workspace\\project\\.npmrc", .data = "registry=https://registry.example.test\n" });

    const cwd = try tmp.dir.realpathAlloc(allocator, "workspace\\project\\child");
    defer allocator.free(cwd);

    try std.testing.expect(try directoryTreeSpecifiesRegistry(allocator, cwd, "npm"));
}

test "filterForwardedArgsForAgePolicy strips yarn bypass flag when minutes is non-zero" {
    const allocator = std.testing.allocator;
    const original = [_][]const u8{ "add", "left-pad", "--bypass-age-policy", "--dev", "--BYPASS-AGE-POLICY" };

    const filtered = try filterForwardedArgsForAgePolicy(allocator, "yarn", 1440, &original);
    defer allocator.free(filtered);

    try std.testing.expectEqual(@as(usize, 3), filtered.len);
    try std.testing.expectEqualStrings("add", filtered[0]);
    try std.testing.expectEqualStrings("left-pad", filtered[1]);
    try std.testing.expectEqualStrings("--dev", filtered[2]);
}

test "filterForwardedArgsForAgePolicy keeps yarn bypass flag when minutes is zero or missing" {
    const allocator = std.testing.allocator;
    const original = [_][]const u8{ "add", "--bypass-age-policy" };

    const missing = try filterForwardedArgsForAgePolicy(allocator, "yarn", null, &original);
    defer allocator.free(missing);
    try std.testing.expectEqual(@as(usize, 2), missing.len);
    try std.testing.expectEqualStrings("--bypass-age-policy", missing[1]);

    const zero = try filterForwardedArgsForAgePolicy(allocator, "yarn", 0, &original);
    defer allocator.free(zero);
    try std.testing.expectEqual(@as(usize, 2), zero.len);
    try std.testing.expectEqualStrings("--bypass-age-policy", zero[1]);
}
