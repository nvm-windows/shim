const std = @import("std");
const build_options = @import("build_options");
const nodeversion = @import("nodeversion");
const resolver = @import("resolver");
const eventlog = @import("eventlog");
const errors = @import("errors");
const shimintegrity = @import("shimintegrity");
const verifycache = @import("verifycache");
const version_firewall = @import("version_firewall");
const install_safety = @import("install_safety");
const module_firewall = @import("module_firewall");
const config = @import("config");
const registry = @import("registry");
const cmd_spawn = @import("cmd_spawn");
const malware_scan = @import("malware_scan.zig");
const bun_lane = @import("bun_lane.zig");

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

    try bun_lane.runIfBun(allocator, cfg, command_name, parsed_args.forwarded);

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
        error.OutOfMemory => return err,
    };

    if (parsed_args.nvm_use_debug) {
        std.debug.print(
            "nvm version resolution: source={s} requested={s} effective={s} resolved={s} node={s}\n",
            .{ resolved.version_source, resolved.requested_version, resolved.effective_version, resolved.resolved_version.?, resolved.node_bin.? },
        );
    }

    var audit_ctx = eventlog.captureAuditContext(allocator);
    defer audit_ctx.deinit(allocator);

    switch (try version_firewall.evaluate(allocator, resolved.resolved_version.?, build_options.certified)) {
        .allow => {},
        .deny => |denied| {
            const message = try std.fmt.allocPrint(
                allocator,
                "NVM4411 Node.js v{s} blocked by version firewall ({s})",
                .{ denied.version, denied.source },
            );
            defer allocator.free(message);
            eventlog.writeLicensedSecurityError(
                allocator,
                cfg.structured_logging,
                "proxy",
                "node.security.version_firewall_blocked",
                .{
                    .action = "execution_blocked",
                    .command = command_name,
                    .detail = denied.source,
                    .failure_kind = "version_firewall",
                    .node_version = denied.version,
                    .source = "proxy",
                    .user = audit_ctx.user,
                    .sid = audit_ctx.sid,
                    .hostname = audit_ctx.hostname,
                    .parent_process = audit_ctx.parent_process,
                    .parent_pid = audit_ctx.parent_pid,
                    .project_name = audit_ctx.project_name,
                    .project_path = audit_ctx.project_path,
                },
                message,
                4411,
            );
            errors.versionFirewallBlocked(denied.version, denied.source);
        },
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
                .user = audit_ctx.user,
                .sid = audit_ctx.sid,
                .hostname = audit_ctx.hostname,
                .parent_process = audit_ctx.parent_process,
                .parent_pid = audit_ctx.parent_pid,
                .project_name = audit_ctx.project_name,
                .project_path = audit_ctx.project_path,
            },
            message,
            4305,
        );
        std.debug.print(
            \\NVM blocked package-manager execution because the Node.js directory is unsafe.
            \\
            \\Path: {s}
            \\Reason: {s}
            \\Action: Run `nvm doctor --autofix` (elevation prompted if needed), or use a private root under %LOCALAPPDATA%.
            \\If this change was unexpected, contact your administrator and review NVM event logs.
            \\Event code: NVM4305
            \\
        , .{ node_install_dir_abs, detail });
        std.process.exit(1);
    };

    const command_path = resolveDelegatedOrCorepackPath(
        allocator,
        node_install_dir_abs,
        command_name,
        resolved.resolved_version.?,
    ) catch |err| switch (err) {
        error.CommandNotFound => std.process.exit(1),
        else => return err,
    };
    defer allocator.free(command_path);

    if (!try enforcePackageManagerConstraint(allocator, cfg, resolved.version_source, command_name, resolved.node_bin.?, command_path)) {
        std.process.exit(1);
    }

    const verify_outcome = verifycache.ensureResolvedNodeTrusted(allocator, cfg.root, resolved.node_bin.?, resolved.resolved_version.?);
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
                        .user = audit_ctx.user,
                        .sid = audit_ctx.sid,
                        .hostname = audit_ctx.hostname,
                        .parent_process = audit_ctx.parent_process,
                        .parent_pid = audit_ctx.parent_pid,
                        .project_name = audit_ctx.project_name,
                        .project_path = audit_ctx.project_path,
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
                        .user = audit_ctx.user,
                        .sid = audit_ctx.sid,
                        .hostname = audit_ctx.hostname,
                        .parent_process = audit_ctx.parent_process,
                        .parent_pid = audit_ctx.parent_pid,
                        .project_name = audit_ctx.project_name,
                        .project_path = audit_ctx.project_path,
                    },
                    recovery_message,
                    4304,
                );
            }
        },
        .version_mismatch => {
            const actual = if (verify_outcome.reason.len == 0) "missing" else verify_outcome.reason;
            const message = try std.fmt.allocPrint(
                allocator,
                "NVM4314 Node.js execution blocked because FileVersion {s} does not match folder {s}: {s}",
                .{ actual, resolved.resolved_version.?, resolved.node_bin.? },
            );
            defer allocator.free(message);
            eventlog.writeLicensedSecurityError(
                allocator,
                cfg.structured_logging,
                "proxy",
                "node.security.version_mismatch",
                .{
                    .action = "execution_blocked",
                    .cache_status = @tagName(verify_outcome.cache_status),
                    .command = command_name,
                    .detail = actual,
                    .failure_kind = "file_version_mismatch",
                    .node_path = resolved.node_bin.?,
                    .node_version = resolved.resolved_version.?,
                    .source = "proxy",
                    .verification_result = "version_mismatch",
                    .user = audit_ctx.user,
                    .sid = audit_ctx.sid,
                    .hostname = audit_ctx.hostname,
                    .parent_process = audit_ctx.parent_process,
                    .parent_pid = audit_ctx.parent_pid,
                    .project_name = audit_ctx.project_name,
                    .project_path = audit_ctx.project_path,
                },
                message,
                4314,
            );
            errors.nodeVersionMismatch(resolved.node_bin.?, resolved.resolved_version.?, actual);
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
                    .user = audit_ctx.user,
                    .sid = audit_ctx.sid,
                    .hostname = audit_ctx.hostname,
                    .parent_process = audit_ctx.parent_process,
                    .parent_pid = audit_ctx.parent_pid,
                    .project_name = audit_ctx.project_name,
                    .project_path = audit_ctx.project_path,
                },
                message,
                4301,
            );
            nodeVerifyFailed(resolved.node_bin.?, resolved.resolved_version.?, verify_outcome.reason);
        },
    }

    try enforceDelegatedCommandTrust(allocator, cfg, command_name, command_path, resolved.node_bin.?, resolved.resolved_version.?, node_install_dir_abs);

    var bare_install = false;
    const npm_module_minimum_age = nodeversion.effectiveNpmModuleMinimumAge(cfg.npm_module_minimum_age, build_options.certified);
    const npm_module_minimum_age_forced = cfg.npm_module_minimum_age_machine_policy;
    const pm_ctx = PmCtx{
        .allocator = allocator,
        .node_install_dir = node_install_dir_abs,
        .node_bin = resolved.node_bin.?,
        .command_name = command_name,
        .command_path = command_path,
        .npm_module_minimum_age = npm_module_minimum_age,
        .npm_module_minimum_age_forced = npm_module_minimum_age_forced,
        .npm_registry_fallback = cfg.npm_registry_fallback,
        .block_lifecycle_scripts = cfg.block_package_manager_lifecycle_scripts,
    };
    try malware_scan.enforce(
        allocator,
        cfg.structured_logging,
        command_name,
        parsed_args.forwarded,
        cfg.root,
        .{ .ctx = @ptrCast(@constCast(&pm_ctx)), .run = runPm },
        &bare_install,
    );

    try enforceModuleFirewall(allocator, cfg.structured_logging, command_name, parsed_args.forwarded);

    const needs_reshim = detectReshimNeeded(command_name, parsed_args.forwarded);

    const snap_before = captureEntrypointSnapSet(allocator, command_path, command_name);
    defer snap_before.deinit(allocator);

    if (cfg.log_executions and build_options.certified) {
        const arguments = if (parsed_args.forwarded.len == 0)
            try allocator.dupe(u8, "")
        else
            try std.mem.join(allocator, " ", parsed_args.forwarded);
        defer allocator.free(arguments);

        const working_directory = std.process.getCwdAlloc(allocator) catch try allocator.dupe(u8, "");
        defer allocator.free(working_directory);

        eventlog.writeStructuredInfoCode(allocator, "proxy", "package_manager.executed", .{
            .command = command_name,
            .node_version = resolved.resolved_version.?,
            .node_path = resolved.node_bin.?,
            .working_directory = working_directory,
            .arguments = arguments,
            .user = audit_ctx.user,
            .sid = audit_ctx.sid,
            .hostname = audit_ctx.hostname,
            .parent_process = audit_ctx.parent_process,
            .parent_pid = audit_ctx.parent_pid,
            .project_name = audit_ctx.project_name,
            .project_path = audit_ctx.project_path,
        }, 0);
    }

    const forwarded = if (bare_install) dropPackageArgs(allocator, parsed_args.forwarded) else parsed_args.forwarded;
    const process_exit_code = runDelegatedCommand(
        allocator,
        node_install_dir_abs,
        resolved.node_bin.?,
        command_name,
        command_path,
        npm_module_minimum_age,
        npm_module_minimum_age_forced,
        cfg.npm_registry_fallback,
        cfg.block_package_manager_lifecycle_scripts,
        forwarded,
    ) catch |err| blk: {
        std.debug.print("proxy failed to run {s}: {s}\n", .{ command_name, @errorName(err) });
        break :blk 1;
    };

    if (process_exit_code == 0 and isNpmAuthCommand(command_name, parsed_args.forwarded)) {
        maybeRefreshNpmIdentity(allocator);
    }

    // std.debug.print("{s}\n", .{node_install_dir});

    if (needs_reshim) {
        eventlog.writeInfo(allocator, "proxy", "reshim scheduled");
        runReshim(allocator, cfg.root, node_install_dir_abs, userInitiatedPmReshim(allocator, cfg.root, cfg.structured_logging));
    } else {
        try maybeReshimAfterSelfUpdate(allocator, cfg.root, node_install_dir_abs, command_name, command_path, snap_before, cfg.structured_logging);
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

fn resolveCommandInDir(allocator: std.mem.Allocator, dir_path: []const u8, command_name: []const u8) !?[]u8 {
    const exts = [_][]const u8{ ".exe", ".cmd", ".bat" };

    for (exts) |ext| {
        const filename = try std.fmt.allocPrint(allocator, "{s}{s}", .{ command_name, ext });
        defer allocator.free(filename);

        const full = try std.fs.path.join(allocator, &.{ dir_path, filename });
        errdefer allocator.free(full);

        std.fs.cwd().access(full, .{}) catch {
            allocator.free(full);
            continue;
        };

        return full;
    }

    return null;
}

fn yarnClassicGlobalBinDir(allocator: std.mem.Allocator) !?[]u8 {
    const local = std.process.getEnvVarOwned(allocator, "LOCALAPPDATA") catch return null;
    defer allocator.free(local);
    if (local.len == 0) return null;
    return try std.fs.path.join(allocator, &.{ local, "Yarn", "bin" });
}

fn resolveYarnClassicGlobalCommand(allocator: std.mem.Allocator, command_name: []const u8) !?[]u8 {
    const bin = try yarnClassicGlobalBinDir(allocator) orelse return null;
    defer allocator.free(bin);
    return resolveCommandInDir(allocator, bin, command_name);
}

fn resolveDelegatedCommandPath(allocator: std.mem.Allocator, node_install_dir: []const u8, command_name: []const u8) ![]u8 {
    return (try resolveCommandInDir(allocator, node_install_dir, command_name)) orelse error.CommandNotFound;
}

fn resolveDelegatedOrCorepackPath(
    allocator: std.mem.Allocator,
    node_install_dir: []const u8,
    command_name: []const u8,
    node_version: []const u8,
) ![]u8 {
    if (isCorepackBackedCommand(command_name)) {
        return resolveCorepackBackedCommand(allocator, node_install_dir, command_name);
    }
    if (std.ascii.eqlIgnoreCase(command_name, "corepack")) {
        return resolveCorepackCommand(allocator, node_install_dir, node_version);
    }

    if (try resolveCommandInDir(allocator, node_install_dir, command_name)) |path| {
        return path;
    }
    if (try resolveYarnClassicGlobalCommand(allocator, command_name)) |path| {
        return path;
    }
    return error.CommandNotFound;
}

fn resolveCorepackCommand(allocator: std.mem.Allocator, node_install_dir: []const u8, node_version: []const u8) ![]u8 {
    if (resolveDelegatedCommandPath(allocator, node_install_dir, "corepack")) |path| {
        return path;
    } else |err| switch (err) {
        error.CommandNotFound => {
            reportMissingCorepack(node_version);
            return error.CommandNotFound;
        },
        else => return err,
    }
}

const LauncherClass = union(enum) {
    package_js: []u8,
    corepack_trampoline,
    reject,
};

/// yarn/yarnpkg/pnpm. A `{name}.exe` next to Node (or in the npm prefix /
/// PNPM_HOME\bin for pnpm) is the native binary. Authenticode must match.
/// Do not fall through to JS when that .exe exists.
///
/// If no `{name}.exe`, treat the npm global the same as other module CLIs:
/// follow the `.cmd` into `node_modules\<pkg>\` (js/cjs/mjs or extensionless
/// script). Corepack is last, and only when no module entry exists.
/// npm, npx, and corepack do not come through here.
fn resolveCorepackBackedCommand(allocator: std.mem.Allocator, node_install_dir: []const u8, command_name: []const u8) ![]u8 {
    if (try resolveNativeCommandExe(allocator, node_install_dir, command_name)) |exe| {
        return exe;
    }

    const package_name = npmGlobalPackageName(command_name);
    var skip_prefix = false;
    if (try findLauncherCmd(allocator, node_install_dir, command_name)) |cmd_path| {
        defer allocator.free(cmd_path);
        switch (try classifyPackageLauncher(allocator, cmd_path, package_name)) {
            .package_js => |js_path| return js_path,
            .corepack_trampoline => skip_prefix = true,
            .reject => {},
        }
    }

    if (!skip_prefix) {
        if (try resolvePackageModuleEntry(allocator, node_install_dir, package_name, command_name)) |entry| {
            return entry;
        }
        if (try resolveNpmPrefixPackageJs(allocator, node_install_dir, command_name)) |js_path| {
            return js_path;
        }
        if (try resolveNpmPrefixModuleEntry(allocator, node_install_dir, command_name)) |entry| {
            return entry;
        }
    }

    if (try resolveCorepackJs(allocator, node_install_dir)) |corepack_js| {
        return corepack_js;
    }

    reportMissingPackageManager(command_name);
    return error.CommandNotFound;
}

fn npmGlobalPackageName(command_name: []const u8) []const u8 {
    if (std.ascii.eqlIgnoreCase(command_name, "pnpm")) return "pnpm";
    return "yarn";
}

fn resolveVersionDirExecutable(allocator: std.mem.Allocator, node_install_dir: []const u8, command_name: []const u8) !?[]u8 {
    const filename = try std.fmt.allocPrint(allocator, "{s}.exe", .{command_name});
    defer allocator.free(filename);
    const full = try std.fs.path.join(allocator, &.{ node_install_dir, filename });
    errdefer allocator.free(full);
    std.fs.cwd().access(full, .{}) catch {
        allocator.free(full);
        return null;
    };
    return full;
}

/// `{command}.exe` only. `.cmd`/`.ps1` stay off PATH; they are pointers, not the CLI.
fn resolveNativeCommandExe(allocator: std.mem.Allocator, node_install_dir: []const u8, command_name: []const u8) !?[]u8 {
    if (try resolveVersionDirExecutable(allocator, node_install_dir, command_name)) |exe| {
        return exe;
    }
    if (try npmGlobalPrefix(allocator, node_install_dir)) |prefix| {
        defer allocator.free(prefix);
        const version_abs = std.fs.path.resolve(allocator, &.{node_install_dir}) catch null;
        defer if (version_abs) |value| allocator.free(value);
        const prefix_abs = std.fs.path.resolve(allocator, &.{prefix}) catch null;
        defer if (prefix_abs) |value| allocator.free(value);
        const same = if (version_abs) |v| if (prefix_abs) |p| pathsEqualAscii(v, p) else true else true;
        if (!same) {
            if (try resolveVersionDirExecutable(allocator, prefix_abs orelse prefix, command_name)) |exe| {
                return exe;
            }
        }
    }
    if (std.ascii.eqlIgnoreCase(command_name, "pnpm")) {
        if (try pnpmHomeExeDir(allocator)) |home| {
            defer allocator.free(home);
            if (try resolveVersionDirExecutable(allocator, home, command_name)) |exe| {
                return exe;
            }
            const bin_dir = try std.fs.path.join(allocator, &.{ home, "bin" });
            defer allocator.free(bin_dir);
            if (try resolveVersionDirExecutable(allocator, bin_dir, command_name)) |exe| {
                return exe;
            }
        }
    }
    return null;
}

fn pnpmHomeExeDir(allocator: std.mem.Allocator) !?[]u8 {
    const home = std.process.getEnvVarOwned(allocator, "PNPM_HOME") catch return null;
    if (home.len == 0) {
        allocator.free(home);
        return null;
    }
    return home;
}

fn resolvePackageModuleEntry(allocator: std.mem.Allocator, dir_path: []const u8, package_name: []const u8, command_name: []const u8) !?[]u8 {
    for (packageModuleRelPaths(package_name, command_name)) |rel| {
        const full = try std.fs.path.join(allocator, &.{ dir_path, "node_modules", rel });
        errdefer allocator.free(full);
        std.fs.cwd().access(full, .{}) catch {
            allocator.free(full);
            continue;
        };
        return full;
    }
    return null;
}

fn resolveNpmPrefixModuleEntry(allocator: std.mem.Allocator, node_install_dir: []const u8, command_name: []const u8) !?[]u8 {
    const prefix = try npmGlobalPrefix(allocator, node_install_dir) orelse return null;
    defer allocator.free(prefix);
    const version_abs = std.fs.path.resolve(allocator, &.{node_install_dir}) catch return null;
    defer allocator.free(version_abs);
    const prefix_abs = std.fs.path.resolve(allocator, &.{prefix}) catch return null;
    defer allocator.free(prefix_abs);
    if (pathsEqualAscii(version_abs, prefix_abs)) return null;
    return resolvePackageModuleEntry(allocator, prefix_abs, npmGlobalPackageName(command_name), command_name);
}

const pnpm_module_rel_paths = [_][]const u8{
    "pnpm\\bin\\pnpm.mjs",
    "pnpm\\bin\\pnpm.cjs",
    "pnpm\\bin\\pnpm.js",
    "pnpm\\pnpm",
};

const yarn_module_rel_paths = [_][]const u8{
    "yarn\\bin\\yarn.js",
    "yarn\\bin\\yarn.cjs",
    "yarn\\bin\\yarn.mjs",
};

fn packageModuleRelPaths(package_name: []const u8, command_name: []const u8) []const []const u8 {
    if (std.ascii.eqlIgnoreCase(command_name, "pnpm") or std.ascii.eqlIgnoreCase(package_name, "pnpm")) {
        return &pnpm_module_rel_paths;
    }
    return &yarn_module_rel_paths;
}

fn findLauncherCmd(allocator: std.mem.Allocator, dir_path: []const u8, command_name: []const u8) !?[]u8 {
    const exts = [_][]const u8{ ".cmd", ".bat" };
    for (exts) |ext| {
        const filename = try std.fmt.allocPrint(allocator, "{s}{s}", .{ command_name, ext });
        defer allocator.free(filename);
        const full = try std.fs.path.join(allocator, &.{ dir_path, filename });
        errdefer allocator.free(full);
        std.fs.cwd().access(full, .{}) catch {
            allocator.free(full);
            continue;
        };
        return full;
    }
    return null;
}

fn resolveNpmPrefixPackageJs(allocator: std.mem.Allocator, node_install_dir: []const u8, command_name: []const u8) !?[]u8 {
    const prefix = try npmGlobalPrefix(allocator, node_install_dir) orelse return null;
    defer allocator.free(prefix);
    const version_abs = std.fs.path.resolve(allocator, &.{node_install_dir}) catch return null;
    defer allocator.free(version_abs);
    const prefix_abs = std.fs.path.resolve(allocator, &.{prefix}) catch return null;
    defer allocator.free(prefix_abs);
    if (pathsEqualAscii(version_abs, prefix_abs)) return null;

    const cmd_path = try findLauncherCmd(allocator, prefix_abs, command_name) orelse return null;
    defer allocator.free(cmd_path);
    switch (try classifyPackageLauncher(allocator, cmd_path, npmGlobalPackageName(command_name))) {
        .package_js => |js_path| return js_path,
        .corepack_trampoline, .reject => return null,
    }
}

fn classifyPackageLauncher(allocator: std.mem.Allocator, cmd_path: []const u8, package_name: []const u8) !LauncherClass {
    const contents = try readTextFileIfPresent(allocator, cmd_path) orelse return .reject;
    defer allocator.free(contents);
    if (contents.len > 64 * 1024) return .reject;

    const cmd_dir = std.fs.path.dirname(cmd_path) orelse return .reject;
    if (launcherMentionsCorepack(contents) and !launcherMentionsPackage(contents, package_name)) {
        return .corepack_trampoline;
    }
    if (launcherMentionsCorepack(contents)) return .reject;

    const token = launcherPackageToken(contents, package_name) orelse return .reject;
    const expanded = try expandLauncherDp0(allocator, token, cmd_dir) orelse return .reject;
    defer allocator.free(expanded);
    if (std.mem.indexOfScalar(u8, expanded, '%') != null) return .reject;

    const resolved = std.fs.path.resolve(allocator, &.{ expanded }) catch return .reject;
    defer allocator.free(resolved);
    if (!isDelegatedScript(resolved)) return .reject;

    const package_root = std.fs.path.join(allocator, &.{ cmd_dir, "node_modules", package_name }) catch return .reject;
    defer allocator.free(package_root);
    const package_abs = std.fs.path.resolve(allocator, &.{package_root}) catch return .reject;
    defer allocator.free(package_abs);
    if (!pathIsInside(package_abs, resolved)) return .reject;
    const node_modules = std.fs.path.join(allocator, &.{ cmd_dir, "node_modules" }) catch return .reject;
    defer allocator.free(node_modules);
    if (pathIsReparsePoint(allocator, cmd_dir)) return .reject;
    if (pathIsReparsePoint(allocator, node_modules)) return .reject;
    if (pathIsReparsePoint(allocator, package_abs)) return .reject;
    if (pathIsReparsePoint(allocator, resolved)) return .reject;

    std.fs.cwd().access(resolved, .{}) catch return .reject;
    return .{ .package_js = try allocator.dupe(u8, resolved) };
}

fn launcherMentionsCorepack(contents: []const u8) bool {
    return indexOfIgnoreCase(contents, "corepack.js") != null;
}

fn launcherMentionsPackage(contents: []const u8, package_name: []const u8) bool {
    return launcherPackageToken(contents, package_name) != null;
}

fn launcherPackageToken(contents: []const u8, package_name: []const u8) ?[]const u8 {
    const markers = [_][]const u8{ "node_modules\\", "node_modules/" };
    var search_from: usize = 0;
    while (search_from < contents.len) {
        const rest = contents[search_from..];
        var found: ?usize = null;
        for (markers) |marker| {
            const needle_len = marker.len + package_name.len;
            var i: usize = 0;
            while (i + needle_len <= rest.len) : (i += 1) {
                if (!std.ascii.eqlIgnoreCase(rest[i .. i + marker.len], marker)) continue;
                if (!std.ascii.eqlIgnoreCase(rest[i + marker.len .. i + needle_len], package_name)) continue;
                const after = i + needle_len;
                if (after >= rest.len) continue;
                const sep = rest[after];
                if (sep != '\\' and sep != '/') continue;
                found = search_from + i;
                break;
            }
            if (found != null) break;
        }
        const at = found orelse return null;
        const token = quotedTokenAt(contents, at);
        if (token.len != 0) return token;
        search_from = at + 1;
    }
    return null;
}

fn quotedTokenAt(contents: []const u8, at: usize) []const u8 {
    var start = at;
    while (start > 0) {
        const ch = contents[start - 1];
        if (ch == '"' or ch == ' ' or ch == '\t' or ch == '\r' or ch == '\n' or ch == '=') break;
        start -= 1;
    }
    var end = at;
    while (end < contents.len) {
        const ch = contents[end];
        if (ch == '"' or ch == ' ' or ch == '\t' or ch == '\r' or ch == '\n') break;
        end += 1;
    }
    return contents[start..end];
}

fn expandLauncherDp0(allocator: std.mem.Allocator, token: []const u8, cmd_dir: []const u8) !?[]u8 {
    const trimmed = std.mem.trim(u8, token, " \t\r\n\"");
    const dir = std.mem.trimRight(u8, cmd_dir, "\\/");
    const patterns = [_][]const u8{ "%~dp0%", "%dp0%", "%~dp0" };
    for (patterns) |pattern| {
        if (std.ascii.startsWithIgnoreCase(trimmed, pattern)) {
            const rest = trimmed[pattern.len..];
            const relative = std.mem.trimLeft(u8, rest, "\\/");
            if (relative.len == 0) return null;
            const joined = try std.fs.path.join(allocator, &.{ dir, relative });
            return joined;
        }
    }
    if (std.fs.path.isAbsolute(trimmed)) {
        const owned = try allocator.dupe(u8, trimmed);
        return owned;
    }
    const joined = try std.fs.path.join(allocator, &.{ dir, trimmed });
    return joined;
}

fn hasScriptExtension(path: []const u8) bool {
    const ext = std.fs.path.extension(path);
    return std.ascii.eqlIgnoreCase(ext, ".js") or
        std.ascii.eqlIgnoreCase(ext, ".cjs") or
        std.ascii.eqlIgnoreCase(ext, ".mjs");
}

fn fileStartsWithMz(path: []const u8) bool {
    const file = std.fs.openFileAbsolute(path, .{}) catch return false;
    defer file.close();
    var buf: [2]u8 = undefined;
    const n = file.read(&buf) catch return false;
    return n == 2 and buf[0] == 'M' and buf[1] == 'Z';
}

/// JS global modules: `.js`/`.cjs`/`.mjs`, or an extensionless non-PE file
/// (pnpm 12 `bin.pnpm` = `"pnpm"`). PE files are native, not scripts.
fn isDelegatedScript(path: []const u8) bool {
    if (hasScriptExtension(path)) return true;
    if (std.fs.path.extension(path).len != 0) return false;
    return !fileStartsWithMz(path);
}

fn pathIsInside(parent: []const u8, child: []const u8) bool {
    if (child.len <= parent.len) return false;
    if (!std.ascii.eqlIgnoreCase(child[0..parent.len], parent)) return false;
    const sep = child[parent.len];
    return sep == '\\' or sep == '/';
}

fn pathsEqualAscii(left: []const u8, right: []const u8) bool {
    return std.ascii.eqlIgnoreCase(std.mem.trimRight(u8, left, "\\/"), std.mem.trimRight(u8, right, "\\/"));
}

fn indexOfIgnoreCase(haystack: []const u8, needle: []const u8) ?usize {
    if (needle.len == 0 or haystack.len < needle.len) return null;
    var i: usize = 0;
    while (i + needle.len <= haystack.len) : (i += 1) {
        if (std.ascii.eqlIgnoreCase(haystack[i .. i + needle.len], needle)) return i;
    }
    return null;
}

fn pathIsReparsePoint(allocator: std.mem.Allocator, path: []const u8) bool {
    const path_w = std.unicode.utf8ToUtf16LeAllocZ(allocator, path) catch return true;
    defer allocator.free(path_w);
    const attrs = std.os.windows.kernel32.GetFileAttributesW(path_w.ptr);
    if (attrs == std.os.windows.INVALID_FILE_ATTRIBUTES) return true;
    return (attrs & 0x400) != 0;
}

/// Windows global prefix from built-in, per-install, and user npmrc files.
/// Project .npmrc and npm_config_prefix are ignored so a repo cannot aim this search.
fn npmGlobalPrefix(allocator: std.mem.Allocator, node_install_dir: []const u8) !?[]u8 {
    const appdata = std.process.getEnvVarOwned(allocator, "APPDATA") catch null;
    defer if (appdata) |value| allocator.free(value);
    var prefix: ?[]u8 = null;
    errdefer if (prefix) |value| allocator.free(value);
    if (appdata) |value| {
        prefix = try std.fs.path.join(allocator, &.{ value, "npm" });
    }

    const builtin = try std.fs.path.join(allocator, &.{ node_install_dir, "node_modules", "npm", "npmrc" });
    defer allocator.free(builtin);
    try applyNpmrcPrefixFile(allocator, &prefix, builtin);

    const install_etc = try std.fs.path.join(allocator, &.{ node_install_dir, "etc", "npmrc" });
    defer allocator.free(install_etc);
    try applyNpmrcPrefixFile(allocator, &prefix, install_etc);

    if (prefix) |current| {
        const prefix_etc = try std.fs.path.join(allocator, &.{ current, "etc", "npmrc" });
        defer allocator.free(prefix_etc);
        try applyNpmrcPrefixFile(allocator, &prefix, prefix_etc);
    }

    const user_profile = std.process.getEnvVarOwned(allocator, "USERPROFILE") catch null;
    defer if (user_profile) |value| allocator.free(value);
    if (user_profile) |value| {
        const user_npmrc = try std.fs.path.join(allocator, &.{ value, ".npmrc" });
        defer allocator.free(user_npmrc);
        try applyNpmrcPrefixFile(allocator, &prefix, user_npmrc);
    }

    return prefix;
}

fn applyNpmrcPrefixFile(allocator: std.mem.Allocator, prefix: *?[]u8, path: []const u8) !void {
    const contents = try readTextFileIfPresent(allocator, path) orelse return;
    defer allocator.free(contents);
    const value = lastNpmrcPrefix(contents) orelse return;
    const owned = try expandKnownPrefixVars(allocator, value);
    if (prefix.*) |previous| allocator.free(previous);
    prefix.* = owned;
}

fn expandKnownPrefixVars(allocator: std.mem.Allocator, value: []const u8) ![]u8 {
    const pairs = [_]struct { token: []const u8, env_name: []const u8 }{
        .{ .token = "%APPDATA%", .env_name = "APPDATA" },
        .{ .token = "${APPDATA}", .env_name = "APPDATA" },
        .{ .token = "%LOCALAPPDATA%", .env_name = "LOCALAPPDATA" },
        .{ .token = "${LOCALAPPDATA}", .env_name = "LOCALAPPDATA" },
        .{ .token = "%USERPROFILE%", .env_name = "USERPROFILE" },
        .{ .token = "${USERPROFILE}", .env_name = "USERPROFILE" },
    };
    var current = try allocator.dupe(u8, value);
    for (pairs) |pair| {
        const env_value = std.process.getEnvVarOwned(allocator, pair.env_name) catch continue;
        defer allocator.free(env_value);
        const replaced = try replaceAllIgnoreCase(allocator, current, pair.token, env_value);
        allocator.free(current);
        current = replaced;
    }
    return current;
}

fn replaceAllIgnoreCase(allocator: std.mem.Allocator, haystack: []const u8, needle: []const u8, replacement: []const u8) ![]u8 {
    var out = std.ArrayListUnmanaged(u8){};
    errdefer out.deinit(allocator);
    var i: usize = 0;
    while (i < haystack.len) {
        if (i + needle.len <= haystack.len and std.ascii.eqlIgnoreCase(haystack[i .. i + needle.len], needle)) {
            try out.appendSlice(allocator, replacement);
            i += needle.len;
            continue;
        }
        try out.append(allocator, haystack[i]);
        i += 1;
    }
    return out.toOwnedSlice(allocator);
}

fn lastNpmrcPrefix(contents: []const u8) ?[]const u8 {
    var last: ?[]const u8 = null;
    var lines = std.mem.splitScalar(u8, contents, '\n');
    while (lines.next()) |raw_line| {
        const line = std.mem.trim(u8, raw_line, " \t\r");
        if (line.len == 0 or line[0] == ';' or line[0] == '#') continue;
        const eq = std.mem.indexOfScalar(u8, line, '=') orelse continue;
        const key = std.mem.trim(u8, line[0..eq], " \t");
        if (!std.ascii.eqlIgnoreCase(key, "prefix")) continue;
        var value = std.mem.trim(u8, line[eq + 1 ..], " \t");
        if (value.len >= 2 and value[0] == '"' and value[value.len - 1] == '"') {
            value = value[1 .. value.len - 1];
        }
        if (value.len == 0) continue;
        last = value;
    }
    return last;
}

fn reportMissingPackageManager(command_name: []const u8) void {
    const prepare_name = if (std.ascii.eqlIgnoreCase(command_name, "yarnpkg")) "yarn" else command_name;
    std.debug.print(
        \\{s} is not installed for this Node.js version.
        \\
        \\Run:  corepack enable
        \\      corepack prepare {s}@stable --activate
        \\
    , .{ command_name, prepare_name });
}

const bundled_corepack_range = "14.19.0-14.x and 16.9.0-24.x";

fn stripNodeVersionPrefix(version: []const u8) []const u8 {
    const trimmed = std.mem.trim(u8, version, " \t");
    if (trimmed.len > 0 and (trimmed[0] == 'v' or trimmed[0] == 'V')) {
        return trimmed[1..];
    }
    return trimmed;
}

fn parseNodeVersion(version: []const u8) ?struct { major: u32, minor: u32 } {
    const shown = stripNodeVersionPrefix(version);
    if (shown.len == 0) return null;
    var it = std.mem.splitScalar(u8, shown, '.');
    const major_s = it.next() orelse return null;
    const minor_s = it.next() orelse "0";
    const major = std.fmt.parseInt(u32, major_s, 10) catch return null;
    var minor_tok = minor_s;
    if (std.mem.indexOfAny(u8, minor_tok, "-+")) |i| minor_tok = minor_tok[0..i];
    const minor = std.fmt.parseInt(u32, minor_tok, 10) catch return null;
    return .{ .major = major, .minor = minor };
}

/// Bundled Corepack: 14.19.0-14.x and 16.9.0-24.x. Not 15.x. Not 25+.
fn nodeShipsBundledCorepack(version: []const u8) bool {
    const parsed = parseNodeVersion(version) orelse return false;
    if (parsed.major == 14) return parsed.minor >= 19;
    if (parsed.major == 15) return false;
    if (parsed.major == 16) return parsed.minor >= 9;
    return parsed.major >= 17 and parsed.major <= 24;
}

fn reportMissingCorepack(node_version: []const u8) void {
    const shown = stripNodeVersionPrefix(node_version);
    if (nodeShipsBundledCorepack(shown)) return;
    const display = if (shown.len == 0) "this version" else shown;
    std.debug.print(
        \\corepack is not installed for Node.js {s}.
        \\
        \\Corepack only shipped with Node.js {s}. Install it for {s}:
        \\  npm install -g corepack
        \\
    , .{ display, bundled_corepack_range, display });
}

fn isCorepackBackedCommand(command_name: []const u8) bool {
    return std.ascii.eqlIgnoreCase(command_name, "yarn") or
        std.ascii.eqlIgnoreCase(command_name, "yarnpkg") or
        std.ascii.eqlIgnoreCase(command_name, "pnpm");
}

fn resolveCorepackJs(allocator: std.mem.Allocator, node_install_dir: []const u8) !?[]u8 {
    return tryJoinExisting(allocator, node_install_dir, &.{ "node_modules", "corepack", "dist", "corepack.js" });
}

fn tryJoinExisting(allocator: std.mem.Allocator, root: []const u8, parts: []const []const u8) !?[]u8 {
    var segments = try allocator.alloc([]const u8, parts.len + 1);
    defer allocator.free(segments);
    segments[0] = root;
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

fn isCorepackJsPath(path: []const u8) bool {
    const lower = std.fs.path.basename(path);
    return std.ascii.eqlIgnoreCase(lower, "corepack.js");
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
            const reason = if (outcome.reason.len == 0) "delegated package-manager entrypoint trust verification failed" else outcome.reason;
            recoverDelegatedTrustOrReport(allocator, cfg, node_install_dir, command_name, cli_js, node_bin, node_version, reason);
            const retry = verifycache.ensureDelegatedScriptTrusted(allocator, cfg.root, cli_js);
            if (retry.result == .failed) {
                reportDelegatedTrustFailure(
                    allocator,
                    cfg,
                    command_name,
                    cli_js,
                    node_bin,
                    node_version,
                    if (retry.reason.len == 0) reason else retry.reason,
                );
            }
        }
        return;
    }

    const ext = std.fs.path.extension(command_path);
    if (std.ascii.eqlIgnoreCase(ext, ".exe") or (ext.len == 0 and fileStartsWithMz(command_path))) {
        // Same TPM verify-cache as node.exe — never full Authenticode on warm path.
        const outcome = verifycache.ensureResolvedNodeTrusted(allocator, cfg.root, command_path, null);
        if (outcome.result == .failed or outcome.result == .version_mismatch) {
            const reason = if (outcome.reason.len == 0) "delegated executable trust verification failed" else outcome.reason;
            recoverDelegatedTrustOrReport(allocator, cfg, node_install_dir, command_name, command_path, node_bin, node_version, reason);
            const retry = verifycache.ensureResolvedNodeTrusted(allocator, cfg.root, command_path, null);
            if (retry.result == .failed) {
                reportDelegatedTrustFailure(
                    allocator,
                    cfg,
                    command_name,
                    command_path,
                    node_bin,
                    node_version,
                    if (retry.reason.len == 0) reason else retry.reason,
                );
            }
        }
        return;
    }

    if (std.ascii.eqlIgnoreCase(ext, ".cmd") or std.ascii.eqlIgnoreCase(ext, ".bat")) {
        const outcome = verifycache.ensureDelegatedScriptTrusted(allocator, cfg.root, command_path);
        if (outcome.result == .failed) {
            const reason = if (outcome.reason.len == 0) "delegated script trust verification failed" else outcome.reason;
            recoverDelegatedTrustOrReport(allocator, cfg, node_install_dir, command_name, command_path, node_bin, node_version, reason);
            const retry = verifycache.ensureDelegatedScriptTrusted(allocator, cfg.root, command_path);
            if (retry.result == .failed) {
                reportDelegatedTrustFailure(
                    allocator,
                    cfg,
                    command_name,
                    command_path,
                    node_bin,
                    node_version,
                    if (retry.reason.len == 0) reason else retry.reason,
                );
            }
        }
        return;
    }

    if (isDelegatedScript(command_path)) {
        const outcome = verifycache.ensureDelegatedScriptTrusted(allocator, cfg.root, command_path);
        if (outcome.result == .failed) {
            const reason = if (outcome.reason.len == 0) "delegated script trust verification failed" else outcome.reason;
            recoverDelegatedTrustOrReport(allocator, cfg, node_install_dir, command_name, command_path, node_bin, node_version, reason);
            const retry = verifycache.ensureDelegatedScriptTrusted(allocator, cfg.root, command_path);
            if (retry.result == .failed) {
                reportDelegatedTrustFailure(
                    allocator,
                    cfg,
                    command_name,
                    command_path,
                    node_bin,
                    node_version,
                    if (retry.reason.len == 0) reason else retry.reason,
                );
            }
        }
        return;
    }

    reportDelegatedTrustFailure(allocator, cfg, command_name, command_path, node_bin, node_version, "unsupported delegated command type");
}

/// True when VerifyCache failure looks like a self-update (not missing cache / schema).
fn isSelfUpdateTrustFailure(reason: []const u8) bool {
    return std.mem.indexOf(u8, reason, "changed since it was trusted") != null or
        std.mem.indexOf(u8, reason, "identity changed") != null or
        std.mem.indexOf(u8, reason, "digest mismatch") != null;
}

fn isMissingDelegatedTrust(reason: []const u8) bool {
    return std.mem.indexOf(u8, reason, "is not trusted") != null;
}

const TrustRecover = enum { recovered, blocked, no_answer };

const no_trust_answer_reason = "No trust answer (toast timeout / no console)";

fn recoverDelegatedTrustOrReport(
    allocator: std.mem.Allocator,
    cfg: nodeversion.ShimConfig,
    node_install_dir: []const u8,
    command_name: []const u8,
    command_path: []const u8,
    node_bin: []const u8,
    node_version: []const u8,
    reason: []const u8,
) void {
    switch (tryRecoverDelegatedTrustFailure(allocator, cfg.root, node_install_dir, command_name, command_path, reason, cfg.structured_logging)) {
        .recovered => return,
        .blocked => reportDelegatedTrustFailure(allocator, cfg, command_name, command_path, node_bin, node_version, reason),
        .no_answer => reportDelegatedTrustFailure(allocator, cfg, command_name, command_path, node_bin, node_version, no_trust_answer_reason),
    }
}

/// Prompt/trust+reshim when an untrusted module's entrypoint changed under us.
fn tryRecoverDelegatedTrustFailure(
    allocator: std.mem.Allocator,
    install_root: []const u8,
    node_install_dir: []const u8,
    command_name: []const u8,
    command_path: []const u8,
    reason: []const u8,
    structured_logging: bool,
) TrustRecover {
    const self_update = isSelfUpdateTrustFailure(reason);
    const missing = isMissingDelegatedTrust(reason);
    if (!self_update and !missing) return .blocked;

    // npm/npx ship with Node. A 2.0.0 upgrade has no script-trust row for them.
    // Re-sign that miss even when TrustedModules is still the old NOT ALL seed.
    if (missing and isBuiltinPackageManager(command_name)) {
        logFirewallInfo(allocator, structured_logging, "firewall.builtin_pm_unsigned", "firewall unsigned npm/npx entrypoint after upgrade; re-signing");
        _ = resignScriptSync(allocator, command_path);
        runReshim(allocator, install_root, node_install_dir, true);
        return .recovered;
    }

    const rules = loadTrustedModules(allocator) catch return .blocked;
    defer module_firewall.freeMultiSz(allocator, rules);

    const trust = classifyModuleTrust(allocator, command_name, rules);
    // Default trust includes npm/npx so their upgrades (and a missing first
    // script-trust entry) re-sign instead of NVM4306.
    if (trust == .trusted and (self_update or (missing and isPackageManagerCommand(command_name)))) {
        logFirewallInfo(allocator, structured_logging, "firewall.trusted_module_stale", "firewall trusted module VerifyCache stale; scheduling reshim");
        _ = resignScriptSync(allocator, command_path);
        runReshim(allocator, install_root, node_install_dir, true);
        return .recovered;
    }
    if (!self_update) return .blocked;
    if (trust == .remote_blocked) {
        const audit = auditFromVerifyCache(allocator, command_path);
        defer audit.deinit(allocator);
        logUntrustedModuleChanged(allocator, structured_logging, command_name, "deny", "remote", "verify_cache", audit);
        logFirewallInfo(allocator, structured_logging, "firewall.remote_blocked", "firewall remote policy blocked module; deny (no prompt)");
        return .blocked;
    }
    switch (untrustedHandlerAction(allocator)) {
        .deny => {
            const audit = auditFromVerifyCache(allocator, command_path);
            defer audit.deinit(allocator);
            logUntrustedModuleChanged(allocator, structured_logging, command_name, "deny", "deny", "verify_cache", audit);
            logFirewallInfo(allocator, structured_logging, "firewall.untrusted_deny", "firewall untrusted module VerifyCache stale; deny (no prompt)");
            return .blocked;
        },
        .allow => {
            const audit = auditFromVerifyCache(allocator, command_path);
            defer audit.deinit(allocator);
            logUntrustedModuleChanged(allocator, structured_logging, command_name, "allow", "allow", "verify_cache", audit);
            logFirewallInfo(allocator, structured_logging, "firewall.untrusted_allow", "firewall untrusted module VerifyCache stale; allow auto-trust; scheduling reshim");
            notifyModuleAutoTrusted(allocator, command_name);
            _ = resignScriptSync(allocator, command_path);
            runReshim(allocator, install_root, node_install_dir, true);
            return .recovered;
        },
        .prompt => {
            switch (promptTrustChange(allocator, command_name)) {
                .accepted => {
                    const audit = auditFromVerifyCache(allocator, command_path);
                    defer audit.deinit(allocator);
                    logUntrustedModuleChanged(allocator, structured_logging, command_name, "prompt_accepted", "prompt", "verify_cache", audit);
                    logFirewallInfo(allocator, structured_logging, "firewall.prompt_accepted", "firewall trust prompt accepted on VerifyCache miss; scheduling reshim");
                    _ = resignScriptSync(allocator, command_path);
                    runReshim(allocator, install_root, node_install_dir, true);
                    return .recovered;
                },
                .declined => {
                    const audit = auditFromVerifyCache(allocator, command_path);
                    defer audit.deinit(allocator);
                    logUntrustedModuleChanged(allocator, structured_logging, command_name, "prompt_declined", "prompt", "verify_cache", audit);
                    logFirewallInfo(allocator, structured_logging, "firewall.prompt_declined", "firewall trust prompt declined on VerifyCache miss");
                    return .blocked;
                },
                .no_answer => {
                    const audit = auditFromVerifyCache(allocator, command_path);
                    defer audit.deinit(allocator);
                    logUntrustedModuleChanged(allocator, structured_logging, command_name, "prompt_timeout", "prompt", "verify_cache", audit);
                    logFirewallInfo(allocator, structured_logging, "firewall.prompt_timeout", "firewall trust prompt timed out on VerifyCache miss");
                    return .no_answer;
                },
            }
        },
    }
}

fn isBuiltinPackageManager(command_name: []const u8) bool {
    return std.ascii.eqlIgnoreCase(command_name, "npm") or
        std.ascii.eqlIgnoreCase(command_name, "npx") or
        std.ascii.eqlIgnoreCase(command_name, "yarn") or
        std.ascii.eqlIgnoreCase(command_name, "yarnpkg") or
        std.ascii.eqlIgnoreCase(command_name, "corepack") or
        std.ascii.eqlIgnoreCase(command_name, "pnpm");
}

fn isPackageManagerCommand(command_name: []const u8) bool {
    return std.ascii.eqlIgnoreCase(command_name, "npm") or
        std.ascii.eqlIgnoreCase(command_name, "npx") or
        std.ascii.eqlIgnoreCase(command_name, "pnpm") or
        std.ascii.eqlIgnoreCase(command_name, "yarn") or
        std.ascii.eqlIgnoreCase(command_name, "yarnpkg") or
        std.ascii.eqlIgnoreCase(command_name, "corepack") or
        std.ascii.eqlIgnoreCase(command_name, "vlt");
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
    var audit_ctx = eventlog.captureAuditContext(allocator);
    defer audit_ctx.deinit(allocator);
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
            .user = audit_ctx.user,
            .sid = audit_ctx.sid,
            .hostname = audit_ctx.hostname,
            .parent_process = audit_ctx.parent_process,
            .parent_pid = audit_ctx.parent_pid,
            .project_name = audit_ctx.project_name,
            .project_path = audit_ctx.project_path,
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
        \\Action: If you trust this change, run `nvm firewall trust module {s}`.
        \\`nvm reshim` alone will not keep this module trusted after the next self-update.
        \\If this change was unexpected, contact your administrator and review NVM event logs.
        \\Event code: NVM4306
        \\
    , .{ command_name, command_path, detail, command_name });
    std.process.exit(1);
}

const PmCtx = struct {
    allocator: std.mem.Allocator,
    node_install_dir: []const u8,
    node_bin: []const u8,
    command_name: []const u8,
    command_path: []const u8,
    npm_module_minimum_age: ?u64,
    npm_module_minimum_age_forced: bool,
    npm_registry_fallback: ?[]const u8,
    block_lifecycle_scripts: bool,
};

fn runPm(ctx: *anyopaque, args: []const []const u8) u8 {
    const pm: *PmCtx = @ptrCast(@alignCast(ctx));
    return runDelegatedCommand(
        pm.allocator,
        pm.node_install_dir,
        pm.node_bin,
        pm.command_name,
        pm.command_path,
        pm.npm_module_minimum_age,
        pm.npm_module_minimum_age_forced,
        pm.npm_registry_fallback,
        pm.block_lifecycle_scripts,
        args,
    ) catch 1;
}

fn dropPackageArgs(allocator: std.mem.Allocator, args: []const []const u8) []const []const u8 {
    var out = std.ArrayListUnmanaged([]const u8){};
    for (args) |arg| {
        if (arg.len == 0) continue;
        if (arg[0] == '-') {
            out.append(allocator, arg) catch return args;
            continue;
        }
        if (out.items.len == 0) out.append(allocator, arg) catch return args;
    }
    return out.toOwnedSlice(allocator) catch args;
}

fn runDelegatedCommand(
    allocator: std.mem.Allocator,
    node_install_dir: []const u8,
    node_bin: []const u8,
    command_name: []const u8,
    command_path: []const u8,
    npm_module_minimum_age: ?u64,
    npm_module_minimum_age_forced: bool,
    npm_registry_fallback: ?[]const u8,
    block_lifecycle_scripts: bool,
    forwarded: []const []const u8,
) !u8 {
    var env_map = try std.process.getEnvMap(allocator);
    defer env_map.deinit();

    const locked = try prepareLifecycleScriptLock(allocator, &env_map, command_name, command_path, block_lifecycle_scripts, forwarded);
    defer if (locked.owns_args) allocator.free(locked.args);

    const forwarded_args = try filterForwardedArgsForAgePolicy(allocator, command_name, npm_module_minimum_age, npm_module_minimum_age_forced, locked.args);
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
    if (isCorepackBackedCommand(command_name) and isCorepackJsPath(command_path)) {
        const argv = try corepackBackedArgv(allocator, node_bin, command_path, command_name, forwarded_args);
        defer allocator.free(argv);
        return spawnArgvSlice(allocator, &env_map, argv);
    }
    if (isDelegatedScript(command_path)) {
        return spawnArgv(allocator, &env_map, node_bin, command_path, forwarded_args);
    }

    // Spawn the entrypoint directly. For .cmd/.bat, Zig's Child uses
    // argvToScriptCommandLineWindows (cmd /c with BatBadBut-safe quoting).
    // Hand-building [cmd.exe,/d,/c,path,...args] breaks when both the path and
    // a forwarded arg contain spaces — see nvm-windows/nvm#1408 / cmd_spawn.zig.
    const argv = try cmd_spawn.buildEntrypointArgv(allocator, command_path, forwarded_args);
    defer allocator.free(argv);
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

fn corepackBackedArgv(
    allocator: std.mem.Allocator,
    node_bin: []const u8,
    corepack_js: []const u8,
    command_name: []const u8,
    forwarded_args: []const []const u8,
) ![]const []const u8 {
    var argv = try allocator.alloc([]const u8, forwarded_args.len + 3);
    argv[0] = node_bin;
    argv[1] = corepack_js;
    argv[2] = command_name;
    for (forwarded_args, 0..) |arg, i| {
        argv[i + 3] = arg;
    }
    return argv;
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

const LifecycleScriptAction = enum {
    unchanged,
    ignore_scripts_flag,
    yarn_berry_env,
};

const PreparedLifecycleLock = struct {
    args: []const []const u8,
    owns_args: bool,
};

fn prepareLifecycleScriptLock(
    allocator: std.mem.Allocator,
    env_map: *std.process.EnvMap,
    command_name: []const u8,
    command_path: []const u8,
    block_lifecycle_scripts: bool,
    forwarded: []const []const u8,
) !PreparedLifecycleLock {
    if (!block_lifecycle_scripts) return .{ .args = forwarded, .owns_args = false };

    const yarn_major = if (commandWantsYarnLock(command_name, forwarded))
        detectYarnMajor(allocator, command_name, command_path)
    else
        null;
    switch (lifecycleScriptAction(command_name, forwarded, yarn_major)) {
        .unchanged => return .{ .args = forwarded, .owns_args = false },
        .ignore_scripts_flag => return .{
            .args = try rewriteIgnoreScriptsArgs(allocator, forwarded),
            .owns_args = true,
        },
        .yarn_berry_env => {
            try env_map.put("YARN_ENABLE_SCRIPTS", "false");
            return .{ .args = forwarded, .owns_args = false };
        },
    }
}

fn lifecycleScriptAction(command_name: []const u8, forwarded: []const []const u8, yarn_major: ?u32) LifecycleScriptAction {
    if (commandWantsIgnoreScriptsFlag(command_name, forwarded)) return .ignore_scripts_flag;
    if (!commandWantsYarnLock(command_name, forwarded)) return .unchanged;
    const major = yarn_major orelse return .unchanged;
    if (major <= 1) return .ignore_scripts_flag;
    return .yarn_berry_env;
}

fn commandWantsIgnoreScriptsFlag(command_name: []const u8, forwarded: []const []const u8) bool {
    if (std.ascii.eqlIgnoreCase(command_name, "npm") or
        std.ascii.eqlIgnoreCase(command_name, "npx") or
        std.ascii.eqlIgnoreCase(command_name, "pnpm") or
        std.ascii.eqlIgnoreCase(command_name, "vlt"))
    {
        return true;
    }
    return std.ascii.eqlIgnoreCase(command_name, "corepack") and
        forwarded.len > 0 and
        std.ascii.eqlIgnoreCase(forwarded[0], "pnpm");
}

fn commandWantsYarnLock(command_name: []const u8, forwarded: []const []const u8) bool {
    if (std.ascii.eqlIgnoreCase(command_name, "yarn") or std.ascii.eqlIgnoreCase(command_name, "yarnpkg")) return true;
    return std.ascii.eqlIgnoreCase(command_name, "corepack") and
        forwarded.len > 0 and
        (std.ascii.eqlIgnoreCase(forwarded[0], "yarn") or std.ascii.eqlIgnoreCase(forwarded[0], "yarnpkg"));
}

fn detectYarnMajor(allocator: std.mem.Allocator, command_name: []const u8, command_path: []const u8) ?u32 {
    if (std.ascii.eqlIgnoreCase(command_name, "corepack") or isCorepackJsPath(command_path)) {
        const cwd = std.process.getCwdAlloc(allocator) catch return null;
        defer allocator.free(cwd);
        return yarnMajorWalkingParents(allocator, cwd, .project_manager);
    }
    const start = std.fs.path.dirname(command_path) orelse return null;
    return yarnMajorWalkingParents(allocator, start, .yarn_package);
}

const PackageJsonYarnKind = enum {
    yarn_package,
    project_manager,
};

fn yarnMajorWalkingParents(allocator: std.mem.Allocator, start_dir: []const u8, kind: PackageJsonYarnKind) ?u32 {
    var current = allocator.dupe(u8, start_dir) catch return null;
    defer allocator.free(current);

    var hop: u8 = 0;
    while (hop < 8) : (hop += 1) {
        const package_json = std.fs.path.join(allocator, &.{ current, "package.json" }) catch return null;
        defer allocator.free(package_json);
        if (yarnMajorAtPackageJson(allocator, package_json, kind)) |major| return major;

        const parent = std.fs.path.dirname(current) orelse break;
        if (std.mem.eql(u8, parent, current)) break;
        const next = allocator.dupe(u8, parent) catch return null;
        allocator.free(current);
        current = next;
    }
    return null;
}

fn yarnMajorAtPackageJson(allocator: std.mem.Allocator, package_json: []const u8, kind: PackageJsonYarnKind) ?u32 {
    var file = std.fs.openFileAbsolute(package_json, .{}) catch return null;
    defer file.close();
    const bytes = file.readToEndAlloc(allocator, 1024 * 1024) catch return null;
    defer allocator.free(bytes);
    return switch (kind) {
        .yarn_package => yarnMajorFromYarnPackageJson(allocator, bytes),
        .project_manager => yarnMajorFromProjectPackageJson(allocator, bytes),
    };
}

fn yarnMajorFromYarnPackageJson(allocator: std.mem.Allocator, bytes: []const u8) ?u32 {
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, bytes, .{}) catch return null;
    defer parsed.deinit();
    const obj = switch (parsed.value) {
        .object => |object| object,
        else => return null,
    };
    const name = obj.get("name") orelse return null;
    if (name != .string or !std.mem.eql(u8, name.string, "yarn")) return null;
    const version = obj.get("version") orelse return null;
    if (version != .string) return null;
    return majorFromVersionString(version.string);
}

fn yarnMajorFromProjectPackageJson(allocator: std.mem.Allocator, bytes: []const u8) ?u32 {
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, bytes, .{}) catch return null;
    defer parsed.deinit();
    const obj = switch (parsed.value) {
        .object => |object| object,
        else => return null,
    };
    const package_manager = obj.get("packageManager") orelse return null;
    if (package_manager != .string) return null;
    return yarnMajorFromPackageManagerField(package_manager.string);
}

fn yarnMajorFromPackageManagerField(raw: []const u8) ?u32 {
    const trimmed = std.mem.trim(u8, raw, " \t\r\n");
    const prefix = "yarn@";
    if (!std.ascii.startsWithIgnoreCase(trimmed, prefix)) return null;
    return majorFromVersionString(trimmed[prefix.len..]);
}

fn majorFromVersionString(raw: []const u8) ?u32 {
    const trimmed = std.mem.trim(u8, raw, " \t\r\n");
    if (trimmed.len == 0) return null;
    var index: usize = if (trimmed[0] == 'v' or trimmed[0] == 'V') 1 else 0;
    const start = index;
    while (index < trimmed.len and std.ascii.isDigit(trimmed[index])) index += 1;
    if (index == start) return null;
    return std.fmt.parseInt(u32, trimmed[start..index], 10) catch null;
}

fn rewriteIgnoreScriptsArgs(allocator: std.mem.Allocator, args: []const []const u8) ![]const []const u8 {
    const separator = passthroughSeparatorIndex(args);
    var kept = std.ArrayListUnmanaged([]const u8){};
    errdefer kept.deinit(allocator);

    var index: usize = 0;
    while (index < separator) {
        const arg = args[index];
        if (isIgnoreScriptsDisabledFlag(arg)) {
            index += 1;
            continue;
        }
        if (isBareIgnoreScripts(arg) and index + 1 < separator and isFalseWord(args[index + 1])) {
            index += 2;
            continue;
        }
        try kept.append(allocator, arg);
        index += 1;
    }

    try kept.append(allocator, "--ignore-scripts");
    if (separator < args.len) {
        try kept.appendSlice(allocator, args[separator..]);
    }
    return kept.toOwnedSlice(allocator);
}

fn passthroughSeparatorIndex(args: []const []const u8) usize {
    for (args, 0..) |arg, index| {
        if (std.mem.eql(u8, arg, "--")) return index;
    }
    return args.len;
}

fn isIgnoreScriptsDisabledFlag(arg: []const u8) bool {
    return std.ascii.eqlIgnoreCase(arg, "--ignore-scripts=false") or
        std.ascii.eqlIgnoreCase(arg, "--no-ignore-scripts") or
        std.ascii.eqlIgnoreCase(arg, "--config.ignore-scripts=false");
}

fn isBareIgnoreScripts(arg: []const u8) bool {
    return std.ascii.eqlIgnoreCase(arg, "--ignore-scripts");
}

fn isFalseWord(arg: []const u8) bool {
    return std.ascii.eqlIgnoreCase(arg, "false");
}

fn filterForwardedArgsForAgePolicy(
    allocator: std.mem.Allocator,
    command_name: []const u8,
    npm_module_minimum_age: ?u64,
    forced: bool,
    forwarded: []const []const u8,
) ![]const []const u8 {
    if (forced) return stripAgeOverrideFlags(allocator, forwarded);

    if (!(std.ascii.eqlIgnoreCase(command_name, "yarn") and (npm_module_minimum_age orelse 0) != 0)) {
        return allocator.dupe([]const u8, forwarded);
    }

    return stripMatchingArgs(allocator, forwarded, isYarnBypassAgePolicyFlag);
}

fn stripAgeOverrideFlags(allocator: std.mem.Allocator, forwarded: []const []const u8) ![]const []const u8 {
    const separator = passthroughSeparatorIndex(forwarded);
    var filtered = std.ArrayListUnmanaged([]const u8){};
    errdefer filtered.deinit(allocator);

    var index: usize = 0;
    while (index < separator) {
        const arg = forwarded[index];
        if (isAgeOverrideEqualsFlag(arg) or isYarnBypassAgePolicyFlag(arg) or isYarnNoTimeGateFlag(arg)) {
            index += 1;
            continue;
        }
        if (isAgeOverrideBareFlag(arg)) {
            index += 1;
            if (index < separator and forwarded[index].len > 0 and forwarded[index][0] != '-') {
                index += 1;
            }
            continue;
        }
        try filtered.append(allocator, arg);
        index += 1;
    }

    if (separator < forwarded.len) {
        try filtered.appendSlice(allocator, forwarded[separator..]);
    }
    return filtered.toOwnedSlice(allocator);
}

fn stripMatchingArgs(
    allocator: std.mem.Allocator,
    forwarded: []const []const u8,
    comptime matches: fn ([]const u8) bool,
) ![]const []const u8 {
    var filtered = std.ArrayListUnmanaged([]const u8){};
    defer filtered.deinit(allocator);

    for (forwarded) |arg| {
        if (matches(arg)) continue;
        try filtered.append(allocator, arg);
    }

    return filtered.toOwnedSlice(allocator);
}

fn isYarnBypassAgePolicyFlag(arg: []const u8) bool {
    return std.ascii.eqlIgnoreCase(arg, "--bypass-age-policy");
}

fn isYarnNoTimeGateFlag(arg: []const u8) bool {
    return std.ascii.eqlIgnoreCase(arg, "--no-time-gate");
}

fn isAgeOverrideBareFlag(arg: []const u8) bool {
    return std.ascii.eqlIgnoreCase(arg, "--min-release-age") or
        std.ascii.eqlIgnoreCase(arg, "--minimum-release-age") or
        std.ascii.eqlIgnoreCase(arg, "--config.min-release-age");
}

fn isAgeOverrideEqualsFlag(arg: []const u8) bool {
    return startsWithIgnoreCase(arg, "--min-release-age=") or
        startsWithIgnoreCase(arg, "--minimum-release-age=") or
        startsWithIgnoreCase(arg, "--config.min-release-age=");
}

fn startsWithIgnoreCase(haystack: []const u8, prefix: []const u8) bool {
    if (haystack.len < prefix.len) return false;
    return std.ascii.eqlIgnoreCase(haystack[0..prefix.len], prefix);
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

fn userInitiatedPmReshim(allocator: std.mem.Allocator, install_root: []const u8, structured_logging: bool) bool {
    // npm i -g from a shell is user intent. npm i -g nested under another global
    // shim (opencode upgrade) is a self-update — keep the VerifyCache gate.
    const data_root = std.fs.path.dirname(install_root) orelse return true;
    const shim_dir = std.fs.path.join(allocator, &.{ data_root, ".shim" }) catch return true;
    defer allocator.free(shim_dir);
    const ancestors = eventlog.listAncestorImagePaths(allocator) catch return true;
    defer eventlog.freeAncestorImagePaths(allocator, ancestors);
    if (module_firewall.nestedUnderNonPmShim(ancestors, shim_dir)) {
        logFirewallInfo(allocator, structured_logging, "firewall.nested_pm_gate", "firewall nested pm install under global shim; leaving VerifyCache gate on");
        return false;
    }
    return true;
}

fn runReshim(allocator: std.mem.Allocator, install_root: []const u8, node_install_dir: []const u8, authorize_changed: bool) void {
    _ = install_root;
    _ = authorize_changed;
    // Route through nvm.exe --reshim so the CLI opens the .shim ACL write
    // window. Spawning utils\reshim.exe alone fails against the locked DACL
    // (manual `nvm reshim` worked because sync/cli unlock first).
    // Authorization to resign disk-changed launchers is decided by nvm.exe
    // from the live parent tree — not NVM_SIGN_CHANGED_MODULES.
    const nvm_path = nodeversion.resolveNvmExePath(allocator) catch {
        std.debug.print("nvm.exe not found under ProgramRoot; skipping post-global reshim\n", .{});
        return;
    };
    defer allocator.free(nvm_path);

    var nonce: [8]u8 = undefined;
    std.crypto.random.bytes(&nonce);
    const hex = std.fmt.bytesToHex(nonce, .lower);
    const ev_name = std.fmt.allocPrint(allocator, "Local\\NVMReshimParentReady-{s}", .{hex}) catch {
        spawnNvmReshim(allocator, nvm_path, node_install_dir, null);
        return;
    };
    defer allocator.free(ev_name);

    const ev = eventlog.createNamedEvent(allocator, ev_name);
    spawnNvmReshim(allocator, nvm_path, node_install_dir, ev_name);
    if (ev) |handle| {
        eventlog.waitAndCloseNamedEvent(handle, 10_000);
    }
}

fn spawnNvmReshim(
    allocator: std.mem.Allocator,
    nvm_path: []const u8,
    node_install_dir: []const u8,
    ready_event: ?[]const u8,
) void {
    var env_map = std.process.getEnvMap(allocator) catch {
        spawnNvmReshimChild(allocator, nvm_path, node_install_dir, ready_event, null);
        return;
    };
    defer env_map.deinit();
    env_map.remove("NVM_SIGN_CHANGED_MODULES");
    spawnNvmReshimChild(allocator, nvm_path, node_install_dir, ready_event, &env_map);
}

fn spawnNvmReshimChild(
    allocator: std.mem.Allocator,
    nvm_path: []const u8,
    node_install_dir: []const u8,
    ready_event: ?[]const u8,
    env_map: ?*std.process.EnvMap,
) void {
    const argv: []const []const u8 = if (ready_event) |name|
        &.{ nvm_path, "--reshim", "--silent", node_install_dir, "--parent-ready-event", name }
    else
        &.{ nvm_path, "--reshim", "--silent", node_install_dir };
    var child = std.process.Child.init(argv, allocator);
    if (env_map) |env| {
        child.env_map = env;
    }
    child.stdin_behavior = .Ignore;
    child.stdout_behavior = .Ignore;
    child.stderr_behavior = .Ignore;
    child.spawn() catch return;
}

fn resignScriptSync(allocator: std.mem.Allocator, script_path: []const u8) bool {
    const nvm_path = nodeversion.resolveNvmExePath(allocator) catch return false;
    defer allocator.free(nvm_path);
    var child = std.process.Child.init(&.{ nvm_path, "--sign-script" }, allocator);
    child.stdin_behavior = .Pipe;
    child.stdout_behavior = .Ignore;
    child.stderr_behavior = .Ignore;
    child.spawn() catch return false;
    if (child.stdin) |stdin| {
        const write_ok = if (stdin.writeAll(script_path)) |_| true else |_| false;
        stdin.close();
        child.stdin = null;
        if (!write_ok) {
            _ = child.kill() catch {};
            _ = child.wait() catch {};
            return false;
        }
    } else {
        _ = child.kill() catch {};
        _ = child.wait() catch {};
        return false;
    }
    const term = child.wait() catch return false;
    return switch (term) {
        .Exited => |code| code == 0,
        else => false,
    };
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

fn hashFileOptional(allocator: std.mem.Allocator, path: []const u8) ?[32]u8 {
    _ = allocator;
    var file = std.fs.openFileAbsolute(path, .{}) catch return null;
    defer file.close();
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    var buf: [8192]u8 = undefined;
    while (true) {
        const n = file.read(&buf) catch return null;
        if (n == 0) break;
        hasher.update(buf[0..n]);
    }
    var out: [32]u8 = undefined;
    hasher.final(&out);
    return out;
}

const EntrypointSnap = struct {
    size: i64,
    mtime: u64,
    volume_serial: u32,
    file_id: u64,
    usn: u64,
    digest: ?[32]u8,
};

fn captureEntrypointSnap(allocator: std.mem.Allocator, path: []const u8) ?EntrypointSnap {
    const times = verifycache.nodeFileTimes(path) catch return null;
    const state = verifycache.nodeFileSecurityState(path) catch return null;
    // Skip full digests for large native binaries (e.g. 100MB+ CLIs); size/mtime/id catch rewrites.
    const digest = if (times.size <= 2 * 1024 * 1024) hashFileOptional(allocator, path) else null;
    return .{
        .size = times.size,
        .mtime = times.mtime,
        .volume_serial = state.volume_serial,
        .file_id = state.file_id,
        .usn = state.usn,
        .digest = digest,
    };
}

/// Content-first comparison. Matching digests win over USN/mtime noise (AV,
/// last-access, ADS). Fall back to identity/size/mtime when a digest is unavailable.
fn entrypointSnapChanged(before: ?EntrypointSnap, after: ?EntrypointSnap) bool {
    const b = before orelse return false;
    const a = after orelse return true;
    if (b.digest) |bd| {
        if (a.digest) |ad| {
            return !std.mem.eql(u8, &bd, &ad);
        }
    }
    if (b.size != a.size) return true;
    if (b.volume_serial != a.volume_serial or b.file_id != a.file_id) return true;
    // mtime without digest: useful for large native CLI self-updates; ignore USN-only noise.
    if (b.mtime != a.mtime) return true;
    return false;
}

const EntrypointSnapSet = struct {
    paths: []const []const u8,
    snaps: []const ?EntrypointSnap,

    fn deinit(self: EntrypointSnapSet, allocator: std.mem.Allocator) void {
        for (self.paths) |p| allocator.free(p);
        allocator.free(self.paths);
        allocator.free(self.snaps);
    }
};

fn captureEntrypointSnapSet(allocator: std.mem.Allocator, command_path: []const u8, command_name: []const u8) EntrypointSnapSet {
    var paths = std.ArrayListUnmanaged([]const u8){};
    errdefer {
        for (paths.items) |p| allocator.free(p);
        paths.deinit(allocator);
    }

    const cmd_path = allocator.dupe(u8, command_path) catch null;
    if (cmd_path) |p| {
        paths.append(allocator, p) catch allocator.free(p);
    }

    appendCompanionBinTargets(allocator, &paths, command_path, command_name);

    const owned_paths = paths.toOwnedSlice(allocator) catch return .{ .paths = &[_][]const u8{}, .snaps = &[_]?EntrypointSnap{} };
    const snaps = allocator.alloc(?EntrypointSnap, owned_paths.len) catch {
        for (owned_paths) |p| allocator.free(p);
        allocator.free(owned_paths);
        return .{ .paths = &[_][]const u8{}, .snaps = &[_]?EntrypointSnap{} };
    };
    for (owned_paths, 0..) |p, i| {
        snaps[i] = captureEntrypointSnap(allocator, p);
    }
    return .{ .paths = owned_paths, .snaps = snaps };
}

fn appendCompanionBinTargets(
    allocator: std.mem.Allocator,
    paths: *std.ArrayListUnmanaged([]const u8),
    command_path: []const u8,
    command_name: []const u8,
) void {
    const ext = std.fs.path.extension(command_path);
    if (!(std.ascii.eqlIgnoreCase(ext, ".cmd") or std.ascii.eqlIgnoreCase(ext, ".bat"))) return;

    const version_dir = std.fs.path.dirname(command_path) orelse return;
    const node_modules = std.fs.path.join(allocator, &.{ version_dir, "node_modules" }) catch return;
    defer allocator.free(node_modules);

    var nm_dir = std.fs.cwd().openDir(node_modules, .{ .iterate = true }) catch return;
    defer nm_dir.close();

    var it = nm_dir.iterate();
    while (it.next() catch null) |entry| {
        if (entry.kind != .directory) continue;
        if (std.mem.eql(u8, entry.name, ".bin")) continue;
        const candidate = std.fs.path.join(allocator, &.{ node_modules, entry.name, "bin", command_name }) catch continue;
        defer allocator.free(candidate);
        // Prefer .exe companion (self-updating native CLIs).
        const exe = std.mem.concat(allocator, u8, &.{ candidate, ".exe" }) catch continue;
        std.fs.cwd().access(exe, .{}) catch {
            allocator.free(exe);
            continue;
        };
        paths.append(allocator, exe) catch allocator.free(exe);
    }
}

fn entrypointSnapSetChanged(before: EntrypointSnapSet, after: EntrypointSnapSet) bool {
    for (before.paths, before.snaps) |bp, bs| {
        var found = false;
        for (after.paths, after.snaps) |ap, as| {
            if (!std.ascii.eqlIgnoreCase(bp, ap)) continue;
            found = true;
            if (entrypointSnapChanged(bs, as)) return true;
            break;
        }
        if (!found and bs != null) return true;
    }
    for (after.paths, after.snaps) |ap, as| {
        if (as == null) continue;
        var found = false;
        for (before.paths) |bp| {
            if (std.ascii.eqlIgnoreCase(bp, ap)) {
                found = true;
                break;
            }
        }
        if (!found) return true;
    }
    return false;
}

fn pmInstallLike(command_name: []const u8, args: []const []const u8) bool {
    return module_firewall.commandInstallLike(command_name, args);
}

const code_module_firewall_blocked: u32 = 4403;
const code_module_firewall_allowed: u32 = 4408;

fn logPackageManagerInstallAudit(
    allocator: std.mem.Allocator,
    command_name: []const u8,
    global: bool,
    pkgs: []const module_firewall.PackageSpec,
    outcome: []const u8,
    event_code: u32,
    denied: bool,
) void {
    if (!build_options.certified) return;

    var audit_ctx = eventlog.captureAuditContext(allocator);
    defer audit_ctx.deinit(allocator);

    const package_raws = allocator.alloc([]const u8, pkgs.len) catch return;
    defer allocator.free(package_raws);
    for (pkgs, 0..) |pkg, i| {
        package_raws[i] = pkg.raw;
    }

    const payload = .{
        .packages = package_raws,
        .global = global,
        .outcome = outcome,
        .command = command_name,
        .user = audit_ctx.user,
        .hostname = audit_ctx.hostname,
        .sid = audit_ctx.sid,
        .parent_process = audit_ctx.parent_process,
        .parent_pid = audit_ctx.parent_pid,
        .project_name = audit_ctx.project_name,
        .project_path = audit_ctx.project_path,
    };
    if (denied) {
        eventlog.writeStructuredErrorCode(allocator, "proxy", "package_manager.install", payload, event_code);
    } else {
        eventlog.writeStructuredInfoCode(allocator, "proxy", "package_manager.install", payload, event_code);
    }
}

fn enforceModuleFirewall(allocator: std.mem.Allocator, structured_logging: bool, command_name: []const u8, args: []const []const u8) !void {
    if (!pmInstallLike(command_name, args)) return;

    const global = npmOrPnpmNeedsReshim(args) or (std.ascii.eqlIgnoreCase(command_name, "yarn") and args.len > 0 and std.ascii.eqlIgnoreCase(args[0], "global"));
    const key = if (global) module_firewall.reg_value_approved_global_modules else module_firewall.reg_value_approved_modules;
    const loaded = module_firewall.loadFirewallList(allocator, key);
    const rules = loaded.values;
    defer module_firewall.freeMultiSz(allocator, rules);

    // Empty list => default ALL (no enforcement).
    if (rules.len == 0) return;

    // HTTPS remote: pass CLI package tokens only. Empty → Go expands lock/package.json.
    if (module_firewall.listHasHttps(rules)) {
        const cli_pkgs = try module_firewall.collectPackageTokensFromArgs(allocator, command_name, args);
        defer module_firewall.freePackageSpecs(allocator, cli_pkgs);
        try evaluateRemoteModuleFirewall(allocator, structured_logging, command_name, global, cli_pkgs, args);
        return;
    }

    const cwd = std.fs.cwd().realpathAlloc(allocator, ".") catch try std.process.getCwdAlloc(allocator);
    defer allocator.free(cwd);

    const pkgs = try module_firewall.collectInstallPackages(allocator, command_name, args, cwd);
    defer module_firewall.freePackageSpecs(allocator, pkgs);

    if (pkgs.len == 0) return;

    var blocked_raws = std.ArrayListUnmanaged([]const u8){};
    defer blocked_raws.deinit(allocator);
    for (pkgs) |pkg| {
        const allowed = module_firewall.isPackageAllowed(pkg, rules) orelse true;
        if (!allowed) {
            try blocked_raws.append(allocator, pkg.raw);
        }
    }
    if (blocked_raws.items.len == 0) {
        logPackageManagerInstallAudit(allocator, command_name, global, pkgs, "allowed", code_module_firewall_allowed, false);
        return;
    }

    const cap: usize = 20;
    const show = @min(blocked_raws.items.len, cap);
    var i: usize = 0;
    while (i < show) : (i += 1) {
        const raw = blocked_raws.items[i];
        std.debug.print("NVM Firewall: {s} blocked by {s}. (NVM4403)\n", .{ raw, loaded.source.label() });
        if (!structured_logging) {
            const msg = std.fmt.allocPrint(allocator, "NVM Firewall: {s} blocked by {s}. (NVM4403)", .{ raw, loaded.source.label() }) catch continue;
            defer allocator.free(msg);
            eventlog.writeInfoCode(allocator, "proxy", msg, code_module_firewall_blocked);
        }
    }
    if (blocked_raws.items.len > cap) {
        std.debug.print("and {d} more\n", .{blocked_raws.items.len - cap});
    }
    logPackageManagerInstallAudit(allocator, command_name, global, pkgs, "denied", code_module_firewall_blocked, true);
    if (structured_logging) {
        logFirewallInfo(allocator, structured_logging, "firewall.module_install_blocked", "firewall module install blocked (NVM4403)");
    }
    std.process.exit(1);
}

fn isNpmAuthCommand(command_name: []const u8, args: []const []const u8) bool {
    const is_npm = std.mem.eql(u8, command_name, "npm") or std.mem.eql(u8, command_name, "npx");
    const is_pnpm = std.mem.eql(u8, command_name, "pnpm");
    if (!is_npm and !is_pnpm) return false;
    for (args) |a| {
        if (a.len == 0 or a[0] == '-') continue;
        return std.mem.eql(u8, a, "login") or
            std.mem.eql(u8, a, "adduser") or
            std.mem.eql(u8, a, "logout") or
            std.mem.eql(u8, a, "whoami");
    }
    return false;
}

fn maybeRefreshNpmIdentity(allocator: std.mem.Allocator) void {
    const nvm_path = nodeversion.resolveNvmExePath(allocator) catch return;
    defer allocator.free(nvm_path);
    var child = std.process.Child.init(&.{ nvm_path, "firewall", "refresh-npm-identity" }, allocator);
    child.stdin_behavior = .Ignore;
    child.stdout_behavior = .Ignore;
    child.stderr_behavior = .Ignore;
    child.spawn() catch return;
    _ = child.wait() catch {};
}

fn evaluateRemoteModuleFirewall(allocator: std.mem.Allocator, structured_logging: bool, command_name: []const u8, global: bool, pkgs: []const module_firewall.PackageSpec, args: []const []const u8) !void {
    const nvm_path = nodeversion.resolveNvmExePath(allocator) catch {
        std.debug.print("NVM4402 Module firewall remote HTTPS policy configured but nvm.exe not found.\n", .{});
        logFirewallError(allocator, structured_logging, "firewall.remote_failed", "firewall remote URL blocked; nvm.exe missing (NVM4402)", 4402);
        std.process.exit(1);
    };
    defer allocator.free(nvm_path);

    var argv = std.ArrayListUnmanaged([]const u8){};
    defer argv.deinit(allocator);
    try argv.append(allocator, nvm_path);
    try argv.append(allocator, "firewall");
    try argv.append(allocator, "check-remote");
    if (global) try argv.append(allocator, "--global");
    try argv.append(allocator, "--shim");
    try argv.append(allocator, command_name);
    const cwd_for_remote = std.fs.cwd().realpathAlloc(allocator, ".") catch try std.process.getCwdAlloc(allocator);
    defer allocator.free(cwd_for_remote);
    try argv.append(allocator, "--cwd");
    try argv.append(allocator, cwd_for_remote);
    if (module_firewall.productionOmit(args)) {
        try argv.append(allocator, "--omit-dev");
    }
    for (pkgs) |pkg| {
        try argv.append(allocator, pkg.raw);
    }

    var child = std.process.Child.init(argv.items, allocator);
    child.stdin_behavior = .Ignore;
    child.stdout_behavior = .Inherit;
    child.stderr_behavior = .Inherit;
    const term = child.spawnAndWait() catch {
        std.debug.print("NVM4402 Module firewall remote validation failed to start.\n", .{});
        logFirewallError(allocator, structured_logging, "firewall.remote_failed", "firewall remote helper spawn failed (NVM4402)", 4402);
        std.process.exit(1);
    };
    switch (term) {
        .Exited => |code| {
            if (code == 0) {
                logPackageManagerInstallAudit(allocator, command_name, global, pkgs, "allowed", code_module_firewall_allowed, false);
                return;
            }
            if (code == 1) {
                logPackageManagerInstallAudit(allocator, command_name, global, pkgs, "denied", code_module_firewall_blocked, true);
                logFirewallInfo(allocator, structured_logging, "firewall.remote_blocked", "firewall remote policy blocked install (NVM4403)");
                std.process.exit(1);
            }
            // Exit 2+: check-remote already wrote the NVM44xx user message to stderr.
            if (code == 2) {
                logFirewallError(allocator, structured_logging, "firewall.remote_failed", "firewall remote validation failed", 4402);
                std.process.exit(1);
            }
            std.debug.print("NVM4402 Module firewall remote validation failed (exit {d}).\n", .{code});
            logFirewallError(allocator, structured_logging, "firewall.remote_failed", "firewall remote validation failed (NVM4402)", 4402);
            std.process.exit(1);
        },
        else => {
            std.debug.print("NVM4402 Module firewall remote validation aborted.\n", .{});
            logFirewallError(allocator, structured_logging, "firewall.remote_failed", "firewall remote validation aborted (NVM4402)", 4402);
            std.process.exit(1);
        },
    }
}

fn loadTrustedModules(allocator: std.mem.Allocator) ![]const []const u8 {
    const rules = module_firewall.loadMultiSzPolicy(allocator, module_firewall.reg_value_trusted_modules) catch &[_][]const u8{};
    if (rules.len == 0) {
        // Empty TrustedModules: deny all except bundled package managers.
        const defaults = [_][]const u8{ "NOT ALL", "npm", "npx", "yarn", "yarnpkg", "corepack", "pnpm" };
        var out = try allocator.alloc([]const u8, defaults.len);
        for (defaults, 0..) |entry, i| {
            out[i] = try allocator.dupe(u8, entry);
        }
        return out;
    }
    return rules;
}

/// Local TrustedModules first; if untrusted and an HTTPS URL is configured, ask nvm check-remote-trust
/// (HTTP only for modules not already trusted locally).
const ModuleTrust = enum { trusted, remote_blocked, untrusted };

fn classifyModuleTrust(allocator: std.mem.Allocator, command_name: []const u8, rules: []const []const u8) ModuleTrust {
    const pkg = module_firewall.PackageSpec{ .name = command_name, .version = "", .raw = command_name };
    if (module_firewall.isPackageAllowed(pkg, rules) orelse false) return .trusted;
    if (module_firewall.extractHttpsUrl(rules) == null) return .untrusted;
    return evaluateRemoteTrust(allocator, command_name);
}

fn evaluateRemoteTrust(allocator: std.mem.Allocator, command_name: []const u8) ModuleTrust {
    const nvm_path = nodeversion.resolveNvmExePath(allocator) catch {
        std.debug.print("NVM Firewall: Remote trust service is unavailable or not responding (nvm.exe not found).\n", .{});
        return .untrusted;
    };
    defer allocator.free(nvm_path);

	var child = std.process.Child.init(&.{ nvm_path, "firewall", "check-remote-trust", "--shim", command_name, command_name }, allocator);
    child.stdin_behavior = .Ignore;
    child.stdout_behavior = .Inherit;
    child.stderr_behavior = .Inherit;
    const term = child.spawnAndWait() catch {
        std.debug.print("NVM Firewall: Remote trust service is unavailable or not responding.\n", .{});
        return .untrusted;
    };
    return switch (term) {
        .Exited => |code| switch (code) {
            0 => .trusted,
            1 => .remote_blocked,
            else => .untrusted,
        },
        else => .untrusted,
    };
}

const UntrustedHandlerAction = enum { deny, prompt, allow };

fn untrustedHandlerAction(allocator: std.mem.Allocator) UntrustedHandlerAction {
    const raw = registry.queryStringWithFallback(allocator, registry.preferenceHives(), config.preference_registry_root, module_firewall.reg_value_untrusted_handler) catch {
        return .prompt;
    };
    defer allocator.free(raw);
    const trimmed = std.mem.trim(u8, raw, " \t");
    if (trimmed.len == 0) return .prompt;
    if (std.ascii.eqlIgnoreCase(trimmed, "deny")) return .deny;
    if (std.ascii.eqlIgnoreCase(trimmed, "allow")) return .allow;
    return .prompt;
}

fn notifyModuleAutoTrusted(allocator: std.mem.Allocator, command_name: []const u8) void {
    const nvm_path = nodeversion.resolveNvmExePath(allocator) catch return;
    defer allocator.free(nvm_path);
    var child = std.process.Child.init(&.{ nvm_path, "firewall", "notify-changed", command_name }, allocator);
    child.stdin_behavior = .Ignore;
    child.stdout_behavior = .Ignore;
    child.stderr_behavior = .Ignore;
    _ = child.spawnAndWait() catch {};
}

fn notifyUntrustedModuleChangedInfo(allocator: std.mem.Allocator, command_name: []const u8) void {
    const msg = std.fmt.allocPrint(
        allocator,
        "Untrusted module '{s}' changed after running. Next launch will ask whether to trust it.\nTo allow self-updates now: nvm firewall trust module {s}\n",
        .{ command_name, command_name },
    ) catch return;
    defer allocator.free(msg);
    std.debug.print("{s}", .{msg});
}

const untrusted_module_changed_code: u32 = 4406;

fn logFirewallInfo(allocator: std.mem.Allocator, structured_logging: bool, event_name: []const u8, plaintext: []const u8) void {
    if (structured_logging) {
        eventlog.writeStructuredInfo(allocator, "proxy", event_name, .{ .message = plaintext });
    } else {
        eventlog.writeInfo(allocator, "proxy", plaintext);
    }
}

fn logFirewallError(allocator: std.mem.Allocator, structured_logging: bool, event_name: []const u8, plaintext: []const u8, code: u32) void {
    if (structured_logging) {
        eventlog.writeStructuredErrorCode(allocator, "proxy", event_name, .{ .message = plaintext }, code);
    } else {
        eventlog.writeInfoCode(allocator, "proxy", plaintext, code);
    }
}

const ModuleChangeAudit = struct {
    path: []u8,
    before_digest: []u8,
    after_digest: []u8,
    before_size: i64,
    after_size: i64,

    fn deinit(self: ModuleChangeAudit, allocator: std.mem.Allocator) void {
        allocator.free(self.path);
        allocator.free(self.before_digest);
        allocator.free(self.after_digest);
    }
};

fn emptyOwned(allocator: std.mem.Allocator) []u8 {
    return allocator.alloc(u8, 0) catch {
        return allocator.dupe(u8, "") catch unreachable;
    };
}

fn digestBytesToHex(allocator: std.mem.Allocator, digest: ?[32]u8) []u8 {
    const d = digest orelse return emptyOwned(allocator);
    var out = allocator.alloc(u8, 64) catch return emptyOwned(allocator);
    const digits = "0123456789abcdef";
    for (d, 0..) |byte, i| {
        out[i * 2] = digits[byte >> 4];
        out[i * 2 + 1] = digits[byte & 0x0f];
    }
    return out;
}

fn auditFromSnaps(allocator: std.mem.Allocator, path: []const u8, before: ?EntrypointSnap, after: ?EntrypointSnap) ModuleChangeAudit {
    return .{
        .path = allocator.dupe(u8, path) catch emptyOwned(allocator),
        .before_digest = digestBytesToHex(allocator, if (before) |b| b.digest else null),
        .after_digest = digestBytesToHex(allocator, if (after) |a| a.digest else null),
        .before_size = if (before) |b| b.size else -1,
        .after_size = if (after) |a| a.size else -1,
    };
}

fn firstChangedEntrypointAudit(allocator: std.mem.Allocator, before: EntrypointSnapSet, after: EntrypointSnapSet, fallback_path: []const u8) ModuleChangeAudit {
    for (before.paths, before.snaps) |bp, bs| {
        var found = false;
        for (after.paths, after.snaps) |ap, as| {
            if (!std.ascii.eqlIgnoreCase(bp, ap)) continue;
            found = true;
            if (entrypointSnapChanged(bs, as)) {
                return auditFromSnaps(allocator, bp, bs, as);
            }
            break;
        }
        if (!found and bs != null) {
            return auditFromSnaps(allocator, bp, bs, null);
        }
    }
    for (after.paths, after.snaps) |ap, as| {
        if (as == null) continue;
        var found = false;
        for (before.paths) |bp| {
            if (std.ascii.eqlIgnoreCase(bp, ap)) {
                found = true;
                break;
            }
        }
        if (!found) {
            return auditFromSnaps(allocator, ap, null, as);
        }
    }
    return auditFromSnaps(allocator, fallback_path, null, null);
}

fn auditFromVerifyCache(allocator: std.mem.Allocator, path: []const u8) ModuleChangeAudit {
    var before_digest = emptyOwned(allocator);
    var before_size: i64 = -1;
    if (verifycache.loadCachedContent(allocator, path)) |cached| {
        allocator.free(before_digest);
        before_digest = cached.digest;
        before_size = cached.size;
    }

    var after_digest = emptyOwned(allocator);
    var after_size: i64 = -1;
    if (verifycache.nodeFileTimes(path) catch null) |times| {
        after_size = times.size;
        if (times.size <= 2 * 1024 * 1024) {
            if (verifycache.fileSha256Hex(allocator, path) catch null) |hex| {
                allocator.free(after_digest);
                after_digest = hex;
            }
        }
    }

    return .{
        .path = allocator.dupe(u8, path) catch emptyOwned(allocator),
        .before_digest = before_digest,
        .after_digest = after_digest,
        .before_size = before_size,
        .after_size = after_size,
    };
}

fn logUntrustedModuleChanged(
    allocator: std.mem.Allocator,
    structured_logging: bool,
    module: []const u8,
    outcome: []const u8,
    handler: []const u8,
    via: []const u8,
    audit: ModuleChangeAudit,
) void {
    const plaintext = blk: {
        if (audit.before_digest.len > 0 or audit.after_digest.len > 0) {
            break :blk std.fmt.allocPrint(
                allocator,
                "NVM{d} Untrusted module '{s}' changed (outcome={s}, handler={s}, via={s}, path={s}, before={s}, after={s})",
                .{ untrusted_module_changed_code, module, outcome, handler, via, audit.path, audit.before_digest, audit.after_digest },
            ) catch return;
        }
        if (audit.before_size >= 0 or audit.after_size >= 0) {
            break :blk std.fmt.allocPrint(
                allocator,
                "NVM{d} Untrusted module '{s}' changed (outcome={s}, handler={s}, via={s}, path={s}, before_size={d}, after_size={d})",
                .{ untrusted_module_changed_code, module, outcome, handler, via, audit.path, audit.before_size, audit.after_size },
            ) catch return;
        }
        break :blk std.fmt.allocPrint(
            allocator,
            "NVM{d} Untrusted module '{s}' changed (outcome={s}, handler={s}, via={s}, path={s})",
            .{ untrusted_module_changed_code, module, outcome, handler, via, audit.path },
        ) catch return;
    };
    defer allocator.free(plaintext);
    var audit_ctx = eventlog.captureAuditContext(allocator);
    defer audit_ctx.deinit(allocator);
    eventlog.writeInfoCode(allocator, "proxy", plaintext, untrusted_module_changed_code);
    if (structured_logging) {
        eventlog.writeStructuredInfoCode(
            allocator,
            "proxy",
            "firewall.untrusted_module_changed",
            .{
                .module = module,
                .outcome = outcome,
                .handler = handler,
                .via = via,
                .path = audit.path,
                .before_digest = audit.before_digest,
                .after_digest = audit.after_digest,
                .before_size = audit.before_size,
                .after_size = audit.after_size,
                .user = audit_ctx.user,
                .sid = audit_ctx.sid,
                .hostname = audit_ctx.hostname,
                .parent_process = audit_ctx.parent_process,
                .parent_pid = audit_ctx.parent_pid,
                .project_name = audit_ctx.project_name,
                .project_path = audit_ctx.project_path,
            },
            untrusted_module_changed_code,
        );
    }
}

const PromptTrustResult = enum { accepted, declined, no_answer };

fn promptTrustChange(allocator: std.mem.Allocator, command_name: []const u8) PromptTrustResult {
    const nvm_path = nodeversion.resolveNvmExePath(allocator) catch {
        return promptTrustChangeConsoleOnly(allocator, command_name, null);
    };
    defer allocator.free(nvm_path);

    var child = std.process.Child.init(&.{ nvm_path, "firewall", "prompt-trust", command_name }, allocator);
    child.stdin_behavior = .Inherit;
    child.stdout_behavior = .Inherit;
    child.stderr_behavior = .Inherit;
    const term = child.spawnAndWait() catch {
        return promptTrustChangeConsoleOnly(allocator, command_name, nvm_path);
    };
    return switch (term) {
        .Exited => |code| switch (code) {
            0 => .accepted,
            2 => .no_answer,
            else => .declined,
        },
        else => .no_answer,
    };
}

fn promptTrustChangeConsoleOnly(allocator: std.mem.Allocator, command_name: []const u8, nvm_path: ?[]const u8) PromptTrustResult {
    const msg = std.fmt.allocPrint(allocator, "Untrusted module '{s}' changed. Do you trust this module? [y/N]: ", .{command_name}) catch {
        return .no_answer;
    };
    defer allocator.free(msg);
    std.debug.print("{s}", .{msg});
    var stdin_buffer: [16]u8 = undefined;
    const stdin = std.fs.File.stdin();
    const n = stdin.read(stdin_buffer[0..]) catch {
        std.debug.print("No trust answer for '{s}' (no console). NVM moved on. If you trust this: nvm firewall trust module {s}\n", .{ command_name, command_name });
        return .no_answer;
    };
    if (n == 0) {
        std.debug.print("No trust answer for '{s}' (no console). NVM moved on. If you trust this: nvm firewall trust module {s}\n", .{ command_name, command_name });
        return .no_answer;
    }
    const answer = std.mem.trim(u8, stdin_buffer[0..n], " \t\r\n");
    const ok = answer.len > 0 and (answer[0] == 'y' or answer[0] == 'Y');
    if (ok) {
        if (nvm_path) |exe| {
            var trust = std.process.Child.init(&.{ exe, "firewall", "trust", "module", command_name }, allocator);
            trust.stdin_behavior = .Ignore;
            trust.stdout_behavior = .Ignore;
            trust.stderr_behavior = .Ignore;
            _ = trust.spawnAndWait() catch {};
            std.debug.print("{s} is now trusted\n", .{command_name});
        }
        return .accepted;
    }
    std.debug.print("{s} is not trusted\n", .{command_name});
    return .declined;
}

fn maybeReshimAfterSelfUpdate(
    allocator: std.mem.Allocator,
    install_root: []const u8,
    node_install_dir: []const u8,
    command_name: []const u8,
    command_path: []const u8,
    snap_before: EntrypointSnapSet,
    structured_logging: bool,
) !void {
    const snap_after = captureEntrypointSnapSet(allocator, command_path, command_name);
    defer snap_after.deinit(allocator);
    if (!entrypointSnapSetChanged(snap_before, snap_after)) return;

    // Package managers already handled via needs_reshim.
    if (isPackageManagerCommand(command_name)) {
        return;
    }

    const rules = try loadTrustedModules(allocator);
    defer module_firewall.freeMultiSz(allocator, rules);

    const trust = classifyModuleTrust(allocator, command_name, rules);
    const audit = firstChangedEntrypointAudit(allocator, snap_before, snap_after, command_path);
    defer audit.deinit(allocator);
    if (trust == .trusted) {
        logFirewallInfo(allocator, structured_logging, "firewall.trusted_module_changed", "firewall trusted module changed; scheduling reshim");
        _ = resignScriptSync(allocator, command_path);
        runReshim(allocator, install_root, node_install_dir, true);
        return;
    }
    if (trust == .remote_blocked) {
        logUntrustedModuleChanged(allocator, structured_logging, command_name, "deny", "remote", "post_run", audit);
        logFirewallInfo(allocator, structured_logging, "firewall.remote_blocked", "firewall remote policy blocked module; reshim not scheduled (no prompt)");
        return;
    }
    switch (untrustedHandlerAction(allocator)) {
        .deny => {
            logUntrustedModuleChanged(allocator, structured_logging, command_name, "deny", "deny", "post_run", audit);
            logFirewallInfo(allocator, structured_logging, "firewall.untrusted_deny", "firewall untrusted module changed; reshim not scheduled (deny)");
        },
        .allow => {
            logUntrustedModuleChanged(allocator, structured_logging, command_name, "allow", "allow", "post_run", audit);
            logFirewallInfo(allocator, structured_logging, "firewall.untrusted_allow", "firewall untrusted module changed; allow auto-trust; scheduling reshim");
            notifyModuleAutoTrusted(allocator, command_name);
            _ = resignScriptSync(allocator, command_path);
            runReshim(allocator, install_root, node_install_dir, true);
        },
        .prompt => {
            logUntrustedModuleChanged(allocator, structured_logging, command_name, "prompt_deferred", "prompt", "post_run", audit);
            logFirewallInfo(allocator, structured_logging, "firewall.prompt_deferred", "firewall untrusted module changed after run; prompt deferred to next launch");
            notifyUntrustedModuleChangedInfo(allocator, command_name);
        },
    }
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

fn expectArgStrings(args: []const []const u8, expected: []const []const u8) !void {
    try std.testing.expectEqual(expected.len, args.len);
    for (expected, args) |want, got| {
        try std.testing.expectEqualStrings(want, got);
    }
}

test "rewriteIgnoreScriptsArgs appends the flag before the passthrough separator" {
    const allocator = std.testing.allocator;
    const args = try rewriteIgnoreScriptsArgs(allocator, &.{ "install", "left-pad", "--", "--coverage" });
    defer allocator.free(args);
    try expectArgStrings(args, &.{ "install", "left-pad", "--ignore-scripts", "--", "--coverage" });
}

test "rewriteIgnoreScriptsArgs removes flags that turn scripts back on" {
    const allocator = std.testing.allocator;
    const args = try rewriteIgnoreScriptsArgs(allocator, &.{
        "install",
        "--ignore-scripts=false",
        "--no-ignore-scripts",
        "--config.ignore-scripts=false",
        "--ignore-scripts",
        "false",
        "left-pad",
    });
    defer allocator.free(args);
    try expectArgStrings(args, &.{ "install", "left-pad", "--ignore-scripts" });
}

test "lifecycleScriptAction selects the package manager lock" {
    try std.testing.expectEqual(LifecycleScriptAction.ignore_scripts_flag, lifecycleScriptAction("npm", &.{ "install", "left-pad" }, null));
    try std.testing.expectEqual(LifecycleScriptAction.ignore_scripts_flag, lifecycleScriptAction("pnpm", &.{"install"}, null));
    try std.testing.expectEqual(LifecycleScriptAction.ignore_scripts_flag, lifecycleScriptAction("corepack", &.{ "pnpm", "install" }, null));
    try std.testing.expectEqual(LifecycleScriptAction.ignore_scripts_flag, lifecycleScriptAction("yarn", &.{"install"}, 1));
    try std.testing.expectEqual(LifecycleScriptAction.yarn_berry_env, lifecycleScriptAction("yarnpkg", &.{"install"}, 4));
    try std.testing.expectEqual(LifecycleScriptAction.yarn_berry_env, lifecycleScriptAction("corepack", &.{ "yarn", "install" }, 3));
    try std.testing.expectEqual(LifecycleScriptAction.unchanged, lifecycleScriptAction("yarn", &.{"install"}, null));
    try std.testing.expectEqual(LifecycleScriptAction.unchanged, lifecycleScriptAction("corepack", &.{ "prepare", "yarn@stable" }, null));
    try std.testing.expectEqual(LifecycleScriptAction.unchanged, lifecycleScriptAction("corepack", &.{"enable"}, 1));
}

test "yarn package json major comes from the yarn package version" {
    const allocator = std.testing.allocator;
    try std.testing.expectEqual(@as(?u32, 1), yarnMajorFromYarnPackageJson(allocator, "{\"name\":\"yarn\",\"version\":\"1.22.22\"}"));
    try std.testing.expectEqual(@as(?u32, 4), yarnMajorFromYarnPackageJson(allocator, "{\"name\":\"yarn\",\"version\":\"4.9.1\"}"));
    try std.testing.expect(yarnMajorFromYarnPackageJson(allocator, "{\"name\":\"corepack\",\"version\":\"0.30.0\"}") == null);
}

test "project packageManager field selects the yarn major" {
    const allocator = std.testing.allocator;
    try std.testing.expectEqual(@as(?u32, 1), yarnMajorFromProjectPackageJson(allocator, "{\"packageManager\":\"yarn@1.22.22\"}"));
    try std.testing.expectEqual(@as(?u32, 4), yarnMajorFromProjectPackageJson(allocator, "{\"packageManager\":\"yarn@4.9.1+sha512.abc\"}"));
    try std.testing.expect(yarnMajorFromProjectPackageJson(allocator, "{\"packageManager\":\"pnpm@9.0.0\"}") == null);
    try std.testing.expectEqual(@as(?u32, 1), yarnMajorFromPackageManagerField("yarn@1"));
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

    const filtered = try filterForwardedArgsForAgePolicy(allocator, "yarn", 1440, false, &original);
    defer allocator.free(filtered);

    try std.testing.expectEqual(@as(usize, 3), filtered.len);
    try std.testing.expectEqualStrings("add", filtered[0]);
    try std.testing.expectEqualStrings("left-pad", filtered[1]);
    try std.testing.expectEqualStrings("--dev", filtered[2]);
}

test "filterForwardedArgsForAgePolicy keeps yarn bypass flag when minutes is zero or missing" {
    const allocator = std.testing.allocator;
    const original = [_][]const u8{ "add", "--bypass-age-policy" };

    const missing = try filterForwardedArgsForAgePolicy(allocator, "yarn", null, false, &original);
    defer allocator.free(missing);
    try std.testing.expectEqual(@as(usize, 2), missing.len);
    try std.testing.expectEqualStrings("--bypass-age-policy", missing[1]);

    const zero = try filterForwardedArgsForAgePolicy(allocator, "yarn", 0, false, &original);
    defer allocator.free(zero);
    try std.testing.expectEqual(@as(usize, 2), zero.len);
    try std.testing.expectEqualStrings("--bypass-age-policy", zero[1]);
}

test "filterForwardedArgsForAgePolicy keeps npm min-release-age when not forced" {
    const allocator = std.testing.allocator;
    const original = [_][]const u8{ "install", "left-pad", "--min-release-age=0" };

    const filtered = try filterForwardedArgsForAgePolicy(allocator, "npm", 2880, false, &original);
    defer allocator.free(filtered);

    try std.testing.expectEqual(@as(usize, 3), filtered.len);
    try std.testing.expectEqualStrings("--min-release-age=0", filtered[2]);
}

test "filterForwardedArgsForAgePolicy strips age flags when HKLM policy is forced" {
    const allocator = std.testing.allocator;
    const original = [_][]const u8{
        "install",
        "left-pad",
        "--min-release-age=0",
        "--min-release-age",
        "0",
        "--config.min-release-age=0",
        "--minimum-release-age",
        "0",
        "--no-time-gate",
        "--bypass-age-policy",
        "--",
        "--min-release-age=0",
    };

    const filtered = try filterForwardedArgsForAgePolicy(allocator, "npm", 2880, true, &original);
    defer allocator.free(filtered);

    try expectArgStrings(filtered, &.{ "install", "left-pad", "--", "--min-release-age=0" });
}

test "filterForwardedArgsForAgePolicy forced DWORD 0 still strips CLI age flags" {
    const allocator = std.testing.allocator;
    const original = [_][]const u8{ "install", "left-pad", "--min-release-age=3" };

    const filtered = try filterForwardedArgsForAgePolicy(allocator, "npm", 0, true, &original);
    defer allocator.free(filtered);

    try expectArgStrings(filtered, &.{ "install", "left-pad" });
}

test "corepackBackedArgv prefixes command name" {
    const allocator = std.testing.allocator;
    const forwarded = [_][]const u8{ "-v", "--verbose" };
    const argv = try corepackBackedArgv(allocator, "C:\\nvm\\node.exe", "C:\\nvm\\corepack.js", "yarn", &forwarded);
    defer allocator.free(argv);

    try std.testing.expectEqual(@as(usize, 5), argv.len);
    try std.testing.expectEqualStrings("C:\\nvm\\node.exe", argv[0]);
    try std.testing.expectEqualStrings("C:\\nvm\\corepack.js", argv[1]);
    try std.testing.expectEqualStrings("yarn", argv[2]);
    try std.testing.expectEqualStrings("-v", argv[3]);
    try std.testing.expectEqualStrings("--verbose", argv[4]);
}

test "isCorepackBackedCommand covers yarn yarnpkg pnpm" {
    try std.testing.expect(isCorepackBackedCommand("yarn"));
    try std.testing.expect(isCorepackBackedCommand("YARNPKG"));
    try std.testing.expect(isCorepackBackedCommand("pnpm"));
    try std.testing.expect(!isCorepackBackedCommand("npm"));
    try std.testing.expect(!isCorepackBackedCommand("corepack"));
}

test "nodeShipsBundledCorepack matches Node shipping windows" {
    try std.testing.expect(!nodeShipsBundledCorepack("12.22.12"));
    try std.testing.expect(!nodeShipsBundledCorepack("14.18.3"));
    try std.testing.expect(nodeShipsBundledCorepack("v14.19.0"));
    try std.testing.expect(nodeShipsBundledCorepack("14.21.3"));
    try std.testing.expect(!nodeShipsBundledCorepack("15.14.0"));
    try std.testing.expect(!nodeShipsBundledCorepack("16.8.0"));
    try std.testing.expect(nodeShipsBundledCorepack("16.9.0"));
    try std.testing.expect(nodeShipsBundledCorepack("18.20.4"));
    try std.testing.expect(nodeShipsBundledCorepack("24.11.0"));
    try std.testing.expect(!nodeShipsBundledCorepack("25.0.0"));
    try std.testing.expect(!nodeShipsBundledCorepack("25.2.1"));
    try std.testing.expect(!nodeShipsBundledCorepack(""));
}

test "resolveCorepackCommand uses corepack.cmd when present" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("node");
    try tmp.dir.writeFile(.{ .sub_path = "node\\corepack.cmd", .data = "@ECHO off\r\n" });

    const version_dir = try tmp.dir.realpathAlloc(allocator, "node");
    defer allocator.free(version_dir);
    const resolved = try resolveCorepackCommand(allocator, version_dir, "25.0.0");
    defer allocator.free(resolved);
    try std.testing.expect(std.ascii.endsWithIgnoreCase(resolved, "corepack.cmd"));
}

test "resolveCorepackCommand notes unbundled Node when missing" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("node");
    const version_dir = try tmp.dir.realpathAlloc(allocator, "node");
    defer allocator.free(version_dir);
    try std.testing.expectError(error.CommandNotFound, resolveCorepackCommand(allocator, version_dir, "25.0.0"));
    try std.testing.expectError(error.CommandNotFound, resolveDelegatedOrCorepackPath(allocator, version_dir, "corepack", "v15.14.0"));
    try std.testing.expectError(error.CommandNotFound, resolveCorepackCommand(allocator, version_dir, "22.11.0"));
}

test "yarnClassicGlobalBinDir joins LocalAppData Yarn bin" {
    const allocator = std.testing.allocator;
    const dir = try yarnClassicGlobalBinDir(allocator) orelse return error.SkipZigTest;
    defer allocator.free(dir);
    try std.testing.expect(std.ascii.endsWithIgnoreCase(dir, "Yarn\\bin") or std.ascii.endsWithIgnoreCase(dir, "Yarn/bin"));
}

test "resolveDelegatedOrCorepackPath uses Yarn Classic global bin" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("node");
    try tmp.dir.makePath("Yarn\\bin");
    try tmp.dir.writeFile(.{ .sub_path = "Yarn\\bin\\vue.cmd", .data = "@ECHO off\r\n" });
    try tmp.dir.writeFile(.{ .sub_path = "node\\tsc.cmd", .data = "@ECHO off\r\n" });

    const version_dir = try tmp.dir.realpathAlloc(allocator, "node");
    defer allocator.free(version_dir);
    const fake_local = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(fake_local);

    const Env = struct {
        extern "kernel32" fn SetEnvironmentVariableW(
            lpName: [*:0]const u16,
            lpValue: ?[*:0]const u16,
        ) callconv(.winapi) std.os.windows.BOOL;

        fn setLocalAppData(gpa: std.mem.Allocator, value: []const u8) !void {
            const name_w = try std.unicode.utf8ToUtf16LeAllocZ(gpa, "LOCALAPPDATA");
            defer gpa.free(name_w);
            const value_w = try std.unicode.utf8ToUtf16LeAllocZ(gpa, value);
            defer gpa.free(value_w);
            if (SetEnvironmentVariableW(name_w, value_w) == 0) return error.SetEnvironmentVariableFailed;
        }
    };

    const previous = std.process.getEnvVarOwned(allocator, "LOCALAPPDATA") catch null;
    defer if (previous) |value| allocator.free(value);
    try Env.setLocalAppData(allocator, fake_local);
    defer {
        if (previous) |value| {
            Env.setLocalAppData(allocator, value) catch {};
        }
    }

    const vue_path = try resolveDelegatedOrCorepackPath(allocator, version_dir, "vue", "24.21.0");
    defer allocator.free(vue_path);
    try std.testing.expect(std.ascii.endsWithIgnoreCase(vue_path, "Yarn\\bin\\vue.cmd") or std.ascii.endsWithIgnoreCase(vue_path, "Yarn/bin/vue.cmd"));

    const tsc_path = try resolveDelegatedOrCorepackPath(allocator, version_dir, "tsc", "24.21.0");
    defer allocator.free(tsc_path);
    try std.testing.expect(std.ascii.endsWithIgnoreCase(tsc_path, "node\\tsc.cmd") or std.ascii.endsWithIgnoreCase(tsc_path, "node/tsc.cmd"));
}

test "lastNpmrcPrefix keeps the last prefix and skips comments" {
    const contents =
        \\; prefix=C:\ignored
        \\registry=https://registry.npmjs.org/
        \\prefix = "D:\first"
        \\# prefix=C:\also-ignored
        \\prefix=E:\global
    ;
    const got = lastNpmrcPrefix(contents) orelse return error.MissingPrefix;
    try std.testing.expectEqualStrings("E:\\global", got);
}

test "classifyPackageLauncher accepts npm yarn shim and rejects traversal and corepack" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("prefix\\node_modules\\yarn\\bin");
    try tmp.dir.makePath("prefix\\node_modules\\pnpm\\bin");
    try tmp.dir.writeFile(.{ .sub_path = "prefix\\node_modules\\yarn\\bin\\yarn.js", .data = "#!/usr/bin/env node\n" });
    try tmp.dir.writeFile(.{ .sub_path = "prefix\\node_modules\\pnpm\\bin\\pnpm.cjs", .data = "#!/usr/bin/env node\n" });
    try tmp.dir.writeFile(.{
        .sub_path = "prefix\\yarn.cmd",
        .data = "@ECHO off\r\n\"%_prog%\" \"%dp0%\\node_modules\\yarn\\bin\\yarn.js\" %*\r\n",
    });
    try tmp.dir.writeFile(.{
        .sub_path = "prefix\\yarnpkg.cmd",
        .data = "@ECHO off\r\n\"%_prog%\" \"%~dp0\\node_modules\\yarn\\bin\\yarn.js\" %*\r\n",
    });
    try tmp.dir.writeFile(.{
        .sub_path = "prefix\\pnpm.cmd",
        .data = "@ECHO off\r\n\"%_prog%\" \"%dp0%\\node_modules\\pnpm\\bin\\pnpm.cjs\" %*\r\n",
    });
    try tmp.dir.writeFile(.{
        .sub_path = "prefix\\yarn-corepack.cmd",
        .data = "@ECHO off\r\nnode \"%~dp0%\\node_modules\\corepack\\dist\\corepack.js\" yarn %*\r\n",
    });
    try tmp.dir.writeFile(.{
        .sub_path = "prefix\\yarn-escape.cmd",
        .data = "@ECHO off\r\nnode \"%dp0%\\node_modules\\yarn\\bin\\..\\..\\..\\outside.js\" %*\r\n",
    });
    try tmp.dir.writeFile(.{ .sub_path = "outside.js", .data = "nope\n" });
    try tmp.dir.writeFile(.{
        .sub_path = "prefix\\yarn-absolute.cmd",
        .data = "@ECHO off\r\nnode \"C:\\evil\\node_modules\\yarn\\bin\\yarn.js\" %*\r\n",
    });

    const root = try tmp.dir.realpathAlloc(allocator, "prefix");
    defer allocator.free(root);

    const yarn_cmd = try std.fs.path.join(allocator, &.{ root, "yarn.cmd" });
    defer allocator.free(yarn_cmd);
    switch (try classifyPackageLauncher(allocator, yarn_cmd, "yarn")) {
        .package_js => |js_path| {
            defer allocator.free(js_path);
            try std.testing.expect(std.ascii.endsWithIgnoreCase(js_path, "node_modules\\yarn\\bin\\yarn.js") or std.ascii.endsWithIgnoreCase(js_path, "node_modules/yarn/bin/yarn.js"));
        },
        else => return error.ExpectedPackageJs,
    }

    const yarnpkg_cmd = try std.fs.path.join(allocator, &.{ root, "yarnpkg.cmd" });
    defer allocator.free(yarnpkg_cmd);
    switch (try classifyPackageLauncher(allocator, yarnpkg_cmd, "yarn")) {
        .package_js => |js_path| allocator.free(js_path),
        else => return error.ExpectedPackageJs,
    }

    const pnpm_cmd = try std.fs.path.join(allocator, &.{ root, "pnpm.cmd" });
    defer allocator.free(pnpm_cmd);
    switch (try classifyPackageLauncher(allocator, pnpm_cmd, "pnpm")) {
        .package_js => |js_path| allocator.free(js_path),
        else => return error.ExpectedPackageJs,
    }

    const corepack_cmd = try std.fs.path.join(allocator, &.{ root, "yarn-corepack.cmd" });
    defer allocator.free(corepack_cmd);
    switch (try classifyPackageLauncher(allocator, corepack_cmd, "yarn")) {
        .corepack_trampoline => {},
        else => return error.ExpectedCorepackTrampoline,
    }

    const escape_cmd = try std.fs.path.join(allocator, &.{ root, "yarn-escape.cmd" });
    defer allocator.free(escape_cmd);
    switch (try classifyPackageLauncher(allocator, escape_cmd, "yarn")) {
        .reject => {},
        .package_js => |js_path| {
            allocator.free(js_path);
            return error.ExpectedReject;
        },
        else => return error.ExpectedReject,
    }

    const absolute_cmd = try std.fs.path.join(allocator, &.{ root, "yarn-absolute.cmd" });
    defer allocator.free(absolute_cmd);
    switch (try classifyPackageLauncher(allocator, absolute_cmd, "yarn")) {
        .reject => {},
        .package_js => |js_path| {
            allocator.free(js_path);
            return error.ExpectedReject;
        },
        else => return error.ExpectedReject,
    }
}

test "version directory corepack trampoline does not use another yarn.js" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("node\\node_modules\\corepack\\dist");
    try tmp.dir.makePath("node\\node_modules\\yarn\\bin");
    try tmp.dir.writeFile(.{ .sub_path = "node\\node_modules\\corepack\\dist\\corepack.js", .data = "corepack\n" });
    try tmp.dir.writeFile(.{ .sub_path = "node\\node_modules\\yarn\\bin\\yarn.js", .data = "yarn\n" });
    try tmp.dir.writeFile(.{
        .sub_path = "node\\yarn.cmd",
        .data = "@ECHO off\r\nnode \"%~dp0%\\node_modules\\corepack\\dist\\corepack.js\" yarn %*\r\n",
    });

    const version = try tmp.dir.realpathAlloc(allocator, "node");
    defer allocator.free(version);
    const resolved = try resolveCorepackBackedCommand(allocator, version, "yarn");
    defer allocator.free(resolved);
    try std.testing.expect(std.ascii.endsWithIgnoreCase(resolved, "corepack.js"));
}

test "classifyPackageLauncher accepts pnpm 12 extensionless bin" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("prefix\\node_modules\\pnpm");
    try tmp.dir.writeFile(.{ .sub_path = "prefix\\node_modules\\pnpm\\pnpm", .data = "#!/usr/bin/env node\n" });
    try tmp.dir.writeFile(.{
        .sub_path = "prefix\\pnpm.cmd",
        .data = "@ECHO off\r\n\"%_prog%\" \"%dp0%\\node_modules\\pnpm\\pnpm\" %*\r\n",
    });

    const root = try tmp.dir.realpathAlloc(allocator, "prefix");
    defer allocator.free(root);
    const pnpm_cmd = try std.fs.path.join(allocator, &.{ root, "pnpm.cmd" });
    defer allocator.free(pnpm_cmd);
    switch (try classifyPackageLauncher(allocator, pnpm_cmd, "pnpm")) {
        .package_js => |js_path| {
            defer allocator.free(js_path);
            try std.testing.expect(std.ascii.endsWithIgnoreCase(js_path, "node_modules\\pnpm\\pnpm") or std.ascii.endsWithIgnoreCase(js_path, "node_modules/pnpm/pnpm"));
        },
        else => return error.ExpectedPackageJs,
    }
}

test "classifyPackageLauncher rejects extensionless PE as a script" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("prefix\\node_modules\\pnpm");
    try tmp.dir.writeFile(.{ .sub_path = "prefix\\node_modules\\pnpm\\pnpm", .data = "MZ\x90\x00native" });
    try tmp.dir.writeFile(.{
        .sub_path = "prefix\\pnpm.cmd",
        .data = "@ECHO off\r\n\"%_prog%\" \"%dp0%\\node_modules\\pnpm\\pnpm\" %*\r\n",
    });

    const root = try tmp.dir.realpathAlloc(allocator, "prefix");
    defer allocator.free(root);
    const pnpm_cmd = try std.fs.path.join(allocator, &.{ root, "pnpm.cmd" });
    defer allocator.free(pnpm_cmd);
    switch (try classifyPackageLauncher(allocator, pnpm_cmd, "pnpm")) {
        .reject => {},
        .package_js => |js_path| {
            allocator.free(js_path);
            return error.ExpectedReject;
        },
        else => return error.ExpectedReject,
    }
}

test "resolvePackageModuleEntry prefers pnpm.mjs over extensionless bin" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("node\\node_modules\\pnpm\\bin");
    try tmp.dir.writeFile(.{ .sub_path = "node\\node_modules\\pnpm\\bin\\pnpm.mjs", .data = "export {}\n" });
    try tmp.dir.writeFile(.{ .sub_path = "node\\node_modules\\pnpm\\pnpm", .data = "#!/usr/bin/env node\n" });

    const version = try tmp.dir.realpathAlloc(allocator, "node");
    defer allocator.free(version);
    const entry = try resolvePackageModuleEntry(allocator, version, "pnpm", "pnpm") orelse return error.MissingEntry;
    defer allocator.free(entry);
    try std.testing.expect(std.ascii.endsWithIgnoreCase(entry, "pnpm.mjs"));
}

test "pnpm.exe in version dir wins over module js" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("node\\node_modules\\pnpm\\bin");
    try tmp.dir.writeFile(.{ .sub_path = "node\\pnpm.exe", .data = "MZ\x90\x00" });
    try tmp.dir.writeFile(.{ .sub_path = "node\\node_modules\\pnpm\\bin\\pnpm.mjs", .data = "export {}\n" });
    try tmp.dir.writeFile(.{
        .sub_path = "node\\pnpm.cmd",
        .data = "@ECHO off\r\n\"%_prog%\" \"%dp0%\\node_modules\\pnpm\\bin\\pnpm.mjs\" %*\r\n",
    });

    const version = try tmp.dir.realpathAlloc(allocator, "node");
    defer allocator.free(version);
    const resolved = try resolveCorepackBackedCommand(allocator, version, "pnpm");
    defer allocator.free(resolved);
    try std.testing.expect(std.ascii.endsWithIgnoreCase(resolved, "pnpm.exe"));
}

test "pnpm without exe uses global module js" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("node\\node_modules\\pnpm\\bin");
    try tmp.dir.writeFile(.{ .sub_path = "node\\node_modules\\pnpm\\bin\\pnpm.mjs", .data = "export {}\n" });
    try tmp.dir.writeFile(.{
        .sub_path = "node\\pnpm.cmd",
        .data = "@ECHO off\r\n\"%_prog%\" \"%dp0%\\node_modules\\pnpm\\bin\\pnpm.mjs\" %*\r\n",
    });

    const version = try tmp.dir.realpathAlloc(allocator, "node");
    defer allocator.free(version);
    const resolved = try resolveCorepackBackedCommand(allocator, version, "pnpm");
    defer allocator.free(resolved);
    if (std.ascii.endsWithIgnoreCase(resolved, "pnpm.exe")) {
        try std.testing.expect(!std.ascii.startsWithIgnoreCase(resolved, version));
        return;
    }
    try std.testing.expect(std.ascii.endsWithIgnoreCase(resolved, "pnpm.mjs"));
}
