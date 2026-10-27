const std = @import("std");
const build_options = @import("build_options");
const registry = @import("registry");
const nodeversion = @import("nodeversion");
const eventlog = @import("eventlog");
const permission_grants = @import("permission_grants");
const config = @import("config");
const errors = @import("errors");
const shimintegrity = @import("shimintegrity");
const verifycache = @import("verifycache");

const shim_version = build_options.version;

const ParsedArgs = struct {
    override_version: ?[]const u8,
    nvm_use_debug: bool,
    show_shim_version: bool,
    forwarded: []const []const u8,
};

const nodeNotFound = errors.nodeNotFound;
const noActiveVersionConfigured = errors.noActiveVersionConfigured;
const nodeVerifyFailed = errors.nodeVerifyFailed;

fn operationCancelled() noreturn {
    std.debug.print("operation cancelled\n", .{});
    std.process.exit(1);
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    const parsed_args = try parseArgs(allocator, args[1..]);
    defer allocator.free(parsed_args.forwarded);

    shimintegrity.verifySelfIfInvokedFromShim(allocator) catch {
        std.debug.print("shim integrity check failed\n", .{});
        std.process.exit(1);
    };

    if (parsed_args.show_shim_version) {
        var stdout_file = std.fs.File.stdout();
        var stdout_buf: [64]u8 = undefined;
        var stdout = stdout_file.writer(&stdout_buf);
        try stdout.interface.print("{s}\n", .{shim_version});
        try stdout.interface.flush();
        return;
    }

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
        error.AutoInstallCancelled => operationCancelled(),
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

    const launch_forwarded: []const []const u8 = if (parsed_args.forwarded.len == 0) &.{} else parsed_args.forwarded;
    var permission_launch = try preparePermissionLaunch(allocator, cfg, resolved.resolved_version.?, launch_forwarded);
    defer permission_launch.deinit(allocator);

    if (cfg.log_executions) {
        const requested_command = std.fs.path.stem(std.fs.path.basename(args[0]));
        const arguments = if (parsed_args.forwarded.len == 0)
            try allocator.dupe(u8, "")
        else
            try std.mem.join(allocator, " ", parsed_args.forwarded);
        defer allocator.free(arguments);

        const working_directory = std.process.getCwdAlloc(allocator) catch try allocator.dupe(u8, "");
        defer allocator.free(working_directory);

        writeNodeExecuted(allocator, audit_ctx, requested_command, resolved.node_bin.?, resolved.resolved_version.?, arguments, working_directory, permission_launch);
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
                    "node-shim",
                    "node.security.cache_state_changed",
                    .{
                        .action = "full_verification_required",
                        .cache_status = @tagName(verify_outcome.cache_status),
                        .node_path = resolved.node_bin.?,
                        .node_version = resolved.resolved_version.?,
                        .source = "node-shim",
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
                    "node-shim",
                    "node.security.full_verification_recovered",
                    .{
                        .action = "execution_allowed",
                        .cache_status = @tagName(verify_outcome.cache_status),
                        .node_path = resolved.node_bin.?,
                        .node_version = resolved.resolved_version.?,
                        .source = "node-shim",
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
                "node-shim",
                "node.security.verification_failed",
                .{
                    .action = "execution_blocked",
                    .cache_status = @tagName(verify_outcome.cache_status),
                    .detail = if (verify_outcome.reason.len == 0) "trust verification failed" else verify_outcome.reason,
                    .failure_kind = "executable_trust_failed",
                    .node_path = resolved.node_bin.?,
                    .node_version = resolved.resolved_version.?,
                    .source = "node-shim",
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

    try runNode(
        allocator,
        resolved.node_bin.?,
        resolved.resolved_version.?,
        cfg,
        shouldForceRepl(parsed_args.forwarded.len == 0, stdinIsConsole()),
        permission_launch,
    );
}

const std_input_handle: u32 = @bitCast(@as(i32, -10));

extern "kernel32" fn GetStdHandle(nStdHandle: u32) callconv(.winapi) ?*anyopaque;
extern "kernel32" fn GetConsoleMode(hConsoleHandle: ?*anyopaque, lpMode: *u32) callconv(.winapi) i32;

fn stdinIsConsole() bool {
    const handle = GetStdHandle(std_input_handle) orelse return false;
    if (@intFromPtr(handle) == std.math.maxInt(usize)) return false;
    var mode: u32 = 0;
    return GetConsoleMode(handle, &mode) != 0;
}

// Bare `node` must open a REPL in a console. Piped/redirected stdin is not a
// TTY; injecting -i forces the REPL, drops async work, and breaks `node < file`.
fn shouldForceRepl(no_forwarded_args: bool, stdin_is_console: bool) bool {
    return no_forwarded_args and stdin_is_console;
}

fn parseArgs(allocator: std.mem.Allocator, args: []const []const u8) !ParsedArgs {
    var forwarded = std.ArrayListUnmanaged([]const u8){};
    defer forwarded.deinit(allocator);

    var override_version: ?[]const u8 = null;
    var nvm_use_debug = false;
    var show_shim_version = false;

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

        if (std.mem.eql(u8, arg, "--nvm-shim-version")) {
            show_shim_version = true;
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
        .show_shim_version = show_shim_version,
        .forwarded = try forwarded.toOwnedSlice(allocator),
    };
}

fn nodeMajorVersion(version: []const u8) u32 {
    const bare = if (version.len > 0 and (version[0] == 'v' or version[0] == 'V')) version[1..] else version;
    const dot = std.mem.indexOfScalar(u8, bare, '.') orelse bare.len;
    return std.fmt.parseInt(u32, bare[0..dot], 10) catch 0;
}

fn forwardedHasExactFlag(forwarded: []const []const u8, flag: []const u8) bool {
    for (forwarded) |arg| {
        if (std.mem.eql(u8, arg, flag)) return true;
    }
    return false;
}

fn alreadyHasPermissionFlag(forwarded: []const []const u8) bool {
    for (forwarded) |arg| {
        if (std.mem.eql(u8, arg, "--permission") or
            std.mem.eql(u8, arg, "--experimental-permission") or
            std.mem.eql(u8, arg, "--permission-audit") or
            std.mem.startsWith(u8, arg, "--permission=") or
            std.mem.startsWith(u8, arg, "--experimental-permission="))
        {
            return true;
        }
    }
    return false;
}

/// Returns the Node permission-model enable flag for this runtime version, or null.
/// Node < 20: unsupported. 20–22: experimental. 23+: stable `--permission`.
fn permissionFlag(version: []const u8, enforce: bool, forwarded: []const []const u8) ?[]const u8 {
    if (!enforce) return null;
    if (alreadyHasPermissionFlag(forwarded)) return null;

    const major = nodeMajorVersion(version);
    if (major < 20) return null;
    if (major >= 23) return "--permission";
    return "--experimental-permission";
}

fn collectSecurityFlags(
    allocator: std.mem.Allocator,
    version: []const u8,
    cfg: nodeversion.ShimConfig,
    forwarded: []const []const u8,
    default_grants: []const []const u8,
) ![]const []const u8 {
    var flags = std.ArrayListUnmanaged([]const u8){};
    errdefer flags.deinit(allocator);

    if (permissionFlag(version, cfg.enforce_permission_model, forwarded)) |flag| {
        try flags.append(allocator, flag);
        for (default_grants) |grant| try flags.append(allocator, grant);
    }

    // --frozen-intrinsics added in Node.js v11.12.0
    if (cfg.freeze_v8_global_objects and
        nodeMajorVersion(version) >= 12 and
        !forwardedHasExactFlag(forwarded, "--frozen-intrinsics"))
    {
        try flags.append(allocator, "--frozen-intrinsics");
    }

    // --disallow-code-generation-from-strings added in Node.js v9.8.0 (always available for supported NVM versions)
    if (cfg.disable_eval_and_string_execution and
        !forwardedHasExactFlag(forwarded, "--disallow-code-generation-from-strings"))
    {
        try flags.append(allocator, "--disallow-code-generation-from-strings");
    }

    return try flags.toOwnedSlice(allocator);
}

const PermissionLaunch = struct {
    filtered: permission_grants.Filtered,
    applied_filter: bool,
    default_values: []const []const u8,
    allow_values: []const []const u8,
    loaded: bool,
    supplied: []u8,
    applied: []u8,
    removed: []u8,

    fn deinit(self: PermissionLaunch, allocator: std.mem.Allocator) void {
        if (self.applied_filter) self.filtered.deinit(allocator);
        if (self.loaded) {
            nodeversion.freeMulti(allocator, self.default_values);
            nodeversion.freeMulti(allocator, self.allow_values);
        }
        allocator.free(self.supplied);
        allocator.free(self.applied);
        allocator.free(self.removed);
    }

    fn active(self: PermissionLaunch) bool {
        return self.supplied.len != 0 or self.applied.len != 0 or self.removed.len != 0;
    }
};

fn preparePermissionLaunch(
    allocator: std.mem.Allocator,
    cfg: nodeversion.ShimConfig,
    version: []const u8,
    forwarded: []const []const u8,
) !PermissionLaunch {
    const supplied = try permission_grants.joinCallerGrants(allocator, forwarded);
    errdefer allocator.free(supplied);
    const injected = permissionFlag(version, cfg.enforce_permission_model, forwarded);
    var default_values: []const []const u8 = &.{};
    var allow_values: []const []const u8 = &.{};
    var loaded_defaults = false;
    var loaded_allow = false;
    var filtered = permission_grants.Filtered{
        .forwarded = forwarded,
        .owns_forwarded = false,
        .dropped = &.{},
        .defaults = &.{},
    };
    var applied_filter = false;
    errdefer if (loaded_defaults) nodeversion.freeMulti(allocator, default_values);
    errdefer if (loaded_allow) nodeversion.freeMulti(allocator, allow_values);
    errdefer if (applied_filter) filtered.deinit(allocator);
    if (injected != null) {
        default_values = try nodeversion.loadPolicyOrPrefMulti(allocator, config.reg_value_default_permission_grants);
        loaded_defaults = true;
        allow_values = try nodeversion.loadPolicyOrPrefMulti(allocator, config.reg_value_allowed_permission_grants);
        loaded_allow = true;
        filtered = try permission_grants.apply(allocator, forwarded, allow_values, default_values);
        applied_filter = true;
    }
    const applied = try std.mem.join(allocator, " ", filtered.defaults);
    errdefer allocator.free(applied);
    const removed = try std.mem.join(allocator, " ", filtered.dropped);
    return .{
        .filtered = filtered,
        .applied_filter = applied_filter,
        .default_values = default_values,
        .allow_values = allow_values,
        .loaded = loaded_defaults and loaded_allow,
        .supplied = supplied,
        .applied = applied,
        .removed = removed,
    };
}

fn writeNodeExecuted(
    allocator: std.mem.Allocator,
    audit_ctx: eventlog.AuditContext,
    requested_command: []const u8,
    resolved_path: []const u8,
    node_version: []const u8,
    arguments: []const u8,
    working_directory: []const u8,
    launch: PermissionLaunch,
) void {
    if (!launch.active()) {
        eventlog.writeStructuredInfo(allocator, "node-shim", "nodejs.executed", .{
            .RequestedCommand = requested_command,
            .ResolvedPath = resolved_path,
            .NodeVersion = node_version,
            .Arguments = arguments,
            .WorkingDirectory = working_directory,
            .user = audit_ctx.user,
            .sid = audit_ctx.sid,
            .hostname = audit_ctx.hostname,
            .parent_process = audit_ctx.parent_process,
            .parent_pid = audit_ctx.parent_pid,
            .project_name = audit_ctx.project_name,
            .project_path = audit_ctx.project_path,
        });
        return;
    }
    eventlog.writeStructuredInfo(allocator, "node-shim", "nodejs.executed", .{
        .RequestedCommand = requested_command,
        .ResolvedPath = resolved_path,
        .NodeVersion = node_version,
        .Arguments = arguments,
        .WorkingDirectory = working_directory,
        .permission_allow = .{
            .supplied = launch.supplied,
            .applied = launch.applied,
            .removed = launch.removed,
        },
        .user = audit_ctx.user,
        .sid = audit_ctx.sid,
        .hostname = audit_ctx.hostname,
        .parent_process = audit_ctx.parent_process,
        .parent_pid = audit_ctx.parent_pid,
        .project_name = audit_ctx.project_name,
        .project_path = audit_ctx.project_path,
    });
}

fn runNode(
    allocator: std.mem.Allocator,
    node_bin: []const u8,
    version: []const u8,
    cfg: nodeversion.ShimConfig,
    force_repl_console: bool,
    launch: PermissionLaunch,
) !void {
    const node_dir = std.fs.path.dirname(node_bin) orelse ".";

    var env_map = try std.process.getEnvMap(allocator);
    defer env_map.deinit();

    const old_path = env_map.get("PATH") orelse "";
    const child_path = try std.fmt.allocPrint(allocator, "{s};{s}", .{ node_dir, old_path });
    defer allocator.free(child_path);

    try env_map.put("PATH", child_path);

    if (cfg.permission_grant_audit or cfg.enforce_permission_model) {
        logPermissionGrants(allocator, cfg, launch) catch {};
    }
    const security_flags = try collectSecurityFlags(allocator, version, cfg, launch.filtered.forwarded, launch.filtered.defaults);
    defer allocator.free(security_flags);
    const extra = security_flags.len;

    if (force_repl_console) {
        var base_argv = try allocator.alloc([]const u8, 2 + extra);
        defer allocator.free(base_argv);
        base_argv[0] = node_bin;
        for (security_flags, 0..) |f, i| {
            base_argv[1 + i] = f;
        }
        base_argv[1 + extra] = "-i";
        var child = std.process.Child.init(base_argv, allocator);
        child.stdin_behavior = .Inherit;
        child.stdout_behavior = .Inherit;
        child.stderr_behavior = .Inherit;
        child.env_map = &env_map;

        try waitAndExit(&child);
        return;
    }

    var argv = try allocator.alloc([]const u8, launch.filtered.forwarded.len + 1 + extra);
    defer allocator.free(argv);
    argv[0] = node_bin;
    for (security_flags, 0..) |f, i| {
        argv[1 + i] = f;
    }
    for (launch.filtered.forwarded, 0..) |a, i| {
        argv[1 + extra + i] = a;
    }

    var child = std.process.Child.init(argv, allocator);
    child.stdin_behavior = .Inherit;
    child.stdout_behavior = .Inherit;
    child.stderr_behavior = .Inherit;
    child.env_map = &env_map;

    try waitAndExit(&child);
}

fn logPermissionGrants(
    allocator: std.mem.Allocator,
    cfg: nodeversion.ShimConfig,
    launch: PermissionLaunch,
) !void {
    if (!launch.active()) return;
    const plaintext = try std.fmt.allocPrint(
        allocator,
        "nodejs.permission_grants supplied {s} applied {s} removed {s}",
        .{ launch.supplied, launch.applied, launch.removed },
    );
    defer allocator.free(plaintext);

    var audit_ctx = eventlog.captureAuditContext(allocator);
    defer audit_ctx.deinit(allocator);
    eventlog.writeLicensedSecurityInfo(allocator, cfg.structured_logging, "node-shim", "nodejs.permission_grants", .{
        .permission_allow = .{
            .supplied = launch.supplied,
            .applied = launch.applied,
            .removed = launch.removed,
        },
        .user = audit_ctx.user,
        .sid = audit_ctx.sid,
        .hostname = audit_ctx.hostname,
        .parent_process = audit_ctx.parent_process,
        .parent_pid = audit_ctx.parent_pid,
        .project_name = audit_ctx.project_name,
        .project_path = audit_ctx.project_path,
    }, plaintext, 0);
}

fn waitAndExit(child: *std.process.Child) !void {
    try child.spawn();
    const term = try child.wait();

    switch (term) {
        .Exited => |code| {
            std.process.exit(code);
        },
        else => {
            std.process.exit(1);
        },
    }
}

test "parseMultiStringUtf16 returns trimmed string entries" {
    const allocator = std.testing.allocator;
    const raw = [_]u16{ 's', 't', 'a', 'b', 'l', 'e', '=', '2', '4', '.', '9', '.', '0', 0, ' ', 'n', 'i', 'g', 'h', 't', 'l', 'y', '=', '2', '5', '.', '0', '.', '0', ' ', 0, 0 };

    const values = try registry.parseMultiStringUtf16(allocator, &raw);
    defer {
        for (values) |value| allocator.free(value);
        allocator.free(values);
    }

    try std.testing.expectEqual(@as(usize, 2), values.len);
    try std.testing.expectEqualStrings("stable=24.9.0", values[0]);
    try std.testing.expectEqualStrings("nightly=25.0.0", values[1]);
}

test "parseArgs accepts nvm-which after forwarded args" {
    const allocator = std.testing.allocator;
    const parsed = try parseArgs(allocator, &.{ "--version", "--nvm-which" });
    defer allocator.free(parsed.forwarded);

    try std.testing.expect(parsed.nvm_use_debug);
    try std.testing.expectEqual(@as(usize, 1), parsed.forwarded.len);
    try std.testing.expectEqualStrings("--version", parsed.forwarded[0]);
}

test "shouldForceRepl only when bare and stdin is console" {
    try std.testing.expect(shouldForceRepl(true, true));
    try std.testing.expect(!shouldForceRepl(true, false));
    try std.testing.expect(!shouldForceRepl(false, true));
    try std.testing.expect(!shouldForceRepl(false, false));
}

test "parseArgs nvm-which alone leaves forwarded empty" {
    const allocator = std.testing.allocator;
    const parsed = try parseArgs(allocator, &.{ "--nvm-which" });
    defer allocator.free(parsed.forwarded);

    try std.testing.expect(parsed.nvm_use_debug);
    try std.testing.expectEqual(@as(usize, 0), parsed.forwarded.len);
}

test "parseArgs detects nvm shim version flag" {
    const allocator = std.testing.allocator;
    const parsed = try parseArgs(allocator, &.{ "--nvm-shim-version", "-e", "console.log('x')" });
    defer allocator.free(parsed.forwarded);

    try std.testing.expect(parsed.show_shim_version);
    try std.testing.expect(parsed.override_version == null);
    try std.testing.expect(!parsed.nvm_use_debug);
    try std.testing.expectEqual(@as(usize, 2), parsed.forwarded.len);
    try std.testing.expectEqualStrings("-e", parsed.forwarded[0]);
    try std.testing.expectEqualStrings("console.log('x')", parsed.forwarded[1]);
}
