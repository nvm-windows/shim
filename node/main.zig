const std = @import("std");
const build_options = @import("build_options");
const registry = @import("registry");
const nodeversion = @import("nodeversion");
const eventlog = @import("eventlog");
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
        else => return err,
    };
    defer resolved.deinit(allocator);

    nodeversion.ensureInstalledNode(allocator, cfg, parsed_args.override_version, &resolved) catch |err| switch (err) {
        error.NodeNotFound => nodeNotFound(resolved.resolved_version orelse resolved.effective_version),
        error.AutoInstallCancelled => operationCancelled(),
        error.AutoInstallFailed => return err,
    };

    if (parsed_args.nvm_use_debug) {
        std.debug.print(
            "nvm version resolution: source={s} requested={s} effective={s} resolved={s} node={s}\n",
            .{ resolved.version_source, resolved.requested_version, resolved.effective_version, resolved.resolved_version.?, resolved.node_bin.? },
        );
    }

    if (cfg.log_executions) {
        const requested_command = std.fs.path.stem(std.fs.path.basename(args[0]));
        const arguments = if (parsed_args.forwarded.len == 0)
            try allocator.dupe(u8, "")
        else
            try std.mem.join(allocator, " ", parsed_args.forwarded);
        defer allocator.free(arguments);

        const working_directory = std.process.getCwdAlloc(allocator) catch try allocator.dupe(u8, "");
        defer allocator.free(working_directory);

        eventlog.writeStructuredInfo(allocator, "node-shim", "nodejs.executed", .{
            .RequestedCommand = requested_command,
            .ResolvedPath = resolved.node_bin.?,
            .NodeVersion = resolved.resolved_version.?,
            .Arguments = arguments,
            .WorkingDirectory = working_directory,
        });
    }

    const verify_outcome = verifycache.ensureResolvedNodeTrusted(allocator, cfg.root, resolved.node_bin.?);
    switch (verify_outcome.result) {
        .trusted_cache, .verified_full => {},
        .failed => {
            const message = if (verify_outcome.reason.len == 0)
                try std.fmt.allocPrint(allocator, "Node.js executable failed trust verification: {s}", .{resolved.node_bin.?})
            else
                try std.fmt.allocPrint(allocator, "Node.js trust verification failed for {s}: {s}", .{ resolved.node_bin.?, verify_outcome.reason });
            defer allocator.free(message);
            eventlog.writeError(allocator, "node-shim", message);
            nodeVerifyFailed(resolved.node_bin.?, verify_outcome.reason);
        },
    }

    if (parsed_args.forwarded.len == 0) {
        try runNode(allocator, resolved.node_bin.?, resolved.resolved_version.?, cfg, &.{}, true);
        return;
    }

    try runNode(allocator, resolved.node_bin.?, resolved.resolved_version.?, cfg, parsed_args.forwarded, false);
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
) ![]const []const u8 {
    var flags = std.ArrayListUnmanaged([]const u8){};
    errdefer flags.deinit(allocator);

    if (permissionFlag(version, cfg.enforce_permission_model, forwarded)) |flag| {
        try flags.append(allocator, flag);
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

fn runNode(
    allocator: std.mem.Allocator,
    node_bin: []const u8,
    version: []const u8,
    cfg: nodeversion.ShimConfig,
    forwarded: []const []const u8,
    force_repl_console: bool,
) !void {
    const node_dir = std.fs.path.dirname(node_bin) orelse ".";

    var env_map = try std.process.getEnvMap(allocator);
    defer env_map.deinit();

    const old_path = env_map.get("PATH") orelse "";
    const child_path = try std.fmt.allocPrint(allocator, "{s};{s}", .{ node_dir, old_path });
    defer allocator.free(child_path);

    try env_map.put("PATH", child_path);

    const security_forwarded = if (force_repl_console) &.{} else forwarded;
    const security_flags = try collectSecurityFlags(allocator, version, cfg, security_forwarded);
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

    var argv = try allocator.alloc([]const u8, forwarded.len + 1 + extra);
    defer allocator.free(argv);
    argv[0] = node_bin;
    for (security_flags, 0..) |f, i| {
        argv[1 + i] = f;
    }
    for (forwarded, 0..) |a, i| {
        argv[1 + extra + i] = a;
    }

    var child = std.process.Child.init(argv, allocator);
    child.stdin_behavior = .Inherit;
    child.stdout_behavior = .Inherit;
    child.stderr_behavior = .Inherit;
    child.env_map = &env_map;

    try waitAndExit(&child);
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
