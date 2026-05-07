const std = @import("std");
const build_options = @import("build_options");
const nodeversion = @import("nodeversion");
const resolver = @import("resolver");
const eventlog = @import("eventlog");
const errors = @import("errors");

const ParsedArgs = struct {
    override_version: ?[]const u8,
    nvm_use_debug: bool,
    forwarded: []const []const u8,
};

const nodeNotFound = errors.nodeNotFound;
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

    const invoked = std.fs.path.basename(argv[0]);
    const command_name = std.fs.path.stem(invoked);
    // std.debug.print("{s}\n", .{command_name});

    const cfg = try nodeversion.loadConfig(allocator);
    defer nodeversion.deinitConfig(allocator, cfg);

    const resolved = try nodeversion.resolveConfiguredNode(allocator, cfg, parsed_args.override_version);
    defer resolved.deinit(allocator);

    if (resolved.resolved_version == null) nodeNotFound(resolved.effective_version);
    if (resolved.node_bin == null) nodeNotFound(resolved.resolved_version.?);

    if (parsed_args.nvm_use_debug) {
        std.debug.print(
            "nvm version resolution: source={s} requested={s} effective={s} resolved={s} node={s}\n",
            .{ resolved.version_source, resolved.requested_version, resolved.effective_version, resolved.resolved_version.?, resolved.node_bin.? },
        );
    }

    if (!try enforcePackageManagerConstraint(allocator, cfg, resolved.version_source, command_name, resolved.node_bin.?)) {
        std.process.exit(1);
    }

    const needs_reshim = detectReshimNeeded(command_name, parsed_args.forwarded);

    const node_install_dir = std.fs.path.dirname(resolved.node_bin.?) orelse ".";
    const node_install_dir_abs = try std.fs.path.resolve(allocator, &.{node_install_dir});
    defer allocator.free(node_install_dir_abs);

    const command_path = try resolveDelegatedCommandPath(allocator, node_install_dir_abs, command_name);
    defer allocator.free(command_path);

    const process_exit_code = runDelegatedCommand(allocator, node_install_dir_abs, command_path, parsed_args.forwarded) catch |err| blk: {
        std.debug.print("proxy failed to run {s}: {s}\n", .{ command_name, @errorName(err) });
        break :blk 1;
    };

    // std.debug.print("{s}\n", .{node_install_dir});

    if (needs_reshim) {
        eventlog.write(allocator, "reshim scheduled");
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

    const current_version = try nodeversion.resolvePackageManagerVersion(allocator, node_bin, command_name);
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
            const log_msg = try std.fmt.allocPrint(allocator, "warning: {s}", .{message});
            defer allocator.free(log_msg);
            eventlog.write(allocator, log_msg);
            return true;
        },
        .@"error" => {
            var stderr_file = std.fs.File.stderr();
            var stderr_buf: [512]u8 = undefined;
            var stderr_writer = stderr_file.writer(&stderr_buf);
            try stderr_writer.interface.print("error: {s}\n", .{message});
            try stderr_writer.interface.flush();
            const log_msg = try std.fmt.allocPrint(allocator, "error: {s}", .{message});
            defer allocator.free(log_msg);
            eventlog.write(allocator, log_msg);
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
    const exts = [_][]const u8{ ".cmd", ".exe", ".bat" };

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

fn runDelegatedCommand(allocator: std.mem.Allocator, node_install_dir: []const u8, command_path: []const u8, forwarded: []const []const u8) !u8 {
    var env_map = try std.process.getEnvMap(allocator);
    defer env_map.deinit();

    const old_path = env_map.get("PATH") orelse "";
    const child_path = try std.fmt.allocPrint(allocator, "{s};{s}", .{ node_install_dir, old_path });
    defer allocator.free(child_path);
    try env_map.put("PATH", child_path);

    const ext = std.fs.path.extension(command_path);
    const use_cmd = std.ascii.eqlIgnoreCase(ext, ".cmd") or std.ascii.eqlIgnoreCase(ext, ".bat");

    var argv = if (use_cmd)
        try allocator.alloc([]const u8, forwarded.len + 4)
    else
        try allocator.alloc([]const u8, forwarded.len + 1);
    defer allocator.free(argv);

    if (use_cmd) {
        argv[0] = "cmd.exe";
        argv[1] = "/d";
        argv[2] = "/c";
        argv[3] = command_path;
        for (forwarded, 0..) |arg, i| {
            argv[i + 4] = arg;
        }
    } else {
        argv[0] = command_path;
        for (forwarded, 0..) |arg, i| {
            argv[i + 1] = arg;
        }
    }

    var child = std.process.Child.init(argv, allocator);
    child.stdin_behavior = .Inherit;
    child.stdout_behavior = .Inherit;
    child.stderr_behavior = .Inherit;
    child.env_map = &env_map;

    try child.spawn();
    const term = try child.wait();

    return switch (term) {
        .Exited => |code| code,
        else => 1,
    };
}

fn runReshim(allocator: std.mem.Allocator, install_root: []const u8, node_install_dir: []const u8) void {
    const reshim_path = std.fs.path.resolve(allocator, &.{ install_root, "..", "utils", "reshim.exe" }) catch return;
    defer allocator.free(reshim_path);

    std.fs.cwd().access(reshim_path, .{}) catch return;

    var child = std.process.Child.init(&.{ reshim_path, node_install_dir }, allocator);
    child.stdin_behavior = .Ignore;
    child.stdout_behavior = .Ignore;
    child.stderr_behavior = .Ignore;

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
