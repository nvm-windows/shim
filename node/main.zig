const std = @import("std");
const command_line = @import("cli.zig");
const build_options = @import("build_options");
const registry = @import("registry");
const nodeversion = @import("nodeversion");
const eventlog = @import("eventlog");
const errors = @import("errors");

const shim_version = build_options.version;

const ParsedArgs = struct {
    override_version: ?[]const u8,
    nvm_use_debug: bool,
    show_shim_version: bool,
    forwarded: []const []const u8,
};

const nodeNotFound = errors.nodeNotFound;

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

    const original_invocation = try command_line.rawInvocation(allocator);
    defer allocator.free(original_invocation);

    const parsed_args = try parseArgs(allocator, args[1..]);
    defer allocator.free(parsed_args.forwarded);

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

    var resolved = try nodeversion.resolveConfiguredNode(allocator, cfg, parsed_args.override_version);
    defer resolved.deinit(allocator);

    if (resolved.resolved_version == null) {
        if (!cfg.auto_install or parsed_args.override_version != null) nodeNotFound(resolved.effective_version);
        if (cfg.auto_install_prompt and !try confirmAutoInstall(allocator, resolved.effective_version)) operationCancelled();

        const install_version = resolved.effective_version;
        resolved.deinit(allocator);
        try nodeversion.autoInstallVersion(allocator, install_version);
        resolved = try nodeversion.resolveConfiguredNode(allocator, cfg, parsed_args.override_version);
        if (resolved.resolved_version == null) nodeNotFound(resolved.effective_version);
    }

    if (resolved.node_bin == null) {
        if (!cfg.auto_install or parsed_args.override_version != null) nodeNotFound(resolved.resolved_version.?);
        if (cfg.auto_install_prompt and !try confirmAutoInstall(allocator, resolved.resolved_version.?)) operationCancelled();

        const install_version = resolved.resolved_version.?;
        resolved.deinit(allocator);
        try nodeversion.autoInstallVersion(allocator, install_version);
        resolved = try nodeversion.resolveConfiguredNode(allocator, cfg, parsed_args.override_version);
        if (resolved.node_bin == null) nodeNotFound(resolved.resolved_version.?);
    }

    if (parsed_args.nvm_use_debug) {
        std.debug.print(
            "nvm version resolution: source={s} requested={s} effective={s} resolved={s} node={s}\n",
            .{ resolved.version_source, resolved.requested_version, resolved.effective_version, resolved.resolved_version.?, resolved.node_bin.? },
        );
    }

    if (cfg.log_executions) {
        const translated_invocation = try command_line.translatedInvocation(allocator, resolved.node_bin.?, parsed_args.forwarded);
        defer allocator.free(translated_invocation);
        const msg = try command_line.formatLogMessage(allocator, original_invocation, translated_invocation);
        defer allocator.free(msg);
        eventlog.write(allocator, msg);
    }

    if (parsed_args.forwarded.len == 0) {
        try runNode(allocator, resolved.node_bin.?, &.{}, true);
        return;
    }

    try runNode(allocator, resolved.node_bin.?, parsed_args.forwarded, false);
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

        if (std.mem.eql(u8, arg, "--version")) {
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

fn confirmAutoInstall(allocator: std.mem.Allocator, version: []const u8) !bool {
    const prompt = try std.fmt.allocPrint(allocator, "Node.js v{s} is not installed. Install now? [Y/n]: ", .{version});
    defer allocator.free(prompt);

    std.debug.print("{s}", .{prompt});

    var stdin_file = std.fs.File.stdin();
    var read_buf: [256]u8 = undefined;
    var reader = stdin_file.reader(&read_buf);
    const raw_line: []const u8 = reader.interface.takeDelimiterInclusive('\n') catch |err| switch (err) {
        error.EndOfStream => "",
        else => return err,
    };
    const line = std.mem.trim(u8, raw_line, " \t\r\n");

    if (line.len == 0) return true;
    if (std.ascii.eqlIgnoreCase(line, "y") or std.ascii.eqlIgnoreCase(line, "yes")) return true;
    if (std.ascii.eqlIgnoreCase(line, "n") or std.ascii.eqlIgnoreCase(line, "no")) return false;

    return false;
}

fn runNode(allocator: std.mem.Allocator, node_bin: []const u8, forwarded: []const []const u8, force_repl_console: bool) !void {
    const node_dir = std.fs.path.dirname(node_bin) orelse ".";

    var env_map = try std.process.getEnvMap(allocator);
    defer env_map.deinit();

    const old_path = env_map.get("PATH") orelse "";
    const child_path = try std.fmt.allocPrint(allocator, "{s};{s}", .{ node_dir, old_path });
    defer allocator.free(child_path);

    try env_map.put("PATH", child_path);
    if (force_repl_console) {
        var child = std.process.Child.init(&.{ node_bin, "-i" }, allocator);
        child.stdin_behavior = .Inherit;
        child.stdout_behavior = .Inherit;
        child.stderr_behavior = .Inherit;
        child.env_map = &env_map;

        try waitAndExit(&child);
        return;
    }

    var argv = try allocator.alloc([]const u8, forwarded.len + 1);
    defer allocator.free(argv);
    argv[0] = node_bin;
    for (forwarded, 0..) |a, i| {
        argv[i + 1] = a;
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
