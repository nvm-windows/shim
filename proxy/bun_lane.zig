const std = @import("std");
const build_options = @import("build_options");
const nodeversion = @import("nodeversion");
const shim_bun = @import("shim_bun");
const malware_scan = @import("malware_scan.zig");

/// If argv0 is bun/bunx, find the real bun, optionally scan, spawn, and exit.
/// Returns when the invoked name is not bun.
pub fn runIfBun(
    allocator: std.mem.Allocator,
    cfg: nodeversion.ShimConfig,
    command_name: []const u8,
    forwarded: []const []const u8,
) !void {
    if (!shim_bun.isBunCommand(command_name)) return;

    const self_exe = try std.fs.selfExePathAlloc(allocator);
    defer allocator.free(self_exe);
    const data_root = std.fs.path.dirname(cfg.root) orelse cfg.root;
    const shim_dir = try std.fs.path.join(allocator, &.{ data_root, ".shim" });
    defer allocator.free(shim_dir);

    const target = (try shim_bun.find(allocator, command_name, shim_dir, self_exe)) orelse {
        std.debug.print("NVM: bun is not on PATH. NVM for Windows does not install bun and does not switch bun versions.\n", .{});
        std.process.exit(1);
    };
    defer target.deinit(allocator);

    if (shim_bun.enabled(build_options.certified)) {
        var bare = false;
        try malware_scan.enforce(
            allocator,
            cfg.structured_logging,
            command_name,
            forwarded,
            cfg.root,
            null,
            &bare,
        );
    }

    const minutes = nodeversion.effectiveNpmModuleMinimumAge(cfg.npm_module_minimum_age, build_options.certified);
    const forced = cfg.npm_module_minimum_age_machine_policy;
    var age_args = try prepareBunMinimumAgeForwarded(allocator, command_name, target.insert_x, minutes, forced, forwarded);
    defer age_args.deinit(allocator);

    var env_map = try std.process.getEnvMap(allocator);
    defer env_map.deinit();
    const code = try spawn(allocator, &env_map, target, age_args.args);
    std.process.exit(code);
}

fn spawn(
    allocator: std.mem.Allocator,
    env_map: *std.process.EnvMap,
    target: shim_bun.Target,
    forwarded: []const []const u8,
) !u8 {
    const extra: usize = if (target.insert_x) 1 else 0;
    var argv = try allocator.alloc([]const u8, forwarded.len + 1 + extra);
    defer allocator.free(argv);
    argv[0] = target.path;
    if (target.insert_x) {
        argv[1] = "x";
        for (forwarded, 0..) |arg, i| argv[i + 2] = arg;
    } else {
        for (forwarded, 0..) |arg, i| argv[i + 1] = arg;
    }

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

pub const BunAgeForwarded = struct {
    args: []const []const u8,
    owned_seconds: ?[]u8,

    pub fn deinit(self: BunAgeForwarded, allocator: std.mem.Allocator) void {
        if (self.owned_seconds) |value| allocator.free(value);
        allocator.free(self.args);
    }
};

/// Bun has no env for minimumReleaseAge — inject `--minimum-release-age <seconds>`
/// (minutes × 60) on install-class commands. Forced HKLM policy strips CLI age
/// flags and excludes so users cannot bypass.
pub fn prepareBunMinimumAgeForwarded(
    allocator: std.mem.Allocator,
    command_name: []const u8,
    insert_x: bool,
    minutes: ?u64,
    forced: bool,
    forwarded: []const []const u8,
) !BunAgeForwarded {
    if (!bunInstallClass(command_name, insert_x, forwarded)) {
        return .{
            .args = try allocator.dupe([]const u8, forwarded),
            .owned_seconds = null,
        };
    }

    const age_minutes = minutes orelse 0;
    if (!forced and age_minutes == 0) {
        return .{
            .args = try allocator.dupe([]const u8, forwarded),
            .owned_seconds = null,
        };
    }

    if (!forced and hasBunAgeFlag(forwarded)) {
        return .{
            .args = try allocator.dupe([]const u8, forwarded),
            .owned_seconds = null,
        };
    }

    const stripped = if (forced)
        try stripBunAgeFlags(allocator, forwarded)
    else
        try allocator.dupe([]const u8, forwarded);
    errdefer allocator.free(stripped);

    if (age_minutes == 0) {
        return .{ .args = stripped, .owned_seconds = null };
    }

    const seconds = age_minutes * 60;
    const seconds_value = try std.fmt.allocPrint(allocator, "{d}", .{seconds});
    errdefer allocator.free(seconds_value);

    // bunx: flags must precede the package so they are not forwarded to it.
    // bun <verb>: inject after the verb (install/add/…).
    const at_front = insert_x or std.ascii.eqlIgnoreCase(command_name, "bunx");
    const injected = try injectBunAgeFlag(allocator, stripped, seconds_value, at_front);
    allocator.free(stripped);
    return .{ .args = injected, .owned_seconds = seconds_value };
}

fn bunInstallClass(command_name: []const u8, insert_x: bool, forwarded: []const []const u8) bool {
    if (insert_x or std.ascii.eqlIgnoreCase(command_name, "bunx")) return true;

    for (forwarded) |arg| {
        if (arg.len == 0) continue;
        if (arg[0] == '-') continue;
        return std.ascii.eqlIgnoreCase(arg, "install") or
            std.ascii.eqlIgnoreCase(arg, "i") or
            std.ascii.eqlIgnoreCase(arg, "add") or
            std.ascii.eqlIgnoreCase(arg, "update") or
            std.ascii.eqlIgnoreCase(arg, "create") or
            std.ascii.eqlIgnoreCase(arg, "x");
    }
    return false;
}

fn hasBunAgeFlag(forwarded: []const []const u8) bool {
    for (forwarded) |arg| {
        if (isBunAgeEqualsFlag(arg) or isBunAgeBareFlag(arg)) return true;
    }
    return false;
}

fn isBunAgeBareFlag(arg: []const u8) bool {
    return std.ascii.eqlIgnoreCase(arg, "--minimum-release-age") or
        std.ascii.eqlIgnoreCase(arg, "--minimum-release-age-excludes");
}

fn isBunAgeEqualsFlag(arg: []const u8) bool {
    return startsWithIgnoreCase(arg, "--minimum-release-age=") or
        startsWithIgnoreCase(arg, "--minimum-release-age-excludes=");
}

fn startsWithIgnoreCase(haystack: []const u8, prefix: []const u8) bool {
    if (haystack.len < prefix.len) return false;
    return std.ascii.eqlIgnoreCase(haystack[0..prefix.len], prefix);
}

fn stripBunAgeFlags(allocator: std.mem.Allocator, forwarded: []const []const u8) ![]const []const u8 {
    var filtered = std.ArrayListUnmanaged([]const u8){};
    errdefer filtered.deinit(allocator);

    var index: usize = 0;
    while (index < forwarded.len) {
        const arg = forwarded[index];
        if (std.mem.eql(u8, arg, "--")) {
            try filtered.appendSlice(allocator, forwarded[index..]);
            break;
        }
        if (isBunAgeEqualsFlag(arg)) {
            index += 1;
            continue;
        }
        if (isBunAgeBareFlag(arg)) {
            index += 1;
            if (index < forwarded.len and forwarded[index].len > 0 and forwarded[index][0] != '-') {
                index += 1;
            }
            continue;
        }
        try filtered.append(allocator, arg);
        index += 1;
    }
    return filtered.toOwnedSlice(allocator);
}

fn injectBunAgeFlag(
    allocator: std.mem.Allocator,
    forwarded: []const []const u8,
    seconds_value: []const u8,
    at_front: bool,
) ![]const []const u8 {
    var out = std.ArrayListUnmanaged([]const u8){};
    errdefer out.deinit(allocator);

    if (at_front) {
        try out.append(allocator, "--minimum-release-age");
        try out.append(allocator, seconds_value);
        try out.appendSlice(allocator, forwarded);
        return out.toOwnedSlice(allocator);
    }

    var inserted = false;
    for (forwarded) |arg| {
        try out.append(allocator, arg);
        if (inserted) continue;
        if (arg.len == 0 or arg[0] == '-') continue;
        try out.append(allocator, "--minimum-release-age");
        try out.append(allocator, seconds_value);
        inserted = true;
    }
    if (!inserted) {
        try out.append(allocator, "--minimum-release-age");
        try out.append(allocator, seconds_value);
    }
    return out.toOwnedSlice(allocator);
}

fn expectArgStrings(args: []const []const u8, expected: []const []const u8) !void {
    try std.testing.expectEqual(expected.len, args.len);
    for (expected, args) |want, got| {
        try std.testing.expectEqualStrings(want, got);
    }
}

test "prepareBunMinimumAgeForwarded injects seconds after install verb" {
    const allocator = std.testing.allocator;
    var prepared = try prepareBunMinimumAgeForwarded(allocator, "bun", false, 1440, false, &.{ "install", "left-pad" });
    defer prepared.deinit(allocator);
    try expectArgStrings(prepared.args, &.{ "install", "--minimum-release-age", "86400", "left-pad" });
}

test "prepareBunMinimumAgeForwarded keeps user flag when not forced" {
    const allocator = std.testing.allocator;
    var prepared = try prepareBunMinimumAgeForwarded(
        allocator,
        "bun",
        false,
        1440,
        false,
        &.{ "add", "--minimum-release-age", "60", "left-pad" },
    );
    defer prepared.deinit(allocator);
    try expectArgStrings(prepared.args, &.{ "add", "--minimum-release-age", "60", "left-pad" });
}

test "prepareBunMinimumAgeForwarded forced strips age and excludes then injects" {
    const allocator = std.testing.allocator;
    var prepared = try prepareBunMinimumAgeForwarded(
        allocator,
        "bun",
        false,
        2880,
        true,
        &.{
            "install",
            "--minimum-release-age=0",
            "--minimum-release-age-excludes",
            "@types/node",
            "left-pad",
            "--",
            "--minimum-release-age=0",
        },
    );
    defer prepared.deinit(allocator);
    try expectArgStrings(prepared.args, &.{
        "install",
        "--minimum-release-age",
        "172800",
        "left-pad",
        "--",
        "--minimum-release-age=0",
    });
}

test "prepareBunMinimumAgeForwarded forced DWORD 0 strips without inject" {
    const allocator = std.testing.allocator;
    var prepared = try prepareBunMinimumAgeForwarded(
        allocator,
        "bun",
        false,
        0,
        true,
        &.{ "install", "--minimum-release-age", "60", "left-pad" },
    );
    defer prepared.deinit(allocator);
    try expectArgStrings(prepared.args, &.{ "install", "left-pad" });
}

test "prepareBunMinimumAgeForwarded skips non-install bun commands" {
    const allocator = std.testing.allocator;
    var prepared = try prepareBunMinimumAgeForwarded(allocator, "bun", false, 1440, false, &.{ "test", "unit" });
    defer prepared.deinit(allocator);
    try expectArgStrings(prepared.args, &.{ "test", "unit" });
}

test "prepareBunMinimumAgeForwarded applies to bunx before package" {
    const allocator = std.testing.allocator;
    var prepared = try prepareBunMinimumAgeForwarded(allocator, "bunx", false, 10, false, &.{"cowsay"});
    defer prepared.deinit(allocator);
    try expectArgStrings(prepared.args, &.{ "--minimum-release-age", "600", "cowsay" });
}
