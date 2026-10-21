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

    var env_map = try std.process.getEnvMap(allocator);
    defer env_map.deinit();
    const code = try spawn(allocator, &env_map, target, forwarded);
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
