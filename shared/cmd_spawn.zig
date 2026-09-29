const std = @import("std");
const builtin = @import("builtin");

/// Argv for spawning a delegated entrypoint (.exe / .cmd / .bat / …).
///
/// For `.cmd`/`.bat`, leave the script as argv[0]. Zig's `std.process.Child` then
/// uses `argvToScriptCommandLineWindows` (safe `cmd /c` quoting). Do **not**
/// hand-build `[cmd.exe, /d, /c, path, …args]` — that breaks when both the
/// script path and a forwarded arg contain spaces (nvm-windows/nvm#1408).
///
/// Returned slice is owned; elements are borrowed from inputs (not duplicated).
pub fn buildEntrypointArgv(
    allocator: std.mem.Allocator,
    command_path: []const u8,
    forwarded_args: []const []const u8,
) ![]const []const u8 {
    var argv = try allocator.alloc([]const u8, forwarded_args.len + 1);
    argv[0] = command_path;
    for (forwarded_args, 0..) |arg, i| {
        argv[i + 1] = arg;
    }
    return argv;
}

/// Legacy argv shape that triggered #1408 (kept for regression proof only).
fn buildLegacyCmdExeArgv(
    allocator: std.mem.Allocator,
    command_path: []const u8,
    forwarded_args: []const []const u8,
) ![]const []const u8 {
    var argv = try allocator.alloc([]const u8, forwarded_args.len + 4);
    argv[0] = "cmd.exe";
    argv[1] = "/d";
    argv[2] = "/c";
    argv[3] = command_path;
    for (forwarded_args, 0..) |arg, i| {
        argv[i + 4] = arg;
    }
    return argv;
}

test "buildEntrypointArgv puts script first without cmd.exe wrap" {
    const allocator = std.testing.allocator;
    const path = "C:\\Author Software\\nvm\\installs\\v24\\opencode.cmd";
    const args = [_][]const u8{ "two words", "--help" };

    const argv = try buildEntrypointArgv(allocator, path, &args);
    defer allocator.free(argv);

    try std.testing.expectEqual(@as(usize, 3), argv.len);
    try std.testing.expectEqualStrings(path, argv[0]);
    try std.testing.expectEqualStrings("two words", argv[1]);
    try std.testing.expectEqualStrings("--help", argv[2]);
    try std.testing.expect(!std.ascii.eqlIgnoreCase(argv[0], "cmd.exe"));
}

test "spaced .cmd path + spaced arg succeeds via entrypoint argv" {
    if (builtin.os.tag != .windows) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Directory name with a space mirrors Author Software install roots.
    try tmp.dir.makePath("shim space test");
    var script_dir = try tmp.dir.openDir("shim space test", .{});
    defer script_dir.close();

    try script_dir.writeFile(.{
        .sub_path = "echoargs.cmd",
        .data = "@echo off\r\necho GOT=[%*]\r\n",
    });

    const abs_dir = try script_dir.realpathAlloc(allocator, ".");
    defer allocator.free(abs_dir);
    const script_path = try std.fs.path.join(allocator, &.{ abs_dir, "echoargs.cmd" });
    defer allocator.free(script_path);

    const forwarded = [_][]const u8{"two words"};
    const argv = try buildEntrypointArgv(allocator, script_path, &forwarded);
    defer allocator.free(argv);

    const result = try std.process.Child.run(.{
        .allocator = allocator,
        .argv = argv,
    });
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    try std.testing.expectEqual(std.process.Child.Term{ .Exited = 0 }, result.term);
    // cmd.exe preserves quotes around spaced args in %*.
    try std.testing.expect(std.mem.indexOf(u8, result.stdout, "GOT=[\"two words\"]") != null);
}

test "legacy cmd.exe /c argv fails when path and arg both have spaces" {
    if (builtin.os.tag != .windows) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("shim space test");
    var script_dir = try tmp.dir.openDir("shim space test", .{});
    defer script_dir.close();

    try script_dir.writeFile(.{
        .sub_path = "echoargs.cmd",
        .data = "@echo off\r\necho GOT=[%*]\r\n",
    });

    const abs_dir = try script_dir.realpathAlloc(allocator, ".");
    defer allocator.free(abs_dir);
    const script_path = try std.fs.path.join(allocator, &.{ abs_dir, "echoargs.cmd" });
    defer allocator.free(script_path);

    const forwarded = [_][]const u8{"two words"};
    const argv = try buildLegacyCmdExeArgv(allocator, script_path, &forwarded);
    defer allocator.free(argv);

    const result = try std.process.Child.run(.{
        .allocator = allocator,
        .argv = argv,
    });
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    // Path tears at the first space → non-zero exit and/or missing GOT= line.
    const ok_out = std.mem.indexOf(u8, result.stdout, "GOT=[\"two words\"]") != null;
    const failed = result.term != .Exited or result.term.Exited != 0 or !ok_out;
    try std.testing.expect(failed);
}
