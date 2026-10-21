const std = @import("std");
const windows = std.os.windows;
const config = @import("config");
const registry = @import("registry");

pub const Target = struct {
    path: []u8,
    insert_x: bool,

    pub fn deinit(self: Target, allocator: std.mem.Allocator) void {
        allocator.free(self.path);
    }
};

pub fn isBunCommand(name: []const u8) bool {
    return std.ascii.eqlIgnoreCase(name, "bun") or std.ascii.eqlIgnoreCase(name, "bunx");
}

/// HKLM policy, then HKCU policy, then preferences, else `certified_default`.
pub fn enabled(certified_default: bool) bool {
    const policy = [_]windows.HKEY{ windows.HKEY_LOCAL_MACHINE, windows.HKEY_CURRENT_USER };
    if (registry.queryDwordOptionalWithFallback(&policy, config.policy_registry_root, config.reg_value_shim_bun) catch null) |value| {
        return value != 0;
    }
    if (registry.queryDwordOptionalWithFallback(registry.preferenceHives(), config.preference_registry_root, config.reg_value_shim_bun) catch null) |value| {
        return value != 0;
    }
    return certified_default;
}

/// Locate a real bun binary. Skip `skip_dir` (the NVM `.shim` folder) and `self_exe`
/// (proxy / leftover shim) so PATH lookup cannot loop.
pub fn find(allocator: std.mem.Allocator, command_name: []const u8, skip_dir: []const u8, self_exe: []const u8) !?Target {
    const want_x = std.ascii.eqlIgnoreCase(command_name, "bunx");
    const names: []const []const u8 = if (want_x)
        &.{ "bunx.exe", "bun.exe" }
    else
        &.{"bun.exe"};

    if (try envJoin(allocator, "BUN_INSTALL", &.{ "bin" })) |dir| {
        defer allocator.free(dir);
        if (try firstExisting(allocator, dir, names, want_x, skip_dir, self_exe)) |target| return target;
    }
    if (try envJoin(allocator, "USERPROFILE", &.{ ".bun", "bin" })) |dir| {
        defer allocator.free(dir);
        if (try firstExisting(allocator, dir, names, want_x, skip_dir, self_exe)) |target| return target;
    }

    const path = std.process.getEnvVarOwned(allocator, "PATH") catch return null;
    defer allocator.free(path);
    var it = std.mem.splitScalar(u8, path, ';');
    while (it.next()) |raw| {
        const dir = std.mem.trim(u8, raw, " \t\"");
        if (dir.len == 0) continue;
        if (try firstExisting(allocator, dir, names, want_x, skip_dir, self_exe)) |target| return target;
    }
    return null;
}

fn envJoin(allocator: std.mem.Allocator, env_name: []const u8, extra: []const []const u8) !?[]u8 {
    const root = std.process.getEnvVarOwned(allocator, env_name) catch return null;
    defer allocator.free(root);
    if (root.len == 0) return null;
    var parts = try allocator.alloc([]const u8, extra.len + 1);
    defer allocator.free(parts);
    parts[0] = root;
    for (extra, 0..) |p, i| parts[i + 1] = p;
    return try std.fs.path.join(allocator, parts);
}

fn firstExisting(
    allocator: std.mem.Allocator,
    dir: []const u8,
    names: []const []const u8,
    want_x: bool,
    skip_dir: []const u8,
    self_exe: []const u8,
) !?Target {
    if (sameDir(dir, skip_dir)) return null;
    for (names) |name| {
        const path = try joinAbs(allocator, dir, name);
        const file = std.fs.openFileAbsolute(path, .{}) catch {
            allocator.free(path);
            continue;
        };
        file.close();
        if (self_exe.len > 0 and sameFile(path, self_exe)) {
            allocator.free(path);
            continue;
        }
        const insert_x = want_x and std.ascii.eqlIgnoreCase(std.fs.path.stem(path), "bun");
        return .{ .path = path, .insert_x = insert_x };
    }
    return null;
}

fn joinAbs(allocator: std.mem.Allocator, dir: []const u8, name: []const u8) ![]u8 {
    const joined = try std.fs.path.join(allocator, &.{ dir, name });
    if (std.fs.path.isAbsolute(joined)) return joined;
    const cwd = try std.process.getCwdAlloc(allocator);
    defer allocator.free(cwd);
    const abs = try std.fs.path.resolve(allocator, &.{ cwd, joined });
    allocator.free(joined);
    return abs;
}

fn trimSep(path: []const u8) []const u8 {
    var end = path.len;
    while (end > 0) {
        const c = path[end - 1];
        if (c != '\\' and c != '/') break;
        end -= 1;
    }
    return path[0..end];
}

fn sameDir(a: []const u8, b: []const u8) bool {
    const aa = trimSep(a);
    const bb = trimSep(b);
    if (aa.len == 0 or bb.len == 0) return false;
    return std.ascii.eqlIgnoreCase(aa, bb);
}

fn sameFile(a: []const u8, b: []const u8) bool {
    const fa = std.fs.openFileAbsolute(a, .{}) catch return false;
    defer fa.close();
    const fb = std.fs.openFileAbsolute(b, .{}) catch return false;
    defer fb.close();
    const sa = fa.stat() catch return false;
    const sb = fb.stat() catch return false;
    return sa.inode == sb.inode;
}

test "isBunCommand" {
    try std.testing.expect(isBunCommand("bun"));
    try std.testing.expect(isBunCommand("BUNX"));
    try std.testing.expect(!isBunCommand("npm"));
}

test "sameDir ignores trailing separators" {
    try std.testing.expect(sameDir("C:\\a\\b", "c:\\a\\b\\"));
    try std.testing.expect(!sameDir("C:\\a\\b", "C:\\a\\c"));
    try std.testing.expect(!sameDir("", "C:\\a"));
}
