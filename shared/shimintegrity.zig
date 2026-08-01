const std = @import("std");
const nodeversion = @import("nodeversion");

pub const ShimIntegrityFailed = error.ShimIntegrityFailed;

pub fn filesHaveSameContents(left_path: []const u8, right_path: []const u8) bool {
    var left = std.fs.openFileAbsolute(left_path, .{ .mode = .read_only }) catch return false;
    defer left.close();

    var right = std.fs.openFileAbsolute(right_path, .{ .mode = .read_only }) catch return false;
    defer right.close();

    const left_size = left.getEndPos() catch return false;
    const right_size = right.getEndPos() catch return false;
    if (left_size != right_size) return false;

    var left_buf: [8192]u8 = undefined;
    var right_buf: [8192]u8 = undefined;

    while (true) {
        const left_n = left.read(&left_buf) catch return false;
        const right_n = right.read(&right_buf) catch return false;

        if (left_n != right_n) return false;
        if (left_n == 0) return true;
        if (!std.mem.eql(u8, left_buf[0..left_n], right_buf[0..right_n])) return false;
    }
}

pub fn verifySelfIfInvokedFromShim(allocator: std.mem.Allocator) !void {
    const self_path = try std.fs.selfExePathAlloc(allocator);
    defer allocator.free(self_path);

    const install_root = nodeversion.loadInstallRoot(allocator) catch return;
    defer allocator.free(install_root);

    const data_root = std.fs.path.dirname(install_root) orelse return;
    const shim_dir = try std.fs.path.join(allocator, &.{ data_root, ".shim" });
    defer allocator.free(shim_dir);

    if (!pathHasPrefixIgnoreCase(self_path, shim_dir)) return;

    const proxy_path = try std.fs.path.join(allocator, &.{ data_root, "proxy.exe" });
    defer allocator.free(proxy_path);

    const base = std.fs.path.basename(self_path);
    if (std.ascii.eqlIgnoreCase(base, "node.exe")) {
        const canonical = resolveProgramNodeShimPath(allocator) catch return error.ShimIntegrityFailed;
        defer allocator.free(canonical);
        if (!filesHaveSameContents(self_path, canonical)) return error.ShimIntegrityFailed;
        return;
    }

    if (!filesHaveSameContents(self_path, proxy_path)) return error.ShimIntegrityFailed;
}

pub fn resolveProgramNodeShimPath(allocator: std.mem.Allocator) ![]u8 {
    const self_path = try std.fs.selfExePathAlloc(allocator);
    defer allocator.free(self_path);

    const self_dir = std.fs.path.dirname(self_path) orelse return error.ProgramShimNotFound;
    const program_root = std.fs.path.dirname(self_dir) orelse return error.ProgramShimNotFound;
    const node_shim = try std.fs.path.join(allocator, &.{ program_root, ".shim", "node.exe" });
    errdefer allocator.free(node_shim);

    std.fs.accessAbsolute(node_shim, .{}) catch return error.ProgramShimNotFound;
    return node_shim;
}

fn pathHasPrefixIgnoreCase(path: []const u8, prefix: []const u8) bool {
    if (path.len < prefix.len) return false;
    return std.ascii.eqlIgnoreCase(path[0..prefix.len], prefix) and
        (path.len == prefix.len or path[prefix.len] == '\\' or path[prefix.len] == '/');
}

test "filesHaveSameContents detects mismatch" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(.{ .sub_path = "left.bin", .data = "abc" });
    try tmp.dir.writeFile(.{ .sub_path = "right.bin", .data = "abd" });

    const left = try tmp.dir.realpathAlloc(std.testing.allocator, "left.bin");
    defer std.testing.allocator.free(left);
    const right = try tmp.dir.realpathAlloc(std.testing.allocator, "right.bin");
    defer std.testing.allocator.free(right);

    try std.testing.expect(!filesHaveSameContents(left, right));
}

test "filesHaveSameContents accepts identical files" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(.{ .sub_path = "left.bin", .data = "abc" });
    try tmp.dir.writeFile(.{ .sub_path = "right.bin", .data = "abc" });

    const left = try tmp.dir.realpathAlloc(std.testing.allocator, "left.bin");
    defer std.testing.allocator.free(left);
    const right = try tmp.dir.realpathAlloc(std.testing.allocator, "right.bin");
    defer std.testing.allocator.free(right);

    try std.testing.expect(filesHaveSameContents(left, right));
}
