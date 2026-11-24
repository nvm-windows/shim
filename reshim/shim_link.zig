const std = @import("std");
const builtin = @import("builtin");
const windows = std.os.windows;

extern "kernel32" fn CreateHardLinkW(
    lpFileName: [*:0]const u16,
    lpExistingFileName: [*:0]const u16,
    lpSecurityAttributes: ?*anyopaque,
) callconv(.winapi) windows.BOOL;

extern "kernel32" fn CreateSymbolicLinkW(
    lpSymlinkFileName: [*:0]const u16,
    lpTargetFileName: [*:0]const u16,
    dwFlags: windows.DWORD,
) callconv(.winapi) windows.BOOLEAN;

const symbolic_link_flag_allow_unprivileged_create: windows.DWORD = 0x2;

/// Create a shim entry pointing at proxy.exe: hardlink first, then file symlink.
pub fn createShimLink(allocator: std.mem.Allocator, link_path: []const u8, existing_path: []const u8) !void {
    // Replace any prior shim entry so hardlink/symlink create can succeed.
    std.fs.deleteFileAbsolute(link_path) catch |err| {
        if (err != error.FileNotFound) {
            return error.ShimFileInUse;
        }
    };

    const link_w = try std.unicode.utf8ToUtf16LeAllocZ(allocator, link_path);
    defer allocator.free(link_w);
    const existing_w = try std.unicode.utf8ToUtf16LeAllocZ(allocator, existing_path);
    defer allocator.free(existing_w);

    if (CreateHardLinkW(link_w, existing_w, null) != 0) {
        return;
    }
    const hardlink_error = windows.GetLastError();
    // Only treat lock contention as terminal; cross-volume / ACL hardlink
    // failures fall through to CreateSymbolicLinkW.
    switch (hardlink_error) {
        .SHARING_VIOLATION, .USER_MAPPED_FILE => return error.ShimFileInUse,
        else => {},
    }

    // Cross-volume (and some ACL) hardlink failures: try a file symlink to proxy.exe.
    // ALLOW_UNPRIVILEGED_CREATE works when Developer Mode / symlink privilege is enabled.
    if (CreateSymbolicLinkW(link_w, existing_w, symbolic_link_flag_allow_unprivileged_create) != 0) {
        return;
    }
    if (CreateSymbolicLinkW(link_w, existing_w, 0) != 0) {
        return;
    }

    const symlink_error = windows.GetLastError();
    switch (symlink_error) {
        .SHARING_VIOLATION, .USER_MAPPED_FILE => return error.ShimFileInUse,
        else => {
            std.debug.print(
                "  CreateHardLinkW={s} CreateSymbolicLinkW={s} link={s} target={s}\n",
                .{ @tagName(hardlink_error), @tagName(symlink_error), link_path, existing_path },
            );
            return error.ShimLinkFailed;
        },
    };
}

pub fn printShimLinkGuidance() void {
    std.debug.print(
        \\
        \\Shim links could not be created (hard link and symlink both failed).
        \\Hard links require .shim and proxy.exe on the same volume; symlinks need
        \\Developer Mode or the Create symbolic links privilege.
        \\
        \\Try one of:
        \\  1) Enable Developer Mode (symlink privilege), then:
        \\       nvm reshim --force
        \\       https://docs.nvm-windows.com/features/modes
        \\  2) Switch to link mode:
        \\       nvm config set mode=link
        \\       nvm use link
        \\
    , .{});
}

test "createShimLink hardlink same volume" {
    if (builtin.os.tag != .windows) return;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const allocator = std.testing.allocator;
    const base = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(base);

    const proxy_path = try std.fs.path.join(allocator, &.{ base, "proxy.exe" });
    defer allocator.free(proxy_path);
    const link_path = try std.fs.path.join(allocator, &.{ base, "npm.exe" });
    defer allocator.free(link_path);

    try tmp.dir.writeFile(.{ .sub_path = "proxy.exe", .data = "proxy-body" });

    try createShimLink(allocator, link_path, proxy_path);

    var link_file = try std.fs.openFileAbsolute(link_path, .{});
    defer link_file.close();
    var buf: [32]u8 = undefined;
    const n = try link_file.readAll(&buf);
    try std.testing.expectEqualStrings("proxy-body", buf[0..n]);
}

test "createShimLink symlink fallback when hardlink cannot use missing target" {
    if (builtin.os.tag != .windows) return;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const allocator = std.testing.allocator;
    const base = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(base);

    // Missing target: CreateHardLinkW fails; CreateSymbolicLinkW may create a
    // dangling file symlink when Developer Mode / privilege allows it.
    const missing_proxy = try std.fs.path.join(allocator, &.{ base, "missing-proxy.exe" });
    defer allocator.free(missing_proxy);
    const link_path = try std.fs.path.join(allocator, &.{ base, "pnpm.exe" });
    defer allocator.free(link_path);

    createShimLink(allocator, link_path, missing_proxy) catch |err| {
        try std.testing.expect(err == error.ShimLinkFailed);
        return;
    };

    // Symlink privilege available: dangling file symlink should exist.
    try std.fs.accessAbsolute(link_path, .{});
    std.fs.deleteFileAbsolute(link_path) catch {};
}

test "createShimLink replace existing link" {
    if (builtin.os.tag != .windows) return;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const allocator = std.testing.allocator;
    const base = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(base);

    const proxy_path = try std.fs.path.join(allocator, &.{ base, "proxy.exe" });
    defer allocator.free(proxy_path);
    const link_path = try std.fs.path.join(allocator, &.{ base, "yarn.exe" });
    defer allocator.free(link_path);

    try tmp.dir.writeFile(.{ .sub_path = "proxy.exe", .data = "proxy-v2" });
    try createShimLink(allocator, link_path, proxy_path);
    try createShimLink(allocator, link_path, proxy_path);

    var link_file = try std.fs.openFileAbsolute(link_path, .{});
    defer link_file.close();
    var buf: [32]u8 = undefined;
    const n = try link_file.readAll(&buf);
    try std.testing.expectEqualStrings("proxy-v2", buf[0..n]);
}

test "createShimLink cross-volume hardlink fails then symlink or ShimLinkFailed" {
    if (builtin.os.tag != .windows) return;

    // Reproduce #1570-style NOT_SAME_DEVICE: proxy on C: temp, link on D: (when D: exists).
    var d_root = std.fs.cwd().openDir("D:\\", .{}) catch return;
    defer d_root.close();

    var tmp_c = std.testing.tmpDir(.{});
    defer tmp_c.cleanup();
    const allocator = std.testing.allocator;
    const c_base = try tmp_c.dir.realpathAlloc(allocator, ".");
    defer allocator.free(c_base);

    const stamp = std.time.milliTimestamp();
    const d_dir_name = try std.fmt.allocPrint(allocator, "nvm1570-shim-{d}", .{stamp});
    defer allocator.free(d_dir_name);
    try d_root.makePath(d_dir_name);
    defer d_root.deleteTree(d_dir_name) catch {};

    const d_base = try std.fs.path.join(allocator, &.{ "D:", d_dir_name });
    defer allocator.free(d_base);

    const proxy_path = try std.fs.path.join(allocator, &.{ c_base, "proxy.exe" });
    defer allocator.free(proxy_path);
    const link_path = try std.fs.path.join(allocator, &.{ d_base, "npm.exe" });
    defer allocator.free(link_path);

    try tmp_c.dir.writeFile(.{ .sub_path = "proxy.exe", .data = "proxy-cross" });

    createShimLink(allocator, link_path, proxy_path) catch |err| {
        // Developer Mode off / no symlink privilege: must hard-fail, not soft-succeed.
        try std.testing.expect(err == error.ShimLinkFailed);
        try std.testing.expectError(error.FileNotFound, std.fs.accessAbsolute(link_path, .{}));
        return;
    };

    // Developer Mode / privilege on: file symlink lands across volumes.
    try std.fs.accessAbsolute(link_path, .{});
    std.fs.deleteFileAbsolute(link_path) catch {};
}
