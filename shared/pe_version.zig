const std = @import("std");
const windows = std.os.windows;

const version_dll = struct {
    pub extern "version" fn GetFileVersionInfoSizeW(
        lptstrFilename: [*:0]const u16,
        lpdwHandle: ?*windows.DWORD,
    ) callconv(.winapi) windows.DWORD;

    pub extern "version" fn GetFileVersionInfoW(
        lptstrFilename: [*:0]const u16,
        dwHandle: windows.DWORD,
        dwLen: windows.DWORD,
        lpData: *anyopaque,
    ) callconv(.winapi) windows.BOOL;

    pub extern "version" fn VerQueryValueW(
        pBlock: *const anyopaque,
        lpSubBlock: [*:0]const u16,
        lplpBuffer: *?*anyopaque,
        puLen: *windows.UINT,
    ) callconv(.winapi) windows.BOOL;
};

const VsFixedFileInfo = extern struct {
    dwSignature: u32,
    dwStrucVersion: u32,
    dwFileVersionMS: u32,
    dwFileVersionLS: u32,
    dwProductVersionMS: u32,
    dwProductVersionLS: u32,
    dwFileFlagsMask: u32,
    dwFileFlags: u32,
    dwFileOS: u32,
    dwFileType: u32,
    dwFileSubtype: u32,
    dwFileDateMS: u32,
    dwFileDateLS: u32,
};

pub const CoreVersion = struct {
    major: u32,
    minor: u32,
    patch: u32,
};

pub fn readFileVersion(allocator: std.mem.Allocator, path: []const u8) !CoreVersion {
    const path_w = try std.unicode.utf8ToUtf16LeAllocZ(allocator, path);
    defer allocator.free(path_w);

    var handle: windows.DWORD = 0;
    const size = version_dll.GetFileVersionInfoSizeW(path_w.ptr, &handle);
    if (size == 0) return error.VersionInfoMissing;

    const buf = try allocator.alloc(u8, size);
    defer allocator.free(buf);

    if (version_dll.GetFileVersionInfoW(path_w.ptr, 0, size, buf.ptr) == 0) {
        return error.VersionInfoMissing;
    }

    const root_w = std.unicode.utf8ToUtf16LeStringLiteral("\\");
    var info_ptr: ?*anyopaque = null;
    var info_len: windows.UINT = 0;
    if (version_dll.VerQueryValueW(buf.ptr, root_w, &info_ptr, &info_len) == 0) {
        return error.VersionInfoMissing;
    }
    if (info_ptr == null or info_len < @sizeOf(VsFixedFileInfo)) return error.VersionInfoMissing;

    const info: *const VsFixedFileInfo = @ptrCast(@alignCast(info_ptr.?));
    if (info.dwSignature != 0xFEEF04BD) return error.VersionInfoMissing;

    return .{
        .major = info.dwFileVersionMS >> 16,
        .minor = info.dwFileVersionMS & 0xffff,
        .patch = info.dwFileVersionLS >> 16,
    };
}

pub fn parseCoreVersion(raw: []const u8) ?CoreVersion {
    var s = std.mem.trim(u8, raw, " \t\r\n");
    if (s.len >= 1 and (s[0] == 'v' or s[0] == 'V')) s = s[1..];
    if (s.len == 0) return null;

    const cut = std.mem.indexOfAny(u8, s, "-+") orelse s.len;
    s = s[0..cut];

    var parts = std.mem.splitScalar(u8, s, '.');
    const major_s = parts.next() orelse return null;
    const minor_s = parts.next() orelse "0";
    const patch_s = parts.next() orelse "0";

    const major = std.fmt.parseInt(u32, major_s, 10) catch return null;
    const minor = std.fmt.parseInt(u32, minor_s, 10) catch return null;
    const patch = std.fmt.parseInt(u32, patch_s, 10) catch return null;
    return .{ .major = major, .minor = minor, .patch = patch };
}

pub fn coreVersionsEqual(file: CoreVersion, expected: []const u8) bool {
    const folder = parseCoreVersion(expected) orelse return false;
    return file.major == folder.major and file.minor == folder.minor and file.patch == folder.patch;
}

pub fn matchesFolderVersion(allocator: std.mem.Allocator, path: []const u8, expected: []const u8) !bool {
    const file = try readFileVersion(allocator, path);
    return coreVersionsEqual(file, expected);
}

test "parseCoreVersion strips v prefix and prerelease" {
    try std.testing.expectEqual(CoreVersion{ .major = 24, .minor = 0, .patch = 0 }, parseCoreVersion("v24.0.0").?);
    try std.testing.expectEqual(CoreVersion{ .major = 24, .minor = 0, .patch = 0 }, parseCoreVersion("24.0.0-nightly20240101").?);
    try std.testing.expectEqual(CoreVersion{ .major = 10, .minor = 0, .patch = 0 }, parseCoreVersion("10.0.0").?);
    try std.testing.expect(parseCoreVersion("") == null);
}

test "coreVersionsEqual catches swapped Node 10 in 24 folder" {
    const file_v10 = CoreVersion{ .major = 10, .minor = 0, .patch = 0 };
    try std.testing.expect(!coreVersionsEqual(file_v10, "24.0.0"));
    try std.testing.expect(coreVersionsEqual(file_v10, "10.0.0"));
    try std.testing.expect(coreVersionsEqual(.{ .major = 24, .minor = 1, .patch = 0 }, "24.1.0-rc.1"));
}
