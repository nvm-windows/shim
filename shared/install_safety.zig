const std = @import("std");
const windows = std.os.windows;

const file_attribute_reparse_point: u32 = 0x400;
const file_generic_write: u32 = 0x00120116;
const generic_write: u32 = 0x40000000;
const generic_all: u32 = 0x10000000;
const delete_access: u32 = 0x00010000;
const write_dac: u32 = 0x00040000;
const write_owner: u32 = 0x00080000;
const cross_user_write_mask: u32 = file_generic_write | generic_write | generic_all | delete_access | write_dac | write_owner;

const dacl_security_information: u32 = 0x00000004;
const se_file_object: u32 = 1;
const win_authenticated_user_sid: i32 = 17;
const win_builtin_users_sid: i32 = 27;

const ACL = extern struct {
    AclRevision: u8,
    Sbz1: u8,
    AclSize: u16,
    AceCount: u16,
    Sbz2: u16,
};

const ACCESS_ALLOWED_ACE = extern struct {
    Header: extern struct {
        AceType: u8,
        AceFlags: u8,
        AceSize: u16,
    },
    Mask: u32,
    SidStart: u32,
};

const advapi32 = struct {
    pub extern "advapi32" fn GetNamedSecurityInfoW(
        pObjectName: [*:0]const u16,
        ObjectType: u32,
        SecurityInfo: u32,
        ppsidOwner: ?*?*anyopaque,
        ppsidGroup: ?*?*anyopaque,
        ppDacl: ?*?*ACL,
        ppSacl: ?*?*ACL,
        ppSecurityDescriptor: *?*anyopaque,
    ) callconv(.winapi) u32;

    pub extern "advapi32" fn LocalFree(hMem: ?*anyopaque) callconv(.winapi) ?*anyopaque;

    pub extern "advapi32" fn CreateWellKnownSid(
        WellKnownSidType: i32,
        DomainSid: ?*anyopaque,
        pSid: *anyopaque,
        cbSid: *u32,
    ) callconv(.winapi) windows.BOOL;

    pub extern "advapi32" fn EqualSid(pSid1: *anyopaque, pSid2: *anyopaque) callconv(.winapi) windows.BOOL;

    pub extern "advapi32" fn GetAce(
        pAcl: *ACL,
        dwAceIndex: u32,
        pAce: *?*anyopaque,
    ) callconv(.winapi) windows.BOOL;
};

const kernel32 = struct {
    pub extern "kernel32" fn GetFileAttributesW(lpFileName: [*:0]const u16) callconv(.winapi) u32;
};

pub const TrustError = error{
    NotADirectory,
    ReparsePoint,
    CrossUserWritable,
    PathUnavailable,
};

/// Refuse planted/hijackable version directories (reparse or cross-user writable).
pub fn checkVersionDirTrust(allocator: std.mem.Allocator, path: []const u8) TrustError!void {
    const trimmed = std.mem.trim(u8, path, " \t\r\n");
    if (trimmed.len == 0) return;

    std.fs.cwd().access(trimmed, .{}) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return error.PathUnavailable,
    };

    var dir = std.fs.cwd().openDir(trimmed, .{}) catch |err| switch (err) {
        error.NotDir => return error.NotADirectory,
        error.FileNotFound => return,
        else => return error.PathUnavailable,
    };
    dir.close();

    if (try isReparsePoint(allocator, trimmed)) return error.ReparsePoint;
    if (try allowsCrossUserWrite(allocator, trimmed)) return error.CrossUserWritable;
}

fn isReparsePoint(allocator: std.mem.Allocator, path: []const u8) TrustError!bool {
    const path_w = std.unicode.utf8ToUtf16LeAllocZ(allocator, path) catch return error.PathUnavailable;
    defer allocator.free(path_w);
    const attrs = kernel32.GetFileAttributesW(path_w.ptr);
    if (attrs == windows.INVALID_FILE_ATTRIBUTES) return error.PathUnavailable;
    return (attrs & file_attribute_reparse_point) != 0;
}

fn allowsCrossUserWrite(allocator: std.mem.Allocator, path: []const u8) TrustError!bool {
    const path_w = std.unicode.utf8ToUtf16LeAllocZ(allocator, path) catch return error.PathUnavailable;
    defer allocator.free(path_w);

    var security_descriptor: ?*anyopaque = null;
    var dacl: ?*ACL = null;
    const status = advapi32.GetNamedSecurityInfoW(
        path_w.ptr,
        se_file_object,
        dacl_security_information,
        null,
        null,
        &dacl,
        null,
        &security_descriptor,
    );
    if (status != 0) return false;
    defer _ = advapi32.LocalFree(security_descriptor);

    const acl = dacl orelse return false;

    var auth_users_buf: [68]u8 align(8) = undefined;
    var users_buf: [68]u8 align(8) = undefined;
    var auth_users_size: u32 = auth_users_buf.len;
    var users_size: u32 = users_buf.len;

    if (advapi32.CreateWellKnownSid(win_authenticated_user_sid, null, &auth_users_buf, &auth_users_size) == 0) {
        return false;
    }
    if (advapi32.CreateWellKnownSid(win_builtin_users_sid, null, &users_buf, &users_size) == 0) {
        return false;
    }

    const ace_count = acl.AceCount;
    var index: u32 = 0;
    while (index < ace_count) : (index += 1) {
        var ace_ptr: ?*anyopaque = null;
        if (advapi32.GetAce(acl, index, &ace_ptr) == 0) continue;
        const ace: *ACCESS_ALLOWED_ACE = @ptrCast(@alignCast(ace_ptr orelse continue));
        if (ace.Header.AceType != 0) continue; // ACCESS_ALLOWED_ACE_TYPE

        const sid: *anyopaque = @ptrCast(&ace.SidStart);
        const matches_auth = advapi32.EqualSid(sid, &auth_users_buf) != 0;
        const matches_users = advapi32.EqualSid(sid, &users_buf) != 0;
        if (!matches_auth and !matches_users) continue;
        if ((ace.Mask & cross_user_write_mask) != 0) return true;
    }

    return false;
}

test "checkVersionDirTrust accepts normal directory" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(path);
    try checkVersionDirTrust(std.testing.allocator, path);
}
