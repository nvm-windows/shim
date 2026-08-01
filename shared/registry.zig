const std = @import("std");
const windows = std.os.windows;
const config = @import("config");

pub fn preferenceHives() []const windows.HKEY {
    return &[_]windows.HKEY{
        windows.HKEY_CURRENT_USER,
    };
}

pub fn commandLookupHives() []const windows.HKEY {
    return &[_]windows.HKEY{
        windows.HKEY_CURRENT_USER,
    };
}

pub fn queryStringWithFallback(allocator: std.mem.Allocator, hives: []const windows.HKEY, sub_key: []const u8, value_name: []const u8) ![]u8 {
    for (hives) |hive| {
        const value = queryString(allocator, hive, sub_key, value_name) catch continue;
        return value;
    }

    return error.RegistryValueNotFound;
}

pub fn queryString(allocator: std.mem.Allocator, hive: windows.HKEY, sub_key: []const u8, value_name: []const u8) ![]u8 {
    const sub_key_w = try std.unicode.utf8ToUtf16LeAllocZ(allocator, sub_key);
    defer allocator.free(sub_key_w);
    const value_name_w = try std.unicode.utf8ToUtf16LeAllocZ(allocator, value_name);
    defer allocator.free(value_name_w);

    var hkey: windows.HKEY = undefined;
    const rc_open = windows.advapi32.RegOpenKeyExW(hive, sub_key_w, 0, windows.KEY_QUERY_VALUE, &hkey);
    if (rc_open != 0) return error.RegistryKeyNotFound;
    defer _ = windows.advapi32.RegCloseKey(hkey);

    var data_type: windows.DWORD = 0;
    var buf_len: windows.DWORD = 0;

    const rc_size = windows.advapi32.RegQueryValueExW(
        hkey,
        value_name_w,
        null,
        &data_type,
        null,
        &buf_len,
    );
    if (rc_size != 0) return error.RegistryValueNotFound;
    if (data_type != config.reg_type_sz and data_type != config.reg_type_expand_sz) {
        return error.RegistryValueWrongType;
    }
    if (buf_len == 0) return try allocator.dupe(u8, "");

    const wide_len = buf_len / @sizeOf(u16);
    const wide_buf = try allocator.alloc(u16, wide_len);
    defer allocator.free(wide_buf);

    const rc_query = windows.advapi32.RegQueryValueExW(
        hkey,
        value_name_w,
        null,
        &data_type,
        @ptrCast(wide_buf.ptr),
        &buf_len,
    );
    if (rc_query != 0) return error.RegistryValueNotFound;
    if (data_type != config.reg_type_sz and data_type != config.reg_type_expand_sz) {
        return error.RegistryValueWrongType;
    }

    const n_chars = buf_len / @sizeOf(u16);
    const slice = wide_buf[0..if (n_chars > 0 and wide_buf[n_chars - 1] == 0) n_chars - 1 else n_chars];
    return std.unicode.utf16LeToUtf8Alloc(allocator, slice);
}

pub fn queryDwordOptionalWithFallback(hives: []const windows.HKEY, sub_key: []const u8, value_name: []const u8) !?u32 {
    for (hives) |hive| {
        if (try queryDwordOptional(hive, sub_key, value_name)) |value| {
            return value;
        }
    }

    return null;
}

pub fn queryQwordOptionalWithFallback(hives: []const windows.HKEY, sub_key: []const u8, value_name: []const u8) !?u64 {
    for (hives) |hive| {
        if (try queryQwordOptional(hive, sub_key, value_name)) |value| {
            return value;
        }
    }

    return null;
}

pub fn queryMultiStringOptionalWithFallback(allocator: std.mem.Allocator, hives: []const windows.HKEY, sub_key: []const u8, value_name: []const u8) !?[]const []const u8 {
    for (hives) |hive| {
        if (try queryMultiStringOptional(allocator, hive, sub_key, value_name)) |value| {
            return value;
        }
    }

    return null;
}

pub fn queryMultiStringOptional(allocator: std.mem.Allocator, hive: windows.HKEY, sub_key: []const u8, value_name: []const u8) !?[]const []const u8 {
    const sub_key_w = try std.unicode.utf8ToUtf16LeAllocZ(allocator, sub_key);
    defer allocator.free(sub_key_w);
    const value_name_w = try std.unicode.utf8ToUtf16LeAllocZ(allocator, value_name);
    defer allocator.free(value_name_w);

    var hkey: windows.HKEY = undefined;
    const rc_open = windows.advapi32.RegOpenKeyExW(hive, sub_key_w, 0, windows.KEY_QUERY_VALUE, &hkey);
    if (rc_open != 0) return null;
    defer _ = windows.advapi32.RegCloseKey(hkey);

    var data_type: windows.DWORD = 0;
    var buf_len: windows.DWORD = 0;

    const rc_size = windows.advapi32.RegQueryValueExW(
        hkey,
        value_name_w,
        null,
        &data_type,
        null,
        &buf_len,
    );
    if (rc_size != 0 or data_type != config.reg_type_multi_sz) return null;
    if (buf_len == 0) return try allocator.alloc([]const u8, 0);

    const wide_len = buf_len / @sizeOf(u16);
    const wide_buf = try allocator.alloc(u16, wide_len);
    defer allocator.free(wide_buf);

    const rc_query = windows.advapi32.RegQueryValueExW(
        hkey,
        value_name_w,
        null,
        &data_type,
        @ptrCast(wide_buf.ptr),
        &buf_len,
    );
    if (rc_query != 0 or data_type != config.reg_type_multi_sz) return null;

    return try parseMultiStringUtf16(allocator, wide_buf);
}

pub fn queryDwordOptional(hive: windows.HKEY, sub_key: []const u8, value_name: []const u8) !?u32 {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const sub_key_w = try std.unicode.utf8ToUtf16LeAllocZ(allocator, sub_key);
    defer allocator.free(sub_key_w);
    const value_name_w = try std.unicode.utf8ToUtf16LeAllocZ(allocator, value_name);
    defer allocator.free(value_name_w);

    var hkey: windows.HKEY = undefined;
    const rc_open = windows.advapi32.RegOpenKeyExW(hive, sub_key_w, 0, windows.KEY_QUERY_VALUE, &hkey);
    if (rc_open != 0) return null;
    defer _ = windows.advapi32.RegCloseKey(hkey);

    var data_type: windows.DWORD = 0;
    var value: u32 = 0;
    var buf_len: windows.DWORD = @sizeOf(u32);

    const rc_query = windows.advapi32.RegQueryValueExW(
        hkey,
        value_name_w,
        null,
        &data_type,
        @ptrCast(&value),
        &buf_len,
    );
    if (rc_query != 0) return null;
    if (data_type != config.reg_type_dword) return null;

    return value;
}

pub fn queryBinaryOptional(allocator: std.mem.Allocator, hive: windows.HKEY, sub_key: []const u8, value_name: []const u8) !?[]u8 {
    const sub_key_w = try std.unicode.utf8ToUtf16LeAllocZ(allocator, sub_key);
    defer allocator.free(sub_key_w);
    const value_name_w = try std.unicode.utf8ToUtf16LeAllocZ(allocator, value_name);
    defer allocator.free(value_name_w);

    var hkey: windows.HKEY = undefined;
    const rc_open = windows.advapi32.RegOpenKeyExW(hive, sub_key_w, 0, windows.KEY_QUERY_VALUE, &hkey);
    if (rc_open != 0) return null;
    defer _ = windows.advapi32.RegCloseKey(hkey);

    var data_type: windows.DWORD = 0;
    var buf_len: windows.DWORD = 0;

    const rc_size = windows.advapi32.RegQueryValueExW(
        hkey,
        value_name_w,
        null,
        &data_type,
        null,
        &buf_len,
    );
    if (rc_size != 0 or data_type != config.reg_type_binary) return null;
    if (buf_len == 0) return try allocator.alloc(u8, 0);

    const buf = try allocator.alloc(u8, buf_len);
    errdefer allocator.free(buf);

    const rc_query = windows.advapi32.RegQueryValueExW(
        hkey,
        value_name_w,
        null,
        &data_type,
        @ptrCast(buf.ptr),
        &buf_len,
    );
    if (rc_query != 0 or data_type != config.reg_type_binary) return null;

    return buf[0..buf_len];
}

pub fn queryQwordOptional(hive: windows.HKEY, sub_key: []const u8, value_name: []const u8) !?u64 {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const sub_key_w = try std.unicode.utf8ToUtf16LeAllocZ(allocator, sub_key);
    defer allocator.free(sub_key_w);
    const value_name_w = try std.unicode.utf8ToUtf16LeAllocZ(allocator, value_name);
    defer allocator.free(value_name_w);

    var hkey: windows.HKEY = undefined;
    const rc_open = windows.advapi32.RegOpenKeyExW(hive, sub_key_w, 0, windows.KEY_QUERY_VALUE, &hkey);
    if (rc_open != 0) return null;
    defer _ = windows.advapi32.RegCloseKey(hkey);

    var data_type: windows.DWORD = 0;
    var value: u64 = 0;
    var buf_len: windows.DWORD = @sizeOf(u64);

    const rc_query = windows.advapi32.RegQueryValueExW(
        hkey,
        value_name_w,
        null,
        &data_type,
        @ptrCast(&value),
        &buf_len,
    );
    if (rc_query != 0) return null;
    if (data_type != config.reg_type_qword) return null;

    return value;
}

pub fn parseMultiStringUtf16(allocator: std.mem.Allocator, raw: []const u16) ![]const []const u8 {
    var out = std.ArrayListUnmanaged([]const u8){};
    errdefer {
        for (out.items) |item| allocator.free(item);
        out.deinit(allocator);
    }

    var start: usize = 0;
    while (start < raw.len) {
        if (raw[start] == 0) break;

        var end = start;
        while (end < raw.len and raw[end] != 0) : (end += 1) {}

        const utf8 = try std.unicode.utf16LeToUtf8Alloc(allocator, raw[start..end]);
        const trimmed = std.mem.trim(u8, utf8, " \t\r\n");

        if (trimmed.len == 0) {
            allocator.free(utf8);
        } else if (trimmed.ptr == utf8.ptr and trimmed.len == utf8.len) {
            try out.append(allocator, utf8);
        } else {
            const copy = try allocator.dupe(u8, trimmed);
            allocator.free(utf8);
            try out.append(allocator, copy);
        }

        start = end + 1;
    }

    return out.toOwnedSlice(allocator);
}
