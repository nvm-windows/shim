const std = @import("std");

extern "kernel32" fn GetCommandLineW() callconv(.winapi) [*:0]const u16;

pub fn rawInvocation(allocator: std.mem.Allocator) ![]u8 {
    const raw_w = GetCommandLineW();
    return std.unicode.utf16LeToUtf8Alloc(allocator, std.mem.span(raw_w));
}

pub fn translatedInvocation(allocator: std.mem.Allocator, executable: []const u8, forwarded_args: []const []const u8) ![]u8 {
    if (forwarded_args.len == 0) {
        return allocator.dupe(u8, executable);
    }

    const joined_args = try std.mem.join(allocator, " ", forwarded_args);
    defer allocator.free(joined_args);

    return std.fmt.allocPrint(allocator, "{s} {s}", .{ executable, joined_args });
}

pub fn formatLogMessage(allocator: std.mem.Allocator, original: []const u8, translated: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "{s} -> {s}", .{ original, translated });
}