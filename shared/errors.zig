const std = @import("std");

pub fn nodeNotFound(ver: []const u8) noreturn {
    const bare = if (ver.len > 0 and (ver[0] == 'v' or ver[0] == 'V')) ver[1..] else ver;
    const dot_count = std.mem.count(u8, bare, ".");
    var buf: [256]u8 = undefined;
    const display = if (dot_count == 0)
        std.fmt.bufPrint(&buf, "{s}.x.x", .{bare}) catch bare
    else if (dot_count == 1)
        std.fmt.bufPrint(&buf, "{s}.x", .{bare}) catch bare
    else
        bare;
    std.debug.print("Node.js v{s} is not installed or cannot be found.\n", .{display});
    std.process.exit(1);
}
