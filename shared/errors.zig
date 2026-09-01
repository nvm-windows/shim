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

pub fn noActiveVersionConfigured() noreturn {
    std.debug.print("No active Node.js version is configured. Run `nvm install <version>` then `nvm use <version>`.\n", .{});
    std.process.exit(1);
}

pub fn noVersionsInstalled() noreturn {
    std.debug.print("No Node.js versions are installed. Run `nvm install <version>` first.\n", .{});
    std.process.exit(1);
}

pub fn unresolvedVersionSpec(spec: []const u8) noreturn {
    const trimmed = std.mem.trim(u8, spec, " \t\r\n");
    if (trimmed.len > 0) {
        std.debug.print(
            "Could not resolve Node.js version \"{s}\". Install a matching version with `nvm install`, or run `nvm use` to select an installed version.\n",
            .{trimmed},
        );
    } else {
        std.debug.print("Could not resolve the configured Node.js version. Run `nvm use` to select an installed version.\n", .{});
    }
    std.process.exit(1);
}

pub fn nodeVerifyFailed(node_bin: []const u8, node_version: []const u8, reason: []const u8) noreturn {
    std.debug.print(
        \\NVM blocked Node.js execution because its integrity could not be verified.
        \\
        \\File: {s}
        \\Reason: {s}
        \\Action: Reinstall this version with `nvm install {s} --force`.
        \\If this change was unexpected, contact your administrator and review NVM event logs.
        \\Event code: NVM4301
        \\
    , .{ node_bin, if (reason.len == 0) "Trust verification failed." else reason, node_version });
    std.process.exit(1);
}
