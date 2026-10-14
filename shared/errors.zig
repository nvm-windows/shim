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

pub const AutoInstallFailure = union(enum) {
    prompt_failed: []const u8,
    nvm_exe_not_found,
    spawn_failed: struct { version: []const u8, path: []const u8 },
    install_failed: struct { version: []const u8, exit_code: u32 },
    unresolved_after_install: []const u8,
};

pub fn formatAutoInstallFailure(allocator: std.mem.Allocator, failure: AutoInstallFailure) ![]u8 {
    return switch (failure) {
        .prompt_failed => |version| std.fmt.allocPrint(allocator,
            \\Could not read the auto-install prompt for Node.js v{s}.
            \\Run `nvm install {s}`.
            \\Event code: NVM4307
            \\
        , .{ version, version }),
        .nvm_exe_not_found => std.fmt.allocPrint(allocator,
            \\Auto-install could not find nvm.exe.
            \\Set NVM_HOME to the folder that contains nvm.exe.
            \\Searched NVM_HOME, the shim directory, and %LOCALAPPDATA%\Author Software\nvm.
            \\Event code: NVM4308
            \\
        , .{}),
        .spawn_failed => |detail| std.fmt.allocPrint(allocator,
            \\Auto-install could not start nvm.exe.
            \\File: {s}
            \\Run `nvm install {s}`.
            \\Event code: NVM4309
            \\
        , .{ detail.path, detail.version }),
        .install_failed => |detail| std.fmt.allocPrint(allocator,
            \\Auto-install stopped because `nvm install {s}` exited with code {d}.
            \\Event code: NVM4310
            \\
        , .{ detail.version, detail.exit_code }),
        .unresolved_after_install => |version| std.fmt.allocPrint(allocator,
            \\Auto-install finished, but Node.js v{s} is still not available.
            \\Run `nvm install {s}` and then `nvm use {s}`.
            \\Event code: NVM4311
            \\
        , .{ version, version, version }),
    };
}

pub fn reportAutoInstallFailure(failure: AutoInstallFailure) noreturn {
    const msg = formatAutoInstallFailure(std.heap.page_allocator, failure) catch
        "Auto-install failed.\nEvent code: NVM4308\n";
    std.debug.print("{s}", .{msg});
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
