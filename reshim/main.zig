const std = @import("std");
const build_options = @import("build_options");
const windows = std.os.windows;
const registry = @import("registry");
const config = @import("config");
const nodeversion = @import("nodeversion");
const eventlog = @import("eventlog");
const shimintegrity = @import("shimintegrity");
const jobobject = @import("jobobject");

const shim_version = build_options.version;

// Marks shim names parked aside because the running image blocked deletion.
const stale_shim_marker = ".nvm-retired-";

extern "kernel32" fn CreateHardLinkW(
    lpFileName: [*:0]const u16,
    lpExistingFileName: [*:0]const u16,
    lpSecurityAttributes: ?*anyopaque,
) callconv(.winapi) windows.BOOL;

extern "kernel32" fn CopyFileW(
    lpExistingFileName: [*:0]const u16,
    lpNewFileName: [*:0]const u16,
    bFailIfExists: windows.BOOL,
) callconv(.winapi) windows.BOOL;

pub fn main() !void {
    _ = eventlog;
    jobobject.bindKillOnCloseJob();

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var force = false;
    var dry_run = false;
    var silent = false;
    var target_version_dir: ?[]const u8 = null;
    const argv = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, argv);

    var i: usize = 1;
    while (i < argv.len) : (i += 1) {
        const arg = argv[i];
        if (std.mem.eql(u8, arg, "--nvm-shim-version")) {
            std.debug.print("{s}\n", .{shim_version});
            return;
        }

        if (std.mem.eql(u8, arg, "--force")) {
            force = true;
            continue;
        }

        if (std.mem.eql(u8, arg, "--dry-run")) {
            dry_run = true;
            continue;
        }

        if (std.mem.eql(u8, arg, "--silent")) {
            silent = true;
            continue;
        }

        if (target_version_dir == null) {
            target_version_dir = arg;
            continue;
        }

        if (!silent) {
            std.debug.print("Unknown argument: {s}\n", .{arg});
            std.debug.print("Usage: reshim [--force] [--dry-run] [--silent] [node_install_dir]\n", .{});
        }
        return;
    }

    const install_root = if (target_version_dir == null)
        try nodeversion.loadInstallRoot(allocator)
    else
        try allocator.dupe(u8, std.fs.path.dirname(target_version_dir.?) orelse ".");
    defer allocator.free(install_root);

    const shim_dir = try std.fs.path.resolve(allocator, &.{ install_root, "..", ".shim" });
    defer allocator.free(shim_dir);

    var existing_before_force = std.StringHashMap(void).init(allocator);
    defer {
        var it_existing_before_force = existing_before_force.keyIterator();
        while (it_existing_before_force.next()) |k| allocator.free(k.*);
        existing_before_force.deinit();
    }

    if (!dry_run) {
        sweepRetiredShims(allocator, shim_dir);
    }

    if (force) {
        try collectExistingShimNames(allocator, shim_dir, &existing_before_force);
    }

    var cmd_names = if (target_version_dir) |version_dir|
        try collectCmdNamesFromVersionDir(allocator, version_dir)
    else
        try collectCmdNamesFromInstallRoot(allocator, install_root);
    var planned_removals = std.ArrayListUnmanaged([]const u8){};
    defer {
        for (planned_removals.items) |name| allocator.free(name);
        planned_removals.deinit(allocator);
    }

    const proxy_path = try std.fs.path.resolve(allocator, &.{ install_root, "..", "proxy.exe" });
    defer allocator.free(proxy_path);

    const program_node_shim = shimintegrity.resolveProgramNodeShimPath(allocator) catch null;
    defer if (program_node_shim) |path| allocator.free(path);

    cmd_names = try reconcileShimExecutables(allocator, shim_dir, proxy_path, program_node_shim, cmd_names, force, dry_run, &planned_removals);
    defer freeNameList(allocator, cmd_names);

    if (dry_run) {
        try writeDryRunJson(allocator, cmd_names, planned_removals.items);
        return;
    }

    // std.debug.print("InstallRoot={s}\n", .{install_root});
    // std.debug.print("ShimDir={s}\n", .{shim_dir});

    if (cmd_names.len == 0) {
        prewarmShims(allocator, shim_dir, silent);
        signVersionScriptsAfterReshim(allocator, install_root, target_version_dir, silent);
        try writeStdoutf(allocator, silent, "All shims up to date.\n", .{});
        return;
    }

    std.fs.accessAbsolute(proxy_path, .{}) catch {
        const program_proxy_path = resolveSiblingProgramProxyPath(allocator) catch {
            prewarmShims(allocator, shim_dir, silent);
            std.debug.print("proxy.exe not found at {s}, cannot create shims.\n", .{proxy_path});
            return;
        };
        defer allocator.free(program_proxy_path);

        copyFile(allocator, program_proxy_path, proxy_path) catch {
            prewarmShims(allocator, shim_dir, silent);
            std.debug.print("proxy.exe not found at {s}, cannot create shims.\n", .{proxy_path});
            return;
        };
    };

    var linked: usize = 0;
    for (cmd_names) |name| {
        const key = try allocator.dupe(u8, name);
        defer allocator.free(key);
        _ = std.ascii.lowerString(key, key);
        const existed_before_force = force and existing_before_force.contains(key);

        const link_name = try std.mem.concat(allocator, u8, &.{ name, ".exe" });
        defer allocator.free(link_name);
        const link_path = try std.fs.path.join(allocator, &.{ shim_dir, link_name });
        defer allocator.free(link_path);

        createHardLink(allocator, link_path, proxy_path) catch |err| {
            if (err == error.ShimFileInUse) {
                std.debug.print("  failed {s}: in use by a running process (close it, then run 'nvm reshim --force')\n", .{link_name});
            } else {
                std.debug.print("  failed {s}: {}\n", .{ link_name, err });
            }
            if (existed_before_force) {
                const removed_msg = std.fmt.allocPrint(allocator, "Global module '{s}' was removed in shim mode.", .{name}) catch null;
                if (removed_msg) |msg| {
                    defer allocator.free(msg);
                    eventlog.writeInfo(allocator, "reshim", msg);
                }
            }
            continue;
        };
        try writeStdoutf(allocator, silent, "  linked: {s}\n", .{link_name});
        if (!existed_before_force and shouldLogModuleEvent(name)) {
            const created_msg = std.fmt.allocPrint(allocator, "Global module '{s}' was made available in shim mode.", .{name}) catch null;
            if (created_msg) |msg| {
                defer allocator.free(msg);
                eventlog.writeInfo(allocator, "reshim", msg);
            }
        }
        linked += 1;
    }

    try writeStdoutf(allocator, silent, "\nCreated {d} shim(s).\n", .{linked});
    prewarmShims(allocator, shim_dir, silent);
    signVersionScriptsAfterReshim(allocator, install_root, target_version_dir, silent);
}

fn signVersionScriptsAfterReshim(
    allocator: std.mem.Allocator,
    install_root: []const u8,
    target_version_dir: ?[]const u8,
    silent: bool,
) void {
    if (target_version_dir) |version_dir| {
        signVersionScripts(allocator, install_root, version_dir);
        return;
    }
    if (silent) {
        signActiveVersionScripts(allocator, install_root);
        return;
    }
    signVersionScripts(allocator, install_root, null);
}

fn signActiveVersionScripts(allocator: std.mem.Allocator, install_root: []const u8) void {
    const version_dir_opt = nodeversion.activeVersionInstallDir(allocator, install_root) catch return;
    const version_dir = version_dir_opt orelse return;
    defer allocator.free(version_dir);
    signVersionScripts(allocator, install_root, version_dir);
}

fn signVersionScripts(allocator: std.mem.Allocator, install_root: []const u8, target_version_dir: ?[]const u8) void {
    const nvm_path = std.fs.path.resolve(allocator, &.{ install_root, "..", "nvm.exe" }) catch return;
    defer allocator.free(nvm_path);
    std.fs.accessAbsolute(nvm_path, .{}) catch return;

    if (target_version_dir) |version_dir| {
        spawnSignVersionScripts(allocator, nvm_path, version_dir);
        return;
    }

    var root_dir = std.fs.cwd().openDir(install_root, .{ .iterate = true }) catch return;
    defer root_dir.close();
    var it = root_dir.iterate();
    while (it.next() catch null) |entry| {
        if (entry.kind != .directory) continue;
        if (!(std.mem.startsWith(u8, entry.name, "v") or std.mem.startsWith(u8, entry.name, "V"))) continue;
        const version_dir = std.fs.path.join(allocator, &.{ install_root, entry.name }) catch continue;
        defer allocator.free(version_dir);
        spawnSignVersionScripts(allocator, nvm_path, version_dir);
    }
}

fn spawnSignVersionScripts(allocator: std.mem.Allocator, nvm_path: []const u8, version_dir: []const u8) void {
    var child = std.process.Child.init(&.{ nvm_path, "--sign-version-scripts", version_dir }, allocator);
    child.stdin_behavior = .Ignore;
    child.stdout_behavior = .Ignore;
    child.stderr_behavior = .Ignore;
    child.spawn() catch return;
    _ = child.wait() catch {};
}

fn prewarmShims(allocator: std.mem.Allocator, shim_dir: []const u8, silent: bool) void {
    // --silent is every nvm.exe bootstrap + nvm use. Spawning node -v without
    // waiting leaves installs\vX\node.exe mapped, so nvm rm of the default
    // version hits unlinkat Access is denied. Skip here; Go PrewarmVerifyCache
    // still signs the HKCU verify cache after reshim.
    if (silent) return;
    runPrewarmCommand(allocator, shim_dir, "npm");
    runPrewarmCommand(allocator, shim_dir, "node");
}

fn runPrewarmCommand(allocator: std.mem.Allocator, shim_dir: []const u8, command_name: []const u8) void {
    const exe_name = std.fmt.allocPrint(allocator, "{s}.exe", .{command_name}) catch return;
    defer allocator.free(exe_name);

    const exe_path = std.fs.path.join(allocator, &.{ shim_dir, exe_name }) catch return;
    defer allocator.free(exe_path);

    std.fs.accessAbsolute(exe_path, .{}) catch return;

    var child = std.process.Child.init(&.{ exe_path, "-v" }, allocator);
    child.stdin_behavior = .Ignore;
    child.stdout_behavior = .Ignore;
    child.stderr_behavior = .Ignore;

    child.spawn() catch return;
    _ = child.wait() catch return;
}

fn createHardLink(allocator: std.mem.Allocator, link_path: []const u8, existing_path: []const u8) !void {
    const link_w = try std.unicode.utf8ToUtf16LeAllocZ(allocator, link_path);
    defer allocator.free(link_w);
    const existing_w = try std.unicode.utf8ToUtf16LeAllocZ(allocator, existing_path);
    defer allocator.free(existing_w);

    if (CreateHardLinkW(link_w, existing_w, null) == 0) {
        if (CopyFileW(existing_w, link_w, 0) == 0) {
            const copy_error = windows.GetLastError();
            if (shimintegrity.filesHaveSameContents(existing_path, link_path)) {
                return;
            }
            return switch (copy_error) {
                .SHARING_VIOLATION, .ACCESS_DENIED, .USER_MAPPED_FILE => error.ShimFileInUse,
                else => error.CreateHardLinkFailed,
            };
        }
    }
}

fn resolveSiblingProgramProxyPath(allocator: std.mem.Allocator) ![]u8 {
    const self_path = try std.fs.selfExePathAlloc(allocator);
    defer allocator.free(self_path);

    const self_dir = std.fs.path.dirname(self_path) orelse return error.ProxyExecutableNotFound;
    const proxy_path = try std.fs.path.join(allocator, &.{ self_dir, "proxy.exe" });
    errdefer allocator.free(proxy_path);

    std.fs.accessAbsolute(proxy_path, .{}) catch return error.ProxyExecutableNotFound;

    return proxy_path;
}

fn copyFile(allocator: std.mem.Allocator, source_path: []const u8, target_path: []const u8) !void {
    const source_w = try std.unicode.utf8ToUtf16LeAllocZ(allocator, source_path);
    defer allocator.free(source_w);
    const target_w = try std.unicode.utf8ToUtf16LeAllocZ(allocator, target_path);
    defer allocator.free(target_w);

    if (CopyFileW(source_w, target_w, 0) == 0) {
        return error.CopyFileFailed;
    }
}

fn deleteFileWithRetries(abs_path: []const u8) !void {
    const max_attempts: usize = 50;
    var attempt: usize = 0;
    while (attempt < max_attempts) : (attempt += 1) {
        std.fs.deleteFileAbsolute(abs_path) catch |err| {
            if (err == error.AccessDenied and attempt + 1 < max_attempts) {
                std.Thread.sleep(5 * std.time.ns_per_ms);
                continue;
            }
            return err;
        };
        return;
    }
}

// Windows refuses to delete the last remaining hardlink to an image mapped by a
// running process, so a stale shim left over from a proxy upgrade can never be
// replaced while anything launched through it is alive. Renaming is still
// allowed, so park the name aside and sweep it on a later run.
fn retireStaleShim(allocator: std.mem.Allocator, shim_dir: []const u8, file_name: []const u8) !void {
    const stamp: u64 = @intCast(std.time.nanoTimestamp() & 0xFFFFFFFFFFFF);
    const retired_name = try std.fmt.allocPrint(allocator, "{s}{s}{x}", .{
        file_name,
        stale_shim_marker,
        stamp,
    });
    defer allocator.free(retired_name);

    const from_path = try std.fs.path.join(allocator, &.{ shim_dir, file_name });
    defer allocator.free(from_path);
    const to_path = try std.fs.path.join(allocator, &.{ shim_dir, retired_name });
    defer allocator.free(to_path);

    try std.fs.renameAbsolute(from_path, to_path);
}

fn sweepRetiredShims(allocator: std.mem.Allocator, shim_dir: []const u8) void {
    var shim = std.fs.openDirAbsolute(shim_dir, .{ .iterate = true }) catch return;
    defer shim.close();

    var retired = std.ArrayListUnmanaged([]const u8){};
    defer {
        for (retired.items) |name| allocator.free(name);
        retired.deinit(allocator);
    }

    var iter = shim.iterate();
    while (iter.next() catch null) |entry| {
        if (entry.kind != .file) continue;
        if (std.mem.indexOf(u8, entry.name, stale_shim_marker) == null) continue;
        retired.append(allocator, allocator.dupe(u8, entry.name) catch continue) catch continue;
    }

    for (retired.items) |name| {
        shim.deleteFile(name) catch continue;
    }
}

fn writeDryRunJson(allocator: std.mem.Allocator, create_names: []const []const u8, remove_names: []const []const u8) !void {
    var json = std.ArrayListUnmanaged(u8){};
    defer json.deinit(allocator);

    try json.appendSlice(allocator, "{\"create\":[");
    for (create_names, 0..) |name, i| {
        if (i != 0) try json.append(allocator, ',');
        try json.append(allocator, '"');
        try appendJsonEscaped(allocator, &json, name);
        try json.appendSlice(allocator, ".exe\"");
    }

    try json.appendSlice(allocator, "],\"remove\":[");
    for (remove_names, 0..) |name, i| {
        if (i != 0) try json.append(allocator, ',');
        try json.append(allocator, '"');
        try appendJsonEscaped(allocator, &json, name);
        try json.append(allocator, '"');
    }
    try json.appendSlice(allocator, "]}");

    try std.fs.File.stdout().writeAll(json.items);
    try std.fs.File.stdout().writeAll("\n");
}

fn writeStdoutf(allocator: std.mem.Allocator, silent: bool, comptime fmt: []const u8, args: anytype) !void {
    if (silent) return;
    const msg = try std.fmt.allocPrint(allocator, fmt, args);
    defer allocator.free(msg);
    try std.fs.File.stdout().writeAll(msg);
}

fn appendJsonEscaped(allocator: std.mem.Allocator, out: *std.ArrayListUnmanaged(u8), input: []const u8) !void {
    for (input) |ch| {
        switch (ch) {
            '"' => try out.appendSlice(allocator, "\\\""),
            '\\' => try out.appendSlice(allocator, "\\\\"),
            '\n' => try out.appendSlice(allocator, "\\n"),
            '\r' => try out.appendSlice(allocator, "\\r"),
            '\t' => try out.appendSlice(allocator, "\\t"),
            else => {
                if (ch < 0x20) {
                    const escaped = try std.fmt.allocPrint(allocator, "\\u{X:0>4}", .{@as(u16, ch)});
                    defer allocator.free(escaped);
                    try out.appendSlice(allocator, escaped);
                } else {
                    try out.append(allocator, ch);
                }
            },
        }
    }
}

fn reconcileShimExecutables(
    allocator: std.mem.Allocator,
    shim_dir: []const u8,
    proxy_path: []const u8,
    program_node_shim: ?[]const u8,
    cmd_names: []const []const u8,
    force: bool,
    dry_run: bool,
    planned_removals: *std.ArrayListUnmanaged([]const u8),
) ![]const []const u8 {
    const RemovalCandidate = struct {
        file_name: []const u8,
        log_module_removed: bool,
    };

    var live = std.StringHashMap(void).init(allocator);
    defer {
        var it = live.keyIterator();
        while (it.next()) |k| allocator.free(k.*);
        live.deinit();
    }

    var existing = std.StringHashMap(void).init(allocator);
    defer {
        var it = existing.keyIterator();
        while (it.next()) |k| allocator.free(k.*);
        existing.deinit();
    }

    var out = std.ArrayListUnmanaged([]const u8){};
    defer out.deinit(allocator);

    var removals = std.ArrayListUnmanaged(RemovalCandidate){};
    defer {
        for (removals.items) |candidate| allocator.free(candidate.file_name);
        removals.deinit(allocator);
    }

    const node_shim_path = try std.fs.path.join(allocator, &.{ shim_dir, "node.exe" });
    defer allocator.free(node_shim_path);
    if (program_node_shim) |canonical_node| {
        if (std.fs.accessAbsolute(node_shim_path, .{})) {
            if (!shimintegrity.filesHaveSameContents(node_shim_path, canonical_node)) {
                try removals.append(allocator, .{
                    .file_name = try allocator.dupe(u8, "node.exe"),
                    .log_module_removed = false,
                });
            }
        } else |_| {}
    }

    for (cmd_names) |name| {
        const key = try allocator.dupe(u8, name);
        _ = std.ascii.lowerString(key, key);

        if (live.contains(key)) {
            allocator.free(key);
            continue;
        }

        try live.put(key, {});
    }

    var shim = std.fs.openDirAbsolute(shim_dir, .{ .iterate = true }) catch {
        for (cmd_names) |name| {
            try out.append(allocator, try allocator.dupe(u8, name));
        }

        freeNameList(allocator, cmd_names);
        return out.toOwnedSlice(allocator);
    };
    defer shim.close();

    var iter = shim.iterate();
    while (try iter.next()) |entry| {
        if (entry.kind != .file) continue;
        if (std.mem.indexOf(u8, entry.name, stale_shim_marker) != null) continue;
        if (!std.ascii.endsWithIgnoreCase(entry.name, ".exe")) continue;
        if (std.ascii.eqlIgnoreCase(entry.name, "node.exe")) continue;
        if (entry.name.len <= 4) continue;

        const base_name = entry.name[0 .. entry.name.len - 4];
        const key = try allocator.dupe(u8, base_name);
        defer allocator.free(key);
        _ = std.ascii.lowerString(key, key);

        if (live.contains(key)) {
            const shim_path = try std.fs.path.join(allocator, &.{ shim_dir, entry.name });
            defer allocator.free(shim_path);

            if (force or !shimintegrity.filesHaveSameContents(shim_path, proxy_path)) {
                if (force) {
                    try removals.append(allocator, .{
                        .file_name = try allocator.dupe(u8, entry.name),
                        .log_module_removed = false,
                    });
                    continue;
                }

                try removals.append(allocator, .{
                    .file_name = try allocator.dupe(u8, entry.name),
                    .log_module_removed = shouldLogModuleEvent(base_name),
                });
                continue;
            }

            try existing.put(try allocator.dupe(u8, key), {});
            continue;
        }

        if (!live.contains(key)) {
            try removals.append(allocator, .{
                .file_name = try allocator.dupe(u8, entry.name),
                .log_module_removed = shouldLogModuleEvent(base_name),
            });
        }
    }

    for (removals.items) |candidate| {
        try planned_removals.append(allocator, try allocator.dupe(u8, candidate.file_name));

        if (dry_run) continue;

        const remove_path = try std.fs.path.join(allocator, &.{ shim_dir, candidate.file_name });
        defer allocator.free(remove_path);

        deleteFileWithRetries(remove_path) catch {
            retireStaleShim(allocator, shim_dir, candidate.file_name) catch |err| {
                std.debug.print("  failed to replace {s}: {}\n", .{ candidate.file_name, err });
                continue;
            };
        };

        if (candidate.log_module_removed and candidate.file_name.len > 4) {
            const base_name = candidate.file_name[0 .. candidate.file_name.len - 4];
            const removed_msg = std.fmt.allocPrint(allocator, "Global module '{s}' was removed in shim mode.", .{base_name}) catch null;
            if (removed_msg) |msg| {
                defer allocator.free(msg);
                eventlog.writeInfo(allocator, "reshim", msg);
            }
        }
    }

    for (cmd_names) |name| {
        const key = try allocator.dupe(u8, name);
        defer allocator.free(key);
        _ = std.ascii.lowerString(key, key);
        const is_existing = existing.contains(key);

        if (!is_existing) {
            try out.append(allocator, try allocator.dupe(u8, name));
        }
    }

    freeNameList(allocator, cmd_names);
    return out.toOwnedSlice(allocator);
}

fn freeNameList(allocator: std.mem.Allocator, names: []const []const u8) void {
    for (names) |name| allocator.free(name);
    allocator.free(names);
}

fn collectCmdNamesFromInstallRoot(allocator: std.mem.Allocator, install_root: []const u8) ![]const []const u8 {
    var dedupe = std.StringHashMap(void).init(allocator);
    defer {
        var it = dedupe.keyIterator();
        while (it.next()) |k| allocator.free(k.*);
        dedupe.deinit();
    }

    var names = std.ArrayListUnmanaged([]const u8){};
    defer names.deinit(allocator);

    var root_dir = try std.fs.openDirAbsolute(install_root, .{ .iterate = true });
    defer root_dir.close();

    var root_iter = root_dir.iterate();
    while (try root_iter.next()) |entry| {
        if (entry.kind != .directory) continue;
        if (!isVersionDirName(entry.name)) continue;

        var version_dir = root_dir.openDir(entry.name, .{ .iterate = true }) catch continue;
        defer version_dir.close();

        try collectCmdNamesFromCommandDirectory(allocator, &version_dir, &dedupe, &names);
    }

    try appendPnpmHomeBinCmdNames(allocator, &dedupe, &names);
    try appendUniqueCommandName(allocator, &dedupe, &names, "pnpm");

    std.mem.sort([]const u8, names.items, {}, lessThanIgnoreCase);
    return names.toOwnedSlice(allocator);
}

fn collectCmdNamesFromVersionDir(allocator: std.mem.Allocator, version_dir_path: []const u8) ![]const []const u8 {
    var dedupe = std.StringHashMap(void).init(allocator);
    defer {
        var it = dedupe.keyIterator();
        while (it.next()) |k| allocator.free(k.*);
        dedupe.deinit();
    }

    var names = std.ArrayListUnmanaged([]const u8){};
    defer names.deinit(allocator);

    const is_abs = std.fs.path.isAbsolute(version_dir_path);
    var version_dir = if (is_abs)
        try std.fs.openDirAbsolute(version_dir_path, .{ .iterate = true })
    else
        try std.fs.cwd().openDir(version_dir_path, .{ .iterate = true });
    defer version_dir.close();

    try collectCmdNamesFromCommandDirectory(allocator, &version_dir, &dedupe, &names);
    try appendPnpmHomeBinCmdNames(allocator, &dedupe, &names);
    try appendUniqueCommandName(allocator, &dedupe, &names, "pnpm");

    std.mem.sort([]const u8, names.items, {}, lessThanIgnoreCase);
    return names.toOwnedSlice(allocator);
}

fn collectCmdNamesFromCommandDirectory(
    allocator: std.mem.Allocator,
    dir: *std.fs.Dir,
    dedupe: *std.StringHashMap(void),
    names: *std.ArrayListUnmanaged([]const u8),
) !void {
    var iter = dir.iterate();
    while (try iter.next()) |file_entry| {
        if (file_entry.kind != .file) continue;
        if (!std.ascii.endsWithIgnoreCase(file_entry.name, ".cmd")) continue;
        if (file_entry.name.len <= 4) continue;

        const base_name = file_entry.name[0 .. file_entry.name.len - 4];
        try appendUniqueCommandName(allocator, dedupe, names, base_name);
    }
}

fn appendPnpmHomeBinCmdNames(
    allocator: std.mem.Allocator,
    dedupe: *std.StringHashMap(void),
    names: *std.ArrayListUnmanaged([]const u8),
) !void {
    const pnpm_home = (try getOptionalEnvVarOwned(allocator, "PNPM_HOME")) orelse return;
    defer allocator.free(pnpm_home);

    const pnpm_home_bin = try std.fs.path.join(allocator, &.{ pnpm_home, "bin" });
    defer allocator.free(pnpm_home_bin);

    const is_abs = std.fs.path.isAbsolute(pnpm_home_bin);
    var pnpm_bin_dir = if (is_abs)
        std.fs.openDirAbsolute(pnpm_home_bin, .{ .iterate = true }) catch return
    else
        std.fs.cwd().openDir(pnpm_home_bin, .{ .iterate = true }) catch return;
    defer pnpm_bin_dir.close();

    try collectCmdNamesFromCommandDirectory(allocator, &pnpm_bin_dir, dedupe, names);
}

fn appendUniqueCommandName(
    allocator: std.mem.Allocator,
    dedupe: *std.StringHashMap(void),
    names: *std.ArrayListUnmanaged([]const u8),
    base_name: []const u8,
) !void {
    const key = try allocator.dupe(u8, base_name);
    _ = std.ascii.lowerString(key, key);

    if (dedupe.contains(key)) {
        allocator.free(key);
        return;
    }

    try dedupe.put(key, {});
    try names.append(allocator, try allocator.dupe(u8, base_name));
}

fn getOptionalEnvVarOwned(allocator: std.mem.Allocator, name: []const u8) !?[]u8 {
    const raw = std.process.getEnvVarOwned(allocator, name) catch |err| switch (err) {
        error.EnvironmentVariableNotFound => return null,
        else => return err,
    };

    const trimmed = std.mem.trim(u8, raw, " \t\r\n\"");
    if (trimmed.len == 0) {
        allocator.free(raw);
        return null;
    }

    if (trimmed.ptr == raw.ptr and trimmed.len == raw.len) {
        return raw;
    }

    const copy = try allocator.dupe(u8, trimmed);
    allocator.free(raw);
    return copy;
}

fn lessThanIgnoreCase(_: void, a: []const u8, b: []const u8) bool {
    return std.ascii.lessThanIgnoreCase(a, b);
}

fn collectExistingShimNames(allocator: std.mem.Allocator, shim_dir: []const u8, out: *std.StringHashMap(void)) !void {
    var shim = std.fs.openDirAbsolute(shim_dir, .{ .iterate = true }) catch return;
    defer shim.close();

    var iter = shim.iterate();
    while (try iter.next()) |entry| {
        if (entry.kind != .file) continue;
        if (std.mem.indexOf(u8, entry.name, stale_shim_marker) != null) continue;
        if (!std.ascii.endsWithIgnoreCase(entry.name, ".exe")) continue;
        if (std.ascii.eqlIgnoreCase(entry.name, "node.exe")) continue;
        if (entry.name.len <= 4) continue;

        const base_name = entry.name[0 .. entry.name.len - 4];
        const key = try allocator.dupe(u8, base_name);
        _ = std.ascii.lowerString(key, key);

        if (out.contains(key)) {
            allocator.free(key);
            continue;
        }

        try out.put(key, {});
    }
}

fn shouldLogModuleEvent(name: []const u8) bool {
    return !std.ascii.eqlIgnoreCase(name, "npm") and
        !std.ascii.eqlIgnoreCase(name, "npx") and
        !std.ascii.eqlIgnoreCase(name, "pnpm");
}

fn isVersionDirName(name: []const u8) bool {
    if (name.len < 2) return false;
    if (name[0] != 'v' and name[0] != 'V') return false;

    var i: usize = 1;
    var segment_count: usize = 0;

    while (i < name.len) {
        const segment_start = i;
        while (i < name.len and std.ascii.isDigit(name[i])) : (i += 1) {}
        if (i == segment_start) return false;

        segment_count += 1;
        if (i == name.len) break;
        if (name[i] != '.') return false;
        i += 1;
    }

    return segment_count == 3;
}
