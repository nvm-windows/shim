const std = @import("std");
const registry = @import("registry");
const config = @import("config");
const resolver = @import("resolver");

const reg_path = config.preference_registry_root;
const reg_value_version = config.reg_value_version;
const reg_value_root = config.reg_value_root;
const reg_value_auto_use = config.reg_value_auto_use;
const reg_value_auto_install = config.reg_value_auto_install;
const reg_value_auto_install_prompt = config.reg_value_auto_install_prompt;
const reg_value_auto_detect = config.reg_value_auto_detect;
const reg_value_aliases = config.reg_value_aliases;
const reg_value_log_executions = config.reg_value_log_executions;
const reg_nvm_cmd_path = config.reg_nvm_cmd_path;
const default_root = config.default_install_root;
const default_auto_detect = config.default_auto_detect;

pub const ShimConfig = struct {
    root: []u8,
    active_version: []u8,
    auto_use: bool,
    auto_install: bool,
    auto_install_prompt: bool,
    auto_detect: []const []const u8,
    aliases: []const []const u8,
    log_executions: bool,
};

pub const DetectedVersion = struct {
    version: []u8,
    source: []const u8,
};

pub const ResolvedNode = struct {
    requested_version: []const u8,
    effective_version: []const u8,
    version_source: []const u8,
    detected_version: ?[]u8 = null,
    resolved_version: ?[]u8 = null,
    node_bin: ?[]u8 = null,

    pub fn deinit(self: ResolvedNode, allocator: std.mem.Allocator) void {
        if (self.node_bin) |value| allocator.free(value);
        if (self.resolved_version) |value| allocator.free(value);
        if (self.detected_version) |value| allocator.free(value);
    }
};

pub fn loadConfig(allocator: std.mem.Allocator) !ShimConfig {
    const config_hives = registry.preferenceHives();

    const raw_version = try registry.queryStringWithFallback(allocator, config_hives, reg_path, reg_value_version);
    const version = try resolver.normalizeVersionSpec(allocator, raw_version);
    allocator.free(raw_version);

    const raw_root = registry.queryStringWithFallback(allocator, config_hives, reg_path, reg_value_root) catch
        try allocator.dupe(u8, default_root);
    const root = try expandEnv(allocator, raw_root);
    allocator.free(raw_root);

    const auto_use = (try registry.queryDwordOptionalWithFallback(config_hives, reg_path, reg_value_auto_use)) orelse 1;
    const auto_install = (try registry.queryDwordOptionalWithFallback(config_hives, reg_path, reg_value_auto_install)) orelse 1;
    const auto_install_prompt = (try registry.queryDwordOptionalWithFallback(config_hives, reg_path, reg_value_auto_install_prompt)) orelse 1;

    const auto_detect_raw = registry.queryStringWithFallback(allocator, config_hives, reg_path, reg_value_auto_detect) catch
        try allocator.dupe(u8, default_auto_detect);
    defer allocator.free(auto_detect_raw);
    const auto_detect = try parseCsvList(allocator, auto_detect_raw);
    const aliases = (try registry.queryMultiStringOptionalWithFallback(allocator, config_hives, reg_path, reg_value_aliases)) orelse
        try allocator.alloc([]const u8, 0);
    const log_executions = (try registry.queryDwordOptionalWithFallback(config_hives, reg_path, reg_value_log_executions)) orelse 0;

    return .{
        .root = root,
        .active_version = version,
        .auto_use = auto_use != 0,
        .auto_install = auto_install != 0,
        .auto_install_prompt = auto_install_prompt != 0,
        .auto_detect = auto_detect,
        .aliases = aliases,
        .log_executions = log_executions != 0,
    };
}

pub fn deinitConfig(allocator: std.mem.Allocator, cfg: ShimConfig) void {
    allocator.free(cfg.root);
    allocator.free(cfg.active_version);
    for (cfg.auto_detect) |value| allocator.free(value);
    allocator.free(cfg.auto_detect);
    for (cfg.aliases) |value| allocator.free(value);
    allocator.free(cfg.aliases);
}

pub fn resolveConfiguredNode(allocator: std.mem.Allocator, cfg: ShimConfig, override_version: ?[]const u8) !ResolvedNode {
    var requested_version: []const u8 = cfg.active_version;
    var version_source: []const u8 = "system_default";
    var detected_version: ?[]u8 = null;

    if (cfg.auto_use) {
        if (try detectVersionFromCwd(allocator, cfg.auto_detect)) |detected| {
            detected_version = detected.version;
            requested_version = detected.version;
            version_source = detected.source;
        }
    }

    if (override_version) |value| {
        requested_version = value;
        version_source = "override";
    }

    if (requested_version.len == 0) {
        if (detected_version) |value| allocator.free(value);
        return error.NoActiveVersion;
    }

    const effective_version = selectEffectiveVersion(cfg.aliases, requested_version);
    const resolved_version = try resolveInstalledVersionSpec(allocator, cfg.root, effective_version);
    errdefer if (resolved_version) |value| allocator.free(value);

    const node_bin = if (resolved_version) |value|
        try resolveNodeBinaryPath(allocator, cfg.root, value)
    else
        null;
    errdefer if (node_bin) |value| allocator.free(value);

    return .{
        .requested_version = requested_version,
        .effective_version = effective_version,
        .version_source = version_source,
        .detected_version = detected_version,
        .resolved_version = resolved_version,
        .node_bin = node_bin,
    };
}

pub fn detectVersionFromCwd(allocator: std.mem.Allocator, detect_files: []const []const u8) !?DetectedVersion {
    for (detect_files) |file_name| {
        const raw = std.fs.cwd().readFileAlloc(allocator, file_name, 1024 * 1024) catch continue;
        defer allocator.free(raw);

        const lower_name = try std.ascii.allocLowerString(allocator, file_name);
        defer allocator.free(lower_name);

        if (std.mem.eql(u8, lower_name, "package.json") or std.mem.eql(u8, lower_name, "package-lock.json")) {
            if (try extractPackageNodeEngine(allocator, raw)) |spec| {
                defer allocator.free(spec);
                const normalized = resolver.normalizeVersionSpec(allocator, spec) catch continue;
                if (normalized.len > 0) {
                    return .{ .version = normalized, .source = file_name };
                }
                allocator.free(normalized);
            }
            continue;
        }

        const spec = std.mem.trim(u8, raw, " \t\r\n");
        if (spec.len == 0) continue;
        const normalized = resolver.normalizeVersionSpec(allocator, spec) catch continue;
        if (normalized.len > 0) {
            return .{ .version = normalized, .source = file_name };
        }
        allocator.free(normalized);
    }

    return null;
}

pub fn resolveInstalledVersionSpec(allocator: std.mem.Allocator, root: []const u8, spec: []const u8) !?[]u8 {
    if (try resolver.resolveInstalledVersionSpec(allocator, root, spec, null)) |installed| {
        return installed;
    }

    const output = execNvmCapture(allocator, &.{ "list", "available" }) catch return null;
    defer allocator.free(output);

    return resolver.resolveInstalledVersionSpec(allocator, root, spec, output);
}

pub fn resolveNodeBinaryPath(allocator: std.mem.Allocator, primary_root: []const u8, version: []const u8) !?[]u8 {
    if (try tryNodePathAtRoot(allocator, primary_root, version)) |path| return path;

    const local_appdata = std.process.getEnvVarOwned(allocator, "LOCALAPPDATA") catch null;
    defer if (local_appdata) |value| allocator.free(value);
    if (local_appdata) |lad| {
        const legacy_root = try std.fs.path.join(allocator, &.{ lad, "nvm" });
        defer allocator.free(legacy_root);
        if (try tryNodePathAtRoot(allocator, legacy_root, version)) |path| return path;

        const legacy_installs = try std.fs.path.join(allocator, &.{ lad, "nvm", "installs" });
        defer allocator.free(legacy_installs);
        if (try tryNodePathAtRoot(allocator, legacy_installs, version)) |path| return path;
    }

    const nvm_home = std.process.getEnvVarOwned(allocator, "NVM_HOME") catch null;
    defer if (nvm_home) |value| allocator.free(value);
    if (nvm_home) |path| {
        if (try tryNodePathAtRoot(allocator, path, version)) |node_path| return node_path;
    }

    return null;
}

pub fn resolveUserAlias(aliases: []const []const u8, version: []const u8) ?[]const u8 {
    const wanted = std.mem.trim(u8, version, " \t\r\n");
    if (wanted.len == 0) return null;

    for (aliases) |pair| {
        const eq_index = std.mem.indexOfScalar(u8, pair, '=') orelse continue;
        const name = std.mem.trim(u8, pair[0..eq_index], " \t\r\n");
        const target = std.mem.trim(u8, pair[eq_index + 1 ..], " \t\r\n");

        if (name.len == 0 or target.len == 0) continue;
        if (std.ascii.eqlIgnoreCase(name, wanted)) return target;
    }

    return null;
}

pub fn selectEffectiveVersion(aliases: []const []const u8, requested: []const u8) []const u8 {
    return resolveUserAlias(aliases, requested) orelse requested;
}

pub fn runNvmCommand(allocator: std.mem.Allocator, nvm_args: []const []const u8) !void {
    simulateNvmCommandLookup(allocator);

    const nvm_exe = try resolveNvmExePath(allocator);
    defer allocator.free(nvm_exe);

    var argv = try allocator.alloc([]const u8, nvm_args.len + 1);
    defer allocator.free(argv);
    argv[0] = nvm_exe;
    for (nvm_args, 0..) |arg, i| {
        argv[i + 1] = arg;
    }

    var child = std.process.Child.init(argv, allocator);
    child.stdin_behavior = .Inherit;
    child.stdout_behavior = .Inherit;
    child.stderr_behavior = .Inherit;

    try child.spawn();
    const term = try child.wait();
    if (term != .Exited or term.Exited != 0) return error.AutoInstallFailed;
}

pub fn autoInstallVersion(allocator: std.mem.Allocator, version: []const u8) !void {
    try runNvmCommand(allocator, &.{ "install", version });
}

fn extractPackageNodeEngine(allocator: std.mem.Allocator, raw: []const u8) !?[]u8 {
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, raw, .{}) catch return null;
    defer parsed.deinit();

    const obj = switch (parsed.value) {
        .object => |o| o,
        else => return null,
    };

    // devEngines.runtime.version takes precedence over engines.node.
    if (obj.get("devEngines")) |dev_engines_val| {
        if (dev_engines_val == .object) {
            if (dev_engines_val.object.get("runtime")) |runtime_val| {
                if (runtime_val == .object) {
                    if (runtime_val.object.get("version")) |version_val| {
                        if (version_val == .string) {
                            return try allocator.dupe(u8, version_val.string);
                        }
                    }
                }
            }
        }
    }

    // Fall back to engines.node.
    if (obj.get("engines")) |engines_val| {
        if (engines_val == .object) {
            if (engines_val.object.get("node")) |node_val| {
                if (node_val == .string) {
                    return try allocator.dupe(u8, node_val.string);
                }
            }
        }
    }

    return null;
}

fn executablePath(allocator: std.mem.Allocator, root: []const u8, version: []const u8) ![]u8 {
    const bare = if (version.len > 0 and (version[0] == 'v' or version[0] == 'V')) version[1..] else version;
    const version_dir = try std.fmt.allocPrint(allocator, "v{s}", .{bare});
    defer allocator.free(version_dir);

    return std.fs.path.join(allocator, &.{ root, version_dir, "node.exe" });
}

fn isInstalled(node_bin: []const u8) bool {
    std.fs.cwd().access(node_bin, .{}) catch return false;
    return true;
}

fn tryNodePathAtRoot(allocator: std.mem.Allocator, root: []const u8, version: []const u8) !?[]u8 {
    const node_bin = try executablePath(allocator, root, version);
    if (isInstalled(node_bin)) return node_bin;
    allocator.free(node_bin);
    return null;
}

fn execNvmCapture(allocator: std.mem.Allocator, nvm_args: []const []const u8) ![]u8 {
    simulateNvmCommandLookup(allocator);

    const nvm_exe = try resolveNvmExePath(allocator);
    defer allocator.free(nvm_exe);

    var argv = try allocator.alloc([]const u8, nvm_args.len + 1);
    defer allocator.free(argv);
    argv[0] = nvm_exe;
    for (nvm_args, 0..) |arg, i| {
        argv[i + 1] = arg;
    }

    const result = try std.process.Child.run(.{
        .allocator = allocator,
        .argv = argv,
    });
    defer allocator.free(result.stderr);

    if (result.term != .Exited or result.term.Exited != 0) {
        defer allocator.free(result.stdout);
        return error.CommandFailed;
    }

    return result.stdout;
}

fn simulateNvmCommandLookup(allocator: std.mem.Allocator) void {
    const command_hives = registry.commandLookupHives();
    const value = registry.queryStringWithFallback(allocator, command_hives, reg_nvm_cmd_path, "") catch return;
    allocator.free(value);
}

fn resolveNvmExePath(allocator: std.mem.Allocator) ![]u8 {
    const self_path = try std.fs.selfExePathAlloc(allocator);
    defer allocator.free(self_path);

    const self_dir = std.fs.path.dirname(self_path) orelse return error.NvmExecutableNotFound;
    const nvm_exe = try std.fs.path.join(allocator, &.{ self_dir, "..", "nvm.exe" });
    std.fs.cwd().access(nvm_exe, .{}) catch return error.NvmExecutableNotFound;
    return nvm_exe;
}

fn parseCsvList(allocator: std.mem.Allocator, raw: []const u8) ![]const []const u8 {
    var out = std.ArrayListUnmanaged([]const u8){};
    defer out.deinit(allocator);

    var it = std.mem.tokenizeScalar(u8, raw, ',');
    while (it.next()) |part| {
        const item = std.mem.trim(u8, part, " \t\r\n");
        if (item.len == 0) continue;
        const copy = try allocator.dupe(u8, item);
        try out.append(allocator, copy);
    }

    if (out.items.len == 0) {
        const fallback = try allocator.dupe(u8, ".nvmrc");
        try out.append(allocator, fallback);
    }

    return out.toOwnedSlice(allocator);
}

fn expandEnv(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    var result = std.ArrayListUnmanaged(u8){};
    defer result.deinit(allocator);

    var i: usize = 0;
    while (i < path.len) {
        if (path[i] == '%') {
            const end = std.mem.indexOfScalarPos(u8, path, i + 1, '%') orelse {
                try result.append(allocator, path[i]);
                i += 1;
                continue;
            };
            const var_name = path[i + 1 .. end];
            const value = std.process.getEnvVarOwned(allocator, var_name) catch null;
            if (value) |env_value| {
                defer allocator.free(env_value);
                try result.appendSlice(allocator, env_value);
            } else {
                try result.append(allocator, '%');
                try result.appendSlice(allocator, var_name);
                try result.append(allocator, '%');
            }
            i = end + 1;
        } else {
            try result.append(allocator, path[i]);
            i += 1;
        }
    }

    return result.toOwnedSlice(allocator);
}

test "resolveUserAlias matches configured aliases case-insensitively" {
    const aliases = [_][]const u8{
        "stable=24.9.0",
        " nightly = 25.0.0 ",
        "broken",
        "empty=",
    };

    try std.testing.expectEqualStrings("24.9.0", resolveUserAlias(&aliases, "stable").?);
    try std.testing.expectEqualStrings("25.0.0", resolveUserAlias(&aliases, "NIGHTLY").?);
    try std.testing.expect(resolveUserAlias(&aliases, "missing") == null);
}

test "selectEffectiveVersion keeps requested version when no alias matches" {
    const aliases = [_][]const u8{
        "stable=24.9.0",
        "nightly=25.0.0",
    };

    try std.testing.expectEqualStrings("18.20.8", selectEffectiveVersion(&aliases, "18.20.8"));
}
