const std = @import("std");
const windows = std.os.windows;
const registry = @import("registry");
const config = @import("config");
const resolver = @import("resolver");

const reg_path = config.preference_registry_root;
const policy_path = config.policy_registry_root;
const reg_value_version = config.reg_value_version;
const reg_value_root = config.reg_value_root;
const reg_value_auto_use = config.reg_value_auto_use;
const reg_value_auto_install = config.reg_value_auto_install;
const reg_value_auto_install_prompt = config.reg_value_auto_install_prompt;
const reg_value_auto_detect = config.reg_value_auto_detect;
const reg_value_aliases = config.reg_value_aliases;
const reg_value_log_executions = config.reg_value_log_executions;
const reg_value_enforce_permission_model = config.reg_value_enforce_permission_model;
const reg_value_package_manager_mismatch_action = config.reg_value_package_manager_mismatch_action;
const reg_value_npm_module_minimum_age = config.reg_value_npm_module_minimum_age;
const reg_value_npm_mirror = config.reg_value_npm_mirror;
const reg_nvm_cmd_path = config.reg_nvm_cmd_path;
const default_root = config.default_install_root;
const default_auto_detect = config.default_auto_detect;

const policy_hives = [_]windows.HKEY{
    windows.HKEY_LOCAL_MACHINE,
};

pub const PackageManagerMismatchAction = enum {
    ignore,
    warn,
    @"error",
};

pub const ShimConfig = struct {
    root: []u8,
    active_version: []u8,
    auto_use: bool,
    auto_install: bool,
    auto_install_prompt: bool,
    auto_detect: []const []const u8,
    aliases: []const []const u8,
    log_executions: bool,
    enforce_permission_model: bool,
    package_manager_mismatch_action: PackageManagerMismatchAction,
    npm_module_minimum_age: ?u64,
    npm_registry_fallback: ?[]u8,
};

pub const PackageManagerConstraint = struct {
    name: []u8,
    version_spec: []u8,

    pub fn deinit(self: PackageManagerConstraint, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        allocator.free(self.version_spec);
    }
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

    const raw_version = registry.queryStringWithFallback(allocator, config_hives, reg_path, reg_value_version) catch |err| switch (err) {
        error.RegistryValueNotFound => try allocator.dupe(u8, ""),
        else => return err,
    };
    const version = try resolver.normalizeVersionSpec(allocator, raw_version);
    allocator.free(raw_version);

    const root = try loadInstallRoot(allocator);

    const auto_use = (try registry.queryDwordOptionalWithFallback(config_hives, reg_path, reg_value_auto_use)) orelse 1;
    const auto_install = (try registry.queryDwordOptionalWithFallback(config_hives, reg_path, reg_value_auto_install)) orelse 1;
    const auto_install_prompt = (try registry.queryDwordOptionalWithFallback(config_hives, reg_path, reg_value_auto_install_prompt)) orelse 1;

    const auto_detect = auto_detect: {
        if (try registry.queryMultiStringOptionalWithFallback(allocator, config_hives, reg_path, reg_value_auto_detect)) |configured| {
            if (configured.len > 0) break :auto_detect configured;
            for (configured) |value| allocator.free(value);
            allocator.free(configured);
        }

        const auto_detect_raw = registry.queryStringWithFallback(allocator, config_hives, reg_path, reg_value_auto_detect) catch
            try allocator.dupe(u8, default_auto_detect);
        defer allocator.free(auto_detect_raw);
        break :auto_detect try parseCsvList(allocator, auto_detect_raw);
    };
    const aliases = (try registry.queryMultiStringOptionalWithFallback(allocator, config_hives, reg_path, reg_value_aliases)) orelse
        try allocator.alloc([]const u8, 0);
    const log_executions = (try registry.queryDwordOptionalWithFallback(config_hives, reg_path, reg_value_log_executions)) orelse 0;
    const enforce_permission_model = try loadEnforcePermissionModel(config_hives);
    const npm_registry_fallback = try loadFirstConfiguredRegistryValue(allocator, config_hives, reg_path, reg_value_npm_mirror);
    const npm_module_minimum_age = age: {
        if (try registry.queryQwordOptionalWithFallback(config_hives, reg_path, reg_value_npm_module_minimum_age)) |value| {
            break :age value;
        }

        if (try registry.queryDwordOptionalWithFallback(config_hives, reg_path, reg_value_npm_module_minimum_age)) |value| {
            break :age @as(u64, value);
        }

        const raw_age = registry.queryStringWithFallback(allocator, config_hives, reg_path, reg_value_npm_module_minimum_age) catch {
            break :age null;
        };
        defer allocator.free(raw_age);

        break :age parseMinimumAgeMinutes(raw_age);
    };

    const raw_package_manager_mismatch_action = registry.queryStringWithFallback(allocator, config_hives, reg_path, reg_value_package_manager_mismatch_action) catch
        try allocator.dupe(u8, "error");
    defer allocator.free(raw_package_manager_mismatch_action);
    const package_manager_mismatch_action = parsePackageManagerMismatchAction(raw_package_manager_mismatch_action);

    return .{
        .root = root,
        .active_version = version,
        .auto_use = auto_use != 0,
        .auto_install = auto_install != 0,
        .auto_install_prompt = auto_install_prompt != 0,
        .auto_detect = auto_detect,
        .aliases = aliases,
        .log_executions = log_executions != 0,
        .enforce_permission_model = enforce_permission_model,
        .package_manager_mismatch_action = package_manager_mismatch_action,
        .npm_module_minimum_age = npm_module_minimum_age,
        .npm_registry_fallback = npm_registry_fallback,
    };
}

fn loadEnforcePermissionModel(config_hives: []const windows.HKEY) !bool {
    // HKLM policy wins (ADMX); then machine/user preferences (nvm config).
    if (try registry.queryDwordOptionalWithFallback(&policy_hives, policy_path, reg_value_enforce_permission_model)) |value| {
        return value != 0;
    }
    if (try registry.queryDwordOptionalWithFallback(config_hives, reg_path, reg_value_enforce_permission_model)) |value| {
        return value != 0;
    }
    return false;
}

pub fn loadInstallRoot(allocator: std.mem.Allocator) ![]u8 {
    const config_hives = registry.preferenceHives();
    const raw_root = registry.queryStringWithFallback(allocator, config_hives, reg_path, reg_value_root) catch
        try allocator.dupe(u8, default_root);
    defer allocator.free(raw_root);

    return expandEnv(allocator, raw_root);
}

pub fn deinitConfig(allocator: std.mem.Allocator, cfg: ShimConfig) void {
    allocator.free(cfg.root);
    allocator.free(cfg.active_version);
    for (cfg.auto_detect) |value| allocator.free(value);
    allocator.free(cfg.auto_detect);
    for (cfg.aliases) |value| allocator.free(value);
    allocator.free(cfg.aliases);
    if (cfg.npm_registry_fallback) |value| allocator.free(value);
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

pub fn shouldCheckPackageManagerMismatch(source: []const u8, action: PackageManagerMismatchAction) bool {
    if (action == .ignore) return false;
    return std.ascii.eqlIgnoreCase(source, "package.json") or std.ascii.eqlIgnoreCase(source, "package-lock.json");
}

pub fn detectPackageManagerConstraintFromFile(allocator: std.mem.Allocator, file_name: []const u8) !?PackageManagerConstraint {
    if (!(std.ascii.eqlIgnoreCase(file_name, "package.json") or std.ascii.eqlIgnoreCase(file_name, "package-lock.json"))) {
        return null;
    }

    const raw = std.fs.cwd().readFileAlloc(allocator, file_name, 1024 * 1024) catch return null;
    defer allocator.free(raw);

    const parsed = std.json.parseFromSlice(std.json.Value, allocator, raw, .{}) catch return null;
    defer parsed.deinit();

    const obj = switch (parsed.value) {
        .object => |o| o,
        else => return null,
    };

    if (obj.get("devEngines")) |dev_engines_val| {
        if (dev_engines_val == .object) {
            if (dev_engines_val.object.get("packageManager")) |pm_val| {
                if (pm_val == .object) {
                    const name_val = pm_val.object.get("name") orelse return null;
                    const version_val = pm_val.object.get("version") orelse return null;

                    if (name_val != .string or version_val != .string) {
                        return null;
                    }

                    const required_spec = std.mem.trim(u8, version_val.string, " \t\r\n");
                    if (required_spec.len == 0) return null;

                    return .{
                        .name = try allocator.dupe(u8, name_val.string),
                        .version_spec = try allocator.dupe(u8, required_spec),
                    };
                }
            }
        }
    }

    return null;
}

pub fn resolvePackageManagerVersion(allocator: std.mem.Allocator, node_bin: []const u8, command_name: []const u8, command_path: []const u8) !?[]u8 {
    const node_install_dir = std.fs.path.dirname(node_bin) orelse return null;

    const package_name = if (std.ascii.eqlIgnoreCase(command_name, "npx")) "npm" else command_name;
    const package_json = try std.fs.path.join(allocator, &.{ node_install_dir, "node_modules", package_name, "package.json" });
    defer allocator.free(package_json);

    const raw = std.fs.cwd().readFileAlloc(allocator, package_json, 1024 * 1024) catch {
        return try resolvePackageManagerVersionFromCommand(allocator, node_install_dir, command_path);
    };
    defer allocator.free(raw);

    const parsed = std.json.parseFromSlice(std.json.Value, allocator, raw, .{}) catch {
        return try resolvePackageManagerVersionFromCommand(allocator, node_install_dir, command_path);
    };
    defer parsed.deinit();

    const obj = switch (parsed.value) {
        .object => |o| o,
        else => return try resolvePackageManagerVersionFromCommand(allocator, node_install_dir, command_path),
    };

    const version_val = obj.get("version") orelse return try resolvePackageManagerVersionFromCommand(allocator, node_install_dir, command_path);
    if (version_val != .string) return try resolvePackageManagerVersionFromCommand(allocator, node_install_dir, command_path);

    const version = std.mem.trim(u8, version_val.string, " \t\r\n");
    if (version.len == 0) return try resolvePackageManagerVersionFromCommand(allocator, node_install_dir, command_path);

    return @as(?[]u8, try allocator.dupe(u8, version));
}

fn resolvePackageManagerVersionFromCommand(allocator: std.mem.Allocator, node_install_dir: []const u8, command_path: []const u8) !?[]u8 {
    var env_map = try std.process.getEnvMap(allocator);
    defer env_map.deinit();

    const old_path = env_map.get("PATH") orelse "";
    const child_path = try std.fmt.allocPrint(allocator, "{s};{s}", .{ node_install_dir, old_path });
    defer allocator.free(child_path);
    try env_map.put("PATH", child_path);

    const ext = std.fs.path.extension(command_path);
    const use_cmd = std.ascii.eqlIgnoreCase(ext, ".cmd") or std.ascii.eqlIgnoreCase(ext, ".bat");

    var argv = if (use_cmd)
        try allocator.alloc([]const u8, 5)
    else
        try allocator.alloc([]const u8, 2);
    defer allocator.free(argv);

    if (use_cmd) {
        argv[0] = "cmd.exe";
        argv[1] = "/d";
        argv[2] = "/c";
        argv[3] = command_path;
        argv[4] = "--version";
    } else {
        argv[0] = command_path;
        argv[1] = "--version";
    }

    const result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = argv,
        .env_map = &env_map,
    }) catch return null;
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    if (result.term != .Exited or result.term.Exited != 0) {
        return null;
    }

    var lines = std.mem.tokenizeAny(u8, result.stdout, "\r\n");
    const line = lines.next() orelse return null;
    const trimmed = std.mem.trim(u8, line, " \t\r\n");
    if (trimmed.len == 0) return null;

    return try allocator.dupe(u8, trimmed);
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

fn parsePackageManagerMismatchAction(raw: []const u8) PackageManagerMismatchAction {
    const value = std.mem.trim(u8, raw, " \t\r\n");
    if (std.ascii.eqlIgnoreCase(value, "ignore")) return .ignore;
    if (std.ascii.eqlIgnoreCase(value, "warn")) return .warn;
    return .@"error";
}

fn parseMinimumAgeMinutes(raw: []const u8) ?u64 {
    const trimmed = std.mem.trim(u8, raw, " \t\r\n");
    if (trimmed.len == 0) return null;

    return std.fmt.parseUnsigned(u64, trimmed, 10) catch |err| switch (err) {
        error.Overflow => std.math.maxInt(u64),
        else => null,
    };
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

fn loadFirstConfiguredRegistryValue(allocator: std.mem.Allocator, hives: anytype, sub_key: []const u8, value_name: []const u8) !?[]u8 {
    if (try registry.queryMultiStringOptionalWithFallback(allocator, hives, sub_key, value_name)) |configured| {
        defer freeStringList(allocator, configured);

        for (configured) |item| {
            const trimmed = std.mem.trim(u8, item, " \t\r\n");
            if (trimmed.len == 0) continue;
            return try allocator.dupe(u8, trimmed);
        }
    }

    const raw = registry.queryStringWithFallback(allocator, hives, sub_key, value_name) catch return null;
    defer allocator.free(raw);

    var it = std.mem.tokenizeScalar(u8, raw, ',');
    while (it.next()) |part| {
        const trimmed = std.mem.trim(u8, part, " \t\r\n");
        if (trimmed.len == 0) continue;
        return try allocator.dupe(u8, trimmed);
    }

    return null;
}

fn freeStringList(allocator: std.mem.Allocator, values: []const []const u8) void {
    for (values) |item| allocator.free(item);
    allocator.free(values);
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

test "parseMinimumAgeMinutes parses valid decimal strings" {
    try std.testing.expectEqual(@as(?u64, 1440), parseMinimumAgeMinutes("1440"));
    try std.testing.expectEqual(@as(?u64, 0), parseMinimumAgeMinutes("0"));
}

test "parseMinimumAgeMinutes saturates overflow and rejects invalid" {
    try std.testing.expectEqual(@as(?u64, std.math.maxInt(u64)), parseMinimumAgeMinutes("10000000000000000000000000"));
    try std.testing.expect(parseMinimumAgeMinutes("not-a-number") == null);
    try std.testing.expect(parseMinimumAgeMinutes("   ") == null);
}
