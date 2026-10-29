const std = @import("std");
const permission_grants = @import("permission_grants");

/// npm/npx/pnpm read this as `--node-options` for lifecycle `node` children.
/// It does not change the already-running package-manager process.
pub const env_name = "npm_config_node_options";

pub const Policy = struct {
    enforce_permission_model: bool,
    enforce_permission_model_machine_policy: bool,
    freeze_v8_global_objects: bool,
    disable_eval_and_string_execution: bool,
};

pub fn appliesToCommand(command_name: []const u8) bool {
    return std.ascii.eqlIgnoreCase(command_name, "npm") or
        std.ascii.eqlIgnoreCase(command_name, "npx") or
        std.ascii.eqlIgnoreCase(command_name, "pnpm");
}

fn nodeMajorVersion(version: []const u8) u32 {
    const bare = if (version.len > 0 and (version[0] == 'v' or version[0] == 'V')) version[1..] else version;
    const dot = std.mem.indexOfScalar(u8, bare, '.') orelse bare.len;
    return std.fmt.parseInt(u32, bare[0..dot], 10) catch 0;
}

/// Same enable flag as node-shim. Scripts have no caller argv, so audit never
/// counts as already enabled.
pub fn permissionFlag(version: []const u8, enforce: bool) ?[]const u8 {
    if (!enforce) return null;
    const major = nodeMajorVersion(version);
    if (major < 20) return null;
    if (major >= 23) return "--permission";
    return "--experimental-permission";
}

/// Same flags node-shim would inject on an empty forwarded argv.
pub fn collectFlags(
    allocator: std.mem.Allocator,
    version: []const u8,
    policy: Policy,
    default_grants: []const []const u8,
) ![]const []const u8 {
    var flags = std.ArrayListUnmanaged([]const u8){};
    errdefer flags.deinit(allocator);

    if (permissionFlag(version, policy.enforce_permission_model)) |flag| {
        try flags.append(allocator, flag);
        for (default_grants) |grant| {
            const trimmed = std.mem.trim(u8, grant, " \t\r\n");
            if (trimmed.len == 0) continue;
            if (permission_grants.isPermissionAuditFlag(trimmed)) continue;
            try flags.append(allocator, trimmed);
        }
    }

    if (policy.freeze_v8_global_objects and nodeMajorVersion(version) >= 12) {
        try flags.append(allocator, "--frozen-intrinsics");
    }
    if (policy.disable_eval_and_string_execution) {
        try flags.append(allocator, "--disallow-code-generation-from-strings");
    }

    return try flags.toOwnedSlice(allocator);
}

fn isAsciiWhitespace(ch: u8) bool {
    return ch == ' ' or ch == '\t' or ch == '\r' or ch == '\n';
}

fn tokenize(allocator: std.mem.Allocator, raw: []const u8) ![][]const u8 {
    var out = std.ArrayListUnmanaged([]const u8){};
    errdefer out.deinit(allocator);
    var index: usize = 0;
    while (index < raw.len) {
        while (index < raw.len and isAsciiWhitespace(raw[index])) index += 1;
        if (index >= raw.len) break;
        const start = index;
        while (index < raw.len and !isAsciiWhitespace(raw[index])) index += 1;
        try out.append(allocator, raw[start..index]);
    }
    return try out.toOwnedSlice(allocator);
}

fn hasToken(tokens: []const []const u8, flag: []const u8) bool {
    for (tokens) |token| {
        if (std.mem.eql(u8, token, flag)) return true;
    }
    return false;
}

fn isPermissionEnableFlag(token: []const u8) bool {
    return std.mem.eql(u8, token, "--permission") or
        std.mem.eql(u8, token, "--experimental-permission") or
        std.mem.startsWith(u8, token, "--permission=") or
        std.mem.startsWith(u8, token, "--experimental-permission=");
}

fn hasPermissionEnable(tokens: []const []const u8) bool {
    for (tokens) |token| {
        if (isPermissionEnableFlag(token)) return true;
    }
    return false;
}

fn formatToken(allocator: std.mem.Allocator, token: []const u8) ![]u8 {
    if (std.mem.indexOfAny(u8, token, " \t") == null) {
        return allocator.dupe(u8, token);
    }
    return std.fmt.allocPrint(allocator, "\"{s}\"", .{token});
}

/// Merge policy flags into an existing `npm_config_node_options` value.
/// Returns null when the result equals `existing` (caller must not write env).
pub fn mergeOptions(
    allocator: std.mem.Allocator,
    existing: []const u8,
    flags: []const []const u8,
    strip_audit: bool,
) !?[]u8 {
    const existing_tokens = try tokenize(allocator, existing);
    defer allocator.free(existing_tokens);

    var kept = std.ArrayListUnmanaged([]const u8){};
    defer kept.deinit(allocator);
    for (existing_tokens) |token| {
        if (strip_audit and permission_grants.isPermissionAuditFlag(token)) continue;
        try kept.append(allocator, token);
    }
    for (flags) |flag| {
        if (hasToken(kept.items, flag)) continue;
        if (isPermissionEnableFlag(flag) and hasPermissionEnable(kept.items)) continue;
        try kept.append(allocator, flag);
    }

    if (kept.items.len == 0) {
        if (existing.len == 0) return null;
        return try allocator.dupe(u8, "");
    }

    var parts = std.ArrayListUnmanaged([]u8){};
    defer {
        for (parts.items) |part| allocator.free(part);
        parts.deinit(allocator);
    }
    for (kept.items) |token| {
        try parts.append(allocator, try formatToken(allocator, token));
    }

    var total: usize = 0;
    for (parts.items, 0..) |part, i| {
        total += part.len;
        if (i != 0) total += 1;
    }
    var out = try allocator.alloc(u8, total);
    var offset: usize = 0;
    for (parts.items, 0..) |part, i| {
        if (i != 0) {
            out[offset] = ' ';
            offset += 1;
        }
        @memcpy(out[offset..][0..part.len], part);
        offset += part.len;
    }
    if (std.mem.eql(u8, out, existing)) {
        allocator.free(out);
        return null;
    }
    return out;
}

pub fn applyToEnv(
    allocator: std.mem.Allocator,
    env: *std.process.EnvMap,
    command_name: []const u8,
    version: []const u8,
    policy: Policy,
    default_grants: []const []const u8,
) !void {
    if (!appliesToCommand(command_name)) return;
    const flags = try collectFlags(allocator, version, policy, default_grants);
    defer allocator.free(flags);
    if (flags.len == 0) return;

    const existing = env.get(env_name) orelse "";
    const strip_audit = policy.enforce_permission_model and policy.enforce_permission_model_machine_policy;
    const merged = try mergeOptions(allocator, existing, flags, strip_audit) orelse return;
    defer allocator.free(merged);
    try env.put(env_name, merged);
}

test "appliesToCommand is npm npx pnpm only" {
    try std.testing.expect(appliesToCommand("npm"));
    try std.testing.expect(appliesToCommand("NPX"));
    try std.testing.expect(appliesToCommand("pnpm"));
    try std.testing.expect(!appliesToCommand("yarn"));
    try std.testing.expect(!appliesToCommand("yarnpkg"));
    try std.testing.expect(!appliesToCommand("corepack"));
    try std.testing.expect(!appliesToCommand("vlt"));
    try std.testing.expect(!appliesToCommand("node"));
}

test "collectFlags empty when policy off" {
    const flags = try collectFlags(std.testing.allocator, "24.0.0", .{
        .enforce_permission_model = false,
        .enforce_permission_model_machine_policy = false,
        .freeze_v8_global_objects = false,
        .disable_eval_and_string_execution = false,
    }, &.{});
    defer std.testing.allocator.free(flags);
    try std.testing.expectEqual(@as(usize, 0), flags.len);
}

test "collectFlags permission and grants for node 24" {
    const grants = [_][]const u8{ "--allow-fs-read=*", " --permission-audit ", "  " };
    const flags = try collectFlags(std.testing.allocator, "v24.11.0", .{
        .enforce_permission_model = true,
        .enforce_permission_model_machine_policy = false,
        .freeze_v8_global_objects = false,
        .disable_eval_and_string_execution = false,
    }, &grants);
    defer std.testing.allocator.free(flags);
    try std.testing.expectEqual(@as(usize, 2), flags.len);
    try std.testing.expectEqualStrings("--permission", flags[0]);
    try std.testing.expectEqualStrings("--allow-fs-read=*", flags[1]);
}

test "collectFlags experimental permission on node 20" {
    const flags = try collectFlags(std.testing.allocator, "20.19.0", .{
        .enforce_permission_model = true,
        .enforce_permission_model_machine_policy = true,
        .freeze_v8_global_objects = false,
        .disable_eval_and_string_execution = false,
    }, &.{});
    defer std.testing.allocator.free(flags);
    try std.testing.expectEqualStrings("--experimental-permission", flags[0]);
}

test "collectFlags skips permission on node 18" {
    const flags = try collectFlags(std.testing.allocator, "18.20.0", .{
        .enforce_permission_model = true,
        .enforce_permission_model_machine_policy = true,
        .freeze_v8_global_objects = true,
        .disable_eval_and_string_execution = true,
    }, &.{});
    defer std.testing.allocator.free(flags);
    try std.testing.expectEqual(@as(usize, 2), flags.len);
    try std.testing.expectEqualStrings("--frozen-intrinsics", flags[0]);
    try std.testing.expectEqualStrings("--disallow-code-generation-from-strings", flags[1]);
}

test "mergeOptions skips write when unchanged" {
    const flags = [_][]const u8{"--permission"};
    const merged = try mergeOptions(std.testing.allocator, "--permission", &flags, false);
    try std.testing.expect(merged == null);
}

test "mergeOptions prepends missing flags and keeps user tokens" {
    const flags = [_][]const u8{ "--permission", "--allow-fs-read=*" };
    const merged = try mergeOptions(std.testing.allocator, "--inspect", &flags, false);
    defer std.testing.allocator.free(merged.?);
    try std.testing.expectEqualStrings("--inspect --permission --allow-fs-read=*", merged.?);
}

test "mergeOptions strips audit when machine policy" {
    const flags = [_][]const u8{"--permission"};
    const merged = try mergeOptions(std.testing.allocator, "--permission-audit --inspect", &flags, true);
    defer std.testing.allocator.free(merged.?);
    try std.testing.expectEqualStrings("--inspect --permission", merged.?);
}

test "mergeOptions keeps audit on preference path" {
    const flags = [_][]const u8{"--permission"};
    const merged = try mergeOptions(std.testing.allocator, "--permission-audit", &flags, false);
    defer std.testing.allocator.free(merged.?);
    try std.testing.expectEqualStrings("--permission-audit --permission", merged.?);
}

test "mergeOptions does not duplicate permission enable flag" {
    const flags = [_][]const u8{"--permission"};
    const merged = try mergeOptions(std.testing.allocator, "--experimental-permission --inspect", &flags, false);
    try std.testing.expect(merged == null);
}

test "applyToEnv no-op without policy" {
    var env = std.process.EnvMap.init(std.testing.allocator);
    defer env.deinit();
    try applyToEnv(std.testing.allocator, &env, "npm", "24.0.0", .{
        .enforce_permission_model = false,
        .enforce_permission_model_machine_policy = false,
        .freeze_v8_global_objects = false,
        .disable_eval_and_string_execution = false,
    }, &.{});
    try std.testing.expect(env.get(env_name) == null);
}

test "applyToEnv no-op for yarn" {
    var env = std.process.EnvMap.init(std.testing.allocator);
    defer env.deinit();
    try applyToEnv(std.testing.allocator, &env, "yarn", "24.0.0", .{
        .enforce_permission_model = true,
        .enforce_permission_model_machine_policy = true,
        .freeze_v8_global_objects = true,
        .disable_eval_and_string_execution = true,
    }, &.{});
    try std.testing.expect(env.get(env_name) == null);
}

test "applyToEnv sets npm_config_node_options for npm" {
    var env = std.process.EnvMap.init(std.testing.allocator);
    defer env.deinit();
    try applyToEnv(std.testing.allocator, &env, "npm", "24.0.0", .{
        .enforce_permission_model = true,
        .enforce_permission_model_machine_policy = false,
        .freeze_v8_global_objects = true,
        .disable_eval_and_string_execution = false,
    }, &.{});
    try std.testing.expectEqualStrings("--permission --frozen-intrinsics", env.get(env_name).?);
}

test "applyToEnv does not set NODE_OPTIONS" {
    var env = std.process.EnvMap.init(std.testing.allocator);
    defer env.deinit();
    try env.put("NODE_OPTIONS", "--inspect");
    try applyToEnv(std.testing.allocator, &env, "pnpm", "22.0.0", .{
        .enforce_permission_model = true,
        .enforce_permission_model_machine_policy = false,
        .freeze_v8_global_objects = false,
        .disable_eval_and_string_execution = false,
    }, &.{});
    try std.testing.expectEqualStrings("--experimental-permission", env.get(env_name).?);
    try std.testing.expectEqualStrings("--inspect", env.get("NODE_OPTIONS").?);
}

test "applyToEnv merges existing npm_config_node_options" {
    var env = std.process.EnvMap.init(std.testing.allocator);
    defer env.deinit();
    try env.put(env_name, "--inspect");
    try applyToEnv(std.testing.allocator, &env, "npx", "24.0.0", .{
        .enforce_permission_model = true,
        .enforce_permission_model_machine_policy = true,
        .freeze_v8_global_objects = false,
        .disable_eval_and_string_execution = false,
    }, &.{"--allow-fs-read=*"});
    try std.testing.expectEqualStrings("--inspect --permission --allow-fs-read=*", env.get(env_name).?);
}
