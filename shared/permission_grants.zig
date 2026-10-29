const std = @import("std");

pub const Filtered = struct {
    forwarded: []const []const u8,
    owns_forwarded: bool,
    dropped: []const []const u8,
    defaults: []const []const u8,

    pub fn deinit(self: Filtered, allocator: std.mem.Allocator) void {
        if (self.owns_forwarded) allocator.free(self.forwarded);
        allocator.free(self.dropped);
        allocator.free(self.defaults);
    }
};

pub fn isAllowFlag(arg: []const u8) bool {
    return std.mem.startsWith(u8, arg, "--allow-");
}

/// Node.js 25.8+ report-only permission model. NVM never injects this flag.
pub fn isPermissionAuditFlag(arg: []const u8) bool {
    return std.mem.eql(u8, arg, "--permission-audit") or
        std.mem.startsWith(u8, arg, "--permission-audit=");
}

pub const Stripped = struct {
    args: []const []const u8,
    owns: bool,

    pub fn deinit(self: Stripped, allocator: std.mem.Allocator) void {
        if (self.owns) allocator.free(self.args);
    }
};

fn isAsciiWhitespace(ch: u8) bool {
    return ch == ' ' or ch == '\t' or ch == '\r' or ch == '\n';
}

fn tokenizeOptions(allocator: std.mem.Allocator, raw: []const u8) ![][]const u8 {
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

/// Returns null when `raw` has no `--permission-audit` tokens.
/// Empty string means every token was audit (caller should unset the env var).
pub fn stripPermissionAuditFromOptions(allocator: std.mem.Allocator, raw: []const u8) !?[]u8 {
    const tokens = try tokenizeOptions(allocator, raw);
    defer allocator.free(tokens);

    var found = false;
    var kept = std.ArrayListUnmanaged([]const u8){};
    defer kept.deinit(allocator);
    for (tokens) |token| {
        if (isPermissionAuditFlag(token)) {
            found = true;
            continue;
        }
        try kept.append(allocator, token);
    }
    if (!found) return null;
    if (kept.items.len == 0) return try allocator.dupe(u8, "");

    var total: usize = 0;
    for (kept.items, 0..) |token, i| {
        total += token.len;
        if (i != 0) total += 1;
    }
    var out = try allocator.alloc(u8, total);
    var offset: usize = 0;
    for (kept.items, 0..) |token, i| {
        if (i != 0) {
            out[offset] = ' ';
            offset += 1;
        }
        @memcpy(out[offset..][0..token.len], token);
        offset += token.len;
    }
    return out;
}

fn stripEnvOptionsKey(allocator: std.mem.Allocator, env: *std.process.EnvMap, key: []const u8) !void {
    const raw = env.get(key) orelse return;
    const copy = try allocator.dupe(u8, raw);
    defer allocator.free(copy);
    const stripped = (try stripPermissionAuditFromOptions(allocator, copy)) orelse return;
    defer allocator.free(stripped);
    if (stripped.len == 0) {
        env.remove(key);
        return;
    }
    try env.put(key, stripped);
}

/// HKLM Policies `EnforcePermissionModel`: drop `--permission-audit` from
/// `NODE_OPTIONS` and `npm_config_node_options` so users cannot opt out of enforce.
pub fn stripPermissionAuditFromEnvMap(allocator: std.mem.Allocator, env: *std.process.EnvMap) !void {
    try stripEnvOptionsKey(allocator, env, "NODE_OPTIONS");
    try stripEnvOptionsKey(allocator, env, "npm_config_node_options");
}

/// Drop caller `--permission-audit` when HKLM Policies forces EnforcePermissionModel.
pub fn stripPermissionAuditFlags(allocator: std.mem.Allocator, forwarded: []const []const u8) !Stripped {
    var found = false;
    for (forwarded) |arg| {
        if (isPermissionAuditFlag(arg)) {
            found = true;
            break;
        }
    }
    if (!found) return .{ .args = forwarded, .owns = false };

    var kept = std.ArrayListUnmanaged([]const u8){};
    errdefer kept.deinit(allocator);
    for (forwarded) |arg| {
        if (isPermissionAuditFlag(arg)) continue;
        try kept.append(allocator, arg);
    }
    return .{ .args = try kept.toOwnedSlice(allocator), .owns = true };
}

pub fn isCallerGrant(arg: []const u8) bool {
    return isAllowFlag(arg) or
        std.mem.eql(u8, arg, "--permission") or
        std.mem.eql(u8, arg, "--experimental-permission") or
        std.mem.eql(u8, arg, "--permission-audit") or
        std.mem.startsWith(u8, arg, "--permission=") or
        std.mem.startsWith(u8, arg, "--experimental-permission=");
}

fn listed(allow: []const []const u8, arg: []const u8) bool {
    for (allow) |item| {
        if (std.mem.eql(u8, std.mem.trim(u8, item, " \t\r\n"), arg)) return true;
    }
    return false;
}

fn hasExact(args: []const []const u8, flag: []const u8) bool {
    for (args) |arg| {
        if (std.mem.eql(u8, arg, flag)) return true;
    }
    return false;
}

fn isSeparateValue(arg: []const u8) bool {
    return arg.len > 0 and arg[0] != '-';
}

/// An empty allow list leaves caller arguments unchanged.
/// Default grants are appended by the caller after the permission flag. Entries the caller already passed are omitted.
pub fn apply(allocator: std.mem.Allocator, forwarded: []const []const u8, allow: []const []const u8, defaults: []const []const u8) !Filtered {
    var dropped = std.ArrayListUnmanaged([]const u8){};
    errdefer dropped.deinit(allocator);
    var kept = std.ArrayListUnmanaged([]const u8){};
    errdefer kept.deinit(allocator);

    const filtering = allow.len != 0;
    var i: usize = 0;
    while (i < forwarded.len) : (i += 1) {
        const arg = forwarded[i];
        if (filtering and isAllowFlag(arg) and !listed(allow, arg)) {
            try dropped.append(allocator, arg);
            if (std.mem.indexOfScalar(u8, arg, '=') == null and i + 1 < forwarded.len and isSeparateValue(forwarded[i + 1])) {
                i += 1;
                try dropped.append(allocator, forwarded[i]);
            }
            continue;
        }
        try kept.append(allocator, arg);
    }

    const kept_slice = if (filtering) try kept.toOwnedSlice(allocator) else blk: {
        kept.deinit(allocator);
        break :blk forwarded;
    };
    errdefer if (filtering) allocator.free(kept_slice);

    var added = std.ArrayListUnmanaged([]const u8){};
    errdefer added.deinit(allocator);
    for (defaults) |raw| {
        const item = std.mem.trim(u8, raw, " \t\r\n");
        if (item.len == 0) continue;
        if (isPermissionAuditFlag(item)) continue;
        if (hasExact(kept_slice, item) or hasExact(added.items, item)) continue;
        try added.append(allocator, item);
    }

    return .{
        .forwarded = kept_slice,
        .owns_forwarded = filtering,
        .dropped = try dropped.toOwnedSlice(allocator),
        .defaults = try added.toOwnedSlice(allocator),
    };
}

pub fn joinCallerGrants(allocator: std.mem.Allocator, forwarded: []const []const u8) ![]u8 {
    var parts = std.ArrayListUnmanaged([]const u8){};
    defer parts.deinit(allocator);
    var i: usize = 0;
    while (i < forwarded.len) : (i += 1) {
        const arg = forwarded[i];
        if (!isCallerGrant(arg)) continue;
        try parts.append(allocator, arg);
        if (isAllowFlag(arg) and std.mem.indexOfScalar(u8, arg, '=') == null and i + 1 < forwarded.len and isSeparateValue(forwarded[i + 1])) {
            i += 1;
            try parts.append(allocator, forwarded[i]);
        }
    }
    if (parts.items.len == 0) return allocator.dupe(u8, "");
    return std.mem.join(allocator, " ", parts.items);
}

test "empty allow list keeps caller grants" {
    const filtered = try apply(std.testing.allocator, &.{ "--allow-fs-read=*", "app.js" }, &.{}, &.{ "--allow-fs-read=*" });
    defer filtered.deinit(std.testing.allocator);
    try std.testing.expect(!filtered.owns_forwarded);
    try std.testing.expectEqual(@as(usize, 2), filtered.forwarded.len);
    try std.testing.expectEqualStrings("--allow-fs-read=*", filtered.forwarded[0]);
    try std.testing.expectEqual(@as(usize, 0), filtered.dropped.len);
    try std.testing.expectEqual(@as(usize, 0), filtered.defaults.len);
}

test "allow list drops unknown grants and the split value" {
    const allow = [_][]const u8{"--allow-fs-read=*"};
    const filtered = try apply(std.testing.allocator, &.{ "--allow-fs-read=*", "--allow-fs-write", "*", "app.js" }, &allow, &.{});
    defer filtered.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 2), filtered.forwarded.len);
    try std.testing.expectEqualStrings("--allow-fs-read=*", filtered.forwarded[0]);
    try std.testing.expectEqualStrings("app.js", filtered.forwarded[1]);
    try std.testing.expectEqual(@as(usize, 2), filtered.dropped.len);
    try std.testing.expectEqualStrings("--allow-fs-write", filtered.dropped[0]);
    try std.testing.expectEqualStrings("*", filtered.dropped[1]);
}

test "default grants skip flags the caller already passed" {
    const defaults = [_][]const u8{ "--allow-fs-read=*", "--allow-child-process", "  " };
    const filtered = try apply(std.testing.allocator, &.{ "--allow-fs-read=*", "app.js" }, &.{}, &defaults);
    defer filtered.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 1), filtered.defaults.len);
    try std.testing.expectEqualStrings("--allow-child-process", filtered.defaults[0]);
}

test "joinCallerGrants names permission and allow flags" {
    const text = try joinCallerGrants(std.testing.allocator, &.{ "app.js", "--permission", "--allow-fs-read", "*" });
    defer std.testing.allocator.free(text);
    try std.testing.expectEqualStrings("--permission --allow-fs-read *", text);
}

test "joinCallerGrants is empty when the caller passed no grants" {
    const text = try joinCallerGrants(std.testing.allocator, &.{"app.js"});
    defer std.testing.allocator.free(text);
    try std.testing.expectEqualStrings("", text);
}

test "stripPermissionAuditFlags drops audit tokens and keeps the rest" {
    const stripped = try stripPermissionAuditFlags(
        std.testing.allocator,
        &.{ "--permission-audit", "app.js", "--permission-audit=fs", "--allow-fs-read=*" },
    );
    defer stripped.deinit(std.testing.allocator);
    try std.testing.expect(stripped.owns);
    try std.testing.expectEqual(@as(usize, 2), stripped.args.len);
    try std.testing.expectEqualStrings("app.js", stripped.args[0]);
    try std.testing.expectEqualStrings("--allow-fs-read=*", stripped.args[1]);
}

test "stripPermissionAuditFlags is a no-op when audit is absent" {
    const original = [_][]const u8{ "--permission", "app.js" };
    const stripped = try stripPermissionAuditFlags(std.testing.allocator, &original);
    defer stripped.deinit(std.testing.allocator);
    try std.testing.expect(!stripped.owns);
    try std.testing.expectEqual(@as(usize, 2), stripped.args.len);
    try std.testing.expectEqualStrings("--permission", stripped.args[0]);
}

test "stripPermissionAuditFromOptions drops audit tokens" {
    const allocator = std.testing.allocator;
    const only = (try stripPermissionAuditFromOptions(allocator, "--permission-audit")).?;
    defer allocator.free(only);
    try std.testing.expectEqualStrings("", only);

    const mixed = (try stripPermissionAuditFromOptions(allocator, "--inspect --permission-audit --trace-warnings")).?;
    defer allocator.free(mixed);
    try std.testing.expectEqualStrings("--inspect --trace-warnings", mixed);

    const equals = (try stripPermissionAuditFromOptions(allocator, "--permission-audit=fs --inspect")).?;
    defer allocator.free(equals);
    try std.testing.expectEqualStrings("--inspect", equals);

    try std.testing.expect(try stripPermissionAuditFromOptions(allocator, "--inspect") == null);
}

test "stripPermissionAuditFromEnvMap unsets audit-only NODE_OPTIONS" {
    var env = std.process.EnvMap.init(std.testing.allocator);
    defer env.deinit();
    try env.put("NODE_OPTIONS", "--permission-audit");
    try env.put("npm_config_node_options", "--inspect --permission-audit");
    try stripPermissionAuditFromEnvMap(std.testing.allocator, &env);
    try std.testing.expect(env.get("NODE_OPTIONS") == null);
    try std.testing.expectEqualStrings("--inspect", env.get("npm_config_node_options").?);
}

test "stripPermissionAuditFromEnvMap no-op without audit" {
    var env = std.process.EnvMap.init(std.testing.allocator);
    defer env.deinit();
    try env.put("NODE_OPTIONS", "--inspect");
    try stripPermissionAuditFromEnvMap(std.testing.allocator, &env);
    try std.testing.expectEqualStrings("--inspect", env.get("NODE_OPTIONS").?);
}

test "default grants skip --permission-audit" {
    const defaults = [_][]const u8{ "--allow-fs-read=*", "--permission-audit" };
    const filtered = try apply(std.testing.allocator, &.{"app.js"}, &.{}, &defaults);
    defer filtered.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 1), filtered.defaults.len);
    try std.testing.expectEqualStrings("--allow-fs-read=*", filtered.defaults[0]);
}
