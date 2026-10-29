const std = @import("std");
const windows = std.os.windows;
const config = @import("config");
const registry = @import("registry");
const resolver = @import("resolver");

const policy_path = config.policy_registry_root;
const pref_path = config.preference_registry_root;
const allow_key = "VersionAllowList";
const block_key = "VersionBlockList";

const RegistrySource = struct {
    hive: windows.HKEY,
    path: []const u8,
};

const DenyReason = struct {
    version: []const u8,
    source: []const u8,
};

pub const Decision = union(enum) {
    allow,
    deny: DenyReason,
};

fn hiveIsLocalMachine(hive: windows.HKEY) bool {
    return hive == windows.HKEY_LOCAL_MACHINE;
}

fn collectPolicyThenPrefSources(pref_hives: []const windows.HKEY, out: *[8]RegistrySource) []const RegistrySource {
    var n: usize = 0;
    out[n] = .{ .hive = windows.HKEY_LOCAL_MACHINE, .path = policy_path };
    n += 1;
    for (pref_hives) |hive| {
        if (!hiveIsLocalMachine(hive)) {
            out[n] = .{ .hive = hive, .path = policy_path };
            n += 1;
        }
        out[n] = .{ .hive = hive, .path = pref_path };
        n += 1;
    }
    return out[0..n];
}

fn isServerMagic(raw: []const u8) bool {
    return std.ascii.eqlIgnoreCase(raw, "EOL") or
        std.ascii.eqlIgnoreCase(raw, "ALPHA") or
        std.ascii.eqlIgnoreCase(raw, "MAINTENANCE");
}

fn normalizeVersion(raw: []const u8) []const u8 {
    var s = std.mem.trim(u8, raw, " \t\r\n");
    if (s.len >= 1 and (s[0] == 'v' or s[0] == 'V')) s = s[1..];
    return s;
}

fn appendSplit(allocator: std.mem.Allocator, raw: []const u8, out: *std.ArrayListUnmanaged([]const u8)) !void {
    var start: usize = 0;
    var i: usize = 0;
    while (i <= raw.len) : (i += 1) {
        const at_end = i == raw.len;
        const sep = if (at_end) true else (raw[i] == ',' or raw[i] == ';' or raw[i] == '\n' or raw[i] == '\r');
        if (!sep) continue;
        const part = std.mem.trim(u8, raw[start..i], " \t");
        if (part.len > 0) try out.append(allocator, part);
        start = i + 1;
    }
}

const ListHit = struct {
    allow: ?[]const u8 = null,
    block: ?[]const u8 = null,
};

/// First source that has either list supplies both. Missing key is empty, not a later hive.
fn firstPaired(hits: []const ListHit) ListHit {
    for (hits) |h| {
        if (h.allow != null or h.block != null) return h;
    }
    return .{};
}

const PairedLists = struct {
    allow: ?[]u8 = null,
    block: ?[]u8 = null,

    fn deinit(self: *PairedLists, allocator: std.mem.Allocator) void {
        if (self.allow) |raw| allocator.free(raw);
        if (self.block) |raw| allocator.free(raw);
        self.* = .{};
    }
};

fn loadFromSource(allocator: std.mem.Allocator, src: RegistrySource, value_name: []const u8) !?[]u8 {
    if (try registry.queryMultiStringOptional(allocator, src.hive, src.path, value_name)) |values| {
        defer {
            for (values) |v| allocator.free(v);
            allocator.free(values);
        }
        var joined = std.ArrayListUnmanaged(u8){};
        errdefer joined.deinit(allocator);
        for (values, 0..) |v, idx| {
            if (idx > 0) try joined.append(allocator, '\n');
            try joined.appendSlice(allocator, v);
        }
        return try joined.toOwnedSlice(allocator);
    }
    return registry.queryString(allocator, src.hive, src.path, value_name) catch |err| switch (err) {
        error.RegistryKeyNotFound, error.RegistryValueNotFound, error.RegistryValueWrongType => null,
        else => err,
    };
}

fn loadPairedLists(allocator: std.mem.Allocator, pref_hives: []const windows.HKEY) !PairedLists {
    var buf: [8]RegistrySource = undefined;
    for (collectPolicyThenPrefSources(pref_hives, &buf)) |src| {
        const allow = try loadFromSource(allocator, src, allow_key);
        errdefer if (allow) |raw| allocator.free(raw);
        const block = try loadFromSource(allocator, src, block_key);
        errdefer if (block) |raw| allocator.free(raw);
        if (allow != null or block != null) {
            return .{ .allow = allow, .block = block };
        }
    }
    return .{};
}

fn stripNotPrefix(raw: []const u8) struct { entry: []const u8, negated: bool } {
    var entry = std.mem.trim(u8, raw, " \t\r\n");
    var negated = false;
    if (entry.len >= 3 and std.ascii.eqlIgnoreCase(entry[0..3], "not") and
        (entry.len == 3 or entry[3] == ' ' or entry[3] == '\t'))
    {
        negated = true;
        entry = std.mem.trim(u8, entry[3..], " \t");
    }
    if (entry.len > 0 and entry[0] == '!') {
        negated = true;
        entry = std.mem.trim(u8, entry[1..], " \t");
    }
    return .{ .entry = entry, .negated = negated };
}

fn matchesEntry(allocator: std.mem.Allocator, target: []const u8, raw: []const u8) bool {
    const entry = std.mem.trim(u8, raw, " \t\r\n");
    if (entry.len == 0) return false;
    if (isServerMagic(entry)) return false;
    if (std.ascii.eqlIgnoreCase(entry, "all")) return true;
    return resolver.versionSatisfiesSpec(allocator, entry, target) catch false;
}

fn matchesAny(allocator: std.mem.Allocator, target: []const u8, entries: []const []const u8) bool {
    for (entries) |entry| {
        if (matchesEntry(allocator, target, entry)) return true;
    }
    return false;
}

/// Local version firewall. Community callers pass certified=false (always allow).
/// Magic tokens EOL/ALPHA/MAINTENANCE are ignored locally, matching Go acl.
pub fn evaluate(
    allocator: std.mem.Allocator,
    version: []const u8,
    certified: bool,
) !Decision {
    if (!certified) return .allow;

    const target = normalizeVersion(version);
    if (target.len == 0) return .allow;

    const pref_hives = registry.preferenceHives();
    var lists = try loadPairedLists(allocator, pref_hives);
    defer lists.deinit(allocator);
    return evaluateLists(allocator, target, lists.allow, lists.block);
}

fn evaluateLists(
    allocator: std.mem.Allocator,
    target: []const u8,
    allow_raw: ?[]const u8,
    block_raw: ?[]const u8,
) !Decision {
    var allow_neg = std.ArrayListUnmanaged([]const u8){};
    defer allow_neg.deinit(allocator);
    var allow_pos = std.ArrayListUnmanaged([]const u8){};
    defer allow_pos.deinit(allocator);
    var block_neg = std.ArrayListUnmanaged([]const u8){};
    defer block_neg.deinit(allocator);
    var block_pos = std.ArrayListUnmanaged([]const u8){};
    defer block_pos.deinit(allocator);
    var magic_present = false;

    if (allow_raw) |raw| {
        var parts = std.ArrayListUnmanaged([]const u8){};
        defer parts.deinit(allocator);
        try appendSplit(allocator, raw, &parts);
        for (parts.items) |part| {
            const n = stripNotPrefix(part);
            if (n.entry.len == 0) continue;
            if (isServerMagic(n.entry)) {
                magic_present = true;
                continue;
            }
            if (n.negated) {
                try allow_neg.append(allocator, n.entry);
            } else {
                try allow_pos.append(allocator, n.entry);
            }
        }
    }
    if (block_raw) |raw| {
        var parts = std.ArrayListUnmanaged([]const u8){};
        defer parts.deinit(allocator);
        try appendSplit(allocator, raw, &parts);
        for (parts.items) |part| {
            const n = stripNotPrefix(part);
            if (n.entry.len == 0) continue;
            if (isServerMagic(n.entry)) {
                magic_present = true;
                continue;
            }
            if (n.negated) {
                try block_neg.append(allocator, n.entry);
            } else {
                try block_pos.append(allocator, n.entry);
            }
        }
    }

    if (matchesAny(allocator, target, allow_neg.items)) {
        return .{ .deny = .{ .version = target, .source = "VersionAllowList" } };
    }

    const allow_configured = allow_neg.items.len + allow_pos.items.len > 0;
    if (matchesAny(allocator, target, allow_pos.items)) return .allow;

    if (matchesAny(allocator, target, block_pos.items) and !matchesAny(allocator, target, block_neg.items)) {
        return .{ .deny = .{ .version = target, .source = "VersionBlockList" } };
    }

    if (allow_configured and !magic_present) {
        return .{ .deny = .{ .version = target, .source = "VersionAllowList" } };
    }

    return .allow;
}

test "stripNotPrefix handles NOT and bang" {
    const a = stripNotPrefix("NOT 20.17.0");
    try std.testing.expect(a.negated);
    try std.testing.expectEqualStrings("20.17.0", a.entry);

    const b = stripNotPrefix("!20.x");
    try std.testing.expect(b.negated);
    try std.testing.expectEqualStrings("20.x", b.entry);

    const c = stripNotPrefix("20.x");
    try std.testing.expect(!c.negated);
    try std.testing.expectEqualStrings("20.x", c.entry);
}

test "evaluate Community never denies" {
    const decision = try evaluate(std.testing.allocator, "10.0.0", false);
    try std.testing.expect(decision == .allow);
}

test "matchesEntry understands 20.x and exact" {
    try std.testing.expect(matchesEntry(std.testing.allocator, "20.17.0", "20.x"));
    try std.testing.expect(matchesEntry(std.testing.allocator, "20.17.0", "20"));
    try std.testing.expect(!matchesEntry(std.testing.allocator, "18.19.1", "20.x"));
    try std.testing.expect(matchesEntry(std.testing.allocator, "20.17.0", "ALL"));
    try std.testing.expect(!matchesEntry(std.testing.allocator, "20.17.0", "EOL"));
}

test "firstPaired uses first source with either list" {
    const picked = firstPaired(&.{
        .{},
        .{ .block = "18.x" },
        .{ .allow = "18.x" },
    });
    try std.testing.expect(picked.allow == null);
    try std.testing.expectEqualStrings("18.x", picked.block.?);
}

test "firstPaired empty string is a hit" {
    const picked = firstPaired(&.{
        .{ .allow = "" },
        .{ .block = "18.x" },
    });
    try std.testing.expect(picked.block == null);
    try std.testing.expectEqualStrings("", picked.allow.?);
}

test "evaluateLists HKLM block not punched by later allow" {
    const picked = firstPaired(&.{
        .{ .block = "18.x" },
        .{ .allow = "18.x" },
    });
    const d = try evaluateLists(std.testing.allocator, "18.19.1", picked.allow, picked.block);
    try std.testing.expect(d == .deny);
    switch (d) {
        .deny => |r| try std.testing.expectEqualStrings("VersionBlockList", r.source),
        else => unreachable,
    }
}

test "evaluateLists same-source allow wins over block" {
    const d = try evaluateLists(std.testing.allocator, "18.19.1", "18.x", "18.x");
    try std.testing.expect(d == .allow);
}

test "evaluateLists exclusive allow denies other majors" {
    const d = try evaluateLists(std.testing.allocator, "18.19.1", "20.x", null);
    try std.testing.expect(d == .deny);
    switch (d) {
        .deny => |r| try std.testing.expectEqualStrings("VersionAllowList", r.source),
        else => unreachable,
    }
}

test "evaluateLists EOL magic ignored locally" {
    const d = try evaluateLists(std.testing.allocator, "18.19.1", "EOL", null);
    try std.testing.expect(d == .allow);
}

test "evaluateLists EOL plus allow is not exclusive" {
    const d = try evaluateLists(std.testing.allocator, "18.19.1", "20.x\nEOL", null);
    try std.testing.expect(d == .allow);
}
