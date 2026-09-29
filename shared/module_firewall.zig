const std = @import("std");
const windows = std.os.windows;
const config = @import("config");
const registry = @import("registry");

pub const reg_value_trusted_modules = "TrustedModules";
pub const reg_value_approved_modules = "ApprovedModules";
pub const reg_value_approved_global_modules = "ApprovedGlobalModules";
pub const reg_value_untrusted_handler = "UntrustedModuleHandlerAction";
pub const reg_value_firewall_skip_lockfile = "FirewallSkipLockfile";

pub const PackageSpec = struct {
    name: []const u8,
    version: []const u8,
    raw: []const u8,
};

fn trimAscii(s: []const u8) []const u8 {
    return std.mem.trim(u8, s, " \t\r\n");
}

fn eqlIgnoreCase(a: []const u8, b: []const u8) bool {
    return std.ascii.eqlIgnoreCase(a, b);
}

fn startsWithIgnoreCase(hay: []const u8, needle: []const u8) bool {
    if (hay.len < needle.len) return false;
    return eqlIgnoreCase(hay[0..needle.len], needle);
}

pub fn splitNameVersion(spec: []const u8) struct { name: []const u8, version: []const u8 } {
    const s = trimAscii(spec);
    if (s.len == 0) return .{ .name = "", .version = "" };
    if (s[0] == '@') {
        if (std.mem.indexOfScalar(u8, s[1..], '/')) |slash_rel| {
            const slash = slash_rel + 1;
            const after = s[slash + 1 ..];
            if (std.mem.indexOfScalar(u8, after, '@')) |at| {
                return .{ .name = s[0 .. slash + 1 + at], .version = after[at + 1 ..] };
            }
            return .{ .name = s, .version = "" };
        }
        return .{ .name = s, .version = "" };
    }
    if (std.mem.indexOfScalar(u8, s, '@')) |at| {
        return .{ .name = s[0..at], .version = s[at + 1 ..] };
    }
    return .{ .name = s, .version = "" };
}

fn normalizeRule(raw: []const u8) struct { entry: []const u8, negated: bool } {
    var entry = trimAscii(raw);
    var negated = false;
    if (startsWithIgnoreCase(entry, "not ") or startsWithIgnoreCase(entry, "not\t")) {
        negated = true;
        entry = trimAscii(entry[3..]);
    } else if (entry.len > 0 and entry[0] == '!') {
        negated = true;
        entry = trimAscii(entry[1..]);
    }
    return .{ .entry = entry, .negated = negated };
}

fn nameMatches(pattern: []const u8, pkg_name: []const u8) bool {
    if (eqlIgnoreCase(pattern, "all")) return true;
    if (std.mem.endsWith(u8, pattern, "/*")) {
        const org = pattern[0 .. pattern.len - 2];
        if (pkg_name.len <= org.len) return false;
        if (!eqlIgnoreCase(pkg_name[0..org.len], org)) return false;
        return pkg_name[org.len] == '/';
    }
    return eqlIgnoreCase(pattern, pkg_name);
}

fn versionMatches(pattern_ver: []const u8, pkg_ver: []const u8) bool {
    if (pattern_ver.len == 0) return true;
    if (pkg_ver.len == 0) return true;
    if (std.mem.endsWith(u8, pattern_ver, ".*")) {
        const prefix = pattern_ver[0 .. pattern_ver.len - 2];
        if (eqlIgnoreCase(pkg_ver, prefix)) return true;
        if (pkg_ver.len > prefix.len and eqlIgnoreCase(pkg_ver[0..prefix.len], prefix) and pkg_ver[prefix.len] == '.') return true;
        return false;
    }
    // Exact or prefix equality for MVP ranges like >= are handled loosely: exact match only in Zig;
    // full semver ranges evaluated in Go path / HTTPS. For common 1.0.0 pins:
    return eqlIgnoreCase(pattern_ver, pkg_ver) or startsWithIgnoreCase(pattern_ver, ">=") or startsWithIgnoreCase(pattern_ver, "^") or startsWithIgnoreCase(pattern_ver, "~");
}

fn ruleMatches(rule_entry: []const u8, pkg: PackageSpec) bool {
    if (eqlIgnoreCase(rule_entry, "all")) return true;
    const nv = splitNameVersion(rule_entry);
    if (!nameMatches(nv.name, pkg.name)) return false;
    // For range operators in Zig MVP, treat as name match (policy still useful); exact pins enforced.
    if (nv.version.len > 0 and (nv.version[0] == '>' or nv.version[0] == '^' or nv.version[0] == '~' or nv.version[0] == '<')) {
        return true;
    }
    return versionMatches(nv.version, pkg.version);
}

/// True when policy list contains an https:// URL (remote evaluation mode).
pub fn listHasHttps(rules: []const []const u8) bool {
    for (rules) |r| {
        const e = trimAscii(r);
        if (startsWithIgnoreCase(e, "https://")) return true;
    }
    return false;
}

/// First https:// URL in the list, or null.
pub fn extractHttpsUrl(rules: []const []const u8) ?[]const u8 {
    for (rules) |r| {
        const e = trimAscii(r);
        if (startsWithIgnoreCase(e, "https://")) return e;
    }
    return null;
}

/// Local-list evaluation (VersionAllowList-compatible). HTTPS URL entries are ignored
/// so TrustedModules can mix local names with a remote policy URL.
/// URL-only lists are local-deny (NOT ALL) so callers fall through to remote eval
/// instead of treating an empty leftover list as allow-all.
pub fn isPackageAllowed(pkg: PackageSpec, rules: []const []const u8) ?bool {
    var not_all = false;
    var has_exclusive = false;
    var has_local = false;
    var i: usize = 0;
    while (i < rules.len) : (i += 1) {
        const e = trimAscii(rules[i]);
        if (startsWithIgnoreCase(e, "https://")) continue;
        const norm = normalizeRule(rules[i]);
        if (norm.entry.len == 0) continue;
        has_local = true;
        if (norm.negated and eqlIgnoreCase(norm.entry, "all")) not_all = true;
        if (!norm.negated and !eqlIgnoreCase(norm.entry, "all")) has_exclusive = true;
    }

    if (!has_local and listHasHttps(rules)) return false;

    if (not_all) {
        i = 0;
        while (i < rules.len) : (i += 1) {
            const e = trimAscii(rules[i]);
            if (startsWithIgnoreCase(e, "https://")) continue;
            const norm = normalizeRule(rules[i]);
            if (norm.negated) continue;
            if (ruleMatches(norm.entry, pkg)) return true;
        }
        return false;
    }

    i = 0;
    while (i < rules.len) : (i += 1) {
        const e = trimAscii(rules[i]);
        if (startsWithIgnoreCase(e, "https://")) continue;
        const norm = normalizeRule(rules[i]);
        if (!norm.negated) continue;
        if (ruleMatches(norm.entry, pkg)) return false;
    }
    i = 0;
    while (i < rules.len) : (i += 1) {
        const e = trimAscii(rules[i]);
        if (startsWithIgnoreCase(e, "https://")) continue;
        const norm = normalizeRule(rules[i]);
        if (norm.negated) continue;
        if (ruleMatches(norm.entry, pkg)) return true;
    }
    if (has_exclusive) return false;
    return true;
}

fn pathHasPrefixIgnoreCase(path: []const u8, prefix: []const u8) bool {
    if (prefix.len == 0 or path.len < prefix.len) return false;
    if (!std.ascii.eqlIgnoreCase(path[0..prefix.len], prefix)) return false;
    return path.len == prefix.len or path[prefix.len] == '\\' or path[prefix.len] == '/';
}

pub fn isPackageManagerStem(stem: []const u8) bool {
    const names = [_][]const u8{ "npm", "npx", "pnpm", "yarn", "yarnpkg", "corepack", "vlt", "node" };
    for (names) |n| {
        if (std.ascii.eqlIgnoreCase(stem, n)) return true;
    }
    return false;
}

/// True when image is a global-module shim (in .shim) other than node/npm/etc.
pub fn isNonPmShimImage(image_path: []const u8, shim_dir: []const u8) bool {
    if (!pathHasPrefixIgnoreCase(image_path, shim_dir)) return false;
    const stem = std.fs.path.stem(image_path);
    return !isPackageManagerStem(stem);
}

/// True when a non-PM global shim appears in the ancestor list (nested self-update via npm).
pub fn nestedUnderNonPmShim(ancestor_images: []const []const u8, shim_dir: []const u8) bool {
    for (ancestor_images) |image| {
        if (isNonPmShimImage(image, shim_dir)) return true;
    }
    return false;
}

pub fn loadMultiSzPolicy(allocator: std.mem.Allocator, value_name: []const u8) ![]const []const u8 {
    const policy_hives = [_]windows.HKEY{
        windows.HKEY_LOCAL_MACHINE,
        windows.HKEY_CURRENT_USER,
    };
    if (registry.queryMultiStringOptionalWithFallback(allocator, &policy_hives, config.policy_registry_root, value_name) catch null) |vals| {
        return vals;
    }
    if (registry.queryMultiStringOptionalWithFallback(allocator, registry.preferenceHives(), config.preference_registry_root, value_name) catch null) |vals| {
        return vals;
    }
    return &[_][]const u8{};
}

pub fn freeMultiSz(allocator: std.mem.Allocator, vals: []const []const u8) void {
    if (vals.len == 0) return;
    for (vals) |v| allocator.free(v);
    allocator.free(vals);
}

pub fn loadFirewallSkipLockfile(allocator: std.mem.Allocator) bool {
    _ = allocator;
    const policy_hives = [_]windows.HKEY{
        windows.HKEY_LOCAL_MACHINE,
        windows.HKEY_CURRENT_USER,
    };
    if (registry.queryDwordOptionalWithFallback(&policy_hives, config.policy_registry_root, reg_value_firewall_skip_lockfile) catch null) |value| {
        return value != 0;
    }
    if (registry.queryDwordOptionalWithFallback(registry.preferenceHives(), config.preference_registry_root, reg_value_firewall_skip_lockfile) catch null) |value| {
        return value != 0;
    }
    return false;
}

fn skipCliFlag(arg: []const u8) bool {
    return arg.len >= 1 and arg[0] == '-';
}

fn appendOwnedSpec(allocator: std.mem.Allocator, list: *std.ArrayListUnmanaged(PackageSpec), name: []const u8, version: []const u8) !void {
    const owned_name = try allocator.dupe(u8, name);
    errdefer allocator.free(owned_name);
    const owned_ver = try allocator.dupe(u8, version);
    errdefer allocator.free(owned_ver);
    const raw = if (version.len > 0)
        try std.fmt.allocPrint(allocator, "{s}@{s}", .{ name, version })
    else
        try allocator.dupe(u8, name);
    errdefer allocator.free(raw);
    try list.append(allocator, .{ .name = owned_name, .version = owned_ver, .raw = raw });
}

pub fn freePackageSpecs(allocator: std.mem.Allocator, pkgs: []const PackageSpec) void {
    for (pkgs) |pkg| {
        allocator.free(pkg.name);
        allocator.free(pkg.version);
        allocator.free(pkg.raw);
    }
    allocator.free(pkgs);
}

/// Walk from start_dir toward drive root; return owned path to nearest package.json.
pub fn findNearestPackageJson(allocator: std.mem.Allocator, start_dir: []const u8) !?[]u8 {
    var dir = try allocator.dupe(u8, start_dir);
    defer allocator.free(dir);
    while (true) {
        const candidate = try std.fs.path.join(allocator, &.{ dir, "package.json" });
        defer allocator.free(candidate);
        if (std.fs.openFileAbsolute(candidate, .{})) |file| {
            file.close();
            return try allocator.dupe(u8, candidate);
        } else |_| {}
        const parent = std.fs.path.dirname(dir) orelse return null;
        if (parent.len == dir.len or std.mem.eql(u8, parent, dir)) return null;
        const next = try allocator.dupe(u8, parent);
        allocator.free(dir);
        dir = next;
    }
}

fn depSectionNames(include_dev: bool) []const []const u8 {
    if (include_dev) return &[_][]const u8{ "dependencies", "optionalDependencies", "devDependencies" };
    return &[_][]const u8{ "dependencies", "optionalDependencies" };
}

/// Collect direct deps from package.json content; skip non-string values.
pub fn parsePackageJsonDirectDeps(allocator: std.mem.Allocator, content: []const u8, include_dev: bool) ![]PackageSpec {
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, content, .{});
    defer parsed.deinit();
    const root = switch (parsed.value) {
        .object => |o| o,
        else => return try allocator.alloc(PackageSpec, 0),
    };

    var list = std.ArrayListUnmanaged(PackageSpec){};
    errdefer {
        for (list.items) |pkg| {
            allocator.free(pkg.name);
            allocator.free(pkg.version);
            allocator.free(pkg.raw);
        }
        list.deinit(allocator);
    }
    var seen = std.StringHashMap(void).init(allocator);
    defer seen.deinit();

    for (depSectionNames(include_dev)) |sec| {
        const sec_val = root.get(sec) orelse continue;
        const deps = switch (sec_val) {
            .object => |o| o,
            else => continue,
        };
        var it = deps.iterator();
        while (it.next()) |entry| {
            const name = trimAscii(entry.key_ptr.*);
            if (name.len == 0) continue;
            const ver_val = entry.value_ptr.*;
            const ver = switch (ver_val) {
                .string => |s| trimAscii(s),
                else => continue,
            };
            const key = try std.ascii.allocLowerString(allocator, name);
            defer allocator.free(key);
            if (seen.contains(key)) continue;
            try seen.put(key, {});
            try appendOwnedSpec(allocator, &list, name, ver);
        }
    }
    return try list.toOwnedSlice(allocator);
}

/// True when install should omit devDependencies (npm --production / --omit=dev).
pub fn productionOmit(args: []const []const u8) bool {
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = trimAscii(args[i]);
        if (eqlIgnoreCase(a, "--production") or eqlIgnoreCase(a, "-p") or eqlIgnoreCase(a, "--only=production")) {
            return true;
        }
        if (startsWithIgnoreCase(a, "--omit=")) {
            const omit = trimAscii(a[7..]);
            var parts = std.mem.splitScalar(u8, omit, ',');
            while (parts.next()) |part| {
                if (eqlIgnoreCase(trimAscii(part), "dev")) return true;
            }
        }
        if (eqlIgnoreCase(a, "--omit") and i + 1 < args.len) {
            const next = trimAscii(args[i + 1]);
            if (eqlIgnoreCase(next, "dev")) return true;
            var parts = std.mem.splitScalar(u8, next, ',');
            while (parts.next()) |part| {
                if (eqlIgnoreCase(trimAscii(part), "dev")) return true;
            }
        }
    }
    return false;
}

fn manifestExpandable(command_name: []const u8, args: []const []const u8) bool {
    if (eqlIgnoreCase(command_name, "npx")) return false;
    if (eqlIgnoreCase(command_name, "npm")) {
        if (args.len == 0) return false;
        const sub = args[0];
        if (eqlIgnoreCase(sub, "install") or eqlIgnoreCase(sub, "i") or eqlIgnoreCase(sub, "add") or
            eqlIgnoreCase(sub, "ci"))
            return true;
        if (eqlIgnoreCase(sub, "exec")) return false;
        return false;
    }
    if (eqlIgnoreCase(command_name, "pnpm") or eqlIgnoreCase(command_name, "vlt")) {
        if (args.len == 0) return false;
        const sub = args[0];
        return eqlIgnoreCase(sub, "install") or eqlIgnoreCase(sub, "i") or eqlIgnoreCase(sub, "add") or
            eqlIgnoreCase(sub, "ci");
    }
    if (eqlIgnoreCase(command_name, "yarn")) {
        if (args.len == 0) return true;
        const sub = args[0];
        if (eqlIgnoreCase(sub, "install") or eqlIgnoreCase(sub, "add") or eqlIgnoreCase(sub, "ci")) return true;
        if (eqlIgnoreCase(sub, "global") or eqlIgnoreCase(sub, "dlx") or eqlIgnoreCase(sub, "create")) return false;
        return false;
    }
    return false;
}

/// Package positional tokens from install-like argv (owned PackageSpec slices).
pub fn collectPackageTokensFromArgs(allocator: std.mem.Allocator, command_name: []const u8, args: []const []const u8) ![]PackageSpec {
    var list = std.ArrayListUnmanaged(PackageSpec){};
    errdefer {
        for (list.items) |pkg| {
            allocator.free(pkg.name);
            allocator.free(pkg.version);
            allocator.free(pkg.raw);
        }
        list.deinit(allocator);
    }
    var i: usize = 0;
    if (eqlIgnoreCase(command_name, "npx")) {
        // all positionals
    } else if (args.len > 0) {
        i = 1;
        if (eqlIgnoreCase(command_name, "yarn") and eqlIgnoreCase(args[0], "global") and args.len > 1) {
            i = 2;
        }
    }
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (skipCliFlag(arg)) continue;
        const nv = splitNameVersion(arg);
        try appendOwnedSpec(allocator, &list, nv.name, nv.version);
    }
    return try list.toOwnedSlice(allocator);
}

fn lockPackageNameFromKey(key: []const u8) []const u8 {
    var k = key;
    const prefix = "node_modules/";
    while (true) {
        var last: ?usize = null;
        var i: usize = 0;
        while (i + prefix.len <= k.len) {
            var matches = true;
            for (prefix, 0..) |ch, j| {
                const c = k[i + j];
                if (c == ch or (ch == '/' and c == '\\')) continue;
                matches = false;
                break;
            }
            if (matches) last = i;
            i += 1;
        }
        if (last) |idx| {
            k = k[idx + prefix.len ..];
        } else break;
    }
    return trimAscii(std.mem.trim(u8, k, "/\\"));
}

fn parseLockPackagesFromContent(allocator: std.mem.Allocator, content: []const u8) ![]PackageSpec {
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, content, .{});
    defer parsed.deinit();
    const root = switch (parsed.value) {
        .object => |o| o,
        else => return error.InvalidLockfile,
    };

    var list = std.ArrayListUnmanaged(PackageSpec){};
    errdefer {
        for (list.items) |pkg| {
            allocator.free(pkg.name);
            allocator.free(pkg.version);
            allocator.free(pkg.raw);
        }
        list.deinit(allocator);
    }
    var seen = std.StringHashMap(void).init(allocator);
    defer seen.deinit();

    const add_pkg = struct {
        fn call(
            alloc: std.mem.Allocator,
            lst: *std.ArrayListUnmanaged(PackageSpec),
            seen_map: *std.StringHashMap(void),
            name: []const u8,
            version: []const u8,
        ) !void {
            const n = trimAscii(name);
            if (n.len == 0) return;
            const key = try std.ascii.allocLowerString(alloc, n);
            defer alloc.free(key);
            if (seen_map.contains(key)) return;
            try seen_map.put(key, {});
            try appendOwnedSpec(alloc, lst, n, trimAscii(version));
        }
    }.call;

    if (root.get("packages")) |packages_val| {
        const packages = switch (packages_val) {
            .object => |o| o,
            else => return error.InvalidLockfile,
        };
        var it = packages.iterator();
        while (it.next()) |entry| {
            const key = entry.key_ptr.*;
            if (key.len == 0) continue;
            const meta = switch (entry.value_ptr.*) {
                .object => |o| o,
                else => continue,
            };
            var name: []const u8 = "";
            if (meta.get("name")) |name_val| {
                if (name_val == .string) name = name_val.string;
            }
            if (name.len == 0) name = lockPackageNameFromKey(key);
            var version: []const u8 = "";
            if (meta.get("version")) |ver_val| {
                if (ver_val == .string) version = ver_val.string;
            }
            try add_pkg(allocator, &list, &seen, name, version);
        }
        if (list.items.len > 0) return try list.toOwnedSlice(allocator);
    }

    if (root.get("dependencies")) |deps_val| {
        const deps = switch (deps_val) {
            .object => |o| o,
            else => return error.InvalidLockfile,
        };
        var it = deps.iterator();
        while (it.next()) |entry| {
            var version: []const u8 = "";
            if (entry.value_ptr.* == .object) {
                const meta = entry.value_ptr.object;
                if (meta.get("version")) |ver_val| {
                    if (ver_val == .string) version = ver_val.string;
                }
            }
            try add_pkg(allocator, &list, &seen, entry.key_ptr.*, version);
        }
    }

    if (list.items.len == 0) return error.InvalidLockfile;
    return try list.toOwnedSlice(allocator);
}

fn countLeadingSpaces(line: []const u8) usize {
    var n: usize = 0;
    for (line) |c| {
        if (c == ' ') {
            n += 1;
        } else if (c == '\t') {
            n += 2;
        } else break;
    }
    return n;
}

fn splitPnpmLockKey(key_in: []const u8) struct { name: []const u8, version: []const u8 } {
    var key = trimAscii(key_in);
    if (std.mem.startsWith(u8, key, "/")) key = key[1..];
    if (std.mem.indexOfScalar(u8, key, '(')) |paren| {
        key = key[0..paren];
    }
    if (key.len > 0 and key[0] == '@') {
        if (std.mem.indexOfScalar(u8, key[1..], '/')) |slash_rel| {
            const slash = slash_rel + 1;
            const rest = key[slash + 1 ..];
            if (std.mem.lastIndexOfScalar(u8, rest, '@')) |at| {
                return .{ .name = key[0 .. slash + 1 + at], .version = rest[at + 1 ..] };
            }
            return .{ .name = key, .version = "" };
        }
        return .{ .name = key, .version = "" };
    }
    if (std.mem.lastIndexOfScalar(u8, key, '@')) |at| {
        if (at > 0) return .{ .name = key[0..at], .version = key[at + 1 ..] };
    }
    return .{ .name = key, .version = "" };
}

fn parsePnpmLockContent(allocator: std.mem.Allocator, content: []const u8) ![]PackageSpec {
    var list = std.ArrayListUnmanaged(PackageSpec){};
    errdefer {
        for (list.items) |pkg| {
            allocator.free(pkg.name);
            allocator.free(pkg.version);
            allocator.free(pkg.raw);
        }
        list.deinit(allocator);
    }
    var seen = std.StringHashMap(void).init(allocator);
    defer seen.deinit();
    var in_packages = false;
    var it = std.mem.splitScalar(u8, content, '\n');
    while (it.next()) |raw_line| {
        const line = std.mem.trimRight(u8, raw_line, "\r");
        const trimmed = trimAscii(line);
        if (trimmed.len == 0 or trimmed[0] == '#') continue;
        const indent = countLeadingSpaces(line);
        if (indent == 0 and std.mem.endsWith(u8, trimmed, ":")) {
            const key = trimmed[0 .. trimmed.len - 1];
            in_packages = std.mem.eql(u8, key, "packages") or std.mem.eql(u8, key, "snapshots");
            continue;
        }
        if (!in_packages or indent != 2 or !std.mem.endsWith(u8, trimmed, ":")) continue;
        var key = trimmed[0 .. trimmed.len - 1];
        key = std.mem.trim(u8, key, "\"'");
        const nv = splitPnpmLockKey(key);
        if (nv.name.len == 0) continue;
        const lkey = try std.ascii.allocLowerString(allocator, nv.name);
        defer allocator.free(lkey);
        if (seen.contains(lkey)) continue;
        try seen.put(lkey, {});
        try appendOwnedSpec(allocator, &list, nv.name, nv.version);
    }
    if (list.items.len == 0) return error.InvalidLockfile;
    return try list.toOwnedSlice(allocator);
}

fn yarnNameFromDescriptor(desc_in: []const u8) []const u8 {
    var desc = trimAscii(desc_in);
    desc = std.mem.trim(u8, desc, "\"'");
    if (desc.len == 0) return "";
    if (std.mem.indexOf(u8, desc, "@npm:")) |at| {
        if (at > 0) return desc[0..at];
    }
    if (std.mem.indexOf(u8, desc, "@workspace:")) |at| {
        if (at > 0) return desc[0..at];
    }
    if (desc[0] == '@') {
        if (std.mem.indexOfScalar(u8, desc[1..], '/')) |slash_rel| {
            const slash = slash_rel + 1;
            const rest = desc[slash + 1 ..];
            if (std.mem.indexOfScalar(u8, rest, '@')) |at| {
                return desc[0 .. slash + 1 + at];
            }
            return desc;
        }
        return desc;
    }
    if (std.mem.indexOfScalar(u8, desc, '@')) |at| {
        if (at > 0) return desc[0..at];
    }
    return desc;
}

fn parseYarnLockContent(allocator: std.mem.Allocator, content: []const u8) ![]PackageSpec {
    var list = std.ArrayListUnmanaged(PackageSpec){};
    errdefer {
        for (list.items) |pkg| {
            allocator.free(pkg.name);
            allocator.free(pkg.version);
            allocator.free(pkg.raw);
        }
        list.deinit(allocator);
    }
    var seen = std.StringHashMap(void).init(allocator);
    defer seen.deinit();
    var pending = std.ArrayListUnmanaged([]const u8){};
    defer {
        for (pending.items) |n| allocator.free(n);
        pending.deinit(allocator);
    }
    var it = std.mem.splitScalar(u8, content, '\n');
    while (it.next()) |raw_line| {
        const line = std.mem.trimRight(u8, raw_line, "\r");
        const trimmed = trimAscii(line);
        if (trimmed.len == 0 or trimmed[0] == '#') continue;
        const indent = countLeadingSpaces(line);
        if (indent == 0 and std.mem.endsWith(u8, trimmed, ":")) {
            for (pending.items) |n| allocator.free(n);
            pending.clearRetainingCapacity();
            const header = trimmed[0 .. trimmed.len - 1];
            var parts = std.mem.splitScalar(u8, header, ',');
            while (parts.next()) |part| {
                const name = yarnNameFromDescriptor(part);
                if (name.len == 0) continue;
                const owned = try allocator.dupe(u8, name);
                errdefer allocator.free(owned);
                const lkey = try std.ascii.allocLowerString(allocator, name);
                defer allocator.free(lkey);
                var dup = false;
                for (pending.items) |existing| {
                    if (eqlIgnoreCase(existing, name)) {
                        dup = true;
                        break;
                    }
                }
                if (dup) {
                    allocator.free(owned);
                    continue;
                }
                try pending.append(allocator, owned);
            }
            continue;
        }
        if (pending.items.len == 0) continue;
        const lower_ok = std.ascii.startsWithIgnoreCase(trimmed, "version ") or std.ascii.startsWithIgnoreCase(trimmed, "version:");
        if (!lower_ok) continue;
        var ver = trimmed["version".len..];
        if (ver.len > 0 and ver[0] == ':') ver = ver[1..];
        ver = trimAscii(ver);
        ver = std.mem.trim(u8, ver, "\"'");
        for (pending.items) |name| {
            const lkey = try std.ascii.allocLowerString(allocator, name);
            defer allocator.free(lkey);
            if (seen.contains(lkey)) continue;
            try seen.put(lkey, {});
            try appendOwnedSpec(allocator, &list, name, ver);
        }
        for (pending.items) |n| allocator.free(n);
        pending.clearRetainingCapacity();
    }
    if (list.items.len == 0) return error.InvalidLockfile;
    return try list.toOwnedSlice(allocator);
}

fn loadLockPackagesBesidePackageJson(allocator: std.mem.Allocator, package_json_path: []const u8, command_name: []const u8) ![]PackageSpec {
    const dir = std.fs.path.dirname(package_json_path) orelse return error.InvalidPath;
    const lock_names = lockfileCandidates(command_name);
    for (lock_names) |lock_name| {
        const lock_path = try std.fs.path.join(allocator, &.{ dir, lock_name });
        defer allocator.free(lock_path);
        const file = std.fs.openFileAbsolute(lock_path, .{}) catch continue;
        defer file.close();
        const content = file.readToEndAlloc(allocator, 64 * 1024 * 1024) catch continue;
        defer allocator.free(content);
        if (std.ascii.eqlIgnoreCase(lock_name, "pnpm-lock.yaml")) {
            if (parsePnpmLockContent(allocator, content)) |mods| {
                if (mods.len > 0) return mods;
                freePackageSpecs(allocator, mods);
            } else |_| {}
            continue;
        }
        if (std.ascii.eqlIgnoreCase(lock_name, "yarn.lock")) {
            if (parseYarnLockContent(allocator, content)) |mods| {
                if (mods.len > 0) return mods;
                freePackageSpecs(allocator, mods);
            } else |_| {}
            continue;
        }
        if (parseLockPackagesFromContent(allocator, content)) |mods| {
            if (mods.len > 0) return mods;
            freePackageSpecs(allocator, mods);
        } else |_| {}
    }
    return error.NoLockPackages;
}

fn lockfileCandidates(command_name: []const u8) []const []const u8 {
    if (eqlIgnoreCase(command_name, "pnpm") or eqlIgnoreCase(command_name, "vlt")) {
        return &[_][]const u8{ "pnpm-lock.yaml", "package-lock.json", "npm-shrinkwrap.json" };
    }
    if (eqlIgnoreCase(command_name, "yarn") or eqlIgnoreCase(command_name, "yarnpkg")) {
        return &[_][]const u8{ "yarn.lock", "package-lock.json", "npm-shrinkwrap.json" };
    }
    return &[_][]const u8{ "package-lock.json", "npm-shrinkwrap.json" };
}

fn emptyPackageSpecs(allocator: std.mem.Allocator) ![]PackageSpec {
    return try allocator.alloc(PackageSpec, 0);
}

/// CLI package tokens, or manifest/lock expansion when install-like with no positionals.
pub fn collectInstallPackages(allocator: std.mem.Allocator, command_name: []const u8, args: []const []const u8, cwd: []const u8) ![]PackageSpec {
    const cli = try collectPackageTokensFromArgs(allocator, command_name, args);
    if (cli.len > 0) return cli;
    defer freePackageSpecs(allocator, cli);

    if (!manifestExpandable(command_name, args)) return emptyPackageSpecs(allocator);

    const pkg_path = try findNearestPackageJson(allocator, cwd) orelse return emptyPackageSpecs(allocator);
    defer allocator.free(pkg_path);

    const include_dev = !productionOmit(args);
    if (!loadFirewallSkipLockfile(allocator)) {
        if (loadLockPackagesBesidePackageJson(allocator, pkg_path, command_name)) |mods| {
            return mods;
        } else |_| {}
    }

    const file = std.fs.openFileAbsolute(pkg_path, .{}) catch return emptyPackageSpecs(allocator);
    defer file.close();
    const content = try file.readToEndAlloc(allocator, 16 * 1024 * 1024);
    defer allocator.free(content);
    return parsePackageJsonDirectDeps(allocator, content, include_dev) catch emptyPackageSpecs(allocator);
}

test "not all with exception" {
    const rules = [_][]const u8{ "NOT ALL", "porthog" };
    const ok = isPackageAllowed(.{ .name = "porthog", .version = "", .raw = "porthog" }, &rules);
    try std.testing.expect(ok != null and ok.?);
    const deny = isPackageAllowed(.{ .name = "eslint", .version = "", .raw = "eslint" }, &rules);
    try std.testing.expect(deny != null and !deny.?);
}

test "splitNameVersion scoped unscoped" {
    const scoped = splitNameVersion("@a/b@1.2.3");
    try std.testing.expectEqualStrings("@a/b", scoped.name);
    try std.testing.expectEqualStrings("1.2.3", scoped.version);
    const unscoped = splitNameVersion("a@1");
    try std.testing.expectEqualStrings("a", unscoped.name);
    try std.testing.expectEqualStrings("1", unscoped.version);
}

test "listHasHttps true false" {
    const yes = [_][]const u8{ "eslint", "https://policy.example/fw" };
    try std.testing.expect(listHasHttps(&yes));
    const no = [_][]const u8{ "eslint", "ALL" };
    try std.testing.expect(!listHasHttps(&no));
}

test "isPackageAllowed bang deny" {
    const rules = [_][]const u8{ "ALL", "!eslint" };
    const deny = isPackageAllowed(.{ .name = "eslint", .version = "", .raw = "eslint" }, &rules);
    try std.testing.expect(deny != null and !deny.?);
    const allow = isPackageAllowed(.{ .name = "lodash", .version = "", .raw = "lodash" }, &rules);
    try std.testing.expect(allow != null and allow.?);
}

test "isPackageAllowed exclusive miss" {
    const rules = [_][]const u8{"eslint"};
    const miss = isPackageAllowed(.{ .name = "lodash", .version = "", .raw = "lodash" }, &rules);
    try std.testing.expect(miss != null and !miss.?);
}

test "isPackageAllowed https ignored for local" {
    const rules = [_][]const u8{ "NOT ALL", "eslint", "https://policy.example/fw" };
    const ok = isPackageAllowed(.{ .name = "eslint", .version = "", .raw = "eslint" }, &rules);
    try std.testing.expect(ok != null and ok.?);
    const deny = isPackageAllowed(.{ .name = "lodash", .version = "", .raw = "lodash" }, &rules);
    try std.testing.expect(deny != null and !deny.?);
}

test "isPackageAllowed https-only is local deny" {
    const rules = [_][]const u8{"https://127.0.0.1:8443/module/trust"};
    const deny = isPackageAllowed(.{ .name = "opencode", .version = "", .raw = "opencode" }, &rules);
    try std.testing.expect(deny != null and !deny.?);
}

test "nestedUnderNonPmShim user npm from shell" {
    const shim = "C:\\Users\\x\\AppData\\Local\\Author Software\\nvm\\.shim";
    const ancestors = [_][]const u8{
        "C:\\Program Files\\PowerShell\\7\\pwsh.exe",
        "C:\\Windows\\explorer.exe",
    };
    try std.testing.expect(!nestedUnderNonPmShim(&ancestors, shim));
}

test "nestedUnderNonPmShim opencode spawning npm" {
    const shim = "C:\\Users\\x\\AppData\\Local\\Author Software\\nvm\\.shim";
    const ancestors = [_][]const u8{
        "C:\\Users\\x\\AppData\\Local\\Author Software\\nvm\\installs\\v24.20.0\\node.exe",
        "C:\\Users\\x\\AppData\\Local\\Author Software\\nvm\\.shim\\opencode.exe",
        "C:\\Program Files\\PowerShell\\7\\pwsh.exe",
    };
    try std.testing.expect(nestedUnderNonPmShim(&ancestors, shim));
}

test "nestedUnderNonPmShim npm.exe in shim is package manager" {
    const shim = "C:\\Users\\x\\AppData\\Local\\Author Software\\nvm\\.shim";
    const ancestors = [_][]const u8{
        "C:\\Users\\x\\AppData\\Local\\Author Software\\nvm\\.shim\\npm.exe",
        "C:\\Program Files\\PowerShell\\7\\pwsh.exe",
    };
    try std.testing.expect(!nestedUnderNonPmShim(&ancestors, shim));
}

test "extractHttpsUrl" {
    const rules = [_][]const u8{ "eslint", "https://policy.example/fw" };
    const url = extractHttpsUrl(&rules) orelse {
        try std.testing.expect(false);
        return;
    };
    try std.testing.expectEqualStrings("https://policy.example/fw", url);
}

test "isPackageAllowed org wildcard" {
    const rules = [_][]const u8{ "NOT ALL", "@org/*" };
    const ok = isPackageAllowed(.{ .name = "@org/pkg", .version = "1.0.0", .raw = "@org/pkg@1.0.0" }, &rules);
    try std.testing.expect(ok != null and ok.?);
}

test "isPackageAllowed star pin match miss" {
    const rules = [_][]const u8{"eslint@1.*"};
    const match = isPackageAllowed(.{ .name = "eslint", .version = "1.2.3", .raw = "eslint@1.2.3" }, &rules);
    try std.testing.expect(match != null and match.?);
    const miss = isPackageAllowed(.{ .name = "eslint", .version = "2.0.0", .raw = "eslint@2.0.0" }, &rules);
    try std.testing.expect(miss != null and !miss.?);
}

test "parsePackageJsonDirectDeps scoped and unscoped" {
    const allocator = std.testing.allocator;
    const json =
        \\{"dependencies":{"lodash":"^4.0.0","@scope/pkg":"1.0.0"},"devDependencies":{"eslint":"8.0.0"}}
    ;
    const all = try parsePackageJsonDirectDeps(allocator, json, true);
    defer freePackageSpecs(allocator, all);
    try std.testing.expect(all.len == 3);
    var found_scope = false;
    for (all) |pkg| {
        if (std.mem.eql(u8, pkg.name, "@scope/pkg")) {
            try std.testing.expectEqualStrings("1.0.0", pkg.version);
            try std.testing.expectEqualStrings("@scope/pkg@1.0.0", pkg.raw);
            found_scope = true;
        }
    }
    try std.testing.expect(found_scope);

    const prod = try parsePackageJsonDirectDeps(allocator, json, false);
    defer freePackageSpecs(allocator, prod);
    try std.testing.expect(prod.len == 2);
}

test "parsePackageJsonDirectDeps empty and skip non-string" {
    const allocator = std.testing.allocator;
    const empty = try parsePackageJsonDirectDeps(allocator, "{}", true);
    defer freePackageSpecs(allocator, empty);
    try std.testing.expect(empty.len == 0);

    const mixed =
        \\{"dependencies":{"ok":"1.0.0","bad":{"version":"1"},"num":1}}
    ;
    const deps = try parsePackageJsonDirectDeps(allocator, mixed, true);
    defer freePackageSpecs(allocator, deps);
    try std.testing.expect(deps.len == 1);
    try std.testing.expectEqualStrings("ok", deps[0].name);
}

test "productionOmit flags" {
    try std.testing.expect(productionOmit(&[_][]const u8{"install", "--production"}));
    try std.testing.expect(productionOmit(&[_][]const u8{"install", "--omit=dev"}));
    try std.testing.expect(!productionOmit(&[_][]const u8{"install", "--omit=optional"}));
}
