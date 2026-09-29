const std = @import("std");
const windows = std.os.windows;
const config = @import("config");
const registry = @import("registry");

pub const reg_value_trusted_modules = "TrustedModules";
pub const reg_value_approved_modules = "ApprovedModules";
pub const reg_value_approved_global_modules = "ApprovedGlobalModules";
pub const reg_value_untrusted_handler = "UntrustedModuleHandlerAction";

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
