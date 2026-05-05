const std = @import("std");

pub const SemVer = struct {
    major: u32,
    minor: u32,
    patch: u32,
    prerelease: ?[]const u8 = null,
};

const Bound = struct {
    version: SemVer,
    inclusive: bool,
};

pub const Requirement = struct {
    min: ?Bound = null,
    max: ?Bound = null,
    // For open-ended lower-bound ranges like ">20", use the oldest matching
    // available version when no installed version satisfies the requirement.
    prefer_oldest_when_no_installed: bool = false,
};

const VersionPattern = struct {
    any: bool = false,
    major: ?u32 = null,
    minor: ?u32 = null,
    patch: ?u32 = null,
    minor_wild: bool = false,
    patch_wild: bool = false,
    prerelease: ?[]const u8 = null,
};

pub fn normalizeVersionSpec(allocator: std.mem.Allocator, raw: []const u8) ![]u8 {
    const trimmed = std.mem.trim(u8, raw, " \t\r\n");
    if (trimmed.len == 0) return allocator.dupe(u8, "");

    if ((trimmed[0] == 'v' or trimmed[0] == 'V') and trimmed.len > 1 and std.ascii.isDigit(trimmed[1])) {
        return allocator.dupe(u8, trimmed[1..]);
    }

    return allocator.dupe(u8, trimmed);
}

pub fn resolveInstalledVersionSpec(allocator: std.mem.Allocator, root: []const u8, spec: []const u8, available_versions_text: ?[]const u8) !?[]u8 {
    const normalized = try normalizeVersionSpec(allocator, spec);
    defer allocator.free(normalized);

    if (normalized.len == 0) return null;

    const req_set = try parseRequirementSet(allocator, normalized);
    defer allocator.free(req_set.alternatives);

    if (try findBestInstalledVersion(allocator, root, req_set.alternatives)) |installed| {
        return installed;
    }

    if (available_versions_text) |output| {
        return try findBestVersionInText(allocator, output, req_set.alternatives, req_set.prefer_oldest_when_no_installed);
    }

    return null;
}

const RequirementSet = struct {
    alternatives: []Requirement,
    prefer_oldest_when_no_installed: bool,
};

fn findBestInstalledVersion(allocator: std.mem.Allocator, root: []const u8, reqs: []const Requirement) !?[]u8 {
    var best_ver: ?SemVer = null;
    var best_name: ?[]u8 = null;

    var dir = std.fs.openDirAbsolute(root, .{ .iterate = true }) catch return null;
    defer dir.close();

    var it = dir.iterate();
    while (try it.next()) |entry| {
        if (entry.kind != .directory) continue;
        if (entry.name.len < 2 or entry.name[0] != 'v') continue;

        const cand = entry.name[1..];
        const parsed = parseFullSemver(cand) catch continue;
        if (!matchesAnyRequirement(parsed, reqs)) continue;

        if (best_ver == null or compareSemver(parsed, best_ver.?) > 0) {
            if (best_name) |old| allocator.free(old);
            best_ver = parsed;
            best_name = try allocator.dupe(u8, cand);
        }
    }

    return best_name;
}

fn findBestVersionInText(allocator: std.mem.Allocator, text: []const u8, reqs: []const Requirement, prefer_oldest_when_no_installed: bool) !?[]u8 {
    var best_ver: ?SemVer = null;
    var best_name: ?[]u8 = null;

    var tokens = std.mem.tokenizeAny(u8, text, " \t\r\n|,:;()[]{}");
    while (tokens.next()) |tok| {
        const parsed = parseFullSemver(tok) catch continue;
        if (!matchesAnyRequirement(parsed, reqs)) continue;

        const should_replace = if (best_ver == null)
            true
        else if (prefer_oldest_when_no_installed)
            compareSemver(parsed, best_ver.?) < 0
        else
            compareSemver(parsed, best_ver.?) > 0;

        if (should_replace) {
            if (best_name) |old| allocator.free(old);
            best_ver = parsed;
            best_name = try allocator.dupe(u8, tok);
        }
    }

    return best_name;
}

fn parseRequirementSet(allocator: std.mem.Allocator, spec: []const u8) !RequirementSet {
    const trimmed = std.mem.trim(u8, spec, " \t\r\n");
    if (trimmed.len == 0) return error.UnsupportedVersionSpec;

    var alternatives = std.ArrayListUnmanaged(Requirement){};
    errdefer alternatives.deinit(allocator);

    var it = std.mem.splitSequence(u8, trimmed, "||");
    while (it.next()) |part_raw| {
        const part = std.mem.trim(u8, part_raw, " \t\r\n");
        if (part.len == 0) return error.UnsupportedVersionSpec;
        const req = try parseRequirement(part);
        try alternatives.append(allocator, req);
    }

    if (alternatives.items.len == 0) return error.UnsupportedVersionSpec;

    const prefer_oldest_when_no_installed =
        alternatives.items.len == 1 and alternatives.items[0].prefer_oldest_when_no_installed;

    return .{
        .alternatives = try alternatives.toOwnedSlice(allocator),
        .prefer_oldest_when_no_installed = prefer_oldest_when_no_installed,
    };
}

fn parseRequirement(spec: []const u8) !Requirement {
    const trimmed = std.mem.trim(u8, spec, " \t\r\n");
    if (trimmed.len == 0) return error.UnsupportedVersionSpec;

    if (findHyphenRangeSeparator(trimmed)) |sep| {
        const left_raw = std.mem.trim(u8, trimmed[0..sep.start], " \t\r\n");
        const right_raw = std.mem.trim(u8, trimmed[sep.end..], " \t\r\n");
        if (left_raw.len == 0 or right_raw.len == 0) return error.UnsupportedVersionSpec;
        return parseHyphenRange(left_raw, right_raw);
    }

    const is_any = std.ascii.eqlIgnoreCase(trimmed, "*") or std.ascii.eqlIgnoreCase(trimmed, "x");
    if (is_any) return .{};

    var req = Requirement{};
    var tokenized = false;
    var token_count: usize = 0;
    var first_token: []const u8 = "";
    var it = std.mem.tokenizeAny(u8, trimmed, " \t\r\n");

    while (it.next()) |token| {
        tokenized = true;
        if (token_count == 0) first_token = token;
        token_count += 1;
        const next_req = try parseSingleToken(token);
        req = try intersectRequirements(req, next_req);
    }

    if (!tokenized) return error.UnsupportedVersionSpec;

    if (token_count == 1 and isOpenLowerBoundToken(first_token) and req.min != null and req.max == null) {
        req.prefer_oldest_when_no_installed = true;
    }

    return req;
}

const HyphenSeparator = struct {
    start: usize,
    end: usize,
};

fn findHyphenRangeSeparator(spec: []const u8) ?HyphenSeparator {
    if (spec.len < 3) return null;

    var i: usize = 1;
    while (i + 1 < spec.len) : (i += 1) {
        if (spec[i] != '-') continue;
        if (!std.ascii.isWhitespace(spec[i - 1]) or !std.ascii.isWhitespace(spec[i + 1])) continue;

        var start = i;
        while (start > 0 and std.ascii.isWhitespace(spec[start - 1])) : (start -= 1) {}

        var end = i + 1;
        while (end < spec.len and std.ascii.isWhitespace(spec[end])) : (end += 1) {}

        return .{ .start = start, .end = end };
    }

    return null;
}

fn parseHyphenRange(left_raw: []const u8, right_raw: []const u8) !Requirement {
    const left = try parseVersionPattern(left_raw);
    const right = try parseVersionPattern(right_raw);

    if (left.any or right.any) return error.UnsupportedVersionSpec;

    const min = try lowerBoundFromPattern(left);
    const upper = try hyphenUpperBoundFromPattern(right);

    return .{
        .min = .{ .version = min, .inclusive = true },
        .max = .{ .version = upper.version, .inclusive = upper.inclusive },
    };
}

fn hyphenUpperBoundFromPattern(pattern: VersionPattern) !Bound {
    if (pattern.any or pattern.major == null) return error.UnsupportedVersionSpec;

    if (pattern.minor == null or pattern.minor_wild) {
        return .{ .version = .{ .major = pattern.major.? + 1, .minor = 0, .patch = 0, .prerelease = null }, .inclusive = false };
    }

    if (pattern.patch == null or pattern.patch_wild) {
        return .{ .version = .{ .major = pattern.major.?, .minor = pattern.minor.? + 1, .patch = 0, .prerelease = null }, .inclusive = false };
    }

    return .{ .version = .{ .major = pattern.major.?, .minor = pattern.minor.?, .patch = pattern.patch.?, .prerelease = pattern.prerelease }, .inclusive = true };
}

fn isOpenLowerBoundToken(token_raw: []const u8) bool {
    const token = std.mem.trim(u8, token_raw, " \t\r\n");
    return std.mem.startsWith(u8, token, ">=") or std.mem.startsWith(u8, token, ">");
}

fn parseSingleToken(token_raw: []const u8) !Requirement {
    const token = std.mem.trim(u8, token_raw, " \t\r\n");
    if (token.len == 0) return error.UnsupportedVersionSpec;

    if (token[0] == '^') {
        const pattern = try parseVersionPattern(token[1..]);
        const min = try lowerBoundFromPattern(pattern);
        const max = try caretUpperBound(pattern);
        return .{ .min = .{ .version = min, .inclusive = true }, .max = .{ .version = max, .inclusive = false } };
    }

    if (token[0] == '~') {
        const pattern = try parseVersionPattern(token[1..]);
        const min = try lowerBoundFromPattern(pattern);
        const max = try tildeUpperBound(pattern);
        return .{ .min = .{ .version = min, .inclusive = true }, .max = .{ .version = max, .inclusive = false } };
    }

    if (std.mem.startsWith(u8, token, ">=")) {
        const v = try comparatorVersion(token[2..]);
        return .{ .min = .{ .version = v, .inclusive = true } };
    }

    if (std.mem.startsWith(u8, token, ">")) {
        const v = try comparatorVersion(token[1..]);
        return .{ .min = .{ .version = v, .inclusive = false } };
    }

    if (std.mem.startsWith(u8, token, "<=")) {
        const v = try comparatorVersion(token[2..]);
        return .{ .max = .{ .version = v, .inclusive = true } };
    }

    if (std.mem.startsWith(u8, token, "<")) {
        const v = try comparatorVersion(token[1..]);
        return .{ .max = .{ .version = v, .inclusive = false } };
    }

    if (std.mem.startsWith(u8, token, "=")) {
        const v = try comparatorVersion(token[1..]);
        return .{ .min = .{ .version = v, .inclusive = true }, .max = .{ .version = v, .inclusive = true } };
    }

    const pattern = try parseVersionPattern(token);
    if (pattern.any) return .{};

    if (pattern.minor == null or pattern.minor_wild or pattern.patch == null or pattern.patch_wild) {
        const min = try lowerBoundFromPattern(pattern);
        const max = try wildcardUpperBound(pattern);
        return .{ .min = .{ .version = min, .inclusive = true }, .max = .{ .version = max, .inclusive = false } };
    }

    const exact = SemVer{ .major = pattern.major.?, .minor = pattern.minor.?, .patch = pattern.patch.?, .prerelease = pattern.prerelease };
    return .{ .min = .{ .version = exact, .inclusive = true }, .max = .{ .version = exact, .inclusive = true } };
}

fn parseVersionPattern(raw: []const u8) !VersionPattern {
    const trimmed = std.mem.trim(u8, raw, " \t\r\n");
    if (trimmed.len == 0) return error.UnsupportedVersionSpec;

    if (std.ascii.eqlIgnoreCase(trimmed, "*") or std.ascii.eqlIgnoreCase(trimmed, "x")) {
        return .{ .any = true };
    }

    const base_and_build = std.mem.splitScalar(u8, trimmed, '+');
    var build_it = base_and_build;
    const without_build = build_it.first();

    const dash_idx = std.mem.indexOfScalar(u8, without_build, '-');
    const core = if (dash_idx) |idx| without_build[0..idx] else without_build;
    const prerelease = if (dash_idx) |idx| without_build[idx + 1 ..] else null;

    if (prerelease) |pr| {
        if (!isValidPrerelease(pr)) return error.UnsupportedVersionSpec;
    }

    var pattern = VersionPattern{};
    var it = std.mem.splitScalar(u8, core, '.');
    var index: usize = 0;

    while (it.next()) |part_raw| {
        const part = std.mem.trim(u8, part_raw, " \t\r\n");
        if (part.len == 0 or index >= 3) return error.UnsupportedVersionSpec;

        if (isWildcard(part)) {
            switch (index) {
                0 => pattern.any = true,
                1 => pattern.minor_wild = true,
                2 => pattern.patch_wild = true,
                else => {},
            }
            index += 1;
            continue;
        }

        var numeric = part;
        if (index == 0 and numeric.len > 1 and (numeric[0] == 'v' or numeric[0] == 'V') and std.ascii.isDigit(numeric[1])) {
            numeric = numeric[1..];
        }

        for (numeric) |c| {
            if (!std.ascii.isDigit(c)) return error.UnsupportedVersionSpec;
        }

        const value = try std.fmt.parseUnsigned(u32, numeric, 10);
        switch (index) {
            0 => pattern.major = value,
            1 => pattern.minor = value,
            2 => pattern.patch = value,
            else => {},
        }

        index += 1;
    }

    if (pattern.any) {
        if (pattern.major != null or pattern.minor != null or pattern.patch != null) {
            return error.UnsupportedVersionSpec;
        }
        return pattern;
    }

    if (pattern.major == null) return error.UnsupportedVersionSpec;

    if (pattern.minor_wild and pattern.patch != null and !pattern.patch_wild) return error.UnsupportedVersionSpec;

    if (prerelease != null and (pattern.patch == null or pattern.patch_wild or pattern.minor == null or pattern.minor_wild)) {
        return error.UnsupportedVersionSpec;
    }

    pattern.prerelease = prerelease;

    return pattern;
}

fn isValidPrerelease(s: []const u8) bool {
    if (s.len == 0) return false;

    var it = std.mem.splitScalar(u8, s, '.');
    while (it.next()) |part| {
        if (part.len == 0) return false;
        for (part) |c| {
            if (!(std.ascii.isAlphanumeric(c) or c == '-')) return false;
        }
    }

    return true;
}

fn isWildcard(token: []const u8) bool {
    return std.ascii.eqlIgnoreCase(token, "x") or std.mem.eql(u8, token, "*");
}

fn lowerBoundFromPattern(pattern: VersionPattern) !SemVer {
    if (pattern.any or pattern.major == null) return error.UnsupportedVersionSpec;

    return .{
        .major = pattern.major.?,
        .minor = if (pattern.minor != null and !pattern.minor_wild) pattern.minor.? else 0,
        .patch = if (pattern.patch != null and !pattern.patch_wild) pattern.patch.? else 0,
        .prerelease = if (pattern.patch != null and !pattern.patch_wild and pattern.prerelease != null) pattern.prerelease else null,
    };
}

fn wildcardUpperBound(pattern: VersionPattern) !SemVer {
    if (pattern.any or pattern.major == null) return error.UnsupportedVersionSpec;

    if (pattern.minor == null or pattern.minor_wild) {
        return .{ .major = pattern.major.? + 1, .minor = 0, .patch = 0, .prerelease = null };
    }

    if (pattern.patch == null or pattern.patch_wild) {
        return .{ .major = pattern.major.?, .minor = pattern.minor.? + 1, .patch = 0, .prerelease = null };
    }

    return .{ .major = pattern.major.?, .minor = pattern.minor.?, .patch = pattern.patch.? + 1, .prerelease = null };
}

fn tildeUpperBound(pattern: VersionPattern) !SemVer {
    if (pattern.any) return error.UnsupportedVersionSpec;
    const min = try lowerBoundFromPattern(pattern);

    if (pattern.minor == null or pattern.minor_wild) {
        return .{ .major = min.major + 1, .minor = 0, .patch = 0, .prerelease = null };
    }

    return .{ .major = min.major, .minor = min.minor + 1, .patch = 0, .prerelease = null };
}

fn caretUpperBound(pattern: VersionPattern) !SemVer {
    if (pattern.any) return error.UnsupportedVersionSpec;
    const min = try lowerBoundFromPattern(pattern);

    if (min.major > 0) {
        return .{ .major = min.major + 1, .minor = 0, .patch = 0, .prerelease = null };
    }

    if (min.minor > 0) {
        return .{ .major = 0, .minor = min.minor + 1, .patch = 0, .prerelease = null };
    }

    return .{ .major = 0, .minor = 0, .patch = min.patch + 1, .prerelease = null };
}

fn comparatorVersion(raw: []const u8) !SemVer {
    const pattern = try parseVersionPattern(raw);
    if (pattern.any) return error.UnsupportedVersionSpec;
    return lowerBoundFromPattern(pattern);
}

fn intersectRequirements(a: Requirement, b: Requirement) !Requirement {
    var merged = Requirement{};

    merged.min = mergeMinBound(a.min, b.min);
    merged.max = mergeMaxBound(a.max, b.max);
    merged.prefer_oldest_when_no_installed = a.prefer_oldest_when_no_installed or b.prefer_oldest_when_no_installed;

    if (merged.min != null and merged.max != null) {
        const cmp = compareSemver(merged.min.?.version, merged.max.?.version);
        if (cmp > 0) return error.UnsupportedVersionSpec;
        if (cmp == 0 and (!merged.min.?.inclusive or !merged.max.?.inclusive)) {
            return error.UnsupportedVersionSpec;
        }
    }

    return merged;
}

fn mergeMinBound(a: ?Bound, b: ?Bound) ?Bound {
    if (a == null) return b;
    if (b == null) return a;

    const cmp = compareSemver(a.?.version, b.?.version);
    if (cmp > 0) return a;
    if (cmp < 0) return b;

    return .{ .version = a.?.version, .inclusive = a.?.inclusive and b.?.inclusive };
}

fn mergeMaxBound(a: ?Bound, b: ?Bound) ?Bound {
    if (a == null) return b;
    if (b == null) return a;

    const cmp = compareSemver(a.?.version, b.?.version);
    if (cmp < 0) return a;
    if (cmp > 0) return b;

    return .{ .version = a.?.version, .inclusive = a.?.inclusive and b.?.inclusive };
}

fn matchesRequirement(v: SemVer, req: Requirement) bool {
    if (req.min) |min| {
        const cmp = compareSemver(v, min.version);
        if (cmp < 0 or (cmp == 0 and !min.inclusive)) return false;
    }

    if (req.max) |max| {
        const cmp = compareSemver(v, max.version);
        if (cmp > 0 or (cmp == 0 and !max.inclusive)) return false;
    }

    return true;
}

fn matchesAnyRequirement(v: SemVer, reqs: []const Requirement) bool {
    for (reqs) |req| {
        if (matchesRequirement(v, req)) return true;
    }
    return false;
}

fn compareSemver(a: SemVer, b: SemVer) i32 {
    if (a.major < b.major) return -1;
    if (a.major > b.major) return 1;
    if (a.minor < b.minor) return -1;
    if (a.minor > b.minor) return 1;
    if (a.patch < b.patch) return -1;
    if (a.patch > b.patch) return 1;
    return comparePrerelease(a.prerelease, b.prerelease);
}

fn comparePrerelease(a: ?[]const u8, b: ?[]const u8) i32 {
    if (a == null and b == null) return 0;
    if (a == null) return 1;
    if (b == null) return -1;

    var a_it = std.mem.splitScalar(u8, a.?, '.');
    var b_it = std.mem.splitScalar(u8, b.?, '.');

    while (true) {
        const a_part = a_it.next();
        const b_part = b_it.next();

        if (a_part == null and b_part == null) return 0;
        if (a_part == null) return -1;
        if (b_part == null) return 1;

        const cmp = comparePrereleaseIdentifier(a_part.?, b_part.?);
        if (cmp != 0) return cmp;
    }
}

fn comparePrereleaseIdentifier(a: []const u8, b: []const u8) i32 {
    const a_numeric = isNumericIdentifier(a);
    const b_numeric = isNumericIdentifier(b);

    if (a_numeric and b_numeric) {
        const a_num = std.fmt.parseUnsigned(u64, a, 10) catch return compareLex(a, b);
        const b_num = std.fmt.parseUnsigned(u64, b, 10) catch return compareLex(a, b);
        if (a_num < b_num) return -1;
        if (a_num > b_num) return 1;
        return 0;
    }

    if (a_numeric and !b_numeric) return -1;
    if (!a_numeric and b_numeric) return 1;

    return compareLex(a, b);
}

fn isNumericIdentifier(s: []const u8) bool {
    if (s.len == 0) return false;
    for (s) |c| {
        if (!std.ascii.isDigit(c)) return false;
    }
    return true;
}

fn compareLex(a: []const u8, b: []const u8) i32 {
    const ord = std.mem.order(u8, a, b);
    return switch (ord) {
        .lt => -1,
        .eq => 0,
        .gt => 1,
    };
}

fn parseFullSemver(v: []const u8) !SemVer {
    const trimmed = std.mem.trim(u8, v, " \t\r\n");
    if (trimmed.len == 0) return error.UnsupportedVersionSpec;

    const body = if ((trimmed[0] == 'v' or trimmed[0] == 'V') and trimmed.len > 1 and std.ascii.isDigit(trimmed[1])) trimmed[1..] else trimmed;

    var build_it = std.mem.splitScalar(u8, body, '+');
    const without_build = build_it.first();

    const dash_idx = std.mem.indexOfScalar(u8, without_build, '-');
    const core = if (dash_idx) |idx| without_build[0..idx] else without_build;
    const prerelease = if (dash_idx) |idx| without_build[idx + 1 ..] else null;

    if (prerelease) |pr| {
        if (!isValidPrerelease(pr)) return error.UnsupportedVersionSpec;
    }

    var it = std.mem.splitScalar(u8, core, '.');
    const a = it.next() orelse return error.UnsupportedVersionSpec;
    const b = it.next() orelse return error.UnsupportedVersionSpec;
    const c = it.next() orelse return error.UnsupportedVersionSpec;
    if (it.next() != null) return error.UnsupportedVersionSpec;

    for (a) |ch| if (!std.ascii.isDigit(ch)) return error.UnsupportedVersionSpec;
    for (b) |ch| if (!std.ascii.isDigit(ch)) return error.UnsupportedVersionSpec;
    for (c) |ch| if (!std.ascii.isDigit(ch)) return error.UnsupportedVersionSpec;

    return .{
        .major = try std.fmt.parseUnsigned(u32, a, 10),
        .minor = try std.fmt.parseUnsigned(u32, b, 10),
        .patch = try std.fmt.parseUnsigned(u32, c, 10),
        .prerelease = prerelease,
    };
}

fn expectResolvedTo(allocator: std.mem.Allocator, root: []const u8, available: []const u8, spec: []const u8, expected: []const u8) !void {
    const resolved = (try resolveInstalledVersionSpec(allocator, root, spec, available)).?;
    defer allocator.free(resolved);
    try std.testing.expectEqualStrings(expected, resolved);
}

fn expectUnsupported(allocator: std.mem.Allocator, root: []const u8, available: []const u8, spec: []const u8) !void {
    try std.testing.expectError(error.UnsupportedVersionSpec, resolveInstalledVersionSpec(allocator, root, spec, available));
}

test "resolve supports exact, comparator, caret, tilde, range, wildcard, partial, and prerelease specs" {
    const allocator = std.testing.allocator;
    const root = "C:\\does-not-exist";
    const available =
        "14.20.0 15.5.0 16.0.0 16.0.9 16.1.0 16.9.1 16.20.2 17.0.0 18.12.1 18.12.2 18.13.0 20.0.0-rc.1 20.0.0 20.0.1 21.0.0-beta.1 21.0.0-rc.1 21.0.0-rc.2 21.0.0 24.9.9 25.0.0 25.9.0";

    const v_exact = (try resolveInstalledVersionSpec(allocator, root, "18.12.1", available)).?;
    defer allocator.free(v_exact);
    try std.testing.expectEqualStrings("18.12.1", v_exact);

    const v_gte = (try resolveInstalledVersionSpec(allocator, root, ">=16.0.0", available)).?;
    defer allocator.free(v_gte);
    try std.testing.expectEqualStrings("16.0.0", v_gte);

    const v_caret = (try resolveInstalledVersionSpec(allocator, root, "^16.0.0", available)).?;
    defer allocator.free(v_caret);
    try std.testing.expectEqualStrings("16.20.2", v_caret);

    const v_tilde = (try resolveInstalledVersionSpec(allocator, root, "~16.0.0", available)).?;
    defer allocator.free(v_tilde);
    try std.testing.expectEqualStrings("16.0.9", v_tilde);

    const v_range = (try resolveInstalledVersionSpec(allocator, root, ">=14.0.0 <17.0.0", available)).?;
    defer allocator.free(v_range);
    try std.testing.expectEqualStrings("16.20.2", v_range);

    const v_wildcard = (try resolveInstalledVersionSpec(allocator, root, "16.x", available)).?;
    defer allocator.free(v_wildcard);
    try std.testing.expectEqualStrings("16.20.2", v_wildcard);

    const v_any = (try resolveInstalledVersionSpec(allocator, root, "*", available)).?;
    defer allocator.free(v_any);
    try std.testing.expectEqualStrings("25.9.0", v_any);

    const v_partial_major = (try resolveInstalledVersionSpec(allocator, root, "25", available)).?;
    defer allocator.free(v_partial_major);
    try std.testing.expectEqualStrings("25.9.0", v_partial_major);

    const v_partial_minor = (try resolveInstalledVersionSpec(allocator, root, "18.12", available)).?;
    defer allocator.free(v_partial_minor);
    try std.testing.expectEqualStrings("18.12.2", v_partial_minor);

    const v_lt_25 = (try resolveInstalledVersionSpec(allocator, root, "<25", available)).?;
    defer allocator.free(v_lt_25);
    try std.testing.expectEqualStrings("24.9.9", v_lt_25);

    const v_gt_20 = (try resolveInstalledVersionSpec(allocator, root, ">20", available)).?;
    defer allocator.free(v_gt_20);
    try std.testing.expectEqualStrings("20.0.1", v_gt_20);

    const v_exact_pr = (try resolveInstalledVersionSpec(allocator, root, "21.0.0-rc.2", available)).?;
    defer allocator.free(v_exact_pr);
    try std.testing.expectEqualStrings("21.0.0-rc.2", v_exact_pr);

    const v_lt_pr = (try resolveInstalledVersionSpec(allocator, root, "<21.0.0", available)).?;
    defer allocator.free(v_lt_pr);
    try std.testing.expectEqualStrings("21.0.0-rc.2", v_lt_pr);

    const v_or = (try resolveInstalledVersionSpec(allocator, root, ">=14 <15 || >=24 <25", available)).?;
    defer allocator.free(v_or);
    try std.testing.expectEqualStrings("24.9.9", v_or);

    const v_hyphen_full = (try resolveInstalledVersionSpec(allocator, root, "20.0.0-rc.1 - 20.0.1", available)).?;
    defer allocator.free(v_hyphen_full);
    try std.testing.expectEqualStrings("20.0.1", v_hyphen_full);

    const v_hyphen_partial = (try resolveInstalledVersionSpec(allocator, root, "20 - 21", available)).?;
    defer allocator.free(v_hyphen_partial);
    try std.testing.expectEqualStrings("21.0.0", v_hyphen_partial);
}

test "installed versions prefer newest match before fallback behavior" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makeDir("v20.0.1");
    try tmp.dir.makeDir("v22.0.0");
    try tmp.dir.makeDir("v23.1.4");

    const root = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);

    const available = "20.0.1 21.0.0 25.9.0";

    const resolved = (try resolveInstalledVersionSpec(allocator, root, ">20", available)).?;
    defer allocator.free(resolved);

    try std.testing.expectEqualStrings("23.1.4", resolved);
}

test "npm engines parity matrix for supported grammar" {
    const allocator = std.testing.allocator;
    const root = "C:\\does-not-exist";
    const available =
        "0.0.3 0.0.4 0.2.3 0.2.5 0.3.0 14.20.0 16.20.2 18.12.1 18.12.2 18.13.0 20.0.0-rc.1 20.0.0 20.0.1 21.0.0-beta.1 21.0.0-rc.1 21.0.0-rc.2 21.0.0 21.1.0 24.9.9 25.0.0 25.9.0";

    try expectResolvedTo(allocator, root, available, "=18.12.2", "18.12.2");
    try expectResolvedTo(allocator, root, available, "v18.12.2", "18.12.2");
    try expectResolvedTo(allocator, root, available, "<=18.12.2", "18.12.2");
    try expectResolvedTo(allocator, root, available, "~21", "21.1.0");
    try expectResolvedTo(allocator, root, available, "^0.2.3", "0.2.5");
    try expectResolvedTo(allocator, root, available, "^0.0.3", "0.0.3");
    try expectResolvedTo(allocator, root, available, "18.12.1 - 18.13", "18.13.0");
    try expectResolvedTo(allocator, root, available, "18 - 18", "18.13.0");
    try expectResolvedTo(allocator, root, available, "18.12.1  -   18.13", "18.13.0");
    try expectResolvedTo(allocator, root, available, "18.12.1\t-\t18.13", "18.13.0");
    try expectResolvedTo(allocator, root, available, ">=21.0.0-rc.1 <21.0.0", "21.0.0-rc.2");
    try expectResolvedTo(allocator, root, available, "21.x || 18.12.x", "21.1.0");
    try expectResolvedTo(allocator, root, available, "21.x.x", "21.1.0");
    try expectResolvedTo(allocator, root, available, "21.*.*", "21.1.0");
    try expectResolvedTo(allocator, root, available, "<25", "24.9.9");
    try expectResolvedTo(allocator, root, available, ">20", "20.0.1");
}

test "alpha prerelease continuity for future node releases" {
    const allocator = std.testing.allocator;
    const root = "C:\\does-not-exist";
    const available = "25.9.0 26.0.0-alpha.1 26.0.0-alpha.2 26.0.0";

    try expectResolvedTo(allocator, root, available, "26.0.0-alpha.2", "26.0.0-alpha.2");
    try expectResolvedTo(allocator, root, available, ">=26.0.0-alpha.1 <26.0.0", "26.0.0-alpha.2");
}

test "npm engines invalid grammar rejects malformed expressions" {
    const allocator = std.testing.allocator;
    const root = "C:\\does-not-exist";
    const available = "18.12.1 18.12.2 21.0.0";

    try expectUnsupported(allocator, root, available, "||");
    try expectUnsupported(allocator, root, available, "18.12.1 -");
    try expectUnsupported(allocator, root, available, ">=");
    try expectUnsupported(allocator, root, available, "1..2");
    try expectUnsupported(allocator, root, available, "1 || || 2");
    try expectUnsupported(allocator, root, available, "1.2.x-rc.1");
}

test "real world engines grammar matrix" {
    const allocator = std.testing.allocator;
    const root = "C:\\does-not-exist";
    const available =
        "10.24.1 12.22.12 14.21.3 16.20.2 18.17.1 18.18.0 18.19.1 20.9.0 20.10.0 20.10.1 20.11.1 20.17.0 20.18.2 21.1.0 21.7.3 22.0.0-alpha.1 22.0.0-alpha.2 22.0.0 22.1.0 22.9.0 22.12.0 24.0.0-alpha.1 24.0.0 24.5.0 25.9.0";

    const Case = struct {
        spec: []const u8,
        expected: []const u8,
    };

    const cases = [_]Case{
        .{ .spec = ">=18", .expected = "18.17.1" },
        .{ .spec = "^18.18.0 || ^20.9.0 || >=21.1.0", .expected = "25.9.0" },
        .{ .spec = ">=16.14 <17 || >=18.0.0", .expected = "25.9.0" },
        .{ .spec = "14 || >=16.0.0 || ^18", .expected = "25.9.0" },
        .{ .spec = "^20.17.0 || >=22.9.0", .expected = "25.9.0" },
        .{ .spec = "~20.10.0", .expected = "20.10.1" },
        .{ .spec = "18.x || 20.x || 22.x", .expected = "22.12.0" },
        .{ .spec = ">=18 <19 || >=20 <21", .expected = "20.18.2" },
        .{ .spec = "20 - 22", .expected = "22.12.0" },
        .{ .spec = "<=22", .expected = "22.0.0" },
        .{ .spec = "22 - 22", .expected = "22.12.0" },
        .{ .spec = "22.x", .expected = "22.12.0" },
        .{ .spec = "22.x.x", .expected = "22.12.0" },
        .{ .spec = "22.*.*", .expected = "22.12.0" },
        .{ .spec = "=20.17.0", .expected = "20.17.0" },
        .{ .spec = "v20.17.0", .expected = "20.17.0" },
        .{ .spec = ">=22.0.0-alpha.1 <22.0.0", .expected = "22.0.0-alpha.2" },
        .{ .spec = "^22.0.0-alpha.1", .expected = "22.12.0" },
        .{ .spec = "24 - 25", .expected = "25.9.0" },
        .{ .spec = ">=24.0.0", .expected = "24.0.0" },
    };

    for (cases) |c| {
        try expectResolvedTo(allocator, root, available, c.spec, c.expected);
    }
}
