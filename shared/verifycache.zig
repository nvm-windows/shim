const std = @import("std");
const windows = std.os.windows;
const config = @import("config");
const registry = @import("registry");
const wintrust = @import("wintrust");

const bcrypt_ms_primitive_provider = "Microsoft Primitive Provider";
const bcrypt_ecdsa_p256 = "ECDSA_P256";
const bcrypt_eccpublic_blob = "ECCPUBLICBLOB";

const GetFileExInfoStandard: u32 = 0;

const Win32FileAttributeData = extern struct {
    dwFileAttributes: windows.DWORD,
    ftCreationTime: windows.FILETIME,
    ftLastAccessTime: windows.FILETIME,
    ftLastWriteTime: windows.FILETIME,
    nFileSizeHigh: windows.DWORD,
    nFileSizeLow: windows.DWORD,
};

const ByHandleFileInformation = extern struct {
    dwFileAttributes: windows.DWORD,
    ftCreationTime: windows.FILETIME,
    ftLastAccessTime: windows.FILETIME,
    ftLastWriteTime: windows.FILETIME,
    dwVolumeSerialNumber: windows.DWORD,
    nFileSizeHigh: windows.DWORD,
    nFileSizeLow: windows.DWORD,
    nNumberOfLinks: windows.DWORD,
    nFileIndexHigh: windows.DWORD,
    nFileIndexLow: windows.DWORD,
};

const fsctl_read_file_usn_data: u32 = 0x000900eb;
const ReadFileUsnData = extern struct {
    min_major_version: u16,
    max_major_version: u16,
};

const bcrypt = struct {
    pub extern "bcrypt" fn BCryptOpenAlgorithmProvider(
        phAlgorithm: *windows.HANDLE,
        pszAlgId: [*:0]u16,
        pszImplementation: ?[*:0]u16,
        dwFlags: u32,
    ) callconv(.winapi) u32;

    pub extern "bcrypt" fn BCryptCloseAlgorithmProvider(
        hAlgorithm: windows.HANDLE,
        dwFlags: u32,
    ) callconv(.winapi) u32;

    pub extern "bcrypt" fn BCryptImportKeyPair(
        hAlgorithm: windows.HANDLE,
        hImportKey: ?windows.HANDLE,
        pszBlobType: [*:0]u16,
        phKey: *windows.HANDLE,
        pbInput: [*]const u8,
        cbInput: u32,
        dwFlags: u32,
    ) callconv(.winapi) u32;

    pub extern "bcrypt" fn BCryptDestroyKey(
        hKey: windows.HANDLE,
    ) callconv(.winapi) u32;

    pub extern "bcrypt" fn BCryptVerifySignature(
        hKey: windows.HANDLE,
        pPaddingInfo: ?*anyopaque,
        pbHash: [*]const u8,
        cbHash: u32,
        pbSignature: [*]const u8,
        cbSignature: u32,
        dwFlags: u32,
    ) callconv(.winapi) u32;
};

const kernel32 = struct {
    pub extern "kernel32" fn GetFileAttributesExW(
        lpFileName: [*:0]u16,
        fInfoLevelId: u32,
        lpFileInformation: *Win32FileAttributeData,
    ) callconv(.winapi) windows.BOOL;

    pub extern "kernel32" fn GetFileInformationByHandle(
        hFile: windows.HANDLE,
        lpFileInformation: *ByHandleFileInformation,
    ) callconv(.winapi) windows.BOOL;

    pub extern "kernel32" fn DeviceIoControl(
        hDevice: windows.HANDLE,
        dwIoControlCode: u32,
        lpInBuffer: ?*const anyopaque,
        nInBufferSize: u32,
        lpOutBuffer: ?*anyopaque,
        nOutBufferSize: u32,
        lpBytesReturned: *u32,
        lpOverlapped: ?*anyopaque,
    ) callconv(.winapi) windows.BOOL;
};

pub const VerifyResult = enum {
    trusted_cache,
    verified_full,
    failed,
};

pub const CacheStatus = enum {
    none,
    path_changed,
    metadata_changed,
    identity_changed,
    signature_invalid,
};

pub const VerifyOutcome = struct {
    result: VerifyResult,
    reason: []const u8 = "",
    cache_status: CacheStatus = .none,
    reason_storage: [512]u8 = undefined,

    pub fn failedStatic(comptime message: []const u8) VerifyOutcome {
        return .{ .result = .failed, .reason = message };
    }

    pub fn setReason(self: *VerifyOutcome, comptime fmt: []const u8, args: anytype) void {
        self.result = .failed;
        self.reason = std.fmt.bufPrint(&self.reason_storage, fmt, args) catch "trust verification failed";
    }
};

const NodeFileTimes = struct {
    size: i64,
    mtime: u64,
};

const FileSecurityState = struct {
    volume_serial: u32,
    file_id: u64,
    usn: u64,
};

const CacheEntry = struct {
    path: []u8,
    size: i64,
    mtime: u64,
    thumbprint: []u8,
    digest: []u8,
    volume_serial: u32,
    file_id: u64,
    usn: u64,
    sig: []u8,
    version: u32,

    pub fn deinit(self: CacheEntry, allocator: std.mem.Allocator) void {
        allocator.free(self.path);
        allocator.free(self.thumbprint);
        allocator.free(self.digest);
        allocator.free(self.sig);
    }
};

const default_allowed_signers = config.default_allowed_signers;

const policy_hives = &[_]windows.HKEY{
    windows.HKEY_LOCAL_MACHINE,
};

pub fn resolveDataRoot(allocator: std.mem.Allocator, install_root: []const u8) ![]u8 {
    const trimmed = std.mem.trim(u8, install_root, " \t\r\n");
    if (trimmed.len == 0) return error.InvalidInstallRoot;
    const data_root = std.fs.path.dirname(trimmed) orelse return error.InvalidInstallRoot;
    if (data_root.len == 0 or std.mem.eql(u8, data_root, ".")) return error.InvalidInstallRoot;
    return try allocator.dupe(u8, data_root);
}

pub fn loadAllowedSigners(allocator: std.mem.Allocator) ![]const []const u8 {
    if (registry.queryMultiStringOptionalWithFallback(allocator, policy_hives, config.policy_registry_root, config.reg_value_allowed_signers) catch null) |signers| {
        if (signers.len > 0) return signers;
        freeAllowedSigners(allocator, signers);
    }

    if (registry.queryMultiStringOptionalWithFallback(allocator, registry.preferenceHives(), config.preference_registry_root, config.reg_value_allowed_signers) catch null) |signers| {
        if (signers.len > 0) return signers;
        freeAllowedSigners(allocator, signers);
    }

    return try duplicateAllowedSigners(allocator, &default_allowed_signers);
}

pub fn freeAllowedSigners(allocator: std.mem.Allocator, signers: []const []const u8) void {
    for (signers) |signer| allocator.free(signer);
    allocator.free(signers);
}

fn duplicateAllowedSigners(allocator: std.mem.Allocator, signers: []const []const u8) ![]const []const u8 {
    const out = try allocator.alloc([]const u8, signers.len);
    errdefer freeAllowedSigners(allocator, out);

    for (signers, 0..) |signer, i| {
        out[i] = try allocator.dupe(u8, signer);
    }
    return out;
}

fn queryConfigString(allocator: std.mem.Allocator, value_name: []const u8) ?[]u8 {
    if (registry.queryStringWithFallback(allocator, policy_hives, config.policy_registry_root, value_name)) |value| {
        return value;
    } else |_| {}
    if (registry.queryStringWithFallback(allocator, registry.preferenceHives(), config.preference_registry_root, value_name)) |value| {
        return value;
    } else |_| {}
    return null;
}

fn isAirGapped() bool {
    if (registry.queryDwordOptionalWithFallback(policy_hives, config.policy_registry_root, config.reg_value_air_gapped) catch null) |value| {
        return value != 0;
    }
    if (registry.queryDwordOptionalWithFallback(registry.preferenceHives(), config.preference_registry_root, config.reg_value_air_gapped) catch null) |value| {
        return value != 0;
    }
    return false;
}

/// Shim runtime revocation: never online (latency invariant). Default mirrors seed (online→cached).
pub fn loadRuntimeRevocationMode(allocator: std.mem.Allocator) wintrust.RevocationMode {
    var mode: wintrust.RevocationMode = .online;
    if (queryConfigString(allocator, config.reg_value_authenticode_revocation)) |raw| {
        defer allocator.free(raw);
        mode = wintrust.parseRevocationMode(raw);
    }
    if (isAirGapped() and mode == .online) {
        mode = .cached;
    }
    return wintrust.clampRuntimeRevocationMode(mode);
}

pub fn loadAllowedThumbprints(allocator: std.mem.Allocator) ![]const []const u8 {
    if (registry.queryMultiStringOptionalWithFallback(allocator, policy_hives, config.policy_registry_root, config.reg_value_allowed_thumbprints) catch null) |pins| {
        if (pins.len > 0) return try normalizeThumbprintList(allocator, pins);
        freeAllowedSigners(allocator, pins);
    }
    if (registry.queryMultiStringOptionalWithFallback(allocator, registry.preferenceHives(), config.preference_registry_root, config.reg_value_allowed_thumbprints) catch null) |pins| {
        if (pins.len > 0) return try normalizeThumbprintList(allocator, pins);
        freeAllowedSigners(allocator, pins);
    }
    return try allocator.alloc([]const u8, 0);
}

fn normalizeThumbprintList(allocator: std.mem.Allocator, pins: []const []const u8) ![]const []const u8 {
    defer freeAllowedSigners(allocator, pins);
    var out = try allocator.alloc([]const u8, pins.len);
    errdefer freeAllowedSigners(allocator, out);
    var n: usize = 0;
    for (pins) |pin| {
        const normalized = try wintrust.normalizeThumbprint(allocator, pin);
        if (normalized.len == 0) {
            allocator.free(normalized);
            continue;
        }
        out[n] = normalized;
        n += 1;
    }
    if (n == out.len) return out;
    return try allocator.realloc(out, n);
}

pub fn freeAllowedThumbprints(allocator: std.mem.Allocator, pins: []const []const u8) void {
    freeAllowedSigners(allocator, pins);
}

pub fn ensureResolvedNodeTrusted(
    allocator: std.mem.Allocator,
    install_root: []const u8,
    node_exe_path: []const u8,
) VerifyOutcome {
    const data_root = resolveDataRoot(allocator, install_root) catch {
        return VerifyOutcome.failedStatic("invalid install root configuration");
    };
    defer allocator.free(data_root);

    const allowed_signers = loadAllowedSigners(allocator) catch {
        const defaults = duplicateAllowedSigners(allocator, &default_allowed_signers) catch {
            return VerifyOutcome.failedStatic("unable to load allowed code signers");
        };
        defer freeAllowedSigners(allocator, defaults);
        return ensureNodeTrusted(allocator, data_root, node_exe_path, defaults);
    };
    defer freeAllowedSigners(allocator, allowed_signers);

    return ensureNodeTrusted(allocator, data_root, node_exe_path, allowed_signers);
}

pub fn ensureNodeTrusted(
    allocator: std.mem.Allocator,
    data_root: []const u8,
    node_exe_path: []const u8,
    allowed_signers: ?[]const []const u8,
) VerifyOutcome {
    const stat = nodeFileTimes(node_exe_path) catch |err| switch (err) {
        error.FileNotFound => return VerifyOutcome.failedStatic("Node.js executable not found or inaccessible"),
        else => return VerifyOutcome.failedStatic("unable to read Node.js executable metadata"),
    };

    const pubkey = loadTrustedPublicKey(allocator, data_root) catch {
        return runFullVerify(allocator, node_exe_path, allowed_signers);
    };
    defer allocator.free(pubkey);

    const cache_key = cacheKeyForPath(allocator, node_exe_path) catch {
        return runFullVerify(allocator, node_exe_path, allowed_signers);
    };
    defer allocator.free(cache_key);

    const entry_opt = loadCacheEntry(allocator, cache_key) catch {
        return runFullVerify(allocator, node_exe_path, allowed_signers);
    };
    const entry = entry_opt orelse {
        return runFullVerify(allocator, node_exe_path, allowed_signers);
    };
    defer entry.deinit(allocator);

    const normalized = normalizeNodePath(allocator, node_exe_path) catch {
        return VerifyOutcome.failedStatic("unable to resolve Node.js executable path");
    };
    defer allocator.free(normalized);

    if (!pathsEqual(normalized, entry.path)) {
        return runFullVerifyAfterCacheChange(allocator, node_exe_path, allowed_signers, .path_changed);
    }
    if (entry.size != stat.size or entry.mtime != stat.mtime) {
        return runFullVerifyAfterCacheChange(allocator, node_exe_path, allowed_signers, .metadata_changed);
    }
    if (entry.version != config.verify_cache_schema_version) {
        return runFullVerify(allocator, node_exe_path, allowed_signers);
    }

    const live_state = nodeFileSecurityState(node_exe_path) catch {
        return runFullVerify(allocator, node_exe_path, allowed_signers);
    };
    if (live_state.volume_serial != entry.volume_serial or
        live_state.file_id != entry.file_id or
        live_state.usn != entry.usn)
    {
        return runFullVerifyAfterCacheChange(allocator, node_exe_path, allowed_signers, .identity_changed);
    }

    const payload = canonicalPayload(
        allocator,
        node_exe_path,
        stat.size,
        stat.mtime,
        entry.thumbprint,
        entry.digest,
        live_state,
    ) catch {
        return VerifyOutcome.failedStatic("unable to build verify-cache payload");
    };
    defer allocator.free(payload);

    verifyCacheSignature(pubkey, payload, entry.sig) catch {
        return runFullVerifyAfterCacheChange(allocator, node_exe_path, allowed_signers, .signature_invalid);
    };

    return .{ .result = .trusted_cache };
}

fn runFullVerify(allocator: std.mem.Allocator, node_exe_path: []const u8, allowed_signers: ?[]const []const u8) VerifyOutcome {
    const mode = loadRuntimeRevocationMode(allocator);
    wintrust.verifyAuthenticodeChain(node_exe_path, mode) catch {
        return VerifyOutcome.failedStatic("authenticode signature verification failed");
    };

    const allowed = allowed_signers orelse &default_allowed_signers;
    const effective = if (allowed.len == 0) &default_allowed_signers else allowed;

    const signer = wintrust.signerOrganization(allocator, node_exe_path) catch null orelse {
        return VerifyOutcome.failedStatic("unable to verify code signer");
    };
    defer allocator.free(signer);

    if (!wintrust.isAllowedSigner(signer, effective)) {
        var outcome = VerifyOutcome{ .result = .failed };
        const allowed_list = formatAllowedSigners(allocator, effective) catch {
            outcome.setReason("code signer \"{s}\" is not allowed", .{signer});
            return outcome;
        };
        defer allocator.free(allowed_list);
        outcome.setReason("code signer \"{s}\" is not allowed (allowed signers: {s})", .{ signer, allowed_list });
        return outcome;
    }

    const pins = loadAllowedThumbprints(allocator) catch {
        return VerifyOutcome.failedStatic("unable to load allowed thumbprints");
    };
    defer freeAllowedThumbprints(allocator, pins);
    if (pins.len > 0) {
        const thumb = wintrust.signerThumbprint(allocator, node_exe_path) catch null orelse {
            return VerifyOutcome.failedStatic("unable to resolve signer thumbprint");
        };
        defer allocator.free(thumb);
        if (!wintrust.isAllowedThumbprint(thumb, pins)) {
            var outcome = VerifyOutcome{ .result = .failed };
            outcome.setReason("signer thumbprint \"{s}\" is not pinned", .{thumb});
            return outcome;
        }
    }

    return .{ .result = .verified_full };
}

fn runFullVerifyAfterCacheChange(
    allocator: std.mem.Allocator,
    node_exe_path: []const u8,
    allowed_signers: ?[]const []const u8,
    cache_status: CacheStatus,
) VerifyOutcome {
    var outcome = runFullVerify(allocator, node_exe_path, allowed_signers);
    outcome.cache_status = cache_status;
    return outcome;
}

fn formatAllowedSigners(allocator: std.mem.Allocator, allowed: []const []const u8) ![]u8 {
    if (allowed.len == 0) return try allocator.dupe(u8, "");
    if (allowed.len == 1) return try allocator.dupe(u8, allowed[0]);

    var total: usize = 0;
    for (allowed, 0..) |signer, i| {
        total += signer.len;
        if (i + 1 < allowed.len) total += 2;
    }

    var out = try allocator.alloc(u8, total);
    errdefer allocator.free(out);

    var offset: usize = 0;
    for (allowed, 0..) |signer, i| {
        @memcpy(out[offset .. offset + signer.len], signer);
        offset += signer.len;
        if (i + 1 < allowed.len) {
            out[offset] = ',';
            out[offset + 1] = ' ';
            offset += 2;
        }
    }
    return out;
}

pub fn normalizeNodePath(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    const trimmed = std.mem.trim(u8, path, " \t\r\n");
    if (trimmed.len == 0) return error.InvalidPath;
    return std.fs.path.resolve(allocator, &.{trimmed});
}

pub fn cacheKeyForPath(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    const normalized = try normalizeNodePath(allocator, path);
    defer allocator.free(normalized);

    const lower_buf = try allocator.dupe(u8, normalized);
    defer allocator.free(lower_buf);
    for (lower_buf) |*c| c.* = std.ascii.toLower(c.*);

    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(lower_buf, &hash, .{});

    return try encodeHexLower(allocator, &hash);
}

fn encodeHexLower(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
    var out = try allocator.alloc(u8, bytes.len * 2);
    const digits = "0123456789abcdef";
    for (bytes, 0..) |byte, i| {
        out[i * 2] = digits[byte >> 4];
        out[i * 2 + 1] = digits[byte & 0x0f];
    }
    return out;
}

pub fn canonicalPayload(
    allocator: std.mem.Allocator,
    path: []const u8,
    size: i64,
    mtime: u64,
    thumbprint: []const u8,
    digest: []const u8,
    state: FileSecurityState,
) ![]u8 {
    const normalized = try normalizeNodePath(allocator, path);
    defer allocator.free(normalized);

    const lower_buf = try allocator.dupe(u8, normalized);
    defer allocator.free(lower_buf);
    for (lower_buf) |*c| c.* = std.ascii.toLower(c.*);

    const upper_thumb_buf = try allocator.dupe(u8, std.mem.trim(u8, thumbprint, " \t\r\n"));
    defer allocator.free(upper_thumb_buf);
    for (upper_thumb_buf) |*c| c.* = std.ascii.toUpper(c.*);

    const lower_digest_buf = try allocator.dupe(u8, std.mem.trim(u8, digest, " \t\r\n"));
    defer allocator.free(lower_digest_buf);
    for (lower_digest_buf) |*c| c.* = std.ascii.toLower(c.*);

    return std.fmt.allocPrint(allocator, "v3\n{s}\n{d}\n{d}\n{s}\n{s}\n{d}\n{d}\n{d}", .{
        lower_buf,
        size,
        mtime,
        upper_thumb_buf,
        lower_digest_buf,
        state.volume_serial,
        state.file_id,
        state.usn,
    });
}

pub fn fileSha256Hex(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    var file = try std.fs.openFileAbsolute(path, .{ .mode = .read_only });
    defer file.close();

    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    var buffer: [64 * 1024]u8 = undefined;
    while (true) {
        const count = try file.read(&buffer);
        if (count == 0) break;
        hash.update(buffer[0..count]);
    }

    var digest: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    hash.final(&digest);
    return encodeHexLower(allocator, &digest);
}

pub fn verifyCacheSignature(public_key_blob: []const u8, payload: []const u8, signature: []const u8) !void {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(payload, &digest, .{});

    const alg_name = try std.unicode.utf8ToUtf16LeAllocZ(std.heap.page_allocator, bcrypt_ecdsa_p256);
    defer std.heap.page_allocator.free(alg_name);
    const provider_name = try std.unicode.utf8ToUtf16LeAllocZ(std.heap.page_allocator, bcrypt_ms_primitive_provider);
    defer std.heap.page_allocator.free(provider_name);
    const blob_type = try std.unicode.utf8ToUtf16LeAllocZ(std.heap.page_allocator, bcrypt_eccpublic_blob);
    defer std.heap.page_allocator.free(blob_type);

    var alg_handle: windows.HANDLE = undefined;
    const open_rc = bcrypt.BCryptOpenAlgorithmProvider(&alg_handle, alg_name.ptr, provider_name.ptr, 0);
    if (open_rc != 0) return error.SignatureVerifyFailed;
    defer _ = bcrypt.BCryptCloseAlgorithmProvider(alg_handle, 0);

    var key_handle: windows.HANDLE = undefined;
    const import_rc = bcrypt.BCryptImportKeyPair(
        alg_handle,
        null,
        blob_type.ptr,
        &key_handle,
        public_key_blob.ptr,
        @intCast(public_key_blob.len),
        0,
    );
    if (import_rc != 0) return error.SignatureVerifyFailed;
    defer _ = bcrypt.BCryptDestroyKey(key_handle);

    const verify_rc = bcrypt.BCryptVerifySignature(
        key_handle,
        null,
        &digest,
        digest.len,
        signature.ptr,
        @intCast(signature.len),
        0,
    );
    if (verify_rc != 0) return error.SignatureVerifyFailed;
}

pub fn nodeFileTimes(path: []const u8) !NodeFileTimes {
    const path_w = try std.unicode.utf8ToUtf16LeAllocZ(std.heap.page_allocator, path);
    defer std.heap.page_allocator.free(path_w);

    var info: Win32FileAttributeData = undefined;
    if (kernel32.GetFileAttributesExW(path_w.ptr, GetFileExInfoStandard, &info) == 0) {
        return error.FileNotFound;
    }

    const size = (@as(i64, info.nFileSizeHigh) << 32) | @as(i64, info.nFileSizeLow);
    const mtime = (@as(u64, info.ftLastWriteTime.dwHighDateTime) << 32) | info.ftLastWriteTime.dwLowDateTime;
    return .{ .size = size, .mtime = mtime };
}

pub fn nodeFileSecurityState(path: []const u8) !FileSecurityState {
    var file = try std.fs.openFileAbsolute(path, .{ .mode = .read_only });
    defer file.close();

    var info: ByHandleFileInformation = undefined;
    if (kernel32.GetFileInformationByHandle(file.handle, &info) == 0) {
        return error.FileSecurityStateUnavailable;
    }

    var output: [512]u64 = undefined;
    const output_bytes = std.mem.asBytes(&output);
    var returned: u32 = 0;
    var input = ReadFileUsnData{ .min_major_version = 2, .max_major_version = 2 };
    if (kernel32.DeviceIoControl(
        file.handle,
        fsctl_read_file_usn_data,
        &input,
        @sizeOf(ReadFileUsnData),
        &output,
        @sizeOf(@TypeOf(output)),
        &returned,
        null,
    ) == 0 or returned < 32) {
        return error.FileSecurityStateUnavailable;
    }
    const major_version = std.mem.readInt(u16, output_bytes[4..6], .little);
    if (major_version != 2) return error.FileSecurityStateUnavailable;

    return .{
        .volume_serial = info.dwVolumeSerialNumber,
        .file_id = std.mem.readInt(u64, output_bytes[8..16], .little),
        .usn = std.mem.readInt(u64, output_bytes[24..32], .little),
    };
}

pub fn loadPublicKey(allocator: std.mem.Allocator, data_root: []const u8) ![]u8 {
    const pubkey_path = try std.fs.path.join(allocator, &.{ data_root, config.verify_dir_name, config.verify_pubkey_file });
    defer allocator.free(pubkey_path);

    var file = try std.fs.openFileAbsolute(pubkey_path, .{});
    defer file.close();

    const stat = try file.stat();
    if (stat.size == 0) return error.MissingPublicKey;

    const blob = try allocator.alloc(u8, stat.size);
    errdefer allocator.free(blob);

    const read_len = try file.readAll(blob);
    if (read_len != stat.size) return error.MissingPublicKey;
    return blob;
}

/// DI-01 C: accept pubkey.cer only when SHA-256 matches pubkey.sha256 from NCrypt export.
pub fn loadTrustedPublicKey(allocator: std.mem.Allocator, data_root: []const u8) ![]u8 {
    const blob = try loadPublicKey(allocator, data_root);
    errdefer allocator.free(blob);

    const fp_path = try std.fs.path.join(allocator, &.{ data_root, config.verify_dir_name, config.verify_pubkey_fingerprint_file });
    defer allocator.free(fp_path);

    var fp_file = std.fs.openFileAbsolute(fp_path, .{}) catch {
        return error.PublicKeyFingerprintMismatch;
    };
    defer fp_file.close();

    const fp_raw = fp_file.readToEndAlloc(allocator, 128) catch {
        return error.PublicKeyFingerprintMismatch;
    };
    defer allocator.free(fp_raw);

    const want = std.mem.trim(u8, fp_raw, " \t\r\n");
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(blob, &digest, .{});
    const got = try encodeHexLower(allocator, &digest);
    defer allocator.free(got);

    if (!std.ascii.eqlIgnoreCase(want, got)) {
        return error.PublicKeyFingerprintMismatch;
    }
    return blob;
}

fn loadCacheEntry(allocator: std.mem.Allocator, cache_key: []const u8) !?CacheEntry {
    const sub_key = try std.fmt.allocPrint(allocator, "{s}\\{s}\\{s}", .{
        config.preference_registry_root,
        config.verify_cache_subkey,
        cache_key,
    });
    defer allocator.free(sub_key);
    return loadCacheEntryAt(allocator, sub_key, true);
}

fn loadScriptCacheEntry(allocator: std.mem.Allocator, cache_key: []const u8) !?CacheEntry {
    const sub_key = try std.fmt.allocPrint(allocator, "{s}\\{s}\\{s}\\{s}", .{
        config.preference_registry_root,
        config.verify_cache_subkey,
        config.verify_script_cache_subkey,
        cache_key,
    });
    defer allocator.free(sub_key);
    return loadCacheEntryAt(allocator, sub_key, false);
}

fn loadCacheEntryAt(allocator: std.mem.Allocator, sub_key: []const u8, require_thumbprint: bool) !?CacheEntry {
    const hive = windows.HKEY_CURRENT_USER;

    const path = registry.queryString(allocator, hive, sub_key, "Path") catch return null;
    errdefer allocator.free(path);

    const size_dword = registry.queryDwordOptional(hive, sub_key, "Size") catch null;
    const size_qword = registry.queryQwordOptional(hive, sub_key, "Size") catch null;
    const size: ?i64 = if (size_qword) |value|
        @intCast(value)
    else if (size_dword) |value|
        @intCast(value)
    else
        null;
    if (size == null) {
        allocator.free(path);
        return null;
    }

    const mtime = registry.queryQwordOptional(hive, sub_key, "Mtime") catch null orelse {
        allocator.free(path);
        return null;
    };

    const thumbprint = if (require_thumbprint)
        registry.queryString(allocator, hive, sub_key, "Thumbprint") catch {
            allocator.free(path);
            return null;
        }
    else
        try allocator.dupe(u8, "");
    errdefer allocator.free(thumbprint);

    const digest = registry.queryString(allocator, hive, sub_key, "Digest") catch {
        allocator.free(path);
        allocator.free(thumbprint);
        return null;
    };
    errdefer allocator.free(digest);

    const volume_serial = registry.queryDwordOptional(hive, sub_key, "VolumeSerial") catch null orelse {
        allocator.free(path);
        allocator.free(thumbprint);
        allocator.free(digest);
        return null;
    };
    const file_id = registry.queryQwordOptional(hive, sub_key, "FileID") catch null orelse {
        allocator.free(path);
        allocator.free(thumbprint);
        allocator.free(digest);
        return null;
    };
    const usn = registry.queryQwordOptional(hive, sub_key, "USN") catch null orelse {
        allocator.free(path);
        allocator.free(thumbprint);
        allocator.free(digest);
        return null;
    };

    const sig = registry.queryBinaryOptional(allocator, hive, sub_key, "Sig") catch null orelse {
        allocator.free(path);
        allocator.free(thumbprint);
        allocator.free(digest);
        return null;
    };
    if (sig.len == 0) {
        allocator.free(path);
        allocator.free(thumbprint);
        allocator.free(digest);
        allocator.free(sig);
        return null;
    }

    const version = registry.queryDwordOptional(hive, sub_key, "Version") catch null orelse {
        allocator.free(path);
        allocator.free(thumbprint);
        allocator.free(digest);
        allocator.free(sig);
        return null;
    };

    return CacheEntry{
        .path = path,
        .size = size.?,
        .mtime = mtime,
        .thumbprint = thumbprint,
        .digest = digest,
        .volume_serial = volume_serial,
        .file_id = file_id,
        .usn = usn,
        .sig = sig,
        .version = version,
    };
}

pub fn canonicalScriptPayload(
    allocator: std.mem.Allocator,
    path: []const u8,
    size: i64,
    mtime: u64,
    digest: []const u8,
    state: FileSecurityState,
) ![]u8 {
    const normalized = try normalizeNodePath(allocator, path);
    defer allocator.free(normalized);

    const lower_buf = try allocator.dupe(u8, normalized);
    defer allocator.free(lower_buf);
    for (lower_buf) |*c| c.* = std.ascii.toLower(c.*);

    const lower_digest_buf = try allocator.dupe(u8, std.mem.trim(u8, digest, " \t\r\n"));
    defer allocator.free(lower_digest_buf);
    for (lower_digest_buf) |*c| c.* = std.ascii.toLower(c.*);

    return std.fmt.allocPrint(allocator, "v1-script\n{s}\n{d}\n{d}\n{s}\n{d}\n{d}\n{d}", .{
        lower_buf,
        size,
        mtime,
        lower_digest_buf,
        state.volume_serial,
        state.file_id,
        state.usn,
    });
}

/// Fail closed unless the .cmd/.bat launcher matches a TPM-signed trust entry.
pub fn ensureDelegatedScriptTrusted(
    allocator: std.mem.Allocator,
    install_root: []const u8,
    script_path: []const u8,
) VerifyOutcome {
    const data_root = resolveDataRoot(allocator, install_root) catch {
        return VerifyOutcome.failedStatic("invalid install root configuration");
    };
    defer allocator.free(data_root);

    const stat = nodeFileTimes(script_path) catch {
        return VerifyOutcome.failedStatic("delegated script not found or inaccessible");
    };
    const live_state = nodeFileSecurityState(script_path) catch {
        return VerifyOutcome.failedStatic("unable to read delegated script identity");
    };
    const digest = fileSha256Hex(allocator, script_path) catch {
        return VerifyOutcome.failedStatic("unable to hash delegated script");
    };
    defer allocator.free(digest);

    const pubkey = loadTrustedPublicKey(allocator, data_root) catch {
        return VerifyOutcome.failedStatic("delegated script trust key unavailable");
    };
    defer allocator.free(pubkey);

    const cache_key = cacheKeyForPath(allocator, script_path) catch {
        return VerifyOutcome.failedStatic("unable to resolve delegated script cache key");
    };
    defer allocator.free(cache_key);

    const entry_opt = loadScriptCacheEntry(allocator, cache_key) catch {
        return VerifyOutcome.failedStatic("unable to read delegated script trust cache");
    };
    const entry = entry_opt orelse {
        return VerifyOutcome.failedStatic("delegated script is not trusted (added after install/reshim)");
    };
    defer entry.deinit(allocator);

    if (entry.version != config.script_cache_schema_version) {
        return VerifyOutcome.failedStatic("delegated script trust cache schema mismatch");
    }

    const normalized = normalizeNodePath(allocator, script_path) catch {
        return VerifyOutcome.failedStatic("unable to resolve delegated script path");
    };
    defer allocator.free(normalized);

    if (!pathsEqual(normalized, entry.path)) {
        return VerifyOutcome.failedStatic("delegated script path mismatch");
    }
    if (entry.size != stat.size or entry.mtime != stat.mtime) {
        return VerifyOutcome.failedStatic("delegated script changed since it was trusted");
    }
    if (live_state.volume_serial != entry.volume_serial or
        live_state.file_id != entry.file_id or
        live_state.usn != entry.usn)
    {
        return VerifyOutcome.failedStatic("delegated script identity changed since it was trusted");
    }
    if (!std.ascii.eqlIgnoreCase(digest, entry.digest)) {
        return VerifyOutcome.failedStatic("delegated script digest mismatch");
    }

    const payload = canonicalScriptPayload(allocator, script_path, stat.size, stat.mtime, digest, live_state) catch {
        return VerifyOutcome.failedStatic("unable to build delegated script trust payload");
    };
    defer allocator.free(payload);

    verifyCacheSignature(pubkey, payload, entry.sig) catch {
        return VerifyOutcome.failedStatic("delegated script trust signature invalid");
    };

    return .{ .result = .trusted_cache };
}

fn pathsEqual(left: []const u8, right: []const u8) bool {
    if (std.mem.eql(u8, left, right)) return true;
    return std.ascii.eqlIgnoreCase(left, right);
}

test "VerifyOutcome setReason formats disallowed signer" {
    var outcome = VerifyOutcome{ .result = .verified_full };
    outcome.setReason("code signer \"{s}\" is not allowed (allowed signers: {s})", .{ "Evil Corp", "OpenJS Foundation, Author Software Inc." });
    try std.testing.expectEqual(VerifyResult.failed, outcome.result);
    try std.testing.expect(std.mem.startsWith(u8, outcome.reason, "code signer \"Evil Corp\""));
}

test "resolveDataRoot derives parent of install root" {
    const allocator = std.testing.allocator;
    const data_root = try resolveDataRoot(allocator, "C:\\nvm\\installs");
    defer allocator.free(data_root);
    try std.testing.expectEqualStrings("C:\\nvm", data_root);
}

test "loadAllowedSigners falls back to defaults" {
    const allocator = std.testing.allocator;
    const signers = try loadAllowedSigners(allocator);
    defer freeAllowedSigners(allocator, signers);
    try std.testing.expect(signers.len >= 3);
}

test "canonicalPayload regression" {
    const allocator = std.testing.allocator;
    const state = FileSecurityState{ .volume_serial = 42, .file_id = 123, .usn = 456 };
    const payload = try canonicalPayload(allocator, "C:\\nvm\\installs\\v22\\node.exe", 12345, 9876543210, "ABCD1234", "AABBCCDD", state);
    defer allocator.free(payload);

    try std.testing.expectEqualStrings("v3\nc:\\nvm\\installs\\v22\\node.exe\n12345\n9876543210\nABCD1234\naabbccdd\n42\n123\n456", payload);
}

test "fileSha256Hex changes with same-size content" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(.{ .sub_path = "node.exe", .data = "first" });
    const path = try tmp.dir.realpathAlloc(allocator, "node.exe");
    defer allocator.free(path);
    const first = try fileSha256Hex(allocator, path);
    defer allocator.free(first);

    try tmp.dir.writeFile(.{ .sub_path = "node.exe", .data = "other" });
    const second = try fileSha256Hex(allocator, path);
    defer allocator.free(second);

    try std.testing.expect(!std.mem.eql(u8, first, second));
}

test "nodeFileSecurityState changes after write" {
    if (@import("builtin").os.tag != .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(.{ .sub_path = "node.exe", .data = "first" });
    const path = try tmp.dir.realpathAlloc(allocator, "node.exe");
    defer allocator.free(path);
    const first = nodeFileSecurityState(path) catch return error.SkipZigTest;

    try tmp.dir.writeFile(.{ .sub_path = "node.exe", .data = "other" });
    const second = try nodeFileSecurityState(path);
    try std.testing.expect(first.file_id != second.file_id or first.usn != second.usn);
}

test "cacheKeyForPath lowercases path component" {
    const allocator = std.testing.allocator;
    const left = try cacheKeyForPath(allocator, "C:\\NVM\\installs\\v22\\node.exe");
    defer allocator.free(left);
    const right = try cacheKeyForPath(allocator, "c:\\nvm\\installs\\v22\\node.exe");
    defer allocator.free(right);

    try std.testing.expectEqualStrings(left, right);
}

test "verifyCacheSignature accepts exported fixture" {
    if (@import("builtin").os.tag != .windows) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    const fixture_root = try std.fs.path.join(allocator, &.{ "testdata", "verifycache" });
    defer allocator.free(fixture_root);

    const pubkey_path = try std.fs.path.join(allocator, &.{ fixture_root, "pubkey.cer" });
    defer allocator.free(pubkey_path);
    const payload_path = try std.fs.path.join(allocator, &.{ fixture_root, "payload.txt" });
    defer allocator.free(payload_path);
    const signature_path = try std.fs.path.join(allocator, &.{ fixture_root, "signature.bin" });
    defer allocator.free(signature_path);

    const pubkey = std.fs.cwd().readFileAlloc(allocator, pubkey_path, 1024 * 1024) catch return error.SkipZigTest;
    defer allocator.free(pubkey);
    const payload = std.fs.cwd().readFileAlloc(allocator, payload_path, 1024 * 1024) catch return error.SkipZigTest;
    defer allocator.free(payload);
    const signature = std.fs.cwd().readFileAlloc(allocator, signature_path, 1024 * 1024) catch return error.SkipZigTest;
    defer allocator.free(signature);

    try verifyCacheSignature(pubkey, payload, signature);
}
