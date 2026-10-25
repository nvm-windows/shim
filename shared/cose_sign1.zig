const std = @import("std");
const windows = std.os.windows;

const feed_signer_org = "Author Software Inc.";
const alg_es256: i64 = -7;
const alg_ps256: i64 = -37;
const header_alg: i64 = 1;
const header_x5chain: i64 = 33;
const x509_asn_encoding: u32 = 1;
const usage_match_and: u32 = 0;
const szoid_pkix_kp_code_signing = "1.3.6.1.5.5.7.3.3";
const cert_chain_policy_base: usize = 1;
const cert_name_attr_type: u32 = 3;
const oid_organization: [*:0]const u8 = "2.5.4.10";

const crypt32 = struct {
    pub extern "crypt32" fn CertCreateCertificateContext(
        dwCertEncodingType: u32,
        pbCertEncoded: [*]const u8,
        cbCertEncoded: u32,
    ) callconv(.winapi) ?*CertContext;

    pub extern "crypt32" fn CertFreeCertificateContext(pCertContext: *CertContext) callconv(.winapi) windows.BOOL;

    pub extern "crypt32" fn CertGetNameStringW(
        pCertContext: *CertContext,
        dwType: u32,
        dwFlags: u32,
        pvTypePara: ?*anyopaque,
        pszNameString: ?[*:0]u16,
        cchNameString: u32,
    ) callconv(.winapi) u32;

    pub extern "crypt32" fn CertGetCertificateChain(
        hChainEngine: ?*anyopaque,
        pCertContext: *CertContext,
        pTime: ?*windows.FILETIME,
        hAdditionalStore: ?windows.HANDLE,
        pChainPara: *CertChainPara,
        dwFlags: u32,
        pvReserved: ?*anyopaque,
        ppChainContext: *?*CertChainContext,
    ) callconv(.winapi) windows.BOOL;

    pub extern "crypt32" fn CertFreeCertificateChain(pChainContext: *CertChainContext) callconv(.winapi) void;

    pub extern "crypt32" fn CertVerifyCertificateChainPolicy(
        pszPolicyOID: usize,
        pChainContext: *CertChainContext,
        pPolicyPara: *CertChainPolicyPara,
        pPolicyStatus: *CertChainPolicyStatus,
    ) callconv(.winapi) windows.BOOL;

    pub extern "crypt32" fn CryptImportPublicKeyInfoEx2(
        dwCertEncodingType: u32,
        pInfo: *CertPublicKeyInfo,
        dwFlags: u32,
        pvAuxInfo: ?*anyopaque,
        phKey: *windows.HANDLE,
    ) callconv(.winapi) windows.BOOL;
};

const bcrypt = struct {
    pub extern "bcrypt" fn BCryptVerifySignature(
        hKey: windows.HANDLE,
        pPaddingInfo: ?*anyopaque,
        pbHash: [*]const u8,
        cbHash: u32,
        pbSignature: [*]const u8,
        cbSignature: u32,
        dwFlags: u32,
    ) callconv(.winapi) u32;

    pub extern "bcrypt" fn BCryptDestroyKey(hKey: windows.HANDLE) callconv(.winapi) u32;
};

const CryptoBlob = extern struct {
    cbData: u32,
    _pad0: u32 = 0,
    pbData: ?[*]u8,
};

const CryptBitBlob = extern struct {
    cbData: u32,
    _pad0: u32 = 0,
    pbData: ?[*]u8,
    cUnusedBits: u32,
    _pad1: u32 = 0,
};

const CryptAlgorithmIdentifier = extern struct {
    pszObjId: ?[*:0]u8,
    Parameters: CryptoBlob,
};

const CertPublicKeyInfo = extern struct {
    Algorithm: CryptAlgorithmIdentifier,
    PublicKey: CryptBitBlob,
};

const CertInfo = extern struct {
    dwVersion: u32,
    _pad0: u32 = 0,
    SerialNumber: CryptoBlob,
    SignatureAlgorithm: CryptAlgorithmIdentifier,
    Issuer: CryptoBlob,
    NotBefore: windows.FILETIME,
    NotAfter: windows.FILETIME,
    Subject: CryptoBlob,
    SubjectPublicKeyInfo: CertPublicKeyInfo,
};

const CertContext = extern struct {
    dwCertEncodingType: u32,
    _pad0: u32 = undefined,
    pbCertEncoded: [*]u8,
    cbCertEncoded: u32,
    _pad1: u32 = undefined,
    pCertInfo: ?*CertInfo,
    hCertStore: windows.HANDLE,
};

const CtlUsage = extern struct {
    cUsageIdentifier: u32,
    _pad0: u32 = 0,
    rgpszUsageIdentifier: ?[*]?[*:0]u8,
};

const CertUsageMatch = extern struct {
    dwType: u32,
    _pad0: u32 = 0,
    Usage: CtlUsage,
};

const CertChainPara = extern struct {
    cbSize: u32,
    _pad0: u32 = 0,
    RequestedUsage: CertUsageMatch,
};

const CertChainContext = extern struct {
    cbSize: u32,
    TrustStatus: [2]u32,
};

const CertChainPolicyPara = extern struct {
    cbSize: u32,
    dwFlags: u32,
    pvExtraPolicyPara: ?*anyopaque = null,
};

const CertChainPolicyStatus = extern struct {
    cbSize: u32,
    dwError: u32,
    lChainIndex: i32,
    lElementIndex: i32,
    pvExtraPolicyStatus: ?*anyopaque = null,
};

const BcryptPssPaddingInfo = extern struct {
    pszAlgId: [*:0]const u16,
    cbSalt: u32,
};

const sha256_alg = std.unicode.utf8ToUtf16LeStringLiteral("SHA256");

pub fn verifyAndStateHash(allocator: std.mem.Allocator, raw: []const u8) ![32]u8 {
    const msg = try parseSign1(raw);
    const alg = headerInt(msg.protected_map, header_alg) orelse headerInt(msg.unprotected_map, header_alg) orelse return error.BadCose;
    const cert_der = x5chainLeaf(msg.unprotected_map) orelse x5chainLeaf(msg.protected_map) orelse return error.BadCose;
    const to_be_signed = try encodeSigStructure(allocator, msg.protected_raw, msg.payload);
    defer allocator.free(to_be_signed);
    try verifyLeaf(allocator, cert_der, alg, to_be_signed, msg.signature);
    return try stateHashFromHead(msg.payload);
}

const Sign1 = struct {
    protected_raw: []const u8,
    protected_map: CborMap,
    unprotected_map: CborMap,
    payload: []const u8,
    signature: []const u8,
};

const CborMap = struct {
    raw: []const u8,
};

fn parseSign1(raw: []const u8) !Sign1 {
    var off: usize = 0;
    const first = try readByte(raw, &off);
    if ((first >> 5) == 6) {
        const tag = try additional(raw, first, &off);
        if (tag != 18) return error.BadCose;
    } else {
        off = 0;
    }
    const arr_head = try readByte(raw, &off);
    if ((arr_head >> 5) != 4) return error.BadCose;
    if (try additional(raw, arr_head, &off) != 4) return error.BadCose;
    const protected = try readBstr(raw, &off);
    const unprotected = try readRawMap(raw, &off);
    const payload = try readBstr(raw, &off);
    const signature = try readBstr(raw, &off);
    if (off != raw.len) return error.BadCose;
    return .{
        .protected_raw = protected,
        .protected_map = .{ .raw = protected },
        .unprotected_map = .{ .raw = unprotected },
        .payload = payload,
        .signature = signature,
    };
}

fn headerInt(map: CborMap, key: i64) ?i64 {
    var off: usize = 0;
    const n = mapCount(map.raw, &off) catch return null;
    var i: u64 = 0;
    while (i < n) : (i += 1) {
        const k = readInt(map.raw, &off) catch return null;
        if (k == key) return readInt(map.raw, &off) catch null;
        skipValue(map.raw, &off) catch return null;
    }
    return null;
}

fn x5chainLeaf(map: CborMap) ?[]const u8 {
    var off: usize = 0;
    const n = mapCount(map.raw, &off) catch return null;
    var i: u64 = 0;
    while (i < n) : (i += 1) {
        const k = readInt(map.raw, &off) catch return null;
        if (k != header_x5chain) {
            skipValue(map.raw, &off) catch return null;
            continue;
        }
        const head = peekByte(map.raw, off) catch return null;
        if ((head >> 5) == 2) return readBstr(map.raw, &off) catch null;
        if ((head >> 5) == 4) {
            const arr_n = additional(map.raw, readByte(map.raw, &off) catch return null, &off) catch return null;
            if (arr_n == 0) return null;
            return readBstr(map.raw, &off) catch null;
        }
        return null;
    }
    return null;
}

fn mapCount(raw: []const u8, off: *usize) !u64 {
    const head = try readByte(raw, off);
    if ((head >> 5) != 5) return error.BadCose;
    return additional(raw, head, off);
}

fn encodeSigStructure(allocator: std.mem.Allocator, protected: []const u8, payload: []const u8) ![]u8 {
    var buf = std.ArrayList(u8).empty;
    errdefer buf.deinit(allocator);
    try buf.append(allocator, 0x84);
    try appendTstr(&buf, allocator, "Signature1");
    try appendBstr(&buf, allocator, protected);
    try appendBstr(&buf, allocator, &.{});
    try appendBstr(&buf, allocator, payload);
    return buf.toOwnedSlice(allocator);
}

fn appendTstr(buf: *std.ArrayList(u8), allocator: std.mem.Allocator, text: []const u8) !void {
    try appendLen(buf, allocator, 3, text.len);
    try buf.appendSlice(allocator, text);
}

fn appendBstr(buf: *std.ArrayList(u8), allocator: std.mem.Allocator, bytes: []const u8) !void {
    try appendLen(buf, allocator, 2, bytes.len);
    try buf.appendSlice(allocator, bytes);
}

fn appendLen(buf: *std.ArrayList(u8), allocator: std.mem.Allocator, major: u8, len: usize) !void {
    if (len < 24) {
        try buf.append(allocator, (major << 5) | @as(u8, @intCast(len)));
        return;
    }
    if (len <= 0xff) {
        try buf.append(allocator, (major << 5) | 24);
        try buf.append(allocator, @intCast(len));
        return;
    }
    if (len <= 0xffff) {
        try buf.append(allocator, (major << 5) | 25);
        try buf.append(allocator, @intCast(len >> 8));
        try buf.append(allocator, @intCast(len & 0xff));
        return;
    }
    try buf.append(allocator, (major << 5) | 26);
    var i: u5 = 24;
    while (true) {
        try buf.append(allocator, @intCast((len >> i) & 0xff));
        if (i == 0) break;
        i -= 8;
    }
}

fn verifyLeaf(allocator: std.mem.Allocator, der: []const u8, alg: i64, to_be_signed: []const u8, signature: []const u8) !void {
    const cert = crypt32.CertCreateCertificateContext(x509_asn_encoding, der.ptr, @intCast(der.len)) orelse return error.BadCose;
    defer _ = crypt32.CertFreeCertificateContext(cert);
    try checkOrg(allocator, cert);
    try checkChain(cert);
    const info = cert.pCertInfo orelse return error.BadCose;
    var key: windows.HANDLE = undefined;
    if (crypt32.CryptImportPublicKeyInfoEx2(x509_asn_encoding, &info.SubjectPublicKeyInfo, 0, null, &key) == 0) {
        return error.BadCose;
    }
    defer _ = bcrypt.BCryptDestroyKey(key);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(to_be_signed, &digest, .{});
    var pss: BcryptPssPaddingInfo = .{ .pszAlgId = sha256_alg, .cbSalt = 32 };
    const flags: u32 = if (alg == alg_ps256) 0x00000008 else 0;
    const padding: ?*anyopaque = if (alg == alg_ps256) @ptrCast(&pss) else null;
    if (alg != alg_es256 and alg != alg_ps256) return error.BadCose;
    if (bcrypt.BCryptVerifySignature(key, padding, &digest, digest.len, signature.ptr, @intCast(signature.len), flags) != 0) {
        return error.BadCose;
    }
}

fn checkOrg(allocator: std.mem.Allocator, cert: *CertContext) !void {
    var scratch: [256:0]u16 = undefined;
    const needed = crypt32.CertGetNameStringW(
        cert,
        cert_name_attr_type,
        0,
        @ptrCast(@constCast(oid_organization)),
        &scratch,
        scratch.len,
    );
    if (needed <= 1) return error.BadCose;
    const org = try std.unicode.utf16LeToUtf8Alloc(allocator, scratch[0 .. needed - 1]);
    defer allocator.free(org);
    if (!std.mem.eql(u8, std.mem.trim(u8, org, " \t"), feed_signer_org)) return error.BadCose;
}

fn checkChain(cert: *CertContext) !void {
    var usage_oid = [_]?[*:0]u8{@constCast(szoid_pkix_kp_code_signing)};
    var para = std.mem.zeroes(CertChainPara);
    para.cbSize = @sizeOf(CertChainPara);
    para.RequestedUsage = .{
        .dwType = usage_match_and,
        .Usage = .{
            .cUsageIdentifier = 1,
            .rgpszUsageIdentifier = &usage_oid,
        },
    };
    const info = cert.pCertInfo orelse return error.BadCose;
    var when = info.NotAfter;
    if (when.dwLowDateTime != 0) when.dwLowDateTime -= 1 else {
        when.dwHighDateTime -= 1;
        when.dwLowDateTime = 0xffffffff;
    }
    var chain: ?*CertChainContext = null;
    if (crypt32.CertGetCertificateChain(null, cert, &when, null, &para, 0, null, &chain) == 0) return error.BadCose;
    const ctx = chain orelse return error.BadCose;
    defer crypt32.CertFreeCertificateChain(ctx);
    var policy_para = CertChainPolicyPara{ .cbSize = @sizeOf(CertChainPolicyPara), .dwFlags = 0 };
    var status = CertChainPolicyStatus{ .cbSize = @sizeOf(CertChainPolicyStatus), .dwError = 0, .lChainIndex = 0, .lElementIndex = 0 };
    if (crypt32.CertVerifyCertificateChainPolicy(cert_chain_policy_base, ctx, &policy_para, &status) == 0) return error.BadCose;
    if (status.dwError != 0) return error.BadCose;
}

fn stateHashFromHead(payload: []const u8) ![32]u8 {
    var off: usize = 0;
    const n = try mapCount(payload, &off);
    var i: u64 = 0;
    while (i < n) : (i += 1) {
        const k = try readInt(payload, &off);
        if (k == 5) {
            const b = try readBstr(payload, &off);
            if (b.len != 32) return error.BadCose;
            var out: [32]u8 = undefined;
            @memcpy(&out, b);
            return out;
        }
        try skipValue(payload, &off);
    }
    return error.BadCose;
}

fn readByte(raw: []const u8, off: *usize) !u8 {
    if (off.* >= raw.len) return error.BadCose;
    const b = raw[off.*];
    off.* += 1;
    return b;
}

fn peekByte(raw: []const u8, off: usize) !u8 {
    if (off >= raw.len) return error.BadCose;
    return raw[off];
}

fn additional(raw: []const u8, head: u8, off: *usize) !u64 {
    const extra = head & 0x1f;
    if (extra < 24) return extra;
    if (extra == 24) return try readByte(raw, off);
    if (extra == 25) {
        const hi = try readByte(raw, off);
        const lo = try readByte(raw, off);
        return (@as(u64, hi) << 8) | lo;
    }
    if (extra == 26) {
        var v: u64 = 0;
        var i: u8 = 0;
        while (i < 4) : (i += 1) v = (v << 8) | try readByte(raw, off);
        return v;
    }
    if (extra == 27) {
        var v: u64 = 0;
        var i: u8 = 0;
        while (i < 8) : (i += 1) v = (v << 8) | try readByte(raw, off);
        return v;
    }
    return error.BadCose;
}

fn readBstr(raw: []const u8, off: *usize) ![]const u8 {
    const head = try readByte(raw, off);
    if ((head >> 5) != 2) return error.BadCose;
    const n = try additional(raw, head, off);
    if (off.* + n > raw.len) return error.BadCose;
    const slice = raw[off.* .. off.* + @as(usize, @intCast(n))];
    off.* += @intCast(n);
    return slice;
}

fn readRawMap(raw: []const u8, off: *usize) ![]const u8 {
    const start = off.*;
    try skipValue(raw, off);
    return raw[start..off.*];
}

fn readInt(raw: []const u8, off: *usize) !i64 {
    const head = try readByte(raw, off);
    const major = head >> 5;
    const n = try additional(raw, head, off);
    if (major == 0) return @intCast(n);
    if (major == 1) return -1 - @as(i64, @intCast(n));
    return error.BadCose;
}

fn skipValue(raw: []const u8, off: *usize) !void {
    const head = try readByte(raw, off);
    const major = head >> 5;
    const n = try additional(raw, head, off);
    switch (major) {
        0, 1, 7 => {},
        2, 3 => {
            if (off.* + n > raw.len) return error.BadCose;
            off.* += @intCast(n);
        },
        4 => {
            var i: u64 = 0;
            while (i < n) : (i += 1) try skipValue(raw, off);
        },
        5 => {
            var i: u64 = 0;
            while (i < n) : (i += 1) {
                try skipValue(raw, off);
                try skipValue(raw, off);
            }
        },
        6 => try skipValue(raw, off),
        else => return error.BadCose,
    }
}

test "unsigned wrap is not trusted" {
    const payload = [_]u8{ 0xa1, 0x05, 0x58, 0x20 } ++ [_]u8{9} ++ [_]u8{0} ** 31;
    var arr = std.ArrayList(u8).empty;
    defer arr.deinit(std.testing.allocator);
    try arr.append(std.testing.allocator, 0xd8);
    try arr.append(std.testing.allocator, 18);
    try arr.append(std.testing.allocator, 0x84);
    try appendBstr(&arr, std.testing.allocator, &.{});
    try arr.append(std.testing.allocator, 0xa0);
    try appendBstr(&arr, std.testing.allocator, &payload);
    try appendBstr(&arr, std.testing.allocator, "sig");
    try std.testing.expectError(error.BadCose, verifyAndStateHash(std.testing.allocator, arr.items));
}
