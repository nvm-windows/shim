const std = @import("std");
const windows = std.os.windows;
const config = @import("config");

const cmsg_signer_cert_info_param: u32 = 7;

const wtd_ui_choice_none: u32 = 2;
const wtd_revoke_none: u32 = 0;
const wtd_choice_file: u32 = 1;
const wtd_state_action_ignore: u32 = 0;
const wtd_prov_flags_safer: u32 = 0x00000100;
const wtd_ui_context_execute: u32 = 0;

const wintrust_action_generic_verify_v2 = windows.GUID{
    .Data1 = 0x00AAC56B,
    .Data2 = 0xCD44,
    .Data3 = 0x11D0,
    .Data4 = .{ 0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE },
};

const WintrustFileInfo = extern struct {
    cbStruct: u32,
    _pad0: u32 = undefined,
    pcwszFilePath: [*:0]u16,
    hFile: usize,
    pgKnownSubject: ?*windows.GUID,
};

// MSVC x64 layout: u32 fields before pointers/HANDLE need explicit padding.
const WintrustData = extern struct {
    cbStruct: u32,
    _pad0: u32 = undefined,
    pPolicyCallbackData: ?*anyopaque,
    pSIPClientData: ?*anyopaque,
    dwUIChoice: u32,
    fdwRevocationChecks: u32,
    dwUnionChoice: u32,
    _pad1: u32 = undefined,
    pFile: ?*WintrustFileInfo,
    dwStateAction: u32,
    _pad2: u32 = undefined,
    hWVTStateData: usize,
    pwszURLReference: ?[*:0]u16,
    dwProvFlags: u32,
    dwUIContext: u32,
    pSignatureSettings: ?*anyopaque,
};

const cert_name_attr_type: u32 = 3;
const cert_name_simple_display_type: u32 = 4;
const cert_name_flags_none: u32 = 0;
const oid_organization: [*:0]const u8 = "2.5.4.10";
const oid_common_name: [*:0]const u8 = "2.5.4.3";

const crypt32 = struct {
    pub extern "crypt32" fn CryptQueryObject(
        dwObjectType: u32,
        pvObject: ?*anyopaque,
        dwExpectedContentTypeFlags: u32,
        dwExpectedFormatTypeFlags: u32,
        dwFlags: u32,
        pdwMsgAndCertEncodingType: ?*u32,
        pdwContentType: ?*u32,
        pdwFormatType: ?*u32,
        phCertStore: ?*windows.HANDLE,
        phMsg: ?*windows.HANDLE,
        ppvContext: ?*?*anyopaque,
    ) callconv(.winapi) windows.BOOL;

    pub extern "crypt32" fn CertCloseStore(
        hCertStore: windows.HANDLE,
        dwFlags: u32,
    ) callconv(.winapi) windows.BOOL;

    pub extern "crypt32" fn CertFindCertificateInStore(
        hCertStore: windows.HANDLE,
        dwCertEncodingType: u32,
        dwFindFlags: u32,
        dwFindType: u32,
        pvFindPara: ?*anyopaque,
        pPrevCertContext: ?*anyopaque,
    ) callconv(.winapi) ?*CertContext;

    pub extern "crypt32" fn CertEnumCertificatesInStore(
        hCertStore: windows.HANDLE,
        pPrevCertContext: ?*CertContext,
    ) callconv(.winapi) ?*CertContext;

    pub extern "crypt32" fn CertCompareCertificate(
        dwCertEncodingType: u32,
        pCertInfo1: ?*anyopaque,
        pCertInfo2: ?*anyopaque,
    ) callconv(.winapi) windows.BOOL;

    pub extern "crypt32" fn CryptMsgGetParam(
        hCryptMsg: windows.HANDLE,
        dwParamType: u32,
        dwIndex: u32,
        pvData: ?*anyopaque,
        pcbData: *u32,
    ) callconv(.winapi) windows.BOOL;

    pub extern "crypt32" fn CryptMsgClose(
        hCryptMsg: windows.HANDLE,
    ) callconv(.winapi) windows.BOOL;

    pub extern "crypt32" fn CertGetNameStringW(
        pCertContext: *CertContext,
        dwType: u32,
        dwFlags: u32,
        pvTypePara: ?*anyopaque,
        pszNameString: ?[*:0]u16,
        cchNameString: u32,
    ) callconv(.winapi) u32;
};

const wintrust = struct {
    pub extern "wintrust" fn WinVerifyTrust(
        hwnd: ?*anyopaque,
        pgActionID: *const windows.GUID,
        pWVTData: *WintrustData,
    ) callconv(.winapi) i32;
};

const CertContext = extern struct {
    dwCertEncodingType: u32,
    _pad0: u32 = undefined,
    pbCertEncoded: [*]u8,
    cbCertEncoded: u32,
    _pad1: u32 = undefined,
    pCertInfo: ?*anyopaque,
    hCertStore: windows.HANDLE,
};

const cert_query_object_file: u32 = 1;
const cert_query_content_flag_pkcs7_signed_embed: u32 = 0x00000400;
const cert_query_format_flag_binary: u32 = 2;
const x509_asn_encoding: u32 = 1;
const pkcs7_asn_encoding: u32 = 0x00010000;
const cert_find_subject_cert: u32 = 7;

const default_allowed_signers = config.default_allowed_signers;

pub const VerifyError = error{
    AuthenticodeFailed,
    SignerNotFound,
    SignerNotAllowed,
    NoAllowedSigners,
};

pub fn verifyAuthenticodeChain(path: []const u8) VerifyError!void {
    const path_w = std.unicode.utf8ToUtf16LeAllocZ(std.heap.page_allocator, path) catch return error.AuthenticodeFailed;
    defer std.heap.page_allocator.free(path_w);

    var file_info = WintrustFileInfo{
        .cbStruct = @sizeOf(WintrustFileInfo),
        .pcwszFilePath = path_w.ptr,
        .hFile = 0,
        .pgKnownSubject = null,
    };

    var trust_data = WintrustData{
        .cbStruct = @sizeOf(WintrustData),
        .pPolicyCallbackData = null,
        .pSIPClientData = null,
        .dwUIChoice = wtd_ui_choice_none,
        .fdwRevocationChecks = wtd_revoke_none,
        .dwUnionChoice = wtd_choice_file,
        .pFile = &file_info,
        .dwStateAction = wtd_state_action_ignore,
        .hWVTStateData = 0,
        .pwszURLReference = null,
        .dwProvFlags = wtd_prov_flags_safer,
        .dwUIContext = wtd_ui_context_execute,
        .pSignatureSettings = null,
    };

    const rc = wintrust.WinVerifyTrust(null, &wintrust_action_generic_verify_v2, &trust_data);
    if (rc == 0) return;
    return error.AuthenticodeFailed;
}

pub fn signerOrganization(allocator: std.mem.Allocator, path: []const u8) !?[]u8 {
    const path_w = try std.unicode.utf8ToUtf16LeAllocZ(allocator, path);
    defer allocator.free(path_w);

    var cert_store: windows.HANDLE = undefined;
    var msg: windows.HANDLE = undefined;

    const ok = crypt32.CryptQueryObject(
        cert_query_object_file,
        @ptrCast(path_w.ptr),
        cert_query_content_flag_pkcs7_signed_embed,
        cert_query_format_flag_binary,
        0,
        null,
        null,
        null,
        &cert_store,
        &msg,
        null,
    );
    if (ok == 0) return null;
    defer _ = crypt32.CertCloseStore(cert_store, 0);
    defer _ = crypt32.CryptMsgClose(msg);

    var size: u32 = 0;
    if (crypt32.CryptMsgGetParam(msg, cmsg_signer_cert_info_param, 0, null, &size) == 0 or size == 0) {
        return null;
    }

    const buf = try allocator.alloc(u8, size);
    defer allocator.free(buf);

    if (crypt32.CryptMsgGetParam(msg, cmsg_signer_cert_info_param, 0, buf.ptr, &size) == 0) {
        return null;
    }

    const cert = findSignerCertificate(cert_store, buf) orelse return null;

    if (certGetSubjectAttribute(allocator, cert, oid_organization)) |organization| {
        return organization;
    }
    if (certGetSubjectAttribute(allocator, cert, oid_common_name)) |common_name| {
        return common_name;
    }
    return certGetNameByType(allocator, cert, cert_name_simple_display_type, null);
}

fn findSignerCertificate(cert_store: windows.HANDLE, signer_info: []u8) ?*CertContext {
    var prev: ?*CertContext = null;
    const encoding = x509_asn_encoding | pkcs7_asn_encoding;
    while (crypt32.CertEnumCertificatesInStore(cert_store, prev)) |cert| {
        prev = cert;
        if (cert.pCertInfo == null) continue;
        if (crypt32.CertCompareCertificate(encoding, signer_info.ptr, cert.pCertInfo) == 0) continue;
        return cert;
    }
    return null;
}

fn certGetNameByType(allocator: std.mem.Allocator, cert: *CertContext, name_type: u32, type_para: ?*anyopaque) ?[]u8 {
    var scratch: [256:0]u16 = undefined;
    const needed = crypt32.CertGetNameStringW(
        cert,
        name_type,
        cert_name_flags_none,
        type_para,
        &scratch,
        scratch.len,
    );
    if (needed <= 1) return null;

    const wide_len = needed - 1;
    const out = std.unicode.utf16LeToUtf8Alloc(allocator, scratch[0..wide_len]) catch return null;

    const trimmed = std.mem.trim(u8, out, " \t\r\n");
    if (trimmed.len == 0) {
        allocator.free(out);
        return null;
    }
    if (trimmed.len != out.len) {
        const trimmed_copy = allocator.dupe(u8, trimmed) catch {
            allocator.free(out);
            return null;
        };
        allocator.free(out);
        return trimmed_copy;
    }
    return out;
}

fn certGetSubjectAttribute(allocator: std.mem.Allocator, cert: *CertContext, oid: [*:0]const u8) ?[]u8 {
    return certGetNameByType(allocator, cert, cert_name_attr_type, @ptrCast(@constCast(oid)));
}

pub fn verifyNodeExecutable(allocator: std.mem.Allocator, path: []const u8, allowed_signers: ?[]const []const u8) VerifyError!void {
    try verifyAuthenticodeChain(path);

    const effective = blk: {
        if (allowed_signers) |signers| {
            if (signers.len > 0) break :blk signers;
        }
        break :blk &default_allowed_signers;
    };

    const signer = try signerOrganization(allocator, path) orelse return error.SignerNotFound;
    defer allocator.free(signer);

    if (!isAllowedSigner(signer, effective)) return error.SignerNotAllowed;
}

pub fn isAllowedSigner(signer: []const u8, allowed: []const []const u8) bool {
    const trimmed_signer = std.mem.trim(u8, signer, " \t\r\n");
    for (allowed) |candidate| {
        const trimmed_candidate = std.mem.trim(u8, candidate, " \t\r\n");
        if (trimmed_candidate.len == 0) continue;
        if (std.ascii.eqlIgnoreCase(trimmed_signer, trimmed_candidate)) return true;
    }
    return false;
}

test "isAllowedSigner matches case-insensitively" {
    const allowed = [_][]const u8{ "OpenJS Foundation", "Author Software Inc." };
    try std.testing.expect(isAllowedSigner("openjs foundation", &allowed));
    try std.testing.expect(!isAllowedSigner("Evil Corp", &allowed));
}

test "verifyAuthenticodeChain accepts installed node.exe when present" {
    if (@import("builtin").os.tag != .windows) return error.SkipZigTest;

    const local_app = std.process.getEnvVarOwned(std.testing.allocator, "LOCALAPPDATA") catch return error.SkipZigTest;
    defer std.testing.allocator.free(local_app);

    const node_path = std.fs.path.join(std.testing.allocator, &.{
        local_app,
        "Author Software",
        "nvm",
        "installs",
        "v24.16.0",
        "node.exe",
    }) catch return error.SkipZigTest;
    defer std.testing.allocator.free(node_path);

    std.fs.cwd().access(node_path, .{}) catch return error.SkipZigTest;

    try verifyAuthenticodeChain(node_path);

    const allowed = [_][]const u8{ "OpenJS Foundation", "Node.js Foundation", "Author Software Inc." };
    try verifyNodeExecutable(std.testing.allocator, node_path, &allowed);
}
