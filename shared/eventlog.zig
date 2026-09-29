//! Thin wrapper around the certified NVM for Windows ETW provider.
//!
//! The machine-scoped provider manifest is installed separately through admin
//! tooling. Logging failures are swallowed so shim execution is never blocked.

const std = @import("std");

const REGHANDLE = u64;

const GUID = extern struct {
    Data1: u32,
    Data2: u16,
    Data3: u16,
    Data4: [8]u8,
};

const EVENT_DESCRIPTOR = extern struct {
    Id: u16,
    Version: u8,
    Channel: u8,
    Level: u8,
    Opcode: u8,
    Task: u16,
    Keyword: u64,
};

const EVENT_DATA_DESCRIPTOR = extern struct {
    Ptr: u64,
    Size: u32,
    Reserved: u32,
};

const provider_guid = GUID{
    .Data1 = 0x4c0f8d8e,
    .Data2 = 0x2d6b,
    .Data3 = 0x4f93,
    .Data4 = .{ 0x9f, 0x0f, 0x3f, 0x0d, 0x7b, 0x4e, 0x2d, 0x11 },
};

const operational_channel: u8 = 16;
const level_error: u8 = 2;
const level_warning: u8 = 3;
const level_informational: u8 = 4;

// Manifest channel keyword base OR'd with provider keyword masks (see NVMWindows.Events.h).
const keyword_operational: u64 = 0x8000000000000001;
const keyword_execution: u64 = 0x8000000000000002;

const task_shim_execution: u16 = 2;
const task_shim_operational: u16 = 3;
const task_structured: u16 = 4;

const shim_execution_descriptor = EVENT_DESCRIPTOR{
    .Id = 200,
    .Version = 0,
    .Channel = operational_channel,
    .Level = level_informational,
    .Opcode = 0,
    .Task = task_shim_execution,
    .Keyword = keyword_execution,
};

const shim_operational_info_descriptor = EVENT_DESCRIPTOR{
    .Id = 210,
    .Version = 0,
    .Channel = operational_channel,
    .Level = level_informational,
    .Opcode = 0,
    .Task = task_shim_operational,
    .Keyword = keyword_operational,
};

const shim_operational_warning_descriptor = EVENT_DESCRIPTOR{
    .Id = 211,
    .Version = 0,
    .Channel = operational_channel,
    .Level = level_warning,
    .Opcode = 0,
    .Task = task_shim_operational,
    .Keyword = keyword_operational,
};

const shim_operational_error_descriptor = EVENT_DESCRIPTOR{
    .Id = 212,
    .Version = 0,
    .Channel = operational_channel,
    .Level = level_error,
    .Opcode = 0,
    .Task = task_shim_operational,
    .Keyword = keyword_operational,
};

const structured_operational_info_descriptor = EVENT_DESCRIPTOR{
    .Id = 120,
    .Version = 0,
    .Channel = operational_channel,
    .Level = level_informational,
    .Opcode = 0,
    .Task = task_structured,
    .Keyword = keyword_operational,
};

const structured_operational_warning_descriptor = EVENT_DESCRIPTOR{
    .Id = 121,
    .Version = 0,
    .Channel = operational_channel,
    .Level = level_warning,
    .Opcode = 0,
    .Task = task_structured,
    .Keyword = keyword_operational,
};

const structured_operational_error_descriptor = EVENT_DESCRIPTOR{
    .Id = 122,
    .Version = 0,
    .Channel = operational_channel,
    .Level = level_error,
    .Opcode = 0,
    .Task = task_structured,
    .Keyword = keyword_operational,
};

extern "advapi32" fn EventRegister(
    ProviderId: *const GUID,
    EnableCallback: ?*const anyopaque,
    CallbackContext: ?*anyopaque,
    RegHandle: *REGHANDLE,
) callconv(.winapi) u32;

extern "advapi32" fn EventWrite(
    RegHandle: REGHANDLE,
    EventDescriptor: *const EVENT_DESCRIPTOR,
    UserDataCount: u32,
    UserData: ?[*]const EVENT_DATA_DESCRIPTOR,
) callconv(.winapi) u32;

extern "advapi32" fn EventUnregister(RegHandle: REGHANDLE) callconv(.winapi) u32;

pub fn write(allocator: std.mem.Allocator, message: []const u8) void {
    writeInfo(allocator, "shim", message);
}

pub fn writeInfo(allocator: std.mem.Allocator, source: []const u8, message: []const u8) void {
    writeOperational(allocator, shim_operational_info_descriptor, source, message, 0) catch {};
}

pub fn writeInfoCode(allocator: std.mem.Allocator, source: []const u8, message: []const u8, code: u32) void {
    writeOperational(allocator, shim_operational_info_descriptor, source, message, code) catch {};
}

pub fn writeWarning(allocator: std.mem.Allocator, source: []const u8, message: []const u8) void {
    writeOperational(allocator, shim_operational_warning_descriptor, source, message, 0) catch {};
}

pub fn writeError(allocator: std.mem.Allocator, source: []const u8, message: []const u8) void {
    writeOperational(allocator, shim_operational_error_descriptor, source, message, 0) catch {};
}

pub fn writeExecution(
    allocator: std.mem.Allocator,
    requested_command: []const u8,
    resolved_path: []const u8,
    node_version: []const u8,
    arguments: []const u8,
    working_directory: []const u8,
) void {
    writeExecutionImpl(allocator, requested_command, resolved_path, node_version, arguments, working_directory) catch {};
}

pub fn writeStructuredInfo(allocator: std.mem.Allocator, source: []const u8, event_name: []const u8, payload: anytype) void {
    writeStructuredValue(allocator, structured_operational_info_descriptor, source, event_name, payload, 0) catch {};
}

pub fn writeStructuredInfoCode(allocator: std.mem.Allocator, source: []const u8, event_name: []const u8, payload: anytype, code: u32) void {
    writeStructuredValue(allocator, structured_operational_info_descriptor, source, event_name, payload, code) catch {};
}

pub fn writeStructuredWarning(allocator: std.mem.Allocator, source: []const u8, event_name: []const u8, payload: anytype) void {
    writeStructuredValue(allocator, structured_operational_warning_descriptor, source, event_name, payload, 0) catch {};
}

pub fn writeStructuredWarningCode(allocator: std.mem.Allocator, source: []const u8, event_name: []const u8, payload: anytype, code: u32) void {
    writeStructuredValue(allocator, structured_operational_warning_descriptor, source, event_name, payload, code) catch {};
}

pub fn writeStructuredError(allocator: std.mem.Allocator, source: []const u8, event_name: []const u8, payload: anytype) void {
    writeStructuredValue(allocator, structured_operational_error_descriptor, source, event_name, payload, 0) catch {};
}

pub fn writeStructuredErrorCode(allocator: std.mem.Allocator, source: []const u8, event_name: []const u8, payload: anytype, code: u32) void {
    writeStructuredValue(allocator, structured_operational_error_descriptor, source, event_name, payload, code) catch {};
}

pub fn writeLicensedSecurityError(
    allocator: std.mem.Allocator,
    structured_logging: bool,
    source: []const u8,
    event_name: []const u8,
    payload: anytype,
    plaintext: []const u8,
    code: u32,
) void {
    if (structured_logging) {
        writeStructuredErrorCode(allocator, source, event_name, payload, code);
    } else {
        writeOperational(allocator, shim_operational_error_descriptor, source, plaintext, code) catch {};
    }
}

pub fn writeLicensedSecurityWarning(
    allocator: std.mem.Allocator,
    structured_logging: bool,
    source: []const u8,
    event_name: []const u8,
    payload: anytype,
    plaintext: []const u8,
    code: u32,
) void {
    if (structured_logging) {
        writeStructuredWarningCode(allocator, source, event_name, payload, code);
    } else {
        writeOperational(allocator, shim_operational_warning_descriptor, source, plaintext, code) catch {};
    }
}

pub fn writeLicensedSecurityInfo(
    allocator: std.mem.Allocator,
    structured_logging: bool,
    source: []const u8,
    event_name: []const u8,
    payload: anytype,
    plaintext: []const u8,
    code: u32,
) void {
    if (structured_logging) {
        writeStructuredInfoCode(allocator, source, event_name, payload, code);
    } else {
        writeOperational(allocator, shim_operational_info_descriptor, source, plaintext, code) catch {};
    }
}

pub fn writeStructuredInfoJson(allocator: std.mem.Allocator, source: []const u8, event_name: []const u8, payload_json: []const u8, code: u32) void {
    writeStructuredJson(allocator, structured_operational_info_descriptor, source, event_name, payload_json, code) catch {};
}

/// Best-effort interactive user label (USERDOMAIN\\USERNAME or USERNAME).
pub fn auditUser(allocator: std.mem.Allocator) ![]const u8 {
    const domain_owned = std.process.getEnvVarOwned(allocator, "USERDOMAIN") catch null;
    defer if (domain_owned) |d| allocator.free(d);
    const user_owned = std.process.getEnvVarOwned(allocator, "USERNAME") catch null;
    defer if (user_owned) |u| allocator.free(u);

    if (domain_owned) |domain| {
        if (user_owned) |user| {
            if (domain.len > 0 and user.len > 0) {
                return std.fmt.allocPrint(allocator, "{s}\\{s}", .{ domain, user });
            }
        }
    }
    if (user_owned) |user| {
        if (user.len > 0) return allocator.dupe(u8, user);
    }
    return allocator.dupe(u8, "unknown");
}

/// Best-effort host label (COMPUTERNAME).
pub fn auditHostname(allocator: std.mem.Allocator) ![]const u8 {
    const computer = std.process.getEnvVarOwned(allocator, "COMPUTERNAME") catch null;
    defer if (computer) |c| allocator.free(c);
    if (computer) |name| {
        if (name.len > 0) return allocator.dupe(u8, name);
    }
    return allocator.dupe(u8, "unknown");
}

const TOKEN_QUERY: u32 = 0x0008;
const TokenUser: i32 = 1;
const TH32CS_SNAPPROCESS: u32 = 0x00000002;

const SID_AND_ATTRIBUTES = extern struct {
    Sid: ?*anyopaque,
    Attributes: u32,
};

const TOKEN_USER = extern struct {
    User: SID_AND_ATTRIBUTES,
};

const PROCESSENTRY32W = extern struct {
    dwSize: u32,
    cntUsage: u32,
    th32ProcessID: u32,
    th32DefaultHeapID: usize,
    th32ModuleID: u32,
    cntThreads: u32,
    th32ParentProcessID: u32,
    pcPriClassBase: i32,
    dwFlags: u32,
    szExeFile: [260]u16,
};

extern "kernel32" fn GetCurrentProcess() callconv(.winapi) *anyopaque;
extern "kernel32" fn GetCurrentProcessId() callconv(.winapi) u32;
extern "kernel32" fn CreateToolhelp32Snapshot(dwFlags: u32, th32ProcessID: u32) callconv(.winapi) *anyopaque;
extern "kernel32" fn Process32FirstW(hSnapshot: *anyopaque, lppe: *PROCESSENTRY32W) callconv(.winapi) u32;
extern "kernel32" fn Process32NextW(hSnapshot: *anyopaque, lppe: *PROCESSENTRY32W) callconv(.winapi) u32;
extern "kernel32" fn CloseHandle(hObject: *anyopaque) callconv(.winapi) u32;
extern "kernel32" fn OpenProcess(dwDesiredAccess: u32, bInheritHandle: i32, dwProcessId: u32) callconv(.winapi) ?*anyopaque;
extern "kernel32" fn QueryFullProcessImageNameW(
    hProcess: *anyopaque,
    dwFlags: u32,
    lpExeName: [*]u16,
    lpdwSize: *u32,
) callconv(.winapi) u32;
extern "kernel32" fn CreateEventW(
    lpEventAttributes: ?*anyopaque,
    bManualReset: i32,
    bInitialState: i32,
    lpName: [*:0]const u16,
) callconv(.winapi) ?*anyopaque;
extern "kernel32" fn WaitForSingleObject(hHandle: *anyopaque, dwMilliseconds: u32) callconv(.winapi) u32;
extern "advapi32" fn OpenProcessToken(ProcessHandle: *anyopaque, DesiredAccess: u32, TokenHandle: *?*anyopaque) callconv(.winapi) u32;
extern "advapi32" fn GetTokenInformation(
    TokenHandle: *anyopaque,
    TokenInformationClass: i32,
    TokenInformation: ?*anyopaque,
    TokenInformationLength: u32,
    ReturnLength: *u32,
) callconv(.winapi) u32;
extern "advapi32" fn ConvertSidToStringSidW(Sid: ?*anyopaque, StringSid: *?[*:0]u16) callconv(.winapi) u32;
extern "kernel32" fn LocalFree(hMem: ?*anyopaque) callconv(.winapi) ?*anyopaque;

fn invalidSnapshotHandle(h: *anyopaque) bool {
    return @intFromPtr(h) == @as(usize, @bitCast(@as(isize, -1)));
}

/// Best-effort Windows SID string for the current process token.
pub fn auditSid(allocator: std.mem.Allocator) ![]u8 {
    var token: ?*anyopaque = null;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token) == 0 or token == null) {
        return allocator.dupe(u8, "unknown");
    }
    defer _ = CloseHandle(token.?);

    var needed: u32 = 0;
    _ = GetTokenInformation(token.?, TokenUser, null, 0, &needed);
    if (needed == 0) return allocator.dupe(u8, "unknown");

    const buf = allocator.alloc(u8, needed) catch return allocator.dupe(u8, "unknown");
    defer allocator.free(buf);

    if (GetTokenInformation(token.?, TokenUser, buf.ptr, needed, &needed) == 0) {
        return allocator.dupe(u8, "unknown");
    }

    const token_user: *const TOKEN_USER = @ptrCast(@alignCast(buf.ptr));
    const sid = token_user.User.Sid orelse return allocator.dupe(u8, "unknown");

    var sid_w: ?[*:0]u16 = null;
    if (ConvertSidToStringSidW(sid, &sid_w) == 0 or sid_w == null) {
        return allocator.dupe(u8, "unknown");
    }
    defer _ = LocalFree(sid_w);

    return std.unicode.utf16LeToUtf8Alloc(allocator, std.mem.span(sid_w.?)) catch allocator.dupe(u8, "unknown");
}

/// Parent process executable file name and PID (Toolhelp32).
pub const AuditParentProcess = struct { name: []u8, pid: u32 };

pub fn auditParentProcess(allocator: std.mem.Allocator) !AuditParentProcess {
    const self_pid = GetCurrentProcessId();
    const snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (invalidSnapshotHandle(snapshot)) {
        return .{
            .name = try allocator.dupe(u8, "unknown"),
            .pid = 0,
        };
    }
    defer _ = CloseHandle(snapshot);

    var entry: PROCESSENTRY32W = undefined;
    entry.dwSize = @sizeOf(PROCESSENTRY32W);

    var parent_pid: u32 = 0;
    if (Process32FirstW(snapshot, &entry) != 0) {
        while (true) {
            if (entry.th32ProcessID == self_pid) {
                parent_pid = entry.th32ParentProcessID;
                break;
            }
            if (Process32NextW(snapshot, &entry) == 0) break;
        }
    }

    if (parent_pid == 0) {
        return .{
            .name = try allocator.dupe(u8, "unknown"),
            .pid = 0,
        };
    }

    entry.dwSize = @sizeOf(PROCESSENTRY32W);
    if (Process32FirstW(snapshot, &entry) != 0) {
        while (true) {
            if (entry.th32ProcessID == parent_pid) {
                const exe_w = std.mem.sliceTo(&entry.szExeFile, 0);
                const exe = std.unicode.utf16LeToUtf8Alloc(allocator, exe_w) catch try allocator.dupe(u8, "unknown");
                return .{ .name = exe, .pid = parent_pid };
            }
            if (Process32NextW(snapshot, &entry) == 0) break;
        }
    }

    return .{
        .name = try allocator.dupe(u8, "unknown"),
        .pid = parent_pid,
    };
}

const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;

fn parentPidFromSnapshot(snapshot: *anyopaque, pid: u32) u32 {
    var entry: PROCESSENTRY32W = undefined;
    entry.dwSize = @sizeOf(PROCESSENTRY32W);
    if (Process32FirstW(snapshot, &entry) == 0) return 0;
    while (true) {
        if (entry.th32ProcessID == pid) return entry.th32ParentProcessID;
        if (Process32NextW(snapshot, &entry) == 0) return 0;
    }
}

fn queryProcessImagePath(allocator: std.mem.Allocator, pid: u32) ?[]u8 {
    const handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) orelse return null;
    defer _ = CloseHandle(handle);
    var buf: [1024]u16 = undefined;
    var size: u32 = buf.len;
    if (QueryFullProcessImageNameW(handle, 0, &buf, &size) == 0 or size == 0) return null;
    return std.unicode.utf16LeToUtf8Alloc(allocator, buf[0..size]) catch null;
}

pub fn freeAncestorImagePaths(allocator: std.mem.Allocator, paths: [][]u8) void {
    for (paths) |p| allocator.free(p);
    allocator.free(paths);
}

/// Full image paths of ancestor processes (parent first), best-effort.
pub fn listAncestorImagePaths(allocator: std.mem.Allocator) ![][]u8 {
    var list: std.ArrayListUnmanaged([]u8) = .{};
    errdefer {
        for (list.items) |p| allocator.free(p);
        list.deinit(allocator);
    }

    const snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (invalidSnapshotHandle(snapshot)) return try list.toOwnedSlice(allocator);
    defer _ = CloseHandle(snapshot);

    var pid = GetCurrentProcessId();
    var hops: u8 = 0;
    var seen: [32]u32 = undefined;
    var seen_len: usize = 0;

    while (hops < 32) : (hops += 1) {
        const parent = parentPidFromSnapshot(snapshot, pid);
        if (parent == 0 or parent == pid) break;
        var dup = false;
        for (seen[0..seen_len]) |s| {
            if (s == parent) {
                dup = true;
                break;
            }
        }
        if (dup) break;
        if (seen_len < seen.len) {
            seen[seen_len] = parent;
            seen_len += 1;
        }
        if (queryProcessImagePath(allocator, parent)) |path| {
            try list.append(allocator, path);
        }
        pid = parent;
    }

    return try list.toOwnedSlice(allocator);
}

pub fn createNamedEvent(allocator: std.mem.Allocator, name: []const u8) ?*anyopaque {
    const name_w = std.unicode.utf8ToUtf16LeAllocZ(allocator, name) catch return null;
    defer allocator.free(name_w);
    return CreateEventW(null, 1, 0, name_w.ptr);
}

pub fn waitAndCloseNamedEvent(handle: *anyopaque, timeout_ms: u32) void {
    _ = WaitForSingleObject(handle, timeout_ms);
    _ = CloseHandle(handle);
}

fn scanPackageJsonName(allocator: std.mem.Allocator, content: []const u8) ![]u8 {
    const marker = "\"name\"";
    var i: usize = 0;
    while (i + marker.len <= content.len) : (i += 1) {
        if (!std.mem.eql(u8, content[i .. i + marker.len], marker)) continue;
        var j = i + marker.len;
        while (j < content.len and std.ascii.isWhitespace(content[j])) : (j += 1) {}
        if (j >= content.len or content[j] != ':') continue;
        j += 1;
        while (j < content.len and std.ascii.isWhitespace(content[j])) : (j += 1) {}
        if (j >= content.len or content[j] != '"') continue;
        j += 1;
        const start = j;
        while (j < content.len and content[j] != '"') : (j += 1) {
            if (content[j] == '\\') j += 1;
        }
        if (j >= content.len) return allocator.dupe(u8, "");
        return allocator.dupe(u8, content[start..j]);
    }
    return allocator.dupe(u8, "");
}

/// Nearest package.json `"name"` walking cwd toward drive root.
pub const AuditProject = struct { name: []u8, path: []u8 };

pub fn auditProjectName(allocator: std.mem.Allocator) !AuditProject {
    var dir = std.process.getCwdAlloc(allocator) catch {
        return .{
            .name = try allocator.dupe(u8, ""),
            .path = try allocator.dupe(u8, ""),
        };
    };
    defer allocator.free(dir);

    while (true) {
        const pkg_path = std.fs.path.join(allocator, &.{ dir, "package.json" }) catch break;
        defer allocator.free(pkg_path);

        if (std.fs.cwd().openFile(pkg_path, .{})) |file| {
            defer file.close();
            const content = file.readToEndAlloc(allocator, 1024 * 1024) catch {
                break;
            };
            defer allocator.free(content);
            const name = scanPackageJsonName(allocator, content) catch try allocator.dupe(u8, "");
            if (name.len > 0) {
                return .{
                    .name = name,
                    .path = try allocator.dupe(u8, pkg_path),
                };
            }
        } else |_| {}

        const parent = std.fs.path.dirname(dir) orelse break;
        if (parent.len == dir.len) break;
        const next = allocator.dupe(u8, parent) catch break;
        allocator.free(dir);
        dir = next;
    }

    return .{
        .name = try allocator.dupe(u8, ""),
        .path = try allocator.dupe(u8, ""),
    };
}

pub const AuditContext = struct {
    user: []const u8,
    sid: []const u8,
    hostname: []const u8,
    parent_process: []const u8,
    parent_pid: u32,
    project_name: []const u8,
    project_path: []const u8,

    pub fn deinit(self: *AuditContext, allocator: std.mem.Allocator) void {
        allocator.free(self.user);
        allocator.free(self.sid);
        allocator.free(self.hostname);
        allocator.free(self.parent_process);
        allocator.free(self.project_name);
        allocator.free(self.project_path);
    }
};

pub fn captureAuditContext(allocator: std.mem.Allocator) AuditContext {
    const user = auditUser(allocator) catch allocator.dupe(u8, "unknown") catch "";
    const sid = auditSid(allocator) catch allocator.dupe(u8, "unknown") catch "";
    const hostname = auditHostname(allocator) catch allocator.dupe(u8, "unknown") catch "";
    const parent = auditParentProcess(allocator) catch AuditParentProcess{
        .name = allocator.dupe(u8, "unknown") catch "",
        .pid = 0,
    };
    const project = auditProjectName(allocator) catch AuditProject{
        .name = allocator.dupe(u8, "") catch "",
        .path = allocator.dupe(u8, "") catch "",
    };

    return .{
        .user = user,
        .sid = sid,
        .hostname = hostname,
        .parent_process = parent.name,
        .parent_pid = parent.pid,
        .project_name = project.name,
        .project_path = project.path,
    };
}

pub fn writeStructuredWarningJson(allocator: std.mem.Allocator, source: []const u8, event_name: []const u8, payload_json: []const u8, code: u32) void {
    writeStructuredJson(allocator, structured_operational_warning_descriptor, source, event_name, payload_json, code) catch {};
}

pub fn writeStructuredErrorJson(allocator: std.mem.Allocator, source: []const u8, event_name: []const u8, payload_json: []const u8, code: u32) void {
    writeStructuredJson(allocator, structured_operational_error_descriptor, source, event_name, payload_json, code) catch {};
}

// ExampleStructuredUsage demonstrates a custom structured shim event payload.
pub fn ExampleStructuredUsage(allocator: std.mem.Allocator) void {
    const payload = .{
        .requested_version = "24.0.0",
        .action = "autoinstall",
        .resolver = "registry",
    };
    writeStructuredInfoCode(allocator, "node-shim", "node.resolve.started", payload, 4201);
}

fn writeOperational(
    allocator: std.mem.Allocator,
    descriptor: EVENT_DESCRIPTOR,
    source: []const u8,
    message: []const u8,
    code: u32,
) !void {
    var handle: REGHANDLE = 0;
    if (EventRegister(&provider_guid, null, null, &handle) != 0) return error.OpenFailed;
    defer _ = EventUnregister(handle);

    const source_w = try std.unicode.utf8ToUtf16LeAllocZ(allocator, source);
    defer allocator.free(source_w);
    const message_w = try std.unicode.utf8ToUtf16LeAllocZ(allocator, message);
    defer allocator.free(message_w);

    const descriptors = [_]EVENT_DATA_DESCRIPTOR{
        utf16Descriptor(source_w),
        utf16Descriptor(message_w),
        scalarDescriptor(&code, @sizeOf(u32)),
    };

    _ = EventWrite(handle, &descriptor, descriptors.len, @ptrCast(&descriptors));
}

fn writeExecutionImpl(
    allocator: std.mem.Allocator,
    requested_command: []const u8,
    resolved_path: []const u8,
    node_version: []const u8,
    arguments: []const u8,
    working_directory: []const u8,
) !void {
    var handle: REGHANDLE = 0;
    if (EventRegister(&provider_guid, null, null, &handle) != 0) return error.OpenFailed;
    defer _ = EventUnregister(handle);

    const requested_command_w = try std.unicode.utf8ToUtf16LeAllocZ(allocator, requested_command);
    defer allocator.free(requested_command_w);
    const resolved_path_w = try std.unicode.utf8ToUtf16LeAllocZ(allocator, resolved_path);
    defer allocator.free(resolved_path_w);
    const node_version_w = try std.unicode.utf8ToUtf16LeAllocZ(allocator, node_version);
    defer allocator.free(node_version_w);
    const arguments_w = try std.unicode.utf8ToUtf16LeAllocZ(allocator, arguments);
    defer allocator.free(arguments_w);
    const working_directory_w = try std.unicode.utf8ToUtf16LeAllocZ(allocator, working_directory);
    defer allocator.free(working_directory_w);

    const descriptors = [_]EVENT_DATA_DESCRIPTOR{
        utf16Descriptor(requested_command_w),
        utf16Descriptor(resolved_path_w),
        utf16Descriptor(node_version_w),
        utf16Descriptor(arguments_w),
        utf16Descriptor(working_directory_w),
    };

    _ = EventWrite(handle, &shim_execution_descriptor, descriptors.len, @ptrCast(&descriptors));
}

fn writeStructuredJson(
    allocator: std.mem.Allocator,
    descriptor: EVENT_DESCRIPTOR,
    source: []const u8,
    event_name: []const u8,
    payload_json: []const u8,
    code: u32,
) !void {
    if (source.len == 0 or event_name.len == 0) return;

    var handle: REGHANDLE = 0;
    if (EventRegister(&provider_guid, null, null, &handle) != 0) return error.OpenFailed;
    defer _ = EventUnregister(handle);

    const source_w = try std.unicode.utf8ToUtf16LeAllocZ(allocator, source);
    defer allocator.free(source_w);
    const event_name_w = try std.unicode.utf8ToUtf16LeAllocZ(allocator, event_name);
    defer allocator.free(event_name_w);
    const payload_json_w = try std.unicode.utf8ToUtf16LeAllocZ(allocator, payload_json);
    defer allocator.free(payload_json_w);

    const descriptors = [_]EVENT_DATA_DESCRIPTOR{
        utf16Descriptor(source_w),
        utf16Descriptor(event_name_w),
        utf16Descriptor(payload_json_w),
        scalarDescriptor(&code, @sizeOf(u32)),
    };

    _ = EventWrite(handle, &descriptor, descriptors.len, @ptrCast(&descriptors));
}

fn writeStructuredValue(
    allocator: std.mem.Allocator,
    descriptor: EVENT_DESCRIPTOR,
    source: []const u8,
    event_name: []const u8,
    payload: anytype,
    code: u32,
) !void {
    const payload_json = try stringifyPayload(allocator, payload);
    defer allocator.free(payload_json);

    try writeStructuredJson(allocator, descriptor, source, event_name, payload_json, code);
}

fn stringifyPayload(allocator: std.mem.Allocator, payload: anytype) ![]u8 {
    return try std.fmt.allocPrint(allocator, "{f}", .{std.json.fmt(payload, .{})});
}

fn utf16Descriptor(value: [:0]const u16) EVENT_DATA_DESCRIPTOR {
    return .{
        .Ptr = @intFromPtr(value.ptr),
        .Size = @as(u32, @intCast((value.len + 1) * @sizeOf(u16))),
        .Reserved = 0,
    };
}

fn scalarDescriptor(value: *const u32, comptime size: usize) EVENT_DATA_DESCRIPTOR {
    return .{
        .Ptr = @intFromPtr(value),
        .Size = @as(u32, @intCast(size)),
        .Reserved = 0,
    };
}
