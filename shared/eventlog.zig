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

pub fn writeStructuredInfoJson(allocator: std.mem.Allocator, source: []const u8, event_name: []const u8, payload_json: []const u8, code: u32) void {
    writeStructuredJson(allocator, structured_operational_info_descriptor, source, event_name, payload_json, code) catch {};
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
