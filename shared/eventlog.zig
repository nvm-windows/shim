//! Thin wrapper around the Windows Event Log API.
//!
//! Writes informational entries to the "NVM for Windows" source under the
//! Application log.  The source must be registered in the registry before
//! events can carry proper descriptions; unregistered sources fall back to
//! the generic Application log and still work - they just show a "description
//! not found" banner in Event Viewer.
//!
//! Usage:
//!   try eventlog.write(allocator, "node script.js");

const std = @import("std");
const windows = std.os.windows;

// -- Win32 types -------------------------------------------------------------

const HANDLE = windows.HANDLE;
const LPCSTR = [*:0]const u8;
const LPCWSTR = [*:0]const u16;
const WORD = u16;
const DWORD = u32;
const BOOL = windows.BOOL;

const EVENTLOG_INFORMATION_TYPE: WORD = 0x0004;

// -- Win32 imports -----------------------------------------------------------

extern "advapi32" fn RegisterEventSourceW(lpUNCServerName: ?LPCWSTR, lpSourceName: LPCWSTR) callconv(.winapi) ?HANDLE;
extern "advapi32" fn DeregisterEventSource(hEventLog: HANDLE) callconv(.winapi) BOOL;
extern "advapi32" fn ReportEventW(
    hEventLog: HANDLE,
    wType: WORD,
    wCategory: WORD,
    dwEventID: DWORD,
    lpUserSid: ?*anyopaque,
    wNumStrings: WORD,
    dwDataSize: DWORD,
    lpStrings: ?[*]LPCWSTR,
    lpRawData: ?*anyopaque,
) callconv(.winapi) BOOL;

/// Source name registered by the installer. Must match the registry key under
/// HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Application\<source>.
const source_name = "NVM for Windows";

/// Event ID for a shim execution entry.
const EVENT_ID_EXEC: DWORD = 1000;

/// Write a single informational entry to the Windows Event Log.
/// `message` is the UTF-8 string to log; it is converted to UTF-16 internally.
/// Errors are silently swallowed so logging never interrupts execution.
pub fn write(allocator: std.mem.Allocator, message: []const u8) void {
    writeImpl(allocator, message) catch {};
}

fn writeImpl(allocator: std.mem.Allocator, message: []const u8) !void {
    // Convert source name to UTF-16.
    const src_w = try std.unicode.utf8ToUtf16LeAllocZ(allocator, source_name);
    defer allocator.free(src_w);

    const h = RegisterEventSourceW(null, src_w.ptr) orelse return error.OpenFailed;
    defer _ = DeregisterEventSource(h);

    // Convert message to UTF-16.
    const msg_w = try std.unicode.utf8ToUtf16LeAllocZ(allocator, message);
    defer allocator.free(msg_w);

    const strings: [1]LPCWSTR = .{msg_w.ptr};
    _ = ReportEventW(
        h,
        EVENTLOG_INFORMATION_TYPE,
        0,
        EVENT_ID_EXEC,
        null,
        1,
        0,
        @ptrCast(@constCast(&strings)),
        null,
    );
}
