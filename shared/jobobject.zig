const builtin = @import("builtin");
const std = @import("std");
const windows = std.os.windows;

// JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE — children die when this process exits
// (last job handle closes). Stops fire-and-forget node.exe/npm.exe from
// outliving reshim and locking installs\vX\node.exe.
const JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: u32 = 0x00002000;
const JobObjectExtendedLimitInformation: i32 = 9;

const JOBOBJECT_BASIC_LIMIT_INFORMATION = extern struct {
    PerProcessUserTimeLimit: i64,
    PerJobUserTimeLimit: i64,
    LimitFlags: u32,
    _pad0: u32 = 0,
    MinimumWorkingSetSize: usize,
    MaximumWorkingSetSize: usize,
    ActiveProcessLimit: u32,
    _pad1: u32 = 0,
    Affinity: usize,
    PriorityClass: u32,
    SchedulingClass: u32,
};

const JOBOBJECT_EXTENDED_LIMIT_INFORMATION = extern struct {
    BasicLimitInformation: JOBOBJECT_BASIC_LIMIT_INFORMATION,
    IoInfo: [6]u64 = .{ 0, 0, 0, 0, 0, 0 },
    ProcessMemoryLimit: usize = 0,
    JobMemoryLimit: usize = 0,
    PeakProcessMemoryUsed: usize = 0,
    PeakJobMemoryUsed: usize = 0,
};

extern "kernel32" fn CreateJobObjectW(
    lpJobAttributes: ?*anyopaque,
    lpName: ?[*:0]const u16,
) callconv(.winapi) ?windows.HANDLE;

extern "kernel32" fn SetInformationJobObject(
    hJob: windows.HANDLE,
    JobObjectInformationClass: i32,
    lpJobObjectInformation: *anyopaque,
    cbJobObjectInformationLength: u32,
) callconv(.winapi) windows.BOOL;

extern "kernel32" fn AssignProcessToJobObject(
    hJob: windows.HANDLE,
    hProcess: windows.HANDLE,
) callconv(.winapi) windows.BOOL;

extern "kernel32" fn GetCurrentProcess() callconv(.winapi) windows.HANDLE;

/// Bind this process to a kill-on-close job. Do not CloseHandle the job:
/// closing the last handle would terminate us. Process exit releases it and
/// kills remaining children. No-op if already in a non-nestable job.
pub fn bindKillOnCloseJob() void {
    if (builtin.os.tag != .windows) return;

    const job = CreateJobObjectW(null, null) orelse return;

    var info = std.mem.zeroes(JOBOBJECT_EXTENDED_LIMIT_INFORMATION);
    info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;

    if (SetInformationJobObject(
        job,
        JobObjectExtendedLimitInformation,
        @ptrCast(&info),
        @sizeOf(JOBOBJECT_EXTENDED_LIMIT_INFORMATION),
    ) == 0) {
        return;
    }

    _ = AssignProcessToJobObject(job, GetCurrentProcess());
}
