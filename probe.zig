const std = @import("std");
const wintrust = @import("shared/wintrust.zig");

test "print signer org" {
    const local_app = try std.process.getEnvVarOwned(std.testing.allocator, "LOCALAPPDATA");
    defer std.testing.allocator.free(local_app);
    const node_path = try std.fs.path.join(std.testing.allocator, &.{ local_app, "Author Software", "nvm", "installs", "v24.16.0", "node.exe" });
    defer std.testing.allocator.free(node_path);
    const signer = try wintrust.signerOrganization(std.testing.allocator, node_path);
    defer if (signer) |s| std.testing.allocator.free(s);
    if (signer) |s| std.debug.print("signer='{s}'\n", .{s}) else std.debug.print("signer=null\n", .{});
}
