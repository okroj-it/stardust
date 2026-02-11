const std = @import("std");

/// Parse /proc/uptime → uptime in seconds
/// Format: "12345.67 98765.43\n" (uptime_secs idle_secs)
pub fn read() !f64 {
    var buf: [128]u8 = undefined;
    const content = try readFile("/proc/uptime", &buf);
    var iter = std.mem.tokenizeScalar(u8, content, ' ');
    const uptime_str = iter.next() orelse return error.ParseError;
    return std.fmt.parseFloat(f64, uptime_str) catch return error.ParseError;
}

fn readFile(path: []const u8, buf: []u8) ![]const u8 {
    const file = try std.fs.openFileAbsolute(path, .{});
    defer file.close();
    const n = try file.readAll(buf);
    return std.mem.trimRight(u8, buf[0..n], "\n ");
}
