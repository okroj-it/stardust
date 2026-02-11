const std = @import("std");
const common = @import("common");

/// Parse /proc/loadavg
/// Format: "0.06 0.04 0.01 2/819 61422\n"
pub fn read() !common.LoadAverage {
    var buf: [128]u8 = undefined;
    const content = try readFile("/proc/loadavg", &buf);
    var iter = std.mem.tokenizeScalar(u8, content, ' ');

    const one_str = iter.next() orelse return error.ParseError;
    const five_str = iter.next() orelse return error.ParseError;
    const fifteen_str = iter.next() orelse return error.ParseError;
    const procs_str = iter.next() orelse return error.ParseError;

    // Parse "2/819"
    var procs_iter = std.mem.tokenizeScalar(u8, procs_str, '/');
    const running_str = procs_iter.next() orelse return error.ParseError;
    const total_str = procs_iter.next() orelse return error.ParseError;

    return .{
        .one = std.fmt.parseFloat(f64, one_str) catch return error.ParseError,
        .five = std.fmt.parseFloat(f64, five_str) catch return error.ParseError,
        .fifteen = std.fmt.parseFloat(f64, fifteen_str) catch return error.ParseError,
        .running_processes = std.fmt.parseInt(u32, running_str, 10) catch return error.ParseError,
        .total_processes = std.fmt.parseInt(u32, total_str, 10) catch return error.ParseError,
    };
}

fn readFile(path: []const u8, buf: []u8) ![]const u8 {
    const file = try std.fs.openFileAbsolute(path, .{});
    defer file.close();
    const n = try file.readAll(buf);
    return std.mem.trimRight(u8, buf[0..n], "\n ");
}
