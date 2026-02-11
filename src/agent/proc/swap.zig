const std = @import("std");
const common = @import("common");

/// Parse /proc/swaps
/// Header: Filename  Type  Size  Used  Priority
/// Data:   /swap     file  4194304  0  -2
pub fn read() !common.SwapStats {
    var buf: [2048]u8 = undefined;
    const content = readFile("/proc/swaps", &buf) catch {
        return .{ .total_bytes = 0, .used_bytes = 0, .free_bytes = 0, .used_percent = 0 };
    };

    var total: u64 = 0;
    var used: u64 = 0;

    var lines = std.mem.splitScalar(u8, content, '\n');
    _ = lines.next(); // skip header

    while (lines.next()) |line| {
        if (line.len == 0) continue;
        var iter = std.mem.tokenizeAny(u8, line, " \t");
        _ = iter.next(); // filename
        _ = iter.next(); // type
        const size_str = iter.next() orelse continue;
        const used_str = iter.next() orelse continue;

        total += std.fmt.parseInt(u64, size_str, 10) catch continue;
        used += std.fmt.parseInt(u64, used_str, 10) catch continue;
    }

    // Values in /proc/swaps are in KB
    total *= 1024;
    used *= 1024;
    const free = total -| used;
    const used_pct: f64 = if (total > 0)
        @as(f64, @floatFromInt(used)) / @as(f64, @floatFromInt(total)) * 100.0
    else
        0;

    return .{
        .total_bytes = total,
        .used_bytes = used,
        .free_bytes = free,
        .used_percent = used_pct,
    };
}

fn readFile(path: []const u8, buf: []u8) ![]const u8 {
    const file = try std.fs.openFileAbsolute(path, .{});
    defer file.close();
    const n = try file.readAll(buf);
    return buf[0..n];
}
