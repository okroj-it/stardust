const std = @import("std");
const common = @import("common");

/// Parse /proc/meminfo
/// Format: "Key:     12345 kB\n" per line
pub fn read() !common.MemoryStats {
    var buf: [4096]u8 = undefined;
    const content = try readFile("/proc/meminfo", &buf);

    var result = common.MemoryStats{
        .total_bytes = 0,
        .free_bytes = 0,
        .available_bytes = 0,
        .buffers_bytes = 0,
        .cached_bytes = 0,
        .active_bytes = 0,
        .inactive_bytes = 0,
        .used_percent = 0,
    };

    var lines = std.mem.splitScalar(u8, content, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        if (parseMemLine(line, "MemTotal:")) |v| {
            result.total_bytes = v * 1024;
        } else if (parseMemLine(line, "MemFree:")) |v| {
            result.free_bytes = v * 1024;
        } else if (parseMemLine(line, "MemAvailable:")) |v| {
            result.available_bytes = v * 1024;
        } else if (parseMemLine(line, "Buffers:")) |v| {
            result.buffers_bytes = v * 1024;
        } else if (parseMemLine(line, "Cached:")) |v| {
            result.cached_bytes = v * 1024;
        } else if (parseMemLine(line, "Active:")) |v| {
            result.active_bytes = v * 1024;
        } else if (parseMemLine(line, "Inactive:")) |v| {
            result.inactive_bytes = v * 1024;
        }
    }

    if (result.total_bytes > 0) {
        const used = result.total_bytes - result.available_bytes;
        result.used_percent = @as(f64, @floatFromInt(used)) / @as(f64, @floatFromInt(result.total_bytes)) * 100.0;
    }

    return result;
}

fn parseMemLine(line: []const u8, prefix: []const u8) ?u64 {
    if (!std.mem.startsWith(u8, line, prefix)) return null;
    const rest = std.mem.trimLeft(u8, line[prefix.len..], " ");
    var iter = std.mem.tokenizeScalar(u8, rest, ' ');
    const val_str = iter.next() orelse return null;
    return std.fmt.parseInt(u64, val_str, 10) catch return null;
}

fn readFile(path: []const u8, buf: []u8) ![]const u8 {
    const file = try std.fs.openFileAbsolute(path, .{});
    defer file.close();
    const n = try file.readAll(buf);
    return buf[0..n];
}
