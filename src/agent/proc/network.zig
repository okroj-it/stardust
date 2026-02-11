const std = @import("std");
const common = @import("common");

const MAX_INTERFACES = 32;

pub fn read(allocator: std.mem.Allocator) ![]const common.NetworkInterface {
    var buf: [4096]u8 = undefined;
    const content = try readFile("/proc/net/dev", &buf);

    var result: std.ArrayList(common.NetworkInterface) = .{};
    errdefer result.deinit(allocator);

    var lines = std.mem.splitScalar(u8, content, '\n');
    _ = lines.next(); // skip header 1
    _ = lines.next(); // skip header 2

    while (lines.next()) |line| {
        if (line.len == 0) continue;
        if (result.items.len >= MAX_INTERFACES) break;

        const colon_pos = std.mem.indexOf(u8, line, ":") orelse continue;
        const name = std.mem.trim(u8, line[0..colon_pos], " ");
        if (std.mem.eql(u8, name, "lo")) continue;

        var iter = std.mem.tokenizeScalar(u8, line[colon_pos + 1 ..], ' ');

        const rx_bytes = parseU64(&iter) orelse continue;
        const rx_packets = parseU64(&iter) orelse continue;
        const rx_errors = parseU64(&iter) orelse continue;
        const rx_dropped = parseU64(&iter) orelse continue;
        _ = iter.next(); // rx_fifo
        _ = iter.next(); // rx_frame
        _ = iter.next(); // rx_compressed
        _ = iter.next(); // rx_multicast
        const tx_bytes = parseU64(&iter) orelse continue;
        const tx_packets = parseU64(&iter) orelse continue;
        const tx_errors = parseU64(&iter) orelse continue;
        const tx_dropped = parseU64(&iter) orelse continue;

        try result.append(allocator, .{
            .name = try allocator.dupe(u8, name),
            .rx_bytes = rx_bytes,
            .rx_packets = rx_packets,
            .rx_errors = rx_errors,
            .rx_dropped = rx_dropped,
            .tx_bytes = tx_bytes,
            .tx_packets = tx_packets,
            .tx_errors = tx_errors,
            .tx_dropped = tx_dropped,
        });
    }

    return result.toOwnedSlice(allocator);
}

fn parseU64(iter: *std.mem.TokenIterator(u8, .scalar)) ?u64 {
    const s = iter.next() orelse return null;
    return std.fmt.parseInt(u64, s, 10) catch return null;
}

fn readFile(path: []const u8, buf: []u8) ![]const u8 {
    const file = try std.fs.openFileAbsolute(path, .{});
    defer file.close();
    const n = try file.readAll(buf);
    return buf[0..n];
}
