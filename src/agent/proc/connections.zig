const std = @import("std");
const common = @import("common");

/// Parse /proc/net/tcp and /proc/net/tcp6 — count connections by state
/// State is column 4 (0-indexed: 3) in hex
/// 01=ESTABLISHED, 06=TIME_WAIT, 08=CLOSE_WAIT, 0A=LISTEN
pub fn read() !common.ConnectionSummary {
    var result = common.ConnectionSummary{
        .established = 0,
        .listen = 0,
        .time_wait = 0,
        .close_wait = 0,
        .total = 0,
    };

    countFromFile("/proc/net/tcp", &result);
    countFromFile("/proc/net/tcp6", &result);

    return result;
}

fn countFromFile(path: []const u8, result: *common.ConnectionSummary) void {
    var buf: [65536]u8 = undefined;
    const content = readFile(path, &buf) catch return;

    var lines = std.mem.splitScalar(u8, content, '\n');
    _ = lines.next(); // skip header

    while (lines.next()) |line| {
        if (line.len == 0) continue;
        var iter = std.mem.tokenizeAny(u8, line, " :");

        // Fields: sl, local_addr, local_port, rem_addr, rem_port, st, ...
        _ = iter.next(); // sl
        _ = iter.next(); // local_addr
        _ = iter.next(); // local_port
        _ = iter.next(); // rem_addr
        _ = iter.next(); // rem_port
        const state_str = iter.next() orelse continue;

        const state = std.fmt.parseInt(u8, state_str, 16) catch continue;
        result.total += 1;
        switch (state) {
            0x01 => result.established += 1,
            0x06 => result.time_wait += 1,
            0x08 => result.close_wait += 1,
            0x0A => result.listen += 1,
            else => {},
        }
    }
}

fn readFile(path: []const u8, buf: []u8) ![]const u8 {
    const file = try std.fs.openFileAbsolute(path, .{});
    defer file.close();
    const n = try file.readAll(buf);
    return buf[0..n];
}
