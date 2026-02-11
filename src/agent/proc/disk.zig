const std = @import("std");
const common = @import("common");

const MAX_DISKS = 32;

pub fn read(allocator: std.mem.Allocator) ![]const common.DiskStats {
    var buf: [8192]u8 = undefined;
    const content = try readFile("/proc/diskstats", &buf);

    var result: std.ArrayList(common.DiskStats) = .{};
    errdefer result.deinit(allocator);

    var lines = std.mem.splitScalar(u8, content, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        if (result.items.len >= MAX_DISKS) break;

        var iter = std.mem.tokenizeScalar(u8, line, ' ');
        _ = iter.next(); // major
        _ = iter.next(); // minor
        const name = iter.next() orelse continue;

        if (!isRealDisk(name)) continue;

        const reads_completed = parseU64(&iter) orelse continue;
        _ = iter.next(); // reads_merged
        const sectors_read = parseU64(&iter) orelse continue;
        const ms_reading = parseU64(&iter) orelse continue;
        const writes_completed = parseU64(&iter) orelse continue;
        _ = iter.next(); // writes_merged
        const sectors_written = parseU64(&iter) orelse continue;
        const ms_writing = parseU64(&iter) orelse continue;
        const io_in_progress = parseU64(&iter) orelse continue;
        const ms_doing_io = parseU64(&iter) orelse continue;

        try result.append(allocator, .{
            .name = try allocator.dupe(u8, name),
            .reads_completed = reads_completed,
            .writes_completed = writes_completed,
            .sectors_read = sectors_read,
            .sectors_written = sectors_written,
            .io_in_progress = io_in_progress,
            .ms_reading = ms_reading,
            .ms_writing = ms_writing,
            .ms_doing_io = ms_doing_io,
        });
    }

    return result.toOwnedSlice(allocator);
}

fn isRealDisk(name: []const u8) bool {
    if (name.len == 3 and std.mem.startsWith(u8, name, "sd")) return true;
    if (name.len == 3 and std.mem.startsWith(u8, name, "vd")) return true;
    if (name.len == 4 and std.mem.startsWith(u8, name, "xvd")) return true;
    if (std.mem.startsWith(u8, name, "nvme")) {
        if (std.mem.indexOf(u8, name[4..], "p") != null) return false;
        return true;
    }
    return false;
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
