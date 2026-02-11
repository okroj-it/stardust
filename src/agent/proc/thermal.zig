const std = @import("std");
const common = @import("common");

const MAX_ZONES = 16;

pub fn read(allocator: std.mem.Allocator) ![]const common.Temperature {
    var result: std.ArrayList(common.Temperature) = .{};
    errdefer result.deinit(allocator);

    var dir = std.fs.openDirAbsolute("/sys/class/thermal", .{ .iterate = true }) catch {
        return result.toOwnedSlice(allocator);
    };
    defer dir.close();

    var iter = dir.iterate();
    while (try iter.next()) |entry| {
        if (!std.mem.startsWith(u8, entry.name, "thermal_zone")) continue;
        if (result.items.len >= MAX_ZONES) break;

        const temp = readZoneTemp(dir, entry.name) orelse continue;
        const label = readZoneType(dir, entry.name) orelse "unknown";

        try result.append(allocator, .{
            .zone = try allocator.dupe(u8, entry.name),
            .label = try allocator.dupe(u8, label),
            .temp_celsius = temp,
        });
    }

    return result.toOwnedSlice(allocator);
}

fn readZoneTemp(dir: std.fs.Dir, zone_name: []const u8) ?f64 {
    var path_buf: [256]u8 = undefined;
    const path = std.fmt.bufPrint(&path_buf, "{s}/temp", .{zone_name}) catch return null;

    var buf: [32]u8 = undefined;
    const file = dir.openFile(path, .{}) catch return null;
    defer file.close();
    const n = file.readAll(&buf) catch return null;
    const content = std.mem.trimRight(u8, buf[0..n], "\n ");
    const millideg = std.fmt.parseInt(i64, content, 10) catch return null;
    return @as(f64, @floatFromInt(millideg)) / 1000.0;
}

fn readZoneType(dir: std.fs.Dir, zone_name: []const u8) ?[]const u8 {
    var path_buf: [256]u8 = undefined;
    const path = std.fmt.bufPrint(&path_buf, "{s}/type", .{zone_name}) catch return null;

    var buf: [128]u8 = undefined;
    const file = dir.openFile(path, .{}) catch return null;
    defer file.close();
    const n = file.readAll(&buf) catch return null;
    return std.mem.trimRight(u8, buf[0..n], "\n ");
}
