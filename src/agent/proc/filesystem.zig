const std = @import("std");
const common = @import("common");

const MAX_FS = 32;

// Linux statfs struct for x86_64
const Statfs = extern struct {
    f_type: i64,
    f_bsize: i64,
    f_blocks: u64,
    f_bfree: u64,
    f_bavail: u64,
    f_files: u64,
    f_ffree: u64,
    f_fsid: [2]i32,
    f_namelen: i64,
    f_frsize: i64,
    f_flags: i64,
    f_spare: [4]i64,
};

const REAL_FS_TYPES = [_][]const u8{
    "ext4", "ext3", "ext2", "xfs", "btrfs", "zfs",
    "ntfs", "vfat", "fat32", "exfat", "f2fs",
    "bcachefs", "reiserfs", "jfs",
};

pub fn read(allocator: std.mem.Allocator) ![]const common.FilesystemStats {
    var buf: [8192]u8 = undefined;
    const content = try readFile("/proc/mounts", &buf);

    var result: std.ArrayListUnmanaged(common.FilesystemStats) = .{};
    errdefer result.deinit(allocator);

    var lines = std.mem.splitScalar(u8, content, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        if (result.items.len >= MAX_FS) break;

        var fields = std.mem.tokenizeScalar(u8, line, ' ');
        _ = fields.next() orelse continue; // device
        const mount_point = fields.next() orelse continue;
        const fs_type = fields.next() orelse continue;

        if (!isRealFs(fs_type)) continue;

        // Call statfs syscall
        var path_buf: [4096]u8 = undefined;
        if (mount_point.len >= path_buf.len) continue;
        @memcpy(path_buf[0..mount_point.len], mount_point);
        path_buf[mount_point.len] = 0;

        var sfs: Statfs = undefined;
        const rc = std.os.linux.syscall2(
            .statfs,
            @intFromPtr(&path_buf),
            @intFromPtr(&sfs),
        );
        if (rc > std.math.maxInt(usize) - 4096) continue; // error

        const block_size: u64 = @intCast(sfs.f_frsize);
        if (block_size == 0) continue;
        const total = sfs.f_blocks * block_size;
        const free = sfs.f_bfree * block_size;
        const avail = sfs.f_bavail * block_size;
        if (total == 0) continue;

        const used = total - free;
        const used_pct = @as(f64, @floatFromInt(used)) / @as(f64, @floatFromInt(total)) * 100.0;

        try result.append(allocator, .{
            .mount_point = try allocator.dupe(u8, mount_point),
            .fs_type = try allocator.dupe(u8, fs_type),
            .total_bytes = total,
            .free_bytes = free,
            .available_bytes = avail,
            .used_percent = used_pct,
        });
    }

    return result.toOwnedSlice(allocator);
}

fn isRealFs(fs_type: []const u8) bool {
    for (REAL_FS_TYPES) |t| {
        if (std.mem.eql(u8, fs_type, t)) return true;
    }
    return false;
}

fn readFile(path: []const u8, buf: []u8) ![]const u8 {
    const file = try std.fs.openFileAbsolute(path, .{});
    defer file.close();
    const n = try file.readAll(buf);
    return buf[0..n];
}
