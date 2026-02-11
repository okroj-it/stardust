const std = @import("std");
const common = @import("common");

const cpu_mod = @import("proc/cpu.zig");
const memory = @import("proc/memory.zig");
const swap = @import("proc/swap.zig");
const loadavg = @import("proc/loadavg.zig");
const disk = @import("proc/disk.zig");
const filesystem = @import("proc/filesystem.zig");
const network = @import("proc/network.zig");
const thermal = @import("proc/thermal.zig");
const connections = @import("proc/connections.zig");
const uptime = @import("proc/uptime.zig");

pub const Collector = struct {
    cpu: cpu_mod.CpuCollector = .{},
    hostname_buf: [256]u8 = undefined,
    agent_id: []const u8 = "local",

    pub fn init(agent_id: ?[]const u8) Collector {
        return .{ .agent_id = agent_id orelse "local" };
    }

    /// Collect all system stats and return serialized JSON.
    /// Caller must free the returned slice.
    pub fn collect(self: *Collector, allocator: std.mem.Allocator) ![]u8 {
        const hostname = self.readHostname();
        const cpu_stats = self.cpu.collect(allocator) catch |err| blk: {
            std.log.warn("cpu collect failed: {}", .{err});
            break :blk common.CpuStats{ .usage_percent = 0, .iowait_percent = 0, .cores = &.{} };
        };
        const mem_stats = memory.read() catch |err| blk: {
            std.log.warn("memory collect failed: {}", .{err});
            break :blk std.mem.zeroes(common.MemoryStats);
        };
        const swap_stats = swap.read() catch std.mem.zeroes(common.SwapStats);
        const load_stats = loadavg.read() catch std.mem.zeroes(common.LoadAverage);
        const disk_stats = disk.read(allocator) catch &.{};
        const fs_stats = filesystem.read(allocator) catch &.{};
        const net_stats = network.read(allocator) catch &.{};
        const temp_stats = thermal.read(allocator) catch &.{};
        const conn_stats = connections.read() catch std.mem.zeroes(common.ConnectionSummary);
        const uptime_secs = uptime.read() catch 0;

        const stats = common.SystemStats{
            .agent_id = self.agent_id,
            .hostname = hostname,
            .timestamp = std.time.milliTimestamp(),
            .uptime_secs = uptime_secs,
            .cpu = cpu_stats,
            .memory = mem_stats,
            .swap = swap_stats,
            .load = load_stats,
            .disks = disk_stats,
            .filesystems = fs_stats,
            .network = net_stats,
            .temperatures = temp_stats,
            .connections = conn_stats,
        };

        return common.protocol.serialize(allocator, stats);
    }

    fn readHostname(self: *Collector) []const u8 {
        const file = std.fs.openFileAbsolute("/proc/sys/kernel/hostname", .{}) catch return "unknown";
        defer file.close();
        const n = file.readAll(&self.hostname_buf) catch return "unknown";
        return std.mem.trimRight(u8, self.hostname_buf[0..n], "\n ");
    }
};
