const std = @import("std");
const common = @import("common");

pub const CpuSample = struct {
    user: u64,
    nice: u64,
    system: u64,
    idle: u64,
    iowait: u64,
    irq: u64,
    softirq: u64,
    steal: u64,

    pub fn totalTicks(self: CpuSample) u64 {
        return self.user + self.nice + self.system + self.idle + self.iowait + self.irq + self.softirq + self.steal;
    }

    pub fn busyTicks(self: CpuSample) u64 {
        return self.totalTicks() - self.idle - self.iowait;
    }
};

const MAX_CORES = 256;

pub const CpuCollector = struct {
    prev_total: ?CpuSample = null,
    prev_cores: [MAX_CORES]?CpuSample = .{null} ** MAX_CORES,
    prev_core_count: usize = 0,

    pub fn collect(self: *CpuCollector, allocator: std.mem.Allocator) !common.CpuStats {
        var buf: [16384]u8 = undefined;
        const content = try readFile("/proc/stat", &buf);

        var current_total: ?CpuSample = null;
        var current_cores: [MAX_CORES]CpuSample = undefined;
        var core_count: usize = 0;

        var lines = std.mem.splitScalar(u8, content, '\n');
        while (lines.next()) |line| {
            if (line.len == 0) continue;
            if (std.mem.startsWith(u8, line, "cpu ")) {
                current_total = parseCpuLine(line);
            } else if (std.mem.startsWith(u8, line, "cpu")) {
                if (core_count < MAX_CORES) {
                    if (parseCpuLine(line)) |sample| {
                        current_cores[core_count] = sample;
                        core_count += 1;
                    }
                }
            }
        }

        const cur = current_total orelse return error.ParseError;

        var usage: f64 = 0;
        var iowait: f64 = 0;

        if (self.prev_total) |prev| {
            const delta_total = cur.totalTicks() -| prev.totalTicks();
            if (delta_total > 0) {
                const dt: f64 = @floatFromInt(delta_total);
                usage = @as(f64, @floatFromInt(cur.busyTicks() -| prev.busyTicks())) / dt * 100.0;
                iowait = @as(f64, @floatFromInt(cur.iowait -| prev.iowait)) / dt * 100.0;
            }
        }

        var cores: std.ArrayList(common.CpuStats.CoreStats) = .{};
        errdefer cores.deinit(allocator);

        for (0..core_count) |i| {
            var core_usage: f64 = 0;
            var core_iowait: f64 = 0;

            if (i < self.prev_core_count) {
                if (self.prev_cores[i]) |prev_core| {
                    const dt_total = current_cores[i].totalTicks() -| prev_core.totalTicks();
                    if (dt_total > 0) {
                        const dt: f64 = @floatFromInt(dt_total);
                        core_usage = @as(f64, @floatFromInt(current_cores[i].busyTicks() -| prev_core.busyTicks())) / dt * 100.0;
                        core_iowait = @as(f64, @floatFromInt(current_cores[i].iowait -| prev_core.iowait)) / dt * 100.0;
                    }
                }
            }

            try cores.append(allocator, .{
                .core_id = @intCast(i),
                .usage_percent = core_usage,
                .iowait_percent = core_iowait,
            });
        }

        self.prev_total = cur;
        self.prev_core_count = core_count;
        for (0..core_count) |i| {
            self.prev_cores[i] = current_cores[i];
        }

        return .{
            .usage_percent = usage,
            .iowait_percent = iowait,
            .cores = try cores.toOwnedSlice(allocator),
        };
    }
};

fn parseCpuLine(line: []const u8) ?CpuSample {
    var iter = std.mem.tokenizeScalar(u8, line, ' ');
    _ = iter.next(); // skip "cpu" or "cpuN"

    return CpuSample{
        .user = parseU64(&iter) orelse return null,
        .nice = parseU64(&iter) orelse return null,
        .system = parseU64(&iter) orelse return null,
        .idle = parseU64(&iter) orelse return null,
        .iowait = parseU64(&iter) orelse return null,
        .irq = parseU64(&iter) orelse return null,
        .softirq = parseU64(&iter) orelse return null,
        .steal = parseU64(&iter) orelse return null,
    };
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
