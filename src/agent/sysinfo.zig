const std = @import("std");

pub const SysInfo = struct {
    os_id_buf: [64]u8 = undefined,
    os_id_len: usize = 0,
    os_version_buf: [64]u8 = undefined,
    os_version_len: usize = 0,
    os_name_buf: [256]u8 = undefined,
    os_name_len: usize = 0,
    arch_buf: [32]u8 = undefined,
    arch_len: usize = 0,
    kernel_buf: [128]u8 = undefined,
    kernel_len: usize = 0,
    cpu_model_buf: [256]u8 = undefined,
    cpu_model_len: usize = 0,
    cpu_cores: u32 = 0,
    total_ram: u64 = 0,
    pkg_manager_buf: [16]u8 = undefined,
    pkg_manager_len: usize = 0,

    pub fn collect() SysInfo {
        var info: SysInfo = .{};
        info.readOsRelease();
        info.readArch();
        info.readKernel();
        info.readCpuInfo();
        info.readMemTotal();
        info.detectPkgManager();
        return info;
    }

    pub fn osId(self: *const SysInfo) []const u8 {
        return if (self.os_id_len > 0) self.os_id_buf[0..self.os_id_len] else "unknown";
    }

    pub fn osVersion(self: *const SysInfo) []const u8 {
        return if (self.os_version_len > 0) self.os_version_buf[0..self.os_version_len] else "";
    }

    pub fn osName(self: *const SysInfo) []const u8 {
        return if (self.os_name_len > 0) self.os_name_buf[0..self.os_name_len] else "Linux";
    }

    pub fn arch(self: *const SysInfo) []const u8 {
        return if (self.arch_len > 0) self.arch_buf[0..self.arch_len] else "unknown";
    }

    pub fn kernel(self: *const SysInfo) []const u8 {
        return if (self.kernel_len > 0) self.kernel_buf[0..self.kernel_len] else "";
    }

    pub fn cpuModel(self: *const SysInfo) []const u8 {
        return if (self.cpu_model_len > 0) self.cpu_model_buf[0..self.cpu_model_len] else "unknown";
    }

    pub fn pkgManager(self: *const SysInfo) []const u8 {
        return if (self.pkg_manager_len > 0) self.pkg_manager_buf[0..self.pkg_manager_len] else "unknown";
    }

    /// Serialize to JSON. Returns slice into provided buffer.
    pub fn serialize(self: *const SysInfo, buf: []u8, agent_id: []const u8) ?[]const u8 {
        const result = std.fmt.bufPrint(buf,
            \\{{"type":"sysinfo","agent_id":"{s}","os_id":"{s}","os_version":"{s}","os_name":"{s}","arch":"{s}","kernel":"{s}","cpu_model":"{s}","cpu_cores":{d},"total_ram":{d},"pkg_manager":"{s}"}}
        , .{
            agent_id,
            self.osId(),
            self.osVersion(),
            self.osName(),
            self.arch(),
            self.kernel(),
            self.cpuModel(),
            self.cpu_cores,
            self.total_ram,
            self.pkgManager(),
        }) catch return null;
        return result;
    }

    fn readOsRelease(self: *SysInfo) void {
        const file = std.fs.openFileAbsolute("/etc/os-release", .{}) catch return;
        defer file.close();

        var read_buf: [4096]u8 = undefined;
        const n = file.readAll(&read_buf) catch return;
        const content = read_buf[0..n];

        var iter = std.mem.splitScalar(u8, content, '\n');
        while (iter.next()) |line| {
            if (self.parseField(line, "ID=", &self.os_id_buf)) |len| {
                self.os_id_len = len;
            } else if (self.parseField(line, "VERSION_ID=", &self.os_version_buf)) |len| {
                self.os_version_len = len;
            } else if (self.parseField(line, "PRETTY_NAME=", &self.os_name_buf)) |len| {
                self.os_name_len = len;
            }
        }
    }

    fn parseField(_: *const SysInfo, line: []const u8, prefix: []const u8, dest: []u8) ?usize {
        if (!std.mem.startsWith(u8, line, prefix)) return null;
        var value = line[prefix.len..];
        // Strip quotes
        if (value.len >= 2 and value[0] == '"' and value[value.len - 1] == '"') {
            value = value[1 .. value.len - 1];
        }
        if (value.len > dest.len) return null;
        @memcpy(dest[0..value.len], value);
        return value.len;
    }

    fn readArch(self: *SysInfo) void {
        const uts = std.posix.uname();
        const machine = std.mem.sliceTo(&uts.machine, 0);
        if (machine.len <= self.arch_buf.len) {
            @memcpy(self.arch_buf[0..machine.len], machine);
            self.arch_len = machine.len;
        }
    }

    fn readKernel(self: *SysInfo) void {
        const file = std.fs.openFileAbsolute("/proc/sys/kernel/osrelease", .{}) catch return;
        defer file.close();
        const n = file.readAll(&self.kernel_buf) catch return;
        self.kernel_len = std.mem.trimRight(u8, self.kernel_buf[0..n], "\n ").len;
    }

    fn readCpuInfo(self: *SysInfo) void {
        const file = std.fs.openFileAbsolute("/proc/cpuinfo", .{}) catch return;
        defer file.close();

        var read_buf: [16384]u8 = undefined;
        const n = file.readAll(&read_buf) catch return;
        const content = read_buf[0..n];

        var cores: u32 = 0;
        var got_model = false;

        var iter = std.mem.splitScalar(u8, content, '\n');
        while (iter.next()) |line| {
            if (!got_model and std.mem.startsWith(u8, line, "model name")) {
                // Find value after ": "
                if (std.mem.indexOf(u8, line, ": ")) |pos| {
                    const val = std.mem.trim(u8, line[pos + 2 ..], " \t\r");
                    if (val.len <= self.cpu_model_buf.len) {
                        @memcpy(self.cpu_model_buf[0..val.len], val);
                        self.cpu_model_len = val.len;
                        got_model = true;
                    }
                }
            }
            if (std.mem.startsWith(u8, line, "processor")) {
                cores += 1;
            }
        }
        self.cpu_cores = cores;

        // ARM64 /proc/cpuinfo lacks "model name" — try fallbacks
        if (!got_model) {
            self.readCpuModelFallback();
        }
    }

    fn readCpuModelFallback(self: *SysInfo) void {
        // Try 1: /sys/firmware/devicetree/base/model (RPi, SBCs)
        if (std.fs.openFileAbsolute("/sys/firmware/devicetree/base/model", .{})) |file| {
            defer file.close();
            const n = file.readAll(&self.cpu_model_buf) catch return;
            self.cpu_model_len = std.mem.trimRight(u8, self.cpu_model_buf[0..n], &.{ 0, '\n', ' ' }).len;
            if (self.cpu_model_len > 0) return;
        } else |_| {}

        // Try 2: "Hardware" field from /proc/cpuinfo (older ARM kernels)
        const file = std.fs.openFileAbsolute("/proc/cpuinfo", .{}) catch return;
        defer file.close();
        var read_buf: [16384]u8 = undefined;
        const n = file.readAll(&read_buf) catch return;
        var iter = std.mem.splitScalar(u8, read_buf[0..n], '\n');
        while (iter.next()) |line| {
            if (std.mem.startsWith(u8, line, "Hardware")) {
                if (std.mem.indexOf(u8, line, ": ")) |pos| {
                    const val = std.mem.trim(u8, line[pos + 2 ..], " \t\r");
                    if (val.len <= self.cpu_model_buf.len) {
                        @memcpy(self.cpu_model_buf[0..val.len], val);
                        self.cpu_model_len = val.len;
                        return;
                    }
                }
            }
        }
    }

    fn readMemTotal(self: *SysInfo) void {
        const file = std.fs.openFileAbsolute("/proc/meminfo", .{}) catch return;
        defer file.close();

        var read_buf: [4096]u8 = undefined;
        const n = file.readAll(&read_buf) catch return;
        const content = read_buf[0..n];

        var iter = std.mem.splitScalar(u8, content, '\n');
        while (iter.next()) |line| {
            if (std.mem.startsWith(u8, line, "MemTotal:")) {
                const val_str = std.mem.trim(u8, line["MemTotal:".len..], " \tkB\r\n");
                const kb = std.fmt.parseInt(u64, val_str, 10) catch return;
                self.total_ram = kb * 1024;
                return;
            }
        }
    }

    fn detectPkgManager(self: *SysInfo) void {
        const managers = [_]struct { path: []const u8, name: []const u8 }{
            .{ .path = "/usr/bin/apt-get", .name = "apt" },
            .{ .path = "/usr/bin/dnf", .name = "dnf" },
            .{ .path = "/usr/bin/yum", .name = "yum" },
            .{ .path = "/usr/bin/pacman", .name = "pacman" },
            .{ .path = "/sbin/apk", .name = "apk" },
        };

        for (managers) |mgr| {
            if (std.fs.accessAbsolute(mgr.path, .{})) |_| {
                @memcpy(self.pkg_manager_buf[0..mgr.name.len], mgr.name);
                self.pkg_manager_len = mgr.name.len;
                return;
            } else |_| {}
        }
    }
};
