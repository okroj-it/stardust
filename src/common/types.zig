const std = @import("std");

pub const Timestamp = i64; // Unix epoch milliseconds

pub const SystemStats = struct {
    agent_id: []const u8,
    hostname: []const u8,
    timestamp: Timestamp,
    uptime_secs: f64,
    cpu: CpuStats,
    memory: MemoryStats,
    swap: SwapStats,
    load: LoadAverage,
    disks: []const DiskStats,
    filesystems: []const FilesystemStats,
    network: []const NetworkInterface,
    temperatures: []const Temperature,
    connections: ConnectionSummary,
};

pub const CpuStats = struct {
    usage_percent: f64,
    iowait_percent: f64,
    cores: []const CoreStats,

    pub const CoreStats = struct {
        core_id: u32,
        usage_percent: f64,
        iowait_percent: f64,
    };
};

pub const MemoryStats = struct {
    total_bytes: u64,
    free_bytes: u64,
    available_bytes: u64,
    buffers_bytes: u64,
    cached_bytes: u64,
    active_bytes: u64,
    inactive_bytes: u64,
    used_percent: f64,
};

pub const SwapStats = struct {
    total_bytes: u64,
    used_bytes: u64,
    free_bytes: u64,
    used_percent: f64,
};

pub const LoadAverage = struct {
    one: f64,
    five: f64,
    fifteen: f64,
    running_processes: u32,
    total_processes: u32,
};

pub const DiskStats = struct {
    name: []const u8,
    reads_completed: u64,
    writes_completed: u64,
    sectors_read: u64,
    sectors_written: u64,
    io_in_progress: u64,
    ms_reading: u64,
    ms_writing: u64,
    ms_doing_io: u64,
};

pub const FilesystemStats = struct {
    mount_point: []const u8,
    fs_type: []const u8,
    total_bytes: u64,
    free_bytes: u64,
    available_bytes: u64,
    used_percent: f64,
};

pub const NetworkInterface = struct {
    name: []const u8,
    rx_bytes: u64,
    rx_packets: u64,
    rx_errors: u64,
    rx_dropped: u64,
    tx_bytes: u64,
    tx_packets: u64,
    tx_errors: u64,
    tx_dropped: u64,
};

pub const Temperature = struct {
    zone: []const u8,
    label: []const u8,
    temp_celsius: f64,
};

pub const ConnectionSummary = struct {
    established: u32,
    listen: u32,
    time_wait: u32,
    close_wait: u32,
    total: u32,
};

test "types compile" {
    const stats = SystemStats{
        .agent_id = "test",
        .hostname = "localhost",
        .timestamp = 0,
        .uptime_secs = 0,
        .cpu = .{ .usage_percent = 0, .iowait_percent = 0, .cores = &.{} },
        .memory = .{ .total_bytes = 0, .free_bytes = 0, .available_bytes = 0, .buffers_bytes = 0, .cached_bytes = 0, .active_bytes = 0, .inactive_bytes = 0, .used_percent = 0 },
        .swap = .{ .total_bytes = 0, .used_bytes = 0, .free_bytes = 0, .used_percent = 0 },
        .load = .{ .one = 0, .five = 0, .fifteen = 0, .running_processes = 0, .total_processes = 0 },
        .disks = &.{},
        .filesystems = &.{},
        .network = &.{},
        .temperatures = &.{},
        .connections = .{ .established = 0, .listen = 0, .time_wait = 0, .close_wait = 0, .total = 0 },
    };
    _ = stats;
}
