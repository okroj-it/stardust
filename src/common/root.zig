pub const types = @import("types.zig");
pub const protocol = @import("protocol.zig");
pub const ws = @import("ws.zig");

// Re-export commonly used types at top level
pub const SystemStats = types.SystemStats;
pub const CpuStats = types.CpuStats;
pub const MemoryStats = types.MemoryStats;
pub const SwapStats = types.SwapStats;
pub const LoadAverage = types.LoadAverage;
pub const DiskStats = types.DiskStats;
pub const FilesystemStats = types.FilesystemStats;
pub const NetworkInterface = types.NetworkInterface;
pub const Temperature = types.Temperature;
pub const ConnectionSummary = types.ConnectionSummary;
pub const Timestamp = types.Timestamp;
