const std = @import("std");
const types = @import("types.zig");

/// Agent → Server messages
pub const AgentMessage = struct {
    type: MessageType,
    auth: ?AuthRequest = null,
    stats: ?types.SystemStats = null,
    heartbeat: ?Heartbeat = null,
};

pub const MessageType = enum {
    auth,
    stats,
    heartbeat,
};

pub const AuthRequest = struct {
    agent_id: []const u8,
    token: []const u8,
    version: []const u8,
};

pub const Heartbeat = struct {
    agent_id: []const u8,
    timestamp: types.Timestamp,
};

/// Server → Agent messages
pub const ServerMessage = struct {
    type: ServerMessageType,
    auth_ok: ?AuthOk = null,
    auth_fail: ?AuthFail = null,
    config: ?ConfigUpdate = null,
};

pub const ServerMessageType = enum {
    auth_ok,
    auth_fail,
    config,
    pong,
};

pub const AuthOk = struct {
    server_time: types.Timestamp,
    collect_interval_ms: u32,
};

pub const AuthFail = struct {
    reason: []const u8,
};

pub const ConfigUpdate = struct {
    collect_interval_ms: u32,
};

/// Serialize any value to JSON string. Caller must free returned slice.
pub fn serialize(allocator: std.mem.Allocator, value: anytype) ![]u8 {
    return std.fmt.allocPrint(allocator, "{f}", .{std.json.fmt(value, .{})});
}

pub fn parseAgentMessage(allocator: std.mem.Allocator, json_bytes: []const u8) !std.json.Parsed(AgentMessage) {
    return std.json.parseFromSlice(AgentMessage, allocator, json_bytes, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    });
}

pub fn parseServerMessage(allocator: std.mem.Allocator, json_bytes: []const u8) !std.json.Parsed(ServerMessage) {
    return std.json.parseFromSlice(ServerMessage, allocator, json_bytes, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    });
}
