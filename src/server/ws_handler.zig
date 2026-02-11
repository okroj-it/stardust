const std = @import("std");
const zap = @import("zap");
const common = @import("common");
const Store = @import("store.zig").Store;

/// Per-connection WebSocket context.
const ConnContext = struct {
    agent_id: ?[]const u8 = null,
    authenticated: bool = false,
};

/// Global state shared across all WebSocket connections.
pub const WsState = struct {
    allocator: std.mem.Allocator,
    store: *Store,
    /// Valid tokens: agent_id → token
    valid_tokens: std.StringHashMap([]const u8),
    mu: std.Thread.Mutex = .{},

    pub fn init(allocator: std.mem.Allocator, store: *Store) WsState {
        return .{
            .allocator = allocator,
            .store = store,
            .valid_tokens = std.StringHashMap([]const u8).init(allocator),
        };
    }

    pub fn deinit(self: *WsState) void {
        self.valid_tokens.deinit();
    }

    pub fn addToken(self: *WsState, agent_id: []const u8, token: []const u8) !void {
        self.mu.lock();
        defer self.mu.unlock();
        try self.valid_tokens.put(agent_id, token);
    }

    pub fn removeToken(self: *WsState, agent_id: []const u8) void {
        self.mu.lock();
        defer self.mu.unlock();
        _ = self.valid_tokens.remove(agent_id);
    }

    pub fn validateToken(self: *WsState, agent_id: []const u8, token: []const u8) bool {
        self.mu.lock();
        defer self.mu.unlock();
        const expected = self.valid_tokens.get(agent_id) orelse return false;
        return std.mem.eql(u8, expected, token);
    }
};

pub const WsHandler = zap.WebSockets.Handler(WsState);
const WsHandle = zap.WebSockets.WsHandle;

pub fn getSettings(state: *WsState) WsHandler.WebSocketSettings {
    return .{
        .on_open = onOpen,
        .on_message = onMessage,
        .on_close = onClose,
        .context = state,
    };
}

fn onOpen(state: ?*WsState, handle: WsHandle) !void {
    _ = state;
    _ = handle;
    std.log.info("ws: new connection", .{});
}

fn onMessage(state: ?*WsState, handle: WsHandle, message: []const u8, is_text: bool) !void {
    _ = is_text;
    const ws_state = state orelse return;

    // Try to parse the JSON message to determine its type
    // Simple approach: check for "type":"auth" or treat as stats
    if (std.mem.indexOf(u8, message, "\"type\":\"auth\"")) |_| {
        handleAuth(ws_state, handle, message) catch |err| {
            std.log.warn("ws: auth handling failed: {}", .{err});
        };
    } else {
        // Treat as stats payload — the agent sends raw SystemStats JSON
        handleStats(ws_state, handle, message) catch |err| {
            std.log.warn("ws: stats handling failed: {}", .{err});
        };
    }
}

fn handleAuth(state: *WsState, handle: WsHandle, message: []const u8) !void {
    // Parse auth fields from the JSON
    // The agent sends: {"type":"auth","agent_id":"...","token":"...","version":"..."}
    const parsed = std.json.parseFromSlice(AuthMsg, state.allocator, message, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    }) catch {
        const fail = "{\"type\":\"auth_fail\",\"reason\":\"invalid auth message\"}";
        WsHandler.write(handle, fail, true) catch {};
        return;
    };
    defer parsed.deinit();

    const agent_id = parsed.value.agent_id;
    const token = parsed.value.token;

    if (state.validateToken(agent_id, token)) {
        std.log.info("ws: agent '{s}' authenticated", .{agent_id});

        const now = std.time.milliTimestamp();
        var buf: [256]u8 = undefined;
        const resp = std.fmt.bufPrint(&buf,
            \\{{"type":"auth_ok","server_time":{d},"collect_interval_ms":5000}}
        , .{now}) catch return;
        WsHandler.write(handle, resp, true) catch {};
    } else {
        std.log.warn("ws: auth failed for agent '{s}'", .{agent_id});
        const fail = "{\"type\":\"auth_fail\",\"reason\":\"invalid credentials\"}";
        WsHandler.write(handle, fail, true) catch {};
    }
}

fn handleStats(state: *WsState, _: WsHandle, message: []const u8) !void {
    // Extract agent_id from the JSON stats to know which agent this belongs to.
    // We parse just enough to get the agent_id field.
    const parsed = std.json.parseFromSlice(StatsIdExtract, state.allocator, message, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    }) catch {
        std.log.warn("ws: could not parse stats agent_id", .{});
        return;
    };
    defer parsed.deinit();

    try state.store.pushStats(parsed.value.agent_id, message);
}

fn onClose(state: ?*WsState, uuid: isize) !void {
    _ = state;
    _ = uuid;
    std.log.info("ws: connection closed", .{});
}

const AuthMsg = struct {
    type: []const u8,
    agent_id: []const u8,
    token: []const u8,
    version: []const u8 = "unknown",
};

const StatsIdExtract = struct {
    agent_id: []const u8,
};
