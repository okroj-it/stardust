const std = @import("std");
const zap = @import("zap");
const common = @import("common");
const Store = @import("store.zig").Store;
const Db = @import("db.zig").Db;

/// Per-connection WebSocket context.
const ConnContext = struct {
    agent_id: ?[]const u8 = null,
    authenticated: bool = false,
};

/// Global state shared across all WebSocket connections.
pub const WsState = struct {
    allocator: std.mem.Allocator,
    store: *Store,
    db: ?*Db = null,
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
        var it = self.valid_tokens.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.valid_tokens.deinit();
    }

    pub fn addToken(self: *WsState, agent_id: []const u8, token: []const u8) !void {
        self.mu.lock();
        defer self.mu.unlock();

        // Free old value if key already exists
        if (self.valid_tokens.fetchRemove(agent_id)) |old| {
            self.allocator.free(old.key);
            self.allocator.free(old.value);
        }

        const key = try self.allocator.dupe(u8, agent_id);
        errdefer self.allocator.free(key);
        const val = try self.allocator.dupe(u8, token);
        errdefer self.allocator.free(val);
        try self.valid_tokens.put(key, val);
    }

    pub fn removeToken(self: *WsState, agent_id: []const u8) void {
        self.mu.lock();
        defer self.mu.unlock();
        if (self.valid_tokens.fetchRemove(agent_id)) |old| {
            self.allocator.free(old.key);
            self.allocator.free(old.value);
        }
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
    std.log.info("[GROUND CONTROL] New signal incoming", .{});
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
    } else if (std.mem.indexOf(u8, message, "\"type\":\"sysinfo\"")) |_| {
        handleSysinfo(ws_state, message) catch |err| {
            std.log.warn("ws: sysinfo handling failed: {}", .{err});
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
        std.log.info("[GROUND CONTROL] Signal received from Spider '{s}'", .{agent_id});

        const now = std.time.milliTimestamp();
        var buf: [256]u8 = undefined;
        const resp = std.fmt.bufPrint(&buf,
            \\{{"type":"auth_ok","server_time":{d},"collect_interval_ms":5000}}
        , .{now}) catch return;
        WsHandler.write(handle, resp, true) catch {};
    } else {
        std.log.warn("[GROUND CONTROL] Unknown signal from '{s}' — credentials invalid", .{agent_id});
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
    std.log.info("[GROUND CONTROL] Signal lost", .{});
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

const SysinfoMsg = struct {
    agent_id: []const u8,
    os_id: []const u8 = "",
    os_version: []const u8 = "",
    os_name: []const u8 = "",
    arch: []const u8 = "",
    kernel: []const u8 = "",
    cpu_model: []const u8 = "",
    cpu_cores: i64 = 0,
    total_ram: i64 = 0,
    pkg_manager: []const u8 = "",
};

fn handleSysinfo(state: *WsState, message: []const u8) !void {
    const db = state.db orelse return;

    const parsed = std.json.parseFromSlice(SysinfoMsg, state.allocator, message, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    }) catch {
        std.log.warn("ws: could not parse sysinfo message", .{});
        return;
    };
    defer parsed.deinit();

    const v = parsed.value;
    std.log.info("[GROUND CONTROL] Sysinfo from Spider '{s}': {s} {s} ({s}), cpu={s} x{d}, ram={d}MB, pkg={s}", .{
        v.agent_id,
        v.os_id,
        v.os_version,
        v.arch,
        v.cpu_model,
        v.cpu_cores,
        @divTrunc(v.total_ram, 1024 * 1024),
        v.pkg_manager,
    });

    db.updateSystemInfo(
        v.agent_id,
        v.os_id,
        v.os_version,
        v.os_name,
        v.arch,
        v.kernel,
        v.cpu_model,
        v.cpu_cores,
        v.total_ram,
        v.pkg_manager,
    ) catch |err| {
        std.log.warn("ws: failed to store sysinfo for '{s}': {}", .{ v.agent_id, err });
    };
}
