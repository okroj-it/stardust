const std = @import("std");
const common = @import("common");

/// In-memory ring buffer storing the last N stat snapshots per agent.
/// Thread-safe via mutex (zap uses multiple threads).
pub const Store = struct {
    const MAX_SNAPSHOTS = 120; // ~10 minutes at 5s interval

    allocator: std.mem.Allocator,
    mu: std.Thread.Mutex = .{},

    /// agent_id → ring buffer of JSON snapshots
    agents: std.StringHashMap(AgentData),

    pub const AgentData = struct {
        snapshots: [MAX_SNAPSHOTS]?[]const u8 = [_]?[]const u8{null} ** MAX_SNAPSHOTS,
        write_idx: usize = 0,
        count: usize = 0,
        last_seen: i64 = 0,
        connected: bool = false,
    };

    pub fn init(allocator: std.mem.Allocator) Store {
        return .{
            .allocator = allocator,
            .agents = std.StringHashMap(AgentData).init(allocator),
        };
    }

    pub fn deinit(self: *Store) void {
        var it = self.agents.iterator();
        while (it.next()) |entry| {
            for (&entry.value_ptr.snapshots) |*slot| {
                if (slot.*) |s| {
                    self.allocator.free(s);
                    slot.* = null;
                }
            }
            self.allocator.free(entry.key_ptr.*);
        }
        self.agents.deinit();
    }

    /// Push a stats JSON snapshot for an agent. Overwrites oldest if full.
    pub fn pushStats(self: *Store, agent_id: []const u8, json: []const u8) !void {
        self.mu.lock();
        defer self.mu.unlock();

        const gop = try self.agents.getOrPut(agent_id);
        if (!gop.found_existing) {
            gop.key_ptr.* = try self.allocator.dupe(u8, agent_id);
            gop.value_ptr.* = .{};
        }

        var data = gop.value_ptr;
        const now = std.time.milliTimestamp();
        data.last_seen = now;
        data.connected = true;

        // Free old snapshot in this slot
        if (data.snapshots[data.write_idx]) |old| {
            self.allocator.free(old);
        }
        data.snapshots[data.write_idx] = try self.allocator.dupe(u8, json);
        data.write_idx = (data.write_idx + 1) % MAX_SNAPSHOTS;
        if (data.count < MAX_SNAPSHOTS) data.count += 1;
    }

    /// Get the latest snapshot for an agent.
    pub fn getLatest(self: *Store, agent_id: []const u8) ?[]const u8 {
        self.mu.lock();
        defer self.mu.unlock();

        const data = self.agents.get(agent_id) orelse return null;
        if (data.count == 0) return null;
        const idx = if (data.write_idx == 0) MAX_SNAPSHOTS - 1 else data.write_idx - 1;
        return data.snapshots[idx];
    }

    /// Get the last N snapshots (oldest first).
    pub fn getHistory(self: *Store, allocator: std.mem.Allocator, agent_id: []const u8, count: usize) ![]const []const u8 {
        self.mu.lock();
        defer self.mu.unlock();

        const data = self.agents.get(agent_id) orelse return &.{};
        const n = @min(count, data.count);
        if (n == 0) return &.{};

        var result = try allocator.alloc([]const u8, n);
        // Start from oldest of the requested range
        var start_idx: usize = undefined;
        if (data.count < MAX_SNAPSHOTS) {
            // Haven't wrapped yet
            start_idx = if (data.count >= n) data.count - n else 0;
        } else {
            // Wrapped: oldest is at write_idx
            start_idx = (data.write_idx + MAX_SNAPSHOTS - n) % MAX_SNAPSHOTS;
        }

        for (0..n) |i| {
            const idx = (start_idx + i) % MAX_SNAPSHOTS;
            result[i] = data.snapshots[idx] orelse "";
        }
        return result;
    }

    /// Mark agent as disconnected.
    pub fn setDisconnected(self: *Store, agent_id: []const u8) void {
        self.mu.lock();
        defer self.mu.unlock();
        if (self.agents.getPtr(agent_id)) |data| {
            data.connected = false;
        }
    }

    /// Remove an agent entirely from the store.
    pub fn removeAgent(self: *Store, agent_id: []const u8) void {
        self.mu.lock();
        defer self.mu.unlock();
        if (self.agents.getPtr(agent_id)) |data| {
            for (&data.snapshots) |*snap| {
                if (snap.*) |s| {
                    self.allocator.free(s);
                    snap.* = null;
                }
            }
        }
        if (self.agents.fetchRemove(agent_id)) |kv| {
            self.allocator.free(kv.key);
        }
    }

    /// Get status of all known agents.
    pub fn getAllAgentStatus(self: *Store, allocator: std.mem.Allocator) ![]const AgentStatus {
        self.mu.lock();
        defer self.mu.unlock();

        var result: std.ArrayListUnmanaged(AgentStatus) = .{};
        var it = self.agents.iterator();
        while (it.next()) |entry| {
            try result.append(allocator, .{
                .agent_id = entry.key_ptr.*,
                .connected = entry.value_ptr.connected,
                .last_seen = entry.value_ptr.last_seen,
                .snapshot_count = entry.value_ptr.count,
            });
        }
        return try result.toOwnedSlice(allocator);
    }

    pub const AgentStatus = struct {
        agent_id: []const u8,
        connected: bool,
        last_seen: i64,
        snapshot_count: usize,
    };
};
