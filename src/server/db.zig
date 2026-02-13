const std = @import("std");
const zqlite = @import("zqlite");

pub const NodeRecord = struct {
    id: []const u8,
    name: []const u8,
    host: []const u8,
    port: i64,
    ssh_user: []const u8,
    ssh_key_enc: []const u8, // blob
    ssh_key_nonce: []const u8, // 12 bytes
    ssh_key_tag: []const u8, // 16 bytes
    sudo_pass_enc: ?[]const u8, // encrypted sudo password (nullable)
    sudo_pass_nonce: ?[]const u8, // 12 bytes
    sudo_pass_tag: ?[]const u8, // 16 bytes
    status: []const u8,
    agent_token: []const u8,
    created_at: i64,
    last_seen: ?i64,
    // System info (populated by agent sysinfo message)
    os_id: ?[]const u8 = null,
    os_version: ?[]const u8 = null,
    os_name: ?[]const u8 = null,
    arch: ?[]const u8 = null,
    kernel: ?[]const u8 = null,
    cpu_model: ?[]const u8 = null,
    cpu_cores: ?i64 = null,
    total_ram: ?i64 = null,
    pkg_manager: ?[]const u8 = null,

    /// Free all heap-allocated string/blob fields.
    pub fn deinit(self: NodeRecord, allocator: std.mem.Allocator) void {
        allocator.free(self.id);
        allocator.free(self.name);
        allocator.free(self.host);
        allocator.free(self.ssh_user);
        allocator.free(self.ssh_key_enc);
        allocator.free(self.ssh_key_nonce);
        allocator.free(self.ssh_key_tag);
        if (self.sudo_pass_enc) |v| allocator.free(v);
        if (self.sudo_pass_nonce) |v| allocator.free(v);
        if (self.sudo_pass_tag) |v| allocator.free(v);
        allocator.free(self.status);
        allocator.free(self.agent_token);
        if (self.os_id) |v| allocator.free(v);
        if (self.os_version) |v| allocator.free(v);
        if (self.os_name) |v| allocator.free(v);
        if (self.arch) |v| allocator.free(v);
        if (self.kernel) |v| allocator.free(v);
        if (self.cpu_model) |v| allocator.free(v);
        if (self.pkg_manager) |v| allocator.free(v);
    }
};

pub const DriftSnapshot = struct {
    id: i64,
    node_id: []const u8,
    packages: ?[]const u8,
    services: ?[]const u8,
    ports: ?[]const u8,
    users_data: ?[]const u8,
    is_baseline: bool,
    created_at: i64,

    pub fn deinit(self: DriftSnapshot, allocator: std.mem.Allocator) void {
        allocator.free(self.node_id);
        if (self.packages) |v| allocator.free(v);
        if (self.services) |v| allocator.free(v);
        if (self.ports) |v| allocator.free(v);
        if (self.users_data) |v| allocator.free(v);
    }
};

pub const Db = struct {
    conn: zqlite.Conn,

    pub fn init(path: [*:0]const u8) !Db {
        var conn = try zqlite.open(path, zqlite.OpenFlags.Create | zqlite.OpenFlags.ReadWrite | zqlite.OpenFlags.EXResCode);
        try conn.execNoArgs("PRAGMA journal_mode=WAL");
        try conn.execNoArgs("PRAGMA foreign_keys=ON");
        try conn.execNoArgs(
            \\CREATE TABLE IF NOT EXISTS nodes (
            \\    id              TEXT PRIMARY KEY,
            \\    name            TEXT NOT NULL,
            \\    host            TEXT NOT NULL,
            \\    port            INTEGER DEFAULT 22,
            \\    ssh_user        TEXT NOT NULL,
            \\    ssh_key_enc     BLOB NOT NULL,
            \\    ssh_key_nonce   BLOB NOT NULL,
            \\    ssh_key_tag     BLOB NOT NULL,
            \\    sudo_pass_enc   BLOB,
            \\    sudo_pass_nonce BLOB,
            \\    sudo_pass_tag   BLOB,
            \\    status          TEXT DEFAULT 'pending',
            \\    agent_token     TEXT NOT NULL,
            \\    created_at      INTEGER NOT NULL,
            \\    last_seen       INTEGER
            \\)
        );
        try conn.execNoArgs(
            \\CREATE TABLE IF NOT EXISTS settings (
            \\    key   TEXT PRIMARY KEY,
            \\    value TEXT NOT NULL
            \\)
        );
        try conn.execNoArgs(
            \\CREATE TABLE IF NOT EXISTS users (
            \\    id         INTEGER PRIMARY KEY AUTOINCREMENT,
            \\    username   TEXT NOT NULL UNIQUE,
            \\    password   TEXT NOT NULL,
            \\    created_at INTEGER NOT NULL
            \\)
        );

        try conn.execNoArgs(
            \\CREATE TABLE IF NOT EXISTS node_tags (
            \\    node_id TEXT NOT NULL,
            \\    tag     TEXT NOT NULL,
            \\    UNIQUE(node_id, tag)
            \\)
        );

        try conn.execNoArgs(
            \\CREATE TABLE IF NOT EXISTS drift_snapshots (
            \\    id          INTEGER PRIMARY KEY AUTOINCREMENT,
            \\    node_id     TEXT NOT NULL,
            \\    packages    TEXT,
            \\    services    TEXT,
            \\    ports       TEXT,
            \\    users_data  TEXT,
            \\    is_baseline INTEGER DEFAULT 0,
            \\    created_at  INTEGER NOT NULL
            \\)
        );

        try conn.execNoArgs(
            \\CREATE TABLE IF NOT EXISTS events (
            \\    id         INTEGER PRIMARY KEY AUTOINCREMENT,
            \\    created_at INTEGER NOT NULL,
            \\    event_type TEXT NOT NULL,
            \\    node_id    TEXT,
            \\    message    TEXT NOT NULL,
            \\    detail     TEXT
            \\)
        );
        conn.execNoArgs("CREATE INDEX IF NOT EXISTS idx_events_created ON events(created_at DESC)") catch {};
        conn.execNoArgs("CREATE INDEX IF NOT EXISTS idx_events_node ON events(node_id)") catch {};

        try conn.execNoArgs(
            \\CREATE TABLE IF NOT EXISTS schedules (
            \\    id          INTEGER PRIMARY KEY AUTOINCREMENT,
            \\    name        TEXT NOT NULL,
            \\    job_type    TEXT NOT NULL,
            \\    config      TEXT NOT NULL,
            \\    target_type TEXT NOT NULL,
            \\    target_value TEXT,
            \\    cron_minute TEXT DEFAULT '*',
            \\    cron_hour   TEXT DEFAULT '*',
            \\    cron_dom    TEXT DEFAULT '*',
            \\    cron_month  TEXT DEFAULT '*',
            \\    cron_dow    TEXT DEFAULT '*',
            \\    enabled     INTEGER DEFAULT 1,
            \\    last_run    INTEGER,
            \\    last_status TEXT,
            \\    created_at  INTEGER NOT NULL,
            \\    updated_at  INTEGER NOT NULL
            \\)
        );

        try conn.execNoArgs(
            \\CREATE TABLE IF NOT EXISTS schedule_runs (
            \\    id          INTEGER PRIMARY KEY AUTOINCREMENT,
            \\    schedule_id INTEGER NOT NULL,
            \\    started_at  INTEGER NOT NULL,
            \\    finished_at INTEGER,
            \\    status      TEXT NOT NULL,
            \\    output      TEXT,
            \\    FOREIGN KEY (schedule_id) REFERENCES schedules(id) ON DELETE CASCADE
            \\)
        );
        conn.execNoArgs("CREATE INDEX IF NOT EXISTS idx_schedule_runs_sched ON schedule_runs(schedule_id, started_at DESC)") catch {};

        // Migration: add sudo columns if missing (for existing DBs)
        conn.execNoArgs("ALTER TABLE nodes ADD COLUMN sudo_pass_enc BLOB") catch {};
        conn.execNoArgs("ALTER TABLE nodes ADD COLUMN sudo_pass_nonce BLOB") catch {};
        conn.execNoArgs("ALTER TABLE nodes ADD COLUMN sudo_pass_tag BLOB") catch {};

        // Migration: add system info columns
        conn.execNoArgs("ALTER TABLE nodes ADD COLUMN os_id TEXT") catch {};
        conn.execNoArgs("ALTER TABLE nodes ADD COLUMN os_version TEXT") catch {};
        conn.execNoArgs("ALTER TABLE nodes ADD COLUMN os_name TEXT") catch {};
        conn.execNoArgs("ALTER TABLE nodes ADD COLUMN arch TEXT") catch {};
        conn.execNoArgs("ALTER TABLE nodes ADD COLUMN kernel TEXT") catch {};
        conn.execNoArgs("ALTER TABLE nodes ADD COLUMN cpu_model TEXT") catch {};
        conn.execNoArgs("ALTER TABLE nodes ADD COLUMN cpu_cores INTEGER") catch {};
        conn.execNoArgs("ALTER TABLE nodes ADD COLUMN total_ram INTEGER") catch {};
        conn.execNoArgs("ALTER TABLE nodes ADD COLUMN pkg_manager TEXT") catch {};

        // Prune events older than 30 days
        const cutoff = std.time.timestamp() - 30 * 86400;
        conn.exec("DELETE FROM events WHERE created_at < ?1", .{cutoff}) catch {};

        // Mark stale schedule runs as failed (server crashed mid-execution)
        conn.exec("UPDATE schedule_runs SET status = 'failed', finished_at = ?1 WHERE status = 'running' OR status = 'pending'", .{std.time.timestamp()}) catch {};

        // Prune old schedule runs (keep last 100 per schedule)
        conn.execNoArgs(
            \\DELETE FROM schedule_runs WHERE id NOT IN (
            \\    SELECT id FROM schedule_runs ORDER BY started_at DESC LIMIT 1000
            \\)
        ) catch {};

        return .{ .conn = conn };
    }

    pub fn deinit(self: *Db) void {
        self.conn.close();
    }

    /// Insert a new node record.
    pub fn insertNode(
        self: *Db,
        id: []const u8,
        name: []const u8,
        host: []const u8,
        port: i64,
        ssh_user: []const u8,
        ssh_key_enc: []const u8,
        ssh_key_nonce: []const u8,
        ssh_key_tag: []const u8,
        agent_token: []const u8,
    ) !void {
        try self.conn.exec(
            \\INSERT INTO nodes (id, name, host, port, ssh_user, ssh_key_enc, ssh_key_nonce, ssh_key_tag, status, agent_token, created_at)
            \\VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'pending', ?9, ?10)
        , .{
            id,
            name,
            host,
            port,
            ssh_user,
            zqlite.blob(ssh_key_enc),
            zqlite.blob(ssh_key_nonce),
            zqlite.blob(ssh_key_tag),
            agent_token,
            std.time.timestamp(),
        });
    }

    /// Update sudo password (encrypted) for a node.
    pub fn updateSudoPass(
        self: *Db,
        id: []const u8,
        enc: []const u8,
        nonce: []const u8,
        tag: []const u8,
    ) !void {
        try self.conn.exec(
            "UPDATE nodes SET sudo_pass_enc = ?1, sudo_pass_nonce = ?2, sudo_pass_tag = ?3 WHERE id = ?4",
            .{ zqlite.blob(enc), zqlite.blob(nonce), zqlite.blob(tag), id },
        );
    }

    /// Update SSH key (encrypted) for a node.
    pub fn updateSshKey(
        self: *Db,
        id: []const u8,
        enc: []const u8,
        nonce: []const u8,
        tag: []const u8,
    ) !void {
        try self.conn.exec(
            "UPDATE nodes SET ssh_key_enc = ?1, ssh_key_nonce = ?2, ssh_key_tag = ?3 WHERE id = ?4",
            .{ zqlite.blob(enc), zqlite.blob(nonce), zqlite.blob(tag), id },
        );
    }

    /// Get a node by ID. Caller must call result.deinit(allocator) when done.
    pub fn getNode(self: *Db, allocator: std.mem.Allocator, id: []const u8) !?NodeRecord {
        const r = try self.conn.row(
            \\SELECT id, name, host, port, ssh_user, ssh_key_enc, ssh_key_nonce, ssh_key_tag,
            \\       sudo_pass_enc, sudo_pass_nonce, sudo_pass_tag,
            \\       status, agent_token, created_at, last_seen,
            \\       os_id, os_version, os_name, arch, kernel, cpu_model, cpu_cores, total_ram, pkg_manager
            \\FROM nodes WHERE id = ?1
        , .{id});
        if (r) |row| {
            defer row.deinit();
            return .{
                .id = try allocator.dupe(u8, row.text(0)),
                .name = try allocator.dupe(u8, row.text(1)),
                .host = try allocator.dupe(u8, row.text(2)),
                .port = row.int(3),
                .ssh_user = try allocator.dupe(u8, row.text(4)),
                .ssh_key_enc = try allocator.dupe(u8, row.blob(5)),
                .ssh_key_nonce = try allocator.dupe(u8, row.blob(6)),
                .ssh_key_tag = try allocator.dupe(u8, row.blob(7)),
                .sudo_pass_enc = if (row.nullableBlob(8)) |b| try allocator.dupe(u8, b) else null,
                .sudo_pass_nonce = if (row.nullableBlob(9)) |b| try allocator.dupe(u8, b) else null,
                .sudo_pass_tag = if (row.nullableBlob(10)) |b| try allocator.dupe(u8, b) else null,
                .status = try allocator.dupe(u8, row.text(11)),
                .agent_token = try allocator.dupe(u8, row.text(12)),
                .created_at = row.int(13),
                .last_seen = row.nullableInt(14),
                .os_id = if (row.nullableText(15)) |v| try allocator.dupe(u8, v) else null,
                .os_version = if (row.nullableText(16)) |v| try allocator.dupe(u8, v) else null,
                .os_name = if (row.nullableText(17)) |v| try allocator.dupe(u8, v) else null,
                .arch = if (row.nullableText(18)) |v| try allocator.dupe(u8, v) else null,
                .kernel = if (row.nullableText(19)) |v| try allocator.dupe(u8, v) else null,
                .cpu_model = if (row.nullableText(20)) |v| try allocator.dupe(u8, v) else null,
                .cpu_cores = row.nullableInt(21),
                .total_ram = row.nullableInt(22),
                .pkg_manager = if (row.nullableText(23)) |v| try allocator.dupe(u8, v) else null,
            };
        }
        return null;
    }

    /// List all nodes. Caller must call deinit(allocator) on each record and free the slice.
    pub fn listNodes(self: *Db, allocator: std.mem.Allocator) ![]NodeRecord {
        var rows = try self.conn.rows(
            \\SELECT id, name, host, port, ssh_user, ssh_key_enc, ssh_key_nonce, ssh_key_tag,
            \\       sudo_pass_enc, sudo_pass_nonce, sudo_pass_tag,
            \\       status, agent_token, created_at, last_seen,
            \\       os_id, os_version, os_name, arch, kernel, cpu_model, cpu_cores, total_ram, pkg_manager
            \\FROM nodes ORDER BY created_at DESC
        , .{});
        defer rows.deinit();

        var result: std.ArrayListUnmanaged(NodeRecord) = .{};
        while (rows.next()) |row| {
            try result.append(allocator, .{
                .id = try allocator.dupe(u8, row.text(0)),
                .name = try allocator.dupe(u8, row.text(1)),
                .host = try allocator.dupe(u8, row.text(2)),
                .port = row.int(3),
                .ssh_user = try allocator.dupe(u8, row.text(4)),
                .ssh_key_enc = try allocator.dupe(u8, row.blob(5)),
                .ssh_key_nonce = try allocator.dupe(u8, row.blob(6)),
                .ssh_key_tag = try allocator.dupe(u8, row.blob(7)),
                .sudo_pass_enc = if (row.nullableBlob(8)) |b| try allocator.dupe(u8, b) else null,
                .sudo_pass_nonce = if (row.nullableBlob(9)) |b| try allocator.dupe(u8, b) else null,
                .sudo_pass_tag = if (row.nullableBlob(10)) |b| try allocator.dupe(u8, b) else null,
                .status = try allocator.dupe(u8, row.text(11)),
                .agent_token = try allocator.dupe(u8, row.text(12)),
                .created_at = row.int(13),
                .last_seen = row.nullableInt(14),
                .os_id = if (row.nullableText(15)) |v| try allocator.dupe(u8, v) else null,
                .os_version = if (row.nullableText(16)) |v| try allocator.dupe(u8, v) else null,
                .os_name = if (row.nullableText(17)) |v| try allocator.dupe(u8, v) else null,
                .arch = if (row.nullableText(18)) |v| try allocator.dupe(u8, v) else null,
                .kernel = if (row.nullableText(19)) |v| try allocator.dupe(u8, v) else null,
                .cpu_model = if (row.nullableText(20)) |v| try allocator.dupe(u8, v) else null,
                .cpu_cores = row.nullableInt(21),
                .total_ram = row.nullableInt(22),
                .pkg_manager = if (row.nullableText(23)) |v| try allocator.dupe(u8, v) else null,
            });
        }
        return try result.toOwnedSlice(allocator);
    }

    /// Update node status.
    pub fn updateNodeStatus(self: *Db, id: []const u8, status: []const u8) !void {
        try self.conn.exec("UPDATE nodes SET status = ?1 WHERE id = ?2", .{ status, id });
    }

    /// Update last_seen timestamp.
    pub fn updateLastSeen(self: *Db, id: []const u8) !void {
        try self.conn.exec("UPDATE nodes SET last_seen = ?1 WHERE id = ?2", .{ std.time.timestamp(), id });
    }

    /// Update system info fields from agent sysinfo message.
    pub fn updateSystemInfo(
        self: *Db,
        id: []const u8,
        os_id: []const u8,
        os_version: []const u8,
        os_name: []const u8,
        arch_val: []const u8,
        kernel_val: []const u8,
        cpu_model: []const u8,
        cpu_cores: i64,
        total_ram: i64,
        pkg_manager: []const u8,
    ) !void {
        try self.conn.exec(
            \\UPDATE nodes SET
            \\  os_id = ?1, os_version = ?2, os_name = ?3, arch = ?4, kernel = ?5,
            \\  cpu_model = ?6, cpu_cores = ?7, total_ram = ?8, pkg_manager = ?9
            \\WHERE id = ?10
        , .{ os_id, os_version, os_name, arch_val, kernel_val, cpu_model, cpu_cores, total_ram, pkg_manager, id });
    }

    /// Wipe encrypted credentials (SSH key + sudo password) for a node.
    pub fn wipeCredentials(self: *Db, id: []const u8) !void {
        try self.conn.exec(
            \\UPDATE nodes SET
            \\  ssh_key_enc = zeroblob(0), ssh_key_nonce = zeroblob(0), ssh_key_tag = zeroblob(0),
            \\  sudo_pass_enc = NULL, sudo_pass_nonce = NULL, sudo_pass_tag = NULL
            \\WHERE id = ?1
        , .{id});
    }

    /// Delete a node and its tags.
    pub fn deleteNode(self: *Db, id: []const u8) !void {
        try self.conn.exec("DELETE FROM node_tags WHERE node_id = ?1", .{id});
        try self.conn.exec("DELETE FROM nodes WHERE id = ?1", .{id});
    }

    /// Get a setting value.
    pub fn getSetting(self: *Db, key: []const u8) !?[]const u8 {
        const r = try self.conn.row("SELECT value FROM settings WHERE key = ?1", .{key});
        if (r) |row| {
            defer row.deinit();
            return row.text(0);
        }
        return null;
    }

    /// Upsert a setting.
    pub fn setSetting(self: *Db, key: []const u8, value: []const u8) !void {
        try self.conn.exec(
            "INSERT INTO settings (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = ?2",
            .{ key, value },
        );
    }

    /// Get all node tokens. Caller must free each entry's strings and the slice.
    pub fn getAllTokens(self: *Db, allocator: std.mem.Allocator) ![]TokenEntry {
        var rows = try self.conn.rows(
            "SELECT id, agent_token FROM nodes WHERE status != 'error'",
            .{},
        );
        defer rows.deinit();

        var result: std.ArrayListUnmanaged(TokenEntry) = .{};
        while (rows.next()) |row| {
            try result.append(allocator, .{
                .agent_id = try allocator.dupe(u8, row.text(0)),
                .token = try allocator.dupe(u8, row.text(1)),
            });
        }
        return try result.toOwnedSlice(allocator);
    }

    pub const TokenEntry = struct {
        agent_id: []const u8,
        token: []const u8,
    };

    /// Get the number of users in the database.
    pub fn getUserCount(self: *Db) !usize {
        const r = try self.conn.row("SELECT COUNT(*) FROM users", .{});
        if (r) |row| {
            defer row.deinit();
            return @intCast(row.int(0));
        }
        return 0;
    }

    /// Get password hash for a username. Caller must free returned slice.
    pub fn getPasswordHash(self: *Db, allocator: std.mem.Allocator, username: []const u8) !?[]const u8 {
        const r = try self.conn.row("SELECT password FROM users WHERE username = ?1", .{username});
        if (r) |row| {
            defer row.deinit();
            return try allocator.dupe(u8, row.text(0));
        }
        return null;
    }

    /// Insert a new user.
    pub fn insertUser(self: *Db, username: []const u8, password_hash: []const u8) !void {
        try self.conn.exec(
            "INSERT INTO users (username, password, created_at) VALUES (?1, ?2, ?3)",
            .{ username, password_hash, std.time.timestamp() },
        );
    }

    /// Update a user's password hash.
    pub fn updatePassword(self: *Db, username: []const u8, password_hash: []const u8) !void {
        try self.conn.exec(
            "UPDATE users SET password = ?1 WHERE username = ?2",
            .{ password_hash, username },
        );
    }

    // --- Node Tags ---

    /// Get all tags for a node. Caller must free each string and the slice.
    pub fn getNodeTags(self: *Db, allocator: std.mem.Allocator, node_id: []const u8) ![][]const u8 {
        var rows = try self.conn.rows(
            "SELECT tag FROM node_tags WHERE node_id = ?1 ORDER BY tag",
            .{node_id},
        );
        defer rows.deinit();

        var result: std.ArrayListUnmanaged([]const u8) = .{};
        while (rows.next()) |row| {
            try result.append(allocator, try allocator.dupe(u8, row.text(0)));
        }
        return try result.toOwnedSlice(allocator);
    }

    /// Replace all tags for a node.
    pub fn setNodeTags(self: *Db, node_id: []const u8, tags: []const []const u8) !void {
        try self.conn.exec("DELETE FROM node_tags WHERE node_id = ?1", .{node_id});
        for (tags) |tag| {
            if (tag.len == 0) continue;
            try self.conn.exec(
                "INSERT OR IGNORE INTO node_tags (node_id, tag) VALUES (?1, ?2)",
                .{ node_id, tag },
            );
        }
    }

    /// Get all unique tags across all nodes. Caller must free each string and the slice.
    pub fn getAllTags(self: *Db, allocator: std.mem.Allocator) ![][]const u8 {
        var rows = try self.conn.rows(
            "SELECT DISTINCT tag FROM node_tags ORDER BY tag",
            .{},
        );
        defer rows.deinit();

        var result: std.ArrayListUnmanaged([]const u8) = .{};
        while (rows.next()) |row| {
            try result.append(allocator, try allocator.dupe(u8, row.text(0)));
        }
        return try result.toOwnedSlice(allocator);
    }

    // --- Drift Snapshots ---

    /// Insert a drift snapshot. Returns the row ID.
    pub fn insertDriftSnapshot(
        self: *Db,
        node_id: []const u8,
        packages: ?[]const u8,
        services: ?[]const u8,
        ports: ?[]const u8,
        users_data: ?[]const u8,
    ) !i64 {
        try self.conn.exec(
            \\INSERT INTO drift_snapshots (node_id, packages, services, ports, users_data, created_at)
            \\VALUES (?1, ?2, ?3, ?4, ?5, ?6)
        , .{ node_id, packages, services, ports, users_data, std.time.timestamp() });
        const r = try self.conn.row("SELECT last_insert_rowid()", .{});
        if (r) |row| {
            defer row.deinit();
            return row.int(0);
        }
        return error.InsertFailed;
    }

    /// Get a drift snapshot by ID. Caller must call deinit.
    pub fn getDriftSnapshot(self: *Db, allocator: std.mem.Allocator, id: i64) !?DriftSnapshot {
        const r = try self.conn.row(
            "SELECT id, node_id, packages, services, ports, users_data, is_baseline, created_at FROM drift_snapshots WHERE id = ?1",
            .{id},
        );
        if (r) |row| {
            defer row.deinit();
            return DriftSnapshot{
                .id = row.int(0),
                .node_id = try allocator.dupe(u8, row.text(1)),
                .packages = if (row.nullableText(2)) |v| try allocator.dupe(u8, v) else null,
                .services = if (row.nullableText(3)) |v| try allocator.dupe(u8, v) else null,
                .ports = if (row.nullableText(4)) |v| try allocator.dupe(u8, v) else null,
                .users_data = if (row.nullableText(5)) |v| try allocator.dupe(u8, v) else null,
                .is_baseline = row.int(6) != 0,
                .created_at = row.int(7),
            };
        }
        return null;
    }

    /// Get the baseline snapshot for a node. Caller must call deinit.
    pub fn getDriftBaseline(self: *Db, allocator: std.mem.Allocator, node_id: []const u8) !?DriftSnapshot {
        const r = try self.conn.row(
            "SELECT id, node_id, packages, services, ports, users_data, is_baseline, created_at FROM drift_snapshots WHERE node_id = ?1 AND is_baseline = 1",
            .{node_id},
        );
        if (r) |row| {
            defer row.deinit();
            return DriftSnapshot{
                .id = row.int(0),
                .node_id = try allocator.dupe(u8, row.text(1)),
                .packages = if (row.nullableText(2)) |v| try allocator.dupe(u8, v) else null,
                .services = if (row.nullableText(3)) |v| try allocator.dupe(u8, v) else null,
                .ports = if (row.nullableText(4)) |v| try allocator.dupe(u8, v) else null,
                .users_data = if (row.nullableText(5)) |v| try allocator.dupe(u8, v) else null,
                .is_baseline = true,
                .created_at = row.int(7),
            };
        }
        return null;
    }

    /// Set a snapshot as the baseline for its node (clears previous baseline).
    pub fn setDriftBaseline(self: *Db, id: i64) !void {
        // Get the node_id for this snapshot
        const r = try self.conn.row("SELECT node_id FROM drift_snapshots WHERE id = ?1", .{id});
        if (r) |row| {
            defer row.deinit();
            const node_id = row.text(0);
            // Clear existing baseline for this node
            try self.conn.exec("UPDATE drift_snapshots SET is_baseline = 0 WHERE node_id = ?1 AND is_baseline = 1", .{node_id});
        }
        // Set the new baseline
        try self.conn.exec("UPDATE drift_snapshots SET is_baseline = 1 WHERE id = ?1", .{id});
    }

    /// List drift snapshots for a node. Caller must deinit each and free the slice.
    pub fn listDriftSnapshots(self: *Db, allocator: std.mem.Allocator, node_id: []const u8, limit: i64) ![]DriftSnapshot {
        var rows = try self.conn.rows(
            "SELECT id, node_id, packages, services, ports, users_data, is_baseline, created_at FROM drift_snapshots WHERE node_id = ?1 ORDER BY created_at DESC LIMIT ?2",
            .{ node_id, limit },
        );
        defer rows.deinit();

        var result: std.ArrayListUnmanaged(DriftSnapshot) = .{};
        while (rows.next()) |row| {
            try result.append(allocator, DriftSnapshot{
                .id = row.int(0),
                .node_id = try allocator.dupe(u8, row.text(1)),
                .packages = if (row.nullableText(2)) |v| try allocator.dupe(u8, v) else null,
                .services = if (row.nullableText(3)) |v| try allocator.dupe(u8, v) else null,
                .ports = if (row.nullableText(4)) |v| try allocator.dupe(u8, v) else null,
                .users_data = if (row.nullableText(5)) |v| try allocator.dupe(u8, v) else null,
                .is_baseline = row.int(6) != 0,
                .created_at = row.int(7),
            });
        }
        return try result.toOwnedSlice(allocator);
    }

    /// Delete a drift snapshot.
    pub fn deleteDriftSnapshot(self: *Db, id: i64) !void {
        try self.conn.exec("DELETE FROM drift_snapshots WHERE id = ?1", .{id});
    }

    // --- Events ---

    /// Insert an event (fire-and-forget: logs errors, never fails the caller).
    pub fn insertEvent(self: *Db, event_type: []const u8, node_id: ?[]const u8, message: []const u8, detail: ?[]const u8) void {
        self.conn.exec(
            "INSERT INTO events (created_at, event_type, node_id, message, detail) VALUES (?1, ?2, ?3, ?4, ?5)",
            .{ std.time.timestamp(), event_type, node_id, message, detail },
        ) catch |err| {
            std.log.warn("[CHANGES] Failed to record event: {}", .{err});
        };
    }

    // --- Schedules ---

    /// Insert a schedule. Returns the row ID.
    pub fn insertSchedule(
        self: *Db,
        name: []const u8,
        job_type: []const u8,
        config: []const u8,
        target_type: []const u8,
        target_value: ?[]const u8,
        cron_minute: []const u8,
        cron_hour: []const u8,
        cron_dom: []const u8,
        cron_month: []const u8,
        cron_dow: []const u8,
        enabled: bool,
    ) !i64 {
        const now = std.time.timestamp();
        try self.conn.exec(
            \\INSERT INTO schedules (name, job_type, config, target_type, target_value,
            \\    cron_minute, cron_hour, cron_dom, cron_month, cron_dow, enabled, created_at, updated_at)
            \\VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
        , .{ name, job_type, config, target_type, target_value, cron_minute, cron_hour, cron_dom, cron_month, cron_dow, @as(i64, if (enabled) 1 else 0), now, now });
        const r = try self.conn.row("SELECT last_insert_rowid()", .{});
        if (r) |row| {
            defer row.deinit();
            return row.int(0);
        }
        return error.InsertFailed;
    }

    /// Update a schedule.
    pub fn updateSchedule(
        self: *Db,
        id: i64,
        name: []const u8,
        job_type: []const u8,
        config: []const u8,
        target_type: []const u8,
        target_value: ?[]const u8,
        cron_minute: []const u8,
        cron_hour: []const u8,
        cron_dom: []const u8,
        cron_month: []const u8,
        cron_dow: []const u8,
    ) !void {
        try self.conn.exec(
            \\UPDATE schedules SET name = ?1, job_type = ?2, config = ?3, target_type = ?4,
            \\    target_value = ?5, cron_minute = ?6, cron_hour = ?7, cron_dom = ?8,
            \\    cron_month = ?9, cron_dow = ?10, updated_at = ?11 WHERE id = ?12
        , .{ name, job_type, config, target_type, target_value, cron_minute, cron_hour, cron_dom, cron_month, cron_dow, std.time.timestamp(), id });
    }

    /// Delete a schedule (runs cascade-delete on schedule_runs).
    pub fn deleteSchedule(self: *Db, id: i64) !void {
        try self.conn.exec("DELETE FROM schedules WHERE id = ?1", .{id});
    }

    /// Toggle a schedule enabled/disabled.
    pub fn setScheduleEnabled(self: *Db, id: i64, enabled: bool) !void {
        try self.conn.exec("UPDATE schedules SET enabled = ?1, updated_at = ?2 WHERE id = ?3", .{
            @as(i64, if (enabled) 1 else 0), std.time.timestamp(), id,
        });
    }

    /// Update last_run and last_status after execution.
    pub fn updateScheduleLastRun(self: *Db, id: i64, timestamp: i64, status: []const u8) void {
        self.conn.exec("UPDATE schedules SET last_run = ?1, last_status = ?2, updated_at = ?3 WHERE id = ?4", .{
            timestamp, status, std.time.timestamp(), id,
        }) catch {};
    }

    /// Get a single schedule by ID.
    pub fn getSchedule(self: *Db, allocator: std.mem.Allocator, id: i64) !?ScheduleRecord {
        const r = try self.conn.row(
            \\SELECT id, name, job_type, config, target_type, target_value,
            \\    cron_minute, cron_hour, cron_dom, cron_month, cron_dow,
            \\    enabled, last_run, last_status, created_at, updated_at
            \\FROM schedules WHERE id = ?1
        , .{id});
        if (r) |row| {
            defer row.deinit();
            return @as(?ScheduleRecord, try readScheduleRow(allocator, row));
        }
        return null;
    }

    /// List all schedules.
    pub fn listSchedules(self: *Db, allocator: std.mem.Allocator) ![]ScheduleRecord {
        var rows = try self.conn.rows(
            \\SELECT id, name, job_type, config, target_type, target_value,
            \\    cron_minute, cron_hour, cron_dom, cron_month, cron_dow,
            \\    enabled, last_run, last_status, created_at, updated_at
            \\FROM schedules ORDER BY created_at DESC
        , .{});
        defer rows.deinit();

        var result: std.ArrayListUnmanaged(ScheduleRecord) = .{};
        while (rows.next()) |row| {
            try result.append(allocator, try readScheduleRow(allocator, row));
        }
        return try result.toOwnedSlice(allocator);
    }

    /// List enabled schedules (for scheduler thread).
    pub fn listEnabledSchedules(self: *Db, allocator: std.mem.Allocator) ![]ScheduleRecord {
        var rows = try self.conn.rows(
            \\SELECT id, name, job_type, config, target_type, target_value,
            \\    cron_minute, cron_hour, cron_dom, cron_month, cron_dow,
            \\    enabled, last_run, last_status, created_at, updated_at
            \\FROM schedules WHERE enabled = 1
        , .{});
        defer rows.deinit();

        var result: std.ArrayListUnmanaged(ScheduleRecord) = .{};
        while (rows.next()) |row| {
            try result.append(allocator, try readScheduleRow(allocator, row));
        }
        return try result.toOwnedSlice(allocator);
    }

    fn readScheduleRow(allocator: std.mem.Allocator, row: anytype) !ScheduleRecord {
        return ScheduleRecord{
            .id = row.int(0),
            .name = try allocator.dupe(u8, row.text(1)),
            .job_type = try allocator.dupe(u8, row.text(2)),
            .config = try allocator.dupe(u8, row.text(3)),
            .target_type = try allocator.dupe(u8, row.text(4)),
            .target_value = if (row.nullableText(5)) |v| try allocator.dupe(u8, v) else null,
            .cron_minute = try allocator.dupe(u8, row.text(6)),
            .cron_hour = try allocator.dupe(u8, row.text(7)),
            .cron_dom = try allocator.dupe(u8, row.text(8)),
            .cron_month = try allocator.dupe(u8, row.text(9)),
            .cron_dow = try allocator.dupe(u8, row.text(10)),
            .enabled = row.int(11) != 0,
            .last_run = row.nullableInt(12),
            .last_status = if (row.nullableText(13)) |v| try allocator.dupe(u8, v) else null,
            .created_at = row.int(14),
            .updated_at = row.int(15),
        };
    }

    /// Insert a schedule run. Returns the row ID.
    pub fn insertScheduleRun(self: *Db, schedule_id: i64, status: []const u8) !i64 {
        try self.conn.exec(
            "INSERT INTO schedule_runs (schedule_id, started_at, status) VALUES (?1, ?2, ?3)",
            .{ schedule_id, std.time.timestamp(), status },
        );
        const r = try self.conn.row("SELECT last_insert_rowid()", .{});
        if (r) |row| {
            defer row.deinit();
            return row.int(0);
        }
        return error.InsertFailed;
    }

    /// Update a schedule run (on completion).
    pub fn updateScheduleRun(self: *Db, id: i64, status: []const u8, output: ?[]const u8) void {
        self.conn.exec(
            "UPDATE schedule_runs SET status = ?1, finished_at = ?2, output = ?3 WHERE id = ?4",
            .{ status, std.time.timestamp(), output, id },
        ) catch {};
    }

    /// List runs for a schedule (newest first).
    pub fn listScheduleRuns(self: *Db, allocator: std.mem.Allocator, schedule_id: i64, limit: i64) ![]ScheduleRunRecord {
        var rows = try self.conn.rows(
            "SELECT id, schedule_id, started_at, finished_at, status, output FROM schedule_runs WHERE schedule_id = ?1 ORDER BY started_at DESC LIMIT ?2",
            .{ schedule_id, limit },
        );
        defer rows.deinit();

        var result: std.ArrayListUnmanaged(ScheduleRunRecord) = .{};
        while (rows.next()) |row| {
            try result.append(allocator, ScheduleRunRecord{
                .id = row.int(0),
                .schedule_id = row.int(1),
                .started_at = row.int(2),
                .finished_at = row.nullableInt(3),
                .status = try allocator.dupe(u8, row.text(4)),
                .output = if (row.nullableText(5)) |v| try allocator.dupe(u8, v) else null,
            });
        }
        return try result.toOwnedSlice(allocator);
    }

    /// Get nodes by tag. Returns node IDs. Caller frees.
    pub fn getNodeIdsByTag(self: *Db, allocator: std.mem.Allocator, tag: []const u8) ![][]const u8 {
        var rows = try self.conn.rows("SELECT node_id FROM node_tags WHERE tag = ?1", .{tag});
        defer rows.deinit();

        var result: std.ArrayListUnmanaged([]const u8) = .{};
        while (rows.next()) |row| {
            try result.append(allocator, try allocator.dupe(u8, row.text(0)));
        }
        return try result.toOwnedSlice(allocator);
    }

    /// Get all node IDs. Caller frees.
    pub fn getAllNodeIds(self: *Db, allocator: std.mem.Allocator) ![][]const u8 {
        var rows = try self.conn.rows("SELECT id FROM nodes", .{});
        defer rows.deinit();

        var result: std.ArrayListUnmanaged([]const u8) = .{};
        while (rows.next()) |row| {
            try result.append(allocator, try allocator.dupe(u8, row.text(0)));
        }
        return try result.toOwnedSlice(allocator);
    }

    /// List events with optional filters and cursor-based pagination.
    pub fn listEvents(self: *Db, allocator: std.mem.Allocator, node_id: ?[]const u8, event_type: ?[]const u8, limit: i64, before_id: ?i64) ![]EventRecord {
        var rows = try self.conn.rows(
            \\SELECT id, created_at, event_type, node_id, message, detail FROM events
            \\WHERE (?1 IS NULL OR node_id = ?1)
            \\  AND (?2 IS NULL OR event_type = ?2)
            \\  AND (?3 IS NULL OR id < ?3)
            \\ORDER BY id DESC LIMIT ?4
        , .{ node_id, event_type, before_id, limit });
        defer rows.deinit();

        var result: std.ArrayListUnmanaged(EventRecord) = .{};
        while (rows.next()) |row| {
            try result.append(allocator, EventRecord{
                .id = row.int(0),
                .created_at = row.int(1),
                .event_type = try allocator.dupe(u8, row.text(2)),
                .node_id = if (row.nullableText(3)) |v| try allocator.dupe(u8, v) else null,
                .message = try allocator.dupe(u8, row.text(4)),
                .detail = if (row.nullableText(5)) |v| try allocator.dupe(u8, v) else null,
            });
        }
        return try result.toOwnedSlice(allocator);
    }
};

pub const EventRecord = struct {
    id: i64,
    created_at: i64,
    event_type: []const u8,
    node_id: ?[]const u8,
    message: []const u8,
    detail: ?[]const u8,

    pub fn deinit(self: EventRecord, allocator: std.mem.Allocator) void {
        allocator.free(self.event_type);
        if (self.node_id) |v| allocator.free(v);
        allocator.free(self.message);
        if (self.detail) |v| allocator.free(v);
    }
};

pub const ScheduleRecord = struct {
    id: i64,
    name: []const u8,
    job_type: []const u8,
    config: []const u8,
    target_type: []const u8,
    target_value: ?[]const u8,
    cron_minute: []const u8,
    cron_hour: []const u8,
    cron_dom: []const u8,
    cron_month: []const u8,
    cron_dow: []const u8,
    enabled: bool,
    last_run: ?i64,
    last_status: ?[]const u8,
    created_at: i64,
    updated_at: i64,

    pub fn deinit(self: ScheduleRecord, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        allocator.free(self.job_type);
        allocator.free(self.config);
        allocator.free(self.target_type);
        if (self.target_value) |v| allocator.free(v);
        allocator.free(self.cron_minute);
        allocator.free(self.cron_hour);
        allocator.free(self.cron_dom);
        allocator.free(self.cron_month);
        allocator.free(self.cron_dow);
        if (self.last_status) |v| allocator.free(v);
    }
};

pub const ScheduleRunRecord = struct {
    id: i64,
    schedule_id: i64,
    started_at: i64,
    finished_at: ?i64,
    status: []const u8,
    output: ?[]const u8,

    pub fn deinit(self: ScheduleRunRecord, allocator: std.mem.Allocator) void {
        allocator.free(self.status);
        if (self.output) |v| allocator.free(v);
    }
};
