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
};
