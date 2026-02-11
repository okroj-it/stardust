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

        // Migration: add sudo columns if missing (for existing DBs)
        conn.execNoArgs("ALTER TABLE nodes ADD COLUMN sudo_pass_enc BLOB") catch {};
        conn.execNoArgs("ALTER TABLE nodes ADD COLUMN sudo_pass_nonce BLOB") catch {};
        conn.execNoArgs("ALTER TABLE nodes ADD COLUMN sudo_pass_tag BLOB") catch {};

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
            \\       status, agent_token, created_at, last_seen
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
            };
        }
        return null;
    }

    /// List all nodes. Caller must call deinit(allocator) on each record and free the slice.
    pub fn listNodes(self: *Db, allocator: std.mem.Allocator) ![]NodeRecord {
        var rows = try self.conn.rows(
            \\SELECT id, name, host, port, ssh_user, ssh_key_enc, ssh_key_nonce, ssh_key_tag,
            \\       sudo_pass_enc, sudo_pass_nonce, sudo_pass_tag,
            \\       status, agent_token, created_at, last_seen
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

    /// Wipe encrypted credentials (SSH key + sudo password) for a node.
    pub fn wipeCredentials(self: *Db, id: []const u8) !void {
        try self.conn.exec(
            \\UPDATE nodes SET
            \\  ssh_key_enc = zeroblob(0), ssh_key_nonce = zeroblob(0), ssh_key_tag = zeroblob(0),
            \\  sudo_pass_enc = NULL, sudo_pass_nonce = NULL, sudo_pass_tag = NULL
            \\WHERE id = ?1
        , .{id});
    }

    /// Delete a node.
    pub fn deleteNode(self: *Db, id: []const u8) !void {
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
};
