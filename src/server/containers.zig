const std = @import("std");
const Db = @import("db.zig").Db;
const CryptoEngine = @import("crypto.zig").CryptoEngine;

pub const ContainerResult = struct {
    ok: bool,
    output: []const u8,
};

pub const ContainerEngine = struct {
    allocator: std.mem.Allocator,
    db: *Db,
    crypto: *const CryptoEngine,

    pub fn init(allocator: std.mem.Allocator, db: *Db, crypto: *const CryptoEngine) ContainerEngine {
        return .{ .allocator = allocator, .db = db, .crypto = crypto };
    }

    /// List all containers (docker || podman). Caller must free output.
    pub fn listContainers(self: *ContainerEngine, node_id: []const u8) ContainerResult {
        const cmd =
            "docker ps -a --format '{{.ID}}\\t{{.Names}}\\t{{.Image}}\\t{{.Status}}\\t{{.State}}\\t{{.Ports}}\\t{{.Size}}' 2>&1 " ++
            "|| podman ps -a --format '{{.ID}}\\t{{.Names}}\\t{{.Image}}\\t{{.Status}}\\t{{.State}}\\t{{.Ports}}\\t{{.Size}}' 2>&1";
        return self.runSshCommand(node_id, cmd, true);
    }

    /// Inspect a container. Caller must free output.
    pub fn containerInspect(self: *ContainerEngine, node_id: []const u8, container_id: []const u8) ContainerResult {
        if (!isValidContainerId(container_id)) return .{ .ok = false, .output = self.allocator.dupe(u8, "Invalid container ID") catch "" };

        const cmd = std.fmt.allocPrint(self.allocator, "docker inspect {s} 2>&1 || podman inspect {s} 2>&1", .{ container_id, container_id }) catch
            return .{ .ok = false, .output = "" };
        defer self.allocator.free(cmd);

        return self.runSshCommand(node_id, cmd, true);
    }

    /// Execute a container action (start/stop/restart/pause/unpause/rm). Caller must free output.
    pub fn containerAction(self: *ContainerEngine, node_id: []const u8, container_id: []const u8, action: []const u8) ContainerResult {
        if (!isValidContainerId(container_id)) return .{ .ok = false, .output = self.allocator.dupe(u8, "Invalid container ID") catch "" };
        if (!isValidAction(action)) return .{ .ok = false, .output = self.allocator.dupe(u8, "Invalid action") catch "" };

        const cmd = std.fmt.allocPrint(self.allocator, "docker {s} {s} 2>&1 || podman {s} {s} 2>&1", .{ action, container_id, action, container_id }) catch
            return .{ .ok = false, .output = "" };
        defer self.allocator.free(cmd);

        return self.runSshCommand(node_id, cmd, true);
    }

    /// Fetch container logs. Caller must free output.
    pub fn containerLogs(self: *ContainerEngine, node_id: []const u8, container_id: []const u8, tail: u32) ContainerResult {
        if (!isValidContainerId(container_id)) return .{ .ok = false, .output = self.allocator.dupe(u8, "Invalid container ID") catch "" };

        const t = if (tail > 500) @as(u32, 500) else if (tail == 0) @as(u32, 100) else tail;
        const cmd = std.fmt.allocPrint(self.allocator, "docker logs --tail {d} {s} 2>&1 || podman logs --tail {d} {s} 2>&1", .{ t, container_id, t, container_id }) catch
            return .{ .ok = false, .output = "" };
        defer self.allocator.free(cmd);

        return self.runSshCommand(node_id, cmd, true);
    }

    // --- Internal ---

    fn runSshCommand(self: *ContainerEngine, node_id: []const u8, command: []const u8, use_sudo: bool) ContainerResult {
        const ctx = self.setupSsh(node_id) catch |err| {
            const msg = std.fmt.allocPrint(self.allocator, "SSH setup failed: {}", .{err}) catch "";
            return .{ .ok = false, .output = msg };
        };
        defer ctx.deinit(self);

        const wrapped = if (use_sudo and ctx.sudo_pass != null)
            std.fmt.allocPrint(self.allocator, "echo '{s}' | sudo -S {s}", .{ ctx.sudo_pass.?, command }) catch
                return .{ .ok = false, .output = "" }
        else if (use_sudo)
            std.fmt.allocPrint(self.allocator, "sudo {s}", .{command}) catch
                return .{ .ok = false, .output = "" }
        else
            self.allocator.dupe(u8, command) catch
                return .{ .ok = false, .output = "" };
        defer self.allocator.free(wrapped);

        const result = std.process.Child.run(.{
            .allocator = self.allocator,
            .argv = &.{
                "ssh", "-i", ctx.tmp_key_path, "-p", ctx.port_str,
                "-o", "StrictHostKeyChecking=no", "-o", "BatchMode=yes",
                "-o", "ConnectTimeout=10",
                ctx.host_arg, wrapped,
            },
            .max_output_bytes = 512 * 1024,
        }) catch |err| {
            const msg = std.fmt.allocPrint(self.allocator, "SSH command failed: {}", .{err}) catch "";
            return .{ .ok = false, .output = msg };
        };
        defer self.allocator.free(result.stderr);

        const ok = result.term.Exited == 0;
        // Strip [sudo] prompt lines that leak via 2>&1
        const output = stripSudoNoise(self.allocator, result.stdout);
        return .{ .ok = ok, .output = output };
    }

    const SshContext = struct {
        tmp_key_path: []const u8,
        host_arg: []const u8,
        port_str: []const u8,
        ssh_key: []u8,
        sudo_pass: ?[]u8,

        fn deinit(self: SshContext, engine: *ContainerEngine) void {
            std.fs.cwd().deleteFile(self.tmp_key_path) catch {};
            engine.allocator.free(self.tmp_key_path);
            engine.allocator.free(self.host_arg);
            engine.allocator.free(self.port_str);
            std.crypto.secureZero(u8, self.ssh_key);
            engine.allocator.free(self.ssh_key);
            if (self.sudo_pass) |p| {
                std.crypto.secureZero(u8, @constCast(p));
                engine.allocator.free(p);
            }
        }
    };

    fn setupSsh(self: *ContainerEngine, node_id: []const u8) !SshContext {
        const node = (try self.db.getNode(self.allocator, node_id)) orelse return error.NodeNotFound;
        defer node.deinit(self.allocator);

        const ssh_key = try self.decryptField(node.ssh_key_enc, node.ssh_key_nonce, node.ssh_key_tag);
        errdefer {
            std.crypto.secureZero(u8, ssh_key);
            self.allocator.free(ssh_key);
        }

        var sudo_pass: ?[]u8 = null;
        if (node.sudo_pass_enc) |enc| {
            if (node.sudo_pass_nonce) |nonce| {
                if (node.sudo_pass_tag) |tag| {
                    sudo_pass = self.decryptField(enc, nonce, tag) catch null;
                }
            }
        }

        const tmp_key_path = try std.fmt.allocPrint(self.allocator, "/tmp/stardust_ctr_{s}", .{node_id});
        errdefer self.allocator.free(tmp_key_path);

        {
            const file = try std.fs.cwd().createFile(tmp_key_path, .{ .mode = 0o600 });
            defer file.close();
            try file.writeAll(ssh_key);
        }

        const host_arg = try std.fmt.allocPrint(self.allocator, "{s}@{s}", .{ node.ssh_user, node.host });
        errdefer self.allocator.free(host_arg);

        const port_str = try std.fmt.allocPrint(self.allocator, "{d}", .{node.port});

        return .{
            .tmp_key_path = tmp_key_path,
            .host_arg = host_arg,
            .port_str = port_str,
            .ssh_key = ssh_key,
            .sudo_pass = sudo_pass,
        };
    }

    fn decryptField(self: *ContainerEngine, enc: []const u8, nonce: []const u8, tag: []const u8) ![]u8 {
        if (nonce.len < 12 or tag.len < 16) return error.InvalidEncryptedData;
        return try self.crypto.decrypt(self.allocator, .{
            .ciphertext = enc,
            .nonce = nonce[0..12].*,
            .tag = tag[0..16].*,
            .salt = [_]u8{0} ** 16,
        });
    }
};

fn isValidContainerId(id: []const u8) bool {
    if (id.len == 0 or id.len > 128) return false;
    for (id) |c| {
        if (!std.ascii.isAlphanumeric(c) and c != '_' and c != '.' and c != '-') return false;
    }
    return true;
}

fn stripSudoNoise(allocator: std.mem.Allocator, raw: []const u8) []const u8 {
    // Filter out "[sudo] password for ..." lines from output
    var buf: std.ArrayListUnmanaged(u8) = .{};
    var iter = std.mem.splitScalar(u8, raw, '\n');
    var first = true;
    while (iter.next()) |line| {
        if (std.mem.startsWith(u8, line, "[sudo]")) continue;
        if (!first) buf.append(allocator, '\n') catch {};
        buf.appendSlice(allocator, line) catch {};
        first = false;
    }
    allocator.free(raw);
    return buf.toOwnedSlice(allocator) catch "";
}

fn isValidAction(action: []const u8) bool {
    const valid = [_][]const u8{ "start", "stop", "restart", "pause", "unpause", "rm" };
    for (valid) |v| {
        if (std.mem.eql(u8, action, v)) return true;
    }
    return false;
}
