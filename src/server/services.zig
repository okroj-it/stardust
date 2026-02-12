const std = @import("std");
const Db = @import("db.zig").Db;
const CryptoEngine = @import("crypto.zig").CryptoEngine;

pub const ServiceScope = enum {
    system,
    user,

    pub fn fromString(s: []const u8) ServiceScope {
        if (std.mem.eql(u8, s, "user")) return .user;
        return .system; // default
    }
};

pub const ServiceResult = struct {
    ok: bool,
    output: []const u8,
};

pub const ServiceEngine = struct {
    allocator: std.mem.Allocator,
    db: *Db,
    crypto: *const CryptoEngine,

    pub fn init(allocator: std.mem.Allocator, db: *Db, crypto: *const CryptoEngine) ServiceEngine {
        return .{ .allocator = allocator, .db = db, .crypto = crypto };
    }

    /// List all services on a node. Caller must free output.
    pub fn listServices(self: *ServiceEngine, node_id: []const u8, scope: ServiceScope) ServiceResult {
        const cmd = switch (scope) {
            .system => "systemctl list-units --type=service --all --no-pager --plain --no-legend 2>&1",
            .user => "XDG_RUNTIME_DIR=/run/user/$(id -u) systemctl --user list-units --type=service --all --no-pager --plain --no-legend 2>&1",
        };
        return self.runSshCommand(node_id, cmd, scope == .system);
    }

    /// Get detailed status for a specific service. Caller must free output.
    pub fn serviceStatus(self: *ServiceEngine, node_id: []const u8, name: []const u8, scope: ServiceScope) ServiceResult {
        if (!isValidServiceName(name)) return .{ .ok = false, .output = self.allocator.dupe(u8, "Invalid service name") catch "" };

        const cmd = switch (scope) {
            .system => std.fmt.allocPrint(self.allocator, "systemctl status {s} --no-pager -l 2>&1", .{name}) catch
                return .{ .ok = false, .output = "" },
            .user => std.fmt.allocPrint(self.allocator, "XDG_RUNTIME_DIR=/run/user/$(id -u) systemctl --user status {s} --no-pager -l 2>&1", .{name}) catch
                return .{ .ok = false, .output = "" },
        };
        defer self.allocator.free(cmd);

        return self.runSshCommand(node_id, cmd, scope == .system);
    }

    /// Execute a service action (start/stop/restart/enable/disable). Caller must free output.
    pub fn serviceAction(self: *ServiceEngine, node_id: []const u8, name: []const u8, action: []const u8, scope: ServiceScope) ServiceResult {
        if (!isValidServiceName(name)) return .{ .ok = false, .output = self.allocator.dupe(u8, "Invalid service name") catch "" };
        if (!isValidAction(action)) return .{ .ok = false, .output = self.allocator.dupe(u8, "Invalid action") catch "" };

        const cmd = switch (scope) {
            .system => std.fmt.allocPrint(self.allocator, "systemctl {s} {s} 2>&1", .{ action, name }) catch
                return .{ .ok = false, .output = "" },
            .user => std.fmt.allocPrint(self.allocator, "XDG_RUNTIME_DIR=/run/user/$(id -u) systemctl --user {s} {s} 2>&1", .{ action, name }) catch
                return .{ .ok = false, .output = "" },
        };
        defer self.allocator.free(cmd);

        // Actions on system services need sudo
        return self.runSshCommand(node_id, cmd, scope == .system);
    }

    // --- Internal ---

    fn runSshCommand(self: *ServiceEngine, node_id: []const u8, command: []const u8, use_sudo: bool) ServiceResult {
        const ctx = self.setupSsh(node_id) catch |err| {
            const msg = std.fmt.allocPrint(self.allocator, "SSH setup failed: {}", .{err}) catch "";
            return .{ .ok = false, .output = msg };
        };
        defer ctx.deinit(self);

        // Wrap with sudo if needed
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
            .max_output_bytes = 256 * 1024,
        }) catch |err| {
            const msg = std.fmt.allocPrint(self.allocator, "SSH command failed: {}", .{err}) catch "";
            return .{ .ok = false, .output = msg };
        };
        defer self.allocator.free(result.stderr);

        const ok = result.term.Exited == 0;
        return .{ .ok = ok, .output = result.stdout };
    }

    const SshContext = struct {
        tmp_key_path: []const u8,
        host_arg: []const u8,
        port_str: []const u8,
        ssh_key: []u8,
        sudo_pass: ?[]u8,

        fn deinit(self: SshContext, engine: *ServiceEngine) void {
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

    fn setupSsh(self: *ServiceEngine, node_id: []const u8) !SshContext {
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

        const tmp_key_path = try std.fmt.allocPrint(self.allocator, "/tmp/stardust_svc_{s}", .{node_id});
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

    fn decryptField(self: *ServiceEngine, enc: []const u8, nonce: []const u8, tag: []const u8) ![]u8 {
        if (nonce.len < 12 or tag.len < 16) return error.InvalidEncryptedData;
        return try self.crypto.decrypt(self.allocator, .{
            .ciphertext = enc,
            .nonce = nonce[0..12].*,
            .tag = tag[0..16].*,
            .salt = [_]u8{0} ** 16,
        });
    }
};

fn isValidServiceName(name: []const u8) bool {
    if (name.len == 0 or name.len > 256) return false;
    for (name) |c| {
        if (!std.ascii.isAlphanumeric(c) and c != '-' and c != '_' and c != '.' and c != '@') return false;
    }
    return true;
}

fn isValidAction(action: []const u8) bool {
    const valid = [_][]const u8{ "start", "stop", "restart", "enable", "disable" };
    for (valid) |v| {
        if (std.mem.eql(u8, action, v)) return true;
    }
    return false;
}
