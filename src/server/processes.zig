const std = @import("std");
const Db = @import("db.zig").Db;
const CryptoEngine = @import("crypto.zig").CryptoEngine;

pub const ProcessResult = struct {
    ok: bool,
    output: []const u8,
};

pub const ProcessEngine = struct {
    allocator: std.mem.Allocator,
    db: *Db,
    crypto: *const CryptoEngine,

    pub fn init(allocator: std.mem.Allocator, db: *Db, crypto: *const CryptoEngine) ProcessEngine {
        return .{ .allocator = allocator, .db = db, .crypto = crypto };
    }

    /// List processes on a node. Caller must free output.
    pub fn listProcesses(self: *ProcessEngine, node_id: []const u8) ProcessResult {
        const cmd = "ps aux --sort=-%cpu --no-headers -ww 2>&1";
        return self.runSshCommand(node_id, cmd, false);
    }

    /// Kill a process on a node. Caller must free output.
    pub fn killProcess(self: *ProcessEngine, node_id: []const u8, pid: u32, signal: u8) ProcessResult {
        // Validate PID (never allow killing PID 0 or 1)
        if (pid <= 1) return .{ .ok = false, .output = self.allocator.dupe(u8, "Cannot kill PID 0 or 1") catch "" };

        // Validate signal
        if (signal != 15 and signal != 9 and signal != 1) return .{ .ok = false, .output = self.allocator.dupe(u8, "Invalid signal (allowed: 1, 9, 15)") catch "" };

        const cmd = std.fmt.allocPrint(self.allocator, "kill -{d} {d} 2>&1", .{ signal, pid }) catch
            return .{ .ok = false, .output = "" };
        defer self.allocator.free(cmd);

        return self.runSshCommand(node_id, cmd, true);
    }

    // --- Internal ---

    fn runSshCommand(self: *ProcessEngine, node_id: []const u8, command: []const u8, use_sudo: bool) ProcessResult {
        const ctx = self.setupSsh(node_id) catch |err| {
            const msg = std.fmt.allocPrint(self.allocator, "SSH setup failed: {}", .{err}) catch "";
            return .{ .ok = false, .output = msg };
        };
        defer ctx.deinit(self);

        // Wrap with sudo if needed
        const wrapped = if (use_sudo and ctx.sudo_pass != null)
            std.fmt.allocPrint(self.allocator, "echo '{s}' | sudo -S -p '' {s}", .{ ctx.sudo_pass.?, command }) catch
                return .{ .ok = false, .output = "" }
        else if (use_sudo)
            std.fmt.allocPrint(self.allocator, "sudo -p '' {s}", .{command}) catch
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
            .max_output_bytes = 512 * 1024, // 512KB — process lists can be large
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

        fn deinit(self: SshContext, engine: *ProcessEngine) void {
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

    fn setupSsh(self: *ProcessEngine, node_id: []const u8) !SshContext {
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

        const tmp_key_path = try std.fmt.allocPrint(self.allocator, "/tmp/stardust_proc_{s}", .{node_id});
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

    fn decryptField(self: *ProcessEngine, enc: []const u8, nonce: []const u8, tag: []const u8) ![]u8 {
        if (nonce.len < 12 or tag.len < 16) return error.InvalidEncryptedData;
        return try self.crypto.decrypt(self.allocator, .{
            .ciphertext = enc,
            .nonce = nonce[0..12].*,
            .tag = tag[0..16].*,
            .salt = [_]u8{0} ** 16,
        });
    }
};
