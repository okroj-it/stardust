const std = @import("std");
const Db = @import("db.zig").Db;
const CryptoEngine = @import("crypto.zig").CryptoEngine;
const EncryptedData = @import("crypto.zig").EncryptedData;

pub const LogStreamJob = struct {
    output: std.ArrayListUnmanaged(u8) = .{},
    done: bool = false,
    ok: bool = false,
    mu: std.Thread.Mutex = .{},
    allocator: std.mem.Allocator,
    child_pid: ?std.posix.pid_t = null,

    const MAX_OUTPUT: usize = 1024 * 1024; // 1MB

    pub fn appendOutput(self: *LogStreamJob, data: []const u8) void {
        self.mu.lock();
        defer self.mu.unlock();
        self.output.appendSlice(self.allocator, data) catch {};

        // Truncate from front if exceeded
        if (self.output.items.len > MAX_OUTPUT) {
            const excess = self.output.items.len - MAX_OUTPUT;
            // Find the next newline after the excess point to truncate cleanly
            var cut = excess;
            while (cut < self.output.items.len and self.output.items[cut] != '\n') : (cut += 1) {}
            if (cut < self.output.items.len) cut += 1; // skip the newline
            // Shift remaining data to front
            const remaining = self.output.items.len - cut;
            std.mem.copyForwards(u8, self.output.items[0..remaining], self.output.items[cut..]);
            self.output.items.len = remaining;
        }
    }

    pub fn finish(self: *LogStreamJob, success: bool) void {
        self.mu.lock();
        defer self.mu.unlock();
        self.done = true;
        self.ok = success;
    }

    pub fn setChildPid(self: *LogStreamJob, pid: std.posix.pid_t) void {
        self.mu.lock();
        defer self.mu.unlock();
        self.child_pid = pid;
    }

    pub const JobState = struct {
        new_output: []const u8,
        done: bool,
        ok: bool,
    };

    pub fn getState(self: *LogStreamJob, offset: usize) JobState {
        self.mu.lock();
        defer self.mu.unlock();
        const start = @min(offset, self.output.items.len);
        return .{
            .new_output = self.output.items[start..],
            .done = self.done,
            .ok = self.ok,
        };
    }

    /// Send SIGTERM to the child SSH process to unblock the reader thread.
    /// Uses raw posix.kill() — NOT Child.kill() which also reaps (causing double-wait panic).
    pub fn requestStop(self: *LogStreamJob) void {
        self.mu.lock();
        defer self.mu.unlock();
        if (self.child_pid) |pid| {
            std.posix.kill(pid, std.posix.SIG.TERM) catch {};
        }
    }

    pub fn deinit(self: *LogStreamJob) void {
        self.output.deinit(self.allocator);
    }
};

pub const LogEngine = struct {
    allocator: std.mem.Allocator,
    db: *Db,
    crypto: *const CryptoEngine,
    jobs: std.StringHashMapUnmanaged(*LogStreamJob) = .{},
    jobs_mu: std.Thread.Mutex = .{},

    pub fn init(allocator: std.mem.Allocator, db: *Db, crypto: *const CryptoEngine) LogEngine {
        return .{ .allocator = allocator, .db = db, .crypto = crypto };
    }

    /// Start a log streaming job. Returns a job ID or null on failure.
    /// source: "journal" or "file"
    /// service: service name for journalctl -u (optional, journal mode only)
    /// path: file path for tail -f (file mode only)
    /// lines: number of initial lines (default 100)
    pub fn startLogStream(
        self: *LogEngine,
        node_id: []const u8,
        source: []const u8,
        service: ?[]const u8,
        file_path: ?[]const u8,
        lines: u32,
    ) ?[]const u8 {
        const ctx = self.setupSsh(node_id) catch return null;

        // Build the command
        const command = self.buildCommand(source, service, file_path, lines) orelse {
            ctx.deinit(self);
            return null;
        };
        defer self.allocator.free(command);

        // Wrap with sudo for journal access and root-owned log files
        const wrapped = if (ctx.sudo_pass) |pass|
            std.fmt.allocPrint(self.allocator, "echo '{s}' | sudo -S -p '' {s} 2>&1", .{ pass, command }) catch {
                ctx.deinit(self);
                return null;
            }
        else
            std.fmt.allocPrint(self.allocator, "sudo -p '' {s} 2>&1", .{command}) catch {
                ctx.deinit(self);
                return null;
            };

        // Create the job
        const job = self.allocator.create(LogStreamJob) catch {
            self.allocator.free(wrapped);
            ctx.deinit(self);
            return null;
        };
        job.* = .{ .allocator = self.allocator };

        // Generate job ID
        var id_bytes: [8]u8 = undefined;
        std.crypto.random.bytes(&id_bytes);
        var hex_buf: [16]u8 = undefined;
        const hex = std.fmt.bufPrint(&hex_buf, "{x:0>16}", .{std.mem.readInt(u64, &id_bytes, .big)}) catch {
            self.allocator.destroy(job);
            self.allocator.free(wrapped);
            ctx.deinit(self);
            return null;
        };
        const job_id = self.allocator.dupe(u8, hex) catch {
            self.allocator.destroy(job);
            self.allocator.free(wrapped);
            ctx.deinit(self);
            return null;
        };

        // Store the job
        self.jobs_mu.lock();
        self.jobs.put(self.allocator, job_id, job) catch {
            self.jobs_mu.unlock();
            self.allocator.free(job_id);
            self.allocator.destroy(job);
            self.allocator.free(wrapped);
            ctx.deinit(self);
            return null;
        };
        self.jobs_mu.unlock();

        // Spawn worker thread
        const thread_ctx = self.allocator.create(StreamThreadCtx) catch {
            self.allocator.free(wrapped);
            ctx.deinit(self);
            return null;
        };
        thread_ctx.* = .{
            .job = job,
            .allocator = self.allocator,
            .key_path = ctx.tmp_key_path,
            .port = ctx.port_str,
            .host_arg = ctx.host_arg,
            .ssh_key = ctx.ssh_key,
            .sudo_pass = ctx.sudo_pass,
            .wrapped_cmd = wrapped,
        };

        const thread = std.Thread.spawn(.{}, streamWorker, .{thread_ctx}) catch {
            self.allocator.free(wrapped);
            self.allocator.destroy(thread_ctx);
            ctx.deinit(self);
            return null;
        };
        thread.detach();

        return job_id;
    }

    pub fn pollLogStream(self: *LogEngine, job_id: []const u8, offset: usize) ?LogStreamJob.JobState {
        self.jobs_mu.lock();
        const job = self.jobs.get(job_id);
        self.jobs_mu.unlock();
        if (job) |j| {
            return j.getState(offset);
        }
        return null;
    }

    pub fn stopLogStream(self: *LogEngine, job_id: []const u8) void {
        self.jobs_mu.lock();
        const job = self.jobs.get(job_id);
        self.jobs_mu.unlock();
        if (job) |j| {
            j.requestStop();
        }
    }

    pub fn removeJob(self: *LogEngine, job_id: []const u8) void {
        self.jobs_mu.lock();
        defer self.jobs_mu.unlock();
        if (self.jobs.fetchRemove(job_id)) |kv| {
            kv.value.deinit();
            self.allocator.destroy(kv.value);
            self.allocator.free(kv.key);
        }
    }

    // --- Internal ---

    fn buildCommand(self: *LogEngine, source: []const u8, service: ?[]const u8, file_path: ?[]const u8, lines: u32) ?[]const u8 {
        if (std.mem.eql(u8, source, "journal")) {
            if (service) |svc| {
                if (svc.len > 0) {
                    if (!isValidServiceName(svc)) return null;
                    return std.fmt.allocPrint(self.allocator, "journalctl -f -u {s} -n {d} --no-pager", .{ svc, lines }) catch null;
                }
            }
            return std.fmt.allocPrint(self.allocator, "journalctl -f -n {d} --no-pager", .{lines}) catch null;
        } else if (std.mem.eql(u8, source, "file")) {
            const path = file_path orelse return null;
            if (!isValidFilePath(path)) return null;
            return std.fmt.allocPrint(self.allocator, "tail -f -n {d} {s}", .{ lines, path }) catch null;
        }
        return null;
    }

    const StreamThreadCtx = struct {
        job: *LogStreamJob,
        allocator: std.mem.Allocator,
        key_path: []const u8,
        port: []const u8,
        host_arg: []const u8,
        ssh_key: []u8,
        sudo_pass: ?[]u8,
        wrapped_cmd: []const u8,

        fn deinit(self: *StreamThreadCtx) void {
            std.fs.cwd().deleteFile(self.key_path) catch {};
            self.allocator.free(self.key_path);
            self.allocator.free(self.host_arg);
            self.allocator.free(self.port);
            std.crypto.secureZero(u8, self.ssh_key);
            self.allocator.free(self.ssh_key);
            if (self.sudo_pass) |p| {
                std.crypto.secureZero(u8, p);
                self.allocator.free(p);
            }
            self.allocator.free(self.wrapped_cmd);
            self.allocator.destroy(self);
        }
    };

    fn streamWorker(ctx: *StreamThreadCtx) void {
        defer ctx.deinit();

        var child = std.process.Child.init(
            &.{
                "ssh", "-i", ctx.key_path, "-p", ctx.port,
                "-o", "StrictHostKeyChecking=no", "-o", "BatchMode=yes",
                "-o", "ConnectTimeout=10",
                ctx.host_arg, ctx.wrapped_cmd,
            },
            ctx.allocator,
        );
        child.stdout_behavior = .Pipe;
        child.stderr_behavior = .Pipe;

        child.spawn() catch {
            ctx.job.appendOutput("Failed to start SSH process\n");
            ctx.job.finish(false);
            return;
        };

        // Store just the PID so requestStop() can send SIGTERM via posix.kill().
        // We must NOT store the Child struct — Child.kill() also reaps the process,
        // which would cause a double-wait panic when the worker calls child.wait().
        ctx.job.setChildPid(child.id);

        // Read stdout in chunks
        const stdout = child.stdout orelse {
            ctx.job.appendOutput("No stdout pipe\n");
            ctx.job.finish(false);
            return;
        };
        var buf: [4096]u8 = undefined;
        while (true) {
            const n = stdout.read(&buf) catch break;
            if (n == 0) break;
            ctx.job.appendOutput(buf[0..n]);
        }

        // Wait for the child to be reaped (this is the only wait call for this child)
        _ = child.wait() catch {};
        ctx.job.finish(true);
    }

    const SshContext = struct {
        tmp_key_path: []const u8,
        host_arg: []const u8,
        port_str: []const u8,
        ssh_key: []u8,
        sudo_pass: ?[]u8,

        fn deinit(self: SshContext, engine: *LogEngine) void {
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

    fn setupSsh(self: *LogEngine, node_id: []const u8) !SshContext {
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

        const tmp_key_path = try std.fmt.allocPrint(self.allocator, "/tmp/stardust_log_{s}", .{node_id});
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

    fn decryptField(self: *LogEngine, enc: []const u8, nonce: []const u8, tag: []const u8) ![]u8 {
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

fn isValidFilePath(path: []const u8) bool {
    if (path.len == 0 or path.len > 4096) return false;
    // Must start with /
    if (path[0] != '/') return false;
    // No shell metacharacters
    for (path) |c| {
        switch (c) {
            ';', '|', '&', '$', '`', '<', '>', '(', ')', '{', '}', '[', ']', '!', '*', '?', '~', '\'', '"' => return false,
            else => {},
        }
    }
    return true;
}
