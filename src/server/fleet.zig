const std = @import("std");
const Db = @import("db.zig").Db;
const CryptoEngine = @import("crypto.zig").CryptoEngine;
const EncryptedData = @import("crypto.zig").EncryptedData;
const StreamJob = @import("deployer.zig").StreamJob;
const JobState = @import("deployer.zig").JobState;

pub const FleetEngine = struct {
    allocator: std.mem.Allocator,
    db: *Db,
    crypto: *const CryptoEngine,
    jobs: std.StringHashMapUnmanaged(*FleetJob) = .{},
    jobs_mu: std.Thread.Mutex = .{},

    pub fn init(allocator: std.mem.Allocator, db: *Db, crypto: *const CryptoEngine) FleetEngine {
        return .{ .allocator = allocator, .db = db, .crypto = crypto };
    }

    /// Start a command across multiple nodes. Returns job ID or null on failure.
    pub fn runCommand(
        self: *FleetEngine,
        command: []const u8,
        node_ids: []const []const u8,
        sudo: bool,
    ) ?[]const u8 {
        // Generate job ID
        var id_bytes: [8]u8 = undefined;
        std.crypto.random.bytes(&id_bytes);
        var hex_buf: [16]u8 = undefined;
        const hex = std.fmt.bufPrint(&hex_buf, "{x:0>16}", .{std.mem.readInt(u64, &id_bytes, .big)}) catch return null;
        const job_id = self.allocator.dupe(u8, hex) catch return null;

        // Create fleet job
        const fleet_job = self.allocator.create(FleetJob) catch {
            self.allocator.free(job_id);
            return null;
        };
        fleet_job.* = .{
            .allocator = self.allocator,
            .command = self.allocator.dupe(u8, command) catch {
                self.allocator.destroy(fleet_job);
                self.allocator.free(job_id);
                return null;
            },
        };

        // Store job
        self.jobs_mu.lock();
        self.jobs.put(self.allocator, job_id, fleet_job) catch {
            self.jobs_mu.unlock();
            self.allocator.free(fleet_job.command);
            self.allocator.destroy(fleet_job);
            self.allocator.free(job_id);
            return null;
        };
        self.jobs_mu.unlock();

        // Spawn a worker for each node
        for (node_ids) |node_id| {
            self.spawnNodeWorker(fleet_job, node_id, command, sudo);
        }

        std.log.info("[STARMAN] Fleet command started: '{s}' across {d} nodes (job={s})", .{
            command[0..@min(command.len, 60)], node_ids.len, job_id,
        });

        return job_id;
    }

    /// Poll a fleet job. Returns per-node results.
    pub fn pollJob(self: *FleetEngine, job_id: []const u8, offsets_keys: []const []const u8, offsets_vals: []const usize) ?FleetPollResult {
        self.jobs_mu.lock();
        const fleet_job = self.jobs.get(job_id);
        self.jobs_mu.unlock();
        const fj = fleet_job orelse return null;

        fj.mu.lock();
        defer fj.mu.unlock();

        var result = FleetPollResult{
            .all_done = true,
        };

        // Iterate all nodes in the job
        var it = fj.node_jobs.iterator();
        while (it.next()) |entry| {
            const nid = entry.key_ptr.*;
            const sj = entry.value_ptr.*;

            // Find offset for this node
            var offset: usize = 0;
            for (offsets_keys, 0..) |k, i| {
                if (std.mem.eql(u8, k, nid)) {
                    offset = offsets_vals[i];
                    break;
                }
            }

            const state = sj.getState(offset);
            if (!state.done) result.all_done = false;

            // Store in result (up to max nodes)
            if (result.count < FleetPollResult.MAX_NODES) {
                const name = fj.node_names.get(nid) orelse nid;
                result.entries[result.count] = .{
                    .node_id = nid,
                    .node_name = name,
                    .new_output = state.new_output,
                    .offset = offset + state.new_output.len,
                    .done = state.done,
                    .ok = state.ok,
                };
                result.count += 1;
            }
        }

        return result;
    }

    /// Remove a completed job and free all resources.
    pub fn removeJob(self: *FleetEngine, job_id: []const u8) void {
        self.jobs_mu.lock();
        defer self.jobs_mu.unlock();
        if (self.jobs.fetchRemove(job_id)) |kv| {
            kv.value.deinit();
            self.allocator.destroy(kv.value);
            self.allocator.free(kv.key);
        }
    }

    // --- Internal ---

    fn spawnNodeWorker(self: *FleetEngine, fleet_job: *FleetJob, node_id: []const u8, command: []const u8, sudo: bool) void {
        // Set up SSH context for this node
        const node = self.db.getNode(self.allocator, node_id) catch {
            self.addFailedNode(fleet_job, node_id, "?", "Failed to look up node");
            return;
        } orelse {
            self.addFailedNode(fleet_job, node_id, "?", "Node not found");
            return;
        };
        defer node.deinit(self.allocator);

        const node_name_dupe = self.allocator.dupe(u8, node.name) catch {
            self.addFailedNode(fleet_job, node_id, "?", "Out of memory");
            return;
        };

        const ssh_key = self.decryptField(node.ssh_key_enc, node.ssh_key_nonce, node.ssh_key_tag) catch {
            self.addFailedNode(fleet_job, node_id, node_name_dupe, "Failed to decrypt SSH key");
            return;
        };
        errdefer {
            std.crypto.secureZero(u8, ssh_key);
            self.allocator.free(ssh_key);
        }

        var sudo_pass: ?[]u8 = null;
        if (sudo) {
            if (node.sudo_pass_enc) |enc| {
                if (node.sudo_pass_nonce) |nonce| {
                    if (node.sudo_pass_tag) |tag| {
                        sudo_pass = self.decryptField(enc, nonce, tag) catch null;
                    }
                }
            }
        }

        const node_id_dupe = self.allocator.dupe(u8, node_id) catch {
            std.crypto.secureZero(u8, ssh_key);
            self.allocator.free(ssh_key);
            if (sudo_pass) |p| {
                std.crypto.secureZero(u8, p);
                self.allocator.free(p);
            }
            self.allocator.free(node_name_dupe);
            return;
        };

        const tmp_key_path = std.fmt.allocPrint(self.allocator, "/tmp/stardust_fleet_{s}", .{node_id}) catch {
            self.allocator.free(node_id_dupe);
            std.crypto.secureZero(u8, ssh_key);
            self.allocator.free(ssh_key);
            if (sudo_pass) |p| {
                std.crypto.secureZero(u8, p);
                self.allocator.free(p);
            }
            self.allocator.free(node_name_dupe);
            return;
        };

        // Write temp key
        {
            const file = std.fs.cwd().createFile(tmp_key_path, .{ .mode = 0o600 }) catch {
                self.addFailedNode(fleet_job, node_id_dupe, node_name_dupe, "Failed to write temp key");
                self.allocator.free(tmp_key_path);
                std.crypto.secureZero(u8, ssh_key);
                self.allocator.free(ssh_key);
                if (sudo_pass) |p| {
                    std.crypto.secureZero(u8, p);
                    self.allocator.free(p);
                }
                return;
            };
            defer file.close();
            file.writeAll(ssh_key) catch {
                self.addFailedNode(fleet_job, node_id_dupe, node_name_dupe, "Failed to write temp key");
                self.allocator.free(tmp_key_path);
                std.crypto.secureZero(u8, ssh_key);
                self.allocator.free(ssh_key);
                if (sudo_pass) |p| {
                    std.crypto.secureZero(u8, p);
                    self.allocator.free(p);
                }
                return;
            };
        }

        const host_arg = std.fmt.allocPrint(self.allocator, "{s}@{s}", .{ node.ssh_user, node.host }) catch {
            self.allocator.free(node_id_dupe);
            self.allocator.free(node_name_dupe);
            self.allocator.free(tmp_key_path);
            std.crypto.secureZero(u8, ssh_key);
            self.allocator.free(ssh_key);
            if (sudo_pass) |p| {
                std.crypto.secureZero(u8, p);
                self.allocator.free(p);
            }
            return;
        };

        const port_str = std.fmt.allocPrint(self.allocator, "{d}", .{node.port}) catch {
            self.allocator.free(node_id_dupe);
            self.allocator.free(node_name_dupe);
            self.allocator.free(tmp_key_path);
            self.allocator.free(host_arg);
            std.crypto.secureZero(u8, ssh_key);
            self.allocator.free(ssh_key);
            if (sudo_pass) |p| {
                std.crypto.secureZero(u8, p);
                self.allocator.free(p);
            }
            return;
        };

        // Wrap command for sudo if needed
        const wrapped_cmd = if (sudo and sudo_pass != null)
            std.fmt.allocPrint(self.allocator, "echo '{s}' | sudo -S bash -c '{s}' 2>&1", .{ sudo_pass.?, command }) catch {
                self.allocator.free(node_id_dupe);
                self.allocator.free(node_name_dupe);
                self.allocator.free(tmp_key_path);
                self.allocator.free(host_arg);
                self.allocator.free(port_str);
                std.crypto.secureZero(u8, ssh_key);
                self.allocator.free(ssh_key);
                if (sudo_pass) |p| {
                    std.crypto.secureZero(u8, p);
                    self.allocator.free(p);
                }
                return;
            }
        else if (sudo)
            std.fmt.allocPrint(self.allocator, "sudo bash -c '{s}' 2>&1", .{command}) catch {
                self.allocator.free(node_id_dupe);
                self.allocator.free(node_name_dupe);
                self.allocator.free(tmp_key_path);
                self.allocator.free(host_arg);
                self.allocator.free(port_str);
                std.crypto.secureZero(u8, ssh_key);
                self.allocator.free(ssh_key);
                return;
            }
        else
            std.fmt.allocPrint(self.allocator, "{s} 2>&1", .{command}) catch {
                self.allocator.free(node_id_dupe);
                self.allocator.free(node_name_dupe);
                self.allocator.free(tmp_key_path);
                self.allocator.free(host_arg);
                self.allocator.free(port_str);
                std.crypto.secureZero(u8, ssh_key);
                self.allocator.free(ssh_key);
                return;
            };

        // Create StreamJob for this node
        const sj = self.allocator.create(StreamJob) catch {
            self.allocator.free(node_id_dupe);
            self.allocator.free(node_name_dupe);
            self.allocator.free(tmp_key_path);
            self.allocator.free(host_arg);
            self.allocator.free(port_str);
            self.allocator.free(wrapped_cmd);
            std.crypto.secureZero(u8, ssh_key);
            self.allocator.free(ssh_key);
            if (sudo_pass) |p| {
                std.crypto.secureZero(u8, p);
                self.allocator.free(p);
            }
            return;
        };
        sj.* = .{ .allocator = self.allocator };

        // Register in fleet job
        fleet_job.mu.lock();
        fleet_job.node_jobs.put(self.allocator, node_id_dupe, sj) catch {
            fleet_job.mu.unlock();
            self.allocator.destroy(sj);
            self.allocator.free(node_id_dupe);
            self.allocator.free(node_name_dupe);
            self.allocator.free(tmp_key_path);
            self.allocator.free(host_arg);
            self.allocator.free(port_str);
            self.allocator.free(wrapped_cmd);
            std.crypto.secureZero(u8, ssh_key);
            self.allocator.free(ssh_key);
            if (sudo_pass) |p| {
                std.crypto.secureZero(u8, p);
                self.allocator.free(p);
            }
            return;
        };
        fleet_job.node_names.put(self.allocator, node_id_dupe, node_name_dupe) catch {};
        fleet_job.mu.unlock();

        // Build thread context
        const ctx = self.allocator.create(FleetWorkerCtx) catch {
            // StreamJob is already registered, just mark it failed
            sj.appendOutput("Failed to allocate thread context\n");
            sj.finish(false);
            self.allocator.free(tmp_key_path);
            self.allocator.free(host_arg);
            self.allocator.free(port_str);
            self.allocator.free(wrapped_cmd);
            std.crypto.secureZero(u8, ssh_key);
            self.allocator.free(ssh_key);
            if (sudo_pass) |p| {
                std.crypto.secureZero(u8, p);
                self.allocator.free(p);
            }
            return;
        };
        ctx.* = .{
            .job = sj,
            .allocator = self.allocator,
            .key_path = tmp_key_path,
            .port = port_str,
            .host_arg = host_arg,
            .ssh_key = ssh_key,
            .sudo_pass = sudo_pass,
            .wrapped_cmd = wrapped_cmd,
        };

        const thread = std.Thread.spawn(.{}, fleetWorker, .{ctx}) catch {
            sj.appendOutput("Failed to spawn worker thread\n");
            sj.finish(false);
            ctx.deinit();
            return;
        };
        thread.detach();
    }

    fn addFailedNode(self: *FleetEngine, fleet_job: *FleetJob, node_id: []const u8, node_name: []const u8, msg: []const u8) void {
        const sj = self.allocator.create(StreamJob) catch return;
        sj.* = .{ .allocator = self.allocator };
        sj.appendOutput(msg);
        sj.appendOutput("\n");
        sj.finish(false);

        const nid = self.allocator.dupe(u8, node_id) catch {
            self.allocator.destroy(sj);
            return;
        };
        const nname = self.allocator.dupe(u8, node_name) catch {
            self.allocator.free(nid);
            self.allocator.destroy(sj);
            return;
        };

        fleet_job.mu.lock();
        fleet_job.node_jobs.put(self.allocator, nid, sj) catch {
            fleet_job.mu.unlock();
            self.allocator.free(nid);
            self.allocator.free(nname);
            self.allocator.destroy(sj);
            return;
        };
        fleet_job.node_names.put(self.allocator, nid, nname) catch {};
        fleet_job.mu.unlock();
    }

    fn decryptField(self: *FleetEngine, enc: []const u8, nonce: []const u8, tag: []const u8) ![]u8 {
        if (nonce.len < 12 or tag.len < 16) return error.InvalidEncryptedData;
        return try self.crypto.decrypt(self.allocator, .{
            .ciphertext = enc,
            .nonce = nonce[0..12].*,
            .tag = tag[0..16].*,
            .salt = [_]u8{0} ** 16,
        });
    }
};

// --- Fleet Job ---

pub const FleetJob = struct {
    allocator: std.mem.Allocator,
    node_jobs: std.StringHashMapUnmanaged(*StreamJob) = .{},
    node_names: std.StringHashMapUnmanaged([]const u8) = .{},
    command: []const u8,
    mu: std.Thread.Mutex = .{},

    fn deinit(self: *FleetJob) void {
        var it = self.node_jobs.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.*.deinit();
            self.allocator.destroy(entry.value_ptr.*);
            self.allocator.free(entry.key_ptr.*);
        }
        self.node_jobs.deinit(self.allocator);

        var name_it = self.node_names.iterator();
        while (name_it.next()) |entry| {
            self.allocator.free(entry.value_ptr.*);
        }
        self.node_names.deinit(self.allocator);

        self.allocator.free(self.command);
    }
};

// --- Poll Result ---

pub const FleetPollResult = struct {
    pub const MAX_NODES = 64;

    entries: [MAX_NODES]NodeResult = undefined,
    count: usize = 0,
    all_done: bool = true,

    pub const NodeResult = struct {
        node_id: []const u8,
        node_name: []const u8,
        new_output: []const u8,
        offset: usize,
        done: bool,
        ok: bool,
    };
};

// --- Worker Thread ---

const FleetWorkerCtx = struct {
    job: *StreamJob,
    allocator: std.mem.Allocator,
    key_path: []const u8,
    port: []const u8,
    host_arg: []const u8,
    ssh_key: []u8,
    sudo_pass: ?[]u8,
    wrapped_cmd: []const u8,

    fn deinit(self: *FleetWorkerCtx) void {
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

fn fleetWorker(ctx: *FleetWorkerCtx) void {
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

    const term = child.wait() catch {
        ctx.job.finish(false);
        return;
    };
    ctx.job.finish(term.Exited == 0);
}
