const std = @import("std");
const Db = @import("db.zig").Db;
const NodeRecord = @import("db.zig").NodeRecord;
const CryptoEngine = @import("crypto.zig").CryptoEngine;
const EncryptedData = @import("crypto.zig").EncryptedData;
const StreamJob = @import("deployer.zig").StreamJob;
const JobState = @import("deployer.zig").JobState;

pub const AnsibleEngine = struct {
    allocator: std.mem.Allocator,
    db: *Db,
    crypto: *const CryptoEngine,
    ansible_path: []const u8,
    galaxy_path: []const u8,
    version: []const u8,
    jobs: std.StringHashMapUnmanaged(*StreamJob) = .{},
    jobs_mu: std.Thread.Mutex = .{},

    /// Try to detect ansible-playbook. Searches $PATH, pipx venvs, and common locations.
    pub fn detect(
        allocator: std.mem.Allocator,
        db: *Db,
        crypto: *const CryptoEngine,
    ) ?AnsibleEngine {
        // Candidate paths to try (in order)
        const home = std.posix.getenv("HOME") orelse "/root";
        const pipx_path = std.fmt.allocPrint(allocator, "{s}/.local/share/pipx/venvs/ansible/bin/ansible-playbook", .{home}) catch null;
        defer if (pipx_path) |p| allocator.free(p);

        const candidates = [_]?[]const u8{
            "ansible-playbook", // $PATH
            pipx_path, // pipx venv
            "/usr/local/bin/ansible-playbook",
            "/usr/bin/ansible-playbook",
        };

        for (candidates) |maybe_candidate| {
            const candidate = maybe_candidate orelse continue;
            const result = std.process.Child.run(.{
                .allocator = allocator,
                .argv = &.{ candidate, "--version" },
                .max_output_bytes = 4096,
            }) catch continue;
            defer allocator.free(result.stderr);

            if (result.term.Exited != 0) {
                allocator.free(result.stdout);
                continue;
            }

            const version = parseVersion(allocator, result.stdout) orelse "unknown";
            allocator.free(result.stdout);

            const path = allocator.dupe(u8, candidate) catch continue;

            // Derive ansible-galaxy path from ansible-playbook path
            const galaxy = deriveGalaxyPath(allocator, path) orelse allocator.dupe(u8, "ansible-galaxy") catch continue;

            std.log.info("[GROUND CONTROL] Ansible integration: enabled (v{s}, {s})", .{ version, path });

            return .{
                .allocator = allocator,
                .db = db,
                .crypto = crypto,
                .ansible_path = path,
                .galaxy_path = galaxy,
                .version = version,
            };
        }

        std.log.info("[GROUND CONTROL] Ansible integration: disabled (ansible-playbook not found)", .{});
        return null;
    }

    fn parseVersion(allocator: std.mem.Allocator, stdout: []const u8) ?[]const u8 {
        // First line: "ansible-playbook [core 2.17.3]"
        const first_line = if (std.mem.indexOfScalar(u8, stdout, '\n')) |nl|
            stdout[0..nl]
        else
            stdout;

        // Look for version between "[core " and "]"
        if (std.mem.indexOf(u8, first_line, "[core ")) |start| {
            const ver_start = start + 6;
            if (std.mem.indexOfScalarPos(u8, first_line, ver_start, ']')) |end| {
                return allocator.dupe(u8, first_line[ver_start..end]) catch null;
            }
        }

        // Fallback: look for a version-like pattern (digits.digits.digits)
        var i: usize = 0;
        while (i < first_line.len) : (i += 1) {
            if (first_line[i] >= '0' and first_line[i] <= '9') {
                var end = i;
                while (end < first_line.len and (first_line[end] >= '0' and first_line[end] <= '9' or first_line[end] == '.')) : (end += 1) {}
                if (end > i and std.mem.indexOfScalar(u8, first_line[i..end], '.') != null) {
                    return allocator.dupe(u8, first_line[i..end]) catch null;
                }
            }
        }

        return null;
    }

    fn deriveGalaxyPath(allocator: std.mem.Allocator, playbook_path: []const u8) ?[]const u8 {
        // Replace "ansible-playbook" suffix with "ansible-galaxy"
        const suffix = "ansible-playbook";
        if (std.mem.endsWith(u8, playbook_path, suffix)) {
            const prefix = playbook_path[0 .. playbook_path.len - suffix.len];
            return std.fmt.allocPrint(allocator, "{s}ansible-galaxy", .{prefix}) catch null;
        }
        return null;
    }

    // --- Inventory generation ---

    const InventoryContext = struct {
        inventory_path: []const u8,
        playbook_path: []const u8,
        requirements_path: ?[]const u8,
        key_paths: std.ArrayListUnmanaged([]const u8),
        sudo_passes: std.ArrayListUnmanaged(?[]u8),
        allocator: std.mem.Allocator,

        fn deinit(self: *InventoryContext) void {
            // Delete inventory file
            std.fs.cwd().deleteFile(self.inventory_path) catch {};
            self.allocator.free(self.inventory_path);

            // Delete playbook file
            std.fs.cwd().deleteFile(self.playbook_path) catch {};
            self.allocator.free(self.playbook_path);

            // Delete requirements file
            if (self.requirements_path) |req_path| {
                std.fs.cwd().deleteFile(req_path) catch {};
                self.allocator.free(req_path);
            }

            // Delete key files and zero passwords
            for (self.key_paths.items) |path| {
                std.fs.cwd().deleteFile(path) catch {};
                self.allocator.free(path);
            }
            self.key_paths.deinit(self.allocator);

            for (self.sudo_passes.items) |maybe_pass| {
                if (maybe_pass) |pass| {
                    std.crypto.secureZero(u8, pass);
                    self.allocator.free(pass);
                }
            }
            self.sudo_passes.deinit(self.allocator);
        }
    };

    fn decryptField(self: *AnsibleEngine, enc: []const u8, nonce: []const u8, tag: []const u8) ![]u8 {
        if (nonce.len < 12 or tag.len < 16) return error.InvalidEncryptedData;
        const enc_data = EncryptedData{
            .ciphertext = enc,
            .nonce = nonce[0..12].*,
            .tag = tag[0..16].*,
            .salt = [_]u8{0} ** 16,
        };
        return try self.crypto.decrypt(self.allocator, enc_data);
    }

    fn writeTempFile(path: []const u8, content: []const u8, mode: std.posix.mode_t) !void {
        const file = try std.fs.cwd().createFile(path, .{ .mode = mode });
        defer file.close();
        try file.writeAll(content);
    }

    fn generateRandomHex(self: *AnsibleEngine) ![16]u8 {
        _ = self;
        var bytes: [8]u8 = undefined;
        std.crypto.random.bytes(&bytes);
        var hex: [16]u8 = undefined;
        _ = std.fmt.bufPrint(&hex, "{x:0>16}", .{std.mem.readInt(u64, &bytes, .big)}) catch unreachable;
        return hex;
    }

    /// Build inventory and write all temp files. Caller must deinit the returned context.
    fn buildInventory(
        self: *AnsibleEngine,
        playbook_yaml: []const u8,
        node_ids: ?[]const []const u8,
        requirements_yaml: ?[]const u8,
    ) !InventoryContext {
        // Get nodes from DB
        const all_nodes = try self.db.listNodes(self.allocator);
        defer {
            for (all_nodes) |*n| n.deinit(self.allocator);
            self.allocator.free(all_nodes);
        }

        var inv_buf: std.ArrayListUnmanaged(u8) = .{};
        defer inv_buf.deinit(self.allocator);

        var key_paths: std.ArrayListUnmanaged([]const u8) = .{};
        var sudo_passes: std.ArrayListUnmanaged(?[]u8) = .{};

        // Header
        try inv_buf.appendSlice(self.allocator, "[stardust]\n");

        for (all_nodes) |node| {
            // If node_ids filter is provided, skip nodes not in the list
            if (node_ids) |ids| {
                var found = false;
                for (ids) |id| {
                    if (std.mem.eql(u8, node.id, id)) {
                        found = true;
                        break;
                    }
                }
                if (!found) continue;
            }

            // Decrypt SSH key
            const ssh_key = self.decryptField(node.ssh_key_enc, node.ssh_key_nonce, node.ssh_key_tag) catch {
                std.log.warn("[GROUND CONTROL] Ansible: failed to decrypt key for node {s}, skipping", .{node.name});
                continue;
            };

            // Write temp key file
            const key_path = try std.fmt.allocPrint(self.allocator, "/tmp/stardust_ansible_key_{s}", .{node.id});
            writeTempFile(key_path, ssh_key, 0o600) catch {
                std.crypto.secureZero(u8, ssh_key);
                self.allocator.free(ssh_key);
                self.allocator.free(key_path);
                continue;
            };
            // Key content written to file, zero and free the memory copy
            std.crypto.secureZero(u8, ssh_key);
            self.allocator.free(ssh_key);

            try key_paths.append(self.allocator, key_path);

            // Decrypt sudo password if available
            var sudo_pass: ?[]u8 = null;
            if (node.sudo_pass_enc) |enc| {
                if (node.sudo_pass_nonce) |nonce| {
                    if (node.sudo_pass_tag) |tag_val| {
                        sudo_pass = self.decryptField(enc, nonce, tag_val) catch null;
                    }
                }
            }
            try sudo_passes.append(self.allocator, sudo_pass);

            // Write inventory line
            // Use node name as ansible host alias, set connection details as host vars
            const line = try std.fmt.allocPrint(self.allocator,
                "{s} ansible_host={s} ansible_port={d} ansible_user={s} ansible_ssh_private_key_file={s}",
                .{ node.name, node.host, node.port, node.ssh_user, key_path },
            );
            defer self.allocator.free(line);
            try inv_buf.appendSlice(self.allocator, line);

            if (sudo_pass) |pass| {
                // Quote the password for INI format (single quotes, escape internal single quotes)
                try inv_buf.appendSlice(self.allocator, " ansible_become_method=sudo ansible_become_pass='");
                for (pass) |c| {
                    if (c == '\'') {
                        try inv_buf.appendSlice(self.allocator, "'\\''");
                    } else {
                        try inv_buf.append(self.allocator, c);
                    }
                }
                try inv_buf.append(self.allocator, '\'');
            }

            try inv_buf.append(self.allocator, '\n');
        }

        // Group vars
        try inv_buf.appendSlice(self.allocator,
            \\
            \\[stardust:vars]
            \\ansible_ssh_common_args=-o StrictHostKeyChecking=no -o BatchMode=yes -o ConnectTimeout=10
            \\ansible_become_flags=-S
            \\
        );

        // Write inventory file
        const inv_hex = try self.generateRandomHex();
        const inv_path = try std.fmt.allocPrint(self.allocator, "/tmp/stardust_inventory_{s}", .{inv_hex});
        try writeTempFile(inv_path, inv_buf.items, 0o600);

        // Write playbook file
        const pb_hex = try self.generateRandomHex();
        const pb_path = try std.fmt.allocPrint(self.allocator, "/tmp/stardust_playbook_{s}.yml", .{pb_hex});
        try writeTempFile(pb_path, playbook_yaml, 0o600);

        // Write requirements file if provided
        var req_path: ?[]const u8 = null;
        if (requirements_yaml) |req_yaml| {
            if (req_yaml.len > 0) {
                const req_hex = try self.generateRandomHex();
                req_path = try std.fmt.allocPrint(self.allocator, "/tmp/stardust_requirements_{s}.yml", .{req_hex});
                try writeTempFile(req_path.?, req_yaml, 0o600);
            }
        }

        return .{
            .inventory_path = inv_path,
            .playbook_path = pb_path,
            .requirements_path = req_path,
            .key_paths = key_paths,
            .sudo_passes = sudo_passes,
            .allocator = self.allocator,
        };
    }

    // --- Playbook execution ---

    const AnsibleThreadCtx = struct {
        job: *StreamJob,
        allocator: std.mem.Allocator,
        inv_ctx: InventoryContext,
        ansible_path: []const u8, // borrowed, not freed
        galaxy_path: []const u8, // borrowed, not freed

        fn deinit(self: *AnsibleThreadCtx) void {
            self.inv_ctx.deinit();
            self.allocator.destroy(self);
        }
    };

    /// Start a playbook run. Returns job_id or null on failure.
    pub fn runPlaybook(
        self: *AnsibleEngine,
        playbook_yaml: []const u8,
        node_ids: ?[]const []const u8,
        requirements_yaml: ?[]const u8,
    ) ?[]const u8 {
        // Build inventory + temp files
        var inv_ctx = self.buildInventory(playbook_yaml, node_ids, requirements_yaml) catch |err| {
            std.log.err("[GROUND CONTROL] Ansible: inventory build failed: {}", .{err});
            return null;
        };

        // Create streaming job
        const job = self.allocator.create(StreamJob) catch {
            inv_ctx.deinit();
            return null;
        };
        job.* = .{ .allocator = self.allocator };

        // Generate job ID
        const hex = self.generateRandomHex() catch {
            self.allocator.destroy(job);
            inv_ctx.deinit();
            return null;
        };
        const job_id = self.allocator.dupe(u8, &hex) catch {
            self.allocator.destroy(job);
            inv_ctx.deinit();
            return null;
        };

        // Store in jobs map
        self.jobs_mu.lock();
        self.jobs.put(self.allocator, job_id, job) catch {
            self.jobs_mu.unlock();
            self.allocator.free(job_id);
            self.allocator.destroy(job);
            inv_ctx.deinit();
            return null;
        };
        self.jobs_mu.unlock();

        // Create thread context
        const thread_ctx = self.allocator.create(AnsibleThreadCtx) catch {
            inv_ctx.deinit();
            return null;
        };
        thread_ctx.* = .{
            .job = job,
            .allocator = self.allocator,
            .inv_ctx = inv_ctx,
            .ansible_path = self.ansible_path,
            .galaxy_path = self.galaxy_path,
        };

        // Spawn worker thread
        const thread = std.Thread.spawn(.{}, ansibleWorker, .{thread_ctx}) catch {
            self.allocator.destroy(thread_ctx);
            // inv_ctx ownership transferred to thread_ctx, but we need to clean up
            // since thread_ctx.deinit won't be called
            return null;
        };
        thread.detach();

        return job_id;
    }

    fn ansibleWorker(ctx: *AnsibleThreadCtx) void {
        defer ctx.deinit();

        // If requirements.yml provided, install roles/collections first
        if (ctx.inv_ctx.requirements_path) |req_path| {
            ctx.job.appendOutput("Installing roles and collections from requirements.yml...\n\n");

            const galaxy_cmd = std.fmt.allocPrint(ctx.allocator,
                "ANSIBLE_NOCOLOR=1 {s} install -r {s} --force 2>&1",
                .{ ctx.galaxy_path, req_path },
            ) catch {
                ctx.job.appendOutput("Failed to build galaxy command\n");
                ctx.job.finish(false);
                return;
            };
            defer ctx.allocator.free(galaxy_cmd);

            var galaxy_child = std.process.Child.init(
                &.{ "sh", "-c", galaxy_cmd },
                ctx.allocator,
            );
            galaxy_child.stdout_behavior = .Pipe;
            galaxy_child.stderr_behavior = .Pipe;

            galaxy_child.spawn() catch |err| {
                const msg = std.fmt.allocPrint(ctx.allocator, "Failed to start ansible-galaxy: {}\n", .{err}) catch {
                    ctx.job.appendOutput("Failed to start ansible-galaxy\n");
                    ctx.job.finish(false);
                    return;
                };
                defer ctx.allocator.free(msg);
                ctx.job.appendOutput(msg);
                ctx.job.finish(false);
                return;
            };

            const galaxy_stdout = galaxy_child.stdout orelse {
                ctx.job.appendOutput("No stdout pipe from ansible-galaxy\n");
                ctx.job.finish(false);
                return;
            };
            var gbuf: [4096]u8 = undefined;
            while (true) {
                const n = galaxy_stdout.read(&gbuf) catch break;
                if (n == 0) break;
                ctx.job.appendOutput(gbuf[0..n]);
            }

            const galaxy_term = galaxy_child.wait() catch {
                ctx.job.appendOutput("\nansible-galaxy process failed\n");
                ctx.job.finish(false);
                return;
            };
            if (galaxy_term.Exited != 0) {
                ctx.job.appendOutput("\nansible-galaxy install failed\n");
                ctx.job.finish(false);
                return;
            }
            ctx.job.appendOutput("\n--- Running playbook ---\n\n");
        }

        // Build shell command with env vars to disable colors and host key checking
        const shell_cmd = std.fmt.allocPrint(ctx.allocator,
            "ANSIBLE_NOCOLOR=1 ANSIBLE_HOST_KEY_CHECKING=False ANSIBLE_RETRY_FILES_ENABLED=False " ++
                "{s} -i {s} {s} --force-handlers 2>&1",
            .{ ctx.ansible_path, ctx.inv_ctx.inventory_path, ctx.inv_ctx.playbook_path },
        ) catch {
            ctx.job.appendOutput("Failed to build ansible command\n");
            ctx.job.finish(false);
            return;
        };
        defer ctx.allocator.free(shell_cmd);

        var child = std.process.Child.init(
            &.{ "sh", "-c", shell_cmd },
            ctx.allocator,
        );
        child.stdout_behavior = .Pipe;
        child.stderr_behavior = .Pipe;

        child.spawn() catch |err| {
            const msg = std.fmt.allocPrint(ctx.allocator, "Failed to start ansible-playbook: {}\n", .{err}) catch {
                ctx.job.appendOutput("Failed to start ansible-playbook\n");
                ctx.job.finish(false);
                return;
            };
            defer ctx.allocator.free(msg);
            ctx.job.appendOutput(msg);
            ctx.job.finish(false);
            return;
        };

        // Read stdout in chunks (stderr merged via 2>&1)
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

    // --- Job polling ---

    pub fn pollJob(self: *AnsibleEngine, job_id: []const u8, offset: usize) ?JobState {
        self.jobs_mu.lock();
        const job = self.jobs.get(job_id);
        self.jobs_mu.unlock();
        if (job) |j| {
            return j.getState(offset);
        }
        return null;
    }

    pub fn removeJob(self: *AnsibleEngine, job_id: []const u8) void {
        self.jobs_mu.lock();
        defer self.jobs_mu.unlock();
        if (self.jobs.fetchRemove(job_id)) |kv| {
            kv.value.deinit();
            self.allocator.destroy(kv.value);
            self.allocator.free(kv.key);
        }
    }
};
