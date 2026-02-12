const std = @import("std");
const Db = @import("db.zig").Db;
const CryptoEngine = @import("crypto.zig").CryptoEngine;
const EncryptedData = @import("crypto.zig").EncryptedData;

pub const CheckResult = struct {
    connected: bool,
    arch: ?[]const u8,
    agent_available: bool,
    message: []const u8,
};

pub const StepResult = struct {
    ok: bool,
    message: []const u8,
};

pub const JobState = struct {
    new_output: []const u8,
    done: bool,
    ok: bool,
};

pub const StreamJob = struct {
    output: std.ArrayListUnmanaged(u8) = .{},
    done: bool = false,
    ok: bool = false,
    mu: std.Thread.Mutex = .{},
    allocator: std.mem.Allocator,

    pub fn appendOutput(self: *StreamJob, data: []const u8) void {
        self.mu.lock();
        defer self.mu.unlock();
        self.output.appendSlice(self.allocator, data) catch {};
    }

    pub fn finish(self: *StreamJob, success: bool) void {
        self.mu.lock();
        defer self.mu.unlock();
        self.done = true;
        self.ok = success;
    }

    pub fn getState(self: *StreamJob, offset: usize) JobState {
        self.mu.lock();
        defer self.mu.unlock();
        const start = @min(offset, self.output.items.len);
        return .{
            .new_output = self.output.items[start..],
            .done = self.done,
            .ok = self.ok,
        };
    }

    pub fn deinit(self: *StreamJob) void {
        self.output.deinit(self.allocator);
    }
};

pub const Deployer = struct {
    allocator: std.mem.Allocator,
    db: *Db,
    crypto: *const CryptoEngine,
    server_url: []const u8,
    agent_binary_path: []const u8,
    jobs: std.StringHashMapUnmanaged(*StreamJob) = .{},
    jobs_mu: std.Thread.Mutex = .{},

    pub fn init(
        allocator: std.mem.Allocator,
        db: *Db,
        crypto_engine: *const CryptoEngine,
        server_url: []const u8,
        agent_binary_path: []const u8,
    ) Deployer {
        return .{
            .allocator = allocator,
            .db = db,
            .crypto = crypto_engine,
            .server_url = server_url,
            .agent_binary_path = agent_binary_path,
        };
    }

    /// SSH into a node and check its architecture + agent availability.
    pub fn checkSystem(
        self: *Deployer,
        host: []const u8,
        port: i64,
        ssh_user: []const u8,
        ssh_key: []const u8,
        sudo_pass: ?[]const u8,
    ) CheckResult {
        _ = sudo_pass;
        // Write temp key file
        const tmp_key_path = std.fmt.allocPrint(self.allocator, "/tmp/stardust_check_{d}", .{std.time.milliTimestamp()}) catch
            return .{ .connected = false, .arch = null, .agent_available = false, .message = "internal error" };
        defer self.allocator.free(tmp_key_path);
        self.writeTempKey(tmp_key_path, ssh_key) catch
            return .{ .connected = false, .arch = null, .agent_available = false, .message = "could not write temp key" };
        defer std.fs.cwd().deleteFile(tmp_key_path) catch {};

        const host_arg = std.fmt.allocPrint(self.allocator, "{s}@{s}", .{ ssh_user, host }) catch
            return .{ .connected = false, .arch = null, .agent_available = false, .message = "internal error" };
        defer self.allocator.free(host_arg);

        const port_str = std.fmt.allocPrint(self.allocator, "{d}", .{port}) catch
            return .{ .connected = false, .arch = null, .agent_available = false, .message = "internal error" };
        defer self.allocator.free(port_str);

        // SSH in and run uname -m
        const result = std.process.Child.run(.{
            .allocator = self.allocator,
            .argv = &.{
                "ssh", "-i", tmp_key_path, "-p", port_str,
                "-o", "StrictHostKeyChecking=no", "-o", "BatchMode=yes",
                "-o", "ConnectTimeout=10",
                host_arg, "uname -m",
            },
            .max_output_bytes = 4096,
        }) catch {
            return .{ .connected = false, .arch = null, .agent_available = false, .message = "SSH connection failed" };
        };
        defer self.allocator.free(result.stdout);
        defer self.allocator.free(result.stderr);

        if (result.term.Exited != 0) {
            if (std.mem.indexOf(u8, result.stderr, "Permission denied") != null) {
                return .{ .connected = false, .arch = null, .agent_available = false, .message = "SSH authentication failed — check your private key" };
            }
            if (std.mem.indexOf(u8, result.stderr, "Connection refused") != null) {
                return .{ .connected = false, .arch = null, .agent_available = false, .message = "Connection refused — check host and port" };
            }
            if (std.mem.indexOf(u8, result.stderr, "Connection timed out") != null or
                std.mem.indexOf(u8, result.stderr, "timed out") != null)
            {
                return .{ .connected = false, .arch = null, .agent_available = false, .message = "Connection timed out — host unreachable" };
            }
            return .{ .connected = false, .arch = null, .agent_available = false, .message = "SSH command failed" };
        }

        const arch_raw = std.mem.trimRight(u8, result.stdout, "\n \t\r");
        if (arch_raw.len == 0) {
            return .{ .connected = true, .arch = null, .agent_available = false, .message = "could not detect architecture" };
        }

        const arch = self.allocator.dupe(u8, arch_raw) catch
            return .{ .connected = true, .arch = null, .agent_available = false, .message = "could not detect architecture" };

        const agent_available = self.hasAgentBinary(arch);

        if (agent_available) {
            return .{ .connected = true, .arch = arch, .agent_available = true, .message = "ready to deploy" };
        } else {
            return .{ .connected = true, .arch = arch, .agent_available = false,
                .message = "no agent binary available for this architecture" };
        }
    }

    /// Step 1: Upload agent binary to the node via SCP.
    pub fn stepUploadBinary(self: *Deployer, node_id: []const u8) StepResult {
        const ctx = self.setupSshContext(node_id) catch |err|
            return .{ .ok = false, .message = sshSetupError(err) };
        defer ctx.deinit(self);

        // Determine which binary to upload (arch-specific or default)
        const binary_path = self.agent_binary_path;

        const scp_dest = std.fmt.allocPrint(self.allocator, "{s}:/tmp/stardust-spider", .{ctx.host_arg}) catch
            return .{ .ok = false, .message = "internal error" };
        defer self.allocator.free(scp_dest);

        self.runCmd(&.{
            "scp", "-i", ctx.tmp_key_path, "-P", ctx.port_str,
            "-o", "StrictHostKeyChecking=no", "-o", "BatchMode=yes",
            "-o", "ConnectTimeout=30",
            binary_path, scp_dest,
        }) catch
            return .{ .ok = false, .message = "Circuit's dead — failed to upload Spider binary" };

        self.db.updateNodeStatus(node_id, "deploying") catch {};
        return .{ .ok = true, .message = "Major Tom stepping through the door" };
    }

    /// Step 2: Install agent — move binary + create systemd service.
    pub fn stepInstallService(self: *Deployer, node_id: []const u8) StepResult {
        const ctx = self.setupSshContext(node_id) catch |err|
            return .{ .ok = false, .message = sshSetupError(err) };
        defer ctx.deinit(self);

        const node = self.db.getNode(self.allocator, node_id) catch
            return .{ .ok = false, .message = "node not found" };
        if (node == null) return .{ .ok = false, .message = "node not found" };
        defer node.?.deinit(self.allocator);

        // Move binary into place
        self.runSudoSsh(ctx.tmp_key_path, ctx.port_str, ctx.host_arg, ctx.sudo_pass,
            "mv /tmp/stardust-spider /usr/local/bin/stardust-spider && chmod +x /usr/local/bin/stardust-spider") catch
            return .{ .ok = false, .message = "Circuit's dead — failed to install binary" };

        // Generate and upload systemd unit
        const unit_content = self.generateUnit(node_id, node.?.agent_token) catch
            return .{ .ok = false, .message = "internal error generating service unit" };
        defer self.allocator.free(unit_content);

        const tmp_unit_path = std.fmt.allocPrint(self.allocator, "/tmp/stardust_unit_{s}", .{node_id}) catch
            return .{ .ok = false, .message = "internal error" };
        defer self.allocator.free(tmp_unit_path);
        {
            const file = std.fs.cwd().createFile(tmp_unit_path, .{}) catch
                return .{ .ok = false, .message = "could not write service file" };
            defer file.close();
            file.writeAll(unit_content) catch
                return .{ .ok = false, .message = "could not write service file" };
        }
        defer std.fs.cwd().deleteFile(tmp_unit_path) catch {};

        const unit_dest = std.fmt.allocPrint(self.allocator, "{s}:/tmp/stardust-spider.service", .{ctx.host_arg}) catch
            return .{ .ok = false, .message = "internal error" };
        defer self.allocator.free(unit_dest);

        self.runCmd(&.{
            "scp", "-i", ctx.tmp_key_path, "-P", ctx.port_str,
            "-o", "StrictHostKeyChecking=no", "-o", "BatchMode=yes",
            tmp_unit_path, unit_dest,
        }) catch
            return .{ .ok = false, .message = "failed to upload service file" };

        // Install and enable
        self.runSudoSsh(ctx.tmp_key_path, ctx.port_str, ctx.host_arg, ctx.sudo_pass,
            "mv /tmp/stardust-spider.service /etc/systemd/system/stardust-spider.service && systemctl daemon-reload && systemctl enable stardust-spider") catch
            return .{ .ok = false, .message = "Circuit's dead — failed to install service" };

        return .{ .ok = true, .message = "Major Tom's circuits are go" };
    }

    /// Step 3: Start the agent service.
    pub fn stepStartService(self: *Deployer, node_id: []const u8) StepResult {
        const ctx = self.setupSshContext(node_id) catch |err|
            return .{ .ok = false, .message = sshSetupError(err) };
        defer ctx.deinit(self);

        self.runSudoSsh(ctx.tmp_key_path, ctx.port_str, ctx.host_arg, ctx.sudo_pass,
            "systemctl restart stardust-spider") catch
            return .{ .ok = false, .message = "Circuit's dead — failed to start Spider" };

        // Brief pause then check if it's still running
        std.Thread.sleep(2 * std.time.ns_per_s);

        self.runSudoSsh(ctx.tmp_key_path, ctx.port_str, ctx.host_arg, ctx.sudo_pass,
            "systemctl is-active stardust-spider") catch
            return .{ .ok = false, .message = "Something's wrong — Spider launched but went silent" };

        self.db.updateNodeStatus(node_id, "online") catch {};
        return .{ .ok = true, .message = "Major Tom has landed" };
    }

    /// Full deploy (all steps). Used for backwards compat / background deploy.
    pub fn deploy(self: *Deployer, node_id: []const u8) !void {
        self.db.updateNodeStatus(node_id, "deploying") catch {};
        errdefer self.db.updateNodeStatus(node_id, "error") catch {};

        var r = self.stepUploadBinary(node_id);
        if (!r.ok) {
            std.log.err("[MAJOR TOM] Upload failed: {s}", .{r.message});
            return error.SshFailed;
        }
        r = self.stepInstallService(node_id);
        if (!r.ok) {
            std.log.err("[MAJOR TOM] Install failed: {s}", .{r.message});
            return error.SshFailed;
        }
        r = self.stepStartService(node_id);
        if (!r.ok) {
            std.log.err("[MAJOR TOM] Start failed: {s}", .{r.message});
            return error.SshFailed;
        }
    }

    /// Offboard: test SSH connectivity.
    pub fn stepConnect(self: *Deployer, node_id: []const u8) StepResult {
        const ctx = self.setupSshContext(node_id) catch |err|
            return .{ .ok = false, .message = sshSetupError(err) };
        defer ctx.deinit(self);

        self.runSshRaw(ctx.tmp_key_path, ctx.port_str, ctx.host_arg, "echo ok") catch
            return .{ .ok = false, .message = "Can you hear me, Major Tom? — node unreachable" };

        return .{ .ok = true, .message = "Signal acquired" };
    }

    /// Offboard: stop the agent service.
    pub fn stepStopService(self: *Deployer, node_id: []const u8) StepResult {
        const ctx = self.setupSshContext(node_id) catch |err|
            return .{ .ok = false, .message = sshSetupError(err) };
        defer ctx.deinit(self);

        self.runSudoSsh(ctx.tmp_key_path, ctx.port_str, ctx.host_arg, ctx.sudo_pass,
            "systemctl stop stardust-spider") catch
            return .{ .ok = false, .message = "failed to stop service" };

        return .{ .ok = true, .message = "Spider standing down" };
    }

    /// Offboard: verify the service is stopped.
    pub fn stepCheckStopped(self: *Deployer, node_id: []const u8) StepResult {
        const ctx = self.setupSshContext(node_id) catch |err|
            return .{ .ok = false, .message = sshSetupError(err) };
        defer ctx.deinit(self);

        // is-active returns non-zero for inactive/dead — that's what we WANT
        const active = self.runSshRawOutput(ctx.tmp_key_path, ctx.port_str, ctx.host_arg,
            "systemctl is-active stardust-spider 2>/dev/null || echo inactive");
        defer if (active) |a| self.allocator.free(a);

        if (active) |output| {
            const trimmed = std.mem.trimRight(u8, output, "\n \t\r");
            if (std.mem.eql(u8, trimmed, "active") or std.mem.eql(u8, trimmed, "activating")) {
                return .{ .ok = false, .message = "service is still running" };
            }
        }
        return .{ .ok = true, .message = "service is stopped" };
    }

    /// Offboard: disable and remove the systemd service file.
    pub fn stepUninstallService(self: *Deployer, node_id: []const u8) StepResult {
        const ctx = self.setupSshContext(node_id) catch |err|
            return .{ .ok = false, .message = sshSetupError(err) };
        defer ctx.deinit(self);

        self.runSudoSsh(ctx.tmp_key_path, ctx.port_str, ctx.host_arg, ctx.sudo_pass,
            "systemctl disable stardust-spider 2>/dev/null; rm -f /etc/systemd/system/stardust-spider.service; systemctl daemon-reload") catch
            return .{ .ok = false, .message = "failed to uninstall service" };

        return .{ .ok = true, .message = "Service file removed from orbit" };
    }

    /// Offboard: verify the service file is gone.
    pub fn stepCheckUninstalled(self: *Deployer, node_id: []const u8) StepResult {
        const ctx = self.setupSshContext(node_id) catch |err|
            return .{ .ok = false, .message = sshSetupError(err) };
        defer ctx.deinit(self);

        // test -f returns 0 if file exists — we want it to NOT exist
        const output = self.runSshRawOutput(ctx.tmp_key_path, ctx.port_str, ctx.host_arg,
            "test -f /etc/systemd/system/stardust-spider.service && echo exists || echo gone");
        defer if (output) |o| self.allocator.free(o);

        if (output) |o| {
            const trimmed = std.mem.trimRight(u8, o, "\n \t\r");
            if (std.mem.eql(u8, trimmed, "exists")) {
                return .{ .ok = false, .message = "service file still exists" };
            }
        }
        return .{ .ok = true, .message = "All clear — no traces in orbit" };
    }

    /// Offboard: remove the agent binary.
    pub fn stepRemoveBinary(self: *Deployer, node_id: []const u8) StepResult {
        const ctx = self.setupSshContext(node_id) catch |err|
            return .{ .ok = false, .message = sshSetupError(err) };
        defer ctx.deinit(self);

        self.runSudoSsh(ctx.tmp_key_path, ctx.port_str, ctx.host_arg, ctx.sudo_pass,
            "rm -f /usr/local/bin/stardust-spider") catch
            return .{ .ok = false, .message = "Failed to remove Spider binary" };

        return .{ .ok = true, .message = "Spider binary jettisoned" };
    }

    /// Offboard: verify the binary is gone.
    pub fn stepCheckRemoved(self: *Deployer, node_id: []const u8) StepResult {
        const ctx = self.setupSshContext(node_id) catch |err|
            return .{ .ok = false, .message = sshSetupError(err) };
        defer ctx.deinit(self);

        const output = self.runSshRawOutput(ctx.tmp_key_path, ctx.port_str, ctx.host_arg,
            "test -f /usr/local/bin/stardust-spider && echo exists || echo gone");
        defer if (output) |o| self.allocator.free(o);

        if (output) |o| {
            const trimmed = std.mem.trimRight(u8, o, "\n \t\r");
            if (std.mem.eql(u8, trimmed, "exists")) {
                return .{ .ok = false, .message = "Spider binary still present" };
            }
        }
        return .{ .ok = true, .message = "All clear — Spider fully deorbited" };
    }

    /// Undeploy: stop and remove agent from remote node (legacy single-shot).
    pub fn undeploy(self: *Deployer, node_id: []const u8) !void {
        const ctx = self.setupSshContext(node_id) catch return;
        defer ctx.deinit(self);

        self.runSudoSsh(ctx.tmp_key_path, ctx.port_str, ctx.host_arg, ctx.sudo_pass,
            "systemctl stop stardust-spider; systemctl disable stardust-spider; rm -f /etc/systemd/system/stardust-spider.service /usr/local/bin/stardust-spider; systemctl daemon-reload") catch |err| {
            std.log.warn("[MAJOR TOM] undeploy ssh failed for {s}: {}", .{ node_id, err });
        };

        self.db.deleteNode(node_id) catch {};
        std.log.info("[MAJOR TOM] Spider deorbited from {s}", .{node_id});
    }

    // --- Internal helpers ---

    const SshContext = struct {
        tmp_key_path: []const u8,
        host_arg: []const u8,
        port_str: []const u8,
        ssh_key: []u8,
        sudo_pass: ?[]u8,

        fn deinit(self: SshContext, deployer: *Deployer) void {
            std.crypto.secureZero(u8, self.ssh_key);
            deployer.allocator.free(self.ssh_key);
            if (self.sudo_pass) |p| {
                std.crypto.secureZero(u8, p);
                deployer.allocator.free(p);
            }
            std.fs.cwd().deleteFile(self.tmp_key_path) catch {};
            deployer.allocator.free(self.tmp_key_path);
            deployer.allocator.free(self.host_arg);
            deployer.allocator.free(self.port_str);
        }
    };

    fn setupSshContext(self: *Deployer, node_id: []const u8) !SshContext {
        const node = try self.db.getNode(self.allocator, node_id) orelse return error.NodeNotFound;
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

        const tmp_key_path = try std.fmt.allocPrint(self.allocator, "/tmp/stardust_key_{s}", .{node_id});
        errdefer self.allocator.free(tmp_key_path);
        try self.writeTempKey(tmp_key_path, ssh_key);

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

    fn writeTempKey(self: *Deployer, path: []const u8, key: []const u8) !void {
        _ = self;
        const file = try std.fs.cwd().createFile(path, .{ .mode = 0o600 });
        defer file.close();
        try file.writeAll(key);
    }

    fn hasAgentBinary(self: *Deployer, arch: []const u8) bool {
        // Check arch-specific: e.g. stardust-spider-x86_64
        const arch_specific = std.fmt.allocPrint(self.allocator, "{s}-{s}", .{ self.agent_binary_path, arch }) catch return false;
        defer self.allocator.free(arch_specific);
        if (std.fs.cwd().access(arch_specific, .{})) |_| return true else |_| {}

        // Fallback: default binary
        if (std.fs.cwd().access(self.agent_binary_path, .{})) |_| return true else |_| {}

        return false;
    }

    fn runSudoSsh(
        self: *Deployer,
        key_path: []const u8,
        port: []const u8,
        host_arg: []const u8,
        sudo_pass: ?[]const u8,
        command: []const u8,
    ) !void {
        if (sudo_pass) |pass| {
            const wrapped = try std.fmt.allocPrint(self.allocator, "echo '{s}' | sudo -S sh -c '{s}'", .{ pass, command });
            defer self.allocator.free(wrapped);
            try self.runCmd(&.{
                "ssh", "-i", key_path, "-p", port,
                "-o", "StrictHostKeyChecking=no", "-o", "BatchMode=yes",
                host_arg, wrapped,
            });
        } else {
            const wrapped = try std.fmt.allocPrint(self.allocator, "sudo sh -c '{s}'", .{command});
            defer self.allocator.free(wrapped);
            try self.runCmd(&.{
                "ssh", "-i", key_path, "-p", port,
                "-o", "StrictHostKeyChecking=no", "-o", "BatchMode=yes",
                host_arg, wrapped,
            });
        }
    }

    /// Run a sudo SSH command and return stdout+stderr (caller must free).
    fn runSudoSshOutput(
        self: *Deployer,
        key_path: []const u8,
        port: []const u8,
        host_arg: []const u8,
        sudo_pass: ?[]const u8,
        command: []const u8,
    ) ?[]u8 {
        const wrapped = if (sudo_pass) |pass|
            std.fmt.allocPrint(self.allocator, "echo '{s}' | sudo -S sh -c '{s}' 2>&1", .{ pass, command }) catch return null
        else
            std.fmt.allocPrint(self.allocator, "sudo sh -c '{s}' 2>&1", .{command}) catch return null;
        defer self.allocator.free(wrapped);

        const result = std.process.Child.run(.{
            .allocator = self.allocator,
            .argv = &.{
                "ssh", "-i", key_path, "-p", port,
                "-o", "StrictHostKeyChecking=no", "-o", "BatchMode=yes",
                "-o", "ConnectTimeout=10",
                host_arg, wrapped,
            },
            .max_output_bytes = 256 * 1024,
        }) catch return null;
        defer self.allocator.free(result.stderr);
        return result.stdout;
    }

    /// Detect the package manager on a node.
    pub fn stepDetectPkgManager(self: *Deployer, node_id: []const u8) StepResult {
        const ctx = self.setupSshContext(node_id) catch |err| {
            std.log.err("[MAJOR TOM] detect-pkg-manager setup failed: {}", .{err});
            return .{ .ok = false, .message = sshSetupError(err) };
        };
        defer ctx.deinit(self);

        const output = self.runSshRawOutput(ctx.tmp_key_path, ctx.port_str, ctx.host_arg,
            "bash -c 'if command -v apt-get >/dev/null 2>&1; then echo apt; elif command -v dnf >/dev/null 2>&1; then echo dnf; elif command -v yum >/dev/null 2>&1; then echo yum; elif command -v pacman >/dev/null 2>&1; then echo pacman; elif command -v apk >/dev/null 2>&1; then echo apk; else echo unknown; fi'");
        defer if (output) |o| self.allocator.free(o);

        if (output) |o| {
            std.log.info("[MAJOR TOM] detect-pkg-manager raw output ({d} bytes): '{s}'", .{ o.len, o[0..@min(o.len, 200)] });
            const managers = [_][]const u8{ "apt", "dnf", "yum", "pacman", "apk" };
            const trimmed = std.mem.trimRight(u8, o, "\n \t\r");
            const last_newline = std.mem.lastIndexOf(u8, trimmed, "\n");
            const last_line = if (last_newline) |pos| std.mem.trimLeft(u8, trimmed[pos + 1 ..], " \t") else trimmed;
            std.log.info("[MAJOR TOM] detect-pkg-manager last_line: '{s}'", .{last_line});

            for (managers) |mgr| {
                if (std.mem.eql(u8, last_line, mgr)) return .{ .ok = true, .message = mgr };
            }
        } else {
            std.log.err("[MAJOR TOM] detect-pkg-manager SSH returned null output", .{});
        }
        return .{ .ok = false, .message = "unknown package manager" };
    }

    /// Run package refresh command and return full output. Caller must free output.
    pub fn stepPkgRefresh(self: *Deployer, node_id: []const u8, pkg_manager: []const u8) ?[]u8 {
        const ctx = self.setupSshContext(node_id) catch return null;
        defer ctx.deinit(self);

        const command: []const u8 = if (std.mem.eql(u8, pkg_manager, "apt"))
            "apt-get update"
        else if (std.mem.eql(u8, pkg_manager, "dnf"))
            "dnf check-update; true"
        else if (std.mem.eql(u8, pkg_manager, "yum"))
            "yum check-update; true"
        else if (std.mem.eql(u8, pkg_manager, "pacman"))
            "pacman -Sy"
        else if (std.mem.eql(u8, pkg_manager, "apk"))
            "apk update"
        else
            return null;

        return self.runSudoSshOutput(
            ctx.tmp_key_path, ctx.port_str, ctx.host_arg, ctx.sudo_pass, command,
        );
    }

    /// Start a streaming pkg refresh job. Returns a job ID or null on failure.
    pub fn startPkgRefreshJob(self: *Deployer, node_id: []const u8, pkg_manager: []const u8) ?[]const u8 {
        const ctx = self.setupSshContext(node_id) catch return null;

        const command: []const u8 = if (std.mem.eql(u8, pkg_manager, "apt"))
            "apt-get update"
        else if (std.mem.eql(u8, pkg_manager, "dnf"))
            "dnf check-update; true"
        else if (std.mem.eql(u8, pkg_manager, "yum"))
            "yum check-update; true"
        else if (std.mem.eql(u8, pkg_manager, "pacman"))
            "pacman -Sy"
        else if (std.mem.eql(u8, pkg_manager, "apk"))
            "apk update"
        else {
            ctx.deinit(self);
            return null;
        };

        const job = self.allocator.create(StreamJob) catch {
            ctx.deinit(self);
            return null;
        };
        job.* = .{ .allocator = self.allocator };

        // Generate job ID from random bytes
        var id_bytes: [8]u8 = undefined;
        std.crypto.random.bytes(&id_bytes);
        var hex_buf: [16]u8 = undefined;
        const hex = std.fmt.bufPrint(&hex_buf, "{x:0>16}", .{std.mem.readInt(u64, &id_bytes, .big)}) catch {
            self.allocator.destroy(job);
            ctx.deinit(self);
            return null;
        };
        const job_id = self.allocator.dupe(u8, hex) catch {
            self.allocator.destroy(job);
            ctx.deinit(self);
            return null;
        };

        // Store the job
        self.jobs_mu.lock();
        self.jobs.put(self.allocator, job_id, job) catch {
            self.jobs_mu.unlock();
            self.allocator.free(job_id);
            self.allocator.destroy(job);
            ctx.deinit(self);
            return null;
        };
        self.jobs_mu.unlock();

        // Build the SSH command
        const wrapped = if (ctx.sudo_pass) |pass|
            std.fmt.allocPrint(self.allocator, "echo '{s}' | sudo -S sh -c '{s}' 2>&1", .{ pass, command }) catch {
                ctx.deinit(self);
                return null;
            }
        else
            std.fmt.allocPrint(self.allocator, "sudo sh -c '{s}' 2>&1", .{command}) catch {
                ctx.deinit(self);
                return null;
            };

        // Spawn thread to run the command and stream output
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

    /// Start a streaming package job (check-updates, upgrade, full-upgrade).
    /// Returns a job ID or null on failure.
    pub fn startPkgJob(self: *Deployer, node_id: []const u8, pkg_manager: []const u8, action: []const u8) ?[]const u8 {
        const ctx = self.setupSshContext(node_id) catch return null;

        const command: ?[]const u8 = if (std.mem.eql(u8, action, "check-updates")) blk: {
            break :blk if (std.mem.eql(u8, pkg_manager, "apt"))
                "apt-get update >/dev/null 2>&1 && apt-get upgrade -s"
            else if (std.mem.eql(u8, pkg_manager, "dnf"))
                "dnf check-update --quiet; true"
            else if (std.mem.eql(u8, pkg_manager, "yum"))
                "yum check-update --quiet; true"
            else if (std.mem.eql(u8, pkg_manager, "pacman"))
                "pacman -Sy >/dev/null 2>&1 && pacman -Qu; true"
            else if (std.mem.eql(u8, pkg_manager, "apk"))
                "apk update >/dev/null 2>&1 && apk upgrade -s"
            else
                null;
        } else if (std.mem.eql(u8, action, "upgrade")) blk: {
            break :blk if (std.mem.eql(u8, pkg_manager, "apt"))
                "DEBIAN_FRONTEND=noninteractive apt-get upgrade -y"
            else if (std.mem.eql(u8, pkg_manager, "dnf"))
                "dnf upgrade --nobest -y"
            else if (std.mem.eql(u8, pkg_manager, "yum"))
                "yum update -y"
            else if (std.mem.eql(u8, pkg_manager, "pacman"))
                "pacman -Syu --noconfirm"
            else if (std.mem.eql(u8, pkg_manager, "apk"))
                "apk upgrade"
            else
                null;
        } else if (std.mem.eql(u8, action, "full-upgrade")) blk: {
            break :blk if (std.mem.eql(u8, pkg_manager, "apt"))
                "DEBIAN_FRONTEND=noninteractive apt-get full-upgrade -y"
            else if (std.mem.eql(u8, pkg_manager, "dnf"))
                "dnf upgrade -y"
            else if (std.mem.eql(u8, pkg_manager, "yum"))
                "yum update -y"
            else if (std.mem.eql(u8, pkg_manager, "pacman"))
                "pacman -Syu --noconfirm"
            else if (std.mem.eql(u8, pkg_manager, "apk"))
                "apk upgrade --available"
            else
                null;
        } else null;

        if (command == null) {
            ctx.deinit(self);
            return null;
        }

        return self.startStreamJob(ctx, command.?);
    }

    /// Internal: start a streaming SSH job given a prepared SSH context and command.
    fn startStreamJob(self: *Deployer, ctx: SshContext, command: []const u8) ?[]const u8 {
        const job = self.allocator.create(StreamJob) catch {
            ctx.deinit(self);
            return null;
        };
        job.* = .{ .allocator = self.allocator };

        var id_bytes: [8]u8 = undefined;
        std.crypto.random.bytes(&id_bytes);
        var hex_buf: [16]u8 = undefined;
        const hex = std.fmt.bufPrint(&hex_buf, "{x:0>16}", .{std.mem.readInt(u64, &id_bytes, .big)}) catch {
            self.allocator.destroy(job);
            ctx.deinit(self);
            return null;
        };
        const job_id = self.allocator.dupe(u8, hex) catch {
            self.allocator.destroy(job);
            ctx.deinit(self);
            return null;
        };

        self.jobs_mu.lock();
        self.jobs.put(self.allocator, job_id, job) catch {
            self.jobs_mu.unlock();
            self.allocator.free(job_id);
            self.allocator.destroy(job);
            ctx.deinit(self);
            return null;
        };
        self.jobs_mu.unlock();

        const wrapped = if (ctx.sudo_pass) |pass|
            std.fmt.allocPrint(self.allocator, "echo '{s}' | sudo -S bash -c '{s}' 2>&1", .{ pass, command }) catch {
                ctx.deinit(self);
                return null;
            }
        else
            std.fmt.allocPrint(self.allocator, "sudo bash -c '{s}' 2>&1", .{command}) catch {
                ctx.deinit(self);
                return null;
            };

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

    const StreamThreadCtx = struct {
        job: *StreamJob,
        allocator: std.mem.Allocator,
        key_path: []const u8,
        port: []const u8,
        host_arg: []const u8,
        ssh_key: []u8,
        sudo_pass: ?[]u8,
        wrapped_cmd: []const u8,

        fn deinit(self: *StreamThreadCtx) void {
            // Clean up temp key file
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

        const term = child.wait() catch {
            ctx.job.finish(false);
            return;
        };
        ctx.job.finish(term.Exited == 0);
    }

    pub fn pollJobOffset(self: *Deployer, job_id: []const u8, offset: usize) ?JobState {
        self.jobs_mu.lock();
        const job = self.jobs.get(job_id);
        self.jobs_mu.unlock();
        if (job) |j| {
            return j.getState(offset);
        }
        return null;
    }

    pub fn removeJob(self: *Deployer, job_id: []const u8) void {
        self.jobs_mu.lock();
        defer self.jobs_mu.unlock();
        if (self.jobs.fetchRemove(job_id)) |kv| {
            kv.value.deinit();
            self.allocator.destroy(kv.value);
            self.allocator.free(kv.key);
        }
    }

    /// Run an SSH command without sudo, just to test connectivity or read output.
    fn runSshRaw(
        self: *Deployer,
        key_path: []const u8,
        port: []const u8,
        host_arg: []const u8,
        command: []const u8,
    ) !void {
        try self.runCmd(&.{
            "ssh", "-i", key_path, "-p", port,
            "-o", "StrictHostKeyChecking=no", "-o", "BatchMode=yes",
            "-o", "ConnectTimeout=10",
            host_arg, command,
        });
    }

    /// Run an SSH command and return stdout (caller must free).
    fn runSshRawOutput(
        self: *Deployer,
        key_path: []const u8,
        port: []const u8,
        host_arg: []const u8,
        command: []const u8,
    ) ?[]u8 {
        const result = std.process.Child.run(.{
            .allocator = self.allocator,
            .argv = &.{
                "ssh", "-i", key_path, "-p", port,
                "-o", "StrictHostKeyChecking=no", "-o", "BatchMode=yes",
                "-o", "ConnectTimeout=10",
                host_arg, command,
            },
            .max_output_bytes = 4096,
        }) catch |err| {
            std.log.err("[MAJOR TOM] runSshRawOutput spawn failed: {}", .{err});
            return null;
        };
        defer self.allocator.free(result.stderr);
        if (result.stderr.len > 0) {
            std.log.info("[MAJOR TOM] runSshRawOutput stderr: '{s}'", .{result.stderr[0..@min(result.stderr.len, 200)]});
        }
        // Return stdout regardless of exit code (check commands may exit non-zero)
        return result.stdout;
    }

    fn decryptField(self: *Deployer, enc: []const u8, nonce: []const u8, tag: []const u8) ![]u8 {
        if (nonce.len < 12 or tag.len < 16) return error.InvalidEncryptedData;
        const enc_data = EncryptedData{
            .ciphertext = enc,
            .nonce = nonce[0..12].*,
            .tag = tag[0..16].*,
            .salt = [_]u8{0} ** 16,
        };
        return try self.crypto.decrypt(self.allocator, enc_data);
    }

    fn runCmd(self: *Deployer, argv: []const []const u8) !void {
        const result = std.process.Child.run(.{
            .allocator = self.allocator,
            .argv = argv,
            .max_output_bytes = 64 * 1024,
        }) catch |err| {
            std.log.err("[MAJOR TOM] failed to spawn process: {}", .{err});
            return error.SshFailed;
        };
        defer self.allocator.free(result.stdout);
        defer self.allocator.free(result.stderr);

        if (result.term.Exited != 0) {
            std.log.err("[MAJOR TOM] command exited {d}: {s}", .{ result.term.Exited, result.stderr });
            return error.SshFailed;
        }
    }

    fn generateUnit(self: *Deployer, node_id: []const u8, token: []const u8) ![]u8 {
        return std.fmt.allocPrint(self.allocator,
            \\[Unit]
            \\Description=Stardust Spider Agent
            \\After=network-online.target
            \\Wants=network-online.target
            \\
            \\[Service]
            \\Type=simple
            \\ExecStart=/usr/local/bin/stardust-spider --server {s} --token {s} --agent-id {s}
            \\Restart=always
            \\RestartSec=5
            \\StandardOutput=journal
            \\StandardError=journal
            \\
            \\[Install]
            \\WantedBy=multi-user.target
            \\
        , .{ self.server_url, token, node_id });
    }

    fn sshSetupError(err: anyerror) []const u8 {
        return switch (err) {
            error.NodeNotFound => "node not found in database",
            error.DecryptionFailed => "failed to decrypt SSH key",
            error.InvalidEncryptedData => "corrupted SSH key data",
            else => "failed to setup SSH connection",
        };
    }
};
