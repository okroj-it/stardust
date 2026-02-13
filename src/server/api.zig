const std = @import("std");
const zap = @import("zap");
const Store = @import("store.zig").Store;
const Db = @import("db.zig").Db;
const CryptoEngine = @import("crypto.zig").CryptoEngine;
const deployer_mod = @import("deployer.zig");
const Deployer = deployer_mod.Deployer;
const Auth = @import("auth.zig").Auth;
const WsState = @import("ws_handler.zig").WsState;
const AnsibleEngine = @import("ansible.zig").AnsibleEngine;
const FleetEngine = @import("fleet.zig").FleetEngine;
const service_mod = @import("services.zig");
const ServiceEngine = service_mod.ServiceEngine;
const ServiceScope = service_mod.ServiceScope;
const process_mod = @import("processes.zig");
const ProcessEngine = process_mod.ProcessEngine;
const log_mod = @import("logs.zig");
const LogEngine = log_mod.LogEngine;
const DriftEngine = @import("drift.zig").DriftEngine;
const security_mod = @import("security.zig");
const SecurityEngine = security_mod.SecurityEngine;
const container_mod = @import("containers.zig");
const ContainerEngine = container_mod.ContainerEngine;
const scheduler_mod = @import("scheduler.zig");
const SchedulerEngine = scheduler_mod.SchedulerEngine;
const common = @import("common");

pub const Api = struct {
    allocator: std.mem.Allocator,
    store: *Store,
    db: ?*Db,
    crypto: ?*const CryptoEngine,
    deployer: ?*Deployer,
    auth: ?*const Auth = null,
    ws_state: ?*WsState = null,
    ansible: ?*AnsibleEngine = null,
    fleet: ?*FleetEngine = null,
    services: ?*ServiceEngine = null,
    processes: ?*ProcessEngine = null,
    logs: ?*LogEngine = null,
    drift: ?*DriftEngine = null,
    security: ?*SecurityEngine = null,
    containers: ?*ContainerEngine = null,
    scheduler: ?*SchedulerEngine = null,

    pub fn init(allocator: std.mem.Allocator, store: *Store) Api {
        return .{
            .allocator = allocator,
            .store = store,
            .db = null,
            .crypto = null,
            .deployer = null,
            .auth = null,
        };
    }

    pub fn setDb(self: *Api, db: *Db) void {
        self.db = db;
    }

    pub fn setCrypto(self: *Api, crypto: *const CryptoEngine) void {
        self.crypto = crypto;
    }

    pub fn setDeployer(self: *Api, deployer: *Deployer) void {
        self.deployer = deployer;
    }

    pub fn setAuth(self: *Api, auth: *const Auth) void {
        self.auth = auth;
    }

    pub fn setWsState(self: *Api, ws: *WsState) void {
        self.ws_state = ws;
    }

    pub fn setAnsible(self: *Api, a: *AnsibleEngine) void {
        self.ansible = a;
    }

    pub fn setFleet(self: *Api, f: *FleetEngine) void {
        self.fleet = f;
    }

    pub fn setServices(self: *Api, s: *ServiceEngine) void {
        self.services = s;
    }

    pub fn setProcesses(self: *Api, p: *ProcessEngine) void {
        self.processes = p;
    }

    pub fn setLogs(self: *Api, l: *LogEngine) void {
        self.logs = l;
    }

    pub fn setDrift(self: *Api, d: *DriftEngine) void {
        self.drift = d;
    }

    pub fn setSecurity(self: *Api, s: *SecurityEngine) void {
        self.security = s;
    }

    pub fn setContainers(self: *Api, c: *ContainerEngine) void {
        self.containers = c;
    }

    pub fn setScheduler(self: *Api, s: *SchedulerEngine) void {
        self.scheduler = s;
    }

    pub fn handleRequest(self: *Api, r: zap.Request) !void {
        const path = r.path orelse {
            r.setStatus(.not_found);
            try r.sendBody("404");
            return;
        };

        // CORS headers for browser access
        r.setHeader("Access-Control-Allow-Origin", "*") catch {};
        r.setHeader("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS") catch {};
        r.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization") catch {};

        if (r.methodAsEnum() == .OPTIONS) {
            r.setStatus(.no_content);
            try r.sendBody("");
            return;
        }

        // Public routes (no auth required)
        if (std.mem.eql(u8, path, "/api/health")) {
            try self.handleHealth(r);
            return;
        }
        if (std.mem.eql(u8, path, "/api/auth/login")) {
            try self.handleLogin(r);
            return;
        }
        if (std.mem.eql(u8, path, "/metrics")) {
            try self.handleMetrics(r);
            return;
        }

        // Auth middleware: check JWT for all other routes
        if (self.auth) |auth| {
            const auth_header = r.getHeader("authorization") orelse {
                r.setStatus(.unauthorized);
                try r.sendJson("{\"error\":\"unauthorized\"}");
                return;
            };
            // Expect "Bearer <token>"
            if (!std.mem.startsWith(u8, auth_header, "Bearer ")) {
                r.setStatus(.unauthorized);
                try r.sendJson("{\"error\":\"invalid authorization header\"}");
                return;
            }
            const token = auth_header["Bearer ".len..];
            if (!auth.validateToken(token)) {
                r.setStatus(.unauthorized);
                try r.sendJson("{\"error\":\"invalid or expired token\"}");
                return;
            }
        }

        // Protected routes
        if (std.mem.eql(u8, path, "/api/capabilities")) {
            try self.handleCapabilities(r);
        } else if (std.mem.eql(u8, path, "/api/auth/password")) {
            try self.handleChangePassword(r);
        } else if (std.mem.eql(u8, path, "/api/tags")) {
            try self.handleTags(r);
        } else if (std.mem.eql(u8, path, "/api/events")) {
            try self.handleEvents(r);
        } else if (std.mem.eql(u8, path, "/api/nodes/check")) {
            try self.handleNodeCheck(r);
        } else if (std.mem.eql(u8, path, "/api/nodes")) {
            try self.handleNodes(r);
        } else if (std.mem.startsWith(u8, path, "/api/nodes/")) {
            try self.handleNodeDetail(r, path);
        } else if (std.mem.startsWith(u8, path, "/api/ansible/")) {
            try self.handleAnsible(r, path);
        } else if (std.mem.startsWith(u8, path, "/api/fleet/")) {
            try self.handleFleet(r, path);
        } else if (std.mem.startsWith(u8, path, "/api/services/")) {
            try self.handleServices(r, path);
        } else if (std.mem.startsWith(u8, path, "/api/processes/")) {
            try self.handleProcesses(r, path);
        } else if (std.mem.startsWith(u8, path, "/api/logs/")) {
            try self.handleLogs(r, path);
        } else if (std.mem.startsWith(u8, path, "/api/drift/")) {
            try self.handleDrift(r, path);
        } else if (std.mem.startsWith(u8, path, "/api/security/")) {
            try self.handleSecurity(r, path);
        } else if (std.mem.startsWith(u8, path, "/api/containers/")) {
            try self.handleContainers(r, path);
        } else if (std.mem.startsWith(u8, path, "/api/schedules")) {
            try self.handleSchedules(r, path);
        } else {
            return; // Let static file handler deal with it
        }
    }

    fn handleHealth(self: *Api, r: zap.Request) !void {
        _ = self;
        try r.sendJson("{\"status\":\"ok\"}");
    }

    fn handleMetrics(self: *Api, r: zap.Request) !void {
        if (r.methodAsEnum() != .GET) {
            r.setStatus(.method_not_allowed);
            try r.sendJson("{\"error\":\"method not allowed\"}");
            return;
        }

        const agents = try self.store.getAllAgentStatus(self.allocator);
        defer self.allocator.free(agents);

        var buf: std.ArrayListUnmanaged(u8) = .{};
        defer buf.deinit(self.allocator);
        const w = buf.writer(self.allocator);

        // --- HELP/TYPE headers ---
        try w.writeAll(
            \\# HELP stardust_up Whether the node is connected (1=up, 0=down).
            \\# TYPE stardust_up gauge
            \\# HELP stardust_uptime_seconds System uptime in seconds.
            \\# TYPE stardust_uptime_seconds gauge
            \\# HELP stardust_cpu_usage_percent CPU usage percentage (0-100).
            \\# TYPE stardust_cpu_usage_percent gauge
            \\# HELP stardust_cpu_iowait_percent CPU I/O wait percentage.
            \\# TYPE stardust_cpu_iowait_percent gauge
            \\# HELP stardust_memory_total_bytes Total physical memory in bytes.
            \\# TYPE stardust_memory_total_bytes gauge
            \\# HELP stardust_memory_free_bytes Free physical memory in bytes.
            \\# TYPE stardust_memory_free_bytes gauge
            \\# HELP stardust_memory_available_bytes Available memory in bytes.
            \\# TYPE stardust_memory_available_bytes gauge
            \\# HELP stardust_memory_buffers_bytes Buffered memory in bytes.
            \\# TYPE stardust_memory_buffers_bytes gauge
            \\# HELP stardust_memory_cached_bytes Cached memory in bytes.
            \\# TYPE stardust_memory_cached_bytes gauge
            \\# HELP stardust_memory_used_percent Memory usage percentage (0-100).
            \\# TYPE stardust_memory_used_percent gauge
            \\# HELP stardust_swap_total_bytes Total swap in bytes.
            \\# TYPE stardust_swap_total_bytes gauge
            \\# HELP stardust_swap_used_bytes Used swap in bytes.
            \\# TYPE stardust_swap_used_bytes gauge
            \\# HELP stardust_swap_used_percent Swap usage percentage (0-100).
            \\# TYPE stardust_swap_used_percent gauge
            \\# HELP stardust_load_1m 1-minute load average.
            \\# TYPE stardust_load_1m gauge
            \\# HELP stardust_load_5m 5-minute load average.
            \\# TYPE stardust_load_5m gauge
            \\# HELP stardust_load_15m 15-minute load average.
            \\# TYPE stardust_load_15m gauge
            \\# HELP stardust_processes_running Number of running processes.
            \\# TYPE stardust_processes_running gauge
            \\# HELP stardust_processes_total Total number of processes.
            \\# TYPE stardust_processes_total gauge
            \\# HELP stardust_filesystem_total_bytes Filesystem total size in bytes.
            \\# TYPE stardust_filesystem_total_bytes gauge
            \\# HELP stardust_filesystem_free_bytes Filesystem free space in bytes.
            \\# TYPE stardust_filesystem_free_bytes gauge
            \\# HELP stardust_filesystem_used_percent Filesystem usage percentage (0-100).
            \\# TYPE stardust_filesystem_used_percent gauge
            \\# HELP stardust_network_rx_bytes_total Network bytes received.
            \\# TYPE stardust_network_rx_bytes_total counter
            \\# HELP stardust_network_tx_bytes_total Network bytes transmitted.
            \\# TYPE stardust_network_tx_bytes_total counter
            \\# HELP stardust_network_rx_errors_total Network receive errors.
            \\# TYPE stardust_network_rx_errors_total counter
            \\# HELP stardust_network_tx_errors_total Network transmit errors.
            \\# TYPE stardust_network_tx_errors_total counter
            \\# HELP stardust_connections_established Number of established TCP connections.
            \\# TYPE stardust_connections_established gauge
            \\# HELP stardust_connections_listen Number of listening TCP sockets.
            \\# TYPE stardust_connections_listen gauge
            \\# HELP stardust_connections_time_wait Number of TCP connections in TIME_WAIT.
            \\# TYPE stardust_connections_time_wait gauge
            \\# HELP stardust_connections_total Total TCP connections.
            \\# TYPE stardust_connections_total gauge
            \\# HELP stardust_temperature_celsius Sensor temperature in degrees Celsius.
            \\# TYPE stardust_temperature_celsius gauge
            \\# HELP stardust_disk_reads_total Disk reads completed.
            \\# TYPE stardust_disk_reads_total counter
            \\# HELP stardust_disk_writes_total Disk writes completed.
            \\# TYPE stardust_disk_writes_total counter
            \\# HELP stardust_disk_io_in_progress Disk I/O operations currently in progress.
            \\# TYPE stardust_disk_io_in_progress gauge
            \\
        );

        for (agents) |agent| {
            // Parse latest snapshot for this agent
            const snapshot_json = self.store.getLatest(agent.agent_id) orelse {
                // No stats — only emit up=0
                try writeMetric(w, "stardust_up", agent.agent_id, "", "0");
                continue;
            };

            const parsed = std.json.parseFromSlice(common.SystemStats, self.allocator, snapshot_json, .{
                .ignore_unknown_fields = true,
                .allocate = .alloc_always,
            }) catch {
                try writeMetric(w, "stardust_up", agent.agent_id, "", if (agent.connected) "1" else "0");
                continue;
            };
            defer parsed.deinit();
            const s = parsed.value;

            const host = s.hostname;
            const id = agent.agent_id;

            // up
            try writeMetricL(w, "stardust_up", id, host, "", if (agent.connected) "1" else "0");

            // uptime
            try std.fmt.format(w, "stardust_uptime_seconds{{agent_id=\"{s}\",hostname=\"{s}\"}} {d:.1}\n", .{ id, host, s.uptime_secs });

            // cpu
            try std.fmt.format(w, "stardust_cpu_usage_percent{{agent_id=\"{s}\",hostname=\"{s}\"}} {d:.2}\n", .{ id, host, s.cpu.usage_percent });
            try std.fmt.format(w, "stardust_cpu_iowait_percent{{agent_id=\"{s}\",hostname=\"{s}\"}} {d:.2}\n", .{ id, host, s.cpu.iowait_percent });

            // memory
            try std.fmt.format(w, "stardust_memory_total_bytes{{agent_id=\"{s}\",hostname=\"{s}\"}} {d}\n", .{ id, host, s.memory.total_bytes });
            try std.fmt.format(w, "stardust_memory_free_bytes{{agent_id=\"{s}\",hostname=\"{s}\"}} {d}\n", .{ id, host, s.memory.free_bytes });
            try std.fmt.format(w, "stardust_memory_available_bytes{{agent_id=\"{s}\",hostname=\"{s}\"}} {d}\n", .{ id, host, s.memory.available_bytes });
            try std.fmt.format(w, "stardust_memory_buffers_bytes{{agent_id=\"{s}\",hostname=\"{s}\"}} {d}\n", .{ id, host, s.memory.buffers_bytes });
            try std.fmt.format(w, "stardust_memory_cached_bytes{{agent_id=\"{s}\",hostname=\"{s}\"}} {d}\n", .{ id, host, s.memory.cached_bytes });
            try std.fmt.format(w, "stardust_memory_used_percent{{agent_id=\"{s}\",hostname=\"{s}\"}} {d:.2}\n", .{ id, host, s.memory.used_percent });

            // swap
            try std.fmt.format(w, "stardust_swap_total_bytes{{agent_id=\"{s}\",hostname=\"{s}\"}} {d}\n", .{ id, host, s.swap.total_bytes });
            try std.fmt.format(w, "stardust_swap_used_bytes{{agent_id=\"{s}\",hostname=\"{s}\"}} {d}\n", .{ id, host, s.swap.used_bytes });
            try std.fmt.format(w, "stardust_swap_used_percent{{agent_id=\"{s}\",hostname=\"{s}\"}} {d:.2}\n", .{ id, host, s.swap.used_percent });

            // load
            try std.fmt.format(w, "stardust_load_1m{{agent_id=\"{s}\",hostname=\"{s}\"}} {d:.4}\n", .{ id, host, s.load.one });
            try std.fmt.format(w, "stardust_load_5m{{agent_id=\"{s}\",hostname=\"{s}\"}} {d:.4}\n", .{ id, host, s.load.five });
            try std.fmt.format(w, "stardust_load_15m{{agent_id=\"{s}\",hostname=\"{s}\"}} {d:.4}\n", .{ id, host, s.load.fifteen });
            try std.fmt.format(w, "stardust_processes_running{{agent_id=\"{s}\",hostname=\"{s}\"}} {d}\n", .{ id, host, s.load.running_processes });
            try std.fmt.format(w, "stardust_processes_total{{agent_id=\"{s}\",hostname=\"{s}\"}} {d}\n", .{ id, host, s.load.total_processes });

            // filesystems
            for (s.filesystems) |fs| {
                try std.fmt.format(w, "stardust_filesystem_total_bytes{{agent_id=\"{s}\",hostname=\"{s}\",mountpoint=\"{s}\",fstype=\"{s}\"}} {d}\n", .{ id, host, fs.mount_point, fs.fs_type, fs.total_bytes });
                try std.fmt.format(w, "stardust_filesystem_free_bytes{{agent_id=\"{s}\",hostname=\"{s}\",mountpoint=\"{s}\",fstype=\"{s}\"}} {d}\n", .{ id, host, fs.mount_point, fs.fs_type, fs.free_bytes });
                try std.fmt.format(w, "stardust_filesystem_used_percent{{agent_id=\"{s}\",hostname=\"{s}\",mountpoint=\"{s}\",fstype=\"{s}\"}} {d:.2}\n", .{ id, host, fs.mount_point, fs.fs_type, fs.used_percent });
            }

            // network
            for (s.network) |iface| {
                try std.fmt.format(w, "stardust_network_rx_bytes_total{{agent_id=\"{s}\",hostname=\"{s}\",interface=\"{s}\"}} {d}\n", .{ id, host, iface.name, iface.rx_bytes });
                try std.fmt.format(w, "stardust_network_tx_bytes_total{{agent_id=\"{s}\",hostname=\"{s}\",interface=\"{s}\"}} {d}\n", .{ id, host, iface.name, iface.tx_bytes });
                try std.fmt.format(w, "stardust_network_rx_errors_total{{agent_id=\"{s}\",hostname=\"{s}\",interface=\"{s}\"}} {d}\n", .{ id, host, iface.name, iface.rx_errors });
                try std.fmt.format(w, "stardust_network_tx_errors_total{{agent_id=\"{s}\",hostname=\"{s}\",interface=\"{s}\"}} {d}\n", .{ id, host, iface.name, iface.tx_errors });
            }

            // connections
            try std.fmt.format(w, "stardust_connections_established{{agent_id=\"{s}\",hostname=\"{s}\"}} {d}\n", .{ id, host, s.connections.established });
            try std.fmt.format(w, "stardust_connections_listen{{agent_id=\"{s}\",hostname=\"{s}\"}} {d}\n", .{ id, host, s.connections.listen });
            try std.fmt.format(w, "stardust_connections_time_wait{{agent_id=\"{s}\",hostname=\"{s}\"}} {d}\n", .{ id, host, s.connections.time_wait });
            try std.fmt.format(w, "stardust_connections_total{{agent_id=\"{s}\",hostname=\"{s}\"}} {d}\n", .{ id, host, s.connections.total });

            // temperatures
            for (s.temperatures) |temp| {
                try std.fmt.format(w, "stardust_temperature_celsius{{agent_id=\"{s}\",hostname=\"{s}\",zone=\"{s}\"}} {d:.1}\n", .{ id, host, temp.zone, temp.temp_celsius });
            }

            // disk I/O
            for (s.disks) |disk| {
                try std.fmt.format(w, "stardust_disk_reads_total{{agent_id=\"{s}\",hostname=\"{s}\",device=\"{s}\"}} {d}\n", .{ id, host, disk.name, disk.reads_completed });
                try std.fmt.format(w, "stardust_disk_writes_total{{agent_id=\"{s}\",hostname=\"{s}\",device=\"{s}\"}} {d}\n", .{ id, host, disk.name, disk.writes_completed });
                try std.fmt.format(w, "stardust_disk_io_in_progress{{agent_id=\"{s}\",hostname=\"{s}\",device=\"{s}\"}} {d}\n", .{ id, host, disk.name, disk.io_in_progress });
            }
        }

        r.setHeader("Content-Type", "text/plain; version=0.0.4; charset=utf-8") catch {};
        try r.sendBody(buf.items);
    }

    fn writeMetric(w: anytype, name: []const u8, agent_id: []const u8, extra_labels: []const u8, value: []const u8) !void {
        try w.writeAll(name);
        try w.writeAll("{agent_id=\"");
        try w.writeAll(agent_id);
        try w.writeByte('"');
        if (extra_labels.len > 0) {
            try w.writeByte(',');
            try w.writeAll(extra_labels);
        }
        try w.writeAll("} ");
        try w.writeAll(value);
        try w.writeByte('\n');
    }

    fn writeMetricL(w: anytype, name: []const u8, agent_id: []const u8, hostname: []const u8, extra_labels: []const u8, value: []const u8) !void {
        try w.writeAll(name);
        try w.writeAll("{agent_id=\"");
        try w.writeAll(agent_id);
        try w.writeAll("\",hostname=\"");
        try w.writeAll(hostname);
        try w.writeByte('"');
        if (extra_labels.len > 0) {
            try w.writeByte(',');
            try w.writeAll(extra_labels);
        }
        try w.writeAll("} ");
        try w.writeAll(value);
        try w.writeByte('\n');
    }

    fn handleLogin(self: *Api, r: zap.Request) !void {
        if (r.methodAsEnum() != .POST) {
            r.setStatus(.method_not_allowed);
            try r.sendJson("{\"error\":\"method not allowed\"}");
            return;
        }

        const auth = self.auth orelse {
            r.setStatus(.service_unavailable);
            try r.sendJson("{\"error\":\"authentication not configured\"}");
            return;
        };

        const db = self.db orelse {
            r.setStatus(.service_unavailable);
            try r.sendJson("{\"error\":\"database not configured\"}");
            return;
        };

        const body = r.body orelse {
            r.setStatus(.bad_request);
            try r.sendJson("{\"error\":\"missing request body\"}");
            return;
        };

        const parsed = std.json.parseFromSlice(LoginRequest, self.allocator, body, .{
            .ignore_unknown_fields = true,
            .allocate = .alloc_always,
        }) catch {
            r.setStatus(.bad_request);
            try r.sendJson("{\"error\":\"invalid JSON body\"}");
            return;
        };
        defer parsed.deinit();

        const req = parsed.value;

        const hash = db.getPasswordHash(self.allocator, req.username) catch {
            r.setStatus(.internal_server_error);
            try r.sendJson("{\"error\":\"internal error\"}");
            return;
        };

        if (hash) |h| {
            defer self.allocator.free(h);
            if (!Auth.verifyPassword(h, req.password)) {
                r.setStatus(.unauthorized);
                try r.sendJson("{\"error\":\"invalid credentials\"}");
                return;
            }
        } else {
            // Dummy verify to prevent timing attacks on user enumeration
            _ = Auth.verifyPassword("$2b$10$000000000000000000000uIHbxjGFi2yU4JEbTxHLGMYE5C3MNO", req.password);
            r.setStatus(.unauthorized);
            try r.sendJson("{\"error\":\"invalid credentials\"}");
            return;
        }

        // Create JWT
        const token = auth.createToken(self.allocator, req.username) catch {
            r.setStatus(.internal_server_error);
            try r.sendJson("{\"error\":\"token creation failed\"}");
            return;
        };
        defer self.allocator.free(token);

        const resp = std.fmt.allocPrint(self.allocator,
            \\{{"token":"{s}"}}
        , .{token}) catch {
            r.setStatus(.internal_server_error);
            try r.sendJson("{\"error\":\"response serialization failed\"}");
            return;
        };
        defer self.allocator.free(resp);

        try r.sendJson(resp);
    }

    fn handleChangePassword(self: *Api, r: zap.Request) !void {
        if (r.methodAsEnum() != .POST) {
            r.setStatus(.method_not_allowed);
            try r.sendJson("{\"error\":\"method not allowed\"}");
            return;
        }

        const auth = self.auth orelse {
            r.setStatus(.service_unavailable);
            try r.sendJson("{\"error\":\"authentication not configured\"}");
            return;
        };

        const db = self.db orelse {
            r.setStatus(.service_unavailable);
            try r.sendJson("{\"error\":\"database not configured\"}");
            return;
        };

        // Extract username from token
        const auth_header = r.getHeader("authorization") orelse {
            r.setStatus(.unauthorized);
            try r.sendJson("{\"error\":\"unauthorized\"}");
            return;
        };
        const token = auth_header["Bearer ".len..];
        var sub_buf: [512]u8 = undefined;
        const username = auth.getTokenSubject(token, &sub_buf) orelse {
            r.setStatus(.unauthorized);
            try r.sendJson("{\"error\":\"invalid token\"}");
            return;
        };

        const body = r.body orelse {
            r.setStatus(.bad_request);
            try r.sendJson("{\"error\":\"missing request body\"}");
            return;
        };

        const parsed = std.json.parseFromSlice(ChangePasswordRequest, self.allocator, body, .{
            .ignore_unknown_fields = true,
            .allocate = .alloc_always,
        }) catch {
            r.setStatus(.bad_request);
            try r.sendJson("{\"error\":\"invalid JSON body\"}");
            return;
        };
        defer parsed.deinit();

        const req = parsed.value;

        // Verify current password
        const hash = db.getPasswordHash(self.allocator, username) catch {
            r.setStatus(.internal_server_error);
            try r.sendJson("{\"error\":\"internal error\"}");
            return;
        };
        if (hash) |h| {
            defer self.allocator.free(h);
            if (!Auth.verifyPassword(h, req.current_password)) {
                r.setStatus(.unauthorized);
                try r.sendJson("{\"error\":\"current password is incorrect\"}");
                return;
            }
        } else {
            r.setStatus(.not_found);
            try r.sendJson("{\"error\":\"user not found\"}");
            return;
        }

        // Hash new password
        const new_hash = Auth.hashPassword(req.new_password) catch {
            r.setStatus(.internal_server_error);
            try r.sendJson("{\"error\":\"failed to hash password\"}");
            return;
        };

        // Update in DB
        db.updatePassword(username, &new_hash) catch {
            r.setStatus(.internal_server_error);
            try r.sendJson("{\"error\":\"failed to update password\"}");
            return;
        };

        try r.sendJson("{\"ok\":true}");
    }

    fn handleNodes(self: *Api, r: zap.Request) !void {
        switch (r.methodAsEnum()) {
            .GET => try self.listNodes(r),
            .POST => try self.addNode(r),
            else => {
                r.setStatus(.method_not_allowed);
                try r.sendJson("{\"error\":\"method not allowed\"}");
            },
        }
    }

    fn handleNodeDetail(self: *Api, r: zap.Request, path: []const u8) !void {
        const after_prefix = path["/api/nodes/".len..];
        const slash_pos = std.mem.indexOf(u8, after_prefix, "/");
        const node_id = if (slash_pos) |pos| after_prefix[0..pos] else after_prefix;
        const rest = if (slash_pos) |pos| after_prefix[pos..] else "";

        if (rest.len == 0) {
            switch (r.methodAsEnum()) {
                .DELETE => try self.deleteNode(r, node_id),
                .GET => try self.getNode(r, node_id),
                .PATCH, .PUT => try self.updateNode(r, node_id),
                else => {
                    r.setStatus(.method_not_allowed);
                    try r.sendJson("{\"error\":\"method not allowed\"}");
                },
            }
        } else if (std.mem.eql(u8, rest, "/stats")) {
            try self.getNodeStats(r, node_id);
        } else if (std.mem.eql(u8, rest, "/stats/history")) {
            try self.getNodeStatsHistory(r, node_id);
        } else if (std.mem.eql(u8, rest, "/deploy")) {
            try self.handleDeploy(r, node_id);
        } else {
            r.setStatus(.not_found);
            try r.sendJson("{\"error\":\"not found\"}");
        }
    }

    fn listNodes(self: *Api, r: zap.Request) !void {
        // Always include live agents from store + DB nodes
        const store_agents = try self.store.getAllAgentStatus(self.allocator);
        defer self.allocator.free(store_agents);

        var buf: std.ArrayListUnmanaged(u8) = .{};
        defer buf.deinit(self.allocator);

        try buf.append(self.allocator, '[');
        var count: usize = 0;

        // Track which agent IDs we've already added (from store)
        var seen = std.StringHashMap(void).init(self.allocator);
        defer seen.deinit();

        // Build DB lookup for node metadata
        var db_lookup = std.StringHashMap(NodeMeta).init(self.allocator);
        defer db_lookup.deinit();

        const db_nodes = if (self.db) |db| db.listNodes(self.allocator) catch &.{} else &.{};
        defer {
            for (db_nodes) |node| node.deinit(self.allocator);
            if (db_nodes.len > 0) self.allocator.free(db_nodes);
        }
        // Collect tags that need freeing after response is sent
        var tag_allocs: std.ArrayListUnmanaged([][]const u8) = .{};
        defer {
            for (tag_allocs.items) |tags| {
                for (tags) |t| self.allocator.free(t);
                self.allocator.free(tags);
            }
            tag_allocs.deinit(self.allocator);
        }

        for (db_nodes) |node| {
            const tags: ?[][]const u8 = if (self.db) |db| blk: {
                const t = db.getNodeTags(self.allocator, node.id) catch break :blk null;
                tag_allocs.append(self.allocator, t) catch {
                    for (t) |s| self.allocator.free(s);
                    self.allocator.free(t);
                    break :blk null;
                };
                break :blk t;
            } else null;

            db_lookup.put(node.id, .{
                .name = node.name,
                .host = node.host,
                .status = node.status,
                .os_id = node.os_id,
                .os_version = node.os_version,
                .os_name = node.os_name,
                .arch = node.arch,
                .kernel = node.kernel,
                .cpu_model = node.cpu_model,
                .cpu_cores = node.cpu_cores,
                .total_ram = node.total_ram,
                .pkg_manager = node.pkg_manager,
                .tags = tags,
            }) catch {};
        }

        // First: add all live agents from the in-memory store (enriched with DB metadata)
        for (store_agents) |agent| {
            if (count > 0) try buf.append(self.allocator, ',');
            const meta = db_lookup.get(agent.agent_id);
            const entry = try self.formatNodeJson(agent.agent_id, meta, agent.connected, agent.last_seen, agent.snapshot_count);
            defer self.allocator.free(entry);
            try buf.appendSlice(self.allocator, entry);
            try seen.put(agent.agent_id, {});
            count += 1;
        }

        // Second: add DB nodes that aren't already in the store (offline nodes)
        for (db_nodes) |node| {
            if (seen.contains(node.id)) continue;
            if (count > 0) try buf.append(self.allocator, ',');
            const meta = db_lookup.get(node.id);
            const entry = try self.formatNodeJson(node.id, meta, false, node.last_seen orelse node.created_at, 0);
            defer self.allocator.free(entry);
            try buf.appendSlice(self.allocator, entry);
            count += 1;
        }

        try buf.append(self.allocator, ']');
        try r.sendJson(buf.items);
    }

    const NodeMeta = struct {
        name: []const u8,
        host: []const u8,
        status: []const u8,
        os_id: ?[]const u8,
        os_version: ?[]const u8,
        os_name: ?[]const u8,
        arch: ?[]const u8,
        kernel: ?[]const u8,
        cpu_model: ?[]const u8,
        cpu_cores: ?i64,
        total_ram: ?i64,
        pkg_manager: ?[]const u8,
        tags: ?[][]const u8 = null,
    };

    fn formatNodeJson(self: *Api, agent_id: []const u8, meta: ?NodeMeta, connected: bool, last_seen: i64, snapshot_count: usize) ![]u8 {
        var json_buf: std.ArrayListUnmanaged(u8) = .{};
        const w = json_buf.writer(self.allocator);
        try w.writeAll("{");
        try std.fmt.format(w, "\"agent_id\":\"{s}\"", .{agent_id});
        try std.fmt.format(w, ",\"name\":\"{s}\"", .{if (meta) |m| m.name else agent_id});
        try std.fmt.format(w, ",\"host\":\"{s}\"", .{if (meta) |m| m.host else ""});
        try std.fmt.format(w, ",\"connected\":{s}", .{if (connected) "true" else "false"});
        try std.fmt.format(w, ",\"last_seen\":{d}", .{last_seen});
        try std.fmt.format(w, ",\"snapshot_count\":{d}", .{snapshot_count});

        // Sysinfo fields
        if (meta) |m| {
            if (m.os_id) |v| try std.fmt.format(w, ",\"os_id\":\"{s}\"", .{v}) else try w.writeAll(",\"os_id\":null");
            if (m.os_version) |v| try std.fmt.format(w, ",\"os_version\":\"{s}\"", .{v}) else try w.writeAll(",\"os_version\":null");
            if (m.os_name) |v| try std.fmt.format(w, ",\"os_name\":\"{s}\"", .{v}) else try w.writeAll(",\"os_name\":null");
            if (m.arch) |v| try std.fmt.format(w, ",\"arch\":\"{s}\"", .{v}) else try w.writeAll(",\"arch\":null");
            if (m.kernel) |v| try std.fmt.format(w, ",\"kernel\":\"{s}\"", .{v}) else try w.writeAll(",\"kernel\":null");
            if (m.cpu_model) |v| try std.fmt.format(w, ",\"cpu_model\":\"{s}\"", .{v}) else try w.writeAll(",\"cpu_model\":null");
            if (m.cpu_cores) |v| try std.fmt.format(w, ",\"cpu_cores\":{d}", .{v}) else try w.writeAll(",\"cpu_cores\":null");
            if (m.total_ram) |v| try std.fmt.format(w, ",\"total_ram\":{d}", .{v}) else try w.writeAll(",\"total_ram\":null");
            if (m.pkg_manager) |v| try std.fmt.format(w, ",\"pkg_manager\":\"{s}\"", .{v}) else try w.writeAll(",\"pkg_manager\":null");
        } else {
            try w.writeAll(",\"os_id\":null,\"os_version\":null,\"os_name\":null,\"arch\":null,\"kernel\":null,\"cpu_model\":null,\"cpu_cores\":null,\"total_ram\":null,\"pkg_manager\":null");
        }

        // Tags
        try w.writeAll(",\"tags\":[");
        if (meta) |m| {
            if (m.tags) |tags| {
                for (tags, 0..) |tag, i| {
                    if (i > 0) try w.writeByte(',');
                    try w.writeByte('"');
                    try w.writeAll(tag);
                    try w.writeByte('"');
                }
            }
        }
        try w.writeByte(']');

        try w.writeAll("}");
        return try json_buf.toOwnedSlice(self.allocator);
    }

    fn getNode(self: *Api, r: zap.Request, node_id: []const u8) !void {
        if (self.store.getLatest(node_id)) |snapshot| {
            try r.sendJson(snapshot);
        } else {
            r.setStatus(.not_found);
            try r.sendJson("{\"error\":\"node not found\"}");
        }
    }

    fn addNode(self: *Api, r: zap.Request) !void {
        const db = self.db orelse {
            r.setStatus(.service_unavailable);
            try r.sendJson("{\"error\":\"database not configured\"}");
            return;
        };
        const crypto_engine = self.crypto orelse {
            r.setStatus(.service_unavailable);
            try r.sendJson("{\"error\":\"crypto not configured\"}");
            return;
        };

        // Parse request body
        const body = r.body orelse {
            r.setStatus(.bad_request);
            try r.sendJson("{\"error\":\"missing request body\"}");
            return;
        };

        const parsed = std.json.parseFromSlice(AddNodeRequest, self.allocator, body, .{
            .ignore_unknown_fields = true,
            .allocate = .alloc_always,
        }) catch {
            r.setStatus(.bad_request);
            try r.sendJson("{\"error\":\"invalid JSON body\"}");
            return;
        };
        defer parsed.deinit();

        const req = parsed.value;

        // Generate node ID and token
        var id_buf: [32]u8 = undefined;
        std.crypto.random.bytes(&id_buf);
        const node_id = std.fmt.bytesToHex(id_buf, .lower);

        var token_buf: [32]u8 = undefined;
        std.crypto.random.bytes(&token_buf);
        const token = std.fmt.bytesToHex(token_buf, .lower);

        // Encrypt SSH key
        const enc = crypto_engine.encrypt(self.allocator, req.ssh_key) catch {
            r.setStatus(.internal_server_error);
            try r.sendJson("{\"error\":\"encryption failed\"}");
            return;
        };
        defer self.allocator.free(enc.ciphertext);

        // Store in DB
        db.insertNode(
            &node_id,
            req.name,
            req.host,
            req.port orelse 22,
            req.ssh_user,
            enc.ciphertext,
            &enc.nonce,
            &enc.tag,
            &token,
        ) catch {
            r.setStatus(.internal_server_error);
            try r.sendJson("{\"error\":\"database insert failed\"}");
            return;
        };

        // Register token in WsState so Spider can authenticate immediately
        if (self.ws_state) |ws| {
            ws.addToken(&node_id, &token) catch {};
        }

        // Store sudo password if provided
        if (req.sudo_password) |pass| {
            if (crypto_engine.encrypt(self.allocator, pass)) |sudo_enc| {
                defer self.allocator.free(sudo_enc.ciphertext);
                db.updateSudoPass(&node_id, sudo_enc.ciphertext, &sudo_enc.nonce, &sudo_enc.tag) catch {};
            } else |_| {
                std.log.warn("api: failed to encrypt sudo password", .{});
            }
        }

        // Respond with node info
        const resp = std.fmt.allocPrint(self.allocator,
            \\{{"id":"{s}","name":"{s}","host":"{s}","token":"{s}","status":"pending"}}
        , .{ node_id, req.name, req.host, token }) catch {
            r.setStatus(.internal_server_error);
            try r.sendJson("{\"error\":\"response serialization failed\"}");
            return;
        };
        defer self.allocator.free(resp);

        r.setStatus(.created);
        try r.sendJson(resp);

        // Record event
        if (self.db) |edb| {
            edb.insertEvent("node.added", &node_id, req.name, null);
        }
    }

    fn deleteNode(self: *Api, r: zap.Request, node_id: []const u8) !void {
        // Record event before deletion (so we still have the node_id)
        if (self.db) |db| {
            db.insertEvent("node.removed", node_id, "Node removed", null);
        }
        // Always delete from DB, regardless of SSH undeploy result
        if (self.db) |db| {
            db.deleteNode(node_id) catch {};
        }
        if (self.ws_state) |ws| {
            ws.removeToken(node_id);
        }
        self.store.removeAgent(node_id);
        try r.sendJson("{\"status\":\"deleted\"}");
    }

    fn updateNode(self: *Api, r: zap.Request, node_id: []const u8) !void {
        const db = self.db orelse {
            r.setStatus(.service_unavailable);
            try r.sendJson("{\"error\":\"database not configured\"}");
            return;
        };
        const crypto_engine = self.crypto orelse {
            r.setStatus(.service_unavailable);
            try r.sendJson("{\"error\":\"crypto not configured\"}");
            return;
        };

        const body = r.body orelse {
            r.setStatus(.bad_request);
            try r.sendJson("{\"error\":\"missing request body\"}");
            return;
        };

        const parsed = std.json.parseFromSlice(UpdateNodeRequest, self.allocator, body, .{
            .ignore_unknown_fields = true,
            .allocate = .alloc_always,
        }) catch {
            r.setStatus(.bad_request);
            try r.sendJson("{\"error\":\"invalid JSON body\"}");
            return;
        };
        defer parsed.deinit();

        const req = parsed.value;

        // Update sudo password if provided
        if (req.sudo_password) |pass| {
            const enc = crypto_engine.encrypt(self.allocator, pass) catch {
                r.setStatus(.internal_server_error);
                try r.sendJson("{\"error\":\"encryption failed\"}");
                return;
            };
            defer self.allocator.free(enc.ciphertext);

            db.updateSudoPass(node_id, enc.ciphertext, &enc.nonce, &enc.tag) catch {
                r.setStatus(.internal_server_error);
                try r.sendJson("{\"error\":\"database update failed\"}");
                return;
            };
        }

        // Update SSH key if provided
        if (req.ssh_key) |key| {
            const enc = crypto_engine.encrypt(self.allocator, key) catch {
                r.setStatus(.internal_server_error);
                try r.sendJson("{\"error\":\"encryption failed\"}");
                return;
            };
            defer self.allocator.free(enc.ciphertext);

            db.updateSshKey(node_id, enc.ciphertext, &enc.nonce, &enc.tag) catch {
                r.setStatus(.internal_server_error);
                try r.sendJson("{\"error\":\"database update failed\"}");
                return;
            };
        }

        // Update tags if provided
        if (req.tags) |tags| {
            db.setNodeTags(node_id, tags) catch {
                r.setStatus(.internal_server_error);
                try r.sendJson("{\"error\":\"tag update failed\"}");
                return;
            };
        }

        try r.sendJson("{\"status\":\"updated\"}");
    }

    fn getNodeStats(self: *Api, r: zap.Request, node_id: []const u8) !void {
        if (self.store.getLatest(node_id)) |snapshot| {
            try r.sendJson(snapshot);
        } else {
            r.setStatus(.not_found);
            try r.sendJson("{\"error\":\"no stats available\"}");
        }
    }

    fn getNodeStatsHistory(self: *Api, r: zap.Request, node_id: []const u8) !void {
        r.parseQuery();
        var count: usize = 60;
        if (r.getParamSlice("count")) |count_str| {
            count = std.fmt.parseInt(usize, count_str, 10) catch 60;
        }

        const history = try self.store.getHistory(self.allocator, node_id, count);
        defer self.allocator.free(history);

        if (history.len == 0) {
            try r.sendJson("[]");
            return;
        }

        var buf: std.ArrayListUnmanaged(u8) = .{};
        defer buf.deinit(self.allocator);

        try buf.append(self.allocator, '[');
        for (history, 0..) |snapshot, i| {
            try buf.appendSlice(self.allocator, snapshot);
            if (i < history.len - 1) try buf.append(self.allocator, ',');
        }
        try buf.append(self.allocator, ']');

        try r.sendJson(buf.items);
    }

    fn handleDeploy(self: *Api, r: zap.Request, node_id: []const u8) !void {
        if (r.methodAsEnum() != .POST) {
            r.setStatus(.method_not_allowed);
            try r.sendJson("{\"error\":\"method not allowed\"}");
            return;
        }

        const deployer = self.deployer orelse {
            r.setStatus(.service_unavailable);
            try r.sendJson("{\"error\":\"deployer not configured\"}");
            return;
        };

        r.parseQuery();
        const step = r.getParamSlice("step") orelse {
            r.setStatus(.bad_request);
            try r.sendJson("{\"error\":\"missing step parameter\"}");
            return;
        };

        var ok: bool = false;
        var message: []const u8 = "";

        const result = if (std.mem.eql(u8, step, "upload"))
            deployer.stepUploadBinary(node_id, r.getParamSlice("arch"))
        else if (std.mem.eql(u8, step, "install"))
            deployer.stepInstallService(node_id)
        else if (std.mem.eql(u8, step, "start")) blk: {
            const sr = deployer.stepStartService(node_id);
            if (sr.ok) {
                if (self.db) |edb| edb.insertEvent("deploy.started", node_id, "Spider deployed", null);
            }
            break :blk sr;
        }
        else if (std.mem.eql(u8, step, "connect"))
            deployer.stepConnect(node_id)
        else if (std.mem.eql(u8, step, "stop"))
            deployer.stepStopService(node_id)
        else if (std.mem.eql(u8, step, "check-stopped"))
            deployer.stepCheckStopped(node_id)
        else if (std.mem.eql(u8, step, "uninstall"))
            deployer.stepUninstallService(node_id)
        else if (std.mem.eql(u8, step, "check-uninstalled"))
            deployer.stepCheckUninstalled(node_id)
        else if (std.mem.eql(u8, step, "remove-binary"))
            deployer.stepRemoveBinary(node_id)
        else if (std.mem.eql(u8, step, "check-removed"))
            deployer.stepCheckRemoved(node_id)
        else if (std.mem.eql(u8, step, "wipe-creds")) blk: {
            if (self.db) |db| {
                db.wipeCredentials(node_id) catch
                    break :blk deployer_mod.StepResult{ .ok = false, .message = "failed to wipe credentials" };
            }
            break :blk deployer_mod.StepResult{ .ok = true, .message = "credentials wiped" };
        } else if (std.mem.eql(u8, step, "detect-pkg-manager"))
            deployer.stepDetectPkgManager(node_id)
        else if (std.mem.eql(u8, step, "pkg-refresh")) {
            // Special case: returns raw output, not a simple StepResult
            const pkg_mgr = r.getParamSlice("pkg") orelse {
                r.setStatus(.bad_request);
                try r.sendJson("{\"error\":\"missing pkg parameter\"}");
                return;
            };
            const output = deployer.stepPkgRefresh(node_id, pkg_mgr);
            defer if (output) |o| self.allocator.free(o);

            if (output) |o| {
                const escaped = jsonEscape(self.allocator, o) catch {
                    r.setStatus(.internal_server_error);
                    try r.sendJson("{\"error\":\"response too large\"}");
                    return;
                };
                defer self.allocator.free(escaped);
                const out_resp = std.fmt.allocPrint(self.allocator,
                    \\{{"ok":true,"output":"{s}"}}
                , .{escaped}) catch {
                    r.setStatus(.internal_server_error);
                    try r.sendJson("{\"error\":\"response serialization failed\"}");
                    return;
                };
                defer self.allocator.free(out_resp);
                try r.sendJson(out_resp);
            } else {
                try r.sendJson("{\"ok\":false,\"output\":\"command failed\"}");
            }
            return;
        } else if (std.mem.eql(u8, step, "pkg-job-start")) {
            const pkg_mgr = r.getParamSlice("pkg") orelse {
                r.setStatus(.bad_request);
                try r.sendJson("{\"error\":\"missing pkg parameter\"}");
                return;
            };
            const action = r.getParamSlice("action") orelse {
                r.setStatus(.bad_request);
                try r.sendJson("{\"error\":\"missing action parameter\"}");
                return;
            };
            const job_id = deployer.startPkgJob(node_id, pkg_mgr, action) orelse {
                r.setStatus(.internal_server_error);
                try r.sendJson("{\"error\":\"failed to start job\"}");
                return;
            };
            const start_resp = std.fmt.allocPrint(self.allocator,
                \\{{"job_id":"{s}"}}
            , .{job_id}) catch {
                r.setStatus(.internal_server_error);
                try r.sendJson("{\"error\":\"response serialization failed\"}");
                return;
            };
            defer self.allocator.free(start_resp);
            try r.sendJson(start_resp);
            return;
        } else if (std.mem.eql(u8, step, "pkg-refresh-start")) {
            const pkg_mgr = r.getParamSlice("pkg") orelse {
                r.setStatus(.bad_request);
                try r.sendJson("{\"error\":\"missing pkg parameter\"}");
                return;
            };
            const job_id = deployer.startPkgRefreshJob(node_id, pkg_mgr) orelse {
                r.setStatus(.internal_server_error);
                try r.sendJson("{\"error\":\"failed to start job\"}");
                return;
            };
            const start_resp = std.fmt.allocPrint(self.allocator,
                \\{{"job_id":"{s}"}}
            , .{job_id}) catch {
                r.setStatus(.internal_server_error);
                try r.sendJson("{\"error\":\"response serialization failed\"}");
                return;
            };
            defer self.allocator.free(start_resp);
            try r.sendJson(start_resp);
            return;
        } else if (std.mem.eql(u8, step, "pkg-refresh-poll")) {
            const job_id = r.getParamSlice("job") orelse {
                r.setStatus(.bad_request);
                try r.sendJson("{\"error\":\"missing job parameter\"}");
                return;
            };
            const offset_str = r.getParamSlice("offset") orelse "0";
            const offset = std.fmt.parseInt(usize, offset_str, 10) catch 0;

            const state = deployer.pollJobOffset(job_id, offset) orelse {
                r.setStatus(.not_found);
                try r.sendJson("{\"error\":\"job not found\"}");
                return;
            };

            const escaped = jsonEscape(self.allocator, state.new_output) catch {
                try r.sendJson("{\"error\":\"encode failed\"}");
                return;
            };
            defer self.allocator.free(escaped);

            const new_offset = offset + state.new_output.len;
            const poll_resp = std.fmt.allocPrint(self.allocator,
                \\{{"output":"{s}","offset":{d},"done":{s},"ok":{s}}}
            , .{
                escaped,
                new_offset,
                if (state.done) "true" else "false",
                if (state.ok) "true" else "false",
            }) catch {
                try r.sendJson("{\"error\":\"response serialization failed\"}");
                return;
            };
            defer self.allocator.free(poll_resp);
            try r.sendJson(poll_resp);

            if (state.done) {
                deployer.removeJob(job_id);
            }
            return;
        } else {
            r.setStatus(.bad_request);
            try r.sendJson("{\"error\":\"invalid step\"}");
            return;
        };
        ok = result.ok;
        message = result.message;

        const resp = std.fmt.allocPrint(self.allocator,
            \\{{"ok":{s},"message":"{s}"}}
        , .{
            if (ok) "true" else "false",
            message,
        }) catch {
            r.setStatus(.internal_server_error);
            try r.sendJson("{\"error\":\"response serialization failed\"}");
            return;
        };
        defer self.allocator.free(resp);

        try r.sendJson(resp);
    }

    fn handleNodeCheck(self: *Api, r: zap.Request) !void {
        if (r.methodAsEnum() != .POST) {
            r.setStatus(.method_not_allowed);
            try r.sendJson("{\"error\":\"method not allowed\"}");
            return;
        }

        const deployer = self.deployer orelse {
            r.setStatus(.service_unavailable);
            try r.sendJson("{\"error\":\"deployer not configured\"}");
            return;
        };

        const body = r.body orelse {
            r.setStatus(.bad_request);
            try r.sendJson("{\"error\":\"missing request body\"}");
            return;
        };

        const parsed = std.json.parseFromSlice(CheckNodeRequest, self.allocator, body, .{
            .ignore_unknown_fields = true,
            .allocate = .alloc_always,
        }) catch {
            r.setStatus(.bad_request);
            try r.sendJson("{\"error\":\"invalid JSON body\"}");
            return;
        };
        defer parsed.deinit();

        const req = parsed.value;

        const result = deployer.checkSystem(
            req.host,
            req.port orelse 22,
            req.ssh_user,
            req.ssh_key,
            req.sudo_password,
        );
        defer if (result.arch) |a| self.allocator.free(a);

        // Build arch JSON value
        var arch_buf: [64]u8 = undefined;
        const arch_json: []const u8 = if (result.arch) |a| blk: {
            const s = std.fmt.bufPrint(&arch_buf, "\"{s}\"", .{a}) catch break :blk "null";
            break :blk s;
        } else "null";

        const resp = std.fmt.allocPrint(self.allocator,
            \\{{"connected":{s},"arch":{s},"agent_available":{s},"message":"{s}"}}
        , .{
            if (result.connected) "true" else "false",
            arch_json,
            if (result.agent_available) "true" else "false",
            result.message,
        }) catch {
            r.setStatus(.internal_server_error);
            try r.sendJson("{\"error\":\"response serialization failed\"}");
            return;
        };
        defer self.allocator.free(resp);

        try r.sendJson(resp);
    }

    // --- Capabilities ---

    fn handleCapabilities(self: *Api, r: zap.Request) !void {
        if (r.methodAsEnum() != .GET) {
            r.setStatus(.method_not_allowed);
            try r.sendJson("{\"error\":\"method not allowed\"}");
            return;
        }

        const ansible_ver = if (self.ansible) |a| a.version else null;
        const ver_json = if (ansible_ver) |v| blk: {
            const j = std.fmt.allocPrint(self.allocator, "\"{s}\"", .{v}) catch break :blk @as([]const u8, "null");
            break :blk j;
        } else @as([]const u8, "null");
        defer if (ansible_ver != null) self.allocator.free(ver_json);

        const resp = std.fmt.allocPrint(self.allocator,
            \\{{"deployer":{s},"auth":{s},"ansible":{s},"ansible_version":{s},"fleet":{s},"services":{s},"processes":{s},"logs":{s},"drift":{s},"security":{s},"containers":{s},"schedules":{s}}}
        , .{
            if (self.deployer != null) "true" else "false",
            if (self.auth != null) "true" else "false",
            if (self.ansible != null) "true" else "false",
            ver_json,
            if (self.fleet != null) "true" else "false",
            if (self.services != null) "true" else "false",
            if (self.processes != null) "true" else "false",
            if (self.logs != null) "true" else "false",
            if (self.drift != null) "true" else "false",
            if (self.security != null) "true" else "false",
            if (self.containers != null) "true" else "false",
            if (self.scheduler != null) "true" else "false",
        }) catch {
            r.setStatus(.internal_server_error);
            try r.sendJson("{\"error\":\"response serialization failed\"}");
            return;
        };
        defer self.allocator.free(resp);
        try r.sendJson(resp);
    }

    // --- Tags ---

    fn handleTags(self: *Api, r: zap.Request) !void {
        if (r.methodAsEnum() != .GET) {
            r.setStatus(.method_not_allowed);
            try r.sendJson("{\"error\":\"method not allowed\"}");
            return;
        }
        const db = self.db orelse {
            try r.sendJson("[]");
            return;
        };
        const tags = db.getAllTags(self.allocator) catch {
            r.setStatus(.internal_server_error);
            try r.sendJson("{\"error\":\"failed to fetch tags\"}");
            return;
        };
        defer {
            for (tags) |t| self.allocator.free(t);
            self.allocator.free(tags);
        }

        var buf: std.ArrayListUnmanaged(u8) = .{};
        defer buf.deinit(self.allocator);
        const w = buf.writer(self.allocator);
        try w.writeByte('[');
        for (tags, 0..) |tag, i| {
            if (i > 0) try w.writeByte(',');
            try w.writeByte('"');
            try w.writeAll(tag);
            try w.writeByte('"');
        }
        try w.writeByte(']');
        try r.sendJson(buf.items);
    }

    // --- Events ---

    fn handleEvents(self: *Api, r: zap.Request) !void {
        if (r.methodAsEnum() != .GET) {
            r.setStatus(.method_not_allowed);
            try r.sendJson("{\"error\":\"method not allowed\"}");
            return;
        }
        const db = self.db orelse {
            try r.sendJson("[]");
            return;
        };

        r.parseQuery();
        const node_id = r.getParamSlice("node_id");
        const event_type = r.getParamSlice("type");
        const limit_str = r.getParamSlice("limit") orelse "50";
        const before_str = r.getParamSlice("before");

        var limit = std.fmt.parseInt(i64, limit_str, 10) catch 50;
        if (limit > 200) limit = 200;
        if (limit < 1) limit = 50;

        const before_id: ?i64 = if (before_str) |s| std.fmt.parseInt(i64, s, 10) catch null else null;

        const events = db.listEvents(self.allocator, node_id, event_type, limit, before_id) catch {
            r.setStatus(.internal_server_error);
            try r.sendJson("{\"error\":\"database error\"}");
            return;
        };
        defer {
            for (events) |e| e.deinit(self.allocator);
            self.allocator.free(events);
        }

        var buf: std.ArrayListUnmanaged(u8) = .{};
        defer buf.deinit(self.allocator);
        const w = buf.writer(self.allocator);
        try w.writeByte('[');
        for (events, 0..) |evt, i| {
            if (i > 0) try w.writeByte(',');
            try w.writeAll("{\"id\":");
            try std.fmt.format(w, "{d}", .{evt.id});
            try w.writeAll(",\"created_at\":");
            try std.fmt.format(w, "{d}", .{evt.created_at});
            try w.writeAll(",\"event_type\":\"");
            try w.writeAll(evt.event_type);
            try w.writeAll("\",\"node_id\":");
            if (evt.node_id) |nid| {
                try w.writeByte('"');
                try w.writeAll(nid);
                try w.writeByte('"');
            } else {
                try w.writeAll("null");
            }
            try w.writeAll(",\"message\":\"");
            const escaped_msg = jsonEscape(self.allocator, evt.message) catch "";
            defer if (escaped_msg.len > 0) self.allocator.free(escaped_msg);
            try w.writeAll(escaped_msg);
            try w.writeAll("\",\"detail\":");
            if (evt.detail) |d| {
                try w.writeByte('"');
                const escaped_det = jsonEscape(self.allocator, d) catch "";
                defer if (escaped_det.len > 0) self.allocator.free(escaped_det);
                try w.writeAll(escaped_det);
                try w.writeByte('"');
            } else {
                try w.writeAll("null");
            }
            try w.writeByte('}');
        }
        try w.writeByte(']');
        try r.sendJson(buf.items);
    }

    // --- Ansible ---

    fn handleAnsible(self: *Api, r: zap.Request, path: []const u8) !void {
        const ansible = self.ansible orelse {
            r.setStatus(.service_unavailable);
            try r.sendJson("{\"error\":\"ansible not available\"}");
            return;
        };

        if (std.mem.eql(u8, path, "/api/ansible/status")) {
            if (r.methodAsEnum() != .GET) {
                r.setStatus(.method_not_allowed);
                try r.sendJson("{\"error\":\"method not allowed\"}");
                return;
            }
            const resp = std.fmt.allocPrint(self.allocator,
                \\{{"available":true,"version":"{s}"}}
            , .{ansible.version}) catch {
                try r.sendJson("{\"error\":\"response serialization failed\"}");
                return;
            };
            defer self.allocator.free(resp);
            try r.sendJson(resp);
        } else if (std.mem.eql(u8, path, "/api/ansible/run")) {
            try self.handleAnsibleRun(r, ansible);
        } else if (std.mem.eql(u8, path, "/api/ansible/poll")) {
            try self.handleAnsiblePoll(r, ansible);
        } else {
            r.setStatus(.not_found);
            try r.sendJson("{\"error\":\"not found\"}");
        }
    }

    fn handleAnsibleRun(self: *Api, r: zap.Request, ansible: *AnsibleEngine) !void {
        if (r.methodAsEnum() != .POST) {
            r.setStatus(.method_not_allowed);
            try r.sendJson("{\"error\":\"method not allowed\"}");
            return;
        }

        const body = r.body orelse {
            r.setStatus(.bad_request);
            try r.sendJson("{\"error\":\"missing request body\"}");
            return;
        };

        // Parse JSON body: { "playbook": "...", "nodes": ["id1","id2"] | null }
        const parsed = std.json.parseFromSlice(AnsibleRunRequest, self.allocator, body, .{ .ignore_unknown_fields = true }) catch {
            r.setStatus(.bad_request);
            try r.sendJson("{\"error\":\"invalid JSON\"}");
            return;
        };
        defer parsed.deinit();
        const req = parsed.value;

        if (req.playbook.len == 0) {
            r.setStatus(.bad_request);
            try r.sendJson("{\"error\":\"playbook content is required\"}");
            return;
        }

        // Pass node IDs and requirements if provided
        const job_id = ansible.runPlaybook(req.playbook, req.nodes, req.requirements) orelse {
            r.setStatus(.internal_server_error);
            try r.sendJson("{\"error\":\"failed to start playbook\"}");
            return;
        };

        // Record event
        if (self.db) |edb| {
            const node_count = if (req.nodes) |n| n.len else 0;
            var msg_buf: [128]u8 = undefined;
            const msg = std.fmt.bufPrint(&msg_buf, "Ansible playbook executed on {d} nodes", .{node_count}) catch "Ansible playbook executed";
            edb.insertEvent("ansible.run", null, msg, null);
        }

        const resp = std.fmt.allocPrint(self.allocator,
            \\{{"job_id":"{s}"}}
        , .{job_id}) catch {
            try r.sendJson("{\"error\":\"response serialization failed\"}");
            return;
        };
        defer self.allocator.free(resp);
        try r.sendJson(resp);
    }

    fn handleAnsiblePoll(self: *Api, r: zap.Request, ansible: *AnsibleEngine) !void {
        if (r.methodAsEnum() != .POST) {
            r.setStatus(.method_not_allowed);
            try r.sendJson("{\"error\":\"method not allowed\"}");
            return;
        }

        r.parseQuery();
        const job_id = r.getParamSlice("job") orelse {
            r.setStatus(.bad_request);
            try r.sendJson("{\"error\":\"missing job parameter\"}");
            return;
        };
        const offset_str = r.getParamSlice("offset") orelse "0";
        const offset = std.fmt.parseInt(usize, offset_str, 10) catch 0;

        const state = ansible.pollJob(job_id, offset) orelse {
            r.setStatus(.not_found);
            try r.sendJson("{\"error\":\"job not found\"}");
            return;
        };

        const escaped = jsonEscape(self.allocator, state.new_output) catch {
            try r.sendJson("{\"error\":\"encode failed\"}");
            return;
        };
        defer self.allocator.free(escaped);

        const new_offset = offset + state.new_output.len;
        const poll_resp = std.fmt.allocPrint(self.allocator,
            \\{{"output":"{s}","offset":{d},"done":{s},"ok":{s}}}
        , .{
            escaped,
            new_offset,
            if (state.done) "true" else "false",
            if (state.ok) "true" else "false",
        }) catch {
            try r.sendJson("{\"error\":\"response serialization failed\"}");
            return;
        };
        defer self.allocator.free(poll_resp);
        try r.sendJson(poll_resp);

        if (state.done) {
            ansible.removeJob(job_id);
        }
    }

    // --- Fleet Command Execution ---

    fn handleFleet(self: *Api, r: zap.Request, path: []const u8) !void {
        const fleet = self.fleet orelse {
            r.setStatus(.service_unavailable);
            try r.sendJson("{\"error\":\"fleet commands not available\"}");
            return;
        };

        if (std.mem.eql(u8, path, "/api/fleet/run")) {
            try self.handleFleetRun(r, fleet);
        } else if (std.mem.eql(u8, path, "/api/fleet/poll")) {
            try self.handleFleetPoll(r, fleet);
        } else {
            r.setStatus(.not_found);
            try r.sendJson("{\"error\":\"not found\"}");
        }
    }

    fn handleFleetRun(self: *Api, r: zap.Request, fleet: *FleetEngine) !void {
        if (r.methodAsEnum() != .POST) {
            r.setStatus(.method_not_allowed);
            try r.sendJson("{\"error\":\"method not allowed\"}");
            return;
        }

        const body = r.body orelse {
            r.setStatus(.bad_request);
            try r.sendJson("{\"error\":\"missing request body\"}");
            return;
        };

        const parsed = std.json.parseFromSlice(FleetRunRequest, self.allocator, body, .{
            .ignore_unknown_fields = true,
            .allocate = .alloc_always,
        }) catch {
            r.setStatus(.bad_request);
            try r.sendJson("{\"error\":\"invalid JSON\"}");
            return;
        };
        defer parsed.deinit();
        const req = parsed.value;

        if (req.command.len == 0) {
            r.setStatus(.bad_request);
            try r.sendJson("{\"error\":\"command is required\"}");
            return;
        }
        if (req.node_ids.len == 0) {
            r.setStatus(.bad_request);
            try r.sendJson("{\"error\":\"at least one node_id is required\"}");
            return;
        }

        const job_id = fleet.runCommand(req.command, req.node_ids, req.sudo) orelse {
            r.setStatus(.internal_server_error);
            try r.sendJson("{\"error\":\"failed to start fleet command\"}");
            return;
        };

        // Record event
        if (self.db) |edb| {
            var msg_buf: [256]u8 = undefined;
            const cmd_preview = if (req.command.len > 60) req.command[0..60] else req.command;
            const msg = std.fmt.bufPrint(&msg_buf, "Fleet: '{s}' on {d} nodes", .{ cmd_preview, req.node_ids.len }) catch "Fleet command executed";
            edb.insertEvent("fleet.command", null, msg, null);
        }

        const resp = std.fmt.allocPrint(self.allocator, "{{\"job_id\":\"{s}\"}}", .{job_id}) catch {
            try r.sendJson("{\"error\":\"response serialization failed\"}");
            return;
        };
        defer self.allocator.free(resp);
        try r.sendJson(resp);
    }

    fn handleFleetPoll(self: *Api, r: zap.Request, fleet: *FleetEngine) !void {
        if (r.methodAsEnum() != .POST) {
            r.setStatus(.method_not_allowed);
            try r.sendJson("{\"error\":\"method not allowed\"}");
            return;
        }

        r.parseQuery();
        const job_id = r.getParamSlice("job") orelse {
            r.setStatus(.bad_request);
            try r.sendJson("{\"error\":\"missing job parameter\"}");
            return;
        };

        // Parse offsets from body
        const body = r.body orelse "{}";
        const parsed = std.json.parseFromSlice(FleetPollRequest, self.allocator, body, .{
            .ignore_unknown_fields = true,
            .allocate = .alloc_always,
        }) catch {
            r.setStatus(.bad_request);
            try r.sendJson("{\"error\":\"invalid JSON\"}");
            return;
        };
        defer parsed.deinit();

        // Build offset arrays for pollJob
        var offset_keys: [64][]const u8 = undefined;
        var offset_vals: [64]usize = undefined;
        var offset_count: usize = 0;
        if (parsed.value.offsets) |offsets| {
            for (offsets) |o| {
                if (offset_count >= 64) break;
                offset_keys[offset_count] = o.node_id;
                offset_vals[offset_count] = o.offset;
                offset_count += 1;
            }
        }

        const result = fleet.pollJob(job_id, offset_keys[0..offset_count], offset_vals[0..offset_count]) orelse {
            r.setStatus(.not_found);
            try r.sendJson("{\"error\":\"job not found\"}");
            return;
        };

        // Build JSON response: { "nodes": { "id": { ... }, ... }, "all_done": true/false }
        var resp_buf = std.ArrayListUnmanaged(u8){};
        defer resp_buf.deinit(self.allocator);
        resp_buf.appendSlice(self.allocator, "{\"nodes\":{") catch {
            try r.sendJson("{\"error\":\"response serialization failed\"}");
            return;
        };

        for (0..result.count) |i| {
            const entry = result.entries[i];
            if (i > 0) resp_buf.append(self.allocator, ',') catch {};

            const escaped_output = jsonEscape(self.allocator, entry.new_output) catch continue;
            defer self.allocator.free(escaped_output);

            const escaped_name = jsonEscape(self.allocator, entry.node_name) catch continue;
            defer self.allocator.free(escaped_name);

            const escaped_id = jsonEscape(self.allocator, entry.node_id) catch continue;
            defer self.allocator.free(escaped_id);

            const node_json = std.fmt.allocPrint(self.allocator,
                \\"{s}":{{"name":"{s}","output":"{s}","offset":{d},"done":{s},"ok":{s}}}
            , .{
                escaped_id,
                escaped_name,
                escaped_output,
                entry.offset,
                if (entry.done) "true" else "false",
                if (entry.ok) "true" else "false",
            }) catch continue;
            defer self.allocator.free(node_json);
            resp_buf.appendSlice(self.allocator, node_json) catch {};
        }

        const tail = std.fmt.allocPrint(self.allocator,
            \\}},"all_done":{s}}}
        , .{if (result.all_done) "true" else "false"}) catch {
            try r.sendJson("{\"error\":\"response serialization failed\"}");
            return;
        };
        defer self.allocator.free(tail);
        resp_buf.appendSlice(self.allocator, tail) catch {};

        try r.sendJson(resp_buf.items);

        if (result.all_done) {
            fleet.removeJob(job_id);
        }
    }

    // --- Services (Life on Mars) ---

    fn handleServices(self: *Api, r: zap.Request, path: []const u8) !void {
        const engine = self.services orelse {
            r.setStatus(.service_unavailable);
            try r.sendJson("{\"error\":\"service manager not available\"}");
            return;
        };

        // Path: /api/services/<node_id>/<action>
        const after = path["/api/services/".len..];
        const slash_pos = std.mem.indexOf(u8, after, "/");
        if (slash_pos == null) {
            r.setStatus(.not_found);
            try r.sendJson("{\"error\":\"missing sub-path\"}");
            return;
        }
        const node_id = after[0..slash_pos.?];
        const rest = after[slash_pos.?..];

        if (std.mem.eql(u8, rest, "/list")) {
            try self.handleServiceList(r, engine, node_id);
        } else if (std.mem.eql(u8, rest, "/status")) {
            try self.handleServiceStatus(r, engine, node_id);
        } else if (std.mem.eql(u8, rest, "/action")) {
            try self.handleServiceAction(r, engine, node_id);
        } else {
            r.setStatus(.not_found);
            try r.sendJson("{\"error\":\"not found\"}");
        }
    }

    fn handleServiceList(self: *Api, r: zap.Request, engine: *ServiceEngine, node_id: []const u8) !void {
        if (r.methodAsEnum() != .GET) {
            r.setStatus(.method_not_allowed);
            try r.sendJson("{\"error\":\"method not allowed\"}");
            return;
        }

        const scope_str = r.getParamSlice("scope") orelse "system";
        const scope = ServiceScope.fromString(scope_str);

        const result = engine.listServices(node_id, scope);
        defer if (result.output.len > 0) self.allocator.free(result.output);

        const escaped = jsonEscape(self.allocator, result.output) catch {
            r.setStatus(.internal_server_error);
            try r.sendJson("{\"error\":\"response serialization failed\"}");
            return;
        };
        defer self.allocator.free(escaped);

        const resp = std.fmt.allocPrint(self.allocator,
            \\{{"ok":{s},"output":"{s}"}}
        , .{
            if (result.ok) "true" else "false",
            escaped,
        }) catch {
            r.setStatus(.internal_server_error);
            try r.sendJson("{\"error\":\"response serialization failed\"}");
            return;
        };
        defer self.allocator.free(resp);
        try r.sendJson(resp);
    }

    fn handleServiceStatus(self: *Api, r: zap.Request, engine: *ServiceEngine, node_id: []const u8) !void {
        if (r.methodAsEnum() != .GET) {
            r.setStatus(.method_not_allowed);
            try r.sendJson("{\"error\":\"method not allowed\"}");
            return;
        }

        const name = r.getParamSlice("name") orelse {
            r.setStatus(.bad_request);
            try r.sendJson("{\"error\":\"missing name parameter\"}");
            return;
        };
        const scope_str = r.getParamSlice("scope") orelse "system";
        const scope = ServiceScope.fromString(scope_str);

        const result = engine.serviceStatus(node_id, name, scope);
        defer if (result.output.len > 0) self.allocator.free(result.output);

        const escaped = jsonEscape(self.allocator, result.output) catch {
            r.setStatus(.internal_server_error);
            try r.sendJson("{\"error\":\"response serialization failed\"}");
            return;
        };
        defer self.allocator.free(escaped);

        const resp = std.fmt.allocPrint(self.allocator,
            \\{{"ok":{s},"output":"{s}"}}
        , .{
            if (result.ok) "true" else "false",
            escaped,
        }) catch {
            r.setStatus(.internal_server_error);
            try r.sendJson("{\"error\":\"response serialization failed\"}");
            return;
        };
        defer self.allocator.free(resp);
        try r.sendJson(resp);
    }

    fn handleServiceAction(self: *Api, r: zap.Request, engine: *ServiceEngine, node_id: []const u8) !void {
        if (r.methodAsEnum() != .POST) {
            r.setStatus(.method_not_allowed);
            try r.sendJson("{\"error\":\"method not allowed\"}");
            return;
        }

        const body = r.body orelse {
            r.setStatus(.bad_request);
            try r.sendJson("{\"error\":\"missing request body\"}");
            return;
        };
        const parsed = std.json.parseFromSlice(ServiceActionRequest, self.allocator, body, .{ .ignore_unknown_fields = true }) catch {
            r.setStatus(.bad_request);
            try r.sendJson("{\"error\":\"invalid JSON\"}");
            return;
        };
        defer parsed.deinit();
        const req = parsed.value;

        const scope = ServiceScope.fromString(req.scope);
        const result = engine.serviceAction(node_id, req.name, req.action, scope);
        defer if (result.output.len > 0) self.allocator.free(result.output);

        // Record event
        if (result.ok) {
            if (self.db) |edb| {
                var msg_buf: [128]u8 = undefined;
                const msg = std.fmt.bufPrint(&msg_buf, "{s} service '{s}' ({s})", .{ req.action, req.name, req.scope }) catch "Service action";
                edb.insertEvent("service.action", node_id, msg, null);
            }
        }

        const escaped = jsonEscape(self.allocator, result.output) catch {
            r.setStatus(.internal_server_error);
            try r.sendJson("{\"error\":\"response serialization failed\"}");
            return;
        };
        defer self.allocator.free(escaped);

        const resp = std.fmt.allocPrint(self.allocator,
            \\{{"ok":{s},"output":"{s}"}}
        , .{
            if (result.ok) "true" else "false",
            escaped,
        }) catch {
            r.setStatus(.internal_server_error);
            try r.sendJson("{\"error\":\"response serialization failed\"}");
            return;
        };
        defer self.allocator.free(resp);
        try r.sendJson(resp);
    }

    // --- Process Explorer ---

    fn handleProcesses(self: *Api, r: zap.Request, path: []const u8) !void {
        const engine = self.processes orelse {
            r.setStatus(.service_unavailable);
            try r.sendJson("{\"error\":\"process explorer not available\"}");
            return;
        };

        // Path: /api/processes/<node_id>/<action>
        const after = path["/api/processes/".len..];
        const slash_pos = std.mem.indexOf(u8, after, "/");
        if (slash_pos == null) {
            r.setStatus(.not_found);
            try r.sendJson("{\"error\":\"missing sub-path\"}");
            return;
        }
        const node_id = after[0..slash_pos.?];
        const rest = after[slash_pos.?..];

        if (std.mem.eql(u8, rest, "/list")) {
            try self.handleProcessList(r, engine, node_id);
        } else if (std.mem.eql(u8, rest, "/kill")) {
            try self.handleProcessKill(r, engine, node_id);
        } else {
            r.setStatus(.not_found);
            try r.sendJson("{\"error\":\"not found\"}");
        }
    }

    fn handleProcessList(self: *Api, r: zap.Request, engine: *ProcessEngine, node_id: []const u8) !void {
        if (r.methodAsEnum() != .GET) {
            r.setStatus(.method_not_allowed);
            try r.sendJson("{\"error\":\"method not allowed\"}");
            return;
        }

        const result = engine.listProcesses(node_id);
        defer if (result.output.len > 0) self.allocator.free(result.output);

        const escaped = jsonEscape(self.allocator, result.output) catch {
            r.setStatus(.internal_server_error);
            try r.sendJson("{\"error\":\"response serialization failed\"}");
            return;
        };
        defer self.allocator.free(escaped);

        const resp = std.fmt.allocPrint(self.allocator,
            \\{{"ok":{s},"output":"{s}"}}
        , .{
            if (result.ok) "true" else "false",
            escaped,
        }) catch {
            r.setStatus(.internal_server_error);
            try r.sendJson("{\"error\":\"response serialization failed\"}");
            return;
        };
        defer self.allocator.free(resp);
        try r.sendJson(resp);
    }

    fn handleProcessKill(self: *Api, r: zap.Request, engine: *ProcessEngine, node_id: []const u8) !void {
        if (r.methodAsEnum() != .POST) {
            r.setStatus(.method_not_allowed);
            try r.sendJson("{\"error\":\"method not allowed\"}");
            return;
        }

        const body = r.body orelse {
            r.setStatus(.bad_request);
            try r.sendJson("{\"error\":\"missing request body\"}");
            return;
        };
        const parsed = std.json.parseFromSlice(ProcessKillRequest, self.allocator, body, .{ .ignore_unknown_fields = true }) catch {
            r.setStatus(.bad_request);
            try r.sendJson("{\"error\":\"invalid JSON\"}");
            return;
        };
        defer parsed.deinit();
        const req = parsed.value;

        const result = engine.killProcess(node_id, req.pid, req.signal);
        defer if (result.output.len > 0) self.allocator.free(result.output);

        const escaped = jsonEscape(self.allocator, result.output) catch {
            r.setStatus(.internal_server_error);
            try r.sendJson("{\"error\":\"response serialization failed\"}");
            return;
        };
        defer self.allocator.free(escaped);

        if (result.ok) {
            if (self.db) |edb| {
                var msg_buf: [128]u8 = undefined;
                const msg = std.fmt.bufPrint(&msg_buf, "Signal {d} sent to PID {d}", .{ req.signal, req.pid }) catch "Process signal sent";
                edb.insertEvent("process.signal", node_id, msg, null);
            }
        }

        const resp = std.fmt.allocPrint(self.allocator,
            \\{{"ok":{s},"output":"{s}"}}
        , .{
            if (result.ok) "true" else "false",
            escaped,
        }) catch {
            r.setStatus(.internal_server_error);
            try r.sendJson("{\"error\":\"response serialization failed\"}");
            return;
        };
        defer self.allocator.free(resp);
        try r.sendJson(resp);
    }

    // --- Log Streaming ---

    fn handleLogs(self: *Api, r: zap.Request, path: []const u8) !void {
        const engine = self.logs orelse {
            r.setStatus(.service_unavailable);
            try r.sendJson("{\"error\":\"log streaming not available\"}");
            return;
        };

        // Path: /api/logs/<node_id>/<action>
        const after = path["/api/logs/".len..];
        const slash_pos = std.mem.indexOf(u8, after, "/");
        if (slash_pos == null) {
            r.setStatus(.not_found);
            try r.sendJson("{\"error\":\"missing sub-path\"}");
            return;
        }
        const node_id = after[0..slash_pos.?];
        const rest = after[slash_pos.?..];

        if (std.mem.eql(u8, rest, "/start")) {
            try self.handleLogStart(r, engine, node_id);
        } else if (std.mem.eql(u8, rest, "/poll")) {
            try self.handleLogPoll(r, engine);
        } else if (std.mem.eql(u8, rest, "/stop")) {
            try self.handleLogStop(r, engine);
        } else {
            r.setStatus(.not_found);
            try r.sendJson("{\"error\":\"not found\"}");
        }
    }

    fn handleLogStart(self: *Api, r: zap.Request, engine: *LogEngine, node_id: []const u8) !void {
        if (r.methodAsEnum() != .POST) {
            r.setStatus(.method_not_allowed);
            try r.sendJson("{\"error\":\"method not allowed\"}");
            return;
        }

        const body = r.body orelse {
            r.setStatus(.bad_request);
            try r.sendJson("{\"error\":\"missing request body\"}");
            return;
        };

        const parsed = std.json.parseFromSlice(LogStartRequest, self.allocator, body, .{ .ignore_unknown_fields = true }) catch {
            r.setStatus(.bad_request);
            try r.sendJson("{\"error\":\"invalid JSON\"}");
            return;
        };
        defer parsed.deinit();
        const req = parsed.value;

        const lines: u32 = if (req.lines > 0 and req.lines <= 10000) req.lines else 100;

        const job_id = engine.startLogStream(node_id, req.source, req.service, req.path, lines) orelse {
            r.setStatus(.internal_server_error);
            try r.sendJson("{\"error\":\"failed to start log stream\"}");
            return;
        };

        const resp = std.fmt.allocPrint(self.allocator,
            \\{{"job_id":"{s}"}}
        , .{job_id}) catch {
            r.setStatus(.internal_server_error);
            try r.sendJson("{\"error\":\"response serialization failed\"}");
            return;
        };
        defer self.allocator.free(resp);
        try r.sendJson(resp);
    }

    fn handleLogPoll(self: *Api, r: zap.Request, engine: *LogEngine) !void {
        if (r.methodAsEnum() != .GET) {
            r.setStatus(.method_not_allowed);
            try r.sendJson("{\"error\":\"method not allowed\"}");
            return;
        }

        const job_id = r.getParamSlice("job") orelse {
            r.setStatus(.bad_request);
            try r.sendJson("{\"error\":\"missing job param\"}");
            return;
        };

        const offset_str = r.getParamSlice("offset") orelse "0";
        const offset = std.fmt.parseInt(usize, offset_str, 10) catch 0;

        const state = engine.pollLogStream(job_id, offset) orelse {
            r.setStatus(.not_found);
            try r.sendJson("{\"error\":\"job not found\"}");
            return;
        };

        const escaped = jsonEscape(self.allocator, state.new_output) catch {
            r.setStatus(.internal_server_error);
            try r.sendJson("{\"error\":\"response serialization failed\"}");
            return;
        };
        defer self.allocator.free(escaped);

        const resp = std.fmt.allocPrint(self.allocator,
            \\{{"output":"{s}","offset":{d},"done":{s},"ok":{s}}}
        , .{
            escaped,
            offset + state.new_output.len,
            if (state.done) "true" else "false",
            if (state.ok) "true" else "false",
        }) catch {
            r.setStatus(.internal_server_error);
            try r.sendJson("{\"error\":\"response serialization failed\"}");
            return;
        };
        defer self.allocator.free(resp);
        try r.sendJson(resp);
    }

    fn handleLogStop(self: *Api, r: zap.Request, engine: *LogEngine) !void {
        if (r.methodAsEnum() != .POST) {
            r.setStatus(.method_not_allowed);
            try r.sendJson("{\"error\":\"method not allowed\"}");
            return;
        }

        const body = r.body orelse {
            r.setStatus(.bad_request);
            try r.sendJson("{\"error\":\"missing request body\"}");
            return;
        };

        const parsed = std.json.parseFromSlice(LogStopRequest, self.allocator, body, .{ .ignore_unknown_fields = true }) catch {
            r.setStatus(.bad_request);
            try r.sendJson("{\"error\":\"invalid JSON\"}");
            return;
        };
        defer parsed.deinit();

        engine.stopLogStream(parsed.value.job_id);
        try r.sendJson("{\"ok\":true}");
    }

    // --- Drift Detection ---

    fn handleDrift(self: *Api, r: zap.Request, path: []const u8) !void {
        const engine = self.drift orelse {
            r.setStatus(.service_unavailable);
            try r.sendJson("{\"error\":\"drift detection not available\"}");
            return;
        };
        const db = self.db orelse {
            r.setStatus(.service_unavailable);
            try r.sendJson("{\"error\":\"database not available\"}");
            return;
        };

        const after = path["/api/drift/".len..];

        if (std.mem.eql(u8, after, "snapshot") and r.methodAsEnum() == .POST) {
            try self.handleDriftSnapshot(r, engine, db);
        } else if (std.mem.eql(u8, after, "snapshots") and r.methodAsEnum() == .GET) {
            try self.handleDriftListSnapshots(r, db);
        } else if (std.mem.startsWith(u8, after, "snapshot/") and r.methodAsEnum() == .GET) {
            const id_str = after["snapshot/".len..];
            const id = std.fmt.parseInt(i64, id_str, 10) catch {
                r.setStatus(.bad_request);
                try r.sendJson("{\"error\":\"invalid snapshot id\"}");
                return;
            };
            try self.handleDriftGetSnapshot(r, db, id);
        } else if (std.mem.startsWith(u8, after, "snapshot/") and r.methodAsEnum() == .DELETE) {
            const id_str = after["snapshot/".len..];
            const id = std.fmt.parseInt(i64, id_str, 10) catch {
                r.setStatus(.bad_request);
                try r.sendJson("{\"error\":\"invalid snapshot id\"}");
                return;
            };
            try self.handleDriftDeleteSnapshot(r, db, id);
        } else if (std.mem.eql(u8, after, "baseline") and r.methodAsEnum() == .POST) {
            try self.handleDriftSetBaseline(r, db);
        } else if (std.mem.eql(u8, after, "diff") and r.methodAsEnum() == .POST) {
            try self.handleDriftDiff(r, db);
        } else {
            r.setStatus(.not_found);
            try r.sendJson("{\"error\":\"not found\"}");
        }
    }

    fn handleDriftSnapshot(self: *Api, r: zap.Request, engine: *DriftEngine, db: *Db) !void {
        const body = r.body orelse {
            r.setStatus(.bad_request);
            try r.sendJson("{\"error\":\"missing body\"}");
            return;
        };

        const parsed = std.json.parseFromSlice(DriftSnapshotRequest, self.allocator, body, .{ .ignore_unknown_fields = true, .allocate = .alloc_always }) catch {
            r.setStatus(.bad_request);
            try r.sendJson("{\"error\":\"invalid JSON\"}");
            return;
        };
        defer parsed.deinit();
        const req = parsed.value;

        if (req.node_ids.len == 0) {
            r.setStatus(.bad_request);
            try r.sendJson("{\"error\":\"node_ids required\"}");
            return;
        }

        // Build node name lookup
        var name_lookup = std.StringHashMapUnmanaged([]const u8){};
        defer {
            var it = name_lookup.iterator();
            while (it.next()) |entry| {
                self.allocator.free(entry.key_ptr.*);
                self.allocator.free(entry.value_ptr.*);
            }
            name_lookup.deinit(self.allocator);
        }
        if (db.listNodes(self.allocator)) |nodes| {
            defer {
                for (nodes) |n| n.deinit(self.allocator);
                self.allocator.free(nodes);
            }
            for (nodes) |n| {
                const k = self.allocator.dupe(u8, n.id) catch continue;
                const v = self.allocator.dupe(u8, n.name) catch {
                    self.allocator.free(k);
                    continue;
                };
                name_lookup.put(self.allocator, k, v) catch {
                    self.allocator.free(k);
                    self.allocator.free(v);
                };
            }
        } else |_| {}

        // Take snapshots
        var buf: std.ArrayListUnmanaged(u8) = .{};
        const w = buf.writer(self.allocator);
        w.writeAll("{\"snapshots\":[") catch {
            r.setStatus(.internal_server_error);
            try r.sendJson("{\"error\":\"allocation failed\"}");
            return;
        };

        var first = true;
        for (req.node_ids) |node_id| {
            const result = engine.takeSnapshot(node_id);
            defer result.deinit(self.allocator);

            if (!result.ok) {
                // Include error in response
                if (!first) w.writeByte(',') catch {};
                first = false;
                const err_msg = result.err_msg orelse "unknown error";
                const escaped_err = jsonEscape(self.allocator, err_msg) catch continue;
                defer self.allocator.free(escaped_err);
                w.print("{{\"node_id\":\"{s}\",\"error\":\"{s}\"}}", .{ node_id, escaped_err }) catch {};
                continue;
            }

            // Store in DB
            const snap_id = db.insertDriftSnapshot(
                node_id,
                result.packages_json,
                result.services_json,
                result.ports_json,
                result.users_json,
            ) catch {
                if (!first) w.writeByte(',') catch {};
                first = false;
                w.print("{{\"node_id\":\"{s}\",\"error\":\"failed to store snapshot\"}}", .{node_id}) catch {};
                continue;
            };

            if (!first) w.writeByte(',') catch {};
            first = false;

            const node_name = name_lookup.get(node_id) orelse node_id;
            w.print("{{\"id\":{d},\"node_id\":\"{s}\",\"node_name\":\"{s}\",\"is_baseline\":false,\"created_at\":{d}}}", .{
                snap_id,
                node_id,
                node_name,
                std.time.timestamp(),
            }) catch {};
        }

        w.writeAll("]}") catch {};

        if (self.db) |edb| {
            var msg_buf: [128]u8 = undefined;
            const msg = std.fmt.bufPrint(&msg_buf, "Drift snapshot taken for {d} node(s)", .{req.node_ids.len}) catch "Drift snapshot taken";
            edb.insertEvent("drift.snapshot", null, msg, null);
        }

        const resp = buf.toOwnedSlice(self.allocator) catch {
            r.setStatus(.internal_server_error);
            try r.sendJson("{\"error\":\"allocation failed\"}");
            return;
        };
        defer self.allocator.free(resp);
        try r.sendJson(resp);
    }

    fn handleDriftListSnapshots(self: *Api, r: zap.Request, db: *Db) !void {
        const node_id = r.getParamSlice("node_id") orelse {
            r.setStatus(.bad_request);
            try r.sendJson("{\"error\":\"node_id required\"}");
            return;
        };

        const snapshots = db.listDriftSnapshots(self.allocator, node_id, 50) catch {
            r.setStatus(.internal_server_error);
            try r.sendJson("{\"error\":\"database error\"}");
            return;
        };
        defer {
            for (snapshots) |s| s.deinit(self.allocator);
            self.allocator.free(snapshots);
        }

        var buf: std.ArrayListUnmanaged(u8) = .{};
        const w = buf.writer(self.allocator);
        w.writeAll("{\"snapshots\":[") catch {
            r.setStatus(.internal_server_error);
            try r.sendJson("{\"error\":\"allocation failed\"}");
            return;
        };

        for (snapshots, 0..) |s, i| {
            if (i > 0) w.writeByte(',') catch {};
            w.print("{{\"id\":{d},\"node_id\":\"{s}\",\"is_baseline\":{s},\"created_at\":{d}}}", .{
                s.id,
                s.node_id,
                if (s.is_baseline) "true" else "false",
                s.created_at,
            }) catch {};
        }

        w.writeAll("]}") catch {};
        const resp = buf.toOwnedSlice(self.allocator) catch {
            r.setStatus(.internal_server_error);
            try r.sendJson("{\"error\":\"allocation failed\"}");
            return;
        };
        defer self.allocator.free(resp);
        try r.sendJson(resp);
    }

    fn handleDriftGetSnapshot(self: *Api, r: zap.Request, db: *Db, id: i64) !void {
        const snap = db.getDriftSnapshot(self.allocator, id) catch {
            r.setStatus(.internal_server_error);
            try r.sendJson("{\"error\":\"database error\"}");
            return;
        } orelse {
            r.setStatus(.not_found);
            try r.sendJson("{\"error\":\"snapshot not found\"}");
            return;
        };
        defer snap.deinit(self.allocator);

        const resp = std.fmt.allocPrint(self.allocator,
            \\{{"id":{d},"node_id":"{s}","is_baseline":{s},"created_at":{d},"packages":{s},"services":{s},"ports":{s},"users":{s}}}
        , .{
            snap.id,
            snap.node_id,
            if (snap.is_baseline) "true" else "false",
            snap.created_at,
            snap.packages orelse "[]",
            snap.services orelse "[]",
            snap.ports orelse "[]",
            snap.users_data orelse "[]",
        }) catch {
            r.setStatus(.internal_server_error);
            try r.sendJson("{\"error\":\"allocation failed\"}");
            return;
        };
        defer self.allocator.free(resp);
        try r.sendJson(resp);
    }

    fn handleDriftDeleteSnapshot(self: *Api, r: zap.Request, db: *Db, id: i64) !void {
        _ = self;
        db.deleteDriftSnapshot(id) catch {
            r.setStatus(.internal_server_error);
            try r.sendJson("{\"error\":\"database error\"}");
            return;
        };
        try r.sendJson("{\"ok\":true}");
    }

    fn handleDriftSetBaseline(self: *Api, r: zap.Request, db: *Db) !void {
        const body = r.body orelse {
            r.setStatus(.bad_request);
            try r.sendJson("{\"error\":\"missing body\"}");
            return;
        };

        const parsed = std.json.parseFromSlice(DriftBaselineRequest, self.allocator, body, .{ .ignore_unknown_fields = true, .allocate = .alloc_always }) catch {
            r.setStatus(.bad_request);
            try r.sendJson("{\"error\":\"invalid JSON\"}");
            return;
        };
        defer parsed.deinit();

        db.setDriftBaseline(parsed.value.snapshot_id) catch {
            r.setStatus(.internal_server_error);
            try r.sendJson("{\"error\":\"database error\"}");
            return;
        };
        try r.sendJson("{\"ok\":true}");
    }

    fn handleDriftDiff(self: *Api, r: zap.Request, db: *Db) !void {
        const body = r.body orelse {
            r.setStatus(.bad_request);
            try r.sendJson("{\"error\":\"missing body\"}");
            return;
        };

        const parsed = std.json.parseFromSlice(DriftDiffRequest, self.allocator, body, .{ .ignore_unknown_fields = true, .allocate = .alloc_always }) catch {
            r.setStatus(.bad_request);
            try r.sendJson("{\"error\":\"invalid JSON\"}");
            return;
        };
        defer parsed.deinit();
        const req = parsed.value;

        // Get snapshot A
        const snap_a = db.getDriftSnapshot(self.allocator, req.snapshot_a) catch {
            r.setStatus(.internal_server_error);
            try r.sendJson("{\"error\":\"database error\"}");
            return;
        } orelse {
            r.setStatus(.not_found);
            try r.sendJson("{\"error\":\"snapshot_a not found\"}");
            return;
        };
        defer snap_a.deinit(self.allocator);

        // Get snapshot B (either explicit ID or baseline for snap_a's node)
        var snap_b_storage: @import("db.zig").DriftSnapshot = undefined;
        var snap_b_allocated = false;
        defer if (snap_b_allocated) snap_b_storage.deinit(self.allocator);

        if (req.snapshot_b) |b_id| {
            snap_b_storage = db.getDriftSnapshot(self.allocator, b_id) catch {
                r.setStatus(.internal_server_error);
                try r.sendJson("{\"error\":\"database error\"}");
                return;
            } orelse {
                r.setStatus(.not_found);
                try r.sendJson("{\"error\":\"snapshot_b not found\"}");
                return;
            };
            snap_b_allocated = true;
        } else if (req.baseline orelse false) {
            snap_b_storage = db.getDriftBaseline(self.allocator, snap_a.node_id) catch {
                r.setStatus(.internal_server_error);
                try r.sendJson("{\"error\":\"database error\"}");
                return;
            } orelse {
                r.setStatus(.not_found);
                try r.sendJson("{\"error\":\"no baseline set for this node\"}");
                return;
            };
            snap_b_allocated = true;
        } else {
            r.setStatus(.bad_request);
            try r.sendJson("{\"error\":\"provide snapshot_b or baseline:true\"}");
            return;
        }

        // Compute diffs for each category
        const pkg_diff = computeDiff(self.allocator, snap_a.packages orelse "[]", snap_b_storage.packages orelse "[]", "name", "version");
        defer self.allocator.free(pkg_diff);
        const svc_diff = computeDiff(self.allocator, snap_a.services orelse "[]", snap_b_storage.services orelse "[]", "name", "state");
        defer self.allocator.free(svc_diff);
        const port_diff = computeDiff(self.allocator, snap_a.ports orelse "[]", snap_b_storage.ports orelse "[]", "port", "address");
        defer self.allocator.free(port_diff);
        const user_diff = computeDiff(self.allocator, snap_a.users_data orelse "[]", snap_b_storage.users_data orelse "[]", "name", "shell");
        defer self.allocator.free(user_diff);

        const resp = std.fmt.allocPrint(self.allocator,
            \\{{"snapshot_a":{d},"snapshot_b":{d},"node_a_id":"{s}","node_b_id":"{s}","packages":{s},"services":{s},"ports":{s},"users":{s}}}
        , .{
            snap_a.id,
            snap_b_storage.id,
            snap_a.node_id,
            snap_b_storage.node_id,
            pkg_diff,
            svc_diff,
            port_diff,
            user_diff,
        }) catch {
            r.setStatus(.internal_server_error);
            try r.sendJson("{\"error\":\"allocation failed\"}");
            return;
        };
        defer self.allocator.free(resp);
        try r.sendJson(resp);
    }

    // --- Security Posture ---

    fn handleSecurity(self: *Api, r: zap.Request, path: []const u8) !void {
        const engine = self.security orelse {
            r.setStatus(.service_unavailable);
            try r.sendJson("{\"error\":\"security engine not available\"}");
            return;
        };

        if (r.methodAsEnum() != .GET) {
            r.setStatus(.method_not_allowed);
            try r.sendJson("{\"error\":\"method not allowed\"}");
            return;
        }

        // Extract node_id from /api/security/:node_id/scan
        const prefix = "/api/security/";
        if (path.len <= prefix.len) {
            r.setStatus(.bad_request);
            try r.sendJson("{\"error\":\"missing node_id\"}");
            return;
        }
        const rest = path[prefix.len..];
        const slash_idx = std.mem.indexOfScalar(u8, rest, '/') orelse {
            r.setStatus(.bad_request);
            try r.sendJson("{\"error\":\"invalid path\"}");
            return;
        };
        const node_id = rest[0..slash_idx];
        const action = rest[slash_idx + 1 ..];

        if (!std.mem.eql(u8, action, "scan")) {
            r.setStatus(.not_found);
            try r.sendJson("{\"error\":\"unknown action\"}");
            return;
        }

        const result = engine.scanNode(node_id);
        defer result.deinit(self.allocator);

        if (!result.ok) {
            r.setStatus(.internal_server_error);
            const err_resp = std.fmt.allocPrint(self.allocator, "{{\"ok\":false,\"error\":{s}}}", .{
                if (result.err_msg) |m| m else "\"scan failed\"",
            }) catch {
                try r.sendJson("{\"ok\":false,\"error\":\"scan failed\"}");
                return;
            };
            defer self.allocator.free(err_resp);
            try r.sendJson(err_resp);
            return;
        }

        if (self.db) |edb| {
            var msg_buf: [128]u8 = undefined;
            const msg = std.fmt.bufPrint(&msg_buf, "Security scan completed (score: {d})", .{result.score}) catch "Security scan completed";
            edb.insertEvent("security.scan", node_id, msg, null);
        }

        const resp = std.fmt.allocPrint(self.allocator,
            \\{{"ok":true,"score":{d},"upgradable":{s},"ssh_config":{s},"ports":{s},"firewall":{s},"autoupdate":{s}}}
        , .{
            result.score,
            result.upgradable_json orelse "[]",
            result.ssh_config_json orelse "[]",
            result.ports_json orelse "[]",
            result.firewall_json orelse "{}",
            result.autoupdate_json orelse "{}",
        }) catch {
            r.setStatus(.internal_server_error);
            try r.sendJson("{\"error\":\"allocation failed\"}");
            return;
        };
        defer self.allocator.free(resp);
        try r.sendJson(resp);
    }

    // --- Container Management (Suffragette City) ---

    fn handleContainers(self: *Api, r: zap.Request, path: []const u8) !void {
        const engine = self.containers orelse {
            r.setStatus(.service_unavailable);
            try r.sendJson("{\"error\":\"container engine not available\"}");
            return;
        };

        const after = path["/api/containers/".len..];
        const slash_pos = std.mem.indexOf(u8, after, "/");
        if (slash_pos == null) {
            r.setStatus(.not_found);
            try r.sendJson("{\"error\":\"missing sub-path\"}");
            return;
        }
        const node_id = after[0..slash_pos.?];
        const rest = after[slash_pos.?..];

        if (std.mem.eql(u8, rest, "/list")) {
            try self.handleContainerList(r, engine, node_id);
        } else if (std.mem.eql(u8, rest, "/inspect")) {
            try self.handleContainerInspect(r, engine, node_id);
        } else if (std.mem.eql(u8, rest, "/action")) {
            try self.handleContainerAction(r, engine, node_id);
        } else if (std.mem.eql(u8, rest, "/logs")) {
            try self.handleContainerLogs(r, engine, node_id);
        } else {
            r.setStatus(.not_found);
            try r.sendJson("{\"error\":\"not found\"}");
        }
    }

    fn handleContainerList(self: *Api, r: zap.Request, engine: *ContainerEngine, node_id: []const u8) !void {
        if (r.methodAsEnum() != .GET) {
            r.setStatus(.method_not_allowed);
            try r.sendJson("{\"error\":\"method not allowed\"}");
            return;
        }

        const result = engine.listContainers(node_id);
        defer if (result.output.len > 0) self.allocator.free(result.output);

        const escaped = jsonEscape(self.allocator, result.output) catch {
            r.setStatus(.internal_server_error);
            try r.sendJson("{\"error\":\"response serialization failed\"}");
            return;
        };
        defer self.allocator.free(escaped);

        const resp = std.fmt.allocPrint(self.allocator,
            \\{{"ok":{s},"output":"{s}"}}
        , .{
            if (result.ok) "true" else "false",
            escaped,
        }) catch {
            r.setStatus(.internal_server_error);
            try r.sendJson("{\"error\":\"response serialization failed\"}");
            return;
        };
        defer self.allocator.free(resp);
        try r.sendJson(resp);
    }

    fn handleContainerInspect(self: *Api, r: zap.Request, engine: *ContainerEngine, node_id: []const u8) !void {
        if (r.methodAsEnum() != .GET) {
            r.setStatus(.method_not_allowed);
            try r.sendJson("{\"error\":\"method not allowed\"}");
            return;
        }

        const container_id = r.getParamSlice("id") orelse {
            r.setStatus(.bad_request);
            try r.sendJson("{\"error\":\"missing id parameter\"}");
            return;
        };

        const result = engine.containerInspect(node_id, container_id);
        defer if (result.output.len > 0) self.allocator.free(result.output);

        const escaped = jsonEscape(self.allocator, result.output) catch {
            r.setStatus(.internal_server_error);
            try r.sendJson("{\"error\":\"response serialization failed\"}");
            return;
        };
        defer self.allocator.free(escaped);

        const resp = std.fmt.allocPrint(self.allocator,
            \\{{"ok":{s},"output":"{s}"}}
        , .{
            if (result.ok) "true" else "false",
            escaped,
        }) catch {
            r.setStatus(.internal_server_error);
            try r.sendJson("{\"error\":\"response serialization failed\"}");
            return;
        };
        defer self.allocator.free(resp);
        try r.sendJson(resp);
    }

    fn handleContainerAction(self: *Api, r: zap.Request, engine: *ContainerEngine, node_id: []const u8) !void {
        if (r.methodAsEnum() != .POST) {
            r.setStatus(.method_not_allowed);
            try r.sendJson("{\"error\":\"method not allowed\"}");
            return;
        }

        const body = r.body orelse {
            r.setStatus(.bad_request);
            try r.sendJson("{\"error\":\"missing request body\"}");
            return;
        };
        const parsed = std.json.parseFromSlice(ContainerActionRequest, self.allocator, body, .{ .ignore_unknown_fields = true }) catch {
            r.setStatus(.bad_request);
            try r.sendJson("{\"error\":\"invalid JSON\"}");
            return;
        };
        defer parsed.deinit();
        const req = parsed.value;

        const result = engine.containerAction(node_id, req.id, req.action);
        defer if (result.output.len > 0) self.allocator.free(result.output);

        if (result.ok) {
            if (self.db) |edb| {
                var msg_buf: [128]u8 = undefined;
                const msg = std.fmt.bufPrint(&msg_buf, "{s} container '{s}'", .{ req.action, req.id }) catch "Container action";
                edb.insertEvent("container.action", node_id, msg, null);
            }
        }

        const escaped = jsonEscape(self.allocator, result.output) catch {
            r.setStatus(.internal_server_error);
            try r.sendJson("{\"error\":\"response serialization failed\"}");
            return;
        };
        defer self.allocator.free(escaped);

        const resp = std.fmt.allocPrint(self.allocator,
            \\{{"ok":{s},"output":"{s}"}}
        , .{
            if (result.ok) "true" else "false",
            escaped,
        }) catch {
            r.setStatus(.internal_server_error);
            try r.sendJson("{\"error\":\"response serialization failed\"}");
            return;
        };
        defer self.allocator.free(resp);
        try r.sendJson(resp);
    }

    fn handleContainerLogs(self: *Api, r: zap.Request, engine: *ContainerEngine, node_id: []const u8) !void {
        if (r.methodAsEnum() != .GET) {
            r.setStatus(.method_not_allowed);
            try r.sendJson("{\"error\":\"method not allowed\"}");
            return;
        }

        const container_id = r.getParamSlice("id") orelse {
            r.setStatus(.bad_request);
            try r.sendJson("{\"error\":\"missing id parameter\"}");
            return;
        };

        const tail_str = r.getParamSlice("tail") orelse "100";
        const tail = std.fmt.parseInt(u32, tail_str, 10) catch 100;

        const result = engine.containerLogs(node_id, container_id, tail);
        defer if (result.output.len > 0) self.allocator.free(result.output);

        const escaped = jsonEscape(self.allocator, result.output) catch {
            r.setStatus(.internal_server_error);
            try r.sendJson("{\"error\":\"response serialization failed\"}");
            return;
        };
        defer self.allocator.free(escaped);

        const resp = std.fmt.allocPrint(self.allocator,
            \\{{"ok":{s},"output":"{s}"}}
        , .{
            if (result.ok) "true" else "false",
            escaped,
        }) catch {
            r.setStatus(.internal_server_error);
            try r.sendJson("{\"error\":\"response serialization failed\"}");
            return;
        };
        defer self.allocator.free(resp);
        try r.sendJson(resp);
    }

    // --- Scheduled Automation (Station to Station) ---

    fn handleSchedules(self: *Api, r: zap.Request, path: []const u8) !void {
        const sched = self.scheduler orelse {
            r.setStatus(.service_unavailable);
            try r.sendJson("{\"error\":\"scheduler not available\"}");
            return;
        };

        const method = r.methodAsEnum();

        // GET/POST /api/schedules (no trailing path)
        if (std.mem.eql(u8, path, "/api/schedules") or std.mem.eql(u8, path, "/api/schedules/")) {
            if (method == .GET) {
                try self.handleScheduleList(r);
            } else if (method == .POST) {
                try self.handleScheduleCreate(r);
            } else {
                r.setStatus(.method_not_allowed);
                try r.sendJson("{\"error\":\"method not allowed\"}");
            }
            return;
        }

        // Routes with ID: /api/schedules/{id}[/action]
        const after = path["/api/schedules/".len..];
        // Parse numeric ID
        const slash_pos = std.mem.indexOf(u8, after, "/");
        const id_str = if (slash_pos) |pos| after[0..pos] else after;
        const id = std.fmt.parseInt(i64, id_str, 10) catch {
            r.setStatus(.bad_request);
            try r.sendJson("{\"error\":\"invalid schedule ID\"}");
            return;
        };
        const sub = if (slash_pos) |pos| after[pos + 1 ..] else "";

        if (sub.len == 0) {
            // GET/PUT/DELETE /api/schedules/{id}
            if (method == .GET) {
                try self.handleScheduleGet(r, id);
            } else if (method == .PUT) {
                try self.handleScheduleUpdate(r, id);
            } else if (method == .DELETE) {
                try self.handleScheduleDelete(r, id);
            } else {
                r.setStatus(.method_not_allowed);
                try r.sendJson("{\"error\":\"method not allowed\"}");
            }
        } else if (std.mem.eql(u8, sub, "toggle")) {
            try self.handleScheduleToggle(r, id);
        } else if (std.mem.eql(u8, sub, "run")) {
            try self.handleScheduleRun(r, id, sched);
        } else if (std.mem.eql(u8, sub, "runs")) {
            try self.handleScheduleRuns(r, id);
        } else {
            r.setStatus(.not_found);
            try r.sendJson("{\"error\":\"unknown schedule action\"}");
        }
    }

    fn handleScheduleList(self: *Api, r: zap.Request) !void {
        const db = self.db orelse {
            r.setStatus(.internal_server_error);
            try r.sendJson("{\"error\":\"no database\"}");
            return;
        };
        const schedules = db.listSchedules(self.allocator) catch {
            r.setStatus(.internal_server_error);
            try r.sendJson("{\"error\":\"failed to list schedules\"}");
            return;
        };
        defer {
            for (schedules) |s| s.deinit(self.allocator);
            self.allocator.free(schedules);
        }

        var buf: std.ArrayListUnmanaged(u8) = .{};
        const w = buf.writer(self.allocator);
        try w.writeByte('[');
        for (schedules, 0..) |s, i| {
            if (i > 0) try w.writeByte(',');
            try self.writeScheduleJson(w, s);
        }
        try w.writeByte(']');
        const json = try buf.toOwnedSlice(self.allocator);
        defer self.allocator.free(json);
        try r.sendJson(json);
    }

    fn handleScheduleGet(self: *Api, r: zap.Request, id: i64) !void {
        const db = self.db orelse {
            r.setStatus(.internal_server_error);
            return;
        };
        const schedule = db.getSchedule(self.allocator, id) catch {
            r.setStatus(.internal_server_error);
            try r.sendJson("{\"error\":\"database error\"}");
            return;
        };
        if (schedule == null) {
            r.setStatus(.not_found);
            try r.sendJson("{\"error\":\"schedule not found\"}");
            return;
        }
        defer schedule.?.deinit(self.allocator);

        var buf: std.ArrayListUnmanaged(u8) = .{};
        const w = buf.writer(self.allocator);
        try self.writeScheduleJson(w, schedule.?);
        const json = try buf.toOwnedSlice(self.allocator);
        defer self.allocator.free(json);
        try r.sendJson(json);
    }

    fn handleScheduleCreate(self: *Api, r: zap.Request) !void {
        const db = self.db orelse {
            r.setStatus(.internal_server_error);
            return;
        };
        const body = r.body orelse {
            r.setStatus(.bad_request);
            try r.sendJson("{\"error\":\"missing body\"}");
            return;
        };
        const parsed = std.json.parseFromSlice(ScheduleCreateRequest, self.allocator, body, .{
            .ignore_unknown_fields = true,
            .allocate = .alloc_always,
        }) catch {
            r.setStatus(.bad_request);
            try r.sendJson("{\"error\":\"invalid JSON\"}");
            return;
        };
        defer parsed.deinit();
        const req = parsed.value;

        // Validate job type
        if (!isValidJobType(req.job_type)) {
            r.setStatus(.bad_request);
            try r.sendJson("{\"error\":\"invalid job_type\"}");
            return;
        }
        // Validate target type
        if (!isValidTargetType(req.target_type)) {
            r.setStatus(.bad_request);
            try r.sendJson("{\"error\":\"invalid target_type\"}");
            return;
        }

        const id = db.insertSchedule(
            req.name,
            req.job_type,
            req.config,
            req.target_type,
            req.target_value,
            req.cron_minute,
            req.cron_hour,
            req.cron_dom,
            req.cron_month,
            req.cron_dow,
            req.enabled,
        ) catch {
            r.setStatus(.internal_server_error);
            try r.sendJson("{\"error\":\"failed to create schedule\"}");
            return;
        };

        // Record event
        if (self.db) |edb| {
            var msg_buf: [256]u8 = undefined;
            const msg = std.fmt.bufPrint(&msg_buf, "Created schedule '{s}' ({s})", .{
                if (req.name.len > 60) req.name[0..60] else req.name,
                req.job_type,
            }) catch "Schedule created";
            edb.insertEvent("schedule.created", null, msg, null);
        }

        const resp = std.fmt.allocPrint(self.allocator, "{{\"id\":{d}}}", .{id}) catch {
            r.setStatus(.internal_server_error);
            return;
        };
        defer self.allocator.free(resp);
        r.setStatus(.created);
        try r.sendJson(resp);
    }

    fn handleScheduleUpdate(self: *Api, r: zap.Request, id: i64) !void {
        const db = self.db orelse {
            r.setStatus(.internal_server_error);
            return;
        };
        const body = r.body orelse {
            r.setStatus(.bad_request);
            try r.sendJson("{\"error\":\"missing body\"}");
            return;
        };
        const parsed = std.json.parseFromSlice(ScheduleCreateRequest, self.allocator, body, .{
            .ignore_unknown_fields = true,
            .allocate = .alloc_always,
        }) catch {
            r.setStatus(.bad_request);
            try r.sendJson("{\"error\":\"invalid JSON\"}");
            return;
        };
        defer parsed.deinit();
        const req = parsed.value;

        db.updateSchedule(id, req.name, req.job_type, req.config, req.target_type, req.target_value, req.cron_minute, req.cron_hour, req.cron_dom, req.cron_month, req.cron_dow) catch {
            r.setStatus(.internal_server_error);
            try r.sendJson("{\"error\":\"failed to update schedule\"}");
            return;
        };

        try r.sendJson("{\"ok\":true}");
    }

    fn handleScheduleDelete(self: *Api, r: zap.Request, id: i64) !void {
        const db = self.db orelse {
            r.setStatus(.internal_server_error);
            return;
        };
        db.deleteSchedule(id) catch {
            r.setStatus(.internal_server_error);
            try r.sendJson("{\"error\":\"failed to delete schedule\"}");
            return;
        };
        try r.sendJson("{\"ok\":true}");
    }

    fn handleScheduleToggle(self: *Api, r: zap.Request, id: i64) !void {
        const db = self.db orelse {
            r.setStatus(.internal_server_error);
            return;
        };
        // Get current state
        const schedule = db.getSchedule(self.allocator, id) catch {
            r.setStatus(.internal_server_error);
            return;
        };
        if (schedule == null) {
            r.setStatus(.not_found);
            try r.sendJson("{\"error\":\"schedule not found\"}");
            return;
        }
        defer schedule.?.deinit(self.allocator);

        db.setScheduleEnabled(id, !schedule.?.enabled) catch {
            r.setStatus(.internal_server_error);
            try r.sendJson("{\"error\":\"failed to toggle schedule\"}");
            return;
        };

        const resp = std.fmt.allocPrint(self.allocator, "{{\"enabled\":{s}}}", .{
            if (!schedule.?.enabled) "true" else "false",
        }) catch {
            r.setStatus(.internal_server_error);
            return;
        };
        defer self.allocator.free(resp);
        try r.sendJson(resp);
    }

    fn handleScheduleRun(self: *Api, r: zap.Request, id: i64, sched: *SchedulerEngine) !void {
        const db = self.db orelse {
            r.setStatus(.internal_server_error);
            return;
        };
        const schedule = db.getSchedule(self.allocator, id) catch {
            r.setStatus(.internal_server_error);
            return;
        };
        if (schedule == null) {
            r.setStatus(.not_found);
            try r.sendJson("{\"error\":\"schedule not found\"}");
            return;
        }
        defer schedule.?.deinit(self.allocator);

        // Fire execution in a detached thread so the API returns immediately
        const s_copy = self.allocator.dupe(u8, std.mem.asBytes(&schedule.?)) catch {
            r.setStatus(.internal_server_error);
            return;
        };
        _ = s_copy;

        // Execute synchronously for now (simple approach)
        sched.executeSchedule(schedule.?, std.time.timestamp());

        try r.sendJson("{\"ok\":true}");
    }

    fn handleScheduleRuns(self: *Api, r: zap.Request, id: i64) !void {
        const db = self.db orelse {
            r.setStatus(.internal_server_error);
            return;
        };
        r.parseQuery();
        const limit_str = r.getParamSlice("limit");
        const limit = if (limit_str) |s| std.fmt.parseInt(i64, s, 10) catch @as(i64, 20) else @as(i64, 20);

        const runs = db.listScheduleRuns(self.allocator, id, limit) catch {
            r.setStatus(.internal_server_error);
            try r.sendJson("{\"error\":\"failed to list runs\"}");
            return;
        };
        defer {
            for (runs) |run| run.deinit(self.allocator);
            self.allocator.free(runs);
        }

        var buf: std.ArrayListUnmanaged(u8) = .{};
        const w = buf.writer(self.allocator);
        try w.writeByte('[');
        for (runs, 0..) |run, i| {
            if (i > 0) try w.writeByte(',');
            const out_escaped = if (run.output) |o| jsonEscape(self.allocator, o) catch null else null;
            defer if (out_escaped) |e| self.allocator.free(e);

            try w.print("{{\"id\":{d},\"schedule_id\":{d},\"started_at\":{d},", .{ run.id, run.schedule_id, run.started_at });
            if (run.finished_at) |f| {
                try w.print("\"finished_at\":{d},", .{f});
            } else {
                try w.writeAll("\"finished_at\":null,");
            }
            try w.print("\"status\":\"{s}\",", .{run.status});
            if (out_escaped) |o| {
                try w.print("\"output\":\"{s}\"}}", .{o});
            } else {
                try w.writeAll("\"output\":null}");
            }
        }
        try w.writeByte(']');
        const json = try buf.toOwnedSlice(self.allocator);
        defer self.allocator.free(json);
        try r.sendJson(json);
    }

    fn writeScheduleJson(self: *Api, w: anytype, s: @import("db.zig").ScheduleRecord) !void {
        const name_escaped = jsonEscape(self.allocator, s.name) catch return;
        defer self.allocator.free(name_escaped);
        const config_escaped = jsonEscape(self.allocator, s.config) catch return;
        defer self.allocator.free(config_escaped);

        try w.print("{{\"id\":{d},\"name\":\"{s}\",\"job_type\":\"{s}\",\"config\":\"{s}\",", .{
            s.id, name_escaped, s.job_type, config_escaped,
        });
        try w.print("\"target_type\":\"{s}\",", .{s.target_type});
        if (s.target_value) |tv| {
            const tv_esc = jsonEscape(self.allocator, tv) catch return;
            defer self.allocator.free(tv_esc);
            try w.print("\"target_value\":\"{s}\",", .{tv_esc});
        } else {
            try w.writeAll("\"target_value\":null,");
        }
        try w.print("\"cron_minute\":\"{s}\",\"cron_hour\":\"{s}\",\"cron_dom\":\"{s}\",\"cron_month\":\"{s}\",\"cron_dow\":\"{s}\",", .{
            s.cron_minute, s.cron_hour, s.cron_dom, s.cron_month, s.cron_dow,
        });
        try w.print("\"enabled\":{s},", .{if (s.enabled) "true" else "false"});
        if (s.last_run) |lr| {
            try w.print("\"last_run\":{d},", .{lr});
        } else {
            try w.writeAll("\"last_run\":null,");
        }
        if (s.last_status) |ls| {
            try w.print("\"last_status\":\"{s}\",", .{ls});
        } else {
            try w.writeAll("\"last_status\":null,");
        }
        try w.print("\"created_at\":{d},\"updated_at\":{d}}}", .{ s.created_at, s.updated_at });
    }
};

fn isValidJobType(t: []const u8) bool {
    const valid = [_][]const u8{ "command", "ansible", "package_update" };
    for (valid) |v| {
        if (std.mem.eql(u8, t, v)) return true;
    }
    return false;
}

fn isValidTargetType(t: []const u8) bool {
    const valid = [_][]const u8{ "all", "nodes", "tags" };
    for (valid) |v| {
        if (std.mem.eql(u8, t, v)) return true;
    }
    return false;
}

const DriftSnapshotRequest = struct {
    node_ids: []const []const u8,
};

const DriftBaselineRequest = struct {
    snapshot_id: i64,
};

const DriftDiffRequest = struct {
    snapshot_a: i64,
    snapshot_b: ?i64 = null,
    baseline: ?bool = null,
};

/// Simple JSON array diff: compare two JSON arrays of objects by key field,
/// report added/removed/changed entries based on a value field.
fn computeDiff(allocator: std.mem.Allocator, a_json: []const u8, b_json: []const u8, key_field: []const u8, value_field: []const u8) []const u8 {
    return computeDiffInner(allocator, a_json, b_json, key_field, value_field) catch
        allocator.dupe(u8, "{\"added\":[],\"removed\":[],\"changed\":[]}") catch "";
}

fn computeDiffInner(allocator: std.mem.Allocator, a_json: []const u8, b_json: []const u8, key_field: []const u8, value_field: []const u8) ![]const u8 {
    // Parse both arrays using std.json scanner approach
    // We'll use a simple approach: extract key-value pairs from JSON arrays
    var a_map = std.StringHashMapUnmanaged([]const u8){};
    defer {
        var it = a_map.iterator();
        while (it.next()) |entry| {
            allocator.free(entry.key_ptr.*);
            allocator.free(entry.value_ptr.*);
        }
        a_map.deinit(allocator);
    }
    var b_map = std.StringHashMapUnmanaged([]const u8){};
    defer {
        var it = b_map.iterator();
        while (it.next()) |entry| {
            allocator.free(entry.key_ptr.*);
            allocator.free(entry.value_ptr.*);
        }
        b_map.deinit(allocator);
    }

    try extractKeyValues(allocator, a_json, key_field, value_field, &a_map);
    try extractKeyValues(allocator, b_json, key_field, value_field, &b_map);

    var buf: std.ArrayListUnmanaged(u8) = .{};
    const w = buf.writer(allocator);

    try w.writeAll("{\"added\":[");
    // Added: in B but not in A
    var first = true;
    {
        var it = b_map.iterator();
        while (it.next()) |entry| {
            if (!a_map.contains(entry.key_ptr.*)) {
                if (!first) try w.writeByte(',');
                first = false;
                try w.writeAll("{\"key\":");
                writeJsonStr(w, entry.key_ptr.*);
                try w.writeAll(",\"value\":");
                writeJsonStr(w, entry.value_ptr.*);
                try w.writeByte('}');
            }
        }
    }

    try w.writeAll("],\"removed\":[");
    // Removed: in A but not in B
    first = true;
    {
        var it = a_map.iterator();
        while (it.next()) |entry| {
            if (!b_map.contains(entry.key_ptr.*)) {
                if (!first) try w.writeByte(',');
                first = false;
                try w.writeAll("{\"key\":");
                writeJsonStr(w, entry.key_ptr.*);
                try w.writeAll(",\"value\":");
                writeJsonStr(w, entry.value_ptr.*);
                try w.writeByte('}');
            }
        }
    }

    try w.writeAll("],\"changed\":[");
    // Changed: in both but different value
    first = true;
    {
        var it = a_map.iterator();
        while (it.next()) |entry| {
            if (b_map.get(entry.key_ptr.*)) |b_val| {
                if (!std.mem.eql(u8, entry.value_ptr.*, b_val)) {
                    if (!first) try w.writeByte(',');
                    first = false;
                    try w.writeAll("{\"key\":");
                    writeJsonStr(w, entry.key_ptr.*);
                    try w.writeAll(",\"old_value\":");
                    writeJsonStr(w, entry.value_ptr.*);
                    try w.writeAll(",\"new_value\":");
                    writeJsonStr(w, b_val);
                    try w.writeByte('}');
                }
            }
        }
    }

    try w.writeAll("]}");
    return try buf.toOwnedSlice(allocator);
}

/// Extract key-value pairs from a JSON array of objects.
fn extractKeyValues(
    allocator: std.mem.Allocator,
    json: []const u8,
    key_field: []const u8,
    value_field: []const u8,
    map: *std.StringHashMapUnmanaged([]const u8),
) !void {
    // Use std.json to parse the array
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, json, .{ .allocate = .alloc_always }) catch return;
    defer parsed.deinit();

    const arr = switch (parsed.value) {
        .array => |a| a,
        else => return,
    };

    for (arr.items) |item| {
        const obj = switch (item) {
            .object => |o| o,
            else => continue,
        };

        const key_val = obj.get(key_field) orelse continue;
        const key_str = switch (key_val) {
            .string => |s| s,
            .integer => |i| std.fmt.allocPrint(allocator, "{d}", .{i}) catch continue,
            else => continue,
        };

        const val_val = obj.get(value_field) orelse continue;
        const val_str = switch (val_val) {
            .string => |s| s,
            .integer => |i| std.fmt.allocPrint(allocator, "{d}", .{i}) catch continue,
            else => continue,
        };

        const k = allocator.dupe(u8, key_str) catch continue;
        const v = allocator.dupe(u8, val_str) catch {
            allocator.free(k);
            continue;
        };
        map.put(allocator, k, v) catch {
            allocator.free(k);
            allocator.free(v);
        };
    }
}

/// Write a JSON-escaped string value (with surrounding quotes) to a writer.
fn writeJsonStr(w: anytype, s: []const u8) void {
    w.writeByte('"') catch {};
    for (s) |c| {
        switch (c) {
            '"' => w.writeAll("\\\"") catch {},
            '\\' => w.writeAll("\\\\") catch {},
            '\n' => w.writeAll("\\n") catch {},
            '\r' => w.writeAll("\\r") catch {},
            '\t' => w.writeAll("\\t") catch {},
            else => {
                if (c < 0x20) {
                    w.print("\\u{x:0>4}", .{c}) catch {};
                } else {
                    w.writeByte(c) catch {};
                }
            },
        }
    }
    w.writeByte('"') catch {};
}

const AnsibleRunRequest = struct {
    playbook: []const u8,
    nodes: ?[]const []const u8 = null,
    requirements: ?[]const u8 = null,
};

const AddNodeRequest = struct {
    name: []const u8,
    host: []const u8,
    port: ?i64 = null,
    ssh_user: []const u8,
    ssh_key: []const u8,
    sudo_password: ?[]const u8 = null,
};

const CheckNodeRequest = struct {
    host: []const u8,
    port: ?i64 = null,
    ssh_user: []const u8,
    ssh_key: []const u8,
    sudo_password: ?[]const u8 = null,
};

const UpdateNodeRequest = struct {
    sudo_password: ?[]const u8 = null,
    ssh_key: ?[]const u8 = null,
    tags: ?[]const []const u8 = null,
};

const LoginRequest = struct {
    username: []const u8,
    password: []const u8,
};

const ChangePasswordRequest = struct {
    current_password: []const u8,
    new_password: []const u8,
};

// --- Fleet Command Execution ---

const FleetRunRequest = struct {
    command: []const u8,
    node_ids: []const []const u8,
    sudo: bool = false,
};

const FleetPollRequest = struct {
    offsets: ?[]const FleetPollOffset = null,

    const FleetPollOffset = struct {
        node_id: []const u8,
        offset: usize = 0,
    };
};

// --- Service Manager ---

const ServiceActionRequest = struct {
    name: []const u8,
    action: []const u8,
    scope: []const u8 = "system",
};

// --- Process Explorer ---

const ProcessKillRequest = struct {
    pid: u32,
    signal: u8 = 15,
};

// --- Scheduled Automation ---

const ScheduleCreateRequest = struct {
    name: []const u8,
    job_type: []const u8,
    config: []const u8,
    target_type: []const u8,
    target_value: ?[]const u8 = null,
    cron_minute: []const u8 = "*",
    cron_hour: []const u8 = "*",
    cron_dom: []const u8 = "*",
    cron_month: []const u8 = "*",
    cron_dow: []const u8 = "*",
    enabled: bool = true,
};

// --- Container Manager ---

const ContainerActionRequest = struct {
    id: []const u8,
    action: []const u8,
};

// --- Log Streaming ---

const LogStartRequest = struct {
    source: []const u8,
    service: ?[]const u8 = null,
    path: ?[]const u8 = null,
    lines: u32 = 100,
};

const LogStopRequest = struct {
    job_id: []const u8,
};

/// Escape a string for embedding inside a JSON string (between quotes).
fn jsonEscape(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    var buf: std.ArrayListUnmanaged(u8) = .{};
    for (input) |c| {
        switch (c) {
            '"' => try buf.appendSlice(allocator, "\\\""),
            '\\' => try buf.appendSlice(allocator, "\\\\"),
            '\n' => try buf.appendSlice(allocator, "\\n"),
            '\r' => try buf.appendSlice(allocator, "\\r"),
            '\t' => try buf.appendSlice(allocator, "\\t"),
            else => {
                if (c < 0x20) {
                    var hex_buf: [6]u8 = undefined;
                    const hex = std.fmt.bufPrint(&hex_buf, "\\u{x:0>4}", .{c}) catch continue;
                    try buf.appendSlice(allocator, hex);
                } else {
                    try buf.append(allocator, c);
                }
            },
        }
    }
    return try buf.toOwnedSlice(allocator);
}
