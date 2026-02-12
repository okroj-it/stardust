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
        } else {
            return; // Let static file handler deal with it
        }
    }

    fn handleHealth(self: *Api, r: zap.Request) !void {
        _ = self;
        try r.sendJson("{\"status\":\"ok\"}");
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
    }

    fn deleteNode(self: *Api, r: zap.Request, node_id: []const u8) !void {
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
            deployer.stepUploadBinary(node_id)
        else if (std.mem.eql(u8, step, "install"))
            deployer.stepInstallService(node_id)
        else if (std.mem.eql(u8, step, "start"))
            deployer.stepStartService(node_id)
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
            \\{{"deployer":{s},"auth":{s},"ansible":{s},"ansible_version":{s},"fleet":{s},"services":{s}}}
        , .{
            if (self.deployer != null) "true" else "false",
            if (self.auth != null) "true" else "false",
            if (self.ansible != null) "true" else "false",
            ver_json,
            if (self.fleet != null) "true" else "false",
            if (self.services != null) "true" else "false",
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
};

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
