const std = @import("std");
const zap = @import("zap");
const Store = @import("store.zig").Store;
const Db = @import("db.zig").Db;
const CryptoEngine = @import("crypto.zig").CryptoEngine;
const deployer_mod = @import("deployer.zig");
const Deployer = deployer_mod.Deployer;
const Auth = @import("auth.zig").Auth;

pub const Api = struct {
    allocator: std.mem.Allocator,
    store: *Store,
    db: ?*Db,
    crypto: ?*const CryptoEngine,
    deployer: ?*Deployer,
    auth: ?*const Auth = null,

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
        if (std.mem.eql(u8, path, "/api/auth/password")) {
            try self.handleChangePassword(r);
        } else if (std.mem.eql(u8, path, "/api/nodes/check")) {
            try self.handleNodeCheck(r);
        } else if (std.mem.eql(u8, path, "/api/nodes")) {
            try self.handleNodes(r);
        } else if (std.mem.startsWith(u8, path, "/api/nodes/")) {
            try self.handleNodeDetail(r, path);
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

        // Build DB lookup for node metadata (name, host, port, status)
        var db_lookup = std.StringHashMap(struct { name: []const u8, host: []const u8, status: []const u8 }).init(self.allocator);
        defer db_lookup.deinit();

        const db_nodes = if (self.db) |db| db.listNodes(self.allocator) catch &.{} else &.{};
        defer {
            for (db_nodes) |node| node.deinit(self.allocator);
            if (db_nodes.len > 0) self.allocator.free(db_nodes);
        }
        for (db_nodes) |node| {
            db_lookup.put(node.id, .{ .name = node.name, .host = node.host, .status = node.status }) catch {};
        }

        // First: add all live agents from the in-memory store (enriched with DB metadata)
        for (store_agents) |agent| {
            if (count > 0) try buf.append(self.allocator, ',');
            const meta = db_lookup.get(agent.agent_id);
            const entry = std.fmt.allocPrint(self.allocator,
                \\{{"agent_id":"{s}","name":"{s}","host":"{s}","connected":{s},"last_seen":{d},"snapshot_count":{d}}}
            , .{
                agent.agent_id,
                if (meta) |m| m.name else agent.agent_id,
                if (meta) |m| m.host else "",
                if (agent.connected) "true" else "false",
                agent.last_seen,
                agent.snapshot_count,
            }) catch continue;
            defer self.allocator.free(entry);
            try buf.appendSlice(self.allocator, entry);
            try seen.put(agent.agent_id, {});
            count += 1;
        }

        // Second: add DB nodes that aren't already in the store (offline nodes)
        for (db_nodes) |node| {
            if (seen.contains(node.id)) continue;
            if (count > 0) try buf.append(self.allocator, ',');
            const entry = std.fmt.allocPrint(self.allocator,
                \\{{"agent_id":"{s}","name":"{s}","host":"{s}","connected":false,"last_seen":{d},"snapshot_count":0}}
            , .{
                node.id, node.name, node.host,
                node.last_seen orelse node.created_at,
            }) catch continue;
            defer self.allocator.free(entry);
            try buf.appendSlice(self.allocator, entry);
            count += 1;
        }

        try buf.append(self.allocator, ']');
        try r.sendJson(buf.items);
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
};

const LoginRequest = struct {
    username: []const u8,
    password: []const u8,
};

const ChangePasswordRequest = struct {
    current_password: []const u8,
    new_password: []const u8,
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
