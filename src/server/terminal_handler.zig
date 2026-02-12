const std = @import("std");
const zap = @import("zap");
const Db = @import("db.zig").Db;
const CryptoEngine = @import("crypto.zig").CryptoEngine;
const EncryptedData = @import("crypto.zig").EncryptedData;
const Auth = @import("auth.zig").Auth;

const fio = zap.fio;
const WsHandle = zap.WebSockets.WsHandle;

pub const THandler = zap.WebSockets.Handler(TerminalState);

// --- State ---

pub const TerminalState = struct {
    allocator: std.mem.Allocator,
    db: *Db,
    crypto: *const CryptoEngine,
    auth: *const Auth,
    sessions: std.AutoHashMapUnmanaged(isize, *TerminalSession) = .{},
    sessions_mu: std.Thread.Mutex = .{},
};

const TerminalSession = struct {
    allocator: std.mem.Allocator,
    state: *TerminalState,
    handle: WsHandle,
    uuid: isize,
    ssh_child: std.process.Child,
    ssh_stdin: std.fs.File,
    tmp_key_path: []const u8,
    host_arg: []const u8,
    port_str: []const u8,
    shell_cmd: []const u8,
    ssh_key: []u8,
    shutdown: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    /// Full cleanup: wait SSH, delete temp key, secure zero, free memory.
    /// Called ONLY from the reader thread after it finishes.
    fn cleanup(self: *TerminalSession) void {
        // Wait for SSH process to fully exit
        _ = self.ssh_child.wait() catch {};

        // Delete temp key file
        std.fs.cwd().deleteFile(self.tmp_key_path) catch {};

        // Secure zero key material
        std.crypto.secureZero(u8, self.ssh_key);

        // Free allocations
        self.allocator.free(self.ssh_key);
        self.allocator.free(self.tmp_key_path);
        self.allocator.free(self.host_arg);
        self.allocator.free(self.port_str);
        self.allocator.free(self.shell_cmd);
        self.allocator.destroy(self);
    }
};

// --- Public API ---

pub fn getSettings(state: *TerminalState) THandler.WebSocketSettings {
    return .{
        .on_open = onOpen,
        .on_message = onMessage,
        .on_close = onClose,
        .context = state,
    };
}

// --- WebSocket Callbacks ---

fn onOpen(_: ?*TerminalState, _: WsHandle) !void {
    std.log.info("[SPACE ODDITY] Terminal connection incoming", .{});
}

fn onMessage(state: ?*TerminalState, handle: WsHandle, message: []const u8, is_text: bool) !void {
    const ts = state orelse return;
    const uuid = fio.websocket_uuid(handle);

    if (is_text) {
        // Text frame = JSON control message
        if (std.mem.indexOf(u8, message, "\"type\":\"auth\"")) |_| {
            handleAuth(ts, handle, uuid, message) catch |err| {
                std.log.warn("[SPACE ODDITY] Auth failed: {}", .{err});
                sendError(handle, "Authentication failed");
            };
        } else if (std.mem.indexOf(u8, message, "\"type\":\"resize\"")) |_| {
            handleResize(ts, uuid, message);
        }
    } else {
        // Binary frame = terminal input (keystrokes)
        ts.sessions_mu.lock();
        const session = ts.sessions.get(uuid);
        ts.sessions_mu.unlock();

        if (session) |s| {
            if (!s.shutdown.load(.acquire)) {
                s.ssh_stdin.writeAll(message) catch {
                    s.shutdown.store(true, .release);
                };
            }
        }
    }
}

fn onClose(state: ?*TerminalState, uuid: isize) !void {
    const ts = state orelse return;

    ts.sessions_mu.lock();
    const removed = ts.sessions.fetchRemove(uuid);
    ts.sessions_mu.unlock();

    if (removed) |kv| {
        std.log.info("[SPACE ODDITY] Terminal closed (uuid={d})", .{uuid});
        kv.value.shutdown.store(true, .release);
        // Kill SSH to unblock the reader thread
        _ = kv.value.ssh_child.kill() catch {};
        // Reader thread handles cleanup (wait, temp key, free memory)
    } else {
        std.log.info("[SPACE ODDITY] Connection closed (no session)", .{});
    }
}

// --- Auth ---

const AuthMsg = struct {
    token: []const u8,
    node_id: []const u8,
    cols: u16 = 80,
    rows: u16 = 24,
};

fn handleAuth(ts: *TerminalState, handle: WsHandle, uuid: isize, message: []const u8) !void {
    // Check if session already exists for this connection
    ts.sessions_mu.lock();
    const exists = ts.sessions.get(uuid) != null;
    ts.sessions_mu.unlock();
    if (exists) return;

    // Parse auth message
    const parsed = std.json.parseFromSlice(AuthMsg, ts.allocator, message, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    }) catch {
        sendError(handle, "Invalid auth message");
        return;
    };
    defer parsed.deinit();

    const token = parsed.value.token;
    const node_id = parsed.value.node_id;

    // Validate JWT
    if (!ts.auth.validateToken(token)) {
        sendError(handle, "Invalid or expired token");
        return;
    }

    // Look up node
    const node = ts.db.getNode(ts.allocator, node_id) catch {
        sendError(handle, "Node not found");
        return;
    } orelse {
        sendError(handle, "Node not found");
        return;
    };
    defer node.deinit(ts.allocator);

    // Decrypt SSH key
    if (node.ssh_key_nonce.len < 12 or node.ssh_key_tag.len < 16) {
        sendError(handle, "Corrupted SSH credentials");
        return;
    }
    const enc_data = EncryptedData{
        .ciphertext = node.ssh_key_enc,
        .nonce = node.ssh_key_nonce[0..12].*,
        .tag = node.ssh_key_tag[0..16].*,
        .salt = [_]u8{0} ** 16,
    };
    const ssh_key = ts.crypto.decrypt(ts.allocator, enc_data) catch {
        sendError(handle, "Failed to decrypt SSH credentials");
        return;
    };
    errdefer {
        std.crypto.secureZero(u8, ssh_key);
        ts.allocator.free(ssh_key);
    }

    // Write temp key to random path
    var rng_buf: [8]u8 = undefined;
    std.crypto.random.bytes(&rng_buf);
    var hex_buf: [16]u8 = undefined;
    _ = std.fmt.bufPrint(&hex_buf, "{x:0>16}", .{std.mem.readInt(u64, &rng_buf, .big)}) catch unreachable;
    const tmp_key_path = try std.fmt.allocPrint(ts.allocator, "/tmp/stardust_term_{s}", .{hex_buf});
    errdefer ts.allocator.free(tmp_key_path);

    {
        const file = std.fs.cwd().createFile(tmp_key_path, .{ .mode = 0o600 }) catch {
            sendError(handle, "Failed to create temp key");
            return;
        };
        defer file.close();
        file.writeAll(ssh_key) catch {
            sendError(handle, "Failed to write temp key");
            return;
        };
    }

    // Build SSH args
    const host_arg = try std.fmt.allocPrint(ts.allocator, "{s}@{s}", .{ node.ssh_user, node.host });
    errdefer ts.allocator.free(host_arg);

    const port_str = try std.fmt.allocPrint(ts.allocator, "{d}", .{node.port});
    errdefer ts.allocator.free(port_str);

    // Bake initial terminal size + TERM into SSH remote command (avoids visible stty on connect)
    const cols = parsed.value.cols;
    const rows = parsed.value.rows;
    const shell_cmd = try std.fmt.allocPrint(ts.allocator, "stty rows {d} cols {d}; env TERM=xterm-256color $SHELL -l", .{ rows, cols });
    errdefer ts.allocator.free(shell_cmd);

    // Spawn SSH with forced PTY
    var child = std.process.Child.init(
        &.{
            "ssh", "-tt",
            "-i",  tmp_key_path,
            "-p",  port_str,
            "-o",  "StrictHostKeyChecking=no",
            "-o",  "ConnectTimeout=10",
            host_arg,
            shell_cmd,
        },
        ts.allocator,
    );
    child.stdin_behavior = .Pipe;
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Pipe;

    child.spawn() catch {
        sendError(handle, "Failed to spawn SSH process");
        return;
    };

    // Create session
    const session = ts.allocator.create(TerminalSession) catch {
        _ = child.kill() catch {};
        _ = child.wait() catch {};
        sendError(handle, "Internal error");
        return;
    };
    session.* = .{
        .allocator = ts.allocator,
        .state = ts,
        .handle = handle,
        .uuid = uuid,
        .ssh_child = child,
        .ssh_stdin = child.stdin.?,
        .tmp_key_path = tmp_key_path,
        .host_arg = host_arg,
        .port_str = port_str,
        .shell_cmd = shell_cmd,
        .ssh_key = ssh_key,
    };

    // Store session
    ts.sessions_mu.lock();
    ts.sessions.put(ts.allocator, uuid, session) catch {
        ts.sessions_mu.unlock();
        _ = child.kill() catch {};
        session.cleanup();
        sendError(handle, "Internal error");
        return;
    };
    ts.sessions_mu.unlock();

    // Send ready
    THandler.write(handle, "{\"type\":\"ready\"}", true) catch {};

    // Spawn reader thread (reads SSH stdout → writes binary WS frames)
    const thread = std.Thread.spawn(.{}, readerWorker, .{session}) catch {
        ts.sessions_mu.lock();
        _ = ts.sessions.remove(uuid);
        ts.sessions_mu.unlock();
        _ = child.kill() catch {};
        session.cleanup();
        sendError(handle, "Failed to start terminal reader");
        return;
    };
    thread.detach();

    std.log.info("[SPACE ODDITY] Terminal opened for node '{s}' via {s}", .{ node_id, host_arg });
}

// --- Resize ---

const ResizeMsg = struct {
    cols: u16 = 80,
    rows: u16 = 24,
};

fn handleResize(ts: *TerminalState, uuid: isize, message: []const u8) void {
    ts.sessions_mu.lock();
    const session = ts.sessions.get(uuid);
    ts.sessions_mu.unlock();
    const s = session orelse return;

    const parsed = std.json.parseFromSlice(ResizeMsg, ts.allocator, message, .{
        .ignore_unknown_fields = true,
    }) catch return;

    var buf: [64]u8 = undefined;
    const cmd = std.fmt.bufPrint(&buf, "stty rows {d} cols {d}\n", .{ parsed.value.rows, parsed.value.cols }) catch return;
    s.ssh_stdin.writeAll(cmd) catch {};
}

// --- Reader Thread ---

fn readerWorker(session: *TerminalSession) void {
    const ts = session.state;
    const stdout = session.ssh_child.stdout orelse {
        ts.sessions_mu.lock();
        _ = ts.sessions.remove(session.uuid);
        ts.sessions_mu.unlock();
        session.cleanup();
        return;
    };
    var buf: [4096]u8 = undefined;

    while (!session.shutdown.load(.acquire)) {
        const n = stdout.read(&buf) catch break;
        if (n == 0) break; // EOF — SSH exited

        // Write binary frame to WebSocket (thread-safe per facil.io docs)
        THandler.write(session.handle, buf[0..n], false) catch break;
    }

    // Try to capture SSH stderr for error diagnostics
    if (session.ssh_child.stderr) |stderr| {
        var err_buf: [2048]u8 = undefined;
        const err_n = stderr.read(&err_buf) catch 0;
        if (err_n > 0 and !session.shutdown.load(.acquire)) {
            THandler.write(session.handle, err_buf[0..err_n], false) catch {};
        }
    }

    // Remove from map FIRST — prevents onClose from accessing freed memory
    ts.sessions_mu.lock();
    _ = ts.sessions.remove(session.uuid);
    ts.sessions_mu.unlock();

    // Notify client and close WebSocket (only if not already shutting down)
    if (!session.shutdown.load(.acquire)) {
        THandler.write(session.handle, "{\"type\":\"closed\"}", true) catch {};
        THandler.close(session.handle);
    }

    std.log.info("[SPACE ODDITY] Terminal reader exited", .{});

    // LAST: cleanup frees the session — nothing must access session after this
    session.cleanup();
}

// --- Helpers ---

fn sendError(handle: WsHandle, msg: []const u8) void {
    var buf: [256]u8 = undefined;
    const json = std.fmt.bufPrint(&buf, "{{\"type\":\"error\",\"message\":\"{s}\"}}", .{msg}) catch return;
    THandler.write(handle, json, true) catch {};
}
