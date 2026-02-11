const std = @import("std");
const zap = @import("zap");
const common = @import("common");
const Store = @import("store.zig").Store;
const ws_handler = @import("ws_handler.zig");
const Api = @import("api.zig").Api;
const Db = @import("db.zig").Db;
const CryptoEngine = @import("crypto.zig").CryptoEngine;
const Deployer = @import("deployer.zig").Deployer;
const Auth = @import("auth.zig").Auth;
const embedded_ui = @import("embedded_ui");

const version = "0.1.0";

const Args = struct {
    port: u16 = 8080,
    db_path: [:0]const u8 = "sroolify.db",
    agent_binary: []const u8 = "zig-out/bin/sroolify-agent",
    server_url: []const u8 = "ws://localhost:8080/ws",
};

var global_api: Api = undefined;
var global_ws_settings: ws_handler.WsHandler.WebSocketSettings = undefined;

fn onRequest(r: zap.Request) !void {
    const path = r.path orelse "/";

    // API routes
    if (std.mem.startsWith(u8, path, "/api/")) {
        global_api.handleRequest(r) catch |err| {
            std.log.err("api error: {}", .{err});
            r.setStatus(.internal_server_error);
            r.sendJson("{\"error\":\"internal server error\"}") catch {};
        };
        return;
    }

    // Serve embedded UI assets
    if (embedded_ui.get(path)) |asset| {
        r.setHeader("Content-Type", asset.content_type) catch {};
        r.setHeader("Cache-Control", "public, max-age=31536000, immutable") catch {};
        if (std.mem.endsWith(u8, asset.content_type, "html; charset=utf-8")) {
            // Don't cache HTML (SPA entry point)
            r.setHeader("Cache-Control", "no-cache") catch {};
        }
        try r.sendBody(asset.content);
        return;
    }

    // Fallback
    r.setStatus(.not_found);
    r.sendBody("404") catch {};
}

fn onUpgrade(r: zap.Request, target_protocol: []const u8) !void {
    _ = target_protocol;
    ws_handler.WsHandler.upgrade(r.h, &global_ws_settings) catch |err| {
        std.log.warn("ws upgrade failed: {}", .{err});
    };
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = parseArgs();

    std.log.info("sroolify-server v{s} starting on port {d}", .{ version, args.port });

    // Init crypto from SROOLIFY_SECRET env var
    const secret = std.posix.getenv("SROOLIFY_SECRET");
    var crypto_engine: ?CryptoEngine = null;
    if (secret) |s| {
        if (s.len >= 16) {
            crypto_engine = CryptoEngine.init(s) catch |err| {
                std.log.err("crypto init failed: {}", .{err});
                return;
            };
            std.log.info("crypto engine initialized (bcrypt-pbkdf)", .{});
        } else {
            std.log.warn("SROOLIFY_SECRET too short (need >= 16 chars), crypto disabled", .{});
        }
    } else {
        std.log.warn("SROOLIFY_SECRET not set, node deployment disabled", .{});
    }

    // Init database
    var db: ?Db = Db.init(args.db_path) catch |err| blk: {
        std.log.err("database init failed: {}", .{err});
        std.log.warn("running without database (in-memory only)", .{});
        break :blk null;
    };
    defer if (db) |*d| d.deinit();

    if (db != null) {
        std.log.info("database initialized at {s}", .{args.db_path});
    }

    // Init store
    var store = Store.init(allocator);
    defer store.deinit();

    // Init WebSocket state
    var ws_state = ws_handler.WsState.init(allocator, &store);
    defer ws_state.deinit();

    // Load tokens from DB if available
    if (db) |*d| {
        const tokens = d.getAllTokens(allocator) catch &.{};
        defer allocator.free(tokens);
        for (tokens) |entry| {
            ws_state.addToken(entry.agent_id, entry.token) catch {};
        }
        if (tokens.len > 0) {
            std.log.info("loaded {d} agent tokens from database", .{tokens.len});
        }
    }

    // Always add a test token for development
    ws_state.addToken("test-agent", "test-token") catch {};

    // Init deployer
    var deployer: ?Deployer = null;
    if (crypto_engine) |*ce| {
        if (db) |*d| {
            deployer = Deployer.init(allocator, d, ce, args.server_url, args.agent_binary);
            std.log.info("deployer initialized (binary: {s})", .{args.agent_binary});
        }
    }

    // Init auth (requires crypto + db)
    var auth: ?Auth = null;
    if (crypto_engine) |ce| {
        if (db) |*d| {
            auth = Auth{ .signing_key = ce.derived_key };

            // Seed admin user on first run
            const user_count = d.getUserCount() catch 0;
            if (user_count == 0) {
                const admin_user = std.posix.getenv("SROOLIFY_ADMIN_USER") orelse "admin";
                const admin_pass = std.posix.getenv("SROOLIFY_ADMIN_PASS") orelse "admin";
                if (std.mem.eql(u8, admin_pass, "admin")) {
                    std.log.warn("using default admin password — set SROOLIFY_ADMIN_PASS in production!", .{});
                }
                const hash = Auth.hashPassword(admin_pass) catch |err| blk: {
                    std.log.err("failed to hash admin password: {}", .{err});
                    break :blk null;
                };
                if (hash) |h| {
                    d.insertUser(admin_user, &h) catch |err| {
                        std.log.err("failed to create admin user: {}", .{err});
                    };
                    std.log.info("created initial admin user '{s}'", .{admin_user});
                }
            }
            std.log.info("dashboard auth: enabled", .{});
        }
    }
    if (auth == null) {
        std.log.warn("dashboard auth: disabled (requires SROOLIFY_SECRET)", .{});
    }

    // Init API handler
    global_api = Api.init(allocator, &store);
    if (db) |*d| global_api.setDb(d);
    if (crypto_engine) |*ce| global_api.setCrypto(ce);
    if (deployer) |*dep| global_api.setDeployer(dep);
    if (auth) |*a| global_api.setAuth(a);

    // Init WebSocket settings
    global_ws_settings = ws_handler.getSettings(&ws_state);

    // Start zap
    var listener = zap.HttpListener.init(.{
        .port = args.port,
        .on_request = onRequest,
        .on_upgrade = onUpgrade,
        .log = false,
        .max_clients = 1024,
        .max_body_size = 10 * 1024 * 1024, // 10MB (SSH keys can be large)
    });

    try listener.listen();

    std.log.info("server listening on http://localhost:{d}", .{args.port});
    std.log.info("WebSocket endpoint: ws://localhost:{d}/ws", .{args.port});
    if (crypto_engine != null and db != null) {
        std.log.info("node deployment: enabled", .{});
    } else {
        std.log.info("node deployment: disabled (set SROOLIFY_SECRET to enable)", .{});
    }

    // This blocks — runs the event loop
    zap.start(.{
        .threads = 2,
        .workers = 1, // single worker for shared state simplicity
    });
}

fn parseArgs() Args {
    var args = Args{};
    var iter = std.process.args();
    _ = iter.next(); // skip binary name

    while (iter.next()) |arg| {
        if (std.mem.eql(u8, arg, "--port")) {
            if (iter.next()) |val| {
                args.port = std.fmt.parseInt(u16, val, 10) catch 8080;
            }
        } else if (std.mem.eql(u8, arg, "--db")) {
            args.db_path = iter.next() orelse "sroolify.db";
        } else if (std.mem.eql(u8, arg, "--agent-binary")) {
            args.agent_binary = iter.next() orelse "zig-out/bin/sroolify-agent";
        } else if (std.mem.eql(u8, arg, "--server-url")) {
            args.server_url = iter.next() orelse "ws://localhost:8080/ws";
        } else if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            printUsage();
            std.process.exit(0);
        }
    }
    return args;
}

fn printUsage() void {
    std.fs.File.stderr().writeAll(
        \\Usage: sroolify-server [OPTIONS]
        \\
        \\Options:
        \\  --port PORT          HTTP/WS port (default: 8080)
        \\  --db PATH            SQLite database path (default: sroolify.db)
        \\  --agent-binary PATH  Path to agent binary for deployment
        \\  --server-url URL     Server WS URL for agent config (default: ws://localhost:8080/ws)
        \\  -h, --help           Show this help
        \\
        \\Environment:
        \\  SROOLIFY_SECRET      Master encryption secret (>= 16 chars, required for deployment + auth)
        \\  SROOLIFY_ADMIN_USER  Initial admin username (default: admin)
        \\  SROOLIFY_ADMIN_PASS  Initial admin password (default: admin)
        \\
    ) catch {};
}
