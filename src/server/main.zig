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
const AnsibleEngine = @import("ansible.zig").AnsibleEngine;
const FleetEngine = @import("fleet.zig").FleetEngine;
const ServiceEngine = @import("services.zig").ServiceEngine;
const ProcessEngine = @import("processes.zig").ProcessEngine;
const LogEngine = @import("logs.zig").LogEngine;
const DriftEngine = @import("drift.zig").DriftEngine;
const terminal_handler = @import("terminal_handler.zig");
const embedded_ui = @import("embedded_ui");

const version = "0.1.0";
const codename = "Ground Control";

const Args = struct {
    port: u16 = 8080,
    db_path: [:0]const u8 = "stardust.db",
    agent_binary: []const u8 = "zig-out/bin/stardust-spider",
    server_url: []const u8 = "ws://localhost:8080/ws",
};

var global_api: Api = undefined;
var global_ws_settings: ws_handler.WsHandler.WebSocketSettings = undefined;
var global_terminal_ws_settings: ?terminal_handler.THandler.WebSocketSettings = null;

fn onRequest(r: zap.Request) !void {
    const path = r.path orelse "/";

    // API routes
    if (std.mem.startsWith(u8, path, "/api/") or std.mem.eql(u8, path, "/metrics")) {
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
    const path = r.path orelse "/ws";

    if (std.mem.eql(u8, path, "/ws/terminal")) {
        if (global_terminal_ws_settings) |*settings| {
            terminal_handler.THandler.upgrade(r.h, settings) catch |err| {
                std.log.warn("[SPACE ODDITY] terminal ws upgrade failed: {}", .{err});
            };
        } else {
            r.setStatus(.service_unavailable);
            r.sendJson("{\"error\":\"terminal not available\"}") catch {};
        }
    } else {
        ws_handler.WsHandler.upgrade(r.h, &global_ws_settings) catch |err| {
            std.log.warn("ws upgrade failed: {}", .{err});
        };
    }
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = parseArgs();

    std.log.info("[GROUND CONTROL] Stardust v{s} — Commencing countdown, engines on.", .{version});
    std.log.info("[GROUND CONTROL] Binding to port {d}", .{args.port});

    // Init crypto from STARDUST_SECRET env var
    const secret = std.posix.getenv("STARDUST_SECRET");
    var crypto_engine: ?CryptoEngine = null;
    if (secret) |s| {
        if (s.len >= 16) {
            crypto_engine = CryptoEngine.init(s) catch |err| {
                std.log.err("crypto init failed: {}", .{err});
                return;
            };
            std.log.info("[GROUND CONTROL] Crypto engine online (bcrypt-pbkdf)", .{});
        } else {
            std.log.warn("STARDUST_SECRET too short (need >= 16 chars), crypto disabled", .{});
        }
    } else {
        std.log.warn("STARDUST_SECRET not set, node deployment disabled", .{});
    }

    // Init database
    var db: ?Db = Db.init(args.db_path) catch |err| blk: {
        std.log.err("database init failed: {}", .{err});
        std.log.warn("running without database (in-memory only)", .{});
        break :blk null;
    };
    defer if (db) |*d| d.deinit();

    if (db != null) {
        std.log.info("[GROUND CONTROL] Database online at {s}", .{args.db_path});
    }

    // Init store
    var store = Store.init(allocator);
    defer store.deinit();

    // Init WebSocket state
    var ws_state = ws_handler.WsState.init(allocator, &store);
    defer ws_state.deinit();
    if (db) |*d| ws_state.db = d;

    // Load tokens from DB if available
    if (db) |*d| {
        const tokens = d.getAllTokens(allocator) catch &.{};
        defer allocator.free(tokens);
        for (tokens) |entry| {
            ws_state.addToken(entry.agent_id, entry.token) catch {};
        }
        if (tokens.len > 0) {
            std.log.info("[GROUND CONTROL] Loaded {d} Spider tokens", .{tokens.len});
        }
    }

    // Always add a test token for development
    ws_state.addToken("test-agent", "test-token") catch {};

    // Init deployer
    var deployer: ?Deployer = null;
    if (crypto_engine) |*ce| {
        if (db) |*d| {
            deployer = Deployer.init(allocator, d, ce, args.server_url, args.agent_binary);
            std.log.info("[MAJOR TOM] Deployer ready (binary: {s})", .{args.agent_binary});
        }
    }

    // Init Ansible (requires crypto + db, auto-detects ansible-playbook)
    var ansible: ?AnsibleEngine = null;
    if (crypto_engine) |*ce| {
        if (db) |*d| {
            ansible = AnsibleEngine.detect(allocator, d, ce);
        }
    }

    // Init fleet command engine (requires crypto + db)
    var fleet: ?FleetEngine = null;
    if (crypto_engine) |*ce| {
        if (db) |*d| {
            fleet = FleetEngine.init(allocator, d, ce);
            std.log.info("[STARMAN] Fleet command engine: enabled", .{});
        }
    }

    // Init service manager (requires crypto + db)
    var services: ?ServiceEngine = null;
    if (crypto_engine) |*ce| {
        if (db) |*d| {
            services = ServiceEngine.init(allocator, d, ce);
            std.log.info("[LIFE ON MARS] Service manager: enabled", .{});
        }
    }

    // Init process explorer (requires crypto + db)
    var processes: ?ProcessEngine = null;
    if (crypto_engine) |*ce| {
        if (db) |*d| {
            processes = ProcessEngine.init(allocator, d, ce);
            std.log.info("[ZIGGY] Process explorer: enabled", .{});
        }
    }

    // Init log streaming engine (requires crypto + db)
    var logs: ?LogEngine = null;
    if (crypto_engine) |*ce| {
        if (db) |*d| {
            logs = LogEngine.init(allocator, d, ce);
            std.log.info("[SOUND AND VISION] Log streaming: enabled", .{});
        }
    }

    // Init drift detection engine (requires crypto + db)
    var drift: ?DriftEngine = null;
    if (crypto_engine) |*ce| {
        if (db) |*d| {
            drift = DriftEngine.init(allocator, d, ce);
            std.log.info("[DRIFT] Drift detection: enabled", .{});
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
                const admin_user = std.posix.getenv("STARDUST_ADMIN_USER") orelse "admin";
                const admin_pass = std.posix.getenv("STARDUST_ADMIN_PASS") orelse "admin";
                if (std.mem.eql(u8, admin_pass, "admin")) {
                    std.log.warn("using default admin password — set STARDUST_ADMIN_PASS in production!", .{});
                }
                const hash = Auth.hashPassword(admin_pass) catch |err| blk: {
                    std.log.err("failed to hash admin password: {}", .{err});
                    break :blk null;
                };
                if (hash) |h| {
                    d.insertUser(admin_user, &h) catch |err| {
                        std.log.err("failed to create admin user: {}", .{err});
                    };
            std.log.info("[GROUND CONTROL] Created initial admin user '{s}'", .{admin_user});
                }
            }
            std.log.info("[GROUND CONTROL] Capsule auth: enabled", .{});
        }
    }
    if (auth == null) {
        std.log.warn("[GROUND CONTROL] Capsule auth: disabled (requires STARDUST_SECRET)", .{});
    }

    // Init terminal handler (requires crypto + db + auth)
    var terminal_state: ?terminal_handler.TerminalState = null;
    if (auth) |*a| {
        if (db) |*d| {
            if (crypto_engine) |*ce| {
                terminal_state = .{ .allocator = allocator, .db = d, .crypto = ce, .auth = a };
                std.log.info("[SPACE ODDITY] Web terminal: enabled", .{});
            }
        }
    }
    if (terminal_state) |*ts| {
        global_terminal_ws_settings = terminal_handler.getSettings(ts);
    }

    // Init API handler
    global_api = Api.init(allocator, &store);
    if (db) |*d| global_api.setDb(d);
    if (crypto_engine) |*ce| global_api.setCrypto(ce);
    if (deployer) |*dep| global_api.setDeployer(dep);
    if (auth) |*a| global_api.setAuth(a);
    if (ansible) |*a| global_api.setAnsible(a);
    if (fleet) |*f| global_api.setFleet(f);
    if (services) |*s| global_api.setServices(s);
    if (processes) |*p| global_api.setProcesses(p);
    if (logs) |*l| global_api.setLogs(l);
    if (drift) |*d| global_api.setDrift(d);
    global_api.setWsState(&ws_state);

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

    std.log.info("[GROUND CONTROL] Listening on http://localhost:{d}", .{args.port});
    std.log.info("[GROUND CONTROL] WebSocket relay: ws://localhost:{d}/ws", .{args.port});
    if (crypto_engine != null and db != null) {
        std.log.info("[GROUND CONTROL] Major Tom deployment: enabled", .{});
    } else {
        std.log.info("[GROUND CONTROL] Major Tom deployment: disabled (set STARDUST_SECRET)", .{});
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
            args.agent_binary = iter.next() orelse "zig-out/bin/stardust-spider";
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
        \\Usage: stardust-server [OPTIONS]
        \\
        \\  Stardust — Orchestrating the Spiders from Mars.
        \\
        \\Options:
        \\  --port PORT          HTTP/WS port (default: 8080)
        \\  --db PATH            SQLite database path (default: stardust.db)
        \\  --agent-binary PATH  Path to Spider binary for deployment
        \\  --server-url URL     Server WS URL for Spider config (default: ws://localhost:8080/ws)
        \\  -h, --help           Show this help
        \\
        \\Environment:
        \\  STARDUST_SECRET      Master encryption secret (>= 16 chars, required for deployment + auth)
        \\  STARDUST_ADMIN_USER  Initial admin username (default: admin)
        \\  STARDUST_ADMIN_PASS  Initial admin password (default: admin)
        \\
    ) catch {};
}
