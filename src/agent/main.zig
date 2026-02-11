const std = @import("std");
const collector = @import("collector.zig");
const WsClient = @import("ws_client.zig").WsClient;

const version = "0.1.0";

const Args = struct {
    server_url: ?[]const u8 = null,
    token: ?[]const u8 = null,
    agent_id: ?[]const u8 = null,
    interval_ms: u32 = 5000,
    stdout_mode: bool = false,
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = parseArgs() orelse return;

    std.log.info("sroolify-agent v{s} starting", .{version});

    if (args.stdout_mode) {
        try runStdoutMode(allocator, args);
    } else {
        if (args.server_url == null or args.token == null or args.agent_id == null) {
            std.log.err("--server, --token, and --agent-id are required (or use --stdout)", .{});
            return;
        }
        try runAgentMode(allocator, args);
    }
}

fn runStdoutMode(allocator: std.mem.Allocator, args: Args) !void {
    var coll = collector.Collector.init(args.agent_id);
    const stdout = std.fs.File.stdout();

    // First sample for CPU delta baseline
    _ = coll.collect(allocator) catch |err| {
        std.log.warn("initial collect failed: {}", .{err});
        return err;
    };
    std.Thread.sleep(std.time.ns_per_s);

    while (true) {
        const stats = try coll.collect(allocator);
        defer allocator.free(stats);

        stdout.writeAll(stats) catch {};
        stdout.writeAll("\n") catch {};

        std.Thread.sleep(@as(u64, args.interval_ms) * std.time.ns_per_ms);
    }
}

fn runAgentMode(allocator: std.mem.Allocator, args: Args) !void {
    const url = args.server_url.?;
    const token = args.token.?;
    const agent_id = args.agent_id.?;

    // Parse ws://host:port/path
    const parsed = parseWsUrl(url) orelse {
        std.log.err("invalid server URL: {s}", .{url});
        return;
    };

    var coll = collector.Collector.init(args.agent_id);

    // Take initial CPU sample
    const initial = coll.collect(allocator) catch |err| {
        std.log.warn("initial collect failed: {}", .{err});
        return err;
    };
    allocator.free(initial);
    std.Thread.sleep(std.time.ns_per_s);

    var backoff: u64 = 1;

    while (true) {
        std.log.info("connecting to {s}:{d}{s} (tls={s})", .{ parsed.host, parsed.port, parsed.path, if (parsed.tls) "yes" else "no" });

        var ws: WsClient = .{};
        ws.connect(allocator, parsed.host, parsed.port, parsed.path, parsed.tls) catch |err| {
            std.log.warn("connection failed: {}, retrying in {d}s", .{ err, backoff });
            std.Thread.sleep(backoff * std.time.ns_per_s);
            backoff = @min(backoff * 2, 60);
            continue;
        };

        std.log.info("connected, authenticating", .{});
        backoff = 1;

        // Send auth message
        var auth_buf: [512]u8 = undefined;
        const auth_json = std.fmt.bufPrint(&auth_buf,
            \\{{"type":"auth","agent_id":"{s}","token":"{s}","version":"{s}"}}
        , .{ agent_id, token, version }) catch continue;

        ws.sendText(auth_json) catch {
            ws.close();
            continue;
        };

        std.log.info("authenticated, streaming stats", .{});

        // Main collect+send loop
        while (ws.connected) {
            const stats = coll.collect(allocator) catch |err| {
                std.log.warn("collect failed: {}", .{err});
                std.Thread.sleep(@as(u64, args.interval_ms) * std.time.ns_per_ms);
                continue;
            };
            defer allocator.free(stats);

            ws.sendText(stats) catch {
                std.log.warn("send failed, reconnecting", .{});
                break;
            };

            std.Thread.sleep(@as(u64, args.interval_ms) * std.time.ns_per_ms);
        }

        ws.close();
        std.log.info("disconnected, reconnecting in {d}s", .{backoff});
        std.Thread.sleep(backoff * std.time.ns_per_s);
        backoff = @min(backoff * 2, 60);
    }
}

const ParsedUrl = struct {
    host: []const u8,
    port: u16,
    path: []const u8,
    tls: bool,
};

fn parseWsUrl(url: []const u8) ?ParsedUrl {
    var use_tls = false;
    const after_scheme = if (std.mem.startsWith(u8, url, "wss://")) blk: {
        use_tls = true;
        break :blk url[6..];
    } else if (std.mem.startsWith(u8, url, "ws://"))
        url[5..]
    else
        return null;

    const path_start = std.mem.indexOf(u8, after_scheme, "/") orelse after_scheme.len;
    const host_port = after_scheme[0..path_start];
    const path = if (path_start < after_scheme.len) after_scheme[path_start..] else "/";

    const default_port: u16 = if (use_tls) 443 else 80;

    if (std.mem.indexOf(u8, host_port, ":")) |colon| {
        return .{
            .host = host_port[0..colon],
            .port = std.fmt.parseInt(u16, host_port[colon + 1 ..], 10) catch return null,
            .path = path,
            .tls = use_tls,
        };
    } else {
        return .{ .host = host_port, .port = default_port, .path = path, .tls = use_tls };
    }
}

fn parseArgs() ?Args {
    var args = Args{};
    var iter = std.process.args();
    _ = iter.next(); // skip binary name

    while (iter.next()) |arg| {
        if (std.mem.eql(u8, arg, "--stdout")) {
            args.stdout_mode = true;
        } else if (std.mem.eql(u8, arg, "--server")) {
            args.server_url = iter.next();
        } else if (std.mem.eql(u8, arg, "--token")) {
            args.token = iter.next();
        } else if (std.mem.eql(u8, arg, "--agent-id")) {
            args.agent_id = iter.next();
        } else if (std.mem.eql(u8, arg, "--interval")) {
            if (iter.next()) |val| {
                args.interval_ms = std.fmt.parseInt(u32, val, 10) catch 5000;
            }
        } else if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            printUsage();
            return null;
        }
    }
    return args;
}

fn printUsage() void {
    std.fs.File.stderr().writeAll(
        \\Usage: sroolify-agent [OPTIONS]
        \\
        \\Options:
        \\  --stdout          Print stats to stdout as JSON (no server connection)
        \\  --server URL      WebSocket server URL (e.g. ws://host:8080/ws)
        \\  --token TOKEN     Authentication token
        \\  --agent-id ID     Unique agent identifier
        \\  --interval MS     Collection interval in milliseconds (default: 5000)
        \\  -h, --help        Show this help
        \\
    ) catch {};
}

test "arg parsing" {
    const args = Args{};
    try std.testing.expect(args.interval_ms == 5000);
    try std.testing.expect(args.stdout_mode == false);
}
