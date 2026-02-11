const std = @import("std");
const common = @import("common");
const tls = std.crypto.tls;
const Certificate = std.crypto.Certificate;

pub const WsClient = struct {
    net_stream: std.net.Stream = undefined,
    net_reader: std.net.Stream.Reader = undefined,
    net_writer: std.net.Stream.Writer = undefined,
    tls_client: ?tls.Client = null,
    connected: bool = false,
    use_tls: bool = false,

    // Buffers — must live as long as the client
    net_read_buf: [tls.Client.min_buffer_len]u8 = undefined,
    net_write_buf: [tls.Client.min_buffer_len]u8 = undefined,
    tls_read_buf: [tls.Client.min_buffer_len]u8 = undefined,
    tls_write_buf: [tls.Client.min_buffer_len]u8 = undefined,

    /// Connect to a WebSocket server. Must be called on a stable (non-moving) pointer.
    pub fn connect(self: *WsClient, allocator: std.mem.Allocator, host: []const u8, port: u16, path: []const u8, use_tls_param: bool) !void {
        self.use_tls = use_tls_param;
        self.connected = false;
        self.tls_client = null;

        // Resolve and connect TCP
        const list = std.net.getAddressList(allocator, host, port) catch return error.ConnectionFailed;
        defer list.deinit();
        if (list.addrs.len == 0) return error.ConnectionFailed;
        const address = list.addrs[0];

        const sock = try std.posix.socket(address.any.family, std.posix.SOCK.STREAM, 0);
        self.net_stream = std.net.Stream{ .handle = sock };
        errdefer self.net_stream.close();

        std.posix.connect(sock, &address.any, address.getOsSockLen()) catch return error.ConnectionFailed;

        // Init net reader/writer with our internal buffers (pointers stable since self is pinned)
        self.net_reader = std.net.Stream.Reader.init(self.net_stream, &self.net_read_buf);
        self.net_writer = std.net.Stream.Writer.init(self.net_stream, &self.net_write_buf);

        // TLS handshake if wss://
        if (use_tls_param) {
            var ca_bundle: Certificate.Bundle = .{};
            ca_bundle.rescan(allocator) catch return error.TlsInitFailed;
            defer ca_bundle.deinit(allocator);

            self.tls_client = tls.Client.init(
                self.net_reader.interface(),
                &self.net_writer.interface,
                .{
                    .host = .{ .explicit = host },
                    .ca = .{ .bundle = ca_bundle },
                    .read_buffer = &self.tls_read_buf,
                    .write_buffer = &self.tls_write_buf,
                    .allow_truncation_attacks = true,
                },
            ) catch return error.TlsInitFailed;
        }

        // Get the appropriate reader/writer for HTTP upgrade
        const writer = self.getWriter();
        const reader = self.getReader();

        // Build and send HTTP upgrade request
        var ws_key: [24]u8 = undefined;
        var random_bytes: [16]u8 = undefined;
        std.crypto.random.bytes(&random_bytes);
        _ = std.base64.standard.Encoder.encode(&ws_key, &random_bytes);

        writer.writeAll("GET ") catch return error.ConnectionFailed;
        writer.writeAll(path) catch return error.ConnectionFailed;
        writer.writeAll(" HTTP/1.1\r\nHost: ") catch return error.ConnectionFailed;
        writer.writeAll(host) catch return error.ConnectionFailed;
        writer.writeAll("\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: ") catch return error.ConnectionFailed;
        writer.writeAll(&ws_key) catch return error.ConnectionFailed;
        writer.writeAll("\r\nSec-WebSocket-Version: 13\r\n\r\n") catch return error.ConnectionFailed;
        writer.flush() catch return error.ConnectionFailed;
        // TLS flush only pushes encrypted bytes into net_writer buffer — flush that too
        if (use_tls_param) {
            self.net_writer.interface.flush() catch return error.ConnectionFailed;
        }

        // Read HTTP 101 response — use peek/toss (readVec doesn't work with TLS reader)
        const status_line = reader.peek(13) catch return error.ConnectionFailed;
        if (!std.mem.startsWith(u8, status_line, "HTTP/1.1 101")) {
            return error.UpgradeFailed;
        }

        // Consume all response headers up to \r\n\r\n
        while (true) {
            const buf = reader.buffered();
            if (std.mem.indexOf(u8, buf, "\r\n\r\n")) |end| {
                reader.toss(end + 4);
                break;
            }
            reader.fillMore() catch return error.ConnectionFailed;
        }

        self.connected = true;
    }

    fn getWriter(self: *WsClient) *std.Io.Writer {
        if (self.tls_client) |*tc| {
            return &tc.writer;
        }
        return &self.net_writer.interface;
    }

    fn getReader(self: *WsClient) *std.Io.Reader {
        if (self.tls_client) |*tc| {
            return &tc.reader;
        }
        return self.net_reader.interface();
    }

    pub fn sendText(self: *WsClient, payload: []const u8) !void {
        var frame_buf: [65536]u8 = undefined;
        const frame = try common.ws.writeFrame(&frame_buf, .text, payload, true);

        const writer = self.getWriter();
        writer.writeAll(frame) catch {
            self.connected = false;
            return error.ConnectionLost;
        };
        writer.flush() catch {
            self.connected = false;
            return error.ConnectionLost;
        };
        if (self.use_tls) {
            self.net_writer.interface.flush() catch {
                self.connected = false;
                return error.ConnectionLost;
            };
        }
    }

    pub fn close(self: *WsClient) void {
        if (self.connected) {
            var frame_buf: [128]u8 = undefined;
            const frame = common.ws.writeFrame(&frame_buf, .close, &.{}, true) catch {
                self.net_stream.close();
                self.connected = false;
                return;
            };
            const writer = self.getWriter();
            writer.writeAll(frame) catch {};
            writer.flush() catch {};
            if (self.use_tls) self.net_writer.interface.flush() catch {};
            self.net_stream.close();
            self.connected = false;
        }
    }
};
