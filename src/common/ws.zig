const std = @import("std");

pub const Opcode = enum(u4) {
    continuation = 0x0,
    text = 0x1,
    binary = 0x2,
    close = 0x8,
    ping = 0x9,
    pong = 0xA,
    _,
};

pub const Frame = struct {
    fin: bool,
    opcode: Opcode,
    payload: []const u8,
};

const WS_MAGIC = "258EAFA5-E914-47DA-95AB-5CC9F31CB4EB";

/// Compute the Sec-WebSocket-Accept value from a Sec-WebSocket-Key
pub fn computeAcceptKey(ws_key: []const u8, out: *[28]u8) void {
    var hasher = std.crypto.hash.Sha1.init(.{});
    hasher.update(ws_key);
    hasher.update(WS_MAGIC);
    const hash = hasher.finalResult();
    _ = std.base64.standard.Encoder.encode(out, &hash);
}

/// Write a WebSocket frame. Client frames must be masked.
pub fn writeFrame(buf: []u8, opcode: Opcode, payload: []const u8, mask: bool) ![]const u8 {
    var pos: usize = 0;

    // Byte 0: FIN + opcode
    buf[pos] = 0x80 | @as(u8, @intFromEnum(opcode));
    pos += 1;

    // Byte 1: mask bit + payload length
    const mask_bit: u8 = if (mask) 0x80 else 0x00;
    if (payload.len < 126) {
        buf[pos] = mask_bit | @as(u8, @intCast(payload.len));
        pos += 1;
    } else if (payload.len <= 65535) {
        buf[pos] = mask_bit | 126;
        pos += 1;
        buf[pos] = @intCast(payload.len >> 8);
        buf[pos + 1] = @intCast(payload.len & 0xFF);
        pos += 2;
    } else {
        buf[pos] = mask_bit | 127;
        pos += 1;
        inline for (0..8) |i| {
            buf[pos + i] = @intCast((payload.len >> @intCast(56 - i * 8)) & 0xFF);
        }
        pos += 8;
    }

    if (mask) {
        var mask_key: [4]u8 = undefined;
        std.crypto.random.bytes(&mask_key);
        @memcpy(buf[pos..][0..4], &mask_key);
        pos += 4;
        for (payload, 0..) |byte, i| {
            buf[pos + i] = byte ^ mask_key[i % 4];
        }
    } else {
        @memcpy(buf[pos..][0..payload.len], payload);
    }
    pos += payload.len;

    return buf[0..pos];
}

/// Read a WebSocket frame from raw bytes. Returns the frame and bytes consumed.
pub fn readFrame(data: []const u8, payload_buf: []u8) !struct { frame: Frame, consumed: usize } {
    if (data.len < 2) return error.NeedMoreData;

    const fin = (data[0] & 0x80) != 0;
    const opcode: Opcode = @enumFromInt(@as(u4, @truncate(data[0] & 0x0F)));
    const masked = (data[1] & 0x80) != 0;
    var payload_len: u64 = data[1] & 0x7F;
    var pos: usize = 2;

    if (payload_len == 126) {
        if (data.len < 4) return error.NeedMoreData;
        payload_len = (@as(u16, data[2]) << 8) | data[3];
        pos = 4;
    } else if (payload_len == 127) {
        if (data.len < 10) return error.NeedMoreData;
        payload_len = 0;
        inline for (0..8) |i| {
            payload_len = (payload_len << 8) | data[2 + i];
        }
        pos = 10;
    }

    var mask_key: [4]u8 = .{ 0, 0, 0, 0 };
    if (masked) {
        if (data.len < pos + 4) return error.NeedMoreData;
        @memcpy(&mask_key, data[pos..][0..4]);
        pos += 4;
    }

    const total_len = pos + @as(usize, @intCast(payload_len));
    if (data.len < total_len) return error.NeedMoreData;
    if (payload_len > payload_buf.len) return error.PayloadTooLarge;

    const plen: usize = @intCast(payload_len);
    @memcpy(payload_buf[0..plen], data[pos..][0..plen]);

    if (masked) {
        for (payload_buf[0..plen], 0..) |*byte, i| {
            byte.* ^= mask_key[i % 4];
        }
    }

    return .{
        .frame = .{
            .fin = fin,
            .opcode = opcode,
            .payload = payload_buf[0..plen],
        },
        .consumed = total_len,
    };
}
