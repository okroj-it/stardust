const std = @import("std");
const crypto = std.crypto;
const HmacSha256 = crypto.auth.hmac.sha2.HmacSha256;
const bcrypt = crypto.pwhash.bcrypt;
const base64url = std.base64.url_safe_no_pad;

pub const Auth = struct {
    signing_key: [32]u8,

    // Pre-computed base64url of {"alg":"HS256","typ":"JWT"}
    const header_b64 = blk: {
        const header_json = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
        var buf: [base64url.Encoder.calcSize(header_json.len)]u8 = undefined;
        _ = base64url.Encoder.encode(&buf, header_json);
        break :blk buf;
    };

    /// Hash a password with bcrypt (crypt format, 2^10 rounds).
    pub fn hashPassword(password: []const u8) ![bcrypt.hash_length]u8 {
        var buf: [bcrypt.hash_length]u8 = undefined;
        _ = try bcrypt.strHash(password, .{
            .params = .{ .rounds_log = 10, .silently_truncate_password = false },
            .encoding = .crypt,
        }, &buf);
        return buf;
    }

    /// Verify a password against a bcrypt hash.
    pub fn verifyPassword(hash: []const u8, password: []const u8) bool {
        bcrypt.strVerify(hash, password, .{ .silently_truncate_password = false }) catch return false;
        return true;
    }

    /// Create a signed JWT token for a username (24h expiry).
    pub fn createToken(self: *const Auth, allocator: std.mem.Allocator, username: []const u8) ![]u8 {
        const now = std.time.timestamp();
        const exp = now + 86400; // 24 hours

        // Build payload JSON
        const payload_json = try std.fmt.allocPrint(allocator, "{{\"sub\":\"{s}\",\"iat\":{d},\"exp\":{d}}}", .{ username, now, exp });
        defer allocator.free(payload_json);

        // Base64url encode payload
        const payload_b64_len = base64url.Encoder.calcSize(payload_json.len);
        const payload_b64 = try allocator.alloc(u8, payload_b64_len);
        defer allocator.free(payload_b64);
        _ = base64url.Encoder.encode(payload_b64, payload_json);

        // Build signing input: header.payload
        const signing_input = try std.fmt.allocPrint(allocator, "{s}.{s}", .{ header_b64, payload_b64 });
        defer allocator.free(signing_input);

        // HMAC-SHA256 signature
        var mac: [HmacSha256.mac_length]u8 = undefined;
        HmacSha256.create(&mac, signing_input, &self.signing_key);

        // Base64url encode signature
        var sig_b64: [base64url.Encoder.calcSize(HmacSha256.mac_length)]u8 = undefined;
        _ = base64url.Encoder.encode(&sig_b64, &mac);

        // Final token: header.payload.signature
        return std.fmt.allocPrint(allocator, "{s}.{s}.{s}", .{ header_b64, payload_b64, sig_b64 });
    }

    /// Validate a JWT token: check structure, signature, and expiry.
    pub fn validateToken(self: *const Auth, token: []const u8) bool {
        // Split into 3 parts on '.'
        const dot1 = std.mem.indexOf(u8, token, ".") orelse return false;
        const rest = token[dot1 + 1 ..];
        const dot2 = std.mem.indexOf(u8, rest, ".") orelse return false;

        const header_payload = token[0 .. dot1 + 1 + dot2]; // "header.payload"
        const sig_b64 = rest[dot2 + 1 ..];
        const payload_b64 = token[dot1 + 1 ..][0..dot2];

        // Decode signature
        const sig_len = base64url.Decoder.calcSizeForSlice(sig_b64) catch return false;
        if (sig_len != HmacSha256.mac_length) return false;
        var received_sig: [HmacSha256.mac_length]u8 = undefined;
        base64url.Decoder.decode(&received_sig, sig_b64) catch return false;

        // Recompute HMAC
        var expected_sig: [HmacSha256.mac_length]u8 = undefined;
        HmacSha256.create(&expected_sig, header_payload, &self.signing_key);

        // Constant-time comparison
        if (!std.crypto.timing_safe.eql([HmacSha256.mac_length]u8, received_sig, expected_sig)) return false;

        // Decode payload and check expiry
        const payload_len = base64url.Decoder.calcSizeForSlice(payload_b64) catch return false;
        if (payload_len > 512) return false;
        var payload_buf: [512]u8 = undefined;
        base64url.Decoder.decode(payload_buf[0..payload_len], payload_b64) catch return false;

        // Parse exp from JSON
        const exp = parseExp(payload_buf[0..payload_len]) orelse return false;
        return exp > std.time.timestamp();
    }

    /// Extract the "sub" (username) from a validated token.
    /// Returns a slice into the provided buffer. Token must already be validated.
    pub fn getTokenSubject(self: *const Auth, token: []const u8, buf: []u8) ?[]const u8 {
        _ = self;
        const dot1 = std.mem.indexOf(u8, token, ".") orelse return null;
        const rest = token[dot1 + 1 ..];
        const dot2 = std.mem.indexOf(u8, rest, ".") orelse return null;
        const payload_b64 = token[dot1 + 1 ..][0..dot2];

        const payload_len = base64url.Decoder.calcSizeForSlice(payload_b64) catch return null;
        if (payload_len > buf.len) return null;
        base64url.Decoder.decode(buf[0..payload_len], payload_b64) catch return null;

        return parseString(buf[0..payload_len], "\"sub\":\"");
    }

    /// Extract "exp" value from a JSON payload without full parsing.
    fn parseExp(json: []const u8) ?i64 {
        const key = "\"exp\":";
        const pos = std.mem.indexOf(u8, json, key) orelse return null;
        const after = json[pos + key.len ..];
        var end: usize = 0;
        for (after) |c| {
            if (c >= '0' and c <= '9') {
                end += 1;
            } else if (c == '-' and end == 0) {
                end += 1;
            } else break;
        }
        if (end == 0) return null;
        return std.fmt.parseInt(i64, after[0..end], 10) catch null;
    }

    /// Extract a quoted string value from JSON given a key prefix like `"sub":"`.
    fn parseString(json: []const u8, key: []const u8) ?[]const u8 {
        const pos = std.mem.indexOf(u8, json, key) orelse return null;
        const after = json[pos + key.len ..];
        const end = std.mem.indexOf(u8, after, "\"") orelse return null;
        return after[0..end];
    }
};
