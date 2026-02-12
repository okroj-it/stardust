const std = @import("std");
const Db = @import("db.zig").Db;
const CryptoEngine = @import("crypto.zig").CryptoEngine;
const EncryptedData = @import("crypto.zig").EncryptedData;

pub const SnapshotResult = struct {
    ok: bool,
    packages_json: ?[]const u8 = null,
    services_json: ?[]const u8 = null,
    ports_json: ?[]const u8 = null,
    users_json: ?[]const u8 = null,
    err_msg: ?[]const u8 = null,

    pub fn deinit(self: SnapshotResult, allocator: std.mem.Allocator) void {
        if (self.packages_json) |v| allocator.free(v);
        if (self.services_json) |v| allocator.free(v);
        if (self.ports_json) |v| allocator.free(v);
        if (self.users_json) |v| allocator.free(v);
        if (self.err_msg) |v| allocator.free(v);
    }
};

pub const DriftEngine = struct {
    allocator: std.mem.Allocator,
    db: *Db,
    crypto: *const CryptoEngine,

    pub fn init(allocator: std.mem.Allocator, db: *Db, crypto: *const CryptoEngine) DriftEngine {
        return .{ .allocator = allocator, .db = db, .crypto = crypto };
    }

    /// Take a configuration snapshot of a node via SSH.
    pub fn takeSnapshot(self: *DriftEngine, node_id: []const u8) SnapshotResult {
        const ctx = self.setupSsh(node_id) catch |err| {
            const msg = std.fmt.allocPrint(self.allocator, "SSH setup failed: {}", .{err}) catch "";
            return .{ .ok = false, .err_msg = msg };
        };
        defer ctx.deinit(self);

        // Detect package manager
        const pkg_cmd = self.getPackageCommand(node_id);

        // Collect all categories
        const packages_raw = if (pkg_cmd) |cmd| self.runSshCmd(ctx, cmd) else SshResult{ .ok = true, .output = self.allocator.dupe(u8, "[]") catch "" };
        const services_raw = self.runSshCmd(ctx, "systemctl list-units --type=service --state=running,exited,failed --no-pager --plain --no-legend 2>&1");
        const ports_raw = self.runSshCmd(ctx, "ss -tlnp 2>/dev/null | tail -n +2");
        const users_raw = self.runSshCmd(ctx, "cat /etc/passwd 2>/dev/null");

        // Parse into JSON
        const packages_json = if (packages_raw.ok) self.parsePackages(packages_raw.output) else self.allocator.dupe(u8, "[]") catch null;
        const services_json = if (services_raw.ok) self.parseServices(services_raw.output) else self.allocator.dupe(u8, "[]") catch null;
        const ports_json = if (ports_raw.ok) self.parsePorts(ports_raw.output) else self.allocator.dupe(u8, "[]") catch null;
        const users_json = if (users_raw.ok) self.parseUsers(users_raw.output) else self.allocator.dupe(u8, "[]") catch null;

        // Free raw outputs
        self.allocator.free(packages_raw.output);
        self.allocator.free(services_raw.output);
        self.allocator.free(ports_raw.output);
        self.allocator.free(users_raw.output);

        return .{
            .ok = true,
            .packages_json = packages_json,
            .services_json = services_json,
            .ports_json = ports_json,
            .users_json = users_json,
        };
    }

    fn getPackageCommand(self: *DriftEngine, node_id: []const u8) ?[]const u8 {
        const node = self.db.getNode(self.allocator, node_id) catch return null;
        if (node) |n| {
            defer n.deinit(self.allocator);
            if (n.pkg_manager) |pm| {
                if (std.mem.eql(u8, pm, "apt") or std.mem.eql(u8, pm, "dpkg"))
                    return "dpkg-query -W -f='${Package}\\t${Version}\\n' 2>/dev/null"
                else if (std.mem.eql(u8, pm, "dnf") or std.mem.eql(u8, pm, "yum") or std.mem.eql(u8, pm, "rpm"))
                    return "rpm -qa --queryformat '%{NAME}\\t%{VERSION}-%{RELEASE}\\n' 2>/dev/null"
                else if (std.mem.eql(u8, pm, "pacman"))
                    return "pacman -Q 2>/dev/null"
                else if (std.mem.eql(u8, pm, "apk"))
                    return "apk list -I 2>/dev/null";
            }
        }
        // Fallback: try dpkg
        return "dpkg-query -W -f='${Package}\\t${Version}\\n' 2>/dev/null || rpm -qa --queryformat '%{NAME}\\t%{VERSION}-%{RELEASE}\\n' 2>/dev/null || pacman -Q 2>/dev/null || echo '[]'";
    }

    // --- Parsers ---

    fn parsePackages(self: *DriftEngine, raw: []const u8) ?[]const u8 {
        var buf: std.ArrayListUnmanaged(u8) = .{};
        const w = buf.writer(self.allocator);
        w.writeByte('[') catch return null;
        var first = true;
        var lines = std.mem.splitScalar(u8, raw, '\n');
        while (lines.next()) |line| {
            if (line.len == 0) continue;
            var parts = std.mem.splitScalar(u8, line, '\t');
            const name = parts.next() orelse continue;
            const version = parts.next() orelse "";
            if (name.len == 0) continue;
            if (!first) w.writeByte(',') catch {};
            first = false;
            w.writeAll("{\"name\":") catch {};
            writeJsonStr(w, name);
            w.writeAll(",\"version\":") catch {};
            writeJsonStr(w, version);
            w.writeByte('}') catch {};
        }
        w.writeByte(']') catch {};
        return buf.toOwnedSlice(self.allocator) catch null;
    }

    fn parseServices(self: *DriftEngine, raw: []const u8) ?[]const u8 {
        var buf: std.ArrayListUnmanaged(u8) = .{};
        const w = buf.writer(self.allocator);
        w.writeByte('[') catch return null;
        var first = true;
        var lines = std.mem.splitScalar(u8, raw, '\n');
        while (lines.next()) |line| {
            if (line.len == 0) continue;
            var it = std.mem.tokenizeScalar(u8, line, ' ');
            const name = it.next() orelse continue;
            _ = it.next(); // load_state
            const active = it.next() orelse "";
            const sub = it.next() orelse "";
            if (!first) w.writeByte(',') catch {};
            first = false;
            w.writeAll("{\"name\":") catch {};
            writeJsonStr(w, name);
            w.writeAll(",\"state\":") catch {};
            writeJsonStr(w, active);
            w.writeAll(",\"sub_state\":") catch {};
            writeJsonStr(w, sub);
            w.writeByte('}') catch {};
        }
        w.writeByte(']') catch {};
        return buf.toOwnedSlice(self.allocator) catch null;
    }

    fn parsePorts(self: *DriftEngine, raw: []const u8) ?[]const u8 {
        var buf: std.ArrayListUnmanaged(u8) = .{};
        const w = buf.writer(self.allocator);
        w.writeByte('[') catch return null;
        var first = true;
        var lines = std.mem.splitScalar(u8, raw, '\n');
        while (lines.next()) |line| {
            if (line.len == 0) continue;
            var it = std.mem.tokenizeScalar(u8, line, ' ');
            _ = it.next(); // state
            _ = it.next(); // recv-q
            _ = it.next(); // send-q
            const local = it.next() orelse continue;
            _ = it.next(); // peer
            const addr_port = parseAddrPort(local);
            if (!first) w.writeByte(',') catch {};
            first = false;
            w.writeAll("{\"proto\":\"tcp\",\"address\":") catch {};
            writeJsonStr(w, addr_port.addr);
            w.writeAll(",\"port\":") catch {};
            writeJsonStr(w, addr_port.port);
            w.writeByte('}') catch {};
        }
        w.writeByte(']') catch {};
        return buf.toOwnedSlice(self.allocator) catch null;
    }

    fn parseUsers(self: *DriftEngine, raw: []const u8) ?[]const u8 {
        var buf: std.ArrayListUnmanaged(u8) = .{};
        const w = buf.writer(self.allocator);
        w.writeByte('[') catch return null;
        var first = true;
        var lines = std.mem.splitScalar(u8, raw, '\n');
        while (lines.next()) |line| {
            if (line.len == 0) continue;
            var parts = std.mem.splitScalar(u8, line, ':');
            const name = parts.next() orelse continue;
            _ = parts.next(); // x
            const uid = parts.next() orelse "";
            const gid = parts.next() orelse "";
            _ = parts.next(); // gecos
            const home = parts.next() orelse "";
            const shell = parts.next() orelse "";
            if (!first) w.writeByte(',') catch {};
            first = false;
            w.writeAll("{\"name\":") catch {};
            writeJsonStr(w, name);
            w.writeAll(",\"uid\":") catch {};
            writeJsonStr(w, uid);
            w.writeAll(",\"gid\":") catch {};
            writeJsonStr(w, gid);
            w.writeAll(",\"home\":") catch {};
            writeJsonStr(w, home);
            w.writeAll(",\"shell\":") catch {};
            writeJsonStr(w, shell);
            w.writeByte('}') catch {};
        }
        w.writeByte(']') catch {};
        return buf.toOwnedSlice(self.allocator) catch null;
    }

    const AddrPort = struct { addr: []const u8, port: []const u8 };

    fn parseAddrPort(local: []const u8) AddrPort {
        // Handle IPv6 bracket notation [::]:port
        if (std.mem.indexOf(u8, local, "]:")) |idx| {
            return .{ .addr = local[0 .. idx + 1], .port = local[idx + 2 ..] };
        }
        // Handle IPv4 addr:port (last colon)
        if (std.mem.lastIndexOfScalar(u8, local, ':')) |idx| {
            return .{ .addr = local[0..idx], .port = local[idx + 1 ..] };
        }
        return .{ .addr = local, .port = "" };
    }

    // --- SSH helpers (same pattern as services.zig) ---

    const SshResult = struct {
        ok: bool,
        output: []const u8,
    };

    fn runSshCmd(self: *DriftEngine, ctx: SshContext, command: []const u8) SshResult {
        const result = std.process.Child.run(.{
            .allocator = self.allocator,
            .argv = &.{
                "ssh", "-i", ctx.tmp_key_path, "-p", ctx.port_str,
                "-o", "StrictHostKeyChecking=no", "-o", "BatchMode=yes",
                "-o", "ConnectTimeout=10",
                ctx.host_arg, command,
            },
            .max_output_bytes = 512 * 1024,
        }) catch |err| {
            const msg = std.fmt.allocPrint(self.allocator, "SSH command failed: {}", .{err}) catch "";
            return .{ .ok = false, .output = msg };
        };
        self.allocator.free(result.stderr);
        return .{ .ok = result.term.Exited == 0, .output = result.stdout };
    }

    const SshContext = struct {
        tmp_key_path: []const u8,
        host_arg: []const u8,
        port_str: []const u8,
        ssh_key: []u8,

        fn deinit(self: SshContext, engine: *DriftEngine) void {
            std.fs.cwd().deleteFile(self.tmp_key_path) catch {};
            engine.allocator.free(self.tmp_key_path);
            engine.allocator.free(self.host_arg);
            engine.allocator.free(self.port_str);
            std.crypto.secureZero(u8, self.ssh_key);
            engine.allocator.free(self.ssh_key);
        }
    };

    fn setupSsh(self: *DriftEngine, node_id: []const u8) !SshContext {
        const node = (try self.db.getNode(self.allocator, node_id)) orelse return error.NodeNotFound;
        defer node.deinit(self.allocator);

        const ssh_key = try self.decryptField(node.ssh_key_enc, node.ssh_key_nonce, node.ssh_key_tag);
        errdefer {
            std.crypto.secureZero(u8, ssh_key);
            self.allocator.free(ssh_key);
        }

        const tmp_key_path = try std.fmt.allocPrint(self.allocator, "/tmp/stardust_drift_{s}", .{node_id});
        errdefer self.allocator.free(tmp_key_path);

        {
            const file = try std.fs.cwd().createFile(tmp_key_path, .{ .mode = 0o600 });
            defer file.close();
            try file.writeAll(ssh_key);
        }

        const host_arg = try std.fmt.allocPrint(self.allocator, "{s}@{s}", .{ node.ssh_user, node.host });
        errdefer self.allocator.free(host_arg);

        const port_str = try std.fmt.allocPrint(self.allocator, "{d}", .{node.port});

        return .{
            .tmp_key_path = tmp_key_path,
            .host_arg = host_arg,
            .port_str = port_str,
            .ssh_key = ssh_key,
        };
    }

    fn decryptField(self: *DriftEngine, enc: []const u8, nonce: []const u8, tag: []const u8) ![]u8 {
        if (nonce.len < 12 or tag.len < 16) return error.InvalidEncryptedData;
        return try self.crypto.decrypt(self.allocator, .{
            .ciphertext = enc,
            .nonce = nonce[0..12].*,
            .tag = tag[0..16].*,
            .salt = [_]u8{0} ** 16,
        });
    }
};

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
