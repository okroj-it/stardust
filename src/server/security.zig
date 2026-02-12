const std = @import("std");
const Db = @import("db.zig").Db;
const CryptoEngine = @import("crypto.zig").CryptoEngine;

pub const ScanResult = struct {
    ok: bool,
    score: u8 = 0,
    upgradable_json: ?[]const u8 = null,
    ssh_config_json: ?[]const u8 = null,
    ports_json: ?[]const u8 = null,
    firewall_json: ?[]const u8 = null,
    autoupdate_json: ?[]const u8 = null,
    err_msg: ?[]const u8 = null,

    pub fn deinit(self: ScanResult, allocator: std.mem.Allocator) void {
        if (self.upgradable_json) |v| allocator.free(v);
        if (self.ssh_config_json) |v| allocator.free(v);
        if (self.ports_json) |v| allocator.free(v);
        if (self.firewall_json) |v| allocator.free(v);
        if (self.autoupdate_json) |v| allocator.free(v);
        if (self.err_msg) |v| allocator.free(v);
    }
};

pub const SecurityEngine = struct {
    allocator: std.mem.Allocator,
    db: *Db,
    crypto: *const CryptoEngine,

    pub fn init(allocator: std.mem.Allocator, db: *Db, crypto: *const CryptoEngine) SecurityEngine {
        return .{ .allocator = allocator, .db = db, .crypto = crypto };
    }

    /// Run a full security posture scan on a node via SSH.
    pub fn scanNode(self: *SecurityEngine, node_id: []const u8) ScanResult {
        const ctx = self.setupSsh(node_id) catch |err| {
            const msg = std.fmt.allocPrint(self.allocator, "SSH setup failed: {}", .{err}) catch "";
            return .{ .ok = false, .err_msg = msg };
        };
        defer ctx.deinit(self);

        // 1. Upgradable packages
        const pkg_cmd = self.getUpgradeCheckCommand(node_id);
        const upgradable_raw = if (pkg_cmd) |cmd| self.runSshCmd(ctx, cmd) else SshResult{ .ok = true, .output = self.allocator.dupe(u8, "") catch "" };
        defer self.allocator.free(upgradable_raw.output);
        const upgradable_json = if (upgradable_raw.ok) self.parseUpgradable(upgradable_raw.output, node_id) else self.allocator.dupe(u8, "[]") catch null;

        // 2. SSH config
        const sshd_raw = self.runSshCmd(ctx, "sshd -T 2>/dev/null");
        defer self.allocator.free(sshd_raw.output);
        const ssh_config_json = if (sshd_raw.ok and sshd_raw.output.len > 0) self.parseSshConfig(sshd_raw.output) else self.allocator.dupe(u8, "[]") catch null;

        // 3. Open ports (with process names)
        const ports_raw = self.runSshCmd(ctx, "ss -tlnp 2>/dev/null | tail -n +2");
        defer self.allocator.free(ports_raw.output);
        const ports_json = if (ports_raw.ok) self.parsePorts(ports_raw.output) else self.allocator.dupe(u8, "[]") catch null;

        // 4. Firewall
        const fw_raw = self.runSshCmd(ctx, "ufw status verbose 2>/dev/null || firewall-cmd --list-all 2>/dev/null || iptables -L -n --line-numbers 2>/dev/null || echo 'NO_FIREWALL'");
        defer self.allocator.free(fw_raw.output);
        const firewall_json = self.parseFirewall(fw_raw.output);

        // 5. Auto-updates
        const au_raw = self.runSshCmd(ctx, "{ dpkg -l unattended-upgrades 2>/dev/null | grep '^ii' && cat /etc/apt/apt.conf.d/20auto-upgrades 2>/dev/null; } || { systemctl is-active dnf-automatic.timer 2>/dev/null; } || echo 'NOT_CONFIGURED'");
        defer self.allocator.free(au_raw.output);
        const autoupdate_json = self.parseAutoUpdate(au_raw.output);

        // Compute score
        const score = computeScore(upgradable_json, ssh_config_json, firewall_json, autoupdate_json);

        return .{
            .ok = true,
            .score = score,
            .upgradable_json = upgradable_json,
            .ssh_config_json = ssh_config_json,
            .ports_json = ports_json,
            .firewall_json = firewall_json,
            .autoupdate_json = autoupdate_json,
        };
    }

    // --- Parsers ---

    fn getUpgradeCheckCommand(self: *SecurityEngine, node_id: []const u8) ?[]const u8 {
        const node = self.db.getNode(self.allocator, node_id) catch return null;
        if (node) |n| {
            defer n.deinit(self.allocator);
            if (n.pkg_manager) |pm| {
                if (std.mem.eql(u8, pm, "apt") or std.mem.eql(u8, pm, "dpkg"))
                    return "apt list --upgradable 2>/dev/null | tail -n +2"
                else if (std.mem.eql(u8, pm, "dnf") or std.mem.eql(u8, pm, "yum"))
                    return "dnf check-update 2>/dev/null; true"
                else if (std.mem.eql(u8, pm, "pacman"))
                    return "pacman -Qu 2>/dev/null"
                else if (std.mem.eql(u8, pm, "apk"))
                    return "apk upgrade -s 2>/dev/null | grep '^(1/' 2>/dev/null || apk version -l '<' 2>/dev/null";
            }
        }
        return "apt list --upgradable 2>/dev/null | tail -n +2 || dnf check-update 2>/dev/null; true";
    }

    fn parseUpgradable(self: *SecurityEngine, raw: []const u8, node_id: []const u8) ?[]const u8 {
        // Detect package manager to choose parser
        const node = self.db.getNode(self.allocator, node_id) catch return self.allocator.dupe(u8, "[]") catch null;
        const pm: []const u8 = if (node) |n| blk: {
            defer n.deinit(self.allocator);
            break :blk if (n.pkg_manager) |p| self.allocator.dupe(u8, p) catch "apt" else "apt";
        } else "apt";
        defer if (node != null) self.allocator.free(pm);

        var buf: std.ArrayListUnmanaged(u8) = .{};
        const w = buf.writer(self.allocator);
        w.writeByte('[') catch return null;
        var first = true;
        var lines = std.mem.splitScalar(u8, raw, '\n');

        while (lines.next()) |line| {
            if (line.len == 0) continue;

            var name: []const u8 = "";
            var current: []const u8 = "";
            var available: []const u8 = "";

            if (std.mem.eql(u8, pm, "apt") or std.mem.eql(u8, pm, "dpkg")) {
                // apt format: "package/suite version arch [upgradable from: old_version]"
                var it = std.mem.splitScalar(u8, line, '/');
                name = it.next() orelse continue;
                const rest = it.rest();
                // Extract available version (first space-separated token after /)
                var rest_it = std.mem.tokenizeScalar(u8, rest, ' ');
                _ = rest_it.next(); // suite
                available = rest_it.next() orelse "";
                // Find "from:" to get current version
                while (rest_it.next()) |tok| {
                    if (std.mem.eql(u8, tok, "from:")) {
                        const cur = rest_it.next() orelse "";
                        // Strip trailing ]
                        current = if (cur.len > 0 and cur[cur.len - 1] == ']') cur[0 .. cur.len - 1] else cur;
                        break;
                    }
                }
            } else if (std.mem.eql(u8, pm, "dnf") or std.mem.eql(u8, pm, "yum")) {
                // dnf format: "package.arch    version    repo"
                var it = std.mem.tokenizeScalar(u8, line, ' ');
                const pkg_arch = it.next() orelse continue;
                available = it.next() orelse "";
                // Split package.arch
                if (std.mem.lastIndexOfScalar(u8, pkg_arch, '.')) |dot| {
                    name = pkg_arch[0..dot];
                } else {
                    name = pkg_arch;
                }
                current = ""; // dnf check-update doesn't show current version
            } else if (std.mem.eql(u8, pm, "pacman")) {
                // pacman format: "package old_version -> new_version"
                var it = std.mem.tokenizeScalar(u8, line, ' ');
                name = it.next() orelse continue;
                current = it.next() orelse "";
                _ = it.next(); // ->
                available = it.next() orelse "";
            } else {
                // Generic: try tab-separated
                var it = std.mem.splitScalar(u8, line, '\t');
                name = it.next() orelse continue;
                current = it.next() orelse "";
                available = it.next() orelse "";
            }

            if (name.len == 0) continue;
            if (!first) w.writeByte(',') catch {};
            first = false;
            w.writeAll("{\"name\":") catch {};
            writeJsonStr(w, name);
            w.writeAll(",\"current\":") catch {};
            writeJsonStr(w, current);
            w.writeAll(",\"available\":") catch {};
            writeJsonStr(w, available);
            w.writeByte('}') catch {};
        }

        w.writeByte(']') catch {};
        return buf.toOwnedSlice(self.allocator) catch null;
    }

    fn parseSshConfig(self: *SecurityEngine, raw: []const u8) ?[]const u8 {
        // sshd -T outputs lines like "passwordauthentication yes"
        const checks = [_]SshCheck{
            .{ .key = "passwordauthentication", .label = "PasswordAuthentication", .good = "no", .status_bad = "fail", .detail_bad = "Password auth is enabled — use key-based auth only", .detail_good = "Password auth disabled" },
            .{ .key = "permitrootlogin", .label = "PermitRootLogin", .good = "no", .status_bad = "fail", .detail_bad = "Root login is permitted — disable or restrict to keys only", .detail_good = "Root login disabled" },
            .{ .key = "pubkeyauthentication", .label = "PubkeyAuthentication", .good = "yes", .status_bad = "fail", .detail_bad = "Public key authentication is disabled", .detail_good = "Public key auth enabled" },
            .{ .key = "x11forwarding", .label = "X11Forwarding", .good = "no", .status_bad = "warn", .detail_bad = "X11 forwarding is enabled — unnecessary attack surface", .detail_good = "X11 forwarding disabled" },
            .{ .key = "permitemptypasswords", .label = "PermitEmptyPasswords", .good = "no", .status_bad = "fail", .detail_bad = "Empty passwords are permitted — critical vulnerability", .detail_good = "Empty passwords not permitted" },
            .{ .key = "maxauthtries", .label = "MaxAuthTries", .good = null, .status_bad = "warn", .detail_bad = "", .detail_good = "" }, // special handling
        };

        // Build a map of key -> value from sshd -T output
        var config_map: [16]struct { key: []const u8, value: []const u8 } = undefined;
        var config_count: usize = 0;

        var lines = std.mem.splitScalar(u8, raw, '\n');
        while (lines.next()) |line| {
            if (line.len == 0) continue;
            // Format: "key value"
            if (std.mem.indexOfScalar(u8, line, ' ')) |sp| {
                const key = line[0..sp];
                const value = line[sp + 1 ..];
                // Check if this is a key we care about
                for (checks) |check| {
                    if (std.mem.eql(u8, key, check.key)) {
                        if (config_count < config_map.len) {
                            config_map[config_count] = .{ .key = key, .value = value };
                            config_count += 1;
                        }
                        break;
                    }
                }
            }
        }

        // Generate JSON
        var buf: std.ArrayListUnmanaged(u8) = .{};
        const w = buf.writer(self.allocator);
        w.writeByte('[') catch return null;
        var first = true;

        for (checks) |check| {
            // Find value in our map
            var value: []const u8 = "unknown";
            for (config_map[0..config_count]) |entry| {
                if (std.mem.eql(u8, entry.key, check.key)) {
                    value = entry.value;
                    break;
                }
            }

            var status: []const u8 = "pass";
            var detail: []const u8 = check.detail_good;

            if (std.mem.eql(u8, check.key, "maxauthtries")) {
                // Special handling for numeric check
                const tries = std.fmt.parseInt(u32, value, 10) catch 6;
                if (tries > 6) {
                    status = "warn";
                    detail = "MaxAuthTries is high — consider lowering to 3-6";
                } else {
                    detail = "MaxAuthTries is reasonable";
                }
            } else if (check.good) |good| {
                if (!std.mem.eql(u8, value, good)) {
                    // permitrootlogin "prohibit-password" is acceptable
                    if (std.mem.eql(u8, check.key, "permitrootlogin") and std.mem.eql(u8, value, "prohibit-password")) {
                        status = "pass";
                        detail = "Root login limited to key-based auth only";
                    } else {
                        status = check.status_bad;
                        detail = check.detail_bad;
                    }
                }
            }

            if (!first) w.writeByte(',') catch {};
            first = false;
            w.writeAll("{\"key\":") catch {};
            writeJsonStr(w, check.label);
            w.writeAll(",\"value\":") catch {};
            writeJsonStr(w, value);
            w.writeAll(",\"status\":") catch {};
            writeJsonStr(w, status);
            w.writeAll(",\"detail\":") catch {};
            writeJsonStr(w, detail);
            w.writeByte('}') catch {};
        }

        w.writeByte(']') catch {};
        return buf.toOwnedSlice(self.allocator) catch null;
    }

    const SshCheck = struct {
        key: []const u8,
        label: []const u8,
        good: ?[]const u8,
        status_bad: []const u8,
        detail_bad: []const u8,
        detail_good: []const u8,
    };

    fn parsePorts(self: *SecurityEngine, raw: []const u8) ?[]const u8 {
        var buf: std.ArrayListUnmanaged(u8) = .{};
        const w = buf.writer(self.allocator);
        w.writeByte('[') catch return null;
        var first = true;
        var lines_iter = std.mem.splitScalar(u8, raw, '\n');

        while (lines_iter.next()) |line| {
            if (line.len == 0) continue;
            var it = std.mem.tokenizeScalar(u8, line, ' ');
            _ = it.next(); // state
            _ = it.next(); // recv-q
            _ = it.next(); // send-q
            const local = it.next() orelse continue;
            _ = it.next(); // peer
            // Remaining tokens may contain process info like users:(("sshd",pid=1234,fd=3))
            var process: []const u8 = "";
            while (it.next()) |tok| {
                if (std.mem.startsWith(u8, tok, "users:((\"")) {
                    // Extract process name from users:(("name",...))
                    const start = "users:((\"".len;
                    if (std.mem.indexOfScalar(u8, tok[start..], '"')) |end| {
                        process = tok[start .. start + end];
                    }
                    break;
                }
            }

            const addr_port = parseAddrPort(local);
            if (!first) w.writeByte(',') catch {};
            first = false;
            w.writeAll("{\"proto\":\"tcp\",\"address\":") catch {};
            writeJsonStr(w, addr_port.addr);
            w.writeAll(",\"port\":") catch {};
            writeJsonStr(w, addr_port.port);
            w.writeAll(",\"process\":") catch {};
            writeJsonStr(w, process);
            w.writeByte('}') catch {};
        }

        w.writeByte(']') catch {};
        return buf.toOwnedSlice(self.allocator) catch null;
    }

    fn parseFirewall(self: *SecurityEngine, raw: []const u8) ?[]const u8 {
        var buf: std.ArrayListUnmanaged(u8) = .{};
        const w = buf.writer(self.allocator);

        // Detect firewall type from output
        if (std.mem.indexOf(u8, raw, "NO_FIREWALL") != null or raw.len == 0) {
            w.writeAll("{\"active\":false,\"type\":\"none\",\"rules\":") catch return null;
            writeJsonStr(w, "No firewall detected");
            w.writeByte('}') catch {};
        } else if (std.mem.indexOf(u8, raw, "Status: active") != null or std.mem.indexOf(u8, raw, "Status: inactive") != null) {
            // UFW
            const active = std.mem.indexOf(u8, raw, "Status: active") != null;
            w.writeAll("{\"active\":") catch return null;
            w.writeAll(if (active) "true" else "false") catch {};
            w.writeAll(",\"type\":\"ufw\",\"rules\":") catch {};
            writeJsonStr(w, raw);
            w.writeByte('}') catch {};
        } else if (std.mem.indexOf(u8, raw, "firewalld") != null or std.mem.indexOf(u8, raw, "target:") != null or std.mem.indexOf(u8, raw, "services:") != null) {
            // firewalld
            w.writeAll("{\"active\":true,\"type\":\"firewalld\",\"rules\":") catch return null;
            writeJsonStr(w, raw);
            w.writeByte('}') catch {};
        } else if (std.mem.indexOf(u8, raw, "Chain") != null) {
            // iptables
            // Check if there are any non-default rules
            const has_rules = std.mem.indexOf(u8, raw, "ACCEPT") != null or std.mem.indexOf(u8, raw, "DROP") != null or std.mem.indexOf(u8, raw, "REJECT") != null;
            w.writeAll("{\"active\":") catch return null;
            w.writeAll(if (has_rules) "true" else "false") catch {};
            w.writeAll(",\"type\":\"iptables\",\"rules\":") catch {};
            writeJsonStr(w, raw);
            w.writeByte('}') catch {};
        } else {
            w.writeAll("{\"active\":false,\"type\":\"unknown\",\"rules\":") catch return null;
            writeJsonStr(w, raw);
            w.writeByte('}') catch {};
        }

        return buf.toOwnedSlice(self.allocator) catch null;
    }

    fn parseAutoUpdate(self: *SecurityEngine, raw: []const u8) ?[]const u8 {
        var buf: std.ArrayListUnmanaged(u8) = .{};
        const w = buf.writer(self.allocator);

        if (std.mem.indexOf(u8, raw, "NOT_CONFIGURED") != null or raw.len == 0) {
            w.writeAll("{\"enabled\":false,\"package\":\"none\",\"detail\":") catch return null;
            writeJsonStr(w, "No automatic updates configured");
            w.writeByte('}') catch {};
        } else if (std.mem.indexOf(u8, raw, "unattended-upgrades") != null) {
            // Check if actually enabled in config
            const enabled = std.mem.indexOf(u8, raw, "\"1\"") != null;
            w.writeAll("{\"enabled\":") catch return null;
            w.writeAll(if (enabled) "true" else "false") catch {};
            w.writeAll(",\"package\":\"unattended-upgrades\",\"detail\":") catch {};
            writeJsonStr(w, raw);
            w.writeByte('}') catch {};
        } else if (std.mem.indexOf(u8, raw, "active") != null) {
            // dnf-automatic timer is active
            w.writeAll("{\"enabled\":true,\"package\":\"dnf-automatic\",\"detail\":") catch return null;
            writeJsonStr(w, raw);
            w.writeByte('}') catch {};
        } else {
            w.writeAll("{\"enabled\":false,\"package\":\"unknown\",\"detail\":") catch return null;
            writeJsonStr(w, raw);
            w.writeByte('}') catch {};
        }

        return buf.toOwnedSlice(self.allocator) catch null;
    }

    // --- Scoring ---

    fn computeScore(upgradable_json: ?[]const u8, ssh_config_json: ?[]const u8, firewall_json: ?[]const u8, autoupdate_json: ?[]const u8) u8 {
        var score: u8 = 0;

        // Upgradable packages (max 25)
        if (upgradable_json) |uj| {
            const count = countJsonArrayItems(uj);
            if (count == 0) {
                score += 25;
            } else if (count <= 10) {
                score += 15;
            } else if (count <= 50) {
                score += 5;
            }
        }

        // SSH config checks (max 35)
        if (ssh_config_json) |sj| {
            // Count pass/fail statuses
            var pos: usize = 0;
            while (pos < sj.len) {
                if (std.mem.indexOf(u8, sj[pos..], "\"status\":\"pass\"")) |idx| {
                    // Determine which check this is by looking backwards for "key"
                    const abs_pos = pos + idx;
                    // Find the preceding key
                    if (findPrecedingKey(sj, abs_pos)) |key| {
                        if (std.mem.eql(u8, key, "PasswordAuthentication")) {
                            score += 10;
                        } else if (std.mem.eql(u8, key, "PermitRootLogin")) {
                            score += 10;
                        } else if (std.mem.eql(u8, key, "PubkeyAuthentication")) {
                            score += 5;
                        } else if (std.mem.eql(u8, key, "PermitEmptyPasswords")) {
                            score += 5;
                        } else if (std.mem.eql(u8, key, "X11Forwarding")) {
                            score += 5;
                        }
                    }
                    pos = abs_pos + 15;
                } else break;
            }
        }

        // Firewall (max 20)
        if (firewall_json) |fj| {
            if (std.mem.indexOf(u8, fj, "\"active\":true") != null) {
                score += 20;
            }
        }

        // Auto-updates (max 20)
        if (autoupdate_json) |aj| {
            if (std.mem.indexOf(u8, aj, "\"enabled\":true") != null) {
                score += 20;
            }
        }

        return score;
    }

    fn findPrecedingKey(json: []const u8, pos: usize) ?[]const u8 {
        // Search backwards from pos for "key":"VALUE"
        const search = "\"key\":\"";
        var search_start: usize = 0;
        var last_match: ?usize = null;
        while (search_start < pos) {
            if (std.mem.indexOf(u8, json[search_start..pos], search)) |idx| {
                last_match = search_start + idx;
                search_start = search_start + idx + search.len;
            } else break;
        }
        if (last_match) |m| {
            const key_start = m + search.len;
            if (key_start < json.len) {
                if (std.mem.indexOfScalar(u8, json[key_start..], '"')) |end| {
                    return json[key_start .. key_start + end];
                }
            }
        }
        return null;
    }

    fn countJsonArrayItems(json: []const u8) usize {
        if (json.len < 3) return 0; // "[]" or less
        if (std.mem.eql(u8, json, "[]")) return 0;
        // Count opening braces as a proxy for object count
        var count: usize = 0;
        var in_string = false;
        var escape = false;
        for (json) |c| {
            if (escape) {
                escape = false;
                continue;
            }
            if (c == '\\') {
                escape = true;
                continue;
            }
            if (c == '"') {
                in_string = !in_string;
                continue;
            }
            if (!in_string and c == '{') {
                count += 1;
            }
        }
        return count;
    }

    // --- Address parsing ---

    const AddrPort = struct { addr: []const u8, port: []const u8 };

    fn parseAddrPort(local: []const u8) AddrPort {
        if (std.mem.indexOf(u8, local, "]:")) |idx| {
            return .{ .addr = local[0 .. idx + 1], .port = local[idx + 2 ..] };
        }
        if (std.mem.lastIndexOfScalar(u8, local, ':')) |idx| {
            return .{ .addr = local[0..idx], .port = local[idx + 1 ..] };
        }
        return .{ .addr = local, .port = "" };
    }

    // --- SSH helpers (same pattern as processes.zig with sudo support) ---

    const SshResult = struct {
        ok: bool,
        output: []const u8,
    };

    fn runSshCmd(self: *SecurityEngine, ctx: SshContext, command: []const u8) SshResult {
        // Wrap with sudo
        const wrapped = if (ctx.sudo_pass) |pass|
            std.fmt.allocPrint(self.allocator, "echo '{s}' | sudo -S -p '' sh -c '{s}' 2>&1", .{ pass, command }) catch
                return .{ .ok = false, .output = "" }
        else
            std.fmt.allocPrint(self.allocator, "sudo -p '' sh -c '{s}' 2>&1", .{command}) catch
                return .{ .ok = false, .output = "" };
        defer self.allocator.free(wrapped);

        const result = std.process.Child.run(.{
            .allocator = self.allocator,
            .argv = &.{
                "ssh", "-i", ctx.tmp_key_path, "-p", ctx.port_str,
                "-o", "StrictHostKeyChecking=no", "-o", "BatchMode=yes",
                "-o", "ConnectTimeout=10",
                ctx.host_arg, wrapped,
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
        sudo_pass: ?[]u8,

        fn deinit(self: SshContext, engine: *SecurityEngine) void {
            std.fs.cwd().deleteFile(self.tmp_key_path) catch {};
            engine.allocator.free(self.tmp_key_path);
            engine.allocator.free(self.host_arg);
            engine.allocator.free(self.port_str);
            std.crypto.secureZero(u8, self.ssh_key);
            engine.allocator.free(self.ssh_key);
            if (self.sudo_pass) |p| {
                std.crypto.secureZero(u8, @constCast(p));
                engine.allocator.free(p);
            }
        }
    };

    fn setupSsh(self: *SecurityEngine, node_id: []const u8) !SshContext {
        const node = (try self.db.getNode(self.allocator, node_id)) orelse return error.NodeNotFound;
        defer node.deinit(self.allocator);

        const ssh_key = try self.decryptField(node.ssh_key_enc, node.ssh_key_nonce, node.ssh_key_tag);
        errdefer {
            std.crypto.secureZero(u8, ssh_key);
            self.allocator.free(ssh_key);
        }

        var sudo_pass: ?[]u8 = null;
        if (node.sudo_pass_enc) |enc| {
            if (node.sudo_pass_nonce) |nonce| {
                if (node.sudo_pass_tag) |tag| {
                    sudo_pass = self.decryptField(enc, nonce, tag) catch null;
                }
            }
        }

        const tmp_key_path = try std.fmt.allocPrint(self.allocator, "/tmp/stardust_sec_{s}", .{node_id});
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
            .sudo_pass = sudo_pass,
        };
    }

    fn decryptField(self: *SecurityEngine, enc: []const u8, nonce: []const u8, tag: []const u8) ![]u8 {
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
