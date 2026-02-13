const std = @import("std");
const Db = @import("db.zig").Db;
const ScheduleRecord = @import("db.zig").ScheduleRecord;
const CryptoEngine = @import("crypto.zig").CryptoEngine;

pub const SchedulerEngine = struct {
    allocator: std.mem.Allocator,
    db: *Db,
    crypto: *const CryptoEngine,
    running: std.atomic.Value(bool),

    pub fn init(allocator: std.mem.Allocator, db: *Db, crypto: *const CryptoEngine) SchedulerEngine {
        return .{
            .allocator = allocator,
            .db = db,
            .crypto = crypto,
            .running = std.atomic.Value(bool).init(true),
        };
    }

    /// Background scheduler loop — runs in a dedicated thread.
    pub fn runLoop(self: *SchedulerEngine) void {
        std.log.info("[STATION TO STATION] Scheduler thread started", .{});
        while (self.running.load(.acquire)) {
            // Sleep until next minute boundary
            const now: u64 = @intCast(std.time.timestamp());
            const remainder = @mod(now, 60);
            const sleep_secs: u64 = if (remainder == 0) 60 else 60 - remainder;
            std.Thread.sleep(sleep_secs * std.time.ns_per_s);

            if (!self.running.load(.acquire)) break;

            self.tick();
        }
        std.log.info("[STATION TO STATION] Scheduler thread stopped", .{});
    }

    fn tick(self: *SchedulerEngine) void {
        const schedules = self.db.listEnabledSchedules(self.allocator) catch return;
        defer {
            for (schedules) |s| s.deinit(self.allocator);
            self.allocator.free(schedules);
        }

        const now = std.time.timestamp();
        for (schedules) |schedule| {
            // Skip if already ran this minute
            if (schedule.last_run) |lr| {
                if (now - lr < 60) continue;
            }
            if (cronMatches(schedule.cron_minute, schedule.cron_hour, schedule.cron_dom, schedule.cron_month, schedule.cron_dow, now)) {
                self.executeSchedule(schedule, now);
            }
        }
    }

    /// Execute a schedule immediately (called from tick or from "Run Now" API).
    pub fn executeSchedule(self: *SchedulerEngine, schedule: ScheduleRecord, now: i64) void {
        // Insert a run record
        const run_id = self.db.insertScheduleRun(schedule.id, "running") catch {
            std.log.warn("[STATION TO STATION] Failed to create run for schedule {d}", .{schedule.id});
            return;
        };

        // Resolve target node IDs
        const node_ids = self.resolveTargets(schedule.target_type, schedule.target_value) catch |err| {
            const msg = std.fmt.allocPrint(self.allocator, "Failed to resolve targets: {}", .{err}) catch "target error";
            defer self.allocator.free(msg);
            self.db.updateScheduleRun(run_id, "failed", msg);
            self.db.updateScheduleLastRun(schedule.id, now, "failed");
            self.recordEvent(schedule, false, msg);
            return;
        };
        defer {
            for (node_ids) |id| self.allocator.free(id);
            self.allocator.free(node_ids);
        }

        if (node_ids.len == 0) {
            self.db.updateScheduleRun(run_id, "failed", "No target nodes found");
            self.db.updateScheduleLastRun(schedule.id, now, "failed");
            self.recordEvent(schedule, false, "No target nodes");
            return;
        }

        // Dispatch by job type
        var output_buf: std.ArrayListUnmanaged(u8) = .{};
        var all_ok = true;

        if (std.mem.eql(u8, schedule.job_type, "command")) {
            self.executeCommand(schedule.config, node_ids, &output_buf, &all_ok);
        } else if (std.mem.eql(u8, schedule.job_type, "package_update")) {
            self.executePackageUpdate(schedule.config, node_ids, &output_buf, &all_ok);
        } else if (std.mem.eql(u8, schedule.job_type, "ansible")) {
            self.executeAnsible(schedule.config, &output_buf, &all_ok);
        } else {
            output_buf.appendSlice(self.allocator, "Unknown job type") catch {};
            all_ok = false;
        }

        const output = output_buf.toOwnedSlice(self.allocator) catch "";
        defer self.allocator.free(output);

        const status: []const u8 = if (all_ok) "ok" else "failed";
        // Truncate output for DB storage (max 64KB)
        const stored_output = if (output.len > 65536) output[0..65536] else output;
        self.db.updateScheduleRun(run_id, status, if (stored_output.len > 0) stored_output else null);
        self.db.updateScheduleLastRun(schedule.id, now, status);
        self.recordEvent(schedule, all_ok, if (output.len > 200) output[0..200] else output);
    }

    fn executeCommand(self: *SchedulerEngine, config_json: []const u8, node_ids: []const []const u8, output_buf: *std.ArrayListUnmanaged(u8), all_ok: *bool) void {
        // Parse config: {"command": "...", "sudo": true/false}
        const parsed = std.json.parseFromSlice(CommandConfig, self.allocator, config_json, .{
            .ignore_unknown_fields = true,
            .allocate = .alloc_always,
        }) catch {
            output_buf.appendSlice(self.allocator, "Invalid command config\n") catch {};
            all_ok.* = false;
            return;
        };
        defer parsed.deinit();
        const cfg = parsed.value;

        for (node_ids) |node_id| {
            const result = self.runSshCommand(node_id, cfg.command, cfg.sudo);
            defer self.allocator.free(result.output);

            // Header per node
            const header = std.fmt.allocPrint(self.allocator, "--- {s} ---\n", .{node_id}) catch "";
            defer self.allocator.free(header);
            output_buf.appendSlice(self.allocator, header) catch {};
            output_buf.appendSlice(self.allocator, result.output) catch {};
            output_buf.append(self.allocator, '\n') catch {};

            if (!result.ok) all_ok.* = false;
        }
    }

    fn executePackageUpdate(self: *SchedulerEngine, config_json: []const u8, node_ids: []const []const u8, output_buf: *std.ArrayListUnmanaged(u8), all_ok: *bool) void {
        // Parse config: {"pkg_action": "upgrade" or "full-upgrade"}
        const parsed = std.json.parseFromSlice(PackageConfig, self.allocator, config_json, .{
            .ignore_unknown_fields = true,
            .allocate = .alloc_always,
        }) catch {
            output_buf.appendSlice(self.allocator, "Invalid package config\n") catch {};
            all_ok.* = false;
            return;
        };
        defer parsed.deinit();
        const full = std.mem.eql(u8, parsed.value.pkg_action, "full-upgrade");

        for (node_ids) |node_id| {
            // Look up node's package manager
            const node = self.db.getNode(self.allocator, node_id) catch continue;
            if (node == null) continue;
            defer node.?.deinit(self.allocator);

            const pm = node.?.pkg_manager orelse "apt";
            const cmd = getUpgradeCommand(pm, full);

            const result = self.runSshCommand(node_id, cmd, true);
            defer self.allocator.free(result.output);

            const header = std.fmt.allocPrint(self.allocator, "--- {s} ({s}) ---\n", .{ node_id, pm }) catch "";
            defer self.allocator.free(header);
            output_buf.appendSlice(self.allocator, header) catch {};
            output_buf.appendSlice(self.allocator, result.output) catch {};
            output_buf.append(self.allocator, '\n') catch {};

            if (!result.ok) all_ok.* = false;
        }
    }

    fn executeAnsible(self: *SchedulerEngine, config_json: []const u8, output_buf: *std.ArrayListUnmanaged(u8), all_ok: *bool) void {
        // Ansible scheduled runs just report that ansible integration is not yet supported in scheduler
        _ = config_json;
        output_buf.appendSlice(self.allocator, "Ansible scheduled execution not yet implemented\n") catch {};
        all_ok.* = false;
    }

    fn resolveTargets(self: *SchedulerEngine, target_type: []const u8, target_value: ?[]const u8) ![][]const u8 {
        if (std.mem.eql(u8, target_type, "all")) {
            return self.db.getAllNodeIds(self.allocator);
        } else if (std.mem.eql(u8, target_type, "tags")) {
            const tag = target_value orelse return error.MissingTargetValue;
            return self.db.getNodeIdsByTag(self.allocator, tag);
        } else if (std.mem.eql(u8, target_type, "nodes")) {
            const val = target_value orelse return error.MissingTargetValue;
            // Comma-separated node IDs
            var result: std.ArrayListUnmanaged([]const u8) = .{};
            var iter = std.mem.splitScalar(u8, val, ',');
            while (iter.next()) |id| {
                const trimmed = std.mem.trim(u8, id, " ");
                if (trimmed.len > 0) {
                    try result.append(self.allocator, try self.allocator.dupe(u8, trimmed));
                }
            }
            return try result.toOwnedSlice(self.allocator);
        }
        return error.InvalidTargetType;
    }

    fn recordEvent(self: *SchedulerEngine, schedule: ScheduleRecord, ok: bool, detail: []const u8) void {
        var msg_buf: [256]u8 = undefined;
        const event_type: []const u8 = if (ok) "schedule.executed" else "schedule.failed";
        const msg = std.fmt.bufPrint(&msg_buf, "Schedule '{s}' ({s}): {s}", .{
            if (schedule.name.len > 60) schedule.name[0..60] else schedule.name,
            schedule.job_type,
            if (ok) "completed" else "failed",
        }) catch "Schedule execution";
        self.db.insertEvent(event_type, null, msg, if (detail.len > 0) detail else null);
    }

    // --- SSH Infrastructure (same pattern as containers.zig) ---

    const SshResult = struct {
        ok: bool,
        output: []const u8,
    };

    fn runSshCommand(self: *SchedulerEngine, node_id: []const u8, command: []const u8, use_sudo: bool) SshResult {
        const ctx = self.setupSsh(node_id) catch |err| {
            const msg = std.fmt.allocPrint(self.allocator, "SSH setup failed: {}", .{err}) catch "";
            return .{ .ok = false, .output = msg };
        };
        defer ctx.deinit(self);

        const wrapped = if (use_sudo and ctx.sudo_pass != null)
            std.fmt.allocPrint(self.allocator, "echo '{s}' | sudo -S {s}", .{ ctx.sudo_pass.?, command }) catch
                return .{ .ok = false, .output = "" }
        else if (use_sudo)
            std.fmt.allocPrint(self.allocator, "sudo {s}", .{command}) catch
                return .{ .ok = false, .output = "" }
        else
            self.allocator.dupe(u8, command) catch
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
        defer self.allocator.free(result.stderr);

        const ok = result.term.Exited == 0;
        const output = stripSudoNoise(self.allocator, result.stdout);
        return .{ .ok = ok, .output = output };
    }

    const SshContext = struct {
        tmp_key_path: []const u8,
        host_arg: []const u8,
        port_str: []const u8,
        ssh_key: []u8,
        sudo_pass: ?[]u8,

        fn deinit(self: SshContext, engine: *SchedulerEngine) void {
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

    fn setupSsh(self: *SchedulerEngine, node_id: []const u8) !SshContext {
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

        const tmp_key_path = try std.fmt.allocPrint(self.allocator, "/tmp/stardust_sched_{s}", .{node_id});
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

    fn decryptField(self: *SchedulerEngine, enc: []const u8, nonce: []const u8, tag: []const u8) ![]u8 {
        if (nonce.len < 12 or tag.len < 16) return error.InvalidEncryptedData;
        return try self.crypto.decrypt(self.allocator, .{
            .ciphertext = enc,
            .nonce = nonce[0..12].*,
            .tag = tag[0..16].*,
            .salt = [_]u8{0} ** 16,
        });
    }
};

// --- Cron matching ---

pub fn cronMatches(minute: []const u8, hour: []const u8, dom: []const u8, month: []const u8, dow: []const u8, timestamp: i64) bool {
    const ts: u64 = @intCast(timestamp);
    const day_seconds = @mod(ts, 86400);
    const current_hour: u8 = @intCast(day_seconds / 3600);
    const current_minute: u8 = @intCast(@mod(day_seconds, 3600) / 60);

    // Days since epoch (1970-01-01 = Thursday)
    const epoch_days = ts / 86400;
    const current_dow: u8 = @intCast(@mod(epoch_days + 4, 7)); // 0=Sun

    // Compute month and day-of-month from epoch
    const ymd = epochToYmd(epoch_days);

    return fieldMatches(minute, current_minute) and
        fieldMatches(hour, current_hour) and
        fieldMatches(dom, ymd.day) and
        fieldMatches(month, ymd.month) and
        fieldMatches(dow, current_dow);
}

fn fieldMatches(field: []const u8, value: u8) bool {
    if (field.len == 0 or std.mem.eql(u8, field, "*")) return true;

    // Handle comma-separated list: "1,15,30"
    var iter = std.mem.splitScalar(u8, field, ',');
    while (iter.next()) |part| {
        if (partMatches(part, value)) return true;
    }
    return false;
}

fn partMatches(part: []const u8, value: u8) bool {
    // Handle step: "*/5" or "1-10/2"
    if (std.mem.indexOf(u8, part, "/")) |slash_pos| {
        const step = std.fmt.parseInt(u8, part[slash_pos + 1 ..], 10) catch return false;
        if (step == 0) return false;
        const range_part = part[0..slash_pos];
        if (std.mem.eql(u8, range_part, "*")) {
            return @mod(value, step) == 0;
        }
        // Range with step: "1-10/2"
        if (std.mem.indexOf(u8, range_part, "-")) |dash_pos| {
            const low = std.fmt.parseInt(u8, range_part[0..dash_pos], 10) catch return false;
            const high = std.fmt.parseInt(u8, range_part[dash_pos + 1 ..], 10) catch return false;
            return value >= low and value <= high and @mod(value - low, step) == 0;
        }
        return false;
    }

    // Handle range: "1-5"
    if (std.mem.indexOf(u8, part, "-")) |dash_pos| {
        const low = std.fmt.parseInt(u8, part[0..dash_pos], 10) catch return false;
        const high = std.fmt.parseInt(u8, part[dash_pos + 1 ..], 10) catch return false;
        return value >= low and value <= high;
    }

    // Exact number
    const n = std.fmt.parseInt(u8, part, 10) catch return false;
    return value == n;
}

const YearMonthDay = struct {
    year: u32,
    month: u8,
    day: u8,
};

fn epochToYmd(epoch_days: u64) YearMonthDay {
    // Civil calendar from epoch days (algorithm from Howard Hinnant)
    const z = epoch_days + 719468;
    const era: u64 = z / 146097;
    const doe: u64 = z - era * 146097;
    const yoe: u64 = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    const y: u64 = yoe + era * 400;
    const doy: u64 = doe - (365 * yoe + yoe / 4 - yoe / 100);
    const mp: u64 = (5 * doy + 2) / 153;
    const d: u8 = @intCast(doy - (153 * mp + 2) / 5 + 1);
    const m: u8 = @intCast(if (mp < 10) mp + 3 else mp - 9);
    const yr: u32 = @intCast(if (m <= 2) y + 1 else y);
    return .{ .year = yr, .month = m, .day = d };
}

fn getUpgradeCommand(pm: []const u8, full: bool) []const u8 {
    if (std.mem.eql(u8, pm, "apt")) {
        return if (full)
            "DEBIAN_FRONTEND=noninteractive apt-get update && apt-get full-upgrade -y"
        else
            "DEBIAN_FRONTEND=noninteractive apt-get update && apt-get upgrade -y";
    } else if (std.mem.eql(u8, pm, "dnf")) {
        return if (full) "dnf upgrade -y" else "dnf upgrade --nobest -y";
    } else if (std.mem.eql(u8, pm, "yum")) {
        return "yum update -y";
    } else if (std.mem.eql(u8, pm, "pacman")) {
        return "pacman -Syu --noconfirm";
    } else if (std.mem.eql(u8, pm, "apk")) {
        return if (full) "apk upgrade --available" else "apk upgrade";
    }
    // Fallback to apt
    return "DEBIAN_FRONTEND=noninteractive apt-get update && apt-get upgrade -y";
}

fn stripSudoNoise(allocator: std.mem.Allocator, raw: []const u8) []const u8 {
    var buf: std.ArrayListUnmanaged(u8) = .{};
    var iter = std.mem.splitScalar(u8, raw, '\n');
    var first = true;
    while (iter.next()) |line| {
        if (std.mem.startsWith(u8, line, "[sudo]")) continue;
        if (!first) buf.append(allocator, '\n') catch {};
        buf.appendSlice(allocator, line) catch {};
        first = false;
    }
    allocator.free(raw);
    return buf.toOwnedSlice(allocator) catch "";
}

const CommandConfig = struct {
    command: []const u8,
    sudo: bool = false,
};

const PackageConfig = struct {
    pkg_action: []const u8 = "upgrade",
};
