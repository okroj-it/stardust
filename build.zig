const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // --- Dependencies ---
    const zap_dep = b.dependency("zap", .{
        .target = target,
        .optimize = optimize,
    });
    const zqlite_dep = b.dependency("zqlite", .{
        .target = target,
        .optimize = optimize,
    });

    // --- Common module (shared types + protocol) ---
    const common_mod = b.addModule("common", .{
        .root_source_file = b.path("src/common/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    // --- Agent binary (no zap/zqlite — keep it tiny) ---
    const agent_mod = b.addModule("agent", .{
        .root_source_file = b.path("src/agent/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    agent_mod.addImport("common", common_mod);
    const agent = b.addExecutable(.{
        .name = "stardust-spider",
        .root_module = agent_mod,
    });
    b.installArtifact(agent);

    // --- Frontend build step (bun run build in frontend/) ---
    const frontend_step = b.addSystemCommand(&.{
        "bun", "run", "build",
    });
    frontend_step.setCwd(b.path("frontend"));

    // --- Embedded UI module (built frontend assets baked into binary) ---
    const embedded_ui_mod = b.addModule("embedded_ui", .{
        .root_source_file = b.path("embedded_ui.zig"),
        .target = target,
        .optimize = optimize,
    });

    // --- Server binary ---
    const server_mod = b.addModule("server", .{
        .root_source_file = b.path("src/server/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    server_mod.addImport("common", common_mod);
    server_mod.addImport("zap", zap_dep.module("zap"));
    server_mod.addImport("zqlite", zqlite_dep.module("zqlite"));
    server_mod.addImport("embedded_ui", embedded_ui_mod);
    const server = b.addExecutable(.{
        .name = "stardust-server",
        .root_module = server_mod,
    });
    // Server compilation depends on frontend build (for @embedFile)
    server.step.dependOn(&frontend_step.step);
    b.installArtifact(server);

    // --- Cross-compiled Spider binaries ---
    const spider_cross = b.step("spider-aarch64", "Cross-compile Spider for aarch64-linux");
    const arm64_target = b.resolveTargetQuery(.{
        .cpu_arch = .aarch64,
        .os_tag = .linux,
    });
    const arm64_common = b.addModule("common_arm64", .{
        .root_source_file = b.path("src/common/root.zig"),
        .target = arm64_target,
        .optimize = optimize,
    });
    const arm64_agent_mod = b.addModule("agent_arm64", .{
        .root_source_file = b.path("src/agent/main.zig"),
        .target = arm64_target,
        .optimize = optimize,
    });
    arm64_agent_mod.addImport("common", arm64_common);
    const arm64_agent = b.addExecutable(.{
        .name = "stardust-spider-aarch64",
        .root_module = arm64_agent_mod,
    });
    spider_cross.dependOn(&b.addInstallArtifact(arm64_agent, .{}).step);

    // --- Tests ---
    const test_step = b.step("test", "Run unit tests");

    const agent_tests_mod = b.addModule("agent_tests", .{
        .root_source_file = b.path("src/agent/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    agent_tests_mod.addImport("common", common_mod);
    const agent_tests = b.addTest(.{
        .name = "agent_tests",
        .root_module = agent_tests_mod,
    });
    test_step.dependOn(&b.addRunArtifact(agent_tests).step);

    const types_tests_mod = b.addModule("types_tests", .{
        .root_source_file = b.path("src/common/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    const types_tests = b.addTest(.{
        .name = "types_tests",
        .root_module = types_tests_mod,
    });
    test_step.dependOn(&b.addRunArtifact(types_tests).step);
}
