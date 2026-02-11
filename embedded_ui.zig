/// Embedded UI assets — built from frontend/ at compile time.
/// When the ui/ directory exists at build time, these files are baked into the binary.
/// This enables single-binary deployment with no external file dependencies.

pub const index_html = @embedFile("ui/index.html");
pub const app_js = @embedFile("ui/assets/app.js");
pub const index_css = @embedFile("ui/assets/index.css");

pub const Asset = struct {
    content: []const u8,
    content_type: []const u8,
};

/// Look up an embedded asset by URL path.
pub fn get(path: []const u8) ?Asset {
    const std = @import("std");

    if (std.mem.eql(u8, path, "/") or std.mem.eql(u8, path, "/index.html")) {
        return .{ .content = index_html, .content_type = "text/html; charset=utf-8" };
    }
    if (std.mem.eql(u8, path, "/assets/app.js")) {
        return .{ .content = app_js, .content_type = "application/javascript; charset=utf-8" };
    }
    if (std.mem.eql(u8, path, "/assets/index.css")) {
        return .{ .content = index_css, .content_type = "text/css; charset=utf-8" };
    }
    // SPA fallback: serve index.html for unknown paths (client-side routing)
    if (!std.mem.startsWith(u8, path, "/api/") and !std.mem.startsWith(u8, path, "/ws")) {
        return .{ .content = index_html, .content_type = "text/html; charset=utf-8" };
    }
    return null;
}
