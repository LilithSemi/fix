//! Pure forge-provider request planning.
//!
//! The expression layer decodes Nix values into `Input`; this module owns the
//! GitHub, GitLab, and SourceHut endpoint conventions used to resolve and
//! download a source tree.

const std = @import("std");

pub const Forge = enum { github, gitlab, sourcehut };

pub const Input = struct {
    owner: []const u8,
    repo: []const u8,
    rev: ?[]const u8 = null,
    ref: ?[]const u8 = null,
    host: ?[]const u8 = null,
    name: ?[]const u8 = null,
};

pub const Plan = struct {
    url: []u8,
    metadata_url: ?[]u8,
    metadata_ref: ?[]u8,
    metadata_head_url: ?[]u8,
    resolved_url_template: ?[]u8,
    name: []u8,
    rev: ?[]u8,

    pub fn deinit(self: Plan, allocator: std.mem.Allocator) void {
        allocator.free(self.url);
        if (self.metadata_url) |url| allocator.free(url);
        if (self.metadata_ref) |ref| allocator.free(ref);
        if (self.metadata_head_url) |url| allocator.free(url);
        if (self.resolved_url_template) |url| allocator.free(url);
        allocator.free(self.name);
        if (self.rev) |rev| allocator.free(rev);
    }
};

pub fn plan(allocator: std.mem.Allocator, kind: Forge, input: Input) !Plan {
    if (input.rev != null and input.ref != null) return error.RefAndRev;

    const archive_ref = input.rev orelse input.ref orelse "HEAD";
    const default_host = switch (kind) {
        .github => "github.com",
        .gitlab => "gitlab.com",
        .sourcehut => "git.sr.ht",
    };
    const host = input.host orelse default_host;

    const url = switch (kind) {
        .gitlab => try std.fmt.allocPrint(allocator, "https://{[host]s}/{[owner]s}/{[repo]s}/-/archive/{[ref]s}/{[repo]s}-{[ref]s}.tar.gz", .{
            .host = host,
            .owner = input.owner,
            .repo = input.repo,
            .ref = archive_ref,
        }),
        .sourcehut => try std.fmt.allocPrint(allocator, "https://{[host]s}/{[owner]s}/{[repo]s}/archive/{[ref]s}.tar.gz", .{
            .host = host,
            .owner = input.owner,
            .repo = input.repo,
            .ref = archive_ref,
        }),
        .github => if (input.host == null)
            // Avoid a cross-origin redirect so the transport never needs to
            // forward an Authorization header from github.com to
            // codeload.github.com.
            try std.fmt.allocPrint(allocator, "https://codeload.github.com/{[owner]s}/{[repo]s}/tar.gz/{[ref]s}", .{
                .owner = input.owner,
                .repo = input.repo,
                .ref = archive_ref,
            })
        else
            try std.fmt.allocPrint(allocator, "https://{[host]s}/{[owner]s}/{[repo]s}/archive/{[ref]s}.tar.gz", .{
                .host = host,
                .owner = input.owner,
                .repo = input.repo,
                .ref = archive_ref,
            }),
    };
    errdefer allocator.free(url);

    const metadata_url: ?[]u8 = switch (kind) {
        .github => if (input.host) |custom|
            try std.fmt.allocPrint(allocator, "https://{[host]s}/api/v3/repos/{[owner]s}/{[repo]s}/commits/{[ref]s}", .{
                .host = custom,
                .owner = input.owner,
                .repo = input.repo,
                .ref = archive_ref,
            })
        else
            try std.fmt.allocPrint(allocator, "https://api.github.com/repos/{[owner]s}/{[repo]s}/commits/{[ref]s}", .{
                .owner = input.owner,
                .repo = input.repo,
                .ref = archive_ref,
            }),
        .gitlab => metadata: {
            const raw_project = try std.fmt.allocPrint(allocator, "{[owner]s}/{[repo]s}", .{ .owner = input.owner, .repo = input.repo });
            defer allocator.free(raw_project);
            const project = try percentEncode(allocator, raw_project);
            defer allocator.free(project);
            const encoded_ref = try percentEncode(allocator, archive_ref);
            defer allocator.free(encoded_ref);
            break :metadata try std.fmt.allocPrint(allocator, "https://{[host]s}/api/v4/projects/{[project]s}/repository/commits/{[ref]s}", .{
                .host = host,
                .project = project,
                .ref = encoded_ref,
            });
        },
        .sourcehut => try std.fmt.allocPrint(allocator, "https://{[host]s}/{[owner]s}/{[repo]s}/info/refs", .{
            .host = host,
            .owner = input.owner,
            .repo = input.repo,
        }),
    };
    errdefer if (metadata_url) |owned| allocator.free(owned);

    const metadata_ref = if (kind == .sourcehut) try allocator.dupe(u8, archive_ref) else null;
    errdefer if (metadata_ref) |owned| allocator.free(owned);
    const metadata_head_url = if (kind == .sourcehut)
        try std.fmt.allocPrint(allocator, "https://{[host]s}/{[owner]s}/{[repo]s}/HEAD", .{
            .host = host,
            .owner = input.owner,
            .repo = input.repo,
        })
    else
        null;
    errdefer if (metadata_head_url) |owned| allocator.free(owned);

    const resolved_url_template: ?[]u8 = switch (kind) {
        .gitlab => try std.fmt.allocPrint(allocator, "https://{[host]s}/{[owner]s}/{[repo]s}/-/archive/{{rev}}/{[repo]s}-{{rev}}.tar.gz", .{
            .host = host,
            .owner = input.owner,
            .repo = input.repo,
        }),
        .sourcehut => try std.fmt.allocPrint(allocator, "https://{[host]s}/{[owner]s}/{[repo]s}/archive/{{rev}}.tar.gz", .{
            .host = host,
            .owner = input.owner,
            .repo = input.repo,
        }),
        .github => if (input.host) |custom|
            try std.fmt.allocPrint(allocator, "https://{[host]s}/{[owner]s}/{[repo]s}/archive/{{rev}}.tar.gz", .{
                .host = custom,
                .owner = input.owner,
                .repo = input.repo,
            })
        else
            try std.fmt.allocPrint(allocator, "https://codeload.github.com/{[owner]s}/{[repo]s}/tar.gz/{{rev}}", .{
                .owner = input.owner,
                .repo = input.repo,
            }),
    };
    errdefer allocator.free(resolved_url_template.?);

    return .{
        .url = url,
        .metadata_url = metadata_url,
        .metadata_ref = metadata_ref,
        .metadata_head_url = metadata_head_url,
        .resolved_url_template = resolved_url_template,
        .name = try allocator.dupe(u8, input.name orelse "source"),
        .rev = if (input.rev) |rev| try allocator.dupe(u8, rev) else null,
    };
}

fn percentEncode(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    var out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer out.deinit(allocator);
    const hex = "0123456789ABCDEF";
    for (input) |byte| {
        if (std.ascii.isAlphanumeric(byte) or byte == '-' or byte == '_' or byte == '.' or byte == '~') {
            try out.append(allocator, byte);
        } else {
            try out.appendSlice(allocator, &.{ '%', hex[byte >> 4], hex[byte & 0xf] });
        }
    }
    return out.toOwnedSlice(allocator);
}

test "plans provider-specific endpoints" {
    const allocator = std.testing.allocator;
    var sourcehut = try plan(allocator, .sourcehut, .{ .owner = "~user", .repo = "project", .ref = "main" });
    defer sourcehut.deinit(allocator);
    try std.testing.expectEqualStrings("https://git.sr.ht/~user/project/archive/main.tar.gz", sourcehut.url);
    try std.testing.expectEqualStrings("https://git.sr.ht/~user/project/info/refs", sourcehut.metadata_url.?);

    var github = try plan(allocator, .github, .{ .owner = "owner", .repo = "repo", .rev = "deadbeef" });
    defer github.deinit(allocator);
    try std.testing.expectEqualStrings("https://codeload.github.com/owner/repo/tar.gz/deadbeef", github.url);
}

test "rejects simultaneous ref and rev" {
    try std.testing.expectError(error.RefAndRev, plan(std.testing.allocator, .github, .{
        .owner = "owner",
        .repo = "repo",
        .ref = "main",
        .rev = "deadbeef",
    }));
}
