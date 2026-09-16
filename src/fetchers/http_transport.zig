//! The evaluator's single HTTP transport.
//!
//! zurl owns protocol details (redirects, TLS, content decoding and
//! connection timeouts). This adapter only supplies Fix policy, names the
//! staging file zurl writes and hashes, hands zurl the proxy environment
//! that libcurl used to read for itself, and translates a transfer fault
//! into a stable fetch error.

const std = @import("std");
const zurl = @import("zurl");

/// zurl takes request headers in this exact shape, so an alias keeps one
/// type across the boundary and no conversion at the call site.
pub const Header = std.http.Header;

pub const Reporter = struct {
    ctx: *anyopaque,
    report: *const fn (ctx: *anyopaque, downloaded: u64, total: u64) void,
};

pub const Options = struct {
    headers: []const Header = &.{},
    reporter: ?Reporter = null,
    connect_timeout_seconds: u32 = 15,
    stalled_timeout_seconds: u32 = 300,
    max_bytes_per_second: u64 = 0,
    ca_file: ?[]const u8 = null,
    max_redirects: u32 = 10,
    /// The process environment, read for the proxy variables. libcurl read
    /// them for itself; zurl reads no environment at all, so a null map here
    /// means every request goes direct.
    ///
    /// Borrowed, and it must outlive the transfer: a proxy host and its
    /// credential are slices into this map, not copies.
    environment: ?*const std.process.Environ.Map = null,
};

pub const Result = struct {
    digest: [std.crypto.hash.sha2.Sha256.digest_length]u8,
    size: u64,
    status: u16,
};

/// Hash an already-downloaded cache file without loading it into evaluator
/// memory. Kept beside the download writer so publication and validation use
/// exactly the same decoded-byte hashing rule.
pub fn fileDigest(io: std.Io, path: []const u8) ![std.crypto.hash.sha2.Sha256.digest_length]u8 {
    var diagnostics: zurl.Diagnostics = .{};
    return zurl.download.fileDigest(io, std.Io.Dir.cwd(), path, &diagnostics) catch {
        // zurl reports every local read fault as one error and puts the real
        // cause in the message, so the message is the only place a missing
        // file can be told apart from an unreadable one.
        const message = diagnostics.message orelse return error.FetchCacheReadFailed;
        if (std.mem.eql(u8, message, "FileNotFound")) return error.FileNotFound;
        return error.FetchCacheReadFailed;
    };
}

/// Carries a Fix reporter through zurl's C-convention progress callback.
const ProgressContext = struct {
    reporter: Reporter,

    fn report(ctx: *anyopaque, transferred: u64, total: u64) callconv(.c) void {
        const self: *ProgressContext = @ptrCast(@alignCast(ctx));
        self.reporter.report(self.reporter.ctx, transferred, total);
    }
};

/// What a download reports to the fetch cache. `FetchTransient` is the one
/// name a retry answers; `FetchCache.retryable` holds that rule.
const FetchError = error{
    FetchClientError,
    FetchInvalidUrl,
    FetchTooManyRedirects,
    FetchTlsVerificationFailed,
    FetchCacheWriteFailed,
    FetchTransient,
    OutOfMemory,
};

/// Turn a zurl transfer fault into the fetch error Fix retries on, or gives
/// up on. The error decides first: a status answer only reaches
/// `Diagnostics` on the one arm that has one, and every other fault leaves
/// it null.
fn fetchError(err: zurl.Error, status: ?u16) FetchError {
    // `fail_on_error` reports a 4xx and a 5xx under one name, so the status
    // is what tells a client mistake, which a retry only repeats, from a
    // server that may recover. 408 and 429 are the two 4xx that ask for a
    // retry by name: a timed-out request and a rate limit.
    if (err == error.HttpReturnedError) {
        const code = status orelse return error.FetchTransient;
        if (code >= 400 and code < 500 and code != 408 and code != 429)
            return error.FetchClientError;
        return error.FetchTransient;
    }
    return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.WriteError => error.FetchCacheWriteFailed,
        error.InvalidUrl, error.UnsupportedProtocol => error.FetchInvalidUrl,
        error.TooManyRedirects => error.FetchTooManyRedirects,
        error.PeerFailedVerification, error.CaCertBadFile => error.FetchTlsVerificationFailed,
        // A body in a coding with no decoder does not become decodable on a
        // second request, so this is permanent the way a 4xx is.
        error.BadContentEncoding => error.FetchClientError,
        else => error.FetchTransient,
    };
}

/// Download `url` into the new/truncated file at `path`, returning the SHA-256
/// of the decoded response body. `path` is staging storage and should only be
/// published by an atomic rename after this succeeds.
pub fn download(
    allocator: std.mem.Allocator,
    io: std.Io,
    url: []const u8,
    path: []const u8,
    options: Options,
) !Result {
    var client: zurl.Client = .init(allocator, io);
    defer client.deinit();

    var progress: ?ProgressContext = if (options.reporter) |reporter| .{ .reporter = reporter } else null;

    var transfer: zurl.Transfer.Options = .{
        .headers = options.headers,
        .reporter = if (progress) |*context|
            .{ .ctx = context, .report = ProgressContext.report }
        else
            null,
        // Clamped, not cast: a hop count past the field's range is still a
        // count no transfer can reach.
        .redirects = .{ .follow = @intCast(@min(options.max_redirects, std.math.maxInt(u16))) },
        .fail_on_error = true,
        .connect_timeout = if (options.connect_timeout_seconds == 0)
            .none
        else
            .{ .duration = .{
                .raw = .fromSeconds(@intCast(options.connect_timeout_seconds)),
                .clock = .awake,
            } },
        // A limit of zero turns the stall watchdog off, which is what a
        // stalled timeout of zero asks for.
        .low_speed_limit = if (options.stalled_timeout_seconds == 0) 0 else 1,
        .low_speed_time_s = options.stalled_timeout_seconds,
        .max_bytes_per_second = options.max_bytes_per_second,
        .user_agent = "fix",
        // Offer every coding zurl can decode. The digest then covers the
        // decoded bytes, so it does not depend on which coding the peer
        // picked.
        .accept_encoding = true,
        .ca = .{ .cacert = options.ca_file },
    };

    // zurl reads no environment of its own, so this is what keeps a proxied
    // fetch proxied. It writes only the fields the environment named, and
    // Fix names none of them itself. A proxy url that does not parse ends
    // the fetch: going direct would send the request exactly where the user
    // meant it not to go, and it will not start parsing on a retry.
    if (options.environment) |environment|
        zurl.proxyFromEnv(&transfer, environment) catch return error.FetchInvalidUrl;

    var diagnostics: zurl.Diagnostics = .{};
    const result = zurl.download.toFile(&client, url, std.Io.Dir.cwd(), path, transfer, &diagnostics) catch |err|
        return fetchError(err, diagnostics.status);

    return .{ .digest = result.digest, .size = result.size, .status = result.status };
}

test "HTTP download follows redirects and streams decoded bytes" {
    const testing = std.testing;
    var address = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    var server = try address.listen(testing.io, .{ .reuse_address = true });
    defer server.deinit(testing.io);
    const port = server.socket.address.ip4.port;
    const Server = struct {
        fn run(s: *std.Io.net.Server) void {
            for (0..2) |request_index| {
                const stream = s.accept(testing.io) catch return;
                defer stream.close(testing.io);
                var read_buffer: [2048]u8 = undefined;
                var reader = std.Io.net.Stream.Reader.init(stream, testing.io, &read_buffer);
                while (true) {
                    const line = reader.interface.takeDelimiterExclusive('\n') catch return;
                    if (line.len == 0 or std.mem.eql(u8, line, "\r")) break;
                }
                var write_buffer: [2048]u8 = undefined;
                var writer = std.Io.net.Stream.Writer.init(stream, testing.io, &write_buffer);
                if (request_index == 0)
                    writer.interface.writeAll("HTTP/1.1 302 Found\r\nLocation: /body\r\nContent-Length: 0\r\nConnection: close\r\n\r\n") catch return
                else
                    writer.interface.writeAll("HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\npayload") catch return;
                writer.interface.flush() catch return;
            }
        }
    };
    const thread = try std.Thread.spawn(.{}, Server.run, .{&server});

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(testing.io, ".", testing.allocator);
    defer testing.allocator.free(root);
    const output = try std.fs.path.join(testing.allocator, &.{ root, "output" });
    defer testing.allocator.free(output);
    const url = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/redirect", .{port});
    defer testing.allocator.free(url);
    const result = try download(testing.allocator, testing.io, url, output, .{});
    thread.join();
    try testing.expectEqual(@as(u64, 7), result.size);
    const contents = try tmp.dir.readFileAlloc(testing.io, "output", testing.allocator, .limited(64));
    defer testing.allocator.free(contents);
    try testing.expectEqualStrings("payload", contents);
}

test "a 404 is a permanent client error, not a transient one" {
    const testing = std.testing;
    var address = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    var server = try address.listen(testing.io, .{ .reuse_address = true });
    defer server.deinit(testing.io);
    const port = server.socket.address.ip4.port;
    const Server = struct {
        fn run(s: *std.Io.net.Server) void {
            const stream = s.accept(testing.io) catch return;
            defer stream.close(testing.io);
            var read_buffer: [2048]u8 = undefined;
            var reader = std.Io.net.Stream.Reader.init(stream, testing.io, &read_buffer);
            while (true) {
                const line = reader.interface.takeDelimiterExclusive('\n') catch return;
                if (line.len == 0 or std.mem.eql(u8, line, "\r")) break;
            }
            var write_buffer: [2048]u8 = undefined;
            var writer = std.Io.net.Stream.Writer.init(stream, testing.io, &write_buffer);
            writer.interface.writeAll("HTTP/1.1 404 Not Found\r\nContent-Length: 3\r\nConnection: close\r\n\r\nno!") catch return;
            writer.interface.flush() catch return;
        }
    };
    const thread = try std.Thread.spawn(.{}, Server.run, .{&server});

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(testing.io, ".", testing.allocator);
    defer testing.allocator.free(root);
    const output = try std.fs.path.join(testing.allocator, &.{ root, "output" });
    defer testing.allocator.free(output);
    const url = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/missing", .{port});
    defer testing.allocator.free(url);
    const failure = download(testing.allocator, testing.io, url, output, .{});
    thread.join();
    try testing.expectError(error.FetchClientError, failure);
    // A failed transfer publishes nothing, so a later cache read cannot find
    // an error page under a confident digest.
    try testing.expectError(error.FileNotFound, tmp.dir.access(testing.io, "output", .{}));
}

test "the proxy environment routes a cleartext request through the proxy" {
    const testing = std.testing;
    var address = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    var server = try address.listen(testing.io, .{ .reuse_address = true });
    defer server.deinit(testing.io);
    const port = server.socket.address.ip4.port;
    const Proxy = struct {
        var absolute_form: bool = false;

        fn run(s: *std.Io.net.Server) void {
            const stream = s.accept(testing.io) catch return;
            defer stream.close(testing.io);
            var read_buffer: [2048]u8 = undefined;
            var reader = std.Io.net.Stream.Reader.init(stream, testing.io, &read_buffer);
            const request_line = reader.interface.takeDelimiterExclusive('\n') catch return;
            // A proxy is asked for the whole url and a direct peer is asked
            // for a path, so the request line is what tells the two apart.
            absolute_form = std.mem.startsWith(u8, request_line, "GET http://origin.invalid/file ");
            while (true) {
                const line = reader.interface.takeDelimiterExclusive('\n') catch return;
                if (line.len == 0 or std.mem.eql(u8, line, "\r")) break;
            }
            var write_buffer: [2048]u8 = undefined;
            var writer = std.Io.net.Stream.Writer.init(stream, testing.io, &write_buffer);
            writer.interface.writeAll("HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\npayload") catch return;
            writer.interface.flush() catch return;
        }
    };
    Proxy.absolute_form = false;
    const thread = try std.Thread.spawn(.{}, Proxy.run, .{&server});

    var environment = std.process.Environ.Map.init(testing.allocator);
    defer environment.deinit();
    const proxy_url = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}", .{port});
    defer testing.allocator.free(proxy_url);
    try environment.put("http_proxy", proxy_url);

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(testing.io, ".", testing.allocator);
    defer testing.allocator.free(root);
    const output = try std.fs.path.join(testing.allocator, &.{ root, "output" });
    defer testing.allocator.free(output);

    // A host no name server answers. Reaching it at all proves the request
    // went to the proxy, because a direct transfer cannot resolve it.
    const result = try download(
        testing.allocator,
        testing.io,
        "http://origin.invalid/file",
        output,
        .{ .environment = &environment },
    );
    thread.join();
    try testing.expect(Proxy.absolute_form);
    try testing.expectEqual(@as(u64, 7), result.size);
    const contents = try tmp.dir.readFileAlloc(testing.io, "output", testing.allocator, .limited(64));
    defer testing.allocator.free(contents);
    try testing.expectEqualStrings("payload", contents);
}

test "a proxy variable that does not parse ends the fetch instead of going direct" {
    const testing = std.testing;
    var environment = std.process.Environ.Map.init(testing.allocator);
    defer environment.deinit();
    // A scheme no proxy speaks. Reading it as an HTTP proxy, and dropping it
    // to dial the origin, both send the request somewhere the user did not
    // ask for.
    try environment.put("http_proxy", "ftp://127.0.0.1");
    try testing.expectError(error.FetchInvalidUrl, download(
        testing.allocator,
        testing.io,
        "http://origin.invalid/file",
        "/nonexistent/output",
        .{ .environment = &environment },
    ));
}
