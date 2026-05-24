const std = @import("std");

fn startsWith(line: []const u8, prefix: []const u8) bool {
    return std.mem.startsWith(u8, line, prefix);
}

fn parseBool(line: []const u8, prefix: []const u8) ?bool {
    if (!startsWith(line, prefix)) return null;
    const v = line[prefix.len..];
    if (std.mem.eql(u8, v, "true") or std.mem.eql(u8, v, "1")) return true;
    if (std.mem.eql(u8, v, "false") or std.mem.eql(u8, v, "0")) return false;
    return null;
}

fn parseI64(line: []const u8, prefix: []const u8) ?i64 {
    if (!startsWith(line, prefix)) return null;
    return std.fmt.parseInt(i64, line[prefix.len..], 10) catch null;
}

fn parseText(line: []const u8, prefix: []const u8) ?[]const u8 {
    if (!startsWith(line, prefix)) return null;
    const v = line[prefix.len..];
    if (v.len == 0) return null;
    return v;
}

fn trimLine(line: []u8) []const u8 {
    return std.mem.trimRight(u8, line, "\r\n");
}

fn isSecureRegularFile(path: []const u8) bool {
    const posix = std.posix;
    const st = posix.lstat(path) catch return false;
    const mode = st.mode;
    if ((mode & posix.S.IFMT) != posix.S.IFREG) return false;
    if ((mode & posix.S.IWGRP) != 0 or (mode & posix.S.IWOTH) != 0) return false;
    return true;
}

fn parseToken(
    allocator: std.mem.Allocator,
    token_path: []const u8,
    required_ring: i32,
    max_age_sec: i64,
    expected_nonce: ?[]const u8,
    replay_state_path: []const u8,
) bool {
    _ = allocator;
    if (!isSecureRegularFile(token_path)) return false;

    const file = std.fs.openFileAbsolute(token_path, .{ .mode = .read_only }) catch return false;
    defer file.close();

    var br = std.io.bufferedReader(file.reader());
    var r = br.reader();

    var buf: [512]u8 = undefined;
    var got_ring = false;
    var got_attested = false;
    var got_ts = false;
    var got_nonce = false;
    var got_counter = false;
    var got_root_attested = false;
    var token_ring: i64 = 0;
    var token_attested = false;
    var token_ts: i64 = 0;
    var token_counter: i64 = 0;
    var token_root_attested = false;
    var token_nonce: [256]u8 = undefined;
    var token_nonce_len: usize = 0;

    while (true) {
        const maybe = r.readUntilDelimiterOrEof(&buf, '\n') catch return false;
        if (maybe == null) break;
        const line = trimLine(maybe.?);

        if (!got_ring) {
            if (parseI64(line, "ring:")) |v| {
                got_ring = true;
                token_ring = v;
                continue;
            }
        }
        if (!got_attested) {
            if (parseBool(line, "attested:")) |v| {
                got_attested = true;
                token_attested = v;
                continue;
            }
        }
        if (!got_ts) {
            if (parseI64(line, "timestamp:")) |v| {
                got_ts = true;
                token_ts = v;
                continue;
            }
        }
        if (!got_nonce) {
            if (parseText(line, "nonce:")) |v| {
                if (v.len == 0 or v.len > token_nonce.len) return false;
                std.mem.copyForwards(u8, token_nonce[0..v.len], v);
                token_nonce_len = v.len;
                got_nonce = true;
                continue;
            }
        }
        if (!got_counter) {
            if (parseI64(line, "counter:")) |v| {
                got_counter = true;
                token_counter = v;
                continue;
            }
        }
        if (!got_root_attested) {
            if (parseBool(line, "root_attested:")) |v| {
                got_root_attested = true;
                token_root_attested = v;
                continue;
            }
        }
    }

    if (!got_ring or !got_attested or !got_ts or !got_counter) return false;
    if (!token_attested) return false;
    if (token_ring != required_ring) return false;
    if (required_ring == -2) {
        if (!got_root_attested or !token_root_attested) return false;
    }
    if (max_age_sec <= 0) return false;
    const now = std.time.timestamp();
    if (token_ts > now) return false;
    if ((now - token_ts) > max_age_sec) return false;

    if (expected_nonce) |nonce| {
        if (!got_nonce) return false;
        if (!std.mem.eql(u8, nonce, token_nonce[0..token_nonce_len])) return false;
    }

    if (replay_state_path.len == 0) return false;
    const state_exists = isSecureRegularFile(replay_state_path);
    var last_counter: i64 = -1;

    if (state_exists) {
        const sf = std.fs.openFileAbsolute(replay_state_path, .{ .mode = .read_only }) catch return false;
        defer sf.close();
        var sbr = std.io.bufferedReader(sf.reader());
        var sr = sbr.reader();
        var sbuf: [128]u8 = undefined;
        const sline = sr.readUntilDelimiterOrEof(&sbuf, '\n') catch return false;
        if (sline) |sl| {
            const t = trimLine(sl);
            last_counter = std.fmt.parseInt(i64, t, 10) catch -1;
        }
    }

    if (token_counter <= last_counter) return false;

    const wf = std.fs.createFileAbsolute(replay_state_path, .{
        .read = false,
        .truncate = true,
        .mode = 0o600,
    }) catch return false;
    defer wf.close();
    wf.writer().print("{d}\n", .{token_counter}) catch return false;
    return true;
}

pub export fn skv_validate_attestation_token(
    token_path_c: [*c]const u8,
    required_ring: i32,
    max_age_sec: i64,
    expected_nonce_c: [*c]const u8,
    replay_state_path_c: [*c]const u8,
) callconv(.C) c_int {
    if (token_path_c == null or replay_state_path_c == null) return 0;
    const token_path = std.mem.span(token_path_c);
    const replay_state_path = std.mem.span(replay_state_path_c);
    if (token_path.len == 0 or replay_state_path.len == 0) return 0;

    const expected_nonce: ?[]const u8 = if (expected_nonce_c == null)
        null
    else
        std.mem.span(expected_nonce_c);

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const ok = parseToken(
        allocator,
        token_path,
        required_ring,
        max_age_sec,
        expected_nonce,
        replay_state_path,
    );
    return if (ok) 1 else 0;
}
