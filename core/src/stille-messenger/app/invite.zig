//! Короткий инвайт-код.
//!
//! v1 (совместимость): shopot1.<base64url(bundle|имя)>[@host:port] —
//! имя зашито в код, но подключение требует взаимного add.
//!
//! v2 (односторонний): stille://i/<base64url(bundle|secret16|имя)>[@host:port]
//! Держатель кода redeem-ит его ОДНИМ add: контакт поднимается, легитимность
//! сессии доказывается JOIN-конвертом (HMAC по secret). Секрет одноразовый.
//! Старые коды shopot://i/ принимаются как legacy.
const std = @import("std");

pub const Error = error{
    BadCode,
    BadName,
    BadAddr,
};

pub const max_name = 32;
/// Длина одноразового секрета приглашения (v2).
pub const secret_len = 16;
/// Префикс v2-кода (URL-схема — кликабелен в мессенджерах/браузерах).
pub const v2_prefix = "stille://i/";
/// Префикс v2-кодов старого неймспейса: принимаем, но больше не генерим.
pub const legacy_v2_prefix = "shopot://i/";

/// Разобранный инвайт. host_len == 0 — адрес не указан (найдём через LAN).
pub const Invite = struct {
    bundle: [64]u8 = @splat(0),
    name_buf: [max_name]u8 = undefined,
    name_len: u8 = 0,
    host_buf: [64]u8 = undefined,
    host_len: u8 = 0,
    port: u16 = 0,
    /// v2: одноразовый секрет приглашения; у v1 — нули.
    secret: [secret_len]u8 = @splat(0),
    /// true — код v2: redeem через JOIN-конверт (односторонний add).
    v2: bool = false,
    /// true — адрес в коде указывает на РЕЛЕЙ (@r/host:port): подключение
    /// через marker-спаривание, пир не видит наш IP.
    relay: bool = false,

    pub fn name(self: *const Invite) []const u8 {
        return self.name_buf[0..self.name_len];
    }
    pub fn addr(self: *const Invite) ?[]const u8 {
        if (self.host_len == 0) return null;
        return self.host_buf[0..self.host_len];
    }
};

/// Кодирует в буфер. Возвращает срез буфера.
pub fn encode(buf: []u8, bundle: [64]u8, name: []const u8, addr_: ?[]const u8) Error![]const u8 {
    if (name.len == 0 or name.len > max_name) return Error.BadName;
    var raw: [64 + 1 + max_name]u8 = undefined;
    raw[0..64].* = bundle;
    raw[64] = @intCast(name.len);
    @memcpy(raw[65 .. 65 + name.len], name);
    // канонический размер: bundle + 1 + имя (без мусорного хвоста raw).
    // b64 от максимума (97 байт) = 130 знаков — буфер с запасом.
    var b64: [132]u8 = undefined;
    const enc_len = std.base64.url_safe_no_pad.Encoder.calcSize(65 + name.len);
    _ = std.base64.url_safe_no_pad.Encoder.encode(b64[0..enc_len], raw[0 .. 65 + name.len]);
    var n: usize = 0;
    const addr_len: usize = if (addr_) |a| (if (a.len > 0) a.len + 1 else 0) else 0;
    if (buf.len < "shopot1.".len + enc_len + addr_len) return Error.BadCode;
    @memcpy(buf[n .. n + 8], "shopot1.");
    n += 8;
    @memcpy(buf[n .. n + enc_len], b64[0..enc_len]);
    n += enc_len;
    if (addr_) |a| {
        if (a.len > 0) {
            buf[n] = '@';
            n += 1;
            @memcpy(buf[n .. n + a.len], a);
            n += a.len;
        }
    }
    return buf[0..n];
}

test "invite: имя макс. длины + адрес не переполняют буфер" {
    var buf: [256]u8 = undefined;
    var name: [max_name]u8 = @splat('a');
    const code = try encode(&buf, @splat(7), &name, "192.168.100.100:65535");
    // декод обратно: имя и адрес выживают (addr() — только хост,
    // порт отдельно: см. decode/main.zig acceptInvite)
    const inv = try decode(code);
    try std.testing.expectEqualSlices(u8, &name, inv.name());
    try std.testing.expectEqualStrings("192.168.100.100", inv.addr().?);
    try std.testing.expectEqual(@as(u16, 65535), inv.port);
}

/// Кодирует v2 (одностороннее приглашение): bundle|secret16|имя.
/// Возвращает срез буфера.
pub fn encode2(buf: []u8, bundle: [64]u8, secret: [secret_len]u8, name: []const u8, addr_: ?[]const u8) Error![]const u8 {
    if (name.len == 0 or name.len > max_name) return Error.BadName;
    const body_len = 64 + secret_len + 1 + name.len;
    var raw: [64 + secret_len + 1 + max_name]u8 = undefined;
    raw[0..64].* = bundle;
    raw[64 .. 64 + secret_len].* = secret;
    raw[64 + secret_len] = @intCast(name.len);
    @memcpy(raw[64 + secret_len + 1 ..][0..name.len], name);
    var b64: [156]u8 = undefined;
    const enc_len = std.base64.url_safe_no_pad.Encoder.calcSize(body_len);
    _ = std.base64.url_safe_no_pad.Encoder.encode(b64[0..enc_len], raw[0..body_len]);
    const addr_len: usize = if (addr_) |a| (if (a.len > 0) a.len + 1 else 0) else 0;
    if (buf.len < v2_prefix.len + enc_len + addr_len) return Error.BadCode;
    var n: usize = 0;
    @memcpy(buf[n .. n + v2_prefix.len], v2_prefix);
    n += v2_prefix.len;
    @memcpy(buf[n .. n + enc_len], b64[0..enc_len]);
    n += enc_len;
    if (addr_) |a| {
        if (a.len > 0) {
            buf[n] = '@';
            n += 1;
            @memcpy(buf[n .. n + a.len], a);
            n += a.len;
        }
    }
    return buf[0..n];
}

/// Разбирает код v1 (shopot1. или голый b64) или v2 (stille://i/,
/// legacy shopot://i/).
pub fn decode(code: []const u8) Error!Invite {
    var s = code;
    var inv = Invite{};
    if (std.mem.startsWith(u8, s, v2_prefix)) {
        s = s[v2_prefix.len..];
        inv.v2 = true;
    } else if (std.mem.startsWith(u8, s, legacy_v2_prefix)) {
        s = s[legacy_v2_prefix.len..];
        inv.v2 = true;
    } else if (std.mem.startsWith(u8, s, "shopot1.")) {
        s = s["shopot1.".len..];
    }
    // хвост @host:port — вне base64url-алфавита
    var host_part: []const u8 = "";
    if (std.mem.lastIndexOfScalar(u8, s, '@')) |at| {
        host_part = s[at + 1 ..];
        s = s[0..at];
    }
    const dec = std.base64.url_safe_no_pad.Decoder;
    if (inv.v2) {
        // v2: bundle(64) || secret(16) || name_len u8 || имя
        var raw: [64 + secret_len + 1 + max_name]u8 = undefined;
        const n = dec.calcSizeForSlice(s) catch return Error.BadCode;
        if (n < 64 + secret_len + 2 or n > raw.len) return Error.BadCode;
        dec.decode(raw[0..n], s) catch return Error.BadCode;
        inv.bundle = raw[0..64].*;
        inv.secret = raw[64 .. 64 + secret_len].*;
        const nl = raw[64 + secret_len];
        if (nl == 0 or nl > max_name) return Error.BadName;
        if (64 + secret_len + 1 + @as(usize, nl) != n) return Error.BadCode;
        inv.name_len = nl;
        @memcpy(inv.name_buf[0..nl], raw[64 + secret_len + 1 ..][0..nl]);
    } else {
        // v1: bundle(64) || name_len u8 || имя
        var raw: [64 + 1 + max_name]u8 = undefined;
        const n = dec.calcSizeForSlice(s) catch return Error.BadCode;
        // канонический размер: bundle + 1 + имя (65..97 байт)
        if (n < 65 + 1 or n > raw.len) return Error.BadCode;
        dec.decode(raw[0..n], s) catch return Error.BadCode;
        inv.bundle = raw[0..64].*;
        const nl = raw[64];
        if (nl == 0 or nl > max_name) return Error.BadName;
        if (65 + @as(usize, nl) != n) return Error.BadCode;
        inv.name_len = nl;
        @memcpy(inv.name_buf[0..nl], raw[65 .. 65 + nl]);
    }
    if (std.mem.startsWith(u8, host_part, "r/")) {
        inv.relay = true;
        host_part = host_part[2..];
    }
    if (host_part.len > 0) {
        const colon = std.mem.lastIndexOfScalar(u8, host_part, ':') orelse return Error.BadAddr;
        inv.port = std.fmt.parseInt(u16, host_part[colon + 1 ..], 10) catch return Error.BadAddr;
        if (colon == 0 or colon > 64) return Error.BadAddr;
        inv.host_len = @intCast(colon);
        @memcpy(inv.host_buf[0..colon], host_part[0..colon]);
    }
    return inv;
}

test "invite: v2 roundtrip с секретом, именем и адресом" {
    const testing = std.testing;
    var bundle: [64]u8 = undefined;
    for (&bundle, 0..) |*b, i| b.* = @truncate(i * 11);
    const secret: [secret_len]u8 = @splat(0xAB);
    var buf: [256]u8 = undefined;
    const code = try encode2(&buf, bundle, secret, "mom", "10.0.0.5:7777");
    const inv = try decode(code);
    try testing.expect(inv.v2);
    try testing.expectEqualSlices(u8, &bundle, &inv.bundle);
    try testing.expectEqualSlices(u8, &secret, &inv.secret);
    try testing.expectEqualStrings("mom", inv.name());
    try testing.expectEqualStrings("10.0.0.5", inv.addr().?);
    try testing.expectEqual(@as(u16, 7777), inv.port);
    // v2 без адреса: LAN-захват
    const code2 = try encode2(&buf, bundle, secret, "mom", null);
    const inv2 = try decode(code2);
    try testing.expect(inv2.v2);
    try testing.expect(inv2.addr() == null);
}

test "invite: legacy shopot://i/ декодируется как v2" {
    const testing = std.testing;
    var bundle: [64]u8 = undefined;
    for (&bundle, 0..) |*b, i| b.* = @truncate(i * 5);
    var secret: [secret_len]u8 = undefined;
    for (&secret, 0..) |*b, i| b.* = @truncate(i * 3);
    var buf: [256]u8 = undefined;
    const code = try encode2(&buf, bundle, secret, "mom", null);
    try testing.expect(std.mem.startsWith(u8, code, v2_prefix));
    var legacy_buf: [256]u8 = undefined;
    const legacy = try std.fmt.bufPrint(&legacy_buf, "{s}{s}", .{ legacy_v2_prefix, code[v2_prefix.len..] });
    const inv = try decode(legacy);
    try testing.expect(inv.v2);
    try testing.expectEqualSlices(u8, &bundle, &inv.bundle);
    try testing.expectEqualSlices(u8, &secret, &inv.secret);
    try testing.expectEqualStrings("mom", inv.name());
}

test "invite: v1 код после добавления v2 всё ещё читается" {
    const testing = std.testing;
    var bundle: [64]u8 = undefined;
    for (&bundle, 0..) |*b, i| b.* = @truncate(i * 5);
    var buf: [256]u8 = undefined;
    const code = try encode(&buf, bundle, "vova", null);
    const inv = try decode(code);
    try testing.expect(!inv.v2);
    try testing.expectEqualStrings("vova", inv.name());
    try testing.expectEqualSlices(u8, &bundle, &inv.bundle);
}

test "invite: roundtrip с адресом и без" {
    const testing = std.testing;
    var bundle: [64]u8 = undefined;
    for (&bundle, 0..) |*b, i| b.* = @truncate(i * 7);
    var buf: [256]u8 = undefined;
    const code = try encode(&buf, bundle, "puxxal", "192.168.1.5:7777");
    const inv = try decode(code);
    try testing.expectEqualSlices(u8, &bundle, &inv.bundle);
    try testing.expectEqualStrings("puxxal", inv.name());
    // addr() — только хост: порт отдельно (semantics decode)
    try testing.expectEqualStrings("192.168.1.5", inv.addr().?);
    try testing.expectEqual(@as(u16, 7777), inv.port);
    const code2 = try encode(&buf, bundle, "eryn", null);
    const inv2 = try decode(code2);
    try testing.expectEqualStrings("eryn", inv2.name());
    try testing.expect(inv2.addr() == null);
}

// ---------------------------------------------------------------- v3 (i3)
// Гибридное одностороннее приглашение (0.3.0 / API 2.7.0): прямой LAN
// endpoint + fallback-релей в ОДНОМ коде. Тело — строго типизированные
// little-endian поля, base64url без паддинга, внешний @-хвост ЗАПРЕЩЁН
// (адреса живут в теле). Префикс stille://i3/ отдельный от v2: старое ядро
// отвергает код без скрытого downgrade, держатель различает версии до dial.
// Секрет — тот же одноразовый secret16, что в v2; JOIN-конверт не меняется.

/// Префикс v3-кода (гибрид direct+relay).
pub const v3_prefix = "stille://i3/";
/// Префикс v3-кодов старого неймспейса: принимаем, но больше не генерим.
pub const legacy_v3_prefix = "shopot://i3/";
/// Максимум общей длины v3-кода в байтах (QR/передача).
pub const v3_max_code = 512;
/// Максимум строки адреса "host:port" в теле.
pub const v3_addr_max = 70;

/// Endpoint "host:port": host — IPv4-литерал или имя (без ':'), порт 1..65535.
pub const Endpoint = struct {
    host_buf: [64]u8 = @splat(0),
    host_len: u8 = 0,
    port: u16 = 0,

    pub fn host(self: *const Endpoint) []const u8 {
        return self.host_buf[0..self.host_len];
    }
    /// "host:port" в буфер; null — endpoint не задан (host_len == 0).
    pub fn addr(self: *const Endpoint, buf: []u8) ?[]const u8 {
        if (self.host_len == 0 or self.port == 0) return null;
        return std.fmt.bufPrint(buf, "{s}:{d}", .{ self.host(), self.port }) catch null;
    }
};

/// Разобранное v3-приглашение: bundle, одноразовый секрет, имя и до двух
/// endpoint'ов (direct — пробуется первым, relay — fallback).
pub const InviteV3 = struct {
    bundle: [64]u8 = @splat(0),
    secret: [secret_len]u8 = @splat(0),
    name_buf: [max_name]u8 = @splat(0),
    name_len: u8 = 0,
    direct: Endpoint = .{},
    has_direct: bool = false,
    relay: Endpoint = .{},
    has_relay: bool = false,

    pub fn name(self: *const InviteV3) []const u8 {
        return self.name_buf[0..self.name_len];
    }
};

/// Тело v3 до base64 (все целые little-endian):
/// [ver u8 = 3][flags u8][bundle 64][secret 16][name_len u16][name]
/// [direct_len u16][direct][relay_len u16][relay].
/// flags: bit0 = есть direct, bit1 = есть relay; прочие биты запрещены.
const v3_body_fixed = 1 + 1 + 64 + secret_len + 2 + 2 + 2;
const v3_body_max = v3_body_fixed + max_name + 2 * v3_addr_max;

/// Строгий разбор "host:port" (host 1..64 без ':', порт 1..65535).
fn parseEndpoint(s: []const u8) Error!Endpoint {
    if (s.len == 0 or s.len > v3_addr_max) return Error.BadAddr;
    const colon = std.mem.lastIndexOfScalar(u8, s, ':') orelse return Error.BadAddr;
    const host = s[0..colon];
    if (host.len == 0 or host.len > 64) return Error.BadAddr;
    if (std.mem.indexOfScalar(u8, host, ':') != null) return Error.BadAddr;
    const port = std.fmt.parseInt(u16, s[colon + 1 ..], 10) catch return Error.BadAddr;
    if (port == 0) return Error.BadAddr;
    var ep = Endpoint{};
    @memcpy(ep.host_buf[0..host.len], host);
    ep.host_len = @intCast(host.len);
    ep.port = port;
    return ep;
}

/// Кодирует v3 (гибрид): direct/relay — null или пустой срез = отсутствует;
/// хотя бы один endpoint обязателен. Возвращает срез буфера.
pub fn encode3(buf: []u8, bundle: [64]u8, secret: [secret_len]u8, name: []const u8, direct: ?[]const u8, relay: ?[]const u8) Error![]const u8 {
    if (name.len == 0 or name.len > max_name) return Error.BadName;
    const d: ?[]const u8 = if (direct) |a| (if (a.len > 0) a else null) else null;
    const r: ?[]const u8 = if (relay) |a| (if (a.len > 0) a else null) else null;
    if (d == null and r == null) return Error.BadCode;
    if (d) |a| _ = try parseEndpoint(a);
    if (r) |a| _ = try parseEndpoint(a);
    var raw: [v3_body_max]u8 = undefined;
    raw[0] = 3;
    raw[1] = @as(u8, if (d != null) 1 else 0) | @as(u8, if (r != null) 2 else 0);
    var n: usize = 2;
    @memcpy(raw[n .. n + 64], &bundle);
    n += 64;
    @memcpy(raw[n .. n + secret_len], &secret);
    n += secret_len;
    std.mem.writeInt(u16, raw[n .. n + 2][0..2], @intCast(name.len), .little);
    n += 2;
    @memcpy(raw[n .. n + name.len], name);
    n += name.len;
    const dlen: u16 = if (d) |a| @intCast(a.len) else 0;
    std.mem.writeInt(u16, raw[n .. n + 2][0..2], dlen, .little);
    n += 2;
    if (d) |a| {
        @memcpy(raw[n .. n + a.len], a);
        n += a.len;
    }
    const rlen: u16 = if (r) |a| @intCast(a.len) else 0;
    std.mem.writeInt(u16, raw[n .. n + 2][0..2], rlen, .little);
    n += 2;
    if (r) |a| {
        @memcpy(raw[n .. n + a.len], a);
        n += a.len;
    }
    const enc_len = std.base64.url_safe_no_pad.Encoder.calcSize(n);
    if (v3_prefix.len + enc_len > v3_max_code) return Error.BadCode;
    if (buf.len < v3_prefix.len + enc_len) return Error.BadCode;
    @memcpy(buf[0..v3_prefix.len], v3_prefix);
    _ = std.base64.url_safe_no_pad.Encoder.encode(buf[v3_prefix.len .. v3_prefix.len + enc_len], raw[0..n]);
    return buf[0 .. v3_prefix.len + enc_len];
}

/// Разбирает v3-код (stille://i3/..., legacy shopot://i3/...): строгая
/// валидация всех полей. Лишние биты flags, хвостовые байты тела,
/// внешний '@' — отказ.
pub fn decode3(code: []const u8) Error!InviteV3 {
    if (code.len > v3_max_code) return Error.BadCode;
    var s = code;
    if (std.mem.startsWith(u8, s, v3_prefix)) {
        s = s[v3_prefix.len..];
    } else if (std.mem.startsWith(u8, s, legacy_v3_prefix)) {
        s = s[legacy_v3_prefix.len..];
    } else {
        return Error.BadCode;
    }
    // v3: адреса только в теле; '@' вне base64url-алфавита — чужой хвост
    if (std.mem.indexOfScalar(u8, s, '@') != null) return Error.BadCode;
    const dec = std.base64.url_safe_no_pad.Decoder;
    const n = dec.calcSizeForSlice(s) catch return Error.BadCode;
    if (n < v3_body_fixed + 1) return Error.BadCode;
    if (n > v3_body_max) return Error.BadCode;
    var raw: [v3_body_max]u8 = undefined;
    dec.decode(raw[0..n], s) catch return Error.BadCode;
    if (raw[0] != 3) return Error.BadCode;
    const flags = raw[1];
    if (flags & ~@as(u8, 3) != 0) return Error.BadCode;
    const has_direct = flags & 1 != 0;
    const has_relay = flags & 2 != 0;
    var inv = InviteV3{};
    inv.bundle = raw[2 .. 2 + 64].*;
    @memcpy(inv.secret[0..secret_len], raw[66 .. 66 + secret_len]);
    var pos: usize = 66 + secret_len;
    const name_len = std.mem.readInt(u16, raw[pos .. pos + 2][0..2], .little);
    pos += 2;
    if (name_len == 0 or name_len > max_name) return Error.BadName;
    if (pos + name_len > n) return Error.BadCode;
    inv.name_len = @intCast(name_len);
    @memcpy(inv.name_buf[0..name_len], raw[pos .. pos + name_len]);
    pos += name_len;
    const dlen = std.mem.readInt(u16, raw[pos .. pos + 2][0..2], .little);
    pos += 2;
    if (has_direct != (dlen > 0)) return Error.BadCode;
    if (pos + dlen > n) return Error.BadCode;
    if (dlen > 0) {
        inv.direct = try parseEndpoint(raw[pos .. pos + dlen]);
        inv.has_direct = true;
    }
    pos += dlen;
    const rlen = std.mem.readInt(u16, raw[pos .. pos + 2][0..2], .little);
    pos += 2;
    if (has_relay != (rlen > 0)) return Error.BadCode;
    if (pos + rlen != n) return Error.BadCode;
    if (rlen > 0) {
        inv.relay = try parseEndpoint(raw[pos .. pos + rlen]);
        inv.has_relay = true;
    }
    if (!inv.has_direct and !inv.has_relay) return Error.BadCode;
    return inv;
}

test "invite: v3 roundtrip с обоими endpoint'ами" {
    const testing = std.testing;
    var bundle: [64]u8 = undefined;
    for (&bundle, 0..) |*b, i| b.* = @truncate(i * 13);
    const secret: [secret_len]u8 = @splat(0xCD);
    var buf: [v3_max_code]u8 = undefined;
    const code = try encode3(&buf, bundle, secret, "mom", "192.168.100.100:7777", "relay.example.com:9000");
    try testing.expect(code.len <= v3_max_code);
    try testing.expect(std.mem.startsWith(u8, code, v3_prefix));
    const inv = try decode3(code);
    try testing.expectEqualSlices(u8, &bundle, &inv.bundle);
    try testing.expectEqualSlices(u8, &secret, &inv.secret);
    try testing.expectEqualStrings("mom", inv.name());
    try testing.expect(inv.has_direct and inv.has_relay);
    try testing.expectEqualStrings("192.168.100.100", inv.direct.host());
    try testing.expectEqual(@as(u16, 7777), inv.direct.port);
    try testing.expectEqualStrings("relay.example.com", inv.relay.host());
    try testing.expectEqual(@as(u16, 9000), inv.relay.port);
    var ab: [96]u8 = undefined;
    try testing.expectEqualStrings("192.168.100.100:7777", inv.direct.addr(&ab).?);
    try testing.expectEqualStrings("relay.example.com:9000", inv.relay.addr(&ab).?);
}

test "invite: legacy shopot://i3/ декодируется как v3" {
    const testing = std.testing;
    const bundle: [64]u8 = @splat(5);
    var buf: [v3_max_code]u8 = undefined;
    const code = try encode3(&buf, bundle, @splat(1), "a", "10.0.0.5:7777", null);
    try testing.expect(std.mem.startsWith(u8, code, v3_prefix));
    var legacy_buf: [v3_max_code]u8 = undefined;
    const legacy = try std.fmt.bufPrint(&legacy_buf, "{s}{s}", .{ legacy_v3_prefix, code[v3_prefix.len..] });
    const inv = try decode3(legacy);
    try testing.expect(inv.has_direct and !inv.has_relay);
    try testing.expectEqualStrings("a", inv.name());
    try testing.expectEqualStrings("10.0.0.5", inv.direct.host());
}

test "invite: v3 только direct / только relay" {
    const testing = std.testing;
    const bundle: [64]u8 = @splat(5);
    var buf: [v3_max_code]u8 = undefined;
    const c1 = try encode3(&buf, bundle, @splat(1), "a", "10.0.0.5:7777", null);
    const inv1 = try decode3(c1);
    try testing.expect(inv1.has_direct and !inv1.has_relay);
    // пустая строка = отсутствует
    const c2 = try encode3(&buf, bundle, @splat(1), "a", "", "r.host:9000");
    const inv2 = try decode3(c2);
    try testing.expect(!inv2.has_direct and inv2.has_relay);
}

test "invite: v3 отказы — валидация полей" {
    const testing = std.testing;
    const bundle: [64]u8 = @splat(9);
    var buf: [v3_max_code]u8 = undefined;
    // без endpoint'ов
    try testing.expectError(Error.BadCode, encode3(&buf, bundle, @splat(1), "a", null, null));
    // невалидные адреса
    try testing.expectError(Error.BadAddr, encode3(&buf, bundle, @splat(1), "a", "nohost:0", null));
    try testing.expectError(Error.BadAddr, encode3(&buf, bundle, @splat(1), "a", "host:65536", null));
    try testing.expectError(Error.BadAddr, encode3(&buf, bundle, @splat(1), "a", ":7777", null));
    try testing.expectError(Error.BadAddr, encode3(&buf, bundle, @splat(1), "a", "host", null));
    // имя вне диапазона
    var long_name: [max_name + 1]u8 = @splat('x');
    _ = &long_name;
    try testing.expectError(Error.BadName, encode3(&buf, bundle, @splat(1), &long_name, "h:1", null));
    // буфер мал
    var small: [8]u8 = undefined;
    try testing.expectError(Error.BadCode, encode3(&small, bundle, @splat(1), "a", "h:1", null));
}

test "invite: v3 отказы — структура тела" {
    const testing = std.testing;
    const bundle: [64]u8 = @splat(9);
    var buf: [v3_max_code]u8 = undefined;
    const code = try encode3(&buf, bundle, @splat(1), "mom", "10.0.0.5:7777", "r.host:9000");
    // '@'-хвост запрещён
    var tailed: [v3_max_code]u8 = undefined;
    @memcpy(tailed[0..code.len], code);
    tailed[code.len] = '@';
    try testing.expectError(Error.BadCode, decode3(tailed[0 .. code.len + 1]));
    // чужой префикс / пустой код
    try testing.expectError(Error.BadCode, decode3("shopot://i/abc"));
    try testing.expectError(Error.BadCode, decode3("shopot1.abc"));
    try testing.expectError(Error.BadCode, decode3(""));
    // тело с испорченным ver/флагами/хвостом: пересобираем base64 руками
    const s = code[v3_prefix.len..];
    const dec = std.base64.url_safe_no_pad.Decoder;
    const n = dec.calcSizeForSlice(s) catch unreachable;
    var raw: [v3_body_max]u8 = undefined;
    dec.decode(raw[0..n], s) catch unreachable;
    const tryBad = struct {
        fn go(bad: []const u8, len: usize) Error!void {
            var b64: [420]u8 = undefined;
            const el = std.base64.url_safe_no_pad.Encoder.calcSize(len);
            _ = std.base64.url_safe_no_pad.Encoder.encode(b64[0..el], bad[0..len]);
            var full: [512]u8 = undefined;
            @memcpy(full[0..v3_prefix.len], v3_prefix);
            @memcpy(full[v3_prefix.len .. v3_prefix.len + el], b64[0..el]);
            _ = try decode3(full[0 .. v3_prefix.len + el]);
        }
    }.go;
    var bad: [v3_body_max]u8 = undefined;
    // ver != 3
    @memcpy(bad[0..n], raw[0..n]);
    bad[0] = 2;
    try testing.expectError(Error.BadCode, tryBad(&bad, n));
    // лишний бит flags
    @memcpy(bad[0..n], raw[0..n]);
    bad[1] |= 4;
    try testing.expectError(Error.BadCode, tryBad(&bad, n));
    // бит флага без адреса (снимаем bit0, длина direct осталась)
    @memcpy(bad[0..n], raw[0..n]);
    bad[1] &= ~@as(u8, 1);
    try testing.expectError(Error.BadCode, tryBad(&bad, n));
    // хвостовой байт тела (лишняя длина relay_len)
    @memcpy(bad[0..n], raw[0..n]);
    bad[n] = 0;
    try testing.expectError(Error.BadCode, tryBad(&bad, n + 1));
}

test "invite: v2 decode отвергает v3-код" {
    const testing = std.testing;
    const bundle: [64]u8 = @splat(3);
    var buf: [v3_max_code]u8 = undefined;
    const code = try encode3(&buf, bundle, @splat(1), "mom", "10.0.0.5:7777", null);
    try testing.expectError(Error.BadCode, decode(code));
}

// ---------------------------------------------------------------- short
// Короткий код личности для диплинков stille.im/invite/{code}: 9 знаков,
// детерминированных из ПУБЛИЧНОГО bundle, без хранения. Это ИДЕНТИФИКАТОР,
// не секрет: код = base32(SHA-256(bundle)[0..40 бит]) + контрольный знак.
// Код необратим информационно (45 бит < 512 бит bundle): из него нельзя
// восстановить bundle — резолв short -> полный код обязан знать bundle
// заранее (локальные контакты/своё имя; для незнакомцев сайт-рендеву
// хранит полный код и отдаёт его диплинком, ядро принимает его через
// ACCEPT_INVITE/EX). Код не даёт никаких прав и не скрывает bundle.

/// Длина короткого кода: 8 знаков данных + 1 контрольный.
pub const short_code_len = 9;
/// Crockford base32: без I, L, O, U (неоднозначные при вводе человеком).
const short_alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const short_data_len = short_code_len - 1; // 8 знаков = 40 бит

/// Контрольный знак: взвешенная позициями сумма значений знаков ловит
/// одиночные замены и перестановки соседних знаков (равные знаки
/// перестановкой не ловятся — как у любой позиционной контрольной суммы).
fn shortCheck(chars: *const [short_data_len]u8) u8 {
    var acc: usize = 0;
    for (chars, 0..) |c, i| acc +%= (i + 1) *% (std.mem.indexOfScalar(u8, short_alphabet, c) orelse 0);
    return @intCast(acc & 31);
}

/// Короткий код из bundle: детерминированный, один и тот же всегда.
pub fn shortCodeFromBundle(bundle: [64]u8) [short_code_len]u8 {
    var d: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&bundle, &d, .{});
    var v: u64 = 0;
    for (d[0..5]) |b| v = (v << 8) | b;
    var out: [short_code_len]u8 = undefined;
    var i: usize = short_data_len;
    while (i > 0) {
        i -= 1;
        out[i] = short_alphabet[@intCast(v & 31)];
        v >>= 5;
    }
    out[short_data_len] = short_alphabet[shortCheck(out[0..short_data_len])];
    return out;
}

/// Нормализация пользовательского ввода кода: регистр + частые опечатки
/// по Крокфорду (I/i/l/L -> 1, O/o -> 0, U/u -> V), затем проверка
/// контрольного знака. null — длина не 9, знак вне алфавита или
/// контрольный знак не сходится.
pub fn shortCodeNormalize(code: []const u8) ?[short_code_len]u8 {
    if (code.len != short_code_len) return null;
    var out: [short_code_len]u8 = undefined;
    for (code, 0..) |c, i| {
        const n: u8 = switch (c) {
            '0'...'9', 'A'...'H', 'J'...'K', 'M'...'N', 'P'...'T', 'V'...'Z' => c,
            'a'...'h', 'j'...'k', 'm'...'n', 'p'...'t', 'v'...'z' => c - 32,
            'I', 'i', 'L', 'l' => '1',
            'O', 'o' => '0',
            'U', 'u' => 'V',
            else => return null,
        };
        out[i] = n;
    }
    const want = shortCheck(out[0..short_data_len]);
    if (out[short_data_len] != short_alphabet[want]) return null;
    return out;
}

test "invite: короткий код — детерминизм, формат, опечатки" {
    const testing = std.testing;
    const bundle: [64]u8 = @splat(9);
    // один и тот же bundle -> один и тот же код
    const a = shortCodeFromBundle(bundle);
    const b = shortCodeFromBundle(bundle);
    try testing.expectEqualSlices(u8, &a, &b);
    // другой bundle -> другой код (на фиксированных векторах)
    const c = shortCodeFromBundle(@splat(10));
    try testing.expect(!std.mem.eql(u8, &a, &c));
    // формат: только алфавит Crockford
    for (a) |ch| try testing.expect(std.mem.indexOfScalar(u8, short_alphabet, ch) != null);
    // нормализация: регистр и опечатки Крокфорда принимаются
    var lower: [short_code_len]u8 = undefined;
    for (a, 0..) |ch, i| {
        lower[i] = if (ch >= 'A' and ch <= 'Z') ch + 32 else ch;
        if (ch == '1') lower[i] = 'I'; // частая опечатка
    }
    const norm = shortCodeNormalize(&lower) orelse return error.TestUnexpectedResult;
    try testing.expectEqualSlices(u8, &a, &norm);
    // контрольный знак обязателен: подмена последнего знака отвергается
    var bad = a;
    bad[short_data_len] = short_alphabet[(shortCheck(bad[0..short_data_len]) +% 1) & 31];
    try testing.expect(shortCodeNormalize(&bad) == null);
    // длина не 9 и знак вне алфавита отвергаются
    try testing.expect(shortCodeNormalize(a[0..8]) == null);
    bad[0] = '?';
    try testing.expect(shortCodeNormalize(&bad) == null);
}

test "invite: короткий код — золотой вектор формата" {
    // Формат фиксируется золотым вектором: случайный рефактор кодирования
    // не должен молча сменить коды у живых пользователей (ссылки умрут).
    const bundle: [64]u8 = @splat(9);
    const code = shortCodeFromBundle(bundle);
    try std.testing.expectEqualStrings("N9S5WMD9D", &code);
}
