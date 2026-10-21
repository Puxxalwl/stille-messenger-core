//! UPnP IGD-клиент (2.10.0, direct-first): просим роутер открыть порт.
//! SSDP-обнаружение шлюза (M-SEARCH, UDP-мультикаст 239.255.255.250:1900)
//! + минимальный HTTP/1.1 + SOAP к WANIPConnection. Результат — публичный
//! IPv4 endpoint (external ip + mapped port), который ядро публикует
//! контакту: пир диалит напрямую, релей для данных не нужен.
//!
//! Протокол UPnP — ВНЕШНИЙ стандарт (HTTP/XML — язык Internet Gateway
//! Device): это межстековая совместимость, как fake-TLS-мимикрия, а не
//! наш провод (наш провод остаётся бинарным LE). Никаких зависимостей:
//! сырые сокеты через net/sysfd.zig, bounded-буферы, дедлайны на каждый
//! сетевой шаг. Ответ роутера — НЕ доверенный ввод: парсеры толерантны к
//! мусору и молча отказывают (null), переполнений нет.
//!
//! Ресурсные границы: SSDP — 1 запрос, таймаут 1500 мс; HTTP-ответ ≤
//! http_max; TCP-операции — дедлайн upnp_io_ms; на всё сопоставление —
//! один поток вызывающего, повторов внутри нет (политика повторов — у
//! app-слоя).
const std = @import("std");
const posix = std.posix;
const sysfd = @import("sysfd.zig");

/// Дедлайн одной TCP-операции (connect/read/write к IGD).
pub const upnp_io_ms: u32 = 3000;
/// SSDP-таймаут (M-SEARCH ждёт ответы мультикаст-группы).
pub const ssdp_timeout_ms: u32 = 1500;
/// Максимум HTTP-ответа (описание IGD: 2-10 КБ у реальных роутеров).
pub const http_max: usize = 8192;
/// Максимум SOAP-запроса (AddPortMapping ~600 байт + запас).
pub const soap_max: usize = 1024;

pub const Error = error{
    BadFrame,
    Network,
    OutOfMemory,
    Timeout,
};

/// Успешное сопоставление: внешний endpoint, который слышен из интернета.
pub const Mapping = struct {
    ip: [4]u8,
    port: u16,
};

/// Разобранный "http://host:port/path" (хост — только IPv4-литерал или
/// домен БЕЗ схемы; path начинается с '/'). Составляющие — срезы входа.
pub const HttpUrl = struct {
    host: []const u8,
    port: u16,
    path: []const u8,

    pub fn parse(url: []const u8) ?HttpUrl {
        if (!std.mem.startsWith(u8, url, "http://")) return null;
        const rest = url["http://".len..];
        const slash = std.mem.indexOfScalar(u8, rest, '/') orelse return null;
        const authority = rest[0..slash];
        var host = authority;
        var port: u16 = 80;
        if (std.mem.lastIndexOfScalar(u8, authority, ':')) |colon| {
            host = authority[0..colon];
            port = std.fmt.parseInt(u16, authority[colon + 1 ..], 10) catch return null;
        }
        if (host.len == 0) return null;
        return .{ .host = host, .port = port, .path = rest[slash..] };
    }
};

/// Выделить содержимое первого тега <name>…</name> (bounded-скан, без
/// аллокаций, регистрозависимость UPC — роутеры пишут канонически).
/// null — тега нет или вход усечен.
pub fn tagValue(xml: []const u8, name: []const u8) ?[]const u8 {
    var open_buf: [64]u8 = undefined;
    var close_buf: [64]u8 = undefined;
    if (name.len + 2 > open_buf.len) return null;
    const open = std.fmt.bufPrint(&open_buf, "<{s}>", .{name}) catch return null;
    const close = std.fmt.bufPrint(&close_buf, "</{s}>", .{name}) catch return null;
    const start = std.mem.indexOf(u8, xml, open) orelse return null;
    const after = start + open.len;
    const end = std.mem.indexOfPos(u8, xml, after, close) orelse return null;
    return xml[after..end];
}

/// IPv4 "a.b.c.d" → байты (внешний адрес из NewExternalIPAddress).
fn parseIp4(text: []const u8) ?[4]u8 {
    const ip4 = std.Io.net.Ip4Address.parse(text, 0) catch return null;
    return ip4.bytes;
}

// ---- HTTP поверх sysfd (только для IGD; Connection: close) -------------

/// Соединение к host:port с дедлайном (неблокирующий connect + poll).
fn dialDeadline(host: []const u8, port: u16) Error!posix.socket_t {
    var ab: [64]u8 = undefined;
    const addr_str = std.fmt.bufPrint(&ab, "{s}:{d}", .{ host, port }) catch return error.BadFrame;
    const colon = std.mem.lastIndexOfScalar(u8, addr_str, ':') orelse return error.BadFrame;
    const port_num = std.fmt.parseInt(u16, addr_str[colon + 1 ..], 10) catch return error.BadFrame;
    const ip4 = std.Io.net.Ip4Address.parse(addr_str[0..colon], port_num) catch return error.BadFrame;
    const sa = sysfd.sockaddrIn(ip4.bytes, port_num);
    const fd = sysfd.socketTcp() catch return error.Network;
    errdefer sysfd.close(fd);
    sysfd.setNonblock(fd, true) catch return error.Network;
    sysfd.connectInNonblock(fd, &sa) catch return error.Network;
    if (!sysfd.pollWritable(fd, upnp_io_ms)) return error.Timeout;
    if (sysfd.soError(fd)) |e| {
        if (e != 0) return error.Network;
    }
    sysfd.setNonblock(fd, false) catch return error.Network;
    return fd;
}

/// HTTP-запрос (method + path + host + body) → ответ целиком (аллокация
/// ≤ http_max; вызывающий освобождает). Дедлайн на всё чтение.
fn httpRequest(alloc: std.mem.Allocator, host: []const u8, port: u16, path: []const u8, method: []const u8, content_type: ?[]const u8, soap_action: ?[]const u8, body: []const u8) Error![]u8 {
    var head: std.ArrayListUnmanaged(u8) = .empty;
    defer head.deinit(alloc);
    head.print(alloc, "{s} {s} HTTP/1.1\r\nHost: {s}\r\nConnection: close\r\n", .{ method, path, host }) catch return error.OutOfMemory;
    if (content_type) |ct| head.print(alloc, "Content-Type: {s}\r\n", .{ct}) catch return error.OutOfMemory;
    if (soap_action) |sa| head.print(alloc, "SOAPACTION: \"{s}\"\r\n", .{sa}) catch return error.OutOfMemory;
    head.print(alloc, "Content-Length: {d}\r\n\r\n", .{body.len}) catch return error.OutOfMemory;
    const fd = try dialDeadline(host, port);
    defer sysfd.close(fd);
    var req_buf: [http_max + soap_max]u8 = undefined;
    if (head.items.len + body.len > req_buf.len) return error.BadFrame;
    @memcpy(req_buf[0..head.items.len], head.items);
    @memcpy(req_buf[head.items.len..][0..body.len], body);
    sysfd.writeAll(fd, req_buf[0 .. head.items.len + body.len]) catch return error.Network;
    // читаем до EOF/close с дедлайном на каждый poll-тик
    var out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer out.deinit(alloc);
    var buf: [4096]u8 = undefined;
    while (out.items.len < http_max) {
        if (!sysfd.pollReadable(fd, upnp_io_ms)) return error.Timeout;
        const n = posix.read(fd, &buf) catch return error.Network;
        if (n == 0) break;
        out.appendSlice(alloc, buf[0..n]) catch return error.OutOfMemory;
    }
    return out.toOwnedSlice(alloc) catch return error.OutOfMemory;
}

/// HTTP-статус ответа (первая строка "HTTP/1.1 200 …").
fn statusCode(resp: []const u8) ?u16 {
    const sp1 = std.mem.indexOfScalar(u8, resp, ' ') orelse return null;
    const sp2 = std.mem.indexOfScalarPos(u8, resp, sp1 + 1, ' ') orelse resp.len;
    return std.fmt.parseInt(u16, resp[sp1 + 1 .. @min(sp2, resp.len)], 10) catch null;
}

// ---- SSDP ----------------------------------------------------------------

/// M-SEARCH к мультикаст-группе SSDP → LOCATION первого ответившего IGD
/// (аллокированная строка URL; вызывающий освобождает). null — никто не
/// ответил за ssdp_timeout_ms: роутер без UPnP, это норма, не ошибка.
pub fn ssdpDiscover(alloc: std.mem.Allocator) Error!?[]u8 {
    const fd = sysfd.socketUdp() catch return error.Network;
    defer sysfd.close(fd);
    const sa = sysfd.sockaddrIn(.{ 239, 255, 255, 250 }, 1900);
    const msearch =
        "M-SEARCH * HTTP/1.1\r\n" ++
        "HOST: 239.255.255.250:1900\r\n" ++
        "MAN: \"ssdp:discover\"\r\n" ++
        "MX: 1\r\n" ++
        "ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n";
    // sendto мультикастом; ответ может прийти unicast-ом на этот сокет
    sysfd.sendtoIn(fd, msearch, &sa);
    if (!sysfd.pollReadable(fd, ssdp_timeout_ms)) return null;
    if (!sysfd.pollReadable(fd, ssdp_timeout_ms)) return null;
    var buf: [2048]u8 = undefined;
    var from: sysfd.SockaddrIn = undefined;
    const n = sysfd.recvfromIn(fd, &buf, &from) orelse return error.Network;
    if (n == 0) return null;
    const resp = buf[0..n];
    // LOCATION: http://… (регистронезависимое имя заголовка)
    var line_it = std.mem.splitScalar(u8, resp, '\n');
    while (line_it.next()) |line_raw| {
        const line = std.mem.trim(u8, line_raw, " \r");
        if (line.len < 11) continue;
        if (!std.ascii.eqlIgnoreCase(line[0..9], "LOCATION:")) continue;
        const val = std.mem.trim(u8, line[9..], " ");
        if (HttpUrl.parse(val) == null) continue;
        return alloc.dupe(u8, val) catch return error.OutOfMemory;
    }
    return null;
}

// ---- SOAP -----------------------------------------------------------------

const service_type = "urn:schemas-upnp-org:service:WANIPConnection:1";

fn soapEnvelope(alloc: std.mem.Allocator, action: []const u8, inner: []const u8) Error![]u8 {
    var out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer out.deinit(alloc);
    out.print(alloc, "<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body><u:{s} xmlns:u=\"{s}\">", .{ action, service_type }) catch return error.OutOfMemory;
    out.appendSlice(alloc, inner) catch return error.OutOfMemory;
    out.print(alloc, "</u:{s}></s:Body></s:Envelope>", .{action}) catch return error.OutOfMemory;
    return out.toOwnedSlice(alloc) catch return error.OutOfMemory;
}

/// Прямое сопоставление порта через ГОТОВЫЙ control URL (склейка
/// LOCATION + URLBase + controlURL — см. requestMapping). internal_ip —
/// наш LAN-адрес (роутер форвардит на него), desc — метка в таблице NAT.
/// null — роутер отказал (нет UPnP/IGD-сервиса): нормальный исход.
pub fn addPortMapping(alloc: std.mem.Allocator, control_url: []const u8, internal_ip: [4]u8, internal_port: u16, external_port: u16, desc: []const u8) Error!?void {
    const url = HttpUrl.parse(control_url) orelse return error.BadFrame;
    var ip_buf: [16]u8 = undefined;
    var inner: std.ArrayListUnmanaged(u8) = .empty;
    defer inner.deinit(alloc);
    inner.print(alloc, "<NewRemoteHost></NewRemoteHost><NewExternalPort>{d}</NewExternalPort><NewProtocol>TCP</NewProtocol><NewInternalPort>{d}</NewInternalPort><NewInternalClient>{s}</NewInternalClient><NewEnabled>1</NewEnabled><NewPortMappingDescription>{s}</NewPortMappingDescription><NewLeaseDuration>0</NewLeaseDuration>", .{
        external_port,
        internal_port,
        fmtIp4Buf(&ip_buf, internal_ip),
        desc,
    }) catch return error.OutOfMemory;
    const body = try soapEnvelope(alloc, "AddPortMapping", inner.items);
    defer alloc.free(body);
    var action_buf: [128]u8 = undefined;
    const action = std.fmt.bufPrint(&action_buf, "{s}#AddPortMapping", .{service_type}) catch return error.BadFrame;
    const resp = httpRequest(alloc, url.host, url.port, url.path, "POST", "text/xml", action, body) catch |e| {
        return if (e == error.Timeout or e == error.Network) null else e;
    };
    defer alloc.free(resp);
    const code = statusCode(resp) orelse return null;
    if (code != 200) return null;
    return {};
}

/// Внешний IP роутера (GetExternalIPAddress) через ГОТОВЫЙ control URL.
pub fn externalIp(alloc: std.mem.Allocator, control_url: []const u8) Error!?[4]u8 {
    const url = HttpUrl.parse(control_url) orelse return error.BadFrame;
    const body = try soapEnvelope(alloc, "GetExternalIPAddress", "");
    defer alloc.free(body);
    var action_buf: [128]u8 = undefined;
    const action = std.fmt.bufPrint(&action_buf, "{s}#GetExternalIPAddress", .{service_type}) catch return error.BadFrame;
    const resp = httpRequest(alloc, url.host, url.port, url.path, "POST", "text/xml", action, body) catch |e| {
        return if (e == error.Timeout or e == error.Network) null else e;
    };
    defer alloc.free(resp);
    const code = statusCode(resp) orelse return null;
    if (code != 200) return null;
    const ip_text = tagValue(resp, "NewExternalIPAddress") orelse return null;
    return parseIp4(ip_text);
}

/// Полный цикл: LOCATION → описание → controlURL → AddPortMapping +
/// GetExternalIPAddress. Один проход, без повторов (политика — у app).
/// null на каждом шаге «роутер не умеет/отказал» — молча.
pub fn requestMapping(alloc: std.mem.Allocator, location: []const u8, internal_ip: [4]u8, internal_port: u16, external_port: u16, desc: []const u8) Error!?Mapping {
    const loc = HttpUrl.parse(location) orelse return error.BadFrame;
    const desc_resp = httpRequest(alloc, loc.host, loc.port, loc.path, "GET", null, null, "") catch |e| {
        return if (e == error.Timeout or e == error.Network) null else e;
    };
    defer alloc.free(desc_resp);
    const code = statusCode(desc_resp) orelse return null;
    if (code != 200) return null;
    // URLBase (опционален) + controlURL (путь или абсолютный URL)
    var host = loc.host;
    var port = loc.port;
    if (tagValue(desc_resp, "URLBase")) |base| {
        if (HttpUrl.parse(base)) |bu| {
            host = bu.host;
            port = bu.port;
        }
    }
    const ctl_rel = tagValue(desc_resp, "controlURL") orelse return null;
    var ctl_buf: [128]u8 = undefined;
    const control_url = blk: {
        if (std.mem.startsWith(u8, ctl_rel, "http://")) {
            if (ctl_rel.len <= ctl_buf.len) {
                @memcpy(ctl_buf[0..ctl_rel.len], ctl_rel);
                break :blk ctl_buf[0..ctl_rel.len];
            }
            return error.BadFrame;
        }
        // относительный путь: контроль на том же хосте, что описание
        var path_buf: [160]u8 = undefined;
        if (ctl_rel.len + 1 > path_buf.len) return error.BadFrame;
        if (ctl_rel.len > 0 and ctl_rel[0] != '/') {
            path_buf[0] = '/';
            @memcpy(path_buf[1..][0..ctl_rel.len], ctl_rel);
        } else {
            @memcpy(path_buf[0..ctl_rel.len], ctl_rel);
        }
        break :blk std.fmt.bufPrint(&ctl_buf, "http://{s}:{d}{s}", .{ host, port, path_buf[0 .. ctl_rel.len + @intFromBool(ctl_rel.len > 0 and ctl_rel[0] != '/')] }) catch return error.BadFrame;
    };
    _ = try addPortMapping(alloc, control_url, internal_ip, internal_port, external_port, desc);
    const ip = (try externalIp(alloc, control_url)) orelse return null;
    return .{ .ip = ip, .port = external_port };
}

fn fmtIp4Buf(buf: *[16]u8, ip: [4]u8) []const u8 {
    return std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}", .{ ip[0], ip[1], ip[2], ip[3] }) catch "?";
}

// ---- Тесты ----------------------------------------------------------------

test "HttpUrl.parse: http://host:port/path и мусор" {
    const t = std.testing;
    const u = HttpUrl.parse("http://192.168.1.1:49152/rootDesc.xml") orelse return error.TestUnexpectedResult;
    try t.expectEqualStrings("192.168.1.1", u.host);
    try t.expectEqual(@as(u16, 49152), u.port);
    try t.expectEqualStrings("/rootDesc.xml", u.path);
    const no_port = HttpUrl.parse("http://10.0.0.1/desc") orelse return error.TestUnexpectedResult;
    try t.expectEqual(@as(u16, 80), no_port.port);
    try t.expect(HttpUrl.parse("https://x/") == null);
    try t.expect(HttpUrl.parse("http://") == null);
    try t.expect(HttpUrl.parse("notaurl") == null);
}

test "tagValue: первый тег, усечения, отсутствие" {
    const t = std.testing;
    const xml = "<root><URLBase>http://1.2.3.4:80</URLBase><controlURL>/ctl</controlURL></root>";
    try t.expectEqualStrings("http://1.2.3.4:80", tagValue(xml, "URLBase").?);
    try t.expectEqualStrings("/ctl", tagValue(xml, "controlURL").?);
    try t.expect(tagValue(xml, "missing") == null);
    try t.expect(tagValue("<a>unclosed", "a") == null);
}

test "statusCode: первая строка ответа" {
    const t = std.testing;
    try t.expectEqual(@as(u16, 200), statusCode("HTTP/1.1 200 OK\r\n\r\nbody").?);
    try t.expectEqual(@as(u16, 500), statusCode("HTTP/1.1 500 Internal Server Error\r\n").?);
    try t.expect(statusCode("garbage") == null);
}

/// Фейковый IGD: описание + control endpoint в одном HTTP-сервере.
const FakeIgd = struct {
    fd: posix.socket_t,
    port: u16,
    external_ip: [4]u8,

    fn start(alloc: std.mem.Allocator, ext_ip: [4]u8) !FakeIgd {
        const fd = try sysfd.socketTcp();
        errdefer sysfd.close(fd);
        sysfd.setReuseAddr(fd);
        const sa = sysfd.sockaddrIn(.{ 127, 0, 0, 1 }, 0);
        try sysfd.bindIn(fd, &sa);
        try sysfd.listen(fd, 4);
        const port = sysfd.localPort(fd).?;
        const self = FakeIgd{ .fd = fd, .port = port, .external_ip = ext_ip };
        const th = try std.Thread.spawn(.{}, serve, .{ self, alloc });
        th.detach();
        return self;
    }

    fn stop(self: FakeIgd) void {
        sysfd.close(self.fd);
    }

    /// Один поток-сервер: accept-цикл до закрытия листенера, каждый конн
    /// читает один HTTP-запрос и отвечает. Порт нужен в GET-ответе
    /// (URLBase) — передаём self целиком, глобального стейта нет.
    fn serve(self: FakeIgd, alloc: std.mem.Allocator) void {
        while (true) {
            const cfd = sysfd.accept(self.fd) catch return;
            handleConn(self, cfd, alloc) catch {};
            sysfd.close(cfd);
        }
    }

    fn handleConn(self: FakeIgd, fd: posix.socket_t, alloc: std.mem.Allocator) !void {
        const ext_ip = self.external_ip;
        // читаем заголовки+тело запроса до \r\n\r\n (bounded)
        var buf: [2048]u8 = undefined;
        var got: usize = 0;
        while (got < buf.len) {
            if (!sysfd.pollReadable(fd, 2000)) return error.Timeout;
            const n = posix.read(fd, buf[got..]) catch return error.Network;
            if (n == 0) break;
            got += n;
            if (std.mem.indexOf(u8, buf[0..got], "\r\n\r\n") != null) break;
        }
        const req = buf[0..got];
        if (std.mem.startsWith(u8, req, "GET ")) {
            if (std.mem.indexOf(u8, req, "desc.xml") != null) {
                var full: [600]u8 = undefined;
                const xml = try std.fmt.bufPrint(&full, "<?xml version=\"1.0\"?><root><URLBase>http://127.0.0.1:{d}</URLBase><controlURL>/ctl</controlURL></root>", .{self.port});
                try sendHttp(fd, alloc, xml);
                return;
            }
            try sendHttp(fd, alloc, "not-found");
            return;
        }
        if (std.mem.startsWith(u8, req, "POST /ctl")) {
            if (std.mem.indexOf(u8, req, "AddPortMapping") != null) {
                try sendHttp(fd, alloc, "<s:Envelope/>");
                return;
            }
            if (std.mem.indexOf(u8, req, "GetExternalIPAddress") != null) {
                var xml_buf: [256]u8 = undefined;
                const xml = try std.fmt.bufPrint(&xml_buf, "<s:Envelope><NewExternalIPAddress>{d}.{d}.{d}.{d}</NewExternalIPAddress></s:Envelope>", .{ ext_ip[0], ext_ip[1], ext_ip[2], ext_ip[3] });
                try sendHttp(fd, alloc, xml);
                return;
            }
        }
        try sendHttp(fd, alloc, "bad");
    }

    fn sendHttp(fd: posix.socket_t, alloc: std.mem.Allocator, body: []const u8) !void {
        var head_buf: [128]u8 = undefined;
        const head = try std.fmt.bufPrint(&head_buf, "HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\nConnection: close\r\nContent-Length: {d}\r\n\r\n", .{body.len});
        var msg: std.ArrayListUnmanaged(u8) = .empty;
        defer msg.deinit(alloc);
        try msg.appendSlice(alloc, head);
        try msg.appendSlice(alloc, body);
        sysfd.writeAll(fd, msg.items) catch return error.Network;
    }
};

test "requestMapping: полный цикл с фейковым IGD на loopback" {
    const t = std.testing;
    const alloc = t.allocator;
    const ext: [4]u8 = .{ 203, 0, 113, 7 };
    const igd = try FakeIgd.start(alloc, ext);
    var loc_buf: [64]u8 = undefined;
    const loc = try std.fmt.bufPrint(&loc_buf, "http://127.0.0.1:{d}/desc.xml", .{igd.port});
    const m = (try requestMapping(alloc, loc, .{ 192, 168, 1, 42 }, 7777, 7777, "stille-test")) orelse return error.TestUnexpectedResult;
    try t.expectEqualSlices(u8, &ext, &m.ip);
    try t.expectEqual(@as(u16, 7777), m.port);
    // teardown: листенер закрываем, serve-поток гаснет на accept-ошибке;
    // короткий сон — коннекты в полёте успевают дописаться до конца теста
    igd.stop();
    sysfd.sleepMs(100);
}
