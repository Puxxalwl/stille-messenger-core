//! LAN-обнаружение контактов без сервера: UDP-мультикаст.
//! Анонс = magic + bundle + TCP-порт. Слышит его только тот, кто уже
//! добавил этот bundle (сверка по хэшу), поэтому шум минимальный.
const std = @import("std");
const posix = std.posix;
const stille_messenger = @import("stille-messenger");
const sysfd = stille_messenger.net.sysfd;

pub const magic = "SHOPOTD1";
pub const group = "239.77.77.77";
pub const udp_port = 57770;
pub const msg_len = magic.len + 64 + 2;

pub const Error = error{
    Network,
    BadPacket,
};

pub const Announce = struct {
    bundle: [64]u8,
    /// TCP-порт, который слушает анонсирующий.
    port: u16,
    /// IPv4 источника (из recvfrom).
    ip: [4]u8,
};

/// Собирает анонс в буфер (msg_len байт).
pub fn buildAnnounce(buf: *[msg_len]u8, bundle: [64]u8, tcp_port: u16) void {
    @memcpy(buf[0..magic.len], magic);
    buf[magic.len .. magic.len + 64].* = bundle;
    std.mem.writeInt(u16, buf[magic.len + 64 ..][0..2], tcp_port, .big);
}

/// Разбирает анонс; чужие/битые пакеты — BadPacket.
pub fn parseAnnounce(buf: []const u8, ip: [4]u8) Error!Announce {
    if (buf.len != msg_len) return Error.BadPacket;
    if (!std.mem.eql(u8, buf[0..magic.len], magic)) return Error.BadPacket;
    return .{
        .bundle = buf[magic.len .. magic.len + 64].*,
        .port = std.mem.readInt(u16, buf[magic.len + 64 ..][0..2], .big),
        .ip = ip,
    };
}

/// Форматирует ip:port в буфер.
pub fn fmtAddr(buf: []u8, ip: [4]u8, port: u16) []const u8 {
    return std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}:{d}", .{ ip[0], ip[1], ip[2], ip[3], port }) catch "?";
}

/// Сокет мультикаста: приём group:udp_port + отправка. Один fd на всё.
pub const Discovery = struct {
    fd: posix.socket_t,

    pub fn init() Error!Discovery {
        const fd = sysfd.socketUdp() catch return Error.Network;
        // reuse: несколько stille-messenger-ов на одной машине для теста
        sysfd.setReuseAddr(fd);
        // bind на адрес группы: несколько stille-messenger-процессов на одной машине
        // (и мультикаст-роутеры) доставляют кадр каждому подписчику
        const bind_sa = sysfd.sockaddrIn(.{ 239, 77, 77, 77 }, udp_port);
        sysfd.bindIn(fd, &bind_sa) catch {
            sysfd.close(fd);
            return Error.Network;
        };
        // вступить в группу мультикаста (без мультикаста — молча работаем
        // на broadcast-сегменте)
        sysfd.joinMulticastGroup(fd, .{ 239, 77, 77, 77 });
        // таймаут приёма, чтобы поток мог крутить цикл
        sysfd.setRcvTimeout1s(fd);
        return .{ .fd = fd };
    }

    pub fn deinit(self: *Discovery) void {
        sysfd.close(self.fd);
    }

    /// Разослать свой анонс в группу.
    pub fn announce(self: *Discovery, bundle: [64]u8, tcp_port: u16) void {
        var buf: [msg_len]u8 = undefined;
        buildAnnounce(&buf, bundle, tcp_port);
        const sa = sysfd.sockaddrIn(.{ 239, 77, 77, 77 }, udp_port);
        sysfd.sendtoIn(self.fd, &buf, &sa);
    }

    /// Ждать анонс до timeout_ms. Возвращает null по таймауту.
    pub fn waitAnnounce(self: *Discovery, timeout_ms: i32) ?Announce {
        var pfd: [1]posix.pollfd = .{.{ .fd = self.fd, .events = posix.POLL.IN, .revents = 0 }};
        const n = posix.poll(&pfd, timeout_ms) catch return null;
        if (n == 0) return null;
        var buf: [512]u8 = undefined;
        var sa: sysfd.SockaddrIn = undefined;
        const rc = sysfd.recvfromIn(self.fd, &buf, &sa) orelse return null;
        const ip: [4]u8 = @bitCast(sa.addr);
        return parseAnnounce(buf[0..rc], ip) catch null;
    }
};

test "discover: анонс roundtrip" {
    const testing = std.testing;
    var bundle: [64]u8 = undefined;
    for (&bundle, 0..) |*b, i| b.* = @truncate(i + 3);
    var buf: [msg_len]u8 = undefined;
    buildAnnounce(&buf, bundle, 7777);
    const a = try parseAnnounce(&buf, .{ 192, 168, 1, 9 });
    try testing.expectEqualSlices(u8, &bundle, &a.bundle);
    try testing.expectEqual(@as(u16, 7777), a.port);
    try testing.expectEqual(@as(u8, 192), a.ip[0]);
    try testing.expectError(Error.BadPacket, parseAnnounce(&buf[0 .. msg_len - 1], a.ip));
    var ab: [32]u8 = undefined;
    try testing.expectEqualStrings("192.168.1.9:7777", fmtAddr(&ab, a.ip, a.port));
}
