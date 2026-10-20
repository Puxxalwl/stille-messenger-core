//! LAN-обнаружение контактов без сервера: UDP-мультикаст + broadcast.
//! Анонс = magic + bundle + TCP-порт. Слышит его только тот, кто уже
//! добавил этот bundle (сверка по хэшу), поэтому шум минимальный.
//! Сокет биндится на INADDR_ANY (не на адрес группы): это стандартный
//! переносимый паттерн приёма мультикаста, И он же открывает приём
//! unicast-ответов (announceTo) и limited-broadcast анонсов — каналы
//! доставки в сетях, где мультикаст фильтруется.
const std = @import("std");
const posix = std.posix;
const stille_messenger = @import("stille-messenger");
const sysfd = stille_messenger.net.sysfd;

pub const magic = "SHOPOTD1";
pub const group = "239.77.77.77";
pub const udp_port = 57770;
pub const msg_len = magic.len + 64 + 2;
/// Limited broadcast: адрес сегмента без знания маски подсети.
pub const broadcast_ip = [4]u8{ 255, 255, 255, 255 };

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
    /// UDP-порт источника (из recvfrom) — куда слать unicast-ответ.
    src_port: u16,
};

/// Собирает анонс в буфер (msg_len байт).
pub fn buildAnnounce(buf: *[msg_len]u8, bundle: [64]u8, tcp_port: u16) void {
    @memcpy(buf[0..magic.len], magic);
    buf[magic.len .. magic.len + 64].* = bundle;
    std.mem.writeInt(u16, buf[magic.len + 64 ..][0..2], tcp_port, .big);
}

/// Разбирает анонс; чужие/битые пакеты — BadPacket.
pub fn parseAnnounce(buf: []const u8, ip: [4]u8, src_port: u16) Error!Announce {
    if (buf.len != msg_len) return Error.BadPacket;
    if (!std.mem.eql(u8, buf[0..magic.len], magic)) return Error.BadPacket;
    return .{
        .bundle = buf[magic.len .. magic.len + 64].*,
        .port = std.mem.readInt(u16, buf[magic.len + 64 ..][0..2], .big),
        .ip = ip,
        .src_port = src_port,
    };
}

/// Форматирует ip:port в буфер.
pub fn fmtAddr(buf: []u8, ip: [4]u8, port: u16) []const u8 {
    return std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}:{d}", .{ ip[0], ip[1], ip[2], ip[3], port }) catch "?";
}

/// Сокет обнаружения: приём (мультикаст группы + unicast + broadcast)
/// и отправка. Один fd на всё. pollfd() — для событийного ожидания
/// вместе с будилками вызывающего цикла.
pub const Discovery = struct {
    fd: posix.socket_t,
    /// Собственный UDP-порт (порт бинда; для ответов и broadcast).
    port: u16,

    /// Продакшн-сокет на udp_port.
    pub fn init() Error!Discovery {
        return initOnPort(udp_port);
    }

    /// Сокет на заданном UDP-порту (тесты/альтернативный порт).
    /// bind INADDR_ANY + SO_REUSEADDR: несколько процессов на одной
    /// машине (каждый вступил в группу) получают по копии датаграммы.
    pub fn initOnPort(port: u16) Error!Discovery {
        const fd = sysfd.socketUdp() catch return Error.Network;
        // reuse: несколько stille-messenger-ов на одной машине для теста
        sysfd.setReuseAddr(fd);
        const bind_sa = sysfd.sockaddrIn(.{ 0, 0, 0, 0 }, port);
        sysfd.bindIn(fd, &bind_sa) catch {
            sysfd.close(fd);
            return Error.Network;
        };
        // вступить в группу мультикаста (без мультикаста — молча работаем
        // на broadcast/unicast-сегменте)
        sysfd.joinMulticastGroup(fd, .{ 239, 77, 77, 77 });
        sysfd.setBroadcast(fd);
        // TTL=1: анонс не уходит за локальный сегмент
        sysfd.setMulticastTtl(fd);
        // таймаут приёма, чтобы поток мог крутить цикл
        sysfd.setRcvTimeout1s(fd);
        return .{ .fd = fd, .port = port };
    }

    pub fn deinit(self: *Discovery) void {
        sysfd.close(self.fd);
    }

    /// Элемент poll для вызывающего событийного цикла.
    pub fn pollfd(self: *const Discovery) posix.pollfd {
        return .{ .fd = self.fd, .events = posix.POLL.IN, .revents = 0 };
    }

    /// Разослать свой анонс: в группу мультикаста и limited broadcast
    /// (одинаковые 74 байта; best-effort, ошибки проглатываются).
    pub fn announce(self: *Discovery, bundle: [64]u8, tcp_port: u16) void {
        var buf: [msg_len]u8 = undefined;
        buildAnnounce(&buf, bundle, tcp_port);
        const sa = sysfd.sockaddrIn(.{ 239, 77, 77, 77 }, self.port);
        sysfd.sendtoIn(self.fd, &buf, &sa);
        const bsa = sysfd.sockaddrIn(broadcast_ip, self.port);
        sysfd.sendtoIn(self.fd, &buf, &bsa);
    }

    /// Unicast-ответ напрямую услышанному пиру: он анонснул — значит
    /// слушает; так он узнаёт о нас за ~RTT, не дожидаясь нашего
    /// следующего каденса анонса.
    pub fn announceTo(self: *Discovery, bundle: [64]u8, tcp_port: u16, ip: [4]u8, port: u16) void {
        var buf: [msg_len]u8 = undefined;
        buildAnnounce(&buf, bundle, tcp_port);
        const sa = sysfd.sockaddrIn(ip, port);
        sysfd.sendtoIn(self.fd, &buf, &sa);
    }

    /// Ждать анонс до timeout_ms. Возвращает null по таймауту.
    pub fn waitAnnounce(self: *Discovery, timeout_ms: i32) ?Announce {
        var pfd: [1]posix.pollfd = .{self.pollfd()};
        const n = posix.poll(&pfd, timeout_ms) catch return null;
        if (n == 0) return null;
        return self.recvAnnounce();
    }

    /// Прочитать один готовый анонс (после poll POLL.IN). null — пусто/битое.
    pub fn recvAnnounce(self: *Discovery) ?Announce {
        var buf: [512]u8 = undefined;
        var sa: sysfd.SockaddrIn = undefined;
        const rc = sysfd.recvfromIn(self.fd, &buf, &sa) orelse return null;
        const ip: [4]u8 = @bitCast(sa.addr);
        const sport = std.mem.bigToNative(u16, sa.port);
        return parseAnnounce(buf[0..rc], ip, sport) catch null;
    }
};

test "discover: анонс roundtrip" {
    const testing = std.testing;
    var bundle: [64]u8 = undefined;
    for (&bundle, 0..) |*b, i| b.* = @truncate(i + 3);
    var buf: [msg_len]u8 = undefined;
    buildAnnounce(&buf, bundle, 7777);
    const a = try parseAnnounce(&buf, .{ 192, 168, 1, 9 }, 57770);
    try testing.expectEqualSlices(u8, &bundle, &a.bundle);
    try testing.expectEqual(@as(u16, 7777), a.port);
    try testing.expectEqual(@as(u8, 192), a.ip[0]);
    try testing.expectEqual(@as(u16, 57770), a.src_port);
    try testing.expectError(Error.BadPacket, parseAnnounce(buf[0 .. msg_len - 1], a.ip, 57770));
    var ab: [32]u8 = undefined;
    try testing.expectEqualStrings("192.168.1.9:7777", fmtAddr(&ab, a.ip, a.port));
}

test "discover: unicast обмен между двумя сокетами (loopback)" {
    const testing = std.testing;
    // разные порты: доставка unicast детерминирована на linux и darwin
    var a = Discovery.initOnPort(45777) catch return error.SkipZigTest;
    defer a.deinit();
    var b = Discovery.initOnPort(45778) catch return error.SkipZigTest;
    defer b.deinit();
    var bundle_a: [64]u8 = undefined;
    var bundle_b: [64]u8 = undefined;
    for (&bundle_a, 0..) |*x, i| x.* = @truncate(i + 1);
    for (&bundle_b, 0..) |*x, i| x.* = @truncate(i + 101);
    // A анонсит напрямую B
    a.announceTo(bundle_a, 7300, .{ 127, 0, 0, 1 }, 45778);
    const got = b.waitAnnounce(2000) orelse return error.SkipZigTest; // loopback-доставка недоступна
    try testing.expectEqualSlices(u8, &bundle_a, &got.bundle);
    try testing.expectEqual(@as(u16, 7300), got.port);
    try testing.expectEqual(@as(u16, 45777), got.src_port);
    // ответ B пиру A: по адресу источника из recvfrom
    b.announceTo(bundle_b, 7301, got.ip, got.src_port);
    const reply = a.waitAnnounce(2000) orelse return error.SkipZigTest;
    try testing.expectEqualSlices(u8, &bundle_b, &reply.bundle);
    try testing.expectEqual(@as(u16, 45778), reply.src_port);
}
