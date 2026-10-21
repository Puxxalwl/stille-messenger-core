//! TCP-транспорт: сырые POSIX-сокеты, адаптер к интерфейсу Conn. std-only.
//! Намеренно БЕЗ std.Io: блокирующие fd в отдельных потоках — самый
//! предсказуемый режим для CLI (Threaded io конкурирует между потоками).
//! Системные вызовы — через net/sysfd.zig (переносимость linux/darwin).
const std = @import("std");
const posix = std.posix;
const interfaces = @import("../core/interfaces.zig");
const sysfd = @import("sysfd.zig");

pub const TcpConn = struct {
    fd: posix.socket_t,
    /// fd уже закрыт: close идемпотентен — rx-поток сессии и внешний
    /// close/shutdown гасят транспорт конкурентно, повторный close(fd)
    /// мог бы закрыть ЧУЖОЙ переиспользованный дескриптор.
    closed: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    pub fn deinit(self: *TcpConn) void {
        self.closeFd();
    }

    /// Однократный shutdown+close (safe при гонке закрытий).
    fn closeFd(self: *TcpConn) void {
        if (self.closed.swap(true, .acq_rel)) return;
        // shutdown, не close: заблокированный в read() поток (rx-поток
        // сессии) просыпается по EOF — close(fd) его не будит (Linux)
        sysfd.shutdownReadWrite(self.fd);
        sysfd.close(self.fd);
    }

    fn readAllImpl(ptr: *anyopaque, buf: []u8) interfaces.ConnError!void {
        const self: *TcpConn = @ptrCast(@alignCast(ptr));
        var got: usize = 0;
        while (got < buf.len) {
            const n = posix.read(self.fd, buf[got..]) catch return error.Closed;
            if (n == 0) return error.Closed;
            got += n;
        }
    }

    fn writeAllImpl(ptr: *anyopaque, bytes: []const u8) interfaces.ConnError!void {
        const self: *TcpConn = @ptrCast(@alignCast(ptr));
        sysfd.writeAll(self.fd, bytes) catch return error.Network;
    }

    fn closeImpl(ptr: *anyopaque) void {
        const self: *TcpConn = @ptrCast(@alignCast(ptr));
        self.closeFd();
    }

    const vtable = interfaces.Conn.VTable{
        .readAll = readAllImpl,
        .writeAll = writeAllImpl,
        .close = closeImpl,
    };

    /// Vtable-адаптер для ядра.
    pub fn conn(self: *TcpConn) interfaces.Conn {
        return .{ .ptr = self, .vtable = &vtable };
    }
};

pub const DialError = error{
    BadAddress,
    Network,
    OutOfMemory,
};

/// Размер очереди accept: переживает всплеск параллельных подключений без
/// изменения протокола и без искусственного ограничения throughput.
const listen_backlog: i32 = 1024;

fn tuneSocket(fd: posix.socket_t) void {
    sysfd.setSocketBuffers(fd);
    // Linux TCP_QUICKACK=12: request immediate ACKs after reads (darwin: no-op).
    sysfd.setQuickAck(fd);
}

/// sockaddr.in из IPv4-литерала + порт.
fn parseV4(host: []const u8, port: u16) ?sysfd.SockaddrIn {
    const ip4 = std.Io.net.Ip4Address.parse(host, port) catch return null;
    return sysfd.sockaddrIn(ip4.bytes, port);
}

/// sockaddr.in6 из IPv6-литерала (БЕЗ скобок) + порт.
fn parseV6(host: []const u8, port: u16) ?sysfd.SockaddrIn6 {
    const ip6 = std.Io.net.Ip6Address.parse(host, port) catch return null;
    return sysfd.sockaddrIn6(ip6.bytes, port);
}

/// Разобранный адрес подключения/листенера: IPv4 "host:port" либо IPv6
/// "[literal]:port" (скобки обязательны — двоеточий в v6 много, без
/// скобок адрес неоднозначен; голый v6 без порта — BadAddress).
pub const Addr = union(enum) {
    v4: sysfd.SockaddrIn,
    v6: sysfd.SockaddrIn6,

    pub fn parse(addr: []const u8) ?Addr {
        if (addr.len >= 2 and addr[0] == '[') {
            const close = std.mem.indexOfScalar(u8, addr, ']') orelse return null;
            if (close + 1 >= addr.len or addr[close + 1] != ':') return null;
            const port = std.fmt.parseInt(u16, addr[close + 2 ..], 10) catch return null;
            const sa6 = parseV6(addr[1..close], port) orelse return null;
            return .{ .v6 = sa6 };
        }
        const colon = std.mem.lastIndexOfScalar(u8, addr, ':') orelse return null;
        const port = std.fmt.parseInt(u16, addr[colon + 1 ..], 10) catch return null;
        const sa = parseV4(addr[0..colon], port) orelse return null;
        return .{ .v4 = sa };
    }
};

/// Dial "host:port" (IPv4-литерал) или "[v6]:port". Домены не поддержаны.
pub fn dial(alloc: std.mem.Allocator, addr: []const u8) DialError!*TcpConn {
    const a = Addr.parse(addr) orelse return error.BadAddress;
    const fd = switch (a) {
        .v4 => |sa| blk: {
            const fd = sysfd.socketTcp() catch return error.Network;
            sysfd.connectIn(fd, &sa) catch {
                sysfd.close(fd);
                return error.Network;
            };
            break :blk fd;
        },
        .v6 => |sa| blk: {
            const fd = sysfd.socketTcp6() catch return error.Network;
            sysfd.connectIn6(fd, &sa) catch {
                sysfd.close(fd);
                return error.Network;
            };
            break :blk fd;
        },
    };
    tuneSocket(fd);
    setNoDelay(fd);
    const tc = alloc.create(TcpConn) catch {
        sysfd.close(fd);
        return error.OutOfMemory;
    };
    tc.* = .{ .fd = fd };
    setKeepalive(fd);
    return tc;
}

/// Формат IPv6-адреса с ::-сжатием самой длинной нулевой группы
/// (≥2 групп; при равенстве — первая). Голый "::" допустим. Нужен для
/// контакт-адресов "[v6]:port" (строка ≤ 64 байт укладывается).
pub fn fmtIp6(buf: []u8, ip: [16]u8) []const u8 {
    var groups: [8]u16 = undefined;
    for (0..8) |i| groups[i] = std.mem.readInt(u16, ip[i * 2 ..][0..2], .big);
    var best_off: usize = 0;
    var best_len: usize = 0;
    var cur_off: usize = 0;
    var cur_len: usize = 0;
    for (groups, 0..) |g, i| {
        if (g == 0) {
            if (cur_len == 0) cur_off = i;
            cur_len += 1;
            if (cur_len > best_len) {
                best_len = cur_len;
                best_off = cur_off;
            }
        } else {
            cur_len = 0;
        }
    }
    var n: usize = 0;
    var i: usize = 0;
    var after_colons = false;
    while (i < 8) {
        if (best_len >= 2 and i == best_off) {
            if (n + 2 > buf.len) break;
            buf[n] = ':';
            buf[n + 1] = ':';
            n += 2;
            i += best_len;
            after_colons = true;
            continue;
        }
        if (i > 0 and !after_colons) {
            if (n + 1 > buf.len) break;
            buf[n] = ':';
            n += 1;
        }
        after_colons = false;
        var hex: [4]u8 = undefined;
        const printed = std.fmt.bufPrint(&hex, "{x}", .{groups[i]}) catch break;
        if (n + printed.len > buf.len) break;
        @memcpy(buf[n..][0..printed.len], printed);
        n += printed.len;
        i += 1;
    }
    return buf[0..n];
}

/// IPv6-адрес fd в "[v6]:port" (getpeername/getsockname по семейству fd).
pub fn ip6PortOf(sa: sysfd.SockaddrIn6) struct { ip: [16]u8, port: u16 } {
    return .{ .ip = sa.addr, .port = std.mem.bigToNative(u16, sa.port) };
}

/// Ядро само детектит мёртвый peer (30с тишины TCP-уровня, без прикладных
/// запросов) — presence-пинги остаются только для статуса «онлайн».
/// TCP_NODELAY: отключаем Nagle — интерактивные кадры (пинг, звонок)
/// не ждут коалесценции 40 мс. Латентность важнее микросэкономии пакетов.
pub fn setNoDelay(fd: posix.socket_t) void {
    sysfd.setNoDelay(fd);
}

pub fn setKeepalive(fd: posix.socket_t) void {
    sysfd.setKeepalive(fd);
}

/// Готовый к accept() слушатель.
pub const Listener = struct {
    fd: posix.socket_t,

    /// Блокирующий accept; возвращает адаптированный TcpConn.
    pub fn accept(self: *Listener, alloc: std.mem.Allocator) !*TcpConn {
        const cfd = sysfd.accept(self.fd) catch return error.Network;
        tuneSocket(cfd);
        setNoDelay(cfd);
        const tc = alloc.create(TcpConn) catch {
            sysfd.close(cfd);
            return error.OutOfMemory;
        };
        tc.* = .{ .fd = cfd };
        setKeepalive(cfd);
        return tc;
    }

    pub fn deinit(self: *Listener) void {
        sysfd.close(self.fd);
    }
};

pub const ListenError = error{
    BadAddress,
    Network,
};

/// Слушать "host:port" (IPv4) или "[v6]:port" (IPv6). SO_REUSEADDR —
/// перезапуск без TIME_WAIT-паузы. IPv6-листенер ставит V6ONLY=1:
/// сосуществует с v4-листенером на том же порту (два отдельных fd,
/// никакой смены поведения v4-пути).
pub fn listen(addr: []const u8) ListenError!Listener {
    const a = Addr.parse(addr) orelse return error.BadAddress;
    switch (a) {
        .v4 => |sa| return listenOn(fd_v4: {
            const fd = sysfd.socketTcp() catch return error.Network;
            sysfd.setReuseAddr(fd);
            sysfd.bindIn(fd, &sa) catch {
                std.debug.print("[listen] bind {s} не удался\n", .{addr});
                sysfd.close(fd);
                return error.Network;
            };
            break :fd_v4 fd;
        }, addr),
        .v6 => |sa| return listenOn(fd_v6: {
            const fd = sysfd.socketTcp6() catch return error.Network;
            sysfd.setReuseAddr(fd);
            sysfd.setV6Only(fd, true);
            sysfd.bindIn6(fd, &sa) catch {
                std.debug.print("[listen] bind {s} не удался\n", .{addr});
                sysfd.close(fd);
                return error.Network;
            };
            break :fd_v6 fd;
        }, addr),
    }
}

fn listenOn(fd: posix.socket_t, addr: []const u8) ListenError!Listener {
    sysfd.listen(fd, listen_backlog) catch {
        std.debug.print("[listen] listen {s} не удался\n", .{addr});
        sysfd.close(fd);
        return error.Network;
    };
    return .{ .fd = fd };
}

test "dial bad address fails clean" {
    try std.testing.expectError(error.BadAddress, dial(std.testing.allocator, "no-colon"));
}

test "Addr.parse: v4, v6, мусор" {
    const t = std.testing;
    const a4 = Addr.parse("127.0.0.1:7777") orelse return error.TestUnexpectedResult;
    try t.expect(a4 == .v4);
    const a6 = Addr.parse("[2001:db8::1]:7777") orelse return error.TestUnexpectedResult;
    try t.expect(a6 == .v6);
    // голый v6 без скобок/порта — неоднозначен, отказ
    try t.expect(Addr.parse("2001:db8::1") == null);
    try t.expect(Addr.parse("[::1]") == null);
    try t.expect(Addr.parse("[::1]:x") == null);
    try t.expect(Addr.parse("host:0") == null);
}

test "fmtIp6: сжатие нулевых групп" {
    const t = std.testing;
    var buf: [64]u8 = undefined;
    try t.expectEqualStrings("2001:db8::1", fmtIp6(&buf, .{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }));
    try t.expectEqualStrings("::1", fmtIp6(&buf, .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }));
    try t.expectEqualStrings("::", fmtIp6(&buf, @splat(0)));
    try t.expectEqualStrings("fe80::1", fmtIp6(&buf, .{ 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }));
    try t.expectEqualStrings("1:2:3:4:5:6:7:8", fmtIp6(&buf, .{ 0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7, 0, 8 }));
}

test "listen/dial IPv6 loopback: сессия байтов туда-обратно" {
    const t = std.testing;
    const alloc = t.allocator;
    var lsn = listen("[::1]:0") catch return error.TestUnexpectedResult;
    defer lsn.deinit();
    const port = sysfd.localPort6(lsn.fd) orelse return error.TestUnexpectedResult;
    var ab: [32]u8 = undefined;
    const addr = try std.fmt.bufPrint(&ab, "[::1]:{d}", .{port});
    var dconn: ?*TcpConn = null;
    const th = try std.Thread.spawn(.{}, struct {
        fn run(a: std.mem.Allocator, ad: []const u8, out: *?*TcpConn) void {
            out.* = dial(a, ad) catch null;
        }
    }.run, .{ alloc, addr, &dconn });
    const srv = try lsn.accept(alloc);
    th.join();
    const cli = dconn orelse return error.TestUnexpectedResult;
    defer {
        cli.deinit();
        alloc.destroy(cli);
    }
    defer {
        srv.deinit();
        alloc.destroy(srv);
    }
    try sysfd.writeAll(cli.fd, "ping-v6");
    var got: [7]u8 = undefined;
    try readExact(srv.fd, &got);
    try t.expectEqualStrings("ping-v6", &got);
    try sysfd.writeAll(srv.fd, "pong-v6");
    try readExact(cli.fd, &got);
    try t.expectEqualStrings("pong-v6", &got);
}

fn readExact(fd: posix.socket_t, buf: []u8) !void {
    var got: usize = 0;
    while (got < buf.len) {
        const n = sysfd.read(fd, buf[got..]) catch return error.Network;
        if (n == 0) return error.Closed;
        got += n;
    }
}
