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

/// sockaddr.in из IPv4-литерала + порт. Поддержка IPv6-литералов — позже.
fn parseV4(host: []const u8, port: u16) ?sysfd.SockaddrIn {
    const ip4 = std.Io.net.Ip4Address.parse(host, port) catch return null;
    return sysfd.sockaddrIn(ip4.bytes, port);
}

/// Dial "host:port" (IPv4-литерал; домены не поддержаны в этой версии).
pub fn dial(alloc: std.mem.Allocator, addr: []const u8) DialError!*TcpConn {
    const colon = std.mem.lastIndexOfScalar(u8, addr, ':') orelse return error.BadAddress;
    const host = addr[0..colon];
    const port = std.fmt.parseInt(u16, addr[colon + 1 ..], 10) catch return error.BadAddress;
    const sa = parseV4(host, port) orelse return error.BadAddress;
    const fd = sysfd.socketTcp() catch return error.Network;
    tuneSocket(fd);
    setNoDelay(fd);
    sysfd.connectIn(fd, &sa) catch {
        sysfd.close(fd);
        return error.Network;
    };
    const tc = alloc.create(TcpConn) catch {
        sysfd.close(fd);
        return error.OutOfMemory;
    };
    tc.* = .{ .fd = fd };
    setKeepalive(fd);
    return tc;
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

/// Слушать "host:port". SO_REUSEADDR включён — перезапуск без TIME_WAIT-паузы.
pub fn listen(addr: []const u8) ListenError!Listener {
    const colon = std.mem.lastIndexOfScalar(u8, addr, ':') orelse return error.BadAddress;
    const host = addr[0..colon];
    const port = std.fmt.parseInt(u16, addr[colon + 1 ..], 10) catch return error.BadAddress;
    const sa = parseV4(host, port) orelse return error.BadAddress;
    const fd = sysfd.socketTcp() catch return error.Network;
    sysfd.setReuseAddr(fd);
    sysfd.bindIn(fd, &sa) catch {
        std.debug.print("[listen] bind {s} не удался\n", .{addr});
        sysfd.close(fd);
        return error.Network;
    };
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
