//! Сырые операции над сокетами/fd — единая точка переносимости net-слоя.
//! Linux — прямые syscall-ы без libc (как исторически, паттерн tcp.zig);
//! Darwin (macOS) — libc (libSystem): номера Linux-syscall-ов и ABI Darwin
//! несовместимы (svc с linux-номером на макоси падает), сырые syscall-ы
//! там недопустимы. Extern-объявления libc — часть std-модели, внешних
//! зависимостей это не добавляет.
//!
//! Константы уровня сокетов берутся из std.posix (system-scoped: значения
//! верны для целевой ОС); различающиеся между ОС номера опций (TCP
//! keepalive, IP_ADD_MEMBERSHIP) — явные локальные константы с комментарием.
const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;

pub const fd_t = posix.socket_t;
/// sockaddr.in целевой ОС (darwin-вариант несёт ведущий байт длины).
pub const SockaddrIn = posix.sockaddr.in;
/// sockaddr.un целевой ОС (для UDS API-сервера).
pub const SockaddrUn = posix.sockaddr.un;

const is_linux = builtin.os.tag == .linux;

// ---- Darwin: libc-externs (std.c не экспортирует их публично) -------------
const cabi = struct {
    const timespec = extern struct { sec: isize, nsec: isize };
    extern "c" fn socket(domain: c_int, sock_type: c_int, protocol: c_int) c_int;
    extern "c" fn connect(sockfd: c_int, addr: *const posix.sockaddr, addrlen: posix.socklen_t) c_int;
    extern "c" fn bind(sockfd: c_int, addr: *const posix.sockaddr, addrlen: posix.socklen_t) c_int;
    extern "c" fn listen(sockfd: c_int, backlog: c_int) c_int;
    extern "c" fn accept(sockfd: c_int, addr: ?*posix.sockaddr, addrlen: ?*posix.socklen_t) c_int;
    extern "c" fn setsockopt(sockfd: c_int, level: c_int, optname: c_int, optval: ?*const anyopaque, optlen: posix.socklen_t) c_int;
    extern "c" fn read(fd: c_int, buf: [*]u8, nbyte: usize) isize;
    extern "c" fn write(fd: c_int, buf: [*]const u8, nbyte: usize) isize;
    extern "c" fn shutdown(sockfd: c_int, how: c_int) c_int;
    extern "c" fn close(fd: c_int) c_int;
    extern "c" fn clock_gettime(clk_id: c_int, tp: *timespec) c_int;
    extern "c" fn nanosleep(req: *const timespec, rem: ?*timespec) c_int;
    extern "c" fn sendto(sockfd: c_int, buf: *const anyopaque, len: usize, flags: c_int, addr: ?*const posix.sockaddr, addrlen: posix.socklen_t) isize;
    extern "c" fn recvfrom(sockfd: c_int, buf: *anyopaque, len: usize, flags: c_int, addr: ?*posix.sockaddr, addrlen: ?*posix.socklen_t) isize;
    extern "c" fn chmod(path: [*:0]const u8, mode: c_int) c_int;
    extern "c" fn open(path: [*:0]const u8, oflag: c_int, ...) c_int;
    extern "c" fn mkdir(path: [*:0]const u8, mode: c_int) c_int;
};

// Darwin open(2) флаги (Linux-вариант берётся из std.os.linux.O).
const darwin_o_rdonly: c_int = 0x0000;
const darwin_o_wronly: c_int = 0x0001;
const darwin_o_creat: c_int = 0x0200;
const darwin_o_trunc: c_int = 0x0400;

/// Darwin: CLOCK_MONOTONIC = 6 (Linux-значение другое и берётся из std).
const darwin_clock_monotonic: c_int = 6;
/// IP_ADD_MEMBERSHIP: 35 на Linux, 12 на Darwin (BSD-наследие).
const ip_add_membership_linux: u32 = 35;
const ip_add_membership_darwin: u32 = 12;
/// TCP keepalive-опции: Linux KEEPIDLE/KEEPINTVL/KEEPCNT = 4/5/9,
/// Darwin TCP_KEEPALIVE/KEEPINTVL/KEEPCNT = 0x10/0x101/0x102.
const tcp_keepidle_linux: u32 = 4;
const tcp_keepintvl_linux: u32 = 5;
const tcp_keepcnt_linux: u32 = 9;
const tcp_keepidle_darwin: u32 = 0x10;
const tcp_keepintvl_darwin: u32 = 0x101;
const tcp_keepcnt_darwin: u32 = 0x102;
/// TCP_QUICKACK — только Linux (12); Darwin молча пропускает.
/// sockaddr.in из IPv4-байтов (порядок в памяти — сетевой) и host-порта.
pub fn sockaddrIn(ip: [4]u8, port_host: u16) SockaddrIn {
    const port = std.mem.nativeToBig(u16, port_host);
    const addr = std.mem.readInt(u32, &ip, .little);
    if (SockaddrIn == posix.sockaddr.in and @hasField(SockaddrIn, "len")) {
        // darwin: ведущий байт длины обязателен
        return .{ .len = @sizeOf(SockaddrIn), .family = posix.AF.INET, .port = port, .addr = addr, .zero = @splat(0) };
    }
    return .{ .family = posix.AF.INET, .port = port, .addr = addr, .zero = @splat(0) };
}

/// Чтение из fd; EINTR повторяется. 0 = EOF (решает вызывающий).
pub fn read(fd: fd_t, buf: []u8) error{Network}!usize {
    if (buf.len == 0) return 0;
    if (is_linux) {
        while (true) {
            const rc = std.os.linux.read(fd, buf.ptr, buf.len);
            const e = std.os.linux.errno(rc);
            if (e == .INTR) continue;
            if (e != .SUCCESS) return error.Network;
            return @intCast(rc);
        }
    }
    while (true) {
        const rc = cabi.read(@intCast(fd), buf.ptr, buf.len);
        if (rc < 0) {
            if (posix.errno(rc) == .INTR) continue;
            return error.Network;
        }
        return @intCast(rc);
    }
}

/// Запись всего буфера; EINTR повторяется.
pub fn writeAll(fd: fd_t, bytes: []const u8) error{Network}!void {
    var sent: usize = 0;
    while (sent < bytes.len) {
        if (is_linux) {
            const rc = std.os.linux.write(fd, bytes[sent..].ptr, bytes.len - sent);
            const e = std.os.linux.errno(rc);
            if (e == .INTR) continue;
            if (e != .SUCCESS) return error.Network;
            if (rc == 0) return error.Network;
            sent += rc;
            continue;
        }
        const rc = cabi.write(@intCast(fd), bytes[sent..].ptr, bytes.len - sent);
        if (rc < 0) {
            if (posix.errno(rc) == .INTR) continue;
            return error.Network;
        }
        if (rc == 0) return error.Network;
        sent += @intCast(rc);
    }
}

pub fn close(fd: fd_t) void {
    if (is_linux) {
        _ = std.os.linux.close(fd);
        return;
    }
    _ = cabi.close(@intCast(fd));
}

/// shutdown(RDWR): будит потоки, блокированные в read (close их не будит).
pub fn shutdownReadWrite(fd: fd_t) void {
    if (is_linux) {
        _ = std.os.linux.shutdown(fd, std.os.linux.SHUT.RDWR);
        return;
    }
    _ = cabi.shutdown(@intCast(fd), posix.SHUT.RDWR);
}

fn socketOf(domain: c_int, sock_type: c_int) error{Network}!fd_t {
    if (is_linux) {
        const rc = std.os.linux.socket(@intCast(domain), @intCast(sock_type), 0);
        if (std.os.linux.errno(rc) != .SUCCESS) return error.Network;
        return @intCast(rc);
    }
    const fd = cabi.socket(domain, sock_type, 0);
    if (fd < 0) return error.Network;
    return fd;
}

pub fn socketTcp() error{Network}!fd_t {
    return socketOf(posix.AF.INET, posix.SOCK.STREAM);
}

pub fn socketUdp() error{Network}!fd_t {
    return socketOf(posix.AF.INET, posix.SOCK.DGRAM);
}

pub fn socketUnix() error{Network}!fd_t {
    return socketOf(posix.AF.UNIX, posix.SOCK.STREAM);
}

pub fn connectIn(fd: fd_t, sa: *const SockaddrIn) error{Network}!void {
    if (is_linux) {
        const rc = std.os.linux.connect(fd, @ptrCast(sa), @sizeOf(SockaddrIn));
        if (std.os.linux.errno(rc) != .SUCCESS) return error.Network;
        return;
    }
    if (cabi.connect(@intCast(fd), @ptrCast(sa), @sizeOf(SockaddrIn)) < 0) return error.Network;
}

pub fn bindIn(fd: fd_t, sa: *const SockaddrIn) error{Network}!void {
    if (is_linux) {
        const rc = std.os.linux.bind(fd, @ptrCast(sa), @sizeOf(SockaddrIn));
        if (std.os.linux.errno(rc) != .SUCCESS) return error.Network;
        return;
    }
    if (cabi.bind(@intCast(fd), @ptrCast(sa), @sizeOf(SockaddrIn)) < 0) return error.Network;
}

pub fn bindUnix(fd: fd_t, sa: *const SockaddrUn) error{Network}!void {
    if (is_linux) {
        const rc = std.os.linux.bind(fd, @ptrCast(sa), @sizeOf(SockaddrUn));
        if (std.os.linux.errno(rc) != .SUCCESS) return error.Network;
        return;
    }
    if (cabi.bind(@intCast(fd), @ptrCast(sa), @sizeOf(SockaddrUn)) < 0) return error.Network;
}

pub fn listen(fd: fd_t, backlog: i32) error{Network}!void {
    if (is_linux) {
        const rc = std.os.linux.listen(fd, @intCast(backlog));
        if (std.os.linux.errno(rc) != .SUCCESS) return error.Network;
        return;
    }
    if (cabi.listen(@intCast(fd), backlog) < 0) return error.Network;
}

/// Блокирующий accept (flags = 0). Ошибка — error.Network (EINTR тоже:
/// вызывающие циклы и так крутятся до флага остановки).
pub fn accept(fd: fd_t) error{Network}!fd_t {
    if (is_linux) {
        const rc = std.os.linux.accept4(fd, null, null, 0);
        if (std.os.linux.errno(rc) != .SUCCESS) return error.Network;
        return @intCast(rc);
    }
    const cfd = cabi.accept(@intCast(fd), null, null);
    if (cfd < 0) return error.Network;
    return cfd;
}

fn setSockOptRaw(fd: fd_t, level: i32, opt: u32, val: []const u8) void {
    if (is_linux) {
        _ = std.os.linux.setsockopt(fd, level, @intCast(opt), val.ptr, @intCast(val.len));
        return;
    }
    _ = cabi.setsockopt(@intCast(fd), level, @intCast(opt), val.ptr, @intCast(val.len));
}

/// SO_REUSEADDR: перезапуск слушателя без TIME_WAIT-паузы.
pub fn setReuseAddr(fd: fd_t) void {
    if (is_linux) {
        _ = std.os.linux.setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, &std.mem.toBytes(@as(c_int, 1)), 4);
        return;
    }
    _ = cabi.setsockopt(@intCast(fd), posix.SOL.SOCKET, posix.SO.REUSEADDR, &std.mem.toBytes(@as(c_int, 1)), 4);
}

/// Буферы ядра TCP (4 MiB; ядро может скорректировать по sysctl).
pub fn setSocketBuffers(fd: fd_t) void {
    const size: c_int = 4 * 1024 * 1024;
    if (is_linux) {
        _ = std.os.linux.setsockopt(fd, posix.SOL.SOCKET, posix.SO.RCVBUF, &std.mem.toBytes(size), @sizeOf(c_int));
        _ = std.os.linux.setsockopt(fd, posix.SOL.SOCKET, posix.SO.SNDBUF, &std.mem.toBytes(size), @sizeOf(c_int));
        return;
    }
    _ = cabi.setsockopt(@intCast(fd), posix.SOL.SOCKET, posix.SO.RCVBUF, &std.mem.toBytes(size), @sizeOf(c_int));
    _ = cabi.setsockopt(@intCast(fd), posix.SOL.SOCKET, posix.SO.SNDBUF, &std.mem.toBytes(size), @sizeOf(c_int));
}

/// TCP_NODELAY: интерактивные кадры не ждут коалесценции Nagle.
pub fn setNoDelay(fd: fd_t) void {
    const one: c_int = 1;
    if (is_linux) {
        _ = std.os.linux.setsockopt(fd, posix.IPPROTO.TCP, posix.TCP.NODELAY, @ptrCast(&one), @sizeOf(c_int));
        return;
    }
    _ = cabi.setsockopt(@intCast(fd), posix.IPPROTO.TCP, posix.TCP.NODELAY, &std.mem.toBytes(one), @sizeOf(c_int));
}

/// TCP_QUICKACK (только Linux; на прочих ОС — no-op).
pub fn setQuickAck(fd: fd_t) void {
    if (!is_linux) return;
    const one: c_int = 1;
    _ = std.os.linux.setsockopt(fd, posix.IPPROTO.TCP, 12, @ptrCast(&one), @sizeOf(c_int));
}

/// Keepalive 30s/10s/3: мгновенный детект мёртвого пира на TCP-уровне.
pub fn setKeepalive(fd: fd_t) void {
    const on: c_int = 1;
    const idle: c_int = 30;
    const intvl: c_int = 10;
    const cnt: c_int = 3;
    if (is_linux) {
        _ = std.os.linux.setsockopt(fd, posix.SOL.SOCKET, posix.SO.KEEPALIVE, &std.mem.toBytes(on), @sizeOf(c_int));
        _ = std.os.linux.setsockopt(fd, posix.IPPROTO.TCP, tcp_keepidle_linux, &std.mem.toBytes(idle), @sizeOf(c_int));
        _ = std.os.linux.setsockopt(fd, posix.IPPROTO.TCP, tcp_keepintvl_linux, &std.mem.toBytes(intvl), @sizeOf(c_int));
        _ = std.os.linux.setsockopt(fd, posix.IPPROTO.TCP, tcp_keepcnt_linux, &std.mem.toBytes(cnt), @sizeOf(c_int));
        return;
    }
    _ = cabi.setsockopt(@intCast(fd), posix.SOL.SOCKET, posix.SO.KEEPALIVE, &std.mem.toBytes(on), @sizeOf(c_int));
    _ = cabi.setsockopt(@intCast(fd), posix.IPPROTO.TCP, tcp_keepidle_darwin, &std.mem.toBytes(idle), @sizeOf(c_int));
    _ = cabi.setsockopt(@intCast(fd), posix.IPPROTO.TCP, tcp_keepintvl_darwin, &std.mem.toBytes(intvl), @sizeOf(c_int));
    _ = cabi.setsockopt(@intCast(fd), posix.IPPROTO.TCP, tcp_keepcnt_darwin, &std.mem.toBytes(cnt), @sizeOf(c_int));
}

/// Таймаут приёма 1с (UDP-поток крутит цикл и проверяет флаг остановки).
pub fn setRcvTimeout1s(fd: fd_t) void {
    const tv: posix.timeval = .{ .sec = 1, .usec = 0 };
    setSockOptRaw(fd, posix.SOL.SOCKET, posix.SO.RCVTIMEO, &std.mem.toBytes(tv));
}

/// SO_BROADCAST: отправка на 255.255.255.255 (limited broadcast) —
/// fallback-канал обнаружения в сетях, где мультикаст фильтруется.
pub fn setBroadcast(fd: fd_t) void {
    if (is_linux) {
        _ = std.os.linux.setsockopt(fd, posix.SOL.SOCKET, posix.SO.BROADCAST, &std.mem.toBytes(@as(c_int, 1)), 4);
        return;
    }
    _ = cabi.setsockopt(@intCast(fd), posix.SOL.SOCKET, posix.SO.BROADCAST, &std.mem.toBytes(@as(c_int, 1)), 4);
}

/// IP_MULTICAST_TTL: 1 — анонс не покидает локальный сегмент (LAN-only).
/// Значение опции 10 совпадает на Linux и Darwin (BSD-наследие).
const ip_multicast_ttl: u32 = 10;
pub fn setMulticastTtl(fd: fd_t) void {
    const ttl: c_int = 1;
    setSockOptRaw(fd, posix.IPPROTO.IP, ip_multicast_ttl, &std.mem.toBytes(ttl));
}

/// Байты struct ip_mreq: адрес группы в сетевом порядке (как есть) +
/// INADDR_ANY (интерфейс по умолчанию).
fn mcastMreq(group_ip: [4]u8) [8]u8 {
    var mreq: [8]u8 = @splat(0);
    @memcpy(mreq[0..4], &group_ip);
    return mreq;
}

/// Вступить в IPv4-мультикаст-группу (INADDR_ANY — интерфейс по умолчанию).
pub fn joinMulticastGroup(fd: fd_t, group_ip: [4]u8) void {
    const mreq = mcastMreq(group_ip);
    const opt: u32 = if (is_linux) ip_add_membership_linux else ip_add_membership_darwin;
    setSockOptRaw(fd, posix.IPPROTO.IP, opt, &mreq);
}

/// UDP sendto на sockaddr.in; ошибки проглатываются (анонс best-effort).
pub fn sendtoIn(fd: fd_t, bytes: []const u8, sa: *const SockaddrIn) void {
    if (is_linux) {
        _ = std.os.linux.sendto(fd, bytes.ptr, bytes.len, 0, @ptrCast(sa), @sizeOf(SockaddrIn));
        return;
    }
    _ = cabi.sendto(@intCast(fd), bytes.ptr, bytes.len, 0, @ptrCast(sa), @sizeOf(SockaddrIn));
}

/// UDP recvfrom; возвращает число прочитанных байтов или null (ошибка/
/// таймаут). Адрес отправителя — в sa.
pub fn recvfromIn(fd: fd_t, buf: []u8, sa: *SockaddrIn) ?usize {
    if (is_linux) {
        var sl: posix.socklen_t = @sizeOf(SockaddrIn);
        const rc = std.os.linux.recvfrom(fd, buf.ptr, buf.len, 0, @ptrCast(sa), &sl);
        if (std.os.linux.errno(rc) != .SUCCESS) return null;
        return @intCast(rc);
    }
    var sl: posix.socklen_t = @sizeOf(SockaddrIn);
    const rc = cabi.recvfrom(@intCast(fd), buf.ptr, buf.len, 0, @ptrCast(sa), &sl);
    if (rc < 0) return null;
    return @intCast(rc);
}

/// Сокет/файл только владельцу (UDS 0700; на Linux — fchmodat AT.FDCWD).
pub fn chmodOwnerOnly(zpath: [*:0]const u8, mode: u32) void {
    if (is_linux) {
        _ = std.os.linux.fchmodat(std.os.linux.AT.FDCWD, zpath, @intCast(mode));
        return;
    }
    _ = cabi.chmod(zpath, @intCast(mode));
}

/// Монотонные наносекунды прямым вызовом (без глобального состояния).
pub fn monoNs() u64 {
    if (is_linux) {
        var ts: std.os.linux.timespec = undefined;
        _ = std.os.linux.clock_gettime(std.os.linux.CLOCK.MONOTONIC, &ts);
        const ns: u64 = @bitCast(@as(i64, ts.sec) *% std.time.ns_per_s +% ts.nsec);
        return ns;
    }
    var ts: cabi.timespec = undefined;
    _ = cabi.clock_gettime(darwin_clock_monotonic, &ts);
    const ns: u64 = @bitCast(@as(i64, ts.sec) *% std.time.ns_per_s +% ts.nsec);
    return ns;
}

/// Настенные миллисекунды (CLOCK.REALTIME, id 0 и на linux, и на darwin):
/// приватные ts_ms записей — прямое чтение часов, без io.
pub fn wallMs() i64 {
    if (is_linux) {
        var ts: std.os.linux.timespec = undefined;
        _ = std.os.linux.clock_gettime(std.os.linux.CLOCK.REALTIME, &ts);
        return @as(i64, @intCast(ts.sec)) * 1000 + @as(i64, @intCast(@divTrunc(ts.nsec, std.time.ns_per_ms)));
    }
    var ts: cabi.timespec = undefined;
    _ = cabi.clock_gettime(0, &ts); // CLOCK_REALTIME = 0
    return @as(i64, @intCast(ts.sec)) * 1000 + @as(i64, @intCast(@divTrunc(ts.nsec, std.time.ns_per_ms)));
}

/// Файл существует? (открыть RDONLY + закрыть.)
pub fn fileExists(zpath: [*:0]const u8) bool {
    if (is_linux) {
        const rc = std.os.linux.openat(@bitCast(@as(i32, -100)), zpath, .{ .ACCMODE = .RDONLY }, 0);
        if (std.os.linux.errno(rc) != .SUCCESS) return false;
        _ = std.os.linux.close(@intCast(rc));
        return true;
    }
    const fd = cabi.open(zpath, darwin_o_rdonly);
    if (fd < 0) return false;
    _ = cabi.close(fd);
    return true;
}

/// Каталог 0700; EEXIST — не ошибка.
pub fn makeDir700(zpath: [*:0]const u8) void {
    if (is_linux) {
        _ = std.os.linux.mkdir(zpath, 0o700);
        return;
    }
    _ = cabi.mkdir(zpath, 0o700);
}

/// Создать файл 0600 на запись (truncate). null — ошибка.
pub fn createFile600(zpath: [*:0]const u8) ?fd_t {
    if (is_linux) {
        const rc = std.os.linux.openat(@bitCast(@as(i32, -100)), zpath, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o600);
        if (std.os.linux.errno(rc) != .SUCCESS) return null;
        return @intCast(rc);
    }
    const fd = cabi.open(zpath, darwin_o_wronly | darwin_o_creat | darwin_o_trunc, @as(c_int, 0o600));
    if (fd < 0) return null;
    return fd;
}

/// Сон потока без std.Io (фоновые циклы net/app-слоя).
pub fn sleepMs(ms: u64) void {
    if (is_linux) {
        var req: std.os.linux.timespec = .{
            .sec = @intCast(ms / std.time.ms_per_s),
            .nsec = @intCast((ms % std.time.ms_per_s) * std.time.ns_per_ms),
        };
        _ = std.os.linux.nanosleep(&req, null);
        return;
    }
    var req: cabi.timespec = .{
        .sec = @intCast(ms / std.time.ms_per_s),
        .nsec = @intCast((ms % std.time.ms_per_s) * std.time.ns_per_ms),
    };
    _ = cabi.nanosleep(&req, null);
}

// ==== Тесты ====
const testing = std.testing;

test "mcastMreq: адрес группы копируется без перестановки байт" {
    // Регрессия: readInt(.little) + writeInt(.big) разворачивал адрес
    // (239.77.77.77 -> 77.77.77.239), IP_ADD_MEMBERSHIP падал с EINVAL,
    // и демон молча оставался без приёма мультикаста.
    const mreq = mcastMreq(.{ 239, 77, 77, 77 });
    try testing.expectEqualSlices(u8, &.{ 239, 77, 77, 77, 0, 0, 0, 0 }, &mreq);
}

test "sockaddrIn: порт big-endian и адрес в сетевом порядке" {
    const sa = sockaddrIn(.{ 192, 168, 1, 9 }, 7777);
    try testing.expectEqual(@as(u16, 7777), std.mem.bigToNative(u16, sa.port));
    var ip_back: [4]u8 = undefined;
    std.mem.writeInt(u32, &ip_back, sa.addr, .little);
    try testing.expectEqualSlices(u8, &.{ 192, 168, 1, 9 }, &ip_back);
}

test "monoNs: монотонно и не спит зря" {
    const a = monoNs();
    const b = monoNs();
    try testing.expect(b >= a);
    sleepMs(1);
    try testing.expect(monoNs() > a);
}
