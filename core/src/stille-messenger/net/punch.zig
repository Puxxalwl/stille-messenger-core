//! NAT-punch: прямой путь между двумя ядрами за NAT через ОДНОВРЕМЕННЫЙ
//! TCP-open (simultaneous open). Рефлексивные кандидаты (публичный
//! ip:port, каким релей видит подключение) обменяны внутри
//! аутентифицированной сессии (envelope PUNCH_CANDIDATES 0x47) —
//! подменить их извне нельзя, replay отсечён рэтчетом сессии.
//!
//! Механика (классика Ford/Srisuresh/Kegel): ОБЕ стороны одновременно
//! дозваниваются на рефлексивные кандидаты друг друга ИЗ ТОГО ЖЕ
//! локального адреса:порта, что и relay-подключение (SO_REUSEADDR на
//! всех сокетах пары). NAT с endpoint-independent маппингом (cone)
//! переиспользует внешний порт; исходящие SYN пересекаются, ядро
//! сводит SYN_SENT + входящий SYN в SYN_RCVD -> ESTABLISHED. Кто из
//! сторон первый завершил connect — неважно: соединение одно и то же.
//! Симметричные NAT не пробиваются — остаёмся на relay (fallback по
//! дизайну, см. PROTOCOL.md §15.1).
//!
//! Бюджет ресурсов (инвариант Bounded): кандидатов ≤ punch_max_targets,
//! раундов ≤ punch_max_rounds, окно раунда punch_round_ms, мс между
//! раундами punch_gap_ms. Аллокаций на раунд нет: массивы сокетов на
//! стеке, буфер poll — на стеке. Один TcpConn на успех.
//!
//! Host-кандидаты (LAN-адрес+listen-порт пира) движок НЕ дозванивает:
//! это обычный прямой dial в листенер пира — его делает вызывающая
//! сторона (app/main.zig, только сторона-инициатор по правилу
//! «меньший bundle»), ответчик принимает штатным авто-листенером.
const std = @import("std");
const posix = std.posix;
const sysfd = @import("sysfd.zig");
const tcp = @import("tcp.zig");

/// Максимум рефлексивных кандидатов в раунде (бюджет fd и poll).
pub const punch_max_targets: usize = 4;
/// Максимум раундов одновременного dial (бюджет времени, ~2 с всего).
pub const punch_max_rounds: u8 = 3;
/// Окно ожидания connect в раунде (мс).
pub const punch_round_ms: u32 = 500;
/// Пауза между раундами (мс): стороны «одновременны» с точностью до
/// окна повторной передачи SYN, а не до миллисекунды.
pub const punch_gap_ms: u64 = 100;
/// Срез poll и период пересоздания отказавших слотов (мс): обе стороны
/// проводят в SYN_SENT почти всё окно раунда — SYN гарантированно
/// пересекаются при разбросе старта до раунда.
pub const punch_retry_ms: i32 = 50;

pub const Error = error{
    /// Сетевой сбой сокета/бинда.
    Network,
    /// Все раунды исчерпаны, пробития нет (симметричный NAT / фильтр).
    Timeout,
    /// Кандидатов нет или лимиты нарушены.
    BadArgs,
    /// Аллокация TcpConn.
    OutOfMemory,
};

/// Рефлексивный кандидат пира: публичный ip:port его NAT-маппинга.
pub const Target = struct {
    ip: [4]u8,
    port: u16,
};

/// Параметры движка. local — локальный адрес:порт RELAY-подключения
/// (getsockname): punch-сокеты биндятся на него же, чтобы NAT
/// переиспользовал внешний порт маппинга.
pub const Options = struct {
    local_ip: [4]u8,
    local_port: u16,
    rounds: u8 = punch_max_rounds,
    round_ms: u32 = punch_round_ms,
};

/// Один слот кандидата в раунде: fd с неблокирующим connect из local.
/// invalid = сокет закрыт (RST/ошибка) — пересоздаётся в плотном цикле
/// раунда (см. dialSimultaneous).
const Slot = struct {
    fd: posix.socket_t,
    target: Target,
    invalid: bool = false,
};

/// Поднять сокет слота: SO_REUSEADDR + bind(local) + неблокирующий
/// connect. true — сокет жив (SYN в полёте).
fn slotDial(s: *Slot, local_ip: [4]u8, local_port: u16) bool {
    const fd = sysfd.socketTcp() catch return false;
    sysfd.setReuseAddr(fd);
    const bind_sa = sysfd.sockaddrIn(local_ip, local_port);
    sysfd.bindIn(fd, &bind_sa) catch {
        sysfd.close(fd);
        return false;
    };
    sysfd.setNonblock(fd, true) catch {
        sysfd.close(fd);
        return false;
    };
    const sa = sysfd.sockaddrIn(s.target.ip, s.target.port);
    sysfd.connectInNonblock(fd, &sa) catch {
        sysfd.close(fd);
        return false;
    };
    s.fd = fd;
    s.invalid = false;
    return true;
}

fn tunePunched(fd: posix.socket_t) void {
    sysfd.setSocketBuffers(fd);
    sysfd.setQuickAck(fd);
    sysfd.setNoDelay(fd);
    sysfd.setKeepalive(fd);
}

/// Одновременный TCP-open по рефлексивным кандидатам пира. Возвращает
/// УСТАНОВЛЕННОЕ соединение (блокирующий fd, тюнинг как у tcp.dial) —
/// поверх него вызывающий запускает штатное рукопожатие/JOIN.
///
/// Раунд — окно round_ms с ПЛОТНЫМ циклом: слоты с отказом (RST —
/// сторона пира ещё не в SYN_SENT) пересоздаются каждые punch_retry_ms,
/// поэтому обе стороны проводят в SYN_SENT почти всё окно и SYN
/// пересекаются независимо от разброса старта. Победитель — первый
/// успешный connect в порядке кандидатов; конкуренты закрываются.
pub fn dialSimultaneous(alloc: std.mem.Allocator, targets: []const Target, opts: Options) Error!*tcp.TcpConn {
    if (targets.len == 0 or targets.len > punch_max_targets) return error.BadArgs;
    if (opts.rounds == 0 or opts.rounds > punch_max_rounds) return error.BadArgs;

    var slots: [punch_max_targets]Slot = undefined;
    const n = targets.len;
    for (targets, 0..) |t, i| slots[i] = .{ .fd = -1, .target = t, .invalid = true };

    var round: u8 = 0;
    while (round < opts.rounds) : (round += 1) {
        const deadline = sysfd.monoNs() + @as(u64, opts.round_ms) * std.time.ns_per_ms;
        while (sysfd.monoNs() < deadline) {
            // пересоздать мёртвые слоты (плотный retry)
            for (slots[0..n]) |*s| {
                if (!s.invalid) continue;
                if (!slotDial(s, opts.local_ip, opts.local_port)) {
                    // бинд/сокет отказали: пауза, попробуем в следующей
                    // итерации окна (без busy-спина)
                    sysfd.sleepMs(punch_retry_ms);
                }
            }
            // poll живых слотов коротким срезом окна
            var pfds: [punch_max_targets]posix.pollfd = undefined;
            var idx: [punch_max_targets]usize = undefined; // pollfd -> слот
            var cnt: usize = 0;
            for (slots[0..n], 0..) |*s, si| {
                if (s.invalid) continue;
                pfds[cnt] = .{ .fd = s.fd, .events = posix.POLL.OUT | posix.POLL.ERR | posix.POLL.HUP, .revents = 0 };
                idx[cnt] = si;
                cnt += 1;
            }
            if (cnt == 0) continue;
            _ = posix.poll(pfds[0..cnt], punch_retry_ms) catch continue;
            // проверить завершения в порядке кандидатов
            var won_fd: ?posix.socket_t = null;
            for (pfds[0..cnt], 0..) |pfd, pi| {
                if (pfd.revents == 0) continue;
                const s = &slots[idx[pi]];
                if (s.invalid) continue;
                const so_err = sysfd.soError(s.fd) orelse @as(i32, -1);
                if (so_err == 0) {
                    if (won_fd == null) won_fd = s.fd; // конкурентов закроем ниже
                    continue;
                }
                // RST/таймаут connect: слот мёртв — пересоздадим в цикле
                sysfd.close(s.fd);
                s.invalid = true;
                s.fd = -1;
            }
            if (won_fd) |fd| {
                for (slots[0..n]) |*s| {
                    if (s.invalid or s.fd == fd) continue;
                    sysfd.close(s.fd);
                    s.invalid = true;
                    s.fd = -1;
                }
                sysfd.setNonblock(fd, false) catch {
                    sysfd.close(fd);
                    return error.Network;
                };
                tunePunched(fd);
                const tc = alloc.create(tcp.TcpConn) catch {
                    sysfd.close(fd);
                    return error.OutOfMemory;
                };
                tc.* = .{ .fd = fd };
                return tc;
            }
        }
        // окно раунда закрыто: все слоты вниз, пауза перед следующим
        for (slots[0..n]) |*s| {
            if (!s.invalid) {
                sysfd.close(s.fd);
                s.invalid = true;
                s.fd = -1;
            }
        }
        if (round + 1 < opts.rounds) sysfd.sleepMs(punch_gap_ms);
    }
    return error.Timeout;
}

// ==== Тесты ====
const testing = std.testing;

/// Фиктивное «relay-подключение»: сокет с SO_REUSEADDR, бинд на
/// свободный loopback-порт (маппинг, который punch переиспользует).
const FakeRelayConn = struct {
    fd: posix.socket_t,
    ip: [4]u8,
    port: u16,

    fn init() !FakeRelayConn {
        const fd = try sysfd.socketTcp();
        errdefer sysfd.close(fd);
        sysfd.setReuseAddr(fd);
        const sa = sysfd.sockaddrIn(.{ 127, 0, 0, 1 }, 0);
        try sysfd.bindIn(fd, &sa);
        const la = sysfd.localAddrIn(fd) orelse return error.Network;
        const ipp = sysfd.ipPortOf(la);
        return .{ .fd = fd, .ip = ipp.ip, .port = ipp.port };
    }

    fn deinit(self: *FakeRelayConn) void {
        sysfd.close(self.fd);
    }
};

test "punch: одновременный open двух сторон на loopback" {
    const alloc = testing.allocator;
    var ra = try FakeRelayConn.init();
    defer ra.deinit();
    var rb = try FakeRelayConn.init();
    defer rb.deinit();

    // стороны обмениваются кандидатами (рефлексивный = адрес пира)
    const Job = struct {
        alloc: std.mem.Allocator,
        target: Target,
        local_ip: [4]u8,
        local_port: u16,
        result: ?*tcp.TcpConn = null,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.result = dialSimultaneous(self.alloc, &.{self.target}, .{
                .local_ip = self.local_ip,
                .local_port = self.local_port,
                .rounds = 3,
                .round_ms = 700,
            }) catch |e| {
                self.err = e;
                return;
            };
        }
    };
    var job_a = Job{ .alloc = alloc, .target = .{ .ip = rb.ip, .port = rb.port }, .local_ip = ra.ip, .local_port = ra.port };
    var job_b = Job{ .alloc = alloc, .target = .{ .ip = ra.ip, .port = ra.port }, .local_ip = rb.ip, .local_port = rb.port };
    // одновременность: оба потока стартуют вместе (бар departed)
    const th_a = try std.Thread.spawn(.{}, Job.run, .{&job_a});
    const th_b = try std.Thread.spawn(.{}, Job.run, .{&job_b});
    th_a.join();
    th_b.join();

    const ca = job_a.result orelse return job_a.err.?;
    defer {
        ca.deinit();
        alloc.destroy(ca);
    }
    const cb = job_b.result orelse return job_b.err.?;
    defer {
        cb.deinit();
        alloc.destroy(cb);
    }
    // соединение установлено «в обе стороны»: peer каждой стороны —
    // локальный порт другой (loopback-«NAT» отдал адрес как есть)
    const pa = sysfd.ipPortOf(sysfd.peerAddrIn(ca.fd).?);
    try testing.expectEqual(rb.port, pa.port);
    try testing.expectEqualSlices(u8, &rb.ip, &pa.ip);
    const pb = sysfd.ipPortOf(sysfd.peerAddrIn(cb.fd).?);
    try testing.expectEqual(ra.port, pb.port);
    // данные текут в обе стороны
    var probe: [3]u8 = .{ 1, 2, 3 };
    try sysfd.writeAll(ca.fd, &probe);
    var back: [3]u8 = undefined;
    try rawReadAll(cb.fd, &back);
    try testing.expectEqualSlices(u8, &probe, &back);
}

test "punch: мёртвый кандидат — Timeout после раундов" {
    const alloc = testing.allocator;
    var ra = try FakeRelayConn.init();
    defer ra.deinit();
    // порт, где никто не слушает и никто не дозванивается одновременно
    var dead = try FakeRelayConn.init();
    const dead_port = dead.port;
    dead.deinit();
    const t0 = sysfd.monoNs();
    const r = dialSimultaneous(alloc, &.{.{ .ip = .{ 127, 0, 0, 1 }, .port = dead_port }}, .{
        .local_ip = ra.ip,
        .local_port = ra.port,
        .rounds = 2,
        .round_ms = 100,
    });
    try testing.expectError(error.Timeout, r);
    // бюджет: 2 раунда × 100 мс + паузы — быстро, без зависаний
    const dt_ms = (sysfd.monoNs() - t0) / std.time.ns_per_ms;
    try testing.expect(dt_ms < 2000);
}

test "punch: лимиты кандидатов и раундов — BadArgs" {
    const alloc = testing.allocator;
    var ra = try FakeRelayConn.init();
    defer ra.deinit();
    const opts = Options{ .local_ip = ra.ip, .local_port = ra.port };
    try testing.expectError(error.BadArgs, dialSimultaneous(alloc, &.{}, opts));
    var many: [punch_max_targets + 1]Target = undefined;
    for (&many) |*t| t.* = .{ .ip = .{ 127, 0, 0, 1 }, .port = 9 };
    try testing.expectError(error.BadArgs, dialSimultaneous(alloc, &many, opts));
    try testing.expectError(error.BadArgs, dialSimultaneous(alloc, many[0..1], .{ .local_ip = ra.ip, .local_port = ra.port, .rounds = 0 }));
}

/// Точный read (у punch-тестов нет TcpConn-обёртки).
fn rawReadAll(fd: posix.socket_t, buf: []u8) !void {
    var got: usize = 0;
    while (got < buf.len) {
        const n = posix.read(fd, buf[got..]) catch return error.Closed;
        if (n == 0) return error.Closed;
        got += n;
    }
}
