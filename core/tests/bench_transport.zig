//! Бенчмарк транспорта: прямой TCP vs relay vs NAT-punch путь
//! (simultaneous open). Топология: loopback одного хоста (ограничение
//! стенда: NAT-маппинги не моделируются, punch-конн по свойствам ==
//! прямому TCP). Запуск:
//!
//!   cd core && zig run -OReleaseFast --dep stille-messenger \
//!     -Mroot=tests/bench_transport.zig \
//!     -Mstille-messenger=src/stille-messenger.zig
//!
//! Результаты зависят от машины; фиксируются в теле коммита, артефакты
//! в репозиторий не идут (AGENTS.md §8).
const std = @import("std");
const stille_messenger = @import("stille-messenger");
const tcp = stille_messenger.net.tcp;
const relay = stille_messenger.net.relay;
const punch = stille_messenger.net.punch;
const sysfd = stille_messenger.net.sysfd;

const chunk = 64 * 1024;
const total_bytes: usize = 32 * 1024 * 1024;
const rtt_rounds = 200;

fn nowMs() u64 {
    return sysfd.monoNs() / std.time.ns_per_ms;
}

/// Прогнать bulk A -> B по уже установленным коннам (a у отправителя).
fn benchBulk(label: []const u8, a: *tcp.TcpConn, b: *tcp.TcpConn) !u64 {
    var buf: [chunk]u8 = @splat(0xA5);
    const t0 = nowMs();
    // приёмник в потоке
    const Recv = struct {
        fn run(conn: *tcp.TcpConn, out: *u64) void {
            var got: usize = 0;
            var rb: [chunk]u8 = undefined;
            while (got < total_bytes) {
                const n = std.posix.read(conn.fd, rb[0..]) catch return;
                if (n == 0) return;
                got += n;
            }
            out.* = got;
        }
    };
    var got_total: u64 = 0;
    const th = try std.Thread.spawn(.{}, Recv.run, .{ b, &got_total });
    var sent: usize = 0;
    while (sent < total_bytes) {
        try sysfd.writeAll(a.fd, buf[0..]);
        sent += buf.len;
    }
    th.join();
    const dt = nowMs() - t0;
    const mibs = @as(f64, @floatFromInt(total_bytes)) / (1024.0 * 1024.0);
    if (dt == 0) return 0;
    const rate = mibs / (@as(f64, @floatFromInt(dt)) / 1000.0);
    std.debug.print("{s: <24} bulk {d} MiB за {d} мс  ~{d:.1} MiB/s\n", .{ label, @as(u32, @intFromFloat(mibs)), dt, rate });
    return dt;
}

/// RTT: эхо-пинг 1 KiB туда-обратно.
fn benchRtt(label: []const u8, a: *tcp.TcpConn, b: *tcp.TcpConn) !void {
    // эхо-приёмник в потоке
    const Echo = struct {
        fn run(conn: *tcp.TcpConn) void {
            var rb: [1024]u8 = undefined;
            while (true) {
                const n = std.posix.read(conn.fd, rb[0..]) catch return;
                if (n == 0) return;
                sysfd.writeAll(conn.fd, rb[0..n]) catch return;
            }
        }
    };
    const th = try std.Thread.spawn(.{}, Echo.run, .{b});
    defer {
        sysfd.shutdownReadWrite(b.fd);
        th.join();
    }
    var w: [1024]u8 = @splat(0x5A);
    var r: [1024]u8 = undefined;
    const t0 = nowMs();
    for (0..rtt_rounds) |_| {
        try sysfd.writeAll(a.fd, &w);
        var got: usize = 0;
        while (got < r.len) {
            const n = std.posix.read(a.fd, r[got..]) catch return;
            if (n == 0) return;
            got += n;
        }
    }
    const dt = nowMs() - t0;
    std.debug.print("{s: <24} rtt {d} × 1 KiB echo за {d} мс  ~{d:.3} мс/раунд\n", .{
        label, rtt_rounds, dt, @as(f64, @floatFromInt(dt)) / @as(f64, @floatFromInt(rtt_rounds)),
    });
}

fn freeConn(alloc: std.mem.Allocator, tc: *tcp.TcpConn) void {
    tc.deinit();
    alloc.destroy(tc);
}

pub fn main() !void {
    // ReleaseFast-аллокатор (бенчмарк, детектор утечек не нужен)
    const alloc = std.heap.smp_allocator;

    // ---- 1) прямой TCP (listener + dial)
    {
        var ab: [24]u8 = undefined;
        const laddr = try std.fmt.bufPrint(&ab, "127.0.0.1:{d}", .{@as(u16, 39601)});
        var lsn = tcp.listen(laddr) catch return error.NoListen;
        defer lsn.deinit();
        const Dial = struct {
            fn run(a: std.mem.Allocator, addr: []const u8, out: *?*tcp.TcpConn) void {
                out.* = tcp.dial(a, addr) catch null;
            }
        };
        var d: ?*tcp.TcpConn = null;
        const th = try std.Thread.spawn(.{}, Dial.run, .{ alloc, laddr, &d });
        const srv = try lsn.accept(alloc);
        th.join();
        const cli = d orelse return error.NoDial;
        defer freeConn(alloc, srv);
        defer freeConn(alloc, cli);
        _ = try benchBulk("direct TCP", cli, srv);
        try benchRtt("direct TCP", cli, srv);
    }

    // ---- 2) relay (marker-спаривание, сплит релеем)
    {
        var ab: [24]u8 = undefined;
        const laddr = try std.fmt.bufPrint(&ab, "127.0.0.1:{d}", .{@as(u16, 39617)});
        var lsn = tcp.listen(laddr) catch return error.NoListen;
        var stop = std.atomic.Value(bool).init(false);
        const th = try std.Thread.spawn(.{}, relay.serve, .{ alloc, &lsn, &stop });
        defer {
            stop.store(true, .seq_cst);
            if (tcp.dial(alloc, laddr)) |wk| {
                freeConn(alloc, wk);
            } else |_| {}
            th.join();
            lsn.deinit();
        }
        const marker = relay.presenceMarker(@splat(0x77));
        // обе стороны в потоках: dial блокируется до спаривания
        const Side = struct {
            fn run(a: std.mem.Allocator, addr: []const u8, m: [32]u8, out: *?*tcp.TcpConn) void {
                out.* = relay.dialMarker(a, addr, m) catch null;
            }
        };
        var ca: ?*tcp.TcpConn = null;
        var cb: ?*tcp.TcpConn = null;
        const ta = try std.Thread.spawn(.{}, Side.run, .{ alloc, laddr, marker, &ca });
        const tb = try std.Thread.spawn(.{}, Side.run, .{ alloc, laddr, marker, &cb });
        ta.join();
        tb.join();
        defer freeConn(alloc, ca.?);
        defer freeConn(alloc, cb.?);
        _ = try benchBulk("relay (split)", ca.?, cb.?);
        try benchRtt("relay (split)", ca.?, cb.?);
    }

    // ---- 3) NAT-punch путь (simultaneous open из портов «relay»-коннов)
    {
        // фиктивные relay-конны: просто занятые порты с SO_REUSEADDR
        const FakeRelay = struct {
            fd: sysfd.fd_t,
            port: u16,
            fn init() !@This() {
                const fd = try sysfd.socketTcp();
                sysfd.setReuseAddr(fd);
                const sa = sysfd.sockaddrIn(.{ 127, 0, 0, 1 }, 0);
                try sysfd.bindIn(fd, &sa);
                const la = sysfd.localAddrIn(fd) orelse return error.Network;
                return .{ .fd = fd, .port = sysfd.ipPortOf(la).port };
            }
        };
        const ra = try FakeRelay.init();
        defer sysfd.close(ra.fd);
        const rb = try FakeRelay.init();
        defer sysfd.close(rb.fd);
        const Job = struct {
            alloc: std.mem.Allocator,
            target: punch.Target,
            local_ip: [4]u8,
            local_port: u16,
            out: ?*tcp.TcpConn = null,
            fn run(self: *@This()) void {
                self.out = punch.dialSimultaneous(self.alloc, &.{self.target}, .{
                    .local_ip = self.local_ip,
                    .local_port = self.local_port,
                }) catch null;
            }
        };
        var ja = Job{ .alloc = alloc, .target = .{ .ip = .{ 127, 0, 0, 1 }, .port = rb.port }, .local_ip = .{ 127, 0, 0, 1 }, .local_port = ra.port };
        var jb = Job{ .alloc = alloc, .target = .{ .ip = .{ 127, 0, 0, 1 }, .port = ra.port }, .local_ip = .{ 127, 0, 0, 1 }, .local_port = rb.port };
        const ta = try std.Thread.spawn(.{}, Job.run, .{&ja});
        const tb = try std.Thread.spawn(.{}, Job.run, .{&jb});
        ta.join();
        tb.join();
        const ca = ja.out orelse return error.PunchFail;
        const cb = jb.out orelse return error.PunchFail;
        defer freeConn(alloc, ca);
        defer freeConn(alloc, cb);
        _ = try benchBulk("punched (sim. open)", ca, cb);
        try benchRtt("punched (sim. open)", ca, cb);
    }
}
