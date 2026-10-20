//! Waker: событийное разбуждение фонового сетевого цикла из потоков
//! API — триггер БЕЗ слепого сна. pipe на linux и darwin (одна семантика
//! на всех платформах): запись байта из любого потока будит poll-цикл;
//! drain() опустошает накопленное. Без локов и аллокаций: wake() — один
//! syscall. Чтение/запись/закрытие — через net/sysfd.zig (переносимость).
//! Ёмкость pipe (64 КиБ байтов) — верхняя граница накопления; цикл
//! drain-ит всё сразу, переполнение при живом цикле невозможно.
const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const stille_messenger = @import("stille-messenger");
const sysfd = stille_messenger.net.sysfd;

const is_linux = builtin.os.tag == .linux;

/// fcntl-константы (linux и darwin совпадают): F_GETFL=3, F_SETFL=4.
const fcntl_getfl: i32 = 3;
const fcntl_setfl: i32 = 4;
/// O_NONBLOCK: Linux 0o4000, Darwin 0x4.
const o_nonblock: usize = if (is_linux) 0o4000 else 0x4;

/// Darwin: libc-extern (std.posix в 0.17 не экспортирует pipe/fcntl).
const cabi = struct {
    extern "c" fn pipe(fds: *[2]c_int) c_int;
    extern "c" fn fcntl(fd: c_int, cmd: c_int, arg: c_int) c_int;
};

pub const Waker = struct {
    rfd: posix.socket_t,
    wfd: posix.socket_t,

    /// Оба конца неблокирующие: drain не ждёт, wake при переполнении
    /// (не бывает при живом цикле) проглатывается без блокировки звавшего.
    pub fn init() error{Network}!Waker {
        var fds: [2]posix.socket_t = undefined;
        if (is_linux) {
            const rc = std.os.linux.pipe(&fds);
            if (std.os.linux.errno(rc) != .SUCCESS) return error.Network;
        } else {
            if (cabi.pipe(@ptrCast(&fds)) != 0) return error.Network;
        }
        var ok = true;
        setNonblock(fds[0]) catch {
            ok = false;
        };
        if (ok) setNonblock(fds[1]) catch {
            ok = false;
        };
        if (!ok) {
            sysfd.close(fds[0]);
            sysfd.close(fds[1]);
            return error.Network;
        }
        return .{ .rfd = fds[0], .wfd = fds[1] };
    }

    pub fn deinit(self: *Waker) void {
        sysfd.close(self.rfd);
        sysfd.close(self.wfd);
    }

    /// Слот poll для цикла ожидания (вместе с сокетом обнаружения).
    pub fn pollfd(self: *const Waker) posix.pollfd {
        return .{ .fd = self.rfd, .events = posix.POLL.IN, .revents = 0 };
    }

    /// Разбудить цикл (из любого потока, без локов). Один байт.
    pub fn wake(self: *Waker) void {
        sysfd.writeAll(self.wfd, &[_]u8{1}) catch {};
    }

    /// Снять все накопленные wake-ы; вызывать в цикле после poll.
    pub fn drain(self: *Waker) void {
        var buf: [256]u8 = undefined;
        while (true) {
            // EAGAIN (пусто) — ошибка чтения: выходим
            const n = sysfd.read(self.rfd, &buf) catch return;
            if (n == 0) return;
        }
    }
};

/// Неблокирующий режим fd (linux — прямые syscall-ы, darwin — libc;
/// паттерн net/sysfd.zig).
fn setNonblock(fd: posix.socket_t) error{Network}!void {
    if (is_linux) {
        const fl = std.os.linux.fcntl(fd, fcntl_getfl, 0);
        if (std.os.linux.errno(fl) != .SUCCESS) return error.Network;
        const want: usize = @as(usize, @intCast(fl)) | o_nonblock;
        const rc = std.os.linux.fcntl(fd, fcntl_setfl, @bitCast(want));
        if (std.os.linux.errno(rc) != .SUCCESS) return error.Network;
        return;
    }
    const cur = cabi.fcntl(@intCast(fd), fcntl_getfl, 0);
    if (cur < 0) return error.Network;
    if (cabi.fcntl(@intCast(fd), fcntl_setfl, cur | @as(c_int, @intCast(o_nonblock))) < 0) return error.Network;
}

test "waker: wake будит poll, drain гасит" {
    const t = std.testing;
    var w = try Waker.init();
    defer w.deinit();
    // без wake: тишина
    var pfd = [1]posix.pollfd{w.pollfd()};
    try t.expectEqual(@as(i32, 0), try posix.poll(&pfd, 0));
    // wake: читаемо немедленно
    w.wake();
    try t.expectEqual(@as(i32, 1), try posix.poll(&pfd, 0));
    w.drain();
    pfd[0].revents = 0;
    try t.expectEqual(@as(i32, 0), try posix.poll(&pfd, 0));
    // много вейков подряд — один drain
    for (0..100) |_| w.wake();
    w.drain();
    pfd[0].revents = 0;
    try t.expectEqual(@as(i32, 0), try posix.poll(&pfd, 0));
}
