//! LAN-обнаружение (linker): анонс по multicast/broadcast, реакция
//! на анонсы пиров и устройств-линков, постановка dial в планировщик.
const std = @import("std");
const stille_messenger = @import("stille-messenger");
const sysfd = stille_messenger.net.sysfd;
const wake = @import("wake.zig");
const discover_mod = @import("discover.zig");
const app_mod = @import("app.zig");
pub const App = app_mod.App;
const connq = @import("connq.zig");
const events = @import("events.zig");
const persist = @import("persist.zig");
const posix = std.posix;

// ------------------------------------------------- автоподключение (LAN)
/// Автодозвон офлайн-контактов по сохранённым адресам: backoff 1с -> 60с
/// с джиттером (фоновая страховка; мгновенный путь — kickConnect из
/// отправки сообщения и событийный linkerLoop). IPv4 в строку (без порта).
pub fn fmtIpBuf(buf: *[16]u8, ip: [4]u8) []const u8 {
    return std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}", .{ ip[0], ip[1], ip[2], ip[3] }) catch "?";
}

/// Каденции анонса, мс: base — фоновое присутствие; burst — пока есть
/// кому доставлять (pending outbox/JOIN), пир с ждущими данными находит
/// нас за интервал burst. 74-байтный датаграмм, один сокет — трафик
/// фонового каденса ~150 Б/с, burst ~750 Б/с.
pub const announce_base_ms: i64 = 500;

pub const announce_burst_ms: i64 = 100;

/// Анонсов за одно пробуждение poll (бюджет цикла на пачку событий).
pub const announce_batch: usize = 8;

/// Есть ли кому доставлять: pending outbox или ждущий JOIN. Под app.mu.
pub fn burstPending(app: *App) bool {
    return app.eng.outbox.items.len > 0 or app.join_map.count() > 0;
}

/// Фоновый поток обнаружения: событийный цикл на poll [сокет обнаружения
/// + будилка]. Слушает сеть ПОСТОЯННО (не окнами): анонс пира слышится в
/// момент его отправки. Анонсирует по каденсу (base/burst), событие от
/// API (kickConnect) — анонс немедленно. Услышав анонс, отвечает своим
/// unicast-ом напрямую (пир узнаёт о нас за ~RTT) и ставит работу
/// подключения в планировщик: НИКОГДА не блокируется на TCP сам.
pub fn linkerLoop(app: *App) void {
    var disc = discover_mod.Discovery.init() catch return;
    defer disc.deinit();
    const my_bundle = app.id.bundle();
    // 0 = анонсировать немедленно: старт демона — пир узнает за ~RTT
    var next_announce_ms: i64 = 0;
    while (app.running) {
        // LAN-поиск управляется конфигурацией (флаг читается под локом);
        // выключен — не анонсим и не читаем сокет (POLL.IN не копится),
        // ждём только будилку/каденс: включат — анонс сразу
        var lan = false;
        {
            app.lock();
            lan = app.cfg.lan_discovery;
            app.unlock();
        }
        const now = app.nowMs();
        var timeout: i32 = 2000;
        if (lan) {
            // таймаут poll = до следующего анонса (насыщение секундой)
            timeout = 0;
            if (next_announce_ms > now) {
                const d: u64 = @intCast(next_announce_ms - now);
                timeout = if (d > 1000) 1000 else @intCast(d);
            }
        } else {
            next_announce_ms = 0;
        }
        var pfd: [2]posix.pollfd = .{
            if (lan) disc.pollfd() else .{ .fd = -1, .events = 0, .revents = 0 },
            .{ .fd = -1, .events = 0, .revents = 0 },
        };
        var waker: ?*wake.Waker = null;
        if (app.link_wake) |*w| {
            waker = w;
            pfd[1] = w.pollfd();
        }
        _ = posix.poll(&pfd, timeout) catch {};
        if (waker != null and pfd[1].revents & posix.POLL.IN != 0) {
            waker.?.drain();
            // событие (отправка офлайн/разрыв сессии): анонс немедленно
            next_announce_ms = 0;
        }
        if (lan and pfd[0].revents & posix.POLL.IN != 0) {
            var heard: usize = 0;
            while (heard < announce_batch) : (heard += 1) {
                const a = disc.recvAnnounce() orelse break;
                handleAnnounce(app, &my_bundle, a, &disc);
            }
        }
        // анонс по каденсу (или немедленно после события/включения)
        if (lan and next_announce_ms <= app.nowMs()) {
            disc.announce(my_bundle, app.listen_port);
            const burst = blk: {
                app.lock();
                defer app.unlock();
                break :blk burstPending(app);
            };
            next_announce_ms = app.nowMs() + if (burst) announce_burst_ms else announce_base_ms;
        }
    }
}

/// Обработка услышанного анонса: обновить адрес контакта, поставить
/// работу подключения в планировщик (single-flight/поколения — как у
/// ручных путей), ответить своим анонсом напрямую. Инициатор — сторона
/// с меньшим bundle (детерминизм, без гонки); держатель инвайт-кода
/// инициирует ВСЕГДА: приглашающий его не знает.
pub fn handleAnnounce(app: *App, my_bundle: *const [64]u8, a: discover_mod.Announce, disc: ?*discover_mod.Discovery) void {
    // анонс НАШЕГО bundle: другое устройство того же пользователя
    // (device_sync). MACи синхронизации не пустят постороннего, а
    // сюда он и не дойдёт — bundle уникален только у своих.
    if (std.mem.eql(u8, &a.bundle, my_bundle)) {
        handleDeviceAnnounce(app, a.ip, a.port);
        return;
    }
    const cid = app_mod.contactIdByBundle(app, a.bundle) orelse return;
    var ab_ip: [16]u8 = undefined;
    const ip_str = fmtIpBuf(&ab_ip, a.ip);
    var need_dial = false;
    var join_due = false;
    {
        // адрес анонса — сохранить для автодозвона (последний известный);
        // мутация контактов — строго под app.mu (ticker и рендер итерируют)
        app.lock();
        defer app.unlock();
        const c = &app.eng.contacts.items[@intCast(cid - 1)];
        if (c.deleted) return;
        c.setAddr(ip_str, a.port);
        const linked = app.eng.sessions.get(cid) != null;
        join_due = app.join_map.contains(cid);
        need_dial = !linked and !c.blocked and
            (std.mem.order(u8, my_bundle, &a.bundle) == .lt or join_due);
    }
    if (!need_dial) return;
    // markSeen не нужен: установление -> bindSession сам метит онлайн.
    // dial — в планировщике (connWorker), не в потоке детекта: цикл
    // обнаружения не блокируется на TCP вообще
    var work = app_mod.ConnWork{ .cid = cid };
    const addr = discover_mod.fmtAddr(&work.addr_buf, a.ip, a.port);
    work.addr_len = @intCast(addr.len);
    connq.connEnqueue(app, work) catch return;
    // ответ пир-у: он анонснул — он слушает; свой анонс напрямую, чтобы
    // он узнал о нас за ~RTT (не ждал нашего каденса). Не-инициатор
    // всё равно сохранит наш адрес (автодозвон/contact_view)
    if (disc) |d| d.announceTo(my_bundle.*, app.listen_port, a.ip, a.src_port);
}

/// Анонс нашего же bundle в LAN: другое устройство пользователя.
/// Дозвон — только ДЕРЖАТЕЛЬ линка (детерминизм, как в join-правиле) и
/// только при включённом device_sync (линк без репликации не нужен;
/// поднять его заново можно кодом инвайта в любой момент).
pub fn handleDeviceAnnounce(app: *App, ip: [4]u8, port: u16) void {
    var ab_ip: [16]u8 = undefined;
    const ip_str = fmtIpBuf(&ab_ip, ip);
    var dial_cid: i64 = -1;
    {
        app.lock();
        defer app.unlock();
        if (!app.cfg.device_sync) return;
        // v1: один линк-контакт (bundle один на все устройства)
        for (app.eng.contacts.items, 0..) |*c, i| {
            if (!std.mem.eql(u8, &c.bundle, &app.id.bundle())) continue;
            if (c.deleted or c.blocked) return;
            if (c.dev_role != app_mod.dev_role_holder) return; // мы — ждущая сторона
            if (app.eng.sessions.contains(@intCast(i + 1))) return; // уже жива
            c.setAddr(ip_str, port);
            dial_cid = @intCast(i + 1);
            break;
        }
    }
    if (dial_cid < 0) return;
    // single-flight + метка попытки (2.7.0): как и ручные пути. dial —
    // в планировщике (connWorker), не в потоке обнаружения: цикл детекта
    // не блокируется на TCP (дедлайн dial — direct_dial_timeout_ms)
    var work = app_mod.ConnWork{ .cid = dial_cid };
    const addr = discover_mod.fmtAddr(&work.addr_buf, ip, port);
    work.addr_len = @intCast(addr.len);
    connq.connEnqueue(app, work) catch return;
}
