//! Планировщик подключений (connq): очередь работ, single-flight,
//! не более conn_active_cap воркеров. Воркеры (connWorker, punchRun)
//! выполняют dial без app.mu (спин-лок сетевой I/O держать нельзя).
const std = @import("std");
const stille_messenger = @import("stille-messenger");
const tcp = stille_messenger.net.tcp;
const punch = stille_messenger.net.punch;
const sysfd = stille_messenger.net.sysfd;
const app_mod = @import("app.zig");
const api = @import("api.zig");
const envelope = stille_messenger.proto.envelope;
const relay_mod = stille_messenger.net.relay;
const session_mod = stille_messenger.core.session;
pub const App = app_mod.App;
const events = @import("events.zig");
const dial = @import("dial.zig");
const presence = @import("presence.zig");
const routes = @import("routes.zig");
const endpoints_mod = @import("endpoints.zig");

/// Событийный кик подключения: отправка офлайн-контакту / потеря сессии
/// НЕ ждут слепых циклов автодозвона. Известен адрес — работа в очередь
/// немедленно (single-flight гасит дубли), адреса нет — DISCOVERING и
/// burst-анонс линкера через будилку (link_wake). ВЫЗЫВАТЬ ПОД app.mu
/// (connq_mu берётся поверх — вкладывание app.mu -> connq_mu допустимо).
pub fn kickConnectLocked(app: *App, cid: i64) void {
    if (cid < 1) return;
    const idx: usize = @intCast(cid - 1);
    if (idx >= app.eng.contacts.items.len) return;
    const c = &app.eng.contacts.items[idx];
    if (c.deleted or c.blocked) return;
    if (app.eng.sessions.get(cid) != null) return;
    var ab: [72]u8 = undefined;
    if (c.addr(&ab)) |a| {
        if (a.len <= 72) {
            var work = app_mod.ConnWork{ .cid = cid };
            @memcpy(work.addr_buf[0..a.len], a);
            work.addr_len = @intCast(a.len);
            // Busy (уже в полёте/очередь переполнена) — не ошибка:
            // фоновые циклы дозвонятся сами
            connEnqueue(app, work) catch {};
            // и разбудить линкер: адрес может быть устаревшим (пир сменил
            // IP) — dial и burst-анонс идут параллельно, кто первый
            if (app.link_wake) |*w| w.wake();
            return;
        }
    }
    // адреса нет — ждём анонс пира; разбудить линкер (burst-каденс)
    events.connDiscoveringLocked(app, cid);
    if (app.link_wake) |*w| w.wake();
}

/// Осталось мс до повтора (насыщение до u32; 0 — повтора нет).
/// next_retry_at — абсолютные wall-мс (0 = не назначен).
pub fn retryRemainingMs(next_retry_at: i64, now: i64) u32 {
    if (next_retry_at <= 0 or next_retry_at <= now) return 0;
    const d: u64 = @intCast(next_retry_at - now);
    if (d > std.math.maxInt(u32)) return std.math.maxInt(u32);
    return @intCast(d);
}

/// Классификация ошибки установления соединения → ConnErr. Детали
/// отказа аутентификации НЕ раскрываются (без oracle-поведения).
pub fn connErrOf(e: anyerror) api.ConnErr {
    return switch (e) {
        error.Timeout => .transport_timeout,
        error.Network, error.BadAddress, error.Closed => .transport_unavailable,
        error.NoRelay => .relay_unreachable,
        error.NoTor => .tor_unavailable,
        error.OutOfMemory => .capacity_exhausted,
        else => .auth_failed,
    };
}

/// Ошибка ФАЗЫ dial (транспорт ещё не поднимался): гибрид-инвайт имеет
/// право упасть на relay-fallback. Отказ ПОСЛЕ dial (рукопожатие/JOIN) —
/// аутентификационный контекст, fallback запрещён.
pub fn isDialPhaseError(e: anyerror) bool {
    return switch (e) {
        error.Network, error.BadAddress, error.Timeout, error.NoRelay, error.NoTor, error.OutOfMemory => true,
        else => false,
    };
}

// ---------------------------------------------------- планировщик (connq)
// Инвариант порядка локов: connq_mu — листовой (НИКОГДА не берётся поверх
// app.mu из своих функций); app.mu → connq_mu вкладывать МОЖНО. Так
// enqueue решает «в полёте?» атомарно с решением по контакту.

/// Занят ли cid работой подключения (в очереди или в полёте).
pub fn connInflight(app: *App, cid: i64) bool {
    app.connq_mu.lockUncancelable(app.io);
    defer app.connq_mu.unlock(app.io);
    return app.conn_inflight.contains(cid);
}

/// Занять single-flight слот на контакт напрямую (autodial/linker/CONNECT,
/// работа БЕЗ очереди): занят — error.Busy (не дублируем dial).
pub fn connFlightBegin(app: *App, cid: i64) error{Busy}!void {
    app.connq_mu.lockUncancelable(app.io);
    defer app.connq_mu.unlock(app.io);
    if (app.conn_inflight.contains(cid)) return error.Busy;
    app.conn_inflight.put(app.alloc, cid, {}) catch return error.Busy;
}

/// Освободить прямой слот + прокачать очередь (мог освободиться активный).
pub fn connFlightEnd(app: *App, cid: i64) void {
    app.connq_mu.lockUncancelable(app.io);
    defer app.connq_mu.unlock(app.io);
    _ = app.conn_inflight.remove(cid);
    connPumpLocked(app);
}

/// Поставить работу подключения в очередь. error.Busy — уже в полёте или
/// очередь переполнена (cap conn_queue_cap: конечный бюджет, без unbounded).
pub fn connEnqueue(app: *App, work: app_mod.ConnWork) error{Busy}!void {
    app.connq_mu.lockUncancelable(app.io);
    defer app.connq_mu.unlock(app.io);
    if (app.conn_inflight.contains(work.cid)) return error.Busy;
    if (app.conn_work.items.len >= app_mod.conn_queue_cap) return error.Busy;
    app.conn_work.append(app.alloc, work) catch return error.Busy;
    app.conn_inflight.put(app.alloc, work.cid, {}) catch {
        _ = app.conn_work.pop();
        return error.Busy;
    };
    connPumpLocked(app);
}

/// Спавн работников на очередь, пока есть слоты (conn_active_cap).
/// ВЫЗЫВАТЬ ПОД connq_mu. Сетевого I/O здесь нет — только spawn.
pub fn connPumpLocked(app: *App) void {
    while (app.conn_active < app_mod.conn_active_cap and app.conn_work.items.len > 0) {
        const work = app.conn_work.orderedRemove(0);
        app.conn_active += 1;
        const th = std.Thread.spawn(.{}, connWorker, .{ app, work }) catch {
            app.conn_active -= 1;
            // вернуть в голову; OOM на вставке — работа теряется (слот
            // и inflight сняты ниже), состояние остаётся по факту
            app.conn_work.insert(app.alloc, 0, work) catch {
                _ = app.conn_inflight.remove(work.cid);
            };
            break;
        };
        th.detach();
    }
}

/// Работник одной попытки подключения: dial → рукопожатие → JOIN — вся
/// сеть БЕЗ app.mu (спин-лок сетевой I/O держать нельзя). Финальный
/// провал — FAILED с классификацией; секрет релея затирается.
pub fn connWorker(app: *App, work: app_mod.ConnWork) void {
    var w = work;
    defer {
        if (w.relay_secret) |*s| std.crypto.secureZero(u8, s);
        app.connq_mu.lockUncancelable(app.io);
        app.conn_active -= 1;
        _ = app.conn_inflight.remove(w.cid);
        connPumpLocked(app);
        app.connq_mu.unlock(app.io);
    }
    // стадия dialing + поколение; отмена (удалён/заблокирован) — выход
    var gen: u32 = 0;
    {
        app.lock();
        defer app.unlock();
        const idx = app.eng.findIndex(w.cid) orelse return;
        const c = &app.eng.contacts.items[idx];
        if (c.deleted) {
            events.connSetLocked(app, w.cid, .failed, .canceled, null);
            return;
        }
        if (c.blocked) {
            events.connSetLocked(app, w.cid, .failed, .canceled, null);
            return;
        }
        gen = events.connBeginAttemptLocked(app, w.cid);
    }
    var err: ?anyerror = null;
    if (w.hybrid and w.relay_secret != null) {
        // гибрид (i3): прямой адрес с таймаутом dial; отказ ТРАНСПОРТА
        // фазы dial — relay-fallback. Отказ после dial — без fallback.
        dial.establishToRelay(app, w.addr(), .{ .cid = w.cid, .gen = gen, .dial_timeout_ms = app_mod.direct_dial_timeout_ms }) catch |e| {
            if (isDialPhaseError(e)) {
                // fallback: marker-спаривание в релее (блокируется до пира)
                dial.establishToRelay(app, w.relayAddr(), .{ .cid = w.cid, .gen = gen, .relay_secret = w.relay_secret }) catch |e2| {
                    err = e2;
                };
            } else {
                err = e;
            }
        };
    } else {
        dial.establishToRelay(app, w.addr(), .{ .cid = w.cid, .gen = gen, .relay_secret = w.relay_secret }) catch |e| {
            err = e;
        };
    }
    // relay-маршрут: держать присутствие marker-ом (реконнекты без кода)
    if (w.relay_secret != null and !app.no_network) {
        app.lock();
        defer app.unlock();
        if (app.eng.findIndex(w.cid)) |idx| {
            if (!app.eng.contacts.items[idx].deleted and !app.eng.contacts.items[idx].blocked) {
                presence.startRelayPresenceLocked(app, w.cid, w.relayAddr());
            }
        }
    }
    if (err) |e| {
        app.lock();
        defer app.unlock();
        events.connSetLocked(app, w.cid, .failed, connErrOf(e), gen);
    }
}

// --------------------------------------------- dial с дедлайном (неблокирующий)
// Linux — прямые syscall-ы std.os.linux (паттерн sysfd.zig), Darwin —
// libc-extern. После успеха fd возвращается в блокирующий режим: дальше
// сессия работает как после tcp.dial.

pub fn maybeStartPunchLocked(app: *App, cid: i64) void {
    if (app.no_network) return;
    if (!app.cfg.nat_punch) return;
    if (app.punch_runs.contains(cid)) return;
    const route = app.punch_routes.getPtr(cid) orelse return;
    if (route.peer.count == 0) return;
    if (app.punch_runs.put(app.alloc, cid, {})) |_| {
        const th = std.Thread.spawn(.{}, punchRun, .{ app, cid }) catch {
            _ = app.punch_runs.remove(cid);
            return;
        };
        th.detach();
    } else |_| {}
}

/// Снимок задания punch-воркера (копируется ПОД локом одним куском).
pub const PunchJob = struct {
    local_ip: [4]u8,
    local_port: u16,
    peer: envelope.Punch,
    me_initiator: bool,
};

/// Воркер NAT-punch: host-dial (инициатор) + simultaneous open по
/// рефлексивным кандидатам пира из ТОГО ЖЕ локального адреса:порта,
/// что relay-конн (SO_REUSEADDR; NAT переиспользует маппинг — cone NAT).
/// Успех — прямой конн на смену relay-сессии (establish/handleAccepted
/// по роли); неудача (symmetric NAT/фильтр) — relay остаётся, повтор
/// с ритмом punch_retry_period_ms. Выход: путь сменился, конфиг
/// выключен, контакт удалён, демон останавливается.
pub fn punchRun(app: *App, cid: i64) void {
    defer {
        app.lock();
        defer app.unlock();
        _ = app.punch_runs.remove(cid);
    }
    while (app.running) {
        var job: PunchJob = undefined;
        {
            app.lock();
            defer app.unlock();
            if (!app.cfg.nat_punch) return;
            const route = app.punch_routes.get(cid) orelse return; // путь сменился/умер
            if (app.eng.findIndex(cid) == null) return; // контакт удалён
            if (!app.eng.sessions.contains(cid)) return; // relay-сессия умерла
            job = .{
                .local_ip = route.local_ip,
                .local_port = route.local_port,
                .peer = route.peer,
                .me_initiator = routes.punchAmInitiatorLocked(app, cid),
            };
        }
        // 1) host-кандидаты пира (только инициатор): прямой dial в его
        // листенер (LAN); респондер принимает штатным листенером
        if (job.me_initiator) {
            for (0..job.peer.count) |i| {
                if (job.peer.types[i] != envelope.punch_host) continue;
                var ab: [endpoints_mod.host_max + 8]u8 = undefined;
                const ip = job.peer.ips[i];
                const addr = std.fmt.bufPrint(&ab, "{d}.{d}.{d}.{d}:{d}", .{
                    ip[0], ip[1], ip[2], ip[3], job.peer.ports[i],
                }) catch continue;
                const tc = dial.dialDeadline(app, addr, app_mod.punch_host_dial_ms) catch continue;
                adoptPunchedConn(app, cid, tc, .lan_dial);
                return;
            }
        }
        // 2) simultaneous open по рефлексивным кандидатам пира
        var targets: [punch.punch_max_targets]punch.Target = undefined;
        var n_targets: usize = 0;
        for (0..job.peer.count) |i| {
            if (job.peer.types[i] != envelope.punch_reflexive) continue;
            if (n_targets >= targets.len) break;
            targets[n_targets] = .{ .ip = job.peer.ips[i], .port = job.peer.ports[i] };
            n_targets += 1;
        }
        if (n_targets > 0) {
            if (punch.dialSimultaneous(app.alloc, targets[0..n_targets], .{
                .local_ip = job.local_ip,
                .local_port = job.local_port,
            })) |tc| {
                adoptPunchedConn(app, cid, tc, .punched);
                return;
            } else |_| {}
        }
        // окно закрыто без пробития: relay работает, повтор позже
        sysfd.sleepMs(app_mod.punch_retry_period_ms);
    }
}

/// Принять пробитый/прямой конн: поднять сессию по роли (инициатор —
/// establishSessionOnConn, респондер — handleAcceptedConn ждёт m1).
/// Роли как в relayPresenceLoop: пробитый конн симметричен, протокольная
/// роль выбирается правилом bundle. Для LAN host-dial мы всегда
/// инициатор (это мы дозвонились в листенер пира).
pub fn adoptPunchedConn(app: *App, cid: i64, tc: *tcp.TcpConn, kind: app_mod.RouteKind) void {
    {
        app.lock();
        defer app.unlock();
        // контакт мог умереть, пока пробивали
        if (app.eng.findIndex(cid) == null) {
            tc.deinit();
            app.alloc.destroy(tc);
            return;
        }
        app.raw_conns.append(app.alloc, tc) catch {
            tc.deinit();
            app.alloc.destroy(tc);
            return;
        };
    }
    const me_initiator = blk: {
        app.lock();
        defer app.unlock();
        break :blk routes.punchAmInitiatorLocked(app, cid);
    };
    if (kind == .lan_dial or me_initiator) {
        // host-dial: инициатор по определению; punched: инициатор по bundle
        dial.establishSessionOnConn(app, cid, tc, kind) catch {
            // рукопожатие не сошлось: конн закрыт внутри, relay жив
        };
    } else {
        dial.handleAcceptedConn(app, tc, kind);
    }
}
