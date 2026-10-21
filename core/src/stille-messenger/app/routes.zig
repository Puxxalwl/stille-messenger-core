//! Маршруты прямого пути (NAT-punch): обмен кандидатами PUNCH/
//! V6_ADDR, состояние маршрута, рефлексивные адреса релея.
const std = @import("std");
const stille_messenger = @import("stille-messenger");
const envelope = stille_messenger.proto.envelope;
const session_mod = stille_messenger.core.session;
const relay_mod = stille_messenger.net.relay;
const tcp = stille_messenger.net.tcp;
const endpoints_mod = @import("endpoints.zig");
const api = @import("api.zig");
const app_mod = @import("app.zig");
const connq = @import("connq.zig");
const persist = @import("persist.zig");
const sync_apply = @import("sync_apply.zig");
const profile_code = @import("profile_code.zig");
pub const App = app_mod.App;
const events = @import("events.zig");
const api_srv = @import("api_server.zig");
const sysfd = stille_messenger.net.sysfd;
const posix = std.posix;

/// ROUTE_STATE: транспорт сессии сменился (relay -> пробитый прямой
/// путь). ВЫЗЫВАТЬ ПОД app.mu (как все evXxx).
pub fn evRouteState(app: *App, cid: i64, route: api.RouteState) void {
    var w = api.Writer.init(app.alloc);
    defer w.deinit();
    w.putU32(@intCast(cid)) catch return;
    w.putU8(@backingInt(route)) catch return;
    api_srv.fanoutEventLocked(app.cli, .ROUTE_STATE, w.items());
}

/// Сторона-инициатор прямого пути для cid (правило то же, что в
/// relayPresenceLoop: меньший bundle инициирует; устройство-линк —
/// держатель). ВЫЗЫВАТЬСЯ ПОД app.mu.
pub fn punchAmInitiatorLocked(app: *App, cid: i64) bool {
    const idx = app.eng.findIndex(cid) orelse return false;
    const c = &app.eng.contacts.items[idx];
    const my_bundle = app.id.bundle();
    if (std.mem.eql(u8, &c.bundle, &my_bundle))
        return c.dev_role == app_mod.dev_role_holder;
    return std.mem.order(u8, &my_bundle, &c.bundle) == .lt;
}

/// Рассылка своих кандидатов прямого пути пир и запись punch-маршрута.
/// ВЫЗЫВАЕТСЯ ПОД app.mu из bindSessionLocked (relay-сессия только что
/// аутентифицирована — кадр уходит внутри AEAD, подмена невозможна).
pub fn sendPunchCandidatesLocked(
    app: *App,
    cid: i64,
    s: *session_mod.Session,
    sc: *app_mod.SessCtx,
    tc: *tcp.TcpConn,
) void {
    // выключен конфигом или тестовым режимом — маршрута нет, кадра нет
    if (!app.cfg.nat_punch or app.no_network) return;
    // локальный адрес relay-конна (fd жив: сессия поднята на нём)
    const la = sysfd.localAddrIn(tc.fd) orelse return;
    const lp = sysfd.ipPortOf(la);
    // локальные адреса интерфейсов (LAN host-кандидаты) — системные
    // вызовы БЕЗ app.mu недопустимы здесь (бindx под локом в этом
    // файле обычен: flushOutbox/sendProfile пишут транспорт так же);
    // enumerateLocalV4 только читает сокеты-таблицу, аллокаций нет
    var ips: [endpoints_mod.max_endpoints][4]u8 = undefined;
    const n_ips = endpoints_mod.enumerateLocalV4(&ips) catch 0;
    // сборка кадра: reflexive (echo relay, если был) + host-кандидаты
    var p: envelope.Punch = .{
        .count = 0,
        .types = @splat(0),
        .ips = @splat(@splat(0)),
        .ports = @splat(0),
    };
    // 2.10.0: UPnP-endpoint — первый host-кандидат (публичный: пир
    // дозванивается напрямую, NAT уже пробит со стороны роутера)
    var upnp_port: u16 = 0;
    var upnp_ip: [4]u8 = .{ 0, 0, 0, 0 };
    if (app.upnp_ext) |m| {
        if (m.port != 0) {
            upnp_port = m.port;
            upnp_ip = m.ip;
            if (p.count < envelope.max_punch_candidates) {
                p.types[p.count] = envelope.punch_host;
                p.ips[p.count] = m.ip;
                p.ports[p.count] = m.port;
                p.count += 1;
            }
        }
    }
    var reflexive = relay_mod.Reflexive{ .ip = upnp_ip, .port = upnp_port };
    if (app.relay_echo.get(tc)) |refl| {
        if (refl.port != 0) {
            reflexive = refl;
            if (p.count < envelope.max_punch_candidates) {
                p.types[p.count] = envelope.punch_reflexive;
                p.ips[p.count] = refl.ip;
                p.ports[p.count] = refl.port;
                p.count += 1;
            }
        }
    }
    for (ips[0..n_ips]) |ip| {
        if (p.count >= envelope.max_punch_candidates) break;
        p.types[p.count] = envelope.punch_host;
        p.ips[p.count] = ip;
        p.ports[p.count] = app.listen_port;
        p.count += 1;
    }
    if (p.count == 0) return; // нечего объявлять — маршрута тоже нет
    // запись маршрута ДО отправки: ответ пира может прийти мгновенно
    app.punch_routes.put(app.alloc, cid, .{
        .local_ip = lp.ip,
        .local_port = lp.port,
        .reflexive = reflexive,
        .peer = .{ .count = 0, .types = @splat(0), .ips = @splat(@splat(0)), .ports = @splat(0) },
    }) catch return;
    s.sendEnvelope(.{ .punch = p }) catch {};
    _ = sc; // контекст не нужен: маршрут записан по cid
}

/// Вход PUNCH_CANDIDATES от пира (envIn, ПОД app.mu, cid привязан):
/// запомнить кандидаты и запустить пробитие, если всё сходится.
pub fn handlePunchInLocked(app: *App, cid: i64, p: envelope.Punch) void {
    const route = app.punch_routes.getPtr(cid) orelse return; // не relay-путь
    route.peer = p;
    connq.maybeStartPunchLocked(app, cid);
}

/// Запуск punch-воркера (дедуп punch_runs). ВЫЗЫВАЕТСЯ ПОД app.mu;
/// поток сам берёт лок. Условия: конфиг включён, маршрут жив,
/// у пира есть кандидаты.
/// V6_ADDR пиру (2.10.0): глобальные/ULA-адреса + listen-порт. Отправка
/// при бинде relay-сессии — внутри аутентифицированного канала. Системные
/// вызовы enumerateLocalV6 под app.mu — тот же паттерн, что
/// sendPunchCandidatesLocked (read-only сокеты-таблица, аллокаций нет).
pub fn sendV6AddrLocked(app: *App, cid: i64, s: *session_mod.Session) void {
    _ = cid;
    if (app.no_network) return;
    var ips: [endpoints_mod.max_endpoints6][16]u8 = undefined;
    const n = endpoints_mod.enumerateLocalV6(&ips) catch 0;
    if (n == 0) return;
    var v: envelope.V6Addr = .{ .count = 0, .ips = @splat(@splat(0)), .port = app.listen_port };
    for (ips[0..@min(n, envelope.max_v6_addrs)]) |ip| {
        v.ips[v.count] = ip;
        v.count += 1;
    }
    if (v.port == 0) return;
    s.sendEnvelope(.{ .v6addr = v }) catch {};
}

/// Принятый V6_ADDR: записать первый адрес пира как его контакт-адрес
/// ("[v6]:port" — для прямого автодозвона и fast-presence). Вызов под
/// app.mu (rx-поток сессии). Перезапись — только если адрес изменился
/// (saveContactAddr сам сравнивает).
pub fn handleV6AddrInLocked(app: *App, cid: i64, v: envelope.V6Addr) void {
    if (v.count == 0 or v.port == 0) return;
    if (cid < 1 or cid > app.eng.contacts.items.len) return;
    var ipbuf: [64]u8 = undefined;
    const ip6 = tcp.fmtIp6(&ipbuf, v.ips[0]);
    var ab: [80]u8 = undefined;
    const addr = std.fmt.bufPrint(&ab, "[{s}]:{d}", .{ ip6, v.port }) catch return;
    persist.saveContactAddr(app, cid, addr);
}

/// Выучить адрес пира из входящего прямого конна (getpeername): v6 —
/// всегда (глобальный адрес без NAT), v4 — тоже (публичный адрес пира
/// виден нам напрямую). Relay-конны исключены — их remote это релей.
/// Вызов ВНЕ app.mu (syscall), saveContactAddr — под локом внутри.
pub fn learnPeerAddr(app: *App, tc: *tcp.TcpConn, cid: i64) void {
    var sa: posix.sockaddr.storage = std.mem.zeroes(posix.sockaddr.storage);
    var sl: posix.socklen_t = @sizeOf(posix.sockaddr.storage);
    const rc = std.os.linux.getpeername(tc.fd, @ptrCast(&sa), &sl);
    if (std.os.linux.errno(rc) != .SUCCESS) return;
    var ab: [80]u8 = undefined;
    const addr: []const u8 = switch (sa.family) {
        posix.AF.INET6 => blk: {
            const sa6: *const posix.sockaddr.in6 = @ptrCast(@alignCast(&sa));
            // v4-mapped (::ffff:a.b.c.d) — это v4-конн на dual-сокете
            if (std.mem.eql(u8, sa6.addr[0..12], &@as([12]u8, @splat(0))) and sa6.addr[12] == 0xff and sa6.addr[13] == 0xff) {
                const ip4: [4]u8 = sa6.addr[12..16].*;
                break :blk std.fmt.bufPrint(&ab, "{d}.{d}.{d}.{d}:{d}", .{ ip4[0], ip4[1], ip4[2], ip4[3], std.mem.bigToNative(u16, sa6.port) }) catch return;
            }
            var ipbuf: [64]u8 = undefined;
            const ip6 = tcp.fmtIp6(&ipbuf, sa6.addr);
            break :blk std.fmt.bufPrint(&ab, "[{s}]:{d}", .{ ip6, std.mem.bigToNative(u16, sa6.port) }) catch return;
        },
        posix.AF.INET => blk: {
            const sa4: *const posix.sockaddr.in = @ptrCast(@alignCast(&sa));
            const ip4: [4]u8 = @bitCast(sa4.addr);
            break :blk std.fmt.bufPrint(&ab, "{d}.{d}.{d}.{d}:{d}", .{ ip4[0], ip4[1], ip4[2], ip4[3], std.mem.bigToNative(u16, sa4.port) }) catch return;
        },
        else => return,
    };
    app.lock();
    defer app.unlock();
    if (cid < 1 or cid > app.eng.contacts.items.len) return;
    persist.saveContactAddr(app, cid, addr);
}

/// Запомнить рефлексивный адрес relay-конна (NAT-punch). ПОД app.mu;
/// карта ограничена relay_echo_cap (ключи протухают с закрытием коннов,
/// значения 8 байт — очистка целиком безболезненна).
pub fn rememberRelayEchoLocked(app: *App, tc: *tcp.TcpConn, refl: relay_mod.Reflexive) void {
    if (refl.port == 0) return; // relay без echo (старый): NAT-punch недоступен
    if (app.relay_echo.count() >= app_mod.relay_echo_cap) app.relay_echo.clearRetainingCapacity();
    app.relay_echo.put(app.alloc, tc, refl) catch {};
}
