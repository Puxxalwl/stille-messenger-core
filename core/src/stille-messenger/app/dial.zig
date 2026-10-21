//! Установление соединений: dial с дедлайном, fake-TLS обёртка,
//! handshake (initiator/responder), привязка сессии, JOIN-окно.
const std = @import("std");
const builtin = @import("builtin");
const stille_messenger = @import("stille-messenger");
const session_mod = stille_messenger.core.session;
const interfaces = stille_messenger.core.interfaces;
const handshake = stille_messenger.crypto.handshake;
const tcp = stille_messenger.net.tcp;
const socks5 = stille_messenger.net.socks5;
const relay_mod = stille_messenger.net.relay;
const faketls_mod = stille_messenger.net.faketls;
const sysfd = stille_messenger.net.sysfd;
const obf = stille_messenger.net.obfuscate;
const config_mod = stille_messenger.app.config;
const receive = @import("receive.zig");
const connq = @import("connq.zig");
const endpoints_mod = @import("endpoints.zig");
const invite_mod = @import("invite.zig");
pub const posix = std.posix;
const app_mod = @import("app.zig");
pub const App = app_mod.App;
const events = @import("events.zig");
const routes = @import("routes.zig");
const envelope = stille_messenger.proto.envelope;

/// fcntl-константы (linux и darwin совпадают): F_GETFL=3, F_SETFL=4.
pub const fcntl_getfl: i32 = 3;

pub const fcntl_setfl: i32 = 4;

/// O_NONBLOCK: Linux 0o4000, Darwin 0x4.
pub const o_nonblock: usize = if (builtin.os.tag == .linux) 0o4000 else 0x4;

pub const dial_cabi = struct {
    extern "c" fn fcntl(fd: c_int, cmd: c_int, arg: c_int) c_int;
    extern "c" fn connect(fd: c_int, addr: *const posix.sockaddr, addrlen: posix.socklen_t) c_int;
    extern "c" fn getsockopt(fd: c_int, level: c_int, optname: c_int, optval: [*]u8, optlen: *posix.socklen_t) c_int;
};

/// Переключить неблокирующий режим fd. Ошибка — error.Network.
pub fn setNonblock(fd: posix.socket_t, on: bool) error{Network}!void {
    if (builtin.os.tag == .linux) {
        const fl = std.os.linux.fcntl(fd, fcntl_getfl, 0);
        if (std.os.linux.errno(fl) != .SUCCESS) return error.Network;
        const cur: usize = @intCast(fl);
        const want: usize = if (on) cur | o_nonblock else cur & ~o_nonblock;
        const rc = std.os.linux.fcntl(fd, fcntl_setfl, want);
        if (std.os.linux.errno(rc) != .SUCCESS) return error.Network;
        return;
    }
    const cur = dial_cabi.fcntl(@intCast(fd), fcntl_getfl, 0);
    if (cur < 0) return error.Network;
    const want: c_int = if (on) cur | @as(c_int, @intCast(o_nonblock)) else cur & ~@as(c_int, @intCast(o_nonblock));
    if (dial_cabi.fcntl(@intCast(fd), fcntl_setfl, want) < 0) return error.Network;
}

/// Прямой TCP dial с дедлайном (мс): connect в неблокирующем режиме +
/// poll. Таймаут — error.Timeout; отказ транспорта — error.Network;
/// некорректный адрес — error.BadAddress (классифицируется вызывающим).
/// Возвращает TcpConn с блокирующим fd (аллокатор приложения).
pub fn dialDeadline(app: *App, addr: []const u8, timeout_ms: u32) error{ Network, Timeout, BadAddress, OutOfMemory }!*tcp.TcpConn {
    const colon = std.mem.lastIndexOfScalar(u8, addr, ':') orelse return error.BadAddress;
    const host = addr[0..colon];
    const port = std.fmt.parseInt(u16, addr[colon + 1 ..], 10) catch return error.BadAddress;
    const ip4 = std.Io.net.Ip4Address.parse(host, port) catch return error.BadAddress;
    const sa = sysfd.sockaddrIn(ip4.bytes, port);
    const fd = sysfd.socketTcp() catch return error.Network;
    var failed = false;
    errdefer if (!failed) sysfd.close(fd);
    setNonblock(fd, true) catch {
        failed = true;
        return error.Network;
    };
    // connect: EINPROGRESS — норма для неблокирующего сокета
    if (builtin.os.tag == .linux) {
        const rc = std.os.linux.connect(fd, @ptrCast(&sa), @sizeOf(sysfd.SockaddrIn));
        const e = std.os.linux.errno(rc);
        if (e != .SUCCESS and e != .INPROGRESS) return error.Network;
    } else {
        const rc = dial_cabi.connect(@intCast(fd), @ptrCast(&sa), @sizeOf(sysfd.SockaddrIn));
        if (rc < 0 and posix.errno(rc) != .INPROGRESS) return error.Network;
    }
    var pfd = [1]posix.pollfd{.{ .fd = fd, .events = posix.POLL.OUT | posix.POLL.ERR | posix.POLL.HUP, .revents = 0 }};
    const n = posix.poll(&pfd, @intCast(timeout_ms)) catch return error.Network;
    if (n == 0) return error.Timeout;
    // итог connect: SO_ERROR (0 = успех)
    var so_err: i32 = 0;
    var so_len: posix.socklen_t = @sizeOf(i32);
    if (builtin.os.tag == .linux) {
        const rc = std.os.linux.getsockopt(fd, posix.SOL.SOCKET, posix.SO.ERROR, @ptrCast(&so_err), &so_len);
        if (std.os.linux.errno(rc) != .SUCCESS) return error.Network;
    } else {
        if (dial_cabi.getsockopt(@intCast(fd), posix.SOL.SOCKET, posix.SO.ERROR, @ptrCast(&so_err), &so_len) < 0) return error.Network;
    }
    if (so_err != 0) return error.Network;
    // назад в блокирующий режим — сессия читает как из tcp.dial
    setNonblock(fd, false) catch return error.Network;
    sysfd.setSocketBuffers(fd);
    sysfd.setQuickAck(fd);
    sysfd.setNoDelay(fd);
    const tc = app.alloc.create(tcp.TcpConn) catch return error.OutOfMemory;
    tc.* = .{ .fd = fd };
    sysfd.setKeepalive(fd);
    return tc;
}

// ------------------------------------------- синхронизация устройств (2.4.0)

pub fn wrapConn(ctx: *anyopaque, raw: interfaces.Conn, keys: stille_messenger.crypto.handshake.SessionKeys, alloc: std.mem.Allocator) anyerror!interfaces.Conn {
    const app: *App = @ptrCast(@alignCast(ctx));
    var key: [32]u8 = undefined;
    stille_messenger.crypto.kdf.expand(keys.transcript, "shopot-obf-v3", &key);
    const oc = try alloc.create(obf.ObfConn);
    oc.* = try obf.ObfConn.init(alloc, app.io, raw, &key);
    app.lock();
    defer app.unlock();
    try app.obfs.append(alloc, oc);
    return obf.obfConn(oc);
}

/// Автолистенер: m1 несёт enc_pk звонящего — опознаём контакт и
/// поднимаем responder-сессию establishIdentified. Не-контакты закрываются.
pub fn identifyCb(ctx: *anyopaque, enc_pk: [32]u8) ?session_mod.Session.IdentifyResult {
    const app: *App = @ptrCast(@alignCast(ctx));
    for (app.eng.contacts.items) |c| {
        if (std.mem.eql(u8, c.bundle[0..32], &enc_pk)) {
            // удалённый чат мёртв: incoming от него — как от незнакомца
            if (c.deleted) return null;
            // enc_pk нужен для сверки статики в m3 (bundle = enc_pk || sign_pk)
            return .{ .enc_pk = c.bundle[0..32].*, .sign_pk = c.bundle[32..64].* };
        }
    }
    return null;
}

pub fn autoAcceptLoop(app: *App, listener: *tcp.Listener) void {
    while (app.running) {
        const tc = listener.accept(app.alloc) catch break;
        {
            app.lock();
            defer app.unlock();
            app.raw_conns.append(app.alloc, tc) catch {
                tc.deinit();
                continue;
            };
        }
        handleAcceptedConn(app, tc, .direct);
    }
}

/// Обработка входящего коннекта (TCP-accept ИЛИ спаренный релей-коннект):
/// fake-TLS обёртка -> m1 -> опознание контакта / pending-join по инвайту.
pub fn handleAcceptedConn(app: *App, tc: *tcp.TcpConn, route: app_mod.RouteKind) void {
    // весь провод завёрнут в fake-TLS: обёртку ставим ДО чтения m1,
    // кадр m1 [len u16][64] приходит внутри записей application_data
    const raw = faketlsServer(app, tc) catch {
        tc.deinit();
        return;
    };
    var hdr: [2]u8 = undefined;
    raw.readAll(&hdr) catch {
        tc.deinit();
        return;
    };
    // длина m1 задаёт crypto/handshake.zig (гибрид X25519+ML-KEM-768);
    // чужая/старая версия ядра не сходится в длине кадра — закрываем
    const m1_len = std.mem.readInt(u16, &hdr, .little);
    if (m1_len != stille_messenger.crypto.handshake.m1_len) {
        tc.deinit();
        return;
    }
    var m1: [stille_messenger.crypto.handshake.m1_len]u8 = undefined;
    raw.readAll(&m1) catch {
        tc.deinit();
        return;
    };
    // какой это контакт — узнаем из enc_pk в m1
    var found_cid: i64 = -1;
    {
        app.lock();
        defer app.unlock();
        for (app.eng.contacts.items, 0..) |c, i| {
            if (std.mem.eql(u8, c.bundle[0..32], m1[32..64])) {
                found_cid = @intCast(i + 1);
                break;
            }
        }
    }
    if (found_cid < 0) {
        // держатель инвайт-кода: поднимаем pending-сессию без опознания
        app.lock();
        const has_invite = blk: {
            for (&app.invites) |*reg| {
                if (!reg.used and reg.created_ms != 0) break :blk true;
            }
            break :blk false;
        };
        const pending_slot = has_invite and app.pending_sessions < app_mod.pending_session_cap;
        if (pending_slot) app.pending_sessions += 1;
        app.unlock();
        if (pending_slot) {
            var eph2: [32]u8 = undefined;
            app.io.random(&eph2);
            const sc = app.alloc.create(app_mod.SessCtx) catch {
                tc.deinit();
                return;
            };
            sc.* = .{
                .app = app,
                .cid = -1,
                .s = null,
                .pending_counted = true,
                .relay_tc = if (route == .relay) tc else null,
                .punched = route == .punched,
                .lan_dial = route == .lan_dial,
            };
            const sp = session_mod.Session.establishPending(
                app.alloc,
                raw,
                &m1,
                app.id,
                eph2,
                app,
                wrapConn,
                .{ .ctx = sc, .onEnvelope = app.session_env_in, .onClosed = app.session_on_closed },
                app.io,
            ) catch {
                app.alloc.destroy(sc);
                tc.deinit();
                return;
            };
            sc.s = sp;
            // окно 3 с: нет валидного JOIN — закрыть
            const tt = std.Thread.spawn(.{}, receive.joinTimeoutWatch, .{sc}) catch {
                sp.close();
                app.alloc.destroy(sc);
                tc.deinit();
                return;
            };
            tt.detach();
        } else {
            tc.deinit();
        }
        return;
    }
    // 2.10.0: прямой входящий конн — выучить адрес пира (v6/v4) для
    // прямого автодозвона; relay-конн исключён (remote = релей)
    if (route != .relay) routes.learnPeerAddr(app, tc, found_cid);
    var eph: [32]u8 = undefined;
    app.io.random(&eph);
    const sc = app.alloc.create(app_mod.SessCtx) catch {
        tc.deinit();
        return;
    };
    sc.* = .{
        .app = app,
        .cid = found_cid,
        .relay_tc = if (route == .relay) tc else null,
        .punched = route == .punched,
        .lan_dial = route == .lan_dial,
    };
    const s = session_mod.Session.establishIdentified(
        app.alloc,
        raw,
        &m1,
        app.id,
        eph,
        identifyCb,
        app,
        app,
        wrapConn,
        .{ .ctx = sc, .onEnvelope = app.session_env_in, .onClosed = app.session_on_closed },
        app.io,
    ) catch {
        app.alloc.destroy(sc);
        tc.deinit();
        return;
    } orelse {
        app.alloc.destroy(sc);
        tc.deinit();
        return;
    };
    app.session_bind(app, found_cid, s, sc) catch {};
}

/// Обернуть TCP-коннект в fake-TLS (server-роль, accept-сторона).
/// use_fake_tls = false: сырой TCP — обфускация и AEAD остаются, но
/// провод больше не похож на TLS (сеть без TLS-подобного трафика).
/// ОБЕ стороны обязаны совпадать по настройке, иначе рукопожатие
/// не сойдётся (старые записи fake-TLS читаются как мусор m1).
pub fn faketlsServer(app: *App, tc: *tcp.TcpConn) !interfaces.Conn {
    {
        app.lock();
        defer app.unlock();
        if (!app.cfg.use_fake_tls) return tc.conn();
    }
    const ft = stille_messenger.net.faketls.wrap(app.alloc, app.io, tc.conn(), .server) catch |e| {
        return e;
    };
    {
        app.lock();
        defer app.unlock();
        app.ftlss.append(app.alloc, ft.ftls) catch {
            ft.ftls.deinit();
            app.alloc.destroy(ft.ftls);
            return error.OutOfMemory;
        };
    }
    return ft.conn;
}

/// Опции установления соединения (establishToRelay).
pub const EstablishOpts = struct {
    cid: i64,
    role: session_mod.HandshakeRole = .initiator,
    /// secret релея: адрес — релей, подключение через marker-спаривание
    /// (пир не видит наш IP).
    relay_secret: ?[16]u8 = null,
    /// Поколение попытки для stage-меток (null — системный вызов без
    /// метки: автодозвон/linker ставят её через connBeginAttemptLocked).
    gen: ?u32 = null,
    /// Таймаут прямого dial в мс (0 — блокирующий dial без дедлайна;
    /// гибрид-инвайты i3 ставят окно direct_dial_timeout_ms).
    dial_timeout_ms: u32 = 0,
};

/// establishTo с опциональным релеем: secret != null — адрес это релей,
/// подключение через marker-спаривание (пир не видит наш IP).
/// Прямые dial при включённом use_tor_mask идут через Tor SOCKS5
/// (релей-подключения Tor не используют: релей и так скрывает IP).
/// Стадии подключения (handshaking после dial) отмечаются в conn_st.
pub fn establishToRelay(app: *App, addr: []const u8, opts: EstablishOpts) !void {
    // конфиг читаем под локом (SET_CONFIG меняет на живом демоне)
    var tor_buf: [config_mod.addr_max]u8 = undefined;
    var tor_len: usize = 0;
    if (opts.relay_secret == null and opts.dial_timeout_ms == 0) {
        app.lock();
        defer app.unlock();
        if (app.cfg.use_tor_mask) {
            const ta = app.cfg.torAddr();
            if (ta.len == 0) return error.NoTor;
            @memcpy(tor_buf[0..ta.len], ta);
            tor_len = ta.len;
        }
    }
    var relay_refl = relay_mod.Reflexive{ .ip = .{ 0, 0, 0, 0 }, .port = 0 };
    const tc = if (opts.relay_secret) |sec|
        relay_mod.dialEcho(app.alloc, addr, sec, &relay_refl) catch return error.NoRelay
    else if (opts.dial_timeout_ms > 0)
        try dialDeadline(app, addr, opts.dial_timeout_ms)
    else if (tor_len > 0)
        socks5.dial(app.alloc, tor_buf[0..tor_len], addr) catch return error.NoTor
    else
        // прямой dial без явного окна — ВСЁ РАВНО с дедлайном: мёртвый
        // адрес (файрвол дропает SYN) не блокирует поток автодозвона
        // минутами (блокирующий connect висел бы до TCP-таймаута ядра)
        try dialDeadline(app, addr, app_mod.direct_dial_timeout_ms);
    {
        app.lock();
        defer app.unlock();
        try app.raw_conns.append(app.alloc, tc);
        if (opts.relay_secret != null) routes.rememberRelayEchoLocked(app, tc, relay_refl);
        // транспорт поднят: стадия handshaking (метка поколения попытки)
        if (opts.gen) |g| events.connSetLocked(app, opts.cid, .handshaking, .none, g);
    }
    if (opts.role != .initiator) {
        // responder через релей: ждём m1 как accept
        handleAcceptedConn(app, tc, if (opts.relay_secret != null) .relay else .direct);
        return;
    }
    try establishSessionOnConn(app, opts.cid, tc, if (opts.relay_secret != null) .relay else .direct);
}

/// Поднять сессию ИНИЦИАТОРОМ на уже подключённом конне (relay-присутствие
/// и establishToRelay): fake-TLS client (настраивается), рукопожатие, bind.
pub fn establishSessionOnConn(app: *App, cid: i64, tc: *tcp.TcpConn, route: app_mod.RouteKind) !void {
    const idx: usize = @intCast(cid - 1);
    if (idx >= app.eng.contacts.items.len) return error.NoContact;
    const bundle = app.eng.contacts.items[idx].bundle;
    var eph: [32]u8 = undefined;
    app.io.random(&eph);
    const sc = try app.alloc.create(app_mod.SessCtx);
    sc.* = .{
        .app = app,
        .cid = cid,
        .relay_tc = if (route == .relay) tc else null,
        .punched = route == .punched,
        .lan_dial = route == .lan_dial,
    };
    // транспортная маскировка под TLS (dialer = client-роль fake-TLS);
    // выключена — сырой TCP поверх tc (обфускация и AEAD остаются)
    var fake_tls: bool = false;
    {
        app.lock();
        defer app.unlock();
        fake_tls = app.cfg.use_fake_tls;
    }
    var transport: interfaces.Conn = undefined;
    if (fake_tls) {
        const ft = stille_messenger.net.faketls.wrap(app.alloc, app.io, tc.conn(), .client) catch |e| {
            app.alloc.destroy(sc);
            return e;
        };
        {
            app.lock();
            defer app.unlock();
            app.ftlss.append(app.alloc, ft.ftls) catch {
                ft.ftls.deinit();
                app.alloc.destroy(ft.ftls);
                app.alloc.destroy(sc);
                return error.OutOfMemory;
            };
        }
        transport = ft.conn;
    } else {
        transport = tc.conn();
    }
    const s = session_mod.Session.establish(
        app.alloc,
        transport,
        .initiator,
        app.id,
        bundle,
        eph,
        app,
        wrapConn,
        .{ .ctx = sc, .onEnvelope = app.session_env_in, .onClosed = app.session_on_closed },
        app.io,
    ) catch |e| {
        app.alloc.destroy(sc);
        return e;
    };
    // держатель инвайта: JOIN — ПЕРВЫМ конвертом, до bind/PROFILE:
    // пир-сторона в pending-режиме закрывает соединение на любом конверте,
    // кроме JOIN. До PROFILE-эха контакт НЕ считается подтверждённым.
    const join_sent = sendJoinIfDue(app, cid, s);
    if (join_sent) {
        // окно ожидания PROFILE-эха (подтверждение добавления): бинд
        // отметит JOINING; эхо/таймаут переведут в ONLINE
        app.lock();
        defer app.unlock();
        const deadline = app.nowMs() + @as(i64, @intCast(app_mod.join_echo_timeout_ms));
        app.conn_await.put(app.alloc, cid, deadline) catch {};
    }
    try app.session_bind(app, cid, s, sc);
    if (join_sent) {
        const th = std.Thread.spawn(.{}, joinEchoWatch, .{ app, cid }) catch null;
        if (th) |t| t.detach();
    }
}

/// Отправка JOIN по join_map (после установления сессии). true — JOIN
/// отправлен (данные погашены в join_map, ждём PROFILE-эхо). Отказ
/// отправки НЕ гасит данные: следующая попытка подключения отправит JOIN
/// заново (секрет одноразовый только на стороне ПРИГЛАШАЮЩЕГО).
pub fn sendJoinIfDue(app: *App, cid: i64, s: *session_mod.Session) bool {
    var ji: app_mod.JoinInfo = undefined;
    var bundle: [64]u8 = undefined;
    var transcript: [32]u8 = undefined;
    app.lock();
    const stored = app.join_map.get(cid) orelse {
        app.unlock();
        return false;
    };
    ji = stored;
    bundle = app.id.bundle();
    transcript = s.keys.transcript;
    app.unlock();

    var sig: [64]u8 = undefined;
    app.id.sign(&transcript, &sig) catch {
        std.crypto.secureZero(u8, &ji.secret);
        return false;
    };
    var mac: [32]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha256.create(&mac, &transcript, &ji.secret);
    const j = envelope.Join{
        .bundle = bundle,
        .name = ji.name(),
        .sig = sig,
        .hmac = mac,
    };
    s.sendEnvelope(.{ .join = j }) catch {
        // отправка не удалась: JOIN-данные остаются в join_map —
        // повторная попытка подключения отправит JOIN заново
        std.crypto.secureZero(u8, &ji.secret);
        return false;
    };
    app.lock();
    if (app.join_map.getPtr(cid)) |pending| {
        // Удаляем только ту же заявку; повторный ACCEPT с новым ключом
        // не должен быть погашен старой отправкой.
        if (std.crypto.timing_safe.eql([invite_mod.secret_len]u8, pending.secret, ji.secret)) {
            std.crypto.secureZero(u8, &pending.secret);
            _ = app.join_map.remove(cid);
        }
    }
    app.unlock();
    std.crypto.secureZero(u8, &ji.secret);
    return true;
}

/// Окно PROFILE-эха после JOIN истекло: сессия аутентифицирована —
/// ONLINE (код join_timeout фиксируется как диагностика; PROFILE —
/// наблюдаемый признак, НЕ криптографическая квитанция JOIN).
pub fn joinEchoWatch(app: *App, cid: i64) void {
    sysfd.sleepMs(app_mod.join_echo_timeout_ms);
    app.lock();
    defer app.unlock();
    if (app.conn_await.remove(cid)) {
        if (app.eng.sessions.get(cid) != null) {
            events.connSetLocked(app, cid, .online, .join_timeout, null);
        } else {
            events.connSetLocked(app, cid, .failed, .join_timeout, null);
        }
    }
}

pub fn acceptLoop(app: *App, listener: *tcp.Listener, cid: i64) void {
    while (app.running) {
        const tc = listener.accept(app.alloc) catch break;
        {
            app.lock();
            defer app.unlock();
            app.raw_conns.append(app.alloc, tc) catch {
                tc.deinit();
                continue;
            };
        }
        const idx: usize = @intCast(cid - 1);
        const bundle = app.eng.contacts.items[idx].bundle;
        var eph: [32]u8 = undefined;
        app.io.random(&eph);
        const sc = app.alloc.create(app_mod.SessCtx) catch {
            tc.deinit();
            continue;
        };
        sc.* = .{ .app = app, .cid = cid };
        const raw = faketlsServer(app, tc) catch {
            app.alloc.destroy(sc);
            tc.deinit();
            continue;
        };
        const s = session_mod.Session.establish(
            app.alloc,
            raw,
            .responder,
            app.id,
            bundle,
            eph,
            app,
            wrapConn,
            .{ .ctx = sc, .onEnvelope = app.session_env_in, .onClosed = app.session_on_closed },
            app.io,
        ) catch {
            app.alloc.destroy(sc);
            continue;
        };
        app.session_bind(app, cid, s, sc) catch {};
    }
}
