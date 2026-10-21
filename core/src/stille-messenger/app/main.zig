//! Точка входа демона: CLI (init/relay/serve), сборка App, запуск
//! подсистем, UDS-апи. Единственный файл, знающий все модули.
//!
//! Следующие ~50 строк — pub-фасад: алиасы модулей app-слоя. Они
//! держат main.zig единственным корнем композиции (его импортирует
//! модуль app-main тестов) и дают остальному коду дерева единообразный
//! доступ к соседям. Каждый алиас — ре-экспорт модуля; документация
//! модулей — в самих файлах.
pub const std = @import("std");
pub const builtin = @import("builtin");
pub const stille_messenger = @import("stille-messenger");
pub const identity = stille_messenger.crypto.identity;
pub const engine_mod = stille_messenger.core.engine;
pub const session_mod = stille_messenger.core.session;
pub const envelope = stille_messenger.proto.envelope;
pub const hb = stille_messenger.net.heartbeat;
pub const obf = stille_messenger.net.obfuscate;
pub const tcp = stille_messenger.net.tcp;
pub const store_mod = stille_messenger.store.log;
pub const interfaces = stille_messenger.core.interfaces;
pub const invite_mod = @import("invite.zig");
pub const endpoints_mod = @import("endpoints.zig");
pub const discover_mod = @import("discover.zig");
pub const wake = @import("wake.zig");
pub const audio_mod = @import("audio.zig");
pub const adpcm_mod = @import("adpcm.zig");
pub const api_srv = @import("api_server.zig");
pub const api = @import("api.zig");
pub const recovery_mod = @import("recovery.zig");
pub const recovery_codec = stille_messenger.crypto.recovery;
pub const search_mod = @import("search.zig");
pub const config_mod = stille_messenger.app.config;
pub const sync_mod = stille_messenger.app.sync;
pub const socks5 = stille_messenger.net.socks5;
pub const sysfd = stille_messenger.net.sysfd;
pub const relay_mod = stille_messenger.net.relay;
pub const punch = stille_messenger.net.punch;
pub const upnp_mod = stille_messenger.net.upnp;
pub const posix = std.posix;
pub const app_mod = @import("app.zig");
pub const App = app_mod.App;
pub const paths = @import("paths.zig");
pub const dispatch = @import("dispatch.zig");
pub const presence = @import("presence.zig");
pub const lan = @import("lan.zig");
pub const dial = @import("dial.zig");
pub const receive = @import("receive.zig");
pub const handlers = @import("api_handlers.zig");
pub const invites = @import("invites.zig");
pub const sync_apply = @import("sync_apply.zig");
pub const connq = @import("connq.zig");
pub const routes = @import("routes.zig");
pub const persist = @import("persist.zig");
pub const events = @import("events.zig");
pub const profile_code = @import("profile_code.zig");

test {
    // агрегация тестов файлов app-слоя: файл обязан принадлежать одному
    // модулю, поэтому тесты app-листьев собирает корень дерева демона
    _ = @import("recovery.zig");
    _ = @import("invite.zig");
    _ = @import("endpoints.zig");
    _ = @import("wake.zig");
    _ = @import("discover.zig");
    _ = @import("api.zig");
    _ = @import("adpcm.zig");
    _ = @import("audio.zig");
    _ = @import("search.zig");
}

const usage =
    \\stille-messenger-core — ядро шифрованного мессенджера (std-only Zig).
    \\Клиенты (GUI) подключаются через бинарное UDS-апи
    \\($HOME/.stille-messenger/api.sock). Спецификация — docs/CORE-API.md.
    \\
    \\  init    создать личность (~/.stille-messenger/zig-seed, 0600)
    \\  relay   режим IP-скрывающего релея (для сервера)
    \\  serve   демон: ядро + UDS-апи; без сида — режим восстановления
    \\
;

/// Поднять сетевую часть демона: тикер presence (PING/автодозвон/слив
/// retired), автолистенер 7777-7786 и LAN-поиск. Вызывается на провиженном
/// старте serve и после восстановления профиля. Потоки — best-effort:
/// неудача спавна/бинда не роняет демон (UDS-апи работает, ошибка — в лог).
/// Фоновый UPnP-маппинг (2.10.0): SSDP-поиск шлюза, AddPortMapping
/// listen-порта, GetExternalIPAddress. Успех -> app.upnp_ext (публичный
/// endpoint): отправляется пирам host-кандидатом в PUNCH_CANDIDATES и
/// возвращается GET_REACHABLE_ENDPOINTS. Неудача молчит — релей и
/// NAT-punch остаются. Один проход на старт демона (повторов нет:
/// маппинг роутера живёт пока жива запись; LeaseDuration=0 — вечная).
fn upnpMapThread(app: *App) void {
    // внутренний IP: первый кандидат интерфейсов (RO-чтение, без лока)
    var ips: [endpoints_mod.max_endpoints][4]u8 = undefined;
    const n = endpoints_mod.enumerateLocalV4(&ips) catch 0;
    if (n == 0) return;
    const internal_port = blk: {
        app.lock();
        defer app.unlock();
        break :blk app.listen_port;
    };
    if (internal_port == 0) return;
    const loc = upnp_mod.ssdpDiscover(app.alloc) catch return orelse return;
    defer app.alloc.free(loc);
    const m = upnp_mod.requestMapping(app.alloc, loc, ips[0], internal_port, internal_port, "stille-messenger") catch return orelse return;
    app.lock();
    defer app.unlock();
    app.upnp_ext = m;
    std.debug.print("UPnP: публичный endpoint {d}.{d}.{d}.{d}:{d} (прямые подключения без релея)\n", .{ m.ip[0], m.ip[1], m.ip[2], m.ip[3], m.port });
}

fn startNetworking(app: *App) void {
    const th = std.Thread.spawn(.{}, presence.tickerLoop, .{app}) catch {
        std.debug.print("startNetworking: тикер не поднялся\n", .{});
        return;
    };
    th.detach();

    // автолистенер: любой контакт из списка может подключиться сам
    var lsn: ?tcp.Listener = null;
    var listen_port: u16 = 7777;
    var attempt: u16 = 7777;
    while (attempt < 7787) : (attempt += 1) {
        var pbuf: [24]u8 = undefined;
        const a = std.fmt.bufPrint(&pbuf, "0.0.0.0:{d}", .{attempt}) catch unreachable;
        if (tcp.listen(a)) |l| {
            lsn = l;
            listen_port = attempt;
            break;
        } else |_| {}
    }
    if (lsn) |l| {
        app.listen_port = listen_port;
        // 2.10.0: IPv6-листенер на том же порту (V6ONLY — отдельный fd,
        // v4-путь не меняется). Нет v6 — молча без него.
        var lsn6: ?tcp.Listener = null;
        {
            var pbuf6: [24]u8 = undefined;
            const a6 = std.fmt.bufPrint(&pbuf6, "[::]:{d}", .{listen_port}) catch unreachable;
            if (tcp.listen(a6)) |l6| {
                lsn6 = l6;
            } else |_| {}
        }
        // 2.7.0: слушатель поднят — GET_REACHABLE_ENDPOINTS отдаёт адреса
        app.lock();
        app.listening = true;
        if (lsn6 != null) app.listening6 = true;
        app.unlock();
        // будилка линкера: событийные анонсы из kickConnect (до потоков;
        // второй вызов startNetworking не переоткроет)
        if (app.link_wake == null) {
            if (wake.Waker.init() catch null) |wk| app.link_wake = wk;
        }
        const lp = app.alloc.create(tcp.Listener) catch return;
        lp.* = l;
        const lt = std.Thread.spawn(.{}, dial.autoAcceptLoop, .{ app, lp }) catch return;
        lt.detach();
        if (lsn6) |l6| {
            const lp6 = app.alloc.create(tcp.Listener) catch return;
            lp6.* = l6;
            const lt6 = std.Thread.spawn(.{}, dial.autoAcceptLoop, .{ app, lp6 }) catch return;
            lt6.detach();
        }
        // 2.10.0: UPnP-маппинг порта (один фоновый поток, один проход:
        // SSDP 1.5 с + HTTP/SOAP ~3 с; результат — публичный endpoint)
        if (app.cfg.autodial) {
            const ut = std.Thread.spawn(.{}, upnpMapThread, .{app}) catch null;
            if (ut) |t| t.detach();
        }
        const linker = std.Thread.spawn(.{}, lan.linkerLoop, .{app}) catch return;
        linker.detach();
        if (lsn6 != null) {
            std.debug.print("авто-режим: слушаю 0.0.0.0:{d} + [::]:{d}, LAN-поиск включён\n", .{ listen_port, listen_port });
        } else {
            std.debug.print("авто-режим: слушаю 0.0.0.0:{d}, LAN-поиск включён\n", .{listen_port});
        }
    } else {
        std.debug.print("авто-режим: порты 7777-7786 заняты, LAN-поиск выключен\n", .{});
    }
}

fn badUsage() error{BadUsage} {
    std.debug.print("{s}\n", .{usage});
    return error.BadUsage;
}

/// Обёртки инверсии зависимостей api_server: нетипизированный ctx -> App.
fn apiLock(ctx: *anyopaque) void {
    const app: *App = @ptrCast(@alignCast(ctx));
    app.lock();
}

fn apiUnlock(ctx: *anyopaque) void {
    const app: *App = @ptrCast(@alignCast(ctx));
    app.unlock();
}

fn apiDispatch(ctx: *anyopaque, conn: *api_srv.Conn, req: api.ApiRequest) bool {
    const app: *App = @ptrCast(@alignCast(ctx));
    return dispatch.dispatchApi(app, conn, req);
}

pub fn main(start: std.process.Init) !void {
    const io = start.io;
    const home: []const u8 = start.environ_map.get("HOME") orelse "";
    const argv = start.minimal.args.vector;

    if (argv.len < 2) {
        std.debug.print("{s}\n", .{usage});
        return;
    }
    const cmd: []const u8 = std.mem.span(argv[1]);

    // relay <host:port>: байтовый сплит без состояния stille-messenger (скрытие IP).
    // Запускается на любом сервере: stille-messenger-core relay 0.0.0.0:9000
    if (std.mem.eql(u8, cmd, "relay")) {
        const addr = if (argv.len >= 3) std.mem.span(argv[2]) else return badUsage();
        var listener = tcp.listen(addr) catch {
            std.debug.print("relay: не удалось слушать {s}\n", .{addr});
            return;
        };
        std.debug.print("relay: слушаю {s}, спариваю по marker-у инвайта\n", .{addr});
        var dbg_state = std.heap.DebugAllocator(.{ .thread_safe = true }){};
        const alloc = dbg_state.allocator();
        stille_messenger.net.relay.serve(alloc, &listener, null);
        return;
    }

    if (std.mem.eql(u8, cmd, "init")) {
        var seed: [32]u8 = undefined;
        io.random(&seed);
        try paths.saveSeed(io, home, seed);
        var id = try identity.Identity.fromSeed(seed);
        defer id.deinit();
        var fp_buf: [96]u8 = undefined;
        std.debug.print("identity created, seed saved to ~/.stille-messenger/zig-seed (0600)\nfingerprint: {s}\n", .{try id.fingerprintTo(&fp_buf)});
        return;
    }

    // serve без сида — режим восстановления: эфемерная личность (никуда
    // не сохраняется) ждёт RESTORE_RECOVERY_BACKUP от GUI; остальные
    // команды, требующие личности, отвечают NOT_INITIALIZED. Битый сид
    // (не 32 байта) — фатально, молча создавать новый поверх нельзя.
    var provisioned = true;
    var seed: [32]u8 = undefined;
    if (std.mem.eql(u8, cmd, "serve")) {
        if (paths.loadSeed(io, home)) |loaded| {
            seed = loaded;
        } else |e| switch (e) {
            error.FileNotFound => {
                provisioned = false;
                io.random(&seed);
                std.debug.print("serve: сид не найден — режим восстановления (GUI: RESTORE_RECOVERY_BACKUP)\n", .{});
            },
            else => return e,
        }
    } else {
        // все остальные команды требуют существующей личности
        seed = try paths.loadSeed(io, home);
    }
    var id = try identity.Identity.fromSeed(seed);
    defer id.deinit();

    if (std.mem.eql(u8, cmd, "serve")) {
        // потоки: rx-сессий, тикер presence, accept-loop — аллокатор общий
        var dbg_state = std.heap.DebugAllocator(.{ .thread_safe = true }){};
        const alloc = dbg_state.allocator();

        var eng = engine_mod.Engine.init(alloc, io, id, undefined);
        var log_ptr: ?*store_mod.Log = null;
        if (provisioned) {
            var store_path_buf: [512]u8 = undefined;
            const store_path = try std.fmt.bufPrint(&store_path_buf, "{s}/{s}/zig-log", .{ home, paths.data_dir_name });
            if (store_mod.Log.open(alloc, store_path, &seed)) |l| {
                const lp = try alloc.create(store_mod.Log);
                lp.* = l;
                log_ptr = lp;
            } else |e| {
                std.debug.print("лог не открылся: {s} (продолжаю без хранения)\n", .{@errorName(e)});
            }
        }

        var pcm_buf: [512]u8 = undefined;
        const pcm_dir = try std.fmt.bufPrint(&pcm_buf, "{s}/{s}/pcm", .{ home, paths.data_dir_name });
        std.Io.Dir.createDirAbsolute(io, pcm_dir, .default_dir) catch {};
        var pcm_heap: []const u8 = "";
        if (home.len > 0) {
            pcm_heap = std.fmt.allocPrint(alloc, "{s}/{s}/pcm", .{ home, paths.data_dir_name }) catch "";
        }

        var app = App{
            .session_bind = receive.bindSession,
            .session_env_in = receive.envIn,
            .session_on_closed = receive.onClosed,
            .alloc = alloc,
            .io = io,
            .id = &id,
            .eng = &eng,
            .log = log_ptr,
            .provisioned = provisioned,
            .home_len = @min(home.len, paths.app_home_max),
            .hb = std.AutoHashMap(i64, hb.State).init(alloc),
            .sess_ctx = std.AutoHashMap(i64, *app_mod.SessCtx).init(alloc),
            .call_pcm_dir = if (pcm_heap.len > 0) pcm_heap else null,
        };
        // синхронизация устройств: ключ — HKDF от сида (один сид на все
        // устройства пользователя); переводчик cid→bundle вызывается
        // только под app.mu. При восстановлении ключ пересчитывается
        // от нового сида (applyBackup).
        app.sync = sync_mod.Sync.init(alloc, &seed);
        app.sync.tr_ctx = &app;
        app.sync.tr_fn = sync_apply.syncTranslateBundle;
        @memcpy(app.home_buf[0..app.home_len], home[0..app.home_len]);
        // epoch ревизий контактов: случайно на старте демона (RESYNC при
        // перезапуске клиента/демона не отдаёт старую ревизию как валидную)
        io.random(&app.contacts_epoch);
        eng.ev = receive.engineEvents(&app);

        // профиль грузится и сеть поднимается только на провиженном
        // старте; после восстановления (RESTORE_RECOVERY_BACKUP) их
        // поднимает цикл ожидания ниже
        if (provisioned) {
            persist.loadContacts(&app);
            startNetworking(&app);
        }

        // Единственный интерфейс: бинарное UDS-апи для GUI-клиента.
        // Зависимости (лок/диспетчер) инжектируются: api_server не знает App.
        api_srv.start(.{
            .ctx = &app,
            .dispatch = apiDispatch,
            .lock = apiLock,
            .unlock = apiUnlock,
            .alloc = alloc,
            .io = io,
            .running = &app.running,
        }, &app.cli, home, paths.data_dir_name);
        std.debug.print("serve: демон работает, UDS-апи готово\n", .{});
        var net_started = provisioned;
        while (app.running) {
            sysfd.sleepMs(250);
            if (!net_started) {
                // восстановление довело профиль до готовности: поднять сеть
                app.lock();
                const up = app.provisioned;
                app.unlock();
                if (up) {
                    net_started = true;
                    startNetworking(&app);
                }
            }
        }

        eng.deinit();
        // новая память приложения: кэш истории и закрепления
        for (app.hist.items) |rec| app.alloc.free(rec);
        app.hist.deinit(app.alloc);
        app.hist_idx.deinit(app.alloc);
        var pit = app.pinned_msgs.valueIterator();
        while (pit.next()) |list| list.deinit(app.alloc);
        app.pinned_msgs.deinit(app.alloc);
        // конфигурация/синхронизация: очереди устройств и клиентская БД
        app.sync.deinit();
        for (app.client_recs.items) |rec| app.alloc.free(rec.data);
        app.client_recs.deinit(app.alloc);
        app.client_macs.deinit(app.alloc);
        app.server_runs.deinit(app.alloc);
        // NAT-punch (2.9.0)
        app.relay_echo.deinit(app.alloc);
        app.punch_routes.deinit(app.alloc);
        app.punch_runs.deinit(app.alloc);
        // планировщик подключений (2.7.0): очередь/состояния/ожидания эха
        app.conn_work.deinit(app.alloc);
        app.conn_inflight.deinit(app.alloc);
        app.conn_st.deinit(app.alloc);
        app.conn_await.deinit(app.alloc);
        // будилка цикла обнаружения
        if (app.link_wake) |*wk| wk.deinit();
        var join_it = app.join_map.valueIterator();
        while (join_it.next()) |ji| std.crypto.secureZero(u8, &ji.secret);
        app.join_map.deinit(app.alloc);
        for (&app.invites) |*reg| std.crypto.secureZero(u8, &reg.secret);
        app.hb.deinit();
        app.sess_ctx.deinit();
        return;
    }

    std.debug.print("{s}\n", .{usage});
}
