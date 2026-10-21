//! Присутствие: тикер heartbeat, relay-присутствие marker-ом,
//! server_mode-присутствие, профильно-кодовый relay-цикл.
const std = @import("std");
const stille_messenger = @import("stille-messenger");
const session_mod = stille_messenger.core.session;
const relay_mod = stille_messenger.net.relay;
const tcp = stille_messenger.net.tcp;
const app_mod = @import("app.zig");
const connq = @import("connq.zig");
const routes = @import("routes.zig");
const envelope = stille_messenger.proto.envelope;
pub const App = app_mod.App;
const events = @import("events.zig");
const dial = @import("dial.zig");
const profile_code = @import("profile_code.zig");
const sysfd = stille_messenger.net.sysfd;
const config_mod = stille_messenger.app.config;
const invite_mod = @import("invite.zig");

// ------------------------------------------------------- heartbeat ticker
/// Применить новую конфигурацию к живому демону. ВЫЗЫВАЕТСЯ ПОД app.mu:
/// эффекты, зависящие от полей (server_mode поднимает присутствие
/// контактов на своём сервере; выключение гасит потоки на следующей
/// итерации). Транспортные флаги (use_fake_tls/use_tor_mask) действуют
/// на НОВЫЕ подключения — установленные сессии живут как поднялись.
/// Живёт в presence (не в dispatch): эффекты — присутствие и потоки.
pub fn applyConfigLocked(app: *App, new: config_mod.Config) void {
    app.cfg = new;
    if (new.server_mode) startServerPresenceForAllLocked(app);
}

pub fn tickerLoop(app: *App) void {
    while (app.running) {
        sysfd.sleepMs(250);
        {
            app.lock();
            defer app.unlock();
            var it = app.hb.iterator();
            const now = app.nowMs();
            while (it.next()) |e| {
                const cid = e.key_ptr.*;
                const st = e.value_ptr;
                const s = app.eng.sessions.get(cid) orelse continue;
                switch (st.tick(now)) {
                    .none => {},
                    .send_ping => |p| s.sendEnvelope(.{ .presence_ping = .{
                        .seq = p.seq,
                        .ts_ms = @intCast(p.ts_ms),
                    } }) catch {},
                    .mark_offline => {
                        app.eng.contacts.items[@intCast(cid - 1)].online = false;
                        if (app.eng.ev.onPresence) |cb|
                            cb(app.eng.ev.ctx, &app.eng.contacts.items[@intCast(cid - 1)], false, now);
                        // молчащая (half-open) сессия мертва: снять с карты —
                        // автодозвон/linker поднимут соединение заново; сам
                        // указатель уйдёт в retired и будет закрыт drain-ом
                        app.eng.retireSession(cid, s);
                        // и не ждать backoff: немедленная попытка дозвона
                        connq.kickConnectLocked(app, cid);
                    },
                }
            }
        }
        // retired-слив: join rx-потоков и destroy — строго ВНЕ app.mu
        drainRetired(app);
    }
}

/// Закрыть и освободить снятые с карты сессии. Вызывается из тикера БЕЗ
/// app.mu: close() ждёт rx-поток, чей выход берёт лок (join под спин-локом
/// — deadlock). Сессии в retired никому не видны — конкурентных_close нет.
pub fn drainRetired(app: *App) void {
    var dead: []*session_mod.Session = undefined;
    {
        app.lock();
        defer app.unlock();
        if (app.eng.retired.items.len == 0) return;
        dead = app.eng.retired.toOwnedSlice(app.alloc) catch return;
    }
    for (dead) |s| {
        s.close();
        app.eng.alloc.destroy(s);
    }
    app.alloc.free(dead);
}

/// Запомнить relay-адрес контакта и поднять presence-поток (один на
/// контакт). ВЫЗЫВАЕТСЯ ПОД app.mu; поток сам ждёт снятия лока.
pub fn startRelayPresenceLocked(app: *App, cid: i64, addr: []const u8) void {
    if (addr.len == 0) return;
    if (app.contact_relays.getPtr(cid)) |old| {
        if (!std.mem.eql(u8, old.*, addr)) {
            const dup = app.alloc.dupe(u8, addr) catch return;
            app.alloc.free(old.*);
            old.* = dup;
        }
    } else {
        const dup = app.alloc.dupe(u8, addr) catch return;
        app.contact_relays.put(app.alloc, cid, dup) catch {
            app.alloc.free(dup);
            return;
        };
    }
    // тесты: relay-адрес в карте есть (восстановление маршрута
    // проверяемо), но сетевой поток не поднимаем — переживёт тест
    if (app.no_network) return;
    if (app.presence_runs.contains(cid)) return;
    app.presence_runs.put(app.alloc, cid, {}) catch return;
    const th = std.Thread.spawn(.{}, relayPresenceLoop, .{ app, cid, false }) catch {
        _ = app.presence_runs.remove(cid);
        return;
    };
    th.detach();
}

/// Присутствие контакта на СВОЁМ сервере (server_mode): как
/// startRelayPresenceLocked, но адрес — cfg.server_addr (self-hosted
/// релей пользователя), а поток живёт, пока включён server_mode.
/// ВЫЗЫВАЕТСЯ ПОД app.mu; поток сам ждёт снятия лока.
pub fn startServerPresenceLocked(app: *App, cid: i64) void {
    if (!app.cfg.server_mode) return;
    if (app.cfg.serverAddr().len == 0) return;
    // тесты: сетевые потоки не поднимаем (профиль загружен, сети нет)
    if (app.no_network) return;
    if (app.presence_runs.contains(cid)) return; // персональный релей уже держит слот
    if (app.server_runs.contains(cid)) return;
    app.server_runs.put(app.alloc, cid, {}) catch return;
    const th = std.Thread.spawn(.{}, relayPresenceLoop, .{ app, cid, true }) catch {
        _ = app.server_runs.remove(cid);
        return;
    };
    th.detach();
}

/// server_mode только что включён: поднять присутствие всем живым контактам.
/// ВЫЗЫВАЕТСЯ ПОД app.mu.
pub fn startServerPresenceForAllLocked(app: *App) void {
    if (!app.cfg.server_mode) return;
    for (app.eng.contacts.items, 0..) |*c, i| {
        if (c.deleted or c.blocked) continue;
        startServerPresenceLocked(app, @intCast(i + 1));
    }
}

// ---------------------------------------------------------- NAT-punch (2.9.0)

/// держим регистрацию слота marker-ом из ДОЛГОСРОЧНОГО контакт-секрета
/// (identity.pairSecret -> relay.presenceMarker): пир появляется в релее —
/// спариваемся и поднимаем сессию БЕЗ нового инвайта. Инициатор
/// рукопожатия — сторона с меньшим bundle (детерминизм: обе стороны
/// вычисляют роль одинаково); устройство-линк (bundle равны) — всегда
/// держатель кода. from_server: присутствие на СВОЁМ сервере
/// (server_mode) — адрес перечитывается из конфигурации каждую
/// итерацию, выключение режима гасит поток. Сессия уже жива —
/// регистрация не нужна, ждём её смерти (прямой путь и присутствие
/// не конфликтуют).
pub fn relayPresenceLoop(app: *App, cid: i64, from_server: bool) void {
    defer {
        app.lock();
        defer app.unlock();
        _ = app.presence_runs.remove(cid);
        _ = app.server_runs.remove(cid);
    }
    var marker: [32]u8 = undefined;
    var me_initiator: bool = false;
    var addr_copy: []u8 = &.{};
    {
        app.lock();
        defer app.unlock();
        const idx = app.eng.findIndex(cid) orelse return;
        const c = &app.eng.contacts.items[idx];
        const sec = app.id.pairSecret(c.bundle) catch return;
        marker = stille_messenger.net.relay.presenceMarker(sec);
        const my_bundle = app.id.bundle();
        if (std.mem.eql(u8, &c.bundle, &my_bundle)) {
            // устройство-близнец: bundle равны, порядок их не разведёт —
            // инициирует держатель линка (как в join-правиле инвайтов)
            me_initiator = c.dev_role == app_mod.dev_role_holder;
        } else {
            me_initiator = std.mem.order(u8, &my_bundle, &c.bundle) == .lt;
        }
        if (!from_server) {
            const stored = app.contact_relays.get(cid) orelse return;
            addr_copy = app.alloc.dupe(u8, stored) catch return;
        }
    }
    defer {
        if (!from_server) app.alloc.free(addr_copy);
    }
    while (app.running) {
        // адрес dial: персональный релей (фиксирован) или свой сервер
        // (перечитывается — SET_CONFIG может сменить адрес/выключить режим)
        var sb: [config_mod.addr_max]u8 = undefined;
        var sb_len: usize = 0;
        {
            app.lock();
            defer app.unlock();
            const idx = app.eng.findIndex(cid) orelse return; // контакт удалён
            if (app.eng.contacts.items[idx].blocked) return;
            if (app.eng.contacts.items[idx].deleted) return;
            if (from_server) {
                if (!app.cfg.server_mode or !app.server_runs.contains(cid)) return;
                const sa = app.cfg.serverAddr();
                if (sa.len == 0 or sa.len > sb.len) return;
                @memcpy(sb[0..sa.len], sa);
                sb_len = sa.len;
            }
            if (app.eng.sessions.contains(cid)) {
                // живая сессия: присутствие не нужно
                sysfd.sleepMs(1000);
                continue;
            }
        }
        const dial_addr: []const u8 = if (from_server) sb[0..sb_len] else addr_copy;
        // dial блокируется в релее до прихода пира (наш marker — слот);
        // echo-запрос заодно: relay вернёт наш рефлексивный адрес
        // (NAT-punch, 2.9.0)
        var refl = relay_mod.Reflexive{ .ip = .{ 0, 0, 0, 0 }, .port = 0 };
        const tc = relay_mod.dialMarkerEcho(app.alloc, dial_addr, marker, &refl) catch {
            sysfd.sleepMs(2000);
            continue;
        };
        {
            app.lock();
            defer app.unlock();
            app.raw_conns.append(app.alloc, tc) catch {
                tc.deinit();
                sysfd.sleepMs(2000);
                continue;
            };
            routes.rememberRelayEchoLocked(app, tc, refl);
        }
        if (me_initiator) {
            dial.establishSessionOnConn(app, cid, tc, .relay) catch {};
        } else {
            // ждём m1 от пира: как TCP-accept
            dial.handleAcceptedConn(app, tc, .relay);
        }
        // сессия поднята или упала — цикл проверит и повторит регистрацию
        sysfd.sleepMs(1000);
    }
}

/// Поток A-стороны релея: держит регистрацию marker-ом, пока инвайт жив.
/// Спаривание -> handleAcceptedConn (JOIN поднимет контакт). Обрыв ->
/// переподключение (пир может дозваниваться долго).
pub fn relayLinkerLoop(app: *App, secret: [16]u8, addr: []const u8) void {
    var secret_copy = secret;
    defer std.crypto.secureZero(u8, &secret_copy);
    const addr_copy = app.alloc.dupe(u8, addr) catch return;
    defer app.alloc.free(addr_copy);
    while (app.running) {
        // инвайт ещё жив? (не redeemed)
        {
            app.lock();
            defer app.unlock();
            var alive = false;
            for (&app.invites) |*reg| {
                if (std.crypto.timing_safe.eql([invite_mod.secret_len]u8, reg.secret, secret_copy) and !reg.used and reg.created_ms != 0) {
                    alive = true;
                    break;
                }
            }
            if (!alive) return;
        }
        var refl = relay_mod.Reflexive{ .ip = .{ 0, 0, 0, 0 }, .port = 0 };
        const tc = relay_mod.dialEcho(app.alloc, addr_copy, secret_copy, &refl) catch {
            sysfd.sleepMs(2000);
            continue;
        };
        {
            app.lock();
            defer app.unlock();
            app.raw_conns.append(app.alloc, tc) catch {
                tc.deinit();
                sysfd.sleepMs(2000);
                continue;
            };
            routes.rememberRelayEchoLocked(app, tc, refl);
        }
        // спарено: входящий пир (m1+JOIN) — как TCP-accept
        dial.handleAcceptedConn(app, tc, .relay);
        // соединение отработало/оборвалось: инвайт ещё жив -> повтор
    }
}

/// Поток релей-присутствия персистентного кода профиля: registration
/// marker-ом, ПОКА ДЕМОН ЖИВ (секрет не сгорает — реестра нет). После
/// рестарта присутствие восстанавливает GUI повторным CREATE_INVITE_EX
/// mode=profile: код детерминирован и не меняется.
pub fn profileRelayLoop(app: *App, addr_copy: []u8) void {
    defer app.alloc.free(addr_copy);
    while (app.running) {
        // эпоха выводится на каждой итерации: после REGENERATE_PROFILE_CODE
        // поток сам переходит на новый секрет (старый marker на релее
        // протухнет по таймауту регистрации)
        var secret = profile_code.profileSecret(app.id, app.profile_epoch);
        defer std.crypto.secureZero(u8, &secret);
        var refl = relay_mod.Reflexive{ .ip = .{ 0, 0, 0, 0 }, .port = 0 };
        const tc = relay_mod.dialEcho(app.alloc, addr_copy, secret, &refl) catch {
            sysfd.sleepMs(2000);
            continue;
        };
        {
            app.lock();
            defer app.unlock();
            app.raw_conns.append(app.alloc, tc) catch {
                tc.deinit();
                sysfd.sleepMs(2000);
                continue;
            };
            routes.rememberRelayEchoLocked(app, tc, refl);
        }
        dial.handleAcceptedConn(app, tc, .relay);
    }
}
