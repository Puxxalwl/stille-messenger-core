//! Инвайты демона: реестр приглашений, v1/v2/v3-потоки принятия,
//! профиль-код (эпоха, REGENERATE), короткие коды, relay-линкеры.
const std = @import("std");
const stille_messenger = @import("stille-messenger");
const identity = stille_messenger.crypto.identity;
const envelope = stille_messenger.proto.envelope;
const session_mod = stille_messenger.core.session;
const relay_mod = stille_messenger.net.relay;
const invite_mod = @import("invite.zig");
const endpoints_mod = @import("endpoints.zig");
const api = @import("api.zig");
const app_mod = @import("app.zig");
pub const App = app_mod.App;
const events = @import("events.zig");
const connq = @import("connq.zig");
const dial = @import("dial.zig");
const presence = @import("presence.zig");
const profile_code = @import("profile_code.zig");
const persist = @import("persist.zig");

/// Запись в кольцо завершённых приглашений (GET_INVITE_STATE).
/// ВЫЗЫВАТЬ ПОД app.mu.
pub fn inviteDonePutLocked(app: *App, invite_id: [16]u8, state: api.InviteState, accepted_cid: u32) void {
    app.invite_done[app.invite_done_pos] = .{
        .invite_id = invite_id,
        .state = @backingInt(state),
        .accepted_cid = accepted_cid,
    };
    app.invite_done_pos = (app.invite_done_pos + 1) % app_mod.invite_done_cap;
    if (app.invite_done_len < app_mod.invite_done_cap) app.invite_done_len += 1;
    // приглашение больше не «в полёте»: used/joining расформированы
    for (&app.invites) |*reg| {
        if (reg.joining and std.mem.eql(u8, &reg.invite_id, &invite_id)) {
            reg.joining = false;
            std.crypto.secureZero(u8, &reg.secret);
        }
    }
}

/// CREATE_INVITE: payload [flags u8 (bit0 = relay)][name str16][addr str16].
/// Ответ: [code str16] — односторонний инвайт-код (URL stille://i/...).
pub fn apiCreateInvite(app: *App, payload: []const u8, w: *api.Writer) api.Status {
    var r = api.Reader.init(payload);
    const flags = r.readU8() catch return .BAD_FRAME;
    const is_relay = flags & 1 != 0;
    const name_in = r.readStr16() catch return .BAD_FRAME;
    const addr_in = r.readStr16() catch return .BAD_FRAME;
    if (r.hasMore()) return .BAD_FRAME;
    if (name_in.len > invite_mod.max_name) return .BAD_ARGS;
    if (is_relay and addr_in.len == 0) return .BAD_ARGS;
    if (addr_in.len > 64) return .BAD_ARGS;
    const name: []const u8 = if (name_in.len == 0) "stille-messenger" else name_in;
    // односторонний v2-код: держатель добавляется ONE accept-ом
    var secret: [invite_mod.secret_len]u8 = undefined;
    app.io.random(&secret);
    defer std.crypto.secureZero(u8, &secret);
    {
        app.lock();
        defer app.unlock();
        var slot: ?usize = null;
        for (&app.invites, 0..) |*reg, i| {
            if (reg.used or reg.created_ms == 0) {
                slot = i;
                break;
            }
        }
        const i = slot orelse return .TOO_MANY_INVITES;
        app.invites[i] = .{ .secret = secret, .created_ms = app.nowMs(), .used = false };
        if (is_relay) {
            const n = @min(addr_in.len, app_mod.relay_addr_max);
            @memcpy(app.invites[i].relay_buf[0..n], addr_in[0..n]);
            app.invites[i].relay_len = @intCast(n);
        }
    }
    var out: [256]u8 = undefined;
    var rbuf: [80]u8 = undefined;
    const code_addr: ?[]const u8 = if (is_relay) blk: {
        const s = std.fmt.bufPrint(&rbuf, "r/{s}", .{addr_in}) catch return .BAD_ARGS;
        break :blk s;
    } else if (addr_in.len > 0) addr_in else null;
    const code = invite_mod.encode2(&out, app.id.bundle(), secret, name, code_addr) catch return .BAD_ARGS;
    w.putStr16(code) catch return .INTERNAL;
    if (is_relay) {
        const addr_copy = app.alloc.dupe(u8, addr_in) catch return .INTERNAL;
        if (std.Thread.spawn(.{}, presence.relayLinkerLoop, .{ app, secret, addr_copy })) |t| {
            t.detach();
        } else |_| {
            app.alloc.free(addr_copy);
        }
    }
    return .OK;
}

/// Результат погашения инвайта (общее ядро ACCEPT_INVITE / _EX).
pub const AcceptOut = struct {
    cid: i64 = 0,
    /// Информирует о постановке работы, НЕ о доверии: контакт
    /// подтверждается только аутентифицированным JOIN.
    disp: api.AcceptDisposition = .accepted,
    state: api.ConnState = .pending,
    attempt: u32 = 0,
};

/// Общее ядро погашения инвайт-кода (v1/v2/v3): разбор, дедуп по bundle,
/// JOIN-данные и постановка работы подключения в планировщик (dial —
/// НЕ в потоке API: ответ уходит сразу). Существующий контакт не
/// дублируется: повторный код возвращает тот же cid.
pub fn acceptInviteCommon(app: *App, payload: []const u8, out: *AcceptOut) api.Status {
    var r = api.Reader.init(payload);
    const code = r.readStr16() catch return .BAD_FRAME;
    const my_name_in = r.readStr16() catch return .BAD_FRAME;
    if (r.hasMore()) return .BAD_FRAME;
    if (code.len == 0) return .BAD_INVITE_CODE;
    if (my_name_in.len > invite_mod.max_name) return .BAD_ARGS;
    const my_name: []const u8 = if (my_name_in.len == 0) "друг" else my_name_in;

    // разбор: v3 (гибрид i3) или v1/v2
    var bundle: [64]u8 = undefined;
    var name_buf: [invite_mod.max_name]u8 = @splat(0);
    var name_len: usize = 0;
    var addr_buf: [80]u8 = undefined;
    var addr: ?[]const u8 = null;
    var relay_addr_buf: [80]u8 = undefined;
    var relay_addr: ?[]const u8 = null;
    var relay_secret: ?[16]u8 = null;
    var code_secret: [16]u8 = @splat(0);
    var has_code_secret = false; // v2/v3: JOIN-конверт погашает секрет кода
    var hybrid = false;
    if (std.mem.startsWith(u8, code, invite_mod.v3_prefix) or
        std.mem.startsWith(u8, code, invite_mod.legacy_v3_prefix))
    {
        const inv = invite_mod.decode3(code) catch return .BAD_INVITE_CODE;
        bundle = inv.bundle;
        @memcpy(name_buf[0..inv.name_len], inv.name());
        name_len = inv.name_len;
        if (inv.has_direct) {
            addr = inv.direct.addr(&addr_buf) orelse return .BAD_INVITE_CODE;
        }
        if (inv.has_relay) {
            relay_addr = inv.relay.addr(&relay_addr_buf) orelse return .BAD_INVITE_CODE;
            relay_secret = inv.secret;
        }
        code_secret = inv.secret;
        has_code_secret = true;
        hybrid = inv.has_direct and inv.has_relay;
    } else {
        if (!std.mem.startsWith(u8, code, invite_mod.v2_prefix) and
            !std.mem.startsWith(u8, code, invite_mod.legacy_v2_prefix) and
            !std.mem.startsWith(u8, code, "shopot1.")) return .BAD_INVITE_CODE;
        const inv = invite_mod.decode(code) catch return .BAD_INVITE_CODE;
        bundle = inv.bundle;
        @memcpy(name_buf[0..inv.name_len], inv.name());
        name_len = inv.name_len;
        // inv.addr() — только хост: порт живёт отдельно, собираем "host:port"
        if (inv.host_len > 0) {
            addr = std.fmt.bufPrint(&addr_buf, "{s}:{d}", .{ inv.addr().?, inv.port }) catch return .BAD_ARGS;
        }
        if (inv.v2) {
            if (inv.relay) {
                relay_addr = addr;
                relay_secret = inv.secret;
            }
            code_secret = inv.secret;
            has_code_secret = true;
        }
    }
    const name: []const u8 = name_buf[0..name_len];

    // мутации движка/хешмапы — строго под локом (ticker и рендер итерируют)
    var enq: ?app_mod.ConnWork = null;
    {
        app.lock();
        defer app.unlock();
        // код от НАШЕГО bundle: линк устройства (оба устройства — один сид
        // личности, записи БД реплицируются MAC-ами этого сида).
        // v1: один линк на демон (bundle один на все устройства — второй
        // линок неразличим с первым).
        const is_device = std.mem.eql(u8, &bundle, &app.id.bundle());
        if (is_device and app.sync.devices.count() > 0) return .TOO_BIG;
        const existing = app_mod.contactIdByBundle(app, bundle);
        if (existing) |ecid| {
            // повторное погашение: тот же cid, дубль не создаётся
            out.cid = ecid;
            if (app.eng.sessions.get(ecid) != null) {
                out.disp = .already_connected;
                out.state = events.connStateOfLocked(app, ecid);
                out.attempt = if (app.conn_st.get(ecid)) |e| e.attempt else 0;
                return .OK;
            }
            // та же незавершённая работа уже в полёте — не дублируем;
            // ДРУГОЙ секрет на летящую работу — не подменяем (BUSY)
            if (connq.connInflight(app, ecid)) {
                if (has_code_secret) {
                    if (app.join_map.get(ecid)) |ji| {
                        if (!std.mem.eql(u8, &ji.secret, &code_secret)) return .BUSY;
                    }
                }
                out.disp = .already_pending;
                out.state = events.connStateOfLocked(app, ecid);
                out.attempt = if (app.conn_st.get(ecid)) |e| e.attempt else 0;
                return .OK;
            }
            // новая работа по тому же контакту: адрес обновить
            if (addr) |a| persist.saveContactAddr(app, ecid, a);
            out.cid = ecid;
        } else {
            const idx = app.eng.addContact(name, bundle) catch return .INTERNAL;
            out.cid = @intCast(idx + 1);
            app.hb.put(out.cid, .{}) catch {};
            // держатель кода линка всегда инициирует подключение (детерминизм:
            // bundle устройств равны, порядок их не разведёт)
            if (is_device) {
                app.eng.contacts.items[idx].dev_role = app_mod.dev_role_holder;
                app.sync.addDevice(out.cid);
            }
            if (addr) |a| persist.saveContactAddr(app, out.cid, a);
            if (app.log) |log| {
                // relay-инвайт: адрес релея в лог — присутствие после рестарта
                persist.logContact(app, log, name, bundle, addr, if (relay_addr != null) relay_addr else null, if (is_device) app_mod.dev_role_holder else 0);
            }
            // новый контакт: представление изменилось — ревизия
            events.bumpContactLocked(app, out.cid);
        }
        const cid = out.cid;
        // v2/v3: JOIN-данные — первым конвертом после рукопожатия.
        // Тот же секрет (повтор кода) — идемпотентно; новый секрет
        // заменяет (работы в полёте нет — проверено выше).
        if (has_code_secret) {
            if (app.join_map.getPtr(cid)) |old| {
                std.crypto.secureZero(u8, &old.secret);
            }
            app.join_map.put(app.alloc, cid, .{
                .secret = code_secret,
                .name_len = @intCast(my_name.len),
                .name_buf = blk: {
                    var nb: [32]u8 = @splat(0);
                    @memcpy(nb[0..my_name.len], my_name);
                    break :blk nb;
                },
            }) catch {};
            std.crypto.secureZero(u8, &code_secret);
        }
        // состояние до работы: адрес есть — dial встанет в очередь;
        // адреса нет — ждём LAN-анонс пира (DISCOVERING)
        if (addr == null and relay_addr == null) {
            if (has_code_secret) events.connSetLocked(app, cid, .pending, .none, null) else events.connDiscoveringLocked(app, cid);
        } else {
            if (app.conn_st.getPtr(cid)) |st| st.next_retry_at = 0;
        }
        // работа: адрес (прямой/релей) или гибрид
        if (addr != null or relay_addr != null) {
            var work = app_mod.ConnWork{ .cid = cid };
            if (hybrid) {
                // i3: прямой адрес + relay-fallback (секрет marker-а)
                work.hybrid = true;
                work.relay_secret = relay_secret;
                if (relay_addr) |ra| {
                    if (ra.len <= work.relay_addr_buf.len) {
                        @memcpy(work.relay_addr_buf[0..ra.len], ra);
                        work.relay_addr_len = @intCast(ra.len);
                    }
                }
                if (addr) |a| {
                    if (a.len <= work.addr_buf.len) {
                        @memcpy(work.addr_buf[0..a.len], a);
                        work.addr_len = @intCast(a.len);
                    }
                }
            } else if (relay_secret != null and relay_addr != null) {
                // v2 relay: marker-спаривание
                work.relay_secret = relay_secret;
                if (relay_addr) |ra| {
                    @memcpy(work.addr_buf[0..ra.len], ra);
                    work.addr_len = @intCast(ra.len);
                }
            } else if (addr) |a| {
                @memcpy(work.addr_buf[0..a.len], a);
                work.addr_len = @intCast(a.len);
            }
            enq = work;
        }
        out.state = events.connStateOfLocked(app, cid);
        out.attempt = if (app.conn_st.get(cid)) |e| e.attempt else 0;
    }
    // постановка в очередь — БЕЗ app.mu (connq_mu — листовый лок)
    if (enq) |work| {
        connq.connEnqueue(app, work) catch {
            // уже в полёте (гонка с другим путём) — это уже_pending
            out.disp = .already_pending;
        };
    }
    return .OK;
}

/// ACCEPT_INVITE: payload [code str16][my_name str16]. Единственное действие
/// держателя кода. Ответ: [cid u32]. Подключение — асинхронно (планировщик
/// 2.7.0): dial не блокирует ответ, стадии видны через GET_CONTACT_STATE /
/// CONTACT_STATE_CHANGED, а статус — по событиям PRESENCE.
pub fn apiAcceptInvite(app: *App, payload: []const u8, w: *api.Writer) api.Status {
    var out = AcceptOut{};
    const st = acceptInviteCommon(app, payload, &out);
    if (st != .OK) return st;
    w.putU32(@intCast(out.cid)) catch return .INTERNAL;
    return .OK;
}

/// ACCEPT_INVITE_EX (44): тот же payload, расширенный ответ:
/// [cid u32][disposition u8][state u8][attempt u32]. disposition
/// информирует о постановке работы, НЕ о доверии (см. PROTOCOL.md §6).
pub fn apiAcceptInviteEx(app: *App, payload: []const u8, w: *api.Writer) api.Status {
    var out = AcceptOut{};
    const st = acceptInviteCommon(app, payload, &out);
    if (st != .OK) return st;
    w.putU32(@intCast(out.cid)) catch return .INTERNAL;
    w.putU8(@backingInt(out.disp)) catch return .INTERNAL;
    w.putU8(@backingInt(out.state)) catch return .INTERNAL;
    w.putU32(out.attempt) catch return .INTERNAL;
    return .OK;
}

/// CREATE_INVITE_EX (49): [mode u8][name str16][direct str16][relay str16]
/// → [code str16][invite_id 16]. mode: 0 discovery / 1 direct / 2 relay_only /
/// 3 direct_then_relay (i3-код: прямой адрес + relay-fallback в одном).
/// direct/relay — "host:port". use_tor_mask + прямой режим — BAD_ARGS
/// (свой IP не раскрываем; relay_only остаётся доступен).
/// invite_id — НЕсекретный идентикатор для GET_INVITE_STATE.
pub fn apiCreateInviteEx(app: *App, payload: []const u8, w: *api.Writer) api.Status {
    var r = api.Reader.init(payload);
    const mode_in = r.readU8() catch return .BAD_FRAME;
    const mode = std.enums.fromInt(api.InviteExMode, mode_in) orelse return .BAD_ARGS;
    const name_in = r.readStr16() catch return .BAD_FRAME;
    const direct_in = r.readStr16() catch return .BAD_FRAME;
    const relay_in = r.readStr16() catch return .BAD_FRAME;
    if (r.hasMore()) return .BAD_FRAME;
    if (name_in.len > invite_mod.max_name) return .BAD_ARGS;
    if (direct_in.len > invite_mod.v3_addr_max or relay_in.len > invite_mod.v3_addr_max) return .BAD_ARGS;
    const d: ?[]const u8 = if (direct_in.len > 0) direct_in else null;
    const rl: ?[]const u8 = if (relay_in.len > 0) relay_in else null;
    switch (mode) {
        .discovery => {
            if (d != null or rl != null) return .BAD_ARGS;
        },
        .direct => {
            if (d == null or rl != null) return .BAD_ARGS;
        },
        .relay_only => {
            if (rl == null or d != null) return .BAD_ARGS;
        },
        .direct_then_relay => {
            if (d == null or rl == null) return .BAD_ARGS;
        },
        // профиль: любые комбинации (∅ / direct / relay / гибрид);
        // для диплинков сайта рекомендован relay (работает через сети)
        .profile => {},
    }
    const name: []const u8 = if (name_in.len == 0) "stille-messenger" else name_in;
    var secret: [invite_mod.secret_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &secret);
    var invite_id: [16]u8 = undefined;
    const is_profile = mode == .profile;
    {
        app.lock();
        defer app.unlock();
        if (mode == .direct or mode == .direct_then_relay or (is_profile and d != null)) {
            if (app.cfg.use_tor_mask) return .BAD_ARGS; // прямой адрес не раскрываем
        }
        if (is_profile) {
            // персистентный код: секрет и invite_id детерминированы из
            // личности; реестр не занимается (валидация stateless),
            // лимита TOO_MANY_INVITES нет
            secret = profile_code.profileSecret(app.id, app.profile_epoch);
            invite_id = profile_code.profileInviteId(app.id);
        } else {
            app.io.random(&secret);
            app.io.random(&invite_id);
            var slot: ?usize = null;
            for (&app.invites, 0..) |*reg, i| {
                if (reg.used or reg.created_ms == 0) {
                    slot = i;
                    break;
                }
            }
            const i = slot orelse return .TOO_MANY_INVITES;
            app.invites[i] = .{ .secret = secret, .created_ms = app.nowMs(), .used = false, .invite_id = invite_id };
            if (rl) |ra| {
                const n = @min(ra.len, app_mod.relay_addr_max);
                @memcpy(app.invites[i].relay_buf[0..n], ra[0..n]);
                app.invites[i].relay_len = @intCast(n);
            }
        }
    }
    // код: гибрид — v3 (i3), одиночные — v2 (обратная совместимость);
    // профиль с обоими адресами — v3-гибрид, иначе v2 (формат не меняется)
    var out: [512]u8 = undefined;
    var rbuf: [80]u8 = undefined;
    const code: []const u8 = blk: {
        switch (mode) {
            .direct_then_relay => break :blk invite_mod.encode3(&out, app.id.bundle(), secret, name, d, rl) catch return .BAD_ARGS,
            .relay_only => {
                const s = std.fmt.bufPrint(&rbuf, "r/{s}", .{rl.?}) catch return .BAD_ARGS;
                break :blk invite_mod.encode2(&out, app.id.bundle(), secret, name, s) catch return .BAD_ARGS;
            },
            .direct => break :blk invite_mod.encode2(&out, app.id.bundle(), secret, name, d) catch return .BAD_ARGS,
            .discovery => break :blk invite_mod.encode2(&out, app.id.bundle(), secret, name, null) catch return .BAD_ARGS,
            .profile => {
                if (d != null and rl != null) {
                    break :blk invite_mod.encode3(&out, app.id.bundle(), secret, name, d, rl) catch return .BAD_ARGS;
                } else if (rl != null) {
                    const s = std.fmt.bufPrint(&rbuf, "r/{s}", .{rl.?}) catch return .BAD_ARGS;
                    break :blk invite_mod.encode2(&out, app.id.bundle(), secret, name, s) catch return .BAD_ARGS;
                } else if (d != null) {
                    break :blk invite_mod.encode2(&out, app.id.bundle(), secret, name, d) catch return .BAD_ARGS;
                } else {
                    break :blk invite_mod.encode2(&out, app.id.bundle(), secret, name, null) catch return .BAD_ARGS;
                }
            },
        }
    };
    w.putStr16(code) catch return .INTERNAL;
    w.putBytes(&invite_id) catch return .INTERNAL;
    if (rl) |ra| {
        const addr_copy = app.alloc.dupe(u8, ra) catch return .INTERNAL;
        if (is_profile) {
            // присутствие на весь срок жизни демона (секрет не сгорает)
            if (std.Thread.spawn(.{}, presence.profileRelayLoop, .{ app, addr_copy })) |t| {
                t.detach();
            } else |_| {
                app.alloc.free(addr_copy);
            }
        } else if (std.Thread.spawn(.{}, presence.relayLinkerLoop, .{ app, secret, addr_copy })) |t| {
            t.detach();
        } else |_| {
            app.alloc.free(addr_copy);
        }
    }
    return .OK;
}

/// GET_INVITE_STATE (50): [invite_id 16] → [state u8][accepted_cid u32]
/// [expires_at_ms i64]. Активные приглашения — из таблицы регистрации;
/// погашенные (consumed/failed) — кольцо диагностики на invite_done_cap
/// записей, дальше NOT_FOUND (клиент обязан держать последний ответ сам).
/// expires_at_ms — 0 (lifetime приглашения управляется владением кода).
pub fn apiGetInviteState(app: *App, payload: []const u8, w: *api.Writer) api.Status {
    var r = api.Reader.init(payload);
    const invite_id = r.readBytes(16) catch return .BAD_FRAME;
    if (r.hasMore()) return .BAD_FRAME;
    app.lock();
    defer app.unlock();
    // персистентный код профиля: детерминированный маркер личности —
    // всегда active, бессрочно, реестра нет (валидация stateless)
    if (std.mem.eql(u8, invite_id, &profile_code.profileInviteId(app.id))) {
        w.putU8(@backingInt(api.InviteState.active)) catch return .INTERNAL;
        w.putU32(0) catch return .INTERNAL;
        w.putI64(0) catch return .INTERNAL;
        return .OK;
    }
    // живая регистрация
    for (&app.invites) |*reg| {
        if (reg.created_ms == 0) continue;
        if (!std.mem.eql(u8, &reg.invite_id, invite_id)) continue;
        if (reg.used) continue;
        const st: api.InviteState = if (reg.joining) .joining else .active;
        w.putU8(@backingInt(st)) catch return .INTERNAL;
        w.putU32(0) catch return .INTERNAL;
        w.putI64(0) catch return .INTERNAL;
        return .OK;
    }
    // кольцо завершённых (свежее поверх старого)
    var i: usize = app.invite_done_len;
    while (i > 0) {
        i -= 1;
        const idx = (app.invite_done_pos + app_mod.invite_done_cap - 1 - i) % app_mod.invite_done_cap;
        const done = app.invite_done[idx];
        if (!std.mem.eql(u8, &done.invite_id, invite_id)) continue;
        w.putU8(done.state) catch return .INTERNAL;
        w.putU32(done.accepted_cid) catch return .INTERNAL;
        w.putI64(0) catch return .INTERNAL;
        return .OK;
    }
    return .NOT_FOUND;
}

/// GENERATE_SHORT_CODE (52): [cid u32 (0 = я)] → [cid u32][code str16].
/// Код детерминирован из публичного bundle, хранения нет. Идентификатор
/// для диплинков stille.im/invite/{code}: без секретов, не раскрывает
/// bundle, не даёт прав. Контакт — его код (удалённые исключаются).
pub fn apiGenerateShortCode(app: *App, payload: []const u8, w: *api.Writer) api.Status {
    if (payload.len != 4) return .BAD_FRAME;
    const cid = std.mem.readInt(u32, payload[0..4], .little);
    app.lock();
    defer app.unlock();
    if (!app.provisioned) return .NOT_INITIALIZED;
    var bundle: [64]u8 = undefined;
    if (cid == 0) {
        bundle = app.id.bundle();
    } else {
        if (cid < 1 or cid > app.eng.contacts.items.len) return .NO_CONTACT;
        const c = &app.eng.contacts.items[cid - 1];
        if (c.deleted) return .NO_CONTACT;
        bundle = c.bundle;
    }
    const code = invite_mod.shortCodeFromBundle(bundle);
    w.putU32(cid) catch return .INTERNAL;
    w.putStr16(&code) catch return .INTERNAL;
    return .OK;
}

/// DECODE_SHORT_CODE (53): [code str16] → [cid u32 (0 = я)]
/// [full_code str16] или NOT_FOUND. Код информационно необратим
/// (45 бит < 512 бит bundle): резолвятся только локально известные
/// bundle — своя личность и контакты (заблокированные включены:
/// блокировка — рендер-решение GUI, не «неизвестность»). Полный код —
/// v1-формат (bundle|имя[|адрес]): тот же формат, что генерит v1-инвайт,
/// GUI может показать его или передать дальше. При коллизии хешей двух
/// контактов (2^-40) резолв детерминирован по младшему cid.
pub fn apiDecodeShortCode(app: *App, payload: []const u8, w: *api.Writer) api.Status {
    var r = api.Reader.init(payload);
    const code_in = r.readStr16() catch return .BAD_FRAME;
    if (r.hasMore()) return .BAD_FRAME;
    const code = invite_mod.shortCodeNormalize(code_in) orelse return .BAD_ARGS;
    app.lock();
    defer app.unlock();
    if (!app.provisioned) return .NOT_INITIALIZED;
    var code_buf: [256]u8 = undefined;
    // свой bundle: cid 0, имя — свой профиль (пустой профиль -> «друг»,
    // v1-код требует непустое имя), адрес не подставляем (свой LAN-адрес
    // в чужом коде бесполезен; добавление — через инвайт)
    if (std.mem.eql(u8, &code, &(invite_mod.shortCodeFromBundle(app.id.bundle())))) {
        const my_name: []const u8 = if (app.eng.myName().len == 0) "друг" else app.eng.myName();
        const full = invite_mod.encode(&code_buf, app.id.bundle(), my_name, null) catch return .INTERNAL;
        w.putU32(0) catch return .INTERNAL;
        w.putStr16(full) catch return .INTERNAL;
        return .OK;
    }
    for (app.eng.contacts.items, 0..) |*c, i| {
        if (c.deleted) continue;
        if (!std.mem.eql(u8, &code, &(invite_mod.shortCodeFromBundle(c.bundle)))) continue;
        var ab: [72]u8 = undefined;
        const addr: ?[]const u8 = if (c.addr(&ab)) |a| a else null;
        const full = invite_mod.encode(&code_buf, c.bundle, c.getName(), addr) catch return .INTERNAL;
        w.putU32(@intCast(i + 1)) catch return .INTERNAL;
        w.putStr16(full) catch return .INTERNAL;
        return .OK;
    }
    return .NOT_FOUND;
}

/// REGENERATE_PROFILE_CODE (54): ∅ → [epoch u32][persisted u8].
/// Ротация секрета персистентного кода: эпоха входит в HKDF-вывод, bump
/// эпохи меняет секрет — слитый код прошлой эпохи перестаёт проходить
/// JOIN немедленно (валидация принимает только текущую эпоху). Новый код
/// GUI получает повторным CREATE_INVITE_EX mode 4. Порядок: сначала
/// запись .set(8) в шифрованный лог, затем bump в памяти (провал записи —
/// INTERNAL, эпоха НЕ меняется: слитый код остаётся мёртвым/живым
/// консистентно с диском). Лога нет (продолжение без хранения) —
/// persisted=0, эпоха живёт до рестарта. Существующие контакты не
/// зависят от кода: их сессии живут по handshake, не по инвайту.
pub fn apiRegenerateProfileCode(app: *App, payload: []const u8, w: *api.Writer) api.Status {
    if (payload.len != 0) return .BAD_FRAME;
    app.lock();
    defer app.unlock();
    if (!app.provisioned) return .NOT_INITIALIZED;
    const new_epoch = app.profile_epoch +% 1;
    var persisted: u8 = 1;
    if (app.log) |log| {
        // [8][epoch u32 LE] — kind .set, подтип 8; реплей восстанавливает
        var rec: [5]u8 = undefined;
        rec[0] = 8;
        std.mem.writeInt(u32, rec[1..5], new_epoch, .little);
        _ = log.append(.set, &rec) catch return .INTERNAL;
    } else {
        persisted = 0;
    }
    app.profile_epoch = new_epoch;
    w.putU32(new_epoch) catch return .INTERNAL;
    w.putU8(persisted) catch return .INTERNAL;
    return .OK;
}
