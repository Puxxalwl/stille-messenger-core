//! Приём: диспетчер входящих конвертов (envIn), обработка JOIN
//! (инвайты/профиль-код), события движка (on*Ev), привязка сессии
//! к контакту (bindSession), pending-сессии и их таймауты.
const std = @import("std");
const stille_messenger = @import("stille-messenger");
const identity = stille_messenger.crypto.identity;
const engine_mod = stille_messenger.core.engine;
const session_mod = stille_messenger.core.session;
const envelope = stille_messenger.proto.envelope;
const relay_mod = stille_messenger.net.relay;
const tcp = stille_messenger.net.tcp;
const invite_mod = @import("invite.zig");
const api_srv = @import("api_server.zig");
const api = @import("api.zig");
const app_mod = @import("app.zig");
const config_mod = stille_messenger.app.config;
const dispatch = @import("dispatch.zig");
const sync_mod = stille_messenger.app.sync;
const sysfd = stille_messenger.net.sysfd;
pub const App = app_mod.App;
const events = @import("events.zig");
const connq = @import("connq.zig");
const routes = @import("routes.zig");
const persist = @import("persist.zig");
const sync_apply = @import("sync_apply.zig");
const calls = @import("calls.zig");
const presence = @import("presence.zig");
const profile_code = @import("profile_code.zig");
const paths = @import("paths.zig");
const invites = @import("invites.zig");

/// Привязать сессию к контакту. sc — контекст событий, уже создан и
/// используется rx-потоком сессии, поэтому здесь не уничтожается никогда
/// (короткоживущий процесс, счёт контекстов равен числу сессий).
/// Реализован свободной функцией, а не методом App: слою dial сессии
/// доступны только через App.session_bind (инверсия зависимости, dial
/// не импортирует слой приёма).
pub fn bindSession(app: *App, cid: i64, s: *session_mod.Session, sc: *app_mod.SessCtx) error{OutOfMemory}!void {
    app.lock();
    defer app.unlock();
    return bindSessionLocked(app, cid, s, sc);
}

/// bind без взятия лока — вызывать ПОД app.mu.
pub fn bindSessionLocked(app: *App, cid: i64, s: *session_mod.Session, sc: *app_mod.SessCtx) !void {
    if (app.eng.sessions.get(cid)) |old| {
        // прошлую сессию — в retired: shutdown транспорта будит её
        // rx-поток, join и destroy сделает drainRetired тикера ВНЕ
        // лока (close+join здесь — deadlock: rx выходит через app.mu)
        app.eng.retireSession(cid, old);
    }
    try app.eng.sessions.put(cid, s);
    try app.sess_ctx.put(cid, sc);
    sc.s = s;
    // prime presence: считаем контакт живым сразу после рукопожатия
    const now = app.nowMs();
    app.eng.markSeen(cid, now);
    if (app.hb.getPtr(cid)) |st| st.onInbound(now);
    // сессия поднята — слить outbox (доставка офлайн-хвоста)
    app.eng.flushOutbox(cid);
    // ...и докачать файлы в полёте (с последнего подтверждённого чанка)
    app.eng.resumeFileTx(cid);
    // устройство-линк: слить очередь синхронизации записей БД
    persist.syncFlushLocked(app, cid);
    // PROFILE-эхо: имя + avatar_id пир-у при каждом установлении
    app.eng.sendProfile(cid) catch {};
    // наблюдаемое состояние (2.7.0): сессия аутентифицирована; ждём
    // PROFILE-эхо после JOIN — JOINING (пир ещё не подтвердил добавление),
    // иначе ONLINE
    if (app.conn_await.contains(cid)) {
        events.connSetLocked(app, cid, .joining, .none, null);
    } else {
        events.connSetLocked(app, cid, .online, .none, null);
    }
    // NAT-punch (2.9.0): путь сессии. Пробитый/LAN-конн — снимаем
    // punch-маршрут (даунгрейда на relay не бывает) и рапортуем
    // ROUTE_STATE; relay-конн — рапортуем relay и рассылаем пир
    // PUNCH_CANDIDATES (внутри аутентифицированной сессии).
    if (sc.punched) {
        _ = app.punch_routes.remove(cid);
        routes.evRouteState(app, cid, .direct_punched);
    } else if (sc.lan_dial) {
        _ = app.punch_routes.remove(cid);
        routes.evRouteState(app, cid, .lan);
    } else if (sc.relay_tc) |tc| {
        routes.evRouteState(app, cid, .relay);
        routes.sendPunchCandidatesLocked(app, cid, s, sc, tc);
        // 2.10.0: relay-сессия — сообщить пиру наши прямые IPv6
        // (пир запомнит их для прямого автодозвона)
        routes.sendV6AddrLocked(app, cid, s);
    }
    events.bumpContactLocked(app, cid);
}

/// События движка: единственная точка, где главный поток (main) получает
/// колбэки движка для нового Engine. Вызывается один раз при сборке App.
pub fn engineEvents(app: *App) engine_mod.Events {
    return .{ .ctx = app, .onText = onTextEv, .onReply = onReplyEv, .onReaction = onReactionEv, .onPresence = onPresenceEv, .onProfile = onProfileEv, .onContactCard = onContactCardEv, .onBlockedNotice = onBlockedEv, .onCallSignal = calls.onCallSignalEv, .onCallAudio = calls.onCallAudioEv, .onDelivered = onDeliveredEv, .onAvatar = onAvatarEv, .onAvatarReq = onAvatarReqEv, .onFileMeta = onFileMetaEv, .onFileData = onFileDataEv, .onFileSent = onFileSentEv, .onSync = sync_apply.onSyncEv, .onSyncAck = sync_apply.onSyncAckEv };
}

pub fn envIn(ctx: *anyopaque, env: envelope.Envelope) void {
    const sc: *app_mod.SessCtx = @ptrCast(@alignCast(ctx));
    const app = sc.app;
    if (sc.cid == -1) {
        // pending-join: единственный допустимый конверт — JOIN
        handleJoinEnvelope(sc, env);
        return;
    }
    const now = app.nowMs();
    app.lock();
    defer app.unlock();
    // NAT-punch (2.9.0): кандидаты пира — до движка (движку кадр
    // безразличен, exhaustiveness закрыт пустой веткой); старые ядра
    // кадр просто пропускают — их маршрут остаётся на relay
    switch (env) {
        .punch => |p| {
            app.eng.markSeen(sc.cid, now);
            if (app.hb.getPtr(sc.cid)) |st| st.onInbound(now);
            routes.handlePunchInLocked(app, sc.cid, p);
            return;
        },
        // V6_ADDR (2.10.0): прямые IPv6-адреса пира -> контакт-адрес
        // для прямого автодозвона (без релея). Старые ядра кадр не
        // отправляют, а неизвестный тег у них — молчаливый пропуск.
        .v6addr => |v| {
            app.eng.markSeen(sc.cid, now);
            if (app.hb.getPtr(sc.cid)) |st| st.onInbound(now);
            routes.handleV6AddrInLocked(app, sc.cid, v);
            return;
        },
        else => {},
    }
    app.eng.markSeen(sc.cid, now);
    if (app.hb.getPtr(sc.cid)) |st| {
        st.onInbound(now);
        switch (env) {
            .presence_pong => |pp| st.onPong(pp.seq, now),
            else => {},
        }
    }
    app.eng.dispatch(sc.cid, env);
}

/// JOIN на pending-сессии (sc.cid == -1): подпись привязывает bundle
/// заявителя к транскрипту (ключам сессии), HMAC доказывает держателя
/// инвайт-кода. Валидно — контакт добавляется, сессия биндится.
pub fn handleJoinEnvelope(sc: *app_mod.SessCtx, env: envelope.Envelope) void {
    const app = sc.app;
    const sess = sc.s orelse return;
    // Мы В rx-потоке сессии: close() ждёт rx (join самого себя — deadlock),
    // поэтому гасим только транспорт — rx выйдет сам и рапортует onClosed.
    const j = switch (env) {
        .join => |j| j,
        else => {
            sess.shutdown();
            return;
        },
    };
    const transcript = sess.keys.transcript;
    // 1) подпись: bundle заявителя привязан к ключам этой сессии
    identity.Identity.verify(j.bundle[32..64].*, &transcript, j.sig) catch {
        sess.shutdown();
        return;
    };
    var failed = false;
    var cid: i64 = 0;
    var bind_failed = false;
    // invite_id для кольца диагностики (погашенного приглашения)
    var invite_done_id: [16]u8 = @splat(0);
    // relay-адрес приглашения: после JOIN — присутствие контакта
    var relay_addr_buf: [app_mod.relay_addr_max]u8 = @splat(0);
    var relay_addr_len: usize = 0;
    {
        app.lock();
        defer app.unlock();
        if (sc.cid != -1) return; // уже промоутнут (повторный кадр)
        // 2) HMAC: секрет одного из живых (не погашенных) приглашений
        // ИЛИ статический секрет персистентного кода профиля (stateless:
        // реестра нет, секрет выведен из сида, не сгорает никогда)
        var matched: ?usize = null;
        var profile_matched = false;
        for (&app.invites, 0..) |*reg, i| {
            if (reg.used) continue;
            var mac: [32]u8 = undefined;
            std.crypto.auth.hmac.sha2.HmacSha256.create(&mac, &transcript, &reg.secret);
            if (std.crypto.timing_safe.eql([32]u8, mac, j.hmac)) {
                matched = i;
                break;
            }
        }
        if (matched == null) {
            var psec = profile_code.profileSecret(app.id, app.profile_epoch);
            var mac: [32]u8 = undefined;
            std.crypto.auth.hmac.sha2.HmacSha256.create(&mac, &transcript, &psec);
            std.crypto.secureZero(u8, &psec);
            if (std.crypto.timing_safe.eql([32]u8, mac, j.hmac)) profile_matched = true;
        }
        if (matched == null and !profile_matched) {
            failed = true;
        } else if (profile_matched) {
            // персистентный код: расходовать нечего, релей-присутствие
            // держит profileRelayLoop демона; идём до бинда тем же путём
            if (app_mod.contactIdByBundle(app, j.bundle)) |existing| {
                cid = existing; // переподключение (новое устройство и т.п.)
            } else {
                const ni = app.eng.addContact(j.name, j.bundle) catch {
                    failed = true;
                    return;
                };
                cid = @intCast(ni + 1);
                app.hb.put(cid, .{}) catch {};
                var role: u8 = 0;
                if (std.mem.eql(u8, &j.bundle, &app.id.bundle())) {
                    role = app_mod.dev_role_waiter;
                    app.eng.contacts.items[ni].dev_role = role;
                    app.sync.addDevice(cid);
                }
                if (app.log) |log| persist.logContact(app, log, j.name, j.bundle, null, null, role);
            }
            if (!failed) {
                sc.cid = cid;
                bindSessionLocked(app, cid, sess, sc) catch {
                    failed = true;
                    bind_failed = true;
                };
            }
        } else {
            // корректный HMAC: приглашение расходуется, идём до бинда —
            // состояние JOINING (GET_INVITE_STATE). Секрет в реестре
            // больше не нужен: relay-linker владеет своей копией.
            app.invites[matched.?].used = true;
            app.invites[matched.?].joining = true;
            invite_done_id = app.invites[matched.?].invite_id;
            relay_addr_len = app.invites[matched.?].relay_len;
            @memcpy(relay_addr_buf[0..relay_addr_len], app.invites[matched.?].relay_buf[0..relay_addr_len]);
            // Relay-присутствие ещё использует секрет после JOIN; direct-код
            // можно стереть сразу. inviteDonePutLocked сотрёт relay-секрет.
            if (relay_addr_len == 0) std.crypto.secureZero(u8, &app.invites[matched.?].secret);
            if (app_mod.contactIdByBundle(app, j.bundle)) |existing| {
                cid = existing; // переподключение держателем кода
            } else {
                const ni = app.eng.addContact(j.name, j.bundle) catch {
                    failed = true;
                    return;
                };
                cid = @intCast(ni + 1);
                app.hb.put(cid, .{}) catch {};
                // JOIN с нашим же bundle: линк устройства; приглашающая
                // сторона — «ждущая» (дозванивается всегда держатель кода)
                var role: u8 = 0;
                if (std.mem.eql(u8, &j.bundle, &app.id.bundle())) {
                    role = app_mod.dev_role_waiter;
                    app.eng.contacts.items[ni].dev_role = role;
                    app.sync.addDevice(cid);
                }
                // контакт переживает рестарт: пишем в шифрованный лог
                if (app.log) |log| persist.logContact(app, log, j.name, j.bundle, null, relay_addr_buf[0..relay_addr_len], role);
            }
            if (!failed) {
                sc.cid = cid;
                bindSessionLocked(app, cid, sess, sc) catch {
                    failed = true;
                    bind_failed = true;
                };
            }
        }
    }
    releasePendingLocked(sc);
    if (failed) {
        // bind не удался после корректного HMAC — приглашение FAILED
        // (секрет уже погашен: повторный JOIN тем же кодом невозможен).
        // Персистентный код (нулевой invite_done_id) в кольцо не пишется:
        // он не «расходуется» — держатель может пробовать снова.
        if (bind_failed and !std.mem.allEqual(u8, &invite_done_id, 0)) {
            app.lock();
            defer app.unlock();
            invites.inviteDonePutLocked(app, invite_done_id, .failed, 0);
        }
        sess.shutdown();
        return;
    }
    // relay-инвайт: присутствие с этого момента — marker из
    // контакт-секрета, реконнекты без нового инвайта
    if (relay_addr_len > 0) {
        app.lock();
        defer app.unlock();
        presence.startRelayPresenceLocked(app, cid, relay_addr_buf[0..relay_addr_len]);
    }
    app.lock();
    defer app.unlock();
    const name = app.eng.contacts.items[@intCast(cid - 1)].getName();
    events.evContactJoined(app, cid, name);
    events.evPresence(app, cid, true, app.nowMs());
    // приглашение погашено контактом: CONSUMED + представление — в ревизию
    invites.inviteDonePutLocked(app, invite_done_id, .consumed, @intCast(cid));
    events.bumpContactLocked(app, cid);
}

/// Сессия умерла (её rx-поток завершился и рапортовал сюда). Снимаем
/// привязку с карты — ТОЛЬКО если она всё ещё наша (ребинд мог поставить
/// новую): иначе мёртвый указатель в eng.sessions навсегда блокирует
/// автодозвон и linker (обе петли видят «сессия есть» и не звонят), а
/// каждое sendText молча падает в outbox — «отправится позже» при живых
/// сторонах. Сессию уводим в retired: drain тикера сделает join+destroy.
pub fn onClosed(ctx: *anyopaque) void {
    const sc: *app_mod.SessCtx = @ptrCast(@alignCast(ctx));
    if (sc.cid < 1) {
        // pending-сессия могла оборваться до JOIN и до таймера.
        releasePending(sc);
        return;
    }
    const s = sc.s orelse return;
    const app = sc.app;
    app.lock();
    defer app.unlock();
    const cur = app.eng.sessions.get(sc.cid) orelse return;
    if (cur != s) return; // уже заменена новой сессией — не трогаем
    app.eng.retireSession(sc.cid, s);
    _ = app.sess_ctx.remove(sc.cid);
    // NAT-punch: relay-путь умер — кандидаты и запуск пробития сняты
    // (воркер сам выйдет по отсутствию маршрута)
    _ = app.punch_routes.remove(sc.cid);
    // неподтверждённые партии синхронизации — назад в очередь устройства
    app.sync.onSessionDown(sc.cid);
    if (app.eng.findIndex(sc.cid)) |idx| {
        app.eng.contacts.items[idx].online = false;
        if (app.eng.ev.onPresence) |cb|
            cb(app.eng.ev.ctx, &app.eng.contacts.items[idx], false, app.nowMs());
    }
    // наблюдаемое состояние (2.7.0): сессия потеряна — OFFLINE;
    // ожидание PROFILE-эха больше не имеет смысла
    _ = app.conn_await.remove(sc.cid);
    events.connSetLocked(app, sc.cid, .offline, .none, null);
    events.bumpContactLocked(app, sc.cid);
    // разрыв — немедленная попытка переподключения (а не backoff-ожидание):
    // короткие моргания сети/пира переживаются незаметно для пользователя
    connq.kickConnectLocked(app, sc.cid);
}

pub fn onTextEv(ctx: *anyopaque, from: *const engine_mod.Contact, msg_id: [16]u8, _: i64, body: []const u8, ents: []const envelope.TextEntity) void {
    const app: *App = @ptrCast(@alignCast(ctx));
    const idx = app_mod.contactIndexOf(app, from) orelse return;
    const now = app.nowMs();
    persist.persistMsg(app, @intCast(idx + 1), false, msg_id, null, true, now, body, ents);
    events.evMessageReceived(app, @intCast(idx + 1), msg_id, now, from.getName(), body, ents);
}

pub fn onReplyEv(ctx: *anyopaque, from: *const engine_mod.Contact, msg_id: [16]u8, _: i64, reply_to: [16]u8, body: []const u8, ents: []const envelope.TextEntity) void {
    const app: *App = @ptrCast(@alignCast(ctx));
    const idx = app_mod.contactIndexOf(app, from) orelse return;
    const now = app.nowMs();
    persist.persistMsg(app, @intCast(idx + 1), false, msg_id, reply_to, true, now, body, ents);
    events.evReplyReceived(app, @intCast(idx + 1), msg_id, reply_to, now, from.getName(), body, ents);
}

/// Получен аватар: кэш (память + лог) + событие AVATAR_RECEIVED.
pub fn onAvatarEv(ctx: *anyopaque, from: *const engine_mod.Contact, avatar_id: [16]u8, data: []const u8) void {
    const app: *App = @ptrCast(@alignCast(ctx));
    const idx = app_mod.contactIndexOf(app, from) orelse return;
    // кэш: могли уже положить (дедуп по id)
    if (!app.avatars.contains(avatar_id)) {
        const copy = app.alloc.dupe(u8, data) catch return;
        app.avatars.put(app.alloc, avatar_id, copy) catch {
            app.alloc.free(copy);
            return;
        };
        if (app.log) |log| {
            var buf: [18 + 16000]u8 = undefined;
            @memcpy(buf[0..16], &avatar_id);
            std.mem.writeInt(u16, buf[16..18], @intCast(data.len), .little);
            @memcpy(buf[18 .. 18 + data.len], data);
            _ = log.append(.avatar, buf[0 .. 18 + data.len]) catch {};
        }
    }
    events.evAvatarReceived(app, @intCast(idx + 1), avatar_id, data);
    // avatar_id контакта изменился — представление для дельты/бутстрапа
    events.bumpContactLocked(app, @intCast(idx + 1));
}

/// FILE_META: начать приём файла (состояние под app.mu) и ответить
/// ПОЗИЦИОННЫМ FILE_ACK — отправитель докачивает с нашей позиции:
/// rx уже в полёте → expected_seq; файл сохранён ранее → total (готово);
/// свежий приём → 0.
pub fn onFileMetaEv(ctx: *anyopaque, from: *const engine_mod.Contact, meta: envelope.FileMeta) void {
    const app: *App = @ptrCast(@alignCast(ctx));
    const total: u32 = @intCast(@divTrunc(
        @as(u64, meta.size) + envelope.max_file_chunk - 1,
        envelope.max_file_chunk,
    ));
    var got: u32 = 0;
    if (app.rx_files.get(meta.file_id)) |rx| {
        got = rx.expected_seq; // докачка: пир продолжает с нашей позиции
    } else if (fileAlreadyStored(app, meta.file_id)) {
        got = total; // приняли ранее — отправителю можно завершать
    } else {
        const rx = app.alloc.create(app_mod.RxFile) catch return;
        rx.* = .{ .size = meta.size, .sha = meta.sha };
        const n = @min(meta.name.len, envelope.max_file_name);
        @memcpy(rx.name_buf[0..n], meta.name[0..n]);
        rx.name_len = n;
        app.rx_files.put(app.alloc, meta.file_id, rx) catch {
            app.alloc.destroy(rx);
            return;
        };
    }
    const cid = app_mod.contactIdByBundle(app, from.bundle) orelse return;
    app.eng.sendFileAck(cid, meta.file_id, got) catch {};
}

/// Период подтверждений приёмника (чанков между FILE_ACK) — окно
/// отправителя на той стороне (core/engine.zig, file_tx_window).
pub const rx_ack_every: u32 = 8;

/// Чанк FILE_DATA: копим; по последнему чанку — сверка SHA и сохранение.
/// ВЫЗЫВАЕТСЯ ПОД app.mu (из envIn).
pub fn onFileDataEv(ctx: *anyopaque, from: *const engine_mod.Contact, data: envelope.FileData) void {
    const app: *App = @ptrCast(@alignCast(ctx));
    const cid = app_mod.contactIdByBundle(app, from.bundle) orelse return;
    const rx = app.rx_files.get(data.file_id) orelse return;
    if (data.seq != rx.expected_seq) return; // дубликат/дыра: ждём свой
    rx.expected_seq += 1;
    rx.buf.appendSlice(app.alloc, data.data) catch return;
    // периодический FILE_ACK: отправитель держит окно и позицию докачки
    if (rx.expected_seq % rx_ack_every == 0) {
        app.eng.sendFileAck(cid, data.file_id, rx.expected_seq) catch {};
    }
    if (rx.buf.items.len < rx.size) return;
    if (rx.buf.items.len != rx.size) { // перелив = поломка передачи
        dropRxFile(app, data.file_id);
        return;
    }
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(rx.buf.items, &digest, .{});
    if (!std.mem.eql(u8, &digest, &rx.sha)) { // битые байты
        dropRxFile(app, data.file_id);
        // сообщаем позицию 0: отправитель видит откат и шлёт заново
        app.eng.sendFileAck(cid, data.file_id, 0) catch {};
        return;
    }
    if (!saveRxFile(app, data.file_id, rx.buf.items)) {
        dropRxFile(app, data.file_id);
        return;
    }
    // лог kind FILE — перезапрос после рестарта не нужен
    persist.persistFileMeta(app, @intCast(cid), data.file_id, rx.size, rx.name());
    events.evFileReceived(app, cid, data.file_id, rx.size, rx.name());
    // финальный ACK: все чанки подтверждены — отправитель закрывает передачу
    app.eng.sendFileAck(cid, data.file_id, rx.expected_seq) catch {};
    dropRxFile(app, data.file_id);
}

/// FILE_SENT от движка: исходящий файл передан целиком — все чанки
/// подтверждены FILE_ACK-ами получателя (состояние передачи ведёт движок,
/// app только рассылает событие GUI). ВЫЗЫВАЕТСЯ ПОД app.mu (из envIn).
pub fn onFileSentEv(ctx: *anyopaque, from: *const engine_mod.Contact, file_id: [16]u8, size: u32, name: []const u8) void {
    const app: *App = @ptrCast(@alignCast(ctx));
    const cid = app_mod.contactIdByBundle(app, from.bundle) orelse return;
    events.evFileSent(app, cid, file_id, size, name);
}

pub fn dropRxFile(app: *App, file_id: [16]u8) void {
    const rx = app.rx_files.get(file_id) orelse return;
    _ = app.rx_files.remove(file_id);
    rx.buf.deinit(app.alloc);
    std.crypto.secureZero(u8, &rx.sha);
    app.alloc.destroy(rx);
}

/// Файл уже сохранён? (кэш ~/.stille-messenger/files/<id_hex32>)
pub fn fileAlreadyStored(app: *App, file_id: [16]u8) bool {
    var hxb: [32]u8 = undefined;
    const hx = paths.toHex(&hxb, &file_id) catch return false;
    var fbuf: [700]u8 = undefined;
    const path = std.fmt.bufPrint(&fbuf, "{s}/{s}/files/{s}", .{ paths.appHomeDir(app), paths.data_dir_name, hx }) catch return false;
    var zbuf: [701]u8 = undefined;
    @memcpy(zbuf[0..path.len], path);
    zbuf[path.len] = 0;
    return sysfd.fileExists(@ptrCast(&zbuf));
}

/// Сохранить принятый файл (SHA уже сверена). true = записан.
pub fn saveRxFile(app: *App, file_id: [16]u8, bytes: []const u8) bool {
    var hxb: [32]u8 = undefined;
    const hx = paths.toHex(&hxb, &file_id) catch return false;
    var pbuf: [600]u8 = undefined;
    const dir = std.fmt.bufPrint(&pbuf, "{s}/{s}/files", .{ paths.appHomeDir(app), paths.data_dir_name }) catch return false;
    var zbuf: [601]u8 = undefined;
    @memcpy(zbuf[0..dir.len], dir);
    zbuf[dir.len] = 0;
    sysfd.makeDir700(@ptrCast(&zbuf)); // EEXIST — не ошибка
    var fbuf: [700]u8 = undefined;
    const path = std.fmt.bufPrint(&fbuf, "{s}/{s}", .{ dir, hx }) catch return false;
    var zbuf2: [701]u8 = undefined;
    @memcpy(zbuf2[0..path.len], path);
    zbuf2[path.len] = 0;
    const fd = sysfd.createFile600(@ptrCast(&zbuf2)) orelse return false;
    defer sysfd.close(fd);
    sysfd.writeAll(fd, bytes) catch return false;
    return true;
}

/// Пир просит аватар с id: перекачать, если это наш текущий.
pub fn onAvatarReqEv(ctx: *anyopaque, from: *const engine_mod.Contact, avatar_id: [16]u8) void {
    const app: *App = @ptrCast(@alignCast(ctx));
    const idx = app_mod.contactIndexOf(app, from) orelse return;
    const cid: i64 = @intCast(idx + 1);
    // наш текущий аватар? (самоисцеление: profile сказал id, мы перекачали)
    if (!std.mem.eql(u8, &app.eng.my_avatar_id, &avatar_id)) return;
    const data = app.avatars.get(avatar_id) orelse return;
    _ = app.eng.sendAvatar(cid, data) catch {};
}

/// ACK дошёл: сообщение доставлено на устройство пир-а.
pub fn onDeliveredEv(ctx: *anyopaque, from: *const engine_mod.Contact, msg_id: [16]u8) void {
    const app: *App = @ptrCast(@alignCast(ctx));
    const idx = app_mod.contactIndexOf(app, from) orelse return;
    const cid: i64 = @intCast(idx + 1);
    persist.persistOutboxAck(app, cid, msg_id);
    events.evMessageDelivered(app, cid, msg_id);
}

pub fn onReactionEv(ctx: *anyopaque, from: *const engine_mod.Contact, r: engine_mod.Reaction) void {
    const app: *App = @ptrCast(@alignCast(ctx));
    const idx = app_mod.contactIndexOf(app, from) orelse return;
    persist.persistReact(app, @intCast(idx + 1), false, r.msg_id, r.op, r.code, app.nowMs());
    events.evReaction(app, @intCast(idx + 1), r.msg_id, r.op, r.code, app.nowMs());
}

pub fn onPresenceEv(ctx: *anyopaque, from: *const engine_mod.Contact, online: bool, last_seen_ms: i64) void {
    const app: *App = @ptrCast(@alignCast(ctx));
    const idx = app_mod.contactIndexOf(app, from) orelse return;
    const cid: i64 = @intCast(idx + 1);
    events.evPresence(app, cid, online, last_seen_ms);
    // наблюдаемое состояние (2.7.0): presence flip синхронизирует conn_st
    // (кроме JOINING — ждём PROFILE-эхо подтверждения добавления)
    if (!app.conn_await.contains(cid)) {
        events.connSetLocked(app, cid, if (online) .online else .offline, .none, null);
    }
    events.bumpContactLocked(app, cid);
}

pub fn onProfileEv(ctx: *anyopaque, from: *const engine_mod.Contact, name: []const u8, avatar_id: [16]u8) void {
    const app: *App = @ptrCast(@alignCast(ctx));
    const idx = app_mod.contactIndexOf(app, from) orelse return;
    const cid: i64 = @intCast(idx + 1);
    events.evContactProfile(app, cid, name, avatar_id);
    // PROFILE-эхо: пир жив и обработал наш JOIN (если ждали) — добавление
    // подтверждено. Эвристика, НЕ криптографическая квитанция.
    if (app.conn_await.remove(cid)) {
        events.connSetLocked(app, cid, .online, .none, null);
    }
    events.bumpContactLocked(app, cid);
}

/// CONTACT_CARD от пира: визитка третьего лица — наружу событием.
pub fn onContactCardEv(ctx: *anyopaque, from: *const engine_mod.Contact, name: []const u8, bundle: [64]u8, addr: []const u8) void {
    const app: *App = @ptrCast(@alignCast(ctx));
    const idx = app_mod.contactIndexOf(app, from) orelse return;
    events.evContactCard(app, @intCast(idx + 1), name, bundle, addr);
}

pub fn onBlockedEv(ctx: *anyopaque, from: *const engine_mod.Contact) void {
    const app: *App = @ptrCast(@alignCast(ctx));
    const idx = app_mod.contactIndexOf(app, from) orelse return;
    events.evBlockedByPeer(app, @intCast(idx + 1));
}

/// Окно pending-join: 3 с на валидный JOIN, иначе сессия закрывается.
pub fn releasePendingLocked(sc: *app_mod.SessCtx) void {
    if (!sc.pending_counted) return;
    const app = sc.app;
    if (app.pending_sessions > 0) app.pending_sessions -= 1;
    sc.pending_counted = false;
}

pub fn releasePending(sc: *app_mod.SessCtx) void {
    const app = sc.app;
    app.lock();
    releasePendingLocked(sc);
    app.unlock();
}

/// Окно pending-join: 3 с на валидный JOIN, иначе сессия закрывается.
pub fn joinTimeoutWatch(sc: *app_mod.SessCtx) void {
    sysfd.sleepMs(3000);
    const app = sc.app;
    app.lock();
    const still_pending = sc.cid == -1;
    app.unlock();
    if (still_pending) {
        releasePending(sc);
        if (sc.s) |sp| sp.close();
    }
}
