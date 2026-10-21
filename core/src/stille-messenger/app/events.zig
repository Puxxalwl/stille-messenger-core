//! События API-клиентам (ev*) и наблюдаемое состояние контактов:
//! стадии коннов, кольцо дельты, контактные view. Всё вызывается
//! ПОД app.mu (список коннов живёт под этим локом).
const std = @import("std");
const stille_messenger = @import("stille-messenger");
const envelope = stille_messenger.proto.envelope;
const session_mod = stille_messenger.core.session;
const api_srv = @import("api_server.zig");
const api = @import("api.zig");
const invite_mod = @import("invite.zig");
const app_mod = @import("app.zig");
const connq = @import("connq.zig");
const persist = @import("persist.zig");
const dispatch = @import("dispatch.zig");
const config_mod = stille_messenger.app.config;
pub const App = app_mod.App;

// ------------------------------------------------- события API (клиентам)
// Все evXxx собирают бинарный payload и рассылают его всем подключённым
// GUI-клиентам. ВЫЗЫВАТЬ ПОД app.mu: список conns живёт под этим локом.

/// MESSAGE_RECEIVED: входящее сообщение контакта. После body — хвост
/// entities форматирования ([ent_count u8] × {entity}, канонический формат
/// proto/envelope.zig); форматирования нет — один байт счётчика 0.
pub fn evMessageReceived(app: *App, cid: i64, msg_id: [16]u8, ts_ms: i64, name: []const u8, body: []const u8, ents: []const envelope.TextEntity) void {
    var w = api.Writer.init(app.alloc);
    defer w.deinit();
    w.putU32(@intCast(cid)) catch return;
    w.putBytes(&msg_id) catch return;
    w.putU64(@intCast(ts_ms)) catch return;
    w.putStr16(name) catch return;
    w.putStr16(body) catch return;
    putEntities(&w, body.len, ents) catch return;
    api_srv.fanoutEventLocked(app.cli, .MESSAGE_RECEIVED, w.items());
}

pub fn evReplyReceived(app: *App, cid: i64, msg_id: [16]u8, reply_to: [16]u8, ts_ms: i64, name: []const u8, body: []const u8, ents: []const envelope.TextEntity) void {
    var w = api.Writer.init(app.alloc);
    defer w.deinit();
    w.putU32(@intCast(cid)) catch return;
    w.putBytes(&msg_id) catch return;
    w.putBytes(&reply_to) catch return;
    w.putU64(@intCast(ts_ms)) catch return;
    w.putStr16(name) catch return;
    w.putStr16(body) catch return;
    putEntities(&w, body.len, ents) catch return;
    api_srv.fanoutEventLocked(app.cli, .REPLY_RECEIVED, w.items());
}

/// Хвост entities в payload ответа/события: те же канонические байты,
/// что на проводе TEXT и в логе. Ошибка валидации (не должно случаться —
/// движок уже валидировал) — счётчик 0.
pub fn putEntities(w: *api.Writer, body_len: usize, ents: []const envelope.TextEntity) !void {
    var tail_buf: [envelope.max_text_tail]u8 = undefined;
    const tail = envelope.encodeEntitiesTail(&tail_buf, ents, body_len) catch {
        try w.putU8(0);
        return;
    };
    try w.putBytes(tail);
}

/// MESSAGE_DELIVERED: ACK — сообщение дошло до устройства пира.
pub fn evMessageDelivered(app: *App, cid: i64, msg_id: [16]u8) void {
    var w = api.Writer.init(app.alloc);
    defer w.deinit();
    w.putU32(@intCast(cid)) catch return;
    w.putBytes(&msg_id) catch return;
    api_srv.fanoutEventLocked(app.cli, .MESSAGE_DELIVERED, w.items());
}

/// PRESENCE: контакт на связи / пропал.
pub fn evPresence(app: *App, cid: i64, online: bool, last_seen_ms: i64) void {
    var w = api.Writer.init(app.alloc);
    defer w.deinit();
    w.putU32(@intCast(cid)) catch return;
    w.putU8(@intFromBool(online)) catch return;
    w.putI64(last_seen_ms) catch return;
    api_srv.fanoutEventLocked(app.cli, .PRESENCE, w.items());
}

/// REACTION: реакция пира на сообщение (op: react_add/react_remove).
pub fn evReaction(app: *App, cid: i64, msg_id: [16]u8, op: u8, code: u32, ts_ms: i64) void {
    var w = api.Writer.init(app.alloc);
    defer w.deinit();
    w.putU32(@intCast(cid)) catch return;
    w.putBytes(&msg_id) catch return;
    w.putU8(op) catch return;
    w.putU32(code) catch return;
    w.putU64(@intCast(ts_ms)) catch return;
    api_srv.fanoutEventLocked(app.cli, .REACTION, w.items());
}

/// CALL_STATE: перемена состояния звонка.
pub fn evCallState(app: *App, cid: i64, call_id: [16]u8, state: api.CallState) void {
    var w = api.Writer.init(app.alloc);
    defer w.deinit();
    w.putU32(@intCast(cid)) catch return;
    w.putBytes(&call_id) catch return;
    w.putU8(@backingInt(state)) catch return;
    api_srv.fanoutEventLocked(app.cli, .CALL_STATE, w.items());
}

/// AVATAR_RECEIVED: байты аватара пира (клиент кэширует по avatar_id).
pub fn evAvatarReceived(app: *App, cid: i64, avatar_id: [16]u8, data: []const u8) void {
    var w = api.Writer.init(app.alloc);
    defer w.deinit();
    w.putU32(@intCast(cid)) catch return;
    w.putBytes(&avatar_id) catch return;
    w.putStr16(data) catch return;
    api_srv.fanoutEventLocked(app.cli, .AVATAR_RECEIVED, w.items());
}

/// FILE_SENT: исходящий файл передан целиком — все чанки подтверждены
/// FILE_ACK-ами получателя.
pub fn evFileSent(app: *App, cid: i64, file_id: [16]u8, size: u32, name: []const u8) void {
    var w = api.Writer.init(app.alloc);
    defer w.deinit();
    w.putU32(@intCast(cid)) catch return;
    w.putBytes(&file_id) catch return;
    w.putU32(size) catch return;
    w.putStr16(name) catch return;
    api_srv.fanoutEventLocked(app.cli, .FILE_SENT, w.items());
}

/// FILE_RECEIVED: файл принят целиком (байты в ~/.stille-messenger/files).
pub fn evFileReceived(app: *App, cid: i64, file_id: [16]u8, size: u32, name: []const u8) void {
    var w = api.Writer.init(app.alloc);
    defer w.deinit();
    w.putU32(@intCast(cid)) catch return;
    w.putBytes(&file_id) catch return;
    w.putU32(size) catch return;
    w.putStr16(name) catch return;
    api_srv.fanoutEventLocked(app.cli, .FILE_RECEIVED, w.items());
}

/// CONTACT_JOINED: держатель кода погасил наш инвайт.
pub fn evContactJoined(app: *App, cid: i64, name: []const u8) void {
    var w = api.Writer.init(app.alloc);
    defer w.deinit();
    w.putU32(@intCast(cid)) catch return;
    w.putStr16(name) catch return;
    api_srv.fanoutEventLocked(app.cli, .CONTACT_JOINED, w.items());
}

/// CONTACT_PROFILE: имя/avatar_id контакта обновились (эхо PROFILE).
pub fn evContactProfile(app: *App, cid: i64, name: []const u8, avatar_id: [16]u8) void {
    var w = api.Writer.init(app.alloc);
    defer w.deinit();
    w.putU32(@intCast(cid)) catch return;
    w.putStr16(name) catch return;
    w.putBytes(&avatar_id) catch return;
    api_srv.fanoutEventLocked(app.cli, .CONTACT_PROFILE, w.items());
}

/// CONTACT_CARD: пир переслал визитку третьего лица.
pub fn evContactCard(app: *App, cid: i64, name: []const u8, bundle: [64]u8, addr: []const u8) void {
    var w = api.Writer.init(app.alloc);
    defer w.deinit();
    w.putU32(@intCast(cid)) catch return;
    w.putStr16(name) catch return;
    w.putBytes(&bundle) catch return;
    w.putStr16(addr) catch return;
    api_srv.fanoutEventLocked(app.cli, .CONTACT_CARD, w.items());
}

/// BLOCKED_BY_PEER: пир заблокировал нас.
pub fn evBlockedByPeer(app: *App, cid: i64) void {
    var w = api.Writer.init(app.alloc);
    defer w.deinit();
    w.putU32(@intCast(cid)) catch return;
    api_srv.fanoutEventLocked(app.cli, .BLOCKED_BY_PEER, w.items());
}

/// CONFIG_CHANGED: конфигурация изменилась (SET_CONFIG, в т.ч. применённая
/// с другого устройства). Payload — blob формата config.zig.
pub fn evConfigChanged(app: *App) void {
    var buf: [config_mod.blob_max]u8 = undefined;
    const blob = app.cfg.encode(&buf) catch return;
    api_srv.fanoutEventLocked(app.cli, .CONFIG_CHANGED, blob);
}

// ----------------------------- наблюдаемое подключение (2.7.0 / 0.3.0)

/// CONTACT_STATE_CHANGED (только подписанным): [epoch 16][revision u64]
/// [cid u32][state u8][attempt u32][last_error u16][next_retry_ms u32].
/// ВЫЗЫВАТЬ ПОД app.mu.
pub fn evContactStateChangedLocked(app: *App, cid: i64) void {
    var w = api.Writer.init(app.alloc);
    defer w.deinit();
    w.putBytes(&app.contacts_epoch) catch return;
    w.putU64(app.contacts_rev) catch return;
    w.putU32(@intCast(cid)) catch return;
    const e = app.conn_st.get(cid) orelse app_mod.ConnEntry{};
    w.putU8(e.state) catch return;
    w.putU32(e.attempt) catch return;
    w.putU16(e.last_error) catch return;
    w.putU32(connq.retryRemainingMs(e.next_retry_at, app.nowMs())) catch return;
    api_srv.fanoutSubEventLocked(app.cli, .CONTACT_STATE_CHANGED, w.items());
}

/// CONTACT_UPSERTED (только подписанным): [epoch 16][revision u64]
/// [cid u32] + contact_view. ВЫЗЫВАТЬ ПОД app.mu.
pub fn evContactUpsertedLocked(app: *App, cid: i64) void {
    var w = api.Writer.init(app.alloc);
    defer w.deinit();
    w.putBytes(&app.contacts_epoch) catch return;
    w.putU64(app.contacts_rev) catch return;
    w.putU32(@intCast(cid)) catch return;
    putContactViewLocked(app, &w, cid) catch return;
    api_srv.fanoutSubEventLocked(app.cli, .CONTACT_UPSERTED, w.items());
}

/// CONTACTS_CHANGED (только подписанным): [epoch 16][revision u64] —
/// «представление изменилось, вытяни delta» (removal и объёмные случаи).
/// ВЫЗЫВАТЬ ПОД app.mu.
pub fn evContactsChangedLocked(app: *App) void {
    var w = api.Writer.init(app.alloc);
    defer w.deinit();
    w.putBytes(&app.contacts_epoch) catch return;
    w.putU64(app.contacts_rev) catch return;
    api_srv.fanoutSubEventLocked(app.cli, .CONTACTS_CHANGED, w.items());
}

/// Контакт ещё НЕ подтверждён пиром: JOIN не отправлен или PROFILE-эхо
/// после JOIN не получено. Имя такого контакта — локальная подсказка из
/// кода, НЕ аутентифицированный профиль. ВЫЗЫВАТЬ ПОД app.mu.
pub fn contactPendingLocked(app: *App, cid: i64) bool {
    return app.join_map.contains(cid) or app.conn_await.contains(cid);
}

/// Верхняя граница сериализованного contact_view (бюджет кадра:
/// 4+1+8+2+32+16+1+4+2+4 = 74 байта + str16-заголовок учтён).
pub const contact_view_size: usize = 4 + 1 + 8 + 2 + invite_mod.max_name + 16 + 1 + 4 + 2 + 4;

/// Эффективное состояние подключения контакта (view-семантика): запись
/// есть — её значение; нет — по факту сессии (online/offline).
/// ВЫЗЫВАТЬ ПОД app.mu.
pub fn connStateOfLocked(app: *App, cid: i64) api.ConnState {
    if (app.conn_st.get(cid)) |e| return @fromBackingInt(@intCast(e.state));
    const idx = app.eng.findIndex(cid) orelse return .offline;
    return if (app.eng.contacts.items[idx].online) .online else .offline;
}

/// Записать contact_view в сборщик ответа: [cid u32][flags u8 bit0 online
/// bit1 blocked bit2 pending][last_seen_ms i64][name str16][avatar_id 16]
/// [state u8][attempt u32][last_error u16][next_retry_ms u32].
/// ВЫЗЫВАТЬ ПОД app.mu.
pub fn putContactViewLocked(app: *App, w: *api.Writer, cid: i64) !void {
    const idx = app.eng.findIndex(cid) orelse return error.NoContact;
    const c = &app.eng.contacts.items[idx];
    var flags: u8 = 0;
    if (c.online) flags |= 1;
    if (c.blocked) flags |= 2;
    if (contactPendingLocked(app, cid)) flags |= 4;
    const seen: i64 = app.eng.lastSeen(cid) orelse 0;
    const e = app.conn_st.get(cid) orelse app_mod.ConnEntry{};
    const state: api.ConnState = connStateOfLocked(app, cid);
    try w.putU32(@intCast(cid));
    try w.putU8(flags);
    try w.putI64(seen);
    try w.putStr16(c.getName());
    try w.putBytes(&c.avatar_id);
    try w.putU8(@backingInt(state));
    try w.putU32(e.attempt);
    try w.putU16(e.last_error);
    try w.putU32(connq.retryRemainingMs(e.next_retry_at, app.nowMs()));
}

/// Добавить запись в кольцо изменений (app.mu): новая ревизия.
pub fn ringAppendLocked(app: *App, kind: api.DeltaChange, cid: i64) void {
    app.contacts_rev += 1;
    const slot = &app.contacts_ring[app.contacts_ring_pos];
    slot.* = .{ .rev = app.contacts_rev, .kind = @backingInt(kind), .cid = @intCast(cid) };
    app.contacts_ring_pos = (app.contacts_ring_pos + 1) % app_mod.contact_ring_cap;
    if (app.contacts_ring_len < app_mod.contact_ring_cap) app.contacts_ring_len += 1;
}

/// Представление контакта изменилось (профиль/presence/avatar/блокировка):
/// ревизия + кольцо + CONTACT_UPSERTED подписанным. ВЫЗЫВАТЬ ПОД app.mu.
pub fn bumpContactLocked(app: *App, cid: i64) void {
    ringAppendLocked(app, .upsert, cid);
    evContactUpsertedLocked(app, cid);
}

/// Чат удалён: ревизия + кольцо (removed) + CONTACTS_CHANGED. ВЫЗЫВАТЬ
/// ПОД app.mu.
pub fn bumpRemovedLocked(app: *App, cid: i64) void {
    ringAppendLocked(app, .removed, cid);
    evContactsChangedLocked(app);
}

/// Смена полей СОСТОЯНИЯ подключения: ревизия + кольцо (view включает
/// state) + CONTACT_STATE_CHANGED подписанным. gen — поколение попытки
/// работника (null — системные переходы: bind/close/profile). Переход
/// опоздавшего поколения молча игнорируется. ВЫЗЫВАТЬ ПОД app.mu.
pub fn connSetLocked(app: *App, cid: i64, state: api.ConnState, err: api.ConnErr, gen: ?u32) void {
    const gop = app.conn_st.getOrPut(app.alloc, cid) catch return;
    if (!gop.found_existing) gop.value_ptr.* = .{};
    if (gen) |g| {
        if (gop.found_existing and g != gop.value_ptr.gen) return;
        if (!gop.found_existing and g != 1) return;
    }
    const e = gop.value_ptr;
    if (e.state == @backingInt(state) and e.last_error == @backingInt(err)) return;
    e.state = @backingInt(state);
    e.last_error = @backingInt(err);
    if (e.next_retry_at != 0 and state != .failed) e.next_retry_at = 0;
    ringAppendLocked(app, .upsert, cid);
    evContactStateChangedLocked(app, cid);
}

/// Начало новой попытки подключения (dial): attempt += 1, gen += 1,
/// состояние dialing. Возвращает поколение для меток работника.
/// ВЫЗЫВАТЬ ПОД app.mu.
pub fn connBeginAttemptLocked(app: *App, cid: i64) u32 {
    const gop = app.conn_st.getOrPut(app.alloc, cid) catch return 0;
    gop.value_ptr.attempt += 1;
    gop.value_ptr.gen += 1;
    gop.value_ptr.state = @backingInt(api.ConnState.dialing);
    gop.value_ptr.last_error = @backingInt(api.ConnErr.none);
    gop.value_ptr.next_retry_at = 0;
    ringAppendLocked(app, .upsert, cid);
    evContactStateChangedLocked(app, cid);
    return gop.value_ptr.gen;
}

/// Контакт уходит в DISCOVERING (ждёт LAN-анонс пира; адреса нет).
/// ВЫЗЫВАТЬ ПОД app.mu.
pub fn connDiscoveringLocked(app: *App, cid: i64) void {
    connSetLocked(app, cid, .discovering, .none, null);
}
