//! API-обработчики демона (методы UDS-апи, кроме приглашений/звонков/
//! восстановления, живущих в своих модулях). Один метод — одна функция,
//! ровно один ответ через dispatch.
const std = @import("std");
const stille_messenger = @import("stille-messenger");
const engine_mod = stille_messenger.core.engine;
const envelope = stille_messenger.proto.envelope;
const store_mod = stille_messenger.store.log;
const sync_mod = stille_messenger.app.sync;
const config_mod = stille_messenger.app.config;
const endpoints_mod = @import("endpoints.zig");
const search_mod = @import("search.zig");
const recovery_mod = @import("recovery.zig");
const api = @import("api.zig");
const app_mod = @import("app.zig");
const dispatch = @import("dispatch.zig");
const invite_mod = @import("invite.zig");
const recovery_codec = stille_messenger.crypto.recovery;
const api_srv = @import("api_server.zig");
const upnp_mod = stille_messenger.net.upnp;
const tcp = stille_messenger.net.tcp;
const routes = @import("routes.zig");
const sysfd = stille_messenger.net.sysfd;
const session_mod = stille_messenger.core.session;
pub const App = app_mod.App;
const events = @import("events.zig");
const connq = @import("connq.zig");
const invites = @import("invites.zig");
const calls = @import("calls.zig");
const persist = @import("persist.zig");
const sync_apply = @import("sync_apply.zig");
const paths = @import("paths.zig");
const presence = @import("presence.zig");
const dial = @import("dial.zig");

/// GET_IDENTITY: свои публичные данные (сверка отпечатка голосом/QR).
/// Ответ: [bundle 64][fingerprint 32]. На непровиженном профиле —
/// NOT_INITIALIZED: GUI показывает онбординг, а не эфемерный bundle.
pub fn apiGetIdentity(app: *App, payload: []const u8, w: *api.Writer) api.Status {
    if (payload.len != 0) return .BAD_FRAME;
    app.lock();
    defer app.unlock();
    if (!app.provisioned) return .NOT_INITIALIZED;
    const bundle = app.id.bundle();
    var digest: [32]u8 = undefined;
    std.crypto.hash.blake2.Blake2s256.hash(&bundle, &digest, .{});
    w.putBytes(&bundle) catch return .INTERNAL;
    w.putBytes(&digest) catch return .INTERNAL;
    return .OK;
}

/// LIST_CONTACTS: все контакты. Ответ:
/// [count u32] × {[cid u32][flags u8 bit0 online bit1 blocked]
/// [last_seen_ms i64 (0 = неизвестно)][name str16]}.
pub fn apiListContacts(app: *App, payload: []const u8, w: *api.Writer) api.Status {
    if (payload.len != 0) return .BAD_FRAME;
    const max_contacts = 10000;
    app.lock();
    defer app.unlock();
    if (app.eng.contacts.items.len > max_contacts) return .TOO_BIG;
    // удалённые чаты (слоты-надгробия) в списке не видны
    var n: usize = 0;
    for (app.eng.contacts.items) |c| {
        if (!c.deleted) n += 1;
    }
    w.putU32(@intCast(n)) catch return .INTERNAL;
    for (app.eng.contacts.items, 0..) |c, i| {
        if (c.deleted) continue;
        const cid: i64 = @intCast(i + 1);
        var flags: u8 = 0;
        if (c.online) flags |= 1;
        if (c.blocked) flags |= 2;
        const seen: i64 = app.eng.lastSeen(cid) orelse 0;
        w.putU32(@intCast(cid)) catch return .INTERNAL;
        w.putU8(flags) catch return .INTERNAL;
        w.putI64(seen) catch return .INTERNAL;
        w.putStr16(c.getName()) catch return .INTERNAL;
    }
    return .OK;
}

/// SEND_MESSAGE: payload [cid u32][body str16 ≤4096][ent_count u8]
/// × {[kind u8][offset u16][len u16][value_len u8][value]}.
/// Ответ: [msg_id 16][flags u8 (bit0 = queued)]. Отправка офлайн — НЕ ошибка.
pub fn apiSendMessage(app: *App, payload: []const u8, w: *api.Writer) api.Status {
    var r = api.Reader.init(payload);
    const cid = r.readU32() catch return .BAD_FRAME;
    const body = r.readStr16() catch return .BAD_FRAME;
    if (body.len == 0 or body.len > envelope.max_text_body) return .BAD_ARGS;
    // хвост entities = остаток payload (структурно обрезан — BAD_FRAME,
    // семантика неверна — BAD_ARGS)
    var ents: [envelope.max_text_entities]envelope.TextEntity = undefined;
    const n = envelope.parseEntities(r.buf[r.pos..], body.len, &ents) catch |e| switch (e) {
        error.Truncated, error.BadLen => return .BAD_FRAME,
        else => return .BAD_ARGS,
    };
    app.lock();
    defer app.unlock();
    if (cid < 1 or cid > app.eng.contacts.items.len) return .NO_CONTACT;
    if (app.eng.contacts.items[cid - 1].deleted) return .NO_CONTACT;
    const oc = app.eng.sendText(@intCast(cid), body, ents[0..n]) catch |e| return dispatch.statusOf(e);
    // delivered в истории = подтверждено ACK (не «улетело в сокет»):
    // погашение пишет persistOutboxAck по событию MESSAGE_DELIVERED
    persist.persistMsg(app, @intCast(cid), true, oc.msg_id, null, false, app.nowMs(), body, ents[0..n]);
    if (oc.result == .queued) {
        persist.persistOutboxAdd(app);
        // офлайн-получатель: dial НЕМЕДЛЕННО (в очередь планировщика),
        // без ожидания циклов автодозвона/обнаружения
        connq.kickConnectLocked(app, @intCast(cid));
    }
    w.putBytes(&oc.msg_id) catch return .INTERNAL;
    w.putU8(if (oc.result == .queued) 1 else 0) catch return .INTERNAL;
    return .OK;
}

/// SEND_REPLY_MESSAGE: payload [cid u32][reply_to_msg_hex str16][body str16]
/// followed by the same entity tail as SEND_MESSAGE. The reference is exactly
/// 32 hexadecimal characters and must identify a message in this chat.
pub fn apiSendReplyMessage(app: *App, payload: []const u8, w: *api.Writer) api.Status {
    var r = api.Reader.init(payload);
    const cid = r.readU32() catch return .BAD_FRAME;
    const ref = r.readStr16() catch return .BAD_FRAME;
    const reply_to = paths.parseMsgIdHex(ref) orelse return .BAD_ARGS;
    const body = r.readStr16() catch return .BAD_FRAME;
    if (body.len == 0 or body.len > envelope.max_text_body) return .BAD_ARGS;
    var ents: [envelope.max_text_entities]envelope.TextEntity = undefined;
    const n = envelope.parseEntities(r.buf[r.pos..], body.len, &ents) catch |e| switch (e) {
        error.Truncated, error.BadLen => return .BAD_FRAME,
        else => return .BAD_ARGS,
    };
    app.lock();
    defer app.unlock();
    if (cid < 1 or cid > app.eng.contacts.items.len) return .NO_CONTACT;
    if (app.eng.contacts.items[cid - 1].deleted) return .NO_CONTACT;
    const target = app.hist_idx.get(reply_to) orelse return .NOT_FOUND;
    const target_rec = app.hist.items[target];
    if (std.mem.readInt(u16, target_rec[0..2], .little) != cid) return .NOT_FOUND;
    const oc = app.eng.sendReplyText(@intCast(cid), reply_to, body, ents[0..n]) catch |e| return dispatch.statusOf(e);
    persist.persistMsg(app, @intCast(cid), true, oc.msg_id, reply_to, false, app.nowMs(), body, ents[0..n]);
    if (oc.result == .queued) {
        persist.persistOutboxAdd(app);
        // офлайн-получатель: dial немедленно, как в SEND_MESSAGE
        connq.kickConnectLocked(app, @intCast(cid));
    }
    w.putBytes(&oc.msg_id) catch return .INTERNAL;
    w.putU8(if (oc.result == .queued) 1 else 0) catch return .INTERNAL;
    return .OK;
}

/// SET_REACTION / REMOVE_REACTION: payload [cid u32][msg_id 16][codepoint u32].
/// codepoint вне U+0000..U+10FFFF — UNSUPPORTED_REACTION. Ответ пуст.
pub fn apiReaction(app: *App, payload: []const u8, add: bool) api.Status {
    var r = api.Reader.init(payload);
    const cid = r.readU32() catch return .BAD_FRAME;
    const mid: [16]u8 = (r.readBytes(16) catch return .BAD_FRAME)[0..16].*;
    const code = r.readU32() catch return .BAD_FRAME;
    if (r.hasMore()) return .BAD_FRAME;
    if (code > 0x10FFFF) return .UNSUPPORTED_REACTION;
    app.lock();
    defer app.unlock();
    if (cid < 1 or cid > app.eng.contacts.items.len) return .NO_CONTACT;
    const op: u8 = if (add) envelope.react_add else envelope.react_remove;
    app.eng.react(@intCast(cid), mid, op, code) catch |e| return dispatch.statusOf(e);
    persist.persistReact(app, @intCast(cid), true, mid, op, code, app.nowMs());
    return .OK;
}

/// BLOCK_CONTACT / UNBLOCK_CONTACT: payload [cid u32]. Ответ пуст.
pub fn apiBlock(app: *App, payload: []const u8, flag: bool) api.Status {
    var r = api.Reader.init(payload);
    const cid = r.readU32() catch return .BAD_FRAME;
    if (r.hasMore()) return .BAD_FRAME;
    app.lock();
    defer app.unlock();
    if (cid < 1 or cid > app.eng.contacts.items.len) return .NO_CONTACT;
    if (flag) {
        app.eng.block(@intCast(cid)) catch |e| return dispatch.statusOf(e);
    } else {
        app.eng.unblock(@intCast(cid)) catch |e| return dispatch.statusOf(e);
        // разблокировка: вернуть релей-присутствие, если было
        if (app.contact_relays.get(@as(i64, @intCast(cid)))) |ra| {
            presence.startRelayPresenceLocked(app, @intCast(cid), ra);
        }
    }
    if (app.log) |log| {
        var buf: [65]u8 = undefined;
        @memcpy(buf[0..64], &app.eng.contacts.items[cid - 1].bundle);
        buf[64] = @intFromBool(flag);
        _ = log.append(.block, &buf) catch {};
        persist.syncEnqueue(app, @backingInt(sync_mod.RecKind.block), &buf);
        persist.syncPumpLocked(app);
    }
    // 2.7.0: флаг блокировки — часть представления контакта
    events.bumpContactLocked(app, @intCast(cid));
    return .OK;
}

// --------------------------------------------- закрепления и удаление чатов

/// PIN_CHAT (25): [cid u32] → ∅. Закреплённый чат один на ядро,
/// переживает рестарт (set:3/set:4).
pub fn apiPinChat(app: *App, payload: []const u8, w: *api.Writer) api.Status {
    _ = w;
    var r = api.Reader.init(payload);
    const cid = r.readU32() catch return .BAD_FRAME;
    if (r.hasMore()) return .BAD_FRAME;
    app.lock();
    defer app.unlock();
    if (cid < 1 or cid > app.eng.contacts.items.len) return .NO_CONTACT;
    if (app.eng.contacts.items[cid - 1].deleted) return .NO_CONTACT;
    app.pinned_chat = cid;
    if (app.log) |log| {
        var buf: [3]u8 = undefined;
        buf[0] = 3;
        std.mem.writeInt(u16, buf[1..3], @intCast(cid), .little);
        _ = log.append(.set, &buf) catch {};
    }
    return .OK;
}

/// GET_PINNED_CHAT (26): ∅ → [cid u32] (0 — не закреплено).
pub fn apiGetPinnedChat(app: *App, payload: []const u8, w: *api.Writer) api.Status {
    if (payload.len != 0) return .BAD_FRAME;
    app.lock();
    defer app.unlock();
    var cid: u32 = 0;
    if (app.pinned_chat >= 1 and app.pinned_chat <= app.eng.contacts.items.len) {
        if (!app.eng.contacts.items[@intCast(app.pinned_chat - 1)].deleted) {
            cid = @intCast(app.pinned_chat);
        }
    }
    w.putU32(cid) catch return .INTERNAL;
    return .OK;
}

/// UNPIN_CHAT (27): ∅ → ∅. Идемпотентно.
pub fn apiUnpinChat(app: *App, payload: []const u8, w: *api.Writer) api.Status {
    _ = w;
    if (payload.len != 0) return .BAD_FRAME;
    app.lock();
    defer app.unlock();
    app.pinned_chat = 0;
    if (app.log) |log| {
        const buf = [_]u8{4};
        _ = log.append(.set, &buf) catch {};
    }
    return .OK;
}

/// DELETE_CHAT (28): [cid u32] → ∅. Слот контакта остаётся (cid стабильны
/// до рестарта), но контакт невидим и мёртв: сессия снята, outbox/файлы/
/// история/закрепления очищены, автодозвон и линкер его не трогают.
/// Переживает рестарт (set:7 по bundle). Повторное знакомство — новый cid
/// с чистой историей.
pub fn apiDeleteChat(app: *App, payload: []const u8, w: *api.Writer) api.Status {
    _ = w;
    var r = api.Reader.init(payload);
    const cid = r.readU32() catch return .BAD_FRAME;
    if (r.hasMore()) return .BAD_FRAME;
    app.lock();
    defer app.unlock();
    if (cid < 1 or cid > app.eng.contacts.items.len) return .NO_CONTACT;
    const c = &app.eng.contacts.items[cid - 1];
    if (c.deleted) return .NO_CONTACT;
    // сессия — в retired (drain закроет и освободит)
    if (app.eng.sessions.get(@intCast(cid))) |s| app.eng.retireSession(@intCast(cid), s);
    _ = app.sess_ctx.remove(@intCast(cid));
    // очередь недоставленных
    var i: usize = 0;
    while (i < app.eng.outbox.items.len) {
        if (app.eng.outbox.items[i].cid == cid) {
            const e = app.eng.outbox.orderedRemove(i);
            app.alloc.free(e.body);
            app.alloc.free(e.ents_tail);
        } else i += 1;
    }
    // исходящие файлы в полёте
    var j: usize = 0;
    while (j < app.eng.file_tx.items.len) {
        if (app.eng.file_tx.items[j].cid == cid) {
            var f = app.eng.file_tx.orderedRemove(j);
            std.crypto.secureZero(u8, &f.sha);
            app.alloc.free(f.name);
            app.alloc.free(f.data);
        } else j += 1;
    }
    // история (кэш), реакции не трогаем — записи без cid-хозяина
    // невидимы: GET_MESSAGE удалённых чатов не бывает
    persist.histPurgeFor(app, cid);
    // закрепления
    if (app.pinned_chat == cid) app.pinned_chat = 0;
    if (app.pinned_msgs.fetchRemove(cid)) |kv| {
        var list = kv.value;
        list.deinit(app.alloc);
    }
    // presence-состояния
    _ = app.hb.remove(cid);
    if (app.eng.seen.fetchRemove(cid)) |kv| {
        var seen = kv.value;
        seen.deinit(app.alloc);
    }
    _ = app.eng.last_seen_ms.remove(cid);
    if (app.contact_relays.fetchRemove(cid)) |kv| {
        app.alloc.free(kv.value);
    }
    // надгробие: при загрузке слот cid станет невидимым (bundle не годится:
    // повторное знакомство с тем же человеком — ДРУГОЙ слот, надгробие по
    // bundle съело бы и его)
    c.deleted = true;
    c.online = false;
    // линк устройства: снять регистрацию (очередь синхронизации очищается;
    // запись device-линка в логе помечена dev_role и не восстановится)
    if (c.dev_role != 0) app.sync.removeDevice(@intCast(cid));
    if (app.log) |log| {
        var buf: [3]u8 = undefined;
        buf[0] = 7;
        std.mem.writeInt(u16, buf[1..3], @intCast(cid), .little);
        _ = log.append(.set, &buf) catch {};
    }
    // 2.7.0: удаление — REMOVED-ревизия; летящая работа увидит deleted
    // и погаснет (canceled), ожидание эха — снять
    _ = app.conn_await.remove(@as(i64, @intCast(cid)));
    events.bumpRemovedLocked(app, @intCast(cid));
    return .OK;
}

/// SEND_CONTACT (29): [to_cid u32][contact_cid u32 (0 = моя карточка)] → ∅.
/// Отправляет конверт CONTACT_CARD по живой сессии; получатель видит
/// событие CONTACT_CARD. Добавить человека из карточки можно только его
/// собственным инвайтом — карточка знакомит, не подключает.
pub fn apiSendContact(app: *App, payload: []const u8, w: *api.Writer) api.Status {
    _ = w;
    var r = api.Reader.init(payload);
    const to_cid = r.readU32() catch return .BAD_FRAME;
    const contact_cid = r.readU32() catch return .BAD_FRAME;
    if (r.hasMore()) return .BAD_FRAME;
    app.lock();
    defer app.unlock();
    if (to_cid < 1 or to_cid > app.eng.contacts.items.len) return .NO_CONTACT;
    const to = &app.eng.contacts.items[to_cid - 1];
    if (to.deleted) return .NO_CONTACT;
    if (to.blocked) return .CONTACT_BLOCKED;
    var name_buf: [32]u8 = undefined;
    var name_len: usize = 0;
    var bundle: [64]u8 = undefined;
    var ab: [80]u8 = undefined;
    var card_addr: []const u8 = "";
    if (contact_cid == 0) {
        // своя карточка: имя профиля + свой bundle
        const my_name = app.eng.myName();
        @memcpy(name_buf[0..my_name.len], my_name);
        name_len = my_name.len;
        bundle = app.id.bundle();
    } else {
        if (contact_cid > app.eng.contacts.items.len) return .NO_CONTACT;
        const c = &app.eng.contacts.items[contact_cid - 1];
        if (c.deleted) return .NO_CONTACT;
        const cname = c.getName();
        @memcpy(name_buf[0..cname.len], cname);
        name_len = cname.len;
        bundle = c.bundle;
        if (c.addr(&ab)) |a| card_addr = a;
    }
    const s = app.eng.sessions.get(@intCast(to_cid)) orelse return .NO_SESSION;
    s.sendEnvelope(.{ .contact_card = .{
        .name = name_buf[0..name_len],
        .bundle = bundle,
        .addr = card_addr,
    } }) catch return .NO_SESSION;
    return .OK;
}

/// PIN_MESSAGE (30): [cid u32][msg_id 16] → ∅. Сообщение обязано быть в
/// истории чата; капа max_pinned_msgs на чат. Переживает рестарт (set:5).
pub fn apiPinMessage(app: *App, payload: []const u8, w: *api.Writer) api.Status {
    _ = w;
    var r = api.Reader.init(payload);
    const cid = r.readU32() catch return .BAD_FRAME;
    const msg_id: [16]u8 = (r.readBytes(16) catch return .BAD_FRAME)[0..16].*;
    if (r.hasMore()) return .BAD_FRAME;
    app.lock();
    defer app.unlock();
    if (cid < 1 or cid > app.eng.contacts.items.len) return .NO_CONTACT;
    if (app.eng.contacts.items[cid - 1].deleted) return .NO_CONTACT;
    const list = app.pinned_msgs.getOrPut(app.alloc, @intCast(cid)) catch return .INTERNAL;
    if (!list.found_existing) list.value_ptr.* = .empty;
    for (list.value_ptr.items) |m| {
        if (std.mem.eql(u8, &m, &msg_id)) return .OK; // уже закреплено
    }
    // сообщение из этого чата?
    const idx = app.hist_idx.get(msg_id) orelse return .NOT_FOUND;
    const rec = app.hist.items[idx];
    if (rec.len < 2 or std.mem.readInt(u16, rec[0..2], .little) != cid) return .NOT_FOUND;
    if (list.value_ptr.items.len >= app_mod.max_pinned_msgs) return .TOO_BIG;
    list.value_ptr.append(app.alloc, msg_id) catch return .INTERNAL;
    if (app.log) |log| {
        var buf: [19]u8 = undefined;
        buf[0] = 5;
        std.mem.writeInt(u16, buf[1..3], @intCast(cid), .little);
        @memcpy(buf[3..19], &msg_id);
        _ = log.append(.set, &buf) catch {};
    }
    return .OK;
}

/// UNPIN_MESSAGE (31): [cid u32][msg_id 16] → ∅. Идемпотентно (set:6).
pub fn apiUnpinMessage(app: *App, payload: []const u8, w: *api.Writer) api.Status {
    _ = w;
    var r = api.Reader.init(payload);
    const cid = r.readU32() catch return .BAD_FRAME;
    const msg_id: [16]u8 = (r.readBytes(16) catch return .BAD_FRAME)[0..16].*;
    if (r.hasMore()) return .BAD_FRAME;
    app.lock();
    defer app.unlock();
    if (cid < 1 or cid > app.eng.contacts.items.len) return .NO_CONTACT;
    if (app.pinned_msgs.getPtr(@intCast(cid))) |list| {
        var i: usize = 0;
        while (i < list.items.len) : (i += 1) {
            if (std.mem.eql(u8, &list.items[i], &msg_id)) {
                _ = list.orderedRemove(i);
                break;
            }
        }
    }
    if (app.log) |log| {
        var buf: [19]u8 = undefined;
        buf[0] = 6;
        std.mem.writeInt(u16, buf[1..3], @intCast(cid), .little);
        @memcpy(buf[3..19], &msg_id);
        _ = log.append(.set, &buf) catch {};
    }
    return .OK;
}

/// GET_PINNED_MESSAGES (32): [cid u32] → [count u32] × {[msg_id 16]}
/// в порядке закрепления.
pub fn apiGetPinnedMessages(app: *App, payload: []const u8, w: *api.Writer) api.Status {
    var r = api.Reader.init(payload);
    const cid = r.readU32() catch return .BAD_FRAME;
    if (r.hasMore()) return .BAD_FRAME;
    app.lock();
    defer app.unlock();
    if (cid < 1 or cid > app.eng.contacts.items.len) return .NO_CONTACT;
    if (app.eng.contacts.items[cid - 1].deleted) return .NO_CONTACT;
    const list = app.pinned_msgs.get(@intCast(cid)) orelse {
        w.putU32(0) catch return .INTERNAL;
        return .OK;
    };
    w.putU32(@intCast(list.items.len)) catch return .INTERNAL;
    for (list.items) |m| {
        w.putBytes(&m) catch return .INTERNAL;
    }
    return .OK;
}

/// SET_NAME: payload [name str16 1..32]. Ответ пуст.
pub fn apiSetName(app: *App, payload: []const u8, w: *api.Writer) api.Status {
    _ = w;
    var r = api.Reader.init(payload);
    const name = r.readStr16() catch return .BAD_FRAME;
    if (r.hasMore()) return .BAD_FRAME;
    if (name.len == 0 or name.len > invite_mod.max_name) return .BAD_ARGS;
    app.lock();
    defer app.unlock();
    app.eng.setMyProfile(name, app.eng.my_avatar_id);
    if (app.log) |log| {
        var nb: [33]u8 = undefined;
        nb[0] = 2;
        @memcpy(nb[1 .. 1 + name.len], name);
        _ = log.append(.set, nb[0 .. 1 + name.len]) catch {};
    }
    for (app.eng.contacts.items, 0..) |_, i| {
        const cid: i64 = @intCast(i + 1);
        if (app.eng.sessions.contains(cid)) {
            app.eng.sendProfile(cid) catch {};
        }
    }
    return .OK;
}

/// SET_AVATAR: payload [data str32 1..16000] — байты картинки inline.
/// Ответ: [avatar_id 16][size u32].
pub fn apiSetAvatar(app: *App, payload: []const u8, w: *api.Writer) api.Status {
    var r = api.Reader.init(payload);
    const bytes = r.readStr32() catch return .BAD_FRAME;
    if (r.hasMore()) return .BAD_FRAME;
    if (bytes.len == 0 or bytes.len > envelope.max_avatar_data) return .TOO_BIG;
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    const id = digest[0..16].*;
    {
        app.lock();
        defer app.unlock();
        if (!app.avatars.contains(id)) {
            const copy = app.alloc.dupe(u8, bytes) catch return .INTERNAL;
            app.avatars.put(app.alloc, id, copy) catch {
                app.alloc.free(copy);
                return .INTERNAL;
            };
        }
        app.eng.setMyProfile(app.eng.myName(), id);
        if (app.log) |log| {
            var rb: [17]u8 = undefined;
            rb[0] = 1;
            @memcpy(rb[1..17], &id);
            _ = log.append(.set, rb[0..17]) catch {};
        }
        // кэш байтов — тоже kind avatar, чтобы peer-REQ перекачивал и после рестарта
        if (app.log) |log| {
            var ab: [18 + 16000]u8 = undefined;
            @memcpy(ab[0..16], &id);
            std.mem.writeInt(u16, ab[16..18], @intCast(bytes.len), .little);
            @memcpy(ab[18 .. 18 + bytes.len], bytes);
            _ = log.append(.avatar, ab[0 .. 18 + bytes.len]) catch {};
        }
        // PROFILE всем онлайн-сессиям
        for (app.eng.contacts.items, 0..) |_, i| {
            const cid: i64 = @intCast(i + 1);
            if (app.eng.sessions.contains(cid)) {
                app.eng.sendProfile(cid) catch {};
            }
        }
    }
    w.putBytes(&id) catch return .INTERNAL;
    w.putU32(@intCast(bytes.len)) catch return .INTERNAL;
    return .OK;
}

/// GET_MY_AVATAR: empty payload; response [avatar_id 16][data str16].
/// Reads the same encrypted-log-backed cache used for peer AVATAR_REQ.
pub fn apiGetMyAvatar(app: *App, payload: []const u8, w: *api.Writer) api.Status {
    if (payload.len != 0) return .BAD_FRAME;
    app.lock();
    defer app.unlock();
    const id = app.eng.my_avatar_id;
    if (std.mem.eql(u8, &id, &@as([16]u8, @splat(0)))) return .NOT_FOUND;
    const data = app.avatars.get(id) orelse return .NOT_FOUND;
    w.putBytes(&id) catch return .INTERNAL;
    w.putStr16(data) catch return .INTERNAL;
    return .OK;
}

/// CREATE_RECOVERY_BACKUP (41): payload [unlock_secret 32] → [backup str32].
/// Запечатывает сид+профиль+контакты (БЕЗ истории) ключом из секрета GUI
/// (passkey PRF / recovery-код); блоб GUI хранит в пользовательском
/// облаке. Секрет по UDS (0700-сокет на машине пользователя) передаётся
/// один раз и ядром не сохраняется. Nonce — до лока (io вне спин-лока).
pub fn apiCreateRecoveryBackup(app: *App, payload: []const u8, w: *api.Writer) api.Status {
    var r = api.Reader.init(payload);
    const secret = r.readBytes(recovery_codec.secret_length) catch return .BAD_FRAME;
    if (r.hasMore()) return .BAD_FRAME;
    var nonce: [recovery_codec.nonce_length]u8 = undefined;
    app.io.random(&nonce);
    app.lock();
    defer app.unlock();
    const res = recovery_mod.createBackup(app, secret[0..recovery_codec.secret_length], nonce);
    const blob = switch (res) {
        .ok => |b| b,
        .err => |st| return st,
    };
    defer app.alloc.free(blob);
    w.putStr32(blob) catch return .INTERNAL;
    return .OK;
}

/// RESTORE_RECOVERY_BACKUP (42): payload [backup str32][unlock_secret 32]
/// → [bundle 64][fingerprint 32][name str16]. Только пустой профиль
/// (демон без сида); битый пакет или чужой секрет — BAD_RECOVERY. После
/// успеха профиль провижен, сетевые потоки поднимаются сами (main loop).
pub fn apiRestoreRecoveryBackup(app: *App, payload: []const u8, w: *api.Writer) api.Status {
    var r = api.Reader.init(payload);
    const blob = r.readStr32() catch return .BAD_FRAME;
    const secret = r.readBytes(recovery_codec.secret_length) catch return .BAD_FRAME;
    if (r.hasMore()) return .BAD_FRAME;
    if (blob.len == 0) return .BAD_ARGS;
    var backup = recovery_codec.open(app.alloc, blob, secret[0..recovery_codec.secret_length]) catch |e| switch (e) {
        error.BadFormat, error.Tampered, error.TooBig => return .BAD_RECOVERY,
        error.OutOfMemory => return .INTERNAL,
    };
    defer backup.deinit(app.alloc);
    app.lock();
    defer app.unlock();
    recovery_mod.applyBackup(app, &backup) catch |e| switch (e) {
        error.AlreadyProvisioned => return .ALREADY_PROVISIONED,
        error.BadRecovery => return .BAD_RECOVERY,
        error.Internal => return .INTERNAL,
    };
    // ответ — как GET_IDENTITY + имя: GUI сразу показывает восстановленный
    // профиль и сверяет отпечаток
    const bundle = app.id.bundle();
    var digest: [32]u8 = undefined;
    std.crypto.hash.blake2.Blake2s256.hash(&bundle, &digest, .{});
    w.putBytes(&bundle) catch return .INTERNAL;
    w.putBytes(&digest) catch return .INTERNAL;
    w.putStr16(app.eng.myName()) catch return .INTERNAL;
    return .OK;
}

/// SEND_FILE: payload [cid u32][path str16] — путь в ФС пользователя демона.
/// Ответ: [file_id 16][size u32][chunks u32].
/// Требует живой сессии (файлы не ставятся в outbox); file_id = SHA-256[0..16].
/// Передача окном tx_window_chunks с подтверждениями FILE_ACK: разрыв
/// сессии не теряет прогресс — докачка автоматически при реконнекте
/// (resumeTxFilesLocked в bindSession).
pub fn apiSendFile(app: *App, payload: []const u8, w: *api.Writer) api.Status {
    var r = api.Reader.init(payload);
    const cid = r.readU32() catch return .BAD_FRAME;
    const path = r.readStr16() catch return .BAD_FRAME;
    if (r.hasMore()) return .BAD_FRAME;
    if (path.len == 0) return .BAD_ARGS;
    // только имя файла, без каталогов
    const base = if (std.mem.lastIndexOfScalar(u8, path, '/')) |i| path[i + 1 ..] else path;
    if (base.len == 0 or base.len > envelope.max_file_name) return .BAD_ARGS;
    const f = std.Io.Dir.openFileAbsolute(app.io, path, .{ .mode = .read_only }) catch
        return .FILE_NOT_FOUND;
    defer f.close(app.io);
    // лимит: 64 МБ (u32 размер + разумный таймаут перекачки)
    const max_file_total = 64 * 1024 * 1024;
    const data = app.alloc.alloc(u8, max_file_total) catch return .INTERNAL;
    defer app.alloc.free(data);
    const n = f.readPositionalAll(app.io, data, 0) catch return .FILE_NOT_FOUND;
    if (n == 0 or n > std.math.maxInt(u32)) return .TOO_BIG;
    const bytes = data[0..n];
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    const file_id = digest[0..16].*;
    const total: u32 = @intCast(@divTrunc(n + envelope.max_file_chunk - 1, envelope.max_file_chunk));
    {
        app.lock();
        defer app.unlock();
        if (cid < 1 or cid > app.eng.contacts.items.len) return .NO_CONTACT;
        // движок владеет передачей (окно, докачка FILE_ACK, память до
        // подтверждения); без сессии файл стоит в очереди как TEXT-outbox
        const outcome = app.eng.sendFile(@intCast(cid), file_id, base, bytes, digest) catch |e| {
            return dispatch.statusOf(e);
        };
        _ = outcome;
    }
    w.putBytes(&file_id) catch return .INTERNAL;
    w.putU32(@intCast(n)) catch return .INTERNAL;
    w.putU32(total) catch return .INTERNAL;
    return .OK;
}

/// GET_AVATAR_ID: payload [cid u32]. Ответ: [avatar_id 16] (нули — аватара нет).
pub fn apiGetAvatarId(app: *App, payload: []const u8, w: *api.Writer) api.Status {
    var r = api.Reader.init(payload);
    const cid = r.readU32() catch return .BAD_FRAME;
    if (r.hasMore()) return .BAD_FRAME;
    app.lock();
    defer app.unlock();
    if (cid < 1 or cid > app.eng.contacts.items.len) return .NO_CONTACT;
    const c = &app.eng.contacts.items[cid - 1];
    w.putBytes(&c.avatar_id) catch return .INTERNAL;
    return .OK;
}

/// GET_HISTORY: payload [cid u32][limit u32] (0 → 50, максимум 200).
/// Ответ: [total u32][count u32] × {[flags u8 bit0 mine bit1 delivered]
/// [msg_id 16][ts_ms u64][body str16][ent_count u8] × {entity}} — записи
/// старые → новые. Окно режется и бюджетом payload (≤ 16 МиБ): count может
/// быть меньше limit для entity-тяжёлой истории. bit1 delivered ставится
/// только ACK-ом (не фактом записи в сокет). Источние данных — кэш
/// истории в памяти (лог читается один раз при старте).
pub fn apiGetHistory(app: *App, payload: []const u8, w: *api.Writer) api.Status {
    var r = api.Reader.init(payload);
    const cid = r.readU32() catch return .BAD_FRAME;
    var limit = r.readU32() catch return .BAD_FRAME;
    if (r.hasMore()) return .BAD_FRAME;
    if (limit == 0) limit = 50;
    if (limit > 200) return .TOO_BIG;
    // под локом: кэш истории живут мутации (persist/ACK/DELETE_CHAT)
    app.lock();
    defer app.unlock();
    if (cid < 1 or cid > app.eng.contacts.items.len) return .NO_CONTACT;
    if (app.eng.contacts.items[cid - 1].deleted) return .NO_CONTACT;
    // записи: [cid u16][flags u8][msg_id 16][ts u64][len u16][body][ents]
    const recs = app.hist.items;
    var total: usize = 0;
    var start: usize = recs.len; // индекс первой записи окна
    {
        var count: usize = 0;
        var budget: usize = 8; // total u32 + count u32
        var i: usize = recs.len;
        while (i > 0) {
            i -= 1;
            const rec = recs[i];
            if (rec.len < 29) continue;
            if (std.mem.readInt(u16, rec[0..2], .little) != cid) continue;
            const body_off = persist.msgBodyOffset(rec) orelse continue;
            const blen = persist.msgBodyLen(rec) orelse continue;
            if (rec.len < body_off + blen) continue;
            const tail = persist.recEntityTail(rec, blen) orelse continue;
            total += 1;
            count += 1;
            budget += 1 + 16 + 8 + 2 + blen + tail.len;
            if (count == limit or budget > api.max_payload) {
                start = i;
                break;
            }
        }
        if (i == 0 and start == recs.len) start = 0;
    }
    // две фазы: посчитать записи окна, потом записать (payload один кадр);
    // фильтры идентичны фазе 1 — записей ровно in_window, бюджет уже учтён
    var in_window: usize = 0;
    var idx2 = start;
    while (idx2 < recs.len) : (idx2 += 1) {
        const rec = recs[idx2];
        if (rec.len < 29) continue;
        if (std.mem.readInt(u16, rec[0..2], .little) != cid) continue;
        const body_off = persist.msgBodyOffset(rec) orelse continue;
        const blen = persist.msgBodyLen(rec) orelse continue;
        if (rec.len < body_off + blen) continue;
        if (persist.recEntityTail(rec, blen) == null) continue;
        in_window += 1;
    }
    w.putU32(@intCast(total)) catch return .INTERNAL;
    w.putU32(@intCast(in_window)) catch return .INTERNAL;
    idx2 = start;
    while (idx2 < recs.len) : (idx2 += 1) {
        const rec = recs[idx2];
        if (rec.len < 29) continue;
        if (std.mem.readInt(u16, rec[0..2], .little) != cid) continue;
        const flags = rec[2];
        const msg_id: [16]u8 = rec[3 .. 3 + 16].*;
        const ts_ms = std.mem.readInt(u64, rec[19..27], .little);
        const body_off = persist.msgBodyOffset(rec) orelse continue;
        const blen = persist.msgBodyLen(rec) orelse continue;
        if (rec.len < body_off + blen) continue;
        const tail = persist.recEntityTail(rec, blen) orelse continue;
        w.putU8(flags) catch return .INTERNAL;
        w.putBytes(&msg_id) catch return .INTERNAL;
        w.putU64(ts_ms) catch return .INTERNAL;
        w.putStr16(rec[body_off .. body_off + blen]) catch return .INTERNAL;
        w.putBytes(tail) catch return .INTERNAL;
    }
    return .OK;
}

/// GET_MESSAGE: payload [msg_id 16]. Ответ:
/// [cid u32][flags u8 bit0 mine bit1 delivered][ts_ms u64][body str16]
/// [ent_count u8] × {entity}
/// [react_count u32] × {[flags u8 bit0 mine][codepoint u32][ts_ms u64]}.
/// Нет записи — NOT_FOUND.
/// GET_CONTACT_STATE (43): [cid u32] → [state u8][attempt u32]
/// [last_error u16][next_retry_ms u32]. Дешёвый опрос стадии подключения
/// вместо полных LIST_CONTACTS/событий. next_retry_ms — остаток до
/// автодозвона (0 — повтора нет/уже пора).
pub fn apiGetContactState(app: *App, payload: []const u8, w: *api.Writer) api.Status {
    var r = api.Reader.init(payload);
    const cid = r.readU32() catch return .BAD_FRAME;
    if (r.hasMore()) return .BAD_FRAME;
    app.lock();
    defer app.unlock();
    if (cid < 1 or cid > app.eng.contacts.items.len) return .NO_CONTACT;
    const state: api.ConnState = events.connStateOfLocked(app, @intCast(cid));
    const e = app.conn_st.get(@intCast(cid)) orelse app_mod.ConnEntry{};
    w.putU8(@backingInt(state)) catch return .INTERNAL;
    w.putU32(e.attempt) catch return .INTERNAL;
    w.putU16(e.last_error) catch return .INTERNAL;
    w.putU32(connq.retryRemainingMs(e.next_retry_at, app.nowMs())) catch return .INTERNAL;
    return .OK;
}

/// SUBSCRIBE_CONTACT_UPDATES (45): ∅ → [epoch 16][revision u64].
/// На этом конне включаются события CONTACT_STATE_CHANGED /
/// CONTACTS_CHANGED / CONTACT_UPSERTED. Идемпотентно: повторная подписка
/// обновляет revision-точку. Остальные события конну не отправляются.
pub fn apiSubscribeContactUpdates(app: *App, conn: *api_srv.Conn, payload: []const u8, w: *api.Writer) api.Status {
    if (payload.len != 0) return .BAD_FRAME;
    app.lock();
    defer app.unlock();
    conn.subscribed = true;
    w.putBytes(&app.contacts_epoch) catch return .INTERNAL;
    w.putU64(app.contacts_rev) catch return .INTERNAL;
    return .OK;
}

/// GET_BOOTSTRAP (46): ∅ → [api_version 3×u16][epoch 16][revision u64]
/// [count u32] × ContactView. Один вызов вместо каскада GET_CONTACTS +
/// GET_CONTACT_STATE: стартовая отрисовка списка. Порядок — порядку
/// слотов движка (стабилен внутри запуска). TOO_BIG — контактов больше
/// bootstrap_max_contacts: клиент обязан идти через GET_CONTACTS +
/// GET_CONTACTS_DELTA.
pub fn apiGetBootstrap(app: *App, payload: []const u8, w: *api.Writer) api.Status {
    if (payload.len != 0) return .BAD_FRAME;
    app.lock();
    defer app.unlock();
    if (!app.provisioned) return .NOT_INITIALIZED;
    // фаза 1: счёт (бюджет кадра)
    var count: usize = 0;
    var budget: usize = 6 + 16 + 8 + 4;
    for (app.eng.contacts.items) |*c| {
        if (c.deleted) continue;
        count += 1;
        budget += events.contact_view_size + 32;
        if (count >= app_mod.bootstrap_max_contacts) return .TOO_BIG;
        if (budget > api.max_payload) return .TOO_BIG;
    }
    w.putU16(api.api_version[0]) catch return .INTERNAL;
    w.putU16(api.api_version[1]) catch return .INTERNAL;
    w.putU16(api.api_version[2]) catch return .INTERNAL;
    w.putBytes(&app.contacts_epoch) catch return .INTERNAL;
    w.putU64(app.contacts_rev) catch return .INTERNAL;
    w.putU32(@intCast(count)) catch return .INTERNAL;
    // фаза 2: записи (мутаций под локом нет — размер совпадает)
    for (app.eng.contacts.items, 0..) |*c, i| {
        if (c.deleted) continue;
        events.putContactViewLocked(app, w, @intCast(i + 1)) catch return .INTERNAL;
    }
    return .OK;
}

/// GET_CONTACTS_DELTA (47): [epoch 16][from_rev u64] → [epoch 16]
/// [to_rev u64][count u32] × {[rev u64][kind u8][cid u32](+view)}.
/// Воспроизведение кольца ревизий: клиент ведёт (epoch, rev) и
/// докачивает пропущенное. RESYNC_REQUIRED — чужой epoch или rev вне
/// окна кольца: полный пересинхрон (GET_BOOTSTRAP/GET_CONTACTS).
pub fn apiGetContactsDelta(app: *App, payload: []const u8, w: *api.Writer) api.Status {
    var r = api.Reader.init(payload);
    const epoch = r.readBytes(16) catch return .BAD_FRAME;
    const from_rev = r.readU64() catch return .BAD_FRAME;
    if (r.hasMore()) return .BAD_FRAME;
    app.lock();
    defer app.unlock();
    if (!app.provisioned) return .NOT_INITIALIZED;
    if (!std.mem.eql(u8, epoch, &app.contacts_epoch)) return .RESYNC_REQUIRED;
    if (from_rev > app.contacts_rev) return .BAD_ARGS;
    // окно кольца: доступная история ревизий
    if (app.contacts_rev == 0 or from_rev == app.contacts_rev) {
        // пустая дельта — валидный ответ (пусто)
        w.putBytes(&app.contacts_epoch) catch return .INTERNAL;
        w.putU64(app.contacts_rev) catch return .INTERNAL;
        w.putU32(0) catch return .INTERNAL;
        return .OK;
    }
    const oldest: u64 = if (app.contacts_ring_len < app_mod.contact_ring_cap)
        app.contacts_rev - app.contacts_ring_len + 1
    else
        app.contacts_ring[app.contacts_ring_pos].rev;
    if (from_rev + 1 < oldest) return .RESYNC_REQUIRED;
    // фаза 1: сбор индексов записей (rev > from_rev, ревизии плотные)
    const span: usize = @intCast(app.contacts_rev - from_rev);
    if (span > app_mod.contact_ring_cap) return .RESYNC_REQUIRED;
    var budget: usize = 16 + 8 + 4 + span * (8 + 1 + 4);
    var iter: usize = 0;
    while (iter < span) : (iter += 1) {
        const idx = (app.contacts_ring_pos + app_mod.contact_ring_cap - span + iter) % app_mod.contact_ring_cap;
        const ch = app.contacts_ring[idx];
        if (ch.kind == @backingInt(api.DeltaChange.upsert)) budget += events.contact_view_size + 32;
    }
    if (budget > api.max_payload) return .TOO_BIG;
    w.putBytes(&app.contacts_epoch) catch return .INTERNAL;
    w.putU64(app.contacts_rev) catch return .INTERNAL;
    w.putU32(@intCast(span)) catch return .INTERNAL;
    // фаза 2: записи (порядок возрастания rev)
    iter = 0;
    while (iter < span) : (iter += 1) {
        const idx = (app.contacts_ring_pos + app_mod.contact_ring_cap - span + iter) % app_mod.contact_ring_cap;
        const ch = app.contacts_ring[idx];
        w.putU64(ch.rev) catch return .INTERNAL;
        w.putU8(ch.kind) catch return .INTERNAL;
        w.putU32(@intCast(ch.cid)) catch return .INTERNAL;
        if (ch.kind == @backingInt(api.DeltaChange.upsert)) {
            // view на ТЕКУЩИЙ момент: применение клиентом идемпотентно
            events.putContactViewLocked(app, w, ch.cid) catch return .INTERNAL;
        }
    }
    return .OK;
}

/// GET_REACHABLE_ENDPOINTS (48): ∅ → [count u8] × [address str16] —
/// "ip:port" прямых адресов, по которым нас можно найти в LAN (для QR
/// прямого приглашения без multicast-поиска). Пусто — не слушаем или
/// включён use_tor_mask (прямой адрес раскрыть нельзя).
pub fn apiGetReachableEndpoints(app: *App, payload: []const u8, w: *api.Writer) api.Status {
    if (payload.len != 0) return .BAD_FRAME;
    app.lock();
    const listening = app.listening;
    const port = app.listen_port;
    const tor = app.cfg.use_tor_mask;
    app.unlock();
    if (!listening or tor) {
        w.putU8(0) catch return .INTERNAL;
        return .OK;
    }
    // перечисление интерфейсов — системные вызовы, БЕЗ app.mu
    var ips: [endpoints_mod.max_endpoints][4]u8 = undefined;
    const n = endpoints_mod.enumerateLocalV4(&ips) catch |e| switch (e) {
        error.Network => {
            // перечисление недоступно: пустой список, не ошибка
            w.putU8(0) catch return .INTERNAL;
            return .OK;
        },
    };
    // 2.10.0: + глобальные IPv6 ("[v6]:port" — прямые адреса без NAT)
    // и UPnP-endpoint ("ip:port" — публичный IPv4). Тот же формат записи.
    var ips6: [endpoints_mod.max_endpoints6][16]u8 = undefined;
    const n6 = endpoints_mod.enumerateLocalV6(&ips6) catch 0;
    var upnp_m: ?upnp_mod.Mapping = null;
    {
        app.lock();
        upnp_m = app.upnp_ext;
        app.unlock();
    }
    const total = @min(n + n6 + @intFromBool(upnp_m != null), 255);
    w.putU8(@intCast(total)) catch return .INTERNAL;
    for (ips[0..n]) |ip| {
        var hbuf: [endpoints_mod.host_max]u8 = undefined;
        var ab: [endpoints_mod.host_max + 8]u8 = undefined;
        const host = endpoints_mod.fmtHost(&hbuf, ip);
        const addr = std.fmt.bufPrint(&ab, "{s}:{d}", .{ host, port }) catch return .INTERNAL;
        w.putStr16(addr) catch return .INTERNAL;
    }
    for (ips6[0..n6]) |ip| {
        var ipbuf: [64]u8 = undefined;
        var ab: [80]u8 = undefined;
        const ip6 = tcp.fmtIp6(&ipbuf, ip);
        const addr = std.fmt.bufPrint(&ab, "[{s}]:{d}", .{ ip6, port }) catch return .INTERNAL;
        w.putStr16(addr) catch return .INTERNAL;
    }
    if (upnp_m) |m| {
        var hbuf: [endpoints_mod.host_max]u8 = undefined;
        var ab: [endpoints_mod.host_max + 8]u8 = undefined;
        const host = endpoints_mod.fmtHost(&hbuf, m.ip);
        const addr = std.fmt.bufPrint(&ab, "{s}:{d}", .{ host, m.port }) catch return .INTERNAL;
        w.putStr16(addr) catch return .INTERNAL;
    }
    return .OK;
}

/// GET_HISTORY_PAGE (51): [cid u32][has_cursor u8][before_ts u64]
/// [before_msg_id 16][limit u16] → [has_more u8][next_ts u64]
/// [next_msg_id 16][count u32] × records (формат записей — как
/// GET_HISTORY). Строгий порядок (ts, msg_id): пагинация курсором —
/// экстремально дешёвая (никаких окон) и стабильная при удалении
/// старых записей: граница — не позиция, а кортеж.
pub fn apiGetHistoryPage(app: *App, payload: []const u8, w: *api.Writer) api.Status {
    var r = api.Reader.init(payload);
    const cid = r.readU32() catch return .BAD_FRAME;
    const has_cursor = r.readU8() catch return .BAD_FRAME;
    const before_ts = r.readU64() catch return .BAD_FRAME;
    const before_msg_id = r.readBytes(16) catch return .BAD_FRAME;
    var limit = r.readU16() catch return .BAD_FRAME;
    if (r.hasMore()) return .BAD_FRAME;
    if (limit == 0) limit = 30;
    if (limit > 200) return .TOO_BIG;
    app.lock();
    defer app.unlock();
    if (cid < 1 or cid > app.eng.contacts.items.len) return .NO_CONTACT;
    if (app.eng.contacts.items[cid - 1].deleted) return .NO_CONTACT;

    // фаза 1: собрать валидные записи чата в буфер индексов, отсортировать
    // по строгому порядку (ts, msg_id) — устойчивая пагинация при равных ts
    const RecIdx = struct { ts: u64, msg_id: [16]u8, rec: usize };
    var recs_idx = std.ArrayListUnmanaged(RecIdx).empty;
    defer recs_idx.deinit(app.alloc);
    const all = app.hist.items;
    for (all, 0..) |rec, i| {
        if (rec.len < 29) continue;
        if (std.mem.readInt(u16, rec[0..2], .little) != cid) continue;
        const body_off = persist.msgBodyOffset(rec) orelse continue;
        const blen = persist.msgBodyLen(rec) orelse continue;
        if (rec.len < body_off + blen) continue;
        if (persist.recEntityTail(rec, blen) == null) continue;
        recs_idx.append(app.alloc, .{
            .ts = std.mem.readInt(u64, rec[19..27], .little),
            .msg_id = rec[3 .. 3 + 16].*,
            .rec = i,
        }) catch return .INTERNAL;
    }
    const ctx = struct {
        fn lt(_: void, a: RecIdx, b: RecIdx) bool {
            if (a.ts != b.ts) return a.ts < b.ts;
            return std.mem.order(u8, &a.msg_id, &b.msg_id) == .lt;
        }
    };
    std.mem.sort(RecIdx, recs_idx.items, {}, ctx.lt);
    // Страница выдаётся от новых записей к старым. Курсор исключает
    // самую старую запись предыдущей страницы и всё, что новее неё.
    var end: usize = recs_idx.items.len;
    if (has_cursor != 0) {
        end = 0;
        while (end < recs_idx.items.len) {
            const it = recs_idx.items[end];
            const before = it.ts < before_ts or
                (it.ts == before_ts and std.mem.order(u8, &it.msg_id, before_msg_id) == .lt);
            if (!before) break;
            end += 1;
        }
    }
    var start: usize = 0;
    if (end > limit) start = end - limit;
    const has_more = start > 0;
    // Курсор следующей страницы: самая старая выданная запись.
    var next_ts: u64 = 0;
    var next_msg_id: [16]u8 = @splat(0);
    if (start < end) {
        next_ts = recs_idx.items[start].ts;
        next_msg_id = recs_idx.items[start].msg_id;
    }
    // фаза 2: бюджет и запись (записи — как GET_HISTORY)
    var budget: usize = 1 + 8 + 16 + 4;
    var i: usize = start;
    while (i < end) : (i += 1) {
        const rec = all[recs_idx.items[i].rec];
        const blen = persist.msgBodyLen(rec).?;
        const tail = persist.recEntityTail(rec, blen).?;
        budget += 1 + 16 + 8 + 2 + blen + tail.len;
    }
    if (budget > api.max_payload) return .TOO_BIG;
    w.putU8(@intFromBool(has_more)) catch return .INTERNAL;
    w.putU64(next_ts) catch return .INTERNAL;
    w.putBytes(&next_msg_id) catch return .INTERNAL;
    w.putU32(@intCast(end - start)) catch return .INTERNAL;
    i = end;
    while (i > start) {
        i -= 1;
        const rec = all[recs_idx.items[i].rec];
        const flags = rec[2];
        const msg_id: [16]u8 = rec[3 .. 3 + 16].*;
        const ts_ms = std.mem.readInt(u64, rec[19..27], .little);
        const body_off = persist.msgBodyOffset(rec).?;
        const blen = persist.msgBodyLen(rec).?;
        const tail = persist.recEntityTail(rec, blen).?;
        w.putU8(flags) catch return .INTERNAL;
        w.putBytes(&msg_id) catch return .INTERNAL;
        w.putU64(ts_ms) catch return .INTERNAL;
        w.putStr16(rec[body_off .. body_off + blen]) catch return .INTERNAL;
        w.putBytes(tail) catch return .INTERNAL;
    }
    return .OK;
}

pub fn apiGetMessage(app: *App, payload: []const u8, w: *api.Writer) api.Status {
    var r = api.Reader.init(payload);
    const want: [16]u8 = (r.readBytes(16) catch return .BAD_FRAME)[0..16].*;
    if (r.hasMore()) return .BAD_FRAME;
    const log = app.log orelse return .NOT_FOUND;
    // под локом: кэш истории живут мутации (persist/DELETE_CHAT)
    app.lock();
    defer app.unlock();
    const i = app.hist_idx.get(want) orelse return .NOT_FOUND;
    const rec = app.hist.items[i];
    const flags = rec[2];
    const cid = std.mem.readInt(u16, rec[0..2], .little);
    const ts_ms = std.mem.readInt(u64, rec[19..27], .little);
    const body_off = persist.msgBodyOffset(rec) orelse return .NOT_FOUND;
    const blen = persist.msgBodyLen(rec) orelse return .NOT_FOUND;
    const tail = persist.recEntityTail(rec, blen) orelse return .NOT_FOUND;
    w.putU32(cid) catch return .INTERNAL;
    w.putU8(flags) catch return .INTERNAL;
    w.putU64(ts_ms) catch return .INTERNAL;
    w.putStr16(rec[body_off .. body_off + blen]) catch return .INTERNAL;
    w.putBytes(tail) catch return .INTERNAL;
    // реакции на это сообщение
    const rrecs = log.readAll(.react, app.alloc) catch return .INTERNAL;
    defer {
        for (rrecs) |rr| app.alloc.free(rr);
        app.alloc.free(rrecs);
    }
    const ReactionState = struct { flags: u8, code: u32, ts: u64 };
    var active: [3]ReactionState = undefined;
    var active_n: usize = 0;
    for (rrecs) |rr| {
        if (rr.len < 31 or !std.mem.eql(u8, rr[3 .. 3 + 16], &want)) continue;
        const op: u8 = if (rr.len >= 32) rr[19] else envelope.react_add;
        const code = if (rr.len >= 32) std.mem.readInt(u32, rr[20..24], .little) else std.mem.readInt(u32, rr[19..23], .little);
        const ts = if (rr.len >= 32) std.mem.readInt(u64, rr[24..32], .little) else std.mem.readInt(u64, rr[23..31], .little);
        var found: ?usize = null;
        for (active[0..active_n], 0..) |item, j| if (item.code == code) {
            found = j;
            break;
        };
        if (op == envelope.react_remove) {
            if (found) |j| {
                active[j] = active[active_n - 1];
                active_n -= 1;
            }
        } else if (found) |j| {
            active[j] = .{ .flags = rr[2], .code = code, .ts = ts };
        } else if (active_n < active.len) {
            active[active_n] = .{ .flags = rr[2], .code = code, .ts = ts };
            active_n += 1;
        }
    }
    w.putU32(@intCast(active_n)) catch return .INTERNAL;
    for (active[0..active_n]) |item| {
        w.putU8(item.flags) catch return .INTERNAL;
        w.putU32(item.code) catch return .INTERNAL;
        w.putU64(item.ts) catch return .INTERNAL;
    }
    return .OK;
}

/// GET_REACTIONS: payload [msg_id 16], response active reactions only.
pub fn apiGetReactions(app: *App, payload: []const u8, w: *api.Writer) api.Status {
    var r = api.Reader.init(payload);
    const want: [16]u8 = (r.readBytes(16) catch return .BAD_FRAME)[0..16].*;
    if (r.hasMore()) return .BAD_FRAME;
    app.lock();
    defer app.unlock();
    if (app.hist_idx.get(want) == null) return .NOT_FOUND;
    const log = app.log orelse {
        w.putU32(0) catch return .INTERNAL;
        return .OK;
    };
    const rrecs = log.readAll(.react, app.alloc) catch return .INTERNAL;
    defer {
        for (rrecs) |rr| app.alloc.free(rr);
        app.alloc.free(rrecs);
    }
    const ReactionState = struct { flags: u8, code: u32, ts: u64 };
    var active: [3]ReactionState = undefined;
    var active_n: usize = 0;
    for (rrecs) |rr| {
        if (rr.len < 31 or !std.mem.eql(u8, rr[3 .. 3 + 16], &want)) continue;
        const op: u8 = if (rr.len >= 32) rr[19] else envelope.react_add;
        const code = if (rr.len >= 32) std.mem.readInt(u32, rr[20..24], .little) else std.mem.readInt(u32, rr[19..23], .little);
        const ts = if (rr.len >= 32) std.mem.readInt(u64, rr[24..32], .little) else std.mem.readInt(u64, rr[23..31], .little);
        var found: ?usize = null;
        for (active[0..active_n], 0..) |item, j| if (item.code == code) {
            found = j;
            break;
        };
        if (op == envelope.react_remove) {
            if (found) |j| {
                active[j] = active[active_n - 1];
                active_n -= 1;
            }
        } else if (found) |j| {
            active[j] = .{ .flags = rr[2], .code = code, .ts = ts };
        } else if (active_n < active.len) {
            active[active_n] = .{ .flags = rr[2], .code = code, .ts = ts };
            active_n += 1;
        }
    }
    w.putU32(@intCast(active_n)) catch return .INTERNAL;
    for (active[0..active_n]) |item| {
        w.putU8(item.flags) catch return .INTERNAL;
        w.putU32(item.code) catch return .INTERNAL;
        w.putU64(item.ts) catch return .INTERNAL;
    }
    return .OK;
}

/// Общая часть SEARCH_MESSAGE / GLOBAL_SEARCH_MESSAGE: чтение лога,
/// разбор записей и сборка ответа (семантика поиска — search.zig).
/// Лога нет — пустой список.
pub fn searchRun(app: *App, args: search_mod.Args, w: *api.Writer) api.Status {
    // под локом: кэш истории живут мутации (persist/ACK/DELETE_CHAT)
    app.lock();
    defer app.unlock();
    const raw = app.hist.items;
    // записи kind msg → Rec поиска; битые (обрезанные/битый хвост
    // entities) и чаты-надгробия пропускаются — как в GET_HISTORY
    const recs = app.alloc.alloc(search_mod.Rec, raw.len) catch return .INTERNAL;
    defer app.alloc.free(recs);
    var n: usize = 0;
    for (raw) |rec| {
        if (!persist.chatAlive(app, std.mem.readInt(u16, rec[0..2], .little))) continue;
        if (persist.msgRecView(rec)) |v| {
            recs[n] = v;
            n += 1;
        }
    }
    return search_mod.writeResponse(app.alloc, w, recs[0..n], args, api.max_payload);
}

/// Жив ли чат cid (в пределах списка, не удалён). 0 — нет.
/// SEARCH_MESSAGE: payload [cid u32][query str16][limit u32][offset u32].
/// Ответ: [total u32][count u32] × {[flags u8 bit0 mine bit1 delivered
/// bit2 fuzzy][msg_id 16][ts_ms u64][body str16][ent_count u8] × {entity}}
/// — сначала точные совпадения (новые → старые), затем нечёткие; окно
/// режут offset/limit и бюджет 16 МиБ. Матчинг и формат — search.zig.
/// Ошибки: NO_CONTACT, BAD_ARGS (пустой query), TOO_BIG (limit/query).
pub fn apiSearchMessage(app: *App, payload: []const u8, w: *api.Writer) api.Status {
    var args = search_mod.parseArgs(payload, false) orelse return .BAD_FRAME;
    if (search_mod.validate(&args)) |st| return st;
    {
        const cid = args.cid orelse return .BAD_FRAME;
        app.lock();
        defer app.unlock();
        if (cid < 1 or cid > app.eng.contacts.items.len) return .NO_CONTACT;
        if (app.eng.contacts.items[cid - 1].deleted) return .NO_CONTACT;
    }
    return searchRun(app, args, w);
}

/// GLOBAL_SEARCH_MESSAGE: payload [query str16][limit u32][offset u32] —
/// поиск по всем чатам; записи ответа те же, но начинаются с [cid u32].
/// Ошибки: BAD_ARGS (пустой query), TOO_BIG (limit/query).
pub fn apiGlobalSearchMessage(app: *App, payload: []const u8, w: *api.Writer) api.Status {
    var args = search_mod.parseArgs(payload, true) orelse return .BAD_FRAME;
    if (search_mod.validate(&args)) |st| return st;
    return searchRun(app, args, w);
}

/// GET_CONFIG (35): ∅ → blob [ver u8][flags u32][server_addr str16]
/// [tor_addr str16] — формат app/config.zig.
pub fn apiGetConfig(app: *App, payload: []const u8, w: *api.Writer) api.Status {
    if (payload.len != 0) return .BAD_FRAME;
    app.lock();
    defer app.unlock();
    var buf: [config_mod.blob_max]u8 = undefined;
    const blob = app.cfg.encode(&buf) catch return .INTERNAL;
    w.putBytes(blob) catch return .INTERNAL;
    return .OK;
}

/// SET_CONFIG (36): blob конфигурации → ∅. Валидация (decode), запись в
/// лог (kind cfg, последняя побеждает), применение, событие
/// CONFIG_CHANGED и репликация на устройства (device_sync). Ответ пуст.
pub fn apiSetConfig(app: *App, payload: []const u8, w: *api.Writer) api.Status {
    _ = w;
    var c = config_mod.Config.defaults();
    c.decode(payload) catch |e| return switch (e) {
        error.BadFrame => .BAD_FRAME,
        error.BadVersion => .BAD_FRAME,
        error.BadFlags => .BAD_ARGS,
        error.BadAddr => .BAD_ARGS,
        error.NoSpace => .INTERNAL,
    };
    app.lock();
    defer app.unlock();
    presence.applyConfigLocked(app, c);
    if (app.log) |log| {
        _ = log.append(.cfg, payload) catch return .INTERNAL;
    }
    events.evConfigChanged(app);
    persist.syncEnqueue(app, @backingInt(sync_mod.RecKind.cfg), payload);
    persist.syncPumpLocked(app);
    return .OK;
}

/// WRITE_DB (37): [tag u8][data str32 ≤ 65000] → [rec_id u32][ts_ms u64].
/// Клиентская запись в шифрованной БД (kind client) + кэш; при
/// device_sync — репликация на связанные устройства. Тег 0xFF —
/// зарезервирован под wildcard чтения.
pub fn apiWriteDb(app: *App, payload: []const u8, w: *api.Writer) api.Status {
    var r = api.Reader.init(payload);
    const tag = r.readU8() catch return .BAD_FRAME;
    const data = r.readStr32() catch return .BAD_FRAME;
    if (r.hasMore()) return .BAD_FRAME;
    if (data.len == 0 or data.len > app_mod.max_client_data) return .TOO_BIG;
    if (tag == app_mod.client_tag_wildcard) return .BAD_ARGS;
    app.lock();
    defer app.unlock();
    if (app.client_bytes + data.len > app_mod.client_db_cap) return .TOO_BIG;
    const log = app.log orelse return .INTERNAL;
    var buf: [11 + app_mod.max_client_data]u8 = undefined;
    const ts: u64 = @intCast(app.nowMs());
    buf[0] = tag;
    std.mem.writeInt(u64, buf[1..9], ts, .little);
    std.mem.writeInt(u16, buf[9..11], @intCast(data.len), .little);
    @memcpy(buf[11..][0..data.len], data);
    const rec = buf[0 .. 11 + data.len];
    const seq = log.append(.client, rec) catch return .INTERNAL;
    const mac = sync_mod.recordMac(&app.sync.key, @backingInt(sync_mod.RecKind.client), rec);
    const copy = app.alloc.dupe(u8, data) catch return .INTERNAL;
    app.client_macs.put(app.alloc, mac, {}) catch {
        app.alloc.free(copy);
        return .INTERNAL;
    };
    app.client_recs.append(app.alloc, .{
        .seq = seq,
        .tag = tag,
        .ts_ms = ts,
        .data = copy,
    }) catch {
        _ = app.client_macs.remove(mac);
        app.alloc.free(copy);
        return .INTERNAL;
    };
    app.client_bytes += data.len;
    persist.syncEnqueue(app, @backingInt(sync_mod.RecKind.client), rec);
    persist.syncPumpLocked(app);
    w.putU32(seq) catch return .INTERNAL;
    w.putU64(ts) catch return .INTERNAL;
    return .OK;
}

/// READ_DB (38): [tag u8 (0xFF = все)][limit u32 (0 → 50, ≤ 200)][offset u32]
/// → [total u32][count u32] × {[rec_id u32][ts_ms u64][tag u8][data str16]},
/// старые → новые. Читает кэш памяти (загружается при старте).
pub fn apiReadDb(app: *App, payload: []const u8, w: *api.Writer) api.Status {
    var r = api.Reader.init(payload);
    const tag = r.readU8() catch return .BAD_FRAME;
    const limit_in = r.readU32() catch return .BAD_FRAME;
    const offset = r.readU32() catch return .BAD_FRAME;
    if (r.hasMore()) return .BAD_FRAME;
    const limit: usize = if (limit_in == 0) 50 else @min(limit_in, 200);
    app.lock();
    defer app.unlock();
    var total: usize = 0;
    for (app.client_recs.items) |rec| {
        if (tag == app_mod.client_tag_wildcard or rec.tag == tag) total += 1;
    }
    w.putU32(@intCast(total)) catch return .INTERNAL;
    var matched: usize = 0;
    var count: usize = 0;
    for (app.client_recs.items) |rec| {
        if (tag != app_mod.client_tag_wildcard and rec.tag != tag) continue;
        if (matched < offset) {
            matched += 1;
            continue;
        }
        if (count >= limit) break;
        w.putU32(rec.seq) catch return .INTERNAL;
        w.putU64(rec.ts_ms) catch return .INTERNAL;
        w.putU8(rec.tag) catch return .INTERNAL;
        w.putStr16(rec.data) catch return .INTERNAL;
        count += 1;
    }
    return .OK;
}

/// DELETE_DB (39): [rec_id u32] → ∅. Tombstone лога (идемпотентно) +
/// снятие с кэша. v1: удаление ЛОКАЛЬНО — на других устройствах копия
/// остаётся (клиент протокола может выразить удаление своей записью —
/// данные тега определены приложением).
pub fn apiDeleteDb(app: *App, payload: []const u8, w: *api.Writer) api.Status {
    _ = w;
    var r = api.Reader.init(payload);
    const rec_id = r.readU32() catch return .BAD_FRAME;
    if (r.hasMore()) return .BAD_FRAME;
    app.lock();
    defer app.unlock();
    if (app.log) |log| _ = log.appendTombstone(rec_id) catch return .INTERNAL;
    var i: usize = 0;
    while (i < app.client_recs.items.len) {
        if (app.client_recs.items[i].seq == rec_id) {
            const rec = app.client_recs.orderedRemove(i);
            app.client_bytes -= rec.data.len;
            app.alloc.free(rec.data);
            // MAC остаётся: повторная доставка этой записи с устройства
            // должна отфильтроваться и после локального удаления
        } else i += 1;
    }
    return .OK;
}

/// CONNECT: payload [cid u32][addr str16] — прямое подключение к контакту
/// (обычно не нужно: автодозвон/LAN сами). Ответ пуст.
pub fn apiConnect(app: *App, payload: []const u8, w: *api.Writer) api.Status {
    _ = w;
    var r = api.Reader.init(payload);
    const cid = r.readU32() catch return .BAD_FRAME;
    const addr = r.readStr16() catch return .BAD_FRAME;
    if (r.hasMore()) return .BAD_FRAME;
    if (addr.len == 0) return .BAD_ARGS;
    var work = app_mod.ConnWork{ .cid = @intCast(cid) };
    if (addr.len > work.addr_buf.len) return .BAD_ARGS;
    {
        app.lock();
        defer app.unlock();
        if (cid < 1 or cid > app.eng.contacts.items.len) return .NO_CONTACT;
        // адрес контакта обновить (автодозвон видит последний известный)
        persist.saveContactAddr(app, @intCast(cid), addr);
    }
    @memcpy(work.addr_buf[0..addr.len], addr);
    work.addr_len = @intCast(addr.len);
    // 2.7.0: dial НЕ блокирует ответ — работа уходит планировщику;
    // стадии/результат — GET_CONTACT_STATE и события. Обычно не нужен:
    // ACCEPT_INVITE уже подключает из кода.
    connq.connEnqueue(app, work) catch return .BUSY;
    return .OK;
}

/// LISTEN: payload [addr str16][cid u32] — слушать входящие для контакта
/// (обычно не нужно: автолистенер уже слушает). Ответ пуст.
pub fn apiListen(app: *App, payload: []const u8, w: *api.Writer) api.Status {
    _ = w;
    var r = api.Reader.init(payload);
    const addr = r.readStr16() catch return .BAD_FRAME;
    const cid = r.readU32() catch return .BAD_FRAME;
    if (r.hasMore()) return .BAD_FRAME;
    if (addr.len == 0) return .BAD_ARGS;
    const lsn = tcp.listen(addr) catch return .TRANSPORT_FAILED;
    const lp = app.alloc.create(tcp.Listener) catch return .INTERNAL;
    lp.* = lsn;
    const th = std.Thread.spawn(.{}, struct {
        fn go(a: *App, l: *tcp.Listener, c: i64) void {
            dial.acceptLoop(a, l, c);
        }
    }.go, .{ app, lp, @as(i64, @intCast(cid)) }) catch return .INTERNAL;
    th.detach();
    return .OK;
}
