//! Применение записей device-sync: MAC-проверка, идемпотентное
//! применение к локальной БД и кэшу, ACK.
const std = @import("std");
const stille_messenger = @import("stille-messenger");
const envelope = stille_messenger.proto.envelope;
const sync_mod = stille_messenger.app.sync;
const app_mod = @import("app.zig");
const api_srv = @import("api_server.zig");
const engine_mod = stille_messenger.core.engine;
const api = @import("api.zig");
pub const App = app_mod.App;
const events = @import("events.zig");
const persist = @import("persist.zig");
const presence = @import("presence.zig");

/// Переводчик cid → bundle для очереди синхронизации (под app.mu).
/// Переводчик cid → bundle для SYNC (вызывается только под app.mu).
/// Публичен для app/recovery.zig (перепривязка после восстановления).
pub fn syncTranslateBundle(ctx: ?*anyopaque, cid: i64) ?[64]u8 {
    const app: *App = @ptrCast(@alignCast(ctx.?));
    if (cid < 1 or cid > app.eng.contacts.items.len) return null;
    return app.eng.contacts.items[@intCast(cid - 1)].bundle;
}

/// SYNC от устройства: проверить MAC каждой записи (ключ — только у
/// устройств с нашим сидом; подделка молча отбрасывается) и применить к
/// локальной БД; ответить SYNC_ACK. Работает в rx-потоке сессии под app.mu.
pub fn onSyncEv(ctx: *anyopaque, from: *const engine_mod.Contact, batch_id: u32, recs: []const u8, count: u8) void {
    const app: *App = @ptrCast(@alignCast(ctx));
    const idx = app_mod.contactIndexOf(app, from) orelse return;
    // неустройство прислать валидный SYNC не может (MAC), но и работы
    // на него не тратим
    if (!std.mem.eql(u8, &app.eng.contacts.items[idx].bundle, &app.id.bundle())) return;
    var views: [envelope.max_sync_recs]envelope.SyncRecView = undefined;
    const n = envelope.parseSyncRecs(recs, count, &views) catch 0;
    for (views[0..n]) |v| {
        if (!app.sync.verifyRec(v.kind, &v.mac, v.data)) continue;
        syncApplyRec(app, v.kind, &v.mac, v.data);
    }
    // партия обработана (применена или осознанно пропущена) — гасим
    if (app.eng.sessions.get(@intCast(idx + 1))) |s| {
        s.sendEnvelope(.{ .sync_ack = .{ .batch_id = batch_id } }) catch {};
    }
}

/// SYNC_ACK от устройства: партии подтверждены, очередь освобождается.
pub fn onSyncAckEv(ctx: *anyopaque, from: *const engine_mod.Contact, batch_id: u32) void {
    const app: *App = @ptrCast(@alignCast(ctx));
    const idx = app_mod.contactIndexOf(app, from) orelse return;
    app.sync.onAck(@intCast(idx + 1), batch_id);
}

/// Применить провалидированную MAC-ом запись SYNC к локальной БД.
/// Идемпотентно (дубликаты/повторы после обрыва ничего не меняют) и НЕ
/// ставит результат в исходящую очередь синхронизации (иначе петля
/// A→B→A). Вызывается ПОД app.mu.
pub fn syncApplyRec(app: *App, kind: u8, mac: *const [32]u8, data: []const u8) void {
    switch (kind) {
        @backingInt(sync_mod.RecKind.msg) => syncApplyMsg(app, data),
        @backingInt(sync_mod.RecKind.contact) => syncApplyContact(app, data),
        @backingInt(sync_mod.RecKind.block) => syncApplyBlock(app, data),
        @backingInt(sync_mod.RecKind.react) => syncApplyReact(app, data),
        @backingInt(sync_mod.RecKind.ack) => syncApplyAck(app, data),
        @backingInt(sync_mod.RecKind.file) => syncApplyFile(app, data),
        @backingInt(sync_mod.RecKind.client) => syncApplyClient(app, mac, data),
        @backingInt(sync_mod.RecKind.cfg) => syncApplyCfg(app, data),
        else => {},
    }
}

/// Запись msg: [bundle 64][flags][msg_id 16][ts 8][reply 16?][len 2][body][ents].
/// bundle → локальный cid; дубликат по msg_id пропускается. Чужие сообщения
/// поднимают событие клиенту, свои — только историю.
pub fn syncApplyMsg(app: *App, data: []const u8) void {
    if (data.len < 64 + 27) return;
    const cid = app_mod.contactIdByBundle(app, data[0..64].*) orelse return;
    const rest = data[64..];
    const flags = rest[0];
    const msg_id = rest[1..17].*;
    if (app.hist_idx.contains(msg_id)) return;
    const has_reply = flags & 0b100 != 0;
    const body_off: usize = if (has_reply) 43 else 27; // координаты rest
    if (rest.len < body_off) return;
    const blen = std.mem.readInt(u16, rest[body_off - 2 ..][0..2], .little);
    if (blen > 4096) return;
    const body_end = body_off + blen;
    if (rest.len < body_end) return;
    const tail = rest[body_end..];
    _ = envelope.parseEntities(tail, blen, null) catch return;
    // пересборка записи с локальным cid
    var buf: [2 + 45 + 2 + 4096 + envelope.max_text_tail]u8 = undefined;
    std.mem.writeInt(u16, buf[0..2], @intCast(cid), .little);
    @memcpy(buf[2..][0..rest.len], rest);
    const rec = buf[0 .. 2 + rest.len];
    if (app.log) |log| _ = log.append(.msg, rec) catch {};
    persist.histAppend(app, rec, msg_id);
    if (flags & 1 == 0) { // чужое сообщение — виден как входящее
        var ents: [envelope.max_text_entities]envelope.TextEntity = undefined;
        const n = envelope.parseEntities(tail, blen, &ents) catch 0;
        const c = &app.eng.contacts.items[@intCast(cid - 1)];
        const ts: i64 = @intCast(std.mem.readInt(u64, rest[17..25], .little));
        if (has_reply) {
            events.evReplyReceived(app, cid, msg_id, rest[27..43].*, ts, c.getName(), rest[body_off..body_end], ents[0..n]);
        } else {
            events.evMessageReceived(app, cid, msg_id, ts, c.getName(), rest[body_off..body_end], ents[0..n]);
        }
    }
}

/// Запись contact: формат лога (bundle-ключуемая). Неизвестный bundle —
/// добавляем контакт; свой bundle не создаём (линк — только явным кодом).
/// В локальный лог пишем только префикс [nlen][name][bundle]: хвосты
/// адресов/релея исходного устройства нам не нужны (свои адреса узнает
/// автодозвон/linker).
pub fn syncApplyContact(app: *App, data: []const u8) void {
    if (data.len < 66) return;
    const nlen: usize = data[0];
    if (data.len < 1 + nlen + 64) return;
    const bundle = data[1 + nlen ..][0..64].*;
    if (std.mem.eql(u8, &bundle, &app.id.bundle())) return;
    if (app_mod.contactIdByBundle(app, bundle) != null) return; // уже знаем
    const idx = app.eng.addContact(data[1 .. 1 + nlen], bundle) catch return;
    app.hb.put(@intCast(idx + 1), .{}) catch {};
    if (app.log) |log| _ = log.append(.contact, data[0 .. 1 + nlen + 64]) catch {};
}

/// Запись block: [bundle 64][flag u8] — флаг контакта.
pub fn syncApplyBlock(app: *App, data: []const u8) void {
    if (data.len != 65) return;
    const cid = app_mod.contactIdByBundle(app, data[0..64].*) orelse return;
    const c = &app.eng.contacts.items[@intCast(cid - 1)];
    if (c.deleted) return;
    c.blocked = data[64] != 0;
    if (app.log) |log| _ = log.append(.block, data) catch {};
    // v1: живую сессию не рвём — флаг применяется, notice/retire локально
}

/// Запись react: [bundle 64][flags][msg_id 16][op][code u32][ts u64];
/// пересборка с локальным cid, чужая реакция — событие клиенту.
pub fn syncApplyReact(app: *App, data: []const u8) void {
    if (data.len != 64 + 30) return;
    const cid = app_mod.contactIdByBundle(app, data[0..64].*) orelse return;
    const rest = data[64..]; // [flags][msg_id 16][op][code][ts] = 30
    var buf: [32]u8 = undefined;
    std.mem.writeInt(u16, buf[0..2], @intCast(cid), .little);
    @memcpy(buf[2..][0..30], rest);
    if (app.log) |log| _ = log.append(.react, buf[0..32]) catch {};
    if (rest[0] == 0) { // чужая реакция
        const msg_id = rest[1..17].*;
        const op = rest[17];
        const code = std.mem.readInt(u32, rest[18..22], .little);
        const ts: i64 = @intCast(std.mem.readInt(u64, rest[22..30], .little));
        events.evReaction(app, cid, msg_id, op, code, ts);
    }
}

/// Запись ack: [msg_id 16] — глобальный идентификатор; локальный cid
/// берём из кэша истории, delivered гасится без повторной постановки
/// в очередь синхронизации.
pub fn syncApplyAck(app: *App, data: []const u8) void {
    if (data.len != 16) return;
    const msg_id = data[0..16].*;
    const i = app.hist_idx.get(msg_id) orelse return;
    const rec = app.hist.items[i];
    if (rec.len < 2) return;
    persist.writeOutboxAck(app, @intCast(std.mem.readInt(u16, rec[0..2], .little)), msg_id);
}

/// Запись file: [bundle 64][file_id 16][size u32][nlen u8][name].
pub fn syncApplyFile(app: *App, data: []const u8) void {
    if (data.len < 64 + 23) return;
    const cid = app_mod.contactIdByBundle(app, data[0..64].*) orelse return;
    const rest = data[64..];
    const nlen: usize = rest[22];
    if (rest.len != 23 + nlen) return;
    var buf: [23 + 64]u8 = undefined;
    std.mem.writeInt(u16, buf[0..2], @intCast(cid), .little);
    @memcpy(buf[2..][0..rest.len], rest);
    if (app.log) |log| _ = log.append(.file, buf[0 .. 23 + nlen]) catch {};
    events.evFileReceived(app, cid, rest[0..16].*, std.mem.readInt(u32, rest[16..20], .little), rest[23..]);
}

/// Запись client: [tag][ts 8][len 2][data]; дедуп по MAC, капа client_db_cap.
pub fn syncApplyClient(app: *App, mac: *const [32]u8, data: []const u8) void {
    if (data.len < 11) return;
    const dlen: usize = std.mem.readInt(u16, data[9..11], .little);
    if (dlen == 0 or dlen > app_mod.max_client_data or data.len != 11 + dlen) return;
    if (app.client_macs.contains(mac.*)) return;
    if (app.client_bytes + dlen > app_mod.client_db_cap) return;
    const seq = blk: {
        const log = app.log orelse return;
        break :blk log.append(.client, data) catch return;
    };
    clientCacheAppend(app, .{
        .seq = seq,
        .tag = data[0],
        .ts_ms = std.mem.readInt(u64, data[1..9], .little),
        .data = app.alloc.dupe(u8, data[11..]) catch return,
    }, mac.*);
}

/// Запись cfg: blob конфигурации. Применяется (валидация decode),
/// пишется в лог и рассылается CONFIG_CHANGED. Постановки в очередь
/// синхронизации НЕТ — применённое не ретранслируется (иначе петля).
pub fn syncApplyCfg(app: *App, data: []const u8) void {
    var c = app.cfg;
    c.decode(data) catch return;
    presence.applyConfigLocked(app, c);
    if (app.log) |log| _ = log.append(.cfg, data) catch {};
    events.evConfigChanged(app);
}

/// Клиентские записи: WRAPPER кэша (память + MAC + счётчик).
pub fn clientCacheAppend(app: *App, rec: app_mod.ClientRec, mac: [32]u8) void {
    app.client_recs.append(app.alloc, rec) catch {
        app.alloc.free(rec.data);
        return;
    };
    app.client_macs.put(app.alloc, mac, {}) catch {};
    app.client_bytes += rec.data.len;
}
