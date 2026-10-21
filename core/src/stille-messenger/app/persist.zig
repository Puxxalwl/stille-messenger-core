//! Персистентность: формат записей лога (msg/contact/react/ack/
//! file/set), кэш истории и закреплений, синхронная постановка
//! записей в device-sync, полный replay профиля при старте.
const std = @import("std");
const stille_messenger = @import("stille-messenger");
const envelope = stille_messenger.proto.envelope;
const store_mod = stille_messenger.store.log;
const sync_mod = stille_messenger.app.sync;
const identity = stille_messenger.crypto.identity;
const invite_mod = @import("invite.zig");
const app_mod = @import("app.zig");
const session_mod = stille_messenger.core.session;
pub const App = app_mod.App;
const events = @import("events.zig");
const search_mod = @import("search.zig");
const presence = @import("presence.zig");

/// Постановка записи формата лога в очереди синхронизации всех устройств.
/// Вызывается ПОД app.mu из persist*/api* — сразу после записи в лог.
/// Записи больше sync_mod.max_rec (например, аватары 16 КБ) не синхронятся.
pub fn syncEnqueue(app: *App, kind: u8, payload: []const u8) void {
    if (!app.cfg.device_sync) return;
    app.sync.enqueue(kind, payload);
}

/// Слить очереди синхронизации всем устройствам с живыми сессиями.
/// Вызывается ПОД app.mu после постановки записей.
pub fn syncPumpLocked(app: *App) void {
    if (!app.cfg.device_sync) return;
    var it = app.sync.devices.keyIterator();
    while (it.next()) |cid| syncFlushLocked(app, cid.*);
}

/// Отдать очереди устройства по живой сессии партиями SYNC. Обрыв или
/// переполнение — партии возвращаются в очередь (повторная доставка
/// идемпотентна на приёме). Вызывается ПОД app.mu.
pub fn syncFlushLocked(app: *App, cid: i64) void {
    if (!app.cfg.device_sync) return;
    const s = app.eng.sessions.get(cid) orelse return;
    const d = app.sync.devices.get(cid) orelse return;
    var buf: [envelope.max_sync_tail]u8 = undefined;
    while (app.sync.takeBatch(d, &buf)) |b| {
        s.sendEnvelope(.{ .sync = .{
            .batch_id = b.batch_id,
            .count = b.count,
            .recs = b.tail,
        } }) catch {
            app.sync.onSessionDown(cid);
            return;
        };
    }
}

/// Закодировать контактную запись формата лога (kind contact) в `buf`;
/// вернуть длину. Имя ≤ 32, хвосты: [alen][host][port u16 LE] адреса,
/// [rlen][rhost][rport u16 LE] релея, затем байт роли линка устройства
/// (пишется только для устройств; старые читатели хвост не знают).
/// Используется логом (logContact) и recovery-пакетом (app/recovery.zig).
pub fn encodeContactRecord(buf: []u8, name: []const u8, bundle: [64]u8, addr_: ?[]const u8, relay_addr: ?[]const u8, dev_role: u8) usize {
    const a: []const u8 = addr_ orelse "";
    const ra: []const u8 = relay_addr orelse "";
    var n: usize = 0;
    buf[0] = @intCast(name.len);
    n = 1;
    @memcpy(buf[n .. n + name.len], name);
    n += name.len;
    @memcpy(buf[n .. n + 64], &bundle);
    n += 64;
    // хвост адреса: [alen][host][port u16 LE] (для совместимости со старыми логами)
    const host_port = splitHostPort(a);
    const alen = host_port.host.len;
    if (alen > 0 and alen <= 64) {
        buf[n] = @intCast(alen);
        n += 1;
        @memcpy(buf[n .. n + alen], host_port.host);
        n += alen;
        std.mem.writeInt(u16, buf[n..][0..2], host_port.port, .little);
        n += 2;
    }
    // хвост relay-адреса: [rlen][rhost][rport u16 LE] (старые логи короче)
    const rhp = splitHostPort(ra);
    if (rhp.host.len > 0 and rhp.host.len <= 64) {
        buf[n] = @intCast(rhp.host.len);
        n += 1;
        @memcpy(buf[n .. n + rhp.host.len], rhp.host);
        n += rhp.host.len;
        std.mem.writeInt(u16, buf[n..][0..2], rhp.port, .little);
        n += 2;
    }
    // хвост роли линка устройства: пишется только для устройств (старые
    // читатели хвост не знают, новые — читают только при наличии байта)
    if (dev_role != 0 and n < buf.len) {
        buf[n] = dev_role;
        n += 1;
    }
    return n;
}

/// Записать контакт в лог (с адресом, если известен; relay_addr — хвост
/// [rlen][rhost][rport LE] для восстановления присутствия после рестарта;
/// dev_role — хвостовой байт роли линка устройства, 0 = не устройство).
pub fn logContact(app: *App, log: *store_mod.Log, name: []const u8, bundle: [64]u8, addr_: ?[]const u8, relay_addr: ?[]const u8, dev_role: u8) void {
    // 232 = максимум записи (имя 32 + bundle + оба хвоста + роль линка)
    var buf: [232]u8 = undefined;
    const n = encodeContactRecord(&buf, name, bundle, addr_, relay_addr, dev_role);
    _ = log.append(.contact, buf[0..n]) catch {};
    syncEnqueue(app, @backingInt(sync_mod.RecKind.contact), buf[0..n]);
    syncPumpLocked(app);
}

pub const HostPort = struct { host: []const u8, port: u16 };

/// "host:port" -> {host, port}; без порта — port 0.
pub fn splitHostPort(a: []const u8) HostPort {
    // 2.10.0: "[v6]:port" — хост без скобок (скобки добавит Contact.addr)
    if (a.len >= 4 and a[0] == '[') {
        if (std.mem.indexOfScalar(u8, a, ']')) |close| {
            if (close + 1 < a.len and a[close + 1] == ':') {
                const port = std.fmt.parseInt(u16, a[close + 2 ..], 10) catch 0;
                return .{ .host = a[1..close], .port = port };
            }
        }
    }
    if (std.mem.lastIndexOfScalar(u8, a, ':')) |c| {
        const port = std.fmt.parseInt(u16, a[c + 1 ..], 10) catch 0;
        return .{ .host = a[0..c], .port = port };
    }
    return .{ .host = a, .port = 0 };
}

/// Запомнить адрес контакта (в памяти и логе).
pub fn saveContactAddr(app: *App, cid: i64, host_port_str: []const u8) void {
    const hp = splitHostPort(host_port_str);
    const c = &app.eng.contacts.items[@intCast(cid - 1)];
    if (hp.port == 0) return;
    // не перезаписываем адрес логом при каждом чихе — только если изменился
    if (c.addr_len == hp.host.len and c.addr_port == hp.port and
        std.mem.eql(u8, c.addr_buf[0..c.addr_len], hp.host)) return;
    c.setAddr(hp.host, hp.port);
    if (app.log) |log| {
        // не теряем relay-хвост и роль линка при перезаписи адреса
        const relay_saved = app.contact_relays.get(cid);
        logContact(app, log, c.getName(), c.bundle, host_port_str, relay_saved, c.dev_role);
    }
}

/// Записать в лог последнюю запись outbox (вызов ПОД локом сразу после
/// sendText == .queued: она наша, очередь под локом).
pub fn persistOutboxAdd(app: *App) void {
    const log = app.log orelse return;
    const items = app.eng.outbox.items;
    if (items.len == 0) return;
    const e = items[items.len - 1];
    if (e.body.len > 4096) return;
    if (e.ents_tail.len > envelope.max_text_tail) return;
    var buf: [3 + 16 + 8 + 16 + 2 + 4096 + envelope.max_text_tail]u8 = undefined;
    std.mem.writeInt(u16, buf[1..3], @intCast(e.cid), .little);
    buf[0] = 1;
    @memcpy(buf[3 .. 3 + 16], &e.msg_id);
    std.mem.writeInt(u64, buf[19..27], e.ts_ms, .little);
    const body_off: usize = if (e.reply_to) |rid| blk: {
        buf[0] |= 0b100;
        @memcpy(buf[29..45], &rid);
        break :blk 45;
    } else 29;
    std.mem.writeInt(u16, buf[body_off - 2 ..][0..2], @intCast(e.body.len), .little);
    @memcpy(buf[body_off .. body_off + e.body.len], e.body);
    var n = body_off + e.body.len;
    // хвост entities: пусто -> счётчик 0 (новые записи всегда с хвостом)
    if (e.ents_tail.len == 0) {
        buf[n] = 0;
        n += 1;
    } else {
        @memcpy(buf[n .. n + e.ents_tail.len], e.ents_tail);
        n += e.ents_tail.len;
    }
    _ = log.append(.outbox, buf[0..n]) catch {};
}

/// Записать в лог погашение (ACK) записи outbox — заодно это отметка
/// delivered для истории: при загрузке ACK-записи ставят бит1 записям
/// kind msg (рассинхрон «доставлено, но в истории 0» после рестарта).
/// Кэш истории гасится сразу. Вызывается ПОД app.mu. Запись НЕ ставится
/// в очередь синхронизации (применённая с устройства — иначе петля).
pub fn persistOutboxAck(app: *App, cid: i64, msg_id: [16]u8) void {
    writeOutboxAck(app, cid, msg_id);
    // доставленность реплицируется: бит delivered в истории другого
    // устройства должен погаситься тем же ACK-ом
    var buf: [3 + 16]u8 = undefined;
    buf[0] = 0;
    std.mem.writeInt(u16, buf[1..3], @intCast(cid), .little);
    @memcpy(buf[3 .. 3 + 16], &msg_id);
    syncEnqueue(app, @backingInt(sync_mod.RecKind.ack), &buf);
    syncPumpLocked(app);
}

/// Чистая запись ACK в лог (без постановки в очередь синхронизации):
/// локальный ACK доставки и путь применения синхронизации.
pub fn writeOutboxAck(app: *App, cid: i64, msg_id: [16]u8) void {
    var buf: [3 + 16]u8 = undefined;
    buf[0] = 0;
    std.mem.writeInt(u16, buf[1..3], @intCast(cid), .little);
    @memcpy(buf[3 .. 3 + 16], &msg_id);
    if (app.log) |log| _ = log.append(.outbox, &buf) catch {};
    histDelivered(app, msg_id);
}

/// Записать реакцию в лог (kind react: [cid u16][flags u8][msg_id 16]
/// [op u8][code u32][ts u64]; бит0 flags = моя реакция).
pub fn persistReact(app: *App, cid: i64, mine: bool, msg_id: [16]u8, op: u8, code: u32, ts_ms: i64) void {
    const log = app.log orelse return;
    var buf: [32]u8 = undefined;
    std.mem.writeInt(u16, buf[0..2], @intCast(cid), .little);
    buf[2] = @intFromBool(mine);
    @memcpy(buf[3 .. 3 + 16], &msg_id);
    buf[19] = op;
    std.mem.writeInt(u32, buf[20..24], code, .little);
    std.mem.writeInt(u64, buf[24..32], @intCast(ts_ms), .little);
    _ = log.append(.react, buf[0..32]) catch {};
    syncEnqueue(app, @backingInt(sync_mod.RecKind.react), buf[0..32]);
    syncPumpLocked(app);
}

/// Заглушка хвоста entities «форматирования нет»: один байт счётчика 0.
pub const zero_tail = [_]u8{0};

/// Message-log body offset. Bit2 in flags marks a reply record and inserts
/// `reply_to[16]` before `[body_len u16][body]`; bit2 was unused in v1.
pub fn msgBodyOffset(rec: []const u8) ?usize {
    if (rec.len < 29) return null;
    return if ((rec[2] & 0b100) != 0) 45 else 29;
}

pub fn msgBodyLen(rec: []const u8) ?usize {
    const off = msgBodyOffset(rec) orelse return null;
    if (rec.len < off) return null;
    return std.mem.readInt(u16, rec[off - 2 ..][0..2], .little);
}

pub fn msgReplyTo(rec: []const u8) ?[16]u8 {
    if (rec.len < 45 or (rec[2] & 0b100) == 0) return null;
    return rec[29..45].*;
}

/// Хвост entities записи kind msg/outbox. Старые записи без reply остаются
/// читаемыми; битый хвост — null: запись пропускается.
pub fn recEntityTail(rec: []const u8, blen: usize) ?[]const u8 {
    const body_off = msgBodyOffset(rec) orelse return null;
    const body_end = body_off + blen;
    if (rec.len == body_end) return &zero_tail;
    if (rec.len < body_end) return null;
    const tail = rec[body_end..];
    _ = envelope.parseEntities(tail, blen, null) catch return null;
    return tail;
}

/// Записать сообщение в историю (kind msg, шифрованный лог). После body —
/// хвост entities (канонический формат; пустые ents -> счётчик 0). Чтение
/// толерантно к старым записям без хвоста (история переживает апгрейд).
/// ts — реальное локальное время (мс), метка в конверте остаётся приватной.
/// Запись попадает и в лог, и в кэш истории (GET_HISTORY/GET_MESSAGE/SEARCH
/// читают только кэш). Вызывается ПОД app.mu.
pub fn persistMsg(app: *App, cid: i64, mine: bool, msg_id: [16]u8, reply_to: ?[16]u8, delivered: bool, ts_ms: i64, body: []const u8, ents: []const envelope.TextEntity) void {
    if (body.len == 0 or body.len > 4096) return;
    var tail_buf: [envelope.max_text_tail]u8 = undefined;
    const tail = envelope.encodeEntitiesTail(&tail_buf, ents, body.len) catch return;
    var buf: [3 + 16 + 8 + 16 + 2 + 4096 + envelope.max_text_tail]u8 = undefined;
    std.mem.writeInt(u16, buf[0..2], @intCast(cid), .little);
    // бит0 = mine, бит1 = delivered (мой текст: 0 до ACK — погашение
    // пишется записью kind outbox в persistOutboxAck)
    const reply_flag: u8 = if (reply_to != null) 0b100 else 0;
    buf[2] = @as(u8, @intFromBool(mine)) | (@as(u8, @intFromBool(delivered)) << 1) | reply_flag;
    @memcpy(buf[3 .. 3 + 16], &msg_id);
    std.mem.writeInt(u64, buf[19..27], @intCast(ts_ms), .little);
    const body_off: usize = if (reply_to) |rid| blk: {
        @memcpy(buf[29..45], &rid);
        break :blk 45;
    } else 29;
    std.mem.writeInt(u16, buf[body_off - 2 ..][0..2], @intCast(body.len), .little);
    @memcpy(buf[body_off .. body_off + body.len], body);
    @memcpy(buf[body_off + body.len ..][0..tail.len], tail);
    const rec = buf[0 .. body_off + body.len + tail.len];
    if (app.log) |log| _ = log.append(.msg, rec) catch {};
    histAppend(app, rec, msg_id);
    syncEnqueue(app, @backingInt(sync_mod.RecKind.msg), rec);
    syncPumpLocked(app);
}

/// Положить копию записи kind msg в кэш истории (+ индекс по msg_id).
/// Вызывается ПОД app.mu.
pub fn histAppend(app: *App, rec: []const u8, msg_id: [16]u8) void {
    const copy = app.alloc.dupe(u8, rec) catch return;
    app.hist.append(app.alloc, copy) catch {
        app.alloc.free(copy);
        return;
    };
    app.hist_idx.put(app.alloc, msg_id, app.hist.items.len - 1) catch {};
}

/// Погасить delivered в кэше истории (ACK дошёл). Вызывается ПОД app.mu.
pub fn histDelivered(app: *App, msg_id: [16]u8) void {
    const i = app.hist_idx.get(msg_id) orelse return;
    const rec = app.hist.items[i];
    if (rec.len >= 3) rec[2] |= 0b10; // бит1 = delivered
}

/// Выкинуть из кэша истории все записи чата (DELETE_CHAT). Полная
/// перекомпоновка: индексы msg_id смещаются. Вызывается ПОД app.mu.
pub fn histPurgeFor(app: *App, cid: i64) void {
    var keep: std.ArrayListUnmanaged([]u8) = .empty;
    for (app.hist.items) |rec| {
        if (rec.len >= 2 and std.mem.readInt(u16, rec[0..2], .little) == cid) {
            app.alloc.free(rec);
        } else {
            keep.append(app.alloc, rec) catch {
                // OOM: запись теряем — лучше потерять кэш-строку, чем упасть
                app.alloc.free(rec);
            };
        }
    }
    app.hist.deinit(app.alloc);
    app.hist = keep;
    app.hist_idx.clearRetainingCapacity();
    for (app.hist.items, 0..) |rec, i| {
        if (rec.len < 29) continue;
        app.hist_idx.put(app.alloc, rec[3 .. 3 + 16].*, i) catch {};
    }
}

/// Записать принятый файл в лог (kind file): переживает рестарты.
/// Вызывается под app.mu.
pub fn persistFileMeta(app: *App, cid: i64, file_id: [16]u8, size: u32, name: []const u8) void {
    const log = app.log orelse return;
    var buf: [23 + 64]u8 = undefined;
    std.mem.writeInt(u16, buf[0..2], @intCast(cid), .little);
    @memcpy(buf[2..18], &file_id);
    std.mem.writeInt(u32, buf[18..22], size, .little);
    const n = @min(name.len, 64);
    buf[22] = @intCast(n);
    @memcpy(buf[23 .. 23 + n], name[0..n]);
    _ = log.append(.file, buf[0 .. 23 + n]) catch {};
    syncEnqueue(app, @backingInt(sync_mod.RecKind.file), buf[0 .. 23 + n]);
    syncPumpLocked(app);
}

/// Загрузка профиля из лога: конфигурация, контакты (+relay-присутствие),
/// настройки (set), история-кэш, аватары, блокировки, клиентская БД.
/// Вызывается стартом serve и восстановлением профиля (app/recovery.zig)
/// ПОД app.mu. Публична для тестов приложения.
pub fn loadContacts(app: *App) void {
    const log = app.log orelse return;
    // конфигурация первой: server_mode поднимает присутствие в конце
    // загрузки, device_sync нужен для регистраций линков. Последняя
    // запись побеждает (SET_CONFIG пишет новую); битая — пропускается
    // (defaults остаются).
    if (log.readAll(.cfg, app.alloc)) |cfgs| {
        defer {
            for (cfgs) |r| app.alloc.free(r);
            app.alloc.free(cfgs);
        }
        for (cfgs) |rec| {
            var c = app.cfg;
            c.decode(rec) catch continue;
            app.cfg = c;
        }
    } else |_| {}
    const recs = log.readAll(.contact, app.alloc) catch return;
    defer {
        for (recs) |r| app.alloc.free(r);
        app.alloc.free(recs);
    }
    for (recs) |rec| {
        if (rec.len < 66) continue;
        const nlen: usize = rec[0];
        if (rec.len < 1 + nlen + 64) continue;
        const name = rec[1 .. 1 + nlen];
        const bundle: [64]u8 = rec[1 + nlen ..][0..64].*;
        const idx = app.eng.addContact(name, bundle) catch return;
        app.hb.put(@intCast(idx + 1), .{}) catch {};
        // хвост адреса: [alen][host][port LE] (последняя запись побеждает)
        const c = &app.eng.contacts.items[idx];
        const tail = 1 + nlen + 64;
        if (rec.len >= tail + 1) {
            const alen: usize = rec[tail];
            if (alen > 0 and alen <= 64 and rec.len >= tail + 1 + alen + 2) {
                const port = std.mem.readInt(u16, rec[tail + 1 + alen ..][0..2], .little);
                c.setAddr(rec[tail + 1 .. tail + 1 + alen], port);
            }
            // relay-хвост: [rlen][rhost][rport LE] — присутствие после рестарта
            const rtail = tail + 1 + alen + 2;
            if (rec.len >= rtail + 1) {
                const rlen: usize = rec[rtail];
                if (rlen > 0 and rlen <= 64 and rec.len >= rtail + 1 + rlen + 2) {
                    const rport = std.mem.readInt(u16, rec[rtail + 1 + rlen ..][0..2], .little);
                    var rbuf: [72]u8 = undefined;
                    const rhost = rec[rtail + 1 .. rtail + 1 + rlen];
                    const raddr = std.fmt.bufPrint(&rbuf, "{s}:{d}", .{ rhost, rport }) catch rbuf[0..0];
                    if (raddr.len > 0) {
                        presence.startRelayPresenceLocked(app, @intCast(idx + 1), raddr);
                    }
                }
                // хвост роли линка устройства: [dev_role u8] после relay
                // (старые записи без байта — не устройство)
                const dtail = rtail + 1 + rlen + 2;
                if (rec.len == dtail + 1) {
                    const role = rec[dtail];
                    if (role == app_mod.dev_role_waiter or role == app_mod.dev_role_holder) {
                        c.dev_role = role;
                    }
                }
            }
        }
    }
    // настройки ДО истории и outbox: надгробия (set:7) должны закрыть слоты
    // раньше, чем записи начнут фильтроваться по deleted
    //   set:1 [1][avatar_id 16] — мой avatar_id
    //   set:2 [2][имя]          — моё имя профиля
    //   set:3 [3][cid u16]      — закрепить чат
    //   set:4 [4]               — снять закрепление чата
    //   set:5 [5][cid u16][msg_id 16] — закрепить сообщение
    //   set:6 [6][cid u16][msg_id 16] — открепить сообщение
    //   set:7 [7][cid u16]      — надгробие удалённого чата (слот невидим)
    const sets = log.readAll(.set, app.alloc) catch return;
    defer {
        for (sets) |r| app.alloc.free(r);
        app.alloc.free(sets);
    }
    for (sets) |rec| {
        if (rec.len == 17 and rec[0] == 1) app.eng.my_avatar_id = rec[1..17].*;
        if (rec.len >= 2 and rec[0] == 2) app.eng.setMyProfile(rec[1..rec.len], app.eng.my_avatar_id);
        if (rec.len == 3 and rec[0] == 3) {
            const cid = std.mem.readInt(u16, rec[1..3], .little);
            if (cid >= 1 and cid <= app.eng.contacts.items.len) app.pinned_chat = cid;
        }
        if (rec.len == 1 and rec[0] == 4) app.pinned_chat = 0;
        if (rec.len == 19 and rec[0] == 5) {
            const cid: i64 = @intCast(std.mem.readInt(u16, rec[1..3], .little));
            const msg_id: [16]u8 = rec[3..19].*;
            if (cid >= 1 and cid <= app.eng.contacts.items.len) {
                const list = app.pinned_msgs.getOrPut(app.alloc, cid) catch continue;
                if (!list.found_existing) list.value_ptr.* = .empty;
                if (list.value_ptr.items.len < app_mod.max_pinned_msgs)
                    list.value_ptr.append(app.alloc, msg_id) catch {};
            }
        }
        if (rec.len == 19 and rec[0] == 6) {
            const cid: i64 = @intCast(std.mem.readInt(u16, rec[1..3], .little));
            const msg_id: [16]u8 = rec[3..19].*;
            if (app.pinned_msgs.getPtr(cid)) |list| {
                var i: usize = 0;
                while (i < list.items.len) : (i += 1) {
                    if (std.mem.eql(u8, &list.items[i], &msg_id)) {
                        _ = list.orderedRemove(i);
                        break;
                    }
                }
            }
        }
        if (rec.len == 3 and rec[0] == 7) {
            const cid = std.mem.readInt(u16, rec[1..3], .little);
            if (cid >= 1 and cid <= app.eng.contacts.items.len) {
                app.eng.contacts.items[cid - 1].deleted = true;
                app.eng.contacts.items[cid - 1].online = false;
            }
        }
        // эпоха персистентного кода профиля (REGENERATE_PROFILE_CODE):
        // реплей применяет ПОСЛЕДНЮЮ записанную (лог append-only)
        if (rec.len == 5 and rec[0] == 8) app.profile_epoch = std.mem.readInt(u32, rec[1..5], .little);
    }
    // история: кэш записей kind msg в памяти (GET_HISTORY/GET_MESSAGE/SEARCH
    // больше не читают лог); чаты-надгробия в кэш не попадают
    const msgs = log.readAll(.msg, app.alloc) catch return;
    defer {
        for (msgs) |r| app.alloc.free(r);
        app.alloc.free(msgs);
    }
    for (msgs) |rec| {
        if (rec.len < 29) continue;
        const cid = std.mem.readInt(u16, rec[0..2], .little);
        if (!chatAlive(app, cid)) continue;
        histAppend(app, rec, rec[3 .. 3 + 16].*);
    }
    // outbox: добавление/погашение в порядке записи лога; ACK заодно
    // гасит delivered в кэше истории (правда о доставке после рестарта)
    const obs = log.readAll(.outbox, app.alloc) catch return;
    defer {
        for (obs) |r| app.alloc.free(r);
        app.alloc.free(obs);
    }
    for (obs) |rec| {
        if (rec.len < 3) continue;
        const cid: i64 = @intCast(std.mem.readInt(u16, rec[1..3], .little));
        if (cid < 1 or cid > app.eng.contacts.items.len) continue;
        if (rec[0] == 0) {
            if (rec.len < 3 + 16) continue;
            const msg_id: [16]u8 = rec[3 .. 3 + 16].*;
            var i: usize = 0;
            while (i < app.eng.outbox.items.len) {
                if (app.eng.outbox.items[i].cid == cid and std.mem.eql(u8, &app.eng.outbox.items[i].msg_id, &msg_id)) {
                    const old = app.eng.outbox.orderedRemove(i);
                    app.alloc.free(old.body);
                    app.alloc.free(old.ents_tail);
                } else i += 1;
            }
            histDelivered(app, msg_id);
            continue;
        }
        if (app.eng.contacts.items[@intCast(cid - 1)].deleted) continue;
        if (rec.len < 3 + 16 + 8 + 2) continue;
        const msg_id: [16]u8 = rec[3 .. 3 + 16].*;
        const ts_ms = std.mem.readInt(u64, rec[19..27], .little);
        const body_off = msgBodyOffset(rec) orelse continue;
        const blen = msgBodyLen(rec) orelse continue;
        if (blen == 0 or blen > 4096 or rec.len < body_off + blen) continue;
        const body = app.alloc.dupe(u8, rec[body_off .. body_off + blen]) catch continue;
        const reply_to = msgReplyTo(rec);
        // хвост entities: старые записи без хвоста — форматирования нет
        var ents_tail: []u8 = &.{};
        if (rec.len > body_off + blen) {
            const t = recEntityTail(rec, blen) orelse {
                app.alloc.free(body);
                continue;
            };
            ents_tail = app.alloc.dupe(u8, t) catch {
                app.alloc.free(body);
                continue;
            };
        }
        // queued_ms в записи лога не хранится (формат записи не меняем):
        // TTL стартует с рестарта — консервативно, запись живёт дольше
        app.eng.outbox.append(app.alloc, .{ .cid = cid, .msg_id = msg_id, .ts_ms = ts_ms, .queued_ms = @intCast(app.nowMs()), .reply_to = reply_to, .body = body, .ents_tail = ents_tail }) catch {
            app.alloc.free(body);
            app.alloc.free(ents_tail);
        };
    }
    // аватары: кэш id -> байты (свои и чужие)
    const avs = log.readAll(.avatar, app.alloc) catch return;
    defer {
        for (avs) |r| app.alloc.free(r);
        app.alloc.free(avs);
    }
    for (avs) |rec| {
        if (rec.len < 18) continue;
        const alen = std.mem.readInt(u16, rec[16..18], .little);
        if (alen == 0 or alen > 16000 or rec.len < 18 + alen) continue;
        const id: [16]u8 = rec[0..16].*;
        const copy = app.alloc.dupe(u8, rec[18 .. 18 + alen]) catch continue;
        app.avatars.put(app.alloc, id, copy) catch {
            app.alloc.free(copy);
        };
    }
    // блокировки поверх загруженных контактов
    const blocks = log.readAll(.block, app.alloc) catch return;
    defer {
        for (blocks) |r| app.alloc.free(r);
        app.alloc.free(blocks);
    }
    for (blocks) |rec| {
        if (rec.len != 65) continue;
        const bundle: [64]u8 = rec[0..64].*;
        const flag = rec[64] == 1;
        for (app.eng.contacts.items) |*c| {
            if (std.mem.eql(u8, &c.bundle, &bundle)) c.blocked = flag;
        }
    }
    // клиентские записи БД (kind client): кэш для READ_DB + MAC-и для
    // дедупа синхронизации. Капа кэша client_db_cap (жёсткая при записи,
    // мягкая при загрузке: лишнее остаётся в логе, но не в памяти).
    if (log.readAllSeq(.client, app.alloc)) |crecs| {
        defer {
            for (crecs) |r| app.alloc.free(r.payload);
            app.alloc.free(crecs);
        }
        for (crecs) |r| loadClientRec(app, r.seq, r.payload);
    } else |_| {}
    // линейки устройств: bundle == наш, слот жив (не надгробие) —
    // регистрируем в синхронизаторе (очередь записей БД на это устройство)
    for (app.eng.contacts.items, 0..) |*c, i| {
        if (c.deleted or c.dev_role == 0) continue;
        if (std.mem.eql(u8, &c.bundle, &app.id.bundle())) {
            app.sync.addDevice(@intCast(i + 1));
        }
    }
    // server_mode с сохранённой конфигурацией: присутствие всем контактам
    presence.startServerPresenceForAllLocked(app);
}

/// Загрузка клиентской записи (kind client): [tag][ts 8][len 2][data].
/// Кэш + MAC (дедуп приёма SYNC) + счётчик капы.
pub fn loadClientRec(app: *App, seq: u32, rec: []const u8) void {
    if (rec.len < 11) return;
    const dlen: usize = std.mem.readInt(u16, rec[9..11], .little);
    if (dlen == 0 or dlen > app_mod.max_client_data or rec.len != 11 + dlen) return;
    if (app.client_bytes + dlen > app_mod.client_db_cap) return; // кэш полон
    const copy = app.alloc.dupe(u8, rec[11..]) catch return;
    const mac = sync_mod.recordMac(&app.sync.key, @backingInt(sync_mod.RecKind.client), rec);
    app.client_macs.put(app.alloc, mac, {}) catch {
        app.alloc.free(copy);
        return;
    };
    app.client_recs.append(app.alloc, .{
        .seq = seq,
        .tag = rec[0],
        .ts_ms = std.mem.readInt(u64, rec[1..9], .little),
        .data = copy,
    }) catch {
        _ = app.client_macs.remove(mac);
        app.alloc.free(copy);
        return;
    };
    app.client_bytes += dlen;
}

// ------------------------------------------------------------- диспетчер

pub fn chatAlive(app: *App, cid: u16) bool {
    if (cid < 1 or cid > app.eng.contacts.items.len) return false;
    return !app.eng.contacts.items[cid - 1].deleted;
}

/// Запись лога kind msg → Rec поиска (срезы указывают в rec):
/// `[cid u16][flags u8][msg_id 16][ts u64][len u16][body][ents]`.
pub fn msgRecView(rec: []const u8) ?search_mod.Rec {
    const body_off = msgBodyOffset(rec) orelse return null;
    const blen = msgBodyLen(rec) orelse return null;
    if (rec.len < body_off + blen) return null;
    const tail = recEntityTail(rec, blen) orelse return null;
    return .{
        .cid = std.mem.readInt(u16, rec[0..2], .little),
        .flags = rec[2],
        .msg_id = rec[3..19].*,
        .ts_ms = std.mem.readInt(u64, rec[19..27], .little),
        .body = rec[body_off .. body_off + blen],
        .tail = tail,
        .size = 1 + 16 + 8 + 2 + blen + tail.len,
    };
}
